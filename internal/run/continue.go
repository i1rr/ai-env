package run

// Step 14: `--continue` support.
//
// This file implements the `--continue` flag's run-side wiring. The flag
// is the user-facing knob the master plan and plan 03 introduce to let
// an operator resume an early-terminated run without losing the agent's
// in-progress workspace state. The plan's wording (plan 03 line 155):
//
//	Implement `--continue`: create new run directory linked to previous
//	run, reuse same worktree.
//
// The behavior is intentionally narrow: we never re-checkout, never
// re-create the workspace, and never re-derive a fresh base ref. The
// previous run's workspace stays exactly as the agent left it; only a
// brand-new run directory is materialized next to the prior one and
// linked back via run.json's linked_previous_run field. The supervisor
// then drives the new run against the same workspace path, so the
// agent picks up where it left off.
//
// What this file owns:
//
//   - PrepareContinuation: the read+validate+materialize helper the CLI
//     calls when `--continue` is set. It encapsulates the "find the
//     previous run, refuse if not continuable, scaffold the new run
//     dir, copy or replace task.md" sequence so the CLI body stays
//     focused on flag parsing and supervisor wiring.
//   - ContinueError: the typed error the helper returns so the CLI can
//     surface a precise diagnostic ("no previous run", "previous run
//     still active", "previous run terminal X cannot be continued")
//     and so tests can assert on the failure cause via errors.As.
//
// What this file deliberately does NOT do:
//
//   - Touch the workspace tree. The previous run already owns the
//     worktree (or copy) at .ai-env/workspaces/<env>/; "reuse same
//     worktree" means we leave it alone. The new run inherits the
//     workspace by walking through workspace.ReadMetadata at supervisor
//     wire time, exactly as a fresh run would.
//   - Launch the supervisor. The supervisor is a separate concern; the
//     CLI builds a SupervisorOptions out of the Continuation result and
//     drives it the same way it would for a fresh run.
//   - Write any lifecycle.jsonl event. The new run's lifecycle log
//     starts at StateCreated when the supervisor's main loop fires; the
//     "continuation" relationship lives in run.json's
//     linked_previous_run field, not in the lifecycle event stream. The
//     plan's lifecycle schema (plan 03 "Event formats") does not carry
//     a continuation event type, and inventing one here would diverge
//     from the documented format for no readability win.

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// ContinueErrorKind classifies the failures PrepareContinuation can
// return. Keeping the kinds enumerated (rather than free-form
// fmt.Errorf strings) lets the CLI map each failure to the right exit
// code and message, and lets tests assert on the failure type without
// pattern-matching on prose.
type ContinueErrorKind int

const (
	// ContinueErrUnknown is the zero value; never returned directly.
	// Present so a defensive switch on Kind has a sensible default
	// case and so a future kind addition does not silently collide
	// with the iota-zero value.
	ContinueErrUnknown ContinueErrorKind = iota

	// ContinueErrNoPreviousRun reports that the env has no recorded
	// runs at all. The CLI surfaces this as "nothing to continue;
	// start a fresh run with `ai-env run <env> --task ...`".
	ContinueErrNoPreviousRun

	// ContinueErrPreviousRunActive reports that the latest run is not
	// yet in a terminal state. We refuse rather than racing the
	// in-flight supervisor: two supervisors writing into the same
	// workspace at once would produce undefined behavior, and the
	// plan's `--continue` is specifically for resuming an early
	// terminal, not for forking a live run.
	ContinueErrPreviousRunActive

	// ContinueErrPreviousRunNotContinuable reports that the latest
	// run reached a terminal state but the terminal is not on the
	// continuation-eligible list (plan 03's `terminalSupportsContinue`:
	// StateKilledByUser, StateTimedOut, StateKilledIdle). The
	// supervisor only prints the `--continue` suggestion for those
	// terminals; refusing here keeps the CLI's behavior in lock-step
	// with the suggestion the user saw.
	ContinueErrPreviousRunNotContinuable

	// ContinueErrPreviousRunMissingRecord reports that the previous
	// run directory exists but its run.json is empty (the
	// post-CreateRunDirectory placeholder) or malformed. We cannot
	// validate the previous terminal without the record, so we refuse
	// rather than guess. This case is rare in production (the
	// supervisor always writes at least one snapshot before exiting)
	// but possible if the previous supervisor crashed before its
	// first transition.
	ContinueErrPreviousRunMissingRecord
)

// ContinueError is the typed error PrepareContinuation returns. It
// carries the failure Kind, the env name, and (when relevant) the
// previous run's ID and terminal state so the CLI message can name the
// exact run that blocked the continuation.
//
// Unwrap returns nil; the failure is fully described by Kind plus the
// formatted message. Callers that need to differentiate failures use
// errors.As(err, &ContinueError{}) and inspect the Kind field.
type ContinueError struct {
	Kind         ContinueErrorKind
	EnvName      string
	PreviousID   string
	PreviousState State
}

// Error implements the error interface. The format is stable so tests
// match on substrings ("no previous run", "still active", "cannot be
// continued") rather than on the precise prose.
func (e *ContinueError) Error() string {
	switch e.Kind {
	case ContinueErrNoPreviousRun:
		return fmt.Sprintf("run: env %q has no previous run to continue", e.EnvName)
	case ContinueErrPreviousRunActive:
		return fmt.Sprintf("run: previous run %s for env %q is still active (state %q); cannot continue", e.PreviousID, e.EnvName, e.PreviousState)
	case ContinueErrPreviousRunNotContinuable:
		return fmt.Sprintf("run: previous run %s for env %q ended in state %q which cannot be continued", e.PreviousID, e.EnvName, e.PreviousState)
	case ContinueErrPreviousRunMissingRecord:
		return fmt.Sprintf("run: previous run %s for env %q has no recorded state; cannot continue", e.PreviousID, e.EnvName)
	}
	return fmt.Sprintf("run: continue env %q failed", e.EnvName)
}

// Continuation is the value PrepareContinuation returns. It bundles
// everything the CLI needs to wire the supervisor for the new run:
//
//   - NewRun: the freshly materialized run directory the supervisor
//     will write into.
//   - PreviousRunID: the predecessor run's ID, ready to be threaded
//     into SupervisorOptions.LinkedPreviousRun (which the supervisor
//     persists into run.json's linked_previous_run field). Exposed as
//     a plain string rather than *string so the CLI's call site reads
//     naturally; the supervisor accepts *string and the CLI wraps with
//     `&cont.PreviousRunID`.
//   - PreviousRecord: the predecessor's run.json snapshot. The CLI
//     uses this to inherit fields the operator did not override on
//     the new run (agent, backend, reduced_safety, etc.) so a
//     `--continue` invocation without those flags lands on the same
//     identity as the previous run rather than re-defaulting.
//   - TaskSource: a short label explaining which task.md the new run
//     ended up with ("inherited" when no --task was passed, "fresh"
//     when the operator supplied one). Surfaced for the CLI summary
//     so the operator sees at a glance which task the agent will see.
type Continuation struct {
	NewRun         RunDirectory
	PreviousRunID  string
	PreviousRecord Record
	TaskSource     TaskSource
}

// TaskSource labels the origin of the new run's task.md content. The
// CLI prints it in the continuation summary so the operator knows
// whether the agent will see a fresh prompt or the prior one.
type TaskSource string

const (
	// TaskSourceFresh means a non-empty `--task` flag was supplied and
	// the new run.md was written from it. The previous task is left in
	// the previous run directory but not propagated.
	TaskSourceFresh TaskSource = "fresh"

	// TaskSourceInherited means no new task was supplied; the previous
	// run's task body was copied into the new run's task.md verbatim.
	// This is the documented "resume where you left off" path: the
	// agent sees the same instruction set on the new run as on the
	// old one.
	TaskSourceInherited TaskSource = "inherited"
)

// PrepareContinuation is the read+validate+materialize helper the CLI
// calls when `ai-env run <env> --continue` fires. It:
//
//  1. Locates the env's latest run via LatestRunForEnv.
//  2. Reads its run.json to learn the terminal state and the task
//     description.
//  3. Validates the terminal is one of the continuation-eligible
//     terminals (terminalSupportsContinue). An in-flight run, a
//     completed run, a failure terminal, or an OOM kill all surface
//     as a ContinueError.
//  4. Generates a fresh run ID and creates the new run directory on
//     disk (via CreateRunDirectory) so the supervisor has somewhere
//     to write.
//  5. Populates the new run's task.md: from the supplied `task`
//     argument when non-empty, or by copying the previous run's task
//     body when the operator did not override it.
//
// Inputs:
//
//   - aiEnvDir is the absolute path to the host's .ai-env/ directory.
//     LatestRunForEnv resolves the runs/ tree underneath; the caller
//     is responsible for finding aiEnvDir (cli.findAIEnvDir handles
//     it in production).
//   - envName is the env to continue. Must be non-empty; the index
//     helpers reject blank queries up front.
//   - task is the operator-supplied --task flag content. Pass "" to
//     inherit the previous run's task body (TaskSourceInherited);
//     pass non-empty to start the new run with a fresh task
//     (TaskSourceFresh). The whitespace check matches WriteTask's
//     contract: a `--task " "` does not count as "supplied".
//   - now is the wall-clock the new run directory records as its
//     CreatedAt. Pass time.Now in production; tests pass a fixed
//     time so the returned Continuation is deterministic.
//
// On success PrepareContinuation returns a fully populated
// Continuation. On failure it returns a *ContinueError describing the
// blocking condition; the new run directory is NOT created in that
// case, so a retry (with a different --continue target or after the
// previous run terminates) starts from a clean slate.
//
// PrepareContinuation deliberately does NOT touch the workspace tree.
// "Reuse same worktree" in the plan's wording means we leave the
// previous run's workspace exactly as it is: no checkout, no reset,
// no clean. The supervisor's run loop opens the workspace via
// workspace.ReadMetadata at wire time, and that metadata file was
// written once by `ai-env new`; it is unchanged across runs. The
// agent sees the workspace exactly as the previous run left it.
func PrepareContinuation(aiEnvDir, envName, task string, now time.Time) (Continuation, error) {
	if aiEnvDir == "" {
		return Continuation{}, errors.New("run: PrepareContinuation requires aiEnvDir")
	}
	if envName == "" {
		return Continuation{}, errors.New("run: PrepareContinuation requires envName")
	}

	prev, err := LatestRunForEnv(aiEnvDir, envName)
	if err != nil {
		if errors.Is(err, ErrNoRuns) {
			return Continuation{}, &ContinueError{
				Kind:    ContinueErrNoPreviousRun,
				EnvName: envName,
			}
		}
		return Continuation{}, fmt.Errorf("run: PrepareContinuation: locate previous run for env %q: %w", envName, err)
	}

	prevRec, recErr := ReadRecord(prev.Path)
	if recErr != nil {
		if errors.Is(recErr, ErrRecordNotWritten) {
			return Continuation{}, &ContinueError{
				Kind:       ContinueErrPreviousRunMissingRecord,
				EnvName:    envName,
				PreviousID: prev.ID,
			}
		}
		return Continuation{}, fmt.Errorf("run: PrepareContinuation: read previous run %s: %w", prev.ID, recErr)
	}

	// A run that has not yet reached a terminal state cannot be
	// continued: a live supervisor is still writing into the workspace
	// and run.json. Refuse rather than racing.
	if !prevRec.State.IsTerminal() {
		return Continuation{}, &ContinueError{
			Kind:          ContinueErrPreviousRunActive,
			EnvName:       envName,
			PreviousID:    prev.ID,
			PreviousState: prevRec.State,
		}
	}

	// The terminal must be one the plan marks as continuable. The
	// supervisor's --continue suggestion (continueSuggestionText /
	// terminalSupportsContinue) uses the same predicate, so the CLI's
	// gate matches what the user saw on the prior run's last line.
	if !terminalSupportsContinue(prevRec.State) {
		return Continuation{}, &ContinueError{
			Kind:          ContinueErrPreviousRunNotContinuable,
			EnvName:       envName,
			PreviousID:    prev.ID,
			PreviousState: prevRec.State,
		}
	}

	// All gates passed. Generate the new ID and materialize the run
	// directory next to the previous one (same .ai-env/runs/ parent).
	newID, err := GenerateRunID()
	if err != nil {
		return Continuation{}, fmt.Errorf("run: PrepareContinuation: generate new run id: %w", err)
	}
	newRun, err := CreateRunDirectory(aiEnvDir, newID, now)
	if err != nil {
		return Continuation{}, fmt.Errorf("run: PrepareContinuation: create new run directory: %w", err)
	}

	// Populate task.md. The supplied task wins when non-empty (per
	// WriteTask's TrimSpace contract); otherwise we fall back to the
	// previous run's task body so the agent on the new run sees the
	// same instructions. The fallback is the documented "resume" path.
	source := TaskSourceFresh
	taskBody := task
	if isTaskEmpty(task) {
		source = TaskSourceInherited
		taskBody = prevRec.Task
	}
	if isTaskEmpty(taskBody) {
		// The previous run had no recorded task either (older run
		// before WriteTask was wired, or a manual run.json edit). We
		// cannot leave task.md empty because WriteTask refuses; surface
		// the failure so the operator supplies one explicitly.
		_ = os.RemoveAll(newRun.Path)
		return Continuation{}, fmt.Errorf("run: PrepareContinuation: previous run %s has no task to inherit; pass --task to supply one", prev.ID)
	}
	if err := WriteTask(aiEnvDir, newRun.ID, taskBody); err != nil {
		// Roll back the freshly created run directory so a retry can
		// proceed without a half-populated tree blocking it. The
		// previous run directory is untouched; we never write to it.
		_ = os.RemoveAll(newRun.Path)
		return Continuation{}, fmt.Errorf("run: PrepareContinuation: write task.md: %w", err)
	}

	return Continuation{
		NewRun:         newRun,
		PreviousRunID:  prev.ID,
		PreviousRecord: prevRec,
		TaskSource:     source,
	}, nil
}

// isTaskEmpty mirrors WriteTask's "non-empty after TrimSpace" check.
// Kept private to the continue path because the trim semantics are an
// implementation detail of WriteTask; if WriteTask ever loosens its
// contract this helper changes with it.
func isTaskEmpty(s string) bool {
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return false
	}
	return true
}

// LinkedPreviousRunPtr is a small convenience the CLI uses to thread
// the Continuation.PreviousRunID into SupervisorOptions.LinkedPreviousRun
// (which is *string). Returning nil when id is empty keeps the
// supervisor's "no link" path (the plan's run.json example shows
// linked_previous_run: null) reachable without the call site having to
// duplicate the pointer dance.
func LinkedPreviousRunPtr(id string) *string {
	if id == "" {
		return nil
	}
	v := id
	return &v
}
