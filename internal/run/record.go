package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// runJSONFileName is the basename of the per-run final-state snapshot. It
// lives at the root of the run directory next to lifecycle.jsonl; the two
// together describe the run on disk (the lifecycle file is the event
// stream, run.json is the latest snapshot). Mirrors lifecycleFileName /
// taskFileName so a single edit changes the layout everywhere.
const runJSONFileName = "run.json"

// runJSONTempPattern is the basename pattern handed to os.CreateTemp for
// the staged write file. Keeping the prefix obvious ("run.json.tmp-")
// makes a stale temp file from a crashed write trivially identifiable
// when an operator inspects the run directory after the fact, and the
// "tmp" segment keeps it from accidentally matching any future glob the
// run directory layout introduces.
const runJSONTempPattern = "run.json.tmp-*"

// StopReason is the human-meaningful explanation the supervisor records
// when a run leaves a terminal state. The plan's run.json example pins
// "agent_exit"; the rest of the constants below cover the other terminal
// origins (timeouts, kills, scan failures) so the rendering side does
// not have to invent strings.
//
// StopReason is a string so it round-trips through JSON unchanged. The
// constants are the only values the supervisor should emit; future
// reasons (e.g. dependency-block) extend the set rather than free-typing.
type StopReason string

const (
	// StopReasonAgentExit is the canonical success reason: the agent
	// finished on its own (zero or non-zero exit code) without an
	// external stop. The plan's example uses this value verbatim.
	StopReasonAgentExit StopReason = "agent_exit"

	// StopReasonTimeout pairs with StateTimedOut: the supervisor's
	// max_runtime_minutes budget elapsed and forced the agent down.
	StopReasonTimeout StopReason = "timeout"

	// StopReasonIdle pairs with StateKilledIdle: idle_timeout_minutes
	// elapsed with no output and no diff so the supervisor stopped the
	// agent.
	StopReasonIdle StopReason = "idle_timeout"

	// StopReasonSignal pairs with StateKilledByUser: SIGINT or SIGTERM
	// arrived and the supervisor honored it.
	StopReasonSignal StopReason = "signal"

	// StopReasonOOM pairs with StateKilledOOM: the backend (or host)
	// reported the run's memory budget was exhausted.
	StopReasonOOM StopReason = "oom"

	// StopReasonBackendFailure pairs with StateFailedBackend: backend
	// bring-up or workspace prep failed.
	StopReasonBackendFailure StopReason = "backend_failure"

	// StopReasonAgentFailure pairs with StateFailedAgent: the agent
	// process refused to start or crashed unexpectedly.
	StopReasonAgentFailure StopReason = "agent_failure"

	// StopReasonPolicyFailure pairs with StateFailedPolicy: a policy
	// install step refused to apply.
	StopReasonPolicyFailure StopReason = "policy_failure"

	// StopReasonScanFailure pairs with StateFailedScan: the scanner
	// infrastructure itself errored (not "the scanner found something").
	StopReasonScanFailure StopReason = "scan_failure"

	// StopReasonQuarantine pairs with StateQuarantined: a scanner found
	// disqualifying content and the run was withheld from the normal
	// surfaces.
	StopReasonQuarantine StopReason = "quarantine"
)

// ModelCredentialMode is the credential-injection mode the supervisor
// selected for this run. The plan's run.json example uses
// "backend_managed" verbatim; the other two cover the documented model
// credential paths in master plan section about credentials.
type ModelCredentialMode string

const (
	// ModelCredentialBackendManaged is the safe default: credentials are
	// injected by the backend per-call, never landing in the agent's
	// process environment.
	ModelCredentialBackendManaged ModelCredentialMode = "backend_managed"

	// ModelCredentialProviderProxy is the proxy fallback: the host runs
	// a provider-compatible endpoint and points the agent at it, so the
	// raw token never enters the sandbox.
	ModelCredentialProviderProxy ModelCredentialMode = "provider_proxy"

	// ModelCredentialRawToken is the reduced-safety fallback: the token
	// is injected into the agent process environment directly. The plan
	// requires every run.json record to mark this case so audit can find
	// it later.
	ModelCredentialRawToken ModelCredentialMode = "raw_token"
)

// Record is the in-memory representation of run.json. It is the single
// source of truth for the file's schema: every field present here ends up
// in the on-disk JSON, and any field plan 03 lists for run.json is present
// here.
//
// Field order matches the plan's example (run.json schema (minimal))
// verbatim so the on-disk JSON reads like the plan when pretty-printed.
// Optional fields (the ones the plan example shows as null or the ones
// only set on terminal transitions) use pointer types so an unset value
// serializes as JSON null rather than a misleading zero value: for
// example, a run that has not stopped yet must record stopped_at as null,
// not "0001-01-01T00:00:00Z".
//
// Times are serialized as RFC3339 strings (the JSON encoder's default for
// time.Time) so the on-disk format matches the plan's example timestamps
// ("2026-05-28T10:13:00+10:00"). The supervisor is responsible for
// passing times in the desired time zone; the record does not rewrite
// them.
type Record struct {
	// RunID is the run identifier and the basename of the run directory.
	RunID string `json:"run_id"`

	// EnvName is the workspace environment name the run targets. The
	// plan's example shows "fix-tests"; v0.1 uses this both as the
	// workspace directory basename and as the user-visible env handle.
	EnvName string `json:"env_name"`

	// Agent is the agent identifier the supervisor launched.
	Agent string `json:"agent"`

	// Task is the verbatim --task flag content. It duplicates task.md so
	// a reader of run.json alone can see what the agent was asked to do
	// without opening a second file.
	Task string `json:"task"`

	// State is the run's current (or terminal) state. The plan's example
	// shows "completed" but the writer is happy with any State value; the
	// supervisor's main loop writes Record snapshots at every transition.
	State State `json:"state"`

	// ExitCode is the agent process's exit code. Pointer-typed because a
	// run that has not stopped yet has no exit code; emitting 0 in that
	// case would be misleading.
	ExitCode *int `json:"exit_code"`

	// StartedAt is the moment the run entered StatePreparingWorkspace
	// (the first post-create transition). It is set once and never
	// rewritten. Pointer-typed so a Record snapshotted before the run
	// started records null rather than a zero time.
	StartedAt *time.Time `json:"started_at"`

	// StoppedAt is the moment the run reached a terminal state. Pointer-
	// typed for the same reason as StartedAt: a still-running record
	// must serialize null, not the Go zero time.
	StoppedAt *time.Time `json:"stopped_at"`

	// StopReason is the human-meaningful explanation for the terminal.
	// Empty (omitted from JSON) until the run actually stops; the
	// pointer keeps the "not set yet" case visible as null.
	StopReason *StopReason `json:"stop_reason"`

	// Backend is the backend identifier the supervisor selected.
	Backend string `json:"backend"`

	// ModelCredentialMode records the credential-injection path. The
	// plan requires this field on every run so a future audit pass can
	// flag raw-token runs.
	ModelCredentialMode ModelCredentialMode `json:"model_credential_mode"`

	// ReducedSafety is true when the run is operating with reduced
	// safety guarantees (raw model token, host mount overrides, etc.).
	// The plan's example shows false; the writer faithfully passes
	// through whatever the supervisor decides.
	ReducedSafety bool `json:"reduced_safety"`

	// LinkedPreviousRun is the run ID of the predecessor run when this
	// run was started with --continue. Pointer-typed because the plan's
	// example explicitly shows null for the no-link case, and a JSON
	// null is the truthful encoding for a chain that has not started
	// yet.
	LinkedPreviousRun *string `json:"linked_previous_run"`
}

// WriteRecord serializes record into run.json under runDir using an
// atomic replace. The plan asks for run.json to be re-writable as the
// supervisor walks the state machine: each call must leave the file
// either fully replaced with the new content or untouched, never
// truncated mid-write where a concurrent reader (status command, audit
// tail) could see partial JSON.
//
// The implementation follows the standard write-temp-then-rename
// pattern:
//
//  1. Encode record into a buffer (pretty-printed with two-space indent
//     so an operator opening the file sees readable JSON; the plan's
//     example is pretty-printed).
//  2. Create a temp file in the same directory as run.json so the rename
//     stays within one filesystem and is therefore atomic on every POSIX
//     filesystem we support (and on NTFS for the Windows case).
//  3. Write the buffer to the temp file, fsync it, and close.
//  4. os.Rename the temp file over run.json. On POSIX rename is atomic;
//     a reader opening run.json either sees the old content or the new,
//     never an empty file or a partial JSON object.
//  5. fsync the parent directory so the rename itself survives a crash.
//     Without the directory fsync, a host crash between rename and
//     dirent flush could leave the temp file lingering and run.json
//     pointing at the previous inode.
//
// On any error the temp file is cleaned up so a retry starts with a
// clean directory. If the cleanup itself fails (rare), the temp file
// pattern makes the leftover easy to identify and remove later.
//
// WriteRecord does not validate the Record's contents beyond requiring
// a non-empty RunID (the plan makes RunID load-bearing for every
// downstream artifact); other fields are the supervisor's
// responsibility. A nil exit code or stopped_at is legal and serializes
// as null per the plan's pointer semantics.
func WriteRecord(runDir string, record Record) error {
	if runDir == "" {
		return errors.New("run: WriteRecord requires runDir")
	}
	if record.RunID == "" {
		return errors.New("run: WriteRecord requires record.RunID")
	}

	// Marshal up front so a malformed Record fails before we touch the
	// filesystem. MarshalIndent matches the plan's example formatting
	// and makes diff'ing run.json across snapshots readable.
	buf, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("run: marshal run.json: %w", err)
	}
	// JSON encoders do not append a trailing newline; adding one keeps
	// the file POSIX-text-friendly so `cat run.json` ends on a clean
	// prompt and editors do not add their own surprise newline diff.
	buf = append(buf, '\n')

	// CreateTemp guarantees a unique name (defeating any race between
	// two concurrent WriteRecord calls), and placing it in runDir keeps
	// the eventual rename intra-filesystem so the atomicity guarantee
	// holds.
	tmp, err := os.CreateTemp(runDir, runJSONTempPattern)
	if err != nil {
		return fmt.Errorf("run: create run.json temp file in %s: %w", runDir, err)
	}
	tmpPath := tmp.Name()
	// removeTmp tears the temp file down on any failure path. The
	// happy path replaces the temp file with the rename so the unlink
	// becomes a no-op there.
	removeTmp := func() {
		_ = os.Remove(tmpPath)
	}

	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		removeTmp()
		return fmt.Errorf("run: write run.json temp file %s: %w", tmpPath, err)
	}
	// Sync the file's bytes before the rename so a crash between
	// rename and writeback does not surface an empty run.json.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		removeTmp()
		return fmt.Errorf("run: sync run.json temp file %s: %w", tmpPath, err)
	}
	// CreateTemp gives a 0o600 file by default; chmod to runFileMode
	// before rename so the on-disk run.json matches the rest of the
	// run-directory permissions (0o644).
	if err := os.Chmod(tmpPath, runFileMode); err != nil {
		_ = tmp.Close()
		removeTmp()
		return fmt.Errorf("run: chmod run.json temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		removeTmp()
		return fmt.Errorf("run: close run.json temp file %s: %w", tmpPath, err)
	}

	finalPath := filepath.Join(runDir, runJSONFileName)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		removeTmp()
		return fmt.Errorf("run: rename run.json temp file into place: %w", err)
	}

	// fsync the parent directory so the rename itself survives a host
	// crash. Failure here is non-fatal in the sense that the rename has
	// already happened; we still surface the error so the supervisor's
	// log shows the partial-durability case. On Windows os.Open on a
	// directory is allowed but Sync may return EINVAL; we treat that as
	// non-fatal to keep the cross-platform contract simple.
	if dir, err := os.Open(runDir); err == nil {
		// Best-effort sync; we explicitly ignore the error on close
		// because a failure to close a directory handle should not
		// mask the successful rename.
		_ = dir.Sync()
		_ = dir.Close()
	}

	return nil
}

// ReadRecord loads run.json from runDir and decodes it back into a
// Record. It is the round-trip companion to WriteRecord: status, list,
// and replay tooling later in this plan and beyond use it to learn the
// run's last-recorded state without re-parsing lifecycle.jsonl.
//
// ReadRecord returns a clear error when run.json is missing or malformed
// so a caller can decide whether to surface "no run yet" or "corrupted
// run record". It does not attempt repair; the atomic write contract on
// WriteRecord means a corrupted file is a sign of an out-of-band
// modification or a filesystem failure, both of which the supervisor
// should report rather than paper over.
func ReadRecord(runDir string) (Record, error) {
	if runDir == "" {
		return Record{}, errors.New("run: ReadRecord requires runDir")
	}
	path := filepath.Join(runDir, runJSONFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return Record{}, fmt.Errorf("run: read run.json %s: %w", path, err)
	}
	// An empty file is the post-CreateRunDirectory placeholder. Treat it
	// as "no record yet" with a dedicated error so callers can branch on
	// it cleanly via errors.Is.
	if len(raw) == 0 {
		return Record{}, ErrRecordNotWritten
	}

	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Record{}, fmt.Errorf("run: parse run.json %s: %w", path, err)
	}
	return rec, nil
}

// ErrRecordNotWritten is returned by ReadRecord when run.json exists but
// is empty (the post-CreateRunDirectory placeholder state). Callers that
// want to distinguish "no record yet" from "record corrupted" can match
// on it with errors.Is.
var ErrRecordNotWritten = errors.New("run: run.json has not been written yet")

// RunJSONPath returns the absolute path of the run.json file inside the
// run directory at runDir. It is the symmetric helper to TaskPath; the
// status and list commands use it to surface the file's location in
// their output without re-encoding the layout.
func RunJSONPath(runDir string) string {
	return filepath.Join(runDir, runJSONFileName)
}
