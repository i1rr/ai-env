package run

// Dedicated step 16 test: "max runtime timeout stops the supervisor".
// Plan 03, line 157. The existing TestSupervisor_MaxRuntimeTimeout in
// supervisor_test.go pins the headline outcome (FinalState and
// StopReason); the test below adds the stronger guarantees the plan-
// executor brief calls for:
//
//   - The supervisor terminates promptly after the budget expires
//     (generous slack so a slow CI box does not flake).
//   - run.json's final snapshot carries the timeout terminal state with
//     a stop_reason of timeout and a populated stopped_at.
//   - The child process is reaped (no zombie). We assert this via
//     cmd.ProcessState exposing Exited / Pid alongside the supervisor's
//     own HasExitCode signal, which is the same handle the production
//     code surfaces.
//   - Lifecycle.jsonl ends on the timed_out terminal so the audit log
//     reflects the timeout cause.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestStep16_MaxRuntimeTimeoutStopsSupervisor wires a real supervisor
// against a long-running `sleep 5` child with a 100ms MaxRuntime budget.
// The child outlives the budget by a factor of 50x; the supervisor must
// kill it, transition the state machine to StateTimedOut, persist the
// terminal in run.json, and return promptly.
func TestStep16_MaxRuntimeTimeoutStopsSupervisor(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)

	const maxRuntime = 100 * time.Millisecond
	// Generous overall budget: max runtime + stop grace + scheduler
	// noise on a busy CI box. Anything well under sleep 5 catches a
	// regression that forgets to enforce the budget.
	const overallBudget = 2 * time.Second

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "step16-timeout",
		Task:              "Sleep past the max runtime budget",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("sleep 5"),
		MaxRuntime:        maxRuntime,
		IdleTimeout:       0,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	start := time.Now()
	result, err := sup.Run(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// --- Promptness ---------------------------------------------------
	// The supervisor should land its terminal long before the `sleep 5`
	// child would naturally exit. We use a generous bound to absorb CI
	// scheduling slack without losing the ability to detect "forgot to
	// enforce the budget" regressions (which would push elapsed past 5s).
	if elapsed > overallBudget {
		t.Errorf("Run took %v; expected timeout to fire within %v (max runtime = %v)", elapsed, overallBudget, maxRuntime)
	}
	if elapsed < maxRuntime {
		// A regression that returned before the budget even elapsed would
		// indicate the timer is mis-armed (firing immediately). The check
		// is a floor, not a tight bound.
		t.Errorf("Run took %v; budget was %v, suspiciously short", elapsed, maxRuntime)
	}

	// --- Result fields ------------------------------------------------
	if result.FinalState != StateTimedOut {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateTimedOut)
	}
	if result.StopReason != StopReasonTimeout {
		t.Errorf("StopReason = %q, want %q", result.StopReason, StopReasonTimeout)
	}
	if result.StoppedAt.IsZero() {
		t.Error("result.StoppedAt is zero, want non-zero")
	}
	if result.StartedAt.IsZero() {
		t.Error("result.StartedAt is zero, want non-zero")
	}
	if !result.StoppedAt.After(result.StartedAt) && !result.StoppedAt.Equal(result.StartedAt) {
		t.Errorf("StoppedAt %v should be >= StartedAt %v", result.StoppedAt, result.StartedAt)
	}

	// --- Child reaping ------------------------------------------------
	// By the time Run returns the waiter goroutine launchChild started
	// has reaped the child. We reach into the supervisor's own state to
	// verify the OS-level state machine reflects that: the process is
	// dead (no zombie) and the supervisor's ProcessState handle is
	// populated. ProcessState.Pid() being non-zero confirms the runtime
	// has reaped the child (otherwise ProcessState would still be nil).
	sup.childMu.Lock()
	child := sup.child
	sup.childMu.Unlock()
	if child == nil {
		t.Fatal("supervisor child is nil after Run returned; launch failed?")
	}
	if child.ProcessState == nil {
		t.Fatal("child.ProcessState is nil; child was not reaped")
	}
	if child.ProcessState.Pid() == 0 {
		t.Errorf("child.ProcessState.Pid = 0, want non-zero (reaped pid)")
	}
	// A timeout kill terminates the child via SIGTERM/SIGKILL (after the
	// grace window). Exited() reports true only for natural exits; for a
	// signal-induced termination it returns false. Either way the
	// process is no longer alive, which is the contract we care about
	// here: ProcessState being populated proves Wait completed.
	// We do not assert Exited() either way because the supervisor's
	// stopChildGracefully sends SIGINT first and may escalate to SIGKILL;
	// the exact disposition depends on whether the child caught SIGINT
	// or was hard-killed.
	if result.HasExitCode {
		// If the child reported an exit code, it should not have been a
		// natural successful exit (sleep 5 only exits 0 after 5 seconds).
		// A non-zero code here means the shell observed the signal; an
		// exit code of 0 would suggest the budget did not actually fire.
		if result.ExitCode == 0 {
			t.Errorf("ExitCode = 0 with timeout terminal; expected signal-induced non-zero or no exit code")
		}
	}

	// --- Lifecycle audit trail ----------------------------------------
	states := readLifecycleStates(t, dir.Path)
	if len(states) == 0 {
		t.Fatal("lifecycle.jsonl is empty")
	}
	if states[len(states)-1] != StateTimedOut {
		t.Errorf("lifecycle last state = %q, want %q (full=%v)", states[len(states)-1], StateTimedOut, states)
	}

	// --- run.json terminal snapshot -----------------------------------
	rec, err := ReadRecord(dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.State != StateTimedOut {
		t.Errorf("run.json State = %q, want %q", rec.State, StateTimedOut)
	}
	if rec.StopReason == nil || *rec.StopReason != StopReasonTimeout {
		t.Errorf("run.json StopReason = %v, want %q", rec.StopReason, StopReasonTimeout)
	}
	if rec.StoppedAt == nil {
		t.Error("run.json StoppedAt = nil, want non-nil")
	}
	if rec.StartedAt == nil {
		t.Error("run.json StartedAt = nil, want non-nil")
	}
	if rec.RunID != dir.ID {
		t.Errorf("run.json RunID = %q, want %q", rec.RunID, dir.ID)
	}
	if rec.EnvName != "step16-timeout" {
		t.Errorf("run.json EnvName = %q, want step16-timeout", rec.EnvName)
	}

	// --- Sanity: run.json file actually exists on disk -----------------
	// We already read it through ReadRecord above, but locking down the
	// physical existence guards against a future refactor that returns a
	// synthesized Record without touching the disk.
	if _, err := os.Stat(filepath.Join(dir.Path, "run.json")); err != nil {
		t.Errorf("run.json missing on disk: %v", err)
	}
}
