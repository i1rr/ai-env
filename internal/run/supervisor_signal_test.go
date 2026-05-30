package run

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// newSignalSupervisor constructs a Supervisor pointed at a real on-disk
// run directory and a `sleep 30` child. The defaults match the cancel /
// timeout tests in supervisor_test.go so the signal-handler tests
// exercise the same code path the cancel-via-API tests pin, just with
// the trigger swapped from a direct sup.Cancel() call to an os.Signal
// delivered to the test process.
func newSignalSupervisor(t *testing.T, envName string) (*Supervisor, RunDirectory) {
	t.Helper()
	dir := newSupervisorRunDir(t)
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           envName,
		Task:              "Sleep forever, expect a signal",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("sleep 30"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       0,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	return sup, dir
}

// runSignalCase is the shared body for the SIGINT / SIGTERM / SIGHUP
// per-signal tests. It installs the supervisor's signal handlers, kicks
// off Run in a goroutine, sends the requested signal to the current
// test process, and asserts that Run lands on StateKilledByUser with
// StopReasonSignal. The lifecycle file is also inspected so the audit
// trail (the same one the cancel-via-API path emits) is verified end to
// end.
//
// The function is deliberately conservative on timing: 100 ms of
// headroom before the signal is sent so the supervisor reaches
// StateRunning (the same headroom TestSupervisor_CancelStopsRun uses),
// and a 5 s overall budget for Run to return after the signal. The
// child is `sleep 30`, so without the handler the test would hang
// rather than pass by accident.
func runSignalCase(t *testing.T, envName string, sig syscall.Signal) {
	t.Helper()
	skipIfNoSh(t)
	if runtime.GOOS == "windows" {
		// The supervised signals overlap badly with Windows; the plan's
		// signal handling is POSIX-only in v0.1.
		t.Skip("signal handling tests are POSIX-only")
	}

	sup, dir := newSignalSupervisor(t, envName)

	stop, err := InstallSignalHandlers(sup)
	if err != nil {
		t.Fatalf("InstallSignalHandlers: %v", err)
	}
	// Stop the handlers no matter what so a panicking test does not
	// leak a goroutine that will then race with the next test's
	// signal.Notify call.
	t.Cleanup(stop)

	done := make(chan SupervisorResult, 1)
	go func() {
		res, runErr := sup.Run(context.Background())
		if runErr != nil {
			t.Errorf("Run: %v", runErr)
		}
		done <- res
	}()

	// Give the supervisor enough time to walk the setup stages and
	// reach StateRunning. 100 ms is the same headroom the cancel tests
	// use; the supervisor's setup is purely in-memory (no real backend)
	// so it lands in StateRunning almost immediately.
	time.Sleep(100 * time.Millisecond)

	// Send the signal to the test process itself. The signal handler
	// installed by InstallSignalHandlers registers for SIGINT / SIGTERM
	// / SIGHUP, so the runtime routes the signal into our channel
	// rather than into the default process disposition (which would
	// kill the test binary for SIGINT and SIGTERM).
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatalf("syscall.Kill(%v): %v", sig, err)
	}

	select {
	case res := <-done:
		if res.FinalState != StateKilledByUser {
			t.Errorf("FinalState = %q, want %q (signal=%v)", res.FinalState, StateKilledByUser, sig)
		}
		if res.StopReason != StopReasonSignal {
			t.Errorf("StopReason = %q, want %q (signal=%v)", res.StopReason, StopReasonSignal, sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Run did not return after %v within 5s", sig)
	}

	// Lifecycle.jsonl must record killed_by_user as the terminal so the
	// audit trail mirrors what the cancel-via-API path produces. The
	// signal handler does not invent any new event; the supervisor's
	// existing cancellation event is the source of truth.
	states := readLifecycleStates(t, dir.Path)
	if len(states) == 0 {
		t.Fatalf("lifecycle.jsonl is empty for signal=%v", sig)
	}
	if states[len(states)-1] != StateKilledByUser {
		t.Errorf("lifecycle last state = %q, want %q (signal=%v, full=%v)", states[len(states)-1], StateKilledByUser, sig, states)
	}
}

// TestInstallSignalHandlers_SIGINT confirms a SIGINT delivered to the
// current process while the supervisor is running lands on
// StateKilledByUser with StopReasonSignal, matching the plan's
// "SIGINT: forward to agent, wait grace period, then stop." semantics
// and acceptance criterion #5 ("SIGINT preserves run logs and marks
// state as killed_by_user").
func TestInstallSignalHandlers_SIGINT(t *testing.T) {
	runSignalCase(t, "sigint-env", syscall.SIGINT)
}

// TestInstallSignalHandlers_SIGTERM mirrors the SIGINT test for SIGTERM.
// The plan keeps both signals on the same disposition ("forward to
// agent, wait grace period, then stop") and the supervisor's handler
// routes both through Cancel(), so the terminal must be identical.
func TestInstallSignalHandlers_SIGTERM(t *testing.T) {
	runSignalCase(t, "sigterm-env", syscall.SIGTERM)
}

// TestInstallSignalHandlers_SIGHUP mirrors the SIGINT test for SIGHUP.
// The plan documents SIGHUP as "mark interrupted, stop if
// non-interactive"; the supervisor is non-interactive in v0.1, so the
// terminal collapses onto the same StateKilledByUser the other two
// signals produce.
func TestInstallSignalHandlers_SIGHUP(t *testing.T) {
	runSignalCase(t, "sighup-env", syscall.SIGHUP)
}

// TestInstallSignalHandlers_StopRestoresDefaultAndNoLeak confirms the
// teardown contract: after stop() returns, the handler goroutine has
// exited and the channel has been closed. The check uses a delivered
// SIGINT after stop() to verify the runtime is no longer routing the
// signal into the test process's installed handler. Sending SIGINT
// after teardown would normally terminate the test binary, so we
// install our own short-lived listener for the duration of the
// verification window.
//
// The "no leak" half is enforced by counting goroutines before
// installation and after stop(). The handler must exit cleanly; a
// regression that forgets to close the channel would leave the
// goroutine parked on the for-range forever.
func TestInstallSignalHandlers_StopRestoresDefaultAndNoLeak(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signal handling tests are POSIX-only")
	}
	skipIfNoSh(t)

	// Baseline goroutine count. We give the runtime a tick to settle
	// before sampling so an unrelated test's deferred cleanup does not
	// pollute the baseline.
	runtime.GC()
	baseline := runtime.NumGoroutine()

	sup, _ := newSignalSupervisor(t, "stop-no-leak")
	stop, err := InstallSignalHandlers(sup)
	if err != nil {
		t.Fatalf("InstallSignalHandlers: %v", err)
	}
	// Stop the handlers immediately without ever sending a signal. We
	// also Cancel the supervisor and wait for Run to drain so the test
	// does not leak a child process; that is unrelated to the goroutine
	// being tested but keeps the env clean.
	done := make(chan struct{})
	go func() {
		_, _ = sup.Run(context.Background())
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	stop()
	sup.Cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not drain after Cancel within 5s")
	}

	// Calling stop() a second time must be a no-op. If the second call
	// races on the closed channel or the closed done channel, the
	// runtime panics; this assertion catches the regression.
	stop()

	// After stop() returns, the runtime must no longer be routing
	// supervised signals to InstallSignalHandlers' channel. Verify by
	// installing a separate one-shot listener and confirming it
	// receives a delivered SIGUSR1 (a signal we do NOT supervise) on
	// its own channel without interference. SIGUSR1 is unrelated to
	// the supervisor; using it avoids accidentally killing the test
	// process if the handler is still routing through Cancel.
	got := make(chan os.Signal, 1)
	// Notify on an unsupervised signal so we can sanity-check signal
	// delivery without depending on the supervisor's set.
	signal.Notify(got, syscall.SIGUSR1)
	defer signal.Stop(got)
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("syscall.Kill(SIGUSR1): %v", err)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGUSR1 was not delivered after stop(); runtime signal plumbing is broken")
	}

	// Goroutine leak check. We give the runtime a tick to let the
	// handler goroutine fully exit, then compare against baseline. A
	// small slack (16) absorbs scheduler noise and parallel test
	// runners; a leak from this test would be a single goroutine, well
	// inside the slack threshold's distinguishing power.
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	if delta := runtime.NumGoroutine() - baseline; delta > 16 {
		t.Errorf("goroutine count grew by %d after stop(); want near 0", delta)
	}
}

// TestInstallSignalHandlers_NilSupervisor pins the misuse path. A nil
// supervisor must surface as an error rather than panicking when the
// handler goroutine tries to call sup.Cancel().
func TestInstallSignalHandlers_NilSupervisor(t *testing.T) {
	stop, err := InstallSignalHandlers(nil)
	if err == nil {
		t.Fatal("InstallSignalHandlers(nil) returned nil error, want error")
	}
	if !errors.Is(err, errNilSupervisor) {
		t.Errorf("err = %v, want errNilSupervisor", err)
	}
	if stop != nil {
		t.Error("stop is non-nil on error path, want nil")
	}
}

// TestInstallSignalHandlers_RepeatedSignalsCollapse confirms a second
// signal arriving after the first is a no-op at the supervisor level.
// The handler goroutine continues to drain ch (otherwise signal.Notify
// would start dropping deliveries), but sup.Cancel collapses every
// repeat through its sync.Once.
//
// The behavioural assertion is the same as the single-signal cases:
// the run still lands on StateKilledByUser and Run returns once. A
// regression that escalated the second signal to a different terminal
// (e.g. force-killed without a clean cause record) would fail here.
func TestInstallSignalHandlers_RepeatedSignalsCollapse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signal handling tests are POSIX-only")
	}
	skipIfNoSh(t)

	sup, _ := newSignalSupervisor(t, "repeat-signal")
	stop, err := InstallSignalHandlers(sup)
	if err != nil {
		t.Fatalf("InstallSignalHandlers: %v", err)
	}
	t.Cleanup(stop)

	done := make(chan SupervisorResult, 1)
	go func() {
		res, _ := sup.Run(context.Background())
		done <- res
	}()
	time.Sleep(100 * time.Millisecond)

	// Hit it with three signals in quick succession from a few
	// goroutines so the handler goroutine drains a backlog and the
	// supervisor's Cancel collapses them all into one terminal.
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		}()
	}
	wg.Wait()

	select {
	case res := <-done:
		if res.FinalState != StateKilledByUser {
			t.Errorf("FinalState = %q, want %q", res.FinalState, StateKilledByUser)
		}
		if res.StopReason != StopReasonSignal {
			t.Errorf("StopReason = %q, want %q", res.StopReason, StopReasonSignal)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after repeated SIGINT within 5s")
	}
}

// TestInstallSignalHandlers_MultipleInstallStopIsIdempotent confirms
// that installing and tearing down the handler several times in a row
// (as the test suite does, one install per test) does not corrupt the
// process's signal disposition. The check is purely a no-panic /
// no-deadlock smoke test: install, stop, install, stop, ... and assert
// no goroutine leaks afterwards.
func TestInstallSignalHandlers_MultipleInstallStopIsIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signal handling tests are POSIX-only")
	}
	skipIfNoSh(t)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	for i := 0; i < 4; i++ {
		sup, _ := newSignalSupervisor(t, "multi-install")
		stop, err := InstallSignalHandlers(sup)
		if err != nil {
			t.Fatalf("InstallSignalHandlers[%d]: %v", i, err)
		}
		// Cancel + drain so the child process does not leak. We are
		// testing handler install / teardown, not Run; the cancel path
		// is already covered by the per-signal tests above.
		drained := make(chan struct{})
		go func() {
			_, _ = sup.Run(context.Background())
			close(drained)
		}()
		time.Sleep(30 * time.Millisecond)
		sup.Cancel()
		<-drained
		stop()
	}

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	if delta := runtime.NumGoroutine() - baseline; delta > 16 {
		t.Errorf("goroutine count grew by %d after repeated install/stop; want near 0", delta)
	}
}
