package run

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// newSupervisorRunDir builds a real RunDirectory on disk so each
// supervisor test starts from the same scaffolded layout the real
// supervisor will see in production. We reuse the same helper shape
// the lifecycle, record, and stream tests use; the test ID and time
// are fixed so any timestamps that leak into assertions are stable.
func newSupervisorRunDir(t *testing.T) RunDirectory {
	t.Helper()
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-a1b2c3"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return dir
}

// readLifecycleStates parses lifecycle.jsonl and returns the State
// field of every event in order. Used by tests that assert on the
// sequence of transitions the supervisor wrote.
func readLifecycleStates(t *testing.T, runDir string) []State {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(runDir, "lifecycle.jsonl"))
	if err != nil {
		t.Fatalf("read lifecycle.jsonl: %v", err)
	}
	var states []State
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var evt LifecycleEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("parse lifecycle line %q: %v", line, err)
		}
		states = append(states, evt.State)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan lifecycle: %v", err)
	}
	return states
}

// shellCmd returns a CommandSpec that runs the given shell snippet.
// Tests use it to drive the supervisor with a real subprocess so the
// stdout/stderr capture, the wait path, and the exit-code recording
// are exercised end to end. On Windows we would need a different
// shell; the supervisor itself is portable but the tests use POSIX
// sh because the project's other tests already assume it.
func shellCmd(snippet string) CommandSpec {
	return CommandSpec{Program: "sh", Args: []string{"-c", snippet}}
}

// skipIfNoSh skips the test when the host has no POSIX sh (chiefly
// Windows). The supervisor's contract does not assume a shell;
// production callers wire a real agent binary. Tests use sh purely
// because it is the most portable way to spell "print, then sleep
// briefly, then exit with this code".
func skipIfNoSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("supervisor tests use POSIX sh; skipping on windows")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("sh not available: %v", err)
	}
}

// TestSupervisor_HappyPath drives the supervisor against a real
// child process that prints to stdout and stderr and exits cleanly.
// It is the canonical end-to-end check the plan asks for: the state
// machine must walk created -> ... -> completed, lifecycle.jsonl must
// record every transition, run.json's final snapshot must show the
// completed state with exit 0 and stop_reason agent_exit, and the
// captured stdout/stderr must contain the bytes the child printed.
func TestSupervisor_HappyPath(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "fix-tests",
		Task:              "Fix the failing tests",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("echo hello-out; echo hello-err >&2; exit 0"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}
	if result.StopReason != StopReasonAgentExit {
		t.Errorf("StopReason = %q, want %q", result.StopReason, StopReasonAgentExit)
	}
	if !result.HasExitCode || result.ExitCode != 0 {
		t.Errorf("ExitCode = %d (has=%v), want 0", result.ExitCode, result.HasExitCode)
	}

	// Lifecycle must include every happy-path transition in order.
	states := readLifecycleStates(t, dir.Path)
	wantHead := []State{
		StatePreparingWorkspace,
		StateStartingBackend,
		StateApplyingPolicy,
		StateStartingAgent,
		StateRunning,
		StateStopping,
		StateScanning,
		StateReporting,
		StateCompleted,
	}
	if len(states) != len(wantHead) {
		t.Fatalf("lifecycle states = %v, want %v", states, wantHead)
	}
	for i, w := range wantHead {
		if states[i] != w {
			t.Errorf("state[%d] = %q, want %q", i, states[i], w)
		}
	}

	// stdout/stderr captures must contain the child's output.
	stdout, err := os.ReadFile(filepath.Join(dir.Path, "stdout.log"))
	if err != nil {
		t.Fatalf("read stdout.log: %v", err)
	}
	if !strings.Contains(string(stdout), "hello-out") {
		t.Errorf("stdout.log = %q, want substring %q", stdout, "hello-out")
	}
	stderr, err := os.ReadFile(filepath.Join(dir.Path, "stderr.log"))
	if err != nil {
		t.Fatalf("read stderr.log: %v", err)
	}
	if !strings.Contains(string(stderr), "hello-err") {
		t.Errorf("stderr.log = %q, want substring %q", stderr, "hello-err")
	}

	// run.json must reflect the terminal state.
	rec, err := ReadRecord(dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.State != StateCompleted {
		t.Errorf("run.json State = %q, want %q", rec.State, StateCompleted)
	}
	if rec.StopReason == nil || *rec.StopReason != StopReasonAgentExit {
		t.Errorf("run.json StopReason = %v, want %q", rec.StopReason, StopReasonAgentExit)
	}
	if rec.ExitCode == nil || *rec.ExitCode != 0 {
		t.Errorf("run.json ExitCode = %v, want 0", rec.ExitCode)
	}
	if rec.StartedAt == nil {
		t.Errorf("run.json StartedAt = nil, want non-nil")
	}
	if rec.StoppedAt == nil {
		t.Errorf("run.json StoppedAt = nil, want non-nil")
	}
	if rec.RunID != dir.ID {
		t.Errorf("run.json RunID = %q, want %q", rec.RunID, dir.ID)
	}
	if rec.EnvName != "fix-tests" {
		t.Errorf("run.json EnvName = %q, want fix-tests", rec.EnvName)
	}
	if rec.Backend != "local-process" {
		t.Errorf("run.json Backend = %q, want local-process", rec.Backend)
	}
	if rec.Agent != "claude" {
		t.Errorf("run.json Agent = %q, want claude", rec.Agent)
	}
	if rec.ModelCredentialMode != ModelCredentialBackendManaged {
		t.Errorf("run.json ModelCredentialMode = %q, want %q", rec.ModelCredentialMode, ModelCredentialBackendManaged)
	}
}

// TestSupervisor_AgentNonZeroExitLandsFailedAgent confirms a child
// that exits with a non-zero code surfaces as StateFailedAgent rather
// than StateCompleted. The plan keeps "the agent exited cleanly" and
// "the agent crashed" on separate terminals; the supervisor must not
// gloss over the difference.
func TestSupervisor_AgentNonZeroExitLandsFailedAgent(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "fix-tests",
		Task:              "Fail on purpose",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 7"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       0,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateFailedAgent {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateFailedAgent)
	}
	if result.StopReason != StopReasonAgentFailure {
		t.Errorf("StopReason = %q, want %q", result.StopReason, StopReasonAgentFailure)
	}
	if !result.HasExitCode || result.ExitCode != 7 {
		t.Errorf("ExitCode = %d (has=%v), want 7", result.ExitCode, result.HasExitCode)
	}

	rec, err := ReadRecord(dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.State != StateFailedAgent {
		t.Errorf("run.json State = %q, want %q", rec.State, StateFailedAgent)
	}
	if rec.ExitCode == nil || *rec.ExitCode != 7 {
		t.Errorf("run.json ExitCode = %v, want 7", rec.ExitCode)
	}
}

// TestSupervisor_MaxRuntimeTimeout confirms a child that overstays
// its MaxRuntime budget is killed and lands on StateTimedOut. This is
// the explicit step-8 acceptance bullet ("Enforce max_runtime_minutes")
// and one of the plan's acceptance criteria (#4).
func TestSupervisor_MaxRuntimeTimeout(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "long-running",
		Task:              "Sleep forever",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("sleep 30"),
		MaxRuntime:        100 * time.Millisecond,
		IdleTimeout:       0,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	start := time.Now()
	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Run took %v; expected timeout to fire quickly", elapsed)
	}
	if result.FinalState != StateTimedOut {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateTimedOut)
	}
	if result.StopReason != StopReasonTimeout {
		t.Errorf("StopReason = %q, want %q", result.StopReason, StopReasonTimeout)
	}

	// Lifecycle.jsonl must include the timed_out terminal as the last
	// event so the audit log reflects what happened.
	states := readLifecycleStates(t, dir.Path)
	if len(states) == 0 || states[len(states)-1] != StateTimedOut {
		t.Errorf("lifecycle last state = %v, want last %q (full: %v)", states[len(states)-1], StateTimedOut, states)
	}

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
}

// TestSupervisor_CancelStopsRun pins the cancel-hook contract that
// step 9's signal handlers will wire into. Calling Cancel() while the
// child is running must produce a StateKilledByUser terminal and a
// clean shutdown.
func TestSupervisor_CancelStopsRun(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "cancel-me",
		Task:              "Sleep forever",
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

	// Kick off Cancel from a background goroutine shortly after Run
	// starts; the child sleeps for 30s so without a Cancel the test
	// would time out.
	done := make(chan struct {
		res SupervisorResult
		err error
	}, 1)
	go func() {
		res, err := sup.Run(context.Background())
		done <- struct {
			res SupervisorResult
			err error
		}{res, err}
	}()
	// Give the supervisor enough headroom to reach StateRunning so the
	// cancel path exercises the runLoop, not the setup-cancel branch.
	time.Sleep(100 * time.Millisecond)
	sup.Cancel()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Run: %v", got.err)
		}
		if got.res.FinalState != StateKilledByUser {
			t.Errorf("FinalState = %q, want %q", got.res.FinalState, StateKilledByUser)
		}
		if got.res.StopReason != StopReasonSignal {
			t.Errorf("StopReason = %q, want %q", got.res.StopReason, StopReasonSignal)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Cancel within 5s")
	}

	states := readLifecycleStates(t, dir.Path)
	if len(states) == 0 || states[len(states)-1] != StateKilledByUser {
		t.Errorf("lifecycle last state = %v, want last %q (full: %v)", states[len(states)-1], StateKilledByUser, states)
	}
}

// TestSupervisor_ContextCancelEqualsCancel confirms a caller-supplied
// context cancellation is treated the same as Cancel(). The plan does
// not require the two to be distinct (step 9 will hook OS signals into
// Cancel itself), but the context seam is convenient for callers and
// must not bypass the terminal-state contract.
func TestSupervisor_ContextCancelEqualsCancel(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "ctx-cancel",
		Task:              "Sleep forever",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("sleep 30"),
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan SupervisorResult, 1)
	go func() {
		res, err := sup.Run(ctx)
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- res
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case res := <-done:
		if res.FinalState != StateKilledByUser {
			t.Errorf("FinalState = %q, want %q", res.FinalState, StateKilledByUser)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel within 5s")
	}
}

// TestSupervisor_IdleTimeout confirms a child that produces no output
// for IdleTimeout is killed and lands on StateKilledIdle. This is the
// step-8 acceptance bullet "Detect idle timeout" and acceptance
// criterion #3 (hung agent stopped by idle timeout).
func TestSupervisor_IdleTimeout(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "idle",
		Task:              "Sleep forever without output",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("sleep 30"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       150 * time.Millisecond,
		StatsPollInterval: 30 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	start := time.Now()
	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Run took %v; expected idle timeout to fire quickly", elapsed)
	}
	if result.FinalState != StateKilledIdle {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateKilledIdle)
	}
	if result.StopReason != StopReasonIdle {
		t.Errorf("StopReason = %q, want %q", result.StopReason, StopReasonIdle)
	}
}

// TestSupervisor_LaunchFailureLandsFailedAgent confirms an unrunnable
// command surfaces as StateFailedAgent. A missing binary is the most
// common real-world way to hit this path; the supervisor must record
// the failure rather than crashing.
func TestSupervisor_LaunchFailureLandsFailedAgent(t *testing.T) {
	dir := newSupervisorRunDir(t)
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "no-binary",
		Task:              "Run a missing binary",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           CommandSpec{Program: "/does/not/exist/ai-env-test-binary"},
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateFailedAgent {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateFailedAgent)
	}
	if result.StopReason != StopReasonAgentFailure {
		t.Errorf("StopReason = %q, want %q", result.StopReason, StopReasonAgentFailure)
	}
	// Even on launch failure the lifecycle log must have the setup
	// stages plus the failed_agent terminal so the audit trail is
	// complete.
	states := readLifecycleStates(t, dir.Path)
	if len(states) == 0 || states[len(states)-1] != StateFailedAgent {
		t.Errorf("lifecycle last state = %v, want last %q (full: %v)", states[len(states)-1], StateFailedAgent, states)
	}
}

// TestSupervisor_SingleShot pins the contract that a single Supervisor
// runs at most once. The lifecycle writer and stream capture are
// closed after Run returns; a second Run would race on freed handles.
func TestSupervisor_SingleShot(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "single-shot",
		Task:              "Exit immediately",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if _, err := sup.Run(context.Background()); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if _, err := sup.Run(context.Background()); err == nil {
		t.Errorf("second Run: expected error, got nil")
	}
}

// TestSupervisor_CancelRaceIsSafe stress-checks the supervisor against
// many concurrent Cancel calls. cancelOnce must collapse them into a
// single close, the terminal cause must be deterministically
// StateKilledByUser, and no goroutine may panic.
func TestSupervisor_CancelRaceIsSafe(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "race",
		Task:              "Sleep forever",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("sleep 30"),
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	done := make(chan SupervisorResult, 1)
	go func() {
		res, _ := sup.Run(context.Background())
		done <- res
	}()
	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sup.Cancel()
		}()
	}
	wg.Wait()

	select {
	case res := <-done:
		if res.FinalState != StateKilledByUser {
			t.Errorf("FinalState = %q, want %q", res.FinalState, StateKilledByUser)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after concurrent Cancel within 5s")
	}
}

// TestSupervisor_RequiredOptions pins the constructor's input
// validation. Missing required fields must surface as errors so a
// misconfigured caller fails loudly.
func TestSupervisor_RequiredOptions(t *testing.T) {
	dir := newSupervisorRunDir(t)
	base := SupervisorOptions{
		RunDir:  dir.Path,
		RunID:   dir.ID,
		EnvName: "env",
		Backend: "local-process",
		Agent:   "claude",
		Task:    "do the thing",
		Command: shellCmd("true"),
	}
	// Each case strips one required field; NewSupervisor must reject
	// it. We mutate a copy so the base stays clean for the next case.
	cases := []struct {
		name string
		mut  func(o *SupervisorOptions)
	}{
		{"missing RunDir", func(o *SupervisorOptions) { o.RunDir = "" }},
		{"missing RunID", func(o *SupervisorOptions) { o.RunID = "" }},
		{"missing EnvName", func(o *SupervisorOptions) { o.EnvName = "" }},
		{"missing Backend", func(o *SupervisorOptions) { o.Backend = "" }},
		{"missing Agent", func(o *SupervisorOptions) { o.Agent = "" }},
		{"missing Task", func(o *SupervisorOptions) { o.Task = "" }},
		{"missing Program", func(o *SupervisorOptions) { o.Command = CommandSpec{} }},
		{"negative MaxRuntime", func(o *SupervisorOptions) { o.MaxRuntime = -1 }},
		{"negative IdleTimeout", func(o *SupervisorOptions) { o.IdleTimeout = -1 }},
		{"negative StatsPollInterval", func(o *SupervisorOptions) { o.StatsPollInterval = -1 }},
		{"negative StopGracePeriod", func(o *SupervisorOptions) { o.StopGracePeriod = -1 }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			opts := base
			c.mut(&opts)
			if _, err := NewSupervisor(opts); err == nil {
				t.Errorf("NewSupervisor: expected error for %s", c.name)
			} else if errors.Is(err, errStopBarrier) {
				// errStopBarrier is unused here; keep the import busy if
				// future refactors need it.
				t.Errorf("unexpected sentinel error: %v", err)
			}
		})
	}
}

// errStopBarrier is a stub kept only to ensure the errors import is
// always used in tests, even when conditional cases vanish. It is
// never returned by production code.
var errStopBarrier = errors.New("test sentinel")
