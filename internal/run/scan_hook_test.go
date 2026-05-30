package run

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestSupervisor_ScanHookRunsBetweenStoppingAndReporting pins plan 06
// step 9: the scan hook fires during StateScanning, after the agent
// has stopped and before the run advances to StateReporting. The hook
// receives the run directory so it can drop secret-scan.json /
// dependency-report.json where the export gate will read them.
func TestSupervisor_ScanHookRunsBetweenStoppingAndReporting(t *testing.T) {
	skipIfNoSh(t)
	fx := newRunFinalizeFixture(t)

	var hookCalls int32
	var observedDir string
	var observedState State

	machineSnapshot := func() State { return "" } // populated below

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            fx.dir.Path,
		RunID:             fx.dir.ID,
		EnvName:           fx.envName,
		Task:              "Verify scan hook lifecycle wiring",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		ScanHook: func(ctx context.Context, runDir string) error {
			atomic.AddInt32(&hookCalls, 1)
			observedDir = runDir
			observedState = machineSnapshot()
			// Drop a minimal artifact at the path ExportGate reads so
			// downstream wiring can observe the hook actually wrote
			// something during StateScanning.
			return os.WriteFile(SecretScanPath(runDir), []byte("{}"), 0o644)
		},
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	machineSnapshot = func() State { return sup.machine.Current() }

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Fatalf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}
	if got := atomic.LoadInt32(&hookCalls); got != 1 {
		t.Fatalf("hook calls = %d, want 1", got)
	}
	if observedDir != fx.dir.Path {
		t.Errorf("hook runDir = %q, want %q", observedDir, fx.dir.Path)
	}
	if observedState != StateScanning {
		t.Errorf("hook saw state = %q, want %q", observedState, StateScanning)
	}

	// secret-scan.json must exist at the canonical path so the export
	// gate can read it without re-deriving the layout.
	if _, err := os.Stat(SecretScanPath(fx.dir.Path)); err != nil {
		t.Errorf("secret-scan.json missing: %v", err)
	}

	states := readLifecycleStates(t, fx.dir.Path)
	want := []State{
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
	if len(states) != len(want) {
		t.Fatalf("lifecycle states = %v, want %v", states, want)
	}
	for i, w := range want {
		if states[i] != w {
			t.Errorf("state[%d] = %q, want %q", i, states[i], w)
		}
	}
}

// TestSupervisor_ScanHookErrorLandsOnFailedScan verifies that a non-nil
// error from the scan hook lands the run in StateFailedScan with
// StopReasonScanFailure, and that the supervisor does NOT continue into
// StateReporting / StateCompleted. Plan 06 step 9 treats a scan-
// infrastructure failure as terminal: the operator must see the
// failure rather than a misleading "completed" record.
func TestSupervisor_ScanHookErrorLandsOnFailedScan(t *testing.T) {
	skipIfNoSh(t)
	fx := newRunFinalizeFixture(t)

	sentinel := errors.New("scanner broke")
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            fx.dir.Path,
		RunID:             fx.dir.ID,
		EnvName:           fx.envName,
		Task:              "Verify scan hook failure path",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		ScanHook: func(ctx context.Context, runDir string) error {
			return sentinel
		},
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateFailedScan {
		t.Fatalf("FinalState = %q, want %q", result.FinalState, StateFailedScan)
	}
	if result.StopReason != StopReasonScanFailure {
		t.Errorf("StopReason = %q, want %q", result.StopReason, StopReasonScanFailure)
	}

	rec, err := ReadRecord(fx.dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.State != StateFailedScan {
		t.Errorf("run.json State = %q, want %q", rec.State, StateFailedScan)
	}
	if rec.StopReason == nil || *rec.StopReason != StopReasonScanFailure {
		t.Errorf("run.json StopReason = %v, want %q", rec.StopReason, StopReasonScanFailure)
	}

	states := readLifecycleStates(t, fx.dir.Path)
	// Walk must reach StateScanning then divert directly to
	// StateFailedScan; StateReporting / StateCompleted must NOT appear.
	wantPrefix := []State{
		StatePreparingWorkspace,
		StateStartingBackend,
		StateApplyingPolicy,
		StateStartingAgent,
		StateRunning,
		StateStopping,
		StateScanning,
		StateFailedScan,
	}
	if len(states) != len(wantPrefix) {
		t.Fatalf("lifecycle states = %v, want %v", states, wantPrefix)
	}
	for i, w := range wantPrefix {
		if states[i] != w {
			t.Errorf("state[%d] = %q, want %q", i, states[i], w)
		}
	}
	for _, s := range states {
		if s == StateReporting || s == StateCompleted {
			t.Errorf("unexpected state in lifecycle after scan failure: %q", s)
		}
	}
}

// TestSupervisor_ScanHookNilSkipsCleanly verifies that the supervisor's
// legacy plan-03 behavior is preserved when no ScanHook is configured:
// StateScanning remains a lifecycle stamp only and the run completes
// cleanly without writing any scan artifacts.
func TestSupervisor_ScanHookNilSkipsCleanly(t *testing.T) {
	skipIfNoSh(t)
	fx := newRunFinalizeFixture(t)

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            fx.dir.Path,
		RunID:             fx.dir.ID,
		EnvName:           fx.envName,
		Task:              "Verify nil scan hook preserves legacy behavior",
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

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Fatalf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}

	// CreateRunDirectory pre-materializes the secret-scan.json placeholder
	// (see runFileNames in run.go); when no ScanHook is configured the
	// supervisor must leave the placeholder empty rather than fabricating
	// content. The placeholder being zero bytes is the operator-visible
	// proof that no scan ran.
	info, err := os.Stat(filepath.Join(fx.dir.Path, "secret-scan.json"))
	if err != nil {
		t.Fatalf("stat secret-scan.json: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("secret-scan.json size = %d, want 0 (placeholder)", info.Size())
	}
}
