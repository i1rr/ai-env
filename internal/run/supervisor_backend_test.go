package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/backend"
)

// stubBackend is a minimal backend.Backend used by the supervisor's
// backend-wiring tests. It is intentionally not the mock backend: we
// want to exercise Exec's stream wiring + Stop dispatch shape rather
// than the mock's call-recording helpers, which already have their own
// tests in their own package.
//
// The stub blocks Exec on stopCh so the test can drive the supervisor
// through the stop / kill paths the same way a real adapter would
// (Exec returns once Stop unwinds the child). For happy-path tests
// callers set Immediate=true so Exec returns straight away.
type stubBackend struct {
	mu sync.Mutex

	// Stdout / Stderr lines the adapter writes into the supervisor's
	// stream capture before Exec returns. Verifies that the
	// ExecOptions.Stdout / Stderr wiring reaches the stream files.
	stdout string
	stderr string

	// ExitCode is the code Exec returns. Defaults to 0.
	exitCode int

	// Immediate, when true, makes Exec return as soon as the writes
	// land. When false Exec blocks on stopCh until Stop is called.
	immediate bool

	// stopCh is closed by Stop; Exec selects on it when Immediate is
	// false.
	stopCh chan struct{}

	// stopCalls records the (sig, timeout) pairs Stop was invoked
	// with so the test can assert on the supervisor's stop sequence.
	stopCalls []stopCall

	// execErr, when non-nil, is returned by Exec instead of an
	// ExecResult. Used by the spawn-failure test.
	execErr error

	// readStdin, when true, causes Exec to drain the supplied stdin
	// into stdinSeen so the supervisor's stdin plumbing can be
	// asserted on.
	readStdin  bool
	stdinSeen  []byte
}

type stopCall struct {
	signal  os.Signal
	timeout time.Duration
}

func newStubBackend() *stubBackend {
	return &stubBackend{stopCh: make(chan struct{}), exitCode: 0}
}

func (b *stubBackend) Detect() backend.BackendStatus {
	return backend.BackendStatus{Name: "stub", Available: true, VersionSupported: true}
}

func (b *stubBackend) Create(spec backend.EnvSpec) (string, error) {
	return spec.Name, nil
}

func (b *stubBackend) Start(envID string) (backend.RuntimeInfo, error) {
	return backend.RuntimeInfo{EnvID: envID}, nil
}

func (b *stubBackend) Exec(envID string, cmd backend.Command, opts backend.ExecOptions) (backend.ExecResult, error) {
	if b.execErr != nil {
		return backend.ExecResult{}, b.execErr
	}
	if opts.Stdout != nil && b.stdout != "" {
		_, _ = opts.Stdout.Write([]byte(b.stdout))
	}
	if opts.Stderr != nil && b.stderr != "" {
		_, _ = opts.Stderr.Write([]byte(b.stderr))
	}
	if b.readStdin && opts.Stdin != nil {
		// Drain stdin so the supervisor's stdin wiring is verified.
		buf := make([]byte, 64)
		var seen []byte
		for {
			n, err := opts.Stdin.Read(buf)
			if n > 0 {
				seen = append(seen, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		b.mu.Lock()
		b.stdinSeen = seen
		b.mu.Unlock()
	}
	if !b.immediate {
		<-b.stopCh
	}
	return backend.ExecResult{ExitCode: b.exitCode, HasExitCode: true}, nil
}

func (b *stubBackend) Stop(envID string, sig os.Signal, timeout time.Duration) error {
	b.mu.Lock()
	b.stopCalls = append(b.stopCalls, stopCall{signal: sig, timeout: timeout})
	b.mu.Unlock()
	// First Stop wakes the Exec goroutine.
	select {
	case <-b.stopCh:
		// already closed
	default:
		close(b.stopCh)
	}
	return nil
}

func (b *stubBackend) CopyIn(envID, src, dest string) error                 { return nil }
func (b *stubBackend) CopyOut(envID, src, dest string) error                { return nil }
func (b *stubBackend) ApplyNetworkPolicy(envID string, p backend.NetworkPolicy) error { return nil }
func (b *stubBackend) Stats(envID string) (backend.ResourceStats, error) {
	return backend.ResourceStats{Available: false}, nil
}
func (b *stubBackend) Destroy(envID string) error { return nil }

func (b *stubBackend) StopCalls() []stopCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]stopCall, len(b.stopCalls))
	copy(out, b.stopCalls)
	return out
}

func (b *stubBackend) StdinSeen() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, len(b.stdinSeen))
	copy(out, b.stdinSeen)
	return out
}

// TestSupervisor_BackendHappyPath verifies that when SupervisorOptions
// carries a BackendAdapter + BackendEnvID, the supervisor routes the
// configured Command through Backend.Exec, the adapter's stdout /
// stderr writes land in the run directory's log files, and the
// resulting run.json snapshot records the chosen Backend identifier.
//
// This is the canonical proof for plan 04 step 8: the supervisor no
// longer hard-codes exec.Command for production runs; the adapter
// drives the agent process.
func TestSupervisor_BackendHappyPath(t *testing.T) {
	dir := newSupervisorRunDir(t)
	stub := newStubBackend()
	stub.immediate = true
	stub.stdout = "hello-from-backend\n"
	stub.stderr = "warn-from-backend\n"

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "fix-tests",
		Task:              "Fix the failing tests",
		Backend:           "stub",
		BackendAdapter:    stub,
		BackendEnvID:      "fix-tests",
		Agent:             "claude",
		Command:           CommandSpec{Program: "claude", Args: []string{"--autonomous"}, Dir: "/workspace"},
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
		t.Fatalf("FinalState = %q, want completed", result.FinalState)
	}
	if !result.HasExitCode || result.ExitCode != 0 {
		t.Fatalf("ExitCode = (%d, has=%v), want (0, true)", result.ExitCode, result.HasExitCode)
	}

	stdout, err := os.ReadFile(filepath.Join(dir.Path, "stdout.log"))
	if err != nil {
		t.Fatalf("read stdout.log: %v", err)
	}
	if !strings.Contains(string(stdout), "hello-from-backend") {
		t.Fatalf("stdout.log = %q, want backend stdout text", string(stdout))
	}
	stderr, err := os.ReadFile(filepath.Join(dir.Path, "stderr.log"))
	if err != nil {
		t.Fatalf("read stderr.log: %v", err)
	}
	if !strings.Contains(string(stderr), "warn-from-backend") {
		t.Fatalf("stderr.log = %q, want backend stderr text", string(stderr))
	}

	rec, err := ReadRecord(dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.Backend != "stub" {
		t.Fatalf("rec.Backend = %q, want stub", rec.Backend)
	}
}

// TestSupervisor_BackendCancelCallsStop verifies that when Cancel
// fires while Backend.Exec is in flight, the supervisor calls
// Backend.Stop on the adapter and the resulting terminal is
// StateKilledByUser. This proves the kill-path wiring matches the
// plan-03 host path, just routed through the adapter.
func TestSupervisor_BackendCancelCallsStop(t *testing.T) {
	dir := newSupervisorRunDir(t)
	stub := newStubBackend()
	// Default: Exec blocks on stopCh until Stop is invoked.

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "fix-tests",
		Task:              "Fix the failing tests",
		Backend:           "stub",
		BackendAdapter:    stub,
		BackendEnvID:      "fix-tests",
		Agent:             "claude",
		Command:           CommandSpec{Program: "claude"},
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	done := make(chan SupervisorResult, 1)
	go func() {
		result, err := sup.Run(context.Background())
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- result
	}()

	// Give the supervisor enough time to reach StateRunning, then
	// trigger Cancel.
	time.Sleep(50 * time.Millisecond)
	sup.Cancel()

	select {
	case result := <-done:
		if result.FinalState != StateKilledByUser {
			t.Fatalf("FinalState = %q, want killed_by_user", result.FinalState)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not terminate after Cancel")
	}

	calls := stub.StopCalls()
	if len(calls) == 0 {
		t.Fatal("Backend.Stop was never called after Cancel")
	}
}

// TestSupervisor_BackendStdinForwarded verifies that
// SupervisorOptions.Stdin is piped into Backend.Exec's ExecOptions.Stdin
// so the agent launcher's "task body on stdin" contract works
// end-to-end with the backend seam.
func TestSupervisor_BackendStdinForwarded(t *testing.T) {
	dir := newSupervisorRunDir(t)
	stub := newStubBackend()
	stub.immediate = true
	stub.readStdin = true

	body := "Fix the failing tests please.\n"

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "fix-tests",
		Task:              "Fix the failing tests",
		Backend:           "stub",
		BackendAdapter:    stub,
		BackendEnvID:      "fix-tests",
		Agent:             "claude",
		Command:           CommandSpec{Program: "claude"},
		Stdin:             strings.NewReader(body),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	if _, err := sup.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := string(stub.StdinSeen())
	if got != body {
		t.Fatalf("stub stdin = %q, want %q", got, body)
	}
}

// TestSupervisor_BackendExecErrIsFailedAgent verifies that a spawn-side
// error from Backend.Exec (the adapter could not launch the child at
// all) lands the run in StateFailedAgent rather than masking the
// failure as a clean completion. This is the equivalent of the
// host-path "binary missing" terminal.
func TestSupervisor_BackendExecErrIsFailedAgent(t *testing.T) {
	dir := newSupervisorRunDir(t)
	stub := newStubBackend()
	stub.execErr = errors.New("simulated spawn failure")

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "fix-tests",
		Task:              "Fix the failing tests",
		Backend:           "stub",
		BackendAdapter:    stub,
		BackendEnvID:      "fix-tests",
		Agent:             "claude",
		Command:           CommandSpec{Program: "claude"},
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
	if result.FinalState != StateFailedAgent {
		t.Fatalf("FinalState = %q, want failed_agent", result.FinalState)
	}
}

// TestNewSupervisor_BackendEnvIDRequired verifies the construction
// guard: a Backend without an envID would crash inside the adapter at
// Exec time, so NewSupervisor refuses up front.
func TestNewSupervisor_BackendEnvIDRequired(t *testing.T) {
	dir := newSupervisorRunDir(t)
	stub := newStubBackend()
	_, err := NewSupervisor(SupervisorOptions{
		RunDir:         dir.Path,
		RunID:          dir.ID,
		EnvName:        "fix-tests",
		Task:           "Fix the failing tests",
		Backend:        "stub",
		BackendAdapter: stub,
		Agent:          "claude",
		Command:        CommandSpec{Program: "claude"},
	})
	if err == nil {
		t.Fatal("NewSupervisor with BackendAdapter and no BackendEnvID should error")
	}
	if !strings.Contains(err.Error(), "BackendEnvID") {
		t.Fatalf("error = %q, want BackendEnvID mention", err.Error())
	}
}

// compile-time check that we did not accidentally break the discard
// io.Discard surface the supervisor uses internally; also keeps the
// bytes / io imports load-bearing in case a future test trims the
// other usages.
var (
	_ io.Writer    = (*bytes.Buffer)(nil)
	_              = fmt.Sprintf
)
