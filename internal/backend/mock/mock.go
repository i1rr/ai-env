// Package mock provides an in-memory no-op implementation of
// backend.Backend used by unit tests. It records every call so tests
// can assert on the supervisor's interaction with the backend without
// needing a real container runtime.
//
// The mock is goroutine-safe. Every public method takes the same
// internal mutex so concurrent calls from the supervisor's main loop
// and its kill/stats goroutines do not race on the recorded calls list
// or the in-memory env map.
package mock

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rivan1986/ai-env/internal/backend"
)

// Backend is the in-memory no-op backend. It satisfies backend.Backend
// and keeps a recorded log of every call so tests can assert on the
// supervisor's interaction with it.
//
// Zero value is usable: New is a convenience that also lets the caller
// override the clock.
type Backend struct {
	mu sync.Mutex

	// envs maps envID to the environment state the mock holds in
	// memory. Entries are added by Create and removed by Destroy.
	envs map[string]*envState

	// calls is the ordered log of method invocations. Each call is
	// recorded just after the method's argument validation so tests see
	// the same sequence the supervisor produced.
	calls []Call

	// status is the BackendStatus returned by Detect. Defaults to an
	// available, supported status; tests override it via SetStatus to
	// simulate unavailable or untested-version paths.
	status backend.BackendStatus

	// execResult is the result returned by Exec. Defaults to a clean
	// exit; tests override it via SetExecResult to drive
	// agent-failure paths.
	execResult backend.ExecResult

	// execErr is the error returned by Exec. Defaults to nil; tests
	// override it via SetExecError.
	execErr error

	// stats is the ResourceStats returned by Stats. Defaults to
	// Available=false (no stats endpoint) so callers exercising the
	// no-op path see the same shape the docker_sbx adapter will report
	// when its underlying stats endpoint is missing.
	stats backend.ResourceStats

	// nextEnvID generates synthetic env IDs as "env-1", "env-2", ...
	// so each Create produces a distinct ID even when the caller passes
	// the same EnvSpec.Name.
	nextEnvID int

	// now is the clock the mock uses for RuntimeInfo.StartedAt and
	// ResourceStats.CollectedAt. Defaults to time.Now when nil.
	now func() time.Time
}

// envState is the in-memory record of a created environment.
type envState struct {
	spec    backend.EnvSpec
	running bool
	info    backend.RuntimeInfo
}

// Call records one invocation of a Backend method. The Method field
// names the method; the other fields carry whichever arguments are
// relevant to that method. Unused fields are left at their zero value
// so tests can assert on a small subset.
type Call struct {
	Method  string
	EnvID   string
	Spec    backend.EnvSpec
	Command backend.Command
	ExecOpts backend.ExecOptions
	Signal  os.Signal
	Timeout time.Duration
	Src     string
	Dest    string
	Policy  backend.NetworkPolicy
}

// New returns a fresh mock with sensible defaults: Detect reports the
// backend as available and version-supported, Exec returns a clean
// zero exit, Stats reports Available=false. Pass nil for now to use
// time.Now; tests typically pass a fixed-step clock so timestamps are
// deterministic.
func New(now func() time.Time) *Backend {
	if now == nil {
		now = time.Now
	}
	return &Backend{
		envs: map[string]*envState{},
		status: backend.BackendStatus{
			Name:             "mock",
			Available:        true,
			Version:          "0.0.0",
			VersionSupported: true,
		},
		execResult: backend.ExecResult{ExitCode: 0, HasExitCode: true},
		stats:      backend.ResourceStats{Available: false},
		now:        now,
	}
}

// SetStatus overrides the BackendStatus returned by Detect.
func (b *Backend) SetStatus(s backend.BackendStatus) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.status = s
}

// SetExecResult overrides the ExecResult returned by Exec.
func (b *Backend) SetExecResult(r backend.ExecResult) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.execResult = r
}

// SetExecError overrides the error returned by Exec. A non-nil error
// causes Exec to return the zero ExecResult alongside err.
func (b *Backend) SetExecError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.execErr = err
}

// SetStats overrides the ResourceStats returned by Stats.
func (b *Backend) SetStats(s backend.ResourceStats) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stats = s
}

// Calls returns a snapshot of the recorded calls. The returned slice
// is a copy; mutating it does not affect the mock's internal log.
func (b *Backend) Calls() []Call {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Call, len(b.calls))
	copy(out, b.calls)
	return out
}

// Reset clears the recorded calls and the in-memory env map. The
// overridden status, exec result, stats, and error are preserved so a
// test fixture can call Reset between scenarios without re-applying
// the overrides.
func (b *Backend) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = nil
	b.envs = map[string]*envState{}
	b.nextEnvID = 0
}

// Detect implements backend.Backend.
func (b *Backend) Detect() backend.BackendStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "Detect"})
	return b.status
}

// Create implements backend.Backend. It assigns a synthetic envID and
// records the spec in memory.
func (b *Backend) Create(spec backend.EnvSpec) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextEnvID++
	envID := fmt.Sprintf("env-%d", b.nextEnvID)
	b.envs[envID] = &envState{spec: spec}
	b.calls = append(b.calls, Call{Method: "Create", EnvID: envID, Spec: spec})
	return envID, nil
}

// Start implements backend.Backend. It marks the env as running and
// returns a RuntimeInfo whose WorkspaceMount mirrors the spec's
// WorkspacePath.
func (b *Backend) Start(envID string) (backend.RuntimeInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "Start", EnvID: envID})
	env, ok := b.envs[envID]
	if !ok {
		return backend.RuntimeInfo{}, fmt.Errorf("mock backend: unknown envID %q", envID)
	}
	if !env.running {
		env.running = true
		env.info = backend.RuntimeInfo{
			EnvID:          envID,
			ContainerID:    "mock-" + envID,
			WorkspaceMount: env.spec.WorkspacePath,
			StartedAt:      b.now(),
		}
	}
	return env.info, nil
}

// Exec implements backend.Backend. It records the call and returns the
// configured ExecResult / error.
func (b *Backend) Exec(envID string, cmd backend.Command, opts backend.ExecOptions) (backend.ExecResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "Exec", EnvID: envID, Command: cmd, ExecOpts: opts})
	if _, ok := b.envs[envID]; !ok {
		return backend.ExecResult{}, fmt.Errorf("mock backend: unknown envID %q", envID)
	}
	if b.execErr != nil {
		return backend.ExecResult{}, b.execErr
	}
	return b.execResult, nil
}

// Stop implements backend.Backend. It marks the env as stopped.
func (b *Backend) Stop(envID string, signal os.Signal, timeout time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "Stop", EnvID: envID, Signal: signal, Timeout: timeout})
	env, ok := b.envs[envID]
	if !ok {
		return fmt.Errorf("mock backend: unknown envID %q", envID)
	}
	env.running = false
	return nil
}

// CopyIn implements backend.Backend.
func (b *Backend) CopyIn(envID, src, dest string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "CopyIn", EnvID: envID, Src: src, Dest: dest})
	if _, ok := b.envs[envID]; !ok {
		return fmt.Errorf("mock backend: unknown envID %q", envID)
	}
	return nil
}

// CopyOut implements backend.Backend.
func (b *Backend) CopyOut(envID, src, dest string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "CopyOut", EnvID: envID, Src: src, Dest: dest})
	if _, ok := b.envs[envID]; !ok {
		return fmt.Errorf("mock backend: unknown envID %q", envID)
	}
	return nil
}

// ApplyNetworkPolicy implements backend.Backend.
func (b *Backend) ApplyNetworkPolicy(envID string, policy backend.NetworkPolicy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "ApplyNetworkPolicy", EnvID: envID, Policy: policy})
	if _, ok := b.envs[envID]; !ok {
		return fmt.Errorf("mock backend: unknown envID %q", envID)
	}
	return nil
}

// Stats implements backend.Backend. It returns the configured snapshot
// and stamps CollectedAt with the mock's clock when Available is true.
func (b *Backend) Stats(envID string) (backend.ResourceStats, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "Stats", EnvID: envID})
	if _, ok := b.envs[envID]; !ok {
		return backend.ResourceStats{}, fmt.Errorf("mock backend: unknown envID %q", envID)
	}
	s := b.stats
	if s.Available && s.CollectedAt.IsZero() {
		s.CollectedAt = b.now()
	}
	return s, nil
}

// Destroy implements backend.Backend.
func (b *Backend) Destroy(envID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "Destroy", EnvID: envID})
	if _, ok := b.envs[envID]; !ok {
		return fmt.Errorf("mock backend: unknown envID %q", envID)
	}
	delete(b.envs, envID)
	return nil
}

// compile-time check that Backend satisfies backend.Backend.
var _ backend.Backend = (*Backend)(nil)
