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

	// gatewayIP is the value Backend.GatewayAddress returns. Empty
	// is the default (the mock has no bridge gateway concept); tests
	// override via SetGatewayAddress to drive the supervisor's
	// BridgeGateway ProviderProxy path.
	gatewayIP string

	// gatewayErr is the error Backend.GatewayAddress returns. nil is
	// the default; tests override via SetGatewayAddress to drive the
	// "gateway lookup failed" branch.
	gatewayErr error

	// mappedUIDs maps envID to the host-side UID Backend.MappedUID
	// returns for that env. Entries default to the in-sandbox UID
	// (EnvSpec.UID dereferenced, 0 when nil); tests override via
	// SetMappedUID to drive userns-remap paths.
	mappedUIDs map[string]int

	// mappedUIDErr is the error Backend.MappedUID returns. nil is
	// the default; tests override via SetMappedUIDError to drive
	// the "remap probe failed" branch.
	mappedUIDErr error

	// probeImageResult is the value Backend.ProbeImage returns.
	// Empty is the default (the mock cannot inspect image layers);
	// tests override via SetProbeImage to drive HomeTarget
	// resolution paths.
	probeImageResult string

	// probeImageErr is the error Backend.ProbeImage returns. nil is
	// the default; tests override via SetProbeImage to drive the
	// probe-failure branch.
	probeImageErr error

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
		mappedUIDs: map[string]int{},
		now:        now,
	}
}

// SetGatewayAddress overrides the (ip, err) tuple Backend.GatewayAddress
// returns for every env. Tests use it to drive the supervisor's
// ProviderProxy reachability picker through the BridgeGateway branch.
func (b *Backend) SetGatewayAddress(ip string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gatewayIP = ip
	b.gatewayErr = err
}

// SetMappedUID overrides the host-side UID Backend.MappedUID returns
// for envID. Tests use it to simulate userns-remap setups where the
// host-mapped UID differs from EnvSpec.UID.
func (b *Backend) SetMappedUID(envID string, hostUID int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.mappedUIDs == nil {
		b.mappedUIDs = map[string]int{}
	}
	b.mappedUIDs[envID] = hostUID
}

// SetMappedUIDError overrides the error Backend.MappedUID returns
// for every env. Tests use it to drive the supervisor's "remap
// probe failed" refuse-to-start branch.
func (b *Backend) SetMappedUIDError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mappedUIDErr = err
}

// SetProbeImage overrides the (homeTarget, err) tuple
// Backend.ProbeImage returns. Tests use it to drive the supervisor's
// HomeTarget resolution before Create.
func (b *Backend) SetProbeImage(homeTarget string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probeImageResult = homeTarget
	b.probeImageErr = err
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
	delete(b.mappedUIDs, envID)
	return nil
}

// GatewayAddress implements backend.Backend. The mock returns the
// (ip, err) tuple SetGatewayAddress configured, or ("", nil) when the
// test left the defaults alone (mirroring the behavior of backends
// that have no bridge gateway concept). An unknown envID returns an
// error even when gatewayErr is nil so the supervisor's
// "env not created" path is exercised.
func (b *Backend) GatewayAddress(envID string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "GatewayAddress", EnvID: envID})
	if _, ok := b.envs[envID]; !ok {
		return "", fmt.Errorf("mock backend: unknown envID %q", envID)
	}
	return b.gatewayIP, b.gatewayErr
}

// MappedUID implements backend.Backend. The mock returns the host-side
// UID SetMappedUID configured for envID, falling back to the
// EnvSpec.UID the env was created with (or 0 when EnvSpec.UID was
// nil). Setting mappedUIDErr via SetMappedUIDError overrides the
// successful path so tests can drive the supervisor's "remap probe
// failed" refuse-to-start branch.
func (b *Backend) MappedUID(envID string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "MappedUID", EnvID: envID})
	if _, ok := b.envs[envID]; !ok {
		return 0, fmt.Errorf("mock backend: unknown envID %q", envID)
	}
	if b.mappedUIDErr != nil {
		return 0, b.mappedUIDErr
	}
	if hostUID, ok := b.mappedUIDs[envID]; ok {
		return hostUID, nil
	}
	env := b.envs[envID]
	if env != nil && env.spec.UID != nil {
		return *env.spec.UID, nil
	}
	return 0, nil
}

// ProbeImage implements backend.Backend. The mock returns the
// (homeTarget, err) tuple SetProbeImage configured. When no override
// is set, the mock returns ("", nil) so the supervisor's HomeTarget
// resolver falls back to the documented "/root" default per
// Plan §0.5; tests that want to exercise the resolver explicitly
// call SetProbeImage with a non-empty path.
func (b *Backend) ProbeImage(template string, uid *int) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: "ProbeImage"})
	return b.probeImageResult, b.probeImageErr
}

// compile-time check that Backend satisfies backend.Backend.
var _ backend.Backend = (*Backend)(nil)
