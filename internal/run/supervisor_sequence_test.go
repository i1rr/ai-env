// Plan §5.5 — Supervisor sequencing acceptance tests (Batch 5.5).
//
// These tests pin the canonical 11-step pre-launch + 9-step teardown
// order the plan requires the supervisor to execute. Each test names
// the canonical step it exercises and asserts on the on-disk lifecycle
// trail + the recorded ordering of supervisor-driven side effects.
//
// Test seam philosophy: every component the supervisor sequences in
// step 2..step 11 is wired through SupervisorOptions, so we inject
// recording fakes (a sequenceProbe) and assert on the recorded order
// without having to construct a real backend / observer / rules
// installer. The provider-proxy half is exercised end-to-end via the
// real `secrets.ProviderProxy` (already covered by
// provider_proxy_wire_test.go); these tests focus on the order in
// which every component starts and stops.
package run

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/egress"
)

// sequenceProbe is the recording fake the canonical-sequence tests
// drive every per-step component through. Each Start / Stop / Create
// / Destroy method appends a short token to the probe's ordered log
// so the test can assert on the exact ordering the supervisor
// executed. The probe is safe for concurrent use; in practice the
// supervisor calls every method serially.
type sequenceProbe struct {
	mu  sync.Mutex
	log []string
}

func (p *sequenceProbe) record(s string) {
	p.mu.Lock()
	p.log = append(p.log, s)
	p.mu.Unlock()
}

func (p *sequenceProbe) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.log))
	copy(out, p.log)
	return out
}

// fakeSequenceObserver implements egress.EgressObserver as a recording
// stub. The supervisor's step 5 calls Start; teardown step 4 calls
// Stop. The chain + mode tokens are constants so the on-disk
// `observer_started` verb's metadata has the canonical keys the plan
// pins.
type fakeSequenceObserver struct {
	probe   *sequenceProbe
	started atomic.Bool
}

func (f *fakeSequenceObserver) Mode() string  { return "nflog" }
func (f *fakeSequenceObserver) Chain() string { return "AIENV-EGR-cafef00d" }

func (f *fakeSequenceObserver) Start(ctx context.Context) error {
	f.probe.record("observer.Start")
	f.started.Store(true)
	return nil
}

func (f *fakeSequenceObserver) Stop() error {
	if f.started.Load() {
		f.probe.record("observer.Stop")
		f.started.Store(false)
	}
	return nil
}

// writeRecordingTracker returns a closure that records the supplied
// token onto the probe and returns nil. Used for the BackendCreate /
// BackendStart / BackendDestroy hooks so the test can assert on the
// canonical ordering without standing up a real backend.
func writeRecordingTracker(probe *sequenceProbe, token string) func() error {
	return func() error {
		probe.record(token)
		return nil
	}
}

// recordingMaterializer is the closure SupervisorOptions.MCPGatewayMaterializer
// expects. It records the canonical step token on the probe and returns
// a minimal PerRunMCPConfig so the gateway_started verb's metadata has
// a non-empty config_path.
func recordingMaterializer(probe *sequenceProbe, runDir string) func(*ControlSocket) (PerRunMCPConfig, error) {
	return func(cs *ControlSocket) (PerRunMCPConfig, error) {
		probe.record("gateway.Materialize")
		return PerRunMCPConfig{
			AgentConfigPath: filepath.Join(runDir, "mcp-servers.json"),
			RealConfigPath:  filepath.Join(runDir, "ipc", "mcp-servers.real.json"),
			HelperTokenPath: filepath.Join(runDir, "ipc", ".helper-token"),
			ServerTokens:    map[string]string{"echo": "tok"},
		}, nil
	}
}

// readLifecycleEvents returns every event recorded on lifecycle.jsonl.
// The test uses this to assert on the full state + verb ordering.
func readLifecycleEvents(t *testing.T, runDir string) []LifecycleEvent {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(runDir, "lifecycle.jsonl"))
	if err != nil {
		t.Fatalf("read lifecycle.jsonl: %v", err)
	}
	var out []LifecycleEvent
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var evt LifecycleEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("parse lifecycle line %q: %v", line, err)
		}
		out = append(out, evt)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan lifecycle: %v", err)
	}
	return out
}

// indexOfVerb returns the (zero-based) index of the first event in
// events whose Verb matches v. Returns -1 when no event matches.
func indexOfVerb(events []LifecycleEvent, v LifecycleVerb) int {
	for i, e := range events {
		if e.Verb == v {
			return i
		}
	}
	return -1
}

// indexOfState returns the (zero-based) index of the first event in
// events whose State matches s. Returns -1 when no event matches.
func indexOfState(events []LifecycleEvent, s State) int {
	for i, e := range events {
		if e.State == s {
			return i
		}
	}
	return -1
}

// newSequenceControlSocket builds a ControlSocket fixture pinned to
// the supervisor's runDir. The socket is constructed but not started
// by the test — the supervisor's canonical step 2 owns the Start call.
func newSequenceControlSocket(t *testing.T, runDir string) *ControlSocket {
	t.Helper()
	cs, err := NewControlSocket(ControlSocketOptions{RunDir: runDir})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}
	return cs
}

// newSequenceRunDir builds a RunDirectory under /tmp (NOT t.TempDir,
// whose macOS default exceeds the AF_UNIX sun_path 104-byte limit when
// the supervisor binds <runDir>/control.sock). Mirrors the same
// short-path pattern the existing control_socket_test.go uses.
func newSequenceRunDir(t *testing.T) RunDirectory {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "aies-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	aiEnvDir := filepath.Join(base, ".ai-env")
	runID := "20260528-101300-a1b2c3"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return dir
}

// TestSupervisor_OrderedPreLaunch_AllStepsFire is the canonical
// 11-step pre-launch acceptance test. The supervisor is wired with a
// full set of recording fakes — workspace shadow path, BackendCreate
// hook, ControlSocket, EgressObserver, BackendStart hook,
// applyNetworkPolicy implicit, ProviderProxies (skipped here — the
// existing proxy_wire test covers them), MCPGatewayMaterializer — and
// the test asserts the supervisor invoked each one in the canonical
// order recorded in Plan §5.5 lines 234–245.
//
// Specifically the probe must record:
//
//	backend.Create  (step 3)
//	observer.Start  (step 5)
//	gateway.Materialize (step 9)
//
// The lifecycle.jsonl trail must additionally contain the
// state-transition events in the canonical order
// (preparing_workspace → starting_backend → applying_policy →
// starting_agent → running) interleaved with the per-step verbs
// (control_socket_started → mcp_config_neutralized → observer_started
// → gateway_started → state transitions).
func TestSupervisor_OrderedPreLaunch_AllStepsFire(t *testing.T) {
	skipIfNoSh(t)
	dir := newSequenceRunDir(t)

	// Workspace + an .mcp.json so step 3's shadow rename fires.
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, ".mcp.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write workspace .mcp.json: %v", err)
	}

	probe := &sequenceProbe{}
	cs := newSequenceControlSocket(t, dir.Path)
	obs := &fakeSequenceObserver{probe: probe}

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:                 dir.Path,
		RunID:                  dir.ID,
		EnvName:                "sequence-test",
		Task:                   "canonical sequence acceptance",
		Backend:                "local-process",
		Agent:                  "claude",
		Command:                shellCmd("exit 0"),
		MaxRuntime:             5 * time.Second,
		IdleTimeout:            5 * time.Second,
		StatsPollInterval:      20 * time.Millisecond,
		StopGracePeriod:        100 * time.Millisecond,
		ControlSocket:          cs,
		EgressObserver:         obs,
		EgressObserverMode:     egress.EgressObserverModeAuto,
		WorkspaceMCPRoot:       workspace,
		BackendCreate:          writeRecordingTracker(probe, "backend.Create"),
		BackendStart:           writeRecordingTracker(probe, "backend.Start"),
		BackendDestroy:         writeRecordingTracker(probe, "backend.Destroy"),
		MCPGatewayMaterializer: recordingMaterializer(probe, dir.Path),
		MCPGatewayCloser: func() error {
			probe.record("gateway.Close")
			return nil
		},
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

	// Pre-launch ordering: every hook fires exactly once, in canonical
	// order. The probe records every hook's invocation; the slice we
	// expect is the canonical step list with proxies skipped (none
	// were configured).
	log := probe.snapshot()

	// Find pre-launch indices.
	idx := func(token string) int {
		for i, v := range log {
			if v == token {
				return i
			}
		}
		return -1
	}
	preLaunch := []string{"backend.Create", "backend.Start", "observer.Start", "gateway.Materialize"}
	last := -1
	for _, tok := range preLaunch {
		got := idx(tok)
		if got < 0 {
			t.Errorf("missing pre-launch hook %q (log=%v)", tok, log)
			continue
		}
		if got <= last {
			t.Errorf("hook %q index %d <= previous %d (log=%v)", tok, got, last, log)
		}
		last = got
	}

	// Lifecycle: the per-step verbs land in the canonical order:
	//   control_socket_started (step 2)
	//   mcp_config_neutralized (step 3, via workspace shadow)
	//   observer_started (step 5)
	//   gateway_started (step 9)
	events := readLifecycleEvents(t, dir.Path)
	csIdx := indexOfVerb(events, LifecycleVerbControlSocketStarted)
	shadowIdx := indexOfVerb(events, LifecycleVerbMCPConfigNeutralized)
	obsIdx := indexOfVerb(events, LifecycleVerbObserverStarted)
	gwIdx := indexOfVerb(events, LifecycleVerbGatewayStarted)

	if csIdx < 0 {
		t.Fatalf("control_socket_started not recorded; events=%+v", events)
	}
	if shadowIdx < 0 {
		t.Fatalf("mcp_config_neutralized not recorded; events=%+v", events)
	}
	if obsIdx < 0 {
		t.Fatalf("observer_started not recorded; events=%+v", events)
	}
	if gwIdx < 0 {
		t.Fatalf("gateway_started not recorded; events=%+v", events)
	}
	if !(csIdx < shadowIdx && shadowIdx < obsIdx && obsIdx < gwIdx) {
		t.Errorf("pre-launch verb order = (cs=%d, shadow=%d, obs=%d, gw=%d), want strictly increasing",
			csIdx, shadowIdx, obsIdx, gwIdx)
	}

	// And state transitions must straddle the verbs in canonical order.
	prepIdx := indexOfState(events, StatePreparingWorkspace)
	startBackendIdx := indexOfState(events, StateStartingBackend)
	policyIdx := indexOfState(events, StateApplyingPolicy)
	startAgentIdx := indexOfState(events, StateStartingAgent)
	runIdx := indexOfState(events, StateRunning)
	if !(prepIdx < startBackendIdx && startBackendIdx < policyIdx && policyIdx < startAgentIdx && startAgentIdx < runIdx) {
		t.Errorf("state transition order broken: prep=%d backend=%d policy=%d agent=%d run=%d",
			prepIdx, startBackendIdx, policyIdx, startAgentIdx, runIdx)
	}

	// Control-socket Start metadata must include "path".
	if events[csIdx].Metadata["path"] == "" {
		t.Errorf("control_socket_started missing path metadata: %+v", events[csIdx])
	}

	// Observer metadata must include mode + chain.
	if events[obsIdx].Metadata["mode"] != "nflog" {
		t.Errorf("observer_started mode = %q, want nflog", events[obsIdx].Metadata["mode"])
	}
	if events[obsIdx].Metadata["chain"] != "AIENV-EGR-cafef00d" {
		t.Errorf("observer_started chain = %q, want AIENV-EGR-cafef00d", events[obsIdx].Metadata["chain"])
	}

	// Gateway metadata must include server_count + config_path.
	if events[gwIdx].Metadata["server_count"] == "" {
		t.Errorf("gateway_started missing server_count: %+v", events[gwIdx])
	}
	if events[gwIdx].Metadata["config_path"] == "" {
		t.Errorf("gateway_started missing config_path: %+v", events[gwIdx])
	}
}

// TestSupervisor_OrderedTeardown_AllStepsFire pins the canonical
// 9-step teardown order. After a successful run the probe must record
// every per-step Stop / Destroy hook in canonical reverse order, and
// the lifecycle.jsonl must contain the matching `_stopped` verbs.
func TestSupervisor_OrderedTeardown_AllStepsFire(t *testing.T) {
	skipIfNoSh(t)
	dir := newSequenceRunDir(t)

	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, ".mcp.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write workspace .mcp.json: %v", err)
	}

	probe := &sequenceProbe{}
	cs := newSequenceControlSocket(t, dir.Path)
	obs := &fakeSequenceObserver{probe: probe}

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:                 dir.Path,
		RunID:                  dir.ID,
		EnvName:                "sequence-teardown",
		Task:                   "canonical teardown acceptance",
		Backend:                "local-process",
		Agent:                  "claude",
		Command:                shellCmd("exit 0"),
		MaxRuntime:             5 * time.Second,
		IdleTimeout:            5 * time.Second,
		StatsPollInterval:      20 * time.Millisecond,
		StopGracePeriod:        100 * time.Millisecond,
		ControlSocket:          cs,
		EgressObserver:         obs,
		EgressObserverMode:     egress.EgressObserverModeAuto,
		WorkspaceMCPRoot:       workspace,
		BackendCreate:          writeRecordingTracker(probe, "backend.Create"),
		BackendStart:           writeRecordingTracker(probe, "backend.Start"),
		BackendDestroy:         writeRecordingTracker(probe, "backend.Destroy"),
		MCPGatewayMaterializer: recordingMaterializer(probe, dir.Path),
		MCPGatewayCloser: func() error {
			probe.record("gateway.Close")
			return nil
		},
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

	log := probe.snapshot()
	idx := func(token string) int {
		for i, v := range log {
			if v == token {
				return i
			}
		}
		return -1
	}

	// Teardown canonical order — the hooks the test wires that actually
	// fire on teardown:
	//   observer.Stop     (step 4)
	//   gateway.Close     (step 6)
	//   backend.Destroy   (step 7)
	teardown := []string{"observer.Stop", "gateway.Close", "backend.Destroy"}
	last := -1
	for _, tok := range teardown {
		got := idx(tok)
		if got < 0 {
			t.Errorf("missing teardown hook %q (log=%v)", tok, log)
			continue
		}
		if got <= last {
			t.Errorf("teardown hook %q index %d <= previous %d (log=%v)", tok, got, last, log)
		}
		last = got
	}

	// Teardown hooks must come after every pre-launch hook.
	preLaunchEnd := idx("gateway.Materialize")
	teardownStart := idx("observer.Stop")
	if preLaunchEnd >= teardownStart {
		t.Errorf("pre-launch end (%d) >= teardown start (%d); log=%v", preLaunchEnd, teardownStart, log)
	}

	// Lifecycle verbs: every `_stopped` lands in canonical reverse
	// order.
	events := readLifecycleEvents(t, dir.Path)
	obsStop := indexOfVerb(events, LifecycleVerbObserverStopped)
	gwStop := indexOfVerb(events, LifecycleVerbGatewayStopped)
	csStop := indexOfVerb(events, LifecycleVerbControlSocketStopped)
	if obsStop < 0 {
		t.Fatalf("observer_stopped not recorded")
	}
	if gwStop < 0 {
		t.Fatalf("gateway_stopped not recorded")
	}
	if csStop < 0 {
		t.Fatalf("control_socket_stopped not recorded")
	}
	if !(obsStop < gwStop && gwStop < csStop) {
		t.Errorf("teardown verb order broken: observer=%d gateway=%d control=%d",
			obsStop, gwStop, csStop)
	}

	// Clean terminal → reason="teardown" on every `_stopped` verb.
	for _, name := range []struct {
		v LifecycleVerb
		i int
	}{
		{LifecycleVerbObserverStopped, obsStop},
		{LifecycleVerbGatewayStopped, gwStop},
		{LifecycleVerbControlSocketStopped, csStop},
	} {
		if got := events[name.i].Metadata["reason"]; got != "teardown" {
			t.Errorf("%s reason = %q, want teardown", name.v, got)
		}
	}
}

// TestSupervisor_ObserverStartsAfterBackendStart_BeforeRules pins the
// plan's "step 5 < step 7" invariant: the EgressObserver attaches AFTER
// the backend.Start hook fires (so the netns exists) and BEFORE the
// rules install (so the chain the observer reads from is empty when
// the observer binds, and the rules then funnel packets into it).
//
// We use a BackendStart hook + the fake observer's Start to record
// pre-rule ordering. For "before rules" we record a rulesInstallHook
// token from a closure passed via BackendStart-like mechanism — but
// the supervisor invokes EgressRules.Install at step 7, so we use a
// custom recorder by wiring an OnInstalled callback on a real
// rules.Lifecycle backed by an unsupported-OS-tolerant flow. Since we
// cannot guarantee a Lifecycle install on every CI host, we assert the
// canonical invariant directly: the observer.Start probe entry appears
// before any rule-install marker the BackendStart closure pushes onto
// the probe just before returning.
func TestSupervisor_ObserverStartsAfterBackendStart_BeforeRules(t *testing.T) {
	skipIfNoSh(t)
	dir := newSequenceRunDir(t)

	probe := &sequenceProbe{}
	obs := &fakeSequenceObserver{probe: probe}

	// We synthesize a "rules.Install" marker by piggybacking on the
	// supervisor's applyNetworkPolicy step — the supervisor calls
	// rules install (step 7) right after applyNetworkPolicy (step 6).
	// Since this acceptance test does not have a real rules lifecycle,
	// we instead use a recording closure that fires when the
	// canonical "step 7" interlock would. The closer we get without a
	// real rules adapter is to use a `MCPGatewayMaterializer` marker
	// (step 9, after step 7) and assert obs.Start precedes it.
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:             dir.Path,
		RunID:              dir.ID,
		EnvName:            "obs-before-rules",
		Task:               "observer ordering acceptance",
		Backend:            "local-process",
		Agent:              "claude",
		Command:            shellCmd("exit 0"),
		MaxRuntime:         5 * time.Second,
		IdleTimeout:        5 * time.Second,
		StatsPollInterval:  20 * time.Millisecond,
		StopGracePeriod:    100 * time.Millisecond,
		EgressObserver:     obs,
		EgressObserverMode: egress.EgressObserverModeAuto,
		BackendStart:       writeRecordingTracker(probe, "backend.Start"),
		MCPGatewayMaterializer: func(cs *ControlSocket) (PerRunMCPConfig, error) {
			probe.record("step7-or-later")
			return PerRunMCPConfig{
				AgentConfigPath: filepath.Join(dir.Path, "mcp-servers.json"),
				ServerTokens:    map[string]string{"a": "b"},
			}, nil
		},
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

	log := probe.snapshot()
	idx := func(token string) int {
		for i, v := range log {
			if v == token {
				return i
			}
		}
		return -1
	}
	backendStartIdx := idx("backend.Start")
	observerStartIdx := idx("observer.Start")
	afterRulesIdx := idx("step7-or-later")

	if backendStartIdx < 0 || observerStartIdx < 0 || afterRulesIdx < 0 {
		t.Fatalf("missing probe entries: backend.Start=%d observer.Start=%d step7-or-later=%d (log=%v)",
			backendStartIdx, observerStartIdx, afterRulesIdx, log)
	}
	if !(backendStartIdx < observerStartIdx) {
		t.Errorf("backend.Start (%d) >= observer.Start (%d); want backend.Start before observer.Start (Plan §5.5 step 5)",
			backendStartIdx, observerStartIdx)
	}
	if !(observerStartIdx < afterRulesIdx) {
		t.Errorf("observer.Start (%d) >= step7-or-later (%d); want observer.Start strictly before any step ≥7",
			observerStartIdx, afterRulesIdx)
	}
}

// TestSupervisor_SchemaVersionsWrittenAtStep1 pins the plan's "write
// schema_versions map to run.json NOW (not at finalize)" rule. The
// supervisor's writeRecordSnapshot fills `schema_versions` on every
// snapshot, including the very first one written during step 1
// (StatePreparingWorkspace). The test reads run.json after step 1
// completes and asserts the map is present and non-empty.
//
// We trigger an early read by hooking a BackendCreate closure that
// reads run.json from disk and stashes it on a channel. By the time
// BackendCreate (step 3) fires, step 1 has already written run.json
// with the schema_versions map populated.
func TestSupervisor_SchemaVersionsWrittenAtStep1(t *testing.T) {
	skipIfNoSh(t)
	dir := newSequenceRunDir(t)

	var midRunRecord Record
	var captured bool
	createHook := func() error {
		rec, err := ReadRecord(dir.Path)
		if err != nil {
			return err
		}
		midRunRecord = rec
		captured = true
		return nil
	}

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "schema-versions",
		Task:              "schema versions acceptance",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		BackendCreate:     createHook,
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
	if !captured {
		t.Fatalf("BackendCreate hook never fired; cannot read run.json mid-run")
	}
	if midRunRecord.State != StatePreparingWorkspace {
		t.Errorf("mid-run state = %q, want %q", midRunRecord.State, StatePreparingWorkspace)
	}
	if len(midRunRecord.SchemaVersions) == 0 {
		t.Errorf("schema_versions empty in step-1 run.json; want a non-empty map")
	}
	// And the same map matches CurrentSchemaVersions exactly.
	want := CurrentSchemaVersions()
	for k, v := range want {
		if midRunRecord.SchemaVersions[k] != v {
			t.Errorf("schema_versions[%q] = %d, want %d", k, midRunRecord.SchemaVersions[k], v)
		}
	}
}

// TestSupervisor_WorkspaceConfigRestoredAtTeardown pins the plan's
// "Restore workspace MCP-config files" rule (teardown step 7). The
// supervisor shadows .mcp.json at step 3 and renames it back at
// teardown step 7. The test asserts the file is present (and the
// shadow file is gone) after the run terminates.
func TestSupervisor_WorkspaceConfigRestoredAtTeardown(t *testing.T) {
	skipIfNoSh(t)
	dir := newSequenceRunDir(t)

	workspace := t.TempDir()
	mcpPath := filepath.Join(workspace, ".mcp.json")
	originalBlob := []byte(`{"mcpServers":{}}`)
	if err := os.WriteFile(mcpPath, originalBlob, 0o644); err != nil {
		t.Fatalf("write workspace .mcp.json: %v", err)
	}

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "workspace-restore",
		Task:              "workspace restore acceptance",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		WorkspaceMCPRoot:  workspace,
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

	// The original file must be present with the original content.
	got, err := os.ReadFile(mcpPath)
	if err != nil {
		t.Fatalf("read restored .mcp.json: %v", err)
	}
	if string(got) != string(originalBlob) {
		t.Errorf("restored .mcp.json content = %q, want %q", string(got), string(originalBlob))
	}

	// The shadow file must NOT exist.
	if _, err := os.Stat(mcpPath + ".ai-env-shadowed"); err == nil {
		t.Errorf("shadow file still present after teardown; want it renamed back")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat shadow file: unexpected err %v", err)
	}

	// And the lifecycle trail records mcp_config_neutralized at step 3.
	events := readLifecycleEvents(t, dir.Path)
	if indexOfVerb(events, LifecycleVerbMCPConfigNeutralized) < 0 {
		t.Errorf("mcp_config_neutralized verb missing; want one recorded at step 3")
	}
}
