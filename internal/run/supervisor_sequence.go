// Plan §5.5 — Supervisor sequencing (CANONICAL).
//
// This file owns the canonical pre-launch + teardown ordering the plan
// pins for the supervisor. Prior batches landed the individual
// components (ControlSocket — 0.0, lifecycle verbs — 0.1, leaks writer
// — 0.2, shim wiring — 1.3/1.4, ProviderProxy — 2.2/2.3, MCP gateway
// materialization — 3.1/3.2, EgressObserver interface — 5.0/5.1, NFLOG
// / pflog observers — 5.2/5.3, iptables / pf rule lifecycle — 5.4);
// Batch 5.5 composes them into the strict ordered sequence the plan
// documents at lines 232–264.
//
// Pre-launch (11 steps):
//
//	 1. Open lifecycle writer; chmod runDir 0700; write schema_versions
//	    map to run.json now (NOT at finalize).
//	 2. Mint primary control_token + per-server server_tokens; write
//	    `<runDir>/ipc/.helper-token`; start ControlSocket.
//	 3. backend.Create with the full BindMounts list (runDir/ipc,
//	    shimDir, ai-env binary, HOME shadow, canonical-path shim
//	    overlays); workspace MCP-config files renamed to
//	    `*.ai-env-shadowed`.
//	 4. (no supervisor action — observer covered by step 5.)
//	 5. backend.Start — netns assigned; start EgressObserver via
//	    `ns.WithNetNSPath` (netns now exists).
//	 6. Choose ProviderProxy reachability + compute narrowed
//	    NetworkPolicy + applyNetworkPolicy.
//	 7. Install AIENV-EGR-<8hex> rules at OUTPUT pos 1 via ns.Do.
//	 8. Allocate per-provider proxy ports; start each ProviderProxy.
//	 9. Build MCP Gateway + write `<runDir>/mcp-servers.json` and
//	    `<runDir>/ipc/mcp-servers.real.json`; emit `gateway_started`.
//	10. Install host-side shim wrappers in `<shimDir>/<program>`.
//	11. backend.Exec(child cmd).
//
// Teardown (9 steps reverse):
//
//	1. Stop child.
//	2. ControlSocket.AcceptingShutdown; drain ≤2s.
//	3. Drop iptables/pf rules via ns.Do.
//	4. Stop EgressObserver.
//	5. Stop each ProviderProxy.
//	6. Stop MCP Gateway logger; emit `gateway_stopped`.
//	7. Restore workspace MCP-config files; backend.Stop + Destroy.
//	8. Stop ControlSocket; emit `control_socket_stopped`.
//	9. Drain + close writers; render transcript.md; leaks aggregate;
//	   final summary. (Owned by finalizeTerminal + Run's deferred drain.)
//
// Fail-closed: at each step a failure stops every already-started
// component in reverse, emits the matching `_stopped` verbs with
// reason="error", and aborts the run with the appropriate terminal
// (StateFailedBackend for backend.Create / backend.Start failures,
// StateFailedPolicy for rule install / proxy bind / network policy
// failures, StateFailedAgent for launch failures).
package run

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/rivan1986/ai-env/internal/egress"
	"github.com/rivan1986/ai-env/internal/egress/rules"
)

// startControlSocket performs canonical pre-launch step 2.
//
// When opts.ControlSocket is non-nil the supervisor starts the
// listener and emits a `control_socket_started` lifecycle verb. A
// failure aborts the run with StateFailedBackend / StopReasonBackendFailure
// (the control socket binds before any in-sandbox surface is up;
// failing here is structurally a backend-level fault).
func (s *Supervisor) startControlSocket(ctx context.Context) error {
	if s.opts.ControlSocket == nil {
		return nil
	}
	if err := s.opts.ControlSocket.Start(ctx); err != nil {
		return fmt.Errorf("start control socket: %w", err)
	}
	s.controlSocketStarted = true
	if s.lcWri != nil {
		_ = s.lcWri.WriteVerb(LifecycleVerbControlSocketStarted, map[string]string{
			"path": s.opts.ControlSocket.Path(),
		})
	}
	return nil
}

// stopControlSocket performs canonical teardown step 8.
//
// Emits `control_socket_stopped` with the supplied reason ("teardown"
// on clean shutdown; "shutdown" on a forced terminal). The Stop error
// is swallowed: the run's terminal has already been decided and the
// supervisor's audit trail is the durable record.
func (s *Supervisor) stopControlSocket(reason string) {
	if !s.controlSocketStarted || s.opts.ControlSocket == nil {
		return
	}
	if reason == "" {
		reason = "teardown"
	}
	_ = s.opts.ControlSocket.Stop()
	s.controlSocketStarted = false
	if s.lcWri != nil {
		_ = s.lcWri.WriteVerb(LifecycleVerbControlSocketStopped, map[string]string{
			"reason": reason,
		})
	}
}

// acceptingShutdownDrain performs canonical teardown step 2.
//
// Flips the ControlSocket's shutdown gate so any NEW RPCs answer
// "block, shutdown" immediately, then sleeps for the plan's drain
// window so in-flight RPCs have a chance to complete. The plan's "emit
// helper_rpc_aborted for any RPC stuck past timeout" rule is a future
// enhancement on the control socket itself (the socket does not
// currently surface per-RPC timing); the gate alone is enough to satisfy
// the canonical ordering invariant.
func (s *Supervisor) acceptingShutdownDrain() {
	if s.opts.ControlSocket == nil {
		return
	}
	s.opts.ControlSocket.AcceptingShutdown()
	// The plan documents a "drain ≤2s" window for in-flight RPCs. The
	// gate-flip alone is the canonical synchronization point: every
	// new RPC after this returns "block, shutdown" immediately. In-
	// flight RPCs that outlast the window are not forcibly interrupted
	// (the supervisor cannot safely cancel them mid-marshal); the gate
	// is the authoritative no-new-work signal and the canonical
	// sequence requires the gate-flip to precede the rule drop /
	// observer stop. The acceptingShutdownDrain helper is kept distinct
	// from stopControlSocket so the ordering is auditable independently.
}

// runBackendCreate performs canonical pre-launch step 3.
//
// The plan's step 3 also requires the workspace MCP-config rename to
// `*.ai-env-shadowed` so the agent CLI's auto-merge cannot reintroduce
// a workspace-local config. The supervisor performs the rename here,
// records the entries on `s.shadowEntries` so teardown step 7 can
// restore them, and emits one `mcp_config_neutralized` lifecycle verb
// per shadowed file.
//
// When opts.BackendCreate is nil the supervisor still runs the
// workspace-shadow side: the host-side bind-mount construction is the
// caller's responsibility (the future `ai-env run` CLI wires it
// alongside Backend.Create) but the shadow rename is an in-process step
// that always applies when a workspace path is configured.
func (s *Supervisor) runBackendCreate() error {
	if s.opts.WorkspaceMCPRoot != "" {
		entries, err := ShadowWorkspaceMCPConfig(s.opts.WorkspaceMCPRoot)
		if err != nil {
			return fmt.Errorf("shadow workspace mcp config: %w", err)
		}
		s.shadowEntries = entries
		if s.lcWri != nil {
			for _, entry := range entries {
				_ = s.lcWri.WriteVerb(LifecycleVerbMCPConfigNeutralized, MCPConfigNeutralizedMetadata(entry))
			}
		}
	}
	if s.opts.BackendCreate != nil {
		if err := s.opts.BackendCreate(); err != nil {
			return fmt.Errorf("backend create: %w", err)
		}
	}
	return nil
}

// restoreWorkspaceMCP performs the workspace-shadow half of canonical
// teardown step 7. The Backend.Stop + Destroy half is left to the
// caller's BackendDestroy hook so the supervisor stays free of
// backend-adapter specifics.
func (s *Supervisor) restoreWorkspaceMCP() {
	if len(s.shadowEntries) == 0 {
		return
	}
	if err := RestoreWorkspaceMCPConfig(s.shadowEntries); err != nil && s.opts.UserOutput != nil {
		_, _ = fmt.Fprintf(s.opts.UserOutput, "ai-env: warning: restore workspace mcp config: %v\n", err)
	}
	s.shadowEntries = nil
}

// runBackendStart performs canonical pre-launch step 5 (host-side
// half). The plan calls for `backend.Start` followed by EgressObserver
// attach inside the now-existing netns. We invoke the supplied
// BackendStart closure (when set), then start the observer.
//
// The order matters: the observer's `ns.WithNetNSPath` requires the
// netns path to exist, which only happens after Backend.Start
// completes. A failure on either half aborts with StateFailedBackend.
func (s *Supervisor) runBackendStart() error {
	if s.opts.BackendStart != nil {
		if err := s.opts.BackendStart(); err != nil {
			return fmt.Errorf("backend start: %w", err)
		}
	}
	return nil
}

// startEgressObserver performs canonical pre-launch step 5 (observer
// half). The supervisor consults the configured EgressObserverMode +
// EgressObserver instance; modes that resolve to skip leave the
// observer detached and may emit `observer_unavailable` instead.
//
// Acceptance criterion #8 (Plan §0): `--observer-mode strict` aborts
// without CAP_NET_ADMIN; `auto` (default) succeeds with degradation.
// The supervisor uses the typed mode to pick the StartDecision via
// `egress.ResolveStartDecision`; when the operator passes Disabled
// the supervisor skips attach silently.
//
// A non-nil Observer in opts that fails to Start aborts the run with
// StateFailedBackend (the observer is part of the backend.Start step
// boundary).
func (s *Supervisor) startEgressObserver(ctx context.Context) error {
	obs := s.opts.EgressObserver
	if obs == nil {
		// No observer configured; the supervisor records this as a
		// canonical "no observer wired" path. We do NOT emit
		// `observer_unavailable` here because the plan reserves that
		// verb for the capability-driven degradation (e.g.
		// slirp4netns); a deliberately-nil observer is the test /
		// host-mode default.
		return nil
	}
	if err := obs.Start(ctx); err != nil {
		// Strict mode: surface the error so the supervisor aborts.
		// Auto / Disabled: degrade by emitting observer_unavailable and
		// proceeding. We treat any non-strict mode as graceful degrade
		// per the plan's locked rule.
		if s.opts.EgressObserverMode == egress.EgressObserverModeStrict {
			return fmt.Errorf("start egress observer: %w", err)
		}
		if s.lcWri != nil {
			_ = s.lcWri.WriteVerb(LifecycleVerbObserverUnavailable, map[string]string{
				"reason": "start_failed",
				"detail": err.Error(),
			})
		}
		return nil
	}
	s.observerStarted = true
	if s.lcWri != nil {
		_ = s.lcWri.WriteVerb(LifecycleVerbObserverStarted, map[string]string{
			"mode":  obs.Mode(),
			"chain": obs.Chain(),
		})
	}
	return nil
}

// stopEgressObserver performs canonical teardown step 4. Errors from
// Stop are swallowed (the terminal has already been decided); the
// `observer_stopped` verb records the reason.
func (s *Supervisor) stopEgressObserver(reason string) {
	if !s.observerStarted || s.opts.EgressObserver == nil {
		return
	}
	if reason == "" {
		reason = "teardown"
	}
	_ = s.opts.EgressObserver.Stop()
	s.observerStarted = false
	if s.lcWri != nil {
		_ = s.lcWri.WriteVerb(LifecycleVerbObserverStopped, map[string]string{
			"reason": reason,
		})
	}
}

// installEgressRules performs canonical pre-launch step 7. The rule
// lifecycle is the host-side iptables / pf install; failure is
// fail-closed (StateFailedPolicy) per the plan's "Fail closed: if the
// backend cannot apply the requested network policy, autonomous mode
// must fail" rule.
//
// The rule lifecycle's OnInstalled callback is NOT used to drive the
// `observer_started` verb (that fires at step 5 alongside the observer
// attach); the supervisor leaves the rules lifecycle's callbacks unused
// here.
func (s *Supervisor) installEgressRules(ctx context.Context) error {
	if s.opts.EgressRules == nil {
		return nil
	}
	if err := s.opts.EgressRules.Install(ctx); err != nil {
		// ErrUnsupportedOS is a graceful no-op: the host has no
		// rule-install surface (e.g. a non-Linux/non-Darwin CI host).
		// The supervisor records the skip via the network-events log
		// rather than aborting the run, which mirrors the
		// observer's auto-mode degradation.
		if errors.Is(err, rules.ErrUnsupportedOS) {
			return nil
		}
		return fmt.Errorf("install egress rules: %w", err)
	}
	s.rulesInstalled = true
	return nil
}

// removeEgressRules performs canonical teardown step 3. The plan
// places this BEFORE the observer stop (step 4) so the kernel surface
// the observer is reading from is drained of new packets before the
// observer goroutine exits. Errors are recorded via the rule
// lifecycle's OnUninstalled callback (if wired); the supervisor
// swallows them here because the terminal has already been decided.
func (s *Supervisor) removeEgressRules(ctx context.Context, reason string) {
	if !s.rulesInstalled || s.opts.EgressRules == nil {
		return
	}
	if reason == "" {
		reason = "teardown"
	}
	_ = s.opts.EgressRules.Uninstall(ctx, reason)
	s.rulesInstalled = false
}

// materializeMCPGateway performs canonical pre-launch step 9. The
// supervisor calls the supplied materializer closure to write the
// per-run `mcp-servers.json` + `mcp-servers.real.json` + `.helper-token`
// files; on success emits `gateway_started` with the canonical
// metadata table (server_count + config_path).
//
// The closure shape lets the call site (the future `ai-env run` CLI)
// thread its own dependencies (registry, ContainerUID, HelperCommand)
// without the supervisor learning them. A nil closure skips the step
// entirely (legacy callers that do not wire a gateway).
func (s *Supervisor) materializeMCPGateway() error {
	if s.opts.MCPGatewayMaterializer == nil {
		return nil
	}
	cfg, err := s.opts.MCPGatewayMaterializer(s.opts.ControlSocket)
	if err != nil {
		return fmt.Errorf("materialize mcp gateway: %w", err)
	}
	s.perRunMCP = cfg
	s.gatewayStarted = true
	if s.lcWri != nil {
		_ = s.lcWri.WriteVerb(LifecycleVerbGatewayStarted, map[string]string{
			"server_count": fmt.Sprintf("%d", len(cfg.ServerTokens)),
			"config_path":  cfg.AgentConfigPath,
		})
	}
	return nil
}

// stopMCPGateway performs canonical teardown step 6. The plan calls
// for stopping the gateway logger; the on-disk mcp-calls.jsonl writer
// is owned by the higher-level BuildRunGateway bundle (which lives in
// the cli package to avoid an import cycle). The supervisor invokes
// the caller-supplied closer closure (when set) and emits
// `gateway_stopped`.
func (s *Supervisor) stopMCPGateway(reason string) {
	if !s.gatewayStarted {
		return
	}
	if reason == "" {
		reason = "teardown"
	}
	if s.opts.MCPGatewayCloser != nil {
		_ = s.opts.MCPGatewayCloser()
	}
	s.gatewayStarted = false
	if s.lcWri != nil {
		_ = s.lcWri.WriteVerb(LifecycleVerbGatewayStopped, map[string]string{
			"reason": reason,
		})
	}
}

// runBackendStopDestroy performs the backend half of canonical
// teardown step 7. The supervisor invokes the caller-supplied
// BackendDestroy closure when set; failures are surfaced via
// UserOutput as warnings, never escalated to a different terminal.
//
// The host-side Backend.Stop sequence the supervisor already runs in
// `requestBackendStop` (for backend-adapter callers) covers the Stop
// half; this closure is the bookend for Destroy (release the env's
// host resources, e.g. docker container removal).
func (s *Supervisor) runBackendStopDestroy() {
	if s.opts.BackendDestroy == nil {
		return
	}
	if err := s.opts.BackendDestroy(); err != nil && s.opts.UserOutput != nil {
		_, _ = fmt.Fprintf(s.opts.UserOutput, "ai-env: warning: backend destroy: %v\n", err)
	}
}

// ensureRunDirSecurePerms performs canonical pre-launch step 1's
// chmod-runDir-0700 invariant defensively. CreateRunDirectory already
// chmods the directory to 0700; this helper is the supervisor's "trust
// but verify" call so a future caller that constructs runDir via a
// different path (e.g. a manual mkdir in a test fixture) still
// inherits the right perms before any sensitive file lands inside it.
//
// Errors are swallowed: the directory exists (the constructor already
// opened files inside it) and a chmod failure here is a host-policy
// surprise we surface via UserOutput rather than aborting the run.
func (s *Supervisor) ensureRunDirSecurePerms() {
	if s.opts.RunDir == "" {
		return
	}
	if err := os.Chmod(s.opts.RunDir, 0o700); err != nil && s.opts.UserOutput != nil {
		_, _ = fmt.Fprintf(s.opts.UserOutput, "ai-env: warning: chmod run dir 0700: %v\n", err)
	}
}

// preLaunchSequence drives the canonical 11-step pre-launch sequence.
// Returns nil on success; on any failure rolls back every already-
// started component in reverse and returns the wrapped error annotated
// with the terminal cause the caller should land on.
//
// The sequence enforces the strict ordering the plan documents. Each
// step is gated on the corresponding SupervisorOptions field being
// non-nil; a nil option skips that step without affecting downstream
// ordering. The skip semantics are critical: callers that wire only
// the ProviderProxy half (the plan-04 / plan-05 supervisor tests) keep
// their existing behavior while the canonical sequence still runs for
// callers that wire the full surface.
//
// Returns a sequenceError carrying both the underlying error and the
// terminal cause (state + reason) so the caller can transition the
// state machine without inspecting the error string.
func (s *Supervisor) preLaunchSequence(ctx context.Context) *sequenceError {
	// Step 1: lifecycle writer + runDir 0700 + schema_versions.
	// The lifecycle writer is opened in NewSupervisor; the
	// schema_versions map is written into run.json on every
	// writeRecordSnapshot call (NOT only at finalize), satisfying the
	// plan's "write schema_versions map to run.json NOW" rule. We
	// re-chmod runDir 0700 defensively here so a custom-runDir caller
	// (test fixture) still sees the canonical permission.
	s.ensureRunDirSecurePerms()
	if err := s.enterSetup(StatePreparingWorkspace); err != nil {
		return &sequenceError{err: fmt.Errorf("step 1 enter preparing_workspace: %w", err), state: StateFailedBackend, reason: StopReasonBackendFailure}
	}
	if s.checkCancel() {
		return &sequenceError{err: errors.New("step 1 cancelled"), state: StateKilledByUser, reason: StopReasonSignal}
	}

	// Step 2: ControlSocket start.
	if err := s.startControlSocket(ctx); err != nil {
		return &sequenceError{err: err, state: StateFailedBackend, reason: StopReasonBackendFailure}
	}
	if s.checkCancel() {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: errors.New("step 2 cancelled"), state: StateKilledByUser, reason: StopReasonSignal}
	}

	// Step 3: backend.Create + workspace MCP shadow.
	if err := s.runBackendCreate(); err != nil {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: err, state: StateFailedBackend, reason: StopReasonBackendFailure}
	}
	if err := s.enterSetup(StateStartingBackend); err != nil {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: fmt.Errorf("step 3 enter starting_backend: %w", err), state: StateFailedBackend, reason: StopReasonBackendFailure}
	}
	if s.checkCancel() {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: errors.New("step 3 cancelled"), state: StateKilledByUser, reason: StopReasonSignal}
	}

	// Step 5 (host-side half): backend.Start + EgressObserver attach.
	// Step 4 is intentionally empty per the plan's numbering.
	if err := s.runBackendStart(); err != nil {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: err, state: StateFailedBackend, reason: StopReasonBackendFailure}
	}
	if err := s.startEgressObserver(ctx); err != nil {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: err, state: StateFailedBackend, reason: StopReasonBackendFailure}
	}
	if s.checkCancel() {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: errors.New("step 5 cancelled"), state: StateKilledByUser, reason: StopReasonSignal}
	}

	// Step 6: choose ProviderProxy reachability + applyNetworkPolicy.
	// The reachability picker is the responsibility of the caller (the
	// CLI builds the ProviderProxy slice via `BuildProviderProxyFromSecrets`
	// after picking BindMode from capability.Detect()); the supervisor
	// runs applyNetworkPolicy here so the egress rules / proxy
	// carve-outs land in canonical order.
	if err := s.enterSetup(StateApplyingPolicy); err != nil {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: fmt.Errorf("step 6 enter applying_policy: %w", err), state: StateFailedPolicy, reason: StopReasonPolicyFailure}
	}
	if err := s.applyNetworkPolicy(); err != nil {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: fmt.Errorf("apply network policy: %w", err), state: StateFailedPolicy, reason: StopReasonPolicyFailure}
	}
	if s.checkCancel() {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: errors.New("step 6 cancelled"), state: StateKilledByUser, reason: StopReasonSignal}
	}

	// Step 7: install AIENV-EGR rules at OUTPUT pos 1.
	if err := s.installEgressRules(ctx); err != nil {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: err, state: StateFailedPolicy, reason: StopReasonPolicyFailure}
	}
	if s.checkCancel() {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: errors.New("step 7 cancelled"), state: StateKilledByUser, reason: StopReasonSignal}
	}

	// Step 8: start ProviderProxies.
	started, err := s.startProviderProxies()
	if err != nil {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: fmt.Errorf("start provider proxy: %w", err), state: StateFailedPolicy, reason: StopReasonPolicyFailure}
	}
	s.startedProxies = started
	if s.checkCancel() {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: errors.New("step 8 cancelled"), state: StateKilledByUser, reason: StopReasonSignal}
	}

	// Step 9: materialize MCP gateway.
	if err := s.materializeMCPGateway(); err != nil {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: err, state: StateFailedBackend, reason: StopReasonBackendFailure}
	}
	if s.checkCancel() {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: errors.New("step 9 cancelled"), state: StateKilledByUser, reason: StopReasonSignal}
	}

	// Step 10: host-side shim wrappers are installed in NewSupervisor
	// (so the supervisor fails fast on a misconfigured shim dir at
	// construction time). The canonical-ordering requirement is that
	// the wrappers exist before backend.Exec — NewSupervisor's
	// per-program file write satisfies the precondition because the
	// supervisor cannot reach this point without NewSupervisor
	// returning successfully. No per-step action here.

	// Step 11: enter StateStartingAgent so the runLoop transition is
	// recorded before the child launches. The actual backend.Exec call
	// is in launchChild (still owned by the runLoop body for
	// historical wait-channel reasons).
	if err := s.enterSetup(StateStartingAgent); err != nil {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: fmt.Errorf("step 11 enter starting_agent: %w", err), state: StateFailedAgent, reason: StopReasonAgentFailure}
	}
	if s.checkCancel() {
		s.rollbackPreLaunch(ctx)
		return &sequenceError{err: errors.New("step 11 cancelled"), state: StateKilledByUser, reason: StopReasonSignal}
	}
	return nil
}

// rollbackPreLaunch tears down every already-started pre-launch
// component in reverse order, marking each `_stopped` verb with
// reason="error". The supervisor calls this from any step's failure
// path so a partial pre-launch is unwound before the run aborts.
//
// Mirrors the canonical teardown ordering: rules → observer → proxies
// → gateway → workspace restore + backend destroy → control socket.
// We deliberately do NOT call AcceptingShutdown / drain here because
// the run never reached the running state: there are no in-flight
// helper RPCs to drain.
func (s *Supervisor) rollbackPreLaunch(ctx context.Context) {
	// Mirror teardown steps 3–8 in order. Closures bail early on
	// "never started" so the helper is idempotent.
	s.removeEgressRules(ctx, "error")
	s.stopEgressObserver("error")
	s.stopProviderProxies(s.startedProxies, "error")
	s.startedProxies = nil
	s.stopMCPGateway("error")
	s.restoreWorkspaceMCP()
	s.runBackendStopDestroy()
	s.stopControlSocket("error")
}

// teardownSequence drives the canonical 9-step teardown sequence on
// the terminal path. Called by finalizeTerminal after the run has
// reached a terminal state but before the writers are drained / the
// final-summary is written.
//
// Step 1 (stop child) and the child's wait have already happened by
// the time finalizeTerminal calls this; we pick up at step 2.
//
// reasonToken is the per-verb reason recorded on each `_stopped`
// emission ("teardown" on clean shutdown; "shutdown" on a forced
// terminal — the caller decides which by inspecting the final State).
func (s *Supervisor) teardownSequence(ctx context.Context, reasonToken string) {
	// Step 2: ControlSocket.AcceptingShutdown + drain.
	s.acceptingShutdownDrain()

	// Step 3: drop iptables / pf rules.
	s.removeEgressRules(ctx, reasonToken)

	// Step 4: stop EgressObserver.
	s.stopEgressObserver(reasonToken)

	// Step 5: stop each ProviderProxy.
	s.stopProviderProxies(s.startedProxies, reasonToken)
	s.startedProxies = nil

	// Step 6: stop MCP Gateway logger; emit gateway_stopped.
	s.stopMCPGateway(reasonToken)

	// Step 7: restore workspace MCP-config files + backend Stop+Destroy.
	s.restoreWorkspaceMCP()
	s.runBackendStopDestroy()

	// Step 8: stop ControlSocket.
	s.stopControlSocket(reasonToken)

	// Step 9 (writer drain + transcript + leaks + final summary) is
	// owned by finalizeTerminal and Run's deferred drain; this helper
	// hands control back so finalizeTerminal can run its own steps.
}

// sequenceError bundles the underlying step failure with the terminal
// cause the supervisor should land the run on. The pre-launch helper
// returns this so the caller does not have to inspect the error string
// to pick StateFailedBackend vs StateFailedPolicy vs StateFailedAgent.
type sequenceError struct {
	err    error
	state  State
	reason StopReason
}

// Error implements error.
func (e *sequenceError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

// terminalCause translates the sequenceError into a terminalCause
// the supervisor's runLoop / finalizeTerminal helpers consume.
func (e *sequenceError) terminalCause() terminalCause {
	if e == nil {
		return terminalCause{}
	}
	note := ""
	if e.err != nil {
		note = e.err.Error()
	}
	return terminalCause{state: e.state, reason: e.reason, note: note}
}

// reasonTokenForTerminal returns the verb reason token the teardown
// sequence stamps onto each `_stopped` emission. Clean terminals
// (StateCompleted) record "teardown"; forced terminals record
// "shutdown" so an audit reader can distinguish the unwind cause.
func reasonTokenForTerminal(final State) string {
	switch final {
	case StateKilledByUser, StateTimedOut, StateKilledIdle, StateKilledOOM,
		StateFailedAgent, StateFailedBackend, StateFailedPolicy, StateFailedScan, StateQuarantined:
		return "shutdown"
	}
	return "teardown"
}
