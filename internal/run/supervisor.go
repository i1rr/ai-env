package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rivan1986/ai-env/internal/backend"
	"github.com/rivan1986/ai-env/internal/egress"
	"github.com/rivan1986/ai-env/internal/egress/rules"
	"github.com/rivan1986/ai-env/internal/network"
	"github.com/rivan1986/ai-env/internal/policy"
	"github.com/rivan1986/ai-env/internal/secrets"
)

// defaultStatsPollInterval is how often the supervisor's stats / idle /
// runtime poll fires while the agent is in StateRunning. The plan asks
// for "Poll stats every 10 seconds"; that cadence is the production
// default. Tests inject a shorter interval through SupervisorOptions so
// the idle and max-runtime paths are exercisable without sleeping for
// minutes at a time.
const defaultStatsPollInterval = 10 * time.Second

// defaultStopGracePeriod is how long the supervisor waits between asking
// the child process to stop (Process.Signal SIGTERM via Cancel / timeout
// path) and escalating to a hard kill. The plan documents
// shutdown_grace_seconds = 15 and kill_grace_seconds = 5 as the
// configured defaults; here we expose them via SupervisorOptions so the
// signal-handling step (step 9) can wire the configured values in
// without reworking this file. A zero value falls back to a short
// constant so tests that do not care about the grace path still
// terminate promptly.
const defaultStopGracePeriod = 5 * time.Second

// StopReasonForState returns the canonical StopReason that pairs with a
// terminal State. It is exported so later batches (the signal handler,
// the `--continue` formatter) do not have to keep their own copy of the
// mapping.
//
// Returns the empty StopReason for non-terminal states; the supervisor
// only records a reason once it actually reaches a terminal.
func StopReasonForState(s State) StopReason {
	switch s {
	case StateCompleted:
		return StopReasonAgentExit
	case StateFailedAgent:
		return StopReasonAgentFailure
	case StateFailedBackend:
		return StopReasonBackendFailure
	case StateFailedPolicy:
		return StopReasonPolicyFailure
	case StateFailedScan:
		return StopReasonScanFailure
	case StateTimedOut:
		return StopReasonTimeout
	case StateKilledByUser:
		return StopReasonSignal
	case StateKilledOOM:
		return StopReasonOOM
	case StateKilledIdle:
		return StopReasonIdle
	case StateQuarantined:
		return StopReasonQuarantine
	}
	return ""
}

// CommandSpec describes how to launch the agent process. The plan calls
// the launch path "backend exec (stub: echo process in this phase)";
// CommandSpec is the value type that the supervisor consumes today and
// that a real Backend.Exec will populate later. Keeping the spec narrow
// (program, args, dir, env) means swapping in a docker-sbx launcher in
// plan 04 only touches the construction site, not the supervisor body.
type CommandSpec struct {
	// Program is the executable name or absolute path the supervisor
	// runs. It is the first argv element, not a shell string; quoting
	// is the caller's concern.
	Program string

	// Args is the rest of argv (without the program). May be nil.
	Args []string

	// Dir is the working directory the child runs in. Typically the
	// workspace path. Empty means "inherit the supervisor's cwd",
	// matching exec.Cmd's default.
	Dir string

	// Env is the environment passed to the child. Nil means "inherit
	// the supervisor's environment", matching exec.Cmd's default. The
	// supervisor does not splice host env vars when this is nil; the
	// caller decides whether the child sees the parent env.
	Env []string
}

// SupervisorOptions bundles every knob the supervisor needs at
// construction. The required fields (RunDir, Command, EnvName, Backend,
// Agent, Task) are load-bearing for lifecycle.jsonl and run.json; the
// optional fields fall back to plan defaults so a production call site
// can omit them.
//
// The options struct lets the supervisor stay constructor-light: tests
// that need a fixed clock, a tight idle window, or a tiny stats poll
// interval flip just those fields and leave the rest at their defaults.
type SupervisorOptions struct {
	// RunDir is the run directory the supervisor writes lifecycle.jsonl,
	// run.json, stdout.log, and stderr.log into. Typically
	// RunDirectory.Path; required.
	RunDir string

	// RunID is the run identifier. Required so lifecycle events and
	// run.json carry the same string everywhere.
	RunID string

	// EnvName is the environment name this run targets. Required for
	// run.json's env_name field.
	EnvName string

	// Task is the verbatim --task content. Stored on the supervisor and
	// copied into run.json so a reader of run.json alone sees what the
	// agent was asked to do. Required (matches WriteTask's contract).
	Task string

	// Backend is the backend identifier (e.g. "docker-sbx",
	// "local-process") the supervisor reports in lifecycle.jsonl and
	// run.json. Required.
	Backend string

	// Agent is the agent identifier (e.g. "claude") the supervisor
	// reports in lifecycle.jsonl and run.json. Required.
	Agent string

	// Command is the spec for the child process. Required; Program may
	// not be empty.
	//
	// When BackendAdapter is non-nil the supervisor dispatches Command
	// through Backend.Exec inside BackendEnvID instead of host-side
	// exec.Command. The fields are interpreted the same way (Program +
	// Args + Dir + Env) but their meaning shifts to "inside the sandbox":
	// Program is resolved against the sandbox's $PATH, Dir is a path
	// inside the sandbox (typically the workspace mount), and Env entries
	// are forwarded into the sandbox environment.
	Command CommandSpec

	// BackendAdapter, when non-nil, makes the supervisor route the child
	// process through Backend.Exec instead of a host-side exec.Command.
	// This is the seam plan 04 step 8 wires: the Docker Sandboxes
	// adapter, the mock backend, and any future adapter all flow through
	// the same Supervisor without it learning their specifics.
	//
	// When BackendAdapter is nil the supervisor falls back to the legacy
	// host-side exec.Command path. That fallback exists so unit tests
	// that exercise the lifecycle / signal / timeout machinery can drive
	// real subprocesses (sh -c ...) without having to construct a mock
	// backend, and so the early plan-03 supervisor tests keep passing
	// verbatim. Production callers (the `ai-env run` CLI) always supply
	// a Backend.
	BackendAdapter backend.Backend

	// BackendEnvID is the envID Backend.Exec / Backend.Stop are addressed
	// by. Required when BackendAdapter is non-nil; ignored otherwise. The
	// CLI obtains it from Backend.Create earlier in the run lifecycle.
	BackendEnvID string

	// NetworkPolicyAdapter, when non-nil, is invoked during
	// StateApplyingPolicy to install the supplied NetworkPolicy on
	// NetworkPolicyEnvID (or BackendEnvID, when the network env id is
	// empty). The supervisor enforces the plan's "fail closed" rule
	// (master plan section 18, plan 05 step 4): if Apply returns a
	// non-nil error, the supervisor aborts the run with
	// StateFailedPolicy / StopReasonPolicyFailure rather than silently
	// continuing into StateStartingAgent. Leaving the field nil skips
	// the apply call entirely and preserves the legacy plan-03/04
	// supervisor behavior where the StateApplyingPolicy transition is
	// only a lifecycle stamp; production CLI call sites populate this
	// once plan 05 wiring lands.
	NetworkPolicyAdapter network.NetworkPolicyAdapter

	// NetworkPolicy is the canonical runtime policy the
	// NetworkPolicyAdapter installs. Used only when
	// NetworkPolicyAdapter is non-nil; ignored otherwise. The supervisor
	// does not validate the policy itself: callers are expected to
	// build it via network.NewNetworkPolicy and call
	// NetworkPolicy.Validate against the run's mode before construction
	// so a misconfigured policy fails closed at config parse time, not
	// after the workspace has been prepared. The supervisor passes the
	// value through to Adapter.Apply verbatim.
	NetworkPolicy network.NetworkPolicy

	// NetworkPolicyEnvID is the envID NetworkPolicyAdapter.Apply is
	// addressed by. Defaults to BackendEnvID when empty: in practice
	// the same envID identifies both the running sandbox (for
	// Backend.Exec / Backend.Stop) and the policy target (for
	// Adapter.Apply). The field is kept distinct so a future backend
	// that separates the two identities (e.g. a network namespace
	// addressed by a different handle than the exec sandbox) can wire
	// them independently without reshaping SupervisorOptions.
	NetworkPolicyEnvID string

	// PolicyEnginePath, when non-empty, asks NewSupervisor to load and
	// validate the policy.yaml at this path and instantiate a
	// PolicyEngine. Plan 08 step 7 enforces "validate config before
	// starting sandbox": a malformed policy.yaml aborts construction
	// with a clear error so the supervisor never reaches the
	// backend-start phase.
	//
	// Mutually exclusive with PolicyEngine: a non-empty path plus a
	// non-nil engine is a configuration error and is rejected at
	// construction time so an operator does not accidentally wire two
	// different policies and pick one silently.
	PolicyEnginePath string

	// PolicyEngine, when non-nil, is the already-constructed policy
	// engine the supervisor uses for runtime network and shell
	// decisions. This is the dependency-injection path tests use to
	// drive deterministic verdicts; production callers either set
	// PolicyEnginePath (the supervisor loads the file) or wire an
	// engine they constructed elsewhere (e.g. the future `ai-env run`
	// CLI that shares the engine with the network policy installer).
	//
	// Setting PolicyEngine without PolicyEnginePath is fine: the
	// supervisor still opens the per-run policy-decisions.jsonl writer
	// so every EvaluateNetworkDomain / EvaluateShellCommand call is
	// recorded.
	PolicyEngine PolicyEngine

	// Stdin, when non-nil, is the reader the supervisor pipes into the
	// child's stdin. Used by the agent launchers (claude, codex) to hand
	// the task prompt to the agent CLI. Nil means "no stdin" (the agent
	// reads from /dev/null inside the sandbox / host).
	Stdin io.Reader

	// ModelCredentialMode records how the agent obtains its model
	// credentials. Defaults to ModelCredentialBackendManaged when
	// empty: the safe default the plan documents.
	ModelCredentialMode ModelCredentialMode

	// ReducedSafety is recorded verbatim in run.json. The supervisor
	// does not interpret it.
	ReducedSafety bool

	// LinkedPreviousRun is the predecessor run ID for --continue runs;
	// nil for a fresh run. Recorded verbatim in run.json.
	LinkedPreviousRun *string

	// MaxRuntime is the budget the supervisor enforces for the entire
	// run. The plan documents max_runtime_minutes = 120 as the default;
	// callers convert that to a Duration before passing it. A zero
	// value disables the timeout (used by tests that exercise the
	// happy path without racing the budget).
	MaxRuntime time.Duration

	// IdleTimeout is the no-output budget the supervisor enforces while
	// the run is in StateRunning. The plan documents
	// idle_timeout_minutes = 20 as the default. A zero value disables
	// the idle detector. The supervisor only counts time spent in
	// StateRunning; setup states do not consume the budget.
	IdleTimeout time.Duration

	// StatsPollInterval is the cadence of the supervisor's stats /
	// idle / runtime poll. Defaults to defaultStatsPollInterval when
	// zero. Tests override it to a few milliseconds.
	StatsPollInterval time.Duration

	// StopGracePeriod is how long the supervisor waits between asking
	// the child to stop (SIGTERM) and escalating to SIGKILL. Defaults
	// to defaultStopGracePeriod when zero. Wired here in step 8 so the
	// signal-handling step can pass the configured value through; the
	// timeout / cancel paths share the same grace window so a hung
	// child still terminates.
	StopGracePeriod time.Duration

	// Now is the clock the supervisor uses for lifecycle timestamps,
	// run.json started_at / stopped_at, and the idle / runtime
	// computations. Defaults to time.Now when nil. Tests inject a
	// fixed-step clock so the on-disk timestamps are deterministic.
	Now func() time.Time

	// StreamOptions are forwarded to OpenStreamCapture. Zero-valued
	// fields fall through to OpenStreamCapture's own defaults so a
	// supervisor caller does not have to wire stream options unless it
	// cares about the tail buffer size or a custom stream clock.
	StreamOptions StreamOptions

	// DiffCollector, when non-nil, is invoked on terminal so the
	// supervisor can fetch the workspace's partial diff and write it
	// into runDir/git-diff.patch before the closing run.json snapshot
	// lands. This is the seam step 10 ("collect partial diff") uses; the
	// CLI wires a workspace-aware collector here (typically built via
	// NewGitWorktreeDiffCollector for a worktree-strategy env). Leaving
	// it nil skips the collection step and leaves the empty git-diff.patch
	// placeholder in place, which is the right v0.1 default for tests
	// and for non-workspace-aware callers.
	//
	// The collector is invoked once per run from the supervisor's
	// terminal path. Errors are advisory: they do NOT change the
	// terminal state. See DiffCollector for the full contract.
	DiffCollector DiffCollector

	// DiffTimeout caps how long DiffCollector is allowed to run. Zero
	// falls back to defaultDiffTimeout (10s). The cap matters because a
	// stuck `git diff` (corrupt index, missing base ref, detached
	// worktree) would otherwise block the supervisor's terminal walk
	// past the user's expectation; the plan's "preserve logs, collect
	// partial diff if possible" sequence treats the diff as advisory,
	// so a timeout is the right escape hatch rather than waiting
	// indefinitely.
	DiffTimeout time.Duration

	// ScanHook, when non-nil, is invoked during StateScanning on the
	// supervisor's happy-path terminal walk so the post-run secret /
	// dependency scanner runs automatically after the agent stops and
	// before the run transitions to StateReporting. Plan 06 step 9
	// ("wire scanner into run lifecycle: run scan automatically after
	// agent stops, before report") is the rule the supervisor enforces
	// here.
	//
	// The hook is responsible for materializing secret-scan.json and
	// dependency-report.json inside runDir; the supervisor never
	// inspects findings itself. A non-nil error returned from the hook
	// is treated as a scanner-infrastructure failure and lands the run
	// in StateFailedScan / StopReasonScanFailure. Findings themselves
	// are NOT failures: the export gate (consulted later by `ai-env
	// patch` / `ai-env pr`) is the surface that refuses the diff, so a
	// run with blocking findings still ends in StateCompleted on disk
	// and remains inspectable.
	//
	// The hook is never invoked on non-happy terminals (timeout, idle,
	// cancel, failed_*) because the run never reached the post-agent
	// drain there is nothing to scan.
	//
	// Leaving the hook nil skips the scan-time call entirely and keeps
	// the legacy plan-03 behavior where the StateScanning transition is
	// a lifecycle stamp only. Production CLI call sites populate this
	// once plan 06 wiring lands; tests that do not need scanning leave
	// it nil.
	ScanHook ScanHook

	// ScanTimeout caps how long ScanHook is allowed to run. Zero falls
	// back to defaultScanTimeout (5m). The cap exists because a wedged
	// external scanner (e.g. a trivy filesystem scan against a corrupt
	// index, or a govulncheck against a flaky module proxy) would
	// otherwise block the supervisor's StateScanning walk past the
	// operator's tolerance. The plan's "scan automatically" rule still
	// honors the bound: a timeout escalates to a StateFailedScan
	// terminal so the operator sees the failure rather than a hung run.
	ScanTimeout time.Duration

	// UserOutput is the io.Writer the supervisor uses for user-visible
	// terminal output. Today it is used by step 10 to print the
	// `ai-env run <env-name> --continue` suggestion when the run lands
	// in a continuation-eligible terminal (killed_by_user, timed_out,
	// killed_idle). Nil is legal: the supervisor still records the
	// suggestion on SupervisorResult.ContinueSuggestion so a programmatic
	// caller can surface it without a writer. Production callers pass
	// os.Stdout; tests pass a bytes.Buffer to assert on the printed
	// text.
	UserOutput io.Writer

	// ShellShim, when true, asks the supervisor to wire the optional
	// shell-shim prototype (internal/policy.Shim) into the run. This is
	// the option the future `ai-env run --shell-shim` CLI flag (plan 08
	// step 9) flips: when set the supervisor opens shell-commands.jsonl
	// in the run directory and prepends ShellShimDir to the child's
	// PATH so the wrapper binary (replacing bash / sh) is resolved
	// before the real system binary.
	//
	// Requires a configured policy engine (PolicyEngine or
	// PolicyEnginePath) and a non-empty ShellShimDir; without those the
	// supervisor would silently degrade into "log every command, deny
	// none" which is the wrong default for the prototype. NewSupervisor
	// rejects the misconfiguration with a clear error.
	//
	// Leaving ShellShim=false skips the wiring entirely: no shell-
	// commands log is opened, the child's PATH is passed through
	// verbatim, and legacy supervisor callers see no behavioral change.
	ShellShim bool

	// ShellShimDir is the absolute path of the directory the supervisor
	// prepends to the child's PATH when ShellShim is true. The
	// supervisor materializes per-program wrapper scripts here via
	// policy.InstallShim (Plan §5.5 step 10) at construction time:
	// the directory is created by the supervisor's caller (the future
	// `ai-env run --shell-shim` CLI or a test fixture), and the
	// supervisor writes one wrapper file per ShimProgramSet entry into
	// it. Ignored when ShellShim is false; required otherwise.
	ShellShimDir string

	// ProviderProxies is the per-run set of ProviderProxy instances the
	// supervisor starts at canonical pre-launch step 8 (Plan §5.5). The
	// CLI builds the slice via secrets.BuildProviderProxyFromSecrets
	// (Batch 2.4) after picking the BindMode at step 6; the supervisor
	// owns the Start / Stop lifecycle and the proxy_started /
	// proxy_stopped lifecycle verb emission (Batch 0.1).
	//
	// A nil / empty slice skips the wiring entirely so legacy callers
	// (the plan-03 / plan-04 supervisor tests that do not stand up a
	// proxy) keep their current behavior. A non-empty slice is
	// fail-closed: any bind failure aborts the run with
	// StateFailedBackend / StopReasonBackendFailure, per Bucket 2's
	// "Hard fail-closed on unreachable" decision.
	//
	// The supervisor stops the proxies in reverse order during
	// finalize (teardown step 5 in Plan §5.5) so the most-recently-
	// started listener tears down first.
	ProviderProxies []*secrets.ProviderProxy

	// ControlSocket is the per-run control socket the supervisor starts
	// at canonical pre-launch step 2 (Plan §5.5). Nil = skip the step
	// (legacy callers that do not stand up a per-run control socket
	// keep their existing behavior). When non-nil the supervisor calls
	// Start at step 2, emits `control_socket_started`, flips
	// AcceptingShutdown at teardown step 2, and calls Stop at teardown
	// step 8 with a matching `control_socket_stopped` verb.
	//
	// The supervisor does NOT mint the socket itself: the construction
	// site (NewControlSocket + RegisterServerToken) is the caller's
	// responsibility so the same socket can be referenced by the
	// MCPGatewayMaterializer and by the agent-env wiring without the
	// supervisor learning the per-server registry.
	ControlSocket *ControlSocket

	// EgressObserver is the per-run packet-log reader the supervisor
	// attaches at canonical pre-launch step 5 (Plan §5.5). Nil = skip
	// the step entirely. Concrete observers (Linux NFLOG, macOS pflog)
	// are constructed by `egress.ChooseObserver` in a future batch;
	// today the supervisor accepts any value that implements
	// `egress.EgressObserver`.
	//
	// Start failures are gated by EgressObserverMode: Strict aborts the
	// run with StateFailedBackend; Auto / Disabled degrade by emitting
	// `observer_unavailable` and continuing. The supervisor stops the
	// observer at teardown step 4 with a matching `observer_stopped`
	// verb.
	EgressObserver egress.EgressObserver

	// EgressObserverMode is the operator-configured policy that gates
	// observer-start failures. Defaults to
	// `egress.DefaultEgressObserverMode` (Auto) when zero-valued.
	// Strict requires the observer; Auto / Disabled degrade.
	EgressObserverMode egress.EgressObserverMode

	// EgressRules is the per-run iptables / pf rule lifecycle the
	// supervisor installs at canonical pre-launch step 7 (Plan §5.5)
	// and uninstalls at teardown step 3. Nil = skip the step (legacy
	// callers).
	//
	// Install failures are fail-closed (StateFailedPolicy /
	// StopReasonPolicyFailure) per the plan's "Fail closed: if the
	// backend cannot apply the requested network policy, autonomous
	// mode must fail" rule. `rules.ErrUnsupportedOS` is treated as a
	// graceful no-op so a non-Linux/non-Darwin host (CI runner) can
	// still run the supervisor without spurious aborts.
	EgressRules *rules.Lifecycle

	// MCPGatewayMaterializer is the closure invoked at canonical
	// pre-launch step 9 (Plan §5.5) to write the per-run
	// `mcp-servers.json` + `mcp-servers.real.json` + `.helper-token`
	// files. The closure receives the configured ControlSocket so it
	// can mint per-server tokens; production callers pass
	// `MaterializePerRunMCPConfig`'s closure form. A non-nil closure
	// that returns an error aborts the run with StateFailedBackend.
	//
	// The supervisor stores the returned PerRunMCPConfig on the
	// supervisor's `perRunMCP` field so a future teardown step can
	// reference the on-disk paths; today the field is only consumed by
	// the `gateway_started` lifecycle verb's metadata.
	MCPGatewayMaterializer func(*ControlSocket) (PerRunMCPConfig, error)

	// MCPGatewayCloser is the closure invoked at canonical teardown
	// step 6 (Plan §5.5) to stop the MCP gateway logger / writer. The
	// production caller passes `RunGateway.Close` (which lives in
	// internal/cli to avoid an import cycle into the run package). A
	// nil closer is fine when the materializer did not allocate a
	// closeable resource (e.g. test fixtures that only write the
	// on-disk files via the materializer).
	MCPGatewayCloser func() error

	// WorkspaceMCPRoot is the absolute path of the workspace directory
	// the supervisor inspects at canonical pre-launch step 3 (Plan §5.5)
	// for workspace-local MCP configs (`.mcp.json`,
	// `.claude/settings.json` with `mcpServers`). When non-empty the
	// supervisor renames matching files to `.ai-env-shadowed`,
	// records `mcp_config_neutralized` lifecycle verbs, and restores
	// the files at canonical teardown step 7. An empty path skips the
	// shadow step entirely (legacy callers without a workspace
	// context).
	WorkspaceMCPRoot string

	// BackendCreate is the closure invoked at canonical pre-launch
	// step 3 (Plan §5.5) to call `backend.Create` with the full
	// BindMounts list. The supervisor calls this AFTER the workspace
	// MCP shadow has been recorded so the bind-mount layout includes
	// the shadowed files' targets. A non-nil closure that returns an
	// error aborts with StateFailedBackend.
	//
	// Nil = skip; legacy callers that drive backend.Create out of band
	// (the existing plan-04 supervisor wires Backend.Exec only) keep
	// their existing behavior.
	BackendCreate func() error

	// BackendStart is the closure invoked at canonical pre-launch
	// step 5 (Plan §5.5) to call `backend.Start` so the netns gets
	// assigned before the EgressObserver attaches. Nil = skip; the
	// EgressObserver still attaches at the same canonical point, but
	// it must already be configured against a netns the caller stood
	// up out of band.
	BackendStart func() error

	// BackendDestroy is the closure invoked at canonical teardown
	// step 7 (Plan §5.5) to call `backend.Stop + Destroy`. Errors are
	// surfaced via UserOutput as warnings (never escalated). Nil =
	// skip; legacy callers handle Destroy at the CLI level.
	BackendDestroy func() error

	// ShimHelperCmd is the command line the wrapper scripts re-exec via
	// `exec` inside the sandbox. Defaults to DefaultShimHelperCmd
	// (`/usr/local/bin/ai-env shim-helper`) when empty: that is the
	// in-sandbox path the `ai-env` binary is bind-mounted at per the
	// plan's canonical pre-launch step 3 mount split. Tests override the
	// value to point at a host-side test stub when they want to drive
	// the wrapper end-to-end without standing up a backend; production
	// callers leave it empty so the default in-sandbox path is used.
	//
	// Ignored when ShellShim is false; the supervisor only materializes
	// wrappers when the shim is wired.
	ShimHelperCmd string
}

// SupervisorResult is the outcome the supervisor reports back from Run.
// It mirrors the run.json snapshot at terminal time but is materialized
// as a Go value so a caller (the CLI) can branch on it without re-
// reading the file. Every field is filled in by the time Run returns,
// regardless of whether the terminal was a success or a failure.
type SupervisorResult struct {
	// FinalState is the terminal state the run landed in. The CLI maps
	// this to an exit code; tests assert on it directly.
	FinalState State

	// StopReason is the StopReason recorded in run.json. Mirrors
	// StopReasonForState(FinalState) under normal circumstances; kept
	// as a field so future custom reasons (a specific scanner verdict)
	// can override the default mapping without breaking callers.
	StopReason StopReason

	// ExitCode is the child process exit code. Negative when the
	// process never produced one (signal kill, exec failure); the
	// caller decides how to surface that. Pointer-free here because
	// the supervisor always knows whether a child ran by the time
	// Run returns.
	ExitCode int

	// HasExitCode reports whether ExitCode reflects a real os.exec
	// reported value. False when the process was force-killed before
	// it reported, or when launch itself failed.
	HasExitCode bool

	// StartedAt is when the run transitioned out of StateCreated, i.e.
	// the wall-clock the lifecycle's first non-created event was
	// stamped. Zero when the supervisor failed before that transition.
	StartedAt time.Time

	// StoppedAt is when the run reached its terminal state. Always
	// non-zero by the time Run returns.
	StoppedAt time.Time

	// ContinueSuggestion is the exact `--continue` command the user can
	// re-run when the terminal supports continuation. Empty for
	// terminals that do not (StateCompleted, the failure terminals).
	// The supervisor also writes the same text to UserOutput when it is
	// non-nil; the result field exists so programmatic callers (a
	// future TUI, a structured-output CLI mode) can surface the
	// suggestion without scraping stdout.
	ContinueSuggestion string

	// PartialDiffPath is the absolute path of the run directory's
	// git-diff.patch file. The supervisor always populates this on
	// terminal so a caller can locate the diff without re-deriving the
	// layout. The file may be zero bytes (no collector configured, or
	// collector returned no changes); it is always present.
	PartialDiffPath string
}

// Supervisor owns one run's main loop. It is constructed once per run
// (see NewSupervisor) and driven exactly once by Run. After Run returns
// the Supervisor is consumed: further calls to Run return an error.
//
// Concurrency: Cancel is safe to call from any goroutine, before or
// during Run. Stop is the alias the signal-handling step (step 9) will
// hook into; both reduce to the same internal request, namely "land on
// StateKilledByUser as soon as you can". Multiple Cancel calls collapse
// to the first one.
//
// What the supervisor deliberately does NOT do in this batch:
//
//   - implement `ai-env status` / `logs` / `list` (those are batch 7).
//   - re-link to a previous run beyond echoing the field through
//     LinkedPreviousRun (that is step 14).
//
// Each of those leaves a clean extension point on this type but no
// behaviour today.
//
// OS signal handlers are installed by InstallSignalHandlers (step 9),
// which routes SIGINT / SIGTERM / SIGHUP into Cancel. Partial-diff
// collection and the `--continue` suggestion (step 10) run inside
// finalizeTerminal so they share the orderly shutdown path; see the
// DiffCollector and UserOutput fields on SupervisorOptions for the
// extension seams.
type Supervisor struct {
	opts SupervisorOptions

	machine *Machine
	lcWri   *LifecycleWriter
	netWri  *NetworkEventsWriter
	pdWri   *PolicyDecisionsWriter
	streams *StreamCapture

	// shellCmdLog, when non-nil, is the per-run shell-commands.jsonl
	// writer the shim appends to. It is opened by NewSupervisor only
	// when SupervisorOptions.ShellShim is true and closed alongside the
	// other per-run JSONL writers in Run's deferred drain. A nil log
	// (the legacy default) means the supervisor was not asked to wire
	// the shim; no shell-commands.jsonl is materialized in the run
	// directory.
	shellCmdLog *policy.ShellCommandsLog

	// engine, when non-nil, is the policy engine the supervisor
	// consults for runtime decisions (EvaluateNetworkDomain,
	// EvaluateShellCommand). It is wired by NewSupervisor either from
	// SupervisorOptions.PolicyEngine (already-constructed) or by
	// loading SupervisorOptions.PolicyEnginePath. A nil engine means
	// no policy was configured for this run; the EvaluateX helpers
	// degrade to no-ops in that case so legacy supervisor callers
	// (plan-03 / plan-04 / plan-05 tests) continue to pass.
	engine PolicyEngine

	now func() time.Time

	// cancelCh is closed by Cancel to ask the main loop to stop. The
	// loop selects on this channel from every blocking operation that
	// can sensibly be interrupted. A channel is used (rather than a
	// context.Context only) because the supervisor accepts both a
	// caller-supplied context and a host-side Cancel, and merging them
	// into one signal upstream keeps the loop's select statements
	// readable.
	cancelCh   chan struct{}
	cancelOnce sync.Once

	// stopReason is set by whichever path (timeout, idle, cancel, exit)
	// decides the run's terminal. The main loop reads it after the
	// child exits to choose the right terminal state. atomic.Value
	// because the timer goroutine and the wait goroutine race on it.
	terminalCause atomic.Value // holds terminalCause

	// ran reports whether Run has been called. The supervisor is
	// single-shot; a second Run would race with the first's file
	// handles and lifecycle writer.
	ranMu sync.Mutex
	ran   bool

	// childMu serializes access to the running exec.Cmd's Process
	// handle across the main loop and the kill paths. The std library
	// already protects exec.Cmd against most races, but signalling
	// Process directly while the wait goroutine reaps it is a known
	// edge case; the mutex collapses both sides onto one path.
	//
	// The same mutex also guards the Backend.Exec bookkeeping
	// (backendResult, backendExecErr) so the runLoop's stop / collect
	// helpers can take a single lock regardless of which exec path is
	// in flight. Exactly one of child / backendActive is meaningful at
	// any time, set by launchChild based on opts.BackendAdapter.
	childMu   sync.Mutex
	child     *exec.Cmd
	childErr  error
	childDone chan struct{}
	waitOnce  sync.Once

	// backendActive reports whether the exec is in flight through
	// Backend.Exec rather than a host exec.Cmd. When true, child is nil
	// and the backend goroutine writes backendResult / backendExecErr
	// under childMu before closing childDone.
	backendActive bool

	// backendResult is the ExecResult Backend.Exec returned. Written by
	// the backend-exec goroutine under childMu before closing
	// childDone; read by collectExit afterwards.
	backendResult backend.ExecResult

	// backendExecErr is the spawn-side error Backend.Exec returned (a
	// non-nil error here is the equivalent of exec.Cmd.Wait returning a
	// non-ExitError). The runLoop maps a non-nil err with no exit code
	// to StateFailedAgent.
	backendExecErr error

	// backendStopped guards Backend.Stop so the cancel + timeout + idle
	// paths can all request a stop without racing the adapter into a
	// double-stop. The Stop call itself is idempotent on every adapter we
	// ship but the contract does not require it; we serialize here so
	// future adapters can rely on at-most-one-Stop semantics.
	backendStopped bool

	// startedAt and stoppedAt are stamped by the main loop and
	// surfaced via the result.
	startedAt time.Time
	stoppedAt time.Time

	// startedProxies is the slice of ProviderProxy instances Start
	// returned successfully. The supervisor stores them between
	// step 8 (Plan §5.5) and the terminal teardown so finalizeTerminal
	// can stop them in reverse order with the matching proxy_stopped
	// lifecycle verbs. Empty / nil when no proxies were configured.
	startedProxies []*secrets.ProviderProxy

	// controlSocketStarted is true between a successful
	// ControlSocket.Start (canonical pre-launch step 2) and
	// ControlSocket.Stop (canonical teardown step 8). Tracked so the
	// rollback / teardown helpers can decide whether the `_stopped`
	// verb fires.
	controlSocketStarted bool

	// observerStarted is the symmetric flag for the EgressObserver
	// (canonical step 5 / teardown step 4).
	observerStarted bool

	// rulesInstalled is true between a successful EgressRules.Install
	// (canonical step 7) and Uninstall (canonical teardown step 3).
	rulesInstalled bool

	// gatewayStarted is true between a successful
	// MCPGatewayMaterializer (canonical step 9) and the matching
	// teardown step 6.
	gatewayStarted bool

	// shadowEntries records the workspace MCP-config files the
	// supervisor renamed to `.ai-env-shadowed` at canonical step 3.
	// finalizeTerminal restores them at canonical teardown step 7 via
	// RestoreWorkspaceMCPConfig.
	shadowEntries []ShadowEntry

	// perRunMCP captures the PerRunMCPConfig the MCPGatewayMaterializer
	// returned. Surfaced on the supervisor for future readers (e.g. a
	// teardown step that emits per-server cleanup verbs); today it
	// only feeds the `gateway_started` verb metadata.
	perRunMCP PerRunMCPConfig
}

// terminalCause is the internal reason the main loop will pick for the
// terminal state when the child finally exits or is killed. Captured by
// the timer / cancel goroutines before they signal the child so the
// post-wait code can map "we killed it" back to the right terminal.
type terminalCause struct {
	// state is the terminal State to record. Used by the post-wait
	// code instead of inferring from exit code alone.
	state State

	// reason is the StopReason to record alongside state.
	reason StopReason

	// note is a short human-readable note that ends up in the run's
	// log for debugging; not persisted anywhere user-visible today.
	note string
}

// NewSupervisor constructs a Supervisor from the supplied options. It
// performs option validation and the per-run resource setup (lifecycle
// writer, stream capture) that Run will consume.
//
// On any failure the partially-opened resources are torn down so a
// retry can start from a clean slate. Callers that get an error must
// not call Run on the returned (zero) Supervisor.
func NewSupervisor(opts SupervisorOptions) (*Supervisor, error) {
	if opts.RunDir == "" {
		return nil, errors.New("run: NewSupervisor requires RunDir")
	}
	if opts.RunID == "" {
		return nil, errors.New("run: NewSupervisor requires RunID")
	}
	if opts.EnvName == "" {
		return nil, errors.New("run: NewSupervisor requires EnvName")
	}
	if opts.Backend == "" {
		return nil, errors.New("run: NewSupervisor requires Backend")
	}
	if opts.Agent == "" {
		return nil, errors.New("run: NewSupervisor requires Agent")
	}
	if opts.Task == "" {
		return nil, errors.New("run: NewSupervisor requires Task")
	}
	if opts.Command.Program == "" {
		return nil, errors.New("run: NewSupervisor requires Command.Program")
	}
	if opts.BackendAdapter != nil && opts.BackendEnvID == "" {
		// A Backend without an envID would crash at Exec time inside the
		// adapter (every shipped adapter rejects an unknown / empty
		// envID). Failing fast at construction keeps the error surface
		// close to the misuse instead of mid-run.
		return nil, errors.New("run: NewSupervisor requires BackendEnvID when BackendAdapter is set")
	}
	if opts.MaxRuntime < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: MaxRuntime must be non-negative, got %v", opts.MaxRuntime)
	}
	if opts.IdleTimeout < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: IdleTimeout must be non-negative, got %v", opts.IdleTimeout)
	}
	if opts.StatsPollInterval < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: StatsPollInterval must be non-negative, got %v", opts.StatsPollInterval)
	}
	if opts.StopGracePeriod < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: StopGracePeriod must be non-negative, got %v", opts.StopGracePeriod)
	}
	if opts.DiffTimeout < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: DiffTimeout must be non-negative, got %v", opts.DiffTimeout)
	}
	if opts.ScanTimeout < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: ScanTimeout must be non-negative, got %v", opts.ScanTimeout)
	}
	if opts.PolicyEnginePath != "" && opts.PolicyEngine != nil {
		// Plan 08 step 7 expects exactly one source of truth for the
		// engine. Rejecting both up front prevents a silent precedence
		// rule that would surprise an operator who wired both for
		// different reasons.
		return nil, errors.New("run: NewSupervisor: PolicyEnginePath and PolicyEngine are mutually exclusive")
	}
	if opts.ShellShim && strings.TrimSpace(opts.ShellShimDir) == "" {
		// Plan 08 step 9 wires the shim only when the caller also tells
		// the supervisor where the wrapper binary lives. The supervisor
		// does not invent a directory: the future `ai-env run` CLI and
		// test fixtures both pin the location explicitly. Failing fast
		// here keeps the misuse surface close to the misconfiguration
		// rather than mid-launch (the PATH mutation would otherwise
		// silently no-op and the agent would call real bash directly).
		return nil, errors.New("run: NewSupervisor: ShellShim requires ShellShimDir")
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if opts.ModelCredentialMode == "" {
		opts.ModelCredentialMode = ModelCredentialBackendManaged
	}
	if opts.StatsPollInterval == 0 {
		opts.StatsPollInterval = defaultStatsPollInterval
	}
	if opts.StopGracePeriod == 0 {
		opts.StopGracePeriod = defaultStopGracePeriod
	}

	machine, err := NewMachine(StateCreated)
	if err != nil {
		return nil, fmt.Errorf("run: NewSupervisor: %w", err)
	}

	// Plan §0.2 (Batch 0.2): sweep stale `leaks.jsonl.tmp.*` files
	// from a previously crashed run before any per-run writer opens.
	// A stale tmp would otherwise block OpenLeaksWriter's O_EXCL the
	// first time the leaks aggregator (Batch 8.1) tries to stage a
	// fresh write. We pass `now()` as the cutoff so a tmp the current
	// process is about to create (impossible here — Open has not been
	// called yet — but defensive against future re-entrant callers) is
	// preserved. CleanupStaleLeaksTemp tolerates a missing runDir and
	// per-entry errors; we surface the aggregate as a non-fatal
	// warning channel later via the lifecycle writer, but for v0.1 a
	// failure here aborts construction so a misconfigured runDir is
	// loud at the same site as the writer opens below.
	if _, err := CleanupStaleLeaksTemp(opts.RunDir, now()); err != nil {
		return nil, fmt.Errorf("run: cleanup stale leaks tmp: %w", err)
	}

	lcWri, err := OpenLifecycleWriter(opts.RunDir, LifecycleWriterOptions{
		RunID:   opts.RunID,
		Backend: opts.Backend,
		Agent:   opts.Agent,
		Now:     now,
	})
	if err != nil {
		return nil, err
	}

	// Open the network-events.jsonl writer alongside the lifecycle
	// writer. The two log files share a lifetime: both are opened here,
	// both are closed in Run's deferred drain, and both must be on disk
	// before any setup-stage transition writes its first event. Failing
	// here aborts construction so a misconfigured runDir surfaces at the
	// same site as the lifecycle writer (rather than later, mid-run, the
	// first time the supervisor tries to record a network event).
	netWri, err := OpenNetworkEventsWriter(opts.RunDir, NetworkEventsWriterOptions{
		RunID:   opts.RunID,
		Backend: opts.Backend,
		Now:     now,
	})
	if err != nil {
		_ = lcWri.Close()
		return nil, err
	}

	streamOpts := opts.StreamOptions
	if streamOpts.Now == nil {
		streamOpts.Now = now
	}
	streams, err := OpenStreamCapture(opts.RunDir, streamOpts)
	if err != nil {
		_ = netWri.Close()
		_ = lcWri.Close()
		return nil, err
	}

	// Plan 08 step 7: load the env's policy file before starting the
	// sandbox so a malformed policy aborts the run with a clear error
	// rather than crashing mid-execution. We do the load here, after
	// the lifecycle / network / stream writers are open, so an
	// operator's "supervisor failed to construct" report still shows
	// the same fail-fast surface for all setup errors. A malformed
	// policy at this stage tears down the writers below and returns
	// the underlying parse / validate error verbatim.
	engine := opts.PolicyEngine
	if engine == nil && opts.PolicyEnginePath != "" {
		loaded, _, loadErr := LoadPolicyEngine(opts.PolicyEnginePath)
		if loadErr != nil {
			_ = streams.Close()
			_ = netWri.Close()
			_ = lcWri.Close()
			return nil, loadErr
		}
		engine = loaded
	}

	// Plan 08 step 7: open the per-run policy-decisions.jsonl writer
	// whenever an engine is configured so every EvaluateNetworkDomain
	// / EvaluateShellCommand call lands a record on disk. We open the
	// writer alongside the lifecycle / network writers so the three
	// share a lifetime: all opened here, all closed in Run's deferred
	// drain. When no engine is wired the writer stays nil and the
	// EvaluateX helpers degrade to no-ops, which preserves the legacy
	// supervisor behavior the plan-03 / plan-04 / plan-05 tests rely
	// on.
	var pdWri *PolicyDecisionsWriter
	if engine != nil {
		pdWri, err = OpenPolicyDecisionsWriter(opts.RunDir, PolicyDecisionsWriterOptions{
			RunID: opts.RunID,
			Now:   now,
		})
		if err != nil {
			_ = streams.Close()
			_ = netWri.Close()
			_ = lcWri.Close()
			return nil, err
		}
	}

	// Plan 08 step 9: wire the optional shell-shim prototype. When
	// ShellShim is true the supervisor (a) requires a configured
	// engine, (b) opens shell-commands.jsonl in the run directory, and
	// (c) prepends ShellShimDir to the child's PATH so the wrapper
	// binary resolves before the real system binary. The wiring is
	// performed here so any setup error tears down the writers opened
	// above; this keeps the fail-fast surface uniform with the other
	// per-run writers. Validation that ShellShim implies engine lives
	// alongside the helpers in shim_wire.go.
	var shellCmdLog *policy.ShellCommandsLog
	if opts.ShellShim {
		if err := validateShellShimOptions(opts, engine); err != nil {
			if pdWri != nil {
				_ = pdWri.Close()
			}
			_ = streams.Close()
			_ = netWri.Close()
			_ = lcWri.Close()
			return nil, err
		}
		shellCmdLog, err = openShellCommandsLog(opts.RunDir, opts.RunID, now)
		if err != nil {
			if pdWri != nil {
				_ = pdWri.Close()
			}
			_ = streams.Close()
			_ = netWri.Close()
			_ = lcWri.Close()
			return nil, err
		}
		// Plan §5.5 step 10 / Batch 1.4: materialize per-program wrapper
		// scripts in ShellShimDir so PATH resolution lands on the shim
		// before the real system binary. The supervisor owns this side
		// of the wiring (the directory is the caller's, the wrappers are
		// the supervisor's); the wrappers are static templates and any
		// failure aborts construction so an operator does not silently
		// run with a degraded shim surface. The HelperCmd is the
		// in-sandbox `ai-env shim-helper` invocation per the plan's
		// canonical mount layout; an empty ShimHelperCmd falls back to
		// DefaultShimHelperCmd so production callers do not have to
		// duplicate the constant.
		if err := installShimWrappers(opts.ShellShimDir, opts.ShimHelperCmd); err != nil {
			if shellCmdLog != nil {
				_ = shellCmdLog.Close()
			}
			if pdWri != nil {
				_ = pdWri.Close()
			}
			_ = streams.Close()
			_ = netWri.Close()
			_ = lcWri.Close()
			return nil, err
		}
		// Plan Batch 1.3: "Host-mode runs emit shim_coverage_degraded
		// lifecycle." Host mode (no BackendAdapter wired) means the
		// supervisor has no sandbox to install the canonical absolute-
		// path shadow mounts into; the shim's coverage is limited to
		// PATH-relative resolution only. Emitting the verb here makes
		// the degradation auditable at the same point the operator can
		// remediate it (wire a backend). The verb is emitted once per
		// run with Metadata describing the missing canonical paths so
		// `ai-env leaks` / the doctor remediation table can map the
		// run's degraded surface to the canonical path set the plan
		// pins.
		if opts.BackendAdapter == nil {
			if err := emitShimHostModeDegraded(lcWri); err != nil {
				if shellCmdLog != nil {
					_ = shellCmdLog.Close()
				}
				if pdWri != nil {
					_ = pdWri.Close()
				}
				_ = streams.Close()
				_ = netWri.Close()
				_ = lcWri.Close()
				return nil, err
			}
		}
		// Mutate the child's PATH so the shim directory resolves first.
		// We rewrite opts.Command.Env in place on the SupervisorOptions
		// value the supervisor stores so launchChildHost /
		// launchChildBackend see the updated slice without an extra
		// indirection. The original caller's slice is not aliased: the
		// helper copies before mutating.
		opts.Command.Env = InjectShimPath(opts.Command.Env, opts.ShellShimDir)
	}

	return &Supervisor{
		opts:        opts,
		machine:     machine,
		lcWri:       lcWri,
		netWri:      netWri,
		pdWri:       pdWri,
		streams:     streams,
		shellCmdLog: shellCmdLog,
		engine:      engine,
		now:         now,
		cancelCh:    make(chan struct{}),
	}, nil
}

// Cancel asks the supervisor to terminate the run as if a user-driven
// signal had arrived. It is safe to call from any goroutine, before or
// during Run, and from multiple goroutines concurrently. Only the first
// call has any effect; later calls are no-ops.
//
// Cancel returns immediately; the actual terminal landing happens on
// the main loop's next select. The terminal state will be
// StateKilledByUser unless an earlier cause (timeout, idle, exit)
// already won the race.
//
// Step 9 (signal handling) installs OS signal handlers and points them
// at Cancel; nothing in step 8 invokes it from production code yet.
func (s *Supervisor) Cancel() {
	s.cancelOnce.Do(func() {
		// Record an intent to land on StateKilledByUser. If a competing
		// cause (timeout, idle, exit) has already recorded its own
		// terminalCause, this CompareAndSwap loses the race and we keep
		// the earlier reason; that mirrors the plan's "whichever wins
		// first decides the terminal" rule.
		s.recordTerminalCause(terminalCause{
			state:  StateKilledByUser,
			reason: StopReasonSignal,
			note:   "cancel requested",
		})
		close(s.cancelCh)
	})
}

// Stop is the alias step 9 (signal handling) will wire into. Today it
// is exactly Cancel; we expose it under the second name so the signal
// handler does not have to import "Cancel" by another spelling and so
// callers reading the public surface see both the "user cancelled"
// (Cancel) and "graceful stop" (Stop) intents the plan distinguishes.
// They have the same semantics in step 8; step 9 may differentiate.
func (s *Supervisor) Stop() {
	s.Cancel()
}

// Run drives the main loop end to end. It walks the state machine from
// StateCreated through every transient stage to a terminal state,
// writes lifecycle.jsonl events on every transition, rewrites run.json
// on every transition, launches the child process during
// StateStartingAgent, enforces the max-runtime and idle timeouts during
// StateRunning, and tears down resources (streams, lifecycle writer)
// before returning.
//
// Run is single-shot. A second call returns an error rather than
// re-driving the loop, because the lifecycle writer and stream capture
// resources have already been closed.
//
// The supplied context.Context is honored as a cancellation source in
// addition to s.Cancel(); a context cancellation lands on
// StateKilledByUser the same way an explicit Cancel does. Pass
// context.Background() for callers that have no upstream cancellation.
//
// Run returns an error only when the supervisor itself cannot make
// progress (lifecycle writer failure, stream writer failure, missing
// run directory). A terminal that records a failure state
// (StateFailedAgent, StateTimedOut, ...) is NOT returned as an error;
// the caller inspects SupervisorResult.FinalState to learn the outcome.
// This split mirrors the rest of the project: errors are "the
// supervisor could not do its job"; failure states are "the supervisor
// did its job and the run failed".
func (s *Supervisor) Run(ctx context.Context) (SupervisorResult, error) {
	if err := s.markRan(); err != nil {
		return SupervisorResult{}, err
	}
	// Resource cleanup always happens, even on the error paths. Close
	// is idempotent on every writer so the deferred Close inside Run
	// does not double-free if Run already closed explicitly. The
	// network-events writer is closed alongside the lifecycle writer:
	// both files share a per-run lifetime and both must flush their
	// last record before Run returns so an observer reading the run on
	// disk sees the terminal state and any late policy / outbound
	// events together.
	defer func() {
		_ = s.streams.Close()
		_ = s.netWri.Close()
		if s.pdWri != nil {
			_ = s.pdWri.Close()
		}
		if s.shellCmdLog != nil {
			_ = s.shellCmdLog.Close()
		}
		_ = s.lcWri.Close()
	}()

	// Wire the caller's context into the same cancel signal Cancel()
	// drives. We spawn one goroutine that waits on ctx.Done and calls
	// Cancel if the context cancels before the run finishes. The
	// goroutine exits as soon as either the context fires or the
	// supervisor's local done channel closes (which happens when Run
	// returns), so it does not leak.
	runDone := make(chan struct{})
	defer close(runDone)
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				s.Cancel()
			case <-runDone:
			}
		}()
	}

	// Plan §5.5 — canonical 11-step pre-launch sequence. The helper
	// walks every step in strict order, performs fail-closed rollback
	// on any failure, and returns a sequenceError carrying the
	// terminal cause the run should land on.
	if seqErr := s.preLaunchSequence(ctx); seqErr != nil {
		return s.finalizeTerminal(seqErr.terminalCause(), exitInfo{}), nil
	}

	// Launch the child. A launch failure (e.g. binary missing) is a
	// StateFailedAgent terminal: the supervisor did its job, but the
	// run could not get off the ground.
	if err := s.launchChild(); err != nil {
		cause := terminalCause{state: StateFailedAgent, reason: StopReasonAgentFailure, note: fmt.Sprintf("exec failed: %v", err)}
		return s.finalizeTerminal(cause, exitInfo{}), nil
	}

	// Transition to StateRunning now that the child is in flight.
	if err := s.enterSetup(StateRunning); err != nil {
		// We are mid-run with a child process holding our streams. Kill
		// it so we do not leak; the resulting terminal is StateFailedAgent
		// because we never managed to record the run state cleanly.
		s.hardKillChild()
		_, _ = s.waitChild()
		cause := terminalCause{state: StateFailedAgent, reason: StopReasonAgentFailure, note: "lifecycle write failed during running"}
		return s.finalizeTerminal(cause, s.collectExit()), err
	}

	// Main loop: poll stats, wait for the child to exit, enforce
	// max-runtime and idle timeouts, honor Cancel. The loop returns the
	// terminalCause that won the race; the post-loop code maps it to
	// the final state.
	cause := s.runLoop()

	// Wait for the child to actually exit (it may already have done so;
	// waitChild collapses both cases).
	exit := s.collectExit()

	// Transition through the rest of the state machine. The exact path
	// depends on the terminal cause: a clean exit walks
	// running -> stopping -> scanning -> reporting -> completed; a
	// timeout / kill / idle goes running -> <terminal> directly.
	final := s.driveTerminalSequence(cause, exit)

	result := s.finalizeTerminal(final, exit)
	return result, nil
}

// markRan flips the single-shot guard. The second caller sees an
// error rather than racing with the first call's file handles.
func (s *Supervisor) markRan() error {
	s.ranMu.Lock()
	defer s.ranMu.Unlock()
	if s.ran {
		return errors.New("run: Supervisor.Run already called")
	}
	s.ran = true
	return nil
}

// recordTerminalCause atomically stores cause if no earlier cause has
// been recorded. First writer wins; later writers are dropped. The
// supervisor's main loop reads the stored cause via takeTerminalCause.
func (s *Supervisor) recordTerminalCause(cause terminalCause) {
	// CompareAndSwap-style logic: only set if nothing is set yet.
	// atomic.Value rejects nil so we use a zero value sentinel via the
	// stored interface{}.
	s.terminalCause.CompareAndSwap(nil, cause)
}

// takeTerminalCause returns the stored cause, falling back to def when
// none has been recorded. Does not consume the value; later reads see
// the same result. Callers that need to know whether a cause was
// recorded compare the result to def.
func (s *Supervisor) takeTerminalCause(def terminalCause) terminalCause {
	v := s.terminalCause.Load()
	if v == nil {
		return def
	}
	c, ok := v.(terminalCause)
	if !ok {
		return def
	}
	return c
}

// checkCancel reports whether Cancel has been requested. Used between
// setup stages so a cancel during workspace prep lands on
// StateKilledByUser instead of marching all the way to StateRunning.
func (s *Supervisor) checkCancel() bool {
	select {
	case <-s.cancelCh:
		return true
	default:
		return false
	}
}

// enterSetup transitions the machine into next and writes the
// corresponding lifecycle event + run.json snapshot. It is the shared
// helper for every non-terminal transition the supervisor performs
// during the setup phase. Returns an error if the machine refuses the
// transition (programming bug) or if the lifecycle write fails (I/O).
//
// run.json writes are NOT fatal in the same sense: a failure here
// surfaces as an error, but the run continues; the next run.json
// snapshot will land the latest state. The lifecycle event must be
// durable because the post-mortem audit log depends on it.
func (s *Supervisor) enterSetup(next State) error {
	if err := s.machine.Transition(next); err != nil {
		return err
	}
	if s.startedAt.IsZero() {
		// First non-created transition stamps the run's start time. We
		// use the supervisor's clock so tests can pin it.
		s.startedAt = s.now()
	}
	if err := s.lcWri.Write(next); err != nil {
		return err
	}
	if err := s.writeRecordSnapshot(next, nil, nil, nil); err != nil {
		// run.json failure is informational here; we do not stop the
		// run. The next snapshot will overwrite the broken file.
		return nil
	}
	return nil
}

// applyNetworkPolicy installs the configured network policy via
// opts.NetworkPolicyAdapter.Apply. It is the supervisor's fail-closed
// hook for plan 05 step 4: the master plan's section 18 rule "Fail
// closed: if the backend cannot apply the requested network policy,
// autonomous mode must fail. Not silently degrade." is enforced here.
//
// When NetworkPolicyAdapter is nil the helper returns nil so the
// supervisor's legacy callers (plan-03 / plan-04 tests that do not
// construct a policy adapter) continue to walk through
// StateApplyingPolicy as a lifecycle stamp only. Production CLI call
// sites (added by later plan-05 batches) always supply an adapter, so
// the nil path is a test convenience, not a runtime escape hatch.
//
// The envID passed to Apply is NetworkPolicyEnvID when set; the
// supervisor falls back to BackendEnvID otherwise (the common case
// where the policy target and the exec sandbox share an identifier).
// A configured adapter with no envID at all is rejected with an error
// so the failure is loud rather than silently applying to the empty
// string, which every shipped adapter already rejects.
//
// A non-nil return aborts the run with StateFailedPolicy /
// StopReasonPolicyFailure; the caller does NOT proceed to
// StateStartingAgent. applyNetworkPolicy itself does not transition
// the state machine; that is the caller's responsibility via
// finalizeTerminal, which keeps the apply helper free of lifecycle
// I/O and matches the rest of the supervisor's "helper computes,
// caller transitions" pattern.
func (s *Supervisor) applyNetworkPolicy() error {
	if s.opts.NetworkPolicyAdapter == nil {
		return nil
	}
	envID := s.opts.NetworkPolicyEnvID
	if envID == "" {
		envID = s.opts.BackendEnvID
	}
	if envID == "" {
		return errors.New("run: NetworkPolicyAdapter configured without NetworkPolicyEnvID or BackendEnvID")
	}

	// Record the policy-install attempt before invoking the adapter so
	// the on-disk trail carries the intended policy snapshot even when
	// Apply errors before emitting its own event (plan 05 step 6:
	// "receives events from backend where available" - the supervisor
	// always fills in the policy-lifecycle half itself). Errors from
	// the writer are best-effort: a network-events log that cannot
	// accept the attempt event must not gate the actual policy install,
	// or a degraded log surface would erase the egress controls the
	// plan requires. The lifecycle.jsonl trail still records the
	// terminal in StateFailedPolicy / completed so an operator is never
	// blind to what happened.
	_ = s.writeNetworkEvent(NetworkEvent{
		Event:        NetworkEventPolicyApplyAttempt,
		EnvID:        envID,
		Backend:      s.opts.NetworkPolicyAdapter.Name(),
		Default:      s.opts.NetworkPolicy.Default,
		AllowDomains: append([]string(nil), s.opts.NetworkPolicy.AllowDomains...),
		BlockedCIDRs: s.opts.NetworkPolicy.BlockedCIDRs(),
		BlockedHosts: s.opts.NetworkPolicy.BlockedHosts(),
	})

	if err := s.opts.NetworkPolicyAdapter.Apply(envID, s.opts.NetworkPolicy); err != nil {
		// Failure event carries the same policy snapshot so a reader
		// who tails network-events.jsonl sees both halves of the
		// attempt without having to cross-reference an earlier record.
		// The supervisor returns the err verbatim: the caller in Run
		// turns it into StateFailedPolicy / StopReasonPolicyFailure.
		_ = s.writeNetworkEvent(NetworkEvent{
			Event:        NetworkEventPolicyApplyFailed,
			EnvID:        envID,
			Backend:      s.opts.NetworkPolicyAdapter.Name(),
			Default:      s.opts.NetworkPolicy.Default,
			AllowDomains: append([]string(nil), s.opts.NetworkPolicy.AllowDomains...),
			BlockedCIDRs: s.opts.NetworkPolicy.BlockedCIDRs(),
			BlockedHosts: s.opts.NetworkPolicy.BlockedHosts(),
			Error:        err.Error(),
		})
		return err
	}

	_ = s.writeNetworkEvent(NetworkEvent{
		Event:        NetworkEventPolicyApplied,
		EnvID:        envID,
		Backend:      s.opts.NetworkPolicyAdapter.Name(),
		Default:      s.opts.NetworkPolicy.Default,
		AllowDomains: append([]string(nil), s.opts.NetworkPolicy.AllowDomains...),
		BlockedCIDRs: s.opts.NetworkPolicy.BlockedCIDRs(),
		BlockedHosts: s.opts.NetworkPolicy.BlockedHosts(),
	})
	return nil
}

// writeNetworkEvent appends evt to the supervisor's network-events.jsonl
// writer. It is the single funnel through which the supervisor (and any
// future backend-event forwarder) records network events: keeping the
// nil-writer guard and the error-swallow policy in one helper means the
// rest of the supervisor body does not have to repeat them.
//
// The writer is constructed in NewSupervisor and is never nil for a
// supervisor built via NewSupervisor; the nil guard exists so a test
// that constructs a Supervisor literal without going through the
// constructor (an unsupported but possible pattern) does not panic on
// the first event.
//
// Errors from the underlying Write are returned to the caller so a
// future emitter that wants to surface a write failure can act on it,
// but the supervisor's own policy-apply call sites swallow the error
// (see applyNetworkPolicy for the reasoning): a network-events log
// failure must not gate the policy install or the terminal walk.
func (s *Supervisor) writeNetworkEvent(evt NetworkEvent) error {
	if s.netWri == nil {
		return nil
	}
	return s.netWri.Write(evt)
}

// launchChild starts the configured command, wires stdout/stderr to the
// stream capture, and stores the result on the supervisor. Returns an
// error if the launch itself fails (binary missing, dir invalid). On
// success the child is running and a single background goroutine is
// reaping it; callers observe its completion via the childDone channel
// and read either childErr or backendExecErr (under childMu) afterwards.
//
// Dispatches on opts.BackendAdapter: when nil the supervisor runs the
// child host-side via exec.Command (the legacy path the plan-03 tests
// use); when non-nil it routes through Backend.Exec (the plan-04 step 8
// wiring). Both paths converge on the same childDone / exit-info
// contract so the runLoop / stop helpers do not need a second select.
func (s *Supervisor) launchChild() error {
	if s.opts.BackendAdapter != nil {
		return s.launchChildBackend()
	}
	return s.launchChildHost()
}

// launchChildHost is the legacy host-side exec.Command path. It is used
// by the run-package unit tests that drive the supervisor against a
// real subprocess (sh -c ...) without constructing a mock backend.
//
// We own the Wait call here (rather than letting individual stop
// helpers spawn their own) because exec.Cmd.Wait can only be called
// once and races with any other observer touching ProcessState. The
// single waiter writes the result; everyone else reads via the
// done channel.
func (s *Supervisor) launchChildHost() error {
	cmd := exec.Command(s.opts.Command.Program, s.opts.Command.Args...)
	cmd.Dir = s.opts.Command.Dir
	cmd.Env = s.opts.Command.Env
	cmd.Stdout = s.streams.Stdout()
	cmd.Stderr = s.streams.Stderr()
	// Run the child in its own process group on POSIX so the kill
	// path can signal the full subtree (shell + grandchildren) and not
	// just the direct child. Without this, a `sh -c "long-cmd"` wrapper
	// that fork+execs the inner command leaves the inner command alive
	// after the shell receives the kill: the inner command keeps the
	// supervisor's stdout pipe open and cmd.Wait blocks until it exits
	// naturally. windows builds get a no-op via applyProcessGroup and
	// the kill path degrades to per-pid delivery.
	applyProcessGroup(cmd)
	// Host fallback: only forward Stdin when the caller explicitly wired
	// one. The legacy behavior was nil (child reads from /dev/null) and
	// the existing plan-03 tests rely on it; an opt-in stdin reader keeps
	// the agent launcher's task-on-stdin contract reachable without
	// changing the no-stdin default the supervisor tests already assume.
	if s.opts.Stdin != nil {
		cmd.Stdin = s.opts.Stdin
	} else {
		cmd.Stdin = nil
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	s.childMu.Lock()
	s.child = cmd
	s.childDone = make(chan struct{})
	s.childMu.Unlock()

	// Start the single waiter. It writes childErr under the mutex and
	// closes childDone exactly once so any number of observers (the
	// runLoop, stopChildGracefully) can wait without racing on the
	// std library's ProcessState writes.
	go func() {
		err := cmd.Wait()
		s.childMu.Lock()
		s.childErr = err
		s.childMu.Unlock()
		close(s.childDone)
	}()
	return nil
}

// launchChildBackend dispatches the configured Command through
// Backend.Exec. The Backend adapter is responsible for the actual
// subprocess wiring; the supervisor only marshals the request, awaits
// the result, and translates it back into the same childDone /
// exit-info shape the host path uses.
//
// Stdin/Stdout/Stderr are wired through ExecOptions so the adapter can
// stream the agent's output directly into the supervisor's
// StreamCapture without an intermediate buffer. ExecOptions.Timeout is
// left zero: the supervisor enforces its own MaxRuntime budget out of
// band in the runLoop, and a second timeout layer in the adapter
// would only race that without adding observability.
func (s *Supervisor) launchChildBackend() error {
	s.childMu.Lock()
	s.backendActive = true
	s.childDone = make(chan struct{})
	done := s.childDone
	s.childMu.Unlock()

	cmd := backend.Command{
		Program: s.opts.Command.Program,
		Args:    s.opts.Command.Args,
		Dir:     s.opts.Command.Dir,
		Env:     s.opts.Command.Env,
	}
	opts := backend.ExecOptions{
		Stdin:  execOptionsReader(s.opts.Stdin),
		Stdout: execOptionsWriter(s.streams.Stdout()),
		Stderr: execOptionsWriter(s.streams.Stderr()),
	}

	go func() {
		// Backend.Exec is synchronous: it blocks until the child inside
		// the sandbox exits or the adapter times it out / kills it. The
		// supervisor's stop path triggers Backend.Stop separately, which
		// causes Backend.Exec to return with a non-zero exit code; that
		// return wakes this goroutine and the rest of the loop unblocks
		// via childDone.
		result, err := s.opts.BackendAdapter.Exec(s.opts.BackendEnvID, cmd, opts)
		s.childMu.Lock()
		s.backendResult = result
		s.backendExecErr = err
		s.childMu.Unlock()
		close(done)
	}()
	return nil
}

// execOptionsReader narrows an io.Reader into the inline interface
// backend.ExecOptions.Stdin declares. The narrowing is cheap and lets
// the supervisor avoid importing the inline interface shape inline.
// Returns nil so the adapter forwards "no stdin" rather than an empty
// reader when the caller did not wire one.
func execOptionsReader(r io.Reader) interface{ Read(p []byte) (int, error) } {
	if r == nil {
		return nil
	}
	return r
}

// execOptionsWriter is the writer analogue of execOptionsReader. The
// StreamCapture's Stdout()/Stderr() never return nil so in practice
// this is always a real writer, but the nil guard keeps the helper
// safe to call from any caller (a test that disables stream capture).
func execOptionsWriter(w io.Writer) interface{ Write(p []byte) (int, error) } {
	if w == nil {
		return nil
	}
	return w
}

// runLoop is the supervisor's StateRunning loop. It selects on the
// child's exit, the cancel channel, the max-runtime deadline, and the
// stats poll ticker. The returned terminalCause is the reason the loop
// is exiting; the post-loop code drives the state machine to the
// matching terminal.
//
// The loop deliberately does NOT close the streams or transition the
// machine; that is the caller's job (driveTerminalSequence) so the
// terminal sequence can vary (completed vs killed) without duplicating
// the close logic here.
func (s *Supervisor) runLoop() terminalCause {
	pollInterval := s.opts.StatsPollInterval
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var deadline <-chan time.Time
	if s.opts.MaxRuntime > 0 {
		// time.After is sufficient here: we never need to reset the
		// timer. The supervisor's deadline is the wall-clock budget
		// from the moment the child started running.
		deadline = time.After(s.opts.MaxRuntime)
	}

	// runningSince marks the start of the StateRunning window. The
	// idle detector measures against the most recent stream output;
	// before any output arrives, runningSince is the reference.
	runningSince := s.now()

	// childDone is owned by launchChild's single-waiter goroutine and
	// closes when the child has been reaped. The runLoop selects on it
	// alongside cancel / timeout / poll; the waiter wrote childErr
	// before closing the channel so post-loop code reads it safely.
	s.childMu.Lock()
	childDone := s.childDone
	s.childMu.Unlock()

	for {
		select {
		case <-childDone:
			// Child exited on its own. The terminalCause depends on
			// whether the exit was clean. We let the post-loop code
			// inspect the recorded exit status; here we just pick the
			// state.
			waitErr, exitCode, hasExitCode := s.childWaitOutcome()
			if waitErr == nil && hasExitCode && exitCode == 0 {
				return terminalCause{state: StateCompleted, reason: StopReasonAgentExit, note: "child exited 0"}
			}
			// Non-zero exit (or spawn-side error from Backend.Exec): a
			// recorded terminalCause (set by an earlier timer / cancel
			// that we beat to the select) wins; otherwise this is a
			// StateFailedAgent terminal because the agent itself
			// returned non-zero or could not be launched.
			recorded := s.takeTerminalCause(terminalCause{})
			if recorded.state != "" {
				return recorded
			}
			if waitErr != nil {
				return terminalCause{state: StateFailedAgent, reason: StopReasonAgentFailure, note: fmt.Sprintf("child exit: %v", waitErr)}
			}
			return terminalCause{state: StateFailedAgent, reason: StopReasonAgentFailure, note: fmt.Sprintf("child exit code %d", exitCode)}

		case <-s.cancelCh:
			// Cancel arrived. Record the intended terminal (Cancel's
			// own goroutine already did this, but recording here is
			// idempotent) and ask the child to stop. The waiter
			// goroutine will then close childDone.
			s.recordTerminalCause(terminalCause{state: StateKilledByUser, reason: StopReasonSignal, note: "cancel"})
			s.stopChildGracefully()
			<-childDone
			return s.takeTerminalCause(terminalCause{state: StateKilledByUser, reason: StopReasonSignal, note: "cancel"})

		case <-deadline:
			// Max-runtime budget exhausted. Record the intent, stop
			// the child gracefully, wait for the exit, and return.
			s.recordTerminalCause(terminalCause{state: StateTimedOut, reason: StopReasonTimeout, note: "max_runtime exceeded"})
			s.stopChildGracefully()
			<-childDone
			return s.takeTerminalCause(terminalCause{state: StateTimedOut, reason: StopReasonTimeout, note: "max_runtime exceeded"})

		case <-ticker.C:
			// Idle check. The plan's idle definition is "no output +
			// no diff for idle_timeout_minutes". We implement the "no
			// output" half here (LastOutputAt against the stream
			// capture); the "no diff" half is wired in step 10 when
			// the partial-diff collector lands. The plan permits this
			// staging: step 8 says "Detect idle timeout (no output +
			// no diff)" and step 10 owns the diff side, so the v0.1
			// behavior is conservative (output-only).
			if s.opts.IdleTimeout > 0 {
				ref := s.streams.LastOutputAt()
				if ref.IsZero() {
					ref = runningSince
				}
				if s.now().Sub(ref) >= s.opts.IdleTimeout {
					s.recordTerminalCause(terminalCause{state: StateKilledIdle, reason: StopReasonIdle, note: "idle timeout"})
					s.stopChildGracefully()
					<-childDone
					return s.takeTerminalCause(terminalCause{state: StateKilledIdle, reason: StopReasonIdle, note: "idle timeout"})
				}
			}
			// Stats poll: this is observational only in v0.1. A future
			// step writes a stats.jsonl event here. We deliberately do
			// not crash on missing stats so the loop stays robust if
			// the backend has no stats endpoint yet.
		}
	}
}

// exitInfo bundles the exit code (or its absence) and the wait error
// for the post-loop terminal sequence. Kept tiny so the caller does
// not have to thread three return values through every helper.
type exitInfo struct {
	code    int
	hasCode bool
	err     error
}

// childWaitOutcome returns the wait-side state the runLoop's exit-
// detection branch needs: the spawn / wait error, the reported exit
// code, and whether an exit code was actually reported. Hides the
// host / backend dispatch so the runLoop body stays readable.
func (s *Supervisor) childWaitOutcome() (waitErr error, exitCode int, hasExitCode bool) {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	if s.backendActive {
		if s.backendExecErr != nil {
			return s.backendExecErr, -1, false
		}
		if s.backendResult.HasExitCode {
			return nil, s.backendResult.ExitCode, true
		}
		return nil, -1, false
	}
	if s.childErr != nil {
		return s.childErr, -1, false
	}
	if s.child != nil && s.child.ProcessState != nil && s.child.ProcessState.Exited() {
		return nil, s.child.ProcessState.ExitCode(), true
	}
	return nil, -1, false
}

// collectExit returns the child's exit info. By the time runLoop
// returns the waiter goroutine has closed childDone and written either
// childErr (host path) or backendResult / backendExecErr (backend
// path), so reading the result here cannot race with the producer. We
// guard the read with childMu for paranoia and to keep the access
// patterns consistent with launchChild.
func (s *Supervisor) collectExit() exitInfo {
	s.childMu.Lock()
	backendActive := s.backendActive
	c := s.child
	done := s.childDone
	s.childMu.Unlock()
	if done != nil {
		<-done
	}
	if backendActive {
		s.childMu.Lock()
		res := s.backendResult
		err := s.backendExecErr
		s.childMu.Unlock()
		if err != nil {
			// Spawn / IO failure inside the adapter. We do not have a
			// canonical exit code in that case; the runLoop maps the
			// missing code to StateFailedAgent the same way a host-side
			// exec.Start failure does.
			return exitInfo{code: -1, hasCode: false, err: err}
		}
		if !res.HasExitCode {
			return exitInfo{code: -1, hasCode: false}
		}
		return exitInfo{code: res.ExitCode, hasCode: true}
	}
	if c == nil {
		return exitInfo{code: -1, hasCode: false}
	}
	s.childMu.Lock()
	st := c.ProcessState
	s.childMu.Unlock()
	if st == nil {
		return exitInfo{code: -1, hasCode: false}
	}
	if !st.Exited() {
		// Killed by signal; no canonical exit code. Use -1 sentinel
		// and HasExitCode=false; the result struct exposes that to the
		// caller for accurate reporting.
		return exitInfo{code: -1, hasCode: false}
	}
	return exitInfo{code: st.ExitCode(), hasCode: true}
}

// driveTerminalSequence walks the state machine through the right
// terminal sequence given the cause and exit info. For a clean exit
// (StateCompleted) we walk the full happy-path post-running stages
// (stopping -> scanning -> reporting -> completed); for any other
// terminal we transition directly to the terminal state.
//
// Each transition emits a lifecycle event and a run.json snapshot. A
// failure on any of those is logged via run.json (best effort) but
// does NOT change the terminal: we already know what state we want to
// land in, and the supervisor's job at this point is to land there
// regardless of partial I/O failures.
func (s *Supervisor) driveTerminalSequence(cause terminalCause, exit exitInfo) terminalCause {
	switch cause.state {
	case StateCompleted:
		// Happy path: walk stopping -> scanning -> reporting -> completed.
		// The supervisor transitions through each stage so the
		// lifecycle.jsonl is the full record the plan documents. The
		// StateScanning stage is no longer a pure stamp: plan 06 step 9
		// wires the post-run scanner here so secret-scan.json and
		// dependency-report.json land on disk before StateReporting. A
		// scan-infrastructure failure diverts the walk to StateFailedScan.
		for _, next := range []State{StateStopping, StateScanning, StateReporting, StateCompleted} {
			if err := s.machine.Transition(next); err != nil {
				// If we cannot transition (e.g. the machine is already
				// terminal because Cancel landed first), give up on
				// the happy walk and return whatever terminal we are
				// stuck on. We never silently skip a terminal.
				return terminalCause{state: s.machine.Current(), reason: StopReasonForState(s.machine.Current())}
			}
			if err := s.lcWri.Write(next); err != nil {
				// Lifecycle write failure on the happy-path drain is a
				// hard signal that something is wrong with disk. We
				// degrade to StateFailedAgent so the operator sees the
				// failure rather than a confused "completed" record.
				_ = s.machine.Transition(StateFailedAgent)
				_ = s.lcWri.Write(StateFailedAgent)
				cause := terminalCause{state: StateFailedAgent, reason: StopReasonAgentFailure, note: fmt.Sprintf("lifecycle write failed in %s", next)}
				_ = s.writeRecordSnapshot(StateFailedAgent, &exit.code, &cause.reason, nil)
				return cause
			}
			_ = s.writeRecordSnapshot(next, &exit.code, nil, nil)

			// Plan 06 step 9: run the scanner during StateScanning so
			// secret-scan.json / dependency-report.json are durable
			// before the run advances to StateReporting. Errors from
			// the hook are scanner-infrastructure failures: the
			// supervisor diverts the walk to StateFailedScan and
			// returns immediately. Findings themselves are advisory at
			// run time; the export gate refuses them later when the
			// user runs `ai-env patch` / `ai-env pr`.
			if next == StateScanning {
				if err := runScanHook(s.opts.RunDir, s.opts.ScanHook, s.opts.ScanTimeout); err != nil {
					if s.opts.UserOutput != nil {
						_, _ = fmt.Fprintf(s.opts.UserOutput, "ai-env: warning: scan hook failed: %v\n", err)
					}
					if terr := s.machine.Transition(StateFailedScan); terr != nil {
						return terminalCause{state: s.machine.Current(), reason: StopReasonForState(s.machine.Current()), note: fmt.Sprintf("scan hook failed: %v", err)}
					}
					_ = s.lcWri.Write(StateFailedScan)
					reason := StopReasonScanFailure
					_ = s.writeRecordSnapshot(StateFailedScan, &exit.code, &reason, nil)
					return terminalCause{state: StateFailedScan, reason: reason, note: fmt.Sprintf("scan hook failed: %v", err)}
				}
			}
		}
		reason := StopReasonAgentExit
		// Final run.json snapshot includes stop_reason and exit_code.
		_ = s.writeRecordSnapshot(StateCompleted, &exit.code, &reason, nil)
		return terminalCause{state: StateCompleted, reason: reason, note: cause.note}

	default:
		// Non-happy terminal: transition directly. The state machine's
		// transition table allows running -> <terminal> for every
		// terminal we set here; if a future cause picks an
		// unreachable state, Transition returns an error and we let
		// the current state stand.
		next := cause.state
		if err := s.machine.Transition(next); err != nil {
			next = s.machine.Current()
		}
		_ = s.lcWri.Write(next)
		reason := cause.reason
		if reason == "" {
			reason = StopReasonForState(next)
		}
		var codePtr *int
		if exit.hasCode {
			codePtr = &exit.code
		}
		_ = s.writeRecordSnapshot(next, codePtr, &reason, nil)
		return terminalCause{state: next, reason: reason, note: cause.note}
	}
}

// finalizeTerminal is the single exit gate for Run. It ensures the
// state machine has landed in cause.state (transitioning + writing the
// lifecycle event if it has not already), stamps stoppedAt, collects
// the partial diff into runDir/git-diff.patch, writes the closing
// run.json snapshot with exit code + stop reason + stopped_at, prints
// the `--continue` suggestion to UserOutput when the terminal supports
// it, and returns the SupervisorResult.
//
// The ordering matters: we land the state first (so an operator
// inspecting lifecycle.jsonl mid-shutdown sees the terminal), then
// collect the partial diff (so the closing run.json snapshot is written
// after the on-disk diff is durable, never the other way around), then
// rewrite run.json one last time, and finally surface the suggestion.
// A failure on any step except the lifecycle transition is logged via
// UserOutput (when set) but does NOT change the terminal: the plan
// treats post-terminal artifacts as advisory.
//
// driveTerminalSequence may have already written some of these
// transitions; in that case Transition returns an error which we
// silently swallow because the machine is already at the desired state
// (or a related one that wins by being terminal). The closing run.json
// snapshot is unconditional: it is the record an operator inspects
// after the fact, and a failure to write it is non-fatal because the
// per-transition snapshots already captured the state on disk.
func (s *Supervisor) finalizeTerminal(cause terminalCause, exit exitInfo) SupervisorResult {
	final := cause.state
	if final == "" {
		final = s.machine.Current()
	}
	// If the machine has not yet reached the terminal state (an early
	// setup failure, a launch failure, or a lifecycle write failure)
	// drive it there now and emit the corresponding lifecycle event so
	// the audit trail records the terminal even on the error paths.
	if s.machine.Current() != final {
		if err := s.machine.Transition(final); err == nil {
			_ = s.lcWri.Write(final)
		} else {
			// The transition was rejected (e.g. the machine is already
			// in a different terminal because Cancel won the race).
			// Land on whatever terminal the machine actually holds and
			// trust the recorded events; a confused operator is better
			// served by an honest record than by a forged one.
			final = s.machine.Current()
		}
	}

	if s.stoppedAt.IsZero() {
		s.stoppedAt = s.now()
	}
	reason := cause.reason
	if reason == "" {
		reason = StopReasonForState(final)
	}
	var codePtr *int
	if exit.hasCode {
		code := exit.code
		codePtr = &code
	}
	stopped := s.stoppedAt

	// Plan §5.5 — canonical 9-step teardown sequence. Step 1 (stop
	// child) has already happened by the time finalizeTerminal runs;
	// the helper picks up at step 2 (AcceptingShutdown + drain), then
	// drops rules (step 3), stops the observer (step 4), stops every
	// ProviderProxy in reverse order (step 5), stops the MCP gateway
	// (step 6), restores the workspace MCP configs + asks Backend to
	// Stop+Destroy (step 7), and stops the ControlSocket (step 8).
	// Step 9 (writer drain + transcript + leaks aggregator + final
	// summary) is owned by the rest of finalizeTerminal + Run's
	// deferred drain.
	reasonToken := reasonTokenForTerminal(final)
	s.teardownSequence(context.Background(), reasonToken)

	// Step 10 (collect partial diff): invoke the configured collector
	// against runDir/git-diff.patch with a context-bound timeout so a
	// stuck git process cannot block the supervisor's terminal walk.
	// The plan's "Collect partial diff if possible" rule treats the
	// diff as advisory; we surface collector failures via UserOutput
	// and via the supervisor's stderr equivalent but never escalate
	// them to a different terminal state. The file is always present
	// on disk after this call (it was created empty by
	// CreateRunDirectory; the helper overwrites it on success and
	// leaves the empty placeholder on the no-collector path).
	if err := collectPartialDiff(s.opts.RunDir, s.opts.DiffCollector, s.opts.DiffTimeout); err != nil {
		// Best-effort warning. Writing to UserOutput here is consistent
		// with how the supervisor surfaces the --continue hint below;
		// callers who left UserOutput nil simply do not see the
		// warning. Nothing else in the codebase consumes this string
		// today, so we keep the format human-readable rather than
		// inventing a structured event.
		if s.opts.UserOutput != nil {
			_, _ = fmt.Fprintf(s.opts.UserOutput, "ai-env: warning: partial diff collection failed: %v\n", err)
		}
	}

	// Closing run.json snapshot. Written after the partial diff lands
	// so the snapshot reflects the run's true post-diff state on disk;
	// a reader who opens run.json then git-diff.patch is guaranteed to
	// see the diff that corresponds to the recorded terminal. Failures
	// here are non-fatal: the per-transition snapshots already captured
	// the state on disk, so the operator still sees the run in its
	// terminal record even if this rewrite fails.
	_ = s.writeRecordSnapshot(final, codePtr, &reason, &stopped)

	// Final summary. Plan 05 task 12 calls for a network summary in
	// final-summary.md so a post-run reviewer can see the policy outcome
	// and outbound decisions without parsing network-events.jsonl.
	// Read the network events from disk (the supervisor's own writer
	// already flushed them) and fold them into a NetworkSummary, then
	// hand the result to WriteFinalSummary. Errors here are advisory:
	// they do NOT change the terminal state; the placeholder file
	// CreateRunDirectory left in place is the fallback record.
	if err := s.writeFinalSummary(final); err != nil {
		if s.opts.UserOutput != nil {
			_, _ = fmt.Fprintf(s.opts.UserOutput, "ai-env: warning: final summary write failed: %v\n", err)
		}
	}

	// Print the `--continue` suggestion if the terminal supports it.
	// The exact line is the master plan's "ai-env run <env-name>
	// --continue"; we record it on the result so a programmatic caller
	// can surface the same text without scraping stdout. Non-eligible
	// terminals (StateCompleted, the failure states) get an empty
	// suggestion both on stdout (nothing printed) and on the result.
	suggestion := printContinueSuggestion(s.opts.UserOutput, s.opts.EnvName, final)

	return SupervisorResult{
		FinalState:         final,
		StopReason:         reason,
		ExitCode:           exit.code,
		HasExitCode:        exit.hasCode,
		StartedAt:          s.startedAt,
		StoppedAt:          s.stoppedAt,
		ContinueSuggestion: suggestion,
		PartialDiffPath:    GitDiffPath(s.opts.RunDir),
	}
}

// writeFinalSummary loads the supervisor's run-local network event log
// from disk, folds it into a NetworkSummary, and hands the result to
// WriteFinalSummary so the on-disk final-summary.md ends up with the
// canonical network section (plan 05 task 12).
//
// The supervisor's own NetworkEventsWriter has already flushed every
// event by the time finalizeTerminal calls this helper (the Sync after
// every Write is the explicit invariant), so re-reading the file on
// disk is the simplest path: the writer does not need a separate
// snapshot API, and a future out-of-process emitter that appends to
// the same file (e.g. a backend-side forwarder) is included
// automatically.
//
// Returns the underlying error so finalizeTerminal can surface it via
// UserOutput. The terminal state is never changed: the placeholder
// CreateRunDirectory left behind is the fallback record.
func (s *Supervisor) writeFinalSummary(final State) error {
	events, _ := ReadNetworkEvents(s.opts.RunDir)
	summary := SummarizeNetworkEvents(events)
	return WriteFinalSummary(s.opts.RunDir, FinalSummaryInput{
		EnvName:   s.opts.EnvName,
		RunID:     s.opts.RunID,
		State:     final,
		StartedAt: s.startedAt,
		StoppedAt: s.stoppedAt,
		Network:   summary,
	})
}

// writeRecordSnapshot rewrites run.json with the latest state. The
// pointer arguments let the caller choose which optional fields to set
// for this snapshot: a setup-stage snapshot leaves exit code and stop
// reason nil; a terminal snapshot fills them in. The fields stamped
// once (run id, env, agent, etc.) are sourced from the supervisor
// options.
//
// A failure to write run.json is returned to the caller; the caller
// decides whether it is fatal (lifecycle stage transitions) or a soft
// warning (terminal snapshots).
func (s *Supervisor) writeRecordSnapshot(state State, exitCode *int, stopReason *StopReason, stoppedAt *time.Time) error {
	var startedAtPtr *time.Time
	if !s.startedAt.IsZero() {
		t := s.startedAt
		startedAtPtr = &t
	}
	rec := Record{
		RunID:               s.opts.RunID,
		EnvName:             s.opts.EnvName,
		Agent:               s.opts.Agent,
		Task:                s.opts.Task,
		State:               state,
		ExitCode:            exitCode,
		StartedAt:           startedAtPtr,
		StoppedAt:           stoppedAt,
		StopReason:          stopReason,
		Backend:             s.opts.Backend,
		ModelCredentialMode: s.opts.ModelCredentialMode,
		ReducedSafety:       s.opts.ReducedSafety,
		LinkedPreviousRun:   s.opts.LinkedPreviousRun,
		// Plan §0.2 + §0 Schema-version contract: the supervisor
		// populates the schema_versions map at every snapshot so a
		// mid-run reader (status command, audit tail, leaks
		// aggregator) sees the per-stream versions immediately,
		// not only after the run terminates. The map is built from
		// the package-level CurrentSchemaVersions snapshot to keep
		// the writer free of per-supervisor branching.
		SchemaVersions: CurrentSchemaVersions(),
	}
	return WriteRecord(s.opts.RunDir, rec)
}

// stopChildGracefully asks the child process to terminate, waits the
// configured grace period for it to exit on its own, and then escalates
// to a hard kill if the child is still running.
//
// This is the path the cancel / timeout / idle terminals use to bring
// the child down. Step 9 (signal handling) reuses the same helper when
// an OS signal arrives; keeping it in one place means there is one
// piece of code to audit for the kill semantics.
//
// Dispatches on backendActive: the host path signals the exec.Cmd
// directly, while the backend path delegates to Backend.Stop and lets
// the adapter pick the right signal / grace-window mechanics for its
// underlying runtime. Both paths still wait on childDone (the goroutine
// launched in launchChild* closes it once the child has been reaped).
//
// stopChildGracefully does NOT call Wait; launchChild owns the single
// Wait goroutine. We observe child exit via the shared childDone
// channel, which the waiter closes after Wait returns.
func (s *Supervisor) stopChildGracefully() {
	s.childMu.Lock()
	backendActive := s.backendActive
	c := s.child
	done := s.childDone
	s.childMu.Unlock()

	if backendActive {
		s.requestBackendStop(signalInterrupt, s.opts.StopGracePeriod)
		// Wait the grace window. The backend goroutine closes done once
		// Backend.Exec returns (which happens after Backend.Stop unwinds
		// the child); if it does not, escalate to a hard stop with a
		// zero timeout (every shipped adapter interprets this as
		// "kill immediately").
		t := time.NewTimer(s.opts.StopGracePeriod)
		defer t.Stop()
		select {
		case <-t.C:
			s.requestBackendStop(nil, 0)
		case <-done:
		}
		return
	}

	if c == nil || c.Process == nil {
		return
	}
	// SIGINT is the polite ask. signalInterrupt is the platform-
	// specific Signal value; on POSIX it is os.Interrupt. We deliver
	// it to the whole process group via signalChildGroup so a shell
	// wrapper's grandchildren also receive it; the launchChildHost
	// path puts the child in its own group via applyProcessGroup.
	_ = signalChildGroup(c, signalInterrupt)
	// Wait the grace window for the child to exit. If it does, the
	// childDone channel closes and we exit promptly. If it does not,
	// we escalate to a hard kill (the waiter goroutine still reaps
	// the child afterwards, so callers blocking on childDone unblock
	// regardless).
	t := time.NewTimer(s.opts.StopGracePeriod)
	defer t.Stop()
	select {
	case <-t.C:
		s.hardKillChild()
	case <-done:
	}
}

// hardKillChild forces the child down with SIGKILL (or its Windows
// equivalent). Used after the grace window in stopChildGracefully and
// in error paths that cannot afford to wait. Backend-path runs route
// through Backend.Stop with a zero timeout, leaving the "use SIGKILL
// equivalent" decision to the adapter.
func (s *Supervisor) hardKillChild() {
	s.childMu.Lock()
	backendActive := s.backendActive
	c := s.child
	s.childMu.Unlock()
	if backendActive {
		// Zero timeout asks the adapter for an immediate kill. Every
		// shipped adapter treats this as "go straight to SIGKILL"; we
		// do not pass a signal because the adapter's docker-sbx call
		// picks the platform default and the kill path does not need a
		// SIGINT pre-step (stopChildGracefully already did it).
		s.requestBackendStop(nil, 0)
		return
	}
	if c == nil || c.Process == nil {
		return
	}
	// Group-aware SIGKILL: deliver to every member of the child's
	// process group so any grandchildren the shell wrapper spawned
	// die alongside the direct child. signalChildGroup falls back to
	// per-pid c.Process.Signal when the group call fails, which is
	// equivalent to the legacy c.Process.Kill behaviour.
	_ = signalChildGroup(c, syscall.SIGKILL)
}

// requestBackendStop invokes Backend.Stop at most once per run. The
// cancel / timeout / idle paths funnel through stopChildGracefully
// (polite ask with SIGINT + grace window) and the hard-kill escalation
// funnels through requestBackendStop(nil, 0). Adapters that document
// at-most-one-Stop semantics see exactly one invocation; the second
// call is dropped here rather than relying on adapter idempotency.
//
// Backend.Stop's contract accepts nil sig to mean "let the adapter
// pick the platform default" and any os.Signal to forward explicitly.
// The error is intentionally swallowed: a Stop failure usually means
// the env is already down, which is exactly the state the caller
// wanted.
func (s *Supervisor) requestBackendStop(sig os.Signal, timeout time.Duration) {
	s.childMu.Lock()
	if s.backendStopped {
		s.childMu.Unlock()
		return
	}
	s.backendStopped = true
	s.childMu.Unlock()
	_ = s.opts.BackendAdapter.Stop(s.opts.BackendEnvID, sig, timeout)
}

// waitChild blocks until the child exits and returns the exit code.
// Used only by the error fallback in Run (a lifecycle failure between
// launch and StateRunning). It reads off the same waiter the runLoop
// uses, so calling it does not race with Wait.
func (s *Supervisor) waitChild() (int, error) {
	s.childMu.Lock()
	c := s.child
	done := s.childDone
	s.childMu.Unlock()
	if c == nil {
		return -1, errors.New("run: no child to wait on")
	}
	if done != nil {
		<-done
	}
	s.childMu.Lock()
	st := c.ProcessState
	werr := s.childErr
	s.childMu.Unlock()
	if st != nil && st.Exited() {
		return st.ExitCode(), werr
	}
	return -1, werr
}
