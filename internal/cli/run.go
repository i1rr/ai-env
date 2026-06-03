package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/i1rr/ai-env/internal/agents"
	"github.com/i1rr/ai-env/internal/backend"
	"github.com/i1rr/ai-env/internal/backend/docker"
	"github.com/i1rr/ai-env/internal/backend/docker_sbx"
	"github.com/i1rr/ai-env/internal/backend/mock"
	"github.com/i1rr/ai-env/internal/backend/podman"
	"github.com/i1rr/ai-env/internal/config"
	"github.com/i1rr/ai-env/internal/egress"
	"github.com/i1rr/ai-env/internal/githubbroker"
	"github.com/i1rr/ai-env/internal/run"
	"github.com/i1rr/ai-env/internal/secrets"
	"github.com/i1rr/ai-env/internal/workspace"
)

// RunOptions captures the parsed flags + positional argument for
// `ai-env run`. The CLI wiring layer (cmd/ai-env/main.go) fills this
// in and calls RunRun; the command body has no direct Cobra
// dependency so it can be exercised from unit tests against the mock
// backend without standing up a real container runtime.
type RunOptions struct {
	// EnvName is the positional <env-name> argument identifying the
	// workspace the agent runs against.
	EnvName string

	// Agent is the agent identifier to launch (defaults to the
	// project's default_agent when empty).
	Agent string

	// Task is the verbatim --task content the supervisor records in
	// task.md and forwards to the agent via stdin. Required.
	Task string

	// Continue links this run to the env's most recent previous run.
	Continue bool

	// ShellShim enables the optional shell-shim prototype (Plan §5.5
	// step 10).
	ShellShim bool

	// ObserverMode mirrors `--observer-mode` (auto / strict /
	// disabled). Empty falls back to the egress package default
	// (auto).
	ObserverMode string

	// Cwd is the working directory the command was invoked from. The
	// run command walks upward from Cwd looking for the project's
	// .ai-env/ directory so users can run `ai-env run` from any
	// subdirectory of a project.
	Cwd string

	// Stdout is the writer for the run's human-readable summary
	// (run-id, run dir path, continue suggestion).
	Stdout io.Writer

	// Stderr is the writer for warnings (loose secrets file mode,
	// fallback backend selection notice).
	Stderr io.Writer
}

// BackendFactoryOptions carries the ai-env.yaml sandbox-section knobs
// the docker / podman adapters need at construction time so an
// operator-supplied `accept_reduced_isolation: true` actually reaches
// the Detect gate. Without this, the docker fallback rejects
// autonomous mode with "requires --accept-reduced-isolation" even
// when the YAML field is set.
type BackendFactoryOptions struct {
	// Mode is the project's default_mode (autonomous / interactive /
	// dry-run). docker/podman use it to decide whether reduced
	// isolation must be explicitly accepted.
	Mode string

	// AcceptReducedIsolation mirrors sandbox.accept_reduced_isolation.
	// True is the operator's acknowledgement that the rootless
	// docker/podman fallback is acceptable for autonomous runs.
	AcceptReducedIsolation bool
}

// BackendFactory is the package-level seam unit tests use to
// substitute the real backend constructors with the in-memory mock
// backend. Production keeps the default mapping that returns the
// concrete adapter for each name; tests rebind the variable before
// invoking RunRun.
var BackendFactory = defaultBackendFactory

// defaultBackendFactory maps a backend identifier (the ai-env.yaml
// sandbox.backend / sandbox.fallback_backend value) to a constructed
// backend.Backend instance. Unknown names produce an error so a
// misconfigured project fails loudly rather than silently picking
// the wrong adapter.
func defaultBackendFactory(name string, opts BackendFactoryOptions) (backend.Backend, error) {
	switch name {
	case "mock":
		return mock.New(nil), nil
	case "docker-sbx":
		return docker_sbx.New(docker_sbx.Options{}), nil
	case "docker":
		return docker.New(docker.Options{
			Mode:                   opts.Mode,
			AcceptReducedIsolation: opts.AcceptReducedIsolation,
		}), nil
	case "podman":
		return podman.New(podman.Options{
			Mode:                   opts.Mode,
			AcceptReducedIsolation: opts.AcceptReducedIsolation,
		}), nil
	case "", "none":
		return nil, fmt.Errorf("backend identifier is empty")
	default:
		return nil, fmt.Errorf("unknown backend %q", name)
	}
}

// RunAgentPlanner is the package-level seam unit tests use to
// substitute the real agent Probe + Plan pipeline with a canned
// LaunchPlan. Production keeps the default that resolves the
// launcher from LauncherFactory, runs the binary probe, and asks
// the launcher to build the backend.Command.
var RunAgentPlanner = defaultRunAgentPlanner

// defaultRunAgentPlanner resolves the launcher for agentName, runs
// the Probe under agentsProbeTimeout, and returns the LaunchPlan
// the supervisor will execute. Probe failures are surfaced verbatim.
func defaultRunAgentPlanner(ctx context.Context, agentName string, contract config.AgentEntry, req agents.Request, envProbe agents.EnvironmentProbe) (agents.LaunchPlan, error) {
	launchers := LauncherFactory()
	launcher, ok := launchers[agentName]
	if !ok {
		return agents.LaunchPlan{}, fmt.Errorf("no launcher registered for agent %q", agentName)
	}
	probeCtx, cancel := context.WithTimeout(ctx, agentsProbeTimeout)
	defer cancel()
	probe := launcher.Probe(probeCtx, contract, agents.ProbeDeps{})
	if probe.Error != nil {
		return agents.LaunchPlan{}, probe.Error
	}
	return launcher.Plan(req, probe, envProbe)
}

// RunRun is the entry point used by the Cobra wiring. It walks the
// canonical pre-launch sequence the supervisor expects: load
// configuration, resolve the workspace, build per-run primitives
// (backend, control socket, provider proxies), select the agent
// launcher, construct the supervisor, drive it, and surface the
// outcome.
//
// Error contract:
//
//   - Validation errors (missing --task, unknown env, missing
//     workspace) are returned verbatim.
//   - I/O failures during setup (load ai-env.yaml, load
//     secrets.local.yaml, create run directory) wrap the underlying
//     error with `ai-env run:`.
//   - A non-zero supervisor terminal (timeout, agent failure, etc.)
//     is reported as a CLI exit error so the shell exit code
//     reflects the run outcome.
func RunRun(opts RunOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env run: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if strings.TrimSpace(opts.Task) == "" {
		return errors.New("ai-env run: --task is required")
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env run: %w", err)
	}

	observerMode, err := egress.ParseEgressObserverMode(opts.ObserverMode)
	if err != nil {
		return fmt.Errorf("ai-env run: %w", err)
	}
	// `--observer-mode strict` advertises "abort if capability missing"
	// (see cmd/ai-env/main.go newRunCmd flag help). The concrete
	// egress.ChooseObserver wiring is not yet implemented, so RunRun
	// passes a nil EgressObserver to the supervisor and
	// startEgressObserver short-circuits before the mode check. Accepting
	// strict here would silently degrade to auto/disabled — the exact
	// opposite of the fail-closed contract. Reject it up front so the
	// operator sees a clear error instead of an apparently-successful
	// strict run with no observer attached.
	if observerMode == egress.EgressObserverModeStrict {
		return errors.New("ai-env run: --observer-mode strict is not yet wired (egress observer not implemented); use --observer-mode auto or disabled")
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env run: %w", err)
	}

	cfg, err := config.LoadAIEnv(filepath.Join(aiEnvDir, "ai-env.yaml"))
	if err != nil {
		return fmt.Errorf("ai-env run: %w", err)
	}

	agentName := strings.TrimSpace(opts.Agent)
	if agentName == "" {
		agentName = cfg.Project.DefaultAgent
	}
	if agentName == "" {
		return errors.New("ai-env run: agent not specified and ai-env.yaml has no project.default_agent")
	}

	wsPath := workspace.WorkspacePath(aiEnvDir, opts.EnvName)
	if _, statErr := os.Stat(wsPath); statErr != nil {
		if os.IsNotExist(statErr) {
			return fmt.Errorf("ai-env run: workspace for env %q not found at %s; run `ai-env new %s` first", opts.EnvName, wsPath, opts.EnvName)
		}
		return fmt.Errorf("ai-env run: stat workspace %s: %w", wsPath, statErr)
	}

	// Best-effort metadata read; missing file is non-fatal since the
	// workspace itself is the source of truth for the run.
	if _, metaErr := workspace.ReadMetadata(aiEnvDir, opts.EnvName); metaErr != nil {
		fmt.Fprintf(opts.Stderr, "warning: read workspace metadata for %s: %v\n", opts.EnvName, metaErr)
	}

	secretsCfg, secretsWarnings, secErr := secrets.LoadLocal(filepath.Join(aiEnvDir, secrets.LocalConfigDefaultFilename))
	if secErr != nil {
		return fmt.Errorf("ai-env run: load secrets.local.yaml: %w", secErr)
	}
	for _, w := range secretsWarnings {
		fmt.Fprintf(opts.Stderr, "warning: %s permissions are loose (mode=%o wanted=%o reason=%s)\n",
			w.Path, w.Mode, w.Wanted, w.Reason)
	}

	proxyBuild, perr := secrets.BuildProviderProxyFromSecrets(secretsCfg, secrets.BuildOptions{})
	if perr != nil {
		return fmt.Errorf("ai-env run: build provider proxies: %w", perr)
	}
	for _, sp := range proxyBuild.SkippedProviders {
		fmt.Fprintf(opts.Stderr, "warning: provider %q skipped: %s\n", sp.Provider, sp.Reason)
	}
	for _, unk := range proxyBuild.UnknownProviders {
		fmt.Fprintf(opts.Stderr, "warning: unknown provider key %q in secrets.local.yaml\n", unk)
	}

	// Attempt broker construction so an operator with misconfigured
	// GitHub credentials sees the error at run start rather than at
	// `ai-env pr` time. ErrNoTokenSource (no GitHub credential
	// configured) and ErrRepoUnconfigured (no repo wired into the
	// build options here, expected for `ai-env run`) are both
	// tolerated; the broker itself is consumed by `ai-env pr`, not
	// the supervisor.
	if _, brokerErr := githubbroker.BuildBrokerFromSecrets(secretsCfg, githubbroker.BuildBrokerOptions{}); brokerErr != nil {
		if !errors.Is(brokerErr, githubbroker.ErrNoTokenSource) && !errors.Is(brokerErr, githubbroker.ErrRepoUnconfigured) {
			fmt.Fprintf(opts.Stderr, "warning: github broker construction failed: %v\n", brokerErr)
		}
	}

	bk, backendName, err := selectBackend(cfg, opts.Stderr)
	if err != nil {
		return fmt.Errorf("ai-env run: %w", err)
	}

	contracts, _, err := loadAgentsContracts(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env run: %w", err)
	}
	contract, ok := contracts[agentName]
	if !ok {
		return fmt.Errorf("ai-env run: agent %q not configured in agents.yaml", agentName)
	}

	// Build the EnvironmentProbe the launcher consults to pick its
	// credential mode. backend_managed is the safe default; an
	// available provider proxy promotes provider_proxy as well.
	envProbe := agents.EnvironmentProbe{BackendManaged: true}
	if len(proxyBuild.Proxies) > 0 {
		envProbe.ProviderProxyURL = proxyBuild.Proxies[0].URL()
		envProbe.ProviderProxyProvider = proxyBuild.Proxies[0].Provider()
	}

	plan, err := RunAgentPlanner(context.Background(), agentName, contract, agents.Request{
		Mode:           "autonomous",
		TaskBody:       opts.Task,
		WorkspaceDir:   wsPath,
		CredentialMode: contract.CredentialMode,
	}, envProbe)
	if err != nil {
		return fmt.Errorf("ai-env run: plan agent %q: %w", agentName, err)
	}

	envID, err := bk.Create(backend.EnvSpec{
		Name:          opts.EnvName,
		Template:      cfg.Sandbox.Template,
		WorkspacePath: wsPath,
	})
	if err != nil {
		return fmt.Errorf("ai-env run: backend.Create: %w", err)
	}

	var (
		runID      string
		runDir     run.RunDirectory
		linkedPrev *string
	)
	if opts.Continue {
		cont, contErr := run.PrepareContinuation(aiEnvDir, opts.EnvName, opts.Task, time.Now())
		if contErr != nil {
			_ = bk.Destroy(envID)
			return fmt.Errorf("ai-env run: %w", contErr)
		}
		runID = cont.NewRun.ID
		runDir = cont.NewRun
		linkedPrev = run.LinkedPreviousRunPtr(cont.PreviousRunID)
	} else {
		newID, idErr := run.GenerateRunID()
		if idErr != nil {
			_ = bk.Destroy(envID)
			return fmt.Errorf("ai-env run: generate run id: %w", idErr)
		}
		newDir, dirErr := run.CreateRunDirectory(aiEnvDir, newID, time.Now())
		if dirErr != nil {
			_ = bk.Destroy(envID)
			return fmt.Errorf("ai-env run: create run directory: %w", dirErr)
		}
		if writeErr := run.WriteTask(aiEnvDir, newID, opts.Task); writeErr != nil {
			_ = bk.Destroy(envID)
			_ = os.RemoveAll(newDir.Path)
			return fmt.Errorf("ai-env run: %w", writeErr)
		}
		runID = newID
		runDir = newDir
	}

	cs, csErr := run.NewControlSocket(run.ControlSocketOptions{RunDir: runDir.Path})
	if csErr != nil {
		_ = bk.Destroy(envID)
		_ = os.RemoveAll(runDir.Path)
		return fmt.Errorf("ai-env run: control socket: %w", csErr)
	}

	superOpts := run.SupervisorOptions{
		RunDir:              runDir.Path,
		RunID:               runID,
		EnvName:             opts.EnvName,
		Task:                opts.Task,
		Backend:             backendName,
		Agent:               agentName,
		Command:             run.CommandSpec(plan.Command),
		BackendAdapter:      bk,
		BackendEnvID:        envID,
		Stdin:               strings.NewReader(plan.StdinBody),
		ControlSocket:       cs,
		EgressObserverMode:  observerMode,
		UserOutput:          opts.Stdout,
		ProviderProxies:     proxyBuild.Proxies,
		WorkspaceMCPRoot:    wsPath,
		ModelCredentialMode: credentialModeForRecord(plan.CredentialMode),
		BackendStart: func() error {
			_, err := bk.Start(envID)
			return err
		},
		BackendDestroy: func() error {
			return bk.Destroy(envID)
		},
		LinkedPreviousRun: linkedPrev,
		MaxRuntime:        time.Duration(cfg.Supervision.MaxRuntimeMinutes) * time.Minute,
		IdleTimeout:       time.Duration(cfg.Supervision.IdleTimeoutMinutes) * time.Minute,
		StopGracePeriod:   time.Duration(cfg.Supervision.KillGraceSeconds) * time.Second,
	}

	if opts.ShellShim {
		policyPath := filepath.Join(aiEnvDir, "policy.yaml")
		if _, statErr := os.Stat(policyPath); statErr != nil {
			_ = cs.Stop()
			_ = bk.Destroy(envID)
			_ = os.RemoveAll(runDir.Path)
			if os.IsNotExist(statErr) {
				return fmt.Errorf("ai-env run: --shell-shim requires %s; run `ai-env policy init` first", policyPath)
			}
			return fmt.Errorf("ai-env run: stat %s: %w", policyPath, statErr)
		}
		superOpts.ShellShim = true
		superOpts.ShellShimDir = filepath.Join(runDir.Path, "shim")
		superOpts.PolicyEnginePath = policyPath
		if mkErr := os.MkdirAll(superOpts.ShellShimDir, 0o700); mkErr != nil {
			_ = cs.Stop()
			_ = bk.Destroy(envID)
			_ = os.RemoveAll(runDir.Path)
			return fmt.Errorf("ai-env run: create shim dir: %w", mkErr)
		}
	}

	supervisor, sErr := run.NewSupervisor(superOpts)
	if sErr != nil {
		_ = cs.Stop()
		_ = bk.Destroy(envID)
		_ = os.RemoveAll(runDir.Path)
		return fmt.Errorf("ai-env run: %w", sErr)
	}

	// Route SIGINT / SIGTERM / SIGHUP into supervisor.Cancel so a Ctrl-C
	// at the host shell triggers the supervisor's canonical 9-step
	// teardown (BackendDestroy, control socket Stop, terminal run.json,
	// final lifecycle verb). Without this, the parent dies immediately
	// and the env/control socket/run state are left to the OS to clean
	// up best-effort. The supervisor itself documents this exact call
	// shape (see internal/run/supervisor_signal.go).
	stopSignals, sigErr := run.InstallSignalHandlers(supervisor)
	if sigErr != nil {
		_ = cs.Stop()
		_ = bk.Destroy(envID)
		_ = os.RemoveAll(runDir.Path)
		return fmt.Errorf("ai-env run: %w", sigErr)
	}
	defer stopSignals()

	result, runErr := supervisor.Run(context.Background())
	if runErr != nil {
		return fmt.Errorf("ai-env run: %w", runErr)
	}

	// The supervisor's printContinueSuggestion already writes the
	// suggestion to UserOutput (= opts.Stdout) for continuable terminals.
	// We deliberately do NOT echo result.ContinueSuggestion here to
	// avoid a duplicate line on `--continue`-eligible terminals.
	fmt.Fprintf(opts.Stdout, "run id:    %s\n", runID)
	fmt.Fprintf(opts.Stdout, "run dir:   %s\n", runDir.Path)
	fmt.Fprintf(opts.Stdout, "state:     %s\n", result.FinalState)

	if result.FinalState != run.StateCompleted {
		return fmt.Errorf("ai-env run: terminal state %s (exit %d)", result.FinalState, result.ExitCode)
	}
	return nil
}

// credentialModeForRecord maps the launcher's chosen credential mode
// string into the run-package's ModelCredentialMode value the supervisor
// records in run.json. The agents package emits "brokered" as a synonym
// for backend_managed at runtime (no broker integration is wired into
// launchers yet); we collapse it here so audit consumers see one of the
// three canonical record values and never an unknown literal.
func credentialModeForRecord(mode string) run.ModelCredentialMode {
	switch mode {
	case "", agents.CredentialModeBackendManaged, agents.CredentialModeBrokered:
		return run.ModelCredentialBackendManaged
	case agents.CredentialModeProviderProxy:
		return run.ModelCredentialProviderProxy
	case agents.CredentialModeRawEnvExplicit:
		return run.ModelCredentialRawEnvExplicit
	default:
		return run.ModelCredentialBackendManaged
	}
}

// selectBackend constructs the primary backend, probes its
// availability via Detect, and falls back to sandbox.fallback_backend
// when the primary is unusable. A warning is printed when the
// fallback is selected so the operator sees the substitution rather
// than wondering why a different adapter ran.
func selectBackend(cfg *config.AIEnvConfig, stderr io.Writer) (backend.Backend, string, error) {
	bfOpts := BackendFactoryOptions{
		Mode:                   cfg.Project.DefaultMode,
		AcceptReducedIsolation: cfg.Sandbox.AcceptReducedIsolation,
	}
	primary := cfg.Sandbox.Backend
	bk, err := BackendFactory(primary, bfOpts)
	if err != nil {
		return nil, "", fmt.Errorf("construct backend %q: %w", primary, err)
	}
	status := bk.Detect()
	if status.Available {
		// Surface the version-incompatibility hint when the adapter
		// reports Available but flags the runtime as outside the tested
		// range. The adapter's own Message documents the canonical
		// follow-up (a future --allow-untested-backend-version flag); we
		// print it as a notice today so an operator pinning an untested
		// sbx release sees the warning instead of running silently
		// against an unsupported backend.
		if !status.VersionSupported && strings.TrimSpace(status.Message) != "" {
			fmt.Fprintf(stderr, "notice: backend %q: %s\n", primary, status.Message)
		}
		return bk, primary, nil
	}
	fallback := cfg.Sandbox.FallbackBackend
	if fallback == "" || fallback == "none" {
		return nil, "", fmt.Errorf("backend %q unavailable: %s", primary, status.Message)
	}
	fbBk, fbErr := BackendFactory(fallback, bfOpts)
	if fbErr != nil {
		return nil, "", fmt.Errorf("construct fallback backend %q: %w", fallback, fbErr)
	}
	fbStatus := fbBk.Detect()
	if !fbStatus.Available {
		return nil, "", fmt.Errorf("backend %q unavailable (%s); fallback %q also unavailable (%s)",
			primary, status.Message, fallback, fbStatus.Message)
	}
	fmt.Fprintf(stderr, "notice: primary backend %q unavailable (%s); using fallback %q\n",
		primary, status.Message, fallback)
	return fbBk, fallback, nil
}
