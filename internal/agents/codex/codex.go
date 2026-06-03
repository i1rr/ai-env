// Package codex implements the agents.Launcher for the Codex CLI
// (binary "codex").
//
// The launcher follows the same five-step structure as the Claude
// launcher; the Codex-specific bits are:
//
//   - Autonomous mode passes --dangerously-bypass-approvals-and-sandbox
//     (verified against `codex --help`).
//   - The task body is piped on stdin: Codex reads its prompt from
//     stdin when one is supplied.
//   - Credential injection covers OPENAI_API_KEY (raw_env_explicit)
//     and OPENAI_BASE_URL (provider_proxy). backend_managed
//     credentials are injected by the backend, not the launcher.
package codex

import (
	"context"
	"fmt"

	"github.com/i1rr/ai-env/internal/agents"
	"github.com/i1rr/ai-env/internal/backend"
	"github.com/i1rr/ai-env/internal/config"
)

// Name is the agent identifier surfaced through Launcher.Name and
// matched against the agents.yaml key.
const Name = "codex"

// Launcher is the Codex implementation of agents.Launcher.
type Launcher struct{}

// New returns a Codex launcher.
func New() *Launcher { return &Launcher{} }

// Name implements agents.Launcher.
func (l *Launcher) Name() string { return Name }

// Probe implements agents.Launcher. It resolves the binary, probes
// the version, runs `codex --help` to verify autonomous flags, and
// returns a populated ProbeResult.
func (l *Launcher) Probe(ctx context.Context, contract config.AgentEntry, deps agents.ProbeDeps) agents.ProbeResult {
	result := agents.ProbeResult{}

	path, err := agents.ResolveBinary(deps, contract.Command)
	if err != nil {
		result.Error = err
		return result
	}
	result.BinaryPath = path

	version, _, err := agents.ProbeVersion(ctx, deps, path, contract.Probe)
	if err != nil {
		result.Error = err
		return result
	}
	result.Version = version

	ok, err := agents.SatisfiesConstraint(version, contract.VersionConstraint)
	if err != nil {
		result.Error = err
		return result
	}
	result.VersionSupported = ok
	if !ok {
		result.Error = fmt.Errorf("agents/codex: version %s does not satisfy %s", version, contract.VersionConstraint)
		return result
	}

	help, err := agents.ProbeHelp(ctx, deps, path)
	if err != nil {
		result.Error = err
		return result
	}
	result.HelpOutput = help

	if mode, ok := contract.Modes["autonomous"]; ok {
		flags, supported := agents.SelectAutonomousFlags(mode, help)
		if !supported {
			result.Error = fmt.Errorf("agents/codex: %w (tried %v)",
				agents.ErrFlagsUnsupported, mode.ArgsCandidates)
			return result
		}
		result.SelectedFlags = flags
	}

	return result
}

// Plan implements agents.Launcher. It turns a Request plus a probe
// result into a backend.Command.
func (l *Launcher) Plan(req agents.Request, probe agents.ProbeResult, env agents.EnvironmentProbe) (agents.LaunchPlan, error) {
	if probe.Error != nil {
		return agents.LaunchPlan{}, probe.Error
	}
	if probe.BinaryPath == "" {
		return agents.LaunchPlan{}, fmt.Errorf("agents/codex: Plan requires a successful Probe (BinaryPath empty)")
	}
	if req.Mode != "autonomous" {
		return agents.LaunchPlan{}, fmt.Errorf("agents/codex: mode %q not supported yet (autonomous only)", req.Mode)
	}
	if probe.SelectedFlags == nil {
		return agents.LaunchPlan{}, fmt.Errorf("agents/codex: %w", agents.ErrFlagsUnsupported)
	}

	// Codex reads OPENAI_BASE_URL when present, so for the
	// provider_proxy probe in ResolveCredentialMode we report the
	// custom-base-URL capability as satisfied. The proxy URL itself is
	// supplied by the supervisor through EnvironmentProbe in Plan 05.
	probeEnv := env
	probeEnv.AgentSupportsCustomBaseURL = true

	contract := req.CredentialMode
	if contract.Default == "" {
		contract = config.AgentCredentialMode{
			Default:       agents.CredentialModeBackendManaged,
			FallbackOrder: []string{agents.CredentialModeProviderProxy, agents.CredentialModeRawEnvExplicit},
		}
	}
	resolved, err := agents.ResolveCredentialModeDetailed(contract, probeEnv, req.AllowRawModelToken)
	if err != nil {
		return agents.LaunchPlan{}, fmt.Errorf("agents/codex: %w", err)
	}

	args := append([]string{}, probe.SelectedFlags...)
	args = append(args, req.ExtraArgs...)

	cmd := backend.Command{
		Program: Name,
		Args:    args,
		Dir:     req.WorkspaceDir,
		Env:     agents.MergeEnv(resolved.InjectedEnv, req.ExtraEnv),
	}

	return agents.LaunchPlan{
		Command:        cmd,
		CredentialMode: resolved.Mode,
		StdinBody:      req.TaskBody,
	}, nil
}

// compile-time check that Launcher satisfies agents.Launcher.
var _ agents.Launcher = (*Launcher)(nil)
