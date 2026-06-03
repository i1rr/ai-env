// Package claude implements the agents.Launcher for the Claude Code
// CLI (binary "claude").
//
// The launcher follows the five-step structure documented on
// agents.Launcher: resolve binary, probe version, select autonomous
// flags, detect credential mode, build launch command. The Claude-
// specific bits are:
//
//   - Autonomous mode passes --dangerously-skip-permissions (verified
//     against `claude --help`).
//   - The task body is piped on stdin: Claude reads its prompt from
//     stdin when one is supplied, which avoids dropping a temporary
//     file in the workspace.
//   - Credential injection covers ANTHROPIC_API_KEY (raw_env_explicit)
//     and ANTHROPIC_BASE_URL (provider_proxy). backend_managed
//     credentials are injected by the backend, not the launcher.
package claude

import (
	"context"
	"fmt"

	"github.com/i1rr/ai-env/internal/agents"
	"github.com/i1rr/ai-env/internal/backend"
	"github.com/i1rr/ai-env/internal/config"
)

// Name is the agent identifier surfaced through Launcher.Name and
// matched against the agents.yaml key. Exposed as a constant so the
// CLI and tests do not have to hard-code the string.
const Name = "claude"

// Launcher is the Claude Code implementation of agents.Launcher.
// The zero value is usable; New is a convenience constructor that
// matches the codex package's signature for symmetry.
type Launcher struct{}

// New returns a Claude launcher.
func New() *Launcher { return &Launcher{} }

// Name implements agents.Launcher.
func (l *Launcher) Name() string { return Name }

// Probe implements agents.Launcher. It resolves the binary, probes
// the version, runs `claude --help` to verify autonomous flags, and
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
		result.Error = fmt.Errorf("agents/claude: version %s does not satisfy %s", version, contract.VersionConstraint)
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
			result.Error = fmt.Errorf("agents/claude: %w (tried %v)",
				agents.ErrFlagsUnsupported, mode.ArgsCandidates)
			return result
		}
		result.SelectedFlags = flags
	}

	return result
}

// Plan implements agents.Launcher. It turns a Request plus a probe
// result into a backend.Command. The task body is piped to the
// agent's stdin (LaunchPlan.StdinBody) rather than written to a
// file; Claude reads from stdin when one is attached, and the
// supervisor already records the body in task.md for audit.
func (l *Launcher) Plan(req agents.Request, probe agents.ProbeResult, env agents.EnvironmentProbe) (agents.LaunchPlan, error) {
	if probe.Error != nil {
		return agents.LaunchPlan{}, probe.Error
	}
	if probe.BinaryPath == "" {
		return agents.LaunchPlan{}, fmt.Errorf("agents/claude: Plan requires a successful Probe (BinaryPath empty)")
	}
	if req.Mode != "autonomous" {
		// The plan's first delivery target is autonomous runs. Other
		// modes are recognized by the contract but the launcher
		// refuses them until the supervisor wires interactive /
		// dry-run / continue handling (later milestones).
		return agents.LaunchPlan{}, fmt.Errorf("agents/claude: mode %q not supported yet (autonomous only)", req.Mode)
	}
	if probe.SelectedFlags == nil {
		return agents.LaunchPlan{}, fmt.Errorf("agents/claude: %w", agents.ErrFlagsUnsupported)
	}

	// Claude reads ANTHROPIC_BASE_URL when present, so for the
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
		return agents.LaunchPlan{}, fmt.Errorf("agents/claude: %w", err)
	}

	args := append([]string{}, probe.SelectedFlags...)
	args = append(args, req.ExtraArgs...)

	cmd := backend.Command{
		// Use the contract-declared command name. The backend resolves
		// it inside the env via $PATH; passing the host-side absolute
		// path would not make sense for a sandbox where filesystems
		// differ.
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
