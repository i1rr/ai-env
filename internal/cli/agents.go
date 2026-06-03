package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/i1rr/ai-env/internal/agents"
	"github.com/i1rr/ai-env/internal/agents/claude"
	"github.com/i1rr/ai-env/internal/agents/codex"
	"github.com/i1rr/ai-env/internal/config"
)

// agentsProbeTimeout caps how long a single agent probe (version or
// --help) is allowed to run. Probes shell out to third-party CLIs so we
// keep the timeout short: a hung binary should not wedge `agents
// doctor` or `agents probe`.
const agentsProbeTimeout = 10 * time.Second

// LauncherFactory returns the set of registered agent launchers keyed
// by their short name. Exposed as a variable so tests can swap in a
// fixed set of launchers and assert against the registry without
// shelling out to the real binaries.
var LauncherFactory = func() map[string]agents.Launcher {
	return map[string]agents.Launcher{
		claude.Name: claude.New(),
		codex.Name:  codex.New(),
	}
}

// AgentsListOptions captures the parsed flags for `ai-env agents list`.
// The command takes no positional arguments today; the struct exists so
// future flags (e.g. --json) can slot in without changing the Cobra
// wiring.
type AgentsListOptions struct {
	// Cwd is the working directory the command was invoked from.
	// RunAgentsList walks upward from Cwd looking for the project's
	// .ai-env/ directory so users can run `ai-env agents list` from
	// any subdirectory of a project. Tests pass a temp dir; the CLI
	// wiring passes os.Getwd().
	Cwd string

	// Stdout is the writer for the human-readable table.
	Stdout io.Writer

	// Stderr is the writer for warnings about partial probes.
	Stderr io.Writer
}

// AgentsDoctorOptions captures the parsed flags for `ai-env agents
// doctor`. Doctor runs the same probes the supervisor uses, plus a
// best-effort credential check, and prints pass/fail per agent.
type AgentsDoctorOptions struct {
	Cwd    string
	Stdout io.Writer
	Stderr io.Writer
}

// AgentsProbeOptions captures the parsed flags + positional argument
// for `ai-env agents probe`. Probe targets one agent and prints its
// discovered version, autonomous flags, and captured --help text.
type AgentsProbeOptions struct {
	// AgentName is the positional <agent> argument identifying which
	// launcher to probe. It must match a key in agents.yaml.
	AgentName string

	Cwd    string
	Stdout io.Writer
	Stderr io.Writer
}

// RunAgentsList implements `ai-env agents list`. It loads the project's
// agents.yaml, enumerates the registered launchers, and prints one row
// per agent with binary status and detected version. Agents that the
// host cannot probe (missing binary, etc.) still appear with a clear
// status string so the operator sees the whole registry.
func RunAgentsList(opts AgentsListOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env agents list: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}

	contracts, _, err := loadAgentsContracts(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env agents list: %w", err)
	}

	launchers := LauncherFactory()
	names := registeredAgentNames(contracts, launchers)

	tw := tabwriter.NewWriter(opts.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tBINARY\tVERSION\tSTATUS")
	for _, name := range names {
		row := buildListRow(name, contracts, launchers)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", row.Name, row.Binary, row.Version, row.Status)
	}
	_ = tw.Flush()
	return nil
}

// listRow is one rendered line of `ai-env agents list`.
type listRow struct {
	Name    string
	Binary  string
	Version string
	Status  string
}

// buildListRow assembles a single listing row by running a quick probe
// against the agent. Missing-from-PATH and unparseable versions both
// produce a descriptive Status string instead of an error so the table
// stays uniform.
func buildListRow(name string, contracts map[string]config.AgentEntry, launchers map[string]agents.Launcher) listRow {
	contract, hasContract := contracts[name]
	launcher, hasLauncher := launchers[name]

	row := listRow{
		Name:    name,
		Binary:  "-",
		Version: "-",
		Status:  "-",
	}

	switch {
	case !hasLauncher && !hasContract:
		row.Status = "unknown agent"
		return row
	case !hasLauncher:
		row.Binary = contract.Command
		row.Status = "no launcher registered"
		return row
	case !hasContract:
		row.Status = "no contract in agents.yaml"
		return row
	}

	row.Binary = contract.Command

	ctx, cancel := context.WithTimeout(context.Background(), agentsProbeTimeout)
	defer cancel()
	probe := launcher.Probe(ctx, contract, agents.ProbeDeps{})

	if probe.BinaryPath == "" {
		row.Status = "binary not found"
		return row
	}
	if probe.Version != "" {
		row.Version = probe.Version
	}
	switch {
	case probe.Error != nil && probe.Version == "":
		row.Status = "probe failed"
	case probe.Error != nil && !probe.VersionSupported:
		row.Status = fmt.Sprintf("version unsupported (%s)", contract.VersionConstraint)
	case probe.Error != nil:
		row.Status = "probe failed"
	default:
		row.Status = "ok"
	}
	return row
}

// RunAgentsDoctor implements `ai-env agents doctor`. For every
// registered agent it runs four checks: binary on PATH, version
// satisfies constraint, autonomous flags supported, and credential
// mode resolvable. Each check prints a single PASS/FAIL line with a
// short reason so the operator can scan the output. Doctor exits
// non-zero when any check fails so it can be wired into CI.
func RunAgentsDoctor(opts AgentsDoctorOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env agents doctor: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}

	contracts, _, err := loadAgentsContracts(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env agents doctor: %w", err)
	}

	launchers := LauncherFactory()
	names := registeredAgentNames(contracts, launchers)

	anyFail := false
	for i, name := range names {
		if i > 0 {
			fmt.Fprintln(opts.Stdout, "")
		}
		failed := writeDoctorReport(opts.Stdout, name, contracts, launchers)
		if failed {
			anyFail = true
		}
	}
	if anyFail {
		return errors.New("ai-env agents doctor: one or more checks failed")
	}
	return nil
}

// writeDoctorReport writes the per-agent block to w and returns true
// when any check failed. The block is plain "PASS|FAIL  <check>:
// <reason>" lines so the output is grep-friendly.
func writeDoctorReport(w io.Writer, name string, contracts map[string]config.AgentEntry, launchers map[string]agents.Launcher) bool {
	contract, hasContract := contracts[name]
	launcher, hasLauncher := launchers[name]

	fmt.Fprintf(w, "agent: %s\n", name)

	if !hasContract {
		writeDoctorLine(w, false, "contract", "no entry in agents.yaml")
		return true
	}
	writeDoctorLine(w, true, "contract", fmt.Sprintf("command %q, constraint %q", contract.Command, contract.VersionConstraint))

	if !hasLauncher {
		writeDoctorLine(w, false, "launcher", fmt.Sprintf("no launcher registered for %q", name))
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), agentsProbeTimeout)
	defer cancel()
	probe := launcher.Probe(ctx, contract, agents.ProbeDeps{})

	failed := false

	// 1. Binary present.
	if probe.BinaryPath == "" {
		writeDoctorLine(w, false, "binary", fmt.Sprintf("%s not found on PATH", contract.Command))
		failed = true
	} else {
		writeDoctorLine(w, true, "binary", probe.BinaryPath)
	}

	// 2. Version compatible.
	switch {
	case probe.Version == "" && probe.BinaryPath != "":
		writeDoctorLine(w, false, "version", fmt.Sprintf("could not parse version (%v)", probe.Error))
		failed = true
	case probe.Version == "":
		// Binary missing already reported; suppress duplicate failure.
	case !probe.VersionSupported:
		writeDoctorLine(w, false, "version",
			fmt.Sprintf("%s does not satisfy %s", probe.Version, contract.VersionConstraint))
		failed = true
	default:
		writeDoctorLine(w, true, "version",
			fmt.Sprintf("%s satisfies %s", probe.Version, contract.VersionConstraint))
	}

	// 3. Autonomous flags supported.
	if mode, ok := contract.Modes["autonomous"]; ok {
		switch {
		case probe.HelpOutput == "" && probe.BinaryPath != "" && probe.VersionSupported:
			writeDoctorLine(w, false, "autonomous flags", "could not capture --help output")
			failed = true
		case len(probe.SelectedFlags) > 0:
			writeDoctorLine(w, true, "autonomous flags",
				strings.Join(probe.SelectedFlags, " "))
		case probe.BinaryPath != "" && probe.VersionSupported:
			writeDoctorLine(w, false, "autonomous flags",
				fmt.Sprintf("no candidate matched help (tried %v)", mode.ArgsCandidates))
			failed = true
		}
	}

	// 4. Credential mode resolvable. This is a host-side best-effort
	// probe: we have no backend or proxy plumbed in yet (those land in
	// Plan 04 step 7 / Plan 05), so doctor reports the modes the
	// contract prefers and which raw env vars the host could supply
	// with --allow-raw-model-token-in-sandbox.
	credPass, credReason := evaluateCredentialMode(name, contract.CredentialMode)
	writeDoctorLine(w, credPass, "credential mode", credReason)
	if !credPass {
		failed = true
	}

	return failed
}

// writeDoctorLine renders a single "PASS|FAIL  <check>: <reason>" row.
func writeDoctorLine(w io.Writer, pass bool, check, reason string) {
	tag := "PASS"
	if !pass {
		tag = "FAIL"
	}
	fmt.Fprintf(w, "  %s  %s: %s\n", tag, check, reason)
}

// evaluateCredentialMode is the host-side credential probe used by
// doctor. It walks the contract's preference order and reports the
// first mode the host can plausibly satisfy:
//
//   - backend_managed: cannot be verified without an active backend, so
//     it is reported as deferred-to-run-time and marked PASS.
//   - brokered: same shape as backend_managed — the broker contract is
//     validated by the supervisor at run time (githubbroker /
//     provider-proxy plumbing), so doctor reports it PASS and defers.
//   - provider_proxy: cannot be verified without secrets.local.yaml
//     plumbing (Plan 07); reported as informational.
//   - raw_env_explicit: requires the operator to pass
//     --allow-raw-model-token-in-sandbox at runtime and to have the
//     provider's API key in the host environment. We check whether the
//     env var is present so the operator knows raw-env fallback is at
//     least available.
//
// We mark the check PASS when at least one mode is plausibly available.
// That is intentionally permissive: this command is diagnostic, not a
// gate. The supervisor enforces the real fail-closed check at run time
// via ResolveCredentialMode.
func evaluateCredentialMode(agentName string, cred config.AgentCredentialMode) (bool, string) {
	order := append([]string{cred.Default}, cred.FallbackOrder...)
	var notes []string
	pass := false
	for _, m := range order {
		switch m {
		case "":
			continue
		case "backend_managed":
			notes = append(notes, "backend_managed (verified at run time)")
			pass = true
		case "brokered":
			notes = append(notes, "brokered (validated at run time)")
			pass = true
		case "provider_proxy":
			notes = append(notes, "provider_proxy (requires secrets.local.yaml)")
		case "raw_env_explicit":
			envVar := rawTokenEnvForAgent(agentName)
			if envVar != "" && os.Getenv(envVar) != "" {
				notes = append(notes, fmt.Sprintf("raw_env_explicit (%s set)", envVar))
				pass = true
			} else if envVar != "" {
				notes = append(notes, fmt.Sprintf("raw_env_explicit (%s not set)", envVar))
			} else {
				notes = append(notes, "raw_env_explicit (no known env var)")
			}
		default:
			notes = append(notes, fmt.Sprintf("%s (unknown mode)", m))
		}
	}
	if len(notes) == 0 {
		return false, "no credential modes declared"
	}
	return pass, strings.Join(notes, ", ")
}

// rawTokenEnvForAgent returns the conventional raw-env variable name
// for an agent's provider, or "" when no convention is recorded. This
// is the host-side counterpart of the launcher's credential injection
// and is kept narrow so a new agent does not silently match a stale
// env var.
func rawTokenEnvForAgent(name string) string {
	switch name {
	case "claude":
		return "ANTHROPIC_API_KEY"
	case "codex":
		return "OPENAI_API_KEY"
	default:
		return ""
	}
}

// RunAgentsProbe implements `ai-env agents probe <agent>`. It runs the
// full Probe pipeline for the named agent and prints the discovered
// version, the selected autonomous flags, and the first lines of the
// captured --help output. The probe never trial-runs the agent: it only
// invokes the version subcommand and --help.
func RunAgentsProbe(opts AgentsProbeOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env agents probe: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if strings.TrimSpace(opts.AgentName) == "" {
		return fmt.Errorf("ai-env agents probe: agent name is required")
	}

	contracts, _, err := loadAgentsContracts(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env agents probe: %w", err)
	}

	contract, ok := contracts[opts.AgentName]
	if !ok {
		return fmt.Errorf("ai-env agents probe: agent %q not in agents.yaml", opts.AgentName)
	}
	launcher, ok := LauncherFactory()[opts.AgentName]
	if !ok {
		return fmt.Errorf("ai-env agents probe: no launcher registered for agent %q", opts.AgentName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), agentsProbeTimeout)
	defer cancel()
	probe := launcher.Probe(ctx, contract, agents.ProbeDeps{})

	fmt.Fprintf(opts.Stdout, "agent:       %s\n", opts.AgentName)
	fmt.Fprintf(opts.Stdout, "command:     %s\n", contract.Command)
	fmt.Fprintf(opts.Stdout, "constraint:  %s\n", contract.VersionConstraint)
	if probe.BinaryPath != "" {
		fmt.Fprintf(opts.Stdout, "binary path: %s\n", probe.BinaryPath)
	} else {
		fmt.Fprintln(opts.Stdout, "binary path: (not found)")
	}
	if probe.Version != "" {
		supported := "no"
		if probe.VersionSupported {
			supported = "yes"
		}
		fmt.Fprintf(opts.Stdout, "version:     %s (supported: %s)\n", probe.Version, supported)
	} else {
		fmt.Fprintln(opts.Stdout, "version:     (unknown)")
	}

	if mode, ok := contract.Modes["autonomous"]; ok {
		fmt.Fprintln(opts.Stdout, "autonomous flag candidates:")
		for _, c := range mode.ArgsCandidates {
			fmt.Fprintf(opts.Stdout, "  - %s\n", strings.Join(c, " "))
		}
		if len(probe.SelectedFlags) > 0 {
			fmt.Fprintf(opts.Stdout, "autonomous flags (selected): %s\n",
				strings.Join(probe.SelectedFlags, " "))
		} else {
			fmt.Fprintln(opts.Stdout, "autonomous flags (selected): (none matched)")
		}
	}

	fmt.Fprintf(opts.Stdout, "credential mode default: %s\n", contract.CredentialMode.Default)
	if len(contract.CredentialMode.FallbackOrder) > 0 {
		fmt.Fprintf(opts.Stdout, "credential mode fallback: %s\n",
			strings.Join(contract.CredentialMode.FallbackOrder, ", "))
	}

	if probe.Error != nil {
		fmt.Fprintf(opts.Stdout, "probe error: %v\n", probe.Error)
	}

	if probe.HelpOutput != "" {
		fmt.Fprintln(opts.Stdout, "")
		fmt.Fprintln(opts.Stdout, "--help (first lines):")
		writeHelpPreview(opts.Stdout, probe.HelpOutput, 20)
	}

	if probe.Error != nil {
		return fmt.Errorf("ai-env agents probe: %s: %w", opts.AgentName, probe.Error)
	}
	return nil
}

// writeHelpPreview prints up to maxLines non-empty leading lines of
// helpText, prefixed for visual separation from the rest of the
// report.
func writeHelpPreview(w io.Writer, helpText string, maxLines int) {
	count := 0
	for _, raw := range splitLines(helpText) {
		line := stripTrailingSpace(raw)
		if line == "" && count == 0 {
			continue
		}
		fmt.Fprintf(w, "  %s\n", line)
		count++
		if count >= maxLines {
			break
		}
	}
}

// loadAgentsContracts locates the project's .ai-env/agents.yaml and
// returns its parsed Agents map plus the absolute path that was read.
// The returned path is included so callers can surface it in error
// messages, mirroring the style of `ai-env list`.
func loadAgentsContracts(cwd string) (map[string]config.AgentEntry, string, error) {
	aiEnvDir, err := findAIEnvDir(cwd)
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(aiEnvDir, "agents.yaml")
	cfg, err := config.LoadAgents(path)
	if err != nil {
		return nil, path, err
	}
	return cfg.Agents, path, nil
}

// registeredAgentNames returns the union of contract keys and launcher
// keys, sorted alphabetically. Both sources are unioned so the
// operator sees agents that are registered in code but missing from
// agents.yaml (and vice versa) instead of having them silently
// dropped.
func registeredAgentNames(contracts map[string]config.AgentEntry, launchers map[string]agents.Launcher) []string {
	seen := make(map[string]struct{}, len(contracts)+len(launchers))
	for k := range contracts {
		seen[k] = struct{}{}
	}
	for k := range launchers {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
