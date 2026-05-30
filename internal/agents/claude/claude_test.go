package claude

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/agents"
	"github.com/rivan1986/ai-env/internal/config"
)

// claudeHelpFixture is a plausible subset of `claude --help` output.
// The autonomous flag the contract asks for must appear here for
// SelectAutonomousFlags to accept the candidate.
const claudeHelpFixture = `Usage: claude [options] [prompt]

Options:
  -h, --help                          show this help message and exit
      --version                       print the version and exit
      --dangerously-skip-permissions  skip all permission prompts (autonomous)
      --model <name>                  override the default model
`

// claudeContract returns a contract that matches the agents.yaml shape
// for the claude entry in the plan.
func claudeContract() config.AgentEntry {
	return config.AgentEntry{
		Command:           "claude",
		VersionConstraint: ">=1.0.0",
		Probe: config.AgentProbe{
			Args:  []string{"--version"},
			Parse: "semver",
		},
		Modes: map[string]config.AgentMode{
			"autonomous": {
				ArgsCandidates: [][]string{
					{"--dangerously-skip-permissions"},
				},
			},
		},
		CredentialMode: config.AgentCredentialMode{
			Default:       agents.CredentialModeBackendManaged,
			FallbackOrder: []string{agents.CredentialModeProviderProxy, agents.CredentialModeRawEnvExplicit},
		},
		Requires: []string{"anthropic"},
	}
}

// scriptedRunner returns a ProbeRunner that dispatches on the argv it
// receives. The version probe returns versionOut; the --help probe
// returns helpOut. Any other argv produces an error so a test typo is
// loud rather than silent.
func scriptedRunner(versionOut, helpOut string) agents.ProbeRunner {
	return func(_ context.Context, _ string, args []string, stdout, _ io.Writer) (int, error) {
		switch {
		case len(args) == 1 && args[0] == "--version":
			_, _ = stdout.Write([]byte(versionOut))
			return 0, nil
		case len(args) == 1 && args[0] == "--help":
			_, _ = stdout.Write([]byte(helpOut))
			return 0, nil
		default:
			return -1, errors.New("unexpected argv: " + strings.Join(args, " "))
		}
	}
}

// TestLauncherName ensures the launcher reports the contract key.
func TestLauncherName(t *testing.T) {
	t.Parallel()
	if got := New().Name(); got != Name {
		t.Errorf("Name() = %q, want %q", got, Name)
	}
	if Name != "claude" {
		t.Errorf("Name constant = %q, want %q", Name, "claude")
	}
}

// TestProbe_HappyPath wires fakes through ProbeDeps so the launcher
// runs without a real claude binary. We expect BinaryPath, Version,
// VersionSupported, HelpOutput, and SelectedFlags to all populate.
func TestProbe_HappyPath(t *testing.T) {
	t.Parallel()

	deps := agents.ProbeDeps{
		LookPath: func(name string) (string, error) {
			if name != "claude" {
				t.Errorf("LookPath got %q, want claude", name)
			}
			return "/usr/local/bin/claude", nil
		},
		Runner: scriptedRunner("claude 1.2.3 (build abc)\n", claudeHelpFixture),
	}

	res := New().Probe(context.Background(), claudeContract(), deps)
	if res.Error != nil {
		t.Fatalf("Probe error = %v", res.Error)
	}
	if res.BinaryPath != "/usr/local/bin/claude" {
		t.Errorf("BinaryPath = %q, want /usr/local/bin/claude", res.BinaryPath)
	}
	if res.Version != "1.2.3" {
		t.Errorf("Version = %q, want 1.2.3", res.Version)
	}
	if !res.VersionSupported {
		t.Errorf("VersionSupported = false, want true")
	}
	if !reflect.DeepEqual(res.SelectedFlags, []string{"--dangerously-skip-permissions"}) {
		t.Errorf("SelectedFlags = %v, want [--dangerously-skip-permissions]", res.SelectedFlags)
	}
	if !strings.Contains(res.HelpOutput, "--dangerously-skip-permissions") {
		t.Errorf("HelpOutput missing flag (got %q)", res.HelpOutput)
	}
}

// TestProbe_BinaryMissing exercises the LookPath failure: BinaryPath is
// empty, Error is set, and later fields are zero.
func TestProbe_BinaryMissing(t *testing.T) {
	t.Parallel()

	deps := agents.ProbeDeps{
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
		Runner:   scriptedRunner("", ""),
	}
	res := New().Probe(context.Background(), claudeContract(), deps)
	if res.Error == nil {
		t.Fatalf("Error = nil, want LookPath error")
	}
	if res.BinaryPath != "" {
		t.Errorf("BinaryPath = %q, want empty on lookup miss", res.BinaryPath)
	}
	if res.Version != "" || res.VersionSupported {
		t.Errorf("Version / VersionSupported populated despite LookPath miss")
	}
}

// TestProbe_VersionBelowConstraint covers the "found but too old" path.
// The contract requires >=1.0.0; 0.9.0 must fail closed.
func TestProbe_VersionBelowConstraint(t *testing.T) {
	t.Parallel()

	deps := agents.ProbeDeps{
		LookPath: func(string) (string, error) { return "/usr/local/bin/claude", nil },
		Runner:   scriptedRunner("claude 0.9.0\n", claudeHelpFixture),
	}
	res := New().Probe(context.Background(), claudeContract(), deps)
	if res.Error == nil {
		t.Fatalf("Error = nil, want version-constraint error")
	}
	if res.Version != "0.9.0" {
		t.Errorf("Version = %q, want 0.9.0", res.Version)
	}
	if res.VersionSupported {
		t.Errorf("VersionSupported = true, want false")
	}
	if !strings.Contains(res.Error.Error(), ">=1.0.0") {
		t.Errorf("Error = %v, want it to mention the constraint", res.Error)
	}
}

// TestProbe_FlagsUnsupported confirms the launcher reports
// ErrFlagsUnsupported when none of the args_candidates appear in help.
func TestProbe_FlagsUnsupported(t *testing.T) {
	t.Parallel()

	missingFlagHelp := "Usage: claude [options]\n  --model <name>\n"
	deps := agents.ProbeDeps{
		LookPath: func(string) (string, error) { return "/usr/local/bin/claude", nil },
		Runner:   scriptedRunner("claude 1.0.0\n", missingFlagHelp),
	}
	res := New().Probe(context.Background(), claudeContract(), deps)
	if res.Error == nil {
		t.Fatalf("Error = nil, want flags-unsupported error")
	}
	if !errors.Is(res.Error, agents.ErrFlagsUnsupported) {
		t.Errorf("Error = %v, want it to wrap ErrFlagsUnsupported", res.Error)
	}
	if res.SelectedFlags != nil {
		t.Errorf("SelectedFlags = %v, want nil on unsupported", res.SelectedFlags)
	}
}

// TestPlan_HappyPath ensures Plan builds the autonomous command with
// the selected flag and the credential mode the resolver picks.
func TestPlan_HappyPath(t *testing.T) {
	t.Parallel()

	probe := agents.ProbeResult{
		BinaryPath:       "/usr/local/bin/claude",
		Version:          "1.0.0",
		VersionSupported: true,
		SelectedFlags:    []string{"--dangerously-skip-permissions"},
	}
	req := agents.Request{
		Mode:         "autonomous",
		WorkspaceDir: "/work",
		TaskBody:     "fix tests",
	}
	plan, err := New().Plan(req, probe, agents.EnvironmentProbe{BackendManaged: true})
	if err != nil {
		t.Fatalf("Plan err = %v", err)
	}
	if plan.Command.Program != Name {
		t.Errorf("Program = %q, want %q", plan.Command.Program, Name)
	}
	if !reflect.DeepEqual(plan.Command.Args, []string{"--dangerously-skip-permissions"}) {
		t.Errorf("Args = %v", plan.Command.Args)
	}
	if plan.Command.Dir != "/work" {
		t.Errorf("Dir = %q, want /work", plan.Command.Dir)
	}
	if plan.CredentialMode != agents.CredentialModeBackendManaged {
		t.Errorf("CredentialMode = %q, want %q", plan.CredentialMode, agents.CredentialModeBackendManaged)
	}
	if plan.StdinBody != "fix tests" {
		t.Errorf("StdinBody = %q, want %q", plan.StdinBody, "fix tests")
	}
}

// TestPlan_RefusesNonAutonomous pins the autonomous-only delivery
// scope. Interactive / dry-run / continue must not slip through this
// launcher today.
func TestPlan_RefusesNonAutonomous(t *testing.T) {
	t.Parallel()
	probe := agents.ProbeResult{
		BinaryPath:    "/usr/local/bin/claude",
		SelectedFlags: []string{"--dangerously-skip-permissions"},
	}
	for _, mode := range []string{"interactive", "dry-run", "continue", ""} {
		_, err := New().Plan(agents.Request{Mode: mode}, probe, agents.EnvironmentProbe{BackendManaged: true})
		if err == nil {
			t.Errorf("mode %q: err = nil, want refusal", mode)
		}
	}
}

// TestPlan_ProviderProxySelectedForcesCustomBaseURL covers the claude-
// specific behavior: the launcher always sets AgentSupportsCustomBaseURL
// before calling the resolver, so a configured proxy URL is enough to
// pick provider_proxy even if the caller's EnvironmentProbe did not.
func TestPlan_ProviderProxySelectedForcesCustomBaseURL(t *testing.T) {
	t.Parallel()
	probe := agents.ProbeResult{
		BinaryPath:    "/usr/local/bin/claude",
		SelectedFlags: []string{"--dangerously-skip-permissions"},
	}
	envProbe := agents.EnvironmentProbe{
		// AgentSupportsCustomBaseURL deliberately left false; the
		// launcher must flip it to true before resolving.
		ProviderProxyURL: "https://proxy.example.com",
	}
	plan, err := New().Plan(agents.Request{Mode: "autonomous"}, probe, envProbe)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if plan.CredentialMode != agents.CredentialModeProviderProxy {
		t.Errorf("CredentialMode = %q, want %q", plan.CredentialMode, agents.CredentialModeProviderProxy)
	}
	wantBaseURL := "ANTHROPIC_BASE_URL=https://proxy.example.com"
	found := false
	for _, e := range plan.Command.Env {
		if e == wantBaseURL {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Env = %v, want it to contain %q", plan.Command.Env, wantBaseURL)
	}
}
