package codex

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

// codexHelpFixture is a plausible subset of `codex --help` output.
const codexHelpFixture = `Usage: codex [options]

Options:
  -h, --help                                           show help
      --version                                        print version
      --dangerously-bypass-approvals-and-sandbox       run without approvals (autonomous)
      --model <name>                                   model selector
`

// codexContract returns the agents.yaml-shaped contract for codex.
func codexContract() config.AgentEntry {
	return config.AgentEntry{
		Command:           "codex",
		VersionConstraint: ">=0.0.0",
		Probe: config.AgentProbe{
			Args:  []string{"--version"},
			Parse: "semver",
		},
		Modes: map[string]config.AgentMode{
			"autonomous": {
				ArgsCandidates: [][]string{
					{"--dangerously-bypass-approvals-and-sandbox"},
				},
			},
		},
		CredentialMode: config.AgentCredentialMode{
			Default:       agents.CredentialModeBackendManaged,
			FallbackOrder: []string{agents.CredentialModeProviderProxy, agents.CredentialModeRawEnvExplicit},
		},
		Requires: []string{"openai"},
	}
}

// scriptedRunner dispatches on argv: --version returns versionOut,
// --help returns helpOut, anything else fails loudly.
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
	if Name != "codex" {
		t.Errorf("Name constant = %q, want %q", Name, "codex")
	}
}

// TestProbe_HappyPath wires fakes through ProbeDeps and asserts the
// expected ProbeResult shape.
func TestProbe_HappyPath(t *testing.T) {
	t.Parallel()

	deps := agents.ProbeDeps{
		LookPath: func(name string) (string, error) {
			if name != "codex" {
				t.Errorf("LookPath got %q, want codex", name)
			}
			return "/usr/local/bin/codex", nil
		},
		Runner: scriptedRunner("codex 0.3.1\n", codexHelpFixture),
	}
	res := New().Probe(context.Background(), codexContract(), deps)
	if res.Error != nil {
		t.Fatalf("Probe error = %v", res.Error)
	}
	if res.Version != "0.3.1" {
		t.Errorf("Version = %q, want 0.3.1", res.Version)
	}
	if !res.VersionSupported {
		t.Errorf("VersionSupported = false, want true")
	}
	want := []string{"--dangerously-bypass-approvals-and-sandbox"}
	if !reflect.DeepEqual(res.SelectedFlags, want) {
		t.Errorf("SelectedFlags = %v, want %v", res.SelectedFlags, want)
	}
}

// TestProbe_FlagsUnsupported confirms the launcher reports
// ErrFlagsUnsupported when none of the candidates appear in help.
func TestProbe_FlagsUnsupported(t *testing.T) {
	t.Parallel()

	deps := agents.ProbeDeps{
		LookPath: func(string) (string, error) { return "/usr/local/bin/codex", nil },
		Runner:   scriptedRunner("codex 0.3.0\n", "Usage: codex [options]\n  --model <name>\n"),
	}
	res := New().Probe(context.Background(), codexContract(), deps)
	if res.Error == nil {
		t.Fatalf("Error = nil, want flags-unsupported error")
	}
	if !errors.Is(res.Error, agents.ErrFlagsUnsupported) {
		t.Errorf("Error = %v, want ErrFlagsUnsupported", res.Error)
	}
}

// TestProbe_VersionProbeFails covers the version-probe failure path:
// the binary exists but `--version` errors out. The launcher must surface
// the runner error through ProbeResult.Error.
func TestProbe_VersionProbeFails(t *testing.T) {
	t.Parallel()

	deps := agents.ProbeDeps{
		LookPath: func(string) (string, error) { return "/usr/local/bin/codex", nil },
		Runner: func(_ context.Context, _ string, args []string, stdout, stderr io.Writer) (int, error) {
			if len(args) == 1 && args[0] == "--version" {
				_, _ = stderr.Write([]byte("not initialized"))
				return 1, nil
			}
			return 0, nil
		},
	}
	res := New().Probe(context.Background(), codexContract(), deps)
	if res.Error == nil {
		t.Fatalf("Error = nil, want version-probe failure")
	}
	if res.Version != "" || res.VersionSupported {
		t.Errorf("Version/VersionSupported populated despite version probe failure")
	}
}

// TestPlan_HappyPath confirms the launcher builds a backend.Command
// targeting the codex binary with the selected autonomous flag.
func TestPlan_HappyPath(t *testing.T) {
	t.Parallel()

	probe := agents.ProbeResult{
		BinaryPath:       "/usr/local/bin/codex",
		Version:          "0.3.0",
		VersionSupported: true,
		SelectedFlags:    []string{"--dangerously-bypass-approvals-and-sandbox"},
	}
	req := agents.Request{
		Mode:         "autonomous",
		WorkspaceDir: "/work",
		TaskBody:     "refactor",
		ExtraArgs:    []string{"--model", "gpt-x"},
	}
	plan, err := New().Plan(req, probe, agents.EnvironmentProbe{BackendManaged: true})
	if err != nil {
		t.Fatalf("Plan err = %v", err)
	}
	if plan.Command.Program != Name {
		t.Errorf("Program = %q, want %q", plan.Command.Program, Name)
	}
	wantArgs := []string{"--dangerously-bypass-approvals-and-sandbox", "--model", "gpt-x"}
	if !reflect.DeepEqual(plan.Command.Args, wantArgs) {
		t.Errorf("Args = %v, want %v", plan.Command.Args, wantArgs)
	}
	if plan.CredentialMode != agents.CredentialModeBackendManaged {
		t.Errorf("CredentialMode = %q, want %q", plan.CredentialMode, agents.CredentialModeBackendManaged)
	}
	if plan.StdinBody != "refactor" {
		t.Errorf("StdinBody = %q, want %q", plan.StdinBody, "refactor")
	}
}

// TestPlan_RawTokenRequiresFlag confirms raw_env_explicit is gated on
// AllowRawModelToken.
func TestPlan_RawTokenRequiresFlag(t *testing.T) {
	t.Parallel()

	probe := agents.ProbeResult{
		BinaryPath:    "/usr/local/bin/codex",
		SelectedFlags: []string{"--dangerously-bypass-approvals-and-sandbox"},
	}
	envProbe := agents.EnvironmentProbe{
		RawTokenEnv: []string{"OPENAI_API_KEY=sk-test"},
	}

	// Without the flag, Plan fails closed because no other mode is satisfied.
	_, err := New().Plan(agents.Request{Mode: "autonomous"}, probe, envProbe)
	if err == nil {
		t.Errorf("err = nil, want fail-closed without AllowRawModelToken")
	}

	// With the flag, raw_env_explicit is chosen and OPENAI_API_KEY is
	// injected into the command environment.
	plan, err := New().Plan(agents.Request{Mode: "autonomous", AllowRawModelToken: true}, probe, envProbe)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if plan.CredentialMode != agents.CredentialModeRawEnvExplicit {
		t.Errorf("CredentialMode = %q, want %q", plan.CredentialMode, agents.CredentialModeRawEnvExplicit)
	}
	found := false
	for _, e := range plan.Command.Env {
		if e == "OPENAI_API_KEY=sk-test" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Env = %v, want it to contain OPENAI_API_KEY=sk-test", plan.Command.Env)
	}
}

// TestPlan_RefusesNonAutonomous mirrors the claude launcher test.
func TestPlan_RefusesNonAutonomous(t *testing.T) {
	t.Parallel()
	probe := agents.ProbeResult{
		BinaryPath:    "/usr/local/bin/codex",
		SelectedFlags: []string{"--dangerously-bypass-approvals-and-sandbox"},
	}
	for _, mode := range []string{"interactive", "dry-run", "continue", ""} {
		_, err := New().Plan(agents.Request{Mode: mode}, probe, agents.EnvironmentProbe{BackendManaged: true})
		if err == nil {
			t.Errorf("mode %q: err = nil, want refusal", mode)
		}
	}
}
