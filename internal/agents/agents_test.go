package agents

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/config"
)

// TestExtractSemver pins the regex used to pull a version token out of
// `<agent> --version` output. The regex deliberately matches the first
// dotted-numeric token; tests document the boundary cases launchers
// rely on (leading "v", embedded version, no version).
func TestExtractSemver(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain three components", in: "1.2.3", want: "1.2.3"},
		{name: "plain two components", in: "0.4", want: "0.4"},
		{name: "leading v stripped", in: "v0.4.2", want: "0.4.2"},
		{name: "embedded in line", in: "claude version 1.0.0 (build abc)", want: "1.0.0"},
		{name: "first match wins", in: "build 1.2 then v0.5.0", want: "1.2"},
		{name: "no version found", in: "no numbers here", want: ""},
		{name: "empty input", in: "", want: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ExtractSemver(tc.in); got != tc.want {
				t.Errorf("ExtractSemver(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseSemver covers the parser the SatisfiesConstraint resolver
// relies on. The parser accepts 1-3 dotted components with an optional
// leading "v" / "V" and trims "-rc1" or "+build" suffixes; everything
// else fails closed.
func TestParseSemver(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      string
		want    Semver
		wantErr bool
	}{
		{name: "three components", in: "1.2.3", want: Semver{1, 2, 3}},
		{name: "two components", in: "0.4", want: Semver{0, 4, 0}},
		{name: "one component", in: "5", want: Semver{5, 0, 0}},
		{name: "leading v", in: "v1.2.3", want: Semver{1, 2, 3}},
		{name: "leading V uppercase", in: "V1.2.3", want: Semver{1, 2, 3}},
		{name: "trim prerelease", in: "1.2.3-rc1", want: Semver{1, 2, 3}},
		{name: "trim build metadata", in: "1.2.3+sha", want: Semver{1, 2, 3}},
		{name: "trim both", in: "v1.2.3-alpha+sha", want: Semver{1, 2, 3}},
		{name: "trim whitespace", in: "  1.0.0  ", want: Semver{1, 0, 0}},
		{name: "empty rejected", in: "", wantErr: true},
		{name: "whitespace only rejected", in: "   ", wantErr: true},
		{name: "four components rejected", in: "1.2.3.4", wantErr: true},
		{name: "non-numeric rejected", in: "1.x.3", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseSemver(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSemver(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSemver(%q) error = %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseSemver(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestSemverCmp pins the ordering SatisfiesConstraint relies on.
func TestSemverCmp(t *testing.T) {
	t.Parallel()

	cases := []struct {
		a, b Semver
		want int
	}{
		{Semver{0, 1, 0}, Semver{0, 1, 0}, 0},
		{Semver{0, 1, 0}, Semver{0, 1, 1}, -1},
		{Semver{0, 2, 0}, Semver{0, 1, 9}, 1},
		{Semver{1, 0, 0}, Semver{0, 99, 99}, 1},
		{Semver{2, 0, 0}, Semver{1, 9, 9}, 1},
	}
	for _, tc := range cases {
		if got := tc.a.Cmp(tc.b); got != tc.want {
			t.Errorf("%+v.Cmp(%+v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestSatisfiesConstraint covers each operator the resolver understands
// plus the failure modes the launchers depend on. Bare versions are
// treated as "=" per the doc comment; unknown operators / unparseable
// targets must fail closed so a typo in agents.yaml cannot silently
// disable version gating.
func TestSatisfiesConstraint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		version    string
		constraint string
		want       bool
		wantErr    bool
	}{
		{name: "empty constraint always matches", version: "1.2.3", constraint: "", want: true},
		{name: "whitespace constraint always matches", version: "0.0.1", constraint: "   ", want: true},
		{name: ">= satisfied equal", version: "1.0.0", constraint: ">=1.0.0", want: true},
		{name: ">= satisfied above", version: "1.2.3", constraint: ">=1.0.0", want: true},
		{name: ">= not satisfied below", version: "0.9.9", constraint: ">=1.0.0", want: false},
		{name: "> strictly above", version: "1.0.1", constraint: ">1.0.0", want: true},
		{name: "> not satisfied at equal", version: "1.0.0", constraint: ">1.0.0", want: false},
		{name: "<= satisfied equal", version: "2.0.0", constraint: "<=2.0.0", want: true},
		{name: "<= satisfied below", version: "1.9.9", constraint: "<=2.0.0", want: true},
		{name: "<= not satisfied above", version: "2.0.1", constraint: "<=2.0.0", want: false},
		{name: "< strictly below", version: "1.9.9", constraint: "<2.0.0", want: true},
		{name: "< not satisfied equal", version: "2.0.0", constraint: "<2.0.0", want: false},
		{name: "= exact match", version: "1.2.3", constraint: "=1.2.3", want: true},
		{name: "= mismatch", version: "1.2.4", constraint: "=1.2.3", want: false},
		{name: "bare version is exact match", version: "1.2.3", constraint: "1.2.3", want: true},
		{name: "bare mismatch", version: "1.2.4", constraint: "1.2.3", want: false},
		{name: "v prefix on both sides", version: "v1.0.0", constraint: ">=v1.0.0", want: true},
		{name: "prerelease version against >= range", version: "1.0.0-rc1", constraint: ">=1.0.0", want: true},
		{name: "missing patch component", version: "1.2", constraint: ">=1.2.0", want: true},
		{name: "invalid version returns error", version: "not-a-version", constraint: ">=1.0.0", wantErr: true},
		{name: "invalid target returns error", version: "1.0.0", constraint: ">=not-a-version", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := SatisfiesConstraint(tc.version, tc.constraint)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("SatisfiesConstraint(%q, %q) = %v, want error", tc.version, tc.constraint, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SatisfiesConstraint(%q, %q) error = %v", tc.version, tc.constraint, err)
			}
			if got != tc.want {
				t.Errorf("SatisfiesConstraint(%q, %q) = %v, want %v", tc.version, tc.constraint, got, tc.want)
			}
		})
	}
}

// --- Flag probe / help-text logic ---------------------------------------

// claudeHelpFixture is a plausible subset of `claude --help` output. It
// includes the autonomous flag we care about so SelectAutonomousFlags
// can find it, plus surrounding noise to confirm the substring match
// does not over-trigger on whitespace.
const claudeHelpFixture = `Usage: claude [options] [prompt]

Run Claude Code in autonomous or interactive mode.

Options:
  -h, --help                          show this help message and exit
      --version                       print the version and exit
      --dangerously-skip-permissions  skip all permission prompts (autonomous)
      --model <name>                  override the default model
      --output-format <fmt>           plain | json
`

// codexHelpFixture is the corresponding fixture for the codex CLI.
const codexHelpFixture = `Usage: codex [options]

Options:
  -h, --help                                           show help
      --version                                        print version
      --dangerously-bypass-approvals-and-sandbox       run without approvals (autonomous)
      --model <name>                                   model selector
`

// TestFlagsSupportedByHelp confirms the help-text probe accepts a
// candidate when every flag token appears in the fixture, and rejects
// when even one is missing.
func TestFlagsSupportedByHelp(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		candidate []string
		help      string
		want      bool
	}{
		{
			name:      "claude dangerously-skip-permissions present",
			candidate: []string{"--dangerously-skip-permissions"},
			help:      claudeHelpFixture,
			want:      true,
		},
		{
			name:      "codex bypass-approvals present",
			candidate: []string{"--dangerously-bypass-approvals-and-sandbox"},
			help:      codexHelpFixture,
			want:      true,
		},
		{
			name:      "claude flag missing from codex help",
			candidate: []string{"--dangerously-skip-permissions"},
			help:      codexHelpFixture,
			want:      false,
		},
		{
			name:      "missing flag rejects whole candidate",
			candidate: []string{"--dangerously-skip-permissions", "--no-such-flag"},
			help:      claudeHelpFixture,
			want:      false,
		},
		{
			name:      "positional-only candidate matches unconditionally",
			candidate: []string{"prompt.md"},
			help:      "",
			want:      true,
		},
		{
			name:      "empty candidate matches unconditionally",
			candidate: nil,
			help:      "anything",
			want:      true,
		},
		{
			name:      "positional plus supported flag accepted",
			candidate: []string{"--dangerously-skip-permissions", "prompt.md"},
			help:      claudeHelpFixture,
			want:      true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := FlagsSupportedByHelp(tc.candidate, tc.help); got != tc.want {
				t.Errorf("FlagsSupportedByHelp(%v) = %v, want %v", tc.candidate, got, tc.want)
			}
		})
	}
}

// TestSelectAutonomousFlags walks the candidate list and confirms the
// first supported entry is returned with an independent backing slice
// (mutating the result must not corrupt the contract). When nothing
// matches, the function returns (nil, false) so the launcher can attach
// the contract's candidate list to the resulting error message.
func TestSelectAutonomousFlags(t *testing.T) {
	t.Parallel()

	t.Run("first supported candidate wins", func(t *testing.T) {
		t.Parallel()
		mode := config.AgentMode{ArgsCandidates: [][]string{
			{"--no-such-flag"},
			{"--dangerously-skip-permissions"},
		}}
		flags, ok := SelectAutonomousFlags(mode, claudeHelpFixture)
		if !ok {
			t.Fatalf("SelectAutonomousFlags ok = false, want true")
		}
		if !reflect.DeepEqual(flags, []string{"--dangerously-skip-permissions"}) {
			t.Errorf("flags = %v, want [--dangerously-skip-permissions]", flags)
		}
	})

	t.Run("no candidate supported returns nil false", func(t *testing.T) {
		t.Parallel()
		mode := config.AgentMode{ArgsCandidates: [][]string{
			{"--no-such-flag"},
			{"--another-missing"},
		}}
		flags, ok := SelectAutonomousFlags(mode, claudeHelpFixture)
		if ok {
			t.Errorf("SelectAutonomousFlags ok = true, want false")
		}
		if flags != nil {
			t.Errorf("flags = %v, want nil", flags)
		}
	})

	t.Run("returned slice is independent of contract", func(t *testing.T) {
		t.Parallel()
		original := []string{"--dangerously-skip-permissions"}
		mode := config.AgentMode{ArgsCandidates: [][]string{original}}
		flags, ok := SelectAutonomousFlags(mode, claudeHelpFixture)
		if !ok {
			t.Fatalf("SelectAutonomousFlags ok = false")
		}
		flags[0] = "MUTATED"
		if original[0] != "--dangerously-skip-permissions" {
			t.Errorf("mutating result mutated contract candidate: %q", original[0])
		}
	})

	t.Run("empty mode has no candidates", func(t *testing.T) {
		t.Parallel()
		flags, ok := SelectAutonomousFlags(config.AgentMode{}, claudeHelpFixture)
		if ok || flags != nil {
			t.Errorf("SelectAutonomousFlags({}) = (%v, %v), want (nil, false)", flags, ok)
		}
	})
}

// fakeRunner builds a ProbeRunner that returns canned output for a
// single invocation. It records the argv it received so tests can
// assert ProbeVersion / ProbeHelp invoked the binary with the expected
// argv.
type fakeRunner struct {
	stdout   string
	stderr   string
	exitCode int
	spawnErr error
	gotArgs  []string
	gotBin   string
}

func (f *fakeRunner) Runner() ProbeRunner {
	return func(_ context.Context, binary string, args []string, stdout, stderr io.Writer) (int, error) {
		f.gotBin = binary
		f.gotArgs = append([]string(nil), args...)
		if stdout != nil && f.stdout != "" {
			_, _ = stdout.Write([]byte(f.stdout))
		}
		if stderr != nil && f.stderr != "" {
			_, _ = stderr.Write([]byte(f.stderr))
		}
		if f.spawnErr != nil {
			return -1, f.spawnErr
		}
		return f.exitCode, nil
	}
}

// TestProbeVersion covers the version-extraction seam: a successful
// runner produces stdout the regex picks up, a non-zero exit code is
// reported as an error, and unparsable stdout fails closed.
func TestProbeVersion(t *testing.T) {
	t.Parallel()

	probe := config.AgentProbe{Args: []string{"--version"}, Parse: "semver"}

	t.Run("happy path semver extracted", func(t *testing.T) {
		t.Parallel()
		fr := &fakeRunner{stdout: "claude 1.2.3 (build abc)\n", exitCode: 0}
		v, raw, err := ProbeVersion(context.Background(), ProbeDeps{Runner: fr.Runner()}, "claude", probe)
		if err != nil {
			t.Fatalf("ProbeVersion error = %v", err)
		}
		if v != "1.2.3" {
			t.Errorf("version = %q, want 1.2.3", v)
		}
		if !strings.Contains(raw, "1.2.3") {
			t.Errorf("raw stdout = %q, want it to contain version", raw)
		}
		if fr.gotBin != "claude" || !reflect.DeepEqual(fr.gotArgs, []string{"--version"}) {
			t.Errorf("runner saw bin=%q args=%v, want bin=claude args=[--version]", fr.gotBin, fr.gotArgs)
		}
	})

	t.Run("non-zero exit returns error", func(t *testing.T) {
		t.Parallel()
		fr := &fakeRunner{stderr: "not installed", exitCode: 1}
		_, _, err := ProbeVersion(context.Background(), ProbeDeps{Runner: fr.Runner()}, "claude", probe)
		if err == nil {
			t.Fatalf("ProbeVersion err = nil, want error on non-zero exit")
		}
		if !strings.Contains(err.Error(), "exited 1") {
			t.Errorf("err = %v, want it to mention exit code", err)
		}
	})

	t.Run("unparsable stdout returns error", func(t *testing.T) {
		t.Parallel()
		fr := &fakeRunner{stdout: "no version here", exitCode: 0}
		_, _, err := ProbeVersion(context.Background(), ProbeDeps{Runner: fr.Runner()}, "claude", probe)
		if err == nil {
			t.Fatalf("ProbeVersion err = nil, want error on unparsable stdout")
		}
	})

	t.Run("spawn error surfaces", func(t *testing.T) {
		t.Parallel()
		fr := &fakeRunner{spawnErr: errors.New("boom")}
		_, _, err := ProbeVersion(context.Background(), ProbeDeps{Runner: fr.Runner()}, "claude", probe)
		if err == nil {
			t.Fatalf("err = nil, want spawn error")
		}
		if !strings.Contains(err.Error(), "boom") {
			t.Errorf("err = %v, want it to wrap spawn error", err)
		}
	})

	t.Run("unsupported parse mode rejected", func(t *testing.T) {
		t.Parallel()
		fr := &fakeRunner{stdout: "claude 1.0.0", exitCode: 0}
		bad := config.AgentProbe{Args: []string{"--version"}, Parse: "unknown"}
		_, _, err := ProbeVersion(context.Background(), ProbeDeps{Runner: fr.Runner()}, "claude", bad)
		if err == nil {
			t.Fatalf("err = nil, want error for unsupported parse")
		}
	})

	t.Run("empty parse defaults to semver", func(t *testing.T) {
		t.Parallel()
		fr := &fakeRunner{stdout: "v0.5.0", exitCode: 0}
		empty := config.AgentProbe{Args: []string{"--version"}, Parse: ""}
		v, _, err := ProbeVersion(context.Background(), ProbeDeps{Runner: fr.Runner()}, "claude", empty)
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if v != "0.5.0" {
			t.Errorf("version = %q, want 0.5.0", v)
		}
	})
}

// TestProbeHelp covers the --help capture seam. We confirm the runner
// receives "--help" as its only arg, stdout / stderr are merged, and a
// non-zero exit with empty streams is treated as a hard failure.
func TestProbeHelp(t *testing.T) {
	t.Parallel()

	t.Run("merges stdout and stderr", func(t *testing.T) {
		t.Parallel()
		fr := &fakeRunner{stdout: "USAGE\n", stderr: "OPTIONS\n", exitCode: 0}
		out, err := ProbeHelp(context.Background(), ProbeDeps{Runner: fr.Runner()}, "claude")
		if err != nil {
			t.Fatalf("ProbeHelp err = %v", err)
		}
		if !strings.Contains(out, "USAGE") || !strings.Contains(out, "OPTIONS") {
			t.Errorf("output = %q, want it to contain both stdout and stderr", out)
		}
		if !reflect.DeepEqual(fr.gotArgs, []string{"--help"}) {
			t.Errorf("runner argv = %v, want [--help]", fr.gotArgs)
		}
	})

	t.Run("non-zero exit with stdout still returns output", func(t *testing.T) {
		t.Parallel()
		fr := &fakeRunner{stdout: "USAGE\n", exitCode: 1}
		out, err := ProbeHelp(context.Background(), ProbeDeps{Runner: fr.Runner()}, "codex")
		if err != nil {
			t.Fatalf("ProbeHelp err = %v, want nil (CLIs sometimes exit 1 on --help)", err)
		}
		if !strings.Contains(out, "USAGE") {
			t.Errorf("output = %q, want it to contain stdout", out)
		}
	})

	t.Run("non-zero exit with no output is an error", func(t *testing.T) {
		t.Parallel()
		fr := &fakeRunner{exitCode: 1}
		_, err := ProbeHelp(context.Background(), ProbeDeps{Runner: fr.Runner()}, "codex")
		if err == nil {
			t.Fatalf("ProbeHelp err = nil, want error for empty output non-zero exit")
		}
	})

	t.Run("spawn error surfaces", func(t *testing.T) {
		t.Parallel()
		fr := &fakeRunner{spawnErr: errors.New("kaboom")}
		_, err := ProbeHelp(context.Background(), ProbeDeps{Runner: fr.Runner()}, "claude")
		if err == nil {
			t.Fatalf("err = nil, want spawn error")
		}
		if !strings.Contains(err.Error(), "kaboom") {
			t.Errorf("err = %v, want it to wrap spawn error", err)
		}
	})

	t.Run("context cancellation propagates", func(t *testing.T) {
		t.Parallel()
		// The runner inspects the context and returns its error. This
		// confirms ProbeHelp does not strip the deadline before calling.
		runner := func(ctx context.Context, _ string, _ []string, _, _ io.Writer) (int, error) {
			dl, ok := ctx.Deadline()
			if !ok {
				return 0, errors.New("no deadline")
			}
			if time.Until(dl) <= 0 {
				return 0, errors.New("deadline already past")
			}
			return 0, errors.New("ctx-was-set")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := ProbeHelp(ctx, ProbeDeps{Runner: runner}, "claude")
		if err == nil || !strings.Contains(err.Error(), "ctx-was-set") {
			t.Errorf("err = %v, want runner to observe context deadline", err)
		}
	})
}

// --- Credential mode resolution ----------------------------------------

// claudeContract is the default contract Claude uses: prefer
// backend_managed, fall back to provider_proxy, then raw_env_explicit.
var claudeContract = config.AgentCredentialMode{
	Default:       CredentialModeBackendManaged,
	FallbackOrder: []string{CredentialModeProviderProxy, CredentialModeRawEnvExplicit},
}

// TestResolveCredentialMode_BackendManagedSelected confirms the
// happy-path mode (backend brokers credentials).
func TestResolveCredentialMode_BackendManagedSelected(t *testing.T) {
	t.Parallel()

	mode, env, err := ResolveCredentialMode(claudeContract, EnvironmentProbe{BackendManaged: true}, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if mode != CredentialModeBackendManaged {
		t.Errorf("mode = %q, want %q", mode, CredentialModeBackendManaged)
	}
	if env != nil {
		t.Errorf("injectedEnv = %v, want nil (backend handles injection)", env)
	}
}

// TestResolveCredentialMode_ProviderProxySelected exercises the
// fallback when backend_managed is unavailable but the agent supports a
// custom base URL and one is configured.
func TestResolveCredentialMode_ProviderProxySelected(t *testing.T) {
	t.Parallel()

	probe := EnvironmentProbe{
		BackendManaged:             false,
		AgentSupportsCustomBaseURL: true,
		ProviderProxyURL:           "https://proxy.example.com",
	}
	mode, env, err := ResolveCredentialMode(claudeContract, probe, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if mode != CredentialModeProviderProxy {
		t.Fatalf("mode = %q, want %q", mode, CredentialModeProviderProxy)
	}
	wantEnv := []string{
		"ANTHROPIC_BASE_URL=https://proxy.example.com",
		"OPENAI_BASE_URL=https://proxy.example.com",
	}
	if !reflect.DeepEqual(env, wantEnv) {
		t.Errorf("injectedEnv = %v, want %v", env, wantEnv)
	}
}

// TestResolveCredentialMode_RawEnvNeedsFlag covers the
// --allow-raw-model-token-in-sandbox gate: raw_env_explicit is skipped
// unless the operator opted in.
func TestResolveCredentialMode_RawEnvNeedsFlag(t *testing.T) {
	t.Parallel()

	probe := EnvironmentProbe{
		BackendManaged:             false,
		AgentSupportsCustomBaseURL: false,
		RawTokenEnv:                []string{"ANTHROPIC_API_KEY=sk-test"},
	}

	// Without the opt-in flag, the resolver fails closed.
	_, _, err := ResolveCredentialMode(claudeContract, probe, false)
	if err == nil {
		t.Fatalf("err = nil, want fail-closed without allowRawToken")
	}
	if !errors.Is(err, ErrCredentialModeUnavailable) {
		t.Errorf("err = %v, want it to wrap ErrCredentialModeUnavailable", err)
	}

	// With the opt-in flag, raw_env_explicit is selected and the token
	// is injected verbatim.
	mode, env, err := ResolveCredentialMode(claudeContract, probe, true)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if mode != CredentialModeRawEnvExplicit {
		t.Errorf("mode = %q, want %q", mode, CredentialModeRawEnvExplicit)
	}
	if !reflect.DeepEqual(env, []string{"ANTHROPIC_API_KEY=sk-test"}) {
		t.Errorf("injectedEnv = %v, want raw token forwarded", env)
	}
}

// TestResolveCredentialMode_FailClosedWithTrace asserts that when no
// mode is selectable, every contract mode is recorded in the
// CredentialResolutionError. This is what doctor surfaces to operators.
func TestResolveCredentialMode_FailClosedWithTrace(t *testing.T) {
	t.Parallel()

	probe := EnvironmentProbe{}
	_, err := ResolveCredentialModeDetailed(claudeContract, probe, false)
	if err == nil {
		t.Fatalf("err = nil, want fail-closed when no mode is satisfied")
	}
	if !errors.Is(err, ErrCredentialModeUnavailable) {
		t.Errorf("err = %v, want it to wrap ErrCredentialModeUnavailable", err)
	}

	var resErr *CredentialResolutionError
	if !errors.As(err, &resErr) {
		t.Fatalf("err = %T, want *CredentialResolutionError", err)
	}
	if len(resErr.Considered) != 3 {
		t.Fatalf("considered = %d entries, want 3 (one per contract mode)", len(resErr.Considered))
	}
	for _, a := range resErr.Considered {
		if a.OK {
			t.Errorf("attempt %q OK = true, want all false on fail-closed", a.Mode)
		}
	}
	// The error message should mention each mode's rejection reason.
	msg := err.Error()
	for _, m := range []string{
		CredentialModeBackendManaged,
		CredentialModeProviderProxy,
		CredentialModeRawEnvExplicit,
	} {
		if !strings.Contains(msg, m) {
			t.Errorf("err message %q missing mode %q", msg, m)
		}
	}
}

// TestResolveCredentialMode_BrokeredSelectsWhenBackendManaged confirms
// the runtime accepts brokered (the default-scaffold mode) without
// regressing to ErrUnknownCredentialMode. Doctor already reports PASS
// for brokered; this pins the runtime to match so `ai-env run` works
// against a freshly scaffolded project.
func TestResolveCredentialMode_BrokeredSelectsWhenBackendManaged(t *testing.T) {
	t.Parallel()

	contract := config.AgentCredentialMode{
		Default:       CredentialModeBrokered,
		FallbackOrder: []string{CredentialModeRawEnvExplicit},
	}
	probe := EnvironmentProbe{BackendManaged: true}
	res, err := ResolveCredentialModeDetailed(contract, probe, false)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if res.Mode != CredentialModeBrokered {
		t.Errorf("Mode = %q, want %q", res.Mode, CredentialModeBrokered)
	}
	if res.InjectedEnv != nil {
		t.Errorf("InjectedEnv = %v, want nil (backend brokers credential)", res.InjectedEnv)
	}
	if res.RequiresWarning {
		t.Errorf("RequiresWarning = true, want false for brokered")
	}
}

// TestResolveCredentialMode_BrokeredFallsThroughWhenNoBackend confirms
// brokered defers to the next mode in FallbackOrder when the backend
// does not advertise managed credentials.
func TestResolveCredentialMode_BrokeredFallsThroughWhenNoBackend(t *testing.T) {
	t.Parallel()

	contract := config.AgentCredentialMode{
		Default:       CredentialModeBrokered,
		FallbackOrder: []string{CredentialModeBackendManaged},
	}
	probe := EnvironmentProbe{BackendManaged: false}
	_, err := ResolveCredentialModeDetailed(contract, probe, false)
	if err == nil {
		t.Fatalf("err = nil, want fail-closed when neither mode satisfies")
	}
	if !errors.Is(err, ErrCredentialModeUnavailable) {
		t.Errorf("err = %v, want it to wrap ErrCredentialModeUnavailable", err)
	}
	var resErr *CredentialResolutionError
	if !errors.As(err, &resErr) {
		t.Fatalf("err = %T, want *CredentialResolutionError", err)
	}
	if len(resErr.Considered) != 2 {
		t.Fatalf("considered = %d, want 2 entries (brokered + backend_managed)", len(resErr.Considered))
	}
	if resErr.Considered[0].Mode != CredentialModeBrokered {
		t.Errorf("first attempt = %q, want %q (preserved order)", resErr.Considered[0].Mode, CredentialModeBrokered)
	}
}

// TestResolveCredentialMode_UnknownModeFailsClosed protects against
// silent typos in agents.yaml.
func TestResolveCredentialMode_UnknownModeFailsClosed(t *testing.T) {
	t.Parallel()

	contract := config.AgentCredentialMode{Default: "magic_mode"}
	_, err := ResolveCredentialModeDetailed(contract, EnvironmentProbe{BackendManaged: true}, true)
	if err == nil {
		t.Fatalf("err = nil, want unknown-mode error")
	}
	if !errors.Is(err, ErrUnknownCredentialMode) {
		t.Errorf("err = %v, want it to wrap ErrUnknownCredentialMode", err)
	}
}

// TestResolveCredentialMode_ProviderProxyRequiresBothSignals confirms
// the resolver does not select provider_proxy when only one of the two
// required signals is present.
func TestResolveCredentialMode_ProviderProxyRequiresBothSignals(t *testing.T) {
	t.Parallel()

	// URL present but agent does not support custom base URL.
	probe := EnvironmentProbe{
		AgentSupportsCustomBaseURL: false,
		ProviderProxyURL:           "https://proxy.example.com",
	}
	if _, err := ResolveCredentialModeDetailed(claudeContract, probe, false); err == nil {
		t.Errorf("err = nil, want fail-closed when agent does not support custom base URL")
	}

	// Agent supports custom base URL but no proxy URL configured.
	probe = EnvironmentProbe{AgentSupportsCustomBaseURL: true}
	if _, err := ResolveCredentialModeDetailed(claudeContract, probe, false); err == nil {
		t.Errorf("err = nil, want fail-closed when proxy URL is empty")
	}
}

// TestResolveCredentialMode_RequiresWarning confirms the resolver
// flags raw_env_explicit selection for the supervisor's banner.
func TestResolveCredentialMode_RequiresWarning(t *testing.T) {
	t.Parallel()

	probe := EnvironmentProbe{RawTokenEnv: []string{"ANTHROPIC_API_KEY=sk-test"}}
	res, err := ResolveCredentialModeDetailed(claudeContract, probe, true)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !res.RequiresWarning {
		t.Errorf("RequiresWarning = false, want true for raw_env_explicit")
	}
	if !IsRawTokenMode(res.Mode) {
		t.Errorf("IsRawTokenMode(%q) = false, want true", res.Mode)
	}
}

// TestResolveCredentialMode_PreservesOrder confirms the per-mode trace
// records modes in the contract's declared order (Default first, then
// FallbackOrder). The supervisor uses this to print a faithful audit.
func TestResolveCredentialMode_PreservesOrder(t *testing.T) {
	t.Parallel()

	// Build a contract that intentionally inverts the canonical order so
	// we know the resolver isn't sorting.
	contract := config.AgentCredentialMode{
		Default: CredentialModeRawEnvExplicit,
		FallbackOrder: []string{
			CredentialModeProviderProxy,
			CredentialModeBackendManaged,
		},
	}

	probe := EnvironmentProbe{BackendManaged: true}
	res, err := ResolveCredentialModeDetailed(contract, probe, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}

	if res.Mode != CredentialModeBackendManaged {
		t.Errorf("Mode = %q, want %q", res.Mode, CredentialModeBackendManaged)
	}
	wantOrder := []string{
		CredentialModeRawEnvExplicit,
		CredentialModeProviderProxy,
		CredentialModeBackendManaged,
	}
	if len(res.Considered) != len(wantOrder) {
		t.Fatalf("Considered len = %d, want %d", len(res.Considered), len(wantOrder))
	}
	for i, m := range wantOrder {
		if res.Considered[i].Mode != m {
			t.Errorf("Considered[%d].Mode = %q, want %q", i, res.Considered[i].Mode, m)
		}
	}
	// Exactly one OK=true.
	okCount := 0
	for _, a := range res.Considered {
		if a.OK {
			okCount++
			if a.Mode != CredentialModeBackendManaged {
				t.Errorf("OK attempt = %q, want %q", a.Mode, CredentialModeBackendManaged)
			}
		}
	}
	if okCount != 1 {
		t.Errorf("OK count = %d, want exactly 1", okCount)
	}
}

// TestMergeEnv confirms credential-mode env entries appear before
// supervisor-supplied ExtraEnv, so duplicate keys take the supervisor
// value (os/exec semantics: last value wins). Mutating the result must
// not mutate either input.
func TestMergeEnv(t *testing.T) {
	t.Parallel()

	credEnv := []string{"ANTHROPIC_API_KEY=sk-test", "ANTHROPIC_BASE_URL=https://default"}
	extra := []string{"ANTHROPIC_BASE_URL=https://override", "EXTRA=1"}

	got := MergeEnv(credEnv, extra)
	want := []string{
		"ANTHROPIC_API_KEY=sk-test",
		"ANTHROPIC_BASE_URL=https://default",
		"ANTHROPIC_BASE_URL=https://override",
		"EXTRA=1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MergeEnv = %v, want %v", got, want)
	}

	// Mutating result must not corrupt inputs.
	got[0] = "MUTATED"
	if credEnv[0] != "ANTHROPIC_API_KEY=sk-test" {
		t.Errorf("MergeEnv mutated credEnv: %q", credEnv[0])
	}
}

// TestResolveBinary covers the LookPath seam. We inject a fake LookPath
// to confirm the wrapper returns its output verbatim on success and
// wraps the error on miss.
func TestResolveBinary(t *testing.T) {
	t.Parallel()

	t.Run("found", func(t *testing.T) {
		t.Parallel()
		deps := ProbeDeps{LookPath: func(name string) (string, error) {
			if name != "claude" {
				t.Errorf("LookPath got %q, want claude", name)
			}
			return "/usr/local/bin/claude", nil
		}}
		path, err := ResolveBinary(deps, "claude")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if path != "/usr/local/bin/claude" {
			t.Errorf("path = %q, want /usr/local/bin/claude", path)
		}
	})

	t.Run("missing wraps error", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("not found")
		deps := ProbeDeps{LookPath: func(string) (string, error) { return "", boom }}
		_, err := ResolveBinary(deps, "claude")
		if err == nil {
			t.Fatalf("err = nil, want wrapped error")
		}
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want it to wrap %v", err, boom)
		}
		if !strings.Contains(err.Error(), "claude") {
			t.Errorf("err = %v, want it to mention command name", err)
		}
	})
}
