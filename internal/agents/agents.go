// Package agents defines the abstraction ai-env uses to launch agent
// CLIs (Claude Code, Codex, ...) inside a backend environment.
//
// Each concrete launcher (internal/agents/claude, internal/agents/codex)
// turns a high-level launch request (mode, task body, credentials,
// host environment) into a backend.Command the supervisor hands to
// Backend.Exec. The shared steps are:
//
//  1. Resolve binary path: confirm the agent CLI exists.
//  2. Probe version: run the agent's version subcommand, parse a semver.
//  3. Select autonomous flags: pick a candidate argv from the contract,
//     verified against either a versioned constraint or a --help probe.
//  4. Detect credential mode: walk the credential_mode preference list
//     and report which mode the host can actually satisfy.
//  5. Build launch command: produce the backend.Command + env the
//     supervisor passes to Backend.Exec.
//
// The package is split into three pieces:
//
//   - agents (this file): the Launcher interface, shared request /
//     plan / probe types, and helpers (semver parsing, --help-based
//     flag probing, credential-mode resolution against an
//     EnvironmentProbe).
//   - agents/claude: the Claude Code launcher (binary "claude").
//   - agents/codex: the Codex launcher (binary "codex").
//
// The launchers are stateless: every method takes the inputs it needs
// and returns a value. Tests inject fakes for exec.LookPath and the
// runner that backs ProbeVersion / FlagProbe so unit tests do not need
// the real binaries on PATH.
package agents

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/rivan1986/ai-env/internal/backend"
	"github.com/rivan1986/ai-env/internal/config"
)

// Launcher is the contract every agent launcher satisfies. The
// supervisor obtains a Launcher for the agent named in the run
// request, then drives it through Probe -> Plan to produce a
// backend.Command for Backend.Exec.
//
// Implementations are stateless: every method takes the inputs it
// needs explicitly. This keeps launchers cheap to construct in tests
// and lets the supervisor wire fakes (LookPath, Runner) without a
// constructor dance.
type Launcher interface {
	// Name is the short agent identifier ("claude", "codex"). It must
	// match the key in agents.yaml.
	Name() string

	// Probe reports the agent's installation state: binary path,
	// version, and which autonomous-flag candidate from the contract
	// is supported. Probe never returns a partial ProbeResult: if any
	// step fails, ProbeResult.Error is set and the rest of the fields
	// describe how far the probe got.
	Probe(ctx context.Context, contract config.AgentEntry, deps ProbeDeps) ProbeResult

	// Plan turns a high-level Request plus a successful ProbeResult
	// into a LaunchPlan the supervisor hands to Backend.Exec. Plan
	// does not start the agent; it only constructs the command.
	Plan(req Request, probe ProbeResult, env EnvironmentProbe) (LaunchPlan, error)
}

// Request is the supervisor's high-level description of what to run.
// It is independent of which agent the operator picked: the launcher
// translates Mode and TaskBody into agent-specific flags.
type Request struct {
	// Mode is the policy.yaml mode ("autonomous", "interactive",
	// "dry-run", "continue"). Launchers consult contract.Modes[Mode]
	// for the args_candidates.
	Mode string

	// TaskBody is the rendered task prompt the agent reads on stdin.
	// The supervisor writes it to task.md and forwards the body here
	// so the launcher can decide whether to pipe it on stdin or hand
	// the agent a path.
	TaskBody string

	// WorkspaceDir is the absolute path to the workspace inside the
	// environment. The supervisor sets it from RuntimeInfo.WorkspaceMount.
	WorkspaceDir string

	// AllowRawModelToken mirrors --allow-raw-model-token-in-sandbox.
	// When false, Plan must refuse to fall back to raw_env_explicit
	// even if the credential_mode contract lists it.
	AllowRawModelToken bool

	// CredentialMode is the contract's credential_mode block from
	// agents.yaml: the launcher hands it to ResolveCredentialMode so
	// the contract drives the preference order rather than a
	// hardcoded list. The supervisor populates this from the loaded
	// AgentsConfig before calling Plan. A zero value falls back to the
	// launcher's documented default (backend_managed first, then
	// provider_proxy, then raw_env_explicit), which keeps single-call
	// test usage simple but is not what production code should rely on.
	CredentialMode config.AgentCredentialMode

	// ExtraEnv is additional KEY=VALUE entries the supervisor wants
	// injected on top of whatever credential mode resolution produces.
	// May be nil.
	ExtraEnv []string

	// ExtraArgs is additional argv tokens appended after the
	// autonomous-mode flags. Operators use it for one-off overrides;
	// supervisors generally leave it nil.
	ExtraArgs []string
}

// ProbeDeps lets tests inject fakes for the OS-level helpers a real
// probe needs. The zero value is usable in production: nil hooks fall
// back to exec.LookPath and an os/exec-backed Runner.
type ProbeDeps struct {
	// LookPath finds an executable on PATH. Nil means exec.LookPath.
	LookPath func(name string) (string, error)

	// Runner runs the agent's probe subcommand and captures stdout +
	// stderr. Nil means an os/exec-backed runner is used.
	Runner ProbeRunner
}

// ProbeRunner is the seam tests use to intercept a launcher's probe
// invocations (version probe, --help flag probe). A nil error with
// non-zero exit code is a clean failure from the agent; a non-nil
// error is a spawn/IO failure of the runner itself.
type ProbeRunner func(ctx context.Context, binary string, args []string, stdout, stderr io.Writer) (exitCode int, err error)

// ProbeResult is the outcome of Launcher.Probe. A healthy probe sets
// BinaryPath, Version, VersionSupported, and SelectedFlags. A failed
// probe sets Error and leaves later fields zero.
type ProbeResult struct {
	// BinaryPath is the absolute path to the agent CLI as found on
	// PATH. Empty when the binary was not found.
	BinaryPath string

	// Version is the parsed semver-ish version string (without the
	// leading "v"). Empty when the version probe did not produce a
	// recognizable version.
	Version string

	// VersionSupported reports whether Version satisfies the
	// contract's version_constraint. False on an unknown version is
	// fail-closed: the supervisor refuses to launch.
	VersionSupported bool

	// SelectedFlags is the autonomous-mode argv candidate the probe
	// confirmed the binary supports. Nil when the requested mode has
	// no candidates or when no candidate could be verified.
	SelectedFlags []string

	// HelpOutput is the captured `<agent> --help` text the probe used
	// when verifying flag candidates. Stored on the result so the
	// supervisor can echo it in doctor output for the operator.
	HelpOutput string

	// Error is non-nil when the probe failed. The other fields
	// describe how far the probe got before the failure.
	Error error
}

// LaunchPlan is the output of Launcher.Plan: a backend.Command the
// supervisor passes to Backend.Exec plus the credential mode that was
// chosen. The credential mode is reported back so the supervisor can
// record it in run.json (and surface a warning when raw_env_explicit
// is in play).
type LaunchPlan struct {
	// Command is the backend.Command to execute. Program is the agent
	// binary (its name; the backend resolves it inside the env), Args
	// are the flags + task path, Dir is the workspace mount, Env is
	// the merged environment (credential vars + ExtraEnv).
	Command backend.Command

	// CredentialMode is the mode Plan settled on after walking the
	// contract's preference list. The supervisor records it in
	// run.json; raw_env_explicit additionally triggers a warning.
	CredentialMode string

	// StdinBody, when non-empty, is the byte string the supervisor
	// must pipe into the agent's stdin. Empty means the agent reads
	// the task body from a file path embedded in Args (most agents
	// support both; the launcher picks one).
	StdinBody string
}

// EnvironmentProbe describes what the host can offer the agent for
// credentials. The supervisor builds it from the active policy +
// secrets.local.yaml + the backend's reported capabilities; the
// launcher uses it to walk the contract's credential_mode preference
// list.
//
// Each field reports a capability; the launcher decides which mode to
// use based on the contract's Default + FallbackOrder.
type EnvironmentProbe struct {
	// BackendManaged reports whether the backend can broker the
	// provider credential on its own (e.g., sbx-managed credential
	// vault). When true, Plan does not need to inject any env var.
	BackendManaged bool

	// AgentSupportsCustomBaseURL reports whether the agent CLI can be
	// pointed at a custom provider endpoint (typically via a
	// PROVIDER_BASE_URL environment variable). The launcher sets this
	// based on what it knows about its own binary (Claude reads
	// ANTHROPIC_BASE_URL, Codex reads OPENAI_BASE_URL). It is a
	// prerequisite for provider_proxy: per the plan, provider_proxy
	// resolution must verify the agent supports a custom base URL.
	// The proxy URL plumbing itself lands in Plan 05; this flag is the
	// stub the resolver checks today.
	AgentSupportsCustomBaseURL bool

	// ProviderProxyURL is the base URL of the provider proxy when one
	// is configured. Empty means provider_proxy is unavailable. Plan
	// 05 wires this from secrets.local.yaml; today the launcher leaves
	// it empty unless the operator threads it through ExtraEnv.
	ProviderProxyURL string

	// RawTokenEnv is the explicit KEY=VALUE list the operator
	// supplied for raw_env_explicit (e.g., ANTHROPIC_API_KEY=sk-...).
	// Empty means raw_env_explicit is not configured. Plan only
	// honors this when Request.AllowRawModelToken is true.
	RawTokenEnv []string
}

// ErrCredentialModeUnavailable is returned by Plan when none of the
// contract's credential modes can be satisfied by the host. The
// supervisor surfaces this with the contract's fallback_order so the
// operator can see which mechanisms were tried. The error wraps a
// *CredentialResolutionError when more detail is available.
var ErrCredentialModeUnavailable = fmt.Errorf("agents: no supported credential mode available")

// ErrUnknownCredentialMode is returned by the resolver when the
// contract names a credential mode the launcher does not understand.
// Failing closed on an unknown mode prevents a typo in agents.yaml
// from silently disabling the credential check.
var ErrUnknownCredentialMode = fmt.Errorf("agents: unknown credential mode in contract")

// Canonical credential mode identifiers. These mirror the strings the
// plan uses verbatim in agents.yaml, run.json, and operator-visible
// surfaces. Callers should compare against these constants rather than
// retyping the literals so a future rename is one edit.
const (
	// CredentialModeBackendManaged is the safe default: the backend
	// injects the provider credential per-call, the raw token never
	// enters the agent process environment.
	CredentialModeBackendManaged = "backend_managed"

	// CredentialModeProviderProxy points the agent at a host-side
	// provider-compatible proxy. The raw token stays on the host; the
	// sandbox only sees the proxy URL.
	CredentialModeProviderProxy = "provider_proxy"

	// CredentialModeRawEnvExplicit injects the raw provider token into
	// the agent's process environment. The operator must opt in with
	// --allow-raw-model-token-in-sandbox; the supervisor records the
	// mode in run.json and prints a warning.
	CredentialModeRawEnvExplicit = "raw_env_explicit"
)

// CredentialModeAttempt records the resolver's verdict on one mode
// from the contract's preference list. The resolver returns a slice of
// attempts so the supervisor can surface a complete fail-closed
// diagnostic ("we tried X, Y, Z; here is why each failed").
type CredentialModeAttempt struct {
	// Mode is the mode name from the contract (e.g. "backend_managed").
	Mode string

	// OK is true when this mode was selected. Exactly one entry in a
	// successful resolution has OK=true; in a failed resolution every
	// entry has OK=false.
	OK bool

	// Reason is a short human-readable explanation. For OK=true it is
	// "selected"; for OK=false it describes why the mode was rejected
	// (e.g. "backend does not support managed credentials",
	// "agent does not support a custom base URL",
	// "raw token not allowed: pass --allow-raw-model-token-in-sandbox").
	Reason string
}

// CredentialResolutionError is the structured error the resolver
// returns wrapped in ErrCredentialModeUnavailable. It carries the full
// list of attempted modes so the supervisor and doctor surfaces can
// print every mechanism that was considered and why it was rejected.
type CredentialResolutionError struct {
	// Considered is the resolver's per-mode verdict in the order the
	// contract listed them (Default first, then FallbackOrder).
	Considered []CredentialModeAttempt
}

// Error implements the error interface. The message is intentionally
// terse; callers that want the full breakdown read Considered directly.
func (e *CredentialResolutionError) Error() string {
	if e == nil || len(e.Considered) == 0 {
		return ErrCredentialModeUnavailable.Error()
	}
	parts := make([]string, 0, len(e.Considered))
	for _, a := range e.Considered {
		parts = append(parts, fmt.Sprintf("%s: %s", a.Mode, a.Reason))
	}
	return fmt.Sprintf("%s (tried %s)",
		ErrCredentialModeUnavailable.Error(), strings.Join(parts, "; "))
}

// Unwrap lets errors.Is reach ErrCredentialModeUnavailable through the
// structured error.
func (e *CredentialResolutionError) Unwrap() error { return ErrCredentialModeUnavailable }

// ErrFlagsUnsupported is returned by Plan when the requested mode
// has no verified args_candidate. The supervisor surfaces this with
// the contract's candidate list so the operator can see what was
// tried.
var ErrFlagsUnsupported = fmt.Errorf("agents: no supported autonomous-flag candidate")

// ResolveBinary looks up the agent binary on PATH. It is the first
// step of every Probe implementation; pulling it out keeps Claude and
// Codex from duplicating the lookup + error wrapping.
func ResolveBinary(deps ProbeDeps, command string) (string, error) {
	lookPath := deps.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	path, err := lookPath(command)
	if err != nil {
		return "", fmt.Errorf("agents: %s not found on PATH: %w", command, err)
	}
	return path, nil
}

// ProbeVersion runs the contract's probe args against the binary,
// captures stdout, and extracts a semver-ish token. The returned
// version has no leading "v". An error indicates either a runner
// failure or unparsable output; the caller surfaces it through
// ProbeResult.Error.
func ProbeVersion(ctx context.Context, deps ProbeDeps, binary string, probe config.AgentProbe) (string, string, error) {
	runner := deps.Runner
	if runner == nil {
		runner = realProbeRunner
	}
	var stdout, stderr strings.Builder
	exitCode, err := runner(ctx, binary, probe.Args, &stdout, &stderr)
	if err != nil {
		return "", stdout.String(), fmt.Errorf("agents: %s %v spawn failed: %w", binary, probe.Args, err)
	}
	if exitCode != 0 {
		return "", stdout.String(), fmt.Errorf("agents: %s %v exited %d: %s",
			binary, probe.Args, exitCode, strings.TrimSpace(stderr.String()))
	}
	switch probe.Parse {
	case "semver", "":
		version := ExtractSemver(stdout.String())
		if version == "" {
			return "", stdout.String(), fmt.Errorf("agents: %s %v produced no recognizable version: %s",
				binary, probe.Args, strings.TrimSpace(stdout.String()))
		}
		return version, stdout.String(), nil
	default:
		return "", stdout.String(), fmt.Errorf("agents: unsupported probe.parse %q", probe.Parse)
	}
}

// realProbeRunner is the production ProbeRunner: shell out via
// os/exec, return the child's exit code, and treat a clean non-zero
// exit as a non-error from the runner's perspective.
func realProbeRunner(ctx context.Context, binary string, args []string, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return cmd.ProcessState.ExitCode(), nil
	}
	var exitErr *exec.ExitError
	if asExitErr(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode(), err
	}
	return -1, err
}

// asExitErr wraps errors.As so the file does not need an extra import
// purely for one cast. It returns true when err is an *exec.ExitError.
func asExitErr(err error, target **exec.ExitError) bool {
	for e := err; e != nil; {
		if ee, ok := e.(*exec.ExitError); ok {
			*target = ee
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// semverRe extracts the first semver-ish token in a free-form
// version string. We deliberately keep this regex loose; per the plan
// we parse minimally and rely on the agent CLI to follow conventional
// semver output. Pre-release / build suffixes are tolerated by
// SemverCompare via separate trimming.
var semverRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?)`)

// ExtractSemver returns the first semver token in raw, with any
// leading "v" stripped. Empty when no token is found.
func ExtractSemver(raw string) string {
	m := semverRe.FindStringSubmatch(raw)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// Semver is the minimal three-component representation used to
// evaluate version_constraint expressions. Pre-release / build
// suffixes are ignored: this matches the docker_sbx adapter's
// approach and the plan's "parse minimally" rule.
type Semver struct {
	Major int
	Minor int
	Patch int
}

// ParseSemver tolerates a leading "v" and trailing "-rc1" / "+build"
// suffixes. It returns an error when the numeric core does not have
// at least one component. Missing minor / patch default to zero.
func ParseSemver(s string) (Semver, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return Semver{}, fmt.Errorf("agents: empty version string")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return Semver{}, fmt.Errorf("agents: too many version components in %q", s)
	}
	out := Semver{}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return Semver{}, fmt.Errorf("agents: version component %q not numeric: %w", p, err)
		}
		switch i {
		case 0:
			out.Major = n
		case 1:
			out.Minor = n
		case 2:
			out.Patch = n
		}
	}
	return out, nil
}

// Cmp returns -1, 0, or 1 comparing a against b.
func (a Semver) Cmp(b Semver) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// SatisfiesConstraint evaluates a small subset of semver constraint
// expressions against version. The subset covers what agents.yaml
// uses today: ">=X.Y.Z", ">X.Y.Z", "<=X.Y.Z", "<X.Y.Z", "=X.Y.Z",
// and a bare "X.Y.Z" treated as "=X.Y.Z". An empty constraint always
// matches. Unknown operators return an error so the caller fails
// closed rather than silently treating the constraint as satisfied.
func SatisfiesConstraint(version, constraint string) (bool, error) {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return true, nil
	}
	v, err := ParseSemver(version)
	if err != nil {
		return false, err
	}
	// Identify the operator prefix. Two-character ops (">=", "<=")
	// must be checked before one-character ops.
	op, rest := ">=", ""
	switch {
	case strings.HasPrefix(constraint, ">="):
		rest = strings.TrimPrefix(constraint, ">=")
	case strings.HasPrefix(constraint, "<="):
		op = "<="
		rest = strings.TrimPrefix(constraint, "<=")
	case strings.HasPrefix(constraint, ">"):
		op = ">"
		rest = strings.TrimPrefix(constraint, ">")
	case strings.HasPrefix(constraint, "<"):
		op = "<"
		rest = strings.TrimPrefix(constraint, "<")
	case strings.HasPrefix(constraint, "="):
		op = "="
		rest = strings.TrimPrefix(constraint, "=")
	default:
		op = "="
		rest = constraint
	}
	target, err := ParseSemver(strings.TrimSpace(rest))
	if err != nil {
		return false, fmt.Errorf("agents: invalid version_constraint %q: %w", constraint, err)
	}
	c := v.Cmp(target)
	switch op {
	case ">=":
		return c >= 0, nil
	case "<=":
		return c <= 0, nil
	case ">":
		return c > 0, nil
	case "<":
		return c < 0, nil
	case "=":
		return c == 0, nil
	}
	return false, fmt.Errorf("agents: unknown version_constraint operator %q", op)
}

// SelectAutonomousFlags walks the args_candidates for the requested
// mode and returns the first candidate the agent supports. Support
// is verified by checking that every flag token (the entries that
// start with "-") appears in helpText. Candidates with no flag
// tokens (a pure positional candidate) match unconditionally.
//
// When no candidate matches, an empty slice and false are returned
// so the caller can attach the contract's candidate list to the
// resulting error message.
func SelectAutonomousFlags(mode config.AgentMode, helpText string) ([]string, bool) {
	for _, candidate := range mode.ArgsCandidates {
		if FlagsSupportedByHelp(candidate, helpText) {
			out := make([]string, len(candidate))
			copy(out, candidate)
			return out, true
		}
	}
	return nil, false
}

// FlagsSupportedByHelp reports whether every flag token in candidate
// appears literally in helpText. A flag token is any element that
// starts with "-". Non-flag tokens are treated as positional and do
// not need to appear in help. An empty candidate matches everything.
//
// The check is intentionally a substring test rather than a full
// help parser: agent CLIs format help differently and the plan's
// parsing principle is to parse minimally. The trade-off is that a
// flag name that happens to appear in another flag's description
// could match; that is acceptable here because we only ever check
// candidates the contract author put in agents.yaml, not arbitrary
// user input.
func FlagsSupportedByHelp(candidate []string, helpText string) bool {
	for _, tok := range candidate {
		if !strings.HasPrefix(tok, "-") {
			continue
		}
		if !strings.Contains(helpText, tok) {
			return false
		}
	}
	return true
}

// ProbeHelp runs `<binary> --help` and returns the captured output.
// Launchers call it once during Probe and stash the result on
// ProbeResult.HelpOutput so SelectAutonomousFlags has something to
// check against. An error from the runner is surfaced verbatim.
func ProbeHelp(ctx context.Context, deps ProbeDeps, binary string) (string, error) {
	runner := deps.Runner
	if runner == nil {
		runner = realProbeRunner
	}
	var stdout, stderr strings.Builder
	exitCode, err := runner(ctx, binary, []string{"--help"}, &stdout, &stderr)
	if err != nil {
		return "", fmt.Errorf("agents: %s --help spawn failed: %w", binary, err)
	}
	// Some CLIs exit non-zero on --help (rare but seen in the wild).
	// We still surface their captured output because the plan's
	// parsing principle is to rely on visible content, not on the
	// exit code, for this specific probe.
	if exitCode != 0 && stdout.Len() == 0 && stderr.Len() == 0 {
		return "", fmt.Errorf("agents: %s --help exited %d with no output", binary, exitCode)
	}
	// Many CLIs print help on stderr; merge both streams so the
	// downstream substring check sees the full text.
	return stdout.String() + "\n" + stderr.String(), nil
}

// ResolveCredentialMode walks the contract's Default + FallbackOrder
// list against the supplied EnvironmentProbe and returns the first
// mode the host can satisfy, along with the env vars to inject (when
// applicable). raw_env_explicit is only honored when allowRawToken is
// true; otherwise it is skipped and the next mode is tried.
//
// When no mode is available, the returned error wraps
// ErrCredentialModeUnavailable inside a *CredentialResolutionError
// that records why each mode was rejected. The supervisor surfaces
// the breakdown so the operator can see the full fail-closed audit.
//
// This is the back-compat wrapper around ResolveCredentialModeDetailed
// for callers that only need the chosen mode + env. New callers that
// want the per-mode attempts (doctor, supervisor diagnostics) should
// use ResolveCredentialModeDetailed directly.
func ResolveCredentialMode(contract config.AgentCredentialMode, env EnvironmentProbe, allowRawToken bool) (mode string, injectedEnv []string, err error) {
	res, err := ResolveCredentialModeDetailed(contract, env, allowRawToken)
	if err != nil {
		return "", nil, err
	}
	return res.Mode, res.InjectedEnv, nil
}

// CredentialResolution is the result of ResolveCredentialModeDetailed.
// It carries the chosen mode, the env vars to inject, and the full
// per-mode trace so callers can surface diagnostics.
type CredentialResolution struct {
	// Mode is the mode the resolver settled on (one of the
	// CredentialMode* constants).
	Mode string

	// InjectedEnv is the slice of KEY=VALUE entries the launcher must
	// place in backend.Command.Env on top of any caller-supplied
	// ExtraEnv. May be nil when the chosen mode injects nothing (e.g.
	// backend_managed).
	InjectedEnv []string

	// Considered is the per-mode trace, in the order the contract
	// listed them. Exactly one entry has OK=true. The supervisor
	// records this in lifecycle.jsonl so the operator can see what
	// fallback chain was walked.
	Considered []CredentialModeAttempt

	// RequiresWarning is true when the selected mode is
	// raw_env_explicit. The supervisor uses it to decide whether to
	// print a "reduced safety: raw provider token in sandbox" warning
	// banner.
	RequiresWarning bool
}

// ResolveCredentialModeDetailed walks the contract's preference list
// and returns a structured CredentialResolution. Failures wrap
// ErrCredentialModeUnavailable inside a *CredentialResolutionError so
// errors.Is(err, ErrCredentialModeUnavailable) keeps working.
//
// The check semantics, per plan step 7:
//
//   - backend_managed selects when env.BackendManaged is true. This is
//     the "verify backend supports it" check.
//   - provider_proxy selects only when both the agent supports a
//     custom base URL (env.AgentSupportsCustomBaseURL) and a proxy
//     URL is configured (env.ProviderProxyURL). The plan calls the
//     proxy URL plumbing a Plan 05 stub: today the resolver does the
//     correct check, callers just rarely supply a URL.
//   - raw_env_explicit selects only when allowRawToken is true AND
//     env.RawTokenEnv is non-empty. allowRawToken mirrors the
//     --allow-raw-model-token-in-sandbox flag. Selection sets
//     RequiresWarning so the supervisor knows to print the banner.
//   - An unknown mode name returns ErrUnknownCredentialMode (fail
//     closed; a typo in agents.yaml must not silently disable the
//     credential check).
func ResolveCredentialModeDetailed(contract config.AgentCredentialMode, env EnvironmentProbe, allowRawToken bool) (CredentialResolution, error) {
	order := credentialModeOrder(contract)
	considered := make([]CredentialModeAttempt, 0, len(order))

	for _, m := range order {
		switch m {
		case CredentialModeBackendManaged:
			if env.BackendManaged {
				considered = append(considered, CredentialModeAttempt{
					Mode: m, OK: true, Reason: "selected: backend brokers provider credential",
				})
				return CredentialResolution{
					Mode:        m,
					InjectedEnv: nil,
					Considered:  considered,
				}, nil
			}
			considered = append(considered, CredentialModeAttempt{
				Mode: m, Reason: "backend does not advertise managed credentials",
			})

		case CredentialModeProviderProxy:
			if !env.AgentSupportsCustomBaseURL {
				considered = append(considered, CredentialModeAttempt{
					Mode: m, Reason: "agent does not support a custom provider base URL (Plan 05)",
				})
				continue
			}
			if env.ProviderProxyURL == "" {
				considered = append(considered, CredentialModeAttempt{
					Mode: m, Reason: "no provider proxy URL configured (Plan 05)",
				})
				continue
			}
			injected := providerProxyEnv(env.ProviderProxyURL)
			considered = append(considered, CredentialModeAttempt{
				Mode: m, OK: true, Reason: "selected: agent points at provider proxy",
			})
			return CredentialResolution{
				Mode:        m,
				InjectedEnv: injected,
				Considered:  considered,
			}, nil

		case CredentialModeRawEnvExplicit:
			if !allowRawToken {
				considered = append(considered, CredentialModeAttempt{
					Mode: m, Reason: "raw token not allowed: pass --allow-raw-model-token-in-sandbox",
				})
				continue
			}
			if len(env.RawTokenEnv) == 0 {
				considered = append(considered, CredentialModeAttempt{
					Mode: m, Reason: "no raw provider token available in host environment",
				})
				continue
			}
			out := make([]string, len(env.RawTokenEnv))
			copy(out, env.RawTokenEnv)
			considered = append(considered, CredentialModeAttempt{
				Mode: m, OK: true, Reason: "selected: raw provider token injected into sandbox",
			})
			return CredentialResolution{
				Mode:            m,
				InjectedEnv:     out,
				Considered:      considered,
				RequiresWarning: true,
			}, nil

		case "":
			continue

		default:
			return CredentialResolution{}, fmt.Errorf("%w: %q", ErrUnknownCredentialMode, m)
		}
	}

	return CredentialResolution{}, &CredentialResolutionError{Considered: considered}
}

// credentialModeOrder returns the contract's preference list as a flat
// slice (Default first, then FallbackOrder). Empty entries are dropped
// later in the switch; we keep them here so the slice index stays
// aligned with the contract's original order for diagnostics.
func credentialModeOrder(contract config.AgentCredentialMode) []string {
	out := make([]string, 0, 1+len(contract.FallbackOrder))
	out = append(out, contract.Default)
	out = append(out, contract.FallbackOrder...)
	return out
}

// providerProxyEnv returns the KEY=VALUE pairs the launcher must
// inject so the agent CLI routes requests through proxyURL. Both
// Claude and Codex honor the same convention (ANTHROPIC_BASE_URL /
// OPENAI_BASE_URL), so emitting both is harmless: each agent ignores
// the other's variable. Splitting this out keeps the resolver's main
// switch readable.
func providerProxyEnv(proxyURL string) []string {
	return []string{
		"ANTHROPIC_BASE_URL=" + proxyURL,
		"OPENAI_BASE_URL=" + proxyURL,
	}
}

// IsRawTokenMode reports whether the resolved mode is
// raw_env_explicit. Centralizing the check keeps the supervisor and
// doctor surfaces from retyping the string literal when deciding
// whether to print the reduced-safety warning.
func IsRawTokenMode(mode string) bool {
	return mode == CredentialModeRawEnvExplicit
}

// MergeEnv combines credential-mode env injection with the
// supervisor's ExtraEnv. Duplicate keys keep the last value, which
// matches os/exec semantics so the supervisor can override a
// credential-mode default by appending to ExtraEnv.
func MergeEnv(credentialEnv, extraEnv []string) []string {
	out := make([]string, 0, len(credentialEnv)+len(extraEnv))
	out = append(out, credentialEnv...)
	out = append(out, extraEnv...)
	return out
}
