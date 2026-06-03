// Tests for the rootless Podman fallback backend.
//
// These mirror the docker fallback tests for the same offline-by-default
// contract the master plan calls out (plan 05 step 10): the fallback
// must default to `--network none`, must reject autonomous mode without
// --accept-reduced-isolation, must keep outbound blocked even with
// --accept-reduced-isolation when --unsafe-host-network is not set,
// and must surface the reduced-isolation warning verbatim.
//
// The tests use a fakeRunner (mirroring the docker_sbx compat_test.go
// pattern) to intercept the `podman` CLI invocations at the Runner
// boundary so they exercise the adapter's policy-shaping/decision
// logic deterministically without requiring podman to be installed.
// Real-CLI integration coverage lives in integration_test.go behind the
// AI_ENV_BACKEND_INTEGRATION=1 gate.
package podman

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/backend"
	"github.com/i1rr/ai-env/internal/config"
	"github.com/i1rr/ai-env/internal/network"
)

// fakeRunner is a Runner that records every invocation and replays
// canned stdout/stderr/exit-code triples. See the docker package's
// equivalent for the rationale; this copy lives here so the podman
// tests do not pull a sibling package into the test binary.
type fakeRunner struct {
	responses []fakeResponse
	gotArgs   [][]string
}

type fakeResponse struct {
	stdout   string
	stderr   string
	exitCode int
	spawnErr error
}

func (f *fakeRunner) Run(_ context.Context, _ string, args []string, _ io.Reader, stdout, stderr io.Writer, _ []string, _ string) (int, error) {
	f.gotArgs = append(f.gotArgs, append([]string(nil), args...))
	var resp fakeResponse
	if len(f.responses) > 0 {
		resp = f.responses[0]
		f.responses = f.responses[1:]
	}
	if stdout != nil && resp.stdout != "" {
		_, _ = stdout.Write([]byte(resp.stdout))
	}
	if stderr != nil && resp.stderr != "" {
		_, _ = stderr.Write([]byte(resp.stderr))
	}
	if resp.spawnErr != nil {
		return -1, resp.spawnErr
	}
	return resp.exitCode, nil
}

func (f *fakeRunner) lastArgs() []string {
	if len(f.gotArgs) == 0 {
		return nil
	}
	return f.gotArgs[len(f.gotArgs)-1]
}

func findArg(argv []string, flag string) string {
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == flag {
			return argv[i+1]
		}
	}
	return ""
}

func makeBackend(t *testing.T, runner *fakeRunner, opts Options) *Backend {
	t.Helper()
	if opts.Binary == "" {
		opts.Binary = "sh"
	}
	opts.Runner = runner.Run
	if opts.DetectTimeout == 0 {
		opts.DetectTimeout = 2 * time.Second
	}
	return New(opts)
}

func envFixture(t *testing.T, b *Backend, name string) string {
	t.Helper()
	envID, err := b.Create(backend.EnvSpec{
		Name:          name,
		WorkspacePath: "/tmp/" + name,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := b.Start(envID); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return envID
}

// TestStart_DefaultNetworkIsNone is the headline assertion of step 11:
// without any opt-in flags, the fallback brings the container up with
// `--network none`, so no outbound traffic is possible regardless of
// what policy.yaml requested.
func TestStart_DefaultNetworkIsNone(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "fake-container-id\n", exitCode: 0},
	}}
	b := makeBackend(t, runner, Options{})

	_ = envFixture(t, b, "fallback-default")

	argv := runner.lastArgs()
	if got := findArg(argv, "--network"); got != "none" {
		t.Fatalf("podman run --network = %q, want %q (argv=%v)", got, "none", argv)
	}
	if len(argv) == 0 || argv[0] != "run" {
		t.Errorf("podman invocation = %v, want it to begin with `run`", argv)
	}
}

// TestStart_AcceptReducedIsolationAloneStaysNone verifies that
// --accept-reduced-isolation by itself does NOT widen the network: it
// only unlocks autonomous mode. Outbound is still blocked because
// --unsafe-host-network was not set.
func TestStart_AcceptReducedIsolationAloneStaysNone(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "fake-container-id\n", exitCode: 0},
	}}
	b := makeBackend(t, runner, Options{
		AcceptReducedIsolation: true,
	})

	_ = envFixture(t, b, "fallback-accept-only")

	argv := runner.lastArgs()
	if got := findArg(argv, "--network"); got != "none" {
		t.Fatalf("podman run --network = %q, want %q with accept-only (argv=%v)", got, "none", argv)
	}
}

// TestStart_UnsafeHostNetworkRequiresAcceptance verifies UnsafeHostNetwork
// without AcceptReducedIsolation does not open the network.
func TestStart_UnsafeHostNetworkRequiresAcceptance(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "fake-container-id\n", exitCode: 0},
	}}
	b := makeBackend(t, runner, Options{
		AcceptReducedIsolation: false,
		UnsafeHostNetwork:      true,
	})

	_ = envFixture(t, b, "fallback-unsafe-only")

	argv := runner.lastArgs()
	if got := findArg(argv, "--network"); got != "none" {
		t.Fatalf("podman run --network = %q, want %q without acceptance (argv=%v)", got, "none", argv)
	}
}

// TestStart_HostNetworkRequiresBothFlags confirms the only path that
// opens the network: AcceptReducedIsolation AND UnsafeHostNetwork.
func TestStart_HostNetworkRequiresBothFlags(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "fake-container-id\n", exitCode: 0},
	}}
	b := makeBackend(t, runner, Options{
		AcceptReducedIsolation: true,
		UnsafeHostNetwork:      true,
	})

	_ = envFixture(t, b, "fallback-host")

	argv := runner.lastArgs()
	if got := findArg(argv, "--network"); got != "host" {
		t.Fatalf("podman run --network = %q, want %q with both flags (argv=%v)", got, "host", argv)
	}
}

// TestDetect_AutonomousWithoutAcceptanceRejected verifies that an
// autonomous run that selects this backend without
// --accept-reduced-isolation is rejected at Detect time with a clear
// message that includes the reduced-isolation warning text.
func TestDetect_AutonomousWithoutAcceptanceRejected(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "podman version 4.7.0\n", exitCode: 0},
	}}
	var warnings bytes.Buffer
	b := makeBackend(t, runner, Options{
		Mode:                   "autonomous",
		AcceptReducedIsolation: false,
		WarningWriter:          &warnings,
	})

	status := b.Detect()

	if status.Available {
		t.Fatalf("Detect.Available = true, want false for autonomous without acceptance")
	}
	if !strings.Contains(status.Message, "--accept-reduced-isolation") {
		t.Errorf("Detect.Message = %q, want it to mention --accept-reduced-isolation", status.Message)
	}
	if !strings.Contains(status.Message, "WARNING:") {
		t.Errorf("Detect.Message = %q, want it to embed the reduced-isolation warning", status.Message)
	}
}

// TestDetect_AutonomousWithAcceptanceAllowedAndWarned verifies the
// positive path: with --accept-reduced-isolation the backend is
// available for autonomous mode AND the reduced-isolation warning is
// emitted to the configured writer.
func TestDetect_AutonomousWithAcceptanceAllowedAndWarned(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "podman version 4.7.0\n", exitCode: 0},
	}}
	var warnings bytes.Buffer
	b := makeBackend(t, runner, Options{
		Mode:                   "autonomous",
		AcceptReducedIsolation: true,
		WarningWriter:          &warnings,
	})

	status := b.Detect()

	if !status.Available {
		t.Fatalf("Detect.Available = false, want true with acceptance (message=%q)", status.Message)
	}
	if !strings.Contains(warnings.String(), ReducedIsolationWarning) {
		t.Errorf("warning writer = %q, want it to contain ReducedIsolationWarning", warnings.String())
	}
	if !strings.Contains(status.Message, "acknowledged") {
		t.Errorf("Detect.Message = %q, want it to mention acknowledgement", status.Message)
	}
}

// TestDetect_InteractiveWithoutAcceptanceWarned verifies that an
// interactive run still gets the reduced-isolation warning, even
// though acceptance is not required.
func TestDetect_InteractiveWithoutAcceptanceWarned(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "podman version 4.7.0\n", exitCode: 0},
	}}
	var warnings bytes.Buffer
	b := makeBackend(t, runner, Options{
		Mode:          "interactive",
		WarningWriter: &warnings,
	})

	status := b.Detect()

	if !status.Available {
		t.Fatalf("Detect.Available = false for interactive mode (message=%q)", status.Message)
	}
	if !strings.Contains(warnings.String(), ReducedIsolationWarning) {
		t.Errorf("warning writer = %q, want it to contain ReducedIsolationWarning", warnings.String())
	}
}

// TestDetect_WarningPrintedOnce verifies the warning is emitted on the
// first Detect that observes a warn-triggering state and suppressed on
// subsequent calls.
func TestDetect_WarningPrintedOnce(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "podman version 4.7.0\n", exitCode: 0},
		{stdout: "podman version 4.7.0\n", exitCode: 0},
	}}
	var warnings bytes.Buffer
	b := makeBackend(t, runner, Options{
		Mode:          "interactive",
		WarningWriter: &warnings,
	})

	_ = b.Detect()
	_ = b.Detect()

	got := warnings.String()
	count := strings.Count(got, "WARNING: This backend provides reduced isolation.")
	if count != 1 {
		t.Errorf("warning printed %d times, want 1; output=%q", count, got)
	}
}

// TestReducedIsolationWarningTextExact pins the exact warning text the
// plan fixes in section "Reduced-isolation fallback warning". The
// docker and podman fallbacks share the same wording; this test pins
// the podman copy.
func TestReducedIsolationWarningTextExact(t *testing.T) {
	t.Parallel()

	const want = `WARNING: This backend provides reduced isolation. It is suitable for development
and testing, but not for high-risk autonomous execution with untrusted dependencies
or secrets.`
	if ReducedIsolationWarning != want {
		t.Errorf("ReducedIsolationWarning = %q,\n want %q", ReducedIsolationWarning, want)
	}
}

// TestApplyNetworkPolicy_NoneModeAcceptsAnyPolicy verifies that once
// the container is brought up with `--network none`, the adapter
// accepts every policy (because no outbound traffic is possible).
func TestApplyNetworkPolicy_NoneModeAcceptsAnyPolicy(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "fake-container-id\n", exitCode: 0},
	}}
	b := makeBackend(t, runner, Options{})
	envID := envFixture(t, b, "policy-none")

	cases := []backend.NetworkPolicy{
		{Default: "deny"},
		{Default: "deny", AllowDomains: []string{"example.com"}},
		{Default: "allow"},
		{Default: "deny", BlockMetadataServices: true, BlockPrivateRanges: true,
			BlockLocalhost: true, BlockHostDockerInternal: true},
	}
	for _, p := range cases {
		if err := b.ApplyNetworkPolicy(envID, p); err != nil {
			t.Errorf("ApplyNetworkPolicy(%+v) on `none` env returned %v, want nil", p, err)
		}
	}
}

// TestApplyNetworkPolicy_HostModeRejectsAllowlist verifies the
// fail-closed contract: in host network mode the adapter cannot
// enforce a domain allowlist, so a deny+allowlist policy must be
// rejected so the supervisor can fail the run with `failed_policy`.
func TestApplyNetworkPolicy_HostModeRejectsAllowlist(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "fake-container-id\n", exitCode: 0},
	}}
	b := makeBackend(t, runner, Options{
		AcceptReducedIsolation: true,
		UnsafeHostNetwork:      true,
	})
	envID := envFixture(t, b, "policy-host-allowlist")

	err := b.ApplyNetworkPolicy(envID, backend.NetworkPolicy{
		Default:      "deny",
		AllowDomains: []string{"example.com"},
	})
	if err == nil {
		t.Fatalf("ApplyNetworkPolicy on host with allowlist returned nil, want error")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("error = %q, want it to mention allowlist", err.Error())
	}
}

// TestApplyNetworkPolicy_HostModeAcceptsDenyOnlyAndAllow verifies that
// host mode still accepts policies without an allowlist.
func TestApplyNetworkPolicy_HostModeAcceptsDenyOnlyAndAllow(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "fake-container-id\n", exitCode: 0},
	}}
	b := makeBackend(t, runner, Options{
		AcceptReducedIsolation: true,
		UnsafeHostNetwork:      true,
	})
	envID := envFixture(t, b, "policy-host-ok")

	cases := []backend.NetworkPolicy{
		{Default: "deny"},
		{Default: "allow"},
	}
	for _, p := range cases {
		if err := b.ApplyNetworkPolicy(envID, p); err != nil {
			t.Errorf("ApplyNetworkPolicy(%+v) on host env returned %v, want nil", p, err)
		}
	}
}

// TestNetworkPolicyAdapter_RoutesThroughBackend verifies the
// NetworkPolicyAdapter wrapper is wired correctly.
func TestNetworkPolicyAdapter_RoutesThroughBackend(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: "fake-container-id\n", exitCode: 0},
	}}
	b := makeBackend(t, runner, Options{})
	envID := envFixture(t, b, "adapter-route")

	adapter := NewNetworkPolicyAdapter(b)
	if adapter.Name() != Name {
		t.Errorf("adapter.Name() = %q, want %q", adapter.Name(), Name)
	}

	policy := network.NewNetworkPolicy(config.NetworkPolicy{Default: "deny"})
	if err := adapter.Apply(envID, policy); err != nil {
		t.Errorf("adapter.Apply: %v", err)
	}
}

// TestNetworkPolicyAdapter_RejectsEmptyEnvID guards against a
// supervisor bug where the adapter is invoked before Create completes.
func TestNetworkPolicyAdapter_RejectsEmptyEnvID(t *testing.T) {
	t.Parallel()

	b := makeBackend(t, &fakeRunner{}, Options{})
	adapter := NewNetworkPolicyAdapter(b)

	policy := network.NewNetworkPolicy(config.NetworkPolicy{Default: "deny"})
	err := adapter.Apply("", policy)
	if err == nil {
		t.Fatalf("adapter.Apply with empty envID returned nil, want error")
	}
	if !strings.Contains(err.Error(), "envID") {
		t.Errorf("error = %q, want it to mention envID", err.Error())
	}
}

// TestDetect_BinaryMissing covers the LookPath miss path: a host
// without podman on PATH must report Available=false with an
// actionable message.
func TestDetect_BinaryMissing(t *testing.T) {
	t.Parallel()

	b := New(Options{Binary: "definitely-not-a-real-binary-ai-env-fallback"})
	status := b.Detect()

	if status.Available {
		t.Fatalf("Detect.Available = true, want false for missing binary")
	}
	if !strings.Contains(status.Message, "not found") {
		t.Errorf("Detect.Message = %q, want it to mention missing binary", status.Message)
	}
}

// TestDetect_SpawnErrorReportedUnavailable covers a runner-side error
// (process could not be spawned at all).
func TestDetect_SpawnErrorReportedUnavailable(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{spawnErr: errors.New("boom")},
	}}
	b := makeBackend(t, runner, Options{})

	status := b.Detect()

	if status.Available {
		t.Fatalf("Detect.Available = true on spawn error")
	}
	if !strings.Contains(status.Message, "boom") {
		t.Errorf("Detect.Message = %q, want it to mention runner error", status.Message)
	}
}

// Compile-time guard that fakeRunner.Run has the Runner signature.
var _ Runner = (*fakeRunner)(nil).Run
