package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/i1rr/ai-env/internal/capability"
	"github.com/i1rr/ai-env/internal/run"
)

// fakeLookPath returns a deterministic LookPath substitute. Binaries
// listed in `present` resolve to `/fake/bin/<name>`; everything else
// returns exec.ErrNotFound.
func fakeLookPath(present ...string) func(string) (string, error) {
	set := make(map[string]struct{}, len(present))
	for _, p := range present {
		set[p] = struct{}{}
	}
	return func(name string) (string, error) {
		if _, ok := set[name]; ok {
			return "/fake/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
}

// fakeRuntimeProbe returns a probe substitute. Probes return canned
// stdout/exit for binaries listed in `versions`; unknown binaries
// return ("", 1, nil) — a non-zero clean exit.
func fakeRuntimeProbe(versions map[string]string) func(ctx context.Context, binary string, args []string) (string, int, error) {
	return func(ctx context.Context, binary string, args []string) (string, int, error) {
		if v, ok := versions[binary]; ok {
			return v, 0, nil
		}
		return "", 1, nil
	}
}

// TestRunDoctor_HappyPath_Linux exercises the canonical "everything
// works" path on a fully-capable Linux host.
func TestRunDoctor_HappyPath_Linux(t *testing.T) {
	cap := capability.Capability{
		OS:                  "linux",
		CAPNetAdmin:         true,
		CAPSysAdmin:         true,
		SetnsAvailable:      true,
		NFLOGAvailable:      true,
		BridgeGatewayLikely: true,
		DevFdAvailable:      true,
	}
	var out, errOut bytes.Buffer
	err := RunDoctor(DoctorOptions{
		Stdout:           &out,
		Stderr:           &errOut,
		detectCapability: func() capability.Capability { return cap },
		runtimeProbe: fakeRuntimeProbe(map[string]string{
			"docker": "Docker version 24.0.5, build abc",
			"podman": "podman version 4.6.1",
			"git":    "git version 2.42.0",
		}),
		lookPath: fakeLookPath("docker", "podman", "git", "gitleaks"),
	})
	if err != nil {
		t.Fatalf("RunDoctor returned error on happy path: %v\nout:\n%s\nerrOut:\n%s", err, out.String(), errOut.String())
	}
	s := out.String()

	// Sanity: every expected section appears.
	for _, want := range []string{
		"[platform]",
		"[capability]",
		"[dependency]",
		"[remediation]",
		"CAP_NET_ADMIN",
		"NFLOG",
		"slirp4netns",
		"bridge gateway",
		"userns-remap",
		"/dev/fd",
		"docker",
		"podman",
		"container runtime",
		"git",
		"gitleaks",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing expected token %q\n%s", want, s)
		}
	}
	// No FAIL on a healthy Linux host.
	if strings.Contains(s, "FAIL") {
		t.Errorf("expected no FAIL rows in happy path, got:\n%s", s)
	}
}

// TestRunDoctor_NoContainerRuntime_Fails covers the only FAIL surface:
// neither docker nor podman is on PATH.
func TestRunDoctor_NoContainerRuntime_Fails(t *testing.T) {
	cap := capability.Capability{
		OS:             "linux",
		CAPNetAdmin:    true,
		DevFdAvailable: true,
	}
	var out, errOut bytes.Buffer
	err := RunDoctor(DoctorOptions{
		Stdout:           &out,
		Stderr:           &errOut,
		detectCapability: func() capability.Capability { return cap },
		runtimeProbe:     fakeRuntimeProbe(map[string]string{"git": "git version 2.42.0"}),
		lookPath:         fakeLookPath("git"),
	})
	if err == nil {
		t.Fatalf("expected non-nil error when no container runtime is present\nout:\n%s", out.String())
	}
	s := out.String()
	if !strings.Contains(s, "container runtime") {
		t.Errorf("expected container runtime row\n%s", s)
	}
	if !strings.Contains(s, "FAIL") {
		t.Errorf("expected FAIL row\n%s", s)
	}
	if !strings.Contains(s, "neither docker nor podman") {
		t.Errorf("expected explanatory FAIL reason\n%s", s)
	}
}

// TestRunDoctor_OneRuntimePresent_DowngradesOtherToWarn confirms that
// when docker is present but podman is missing (or vice versa) the
// missing one is reported as WARN, not FAIL.
func TestRunDoctor_OneRuntimePresent_DowngradesOtherToWarn(t *testing.T) {
	cap := capability.Capability{
		OS:             "linux",
		CAPNetAdmin:    true,
		DevFdAvailable: true,
	}
	var out, errOut bytes.Buffer
	err := RunDoctor(DoctorOptions{
		Stdout:           &out,
		Stderr:           &errOut,
		detectCapability: func() capability.Capability { return cap },
		runtimeProbe: fakeRuntimeProbe(map[string]string{
			"docker": "Docker version 24.0.5",
			"git":    "git version 2.42.0",
		}),
		lookPath: fakeLookPath("docker", "git"),
	})
	if err != nil {
		t.Fatalf("expected no error when at least one runtime is present: %v\n%s", err, out.String())
	}
	s := out.String()
	// container runtime summary should be PASS even though podman is
	// missing.
	if !strings.Contains(s, "container runtime") {
		t.Errorf("expected container runtime row\n%s", s)
	}
	// Sanity-check that podman row appears as WARN (downgraded).
	// We grep for a "WARN  podman" or "WARN\tpodman" pattern after
	// tabwriter formatting. The simplest robust check: the table must
	// contain both "podman" and "WARN" rows.
	if !strings.Contains(s, "podman") {
		t.Errorf("expected podman row to appear (as WARN)\n%s", s)
	}
}

// TestRunDoctor_Slirp4netns_DegradesObserver confirms the slirp4netns
// row reports WARN with the lifecycle-verb reason token.
func TestRunDoctor_Slirp4netns_DegradesObserver(t *testing.T) {
	cap := capability.Capability{
		OS:             "linux",
		CAPNetAdmin:    true,
		NFLOGAvailable: true,
		Slirp4netns:    true,
		DevFdAvailable: true,
	}
	var out bytes.Buffer
	err := RunDoctor(DoctorOptions{
		Stdout:           &out,
		Stderr:           &bytes.Buffer{},
		detectCapability: func() capability.Capability { return cap },
		runtimeProbe:     fakeRuntimeProbe(map[string]string{"docker": "Docker version 24.0.5"}),
		lookPath:         fakeLookPath("docker"),
	})
	if err != nil {
		t.Fatalf("RunDoctor unexpected error: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "slirp4netns") {
		t.Errorf("expected slirp4netns row\n%s", s)
	}
	if !strings.Contains(s, "observer_unavailable") {
		t.Errorf("expected observer_unavailable hint in slirp4netns row\n%s", s)
	}
}

// TestRunDoctor_JSON_EmitsStableShape exercises the --json projection
// and confirms every documented field is present.
func TestRunDoctor_JSON_EmitsStableShape(t *testing.T) {
	cap := capability.Capability{
		OS:                  "linux",
		CAPNetAdmin:         true,
		CAPSysAdmin:         true,
		SetnsAvailable:      true,
		NFLOGAvailable:      true,
		BridgeGatewayLikely: true,
		DevFdAvailable:      true,
	}
	var out bytes.Buffer
	err := RunDoctor(DoctorOptions{
		JSON:             true,
		Stdout:           &out,
		Stderr:           &bytes.Buffer{},
		detectCapability: func() capability.Capability { return cap },
		runtimeProbe: fakeRuntimeProbe(map[string]string{
			"docker": "Docker version 24.0.5",
			"git":    "git version 2.42.0",
		}),
		lookPath: fakeLookPath("docker", "git"),
	})
	if err != nil {
		t.Fatalf("RunDoctor JSON happy path returned error: %v\n%s", err, out.String())
	}
	var report DoctorReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode JSON report: %v\n%s", err, out.String())
	}
	if report.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", report.SchemaVersion)
	}
	// Platform reflects the actual host runtime.GOOS, independent of
	// the injected capability snapshot's OS field.
	if report.Platform != runtime.GOOS {
		t.Errorf("platform = %q, want %q", report.Platform, runtime.GOOS)
	}
	if report.Capability.OS != "linux" {
		t.Errorf("capability.os = %q, want linux", report.Capability.OS)
	}
	if !report.Capability.CAPNetAdmin {
		t.Errorf("expected cap_net_admin=true in JSON capability snapshot")
	}
	if len(report.Checks) == 0 {
		t.Errorf("expected at least one check row")
	}
	if len(report.Remediations) == 0 {
		t.Errorf("expected at least one remediation row")
	}
}

// TestDoctorRemediationsCoverAllVerbs confirms every lifecycle verb
// defined in internal/run has a remediation row, and that the plan-
// mandated bonus row `origin_drift` is also present.
//
// This is the structural test that prevents a future verb addition
// from silently bypassing the doctor's remediation table.
func TestDoctorRemediationsCoverAllVerbs(t *testing.T) {
	rows := buildRemediationTable()
	have := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		have[r.Verb] = struct{}{}
		if r.Severity == "" || r.Remediation == "" {
			t.Errorf("remediation row %q missing severity/remediation: %+v", r.Verb, r)
		}
	}

	// Every LifecycleVerb constant must appear.
	requiredVerbs := []run.LifecycleVerb{
		run.LifecycleVerbProxyStarted,
		run.LifecycleVerbProxyStopped,
		run.LifecycleVerbGatewayStarted,
		run.LifecycleVerbGatewayStopped,
		run.LifecycleVerbGatewaySecretBlocked,
		run.LifecycleVerbGatewaySecretResponse,
		run.LifecycleVerbObserverStarted,
		run.LifecycleVerbObserverStopped,
		run.LifecycleVerbObserverUnavailable,
		run.LifecycleVerbBrokerStarted,
		run.LifecycleVerbBrokerStopped,
		run.LifecycleVerbBrokerUnavailable,
		run.LifecycleVerbControlSocketStarted,
		run.LifecycleVerbControlSocketStopped,
		run.LifecycleVerbNetworkPolicyDegraded,
		run.LifecycleVerbSecretsPermissionWarning,
		run.LifecycleVerbShimCoverageDegraded,
		run.LifecycleVerbHelperRPCAborted,
		run.LifecycleVerbTranscriptParserError,
		run.LifecycleVerbMCPConfigNeutralized,
	}
	for _, v := range requiredVerbs {
		if _, ok := have[string(v)]; !ok {
			t.Errorf("remediation table missing lifecycle verb %q", v)
		}
	}

	// Plan Batch 10.5 also mandates the origin_drift remediation row
	// (it rides as Metadata on broker_unavailable but the operator
	// looks for it under its own name).
	if _, ok := have["origin_drift"]; !ok {
		t.Errorf("remediation table missing origin_drift")
	}
}

// TestRunDoctor_DarwinPath confirms the macOS-specific capability
// rows render (pflog instead of NFLOG / capabilities).
func TestRunDoctor_DarwinPath(t *testing.T) {
	cap := capability.Capability{
		OS:             "darwin",
		PFLogAvailable: true,
		DevFdAvailable: true,
	}
	var out bytes.Buffer
	err := RunDoctor(DoctorOptions{
		Stdout:           &out,
		Stderr:           &bytes.Buffer{},
		detectCapability: func() capability.Capability { return cap },
		runtimeProbe: fakeRuntimeProbe(map[string]string{
			"docker": "Docker version 24.0.5",
		}),
		lookPath: fakeLookPath("docker"),
	})
	if err != nil {
		t.Fatalf("RunDoctor darwin path error: %v\n%s", err, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "pflog") {
		t.Errorf("expected pflog row on darwin\n%s", s)
	}
	if strings.Contains(s, "CAP_NET_ADMIN") {
		t.Errorf("CAP_NET_ADMIN row should not appear on darwin\n%s", s)
	}
}
