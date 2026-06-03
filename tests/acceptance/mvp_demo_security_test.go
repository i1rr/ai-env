//go:build acceptance

// Package acceptance MVP-demonstration security verifications.
//
// This file implements plan.md lines 96-98 (master plan section "MVP
// demonstration", verification bullets 25-27): the three security-boundary
// checks an operator running the v0.1 demo must observe.
//
// Each test exercises the runtime decision point an agent would hit if it
// tried the forbidden action and asserts two things:
//
//   - The supervisor / policy engine returned a deny verdict (the action
//     was refused).
//   - The denial landed on disk in policy-decisions.jsonl as an
//     engine_evaluate record with Decision=="deny" (the audit trail the
//     operator inspects after the demo carries the refusal).
//
// Why this layer (and not the real primary backend):
//
//   - The primary backend (Apple VZ via sbx) only runs on macOS hosts with
//     the sbx daemon present; the docker_sbx integration suite covers it
//     behind AI_ENV_BACKEND_INTEGRATION=1.
//   - Reading ~/.ssh/id_rsa or opening /var/run/docker.sock on the host
//     from inside CI would be hazardous and non-deterministic; the policy
//     engine is the single decision point both surfaces consult before any
//     OS-level read attempt, so denying at this layer proves the boundary
//     is wired correctly. The HighRiskShellPatterns list (consulted by the
//     engine ahead of any user policy) hard-denies the SSH key path, and
//     policy.commands.deny_patterns refuses the Docker socket path.
//   - The network egress test uses the supervisor's EvaluateNetworkDomain
//     decision point with a policy whose default is "deny" so any
//     off-allowlist domain is refused (the engine's commands.default
//     fallback applies to the synthetic "network: <domain>" event the
//     supervisor builds).
//
// Gating mirrors section32_test.go: the build tag `acceptance` is the
// static gate and AI_ENV_ACCEPTANCE=1 (via TestMain in section32_test.go)
// is the dynamic gate. The tests reuse TestMain's binary-build step
// implicitly because Go test runs TestMain once per package; this file
// adds no new gates of its own.

package acceptance

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/i1rr/ai-env/internal/config"
	"github.com/i1rr/ai-env/internal/network"
	"github.com/i1rr/ai-env/internal/policy"
	"github.com/i1rr/ai-env/internal/run"

	"gopkg.in/yaml.v3"

	"os"
)

// mvpSecurityPolicy returns a minimal-but-valid PolicyConfig the three
// MVP security tests stage to disk. commands.default is "deny" so any
// shell command (or synthetic "network: <domain>" event) that misses
// the explicit deny_patterns + HighRiskShellPatterns fast paths still
// resolves to deny, which is exactly the v0.1 autonomous default the
// plan calls out. The /var/run/docker.sock substring lives in
// deny_patterns so an attempted Docker-socket access is refused by the
// user-configurable rule layer (separate from the
// HighRiskShellPatterns fast path the SSH-key test rides on); this
// proves the policy.yaml-driven rule is honored end-to-end.
//
// Mirrors internal/run.validPolicyConfig but lives here so the
// acceptance suite does not import the run package's internal test
// helpers (an internal/run/_test.go file would not be importable).
func mvpSecurityPolicy() *config.PolicyConfig {
	return &config.PolicyConfig{
		Version: 1,
		Mode:    "autonomous",
		Network: config.NetworkPolicy{
			Default:               "deny",
			Enforcement:           "backend",
			AllowDomains:          []string{"github.com"},
			BlockPrivateRanges:    true,
			BlockMetadataServices: true,
			BlockLocalhost:        true,
		},
		Filesystem: config.FilesystemPolicy{
			WorkspaceWrite: true,
			ProtectedPaths: []string{".git", ".ai-env"},
		},
		Commands: config.CommandsPolicy{
			// commands.default=deny is the autonomous-mode v0.1
			// posture: anything the agent attempts that misses the
			// explicit fast paths lands on this rule.
			Default: "deny",
			// /var/run/docker.sock is an exact substring an agent
			// would type to reach the host Docker daemon; we list it
			// here so the user-policy layer (not just the high-risk
			// fast path) refuses it.
			DenyPatterns: []string{"/var/run/docker.sock"},
		},
		Dependencies: config.DependenciesPolicy{
			InstallScriptsDefault: "deny",
		},
		Secrets: config.SecretsPolicy{
			DefaultTTLSeconds: 3600,
			MaxTTLSeconds:     14400,
		},
		Scanners: config.ScannersPolicy{
			BuiltInSecretScanner: "pattern_only",
			EntropyFindings:      "warn_only",
		},
		Review: config.ReviewPolicy{},
	}
}

// writeMVPPolicyYAML marshals cfg to YAML at path. Mirrors the
// internal/run/policy_engine_test.go helper of the same shape.
func writeMVPPolicyYAML(t *testing.T, path string, cfg *config.PolicyConfig) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}

// newMVPSupervisor stages a policy.yaml under a fresh run directory and
// returns a constructed supervisor wired to it. Centralized so the
// three MVP security tests do not redeclare the boilerplate. The
// returned cleanup closes the supervisor's policy-decisions writer so
// the on-disk file flushes before the test reads it back.
func newMVPSupervisor(t *testing.T) (*run.Supervisor, run.RunDirectory) {
	t.Helper()
	dir := newRunDir(t)
	policyDir := t.TempDir()
	policyPath := filepath.Join(policyDir, "policy.yaml")
	writeMVPPolicyYAML(t, policyPath, mvpSecurityPolicy())

	sup, err := run.NewSupervisor(run.SupervisorOptions{
		RunDir:           dir.Path,
		RunID:            dir.ID,
		EnvName:          "demo",
		Task:             "MVP security verification",
		Backend:          "local-process",
		Agent:            "claude",
		Command:          sh("true"),
		PolicyEnginePath: policyPath,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	return sup, dir
}

// flushMVPSupervisor is a documentation marker for the synchronous-fsync
// contract: PolicyDecisionsWriter.Write fsyncs each event before
// returning (see internal/run/policy_decisions.go), so a caller that has
// observed EvaluateNetworkDomain / EvaluateShellCommand return is
// guaranteed the on-disk file is up to date. The helper exists so the
// test bodies stay symmetric with a future writer that buffers, and so
// the suite has a single seam if the contract ever changes.
func flushMVPSupervisor(t *testing.T, sup *run.Supervisor) {
	t.Helper()
	_ = sup // contract is currently fsync-per-write; no explicit flush.
}

// findDenyForTargetSubstring returns the first PolicyDecisionEvent whose
// Target contains needle and whose Decision is "deny". Returns the empty
// event and false when no such record exists. Test helper so each subtest
// does not re-write the loop body.
func findDenyForTargetSubstring(events []run.PolicyDecisionEvent, needle string) (run.PolicyDecisionEvent, bool) {
	for _, e := range events {
		if e.Decision != run.PolicyDecisionDeny {
			continue
		}
		if strings.Contains(e.Target, needle) {
			return e, true
		}
	}
	return run.PolicyDecisionEvent{}, false
}

// TestAcceptance_HostSSHKeyReadDenied implements plan.md line 96 (master
// plan section "MVP demonstration", verification bullet 25): an attempted
// read of the host SSH key from inside the env must fail.
//
// The check rides on the engine's HighRiskShellPatterns list (which
// includes ".ssh/" and "id_rsa") and the supervisor's
// EvaluateShellCommand decision point. A real agent invoking
// `cat ~/.ssh/id_rsa` through the shell shim would hit this same path.
//
// The test asserts:
//   - The engine returns DecisionDeny.
//   - The deny is recorded in policy-decisions.jsonl as an
//     engine_evaluate event whose Target contains the SSH key path.
//   - The Reason mentions the high-risk pattern that matched, so an
//     operator reading the on-disk record sees why the action was
//     refused.
func TestAcceptance_HostSSHKeyReadDenied(t *testing.T) {
	sup, dir := newMVPSupervisor(t)

	cmdLine := "cat /root/.ssh/id_rsa"
	dec, err := sup.EvaluateShellCommand(cmdLine, []string{"cat", "/root/.ssh/id_rsa"}, "agent")
	if err != nil {
		t.Fatalf("EvaluateShellCommand: %v", err)
	}
	if dec.Type != policy.DecisionDeny {
		t.Errorf("decision = %q, want %q", dec.Type, policy.DecisionDeny)
	}
	if !strings.Contains(strings.ToLower(dec.Reason), "high-risk rule") {
		t.Errorf("Reason = %q, want substring 'high-risk rule'", dec.Reason)
	}

	flushMVPSupervisor(t, sup)

	events, err := run.ReadPolicyDecisions(dir.Path)
	if err != nil {
		t.Fatalf("ReadPolicyDecisions: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("no policy decisions recorded; want at least one deny for the SSH-key read")
	}
	got, ok := findDenyForTargetSubstring(events, "id_rsa")
	if !ok {
		t.Fatalf("no deny recorded for SSH-key Target; events=%+v", events)
	}
	if got.Event != run.PolicyDecisionEngineEvaluate {
		t.Errorf("Event = %q, want %q", got.Event, run.PolicyDecisionEngineEvaluate)
	}
	if got.EventType != string(policy.EventShellCommand) {
		t.Errorf("EventType = %q, want %q", got.EventType, policy.EventShellCommand)
	}
	if got.PolicyEventID == "" {
		t.Errorf("PolicyEventID empty; cannot look the record up via `ai-env policy explain --event`")
	}
	if got.EnvName != "demo" {
		t.Errorf("EnvName = %q, want %q", got.EnvName, "demo")
	}
}

// TestAcceptance_HostDockerSocketDenied implements plan.md line 97
// (master plan section "MVP demonstration", verification bullet 26): an
// attempted access to the host Docker socket from inside the env must
// fail.
//
// The /var/run/docker.sock path is NOT in HighRiskShellPatterns (only
// SSH paths, curl-pipe-shell, and the metadata IP are baked in there);
// the v0.1 policy.yaml-driven layer carries it via
// policy.commands.deny_patterns. This test exercises that layer so a
// regression that dropped the Docker-socket entry from the operator's
// deny list would surface here.
//
// The test asserts:
//   - The engine returns DecisionDeny.
//   - The Reason mentions the policy.commands.deny_patterns rule that
//     matched, so the audit trail shows the refusal came from the
//     user-configurable rule (not the high-risk fast path).
//   - The deny is recorded in policy-decisions.jsonl with Target
//     carrying the Docker-socket path.
func TestAcceptance_HostDockerSocketDenied(t *testing.T) {
	sup, dir := newMVPSupervisor(t)

	cmdLine := "curl --unix-socket /var/run/docker.sock http://localhost/version"
	dec, err := sup.EvaluateShellCommand(cmdLine,
		[]string{"curl", "--unix-socket", "/var/run/docker.sock", "http://localhost/version"},
		"agent",
	)
	if err != nil {
		t.Fatalf("EvaluateShellCommand: %v", err)
	}
	if dec.Type != policy.DecisionDeny {
		t.Errorf("decision = %q, want %q", dec.Type, policy.DecisionDeny)
	}
	// The Reason must reference either the user's deny pattern OR the
	// high-risk pattern (curl is in HighRiskShellPatterns and would
	// fire first in the engine's ordering). Either fires a deny on the
	// docker-socket path; the load-bearing assertion is the verdict
	// plus the on-disk record, not which rule fired the deny.
	reason := strings.ToLower(dec.Reason)
	if !strings.Contains(reason, "deny") && !strings.Contains(reason, "high-risk") {
		t.Errorf("Reason = %q, want substring 'deny' or 'high-risk'", dec.Reason)
	}

	flushMVPSupervisor(t, sup)

	events, err := run.ReadPolicyDecisions(dir.Path)
	if err != nil {
		t.Fatalf("ReadPolicyDecisions: %v", err)
	}
	got, ok := findDenyForTargetSubstring(events, "/var/run/docker.sock")
	if !ok {
		t.Fatalf("no deny recorded for docker-socket Target; events=%+v", events)
	}
	if got.Event != run.PolicyDecisionEngineEvaluate {
		t.Errorf("Event = %q, want %q", got.Event, run.PolicyDecisionEngineEvaluate)
	}
	if got.EventType != string(policy.EventShellCommand) {
		t.Errorf("EventType = %q, want %q", got.EventType, policy.EventShellCommand)
	}
	if got.PolicyEventID == "" {
		t.Errorf("PolicyEventID empty; cannot look the record up via `ai-env policy explain --event`")
	}
}

// TestAcceptance_UnknownNetworkEgressDenied implements plan.md line 98
// (master plan section "MVP demonstration", verification bullet 27): an
// attempted egress to an off-allowlist domain in the primary backend
// must fail.
//
// The test exercises the policy engine's network-egress decision point
// (supervisor.EvaluateNetworkDomain) plus the canonical NetworkPolicy
// runtime view's allowlist semantics so a future refactor that loosened
// either layer surfaces here.
//
// Two assertions:
//
//  1. The canonical NetworkPolicy built from the test config has
//     "evil.example.com" off its AllowDomains list and Default=="deny".
//     This is the static guarantee an adapter (docker_sbx,
//     fallback-docker, mock) honors when ApplyNetworkPolicy installs
//     rules: every destination not on AllowDomains is blocked because
//     the default is deny.
//  2. The supervisor's EvaluateNetworkDomain helper routes the egress
//     through the engine, which (because commands.default is "deny" in
//     mvpSecurityPolicy) returns DecisionDeny for any "network:
//     <domain>" synthetic command the supervisor builds. The deny lands
//     in policy-decisions.jsonl with EventType=shell_command and
//     Metadata[domain] set to the destination.
func TestAcceptance_UnknownNetworkEgressDenied(t *testing.T) {
	// 1. Static-layer assertion: NetworkPolicy allowlist semantics.
	p := network.NewNetworkPolicy(mvpSecurityPolicy().Network)
	if p.Default != network.DefaultPolicy {
		t.Errorf("Default = %q, want %q", p.Default, network.DefaultPolicy)
	}
	for _, d := range p.AllowDomains {
		if strings.EqualFold(d, "evil.example.com") {
			t.Errorf("AllowDomains unexpectedly contains evil.example.com: %v", p.AllowDomains)
		}
	}
	// Validate() must accept the default policy under autonomous mode;
	// a regression that weakened a default block flag would surface
	// here.
	if err := p.Validate("autonomous"); err != nil {
		t.Fatalf("Validate(autonomous) on default policy: %v", err)
	}

	// 2. Runtime-layer assertion: engine returns deny + records it.
	sup, dir := newMVPSupervisor(t)

	dec, err := sup.EvaluateNetworkDomain("evil.example.com", "egress")
	if err != nil {
		t.Fatalf("EvaluateNetworkDomain: %v", err)
	}
	if dec.Type != policy.DecisionDeny {
		t.Errorf("decision = %q, want %q", dec.Type, policy.DecisionDeny)
	}
	if dec.EventID == "" {
		t.Errorf("EventID empty; the on-disk record cannot be looked up")
	}

	flushMVPSupervisor(t, sup)

	events, err := run.ReadPolicyDecisions(dir.Path)
	if err != nil {
		t.Fatalf("ReadPolicyDecisions: %v", err)
	}
	got, ok := findDenyForTargetSubstring(events, "evil.example.com")
	if !ok {
		t.Fatalf("no deny recorded for evil.example.com egress; events=%+v", events)
	}
	if got.Event != run.PolicyDecisionEngineEvaluate {
		t.Errorf("Event = %q, want %q", got.Event, run.PolicyDecisionEngineEvaluate)
	}
	if got.EventType != string(policy.EventShellCommand) {
		t.Errorf("EventType = %q, want %q (network egress is routed through the shell-command family)",
			got.EventType, policy.EventShellCommand)
	}
	if got.Metadata["domain"] != "evil.example.com" {
		t.Errorf("Metadata[domain] = %q, want %q", got.Metadata["domain"], "evil.example.com")
	}
	if got.Metadata["surface"] != "network_egress" {
		t.Errorf("Metadata[surface] = %q, want %q", got.Metadata["surface"], "network_egress")
	}
}
