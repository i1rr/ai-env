package run

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/config"
	"github.com/i1rr/ai-env/internal/policy"

	"gopkg.in/yaml.v3"
)

// validPolicyConfig returns a minimal policy.yaml-shaped config that
// passes config.ValidatePolicy. The helper mirrors the
// internal/cli.defaultPolicyConfig defaults but duplicates the shape so
// the run-package tests do not depend on internal/cli (which would be
// a cycle anyway).
func validPolicyConfig() *config.PolicyConfig {
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
			Default:      "allow_in_sandbox",
			DenyPatterns: []string{"rm -rf /"},
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

// writePolicyYAML marshals cfg to YAML at path. Helper that lets a test
// stage a policy.yaml on disk without dragging in the cli package's
// writeYAMLFile.
func writePolicyYAML(t *testing.T, path string, cfg *config.PolicyConfig) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}

// readPolicyDecisionLines parses policy-decisions.jsonl in runDir and
// returns the events in order. A missing or empty file returns an
// empty slice rather than failing so tests that want to assert "no
// records" do not need a special path.
func readPolicyDecisionLines(t *testing.T, runDir string) []PolicyDecisionEvent {
	t.Helper()
	events, err := ReadPolicyDecisions(runDir)
	if err != nil {
		t.Fatalf("ReadPolicyDecisions: %v", err)
	}
	return events
}

// TestNewSupervisor_LoadsPolicyEngineFromPath pins Plan 08 step 7's
// "load the env's policy file at run startup" contract: NewSupervisor
// must accept a PolicyEnginePath, read + validate the file, and store
// the engine on the supervisor for the runtime decision points to
// consult.
func TestNewSupervisor_LoadsPolicyEngineFromPath(t *testing.T) {
	dir := newSupervisorRunDir(t)
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	writePolicyYAML(t, policyPath, validPolicyConfig())

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:           dir.Path,
		RunID:            dir.ID,
		EnvName:          "fix-tests",
		Task:             "Fix the failing tests",
		Backend:          "local-process",
		Agent:            "claude",
		Command:          shellCmd("true"),
		PolicyEnginePath: policyPath,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if sup.engine == nil {
		t.Fatal("supervisor.engine = nil, want non-nil after loading policy.yaml")
	}
	if sup.pdWri == nil {
		t.Fatal("supervisor.pdWri = nil, want non-nil after loading policy.yaml")
	}
}

// TestNewSupervisor_MalformedPolicyFileAborts pins Plan 08 step 7's
// "validate config before starting sandbox" rule: a policy.yaml that
// fails parse / validate must cause NewSupervisor to fail with a clear
// error so the run never reaches the sandbox-start phase.
//
// The test also asserts that no lifecycle event is recorded on disk
// (the construction error happens before any state transition writes
// happen).
func TestNewSupervisor_MalformedPolicyFileAborts(t *testing.T) {
	dir := newSupervisorRunDir(t)
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")

	// Two failure modes to exercise: a syntactically invalid YAML and a
	// syntactically valid YAML that fails validation. Both must surface
	// as a NewSupervisor error.
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "syntax error",
			content: "version: 1\nmode: [unterminated",
			want:    "policy",
		},
		{
			name: "validation error",
			content: strings.Join([]string{
				"version: 1",
				"mode: not-a-mode",
				"network:",
				"  default: deny",
				"  enforcement: backend",
				"commands:",
				"  default: allow_in_sandbox",
				"dependencies:",
				"  install_scripts_default: deny",
				"scanners:",
				"  built_in_secret_scanner: pattern_only",
				"  entropy_findings: warn_only",
				"",
			}, "\n"),
			want: "mode",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(policyPath, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("write policy: %v", err)
			}
			_, err := NewSupervisor(SupervisorOptions{
				RunDir:           dir.Path,
				RunID:            dir.ID,
				EnvName:          "fix-tests",
				Task:             "Fix the failing tests",
				Backend:          "local-process",
				Agent:            "claude",
				Command:          shellCmd("true"),
				PolicyEnginePath: policyPath,
			})
			if err == nil {
				t.Fatalf("NewSupervisor with malformed policy: expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("NewSupervisor error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}

	// The lifecycle file should still be empty / not-yet-written: a
	// failed construction must not have transitioned any state.
	lifecycle := filepath.Join(dir.Path, "lifecycle.jsonl")
	info, err := os.Stat(lifecycle)
	if err != nil {
		t.Fatalf("stat lifecycle.jsonl: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("lifecycle.jsonl size = %d, want 0 (construction error must not transition)", info.Size())
	}
}

// TestNewSupervisor_MutuallyExclusivePolicySources pins the
// configuration-error rule: a caller that wires both PolicyEnginePath
// and PolicyEngine has not chosen which engine wins, so the
// constructor refuses rather than picking one silently.
func TestNewSupervisor_MutuallyExclusivePolicySources(t *testing.T) {
	dir := newSupervisorRunDir(t)
	eng := policy.NewEngine(validPolicyConfig())
	_, err := NewSupervisor(SupervisorOptions{
		RunDir:           dir.Path,
		RunID:            dir.ID,
		EnvName:          "fix-tests",
		Task:             "Fix the failing tests",
		Backend:          "local-process",
		Agent:            "claude",
		Command:          shellCmd("true"),
		PolicyEnginePath: "/path/to/some/policy.yaml",
		PolicyEngine:     eng,
	})
	if err == nil {
		t.Fatal("expected error when both PolicyEnginePath and PolicyEngine are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error = %q, want substring 'mutually exclusive'", err.Error())
	}
}

// TestEvaluateNetworkDomain_RecordsDeny pins the network-egress
// decision point: when the policy's deny_patterns lists a domain (or
// the engine's commands.default is "deny") the supervisor records a
// deny verdict in policy-decisions.jsonl. The test exercises the full
// path: construct supervisor with a real policy.yaml, call
// EvaluateNetworkDomain for a denied domain, then read the JSONL file
// and assert the decision shape.
func TestEvaluateNetworkDomain_RecordsDeny(t *testing.T) {
	dir := newSupervisorRunDir(t)
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	cfg := validPolicyConfig()
	// "evil.example.com" is not in allow_domains; instead we list it
	// in commands.deny_patterns so the engine's shell-command rule
	// matches the "network: evil.example.com" synthetic command line
	// EvaluateNetworkDomain builds.
	cfg.Commands.DenyPatterns = []string{"evil.example.com"}
	writePolicyYAML(t, policyPath, cfg)

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:           dir.Path,
		RunID:            dir.ID,
		EnvName:          "fix-tests",
		Task:             "Fix the failing tests",
		Backend:          "local-process",
		Agent:            "claude",
		Command:          shellCmd("true"),
		PolicyEnginePath: policyPath,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	defer func() {
		if sup.pdWri != nil {
			_ = sup.pdWri.Close()
		}
	}()

	dec, err := sup.EvaluateNetworkDomain("evil.example.com", "egress")
	if err != nil {
		t.Fatalf("EvaluateNetworkDomain: %v", err)
	}
	if dec.Type != policy.DecisionDeny {
		t.Errorf("decision = %q, want %q", dec.Type, policy.DecisionDeny)
	}
	if dec.EventID == "" {
		t.Errorf("EventID must be non-empty")
	}

	// Close the writer so the on-disk content flushes.
	if err := sup.pdWri.Close(); err != nil {
		t.Fatalf("Close pdWri: %v", err)
	}
	sup.pdWri = nil // prevent the defer from double-closing

	events := readPolicyDecisionLines(t, dir.Path)
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	got := events[0]
	if got.Event != PolicyDecisionEngineEvaluate {
		t.Errorf("Event = %q, want %q", got.Event, PolicyDecisionEngineEvaluate)
	}
	if got.Decision != PolicyDecisionDeny {
		t.Errorf("Decision = %q, want %q", got.Decision, PolicyDecisionDeny)
	}
	if got.PolicyEventID == "" {
		t.Errorf("PolicyEventID must be non-empty")
	}
	if got.EventType != string(policy.EventShellCommand) {
		t.Errorf("EventType = %q, want %q", got.EventType, policy.EventShellCommand)
	}
	if got.EnvName != "fix-tests" {
		t.Errorf("EnvName = %q, want %q", got.EnvName, "fix-tests")
	}
	if got.Metadata["domain"] != "evil.example.com" {
		t.Errorf("Metadata[domain] = %q, want %q", got.Metadata["domain"], "evil.example.com")
	}
}

// TestEvaluateShellCommand_RecordsAllow pins the tool-decision point:
// when a command does not match any deny pattern and commands.default
// is "allow_in_sandbox", the supervisor records an allow verdict. The
// test exercises the full path: construct supervisor, call
// EvaluateShellCommand, then read the JSONL file and assert the
// decision shape.
func TestEvaluateShellCommand_RecordsAllow(t *testing.T) {
	dir := newSupervisorRunDir(t)
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	cfg := validPolicyConfig()
	// commands.default is "allow_in_sandbox" by default and deny_patterns
	// is "rm -rf /"; "go test ./..." matches neither so the engine
	// should allow it.
	writePolicyYAML(t, policyPath, cfg)

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:           dir.Path,
		RunID:            dir.ID,
		EnvName:          "fix-tests",
		Task:             "Fix the failing tests",
		Backend:          "local-process",
		Agent:            "claude",
		Command:          shellCmd("true"),
		PolicyEnginePath: policyPath,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	defer func() {
		if sup.pdWri != nil {
			_ = sup.pdWri.Close()
		}
	}()

	dec, err := sup.EvaluateShellCommand("go test ./...", []string{"go", "test", "./..."}, "agent")
	if err != nil {
		t.Fatalf("EvaluateShellCommand: %v", err)
	}
	if dec.Type != policy.DecisionAllow {
		t.Errorf("decision = %q, want %q", dec.Type, policy.DecisionAllow)
	}
	if dec.EventID == "" {
		t.Errorf("EventID must be non-empty")
	}

	if err := sup.pdWri.Close(); err != nil {
		t.Fatalf("Close pdWri: %v", err)
	}
	sup.pdWri = nil

	events := readPolicyDecisionLines(t, dir.Path)
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	got := events[0]
	if got.Event != PolicyDecisionEngineEvaluate {
		t.Errorf("Event = %q, want %q", got.Event, PolicyDecisionEngineEvaluate)
	}
	if got.Decision != PolicyDecisionAllow {
		t.Errorf("Decision = %q, want %q", got.Decision, PolicyDecisionAllow)
	}
	if got.PolicyEventID == "" {
		t.Errorf("PolicyEventID must be non-empty")
	}
	if got.EventType != string(policy.EventShellCommand) {
		t.Errorf("EventType = %q, want %q", got.EventType, policy.EventShellCommand)
	}
	if got.Action != "exec" {
		t.Errorf("Action = %q, want %q", got.Action, "exec")
	}
	if got.Target != "go test ./..." {
		t.Errorf("Target = %q, want %q", got.Target, "go test ./...")
	}
	if got.Metadata["argv"] != "go test ./..." {
		t.Errorf("Metadata[argv] = %q, want %q", got.Metadata["argv"], "go test ./...")
	}
	if got.Metadata["phase"] != "agent" {
		t.Errorf("Metadata[phase] = %q, want %q", got.Metadata["phase"], "agent")
	}
}

// TestEvaluate_NoEngineConfiguredIsNoOp pins the legacy behavior: a
// supervisor constructed without an engine returns a zero-value
// decision from the EvaluateX helpers and writes nothing to the
// policy-decisions.jsonl file. This is the path every plan-03 /
// plan-04 / plan-05 supervisor test takes today; the wiring must not
// break it.
func TestEvaluate_NoEngineConfiguredIsNoOp(t *testing.T) {
	dir := newSupervisorRunDir(t)

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:  dir.Path,
		RunID:   dir.ID,
		EnvName: "fix-tests",
		Task:    "Fix the failing tests",
		Backend: "local-process",
		Agent:   "claude",
		Command: shellCmd("true"),
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if sup.engine != nil {
		t.Errorf("supervisor.engine = %v, want nil", sup.engine)
	}
	if sup.pdWri != nil {
		t.Errorf("supervisor.pdWri = %v, want nil", sup.pdWri)
	}

	dec, err := sup.EvaluateNetworkDomain("github.com", "egress")
	if err != nil {
		t.Fatalf("EvaluateNetworkDomain: %v", err)
	}
	if dec.Type != "" {
		t.Errorf("decision.Type = %q, want empty (no engine)", dec.Type)
	}

	dec, err = sup.EvaluateShellCommand("go test ./...", nil, "")
	if err != nil {
		t.Fatalf("EvaluateShellCommand: %v", err)
	}
	if dec.Type != "" {
		t.Errorf("decision.Type = %q, want empty (no engine)", dec.Type)
	}

	// The file must be the empty placeholder CreateRunDirectory wrote.
	info, err := os.Stat(filepath.Join(dir.Path, "policy-decisions.jsonl"))
	if err != nil {
		t.Fatalf("stat policy-decisions.jsonl: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("policy-decisions.jsonl size = %d, want 0 (no engine, no records)", info.Size())
	}
}

// TestSupervisor_RunCompletesWithPolicyEngineWired drives a real
// supervisor.Run end-to-end against a no-op child, with a policy
// engine wired in. The test asserts that (a) the run reaches
// StateCompleted as it normally would, and (b) any policy decisions
// recorded during the run are still on disk after Run returns (the
// pdWri Close in Run's deferred drain must flush the trail).
func TestSupervisor_RunCompletesWithPolicyEngineWired(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	writePolicyYAML(t, policyPath, validPolicyConfig())

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "fix-tests",
		Task:              "Fix the failing tests",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("echo hello; exit 0"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		PolicyEnginePath:  policyPath,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	// Record a decision before Run so the trail has something to
	// preserve through the run's deferred close.
	dec, err := sup.EvaluateShellCommand("echo hello", []string{"echo", "hello"}, "setup")
	if err != nil {
		t.Fatalf("EvaluateShellCommand: %v", err)
	}
	if dec.Type != policy.DecisionAllow {
		t.Fatalf("pre-run decision = %q, want %q", dec.Type, policy.DecisionAllow)
	}

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}

	// The decision recorded before Run must still be readable
	// afterwards: Run's deferred Close on pdWri flushed the trail.
	events := readPolicyDecisionLines(t, dir.Path)
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	if events[0].Decision != PolicyDecisionAllow {
		t.Errorf("Decision = %q, want %q", events[0].Decision, PolicyDecisionAllow)
	}
	if events[0].PolicyEventID == "" {
		t.Errorf("PolicyEventID must be non-empty")
	}
	if events[0].Metadata["phase"] != "setup" {
		t.Errorf("Metadata[phase] = %q, want %q", events[0].Metadata["phase"], "setup")
	}

	// Re-decode the raw line as a sanity check that the JSON envelope
	// is valid.
	raw, err := os.ReadFile(filepath.Join(dir.Path, "policy-decisions.jsonl"))
	if err != nil {
		t.Fatalf("read policy-decisions.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("policy-decisions.jsonl lines = %d, want 1", len(lines))
	}
	var verify PolicyDecisionEvent
	if err := json.Unmarshal([]byte(lines[0]), &verify); err != nil {
		t.Fatalf("unmarshal line: %v", err)
	}
	if verify.RunID != dir.ID {
		t.Errorf("RunID = %q, want %q", verify.RunID, dir.ID)
	}
}
