package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile is a tiny helper that creates path with contents.
// Tests use it to drop real YAML files into t.TempDir().
func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// --- ai-env.yaml ----------------------------------------------------------

const validAIEnvYAML = `version: 1
project:
  name: demo
  root: ..
  default_agent: claude
  default_mode: autonomous

workspace:
  strategy: auto
  git_default: worktree
  non_git_default: copy
  branch_prefix: ai-env/
  direct_write: false
  export: patch

sandbox:
  backend: docker-sbx
  fallback_backend: none
  template: default
  destroy_on_exit: false
  private_docker_daemon: true
  host_docker_socket: false
  mount_home: false
  accept_reduced_isolation: false

supervision:
  max_runtime_minutes: 120
  idle_timeout_minutes: 20
  shutdown_grace_seconds: 15
  kill_grace_seconds: 5
  max_stdout_bytes: 50000000
  max_stderr_bytes: 50000000
  stream_output_to_disk: true
  max_processes: 1024

logging:
  level: info
  retain_runs: 50
  redact_secrets: true
  run_id_format: timestamp_random_suffix
`

func TestLoadAIEnv_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ai-env.yaml")
	writeFile(t, path, validAIEnvYAML)

	cfg, err := LoadAIEnv(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("version = %d, want 1", cfg.Version)
	}
	if cfg.Project.Name != "demo" {
		t.Errorf("project.name = %q, want demo", cfg.Project.Name)
	}
	if cfg.Workspace.Strategy != "auto" {
		t.Errorf("workspace.strategy = %q, want auto", cfg.Workspace.Strategy)
	}
	if cfg.Sandbox.Backend != "docker-sbx" {
		t.Errorf("sandbox.backend = %q, want docker-sbx", cfg.Sandbox.Backend)
	}
	if cfg.Supervision.MaxRuntimeMinutes != 120 {
		t.Errorf("supervision.max_runtime_minutes = %d, want 120", cfg.Supervision.MaxRuntimeMinutes)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("logging.level = %q, want info", cfg.Logging.Level)
	}
}

func TestLoadAIEnv_FileMissing(t *testing.T) {
	_, err := LoadAIEnv(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("error should mention read: %v", err)
	}
}

func TestLoadAIEnv_UnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ai-env.yaml")
	writeFile(t, path, validAIEnvYAML+"\nbogus_unknown_field: true\n")

	_, err := LoadAIEnv(path)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention parse: %v", err)
	}
}

func TestValidateAIEnv_VersionMismatch(t *testing.T) {
	cfg := mustParseAIEnv(t, validAIEnvYAML)
	cfg.Version = 2
	err := ValidateAIEnv(cfg)
	requireFieldErr(t, err, "version")
}

func TestValidateAIEnv_MissingProjectName(t *testing.T) {
	cfg := mustParseAIEnv(t, validAIEnvYAML)
	cfg.Project.Name = ""
	err := ValidateAIEnv(cfg)
	requireFieldErr(t, err, "project.name")
}

func TestValidateAIEnv_BadDefaultMode(t *testing.T) {
	cfg := mustParseAIEnv(t, validAIEnvYAML)
	cfg.Project.DefaultMode = "lunatic"
	err := ValidateAIEnv(cfg)
	requireFieldErr(t, err, "project.default_mode")
}

func TestValidateAIEnv_EnumChecks(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*AIEnvConfig)
		fieldHint string
	}{
		{"strategy", func(c *AIEnvConfig) { c.Workspace.Strategy = "swap" }, "workspace.strategy"},
		{"git_default", func(c *AIEnvConfig) { c.Workspace.GitDefault = "swap" }, "workspace.git_default"},
		{"non_git_default", func(c *AIEnvConfig) { c.Workspace.NonGitDefault = "swap" }, "workspace.non_git_default"},
		{"export", func(c *AIEnvConfig) { c.Workspace.Export = "carrier-pigeon" }, "workspace.export"},
		{"logging.level", func(c *AIEnvConfig) { c.Logging.Level = "loud" }, "logging.level"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParseAIEnv(t, validAIEnvYAML)
			tc.mutate(cfg)
			requireFieldErr(t, ValidateAIEnv(cfg), tc.fieldHint)
		})
	}
}

func TestValidateAIEnv_NumericGuards(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*AIEnvConfig)
		fieldHint string
	}{
		{"max_runtime_minutes_zero", func(c *AIEnvConfig) { c.Supervision.MaxRuntimeMinutes = 0 }, "supervision.max_runtime_minutes"},
		{"idle_timeout_minutes_neg", func(c *AIEnvConfig) { c.Supervision.IdleTimeoutMinutes = -1 }, "supervision.idle_timeout_minutes"},
		{"shutdown_grace_neg", func(c *AIEnvConfig) { c.Supervision.ShutdownGraceSeconds = -1 }, "supervision.shutdown_grace_seconds"},
		{"max_stdout_zero", func(c *AIEnvConfig) { c.Supervision.MaxStdoutBytes = 0 }, "supervision.max_stdout_bytes"},
		{"max_processes_zero", func(c *AIEnvConfig) { c.Supervision.MaxProcesses = 0 }, "supervision.max_processes"},
		{"retain_runs_zero", func(c *AIEnvConfig) { c.Logging.RetainRuns = 0 }, "logging.retain_runs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParseAIEnv(t, validAIEnvYAML)
			tc.mutate(cfg)
			requireFieldErr(t, ValidateAIEnv(cfg), tc.fieldHint)
		})
	}
}

func TestValidateAIEnv_NilConfig(t *testing.T) {
	if err := ValidateAIEnv(nil); err == nil {
		t.Fatal("expected error for nil config")
	}
}

// --- policy.yaml ----------------------------------------------------------

const validPolicyYAML = `version: 1
mode: interactive
network:
  default: deny
  enforcement: backend
  tls_mitm: false
  allow_domains: []
  block_private_ranges: true
  block_metadata_services: true
  block_localhost: true
  block_host_docker_internal: true
filesystem:
  workspace_write: true
  host_home_read: false
  host_home_write: false
  protected_paths: [".git", ".ai-env"]
commands:
  default: allow_in_sandbox
  deny_patterns: []
dependencies:
  install_scripts_default: deny
  allow_install_scripts_only_in_setup_phase: true
  no_secrets_during_setup: true
secrets:
  raw_env_injection: false
  brokered_only: true
  default_ttl_seconds: 3600
  max_ttl_seconds: 14400
  rotate_per_action: false
  revoke_on_destroy: true
scanners:
  built_in_secret_scanner: pattern_and_entropy
  entropy_findings: warn_only
  custom_patterns: []
review:
  require_diff_review: true
  require_scan_before_export: true
  fail_on_secret_leak: true
  fail_on_high_vulnerability: true
  scan_pr_title_body_and_commit_messages: true
  block_auto_pr_on_workflow_changes: true
`

func TestLoadPolicy_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeFile(t, path, validPolicyYAML)

	cfg, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != "interactive" {
		t.Errorf("mode = %q, want interactive", cfg.Mode)
	}
	if cfg.Secrets.DefaultTTLSeconds != 3600 {
		t.Errorf("default_ttl_seconds = %d, want 3600", cfg.Secrets.DefaultTTLSeconds)
	}
}

func TestValidatePolicy_TTLOrdering(t *testing.T) {
	cfg := mustParsePolicy(t, validPolicyYAML)
	cfg.Secrets.DefaultTTLSeconds = 20000 // exceeds max 14400
	requireFieldErr(t, ValidatePolicy(cfg), "secrets.default_ttl_seconds")
}

func TestValidatePolicy_BadEnums(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*PolicyConfig)
		fieldHint string
	}{
		{"mode", func(c *PolicyConfig) { c.Mode = "magic" }, "mode"},
		{"network.default", func(c *PolicyConfig) { c.Network.Default = "maybe" }, "network.default"},
		{"network.enforcement", func(c *PolicyConfig) { c.Network.Enforcement = "kernel" }, "network.enforcement"},
		{"commands.default", func(c *PolicyConfig) { c.Commands.Default = "ask_nicely" }, "commands.default"},
		{"deps.install_scripts", func(c *PolicyConfig) { c.Dependencies.InstallScriptsDefault = "perhaps" }, "dependencies.install_scripts_default"},
		{"scanners.builtin", func(c *PolicyConfig) { c.Scanners.BuiltInSecretScanner = "ml" }, "scanners.built_in_secret_scanner"},
		{"scanners.entropy", func(c *PolicyConfig) { c.Scanners.EntropyFindings = "ignore" }, "scanners.entropy_findings"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParsePolicy(t, validPolicyYAML)
			tc.mutate(cfg)
			requireFieldErr(t, ValidatePolicy(cfg), tc.fieldHint)
		})
	}
}

// --- agents.yaml ----------------------------------------------------------

const validAgentsYAML = `version: 1
agents:
  claude:
    command: claude
    version_constraint: ">=0.0.0"
    probe:
      args: ["--version"]
      parse: semver
    modes:
      autonomous:
        args_candidates:
          - ["--print"]
      interactive:
        args_candidates:
          - []
    credential_mode:
      default: brokered
      fallback_order: ["raw_env_explicit"]
    requires: []
`

func TestLoadAgents_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agents.yaml")
	writeFile(t, path, validAgentsYAML)

	cfg, err := LoadAgents(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	claude, ok := cfg.Agents["claude"]
	if !ok {
		t.Fatal("expected claude agent")
	}
	if claude.Command != "claude" {
		t.Errorf("command = %q, want claude", claude.Command)
	}
	if len(claude.Probe.Args) == 0 {
		t.Error("expected non-empty probe args")
	}
}

func TestValidateAgents_EmptyMap(t *testing.T) {
	cfg := &AgentsConfig{Version: 1}
	requireFieldErr(t, ValidateAgents(cfg), "agents")
}

func TestValidateAgents_MissingCommand(t *testing.T) {
	cfg := mustParseAgents(t, validAgentsYAML)
	entry := cfg.Agents["claude"]
	entry.Command = ""
	cfg.Agents["claude"] = entry
	requireFieldErr(t, ValidateAgents(cfg), "agents.claude.command")
}

func TestValidateAgents_BadModeKey(t *testing.T) {
	cfg := mustParseAgents(t, validAgentsYAML)
	entry := cfg.Agents["claude"]
	entry.Modes = map[string]AgentMode{"loud": {ArgsCandidates: [][]string{{}}}}
	cfg.Agents["claude"] = entry
	err := ValidateAgents(cfg)
	if err == nil || !strings.Contains(err.Error(), "modes key") {
		t.Fatalf("expected modes-key error, got %v", err)
	}
}

// --- secrets.example.yaml -------------------------------------------------

const validSecretsExampleYAML = `version: 1
secrets:
  providers:
    anthropic:
      mode: brokered
      token_type: api_key
      ttl_seconds: 3600
  deny:
    - aws_root_credentials
`

func TestLoadSecretsExample_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.example.yaml")
	writeFile(t, path, validSecretsExampleYAML)

	cfg, err := LoadSecretsExample(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	anthropic, ok := cfg.Secrets.Providers["anthropic"]
	if !ok {
		t.Fatal("expected anthropic provider")
	}
	if anthropic.Mode != "brokered" {
		t.Errorf("mode = %q, want brokered", anthropic.Mode)
	}
}

func TestValidateSecretsExample_NoProviders(t *testing.T) {
	cfg := &SecretsExampleConfig{Version: 1}
	requireFieldErr(t, ValidateSecretsExample(cfg), "secrets.providers")
}

func TestValidateSecretsExample_BadMode(t *testing.T) {
	cfg := mustParseSecretsExample(t, validSecretsExampleYAML)
	p := cfg.Secrets.Providers["anthropic"]
	p.Mode = "plaintext"
	cfg.Secrets.Providers["anthropic"] = p
	requireFieldErr(t, ValidateSecretsExample(cfg), "secrets.providers.anthropic.mode")
}

func TestValidateSecretsExample_NegativeTTL(t *testing.T) {
	cfg := mustParseSecretsExample(t, validSecretsExampleYAML)
	p := cfg.Secrets.Providers["anthropic"]
	p.TTLSeconds = -1
	cfg.Secrets.Providers["anthropic"] = p
	requireFieldErr(t, ValidateSecretsExample(cfg), "secrets.providers.anthropic.ttl_seconds")
}

// --- shared helpers -------------------------------------------------------

func mustParseAIEnv(t *testing.T, yamlStr string) *AIEnvConfig {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ai-env.yaml")
	writeFile(t, path, yamlStr)
	cfg, err := LoadAIEnv(path)
	if err != nil {
		t.Fatalf("parse fixture ai-env.yaml: %v", err)
	}
	return cfg
}

func mustParsePolicy(t *testing.T, yamlStr string) *PolicyConfig {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeFile(t, path, yamlStr)
	cfg, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("parse fixture policy.yaml: %v", err)
	}
	return cfg
}

func mustParseAgents(t *testing.T, yamlStr string) *AgentsConfig {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agents.yaml")
	writeFile(t, path, yamlStr)
	cfg, err := LoadAgents(path)
	if err != nil {
		t.Fatalf("parse fixture agents.yaml: %v", err)
	}
	return cfg
}

func mustParseSecretsExample(t *testing.T, yamlStr string) *SecretsExampleConfig {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.example.yaml")
	writeFile(t, path, yamlStr)
	cfg, err := LoadSecretsExample(path)
	if err != nil {
		t.Fatalf("parse fixture secrets.example.yaml: %v", err)
	}
	return cfg
}

// requireFieldErr asserts err is a *FieldError whose Field contains the
// given substring. We use Contains rather than equality so tests stay
// resilient to small wording tweaks in error messages.
func requireFieldErr(t *testing.T, err error, fieldHint string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error for field containing %q, got nil", fieldHint)
	}
	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *FieldError, got %T: %v", err, err)
	}
	if !strings.Contains(fe.Field, fieldHint) {
		t.Fatalf("field = %q, want substring %q (full error: %v)", fe.Field, fieldHint, err)
	}
}
