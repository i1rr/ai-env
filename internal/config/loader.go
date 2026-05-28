package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// supportedVersion is the only schema version recognized by this build.
// All four config files share this version field.
const supportedVersion = 1

// LoadAIEnv reads and validates .ai-env/ai-env.yaml at the given path.
// The returned error always includes the file path and (when known) the
// field that failed validation.
func LoadAIEnv(path string) (*AIEnvConfig, error) {
	var cfg AIEnvConfig
	if err := readYAML(path, &cfg); err != nil {
		return nil, err
	}
	if err := ValidateAIEnv(&cfg); err != nil {
		return nil, wrapValidate(path, err)
	}
	return &cfg, nil
}

// LoadPolicy reads and validates .ai-env/policy.yaml.
func LoadPolicy(path string) (*PolicyConfig, error) {
	var cfg PolicyConfig
	if err := readYAML(path, &cfg); err != nil {
		return nil, err
	}
	if err := ValidatePolicy(&cfg); err != nil {
		return nil, wrapValidate(path, err)
	}
	return &cfg, nil
}

// LoadAgents reads and validates .ai-env/agents.yaml.
func LoadAgents(path string) (*AgentsConfig, error) {
	var cfg AgentsConfig
	if err := readYAML(path, &cfg); err != nil {
		return nil, err
	}
	if err := ValidateAgents(&cfg); err != nil {
		return nil, wrapValidate(path, err)
	}
	return &cfg, nil
}

// LoadSecretsExample reads and validates .ai-env/secrets.example.yaml.
func LoadSecretsExample(path string) (*SecretsExampleConfig, error) {
	var cfg SecretsExampleConfig
	if err := readYAML(path, &cfg); err != nil {
		return nil, err
	}
	if err := ValidateSecretsExample(&cfg); err != nil {
		return nil, wrapValidate(path, err)
	}
	return &cfg, nil
}

// readYAML is the shared read+unmarshal helper. It uses strict decoding so
// unknown keys surface as errors instead of silently being dropped.
func readYAML(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("config: parse %s: %w", path, err)
	}
	return nil
}

// wrapValidate prefixes a validation error with the offending file path.
func wrapValidate(path string, err error) error {
	return fmt.Errorf("config: validate %s: %w", path, err)
}

// FieldError identifies which configuration field failed validation.
type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("field %q: %s", e.Field, e.Message)
}

// newFieldErr builds a FieldError for a named field.
func newFieldErr(field, msg string) error {
	return &FieldError{Field: field, Message: msg}
}

// requireOneOf returns an error if value is not in allowed.
func requireOneOf(field, value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return newFieldErr(field, fmt.Sprintf("must be one of %v, got %q", allowed, value))
}

// requireNonEmpty returns an error if value is the empty string.
func requireNonEmpty(field, value string) error {
	if value == "" {
		return newFieldErr(field, "must be non-empty")
	}
	return nil
}

// requirePositive returns an error if value is <= 0.
func requirePositive(field string, value int) error {
	if value <= 0 {
		return newFieldErr(field, fmt.Sprintf("must be > 0, got %d", value))
	}
	return nil
}

// requireNonNegative returns an error if value is < 0.
func requireNonNegative(field string, value int) error {
	if value < 0 {
		return newFieldErr(field, fmt.Sprintf("must be >= 0, got %d", value))
	}
	return nil
}

// ValidateAIEnv enforces required fields and enum values for ai-env.yaml.
func ValidateAIEnv(c *AIEnvConfig) error {
	if c == nil {
		return errors.New("nil AIEnvConfig")
	}
	if c.Version != supportedVersion {
		return newFieldErr("version", fmt.Sprintf("unsupported version %d, expected %d", c.Version, supportedVersion))
	}
	// project.*
	if err := requireNonEmpty("project.name", c.Project.Name); err != nil {
		return err
	}
	if err := requireNonEmpty("project.root", c.Project.Root); err != nil {
		return err
	}
	if err := requireNonEmpty("project.default_agent", c.Project.DefaultAgent); err != nil {
		return err
	}
	if err := requireOneOf("project.default_mode", c.Project.DefaultMode,
		"autonomous", "interactive", "dry-run", "continue"); err != nil {
		return err
	}
	// workspace.*
	if err := requireOneOf("workspace.strategy", c.Workspace.Strategy,
		"auto", "worktree", "copy", "direct"); err != nil {
		return err
	}
	if err := requireOneOf("workspace.git_default", c.Workspace.GitDefault,
		"worktree", "copy", "direct"); err != nil {
		return err
	}
	if err := requireOneOf("workspace.non_git_default", c.Workspace.NonGitDefault,
		"worktree", "copy", "direct"); err != nil {
		return err
	}
	if err := requireNonEmpty("workspace.branch_prefix", c.Workspace.BranchPrefix); err != nil {
		return err
	}
	if err := requireOneOf("workspace.export", c.Workspace.Export,
		"patch", "branch", "pr", "none"); err != nil {
		return err
	}
	// sandbox.*
	if err := requireNonEmpty("sandbox.backend", c.Sandbox.Backend); err != nil {
		return err
	}
	if err := requireNonEmpty("sandbox.template", c.Sandbox.Template); err != nil {
		return err
	}
	// supervision.*
	if err := requirePositive("supervision.max_runtime_minutes", c.Supervision.MaxRuntimeMinutes); err != nil {
		return err
	}
	if err := requirePositive("supervision.idle_timeout_minutes", c.Supervision.IdleTimeoutMinutes); err != nil {
		return err
	}
	if err := requireNonNegative("supervision.shutdown_grace_seconds", c.Supervision.ShutdownGraceSeconds); err != nil {
		return err
	}
	if err := requireNonNegative("supervision.kill_grace_seconds", c.Supervision.KillGraceSeconds); err != nil {
		return err
	}
	if err := requirePositive("supervision.max_stdout_bytes", c.Supervision.MaxStdoutBytes); err != nil {
		return err
	}
	if err := requirePositive("supervision.max_stderr_bytes", c.Supervision.MaxStderrBytes); err != nil {
		return err
	}
	if err := requirePositive("supervision.max_processes", c.Supervision.MaxProcesses); err != nil {
		return err
	}
	// logging.*
	if err := requireOneOf("logging.level", c.Logging.Level,
		"debug", "info", "warn", "error"); err != nil {
		return err
	}
	if err := requirePositive("logging.retain_runs", c.Logging.RetainRuns); err != nil {
		return err
	}
	if err := requireNonEmpty("logging.run_id_format", c.Logging.RunIDFormat); err != nil {
		return err
	}
	return nil
}

// ValidatePolicy enforces required fields and enum values for policy.yaml.
func ValidatePolicy(c *PolicyConfig) error {
	if c == nil {
		return errors.New("nil PolicyConfig")
	}
	if c.Version != supportedVersion {
		return newFieldErr("version", fmt.Sprintf("unsupported version %d, expected %d", c.Version, supportedVersion))
	}
	if err := requireOneOf("mode", c.Mode,
		"autonomous", "interactive", "dry-run", "continue"); err != nil {
		return err
	}
	if err := requireOneOf("network.default", c.Network.Default,
		"allow", "deny"); err != nil {
		return err
	}
	if err := requireOneOf("network.enforcement", c.Network.Enforcement,
		"backend", "host", "none"); err != nil {
		return err
	}
	if err := requireOneOf("commands.default", c.Commands.Default,
		"allow", "deny", "allow_in_sandbox"); err != nil {
		return err
	}
	if err := requireOneOf("dependencies.install_scripts_default", c.Dependencies.InstallScriptsDefault,
		"allow", "deny"); err != nil {
		return err
	}
	if err := requireNonNegative("secrets.default_ttl_seconds", c.Secrets.DefaultTTLSeconds); err != nil {
		return err
	}
	if err := requireNonNegative("secrets.max_ttl_seconds", c.Secrets.MaxTTLSeconds); err != nil {
		return err
	}
	if c.Secrets.MaxTTLSeconds > 0 && c.Secrets.DefaultTTLSeconds > c.Secrets.MaxTTLSeconds {
		return newFieldErr("secrets.default_ttl_seconds",
			fmt.Sprintf("must be <= secrets.max_ttl_seconds (%d)", c.Secrets.MaxTTLSeconds))
	}
	if err := requireOneOf("scanners.built_in_secret_scanner", c.Scanners.BuiltInSecretScanner,
		"off", "pattern_only", "pattern_and_entropy"); err != nil {
		return err
	}
	if err := requireOneOf("scanners.entropy_findings", c.Scanners.EntropyFindings,
		"warn_only", "fail", "off"); err != nil {
		return err
	}
	return nil
}

// ValidateAgents enforces required fields for agents.yaml.
func ValidateAgents(c *AgentsConfig) error {
	if c == nil {
		return errors.New("nil AgentsConfig")
	}
	if c.Version != supportedVersion {
		return newFieldErr("version", fmt.Sprintf("unsupported version %d, expected %d", c.Version, supportedVersion))
	}
	if len(c.Agents) == 0 {
		return newFieldErr("agents", "must define at least one agent")
	}
	for name, entry := range c.Agents {
		if name == "" {
			return newFieldErr("agents", "agent key must be non-empty")
		}
		if err := requireNonEmpty(fmt.Sprintf("agents.%s.command", name), entry.Command); err != nil {
			return err
		}
		if err := requireNonEmpty(fmt.Sprintf("agents.%s.version_constraint", name), entry.VersionConstraint); err != nil {
			return err
		}
		if len(entry.Probe.Args) == 0 {
			return newFieldErr(fmt.Sprintf("agents.%s.probe.args", name), "must list at least one probe argument")
		}
		if err := requireNonEmpty(fmt.Sprintf("agents.%s.probe.parse", name), entry.Probe.Parse); err != nil {
			return err
		}
		if len(entry.Modes) == 0 {
			return newFieldErr(fmt.Sprintf("agents.%s.modes", name), "must define at least one mode")
		}
		for modeName := range entry.Modes {
			if err := requireOneOf(fmt.Sprintf("agents.%s.modes key", name), modeName,
				"autonomous", "interactive", "dry-run", "continue"); err != nil {
				return err
			}
		}
		if err := requireNonEmpty(fmt.Sprintf("agents.%s.credential_mode.default", name), entry.CredentialMode.Default); err != nil {
			return err
		}
	}
	return nil
}

// ValidateSecretsExample enforces required fields for secrets.example.yaml.
// This file documents providers; it must never embed raw credentials, so the
// validator only checks structural fields.
func ValidateSecretsExample(c *SecretsExampleConfig) error {
	if c == nil {
		return errors.New("nil SecretsExampleConfig")
	}
	if c.Version != supportedVersion {
		return newFieldErr("version", fmt.Sprintf("unsupported version %d, expected %d", c.Version, supportedVersion))
	}
	if len(c.Secrets.Providers) == 0 {
		return newFieldErr("secrets.providers", "must define at least one provider")
	}
	for name, provider := range c.Secrets.Providers {
		if name == "" {
			return newFieldErr("secrets.providers", "provider key must be non-empty")
		}
		if err := requireOneOf(fmt.Sprintf("secrets.providers.%s.mode", name), provider.Mode,
			"backend_managed", "brokered", "provider_proxy", "raw_env_explicit", "raw_env_explicit_only"); err != nil {
			return err
		}
		if err := requireNonNegative(fmt.Sprintf("secrets.providers.%s.ttl_seconds", name), provider.TTLSeconds); err != nil {
			return err
		}
	}
	return nil
}
