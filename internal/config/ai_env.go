// Package config defines the structures and loader for ai-env configuration
// files written to a project's .ai-env/ directory. Each top-level YAML file
// (ai-env.yaml, policy.yaml, agents.yaml, secrets.example.yaml) maps to a
// dedicated struct in this package.
package config

// AIEnvConfig models .ai-env/ai-env.yaml. It records project identity,
// workspace strategy, sandbox backend selection, runtime supervision
// limits, and logging policy.
type AIEnvConfig struct {
	Version     int                `yaml:"version"`
	Project     ProjectSection     `yaml:"project"`
	Workspace   WorkspaceSection   `yaml:"workspace"`
	Sandbox     SandboxSection     `yaml:"sandbox"`
	Supervision SupervisionSection `yaml:"supervision"`
	Logging     LoggingSection     `yaml:"logging"`
}

// ProjectSection identifies the environment and its source project.
type ProjectSection struct {
	Name         string `yaml:"name"`
	Root         string `yaml:"root"`
	DefaultAgent string `yaml:"default_agent"`
	DefaultMode  string `yaml:"default_mode"`
}

// WorkspaceSection controls how the workspace is materialized (worktree,
// copy, etc.) and how changes are exported back to the source project.
type WorkspaceSection struct {
	Strategy      string `yaml:"strategy"`
	GitDefault    string `yaml:"git_default"`
	NonGitDefault string `yaml:"non_git_default"`
	BranchPrefix  string `yaml:"branch_prefix"`
	DirectWrite   bool   `yaml:"direct_write"`
	Export        string `yaml:"export"`
}

// SandboxSection selects the backend (docker-sbx, etc.) and tunes isolation
// behavior such as Docker daemon and host filesystem exposure.
type SandboxSection struct {
	Backend                string `yaml:"backend"`
	FallbackBackend        string `yaml:"fallback_backend"`
	Template               string `yaml:"template"`
	DestroyOnExit          bool   `yaml:"destroy_on_exit"`
	PrivateDockerDaemon    bool   `yaml:"private_docker_daemon"`
	HostDockerSocket       bool   `yaml:"host_docker_socket"`
	MountHome              bool   `yaml:"mount_home"`
	AcceptReducedIsolation bool   `yaml:"accept_reduced_isolation"`
}

// SupervisionSection bounds how long an agent run may execute and how much
// output it may produce before the supervisor intervenes.
type SupervisionSection struct {
	MaxRuntimeMinutes    int  `yaml:"max_runtime_minutes"`
	IdleTimeoutMinutes   int  `yaml:"idle_timeout_minutes"`
	ShutdownGraceSeconds int  `yaml:"shutdown_grace_seconds"`
	KillGraceSeconds     int  `yaml:"kill_grace_seconds"`
	MaxStdoutBytes       int  `yaml:"max_stdout_bytes"`
	MaxStderrBytes       int  `yaml:"max_stderr_bytes"`
	StreamOutputToDisk   bool `yaml:"stream_output_to_disk"`
	MaxProcesses         int  `yaml:"max_processes"`
}

// LoggingSection controls verbosity and retention for per-run logs.
type LoggingSection struct {
	Level         string `yaml:"level"`
	RetainRuns    int    `yaml:"retain_runs"`
	RedactSecrets bool   `yaml:"redact_secrets"`
	RunIDFormat   string `yaml:"run_id_format"`
}
