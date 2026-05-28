package config

// PolicyConfig models .ai-env/policy.yaml. It describes the security
// policy applied to agent runs: network access, filesystem protections,
// command restrictions, dependency-install behavior, secret handling,
// scanner defaults, and review gates.
type PolicyConfig struct {
	Version      int                  `yaml:"version"`
	Mode         string               `yaml:"mode"`
	Network      NetworkPolicy        `yaml:"network"`
	Filesystem   FilesystemPolicy     `yaml:"filesystem"`
	Commands     CommandsPolicy       `yaml:"commands"`
	Dependencies DependenciesPolicy   `yaml:"dependencies"`
	Secrets      SecretsPolicy        `yaml:"secrets"`
	Scanners     ScannersPolicy       `yaml:"scanners"`
	Review       ReviewPolicy         `yaml:"review"`
}

// NetworkPolicy controls outbound network access from the sandbox.
type NetworkPolicy struct {
	Default                 string   `yaml:"default"`
	Enforcement             string   `yaml:"enforcement"`
	TLSMITM                 bool     `yaml:"tls_mitm"`
	AllowDomains            []string `yaml:"allow_domains"`
	BlockPrivateRanges      bool     `yaml:"block_private_ranges"`
	BlockMetadataServices   bool     `yaml:"block_metadata_services"`
	BlockLocalhost          bool     `yaml:"block_localhost"`
	BlockHostDockerInternal bool     `yaml:"block_host_docker_internal"`
}

// FilesystemPolicy controls what the agent can read or write outside its
// workspace and which in-workspace paths are still protected.
type FilesystemPolicy struct {
	WorkspaceWrite  bool     `yaml:"workspace_write"`
	HostHomeRead    bool     `yaml:"host_home_read"`
	HostHomeWrite   bool     `yaml:"host_home_write"`
	ProtectedPaths  []string `yaml:"protected_paths"`
}

// CommandsPolicy controls which commands the agent may run.
type CommandsPolicy struct {
	Default      string   `yaml:"default"`
	DenyPatterns []string `yaml:"deny_patterns"`
}

// DependenciesPolicy controls dependency-install side effects.
type DependenciesPolicy struct {
	InstallScriptsDefault             string `yaml:"install_scripts_default"`
	AllowInstallScriptsOnlyInSetup    bool   `yaml:"allow_install_scripts_only_in_setup_phase"`
	NoSecretsDuringSetup              bool   `yaml:"no_secrets_during_setup"`
}

// SecretsPolicy controls how secrets are exposed to the agent.
type SecretsPolicy struct {
	RawEnvInjection   bool `yaml:"raw_env_injection"`
	BrokeredOnly      bool `yaml:"brokered_only"`
	DefaultTTLSeconds int  `yaml:"default_ttl_seconds"`
	MaxTTLSeconds     int  `yaml:"max_ttl_seconds"`
	RotatePerAction   bool `yaml:"rotate_per_action"`
	RevokeOnDestroy   bool `yaml:"revoke_on_destroy"`
}

// ScannersPolicy controls built-in secret-scanning behavior.
type ScannersPolicy struct {
	BuiltInSecretScanner string   `yaml:"built_in_secret_scanner"`
	EntropyFindings      string   `yaml:"entropy_findings"`
	CustomPatterns       []string `yaml:"custom_patterns"`
}

// ReviewPolicy controls export gating: diff review, scanning, and PR
// safety checks.
type ReviewPolicy struct {
	RequireDiffReview              bool `yaml:"require_diff_review"`
	RequireScanBeforeExport        bool `yaml:"require_scan_before_export"`
	FailOnSecretLeak               bool `yaml:"fail_on_secret_leak"`
	FailOnHighVulnerability        bool `yaml:"fail_on_high_vulnerability"`
	ScanPRTitleBodyAndCommits      bool `yaml:"scan_pr_title_body_and_commit_messages"`
	BlockAutoPRonWorkflowChanges   bool `yaml:"block_auto_pr_on_workflow_changes"`
}
