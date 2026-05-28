package config

// AgentsConfig models .ai-env/agents.yaml. It is a registry of agent
// adapter contracts keyed by short agent name (claude, codex, ...).
type AgentsConfig struct {
	Version int                    `yaml:"version"`
	Agents  map[string]AgentEntry  `yaml:"agents"`
}

// AgentEntry describes how a single agent binary is invoked and probed.
type AgentEntry struct {
	Command           string                 `yaml:"command"`
	VersionConstraint string                 `yaml:"version_constraint"`
	Probe             AgentProbe             `yaml:"probe"`
	Modes             map[string]AgentMode   `yaml:"modes"`
	CredentialMode    AgentCredentialMode    `yaml:"credential_mode"`
	Requires          []string               `yaml:"requires"`
}

// AgentProbe describes how to detect an agent's installed version.
type AgentProbe struct {
	Args  []string `yaml:"args"`
	Parse string   `yaml:"parse"`
}

// AgentMode describes how the agent is launched in a particular mode
// (autonomous, interactive, dry-run, continue).
type AgentMode struct {
	ArgsCandidates [][]string `yaml:"args_candidates"`
}

// AgentCredentialMode describes how the agent obtains provider credentials.
type AgentCredentialMode struct {
	Default       string   `yaml:"default"`
	FallbackOrder []string `yaml:"fallback_order"`
}
