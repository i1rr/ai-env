package config

// SecretsExampleConfig models .ai-env/secrets.example.yaml. The file
// documents required providers and safe defaults; it never holds raw
// credentials (those live in the gitignored secrets.local.yaml).
type SecretsExampleConfig struct {
	Version int            `yaml:"version"`
	Secrets SecretsSection `yaml:"secrets"`
}

// SecretsSection groups the provider list and the deny list of categories
// that must never be exposed to agents.
type SecretsSection struct {
	Providers map[string]SecretsProvider `yaml:"providers"`
	Deny      []string                   `yaml:"deny"`
}

// SecretsProvider describes one credential source (openai, anthropic,
// github, ...). Optional fields stay zero-valued when absent.
type SecretsProvider struct {
	Mode          string   `yaml:"mode"`
	FallbackOrder []string `yaml:"fallback_order,omitempty"`
	TokenType     string   `yaml:"token_type,omitempty"`
	TTLSeconds    int      `yaml:"ttl_seconds,omitempty"`
	Scopes        []string `yaml:"scopes,omitempty"`
	BranchPrefix  string   `yaml:"branch_prefix,omitempty"`
}
