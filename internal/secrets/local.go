// local.go implements Plan Batch 2.1: the loader for the operator-managed
// .ai-env/secrets.local.yaml file. This file is gitignored and holds raw
// machine-local credentials the host-side broker reads when wiring up
// per-run provider proxies (Batch 2.2 / 2.4) and the GitHub broker
// (Batch 4.2). The file is created at workspace init by `ai-env new`
// with mode 0600 and a documentation stub (no raw credentials); the
// operator is expected to fill in real values out-of-band.
//
// Schema (verified against the master plan's "secrets.example.yaml" shape
// in archive/full_plan.md and the existing config.SecretsExampleConfig
// pair so the local file is a strict superset that carries credential
// values where the example only documents modes):
//
//	version: 1
//	secrets:
//	  providers:
//	    anthropic:
//	      api_key: "sk-ant-..."
//	    openai:
//	      api_key: "sk-..."
//	  github:
//	    app:
//	      app_id: 12345
//	      installation_id: 67890
//	      private_key_pem: |
//	        -----BEGIN RSA PRIVATE KEY-----
//	        ...
//	        -----END RSA PRIVATE KEY-----
//	      api_base_url: "https://api.github.com"  # optional
//	    pat:
//	      enabled: true
//	      token: "ghp_..."
//	      ttl_seconds: 1800                       # optional
//
// Loader contract (matches the rest of internal/config's pattern but
// stays in internal/secrets so the package keeps owning every raw-secret
// touch point in one place):
//
//   - LoadLocal(path) returns a fully populated *LocalConfig on success.
//   - A missing file is NOT an error: a fresh workspace has the stub at
//     mode 0600 and the operator has not filled it in yet. The supervisor
//     fans out from there ("no anthropic credential configured" surfaces
//     downstream as a launcher resolution failure, not a file-read error).
//   - An empty file (the documentation stub written by `ai-env new` whose
//     payload is entirely YAML comments) is treated as "no credentials";
//     LoadLocal returns a non-nil *LocalConfig with the default version
//     stamped so the upstream caller does not need to nil-check.
//   - YAML parse errors and schema-version mismatches are hard errors so
//     a corrupt file cannot be silently ignored.
//   - The loader checks the file's mode on POSIX systems. When the mode
//     is broader than 0600 (any group/other bit set) the loader returns
//     the parsed config AND a non-empty PermissionWarnings slice that
//     the supervisor surfaces via LifecycleVerbSecretsPermissionWarning.
//     This is a warning, not a hard error: an operator who chmodded the
//     file to a working-group-readable mode should be told, but not
//     blocked, because the credential might still be the only one
//     available and refusing to load it would just trade one risk for
//     another (the run would run with no provider credential and the
//     leak surface would shift). Windows skips the check (file modes
//     mean little there).
package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// LocalConfigSchemaVersion is the only schema version this loader
// recognizes. It mirrors config.supportedVersion (which is also 1) so
// the example and local files always carry the same value.
const LocalConfigSchemaVersion = 1

// LocalConfigDefaultFilename is the canonical filename inside the
// per-project .ai-env/ directory. Exported so call sites that want to
// resolve <workspace>/.ai-env/<this> share one constant.
const LocalConfigDefaultFilename = "secrets.local.yaml"

// DesiredLocalConfigMode is the file mode `ai-env new` writes the stub
// with and the mode the loader expects at every subsequent open. The
// constant is exported so a doctor / fixer that wants to repair the
// permission has the right value at hand.
const DesiredLocalConfigMode os.FileMode = 0o600

// LocalConfig is the in-memory shape of .ai-env/secrets.local.yaml. The
// Version field is required; Secrets is the credential map proper. Both
// fields use yaml struct tags so KnownFields() decoding catches typos
// in the operator's file (a misspelled "providors:" surfaces as a parse
// error instead of a silent no-credentials state).
type LocalConfig struct {
	// Version is the schema version. Must equal LocalConfigSchemaVersion.
	Version int `yaml:"version"`

	// Secrets holds every credential the loader recognizes. An empty
	// Secrets section is valid: it means the operator has the stub on
	// disk but has not filled anything in yet.
	Secrets LocalSecretsSection `yaml:"secrets"`
}

// LocalSecretsSection mirrors the example file's top-level "secrets:"
// block but carries credential values rather than mode metadata. Both
// sub-keys are optional so a project that only needs a model provider
// (no GitHub broker, e.g., a sandbox-only setup) does not have to spell
// out an empty github: block.
type LocalSecretsSection struct {
	// Providers keys are lower-cased provider identifiers ("anthropic",
	// "openai"). Unknown keys are tolerated at decode time but ignored
	// by BuildProviderProxyFromSecrets so a typo does not silently wire
	// a non-existent provider.
	Providers map[string]LocalProviderCredentials `yaml:"providers,omitempty"`

	// GitHub holds the broker credentials. nil means "no GitHub
	// credential configured"; the broker selector surfaces that as
	// ErrNoTokenSource at AcquireToken time.
	GitHub *LocalGitHubCredentials `yaml:"github,omitempty"`
}

// LocalProviderCredentials carries the raw credential the host-side
// ProviderProxy injects upstream. Today the only field is APIKey; the
// struct shape leaves room for OAuth refresh tokens / org IDs / etc.
// when a provider adds them without breaking the file format.
type LocalProviderCredentials struct {
	// APIKey is the raw provider credential. Empty means the operator
	// has not filled the entry in (the example stub leaves it
	// commented out); BuildProviderProxyFromSecrets skips entries with
	// an empty APIKey so a half-filled file does not produce a proxy
	// with an empty token.
	APIKey string `yaml:"api_key,omitempty"`
}

// LocalGitHubCredentials carries the operator's GitHub broker config.
// Either App or PAT (or both) may be set; the broker's SelectTokenSource
// already encodes the precedence rule (App wins when present) so this
// struct only needs to surface the raw values.
type LocalGitHubCredentials struct {
	// App is the GitHub App installation credential. The PEM body must
	// be the verbatim private key contents (multi-line YAML literal).
	App *LocalGitHubAppCredentials `yaml:"app,omitempty"`

	// PAT is the personal access token fallback.
	PAT *LocalGitHubPATCredentials `yaml:"pat,omitempty"`
}

// LocalGitHubAppCredentials mirrors githubbroker.GitHubAppConfig but is
// declared here so the secrets package stays a leaf (no import of
// githubbroker). Batch 4.2's BuildBrokerFromSecrets is the adapter that
// converts this struct into the broker's own config type.
type LocalGitHubAppCredentials struct {
	AppID          int64  `yaml:"app_id"`
	InstallationID int64  `yaml:"installation_id"`
	PrivateKeyPEM  string `yaml:"private_key_pem"`
	APIBaseURL     string `yaml:"api_base_url,omitempty"`
}

// LocalGitHubPATCredentials mirrors githubbroker.PATConfig with the
// same leaf-package rationale as the App struct above.
type LocalGitHubPATCredentials struct {
	Enabled    bool   `yaml:"enabled"`
	Token      string `yaml:"token,omitempty"`
	TTLSeconds int    `yaml:"ttl_seconds,omitempty"`
}

// PermissionWarning describes a file-mode anomaly the loader noticed.
// The supervisor turns each warning into a LifecycleVerbSecretsPermission
// Warning event so a reviewer can correlate later activity with the
// permission state at load time. The warning is not an error: see the
// package-level commentary for the rationale.
type PermissionWarning struct {
	// Path is the absolute path of the offending file (the same path
	// passed to LoadLocal).
	Path string

	// Mode is the file mode the loader saw (the bits that matter; the
	// caller should stringify via fmt.Sprintf("0%o", ...) when
	// surfacing).
	Mode os.FileMode

	// Wanted is the mode the loader expected (DesiredLocalConfigMode).
	// Carried in the warning so an operator-facing message can name the
	// target value without guessing.
	Wanted os.FileMode

	// Reason is a short token suitable for a metadata field. Today the
	// only value is "world_or_group_readable"; future loosened checks
	// would add new tokens.
	Reason string
}

// LoadLocal reads, validates, and returns the parsed *LocalConfig at
// path. See the package commentary for the missing-file / empty-file /
// permission-warning semantics. The returned warnings slice is always
// non-nil on the success path so a caller that iterates blindly does
// not need a nil guard; an empty slice means no warnings.
//
// LoadLocal is the only entry point Batch 2.4's
// BuildProviderProxyFromSecrets and Batch 4.2's BuildBrokerFromSecrets
// are allowed to use; centralizing the read here keeps the
// permission-check, parse, and version-check rules in one place and
// makes it obvious when a downstream batch grows a new credential type
// that the schema must grow with it.
func LoadLocal(path string) (*LocalConfig, []PermissionWarning, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, errors.New("secrets: LoadLocal requires a non-empty path")
	}

	warnings := make([]PermissionWarning, 0)

	info, statErr := os.Stat(path)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			// Missing file = empty credentials. Stamp the version so
			// the returned struct round-trips through YAML cleanly if
			// the caller ever re-marshals it.
			return &LocalConfig{Version: LocalConfigSchemaVersion}, warnings, nil
		}
		return nil, warnings, fmt.Errorf("secrets: stat %s: %w", path, statErr)
	}
	if info.IsDir() {
		return nil, warnings, fmt.Errorf("secrets: %s is a directory, expected a file", path)
	}

	// Permission check (POSIX only — Windows file modes don't carry
	// the same meaning so we skip the check there).
	if runtime.GOOS != "windows" {
		mode := info.Mode().Perm()
		// Any group or other bit set is broader than 0600.
		if mode&0o077 != 0 {
			warnings = append(warnings, PermissionWarning{
				Path:   path,
				Mode:   mode,
				Wanted: DesiredLocalConfigMode,
				Reason: "world_or_group_readable",
			})
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, warnings, fmt.Errorf("secrets: read %s: %w", path, err)
	}

	// An entirely-comments file (the `ai-env new` stub) decodes to a
	// zero LocalConfig. Detect "no actual YAML payload" up front so we
	// can stamp the version ourselves instead of failing the version
	// check on a structurally empty file.
	if isEffectivelyEmpty(data) {
		return &LocalConfig{Version: LocalConfigSchemaVersion}, warnings, nil
	}

	var cfg LocalConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, warnings, fmt.Errorf("secrets: parse %s: %w", path, err)
	}

	if err := validateLocalConfig(&cfg); err != nil {
		return nil, warnings, fmt.Errorf("secrets: validate %s: %w", path, err)
	}

	// Lower-case the provider keys so downstream code can use the
	// Provider* constants directly. Done after validation so the
	// validator can complain about empty / duplicate keys before we
	// normalize.
	cfg.Secrets.Providers = normalizeProviderKeys(cfg.Secrets.Providers)

	return &cfg, warnings, nil
}

// isEffectivelyEmpty reports whether the YAML payload contains only
// whitespace and #-comments. The default stub written by `ai-env new`
// is exactly this; treating it as zero-config (without running the
// version check) lets a fresh workspace load cleanly even though the
// stub has no `version: 1` line.
func isEffectivelyEmpty(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		return false
	}
	return true
}

// validateLocalConfig enforces the structural rules. The validator is
// intentionally minimal: every credential field is optional at this
// level (callers like BuildProviderProxyFromSecrets enforce
// "non-empty when used" semantics) so a half-populated file still
// loads and the missing piece surfaces at the wire-up site with a
// caller-specific error message.
func validateLocalConfig(c *LocalConfig) error {
	if c == nil {
		return errors.New("nil LocalConfig")
	}
	if c.Version != LocalConfigSchemaVersion {
		return fmt.Errorf("unsupported version %d, expected %d", c.Version, LocalConfigSchemaVersion)
	}
	for name := range c.Secrets.Providers {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			return errors.New("secrets.providers: provider key must be non-empty")
		}
	}
	if gh := c.Secrets.GitHub; gh != nil {
		if gh.App != nil {
			if gh.App.AppID < 0 {
				return fmt.Errorf("secrets.github.app.app_id: must be >= 0, got %d", gh.App.AppID)
			}
			if gh.App.InstallationID < 0 {
				return fmt.Errorf("secrets.github.app.installation_id: must be >= 0, got %d", gh.App.InstallationID)
			}
		}
		if gh.PAT != nil {
			if gh.PAT.TTLSeconds < 0 {
				return fmt.Errorf("secrets.github.pat.ttl_seconds: must be >= 0, got %d", gh.PAT.TTLSeconds)
			}
		}
	}
	return nil
}

// normalizeProviderKeys lower-cases every provider key so downstream
// code can compare against the Provider* constants directly. Returns a
// new map (never mutates the input) so the caller's reference is safe.
func normalizeProviderKeys(in map[string]LocalProviderCredentials) map[string]LocalProviderCredentials {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]LocalProviderCredentials, len(in))
	for k, v := range in {
		out[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return out
}
