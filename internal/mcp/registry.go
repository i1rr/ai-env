// Package mcp implements the Model Context Protocol (MCP) gateway that
// ai-env interposes between an agent and the MCP servers it tries to
// reach. The package is the single chokepoint through which every MCP
// call must pass: nothing routed outside the gateway can be governed
// by ai-env's policy, scope, or audit controls.
//
// Plan 09 builds this surface up in layers. This file contributes the
// foundation: the MCPRegistry, which loads and validates the operator-
// authored .ai-env/mcp.yaml file and answers "is this server permitted
// to run?" using a deny-by-default model.
//
// Later steps in plan 09 add the schema-hash pinning check
// (step 2), the gateway proxy that intercepts MCP requests
// (step 3), filesystem and GitHub scope enforcement
// (steps 4 and 5), the `ai-env mcp ...` CLI commands (step 6),
// the per-run mcp-calls.jsonl audit sink (step 7), and the
// docs/mcp-security.md write-up (step 8). All of those layers
// consume the MCPRegistry as their source of truth for which
// servers exist, what version is pinned, and what scope each
// server is allowed to operate in. Keeping registration concerns
// in this one type means the proxy, the CLI, and the audit code
// all agree on what "registered" means.
//
// Design rules this package enforces:
//
//  1. Deny by default. RegistryConfig.Default is hard-coded to "deny"
//     in v0.2: the master plan forbids an opt-in "allow unknown
//     servers" mode and the loader rejects any other value rather
//     than silently honoring it. An unknown server name passed to
//     Lookup returns ErrUnknownServer; the caller (gateway proxy,
//     CLI) must refuse the request.
//
//  2. Pin version or digest. Every registered server must declare a
//     Source that pins to an exact version (e.g.
//     "npm:@modelcontextprotocol/server-filesystem@1.2.3" or
//     "oci:ghcr.io/example/server:1.0.0") OR a Digest
//     ("sha256:..."). A server with neither cannot be reproduced and
//     so cannot be governed; ValidateRegistry rejects it. A server
//     with both must agree at lookup time: Registry.MatchVersion
//     and Registry.MatchDigest both succeed only when the
//     candidate matches what the registry has on file.
//
//  3. Per-server policy is allow / deny / warn. Servers default to
//     "allow" once registered (registration is itself the gate); an
//     operator can override to "deny" (registered but temporarily
//     parked) or "warn" (registered but the gateway emits a warning
//     on every call). Any other value is rejected at load time.
//
//  4. Scope shape is fixed. Step 1 only stores scope as parsed YAML;
//     the enforcement logic lands in steps 4 and 5. The shape is
//     locked here so later steps don't have to migrate the registry
//     file format: every server may declare a filesystem scope
//     (root: workspace_only) and / or a github scope (repos:
//     current_repo_only, operations: read_only|read_write). Unknown
//     scope kinds are rejected so a typo in mcp.yaml cannot
//     accidentally widen the surface.
//
// This file intentionally does not perform network I/O, hash a
// schema, or proxy any traffic: those concerns belong to later
// steps and to other files in this package. The MCPRegistry is a
// pure in-memory view of a YAML file.
package mcp

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// supportedVersion is the only mcp.yaml schema version this build
// understands. The other ai-env config files (ai-env.yaml,
// policy.yaml, agents.yaml, secrets.example.yaml) also pin to
// version 1; the mcp.yaml file follows the same convention so an
// operator never has to remember that mcp.yaml is "different".
const supportedVersion = 1

// DefaultPolicyDeny is the literal token "deny": the only top-level
// default policy mcp.yaml may declare in v0.2. Mirrored as a
// constant so the loader, the validator, and (later) the gateway
// proxy all compare against the same string instead of retyping it.
const DefaultPolicyDeny = "deny"

// Per-server policy tokens. These are the only values allowed in
// RegistryServer.Policy. "allow" means the server may run and its
// calls flow through the gateway normally. "deny" means the server
// is registered (its metadata is on file) but the gateway refuses
// to launch it: useful for parking a server during an incident
// without losing its pinned version. "warn" means the gateway
// allows the call but emits a warning to the audit log; the
// schema-mismatch path in step 2 also uses this token.
const (
	ServerPolicyAllow = "allow"
	ServerPolicyDeny  = "deny"
	ServerPolicyWarn  = "warn"
)

// Source kind prefixes recognized in RegistryServer.Source. The
// loader does not download or otherwise verify the source: it only
// checks that the string starts with a kind it understands and
// that the kind's "@<version>" or ":<tag>" suffix is present so
// the server is reproducibly pinned. Adding a new kind (e.g.
// "git:") is a deliberate decision that lands in a future plan;
// this constant block is the canonical list.
const (
	SourceKindNPM = "npm:"
	SourceKindOCI = "oci:"
)

// ScopeKind names the supported per-server scope blocks. The
// values are the YAML keys under server.scope: a server may
// declare zero, one, or both. The string constants are exported
// so the gateway proxy (step 3) and the scope-enforcement
// adapters (steps 4 and 5) can refer to the same tokens.
const (
	ScopeKindFilesystem = "filesystem"
	ScopeKindGitHub     = "github"
)

// Filesystem scope tokens. v0.2 only supports "workspace_only":
// the filesystem MCP may not access any path outside
// .ai-env/workspaces/<env-name>/. The constant is exported so
// step 4's enforcement code can compare against the same token.
const (
	FilesystemRootWorkspaceOnly = "workspace_only"
)

// GitHub scope tokens. v0.2 only supports "current_repo_only" for
// repos and read_only / read_write for operations; production
// cloud MCP usage is forbidden by master-plan rule. These tokens
// are exported so step 5's enforcement code shares the literals.
const (
	GitHubReposCurrentRepoOnly = "current_repo_only"
	GitHubOperationsReadOnly   = "read_only"
	GitHubOperationsReadWrite  = "read_write"
)

// ErrUnknownServer is returned by Registry.Lookup when the
// requested server name does not appear in the registry. The
// gateway proxy (step 3) and the CLI surface translate this into
// the operator-facing "unknown MCP server denied" message. The
// error is a sentinel so call sites can match with errors.Is
// instead of string-comparing the message.
var ErrUnknownServer = errors.New("mcp: unknown server")

// ErrVersionMismatch is returned by Registry.MatchVersion when
// the candidate source string does not match the registered
// source for that server. The gateway proxy (step 3) refuses to
// launch the server in that case; the CLI's `ai-env mcp scan`
// surfaces the mismatch to the operator.
var ErrVersionMismatch = errors.New("mcp: server version mismatch")

// ErrDigestMismatch is returned by Registry.MatchDigest when the
// candidate digest does not match the registered digest. Behaves
// like ErrVersionMismatch but for content-addressed sources
// (OCI images, locked tarballs).
var ErrDigestMismatch = errors.New("mcp: server digest mismatch")

// RegistryConfig is the YAML-shaped view of .ai-env/mcp.yaml. The
// field tags mirror the master-plan example verbatim so an
// operator who reads the plan can author the file without
// guessing at struct-field translations.
type RegistryConfig struct {
	Version int                       `yaml:"version"`
	Default string                    `yaml:"default"`
	Servers map[string]RegistryServer `yaml:"servers"`
}

// RegistryServer is a single entry under RegistryConfig.Servers.
// Source pins the upstream package (npm: or oci:); Digest pins
// the content hash; SchemaHash is the hash of the server's tool
// list computed at registration time (step 2 fills this in);
// Scope holds optional per-kind scope blocks; Policy is the
// per-server gate.
type RegistryServer struct {
	Source     string                  `yaml:"source"`
	Digest     string                  `yaml:"digest"`
	SchemaHash string                  `yaml:"schema_hash"`
	Scope      map[string]ScopeSection `yaml:"scope"`
	Policy     string                  `yaml:"policy"`
}

// ScopeSection is the parsed body of one scope kind. Only a
// subset of the fields are meaningful for each kind: filesystem
// uses Root; github uses Repos and Operations. Keeping the
// fields in one flat struct (rather than a kind-tagged union)
// keeps the YAML loader simple and matches the master-plan
// example. The validator (ValidateRegistry) rejects fields that
// do not belong to the declared kind.
type ScopeSection struct {
	// Root applies to the filesystem scope; v0.2 only accepts
	// FilesystemRootWorkspaceOnly.
	Root string `yaml:"root"`

	// Repos applies to the github scope; v0.2 only accepts
	// GitHubReposCurrentRepoOnly.
	Repos string `yaml:"repos"`

	// Operations applies to the github scope; v0.2 accepts
	// GitHubOperationsReadOnly or GitHubOperationsReadWrite.
	Operations string `yaml:"operations"`
}

// LoadRegistry reads and validates .ai-env/mcp.yaml at the given
// path. The returned error always includes the file path and (when
// known) the field that failed validation, mirroring the
// convention used by internal/config's loaders.
func LoadRegistry(path string) (*Registry, error) {
	var cfg RegistryConfig
	if err := readYAML(path, &cfg); err != nil {
		return nil, err
	}
	if err := ValidateRegistry(&cfg); err != nil {
		return nil, wrapValidate(path, err)
	}
	return NewRegistry(&cfg), nil
}

// readYAML is the shared read+unmarshal helper. It uses strict
// decoding so unknown keys surface as errors instead of silently
// being dropped. This matches the internal/config loader so an
// operator who is used to "unknown field" errors on policy.yaml
// gets the same error shape on mcp.yaml.
func readYAML(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("mcp: read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("mcp: parse %s: %w", path, err)
	}
	return nil
}

// wrapValidate prefixes a validation error with the offending
// file path so the operator sees both "what is wrong" and "in
// which file" in a single line.
func wrapValidate(path string, err error) error {
	return fmt.Errorf("mcp: validate %s: %w", path, err)
}

// FieldError identifies which mcp.yaml field failed validation.
// Mirrors config.FieldError so callers can pattern-match the same
// way across both packages.
type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("field %q: %s", e.Field, e.Message)
}

// newFieldErr is the canonical constructor used by every
// validation rule in this file. Centralizing it keeps the wording
// consistent (`field "x": <msg>`) across rules.
func newFieldErr(field, msg string) error {
	return &FieldError{Field: field, Message: msg}
}

// requireOneOf returns a FieldError if value is not in allowed.
// Used for enum-shaped fields (policy, root, repos, operations).
func requireOneOf(field, value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return newFieldErr(field, fmt.Sprintf("must be one of %v, got %q", allowed, value))
}

// requireNonEmpty returns a FieldError if value is the empty
// string. Used for fields that must be present but whose value
// space is open-ended (digest, schema_hash).
func requireNonEmpty(field, value string) error {
	if value == "" {
		return newFieldErr(field, "must be non-empty")
	}
	return nil
}

// ValidateRegistry enforces every structural rule the rest of
// the package relies on: supported version, deny-by-default,
// at least one server, and per-server constraints (source kind
// recognized and pinned, digest or version present, policy
// token recognized, scope sections well-formed). Returning a
// FieldError (rather than a free-form error) lets tests assert
// on the offending field name without grepping the message text.
func ValidateRegistry(c *RegistryConfig) error {
	if c == nil {
		return errors.New("nil RegistryConfig")
	}
	if c.Version != supportedVersion {
		return newFieldErr("version", fmt.Sprintf("unsupported version %d, expected %d", c.Version, supportedVersion))
	}
	if err := requireOneOf("default", c.Default, DefaultPolicyDeny); err != nil {
		return err
	}
	if len(c.Servers) == 0 {
		return newFieldErr("servers", "must define at least one server")
	}
	for name, server := range c.Servers {
		if name == "" {
			return newFieldErr("servers", "server key must be non-empty")
		}
		if err := validateServer(name, server); err != nil {
			return err
		}
	}
	return nil
}

// validateServer applies the per-server rules. Split out from
// ValidateRegistry so the loop above stays at one screen of
// logic and each rule can be unit-tested in isolation.
func validateServer(name string, s RegistryServer) error {
	field := func(suffix string) string { return fmt.Sprintf("servers.%s.%s", name, suffix) }

	if err := requireNonEmpty(field("source"), s.Source); err != nil {
		return err
	}
	if err := validateSource(field("source"), s.Source); err != nil {
		return err
	}
	// The master plan requires version OR digest pinning. Source
	// always carries a version (validateSource enforces that),
	// but operators are encouraged to also include a digest for
	// belt-and-suspenders reproducibility. We require digest to
	// either be empty or have the sha256: prefix; we do not
	// require it to be present, because npm package locks already
	// give us a strong version pin.
	if s.Digest != "" {
		if err := validateDigest(field("digest"), s.Digest); err != nil {
			return err
		}
	}
	// schema_hash is filled in by step 2's scan command; it may
	// be empty at registration time. When present it must look
	// like a sha256 to keep the audit log shape stable.
	if s.SchemaHash != "" {
		if err := validateDigest(field("schema_hash"), s.SchemaHash); err != nil {
			return err
		}
	}
	if err := requireOneOf(field("policy"), s.Policy,
		ServerPolicyAllow, ServerPolicyDeny, ServerPolicyWarn); err != nil {
		return err
	}
	for kind, scope := range s.Scope {
		if err := validateScope(field("scope."+kind), kind, scope); err != nil {
			return err
		}
	}
	return nil
}

// validateSource accepts only the source kinds enumerated in the
// SourceKind* constants and requires each kind's pin suffix to be
// present. The pin requirement is what makes deny-by-default
// meaningful: an unpinned source would let an attacker swap
// implementations without changing mcp.yaml.
func validateSource(field, source string) error {
	switch {
	case strings.HasPrefix(source, SourceKindNPM):
		// npm:<pkg>@<version>; the "@" must appear after the
		// "npm:" prefix and the package name must not be empty.
		rest := strings.TrimPrefix(source, SourceKindNPM)
		at := strings.LastIndex(rest, "@")
		if at <= 0 || at == len(rest)-1 {
			return newFieldErr(field, fmt.Sprintf("npm source must be %q, got %q", "npm:<package>@<version>", source))
		}
		return nil
	case strings.HasPrefix(source, SourceKindOCI):
		// oci:<image>:<tag>; the ":<tag>" must appear after the
		// image name. We do not require a digest here because
		// callers may pin via the Digest field separately.
		rest := strings.TrimPrefix(source, SourceKindOCI)
		colon := strings.LastIndex(rest, ":")
		if colon <= 0 || colon == len(rest)-1 {
			return newFieldErr(field, fmt.Sprintf("oci source must be %q, got %q", "oci:<image>:<tag>", source))
		}
		return nil
	default:
		return newFieldErr(field, fmt.Sprintf("source kind not recognized (want %q or %q), got %q",
			SourceKindNPM, SourceKindOCI, source))
	}
}

// validateDigest checks the canonical "sha256:<hex>" shape used
// throughout ai-env (matches the master-plan example). We
// deliberately do not validate the hex length so future digest
// algorithms (sha512) can be plugged in with one constant change.
func validateDigest(field, digest string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(digest, prefix) {
		return newFieldErr(field, fmt.Sprintf("must start with %q, got %q", prefix, digest))
	}
	if len(strings.TrimPrefix(digest, prefix)) == 0 {
		return newFieldErr(field, "hash body must not be empty")
	}
	return nil
}

// validateScope enforces the per-kind scope rules. The kind itself
// must be one of the supported ScopeKind* constants; unknown
// kinds are rejected so a typo in mcp.yaml never silently widens
// the surface. Within a known kind, only the fields meaningful to
// that kind may be set.
func validateScope(field, kind string, s ScopeSection) error {
	switch kind {
	case ScopeKindFilesystem:
		if s.Repos != "" || s.Operations != "" {
			return newFieldErr(field, "filesystem scope must not set github fields (repos/operations)")
		}
		if err := requireOneOf(field+".root", s.Root, FilesystemRootWorkspaceOnly); err != nil {
			return err
		}
		return nil
	case ScopeKindGitHub:
		if s.Root != "" {
			return newFieldErr(field, "github scope must not set filesystem field (root)")
		}
		if err := requireOneOf(field+".repos", s.Repos, GitHubReposCurrentRepoOnly); err != nil {
			return err
		}
		if err := requireOneOf(field+".operations", s.Operations,
			GitHubOperationsReadOnly, GitHubOperationsReadWrite); err != nil {
			return err
		}
		return nil
	default:
		return newFieldErr(field, fmt.Sprintf("unknown scope kind %q (want %q or %q)",
			kind, ScopeKindFilesystem, ScopeKindGitHub))
	}
}

// Registry is the runtime, lookup-friendly view of a validated
// RegistryConfig. The gateway proxy (step 3), the CLI (step 6),
// and the audit writer (step 7) all consume Registry rather than
// RegistryConfig so they never have to re-handle nil maps,
// missing defaults, or unvalidated entries.
//
// Registry methods are safe for concurrent reads (the underlying
// map is never mutated after NewRegistry returns). Callers that
// need to mutate the registry should round-trip through
// RegistryConfig and rebuild via NewRegistry.
type Registry struct {
	defaultPolicy string
	servers       map[string]RegistryServer
}

// NewRegistry builds a Registry from a previously validated
// RegistryConfig. ValidateRegistry must have returned nil for the
// same cfg first; this constructor does not re-validate. The
// constructor copies the servers map so callers cannot mutate
// the Registry through the original RegistryConfig.
func NewRegistry(cfg *RegistryConfig) *Registry {
	servers := make(map[string]RegistryServer, len(cfg.Servers))
	for name, s := range cfg.Servers {
		servers[name] = s
	}
	return &Registry{
		defaultPolicy: cfg.Default,
		servers:       servers,
	}
}

// DefaultPolicy returns the registry-wide default policy. In v0.2
// this is always DefaultPolicyDeny; the accessor exists so
// future code can still ask the registry rather than re-typing
// the constant.
func (r *Registry) DefaultPolicy() string {
	return r.defaultPolicy
}

// Names returns the sorted list of registered server names. The
// CLI's `ai-env mcp list` (step 6) uses this directly; the sort
// makes test assertions deterministic.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.servers))
	for name := range r.servers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Lookup returns the registered server entry for the given name.
// An unknown name returns ErrUnknownServer; the gateway proxy
// (step 3) and CLI translate this into the deny-by-default
// behavior promised by the master plan. The returned
// RegistryServer is a value (not a pointer), so callers cannot
// mutate the registry through it.
func (r *Registry) Lookup(name string) (RegistryServer, error) {
	s, ok := r.servers[name]
	if !ok {
		return RegistryServer{}, fmt.Errorf("%w: %q", ErrUnknownServer, name)
	}
	return s, nil
}

// MatchVersion reports whether the candidate source string
// (e.g. the one the launcher resolved at runtime) matches the
// registered Source for the named server. An unknown server
// returns ErrUnknownServer; a known server with a different
// source returns ErrVersionMismatch wrapped with both sides so
// the audit log can record what was expected vs. what was seen.
//
// Comparison is exact string equality: we want a pinned source
// to fail closed on any drift, including whitespace or case.
func (r *Registry) MatchVersion(name, candidate string) error {
	s, err := r.Lookup(name)
	if err != nil {
		return err
	}
	if s.Source != candidate {
		return fmt.Errorf("%w: server %q expected %q, got %q",
			ErrVersionMismatch, name, s.Source, candidate)
	}
	return nil
}

// MatchDigest reports whether the candidate digest matches the
// registered Digest for the named server. An unknown server
// returns ErrUnknownServer. A server with an empty registered
// digest accepts any candidate (operators who choose not to pin
// a digest are opting into version-only pinning); a server with
// a non-empty digest fails closed on any mismatch.
func (r *Registry) MatchDigest(name, candidate string) error {
	s, err := r.Lookup(name)
	if err != nil {
		return err
	}
	if s.Digest == "" {
		return nil
	}
	if s.Digest != candidate {
		return fmt.Errorf("%w: server %q expected %q, got %q",
			ErrDigestMismatch, name, s.Digest, candidate)
	}
	return nil
}
