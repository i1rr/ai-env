package cli

// mcp.go implements plan 09 step 6: the operator-facing `ai-env mcp`
// family of subcommands. Each function below is a thin, Cobra-
// independent entry point with the same Options struct + RunXxx
// shape the rest of internal/cli uses (RunNew, RunList, RunPolicyInit,
// etc.) so the Cobra wiring in cmd/ai-env can be a straight pass-
// through.
//
// The commands operate on the project-scoped `.ai-env/mcp.yaml`
// document (the same shape internal/mcp.LoadRegistry consumes).
// v0.2 keeps one mcp.yaml per project: an operator runs
// `ai-env mcp add` to register a server, `ai-env mcp pin` to lock
// the schema hash after the first launch, `ai-env mcp scan` to
// dry-run an AuthorizeLaunch verdict before standing the server up
// for real, `ai-env mcp list` to inspect the registry, and
// `ai-env mcp remove` to deregister a server.
//
// Design rules (mirroring policy.go):
//
//  1. Locate the project's `.ai-env/` directory via findAIEnvDir so the
//     commands work from any subdirectory of the project (matching
//     `ai-env list` / `policy ...`).
//  2. `add` is the only command that creates `mcp.yaml`; the others
//     fail loudly when the file is missing rather than silently using
//     a synthetic empty registry so an operator who deleted the file
//     does not get a confusing "everything is fine" output.
//  3. Mutations (add / pin / remove) round-trip through
//     mcp.ValidateRegistry before writing so a typo in an existing
//     field cannot turn a successful add into an unreadable registry.
//  4. The on-disk YAML is rewritten with yaml.Marshal so the mutation
//     surface is byte-stable: the file is structurally identical to
//     what a hand-written mcp.yaml would look like once normalized
//     (no merge conflicts when the operator commits mcp.yaml to git).
//  5. `scan` does not perform any network I/O: it dry-runs the
//     existing mcp.Gateway against the operator-supplied candidate
//     metadata. This keeps the command safe to run in restrictive
//     sandboxes where the actual MCP server cannot be reached.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"github.com/rivan1986/ai-env/internal/mcp"
)

// mcpFileName is the basename of the project's MCP registry document.
// Pinned here so every entry point in this file agrees on the name
// even if a future refactor moves the constant.
const mcpFileName = "mcp.yaml"

// MCPListOptions captures inputs for `ai-env mcp list`.
type MCPListOptions struct {
	// Cwd is the working directory the command was invoked from. Used
	// to locate the project's .ai-env/ directory.
	Cwd string

	// Stdout is the writer for the human-readable table.
	Stdout io.Writer

	// Stderr is the writer for warnings.
	Stderr io.Writer
}

// RunMCPList prints a deterministic table of every registered MCP
// server in the project's mcp.yaml. The output is column-aligned via
// tabwriter so it stays readable and grep-friendly. Servers are
// listed in sorted order (mcp.Registry.Names already sorts) so the
// table is stable across runs.
//
// Behavior:
//
//   - Missing mcp.yaml: hard error directing the operator to
//     `ai-env mcp add` to register a server.
//   - Malformed mcp.yaml: surface the underlying validation error so
//     the operator sees the exact field that failed.
//   - Valid mcp.yaml with no servers: technically impossible
//     (ValidateRegistry rejects empty Servers), but the table layer
//     still handles len(names)==0 to avoid a panic in a future
//     migration.
func RunMCPList(opts MCPListOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env mcp list: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env mcp list: %w", err)
	}

	registryPath := filepath.Join(aiEnvDir, mcpFileName)
	if _, statErr := os.Stat(registryPath); statErr != nil {
		if os.IsNotExist(statErr) {
			return fmt.Errorf("ai-env mcp list: no %s; run `ai-env mcp add <server>` to register one", registryPath)
		}
		return fmt.Errorf("ai-env mcp list: stat %s: %w", registryPath, statErr)
	}

	reg, err := mcp.LoadRegistry(registryPath)
	if err != nil {
		return fmt.Errorf("ai-env mcp list: %w", err)
	}

	fmt.Fprintf(opts.Stdout, "registry:      %s\n", registryPath)
	fmt.Fprintf(opts.Stdout, "default:       %s\n", reg.DefaultPolicy())
	fmt.Fprintln(opts.Stdout, "")

	names := reg.Names()
	if len(names) == 0 {
		fmt.Fprintln(opts.Stdout, "(no servers registered)")
		return nil
	}

	tw := tabwriter.NewWriter(opts.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSOURCE\tDIGEST\tSCHEMA HASH\tSCOPE\tPOLICY")
	for _, name := range names {
		s, err := reg.Lookup(name)
		if err != nil {
			// Should be unreachable: Names() returned this name from
			// the same map Lookup reads. Surface to stderr instead of
			// crashing so a future regression is visible.
			fmt.Fprintf(opts.Stderr, "warning: lookup %q: %v\n", name, err)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			name,
			s.Source,
			emptyDash(s.Digest),
			emptyDash(s.SchemaHash),
			emptyDash(strings.Join(sortedScopeKindsForList(s.Scope), ",")),
			s.Policy,
		)
	}
	return tw.Flush()
}

// emptyDash returns "-" when v is empty so the table never has blank
// cells (which break operator scan-ability). Used by the list table
// for digest, schema hash, and scope columns.
func emptyDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

// sortedScopeKindsForList returns the keys of the scope map in sorted
// order so the list table's SCOPE column is deterministic. Mirrors
// gateway.sortedScopeKinds but lives here because the CLI file is in
// a different package and the gateway helper is unexported.
func sortedScopeKindsForList(scope map[string]mcp.ScopeSection) []string {
	if len(scope) == 0 {
		return nil
	}
	out := make([]string, 0, len(scope))
	for k := range scope {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MCPAddOptions captures inputs for `ai-env mcp add <server> --source ...`.
type MCPAddOptions struct {
	// Name is the positional <server> argument. Required, must be a
	// non-empty registry-key shaped string.
	Name string

	// Source is the `npm:<pkg>@<version>` or `oci:<image>:<tag>`
	// source string the registry pins. Required.
	Source string

	// Digest is the optional `sha256:<hex>` content digest. Empty
	// means "version-only pinning is OK"; mcp.ValidateRegistry
	// allows that.
	Digest string

	// SchemaHash is the optional `sha256:<hex>` tool-schema hash. If
	// the operator has already computed one via
	// `ai-env mcp scan --record`, they can pass it here so the add
	// and pin happen in one step. Empty means "first launch will
	// record it" per CompareSchemaHash.
	SchemaHash string

	// Policy is the per-server policy token: allow / deny / warn.
	// Defaults to "allow" so a freshly-added server is usable
	// without an extra `policy` mutation.
	Policy string

	// ScopeFilesystemRoot, when non-empty, declares a filesystem
	// scope for the server with the given root token (v0.2 only
	// accepts "workspace_only").
	ScopeFilesystemRoot string

	// ScopeGitHubRepos, when non-empty, declares a github scope
	// repos token (v0.2 only accepts "current_repo_only").
	ScopeGitHubRepos string

	// ScopeGitHubOperations, when non-empty (and a github scope was
	// declared via ScopeGitHubRepos), pins the operations token
	// (read_only or read_write). Defaults to read_only when a
	// github scope is declared without an explicit value.
	ScopeGitHubOperations string

	// Force allows overwriting an existing server entry. Without it
	// the command refuses to clobber so a typo in the subcommand
	// cannot wipe a tuned registration.
	Force bool

	// Cwd is the working directory the command was invoked from.
	Cwd string

	// Stdout is the writer for the human-readable confirmation.
	Stdout io.Writer

	// Stderr is the writer for warnings (file-created notice, etc.).
	Stderr io.Writer
}

// RunMCPAdd registers a new MCP server in the project's mcp.yaml. If
// mcp.yaml does not yet exist it is scaffolded with the default deny
// policy and the new server as its only entry. Existing files are
// loaded, mutated in memory, validated, and rewritten so a partial
// failure cannot leave the registry in a broken state.
//
// Behavior:
//
//   - Missing .ai-env/: hard error directing the operator to run
//     `ai-env new` first.
//   - Missing mcp.yaml: created with version 1, default deny, and the
//     new server. A friendly notice goes to stderr so an operator
//     who expected the file to exist sees the creation.
//   - Existing server with the same name, no --force: refuse so a
//     scripted caller does not silently replace a tuned entry.
//   - Existing server with the same name, --force: replace in place
//     and surface a notice on stderr.
//   - Any other validation failure (bad source kind, bad scope
//     token, bad policy): surface mcp.ValidateRegistry's error so
//     the operator sees the exact field that failed.
func RunMCPAdd(opts MCPAddOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env mcp add: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if strings.TrimSpace(opts.Name) == "" {
		return errors.New("ai-env mcp add: server name must be non-empty")
	}
	if strings.TrimSpace(opts.Source) == "" {
		return errors.New("ai-env mcp add: --source is required (npm:<pkg>@<version> or oci:<image>:<tag>)")
	}

	policy := strings.TrimSpace(opts.Policy)
	if policy == "" {
		policy = mcp.ServerPolicyAllow
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env mcp add: %w", err)
	}
	registryPath := filepath.Join(aiEnvDir, mcpFileName)

	cfg, created, err := loadOrInitRegistryConfig(registryPath)
	if err != nil {
		return fmt.Errorf("ai-env mcp add: %w", err)
	}

	if _, exists := cfg.Servers[opts.Name]; exists && !opts.Force {
		return fmt.Errorf("ai-env mcp add: server %q already registered in %s; rerun with --force to replace", opts.Name, registryPath)
	} else if exists && opts.Force {
		fmt.Fprintf(opts.Stderr, "note: replacing existing registration for %q\n", opts.Name)
	}

	server, err := buildRegistryServer(opts, policy)
	if err != nil {
		return fmt.Errorf("ai-env mcp add: %w", err)
	}
	cfg.Servers[opts.Name] = server

	if err := mcp.ValidateRegistry(cfg); err != nil {
		return fmt.Errorf("ai-env mcp add: post-mutation %s is invalid: %w", mcpFileName, err)
	}
	if err := writeYAMLFile(registryPath, cfg, 0o644); err != nil {
		return fmt.Errorf("ai-env mcp add: %w", err)
	}

	if created {
		fmt.Fprintf(opts.Stderr, "note: created %s with default deny policy\n", registryPath)
	}
	fmt.Fprintf(opts.Stdout, "Registered MCP server %q in %s\n", opts.Name, registryPath)
	return nil
}

// buildRegistryServer assembles a mcp.RegistryServer from the add
// options. Scope sections are added only when the operator passed a
// matching flag so the resulting mcp.yaml does not carry empty stub
// scope blocks (which the validator rejects).
func buildRegistryServer(opts MCPAddOptions, policy string) (mcp.RegistryServer, error) {
	server := mcp.RegistryServer{
		Source:     strings.TrimSpace(opts.Source),
		Digest:     strings.TrimSpace(opts.Digest),
		SchemaHash: strings.TrimSpace(opts.SchemaHash),
		Policy:     policy,
	}

	scope := map[string]mcp.ScopeSection{}
	if strings.TrimSpace(opts.ScopeFilesystemRoot) != "" {
		scope[mcp.ScopeKindFilesystem] = mcp.ScopeSection{
			Root: strings.TrimSpace(opts.ScopeFilesystemRoot),
		}
	}
	if strings.TrimSpace(opts.ScopeGitHubRepos) != "" {
		ops := strings.TrimSpace(opts.ScopeGitHubOperations)
		if ops == "" {
			// Default to read_only so an operator who declares a
			// github scope without picking an operations token gets
			// the conservative choice rather than a validation error.
			ops = mcp.GitHubOperationsReadOnly
		}
		scope[mcp.ScopeKindGitHub] = mcp.ScopeSection{
			Repos:      strings.TrimSpace(opts.ScopeGitHubRepos),
			Operations: ops,
		}
	} else if strings.TrimSpace(opts.ScopeGitHubOperations) != "" {
		return mcp.RegistryServer{}, errors.New("--scope-github-operations requires --scope-github-repos")
	}
	if len(scope) > 0 {
		server.Scope = scope
	}
	return server, nil
}

// loadOrInitRegistryConfig reads the registry from path, or returns a
// fresh empty registry shell when the file does not exist. The
// returned bool is true when the file was synthesized so the caller
// can surface a creation notice.
//
// The synthesized config carries the deny default and an empty
// Servers map; the caller is expected to insert at least one server
// before passing the result back through ValidateRegistry (which
// rejects an empty Servers map).
func loadOrInitRegistryConfig(path string) (*mcp.RegistryConfig, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &mcp.RegistryConfig{
				Version: 1,
				Default: mcp.DefaultPolicyDeny,
				Servers: map[string]mcp.RegistryServer{},
			}, true, nil
		}
		return nil, false, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, false, fmt.Errorf("%s is a directory, expected a file", path)
	}
	cfg, err := readRegistryConfig(path)
	if err != nil {
		return nil, false, err
	}
	if cfg.Servers == nil {
		cfg.Servers = map[string]mcp.RegistryServer{}
	}
	return cfg, false, nil
}

// readRegistryConfig reads path with strict YAML decoding and
// returns the parsed RegistryConfig without running ValidateRegistry.
// Used by the mutation commands which want to load -> mutate ->
// validate -> write rather than load+validate up front (the loaded
// file may already have an invalid state we are about to fix).
func readRegistryConfig(path string) (*mcp.RegistryConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg mcp.RegistryConfig
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}

// MCPPinOptions captures inputs for `ai-env mcp pin <server>`.
type MCPPinOptions struct {
	// Name is the positional <server> argument. Required, must match
	// an existing registry entry.
	Name string

	// SchemaHash is the `sha256:<hex>` tool-schema hash to pin into
	// the server's SchemaHash field. Required.
	SchemaHash string

	// Cwd is the working directory the command was invoked from.
	Cwd string

	// Stdout is the writer for the human-readable confirmation.
	Stdout io.Writer

	// Stderr is the writer for warnings (no-op pin, etc.).
	Stderr io.Writer
}

// RunMCPPin sets (or replaces) the schema_hash field on an existing
// server registration. The hash is validated to match the canonical
// `sha256:<hex>` shape via the same loader path the registry uses
// when reading mcp.yaml.
//
// Behavior:
//
//   - Missing mcp.yaml: hard error pointing at `ai-env mcp add`.
//   - Unknown server: hard error so a typo in the name does not
//     silently create a new entry.
//   - Same hash already pinned: no-op notice on stderr, exits 0 so a
//     scripted caller treats already-pinned as success.
//   - Different hash: replace, write, surface the previous value on
//     stderr so an operator who replaced a pin sees what changed.
func RunMCPPin(opts MCPPinOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env mcp pin: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if strings.TrimSpace(opts.Name) == "" {
		return errors.New("ai-env mcp pin: server name must be non-empty")
	}
	hash := strings.TrimSpace(opts.SchemaHash)
	if hash == "" {
		return errors.New("ai-env mcp pin: --schema-hash is required")
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env mcp pin: %w", err)
	}
	registryPath := filepath.Join(aiEnvDir, mcpFileName)
	if _, statErr := os.Stat(registryPath); statErr != nil {
		if os.IsNotExist(statErr) {
			return fmt.Errorf("ai-env mcp pin: no %s; run `ai-env mcp add <server>` to register one", registryPath)
		}
		return fmt.Errorf("ai-env mcp pin: stat %s: %w", registryPath, statErr)
	}

	cfg, err := readRegistryConfig(registryPath)
	if err != nil {
		return fmt.Errorf("ai-env mcp pin: %w", err)
	}
	server, ok := cfg.Servers[opts.Name]
	if !ok {
		return fmt.Errorf("ai-env mcp pin: server %q not registered in %s", opts.Name, registryPath)
	}

	if server.SchemaHash == hash {
		fmt.Fprintf(opts.Stderr, "note: schema hash for %q already %s; no change\n", opts.Name, hash)
		return nil
	}
	previous := server.SchemaHash
	server.SchemaHash = hash
	cfg.Servers[opts.Name] = server

	if err := mcp.ValidateRegistry(cfg); err != nil {
		return fmt.Errorf("ai-env mcp pin: post-mutation %s is invalid: %w", mcpFileName, err)
	}
	if err := writeYAMLFile(registryPath, cfg, 0o644); err != nil {
		return fmt.Errorf("ai-env mcp pin: %w", err)
	}

	if previous != "" {
		fmt.Fprintf(opts.Stderr, "note: replaced previous schema hash %s\n", previous)
	}
	fmt.Fprintf(opts.Stdout, "Pinned schema hash for %q to %s\n", opts.Name, hash)
	return nil
}

// MCPScanOptions captures inputs for `ai-env mcp scan <server>`.
type MCPScanOptions struct {
	// Name is the positional <server> argument. Required, must match
	// an existing registry entry.
	Name string

	// Source is the runtime-resolved source string the operator
	// would actually launch with (e.g. the npm tarball the launcher
	// resolved). Optional: empty skips the version-pin dimension,
	// which is useful for a "does this registration look sane?"
	// dry-run that has not yet shelled out to npm.
	Source string

	// Digest is the runtime-resolved sha256 digest. Optional, same
	// rules as Source.
	Digest string

	// SchemaHash is the freshly-computed tool-schema hash the
	// operator wants to compare. Optional: empty skips the schema-
	// pin dimension.
	SchemaHash string

	// Cwd is the working directory the command was invoked from.
	Cwd string

	// Stdout is the writer for the human-readable verdict.
	Stdout io.Writer

	// Stderr is the writer for warnings.
	Stderr io.Writer
}

// RunMCPScan dry-runs `mcp.Gateway.AuthorizeLaunch` against the
// operator-supplied candidate metadata and prints the verdict. The
// command does not touch the network or spawn any process: it loads
// the registry, builds a Gateway with a no-op logger, calls
// AuthorizeLaunch, and renders the resulting GatewayDecision plus
// the per-dimension fields the registry already knows about.
//
// A non-Allow verdict produces a non-zero exit so the command is
// usable in CI ("fail the build if mcp scan blocks any server").
// Warn verdicts return nil (exit 0) but surface the warning on
// stderr so an operator sees the soft signal.
//
// Behavior:
//
//   - Missing mcp.yaml: hard error pointing at `ai-env mcp add`.
//   - Unknown server: hard error wrapping mcp.ErrUnknownServer (the
//     gateway's deny-by-default surfaces through the same code
//     path).
//   - Allow: print "OK" plus the registry context.
//   - Warn: print a warning plus the gateway reason; exit 0.
//   - Block: print a failure plus the gateway reason; return a
//     non-nil error so the CLI exits non-zero.
func RunMCPScan(opts MCPScanOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env mcp scan: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if strings.TrimSpace(opts.Name) == "" {
		return errors.New("ai-env mcp scan: server name must be non-empty")
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env mcp scan: %w", err)
	}
	registryPath := filepath.Join(aiEnvDir, mcpFileName)
	if _, statErr := os.Stat(registryPath); statErr != nil {
		if os.IsNotExist(statErr) {
			return fmt.Errorf("ai-env mcp scan: no %s; run `ai-env mcp add <server>` to register one", registryPath)
		}
		return fmt.Errorf("ai-env mcp scan: stat %s: %w", registryPath, statErr)
	}

	reg, err := mcp.LoadRegistry(registryPath)
	if err != nil {
		return fmt.Errorf("ai-env mcp scan: %w", err)
	}

	// Pre-check the lookup so the not-registered case produces a
	// clean operator message rather than the gateway's "unknown
	// server" record. We still let the gateway evaluate (so the
	// schema / digest / version dimensions all surface uniformly)
	// when the name is registered.
	if _, lookupErr := reg.Lookup(opts.Name); lookupErr != nil {
		return fmt.Errorf("ai-env mcp scan: %w", lookupErr)
	}

	gw, err := mcp.NewGateway(reg, nil)
	if err != nil {
		return fmt.Errorf("ai-env mcp scan: %w", err)
	}
	decision, logErr := gw.AuthorizeLaunch(mcp.LaunchRequest{
		Server:         opts.Name,
		Source:         strings.TrimSpace(opts.Source),
		Digest:         strings.TrimSpace(opts.Digest),
		LiveSchemaHash: strings.TrimSpace(opts.SchemaHash),
	})
	if logErr != nil {
		// The noop logger never fails; this branch exists so a
		// future custom logger wired into the CLI surfaces audit-
		// sink errors without losing the decision.
		fmt.Fprintf(opts.Stderr, "warning: %v\n", logErr)
	}

	renderMCPScanResult(opts.Stdout, opts.Stderr, registryPath, opts.Name, decision)

	switch decision.Outcome {
	case mcp.GatewayOutcomeBlock:
		return fmt.Errorf("ai-env mcp scan: %s", decision.Reason)
	default:
		return nil
	}
}

// renderMCPScanResult writes the human-readable verdict to the
// appropriate stream. Allow / Warn go to stdout (with warn also
// echoed to stderr so a piped consumer that filters stderr still
// sees the warning); Block goes to stderr because the caller will
// already see the returned error.
func renderMCPScanResult(stdout, stderr io.Writer, registryPath, name string, dec mcp.GatewayDecision) {
	fmt.Fprintf(stdout, "registry:      %s\n", registryPath)
	fmt.Fprintf(stdout, "server:        %s\n", name)
	fmt.Fprintf(stdout, "decision:      %s\n", dec.Outcome.String())
	fmt.Fprintf(stdout, "reason:        %s\n", dec.Reason)
	if dec.Outcome == mcp.GatewayOutcomeWarn {
		fmt.Fprintf(stderr, "warning: %s\n", dec.Reason)
	}
}

// MCPRemoveOptions captures inputs for `ai-env mcp remove <server>`.
type MCPRemoveOptions struct {
	// Name is the positional <server> argument. Required, must match
	// an existing registry entry.
	Name string

	// Cwd is the working directory the command was invoked from.
	Cwd string

	// Stdout is the writer for the human-readable confirmation.
	Stdout io.Writer

	// Stderr is the writer for warnings.
	Stderr io.Writer
}

// RunMCPRemove deregisters an MCP server. The remove is a pure
// delete on the in-memory map; the result is validated and rewritten
// to disk. Removing the last server leaves mcp.yaml in a state that
// ValidateRegistry rejects (it requires at least one server), so the
// command refuses to remove the last entry and tells the operator to
// delete the file directly instead.
//
// Behavior:
//
//   - Missing mcp.yaml: hard error pointing at `ai-env mcp add`.
//   - Unknown server: hard error so a typo does not silently exit 0.
//   - Last remaining server: refuse with a clear directive; do not
//     leave an invalid registry on disk.
//   - Otherwise: remove, validate, write, surface a confirmation.
func RunMCPRemove(opts MCPRemoveOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env mcp remove: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if strings.TrimSpace(opts.Name) == "" {
		return errors.New("ai-env mcp remove: server name must be non-empty")
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env mcp remove: %w", err)
	}
	registryPath := filepath.Join(aiEnvDir, mcpFileName)
	if _, statErr := os.Stat(registryPath); statErr != nil {
		if os.IsNotExist(statErr) {
			return fmt.Errorf("ai-env mcp remove: no %s; run `ai-env mcp add <server>` to register one", registryPath)
		}
		return fmt.Errorf("ai-env mcp remove: stat %s: %w", registryPath, statErr)
	}

	cfg, err := readRegistryConfig(registryPath)
	if err != nil {
		return fmt.Errorf("ai-env mcp remove: %w", err)
	}
	if _, ok := cfg.Servers[opts.Name]; !ok {
		return fmt.Errorf("ai-env mcp remove: server %q not registered in %s", opts.Name, registryPath)
	}
	if len(cfg.Servers) == 1 {
		return fmt.Errorf("ai-env mcp remove: refusing to remove the last registered server (%q); delete %s directly to disable MCP entirely", opts.Name, registryPath)
	}

	delete(cfg.Servers, opts.Name)

	if err := mcp.ValidateRegistry(cfg); err != nil {
		return fmt.Errorf("ai-env mcp remove: post-mutation %s is invalid: %w", mcpFileName, err)
	}
	if err := writeYAMLFile(registryPath, cfg, 0o644); err != nil {
		return fmt.Errorf("ai-env mcp remove: %w", err)
	}

	fmt.Fprintf(opts.Stdout, "Removed MCP server %q from %s\n", opts.Name, registryPath)
	return nil
}
