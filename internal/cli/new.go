// Package cli implements the Cobra subcommand bodies for the ai-env CLI.
// Subcommand wiring (flag definitions, root attachment) lives in
// cmd/ai-env/main.go; this package contains the actual command logic so it
// can be exercised independently of Cobra wiring.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rivan1986/ai-env/internal/config"
)

// NewOptions captures the parsed flags + positional argument for `ai-env new`.
// The CLI wiring layer fills this in and passes it to RunNew so the command
// body has no direct Cobra dependency.
type NewOptions struct {
	// EnvName is the positional <env-name> argument. It must be a valid
	// short identifier so it can also serve as a directory and Git branch
	// component without quoting.
	EnvName string

	// FromPath, when non-empty, is the source project directory used to
	// detect Git vs non-Git layout and to detect the project stack. When
	// empty the current working directory is used.
	FromPath string

	// Force allows overwriting existing config files in .ai-env/.
	Force bool

	// Cwd is the working directory the command was invoked from. It is
	// the location where .ai-env/ is created when FromPath is empty.
	// Tests pass a temp dir here; the CLI layer passes os.Getwd().
	Cwd string

	// Stdout is the writer used for human-readable command output. It is
	// separated from os.Stdout so tests can capture output.
	Stdout io.Writer
}

// validEnvName matches names that are safe to use as a directory component,
// a Git branch suffix, and a YAML scalar without quoting.
var validEnvName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// gitignoreEntries lists every path pattern the plan requires `.gitignore`
// to cover for an ai-env-managed project. Order is preserved when written.
var gitignoreEntries = []string{
	".ai-env/workspaces/",
	".ai-env/baselines/",
	".ai-env/runs/",
	".ai-env/cache/",
	".ai-env/tmp/",
	".ai-env/secrets.local.yaml",
	".ai-env/*.token",
	".ai-env/*.pem",
}

// gitignoreSectionHeader marks the block of entries appended by `ai-env new`
// so subsequent runs (or humans) can identify it. We do not require this
// header to be present for an entry to be considered "already managed"; the
// per-line check covers both new and pre-existing entries.
const gitignoreSectionHeader = "# ai-env"

// configFileNames lists every config file `ai-env new` writes inside
// .ai-env/. Used both for clobber detection and for the printed summary.
var configFileNames = []string{
	"ai-env.yaml",
	"policy.yaml",
	"agents.yaml",
	"secrets.example.yaml",
	"secrets.local.yaml",
}

// RunNew is the entry point used by the Cobra wiring. It owns the entire
// scaffold flow: validate inputs, detect source layout and stack, create
// .ai-env/, write configs, update .gitignore, and print a summary.
func RunNew(opts NewOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env new: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}

	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env new: %w", err)
	}

	source, err := ResolveSource(opts.Cwd, opts.FromPath)
	if err != nil {
		return fmt.Errorf("ai-env new: %w", err)
	}

	strategy := DetectWorkspaceStrategy(source)
	template := DetectStack(source)

	// .ai-env/ lives inside the *current* working directory, not inside
	// --from. The --from path only influences detection. This matches the
	// plan's note that `ai-env new` creates an environment "for the
	// current directory or --from <path>"; the current dir is the host
	// for the .ai-env/ tree.
	aiEnvDir := filepath.Join(opts.Cwd, ".ai-env")
	if err := ensureDir(aiEnvDir, 0o755); err != nil {
		return fmt.Errorf("ai-env new: %w", err)
	}

	// Refuse to clobber existing config files unless --force.
	if !opts.Force {
		if existing := existingConfigFiles(aiEnvDir); len(existing) > 0 {
			return fmt.Errorf(
				"ai-env new: refusing to overwrite existing config in %s (%s); rerun with --force to replace",
				aiEnvDir, strings.Join(existing, ", "),
			)
		}
	}

	// Build relative path from .ai-env/ to the source project so the
	// generated project.root remains stable when the env tree moves.
	relRoot, err := filepath.Rel(aiEnvDir, source.Path)
	if err != nil || relRoot == "" {
		relRoot = ".."
	}

	aiEnvCfg := defaultAIEnvConfig(opts.EnvName, relRoot, template)
	policyCfg := defaultPolicyConfig()
	agentsCfg := defaultAgentsConfig()
	secretsExampleCfg := defaultSecretsExampleConfig()

	written, err := writeAllConfigs(aiEnvDir, aiEnvCfg, policyCfg, agentsCfg, secretsExampleCfg)
	if err != nil {
		return fmt.Errorf("ai-env new: %w", err)
	}

	// Always (re)write the secrets.local.yaml stub with mode 0600. If it
	// already exists and --force was given, the contents are replaced; if
	// it exists without --force we would have bailed above.
	secretsLocalPath := filepath.Join(aiEnvDir, "secrets.local.yaml")
	if err := writeSecretsLocalStub(secretsLocalPath); err != nil {
		return fmt.Errorf("ai-env new: %w", err)
	}
	written = append(written, secretsLocalPath)

	// .gitignore update is best-effort: if the source dir has one we
	// extend it; if not we print suggested entries.
	giResult := updateGitignore(source.Path)

	printSummary(opts.Stdout, summary{
		envName:        opts.EnvName,
		aiEnvDir:       aiEnvDir,
		sourcePath:     source.Path,
		isGit:          source.IsGit,
		strategy:       strategy,
		template:       template,
		writtenFiles:   written,
		gitignoreState: giResult,
	})

	return nil
}

// ValidateEnvName enforces a conservative grammar so the env name can serve
// as a directory entry, a Git branch component, and a YAML scalar without
// escaping.
func ValidateEnvName(name string) error {
	if name == "" {
		return errors.New("env name must be non-empty")
	}
	if !validEnvName.MatchString(name) {
		return fmt.Errorf(
			"env name %q is invalid; allowed: 1-64 chars, ASCII letters/digits/._-, must start with a letter or digit",
			name,
		)
	}
	return nil
}

// Source describes the resolved project that the env is being created for.
type Source struct {
	// Path is an absolute, cleaned path to the source project root.
	Path string
	// IsGit reports whether Path contains a .git entry (file or dir, to
	// account for worktrees and submodules).
	IsGit bool
}

// ResolveSource picks the source project: --from if given, otherwise cwd.
// The returned path is always absolute.
func ResolveSource(cwd, fromPath string) (Source, error) {
	target := fromPath
	if target == "" {
		target = cwd
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return Source{}, fmt.Errorf("resolve source path %q: %w", target, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Source{}, fmt.Errorf("source path %q: %w", abs, err)
	}
	if !info.IsDir() {
		return Source{}, fmt.Errorf("source path %q is not a directory", abs)
	}
	return Source{
		Path:  abs,
		IsGit: isGitRepo(abs),
	}, nil
}

// isGitRepo reports whether dir has a .git entry. A regular .git file (used
// by worktrees and submodules) also counts.
func isGitRepo(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// DetectWorkspaceStrategy returns the per-plan stub strategy label. The
// actual worktree/copy logic is built in Plan 02; here we only record what
// the strategy *would* be so list and other commands can display it.
func DetectWorkspaceStrategy(s Source) string {
	if s.IsGit {
		return "worktree"
	}
	return "copy"
}

// stackMarker pairs a marker filename with the template name it implies.
// Order matters: earlier entries win when multiple markers are present.
type stackMarker struct {
	file     string
	template string
}

// stackMarkers is the lookup table the plan specifies for stack detection.
var stackMarkers = []stackMarker{
	{"go.mod", "go"},
	{"Cargo.toml", "rust"},
	{"package.json", "node"},
	{"pyproject.toml", "python"},
	{"requirements.txt", "python"},
}

// DetectStack inspects marker files at the source root and returns the
// matching built-in template name. When nothing matches, "default" is
// returned. The first marker in stackMarkers that exists wins.
func DetectStack(s Source) string {
	for _, m := range stackMarkers {
		if _, err := os.Stat(filepath.Join(s.Path, m.file)); err == nil {
			return m.template
		}
	}
	return "default"
}

// ensureDir creates dir (and parents) if it does not exist, applying mode
// only when the directory is newly created.
func ensureDir(dir string, mode os.FileMode) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("path %s exists and is not a directory", dir)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return nil
}

// existingConfigFiles returns the subset of configFileNames that already
// exist inside dir. Used by the no-clobber guard.
func existingConfigFiles(dir string) []string {
	var found []string
	for _, name := range configFileNames {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			found = append(found, name)
		}
	}
	return found
}

// defaultAIEnvConfig returns the canonical ai-env.yaml content described in
// the plan, parameterized by env name, project root, and detected template.
func defaultAIEnvConfig(envName, root, template string) *config.AIEnvConfig {
	return &config.AIEnvConfig{
		Version: 1,
		Project: config.ProjectSection{
			Name:         envName,
			Root:         root,
			DefaultAgent: "claude",
			DefaultMode:  "autonomous",
		},
		Workspace: config.WorkspaceSection{
			Strategy:      "auto",
			GitDefault:    "worktree",
			NonGitDefault: "copy",
			BranchPrefix:  "ai-env/",
			DirectWrite:   false,
			Export:        "patch",
		},
		Sandbox: config.SandboxSection{
			Backend:                "docker-sbx",
			FallbackBackend:        "none",
			Template:               template,
			DestroyOnExit:          false,
			PrivateDockerDaemon:    true,
			HostDockerSocket:       false,
			MountHome:              false,
			AcceptReducedIsolation: false,
		},
		Supervision: config.SupervisionSection{
			MaxRuntimeMinutes:    120,
			IdleTimeoutMinutes:   20,
			ShutdownGraceSeconds: 15,
			KillGraceSeconds:     5,
			MaxStdoutBytes:       50_000_000,
			MaxStderrBytes:       50_000_000,
			StreamOutputToDisk:   true,
			MaxProcesses:         1024,
		},
		Logging: config.LoggingSection{
			Level:         "info",
			RetainRuns:    50,
			RedactSecrets: true,
			RunIDFormat:   "timestamp_random_suffix",
		},
	}
}

// defaultPolicyConfig returns a conservative starter policy.yaml. Values are
// chosen so a freshly scaffolded env defaults to the safest options the
// validator accepts; humans can loosen them as needed.
func defaultPolicyConfig() *config.PolicyConfig {
	return &config.PolicyConfig{
		Version: 1,
		Mode:    "interactive",
		Network: config.NetworkPolicy{
			Default:                 "deny",
			Enforcement:             "backend",
			TLSMITM:                 false,
			AllowDomains:            []string{},
			BlockPrivateRanges:      true,
			BlockMetadataServices:   true,
			BlockLocalhost:          true,
			BlockHostDockerInternal: true,
		},
		Filesystem: config.FilesystemPolicy{
			WorkspaceWrite: true,
			HostHomeRead:   false,
			HostHomeWrite:  false,
			ProtectedPaths: []string{".git", ".ai-env"},
		},
		Commands: config.CommandsPolicy{
			Default:      "allow_in_sandbox",
			DenyPatterns: []string{},
		},
		Dependencies: config.DependenciesPolicy{
			InstallScriptsDefault:          "deny",
			AllowInstallScriptsOnlyInSetup: true,
			NoSecretsDuringSetup:           true,
		},
		Secrets: config.SecretsPolicy{
			RawEnvInjection:   false,
			BrokeredOnly:      true,
			DefaultTTLSeconds: 3600,
			MaxTTLSeconds:     14400,
			RotatePerAction:   false,
			RevokeOnDestroy:   true,
		},
		Scanners: config.ScannersPolicy{
			BuiltInSecretScanner: "pattern_and_entropy",
			EntropyFindings:      "warn_only",
			CustomPatterns:       []string{},
		},
		Review: config.ReviewPolicy{
			RequireDiffReview:            true,
			RequireScanBeforeExport:      true,
			FailOnSecretLeak:             true,
			FailOnHighVulnerability:      true,
			ScanPRTitleBodyAndCommits:    true,
			BlockAutoPRonWorkflowChanges: true,
		},
	}
}

// defaultAgentsConfig returns a minimal agents.yaml that satisfies the
// validator: one registered agent (claude) with a probe and an autonomous
// mode entry. Future templates may extend this set.
func defaultAgentsConfig() *config.AgentsConfig {
	return &config.AgentsConfig{
		Version: 1,
		Agents: map[string]config.AgentEntry{
			"claude": {
				Command:           "claude",
				VersionConstraint: ">=0.0.0",
				Probe: config.AgentProbe{
					Args:  []string{"--version"},
					Parse: "semver",
				},
				Modes: map[string]config.AgentMode{
					"autonomous": {
						ArgsCandidates: [][]string{{"--print"}},
					},
					"interactive": {
						ArgsCandidates: [][]string{{}},
					},
				},
				CredentialMode: config.AgentCredentialMode{
					Default:       "brokered",
					FallbackOrder: []string{"raw_env_explicit"},
				},
				Requires: []string{},
			},
		},
	}
}

// defaultSecretsExampleConfig returns a starter secrets.example.yaml with no
// real credentials, only provider stubs and a deny list.
func defaultSecretsExampleConfig() *config.SecretsExampleConfig {
	return &config.SecretsExampleConfig{
		Version: 1,
		Secrets: config.SecretsSection{
			Providers: map[string]config.SecretsProvider{
				"anthropic": {
					Mode:       "brokered",
					TokenType:  "api_key",
					TTLSeconds: 3600,
				},
			},
			Deny: []string{
				"aws_root_credentials",
				"production_database_passwords",
			},
		},
	}
}

// writeAllConfigs serializes every config to its target file inside dir.
// It first validates each config so we never write a file that the loader
// would reject. Returns the list of absolute paths written.
func writeAllConfigs(
	dir string,
	aiEnv *config.AIEnvConfig,
	policy *config.PolicyConfig,
	agents *config.AgentsConfig,
	secretsEx *config.SecretsExampleConfig,
) ([]string, error) {
	if err := config.ValidateAIEnv(aiEnv); err != nil {
		return nil, fmt.Errorf("generated ai-env.yaml is invalid: %w", err)
	}
	if err := config.ValidatePolicy(policy); err != nil {
		return nil, fmt.Errorf("generated policy.yaml is invalid: %w", err)
	}
	if err := config.ValidateAgents(agents); err != nil {
		return nil, fmt.Errorf("generated agents.yaml is invalid: %w", err)
	}
	if err := config.ValidateSecretsExample(secretsEx); err != nil {
		return nil, fmt.Errorf("generated secrets.example.yaml is invalid: %w", err)
	}

	files := []struct {
		name string
		obj  interface{}
	}{
		{"ai-env.yaml", aiEnv},
		{"policy.yaml", policy},
		{"agents.yaml", agents},
		{"secrets.example.yaml", secretsEx},
	}
	written := make([]string, 0, len(files))
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		if err := writeYAMLFile(path, f.obj, 0o644); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// writeYAMLFile marshals obj as YAML and writes it to path with the given
// mode. The file is created with O_TRUNC so --force overwrites cleanly.
func writeYAMLFile(path string, obj interface{}, mode os.FileMode) error {
	data, err := yaml.Marshal(obj)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile honours mode only on creation; chmod ensures the mode
	// applies even when an existing file is overwritten via --force.
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// secretsLocalStubBody is the documented placeholder written to
// secrets.local.yaml. It must contain no real credentials.
const secretsLocalStubBody = `# .ai-env/secrets.local.yaml
#
# This file is gitignored. It holds machine-local secret values that the
# secret broker may read. Never check this file into version control.
#
# Format (example, commented out):
#
# version: 1
# secrets:
#   anthropic:
#     api_key: "REPLACE_ME"
#
# The 'ai-env new' command writes this stub with mode 0600.
`

// writeSecretsLocalStub writes the gitignored secrets stub with mode 0600.
// We use an explicit Create+Chmod path so the file ends up at 0600 even on
// platforms where WriteFile's umask would loosen it.
func writeSecretsLocalStub(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.WriteString(secretsLocalStubBody); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// gitignoreResult records what updateGitignore did, for the printed summary.
type gitignoreResult struct {
	// Path is the absolute path the result describes.
	Path string
	// Existed reports whether a .gitignore was present before this call.
	Existed bool
	// Added lists entries appended in this call (empty when everything was
	// already covered).
	Added []string
	// Suggested lists entries the caller should add manually because no
	// .gitignore exists at Path.
	Suggested []string
}

// updateGitignore appends any missing required entries to <source>/.gitignore
// when the file already exists. When no .gitignore exists, it returns the
// entries as suggestions instead of creating the file (per plan: "list in
// terminal if no .gitignore exists").
func updateGitignore(sourceDir string) gitignoreResult {
	path := filepath.Join(sourceDir, ".gitignore")
	res := gitignoreResult{Path: path}

	existing, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			res.Suggested = append(res.Suggested, gitignoreEntries...)
			return res
		}
		// On any other read error, fall back to suggestion mode so we
		// never lose the user's file.
		res.Suggested = append(res.Suggested, gitignoreEntries...)
		return res
	}
	res.Existed = true

	have := make(map[string]struct{})
	for _, line := range strings.Split(string(existing), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		have[trimmed] = struct{}{}
	}

	var missing []string
	for _, entry := range gitignoreEntries {
		if _, ok := have[entry]; !ok {
			missing = append(missing, entry)
		}
	}
	if len(missing) == 0 {
		return res
	}

	var b strings.Builder
	b.Write(existing)
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(gitignoreSectionHeader)
	b.WriteString("\n")
	for _, entry := range missing {
		b.WriteString(entry)
		b.WriteString("\n")
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		// On write failure, surface as suggestion so the human still gets
		// the entries.
		res.Suggested = append(res.Suggested, missing...)
		return res
	}
	res.Added = missing
	return res
}

// summary is the bundle of facts the user sees printed after a successful
// `ai-env new` run.
type summary struct {
	envName        string
	aiEnvDir       string
	sourcePath     string
	isGit          bool
	strategy       string
	template       string
	writtenFiles   []string
	gitignoreState gitignoreResult
}

// printSummary writes a deterministic, human-readable summary to w. Output
// is stable enough that future tests can match key lines.
func printSummary(w io.Writer, s summary) {
	fmt.Fprintf(w, "Created ai-env environment %q\n", s.envName)
	fmt.Fprintf(w, "  source:         %s (git=%t)\n", s.sourcePath, s.isGit)
	fmt.Fprintf(w, "  strategy:       %s\n", s.strategy)
	fmt.Fprintf(w, "  template:       %s\n", s.template)
	fmt.Fprintf(w, "  config dir:     %s\n", s.aiEnvDir)

	if len(s.writtenFiles) > 0 {
		names := make([]string, len(s.writtenFiles))
		copy(names, s.writtenFiles)
		sort.Strings(names)
		fmt.Fprintln(w, "  files written:")
		for _, name := range names {
			fmt.Fprintf(w, "    - %s\n", name)
		}
	}

	switch {
	case len(s.gitignoreState.Added) > 0:
		fmt.Fprintf(w, "  .gitignore:     appended %d entr%s to %s\n",
			len(s.gitignoreState.Added),
			pluralY(len(s.gitignoreState.Added)),
			s.gitignoreState.Path)
	case s.gitignoreState.Existed:
		fmt.Fprintf(w, "  .gitignore:     already covers required entries (%s)\n",
			s.gitignoreState.Path)
	case len(s.gitignoreState.Suggested) > 0:
		fmt.Fprintf(w, "  .gitignore:     no file at %s; add these entries manually:\n",
			s.gitignoreState.Path)
		for _, entry := range s.gitignoreState.Suggested {
			fmt.Fprintf(w, "      %s\n", entry)
		}
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Next: review .ai-env/ai-env.yaml and .ai-env/policy.yaml, then run `ai-env list`.")
}

// pluralY returns "y" for 1, "ies" otherwise, used by printSummary.
func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
