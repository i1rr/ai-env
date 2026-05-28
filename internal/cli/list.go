package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/rivan1986/ai-env/internal/config"
)

// ListOptions captures inputs for `ai-env list`. The list command takes no
// flags or positional arguments in plan 01; the struct exists so future
// flags (e.g. --json) can slot in without changing the Cobra wiring.
type ListOptions struct {
	// Cwd is the working directory the command was invoked from. The list
	// command walks upward from Cwd looking for the project's .ai-env/
	// directory so users can run `ai-env list` from any subdirectory of a
	// project. Tests pass a temp dir; the CLI wiring passes os.Getwd().
	Cwd string

	// Stdout is the writer for the human-readable table.
	Stdout io.Writer

	// Stderr is the writer for warnings about malformed workspace entries.
	// Warnings never abort the listing; they accompany it.
	Stderr io.Writer
}

// envEntry is one row in the listing output. Fields are populated on a
// best-effort basis; "unknown" appears when a workspace metadata stub omits
// a value or is unreadable.
type envEntry struct {
	// Name is the environment name. It comes from ai-env.yaml's
	// project.name field when readable; otherwise the workspace directory
	// name is used as a fallback.
	Name string

	// Strategy is the workspace strategy recorded in the workspace's
	// ai-env.yaml (workspace.strategy). "unknown" when unreadable.
	Strategy string

	// Template is the sandbox template recorded in the workspace's
	// ai-env.yaml (sandbox.template). "unknown" when unreadable.
	Template string

	// LastRun is a free-form description of the last recorded run state
	// (e.g. a timestamp or status). Empty string when no run metadata
	// exists on disk; printed as "-" by the table renderer.
	LastRun string

	// Dir is the absolute path to the workspace directory, for diagnostic
	// output only.
	Dir string
}

// RunList is the entry point used by the Cobra wiring. It locates the
// project's .ai-env/ directory, enumerates workspaces under
// .ai-env/workspaces/, reads each workspace's metadata stub, and prints a
// summary table. It never starts a backend process (per plan).
func RunList(opts ListOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env list: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env list: %w", err)
	}

	workspacesDir := filepath.Join(aiEnvDir, "workspaces")
	entries, warnings := scanWorkspaces(workspacesDir)

	for _, w := range warnings {
		fmt.Fprintln(opts.Stderr, "warning:", w)
	}

	printEnvTable(opts.Stdout, aiEnvDir, entries)
	return nil
}

// findAIEnvDir walks upward from start looking for an `.ai-env` directory
// that contains an ai-env.yaml. We require the config file to disambiguate a
// real ai-env project root from any unrelated `.ai-env` directory that might
// shadow it in a parent. Returns an absolute path to .ai-env/ on success.
func findAIEnvDir(start string) (string, error) {
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", start, err)
	}
	dir := abs
	for {
		candidate := filepath.Join(dir, ".ai-env")
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			if _, err := os.Stat(filepath.Join(candidate, "ai-env.yaml")); err == nil {
				return candidate, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no .ai-env/ai-env.yaml found in %s or any parent directory", abs)
		}
		dir = parent
	}
}

// scanWorkspaces enumerates subdirectories of workspacesDir and turns each
// into an envEntry. Returns entries sorted by name plus a list of
// human-readable warnings for malformed workspaces (the listing still
// includes those workspaces with placeholder fields, so users can see them).
func scanWorkspaces(workspacesDir string) ([]envEntry, []string) {
	var entries []envEntry
	var warnings []string

	dirEntries, err := os.ReadDir(workspacesDir)
	if err != nil {
		if os.IsNotExist(err) {
			// No workspaces dir yet (e.g. fresh `ai-env new` before any
			// workspace was materialized). Empty listing is a normal,
			// non-error state per plan acceptance criteria.
			return entries, warnings
		}
		warnings = append(warnings, fmt.Sprintf("read %s: %v", workspacesDir, err))
		return entries, warnings
	}

	for _, de := range dirEntries {
		if !de.IsDir() {
			continue
		}
		// Skip hidden directories (e.g. .DS_Store dirs, accidental dot
		// entries). Real workspaces are named after the env, which our
		// validator forbids starting with a dot.
		if strings.HasPrefix(de.Name(), ".") {
			continue
		}
		dir := filepath.Join(workspacesDir, de.Name())
		entry, warn := readWorkspaceEntry(dir)
		if warn != "" {
			warnings = append(warnings, warn)
		}
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	return entries, warnings
}

// readWorkspaceEntry derives an envEntry from a single workspace directory.
// Metadata is read on a best-effort basis: if ai-env.yaml is missing or
// malformed the entry still appears in the listing with "unknown" fields and
// a warning is returned alongside it. The directory name is always used as
// a fallback for the env name so the user never sees a blank row.
func readWorkspaceEntry(dir string) (envEntry, string) {
	entry := envEntry{
		Name:     filepath.Base(dir),
		Strategy: "unknown",
		Template: "unknown",
		Dir:      dir,
	}

	cfgPath := filepath.Join(dir, "ai-env.yaml")
	if _, err := os.Stat(cfgPath); err != nil {
		// No metadata stub: the workspace exists on disk but has not yet
		// been initialized with an ai-env.yaml. Surface it as a warning so
		// the user knows this row is incomplete, but still list the dir.
		if os.IsNotExist(err) {
			return entry, fmt.Sprintf("workspace %s has no ai-env.yaml; showing directory name only", dir)
		}
		return entry, fmt.Sprintf("workspace %s: stat ai-env.yaml: %v", dir, err)
	}

	cfg, err := config.LoadAIEnv(cfgPath)
	if err != nil {
		return entry, fmt.Sprintf("workspace %s: %v", dir, err)
	}
	if cfg.Project.Name != "" {
		entry.Name = cfg.Project.Name
	}
	if cfg.Workspace.Strategy != "" {
		entry.Strategy = cfg.Workspace.Strategy
	}
	if cfg.Sandbox.Template != "" {
		entry.Template = cfg.Sandbox.Template
	}
	entry.LastRun = readLastRunState(dir)
	return entry, ""
}

// readLastRunState looks for a last-run marker inside the workspace. Plan 01
// does not yet specify the exact format the supervisor will write, so we
// look for a small set of common stub locations and return their contents
// trimmed. An empty string means "no run recorded yet" and is rendered as
// "-" in the table.
//
// Candidate files, in order:
//   - last_run.txt at the workspace root
//   - runs/last_run.txt under the workspace
func readLastRunState(workspaceDir string) string {
	candidates := []string{
		filepath.Join(workspaceDir, "last_run.txt"),
		filepath.Join(workspaceDir, "runs", "last_run.txt"),
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// Use the first non-empty line so multi-line files (e.g. a status
		// followed by details) collapse cleanly into the table cell.
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

// printEnvTable writes a deterministic, column-aligned table of envs to w.
// When there are no envs, a friendly message is printed and the function
// returns without writing a header row. The output is intentionally simple
// (tab-aligned columns) so it is greppable and stable for future tests.
func printEnvTable(w io.Writer, aiEnvDir string, entries []envEntry) {
	if len(entries) == 0 {
		fmt.Fprintf(w, "No environments found under %s/workspaces/.\n", aiEnvDir)
		fmt.Fprintln(w, "Create one with `ai-env new <env-name>`.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTRATEGY\tTEMPLATE\tLAST RUN")
	for _, e := range entries {
		lastRun := e.LastRun
		if lastRun == "" {
			lastRun = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Name, e.Strategy, e.Template, lastRun)
	}
	_ = tw.Flush()
}
