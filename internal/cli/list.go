package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/i1rr/ai-env/internal/config"
	"github.com/i1rr/ai-env/internal/run"
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

	// LastRun is the rendered "<state> (<run-id>)" string the table
	// shows for the env's most recent run, or empty when no run.json
	// has been written for this env yet. The table renderer prints "-"
	// for the empty case so the column stays visually anchored.
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

	// Annotate every entry with its latest run state. We do the runs
	// scan once for the whole listing rather than per workspace so an
	// `.ai-env/runs/` tree of N runs is read O(N) total, not O(N*M)
	// where M is the workspace count. latestRunByEnv returns a map keyed
	// by env name; entries missing from the map have no recorded runs
	// (rendered as "-").
	latestRuns, runWarn := latestRunByEnv(aiEnvDir)
	if runWarn != "" {
		warnings = append(warnings, runWarn)
	}
	for i := range entries {
		if run, ok := latestRuns[entries[i].Name]; ok {
			entries[i].LastRun = run
		}
	}

	for _, w := range warnings {
		fmt.Fprintln(opts.Stderr, "warning:", w)
	}

	printEnvTable(opts.Stdout, aiEnvDir, entries)
	return nil
}

// latestRunByEnv returns a map from env name to the rendered "<state>
// (<run-id>)" cell the LAST RUN column shows. The runs/ directory is
// walked once and per-env latest state is selected by taking the first
// matching run from the descending-sorted ListRuns result. Runs whose
// run.json is missing or empty (the post-CreateRunDirectory placeholder
// state) are skipped so a half-written run does not mask an older
// completed one.
//
// Returns a warning string (empty when no warning is produced) so the
// caller can fold it into the rest of the listing warnings without
// re-doing the I/O.
func latestRunByEnv(aiEnvDir string) (map[string]string, string) {
	runs, err := run.ListRuns(aiEnvDir)
	if err != nil {
		// A failure to read the runs directory is non-fatal for the
		// listing: workspaces are still shown without a last-run
		// annotation. Surface the failure as a warning so the operator
		// knows the column is incomplete rather than empty.
		if !errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, fmt.Sprintf("read runs: %v", err)
		}
		return map[string]string{}, ""
	}
	out := make(map[string]string, len(runs))
	for _, r := range runs {
		if r.EnvName == "" {
			continue
		}
		if _, seen := out[r.EnvName]; seen {
			// ListRuns sorts descending so the first hit is the latest.
			continue
		}
		state := "unknown"
		if rec, err := run.ReadRecord(r.Path); err == nil {
			state = string(rec.State)
		}
		out[r.EnvName] = fmt.Sprintf("%s (%s)", state, r.ID)
	}
	return out, ""
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
	// LastRun is intentionally left empty here. RunList annotates each
	// entry from the .ai-env/runs/ tree after scanWorkspaces returns so
	// the workspace scan does not have to know about the run package's
	// on-disk layout. Workspaces with no recorded runs render as "-".
	return entry, ""
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
