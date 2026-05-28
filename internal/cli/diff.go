package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rivan1986/ai-env/internal/config"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// DiffOptions captures the parsed flags + positional argument for
// `ai-env diff`. The CLI wiring layer fills this in and passes it to
// RunDiff so the command body has no direct Cobra dependency.
type DiffOptions struct {
	// EnvName is the positional <env-name> argument identifying which
	// workspace to diff. It must match the directory under
	// .ai-env/workspaces/ that was created by `ai-env new`.
	EnvName string

	// Cwd is the working directory the command was invoked from. RunDiff
	// walks upward from Cwd looking for the project's .ai-env/ directory
	// (mirroring `ai-env list`), so users can run `ai-env diff` from any
	// subdirectory of a project. Tests pass a temp dir; the CLI wiring
	// passes os.Getwd().
	Cwd string

	// NameOnly suppresses the unified-diff body and renders only the
	// per-file summary table. Useful when scripting against the output
	// (e.g. piping into a reviewer) and when the diff body is too large
	// to be helpful in the terminal.
	NameOnly bool

	// Stdout is the writer for the diff output. Separated from os.Stdout so
	// tests can capture it.
	Stdout io.Writer

	// Stderr is the writer for warnings about protected-path changes and
	// other non-fatal notices. Warnings never abort the diff.
	Stderr io.Writer
}

// RunDiff is the entry point used by the Cobra wiring. It locates the
// project's .ai-env/ directory, loads the policy's protected-path patterns,
// asks the workspace layer for the diff, and prints both the per-file
// summary and (unless --name-only is set) the full unified diff. Protected
// path changes are highlighted in both the summary and a final warning
// block on stderr.
//
// Per plan 02 step 5: the worktree strategy emits a git diff between the
// env branch and base; the copy strategy emits a file-level diff against
// the read-only baseline; protected hits are highlighted in output.
func RunDiff(opts DiffOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env diff: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env diff: %w", err)
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env diff: %w", err)
	}

	matcher, mErr := loadProtectedMatcher(aiEnvDir)
	if mErr != nil {
		// A bad policy.yaml should not silently disable protected-path
		// highlighting; surface the parse error to the user instead of
		// pretending nothing was configured.
		return fmt.Errorf("ai-env diff: %w", mErr)
	}

	result, err := workspace.Diff(aiEnvDir, opts.EnvName, matcher)
	if err != nil {
		return fmt.Errorf("ai-env diff: %w", err)
	}

	renderDiffResult(opts.Stdout, opts.Stderr, result, opts.NameOnly)
	return nil
}

// loadProtectedMatcher reads policy.yaml from aiEnvDir and builds a
// ProtectedMatcher from its filesystem.protected_paths field. When the
// policy file is missing we fall back to DefaultProtectedPaths so the
// baseline categories stay protected; missing policy is treated as
// "user has not customized" rather than "user opted out".
//
// When the policy file is present but unreadable or malformed we return
// the error so the user sees the same diagnostic they would get from
// `ai-env new` or any other command that reads policy.yaml.
func loadProtectedMatcher(aiEnvDir string) (*workspace.ProtectedMatcher, error) {
	policyPath := filepath.Join(aiEnvDir, "policy.yaml")
	if _, err := os.Stat(policyPath); err != nil {
		if os.IsNotExist(err) {
			return workspace.NewProtectedMatcher(nil)
		}
		return nil, fmt.Errorf("stat policy %s: %w", policyPath, err)
	}
	policy, err := config.LoadPolicy(policyPath)
	if err != nil {
		return nil, err
	}
	return workspace.NewProtectedMatcher(policy.Filesystem.ProtectedPaths)
}

// renderDiffResult writes the human-readable rendering of result to stdout
// and protected-path warnings to stderr. The output has two stable
// sections so tests and scripts can match on them:
//
//   1. A header that names the env, its strategy, and the per-file summary
//      (one line per changed file, with a "[protected]" suffix on hits).
//   2. The unified-diff body (suppressed when nameOnly is true). If the
//      diff is empty, we print a single line saying so instead of an empty
//      body, so the user can tell "no changes" from "command failed".
//
// Protected hits are also re-emitted on stderr as a single warning block.
// Keeping warnings on stderr means scripts that pipe stdout (e.g. into
// `patch -p1`) still see the diff body unaffected.
func renderDiffResult(stdout, stderr io.Writer, result workspace.DiffResult, nameOnly bool) {
	fmt.Fprintf(stdout, "env:       %s\n", result.Name)
	fmt.Fprintf(stdout, "strategy:  %s\n", result.Strategy)

	if len(result.Files) == 0 {
		fmt.Fprintln(stdout, "files:     (no changes)")
		return
	}

	fmt.Fprintf(stdout, "files:     %d changed\n", len(result.Files))
	for _, f := range result.Files {
		marker := ""
		if f.Protected {
			marker = "  [protected]"
		}
		fmt.Fprintf(stdout, "  %s  %s%s\n", changeKindGlyph(f.Change), f.Path, marker)
	}

	if !nameOnly && result.Unified != "" {
		fmt.Fprintln(stdout)
		fmt.Fprint(stdout, result.Unified)
		// Ensure a trailing newline so the next line of terminal output
		// does not run into the last diff line.
		if len(result.Unified) > 0 && result.Unified[len(result.Unified)-1] != '\n' {
			fmt.Fprintln(stdout)
		}
	}

	if len(result.ProtectedHits) > 0 {
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "warning: protected paths changed; export will require review:")
		for _, p := range result.ProtectedHits {
			fmt.Fprintf(stderr, "  - %s\n", p)
		}
	}
}

// changeKindGlyph returns a single-character marker for a ChangeKind so the
// per-file summary lines up cleanly. The glyphs mirror what git uses in
// porcelain output to keep the rendering familiar:
//
//   A = added, M = modified, D = deleted, ? = unknown (defensive fallback)
func changeKindGlyph(k workspace.ChangeKind) string {
	switch k {
	case workspace.ChangeAdded:
		return "A"
	case workspace.ChangeModified:
		return "M"
	case workspace.ChangeDeleted:
		return "D"
	default:
		return "?"
	}
}
