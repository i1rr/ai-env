package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/i1rr/ai-env/internal/workspace"
)

// DestroyOptions captures the parsed flags + positional argument for
// `ai-env destroy`. The CLI wiring layer fills this in and passes it to
// RunDestroy so the command body has no direct Cobra dependency.
type DestroyOptions struct {
	// EnvName is the positional <env-name> argument identifying which
	// env to reclaim. Validated through the same ValidateEnvName helper
	// `ai-env new` uses so an operator who passes a bogus name sees the
	// same error message they would have seen at creation time.
	EnvName string

	// Cwd is the working directory the command was invoked from. RunDestroy
	// walks upward from Cwd looking for the project's .ai-env/ directory
	// (mirroring `ai-env list` / `ai-env diff`), so users can run
	// `ai-env destroy` from any subdirectory of a project. Tests pass a
	// temp dir; the CLI wiring passes os.Getwd().
	Cwd string

	// Stdout is the writer for the human-readable summary. Separated
	// from os.Stdout so tests can capture it.
	Stdout io.Writer

	// Stderr is the writer for the "already absent" notice on the
	// idempotent re-run path. Separated from os.Stderr so tests can
	// capture it without losing the exit-code-zero distinction.
	Stderr io.Writer
}

// RunDestroy is the entry point used by the Cobra wiring. It locates the
// project's .ai-env/ directory, asks the workspace layer to reclaim the
// env's on-disk resources, and prints a one-line summary.
//
// Idempotency: running `ai-env destroy <env>` twice in a row exits 0
// both times. The first run removes the workspace, baseline, and (for
// worktree-strategy envs) the ai-env/<env> branch from the source repo;
// the second run sees ErrEnvNotFound from the workspace layer and
// reports "already absent" on stderr without failing. This matches the
// "no-op when nothing is left to do" contract documented on the plan's
// destroy bullet (master plan section 32, MVP demonstration bullet 36).
func RunDestroy(opts DestroyOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env destroy: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env destroy: %w", err)
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env destroy: %w", err)
	}

	res, err := workspace.Destroy(aiEnvDir, opts.EnvName)
	if err != nil {
		if errors.Is(err, workspace.ErrEnvNotFound) {
			// Idempotent: the env is already gone. Print a notice on
			// stderr (so scripts that key on stdout do not see noise)
			// and exit 0. We still print the workspace path so an
			// operator can confirm we looked in the right place.
			fmt.Fprintf(opts.Stderr, "ai-env destroy: env %q already absent (no resources to remove at %s)\n",
				opts.EnvName, res.WorkspacePath)
			return nil
		}
		return fmt.Errorf("ai-env destroy: %w", err)
	}

	printDestroySummary(opts.Stdout, res)
	return nil
}

// printDestroySummary writes a deterministic, human-readable summary of
// what Destroy reclaimed. The format is stable so the acceptance test
// (and an operator's eye) can rely on the field labels remaining the
// same across releases.
func printDestroySummary(w io.Writer, res workspace.DestroyResult) {
	fmt.Fprintf(w, "Destroyed env %q\n", res.Name)
	if res.Strategy != "" {
		fmt.Fprintf(w, "  strategy:  %s\n", res.Strategy)
	}
	if res.RemovedWorkspace {
		fmt.Fprintf(w, "  workspace: removed %s\n", res.WorkspacePath)
	} else {
		fmt.Fprintf(w, "  workspace: not present at %s\n", res.WorkspacePath)
	}
	if res.RemovedBaseline {
		fmt.Fprintf(w, "  baseline:  removed %s\n", res.BaselinePath)
	}
	if res.RemovedBranch {
		fmt.Fprintf(w, "  branch:    deleted %s\n", res.Branch)
	}
}
