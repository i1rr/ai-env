package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rivan1986/ai-env/internal/export"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// PatchOptions captures the parsed flags + positional argument for
// `ai-env patch`. The CLI wiring layer fills this in and passes it to
// RunPatch so the command body has no direct Cobra dependency.
type PatchOptions struct {
	// EnvName is the positional <env-name> argument identifying which
	// workspace to export a patch for. It must match the directory under
	// .ai-env/workspaces/ that was created by `ai-env new`.
	EnvName string

	// OutputPath is the file the unified-diff patch is written to. It is the
	// value of the required --out flag. When empty RunPatch returns an
	// error; the CLI wiring marks --out required so this only triggers if a
	// caller (e.g. a test) bypasses Cobra and forgets to set it.
	OutputPath string

	// RunID, when non-empty, pins the export to a specific historical run
	// for the purposes of the gate's scan / quarantine inputs. Defaults
	// to the env's latest run, mirroring `ai-env scan` and `ai-env
	// report`.
	RunID string

	// Cwd is the working directory the command was invoked from. RunPatch
	// walks upward from Cwd looking for the project's .ai-env/ directory
	// (mirroring `ai-env diff` and `ai-env list`), so users can run
	// `ai-env patch` from any subdirectory of a project. Tests pass a temp
	// dir; the CLI wiring passes os.Getwd().
	Cwd string

	// Stdout is the writer for the per-file summary that follows a successful
	// patch write. Separated from os.Stdout so tests can capture it.
	Stdout io.Writer

	// Stderr is the writer for warnings about protected-path changes. The
	// patch is still written when protected paths are touched; the warning
	// is informational so downstream export gates (which read the same
	// matcher) can require human review.
	Stderr io.Writer
}

// RunPatch is the entry point used by the Cobra wiring for `ai-env patch`.
// It mirrors the structure of RunDiff: locate the project's .ai-env/
// directory, load the protected-path matcher, ask the workspace layer for
// the diff, then write DiffResult.Unified to OutputPath. Per plan 02 step 6
// and plan 06 step 8:
//
//   - The export gate (plan 06) is consulted before the patch file is
//     written: a block verdict refuses the export and prints the
//     blocking reasons to stderr so the operator knows what the gate
//     observed.
//   - The emitted file is a unified-diff patch (DiffResult.Unified is the
//     same text the diff command displays, suitable for `git apply` or
//     `patch -p1`).
//   - Protected path changes are warned about on stderr; the patch is still
//     written so reviewers can see what the agent did before approving.
//   - The copy strategy emits a file-level patch where possible (the
//     workspace diff engine already renders one unified-diff block per
//     changed file for copy-strategy envs).
//
// On success the per-file summary plus a "wrote N bytes to <path>" line are
// printed to stdout so the user has a visible confirmation. An empty diff
// is not an error: an empty patch file is still written (so callers that
// pipe its existence into other tooling continue to work) and the summary
// reports that there were no changes.
func RunPatch(opts PatchOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env patch: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env patch: %w", err)
	}
	if opts.OutputPath == "" {
		return fmt.Errorf("ai-env patch: --out <file> is required")
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env patch: %w", err)
	}

	inputs, err := loadExportInputs(aiEnvDir, opts.EnvName, opts.RunID)
	if err != nil {
		return fmt.Errorf("ai-env patch: %w", err)
	}

	gate := export.NewExportGate(inputs.Policy)
	verdict := gate.Evaluate(export.Input{
		Mode:            export.ModePatch,
		Diff:            inputs.Diff,
		BuiltInResult:   inputs.BuiltInResult,
		ExternalResults: inputs.ExternalResults,
		Policy:          inputs.Policy,
		Record:          inputs.Record,
	})

	if verdict.Blocked() {
		renderGateResult(opts.Stdout, opts.Stderr, "ai-env patch", verdict)
		return fmt.Errorf("ai-env patch: export blocked by %d reason(s); see stderr for details", len(verdict.BlockingReasons()))
	}

	// Resolve --out relative to the original working directory, not to
	// aiEnvDir: users typically expect `ai-env patch foo --out foo.patch`
	// to drop the file in their cwd. We do not auto-create deeply nested
	// parent directories on the assumption that the user can give a real
	// path; if they ask for a missing intermediate directory we return the
	// underlying error so they see the problem.
	outAbs := opts.OutputPath
	if !filepath.IsAbs(outAbs) {
		outAbs = filepath.Join(opts.Cwd, outAbs)
	}

	if err := writePatchFile(outAbs, inputs.Diff.Unified); err != nil {
		return fmt.Errorf("ai-env patch: %w", err)
	}

	renderPatchResult(opts.Stdout, opts.Stderr, inputs.Diff, outAbs)
	renderGateResult(opts.Stdout, opts.Stderr, "ai-env patch", verdict)
	return nil
}

// writePatchFile writes content to path with mode 0644 and O_TRUNC so a
// previous run's output is replaced cleanly. The file is always created
// even when content is empty so callers that test for the patch file's
// existence continue to behave consistently across runs.
func writePatchFile(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write patch %s: %w", path, err)
	}
	return nil
}

// renderPatchResult prints the per-file summary that follows a successful
// patch write plus a final "wrote <path>" line. Protected-path warnings are
// emitted to stderr as a separate block, mirroring RunDiff so scripts that
// pipe stdout into a reviewer still see the summary unaffected.
//
// The output shape mirrors RunDiff's header so tooling that already parses
// `ai-env diff` output can parse this command's summary too without
// special-casing.
func renderPatchResult(stdout, stderr io.Writer, result workspace.DiffResult, outPath string) {
	fmt.Fprintf(stdout, "env:       %s\n", result.Name)
	fmt.Fprintf(stdout, "strategy:  %s\n", result.Strategy)

	if len(result.Files) == 0 {
		fmt.Fprintln(stdout, "files:     (no changes)")
		fmt.Fprintf(stdout, "wrote:     %s (0 bytes)\n", outPath)
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
	fmt.Fprintf(stdout, "wrote:     %s (%d bytes)\n", outPath, len(result.Unified))

	if len(result.ProtectedHits) > 0 {
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "warning: patch touches protected paths; export will require review:")
		for _, p := range result.ProtectedHits {
			fmt.Fprintf(stderr, "  - %s\n", p)
		}
	}
}
