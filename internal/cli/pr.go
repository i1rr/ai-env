package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/rivan1986/ai-env/internal/export"
)

// PROptions captures the parsed flags + positional argument for
// `ai-env pr`. The CLI wiring layer fills this in and passes it to
// RunPR so the command body has no direct Cobra dependency.
//
// Plan 06 step 8 wires the export gate into this command as a stub:
// the gate is evaluated under ModePR (so workflow changes and other
// PR-only hard blockers fire), but the actual brokered PR push is
// deferred to Plan 07. Until that lands, an allowed export prints a
// "would push" preview so an operator can confirm the gate verdict
// without the network round-trip.
type PROptions struct {
	// EnvName is the positional <env-name> argument identifying which
	// workspace to ship a PR for. It must match the directory under
	// .ai-env/workspaces/ that was created by `ai-env new`.
	EnvName string

	// RunID, when non-empty, pins the export to a specific historical
	// run for the purposes of the gate's scan / quarantine inputs.
	// Defaults to the env's latest run.
	RunID string

	// Cwd is the working directory the command was invoked from. Used
	// to locate the project's .ai-env/ directory.
	Cwd string

	Stdout io.Writer
	Stderr io.Writer
}

// RunPR is the entry point used by the Cobra wiring for `ai-env pr`.
// Plan 06 step 8 specifies that the export gate is consulted under
// ModePR; the actual brokered PR push is wired in Plan 07.
//
// Behavior:
//
//   - Block verdict: print the blocking reasons to stderr and return
//     a non-zero error so the caller / CI script sees the failure.
//   - Allow verdict: print the per-file summary, any gate warnings,
//     and a "PR push not yet implemented (plan 07)" notice so the
//     operator knows the gate said yes but no network call was made.
//
// The function keeps the same shape as RunPatch so the two commands
// share the gate plumbing verbatim; only the Mode differs.
func RunPR(opts PROptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env pr: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env pr: %w", err)
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env pr: %w", err)
	}

	inputs, err := loadExportInputs(aiEnvDir, opts.EnvName, opts.RunID)
	if err != nil {
		return fmt.Errorf("ai-env pr: %w", err)
	}

	gate := export.NewExportGate(inputs.Policy)
	verdict := gate.Evaluate(export.Input{
		Mode:            export.ModePR,
		Diff:            inputs.Diff,
		BuiltInResult:   inputs.BuiltInResult,
		ExternalResults: inputs.ExternalResults,
		Policy:          inputs.Policy,
		Record:          inputs.Record,
	})

	if verdict.Blocked() {
		renderGateResult(opts.Stdout, opts.Stderr, "ai-env pr", verdict)
		return fmt.Errorf("ai-env pr: export blocked by %d reason(s); see stderr for details", len(verdict.BlockingReasons()))
	}

	renderPRPreview(opts.Stdout, inputs)
	renderGateResult(opts.Stdout, opts.Stderr, "ai-env pr", verdict)
	fmt.Fprintln(opts.Stdout, "")
	fmt.Fprintln(opts.Stdout, "note:      PR push is not yet implemented (wired in plan 07); gate verdict only")
	return nil
}

// renderPRPreview prints the per-file preview an operator sees when
// the gate allows a PR. The shape mirrors renderPatchResult so the two
// commands feel uniform; the difference is that no patch file is
// emitted, just the summary.
func renderPRPreview(stdout io.Writer, inputs exportInputs) {
	diff := inputs.Diff
	fmt.Fprintf(stdout, "env:       %s\n", diff.Name)
	fmt.Fprintf(stdout, "strategy:  %s\n", diff.Strategy)
	if inputs.RunID != "" {
		fmt.Fprintf(stdout, "run id:    %s\n", inputs.RunID)
	}
	if len(diff.Files) == 0 {
		fmt.Fprintln(stdout, "files:     (no changes)")
		return
	}
	fmt.Fprintf(stdout, "files:     %d changed\n", len(diff.Files))
	for _, f := range diff.Files {
		marker := ""
		if f.Protected {
			marker = "  [protected]"
		}
		fmt.Fprintf(stdout, "  %s  %s%s\n", changeKindGlyph(f.Change), f.Path, marker)
	}
}
