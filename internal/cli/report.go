package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rivan1986/ai-env/internal/run"
)

// ReportOptions captures the parsed flags + positional argument for
// `ai-env report`. The CLI wiring layer fills this in and passes it to
// RunReport so the command body has no direct Cobra dependency.
type ReportOptions struct {
	// EnvName is the positional <env-name> argument identifying which
	// env's latest run to summarize. It must match an env that has at
	// least one recorded run.json under .ai-env/runs/.
	EnvName string

	// RunID, when non-empty, selects a specific historical run instead
	// of the env's latest. Defaults to the env's latest run.
	RunID string

	// Cwd is the working directory the command was invoked from.
	// RunReport walks upward from Cwd looking for the project's
	// .ai-env/ directory (mirroring `ai-env list` / `diff` / `patch`).
	Cwd string

	// Stdout is the writer for the human-readable report.
	Stdout io.Writer

	// Stderr is the writer for warnings (missing optional artifacts,
	// malformed lines in network-events.jsonl). The report command
	// still prints the body on stdout even if a warning fires.
	Stderr io.Writer

	// Now is the clock used to compute elapsed for an in-flight run.
	// Defaults to time.Now when nil; tests inject a fixed clock so the
	// printed elapsed value is deterministic.
	Now func() time.Time
}

// RunReport is the entry point used by the Cobra wiring for
// `ai-env report`. It locates the requested (or latest) run for
// opts.EnvName, reads its run.json snapshot and network-events.jsonl,
// and prints a stable, human-readable report.
//
// The report contains, in order:
//
//  1. Env handle (env, run id, state, agent, backend).
//  2. Timing (started, stopped, elapsed when in flight).
//  3. The network policy summary (plan 05 task 7 and task 12 share
//     the same renderer so the report and final-summary.md agree).
//  4. On-disk artifacts (run dir, run.json, lifecycle.jsonl,
//     network-events.jsonl, final-summary.md, git-diff.patch).
//
// Per the plan, RunReport is a one-shot read: it returns after
// printing the snapshot and does not tail.
func RunReport(opts ReportOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env report: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env report: %w", err)
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env report: %w", err)
	}

	var summary run.RunSummary
	if opts.RunID != "" {
		summary, err = run.FindRunByID(aiEnvDir, opts.RunID)
	} else {
		summary, err = run.LatestRunForEnv(aiEnvDir, opts.EnvName)
	}
	if err != nil {
		if errors.Is(err, run.ErrNoRuns) {
			fmt.Fprintf(opts.Stdout, "env:       %s\n", opts.EnvName)
			fmt.Fprintln(opts.Stdout, "runs:      (none recorded yet)")
			return nil
		}
		return fmt.Errorf("ai-env report: %w", err)
	}

	rec, recErr := run.ReadRecord(summary.Path)
	if recErr != nil && !errors.Is(recErr, run.ErrRecordNotWritten) {
		return fmt.Errorf("ai-env report: %w", recErr)
	}

	events, evErr := run.ReadNetworkEvents(summary.Path)
	if evErr != nil {
		fmt.Fprintf(opts.Stderr, "warning: %v\n", evErr)
	}
	netSummary := run.SummarizeNetworkEvents(events)

	renderReport(opts.Stdout, reportData{
		EnvName:    opts.EnvName,
		RunID:      summary.ID,
		Path:       summary.Path,
		Record:     rec,
		HasRecord:  recErr == nil,
		NetSummary: netSummary,
		Now:        opts.Now(),
	})
	return nil
}

// reportData bundles the fields renderReport prints. Extracted into a
// struct so the renderer signature stays narrow and so tests can build
// a report literal without re-doing the disk I/O.
type reportData struct {
	EnvName    string
	RunID      string
	Path       string
	Record     run.Record
	HasRecord  bool
	NetSummary run.NetworkSummary
	Now        time.Time
}

// renderReport writes the deterministic, label-aligned report to w. It
// mirrors the shape of `ai-env status` (label: value lines) so an
// operator who knows one knows the other.
func renderReport(w io.Writer, r reportData) {
	fmt.Fprintf(w, "env:       %s\n", r.EnvName)
	fmt.Fprintf(w, "run id:    %s\n", r.RunID)

	if !r.HasRecord {
		fmt.Fprintln(w, "state:     (run.json not written yet)")
	} else {
		rec := r.Record
		fmt.Fprintf(w, "state:     %s\n", rec.State)
		if rec.Agent != "" {
			fmt.Fprintf(w, "agent:     %s\n", rec.Agent)
		}
		if rec.Backend != "" {
			fmt.Fprintf(w, "backend:   %s\n", rec.Backend)
		}
		if rec.StartedAt != nil {
			fmt.Fprintf(w, "started:   %s\n", rec.StartedAt.Format(time.RFC3339))
		}
		if rec.StoppedAt != nil {
			fmt.Fprintf(w, "stopped:   %s\n", rec.StoppedAt.Format(time.RFC3339))
			if rec.StartedAt != nil {
				dur := rec.StoppedAt.Sub(*rec.StartedAt)
				fmt.Fprintf(w, "elapsed:   %s\n", formatDuration(dur))
			}
		} else if rec.StartedAt != nil {
			dur := r.Now.Sub(*rec.StartedAt)
			if dur < 0 {
				dur = 0
			}
			fmt.Fprintf(w, "elapsed:   %s (running)\n", formatDuration(dur))
		}
		if rec.ExitCode != nil {
			fmt.Fprintf(w, "exit code: %d\n", *rec.ExitCode)
		}
		if rec.StopReason != nil && *rec.StopReason != "" {
			fmt.Fprintf(w, "stop reason: %s\n", *rec.StopReason)
		}
	}

	// Network summary section (plan 05 task 7 / task 12). Always
	// printed so a run that aborted before the policy stage still
	// produces a "network policy: not attempted" line, matching the
	// final-summary.md output exactly.
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "network:")
	run.RenderNetworkSummaryText(w, r.NetSummary)

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "artifacts:")
	fmt.Fprintf(w, "  run dir            %s\n", r.Path)
	fmt.Fprintf(w, "  run.json           %s\n", run.RunJSONPath(r.Path))
	fmt.Fprintf(w, "  lifecycle          %s\n", run.LifecyclePath(r.Path))
	fmt.Fprintf(w, "  network events     %s\n", run.NetworkEventsPath(r.Path))
	fmt.Fprintf(w, "  final summary      %s\n", run.FinalSummaryPath(r.Path))
	fmt.Fprintf(w, "  git diff           %s\n", run.GitDiffPath(r.Path))
}
