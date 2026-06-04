package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/i1rr/ai-env/internal/run"
)

// StatusOptions captures the parsed flags + positional argument for
// `ai-env status`. The CLI wiring layer fills this in and passes it to
// RunStatus so the command body has no direct Cobra dependency.
type StatusOptions struct {
	// EnvName is the positional <env-name> argument identifying which
	// env's latest run to inspect. It must match an env that has at
	// least one recorded run.json under .ai-env/runs/.
	EnvName string

	// Cwd is the working directory the command was invoked from.
	// RunStatus walks upward from Cwd looking for the project's
	// .ai-env/ directory (mirroring `ai-env list`/`diff`/`patch`).
	Cwd string

	// Stdout is the writer for the human-readable status report.
	Stdout io.Writer

	// Stderr is the writer for warnings (malformed lifecycle entries,
	// missing optional artifacts). The status command still prints the
	// report on stdout even if a warning fires.
	Stderr io.Writer

	// Now is the clock used to compute the "elapsed" line for an
	// in-flight run. Defaults to time.Now when nil; tests inject a
	// fixed clock so the printed elapsed value is deterministic.
	Now func() time.Time
}

// RunStatus is the entry point used by the Cobra wiring for
// `ai-env status`. It locates the latest run for opts.EnvName, reads
// its run.json snapshot and lifecycle.jsonl tail, and prints a
// stable human-readable report.
//
// The report contains, in order:
//
//  1. Env handle (env, run id, state).
//  2. Identity (agent, backend, model credential mode).
//  3. Timing (started_at, stopped_at when terminal, elapsed
//     computed against opts.Now for in-flight runs).
//  4. Exit info (exit code, stop reason, linked previous run).
//  5. On-disk artifacts (run.json, lifecycle.jsonl, stdout/stderr
//     logs, git-diff.patch) so the user has paths to dig into.
//  6. The last few lifecycle events (most recent first) so an
//     operator gets at-a-glance flow without opening the file.
//
// Per the plan, RunStatus is a one-shot read: it returns after
// printing the snapshot and does not tail. Operators who want a live
// view tail run.json / lifecycle.jsonl themselves; the supervisor's
// atomic-replace write contract guarantees readers see either the
// old or the new whole file, never a partial one.
//
// Errors:
//
//   - validate env name failures wrap with "ai-env status:".
//   - ErrNoRuns is surfaced as a friendly "no runs yet" message
//     and a nil error so the command exits 0 (consistent with
//     `ai-env list` on a fresh env).
//   - other I/O failures wrap and return non-nil so the operator
//     sees a precise diagnostic.
func RunStatus(opts StatusOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env status: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env status: %w", err)
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env status: %w", err)
	}

	latest, err := run.LatestRunForEnv(aiEnvDir, opts.EnvName)
	if err != nil {
		if errors.Is(err, run.ErrNoRuns) {
			fmt.Fprintf(opts.Stdout, "env:       %s\n", opts.EnvName)
			fmt.Fprintln(opts.Stdout, "runs:      (none recorded yet)")
			fmt.Fprintln(opts.Stdout, "")
			// Hint mirrors the cobra Use of `ai-env run` (cmd/ai-env/main.go
			// newRunCmd): --task is required, --agent is optional and
			// defaults to project.default_agent from ai-env.yaml, --continue
			// links to the env's previous run. The less common --shell-shim
			// and --observer-mode knobs are documented via `ai-env run -h`.
			fmt.Fprintln(opts.Stdout, "Start one with `ai-env run "+opts.EnvName+" --task \"...\" [--agent <agent>] [--continue]`.")
			fmt.Fprintln(opts.Stdout, "See `ai-env run -h` for --shell-shim and --observer-mode.")
			return nil
		}
		return fmt.Errorf("ai-env status: %w", err)
	}

	rec, recErr := run.ReadRecord(latest.Path)
	if recErr != nil && !errors.Is(recErr, run.ErrRecordNotWritten) {
		// run.json exists but is malformed. Surface it: the listing
		// above already confirmed the directory is present, so we
		// owe the operator a precise diagnostic.
		return fmt.Errorf("ai-env status: %w", recErr)
	}

	events, evErr := run.ReadLifecycleEvents(latest.Path)
	if evErr != nil {
		fmt.Fprintf(opts.Stderr, "warning: %v\n", evErr)
	}

	renderStatusReport(opts.Stdout, statusReport{
		EnvName:   opts.EnvName,
		RunID:     latest.ID,
		Path:      latest.Path,
		Record:    rec,
		HasRecord: recErr == nil,
		Events:    events,
		Now:       opts.Now(),
	})
	return nil
}

// statusReport bundles the fields renderStatusReport prints. Extracted
// into a struct so the renderer signature stays narrow and the tests
// can build a report literal without re-doing the disk I/O.
type statusReport struct {
	// EnvName is the env the user asked about.
	EnvName string

	// RunID is the latest run's directory basename.
	RunID string

	// Path is the absolute run directory path.
	Path string

	// Record is the decoded run.json. Zero-valued when HasRecord is
	// false (the post-CreateRunDirectory placeholder state).
	Record run.Record

	// HasRecord reports whether Record was successfully decoded. When
	// false, the renderer prints a "run.json not written yet" note in
	// place of the schema fields.
	HasRecord bool

	// Events is the lifecycle event trail, in append order (oldest
	// first). The renderer prints the most recent entries last so the
	// reader's eye walks chronologically. May be nil/empty.
	Events []run.LifecycleEvent

	// Now is the wall-clock to compute elapsed against when the run
	// has no stopped_at.
	Now time.Time
}

// renderStatusReport writes the deterministic, column-aligned status
// report to w. The output is intentionally simple so it is greppable
// and stable for future tests; it mirrors the shape of `ai-env diff`
// and `ai-env list` (label-aligned colon-separated lines).
func renderStatusReport(w io.Writer, r statusReport) {
	fmt.Fprintf(w, "env:       %s\n", r.EnvName)
	fmt.Fprintf(w, "run id:    %s\n", r.RunID)

	if !r.HasRecord {
		// The run directory was created but the supervisor never wrote
		// run.json. This happens in the narrow window between
		// CreateRunDirectory and the first lifecycle transition. We
		// still print the trail so the operator can see how far the
		// supervisor got.
		fmt.Fprintln(w, "state:     (run.json not written yet)")
	} else {
		rec := r.Record
		fmt.Fprintf(w, "state:     %s\n", rec.State)
		fmt.Fprintf(w, "agent:     %s\n", rec.Agent)
		fmt.Fprintf(w, "backend:   %s\n", rec.Backend)
		fmt.Fprintf(w, "credential mode: %s\n", rec.ModelCredentialMode)

		if rec.ReducedSafety {
			fmt.Fprintln(w, "reduced safety: yes")
		}

		if rec.StartedAt != nil {
			fmt.Fprintf(w, "started:   %s\n", rec.StartedAt.Format(time.RFC3339))
		} else {
			fmt.Fprintln(w, "started:   (not yet)")
		}

		if rec.StoppedAt != nil {
			fmt.Fprintf(w, "stopped:   %s\n", rec.StoppedAt.Format(time.RFC3339))
			if rec.StartedAt != nil {
				dur := rec.StoppedAt.Sub(*rec.StartedAt)
				fmt.Fprintf(w, "elapsed:   %s\n", formatDuration(dur))
			}
		} else if rec.StartedAt != nil {
			// In-flight run: elapsed is now minus started. We use the
			// caller-supplied clock so the printed value is
			// deterministic in tests.
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
		if rec.LinkedPreviousRun != nil && *rec.LinkedPreviousRun != "" {
			fmt.Fprintf(w, "linked previous run: %s\n", *rec.LinkedPreviousRun)
		}
		if rec.Task != "" {
			fmt.Fprintf(w, "task:      %s\n", firstLine(rec.Task))
		}
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "artifacts:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  run dir\t%s\n", r.Path)
	fmt.Fprintf(tw, "  run.json\t%s\n", run.RunJSONPath(r.Path))
	fmt.Fprintf(tw, "  lifecycle\t%s\n", run.LifecyclePath(r.Path))
	fmt.Fprintf(tw, "  stdout\t%s\n", run.StdoutLogPath(r.Path))
	fmt.Fprintf(tw, "  stderr\t%s\n", run.StderrLogPath(r.Path))
	fmt.Fprintf(tw, "  diff\t%s\n", run.GitDiffPath(r.Path))
	_ = tw.Flush()

	if len(r.Events) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "recent lifecycle:")
		// Show the last few events so an operator gets the run's flow
		// without opening lifecycle.jsonl. Five is enough to cover the
		// "starting_backend -> applying_policy -> starting_agent ->
		// running -> <terminal>" arc; configurable via tail count is
		// future work.
		const tailCount = 5
		start := 0
		if len(r.Events) > tailCount {
			start = len(r.Events) - tailCount
		}
		etw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, e := range r.Events[start:] {
			fmt.Fprintf(etw, "  %s\t%s\n", e.Timestamp, e.State)
		}
		_ = etw.Flush()
	}
}

// formatDuration renders d with one-second resolution so the printed
// elapsed line is stable across calls and easy to read. The default
// Duration.String prints sub-second precision (e.g. "1m13.0421s")
// which is noisy for the status command and unstable in tests.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "0s"
	}
	d = d.Round(time.Second)
	return d.String()
}

// firstLine returns the first non-empty line of s with trailing
// whitespace stripped. Used by the task preview so a multi-line task
// description does not blow up the single-line report.
func firstLine(s string) string {
	for _, raw := range splitLines(s) {
		line := stripTrailingSpace(raw)
		if line != "" {
			return line
		}
	}
	return ""
}

// splitLines is a small \n splitter that mirrors strings.Split without
// pulling in the package just for one call. Kept private so callers
// reach for strings.Split when they need the standard helper.
func splitLines(s string) []string {
	out := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// stripTrailingSpace trims spaces, tabs, and carriage returns off the
// right edge of s. Used by firstLine so a CRLF line ending or trailing
// indentation does not produce a deceptively non-empty cell.
func stripTrailingSpace(s string) string {
	end := len(s)
	for end > 0 {
		c := s[end-1]
		if c == ' ' || c == '\t' || c == '\r' {
			end--
			continue
		}
		break
	}
	return s[:end]
}
