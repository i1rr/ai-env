// Implementation of `ai-env leaks <env-name>` (Plan §8.2).
//
// The command surfaces the unified leaks.jsonl view the supervisor
// finalize step materializes via internal/run.AggregateLeaks. The CLI
// itself does NOT re-aggregate; it reads the on-disk leaks.jsonl
// produced at finalize time and renders one row per LeakRecord in a
// human-readable table (default) or as a JSONL stream (--format json).
//
// Per Plan §8.2 the reader explicitly skips `leaks.jsonl.tmp.*`
// staging files in the run directory: a tmp file is a half-written
// aggregator pass (or a stale artifact from a crashed run) and surfacing
// it to the operator would conflate "the supervisor crashed mid-write"
// with "the run produced leaks". The CLI only ever reads the
// atomically-replaced leaks.jsonl, never the tmp staging path.
//
// Errors:
//
//   - validate env name failures wrap with "ai-env leaks:".
//   - ErrNoRuns surfaces as a friendly "no runs yet" message and exits
//     0 (consistent with `ai-env status` / `ai-env list`).
//   - A missing leaks.jsonl (the placeholder CreateRunDirectory left
//     in place if the supervisor never finalized) is NOT an error: the
//     command prints a "(no leaks recorded)" notice and exits 0.
//   - A malformed JSONL line aborts with a precise diagnostic so the
//     operator knows the file is corrupt.

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/rivan1986/ai-env/internal/run"
)

// LeaksFormat enumerates the output format `ai-env leaks` supports.
// Default is LeaksFormatTable; LeaksFormatJSON is the pass-through
// JSONL form for downstream pipelines (jq, awk).
type LeaksFormat string

const (
	// LeaksFormatTable renders one row per LeakRecord as an
	// aligned table (timestamp / vector / source / verb / detail).
	// The default format.
	LeaksFormatTable LeaksFormat = "table"

	// LeaksFormatJSON re-emits the LeakRecord lines as JSONL on
	// stdout. The input is already JSONL; we re-encode to make the
	// output stable against future schema additions (the reader's
	// LeakRecord shape is the canonical projection).
	LeaksFormatJSON LeaksFormat = "json"
)

// LeaksOptions captures the parsed flags + positional argument for
// `ai-env leaks`. The CLI wiring layer fills this in and passes it to
// RunLeaks so the command body has no direct Cobra dependency.
type LeaksOptions struct {
	// EnvName is the positional <env-name> argument identifying which
	// env's leaks.jsonl to render.
	EnvName string

	// RunID, when non-empty, overrides "the env's latest run" with a
	// specific run id (mirrors `ai-env status --run`).
	RunID string

	// Format picks the on-stdout shape. Empty defaults to
	// LeaksFormatTable. An unknown value returns an error so a typo
	// surfaces loudly.
	Format LeaksFormat

	// Vector filters the output to rows whose Vector matches. Zero
	// (the default) disables the filter and prints every row.
	Vector int

	// Source filters the output to rows whose Source matches. Empty
	// disables the filter.
	Source string

	// Cwd is the working directory the command was invoked from.
	// RunLeaks walks upward from Cwd looking for the project's
	// .ai-env/ directory (mirroring `ai-env status` / `ai-env logs`).
	Cwd string

	// Stdout is the writer for the rendered table / JSONL.
	Stdout io.Writer

	// Stderr is the writer for warnings (missing leaks.jsonl notice,
	// filter hit zero rows). The command still exits 0 in those
	// cases — the notice is purely informational.
	Stderr io.Writer
}

// RunLeaks is the entry point used by the Cobra wiring for
// `ai-env leaks`. It locates the requested run for opts.EnvName
// (latest by default; opts.RunID overrides), reads its leaks.jsonl
// (skipping any leaks.jsonl.tmp.* staging file in the run directory),
// applies opts.Vector / opts.Source filters, and renders the result
// to opts.Stdout in opts.Format.
func RunLeaks(opts LeaksOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env leaks: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if opts.Format == "" {
		opts.Format = LeaksFormatTable
	}
	if opts.Format != LeaksFormatTable && opts.Format != LeaksFormatJSON {
		return fmt.Errorf("ai-env leaks: unknown --format %q (expected table or json)", opts.Format)
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env leaks: %w", err)
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env leaks: %w", err)
	}

	target, err := resolveLeaksRun(aiEnvDir, opts.EnvName, opts.RunID)
	if err != nil {
		if errors.Is(err, run.ErrNoRuns) {
			fmt.Fprintf(opts.Stdout, "env:       %s\n", opts.EnvName)
			fmt.Fprintln(opts.Stdout, "leaks:     (no runs recorded yet)")
			return nil
		}
		return fmt.Errorf("ai-env leaks: %w", err)
	}

	records, err := readLeaksFile(target.Path)
	if err != nil {
		return fmt.Errorf("ai-env leaks: %w", err)
	}

	// Skip tmp staging files explicitly. readLeaksFile already
	// reads the canonical leaks.jsonl path (LeaksPath), not the
	// tmp, but we double-check the directory does not contain a
	// stale tmp that the supervisor's start-of-run sweep failed to
	// remove (Plan §8.2: ignore *.tmp.* files when reading). The
	// guard is informational; we still print the canonical rows.
	if stale := findStaleLeaksTmpFiles(target.Path); len(stale) > 0 {
		fmt.Fprintf(opts.Stderr, "warning: ignoring %d stale leaks.jsonl tmp file(s) in %s\n", len(stale), target.Path)
	}

	// Apply filters before counting so the "no rows" notice
	// reflects the filtered view rather than the raw count.
	filtered := filterLeaks(records, opts.Vector, opts.Source)

	if len(filtered) == 0 {
		fmt.Fprintf(opts.Stdout, "env:       %s\n", opts.EnvName)
		fmt.Fprintf(opts.Stdout, "run:       %s\n", target.ID)
		fmt.Fprintln(opts.Stdout, "leaks:     (no leaks recorded)")
		return nil
	}

	switch opts.Format {
	case LeaksFormatJSON:
		return renderLeaksJSON(opts.Stdout, filtered)
	default:
		return renderLeaksTable(opts.Stdout, opts.EnvName, target.ID, filtered)
	}
}

// resolveLeaksRun picks the run directory to read leaks.jsonl from.
// runID, when non-empty, takes precedence (we look it up by id);
// otherwise we fall back to the env's latest run (LatestRunForEnv).
func resolveLeaksRun(aiEnvDir, envName, runID string) (run.RunSummary, error) {
	if runID != "" {
		return run.FindRunByID(aiEnvDir, runID)
	}
	return run.LatestRunForEnv(aiEnvDir, envName)
}

// readLeaksFile reads <runDir>/leaks.jsonl and returns the parsed
// LeakRecord slice. A missing file returns (nil, nil) so the caller
// can surface a friendly "no leaks recorded" notice without
// distinguishing an absent file from an empty one. A malformed line
// returns the records parsed so far plus a wrapped error.
//
// The function explicitly does NOT touch the tmp staging path
// (<runDir>/leaks.jsonl.tmp.<pid>.<rand>) per Plan §8.2: tmp files
// are aggregator staging artifacts; the canonical view is the
// atomically-renamed leaks.jsonl alone.
func readLeaksFile(runDir string) ([]run.LeakRecord, error) {
	path := run.LeaksPath(runDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read leaks.jsonl %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	out := make([]run.LeakRecord, 0, 16)
	for i, line := range splitLeakLines(data) {
		if len(line) == 0 {
			continue
		}
		var rec run.LeakRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return out, fmt.Errorf("parse leaks.jsonl line %d: %w", i+1, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// splitLeakLines is a trivial \n-splitter so the parser stays small.
// The function lives here (rather than calling into a run-package
// helper) so leaks.jsonl readers in this package do not depend on
// run-package internals.
func splitLeakLines(data []byte) [][]byte {
	out := [][]byte{}
	start := 0
	for i, b := range data {
		if b == '\n' {
			out = append(out, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}

// findStaleLeaksTmpFiles enumerates any leaks.jsonl.tmp.* entries in
// runDir. The CLI ignores these per Plan §8.2; the function is used
// only for the informational warning printed to stderr.
func findStaleLeaksTmpFiles(runDir string) []string {
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "leaks.jsonl.tmp.") {
			continue
		}
		out = append(out, filepath.Join(runDir, name))
	}
	return out
}

// filterLeaks applies the --vector / --source filters to records.
// A zero vector / empty source disables the corresponding filter.
// The relative order of surviving records is preserved.
func filterLeaks(records []run.LeakRecord, vector int, source string) []run.LeakRecord {
	if vector == 0 && source == "" {
		return records
	}
	out := make([]run.LeakRecord, 0, len(records))
	for _, r := range records {
		if vector != 0 && r.Vector != vector {
			continue
		}
		if source != "" && string(r.Source) != source {
			continue
		}
		out = append(out, r)
	}
	return out
}

// renderLeaksTable writes a human-readable table of records to out.
// The columns are: timestamp / vector / source / verb / detail. The
// detail column carries the Evidence.Detail string (falling back to
// the first Extra value when Detail is empty) so the operator sees
// the most informative single-line summary without joining against
// the JSON shape.
func renderLeaksTable(out io.Writer, envName, runID string, records []run.LeakRecord) error {
	fmt.Fprintf(out, "env:       %s\n", envName)
	fmt.Fprintf(out, "run:       %s\n", runID)
	fmt.Fprintf(out, "leaks:     %d row(s)\n", len(records))
	fmt.Fprintln(out, "")

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIMESTAMP\tVECTOR\tSOURCE\tVERB\tDETAIL")
	for _, r := range records {
		detail := r.Evidence.Detail
		if detail == "" {
			detail = firstExtra(r.Evidence.Extra)
		}
		if r.Evidence.Pattern != "" {
			if detail == "" {
				detail = "pattern=" + r.Evidence.Pattern
			} else {
				detail = "pattern=" + r.Evidence.Pattern + "; " + detail
			}
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n",
			r.Timestamp,
			r.Vector,
			string(r.Source),
			truncate(r.Verb, 40),
			truncate(detail, 80),
		)
	}
	return tw.Flush()
}

// firstExtra returns one Extra value (deterministically picked by
// sorted key) so the table column has SOMETHING to display when both
// Detail and Pattern are empty. Returns the empty string for an empty
// map.
func firstExtra(extra map[string]string) string {
	if len(extra) == 0 {
		return ""
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys[0] + "=" + extra[keys[0]]
}

// truncate caps s at max characters, appending an ellipsis when
// truncation occurred. Used to keep the table columns aligned for
// long Verb / Detail strings.
func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// renderLeaksJSON re-emits the records as JSONL on out. The encode is
// deliberate (rather than re-emitting the original byte stream) so
// the output is stable against future schema additions: the operator
// always sees the LeakRecord projection rather than whatever shape
// was on disk when the file was written.
func renderLeaksJSON(out io.Writer, records []run.LeakRecord) error {
	enc := json.NewEncoder(out)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encode leak record: %w", err)
		}
	}
	return nil
}
