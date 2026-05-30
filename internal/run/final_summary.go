package run

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// finalSummaryFileName is the basename of the per-run human-readable
// summary the supervisor writes on terminal. CreateRunDirectory leaves
// an empty placeholder behind so callers that never reach WriteFinalSummary
// still find the path; the supervisor overwrites it on terminal.
const finalSummaryFileName = "final-summary.md"

// FinalSummaryPath returns the absolute path of the final-summary.md
// file inside runDir. Mirrors GitDiffPath / LifecyclePath so callers
// (status, report, the supervisor's finalize step) share a single
// helper for the layout.
func FinalSummaryPath(runDir string) string {
	return filepath.Join(runDir, finalSummaryFileName)
}

// FinalSummaryInput bundles the inputs the final-summary.md writer
// needs. It is a value type so callers can build it once on terminal
// and hand it to WriteFinalSummary without juggling individual
// arguments. The struct intentionally mirrors the fields the report
// renderer surfaces (env, run id, state, network summary) so a future
// extension that adds, say, a secret-scan section threads through one
// place.
type FinalSummaryInput struct {
	// EnvName is the env the run belonged to. Required.
	EnvName string

	// RunID is the run identifier. Required.
	RunID string

	// State is the terminal State the run landed in. Empty when the
	// run aborted before the supervisor could land a terminal; the
	// renderer prints "(unknown)" in that case so the summary still
	// records the run's identity.
	State State

	// StartedAt is the wall-clock start time. Zero when the run never
	// reached StateRunning; the renderer omits the line in that case.
	StartedAt time.Time

	// StoppedAt is the wall-clock terminal time. Zero when the run was
	// summarized mid-flight (a future feature); the renderer omits the
	// line in that case.
	StoppedAt time.Time

	// Network is the aggregated network summary derived from
	// network-events.jsonl. The writer always includes the network
	// section (plan 05 task 12); a zero-valued summary still produces
	// a well-formed "events: 0 total" line.
	Network NetworkSummary
}

// WriteFinalSummary writes the human-readable final-summary.md file
// into runDir. It is the implementation of plan 05 task 12's
// "add network summary to final-summary.md" requirement.
//
// The file is written atomically (temp + rename) so a concurrent
// reader never observes a half-written summary. WriteFinalSummary is
// idempotent: a re-run of the supervisor's finalize step against the
// same run directory overwrites the file with the latest snapshot.
//
// The supervisor calls WriteFinalSummary from finalizeTerminal after
// the closing run.json snapshot has been written and after the partial
// diff has been collected, so the summary reflects the run's true
// post-terminal state on disk.
func WriteFinalSummary(runDir string, in FinalSummaryInput) error {
	if runDir == "" {
		return errors.New("run: WriteFinalSummary requires runDir")
	}
	if in.EnvName == "" {
		return errors.New("run: WriteFinalSummary requires EnvName")
	}
	if in.RunID == "" {
		return errors.New("run: WriteFinalSummary requires RunID")
	}

	var body bytes.Buffer
	renderFinalSummary(&body, in)

	path := FinalSummaryPath(runDir)
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "final-summary.md.tmp-*")
	if err != nil {
		return fmt.Errorf("run: create final-summary temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(body.Bytes()); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("run: write final-summary temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("run: sync final-summary temp file %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, runFileMode); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("run: chmod final-summary temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("run: close final-summary temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("run: rename final-summary temp file into place: %w", err)
	}
	return nil
}

// renderFinalSummary writes the markdown final summary into w. Split
// out of WriteFinalSummary so tests can exercise the markdown shape
// against an in-memory buffer without touching disk.
//
// The document layout:
//
//	# Run <run-id>
//
//	- env: <env-name>
//	- state: <terminal>
//	- started: <RFC3339>
//	- stopped: <RFC3339>
//
//	## Network
//
//	... (RenderNetworkSummaryMarkdown output)
func renderFinalSummary(w *bytes.Buffer, in FinalSummaryInput) {
	fmt.Fprintf(w, "# Run %s\n\n", in.RunID)
	fmt.Fprintf(w, "- env: %s\n", in.EnvName)
	if in.State != "" {
		fmt.Fprintf(w, "- state: %s\n", in.State)
	} else {
		fmt.Fprintln(w, "- state: (unknown)")
	}
	if !in.StartedAt.IsZero() {
		fmt.Fprintf(w, "- started: %s\n", in.StartedAt.Format(time.RFC3339))
	}
	if !in.StoppedAt.IsZero() {
		fmt.Fprintf(w, "- stopped: %s\n", in.StoppedAt.Format(time.RFC3339))
	}
	fmt.Fprintln(w, "")
	RenderNetworkSummaryMarkdown(w, in.Network)
}
