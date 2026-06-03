package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/run"
)

// TestRunLeaks_NoRunsFriendlyMessage confirms an env with no
// recorded runs surfaces a friendly notice (rather than an error)
// and exits with nil — mirroring `ai-env status` on a fresh env.
func TestRunLeaks_NoRunsFriendlyMessage(t *testing.T) {
	project := newProjectWithAIEnv(t)
	var stdout, stderr bytes.Buffer
	err := RunLeaks(LeaksOptions{
		EnvName: "demo",
		Cwd:     project,
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunLeaks: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "no runs recorded yet") {
		t.Errorf("stdout = %q, want friendly no-runs notice", out)
	}
}

// TestRunLeaks_RendersTableFromLeaksFile seeds a real run directory
// with a hand-written leaks.jsonl, then asserts RunLeaks prints the
// table with the expected verb / vector / source columns.
func TestRunLeaks_RendersTableFromLeaksFile(t *testing.T) {
	project, dir := newProjectWithRunDir(t, "demo")

	rec := run.LeakRecord{
		SchemaVersion: 1,
		Timestamp:     time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		RunID:         dir.ID,
		Source:        run.LeakSourceLifecycle,
		SourceLine:    1,
		Vector:        4,
		Verb:          "gateway_secret_blocked",
		Evidence: run.LeakEvidence{
			Pattern:   "Anthropic sk-ant- prefix",
			FindingID: "finding_001",
			Detail:    "secret detected in tools/call body",
		},
	}
	writeLeaksJSONL(t, dir.Path, []run.LeakRecord{rec})

	var stdout, stderr bytes.Buffer
	err := RunLeaks(LeaksOptions{
		EnvName: "demo",
		Cwd:     project,
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunLeaks: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "gateway_secret_blocked") {
		t.Errorf("stdout missing verb; got %q", out)
	}
	if !strings.Contains(out, "lifecycle") {
		t.Errorf("stdout missing source; got %q", out)
	}
	if !strings.Contains(out, "Anthropic sk-ant- prefix") {
		t.Errorf("stdout missing pattern hint; got %q", out)
	}
}

// TestRunLeaks_FormatJSONRoundTrips asserts --format json emits the
// record as JSONL on stdout.
func TestRunLeaks_FormatJSONRoundTrips(t *testing.T) {
	project, dir := newProjectWithRunDir(t, "demo")

	rec := run.LeakRecord{
		SchemaVersion: 1,
		Timestamp:     time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		RunID:         dir.ID,
		Source:        run.LeakSourceSecretScan,
		SourceLine:    1,
		Vector:        4,
		Verb:          "high",
		Evidence: run.LeakEvidence{
			Pattern:   "PASSWORD= assign",
			FindingID: "finding_007",
		},
	}
	writeLeaksJSONL(t, dir.Path, []run.LeakRecord{rec})

	var stdout, stderr bytes.Buffer
	err := RunLeaks(LeaksOptions{
		EnvName: "demo",
		Cwd:     project,
		Format:  LeaksFormatJSON,
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunLeaks: %v", err)
	}
	line := strings.TrimSpace(stdout.String())
	var decoded run.LeakRecord
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("unmarshal stdout line: %v\nstdout=%s", err, stdout.String())
	}
	if decoded.Verb != "high" {
		t.Errorf("decoded.Verb = %q, want high", decoded.Verb)
	}
	if decoded.Vector != 4 {
		t.Errorf("decoded.Vector = %d, want 4", decoded.Vector)
	}
}

// TestRunLeaks_VectorFilter narrows the output to a single vector.
func TestRunLeaks_VectorFilter(t *testing.T) {
	project, dir := newProjectWithRunDir(t, "demo")

	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	recs := []run.LeakRecord{
		{SchemaVersion: 1, Timestamp: ts, RunID: dir.ID, Source: run.LeakSourceLifecycle, SourceLine: 1, Vector: 4, Verb: "gateway_secret_blocked"},
		{SchemaVersion: 1, Timestamp: ts, RunID: dir.ID, Source: run.LeakSourceNetworkEvents, SourceLine: 1, Vector: 3, Verb: "outbound_blocked"},
	}
	writeLeaksJSONL(t, dir.Path, recs)

	var stdout bytes.Buffer
	if err := RunLeaks(LeaksOptions{
		EnvName: "demo",
		Cwd:     project,
		Vector:  3,
		Stdout:  &stdout,
	}); err != nil {
		t.Fatalf("RunLeaks: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "outbound_blocked") {
		t.Errorf("stdout missing vector-3 row; got %q", out)
	}
	if strings.Contains(out, "gateway_secret_blocked") {
		t.Errorf("stdout leaked vector-4 row; got %q", out)
	}
}

// TestRunLeaks_IgnoresStaleTmpFiles asserts the reader does NOT read
// leaks.jsonl.tmp.* files; only the canonical leaks.jsonl path is
// consulted. We seed both a stale tmp (with bogus content) and a
// real leaks.jsonl (empty) and verify the bogus content never
// surfaces.
func TestRunLeaks_IgnoresStaleTmpFiles(t *testing.T) {
	project, dir := newProjectWithRunDir(t, "demo")

	// Stale tmp with bogus content the CLI must NOT read.
	tmpPath := filepath.Join(dir.Path, "leaks.jsonl.tmp.99999.deadbe")
	if err := os.WriteFile(tmpPath, []byte(`{"verb":"poisoned","source_stream":"lifecycle"}`+"\n"), 0o644); err != nil {
		t.Fatalf("seed stale tmp: %v", err)
	}

	// Real leaks.jsonl with one harmless row.
	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	writeLeaksJSONL(t, dir.Path, []run.LeakRecord{
		{SchemaVersion: 1, Timestamp: ts, RunID: dir.ID, Source: run.LeakSourceLifecycle, SourceLine: 1, Vector: 4, Verb: "real_verb"},
	})

	var stdout, stderr bytes.Buffer
	if err := RunLeaks(LeaksOptions{
		EnvName: "demo",
		Cwd:     project,
		Stdout:  &stdout,
		Stderr:  &stderr,
	}); err != nil {
		t.Fatalf("RunLeaks: %v", err)
	}
	out := stdout.String()
	if strings.Contains(out, "poisoned") {
		t.Errorf("stdout surfaced stale tmp content; got %q", out)
	}
	if !strings.Contains(out, "real_verb") {
		t.Errorf("stdout missing real row; got %q", out)
	}
	if !strings.Contains(stderr.String(), "stale leaks.jsonl tmp file") {
		t.Errorf("stderr missing stale-tmp warning; got %q", stderr.String())
	}
}

// TestRunLeaks_UnknownFormatErrors confirms a typo in --format
// surfaces as a precise error rather than silently falling back.
func TestRunLeaks_UnknownFormatErrors(t *testing.T) {
	project := newProjectWithAIEnv(t)
	err := RunLeaks(LeaksOptions{
		EnvName: "demo",
		Cwd:     project,
		Format:  "yaml",
	})
	if err == nil {
		t.Fatal("RunLeaks(--format=yaml) = nil error, want non-nil")
	}
	if !strings.Contains(err.Error(), "unknown --format") {
		t.Errorf("err = %q, want unknown-format text", err)
	}
}

// newProjectWithAIEnv creates a project directory containing an
// .ai-env tree (with the marker ai-env.yaml findAIEnvDir requires)
// so the CLI's directory walk resolves. Returns the project root
// for use as opts.Cwd.
func newProjectWithAIEnv(t *testing.T) string {
	t.Helper()
	project := t.TempDir()
	aiEnvDir := filepath.Join(project, ".ai-env")
	if err := os.MkdirAll(aiEnvDir, 0o755); err != nil {
		t.Fatalf("mkdir .ai-env: %v", err)
	}
	if err := os.WriteFile(filepath.Join(aiEnvDir, "ai-env.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatalf("write ai-env.yaml: %v", err)
	}
	return project
}

// newProjectWithRunDir creates a project directory with a single
// run directory for envName, writes a minimal run.json so
// LatestRunForEnv recognizes it, and returns the project root + the
// RunDirectory.
func newProjectWithRunDir(t *testing.T, envName string) (string, run.RunDirectory) {
	t.Helper()
	project := newProjectWithAIEnv(t)
	aiEnvDir := filepath.Join(project, ".ai-env")
	runID := "20260601-120000-abcdef"
	dir, err := run.CreateRunDirectory(aiEnvDir, runID, time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	// Write a minimal run.json so LatestRunForEnv picks the env.
	runJSON := map[string]any{
		"_schema_version": 1,
		"run_id":          runID,
		"env_name":        envName,
		"state":           "completed",
	}
	b, err := json.MarshalIndent(runJSON, "", "  ")
	if err != nil {
		t.Fatalf("marshal run.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir.Path, "run.json"), b, 0o644); err != nil {
		t.Fatalf("write run.json: %v", err)
	}
	return project, dir
}

// writeLeaksJSONL writes records as newline-delimited JSON at the
// canonical leaks.jsonl path under runDir.
func writeLeaksJSONL(t *testing.T, runDir string, records []run.LeakRecord) {
	t.Helper()
	var buf bytes.Buffer
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal LeakRecord: %v", err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(run.LeaksPath(runDir), buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write leaks.jsonl: %v", err)
	}
}
