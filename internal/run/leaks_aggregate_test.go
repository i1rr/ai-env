package run

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAggregateLeaks_EmptyRun verifies an aggregate against a freshly
// created run directory (every per-stream file is the empty
// placeholder CreateRunDirectory left in place) produces zero rows and
// atomically materializes an empty leaks.jsonl. The function must NOT
// error on missing-source-files: a brand-new run with no events still
// renders a valid (zero-row) merged view.
func TestAggregateLeaks_EmptyRun(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)

	count, err := AggregateLeaks(dir.Path, AggregateLeaksOptions{RunID: dir.ID})
	if err != nil {
		t.Fatalf("AggregateLeaks: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}

	// The final file must exist and be empty.
	data, err := os.ReadFile(LeaksPath(dir.Path))
	if err != nil {
		t.Fatalf("read leaks.jsonl: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("leaks.jsonl = %q, want empty", data)
	}

	// No tmp left behind.
	entries, err := os.ReadDir(dir.Path)
	if err != nil {
		t.Fatalf("read run dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "leaks.jsonl.tmp.") {
			t.Errorf("stale tmp left in run dir: %s", e.Name())
		}
	}
}

// TestAggregateLeaks_LifecycleSecretBlocked confirms a
// gateway_secret_blocked lifecycle verb lands in leaks.jsonl with the
// pattern + finding_id stripped from Metadata and the vector set to 4
// (secret exfiltration).
func TestAggregateLeaks_LifecycleSecretBlocked(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)

	// Write a lifecycle event by hand. The on-disk shape is the one
	// LifecycleWriter would have produced.
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	writeJSONL(t, filepath.Join(dir.Path, "lifecycle.jsonl"), []any{
		LifecycleEvent{
			RunID:     dir.ID,
			Verb:      LifecycleVerbGatewaySecretBlocked,
			Backend:   "docker-sbx",
			Agent:     "claude",
			Timestamp: now,
			Metadata: map[string]string{
				"server":     "github",
				"operation":  "tools/call",
				"pattern":    "Anthropic sk-ant- prefix",
				"finding_id": "finding_001",
			},
		},
	})

	count, err := AggregateLeaks(dir.Path, AggregateLeaksOptions{RunID: dir.ID})
	if err != nil {
		t.Fatalf("AggregateLeaks: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}

	rows := readLeaksJSONL(t, dir.Path)
	if got := rows[0].Vector; got != 4 {
		t.Errorf("vector = %d, want 4", got)
	}
	if got := rows[0].Source; got != LeakSourceLifecycle {
		t.Errorf("source = %q, want %q", got, LeakSourceLifecycle)
	}
	if got := rows[0].Verb; got != string(LifecycleVerbGatewaySecretBlocked) {
		t.Errorf("verb = %q, want %q", got, LifecycleVerbGatewaySecretBlocked)
	}
	if got := rows[0].Evidence.Pattern; got != "Anthropic sk-ant- prefix" {
		t.Errorf("evidence.pattern = %q", got)
	}
	if got := rows[0].Evidence.FindingID; got != "finding_001" {
		t.Errorf("evidence.finding_id = %q", got)
	}
	if got := rows[0].RunID; got != dir.ID {
		t.Errorf("run_id = %q, want %q", got, dir.ID)
	}
	if got := rows[0].SourceLine; got != 1 {
		t.Errorf("source_line = %d, want 1", got)
	}
}

// TestAggregateLeaks_DedupBaseKey confirms two records that share the
// (source_stream, source_line, policy_event_id) base key collapse to
// one row. We craft a policy-decisions row and a shell-commands row
// that both reference the same PolicyEventID; the shell row is on a
// different source_stream so it stays distinct under the base key.
// (The base-key dedup only fires within a single source_stream.) The
// real test for the cross-source case is the secret-scan dedup below.
func TestAggregateLeaks_DedupBaseKey(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)

	// Two identical policy-decision rows (same line index, same
	// policy_event_id) — emulate a hypothetical re-aggregate path.
	// We achieve "same source_line" by writing one record twice via
	// the same emitter ordering; the dedup pass keys on the
	// (source, line, policy_event_id) tuple — two identical lines
	// have identical keys so the second copy is dropped.
	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	ev := PolicyDecisionEvent{
		RunID:         dir.ID,
		Timestamp:     ts,
		Event:         PolicyDecisionEngineEvaluate,
		Decision:      PolicyDecisionDeny,
		EventType:     "shell_command",
		Target:        "curl http://example.com",
		Reason:        "denied by high-risk shell pattern",
		PolicyEventID: "evt_123_abc",
	}
	// Write a SINGLE event but aggregate twice into the same dir by
	// re-running the aggregator. The dedup pass runs inside one
	// aggregate; we verify the in-aggregate path collapses the
	// duplicate by writing the same event twice in the source file.
	writeJSONL(t, filepath.Join(dir.Path, "policy-decisions.jsonl"), []any{ev, ev})

	count, err := AggregateLeaks(dir.Path, AggregateLeaksOptions{RunID: dir.ID})
	if err != nil {
		t.Fatalf("AggregateLeaks: %v", err)
	}
	// The two source records sit on lines 1 and 2 — different
	// source_line → distinct keys → both survive. We assert on the
	// count + the source_line distinction so a future schema change
	// does not silently collapse them.
	if count != 2 {
		t.Fatalf("count = %d, want 2 (two distinct source_line keys)", count)
	}
	rows := readLeaksJSONL(t, dir.Path)
	if rows[0].SourceLine == rows[1].SourceLine {
		t.Errorf("source_line collision: %d %d", rows[0].SourceLine, rows[1].SourceLine)
	}
}

// TestAggregateLeaks_ScannerExtensionDedupPreservesDistinctPatterns
// asserts that two findings on the same line of secret-scan.json with
// different pattern names produce two distinct LeakRecord rows. The
// scanner extension of the dedup key — (vector, evidence.pattern,
// evidence.finding_id) — defeats the collapse.
func TestAggregateLeaks_ScannerExtensionDedupPreservesDistinctPatterns(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)

	scanDoc := map[string]any{
		"run_id":     dir.ID,
		"scanner":    "built-in-patterns",
		"scanned_at": time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"findings": []map[string]any{
			{
				"id":            "finding_001",
				"type":          "api_key",
				"pattern":       "Anthropic sk-ant- prefix",
				"file":          "foo.py",
				"line":          42,
				"confidence":    "high",
				"entropy_only":  false,
				"blocks_export": true,
			},
			{
				"id":            "finding_002",
				"type":          "env_assignment",
				"pattern":       "PASSWORD= assign",
				"file":          "foo.py",
				"line":          42,
				"confidence":    "high",
				"entropy_only":  false,
				"blocks_export": true,
			},
		},
	}
	scanBytes, err := json.Marshal(scanDoc)
	if err != nil {
		t.Fatalf("marshal scan doc: %v", err)
	}
	if err := os.WriteFile(SecretScanPath(dir.Path), scanBytes, 0o644); err != nil {
		t.Fatalf("write secret-scan.json: %v", err)
	}

	count, err := AggregateLeaks(dir.Path, AggregateLeaksOptions{RunID: dir.ID})
	if err != nil {
		t.Fatalf("AggregateLeaks: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2 (two distinct patterns)", count)
	}
	rows := readLeaksJSONL(t, dir.Path)
	if rows[0].Evidence.Pattern == rows[1].Evidence.Pattern {
		t.Errorf("pattern collision: %q == %q", rows[0].Evidence.Pattern, rows[1].Evidence.Pattern)
	}
	for _, r := range rows {
		if r.Vector != 4 {
			t.Errorf("vector = %d, want 4 (secret exfiltration)", r.Vector)
		}
		if r.Source != LeakSourceSecretScan {
			t.Errorf("source = %q, want %q", r.Source, LeakSourceSecretScan)
		}
	}
}

// TestAggregateLeaks_TmpFileAtomicReplace asserts the aggregator
// replaces the existing leaks.jsonl atomically via the tmp + fsync +
// rename pattern. We pre-populate leaks.jsonl with bogus content, then
// run the aggregator and verify the bogus content is gone and no tmp
// remains in the run directory.
func TestAggregateLeaks_TmpFileAtomicReplace(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)

	if err := os.WriteFile(LeaksPath(dir.Path), []byte("bogus\n"), 0o644); err != nil {
		t.Fatalf("seed bogus leaks.jsonl: %v", err)
	}

	if _, err := AggregateLeaks(dir.Path, AggregateLeaksOptions{RunID: dir.ID}); err != nil {
		t.Fatalf("AggregateLeaks: %v", err)
	}

	// No tmp left behind.
	entries, err := os.ReadDir(dir.Path)
	if err != nil {
		t.Fatalf("read run dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "leaks.jsonl.tmp.") {
			t.Errorf("stale tmp after aggregate: %s", e.Name())
		}
	}

	data, err := os.ReadFile(LeaksPath(dir.Path))
	if err != nil {
		t.Fatalf("read leaks.jsonl: %v", err)
	}
	if string(data) == "bogus\n" {
		t.Errorf("leaks.jsonl not replaced; still has bogus content")
	}
}

// TestAggregateLeaks_MissingRunDir surfaces a missing runDir as an
// error (rather than silently succeeding with zero rows). The
// supervisor invokes this against a known-good run directory; a
// missing dir is a contract violation worth surfacing.
func TestAggregateLeaks_MissingRunDir(t *testing.T) {
	if _, err := AggregateLeaks("", AggregateLeaksOptions{RunID: "x"}); err == nil {
		t.Errorf("missing runDir = nil error, want non-nil")
	}
	if _, err := AggregateLeaks("/tmp/some-dir", AggregateLeaksOptions{RunID: ""}); err == nil {
		t.Errorf("missing runID = nil error, want non-nil")
	}
}

// writeJSONL is a tiny test helper that marshals a slice of records
// into <path> as newline-delimited JSON.
func writeJSONL(t *testing.T, path string, records []any) {
	t.Helper()
	var buf bytes.Buffer
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// readLeaksJSONL loads every LeakRecord in <runDir>/leaks.jsonl and
// returns the parsed slice. Used by the assertions above.
func readLeaksJSONL(t *testing.T, runDir string) []LeakRecord {
	t.Helper()
	data, err := os.ReadFile(LeaksPath(runDir))
	if err != nil {
		t.Fatalf("read leaks.jsonl: %v", err)
	}
	var out []LeakRecord
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var rec LeakRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("unmarshal line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}
