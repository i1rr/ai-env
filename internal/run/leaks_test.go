package run

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newRunDirForLeaks builds a real run directory and returns its path
// plus the supplied clock-fixed instant so subtests can pin
// timestamps for deterministic on-disk content.
func newRunDirForLeaks(t *testing.T) (RunDirectory, time.Time) {
	t.Helper()
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-a1b2c3"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return dir, now
}

// TestCreateRunDirectory_ChmodsRunDirTo0700 pins the Batch 0.2
// requirement: CreateRunDirectory ends with chmod runDir 0700 so the
// per-run control socket, MCP server-token registry, and proxy logs
// are inaccessible to any other host user.
func TestCreateRunDirectory_ChmodsRunDirTo0700(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)
	st, err := os.Stat(dir.Path)
	if err != nil {
		t.Fatalf("stat run dir: %v", err)
	}
	if got := st.Mode().Perm(); got != 0o700 {
		t.Errorf("run dir mode = %o, want 0o700", got)
	}
}

// TestRunDirectory_IncludesLeaksAndTranscriptPlaceholders asserts the
// two new per-run files Batch 0.2 adds to the directory layout land
// as empty placeholders alongside the existing streams. The exact
// list is asserted by TestCreateRunDirectory_PopulatesLayout
// (run_test.go); this is the focused regression for Plan §0.2.
func TestRunDirectory_IncludesLeaksAndTranscriptPlaceholders(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)
	for _, name := range []string{"leaks.jsonl", "transcript.jsonl"} {
		st, err := os.Stat(filepath.Join(dir.Path, name))
		if err != nil {
			t.Errorf("expected %s placeholder: %v", name, err)
			continue
		}
		if st.Size() != 0 {
			t.Errorf("%s should start empty, got %d bytes", name, st.Size())
		}
	}
}

// TestRecord_SchemaVersionsWrittenAtSnapshot verifies the
// Plan §0 Schema-version contract: every Record snapshot carries the
// schema_versions map for every existing per-subsystem stream so
// mid-run readers see the per-stream versions immediately.
func TestRecord_SchemaVersionsWrittenAtSnapshot(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)
	rec := fullExampleRecord(dir.ID)
	rec.SchemaVersions = CurrentSchemaVersions()

	if err := WriteRecord(dir.Path, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	got, err := ReadRecord(dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	want := CurrentSchemaVersions()
	if len(got.SchemaVersions) != len(want) {
		t.Fatalf("SchemaVersions size = %d, want %d (got=%v)", len(got.SchemaVersions), len(want), got.SchemaVersions)
	}
	for k, v := range want {
		if got.SchemaVersions[k] != v {
			t.Errorf("SchemaVersions[%q] = %d, want %d", k, got.SchemaVersions[k], v)
		}
	}
}

// TestCurrentSchemaVersions_StableKeys pins the per-stream key set in
// the schema_versions map. A new entry is a deliberate schema event;
// dropping one is a regression that breaks readers.
func TestCurrentSchemaVersions_StableKeys(t *testing.T) {
	want := []string{
		"lifecycle",
		"network-events",
		"shell-commands",
		"policy-decisions",
		"mcp-calls",
	}
	got := CurrentSchemaVersions()
	if len(got) != len(want) {
		t.Fatalf("CurrentSchemaVersions size = %d, want %d (got=%v)", len(got), len(want), got)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in CurrentSchemaVersions", k)
		}
		if got[k] != 1 {
			t.Errorf("CurrentSchemaVersions[%q] = %d, want 1 (v0.1)", k, got[k])
		}
	}
}

// TestLeaksWriter_WriteAndRenameProducesAtomicJSONL stages a short
// sequence of LeakRecords through the writer, closes it, and asserts
// the rendered leaks.jsonl contains one well-formed JSON object per
// line with the expected SchemaVersion / RunID / Source / Verb
// pre-filled by the writer.
func TestLeaksWriter_WriteAndRenameProducesAtomicJSONL(t *testing.T) {
	dir, now := newRunDirForLeaks(t)
	w, err := OpenLeaksWriter(dir.Path, LeaksWriterOptions{
		RunID: dir.ID,
		Now:   func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("OpenLeaksWriter: %v", err)
	}

	recs := []LeakRecord{
		{
			Source:        LeakSourceLifecycle,
			SourceLine:    1,
			Vector:        4,
			Verb:          "gateway_secret_blocked",
			PolicyEventID: "pe-001",
			Evidence: LeakEvidence{
				Pattern:   "Anthropic sk-ant- prefix",
				FindingID: "finding_001",
				Snippet:   "value=sk-ant-aaaaaaaaaaaaaaaaaaaaaaaa",
				Detail:    "blocked outbound request",
			},
		},
		{
			Source:     LeakSourcePolicyDecisions,
			SourceLine: 7,
			Vector:     7,
			Verb:       "shell_block",
			Evidence: LeakEvidence{
				Detail: "interpreter via file",
				Extra: map[string]string{
					"argv0": "bash",
					"note":  "trace: x-api-key: super-secret-value",
				},
			},
		},
	}
	for i, rec := range recs {
		if err := w.Write(rec); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The tmp file must be gone after a successful Close (the
	// rename consumed it). The final leaks.jsonl must exist.
	if _, err := os.Stat(w.TmpPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("tmp file should be gone after Close: stat = %v", err)
	}
	finalPath := LeaksPath(dir.Path)
	raw, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read leaks.jsonl: %v", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	var seen []LeakRecord
	for scanner.Scan() {
		var rec LeakRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("parse leaks line %q: %v", scanner.Text(), err)
		}
		seen = append(seen, rec)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}
	if len(seen) != len(recs) {
		t.Fatalf("seen %d records, want %d", len(seen), len(recs))
	}
	for i, rec := range seen {
		if rec.SchemaVersion != LeaksRecordSchemaVersion {
			t.Errorf("seen[%d].SchemaVersion = %d, want %d", i, rec.SchemaVersion, LeaksRecordSchemaVersion)
		}
		if rec.RunID != dir.ID {
			t.Errorf("seen[%d].RunID = %q, want %q", i, rec.RunID, dir.ID)
		}
		if rec.Timestamp == "" {
			t.Errorf("seen[%d].Timestamp is empty; writer should fill it in", i)
		}
	}
}

// TestLeaksWriter_RedactsEveryStringField pins the Plan §0.2
// invariant: Write redacts every non-empty string field on the
// record (and on the nested LeakEvidence + Extra map) so a leaked
// token surfacing in a captured snippet cannot land on disk.
func TestLeaksWriter_RedactsEveryStringField(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)
	w, err := OpenLeaksWriter(dir.Path, LeaksWriterOptions{RunID: dir.ID})
	if err != nil {
		t.Fatalf("OpenLeaksWriter: %v", err)
	}
	rec := LeakRecord{
		Source:     LeakSourceMCPCalls,
		SourceLine: 2,
		Verb:       "gateway_secret_response",
		// Anthropic-style token in nested evidence; broadened
		// secretPatterns should scrub it.
		Evidence: LeakEvidence{
			Pattern:   "Anthropic sk-ant- prefix",
			FindingID: "finding_002",
			Snippet:   "leaked sk-ant-abcdefghij0123456789xyz!",
			Detail:    "Authorization: Bearer leaked-token-value",
			Extra: map[string]string{
				"value": "ghp_abcdefghij0123456789ABCDEFGHIJxyz",
			},
		},
	}
	if err := w.Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(LeaksPath(dir.Path))
	if err != nil {
		t.Fatalf("read leaks.jsonl: %v", err)
	}
	text := string(raw)
	// None of the original token substrings may appear on disk.
	for _, needle := range []string{
		"sk-ant-abcdefghij0123456789xyz",
		"ghp_abcdefghij0123456789ABCDEFGHIJxyz",
		"Authorization: Bearer leaked-token-value",
	} {
		if strings.Contains(text, needle) {
			t.Errorf("leaks.jsonl leaks token substring %q; raw=%q", needle, text)
		}
	}
	// REDACTED is the expected sentinel; at least one match means
	// the redactor ran.
	if !strings.Contains(text, "REDACTED") {
		t.Errorf("expected REDACTED sentinel in leaks.jsonl; raw=%q", text)
	}
}

// TestLeaksWriter_RejectsWriteWithoutSource pins the dedup
// invariant: a record with no source identifier cannot land on disk
// because the dedup key (source_stream, source_line, ...) would
// collapse against unrelated records.
func TestLeaksWriter_RejectsWriteWithoutSource(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)
	w, err := OpenLeaksWriter(dir.Path, LeaksWriterOptions{RunID: dir.ID})
	if err != nil {
		t.Fatalf("OpenLeaksWriter: %v", err)
	}
	defer func() { _ = w.Abort() }()

	if err := w.Write(LeakRecord{Verb: "stranger"}); err == nil {
		t.Fatal("expected error on Write with empty Source, got nil")
	}
}

// TestLeaksWriter_AbortLeavesPreviousFileIntact verifies that calling
// Abort instead of Close discards the tmp file and does not stomp an
// existing leaks.jsonl. Used by the supervisor's panic-recovery path.
func TestLeaksWriter_AbortLeavesPreviousFileIntact(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)
	previous := []byte(`{"_schema_version":1,"timestamp":"prior","run_id":"prior","source_stream":"lifecycle","source_line":1}` + "\n")
	if err := os.WriteFile(LeaksPath(dir.Path), previous, 0o644); err != nil {
		t.Fatalf("seed previous leaks.jsonl: %v", err)
	}

	w, err := OpenLeaksWriter(dir.Path, LeaksWriterOptions{RunID: dir.ID})
	if err != nil {
		t.Fatalf("OpenLeaksWriter: %v", err)
	}
	if err := w.Write(LeakRecord{Source: LeakSourceLifecycle, SourceLine: 99}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if _, err := os.Stat(w.TmpPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("tmp file should be gone after Abort: stat = %v", err)
	}
	raw, err := os.ReadFile(LeaksPath(dir.Path))
	if err != nil {
		t.Fatalf("read leaks.jsonl after abort: %v", err)
	}
	if !bytes.Equal(raw, previous) {
		t.Errorf("Abort stomped previous leaks.jsonl: got %q want %q", string(raw), string(previous))
	}
}

// TestLeaksWriter_TmpFileExclusiveCreate verifies the Plan §0.2
// invariant: the staged tmp file is created with O_EXCL so a stale
// tmp from a crashed run cannot be silently truncated. Two writers
// constructed with the same deterministic random source compute the
// same tmp path; the second open must fail with a clear error rather
// than silently inheriting (or clobbering) the first writer's bytes.
func TestLeaksWriter_TmpFileExclusiveCreate(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)

	w1, err := OpenLeaksWriter(dir.Path, LeaksWriterOptions{
		RunID:        dir.ID,
		RandomReader: &deterministicReader{seed: 0x42},
	})
	if err != nil {
		t.Fatalf("OpenLeaksWriter first: %v", err)
	}
	defer func() { _ = w1.Abort() }()

	// Second writer with the same seed computes the same tmp path.
	// O_EXCL must reject the open with a clear error rather than
	// silently sharing the file with the first writer.
	w2, err := OpenLeaksWriter(dir.Path, LeaksWriterOptions{
		RunID:        dir.ID,
		RandomReader: &deterministicReader{seed: 0x42},
	})
	if err == nil {
		_ = w2.Abort()
		t.Fatal("expected O_EXCL collision error, got nil")
	}
	if !strings.Contains(err.Error(), "leaks tmp") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

// deterministicReader yields a constant byte sequence so OpenLeaksWriter's
// tmp suffix is reproducible. Test-only: production callers leave
// LeaksWriterOptions.RandomReader nil and the writer reaches for
// crypto/rand.Reader.
type deterministicReader struct{ seed byte }

func (d *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = d.seed
	}
	return len(p), nil
}

// TestCleanupStaleLeaksTemp_RemovesOlderTmps creates two tmp files,
// stamps one before the cutoff and one after, and asserts only the
// older one is removed. The supervisor calls this at run start so a
// tmp from a crashed previous run does not block fresh O_EXCL opens.
func TestCleanupStaleLeaksTemp_RemovesOlderTmps(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)

	older := filepath.Join(dir.Path, leaksTmpPrefix+"111.aaaaaa")
	newer := filepath.Join(dir.Path, leaksTmpPrefix+"222.bbbbbb")
	for _, p := range []string{older, newer} {
		if err := os.WriteFile(p, []byte("stale"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	// Backdate the older file by a minute.
	past := time.Now().Add(-time.Minute)
	if err := os.Chtimes(older, past, past); err != nil {
		t.Fatalf("chtimes older: %v", err)
	}

	removed, err := CleanupStaleLeaksTemp(dir.Path, time.Now().Add(-30*time.Second))
	if err != nil {
		t.Fatalf("CleanupStaleLeaksTemp: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("removed %d files, want 1: %v", len(removed), removed)
	}
	if removed[0] != older {
		t.Errorf("removed = %q, want %q", removed[0], older)
	}
	if _, err := os.Stat(older); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("older tmp should be gone: stat = %v", err)
	}
	if _, err := os.Stat(newer); err != nil {
		t.Errorf("newer tmp should be preserved: stat = %v", err)
	}
}

// TestCleanupStaleLeaksTemp_IgnoresNonTmpFiles guards against the
// helper accidentally widening its glob: only files whose basename
// starts with `leaks.jsonl.tmp.` are eligible for removal.
func TestCleanupStaleLeaksTemp_IgnoresNonTmpFiles(t *testing.T) {
	dir, _ := newRunDirForLeaks(t)

	keep := filepath.Join(dir.Path, "run.json")
	// Ensure it exists from the placeholder.
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := CleanupStaleLeaksTemp(dir.Path, time.Time{}); err != nil {
		t.Fatalf("CleanupStaleLeaksTemp: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("CleanupStaleLeaksTemp should not have removed %s: %v", keep, err)
	}
}

// TestCleanupStaleLeaksTemp_MissingRunDirReturnsNil verifies the
// helper's tolerance for a missing runDir so the supervisor's start
// sweep does not abort on a freshly minted run that has not yet
// materialized any tmp files.
func TestCleanupStaleLeaksTemp_MissingRunDirReturnsNil(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	removed, err := CleanupStaleLeaksTemp(missing, time.Time{})
	if err != nil {
		t.Errorf("expected nil error for missing dir, got %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("expected no removed entries, got %v", removed)
	}
}
