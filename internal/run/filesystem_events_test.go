package run

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFilesystemEventsWriter_AppendsValidJSONL covers the writer's
// primary contract for Plan §6 Bucket 6: each Write call appends
// exactly one valid JSON object followed by a newline to
// filesystem-events.jsonl at the root of the run directory, every line
// round-trips back to a FilesystemEventRecord, every line carries the
// in-record _schema_version tag, and Close finalizes the file cleanly
// (subsequent Write fails, Close is idempotent). The test uses a real
// temp directory and the real JSON encoder/decoder — no mocks of the
// filesystem or encoding layers.
func TestFilesystemEventsWriter_AppendsValidJSONL(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	t1 := now
	t2 := now.Add(time.Second)
	t3 := now.Add(2 * time.Second)

	w, err := OpenFilesystemEventsWriter(dir.Path, FilesystemEventsWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(t1, t2, t3),
	})
	if err != nil {
		t.Fatalf("OpenFilesystemEventsWriter: %v", err)
	}

	// Exercise a representative mix: an MCP-gateway block on a path-
	// escape attempt, a shim exec-stage allow on an interpreter-via-
	// file scan, and an MCP-gateway warn on a list operation. All three
	// families share the FilesystemEventRecord struct so we catch
	// encoder regressions across the omitempty fields too.
	records := []FilesystemEventRecord{
		{
			Source:       FilesystemEventSourceMCPGateway,
			Operation:    FilesystemEventOpRead,
			Path:         "/etc/passwd",
			ResolvedPath: "/etc/passwd",
			Decision:     FilesystemEventDecisionBlock,
			Reason:       "filesystem path outside workspace",
			Server:       "filesystem",
			Tool:         "read_file",
			TurnID:       "turn_001",
		},
		{
			Source:    FilesystemEventSourceShim,
			Operation: FilesystemEventOpExec,
			Path:      "/workspace/script.py",
			Decision:  FilesystemEventDecisionAllow,
			Reason:    "interpreter-via-file content scan passed",
			Program:   "python3",
			Argv:      []string{"python3", "/workspace/script.py", "--flag"},
		},
		{
			Source:    FilesystemEventSourceMCPGateway,
			Operation: FilesystemEventOpList,
			Path:      "/workspace",
			Decision:  FilesystemEventDecisionWarn,
			Reason:    "server \"filesystem\" policy is warn",
			Server:    "filesystem",
			Tool:      "list_directory",
		},
	}

	for i, rec := range records {
		// The writer leaves the caller's Timestamp / RunID empty so it
		// can inject its own; passing empty values exercises the
		// fixed-clock fallback.
		if err := w.Write(rec); err != nil {
			t.Fatalf("Write(records[%d] source=%s op=%s): %v", i, rec.Source, rec.Operation, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close is idempotent per its contract.
	if err := w.Close(); err != nil {
		t.Fatalf("Close (second call): %v", err)
	}

	// Write after Close must fail loudly.
	if err := w.Write(FilesystemEventRecord{
		Source:    FilesystemEventSourceShim,
		Operation: FilesystemEventOpExec,
		Path:      "/x",
		Decision:  FilesystemEventDecisionAllow,
		Reason:    "x",
	}); err == nil {
		t.Fatalf("Write after Close: expected error, got nil")
	}

	// Verify the file lives where the plan requires (run dir root) and
	// the writer materialized real bytes there.
	path := filepath.Join(dir.Path, "filesystem-events.jsonl")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat %s: %v", path, err)
	}
	if info.Size() == 0 {
		t.Fatalf("filesystem-events.jsonl is empty; expected at least one record")
	}

	// Read the file back and round-trip each line through
	// json.Unmarshal into a fresh FilesystemEventRecord so we are
	// exercising real encoding/decoding, not mocks.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	expectedTimestamps := []string{
		t1.Format(time.RFC3339),
		t2.Format(time.RFC3339),
		t3.Format(time.RFC3339),
	}

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(lines) != len(records) {
		t.Fatalf("expected %d lines, got %d (lines=%v)", len(records), len(lines), lines)
	}

	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			t.Fatalf("line[%d] is empty", i)
		}
		var got FilesystemEventRecord
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("Unmarshal line[%d]=%q: %v", i, line, err)
		}
		if got.SchemaVersion != FilesystemEventsRecordSchemaVersion {
			t.Errorf("line[%d] SchemaVersion = %d, want %d", i, got.SchemaVersion, FilesystemEventsRecordSchemaVersion)
		}
		if got.Timestamp != expectedTimestamps[i] {
			t.Errorf("line[%d] Timestamp = %q, want %q", i, got.Timestamp, expectedTimestamps[i])
		}
		if got.RunID != dir.ID {
			t.Errorf("line[%d] RunID = %q, want %q", i, got.RunID, dir.ID)
		}
		if got.Source != records[i].Source {
			t.Errorf("line[%d] Source = %q, want %q", i, got.Source, records[i].Source)
		}
		if got.Operation != records[i].Operation {
			t.Errorf("line[%d] Operation = %q, want %q", i, got.Operation, records[i].Operation)
		}
		if got.Path != records[i].Path {
			t.Errorf("line[%d] Path = %q, want %q", i, got.Path, records[i].Path)
		}
		if got.Decision != records[i].Decision {
			t.Errorf("line[%d] Decision = %q, want %q", i, got.Decision, records[i].Decision)
		}
		if got.Reason != records[i].Reason {
			t.Errorf("line[%d] Reason = %q, want %q", i, got.Reason, records[i].Reason)
		}
		if got.Server != records[i].Server {
			t.Errorf("line[%d] Server = %q, want %q", i, got.Server, records[i].Server)
		}
		if got.Tool != records[i].Tool {
			t.Errorf("line[%d] Tool = %q, want %q", i, got.Tool, records[i].Tool)
		}
		if got.Program != records[i].Program {
			t.Errorf("line[%d] Program = %q, want %q", i, got.Program, records[i].Program)
		}
		if !equalStringSlice(got.Argv, records[i].Argv) {
			t.Errorf("line[%d] Argv = %v, want %v", i, got.Argv, records[i].Argv)
		}
		if got.ResolvedPath != records[i].ResolvedPath {
			t.Errorf("line[%d] ResolvedPath = %q, want %q", i, got.ResolvedPath, records[i].ResolvedPath)
		}
		if got.TurnID != records[i].TurnID {
			t.Errorf("line[%d] TurnID = %q, want %q", i, got.TurnID, records[i].TurnID)
		}
	}
}

// TestFilesystemEventsWriter_PreservesCallerTimestamp covers the
// contract that when the caller (the gateway / shim bridge) supplies its
// own Timestamp, the writer preserves it rather than stamping its own.
// The emitter is the authoritative source for decision-time timestamps;
// the writer's clock is only a fallback for direct-use callers (tests).
func TestFilesystemEventsWriter_PreservesCallerTimestamp(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	// The writer's own clock returns a different time; the test asserts
	// the caller-supplied Timestamp wins.
	writerClock := now.Add(time.Hour)
	emitterStamp := now.Add(5 * time.Second).Format(time.RFC3339)

	w, err := OpenFilesystemEventsWriter(dir.Path, FilesystemEventsWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(writerClock),
	})
	if err != nil {
		t.Fatalf("OpenFilesystemEventsWriter: %v", err)
	}
	defer w.Close()

	rec := FilesystemEventRecord{
		Timestamp: emitterStamp,
		Source:    FilesystemEventSourceMCPGateway,
		Operation: FilesystemEventOpRead,
		Path:      "/etc/hosts",
		Decision:  FilesystemEventDecisionBlock,
		Reason:    "filesystem path outside workspace",
		Server:    "filesystem",
		Tool:      "read_file",
	}
	if err := w.Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}

	records, err := ReadFilesystemEvents(dir.Path)
	if err != nil {
		t.Fatalf("ReadFilesystemEvents: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Timestamp != emitterStamp {
		t.Errorf("Timestamp = %q, want %q (caller-supplied stamp)", records[0].Timestamp, emitterStamp)
	}
}

// TestFilesystemEventsWriter_PreservesCallerRunID confirms that an
// emitter that pre-populates RunID gets its value preserved (mirroring
// the Timestamp passthrough). The supervisor may bind one writer per
// run but a future replay tool may want to forward another run's
// records, so the field is overrideable.
func TestFilesystemEventsWriter_PreservesCallerRunID(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	w, err := OpenFilesystemEventsWriter(dir.Path, FilesystemEventsWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenFilesystemEventsWriter: %v", err)
	}
	defer w.Close()

	const callerRunID = "20260530-080000-aaaaaa"
	rec := FilesystemEventRecord{
		RunID:     callerRunID,
		Source:    FilesystemEventSourceShim,
		Operation: FilesystemEventOpExec,
		Path:      "/workspace/run.sh",
		Decision:  FilesystemEventDecisionAllow,
		Reason:    "interpreter-via-file content scan passed",
		Program:   "sh",
	}
	if err := w.Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}

	records, err := ReadFilesystemEvents(dir.Path)
	if err != nil {
		t.Fatalf("ReadFilesystemEvents: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].RunID != callerRunID {
		t.Errorf("RunID = %q, want %q (caller-supplied)", records[0].RunID, callerRunID)
	}
}

// TestFilesystemEventsWriter_RejectsIncomplete enforces the "fail
// loudly" rules: an empty Source / Operation / Path / Decision / Reason
// should be rejected before the line lands on disk so a misconfigured
// caller does not silently produce an unidentifiable record.
func TestFilesystemEventsWriter_RejectsIncomplete(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenFilesystemEventsWriter(dir.Path, FilesystemEventsWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenFilesystemEventsWriter: %v", err)
	}
	defer w.Close()

	cases := []struct {
		name string
		rec  FilesystemEventRecord
	}{
		{
			name: "missing Source",
			rec: FilesystemEventRecord{
				Operation: FilesystemEventOpRead,
				Path:      "/x",
				Decision:  FilesystemEventDecisionAllow,
				Reason:    "ok",
			},
		},
		{
			name: "missing Operation",
			rec: FilesystemEventRecord{
				Source:   FilesystemEventSourceMCPGateway,
				Path:     "/x",
				Decision: FilesystemEventDecisionAllow,
				Reason:   "ok",
			},
		},
		{
			name: "missing Path",
			rec: FilesystemEventRecord{
				Source:    FilesystemEventSourceMCPGateway,
				Operation: FilesystemEventOpRead,
				Decision:  FilesystemEventDecisionAllow,
				Reason:    "ok",
			},
		},
		{
			name: "missing Decision",
			rec: FilesystemEventRecord{
				Source:    FilesystemEventSourceMCPGateway,
				Operation: FilesystemEventOpRead,
				Path:      "/x",
				Reason:    "ok",
			},
		},
		{
			name: "missing Reason",
			rec: FilesystemEventRecord{
				Source:    FilesystemEventSourceMCPGateway,
				Operation: FilesystemEventOpRead,
				Path:      "/x",
				Decision:  FilesystemEventDecisionAllow,
			},
		},
	}
	for _, c := range cases {
		if err := w.Write(c.rec); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

// TestOpenFilesystemEventsWriter_RejectsMissingOptions enforces that
// the constructor rejects an empty runDir / RunID so a misconfigured
// caller fails at construction rather than producing a record-less
// writer.
func TestOpenFilesystemEventsWriter_RejectsMissingOptions(t *testing.T) {
	if _, err := OpenFilesystemEventsWriter("", FilesystemEventsWriterOptions{RunID: "r"}); err == nil {
		t.Errorf("empty runDir: expected error, got nil")
	}
	if _, err := OpenFilesystemEventsWriter(t.TempDir(), FilesystemEventsWriterOptions{}); err == nil {
		t.Errorf("empty RunID: expected error, got nil")
	}
}

// TestFilesystemEventsWriter_AppendsToPlaceholder confirms the writer
// cooperates with the empty placeholder CreateRunDirectory leaves
// behind: opening the writer against a fresh run directory does not
// fail, and the first Write lands on disk without overwriting the
// placeholder.
func TestFilesystemEventsWriter_AppendsToPlaceholder(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	// Placeholder must exist after CreateRunDirectory.
	if _, err := os.Stat(FilesystemEventsPath(dir.Path)); err != nil {
		t.Fatalf("placeholder filesystem-events.jsonl missing: %v", err)
	}

	w, err := OpenFilesystemEventsWriter(dir.Path, FilesystemEventsWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenFilesystemEventsWriter: %v", err)
	}
	if err := w.Write(FilesystemEventRecord{
		Source:    FilesystemEventSourceMCPGateway,
		Operation: FilesystemEventOpRead,
		Path:      "/etc/passwd",
		Decision:  FilesystemEventDecisionBlock,
		Reason:    "filesystem path outside workspace",
		Server:    "filesystem",
		Tool:      "read_file",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	records, err := ReadFilesystemEvents(dir.Path)
	if err != nil {
		t.Fatalf("ReadFilesystemEvents: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].SchemaVersion != FilesystemEventsRecordSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", records[0].SchemaVersion, FilesystemEventsRecordSchemaVersion)
	}
}

// TestReadFilesystemEvents_EmptyAndMissing covers the read-side
// fallbacks: an absent file returns (nil, nil); an empty (placeholder)
// file returns (nil, nil).
func TestReadFilesystemEvents_EmptyAndMissing(t *testing.T) {
	// Missing file: ReadFilesystemEvents returns (nil, nil).
	tmp := t.TempDir()
	got, err := ReadFilesystemEvents(tmp)
	if err != nil {
		t.Fatalf("ReadFilesystemEvents(missing): %v", err)
	}
	if got != nil {
		t.Errorf("ReadFilesystemEvents(missing) = %v, want nil", got)
	}

	// Empty placeholder file: ReadFilesystemEvents returns (nil, nil).
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	got, err = ReadFilesystemEvents(dir.Path)
	if err != nil {
		t.Fatalf("ReadFilesystemEvents(placeholder): %v", err)
	}
	if got != nil {
		t.Errorf("ReadFilesystemEvents(placeholder) = %v, want nil", got)
	}
}

// TestReadFilesystemEvents_MissingRunDir covers the empty-runDir
// argument: an empty string is a programming error and must be loudly
// rejected rather than silently returning nil.
func TestReadFilesystemEvents_MissingRunDir(t *testing.T) {
	if _, err := ReadFilesystemEvents(""); err == nil {
		t.Errorf("ReadFilesystemEvents(\"\"): expected error, got nil")
	}
}

// TestFilesystemEventsPath_JoinsRunDir confirms the path helper joins
// runDir and the filename constant verbatim. The helper is the single
// place the layout is encoded; a future change to the file basename
// flows through this helper and the tests below.
func TestFilesystemEventsPath_JoinsRunDir(t *testing.T) {
	runDir := filepath.Join("a", "b", "c")
	got := FilesystemEventsPath(runDir)
	want := filepath.Join(runDir, "filesystem-events.jsonl")
	if got != want {
		t.Errorf("FilesystemEventsPath = %q, want %q", got, want)
	}
}

// TestFilesystemEventsWriter_SchemaVersionAlwaysStamped pins the
// in-record _schema_version contract: even when the caller supplies a
// SchemaVersion of 0 (the zero value) or a stale version from a
// downgrade scenario, the writer stamps the current constant. The
// reader is allowed to refuse SchemaVersion > the constant, so
// preserving caller-supplied versions would be a footgun.
func TestFilesystemEventsWriter_SchemaVersionAlwaysStamped(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenFilesystemEventsWriter(dir.Path, FilesystemEventsWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now, now.Add(time.Second)),
	})
	if err != nil {
		t.Fatalf("OpenFilesystemEventsWriter: %v", err)
	}
	defer w.Close()

	// Caller passes SchemaVersion == 0 (zero value).
	if err := w.Write(FilesystemEventRecord{
		Source:    FilesystemEventSourceShim,
		Operation: FilesystemEventOpExec,
		Path:      "/workspace/a.sh",
		Decision:  FilesystemEventDecisionAllow,
		Reason:    "ok",
		Program:   "sh",
	}); err != nil {
		t.Fatalf("Write (zero schema): %v", err)
	}
	// Caller passes a stale SchemaVersion (e.g. a downgraded emitter);
	// writer must overwrite with the current constant.
	if err := w.Write(FilesystemEventRecord{
		SchemaVersion: 99,
		Source:        FilesystemEventSourceShim,
		Operation:     FilesystemEventOpExec,
		Path:          "/workspace/b.sh",
		Decision:      FilesystemEventDecisionAllow,
		Reason:        "ok",
		Program:       "sh",
	}); err != nil {
		t.Fatalf("Write (stale schema): %v", err)
	}

	records, err := ReadFilesystemEvents(dir.Path)
	if err != nil {
		t.Fatalf("ReadFilesystemEvents: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	for i, rec := range records {
		if rec.SchemaVersion != FilesystemEventsRecordSchemaVersion {
			t.Errorf("records[%d] SchemaVersion = %d, want %d", i, rec.SchemaVersion, FilesystemEventsRecordSchemaVersion)
		}
	}
}

// TestFilesystemEvents_NotInCurrentSchemaVersions enforces the Plan §0
// contract that filesystem-events.jsonl (one of the three new streams
// alongside leaks.jsonl and transcript.jsonl) carries its schema
// version in-record rather than via Record.SchemaVersions. Adding it
// to CurrentSchemaVersions would surface a duplicate source of truth a
// future bump could drift across, exactly the regression record.go's
// docstring warns against.
func TestFilesystemEvents_NotInCurrentSchemaVersions(t *testing.T) {
	versions := CurrentSchemaVersions()
	if _, present := versions["filesystem-events"]; present {
		t.Errorf("CurrentSchemaVersions must not include \"filesystem-events\"; got %v", versions)
	}
}
