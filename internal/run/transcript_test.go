package run

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTranscriptWriter_AppendsValidJSONL covers the writer's primary
// contract for Plan §7 Bucket 8: each Write call appends exactly one
// valid JSON object followed by a newline to transcript.jsonl at the
// root of the run directory, every line round-trips back to a
// TranscriptRecord, every line carries the in-record _schema_version
// tag, and Close finalizes the file cleanly (subsequent Write fails,
// Close is idempotent). The test uses a real temp directory and the
// real JSON encoder/decoder — no mocks of the filesystem or encoding
// layers.
func TestTranscriptWriter_AppendsValidJSONL(t *testing.T) {
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

	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(t1, t2, t3),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}

	// Exercise a representative mix: a user prompt, an assistant
	// reply, and a tool_use record carrying Args. All three share the
	// TranscriptRecord struct so we catch encoder regressions across
	// the omitempty fields too.
	records := []TranscriptRecord{
		{
			CLI:    TranscriptCLIClaude,
			Kind:   TranscriptKindUser,
			Role:   "user",
			Text:   "list files",
			TurnID: "t-agent-1",
			Seq:    1,
		},
		{
			CLI:    TranscriptCLIClaude,
			Kind:   TranscriptKindAssistant,
			Role:   "assistant",
			Text:   "I will use the filesystem tool.",
			TurnID: "t-agent-1",
			Seq:    2,
		},
		{
			CLI:    TranscriptCLIClaude,
			Kind:   TranscriptKindToolUse,
			Tool:   "list_directory",
			Args:   `{"path":"/workspace"}`,
			TurnID: "t-agent-1",
			Seq:    3,
		},
	}

	for i, rec := range records {
		if err := w.Write(rec); err != nil {
			t.Fatalf("Write(records[%d] kind=%s): %v", i, rec.Kind, err)
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
	if err := w.Write(TranscriptRecord{
		CLI:  TranscriptCLIClaude,
		Kind: TranscriptKindUser,
	}); err == nil {
		t.Fatalf("Write after Close: expected error, got nil")
	}

	// Verify the file lives where the plan requires (run dir root)
	// and the writer materialized real bytes there.
	path := filepath.Join(dir.Path, "transcript.jsonl")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat %s: %v", path, err)
	}
	if info.Size() == 0 {
		t.Fatalf("transcript.jsonl is empty; expected at least one record")
	}

	// Read the file back and round-trip each line through
	// json.Unmarshal into a fresh TranscriptRecord.
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
		var got TranscriptRecord
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("Unmarshal line[%d]=%q: %v", i, line, err)
		}
		if got.SchemaVersion != TranscriptRecordSchemaVersion {
			t.Errorf("line[%d] SchemaVersion = %d, want %d", i, got.SchemaVersion, TranscriptRecordSchemaVersion)
		}
		if got.Timestamp != expectedTimestamps[i] {
			t.Errorf("line[%d] Timestamp = %q, want %q", i, got.Timestamp, expectedTimestamps[i])
		}
		if got.RunID != dir.ID {
			t.Errorf("line[%d] RunID = %q, want %q", i, got.RunID, dir.ID)
		}
		if got.CLI != records[i].CLI {
			t.Errorf("line[%d] CLI = %q, want %q", i, got.CLI, records[i].CLI)
		}
		if got.Kind != records[i].Kind {
			t.Errorf("line[%d] Kind = %q, want %q", i, got.Kind, records[i].Kind)
		}
		if got.Text != records[i].Text {
			t.Errorf("line[%d] Text = %q, want %q", i, got.Text, records[i].Text)
		}
		if got.Tool != records[i].Tool {
			t.Errorf("line[%d] Tool = %q, want %q", i, got.Tool, records[i].Tool)
		}
		if got.Args != records[i].Args {
			t.Errorf("line[%d] Args = %q, want %q", i, got.Args, records[i].Args)
		}
		if got.TurnID != records[i].TurnID {
			t.Errorf("line[%d] TurnID = %q, want %q", i, got.TurnID, records[i].TurnID)
		}
		if got.Seq != records[i].Seq {
			t.Errorf("line[%d] Seq = %d, want %d", i, got.Seq, records[i].Seq)
		}
	}
}

// TestTranscriptWriter_PreservesCallerTimestamp confirms that an
// emitter-supplied Timestamp wins over the writer's clock fallback.
// The per-CLI parser stamps the line-read time before forwarding;
// preserving it keeps the on-disk timestamp matched to the line
// rather than the append.
func TestTranscriptWriter_PreservesCallerTimestamp(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	writerClock := now.Add(time.Hour)
	emitterStamp := now.Add(5 * time.Second).Format(time.RFC3339)

	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(writerClock),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}
	defer w.Close()

	rec := TranscriptRecord{
		Timestamp: emitterStamp,
		CLI:       TranscriptCLICodex,
		Kind:      TranscriptKindAssistant,
		Role:      "assistant",
		Text:      "hello",
	}
	if err := w.Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}

	records, err := ReadTranscript(dir.Path)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Timestamp != emitterStamp {
		t.Errorf("Timestamp = %q, want %q", records[0].Timestamp, emitterStamp)
	}
}

// TestTranscriptWriter_RejectsIncomplete enforces the "fail loudly"
// rule: an empty CLI or Kind must be rejected before the line lands
// on disk so a misconfigured caller does not silently produce an
// unidentifiable record.
func TestTranscriptWriter_RejectsIncomplete(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}
	defer w.Close()

	cases := []struct {
		name string
		rec  TranscriptRecord
	}{
		{name: "missing CLI", rec: TranscriptRecord{Kind: TranscriptKindUser}},
		{name: "missing Kind", rec: TranscriptRecord{CLI: TranscriptCLIClaude}},
	}
	for _, c := range cases {
		if err := w.Write(c.rec); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

// TestOpenTranscriptWriter_RejectsMissingOptions enforces that the
// constructor rejects an empty runDir / RunID so a misconfigured
// caller fails at construction rather than producing a record-less
// writer.
func TestOpenTranscriptWriter_RejectsMissingOptions(t *testing.T) {
	if _, err := OpenTranscriptWriter("", TranscriptWriterOptions{RunID: "r"}); err == nil {
		t.Errorf("empty runDir: expected error, got nil")
	}
	if _, err := OpenTranscriptWriter(t.TempDir(), TranscriptWriterOptions{}); err == nil {
		t.Errorf("empty RunID: expected error, got nil")
	}
}

// TestTranscriptWriter_AppendsToPlaceholder confirms the writer
// cooperates with the empty placeholder CreateRunDirectory leaves
// behind: opening the writer against a fresh run directory does not
// fail, and the first Write lands on disk without overwriting the
// placeholder.
func TestTranscriptWriter_AppendsToPlaceholder(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	if _, err := os.Stat(TranscriptPath(dir.Path)); err != nil {
		t.Fatalf("placeholder transcript.jsonl missing: %v", err)
	}
	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}
	if err := w.Write(TranscriptRecord{
		CLI:  TranscriptCLIClaude,
		Kind: TranscriptKindUser,
		Role: "user",
		Text: "hi",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	records, err := ReadTranscript(dir.Path)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].SchemaVersion != TranscriptRecordSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", records[0].SchemaVersion, TranscriptRecordSchemaVersion)
	}
}

// TestReadTranscript_EmptyAndMissing covers the read-side fallbacks:
// an absent file returns (nil, nil); an empty (placeholder) file
// returns (nil, nil).
func TestReadTranscript_EmptyAndMissing(t *testing.T) {
	tmp := t.TempDir()
	got, err := ReadTranscript(tmp)
	if err != nil {
		t.Fatalf("ReadTranscript(missing): %v", err)
	}
	if got != nil {
		t.Errorf("ReadTranscript(missing) = %v, want nil", got)
	}
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	got, err = ReadTranscript(dir.Path)
	if err != nil {
		t.Fatalf("ReadTranscript(placeholder): %v", err)
	}
	if got != nil {
		t.Errorf("ReadTranscript(placeholder) = %v, want nil", got)
	}
}

// TestReadTranscript_MissingRunDir covers the empty-runDir argument:
// an empty string is a programming error and must be loudly rejected.
func TestReadTranscript_MissingRunDir(t *testing.T) {
	if _, err := ReadTranscript(""); err == nil {
		t.Errorf("ReadTranscript(\"\"): expected error, got nil")
	}
}

// TestTranscriptPath_JoinsRunDir confirms the path helper joins
// runDir and the filename constant verbatim. The helper is the
// single place the layout is encoded.
func TestTranscriptPath_JoinsRunDir(t *testing.T) {
	runDir := filepath.Join("a", "b", "c")
	got := TranscriptPath(runDir)
	want := filepath.Join(runDir, "transcript.jsonl")
	if got != want {
		t.Errorf("TranscriptPath = %q, want %q", got, want)
	}
}

// TestTranscriptWriter_SchemaVersionAlwaysStamped pins the in-record
// _schema_version contract: even when the caller supplies a
// SchemaVersion of 0 (the zero value) or a stale version from a
// downgrade scenario, the writer stamps the current constant.
func TestTranscriptWriter_SchemaVersionAlwaysStamped(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now, now.Add(time.Second)),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}
	defer w.Close()

	if err := w.Write(TranscriptRecord{CLI: TranscriptCLIClaude, Kind: TranscriptKindUser}); err != nil {
		t.Fatalf("Write (zero schema): %v", err)
	}
	if err := w.Write(TranscriptRecord{SchemaVersion: 99, CLI: TranscriptCLIClaude, Kind: TranscriptKindUser}); err != nil {
		t.Fatalf("Write (stale schema): %v", err)
	}

	records, err := ReadTranscript(dir.Path)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	for i, rec := range records {
		if rec.SchemaVersion != TranscriptRecordSchemaVersion {
			t.Errorf("records[%d] SchemaVersion = %d, want %d", i, rec.SchemaVersion, TranscriptRecordSchemaVersion)
		}
	}
}

// TestTranscript_NotInCurrentSchemaVersions enforces the Plan §0
// contract that transcript.jsonl (one of the three new streams
// alongside leaks.jsonl and filesystem-events.jsonl) carries its
// schema version in-record rather than via Record.SchemaVersions.
func TestTranscript_NotInCurrentSchemaVersions(t *testing.T) {
	versions := CurrentSchemaVersions()
	if _, present := versions["transcript"]; present {
		t.Errorf("CurrentSchemaVersions must not include \"transcript\"; got %v", versions)
	}
}

// fixedTurnSource is a TranscriptTurnSource fake the parser tests use
// to assert correlation. Returns the configured turn id verbatim; the
// role argument is ignored (the parser uses one role per call).
type fixedTurnSource string

func (f fixedTurnSource) CurrentTurnID(role string) string {
	return string(f)
}

// TestParseClaude_ProjectsCommonFrames asserts the Claude stream-json
// projection against a representative sample of frame types: a
// "system" init frame, a "user" prompt, an "assistant" message with a
// plain text content block, an "assistant" tool_use frame, a "user"
// tool_result frame, and a terminal "result" frame. Every record
// must carry CLI=claude, the configured turn id, a monotonic Seq, and
// the projected Kind / Role / Text / Tool / Args.
func TestParseClaude_ProjectsCommonFrames(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}
	defer w.Close()

	frames := []string{
		`{"type":"system","message":{"content":"You are Claude."}}`,
		`{"type":"user","message":{"id":"u1","role":"user","content":"list files"}}`,
		`{"type":"assistant","message":{"id":"a1","role":"assistant","content":[{"type":"text","text":"Sure, I will list files."}]}}`,
		`{"type":"assistant","message":{"id":"a2","role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"list_directory","input":{"path":"/workspace"}}]}}`,
		`{"type":"user","message":{"id":"u2","role":"user","content":[{"type":"tool_result","id":"tu1","content":"file1.txt\nfile2.txt"}]}}`,
		`{"type":"result","subtype":"success","reason":"done"}`,
	}
	input := strings.Join(frames, "\n") + "\n"

	if err := ParseClaude(strings.NewReader(input), w, TranscriptParserOptions{
		TurnSource: fixedTurnSource("t-agent-1"),
		Now:        fixedTimes(now),
	}); err != nil {
		t.Fatalf("ParseClaude: %v", err)
	}

	records, err := ReadTranscript(dir.Path)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(records) != len(frames) {
		t.Fatalf("expected %d records, got %d", len(frames), len(records))
	}

	want := []struct {
		kind  string
		role  string
		text  string
		tool  string
		args  string
		seq   int
		msgID string
	}{
		{kind: TranscriptKindSystem, role: "system", text: "You are Claude.", seq: 1},
		{kind: TranscriptKindUser, role: "user", text: "list files", seq: 2, msgID: "u1"},
		{kind: TranscriptKindAssistant, role: "assistant", text: "Sure, I will list files.", seq: 3, msgID: "a1"},
		{kind: TranscriptKindToolUse, tool: "list_directory", args: `{"path":"/workspace"}`, seq: 4, msgID: "tu1"},
		{kind: TranscriptKindToolResult, tool: "", text: "file1.txt\nfile2.txt", seq: 5, msgID: "tu1"},
		{kind: TranscriptKindResult, seq: 6},
	}
	for i, rec := range records {
		if rec.CLI != TranscriptCLIClaude {
			t.Errorf("records[%d] CLI = %q, want %q", i, rec.CLI, TranscriptCLIClaude)
		}
		if rec.TurnID != "t-agent-1" {
			t.Errorf("records[%d] TurnID = %q, want %q", i, rec.TurnID, "t-agent-1")
		}
		if rec.Kind != want[i].kind {
			t.Errorf("records[%d] Kind = %q, want %q", i, rec.Kind, want[i].kind)
		}
		if rec.Role != want[i].role {
			t.Errorf("records[%d] Role = %q, want %q", i, rec.Role, want[i].role)
		}
		if rec.Text != want[i].text {
			t.Errorf("records[%d] Text = %q, want %q", i, rec.Text, want[i].text)
		}
		if rec.Tool != want[i].tool {
			t.Errorf("records[%d] Tool = %q, want %q", i, rec.Tool, want[i].tool)
		}
		if rec.Seq != want[i].seq {
			t.Errorf("records[%d] Seq = %d, want %d", i, rec.Seq, want[i].seq)
		}
		if want[i].msgID != "" && rec.MessageID != want[i].msgID {
			t.Errorf("records[%d] MessageID = %q, want %q", i, rec.MessageID, want[i].msgID)
		}
		if want[i].args != "" {
			// JSON re-marshal may reorder keys; assert it parses and
			// carries the same "path" value rather than byte equality.
			var got map[string]interface{}
			if err := json.Unmarshal([]byte(rec.Args), &got); err != nil {
				t.Errorf("records[%d] Args not JSON: %v", i, err)
			} else if got["path"] != "/workspace" {
				t.Errorf("records[%d] Args path = %v, want /workspace", i, got["path"])
			}
		}
	}
}

// TestParseCodex_ProjectsCommonFrames asserts the Codex --json
// projection across its frame vocabulary: session_start, user_message,
// agent_message, tool_call, tool_result, shutdown, and an error frame.
func TestParseCodex_ProjectsCommonFrames(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}
	defer w.Close()

	frames := []string{
		`{"type":"session_start","id":"s1","message":"Codex ready"}`,
		`{"type":"user_message","id":"u1","message":"refactor file.go"}`,
		`{"type":"agent_message","id":"a1","message":"I will read the file."}`,
		`{"type":"tool_call","id":"tc1","tool":"read_file","args":{"path":"file.go"}}`,
		`{"type":"tool_result","id":"tc1","tool":"read_file","output":"package foo"}`,
		`{"type":"error","error":"context canceled"}`,
		`{"type":"shutdown","reason":"complete"}`,
	}
	input := strings.Join(frames, "\n") + "\n"

	if err := ParseCodex(strings.NewReader(input), w, TranscriptParserOptions{
		TurnSource: fixedTurnSource("t-agent-2"),
		Now:        fixedTimes(now),
	}); err != nil {
		t.Fatalf("ParseCodex: %v", err)
	}

	records, err := ReadTranscript(dir.Path)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(records) != len(frames) {
		t.Fatalf("expected %d records, got %d", len(frames), len(records))
	}

	want := []struct {
		kind   string
		role   string
		text   string
		tool   string
		reason string
		seq    int
	}{
		{kind: TranscriptKindSystem, role: "system", text: "Codex ready", seq: 1},
		{kind: TranscriptKindUser, role: "user", text: "refactor file.go", seq: 2},
		{kind: TranscriptKindAssistant, role: "assistant", text: "I will read the file.", seq: 3},
		{kind: TranscriptKindToolUse, tool: "read_file", seq: 4},
		{kind: TranscriptKindToolResult, tool: "read_file", text: "package foo", seq: 5},
		{kind: TranscriptKindError, reason: "context canceled", seq: 6},
		{kind: TranscriptKindResult, reason: "complete", seq: 7},
	}
	for i, rec := range records {
		if rec.CLI != TranscriptCLICodex {
			t.Errorf("records[%d] CLI = %q, want %q", i, rec.CLI, TranscriptCLICodex)
		}
		if rec.TurnID != "t-agent-2" {
			t.Errorf("records[%d] TurnID = %q, want %q", i, rec.TurnID, "t-agent-2")
		}
		if rec.Kind != want[i].kind {
			t.Errorf("records[%d] Kind = %q, want %q", i, rec.Kind, want[i].kind)
		}
		if rec.Role != want[i].role {
			t.Errorf("records[%d] Role = %q, want %q", i, rec.Role, want[i].role)
		}
		if rec.Text != want[i].text {
			t.Errorf("records[%d] Text = %q, want %q", i, rec.Text, want[i].text)
		}
		if rec.Tool != want[i].tool {
			t.Errorf("records[%d] Tool = %q, want %q", i, rec.Tool, want[i].tool)
		}
		if rec.Reason != want[i].reason {
			t.Errorf("records[%d] Reason = %q, want %q", i, rec.Reason, want[i].reason)
		}
		if rec.Seq != want[i].seq {
			t.Errorf("records[%d] Seq = %d, want %d", i, rec.Seq, want[i].seq)
		}
	}
}

// errorSinkRecorder is a TranscriptParserErrorSink that records every
// Emit call so tests can assert on the metadata. Mirrors the
// per-error de-dup contract: the parser fires at most once per reason,
// so a flood of malformed lines should surface as exactly one entry
// per reason.
type errorSinkRecorder struct {
	mu      sync.Mutex
	entries []map[string]string
}

func (r *errorSinkRecorder) Emit(metadata map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make(map[string]string, len(metadata))
	for k, v := range metadata {
		cp[k] = v
	}
	r.entries = append(r.entries, cp)
	return nil
}

func (r *errorSinkRecorder) snapshot() []map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]map[string]string, len(r.entries))
	copy(out, r.entries)
	return out
}

// TestParseClaude_AdvisoryJSONError verifies the json_parse advisory
// path: a malformed line surfaces as exactly one
// LifecycleVerbTranscriptParserError event with reason=json_parse, and
// the surrounding valid lines still produce records.
func TestParseClaude_AdvisoryJSONError(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}
	defer w.Close()

	sink := &errorSinkRecorder{}
	input := strings.Join([]string{
		`{"type":"user","message":{"content":"hi"}}`,
		`{not json`,
		`also not json`,
		`{"type":"assistant","message":{"content":"hello"}}`,
	}, "\n") + "\n"

	if err := ParseClaude(strings.NewReader(input), w, TranscriptParserOptions{
		ErrorSink: sink,
		Now:       fixedTimes(now),
	}); err != nil {
		t.Fatalf("ParseClaude: %v", err)
	}

	records, err := ReadTranscript(dir.Path)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 valid records, got %d", len(records))
	}

	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected 1 advisory error (de-duped), got %d (%v)", len(entries), entries)
	}
	if entries[0]["reason"] != TranscriptParserErrorJSONParse {
		t.Errorf("reason = %q, want %q", entries[0]["reason"], TranscriptParserErrorJSONParse)
	}
	if entries[0]["cli"] != string(TranscriptCLIClaude) {
		t.Errorf("cli = %q, want %q", entries[0]["cli"], TranscriptCLIClaude)
	}
}

// TestParseClaude_AdvisoryScanOverflow verifies the scan_overflow
// advisory path: a single line that exceeds transcriptScannerMaxBuffer
// bytes surfaces as exactly one LifecycleVerbTranscriptParserError
// event with reason=scan_overflow, and the parser returns nil (the
// scanner stops at the offending line; upstream code re-opens or
// finalizes).
func TestParseClaude_AdvisoryScanOverflow(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}
	defer w.Close()

	// Build a single line that exceeds 1 MiB. The line itself need
	// not be valid JSON; bufio.Scanner refuses it before json.Unmarshal
	// runs.
	huge := bytes.Repeat([]byte("x"), transcriptScannerMaxBuffer+10)
	input := append([]byte(`{"type":"user","message":{"content":"hi"}}`), '\n')
	input = append(input, huge...)
	input = append(input, '\n')

	sink := &errorSinkRecorder{}
	if err := ParseClaude(bytes.NewReader(input), w, TranscriptParserOptions{
		ErrorSink: sink,
		Now:       fixedTimes(now),
	}); err != nil {
		t.Fatalf("ParseClaude: %v", err)
	}

	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected 1 advisory error, got %d (%v)", len(entries), entries)
	}
	if entries[0]["reason"] != TranscriptParserErrorScanOverflow {
		t.Errorf("reason = %q, want %q", entries[0]["reason"], TranscriptParserErrorScanOverflow)
	}

	// The first (valid) line should still have produced a record.
	records, err := ReadTranscript(dir.Path)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record (the valid line before the overflow), got %d", len(records))
	}
}

// stubReader is an io.Reader that returns a configured error after
// emitting a fixed payload. Used to exercise the stream_error
// advisory path.
type stubReader struct {
	payload []byte
	pos     int
	err     error
}

func (r *stubReader) Read(p []byte) (int, error) {
	if r.pos < len(r.payload) {
		n := copy(p, r.payload[r.pos:])
		r.pos += n
		return n, nil
	}
	return 0, r.err
}

// TestParseClaude_AdvisoryStreamError verifies the stream_error
// advisory path: a reader that returns a non-EOF error mid-scan
// surfaces as exactly one LifecycleVerbTranscriptParserError event
// with reason=stream_error, and ParseClaude returns nil.
func TestParseClaude_AdvisoryStreamError(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}
	defer w.Close()

	sink := &errorSinkRecorder{}
	reader := &stubReader{
		payload: []byte(`{"type":"user","message":{"content":"hi"}}` + "\n"),
		err:     errors.New("simulated stream failure"),
	}
	if err := ParseClaude(reader, w, TranscriptParserOptions{
		ErrorSink: sink,
		Now:       fixedTimes(now),
	}); err != nil {
		t.Fatalf("ParseClaude: %v", err)
	}

	entries := sink.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected 1 advisory error, got %d (%v)", len(entries), entries)
	}
	if entries[0]["reason"] != TranscriptParserErrorStreamError {
		t.Errorf("reason = %q, want %q", entries[0]["reason"], TranscriptParserErrorStreamError)
	}
}

// TestParseClaude_NilGuards confirms ParseClaude / ParseCodex reject a
// nil reader or nil writer up front so a misconfigured caller fails
// loudly rather than silently producing no records.
func TestParseClaude_NilGuards(t *testing.T) {
	if err := ParseClaude(nil, &TranscriptWriter{}, TranscriptParserOptions{}); err == nil {
		t.Errorf("ParseClaude(nil reader): expected error, got nil")
	}
	if err := ParseClaude(strings.NewReader(""), nil, TranscriptParserOptions{}); err == nil {
		t.Errorf("ParseClaude(nil writer): expected error, got nil")
	}
	if err := ParseCodex(nil, &TranscriptWriter{}, TranscriptParserOptions{}); err == nil {
		t.Errorf("ParseCodex(nil reader): expected error, got nil")
	}
	if err := ParseCodex(strings.NewReader(""), nil, TranscriptParserOptions{}); err == nil {
		t.Errorf("ParseCodex(nil writer): expected error, got nil")
	}
}

// TestLifecycleTranscriptErrorSink_RoutesToLifecycleWriter confirms
// the lifecycle adapter forwards every Emit call to the underlying
// LifecycleWriter via WriteVerb(LifecycleVerbTranscriptParserError).
// Asserts on the resulting lifecycle.jsonl bytes so a future change
// to the verb spelling is caught at the writer layer too.
func TestLifecycleTranscriptErrorSink_RoutesToLifecycleWriter(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	lw, err := OpenLifecycleWriter(dir.Path, LifecycleWriterOptions{
		RunID:   dir.ID,
		Backend: "docker-sbx",
		Agent:   "claude",
		Now:     fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenLifecycleWriter: %v", err)
	}
	defer lw.Close()

	sink := LifecycleTranscriptErrorSink(lw)
	if sink == nil {
		t.Fatal("LifecycleTranscriptErrorSink returned nil for non-nil writer")
	}
	if err := sink.Emit(map[string]string{
		"cli":    string(TranscriptCLIClaude),
		"reason": TranscriptParserErrorJSONParse,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	events, err := ReadLifecycleEvents(dir.Path)
	if err != nil {
		t.Fatalf("ReadLifecycleEvents: %v", err)
	}
	found := false
	for _, evt := range events {
		if evt.Verb == LifecycleVerbTranscriptParserError {
			found = true
			if evt.Metadata["reason"] != TranscriptParserErrorJSONParse {
				t.Errorf("metadata.reason = %q, want %q", evt.Metadata["reason"], TranscriptParserErrorJSONParse)
			}
			if evt.Metadata["cli"] != string(TranscriptCLIClaude) {
				t.Errorf("metadata.cli = %q, want %q", evt.Metadata["cli"], TranscriptCLIClaude)
			}
		}
	}
	if !found {
		t.Errorf("LifecycleVerbTranscriptParserError event not found in %v", events)
	}
}

// TestLifecycleTranscriptErrorSink_NilWriterReturnsNil documents the
// adapter's nil-writer contract: a caller that has not wired the
// lifecycle writer gets nil back so it can pass the result through to
// the parser options without a separate guard.
func TestLifecycleTranscriptErrorSink_NilWriterReturnsNil(t *testing.T) {
	if got := LifecycleTranscriptErrorSink(nil); got != nil {
		t.Errorf("LifecycleTranscriptErrorSink(nil) = %v, want nil", got)
	}
}

// TestParseClaude_NilTurnSourceLeavesTurnIDEmpty confirms the parser
// tolerates a nil TurnSource (the supervisor wires *ControlSocket;
// unit tests and CLI dry-runs may not). Records carry an empty TurnID
// rather than a runtime failure.
func TestParseClaude_NilTurnSourceLeavesTurnIDEmpty(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-090000-feedab"
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenTranscriptWriter(dir.Path, TranscriptWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenTranscriptWriter: %v", err)
	}
	defer w.Close()

	if err := ParseClaude(strings.NewReader(`{"type":"user","message":{"content":"hi"}}`+"\n"), w, TranscriptParserOptions{
		Now: fixedTimes(now),
	}); err != nil {
		t.Fatalf("ParseClaude: %v", err)
	}
	records, err := ReadTranscript(dir.Path)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].TurnID != "" {
		t.Errorf("TurnID = %q, want empty (no TurnSource)", records[0].TurnID)
	}
}

// TestTranscriptTurnSourceFunc_ImplementsInterface confirms the
// function adapter type satisfies the TranscriptTurnSource interface.
// Mirrors the cli.TurnSourceFunc adapter the gateway bridge uses.
func TestTranscriptTurnSourceFunc_ImplementsInterface(t *testing.T) {
	var ts TranscriptTurnSource = TranscriptTurnSourceFunc(func(role string) string {
		return "stub-" + role
	})
	if got := ts.CurrentTurnID("agent"); got != "stub-agent" {
		t.Errorf("CurrentTurnID = %q, want %q", got, "stub-agent")
	}
}

// TestControlSocket_SatisfiesTranscriptTurnSource is the static
// interface-satisfaction check that pins the supervisor's wiring
// contract: *run.ControlSocket already exposes CurrentTurnID(role)
// string, so the supervisor can pass it directly into
// TranscriptParserOptions.TurnSource without an intermediate
// adapter. A future refactor that drops CurrentTurnID from
// *ControlSocket would break this assertion.
func TestControlSocket_SatisfiesTranscriptTurnSource(t *testing.T) {
	var _ TranscriptTurnSource = (*ControlSocket)(nil)
}
