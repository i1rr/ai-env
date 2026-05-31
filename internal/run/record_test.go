package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newRunDirForRecord builds a real RunDirectory on disk and returns the
// run path the record writer is exercised against. Centralizing the
// scaffolding here keeps each test case focused on the Record contract
// rather than re-doing the directory setup.
func newRunDirForRecord(t *testing.T) RunDirectory {
	t.Helper()
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-a1b2c3"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return dir
}

// fullExampleRecord builds a Record populated with the plan's example
// values for run.json. Centralizing it means the round-trip test, the
// schema test, and the rewrite test all assert against the same source
// truth and a future schema change only has to be reflected here.
func fullExampleRecord(runID string) Record {
	loc := time.FixedZone("+10:00", 10*3600)
	started := time.Date(2026, 5, 28, 10, 13, 0, 0, loc)
	stopped := time.Date(2026, 5, 28, 10, 24, 0, 0, loc)
	exit := 0
	reason := StopReasonAgentExit
	return Record{
		RunID:               runID,
		EnvName:             "fix-tests",
		Agent:               "claude",
		Task:                "Fix the failing tests",
		State:               StateCompleted,
		ExitCode:            &exit,
		StartedAt:           &started,
		StoppedAt:           &stopped,
		StopReason:          &reason,
		Backend:             "docker-sbx",
		ModelCredentialMode: ModelCredentialBackendManaged,
		ReducedSafety:       false,
		LinkedPreviousRun:   nil,
	}
}

// TestRecord_RoundTripWithFullSchema is the schema test the plan-
// executor task list calls for. It populates every documented field
// with the plan's example values, writes the Record, reads it back,
// and asserts the decoded Record is identical to the source. A schema
// regression (forgotten tag, dropped pointer, time-zone mangling)
// fails this loud.
func TestRecord_RoundTripWithFullSchema(t *testing.T) {
	dir := newRunDirForRecord(t)
	rec := fullExampleRecord(dir.ID)

	if err := WriteRecord(dir.Path, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	got, err := ReadRecord(dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}

	if got.RunID != rec.RunID {
		t.Errorf("RunID = %q, want %q", got.RunID, rec.RunID)
	}
	if got.EnvName != rec.EnvName {
		t.Errorf("EnvName = %q, want %q", got.EnvName, rec.EnvName)
	}
	if got.Agent != rec.Agent {
		t.Errorf("Agent = %q, want %q", got.Agent, rec.Agent)
	}
	if got.Task != rec.Task {
		t.Errorf("Task = %q, want %q", got.Task, rec.Task)
	}
	if got.State != rec.State {
		t.Errorf("State = %q, want %q", got.State, rec.State)
	}
	if got.ExitCode == nil || *got.ExitCode != *rec.ExitCode {
		t.Errorf("ExitCode = %v, want %d", got.ExitCode, *rec.ExitCode)
	}
	if got.StartedAt == nil || !got.StartedAt.Equal(*rec.StartedAt) {
		t.Errorf("StartedAt = %v, want %v", got.StartedAt, *rec.StartedAt)
	}
	if got.StoppedAt == nil || !got.StoppedAt.Equal(*rec.StoppedAt) {
		t.Errorf("StoppedAt = %v, want %v", got.StoppedAt, *rec.StoppedAt)
	}
	if got.StopReason == nil || *got.StopReason != *rec.StopReason {
		t.Errorf("StopReason = %v, want %q", got.StopReason, *rec.StopReason)
	}
	if got.Backend != rec.Backend {
		t.Errorf("Backend = %q, want %q", got.Backend, rec.Backend)
	}
	if got.ModelCredentialMode != rec.ModelCredentialMode {
		t.Errorf("ModelCredentialMode = %q, want %q", got.ModelCredentialMode, rec.ModelCredentialMode)
	}
	if got.ReducedSafety != rec.ReducedSafety {
		t.Errorf("ReducedSafety = %v, want %v", got.ReducedSafety, rec.ReducedSafety)
	}
	if got.LinkedPreviousRun != nil {
		t.Errorf("LinkedPreviousRun = %v, want nil", got.LinkedPreviousRun)
	}
}

// TestRecord_OnDiskJSONMatchesPlanSchema verifies the JSON keys and the
// pointer-as-null semantics by decoding the file as a generic map. The
// plan's run.json example uses snake_case keys and shows null for
// linked_previous_run; both must hold on disk so audit consumers
// matching on the documented schema do not regress.
func TestRecord_OnDiskJSONMatchesPlanSchema(t *testing.T) {
	dir := newRunDirForRecord(t)
	rec := fullExampleRecord(dir.ID)
	if err := WriteRecord(dir.Path, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir.Path, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}

	// Every documented key must be present in the on-disk JSON.
	wantKeys := []string{
		"run_id",
		"env_name",
		"agent",
		"task",
		"state",
		"exit_code",
		"started_at",
		"stopped_at",
		"stop_reason",
		"backend",
		"model_credential_mode",
		"reduced_safety",
		"linked_previous_run",
		"schema_versions",
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal generic: %v", err)
	}
	for _, k := range wantKeys {
		if _, ok := generic[k]; !ok {
			t.Errorf("missing key %q in run.json", k)
		}
	}
	if len(generic) != len(wantKeys) {
		// Extra keys mean we have drifted from the documented schema;
		// fail loud so a new field is reviewed deliberately.
		t.Errorf("run.json has %d keys, want %d (%v)", len(generic), len(wantKeys), keysOf(generic))
	}

	// linked_previous_run must serialize as literal null, not "" or "null".
	if string(generic["linked_previous_run"]) != "null" {
		t.Errorf("linked_previous_run raw = %q, want null", string(generic["linked_previous_run"]))
	}

	// The plan-pinned timestamp ("+10:00") must survive through marshal.
	if !strings.Contains(string(raw), "2026-05-28T10:13:00+10:00") {
		t.Errorf("expected started_at to keep +10:00 offset; raw=%q", string(raw))
	}
}

// keysOf is a tiny helper used to surface the actual key set when the
// schema-key count assertion fires. Keeps the diagnostic readable.
func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRecord_NullsForUnstoppedRun is the "still running" snapshot: a
// record written before the run hits a terminal state must surface
// exit_code, stopped_at, and stop_reason as JSON nulls (not zero values).
// The plan's run.json shape is shared between intermediate snapshots
// and the final record; emitting "0" for exit_code on a still-running
// snapshot would confuse the status command into reporting a clean
// exit.
func TestRecord_NullsForUnstoppedRun(t *testing.T) {
	dir := newRunDirForRecord(t)

	started := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	rec := Record{
		RunID:               dir.ID,
		EnvName:             "fix-tests",
		Agent:               "claude",
		Task:                "Fix the failing tests",
		State:               StateRunning,
		ExitCode:            nil,
		StartedAt:           &started,
		StoppedAt:           nil,
		StopReason:          nil,
		Backend:             "docker-sbx",
		ModelCredentialMode: ModelCredentialBackendManaged,
		ReducedSafety:       false,
		LinkedPreviousRun:   nil,
	}
	if err := WriteRecord(dir.Path, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir.Path, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	for _, key := range []string{"exit_code", "stopped_at", "stop_reason"} {
		needle := fmt.Sprintf(`"%s": null`, key)
		if !strings.Contains(string(raw), needle) {
			t.Errorf("expected %q in run.json; got %q", needle, string(raw))
		}
	}
}

// TestRecord_AtomicReplaceNoPartialFile is the atomicity test the
// plan-executor task list calls for: an in-progress write must not be
// visible to a reader. We exploit the staged-file convention by stat'ing
// the run.json that exists before the first write and asserting that no
// run.json sized between zero and the final length is ever observed
// during a sequence of concurrent rewrites.
//
// The test runs N rewrites in a writer goroutine while a reader
// goroutine constantly polls os.ReadFile on run.json. The reader must
// only see either the seed record or a fully-formed JSON object whose
// run_id matches one of the writes. A torn read (truncated bytes,
// JSON parse error) would surface as a parser failure.
func TestRecord_AtomicReplaceNoPartialFile(t *testing.T) {
	dir := newRunDirForRecord(t)

	// Seed an initial Record so the readers always have something well-
	// formed to look at (the placeholder is empty by default).
	seed := fullExampleRecord(dir.ID)
	if err := WriteRecord(dir.Path, seed); err != nil {
		t.Fatalf("seed WriteRecord: %v", err)
	}

	const rewrites = 60
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Reader: keep parsing run.json. A torn write would produce either an
	// EOF / unexpected-EOF error or a parse failure; both fail the test.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			raw, err := os.ReadFile(filepath.Join(dir.Path, "run.json"))
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			if len(raw) == 0 {
				t.Errorf("read: empty file (atomic replace broken)")
				return
			}
			var rec Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				t.Errorf("read: parse %v on bytes %q", err, string(raw))
				return
			}
			if rec.RunID == "" {
				t.Errorf("read: run_id empty in well-formed JSON")
				return
			}
		}
	}()

	// Writer: stream rewrites as fast as possible. Mutate a small field
	// (state) per iteration so the marshaled bytes differ between writes;
	// otherwise the rename is technically still correct but tests less.
	for i := 0; i < rewrites; i++ {
		rec := fullExampleRecord(dir.ID)
		// Mutate state across writes so each rewrite produces a
		// distinct byte string the reader could in theory see torn.
		switch i % 3 {
		case 0:
			rec.State = StateRunning
		case 1:
			rec.State = StateStopping
		case 2:
			rec.State = StateCompleted
		}
		if err := WriteRecord(dir.Path, rec); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()

	// After all writers finished, no stray temp files should be left in
	// the run directory. A failed atomic-write path would leak them.
	entries, err := os.ReadDir(dir.Path)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "run.json.tmp-") {
			t.Errorf("stale temp file left behind: %s", e.Name())
		}
	}
}

// TestRecord_RewriteUpdatesFields checks the iterative-rewrite path
// the supervisor's main loop relies on: WriteRecord called repeatedly
// against the same run directory must replace the file's contents
// entirely each time, with no leftover bytes from the previous
// snapshot.
//
// We write a record with all timestamps set, then a "shorter" record
// (no stopped_at, no exit code) and verify the resulting file no
// longer contains the dropped values. A naive truncate-then-write
// would pass this test but break atomicity; a non-atomic but full
// rewrite would also pass; only a half-baked merge would fail.
func TestRecord_RewriteUpdatesFields(t *testing.T) {
	dir := newRunDirForRecord(t)

	// First write: full record with the plan-example "completed" state.
	if err := WriteRecord(dir.Path, fullExampleRecord(dir.ID)); err != nil {
		t.Fatalf("first WriteRecord: %v", err)
	}

	// Second write: a minimal "still running" snapshot. The fields the
	// first snapshot set (exit_code, stopped_at, stop_reason) must no
	// longer be present as concrete values.
	started := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	mid := Record{
		RunID:               dir.ID,
		EnvName:             "fix-tests",
		Agent:               "claude",
		Task:                "Fix the failing tests",
		State:               StateRunning,
		StartedAt:           &started,
		Backend:             "docker-sbx",
		ModelCredentialMode: ModelCredentialBackendManaged,
	}
	if err := WriteRecord(dir.Path, mid); err != nil {
		t.Fatalf("second WriteRecord: %v", err)
	}

	got, err := ReadRecord(dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if got.State != StateRunning {
		t.Errorf("State = %q, want %q", got.State, StateRunning)
	}
	if got.ExitCode != nil {
		t.Errorf("ExitCode should be nil after rewrite, got %v", got.ExitCode)
	}
	if got.StoppedAt != nil {
		t.Errorf("StoppedAt should be nil after rewrite, got %v", got.StoppedAt)
	}
	if got.StopReason != nil {
		t.Errorf("StopReason should be nil after rewrite, got %v", got.StopReason)
	}
}

// TestReadRecord_EmptyPlaceholderReturnsSentinel makes sure
// ReadRecord can distinguish "no Record has been written yet" from
// "the file is corrupt", which the status command's planned UX
// depends on.
func TestReadRecord_EmptyPlaceholderReturnsSentinel(t *testing.T) {
	dir := newRunDirForRecord(t)
	if _, err := ReadRecord(dir.Path); !errors.Is(err, ErrRecordNotWritten) {
		t.Errorf("ReadRecord on empty placeholder: err = %v, want %v", err, ErrRecordNotWritten)
	}
}

// TestWriteRecord_RejectsEmptyRunID guards the only invariant
// WriteRecord enforces directly: a record without RunID is meaningless
// because every downstream tool keys on it. Surfacing the failure at
// write time keeps a bug-bait empty run.json out of audit.
func TestWriteRecord_RejectsEmptyRunID(t *testing.T) {
	dir := newRunDirForRecord(t)
	rec := fullExampleRecord(dir.ID)
	rec.RunID = ""
	if err := WriteRecord(dir.Path, rec); err == nil {
		t.Error("expected error for empty RunID, got nil")
	}
}

// TestWriteRecord_RejectsEmptyRunDir mirrors the RunID guard for the
// other required argument. A blank runDir would otherwise resolve to
// CWD which is almost never what the caller meant.
func TestWriteRecord_RejectsEmptyRunDir(t *testing.T) {
	rec := fullExampleRecord("20260528-101300-abcdef")
	if err := WriteRecord("", rec); err == nil {
		t.Error("expected error for empty runDir, got nil")
	}
}

// TestRunJSONPath_MatchesLayout is the symmetric helper test: the
// path helper used by status/list later must agree with the writer
// about where run.json lives.
func TestRunJSONPath_MatchesLayout(t *testing.T) {
	dir := newRunDirForRecord(t)
	want := filepath.Join(dir.Path, "run.json")
	if got := RunJSONPath(dir.Path); got != want {
		t.Errorf("RunJSONPath = %q, want %q", got, want)
	}
}
