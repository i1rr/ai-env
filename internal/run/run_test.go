package run

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// fixedClock pins Now() to a single moment so tests that consume the
// generator's timestamp portion (or CreateRunDirectory's CreatedAt) can
// assert exact values rather than ranges. It mirrors the worktree test
// suite's fixed-time pattern.
type fixedClock struct {
	t time.Time
}

func (c fixedClock) Now() time.Time { return c.t }

// staticReader implements io.Reader by replaying the same bytes on
// every Read. It lets the generator tests produce deterministic
// suffixes without poking at crypto/rand. Three bytes are enough for
// one ID; the slice is repeated as needed so a single reader can serve
// multiple Generate calls.
type staticReader struct {
	src []byte
	pos int
}

func (r *staticReader) Read(p []byte) (int, error) {
	if len(r.src) == 0 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = r.src[r.pos%len(r.src)]
		r.pos++
	}
	return len(p), nil
}

// runIDPattern matches the run ID format the master plan specifies:
// "YYYYMMDD-HHMMSS-<6-hex>". The regex is the same shape later batches
// will use (status, list) so locking it down here protects the format
// against accidental drift.
var runIDPattern = regexp.MustCompile(`^\d{8}-\d{6}-[0-9a-f]{6}$`)

func TestRunIDGenerator_FormatMatchesPlan(t *testing.T) {
	gen := &RunIDGenerator{
		Clock:  fixedClock{t: time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)},
		Random: &staticReader{src: []byte{0xa1, 0xb2, 0xc3}},
	}

	id, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := "20260528-101300-a1b2c3"
	if id != want {
		t.Errorf("Generate = %q, want %q", id, want)
	}
	if !runIDPattern.MatchString(id) {
		t.Errorf("Generate %q does not match %s", id, runIDPattern)
	}
}

func TestRunIDGenerator_SameSecondDistinctIDs(t *testing.T) {
	// Two generators sharing the same clock but different random sources
	// stand in for two runs the user starts within the same second. The
	// plan's acceptance criterion 2 requires their IDs to differ.
	clock := fixedClock{t: time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)}
	a := &RunIDGenerator{Clock: clock, Random: &staticReader{src: []byte{0x01, 0x02, 0x03}}}
	b := &RunIDGenerator{Clock: clock, Random: &staticReader{src: []byte{0x01, 0x02, 0x04}}}

	idA, err := a.Generate()
	if err != nil {
		t.Fatalf("Generate a: %v", err)
	}
	idB, err := b.Generate()
	if err != nil {
		t.Fatalf("Generate b: %v", err)
	}

	// Sanity: timestamps must be identical (the whole point of the test
	// is that the suffix is what makes them unique).
	if idA[:len(runIDTimeLayout)] != idB[:len(runIDTimeLayout)] {
		t.Errorf("expected matching timestamp prefix, got %q vs %q", idA, idB)
	}
	if idA == idB {
		t.Errorf("same-second IDs must differ, got %q", idA)
	}
}

func TestRunIDGenerator_PropagatesRandomError(t *testing.T) {
	gen := &RunIDGenerator{
		Clock:  fixedClock{t: time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)},
		Random: bytes.NewReader(nil),
	}
	if _, err := gen.Generate(); err == nil {
		t.Fatal("Generate returned nil err for empty random source")
	}
}

func TestRunIDGenerator_ZeroValueFallsBackToDefaults(t *testing.T) {
	// A bare RunIDGenerator{} (no Clock, no Random) must still produce a
	// well-formed ID. The zero-value fallback is what GenerateRunID and
	// future package-level helpers rely on.
	id, err := (&RunIDGenerator{}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !runIDPattern.MatchString(id) {
		t.Errorf("zero-value Generate %q does not match %s", id, runIDPattern)
	}
}

func TestGenerateRunID_PackageHelper(t *testing.T) {
	id, err := GenerateRunID()
	if err != nil {
		t.Fatalf("GenerateRunID: %v", err)
	}
	if !runIDPattern.MatchString(id) {
		t.Errorf("GenerateRunID %q does not match %s", id, runIDPattern)
	}
}

func TestCreateRunDirectory_LayoutMatchesPlan(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-a1b2c3"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)

	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	// --- Returned RunDirectory ----------------------------------------
	if dir.ID != runID {
		t.Errorf("dir.ID = %q, want %q", dir.ID, runID)
	}
	wantPath := filepath.Join(aiEnvDir, "runs", runID)
	if dir.Path != wantPath {
		t.Errorf("dir.Path = %q, want %q", dir.Path, wantPath)
	}
	if !dir.CreatedAt.Equal(now) {
		t.Errorf("dir.CreatedAt = %v, want %v", dir.CreatedAt, now)
	}
	if got := dir.TaskPath(); got != filepath.Join(wantPath, "task.md") {
		t.Errorf("dir.TaskPath = %q, want %q", got, filepath.Join(wantPath, "task.md"))
	}

	// --- Run directory exists with the right mode ---------------------
	st, err := os.Stat(dir.Path)
	if err != nil {
		t.Fatalf("stat run dir: %v", err)
	}
	if !st.IsDir() {
		t.Fatalf("run dir is not a directory")
	}

	// --- Every documented file is present and empty -------------------
	wantFiles := []string{
		"task.md",
		"run.json",
		"agent-command.txt",
		"transcript.md",
		"stdout.log",
		"stderr.log",
		"lifecycle.jsonl",
		"shell-commands.jsonl",
		"filesystem-events.jsonl",
		"network-events.jsonl",
		"policy-decisions.jsonl",
		"mcp-calls.jsonl",
		"git-diff.patch",
		"secret-scan.json",
		"dependency-report.json",
		"security-report.md",
		"final-summary.md",
	}
	for _, name := range wantFiles {
		path := filepath.Join(dir.Path, name)
		st, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected file %s to exist: %v", name, err)
			continue
		}
		if st.IsDir() {
			t.Errorf("%s is a directory, want a regular file", name)
		}
		if st.Size() != 0 {
			t.Errorf("%s should start empty, got %d bytes", name, st.Size())
		}
	}

	// --- scan-results/ subdir present ---------------------------------
	scanDir := filepath.Join(dir.Path, "scan-results")
	st, err = os.Stat(scanDir)
	if err != nil {
		t.Fatalf("stat scan-results: %v", err)
	}
	if !st.IsDir() {
		t.Errorf("scan-results is not a directory")
	}

	// --- No extra entries (lockdown against accidental additions) ----
	// We assert the directory contains exactly the files + subdirs we
	// expect so future expansions of the layout are reviewed
	// deliberately rather than slipping in by accident.
	entries, err := os.ReadDir(dir.Path)
	if err != nil {
		t.Fatalf("readdir run dir: %v", err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	want := append([]string(nil), wantFiles...)
	want = append(want, "scan-results")
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("run dir entries = %v, want %v", got, want)
	}
}

func TestCreateRunDirectory_RefusesExisting(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-deadbe"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)

	if _, err := CreateRunDirectory(aiEnvDir, runID, now); err != nil {
		t.Fatalf("first CreateRunDirectory: %v", err)
	}
	if _, err := CreateRunDirectory(aiEnvDir, runID, now); err == nil {
		t.Fatal("second CreateRunDirectory: expected error, got nil")
	}
}

func TestCreateRunDirectory_RejectsEmptyArgs(t *testing.T) {
	if _, err := CreateRunDirectory("", "id", time.Now()); err == nil {
		t.Error("empty aiEnvDir: expected error")
	}
	if _, err := CreateRunDirectory(t.TempDir(), "", time.Now()); err == nil {
		t.Error("empty runID: expected error")
	}
}

func TestWriteTask_PersistsContent(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-abcdef"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)

	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	task := "Fix the failing tests in the auth package."
	if err := WriteTask(aiEnvDir, runID, task); err != nil {
		t.Fatalf("WriteTask: %v", err)
	}

	got, err := os.ReadFile(dir.TaskPath())
	if err != nil {
		t.Fatalf("read task.md: %v", err)
	}
	want := task + "\n"
	if string(got) != want {
		t.Errorf("task.md content = %q, want %q", string(got), want)
	}
}

func TestWriteTask_PreservesExistingTrailingNewline(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-abcdef"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)

	if _, err := CreateRunDirectory(aiEnvDir, runID, now); err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	task := "Refactor the supervisor loop.\n"
	if err := WriteTask(aiEnvDir, runID, task); err != nil {
		t.Fatalf("WriteTask: %v", err)
	}

	got, err := os.ReadFile(TaskPath(aiEnvDir, runID))
	if err != nil {
		t.Fatalf("read task.md: %v", err)
	}
	if string(got) != task {
		t.Errorf("task.md content = %q, want %q", string(got), task)
	}
}

func TestWriteTask_RejectsEmptyTask(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-abcdef"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)

	if _, err := CreateRunDirectory(aiEnvDir, runID, now); err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	cases := []string{"", "   ", "\n\n", "\t"}
	for _, c := range cases {
		if err := WriteTask(aiEnvDir, runID, c); err == nil {
			t.Errorf("WriteTask(%q): expected error, got nil", c)
		}
	}
}

func TestWriteTask_RejectsEmptyArgs(t *testing.T) {
	if err := WriteTask("", "id", "task"); err == nil {
		t.Error("empty aiEnvDir: expected error")
	}
	if err := WriteTask(t.TempDir(), "", "task"); err == nil {
		t.Error("empty runID: expected error")
	}
}

func TestRunPathHelpers(t *testing.T) {
	aiEnvDir := "/tmp/.ai-env"
	runID := "20260528-101300-deadbe"

	if got := RunsRoot(aiEnvDir); got != "/tmp/.ai-env/runs" {
		t.Errorf("RunsRoot = %q", got)
	}
	if got := RunPath(aiEnvDir, runID); got != "/tmp/.ai-env/runs/"+runID {
		t.Errorf("RunPath = %q", got)
	}
	if got := TaskPath(aiEnvDir, runID); got != "/tmp/.ai-env/runs/"+runID+"/task.md" {
		t.Errorf("TaskPath = %q", got)
	}
}
