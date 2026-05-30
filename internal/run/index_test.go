package run

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// seedRun creates one run directory under aiEnvDir and writes a
// run.json populated with envName + state. Returns the run ID for the
// caller's assertions. Centralizing this helper keeps the index tests
// focused on the helper contracts rather than the directory plumbing.
func seedRun(t *testing.T, aiEnvDir, runID, envName string, state State) {
	t.Helper()
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory %s: %v", runID, err)
	}
	rec := Record{
		RunID:               runID,
		EnvName:             envName,
		Agent:               "claude",
		Task:                "test task",
		State:               state,
		Backend:             "local-process",
		ModelCredentialMode: ModelCredentialBackendManaged,
	}
	if err := WriteRecord(dir.Path, rec); err != nil {
		t.Fatalf("WriteRecord %s: %v", runID, err)
	}
}

func TestListRuns_NoRunsDir(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	if err := os.MkdirAll(aiEnvDir, 0o755); err != nil {
		t.Fatalf("mkdir aiEnvDir: %v", err)
	}
	got, err := ListRuns(aiEnvDir)
	if err != nil {
		t.Fatalf("ListRuns on empty .ai-env: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %d entries", len(got))
	}
}

func TestListRuns_SortsDescending(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	seedRun(t, aiEnvDir, "20260528-101300-aaaaaa", "fix-tests", StateRunning)
	seedRun(t, aiEnvDir, "20260528-110000-bbbbbb", "fix-tests", StateCompleted)
	seedRun(t, aiEnvDir, "20260528-103000-cccccc", "other-env", StateRunning)

	got, err := ListRuns(aiEnvDir)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 runs, got %d", len(got))
	}
	wantOrder := []string{
		"20260528-110000-bbbbbb",
		"20260528-103000-cccccc",
		"20260528-101300-aaaaaa",
	}
	for i, want := range wantOrder {
		if got[i].ID != want {
			t.Errorf("ListRuns[%d].ID = %q, want %q", i, got[i].ID, want)
		}
	}
	// Spot-check that EnvName was decoded from run.json.
	if got[2].EnvName != "fix-tests" {
		t.Errorf("oldest run env = %q, want fix-tests", got[2].EnvName)
	}
}

func TestListRuns_SkipsHiddenAndFiles(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	seedRun(t, aiEnvDir, "20260528-101300-aaaaaa", "fix-tests", StateRunning)
	runsDir := RunsRoot(aiEnvDir)
	// Hidden directory and a stray regular file should be ignored.
	if err := os.MkdirAll(filepath.Join(runsDir, ".DS_Store"), 0o755); err != nil {
		t.Fatalf("mkdir hidden dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runsDir, "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write stray file: %v", err)
	}
	got, err := ListRuns(aiEnvDir)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 run, got %d", len(got))
	}
}

func TestLatestRunForEnv_PicksNewestMatch(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	seedRun(t, aiEnvDir, "20260528-101300-aaaaaa", "fix-tests", StateRunning)
	seedRun(t, aiEnvDir, "20260528-103000-bbbbbb", "fix-tests", StateCompleted)
	seedRun(t, aiEnvDir, "20260528-110000-cccccc", "other-env", StateRunning)

	got, err := LatestRunForEnv(aiEnvDir, "fix-tests")
	if err != nil {
		t.Fatalf("LatestRunForEnv: %v", err)
	}
	if got.ID != "20260528-103000-bbbbbb" {
		t.Errorf("LatestRunForEnv.ID = %q, want 20260528-103000-bbbbbb", got.ID)
	}
}

func TestLatestRunForEnv_NoMatch(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	seedRun(t, aiEnvDir, "20260528-101300-aaaaaa", "other-env", StateRunning)

	_, err := LatestRunForEnv(aiEnvDir, "fix-tests")
	if !errors.Is(err, ErrNoRuns) {
		t.Fatalf("expected ErrNoRuns, got %v", err)
	}
}

func TestLatestRunForEnv_NoRunsDir(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	if err := os.MkdirAll(aiEnvDir, 0o755); err != nil {
		t.Fatalf("mkdir aiEnvDir: %v", err)
	}
	_, err := LatestRunForEnv(aiEnvDir, "fix-tests")
	if !errors.Is(err, ErrNoRuns) {
		t.Fatalf("expected ErrNoRuns on missing runs dir, got %v", err)
	}
}

func TestFindRunByID_Found(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	seedRun(t, aiEnvDir, "20260528-101300-aaaaaa", "fix-tests", StateCompleted)
	got, err := FindRunByID(aiEnvDir, "20260528-101300-aaaaaa")
	if err != nil {
		t.Fatalf("FindRunByID: %v", err)
	}
	if got.EnvName != "fix-tests" {
		t.Errorf("EnvName = %q, want fix-tests", got.EnvName)
	}
}

func TestFindRunByID_NotFound(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	_, err := FindRunByID(aiEnvDir, "20260528-999999-zzzzzz")
	if !errors.Is(err, ErrNoRuns) {
		t.Fatalf("expected ErrNoRuns, got %v", err)
	}
}

func TestFindRunByID_RejectsPathTraversal(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	bad := []string{"../escape", ".hidden", "with/slash", "back\\slash"}
	for _, name := range bad {
		if _, err := FindRunByID(aiEnvDir, name); err == nil {
			t.Errorf("expected FindRunByID to reject %q", name)
		}
	}
}

func TestReadLifecycleEvents_RoundTrip(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-aaaaaa"
	seedRun(t, aiEnvDir, runID, "fix-tests", StateRunning)
	runDir := RunPath(aiEnvDir, runID)

	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	w, err := OpenLifecycleWriter(runDir, LifecycleWriterOptions{
		RunID:   runID,
		Backend: "local-process",
		Agent:   "claude",
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("OpenLifecycleWriter: %v", err)
	}
	for _, s := range []State{StatePreparingWorkspace, StateStartingBackend, StateRunning} {
		if err := w.Write(s); err != nil {
			t.Fatalf("Write %s: %v", s, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	events, err := ReadLifecycleEvents(runDir)
	if err != nil {
		t.Fatalf("ReadLifecycleEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[2].State != StateRunning {
		t.Errorf("last event state = %q, want %q", events[2].State, StateRunning)
	}
	if events[0].RunID != runID {
		t.Errorf("first event run id = %q, want %q", events[0].RunID, runID)
	}
}

func TestReadLifecycleEvents_EmptyFile(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-aaaaaa"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	if _, err := CreateRunDirectory(aiEnvDir, runID, now); err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	events, err := ReadLifecycleEvents(RunPath(aiEnvDir, runID))
	if err != nil {
		t.Fatalf("ReadLifecycleEvents on placeholder: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events from empty file, got %d", len(events))
	}
}
