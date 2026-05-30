package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/run"
)

func TestRunList_NoEnvs(t *testing.T) {
	cwd := t.TempDir()
	// Scaffold a fresh `.ai-env/` so findAIEnvDir succeeds, but do not
	// add any workspaces under .ai-env/workspaces/.
	if err := RunNew(NewOptions{EnvName: "placeholder", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	var out, errOut bytes.Buffer
	if err := RunList(ListOptions{Cwd: cwd, Stdout: &out, Stderr: &errOut}); err != nil {
		t.Fatalf("RunList: %v", err)
	}
	// At least the scaffolded "placeholder" workspace should appear; the
	// LAST RUN column should be "-" because no runs are recorded yet.
	s := out.String()
	if !strings.Contains(s, "placeholder") {
		t.Fatalf("expected placeholder env in listing:\n%s", s)
	}
	if !strings.Contains(s, "NAME") || !strings.Contains(s, "LAST RUN") {
		t.Errorf("expected table header in listing:\n%s", s)
	}
	// LAST RUN cell should be "-" for a workspace with no runs.
	if !strings.Contains(s, "-") {
		t.Errorf("expected '-' in LAST RUN column:\n%s", s)
	}
}

func TestRunList_ShowsLatestRunState(t *testing.T) {
	cwd, _ := scaffoldProjectWithRun(t, "fix-tests", run.StateCompleted)
	// Add an older running run for the same env. List should pick the
	// newer completed one.
	aiEnvDir := filepath.Join(cwd, ".ai-env")
	olderID := "20260527-101300-cccccc"
	if rd, err := run.CreateRunDirectory(aiEnvDir, olderID, time.Date(2026, 5, 27, 10, 13, 0, 0, time.UTC)); err == nil {
		rec := run.Record{
			RunID: olderID, EnvName: "fix-tests", Agent: "claude", Task: "old",
			State: run.StateRunning, Backend: "local-process",
			ModelCredentialMode: run.ModelCredentialBackendManaged,
		}
		if err := run.WriteRecord(rd.Path, rec); err != nil {
			t.Fatalf("WriteRecord older: %v", err)
		}
	} else {
		t.Fatalf("CreateRunDirectory older: %v", err)
	}

	var out, errOut bytes.Buffer
	if err := RunList(ListOptions{Cwd: cwd, Stdout: &out, Stderr: &errOut}); err != nil {
		t.Fatalf("RunList: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "fix-tests") {
		t.Fatalf("expected fix-tests env in listing:\n%s", s)
	}
	// The newer run id is 20260528-101300-aaaaaa with state "completed";
	// the table should show that.
	if !strings.Contains(s, "completed") {
		t.Errorf("expected 'completed' in LAST RUN column:\n%s", s)
	}
	if !strings.Contains(s, "20260528-101300-aaaaaa") {
		t.Errorf("expected newer run id in LAST RUN column:\n%s", s)
	}
	if strings.Contains(s, "20260527-101300-cccccc") {
		t.Errorf("older run id should not appear in LAST RUN column:\n%s", s)
	}
}

func TestRunList_HandlesEnvsWithoutRuns(t *testing.T) {
	cwd := t.TempDir()
	if err := RunNew(NewOptions{EnvName: "no-runs", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	var out, errOut bytes.Buffer
	if err := RunList(ListOptions{Cwd: cwd, Stdout: &out, Stderr: &errOut}); err != nil {
		t.Fatalf("RunList: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "no-runs") {
		t.Errorf("expected no-runs env in listing:\n%s", s)
	}
	// The row's LAST RUN cell should be "-".
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "no-runs") {
			if !strings.HasSuffix(strings.TrimRight(line, " "), "-") {
				t.Errorf("no-runs row should end with '-' LAST RUN cell, got %q", line)
			}
		}
	}
}
