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
	// LAST RUN cell should be "-" for a workspace with no runs. A bare
	// strings.Contains(s, "-") would match the tempdir path that the
	// table also prints, so we walk the rows and assert specifically
	// on the placeholder row's trailing cell.
	var placeholderRow string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "placeholder") {
			placeholderRow = line
			break
		}
	}
	if placeholderRow == "" {
		t.Fatalf("placeholder row missing from listing:\n%s", s)
	}
	if !strings.HasSuffix(strings.TrimRight(placeholderRow, " "), "-") {
		t.Errorf("placeholder row should end with '-' LAST RUN cell, got %q", placeholderRow)
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

// TestRunList_ReadsMetadataWhenAIEnvYamlAbsent guards the fallback that
// reads `.env-meta.json` when a workspace has no per-workspace `ai-env.yaml`.
// That is the actual shape produced by `ai-env new` (only the project's
// .ai-env/ai-env.yaml exists; the workspace directory only holds the meta
// stub), so the listing must surface real strategy + template values
// instead of "unknown" plus a misleading warning.
func TestRunList_ReadsMetadataWhenAIEnvYamlAbsent(t *testing.T) {
	cwd := t.TempDir()
	if err := RunNew(NewOptions{EnvName: "meta-only", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}

	// Overwrite the freshly scaffolded `.env-meta.json` so the test
	// asserts on concrete strategy / template strings, decoupled from
	// whatever `ai-env new` happens to detect for an empty temp dir.
	aiEnvDir := filepath.Join(cwd, ".ai-env")
	wsDir := filepath.Join(aiEnvDir, "workspaces", "meta-only")
	metaPath := filepath.Join(wsDir, ".env-meta.json")
	meta := map[string]string{
		"name":           "meta-only",
		"strategy":       "copy",
		"source_path":    cwd,
		"workspace_path": wsDir,
		"created_at":     time.Now().UTC().Format(time.RFC3339),
		"template":       "node",
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(metaPath, append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	// Sanity check: there must be no ai-env.yaml inside the workspace dir.
	if _, err := os.Stat(filepath.Join(wsDir, "ai-env.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected no workspace-level ai-env.yaml, stat err = %v", err)
	}

	var out, errOut bytes.Buffer
	if err := RunList(ListOptions{Cwd: cwd, Stdout: &out, Stderr: &errOut}); err != nil {
		t.Fatalf("RunList: %v", err)
	}

	if strings.Contains(errOut.String(), "has no ai-env.yaml") {
		t.Errorf("did not expect ai-env.yaml warning, stderr:\n%s", errOut.String())
	}

	s := out.String()
	// Find the meta-only row and check its strategy + template columns.
	var row string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "meta-only") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatalf("meta-only row missing from table:\n%s", s)
	}
	if !strings.Contains(row, "copy") {
		t.Errorf("expected strategy 'copy' in row, got %q", row)
	}
	if !strings.Contains(row, "node") {
		t.Errorf("expected template 'node' in row, got %q", row)
	}
}

// TestRunList_WarnsWhenWorkspaceMissingBothFiles covers the case where a
// workspace directory has neither `ai-env.yaml` nor `.env-meta.json`. The
// listing must still include the row (so the user sees the orphan dir) and
// the warning text must name both files so the operator knows what is
// missing.
func TestRunList_WarnsWhenWorkspaceMissingBothFiles(t *testing.T) {
	cwd := t.TempDir()
	if err := RunNew(NewOptions{EnvName: "anchor", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	orphan := filepath.Join(cwd, ".ai-env", "workspaces", "orphan")
	if err := os.MkdirAll(orphan, 0o755); err != nil {
		t.Fatalf("mkdir orphan: %v", err)
	}

	var out, errOut bytes.Buffer
	if err := RunList(ListOptions{Cwd: cwd, Stdout: &out, Stderr: &errOut}); err != nil {
		t.Fatalf("RunList: %v", err)
	}

	if !strings.Contains(errOut.String(), "ai-env.yaml or .env-meta.json") {
		t.Errorf("expected combined warning, got:\n%s", errOut.String())
	}
	if !strings.Contains(out.String(), "orphan") {
		t.Errorf("orphan row should still appear in listing, got:\n%s", out.String())
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
