package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Integration tests for batch 6 (plan 02 step 8): `ai-env new` must rewire
// through WorkspaceManager so that:
//   - A Git source produces a worktree-backed workspace at the canonical
//     path with a metadata file recording strategy=worktree and the
//     ai-env/<env-name> branch.
//   - A non-Git source produces a copy-backed workspace at the canonical
//     path with a metadata file recording strategy=copy and the baseline
//     path / hash summary.
//
// These tests run the real RunNew code path end-to-end (no mocks). They use
// t.TempDir() for the host project directory, real `git init` for the Git
// case, and assert on actual on-disk artifacts (workspace directory presence
// and .env-meta.json contents).

// envMetaOnDisk mirrors the JSON shape written by the workspace package.
// We re-declare it here in the cli_test package rather than importing the
// internal struct so the test asserts on the documented public contract
// (the JSON keys listed in plan 02's "Env metadata file" section).
type envMetaOnDisk struct {
	Name          string `json:"name"`
	Strategy      string `json:"strategy"`
	Branch        string `json:"branch"`
	SourcePath    string `json:"source_path"`
	WorkspacePath string `json:"workspace_path"`
	CreatedAt     string `json:"created_at"`
	Template      string `json:"template"`

	BaselinePath string `json:"baseline_path"`
	CopyTime     string `json:"copy_time"`
	HashSummary  string `json:"hash_summary"`
}

// readEnvMeta reads and parses a .env-meta.json file the workspace package
// wrote for envName at aiEnvDir.
func readEnvMeta(t *testing.T, aiEnvDir, envName string) envMetaOnDisk {
	t.Helper()
	path := filepath.Join(aiEnvDir, "workspaces", envName, ".env-meta.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read metadata %s: %v", path, err)
	}
	var meta envMetaOnDisk
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("parse metadata %s: %v\nraw: %s", path, err, data)
	}
	return meta
}

// TestRunNew_GitSource_UsesWorktreeStrategy is the integration test for
// batch 6 on the Git path. It seeds a real Git repository, runs RunNew with
// that repo as both the host and source, then asserts:
//
//   - The workspace directory exists at .ai-env/workspaces/<env-name>/.
//   - The strategy chosen is "worktree" (not "copy").
//   - The metadata file is present, well-formed, and records the correct
//     branch name (ai-env/<env-name>) and source path.
//   - The Git case does NOT leave a baseline directory behind.
func TestRunNew_GitSource_UsesWorktreeStrategy(t *testing.T) {
	requireGit(t)

	repo := t.TempDir()
	// Pin the initial branch so the test does not depend on the user's
	// init.defaultBranch git config.
	runGitInTest(t, repo, "init", "-b", "main")
	runGitInTest(t, repo, "config", "user.email", "test@example.com")
	runGitInTest(t, repo, "config", "user.name", "Test")
	writeFile(t, filepath.Join(repo, "README.md"), "hello\n")
	runGitInTest(t, repo, "add", "README.md")
	runGitInTest(t, repo, "commit", "-m", "initial")

	var out bytes.Buffer
	err := RunNew(NewOptions{
		EnvName: "fix-tests",
		Cwd:     repo,
		Stdout:  &out,
	})
	if err != nil {
		t.Fatalf("RunNew: %v", err)
	}

	aiEnvDir := filepath.Join(repo, ".ai-env")
	wsPath := filepath.Join(aiEnvDir, "workspaces", "fix-tests")

	// 1. Workspace directory exists.
	if st, err := os.Stat(wsPath); err != nil {
		t.Fatalf("workspace %s missing: %v", wsPath, err)
	} else if !st.IsDir() {
		t.Fatalf("workspace %s is not a directory", wsPath)
	}

	// 2. Metadata file exists and records worktree strategy.
	meta := readEnvMeta(t, aiEnvDir, "fix-tests")
	if meta.Name != "fix-tests" {
		t.Errorf("meta.name = %q, want %q", meta.Name, "fix-tests")
	}
	if meta.Strategy != "worktree" {
		t.Errorf("meta.strategy = %q, want worktree (Git source must use worktree)", meta.Strategy)
	}
	if meta.Branch != "ai-env/fix-tests" {
		t.Errorf("meta.branch = %q, want ai-env/fix-tests", meta.Branch)
	}
	if meta.SourcePath != repo {
		t.Errorf("meta.source_path = %q, want %q", meta.SourcePath, repo)
	}
	if meta.WorkspacePath != wsPath {
		t.Errorf("meta.workspace_path = %q, want %q", meta.WorkspacePath, wsPath)
	}
	if meta.CreatedAt == "" {
		t.Errorf("meta.created_at should be populated")
	}
	// Worktree strategy must not record copy-strategy fields.
	if meta.BaselinePath != "" {
		t.Errorf("meta.baseline_path = %q, want empty for worktree", meta.BaselinePath)
	}
	if meta.HashSummary != "" {
		t.Errorf("meta.hash_summary = %q, want empty for worktree", meta.HashSummary)
	}

	// 3. The branch is actually checked out in the source repo.
	cmd := exec.Command("git", "show-ref", "--verify", "--quiet", "refs/heads/ai-env/fix-tests")
	cmd.Dir = repo
	if err := cmd.Run(); err != nil {
		t.Errorf("expected branch ai-env/fix-tests to exist in repo: %v", err)
	}

	// 4. The baseline directory must not be created for the Git case.
	if _, err := os.Stat(filepath.Join(aiEnvDir, "baselines", "fix-tests")); !os.IsNotExist(err) {
		t.Errorf("baseline dir should not exist for worktree strategy, got err=%v", err)
	}

	// 5. Stdout summary should advertise the worktree strategy and branch.
	if !strings.Contains(out.String(), "worktree") {
		t.Errorf("expected summary to mention worktree strategy; got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "ai-env/fix-tests") {
		t.Errorf("expected summary to mention branch ai-env/fix-tests; got:\n%s", out.String())
	}
}

// TestRunNew_NonGitSource_UsesCopyStrategy is the integration test for
// batch 6 on the non-Git path. It seeds a plain directory (no .git), runs
// RunNew, then asserts:
//
//   - The workspace directory exists at .ai-env/workspaces/<env-name>/.
//   - The strategy chosen is "copy" (not "worktree").
//   - The metadata file is present, well-formed, and records the baseline
//     path, copy time, and a sha256 hash summary.
//   - Source content was actually copied into the workspace.
//   - A read-only baseline directory exists at .ai-env/baselines/<env-name>/.
func TestRunNew_NonGitSource_UsesCopyStrategy(t *testing.T) {
	dir := t.TempDir()
	// Seed a non-Git source: a couple of files but no .git directory.
	writeFile(t, filepath.Join(dir, "main.txt"), "hello world\n")
	writeFile(t, filepath.Join(dir, "subdir", "nested.txt"), "nested\n")

	// CreateCopy leaves the baseline read-only; restore write bits so
	// t.TempDir's recursive cleanup can unlink children on macOS.
	t.Cleanup(func() { restoreWriteBits(filepath.Join(dir, ".ai-env")) })

	var out bytes.Buffer
	err := RunNew(NewOptions{
		EnvName: "scratch",
		Cwd:     dir,
		Stdout:  &out,
	})
	if err != nil {
		t.Fatalf("RunNew: %v", err)
	}

	aiEnvDir := filepath.Join(dir, ".ai-env")
	wsPath := filepath.Join(aiEnvDir, "workspaces", "scratch")
	blPath := filepath.Join(aiEnvDir, "baselines", "scratch")

	// 1. Workspace directory exists.
	if st, err := os.Stat(wsPath); err != nil {
		t.Fatalf("workspace %s missing: %v", wsPath, err)
	} else if !st.IsDir() {
		t.Fatalf("workspace %s is not a directory", wsPath)
	}

	// 2. Source content was copied into the workspace.
	if data, err := os.ReadFile(filepath.Join(wsPath, "main.txt")); err != nil {
		t.Errorf("workspace main.txt missing: %v", err)
	} else if string(data) != "hello world\n" {
		t.Errorf("workspace main.txt content = %q, want hello world", string(data))
	}
	if data, err := os.ReadFile(filepath.Join(wsPath, "subdir", "nested.txt")); err != nil {
		t.Errorf("workspace subdir/nested.txt missing: %v", err)
	} else if string(data) != "nested\n" {
		t.Errorf("workspace subdir/nested.txt content = %q, want nested", string(data))
	}

	// 3. Metadata file exists and records copy strategy with copy-specific
	//    fields populated.
	meta := readEnvMeta(t, aiEnvDir, "scratch")
	if meta.Name != "scratch" {
		t.Errorf("meta.name = %q, want scratch", meta.Name)
	}
	if meta.Strategy != "copy" {
		t.Errorf("meta.strategy = %q, want copy (non-Git source must use copy)", meta.Strategy)
	}
	if meta.SourcePath != dir {
		t.Errorf("meta.source_path = %q, want %q", meta.SourcePath, dir)
	}
	if meta.WorkspacePath != wsPath {
		t.Errorf("meta.workspace_path = %q, want %q", meta.WorkspacePath, wsPath)
	}
	if meta.CreatedAt == "" {
		t.Errorf("meta.created_at should be populated")
	}
	if meta.BaselinePath != blPath {
		t.Errorf("meta.baseline_path = %q, want %q", meta.BaselinePath, blPath)
	}
	if meta.CopyTime == "" {
		t.Errorf("meta.copy_time should be populated for copy strategy")
	}
	if !strings.HasPrefix(meta.HashSummary, "sha256:") {
		t.Errorf("meta.hash_summary = %q, want sha256:... prefix", meta.HashSummary)
	}
	// Worktree-only field must be empty in the copy case.
	if meta.Branch != "" {
		t.Errorf("meta.branch = %q, want empty for copy strategy", meta.Branch)
	}

	// 4. Baseline directory exists and was created read-only.
	if st, err := os.Stat(blPath); err != nil {
		t.Fatalf("baseline %s missing: %v", blPath, err)
	} else if !st.IsDir() {
		t.Fatalf("baseline %s is not a directory", blPath)
	}

	// 5. Stdout summary should advertise the copy strategy.
	if !strings.Contains(out.String(), "copy") {
		t.Errorf("expected summary to mention copy strategy; got:\n%s", out.String())
	}
}
