package workspace

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// initFixtureRepo creates a real Git repository in a temp directory and makes
// one initial commit so HEAD resolves to a real commit. This is the fixture
// the worktree-strategy integration tests run against. It deliberately uses
// the real git binary rather than a stub because the strategy under test is
// itself a thin wrapper over real git invocations; mocking git would defeat
// the purpose of an integration test.
func initFixtureRepo(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not on PATH: %v", err)
	}

	repo := t.TempDir()

	// Pin the initial branch name so the test does not depend on the user's
	// init.defaultBranch git config.
	mustGit(t, repo, "init", "-b", "main")
	// Local identity so commit succeeds even on machines without a global
	// git config.
	mustGit(t, repo, "config", "user.email", "test@example.com")
	mustGit(t, repo, "config", "user.name", "Test")

	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	mustGit(t, repo, "add", "README.md")
	mustGit(t, repo, "commit", "-m", "initial")

	return repo
}

func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

// TestCreateWorktree_HappyPath is the end-to-end check for plan 02 step 3.
// It exercises the real CreateWorktree against a real Git repository and
// asserts the three observable effects the plan requires:
//
//  1. A new branch ai-env/<env-name> exists in the source repo.
//  2. A worktree is registered for that branch at the expected path.
//  3. A .env-meta.json file is written with the recorded branch + path.
func TestCreateWorktree_HappyPath(t *testing.T) {
	repo := initFixtureRepo(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")

	envName := "fix-tests"
	now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

	info, err := CreateWorktree(aiEnvDir, envName, repo, "node", now)
	if err != nil {
		t.Fatalf("CreateWorktree: %v", err)
	}

	// --- WorkspaceInfo correctness ---------------------------------------
	if info.Name != envName {
		t.Errorf("info.Name = %q, want %q", info.Name, envName)
	}
	if info.Strategy != StrategyWorktree {
		t.Errorf("info.Strategy = %q, want %q", info.Strategy, StrategyWorktree)
	}
	wantBranch := "ai-env/fix-tests"
	if info.Branch != wantBranch {
		t.Errorf("info.Branch = %q, want %q", info.Branch, wantBranch)
	}
	wantPath := filepath.Join(aiEnvDir, "workspaces", envName)
	if info.Path != wantPath {
		t.Errorf("info.Path = %q, want %q", info.Path, wantPath)
	}
	if info.SourcePath != repo {
		t.Errorf("info.SourcePath = %q, want %q", info.SourcePath, repo)
	}
	if info.Template != "node" {
		t.Errorf("info.Template = %q, want %q", info.Template, "node")
	}

	// --- Worktree exists on disk ----------------------------------------
	st, err := os.Stat(wantPath)
	if err != nil {
		t.Fatalf("stat worktree path: %v", err)
	}
	if !st.IsDir() {
		t.Fatalf("worktree path %s is not a directory", wantPath)
	}
	// The seed file from the source repo should be checked out into the
	// worktree (worktree shares the commit, so README.md must be present).
	if _, err := os.Stat(filepath.Join(wantPath, "README.md")); err != nil {
		t.Errorf("expected README.md in worktree: %v", err)
	}

	// --- Git knows about the worktree ----------------------------------
	out, err := exec.Command("git", "-C", repo, "worktree", "list", "--porcelain").CombinedOutput()
	if err != nil {
		t.Fatalf("git worktree list: %v\n%s", err, out)
	}
	listing := string(out)
	if !strings.Contains(listing, wantPath) {
		t.Errorf("git worktree list does not mention %q:\n%s", wantPath, listing)
	}
	if !strings.Contains(listing, "branch refs/heads/"+wantBranch) {
		t.Errorf("git worktree list does not mention branch %q:\n%s", wantBranch, listing)
	}

	// --- Branch exists in source repo ----------------------------------
	exists, err := branchExists(repo, wantBranch)
	if err != nil {
		t.Fatalf("branchExists: %v", err)
	}
	if !exists {
		t.Errorf("branch %s not found in %s", wantBranch, repo)
	}

	// --- Metadata file written ------------------------------------------
	metaPath := filepath.Join(wantPath, ".env-meta.json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	var meta envMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v\n%s", err, raw)
	}
	if meta.Name != envName {
		t.Errorf("meta.Name = %q, want %q", meta.Name, envName)
	}
	if meta.Strategy != "worktree" {
		t.Errorf("meta.Strategy = %q, want %q", meta.Strategy, "worktree")
	}
	if meta.Branch != wantBranch {
		t.Errorf("meta.Branch = %q, want %q", meta.Branch, wantBranch)
	}
	if meta.WorkspacePath != wantPath {
		t.Errorf("meta.WorkspacePath = %q, want %q", meta.WorkspacePath, wantPath)
	}
	if meta.SourcePath != repo {
		t.Errorf("meta.SourcePath = %q, want %q", meta.SourcePath, repo)
	}
	if meta.Template != "node" {
		t.Errorf("meta.Template = %q, want %q", meta.Template, "node")
	}
	if meta.CreatedAt != now.Format(time.RFC3339) {
		t.Errorf("meta.CreatedAt = %q, want %q", meta.CreatedAt, now.Format(time.RFC3339))
	}
}

// TestCreateWorktree_RejectsExistingPath confirms the safety check: if the
// target worktree path already exists, CreateWorktree must refuse rather
// than clobber. This is part of plan 02 step 3's guarantee that retries do
// not silently merge state.
func TestCreateWorktree_RejectsExistingPath(t *testing.T) {
	repo := initFixtureRepo(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")

	envName := "dup"
	wtPath := filepath.Join(aiEnvDir, "workspaces", envName)
	if err := os.MkdirAll(wtPath, 0o755); err != nil {
		t.Fatalf("pre-create worktree path: %v", err)
	}

	_, err := CreateWorktree(aiEnvDir, envName, repo, "", time.Now())
	if err == nil {
		t.Fatal("expected error when worktree path already exists, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error %q does not mention existing path", err.Error())
	}
}

// TestCreateWorktree_RejectsExistingBranch confirms the second up-front
// guard: an existing branch with the target name aborts the call cleanly
// instead of letting git fail mid-operation.
func TestCreateWorktree_RejectsExistingBranch(t *testing.T) {
	repo := initFixtureRepo(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")

	envName := "preexist"
	// Pre-create the branch the strategy would otherwise create.
	mustGit(t, repo, "branch", BranchName(envName))

	_, err := CreateWorktree(aiEnvDir, envName, repo, "", time.Now())
	if err == nil {
		t.Fatal("expected error when branch already exists, got nil")
	}
	if !strings.Contains(err.Error(), "branch") {
		t.Errorf("error %q does not mention branch conflict", err.Error())
	}
}
