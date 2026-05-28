package workspace

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests in this file exercise the WorkspaceManager flow against real
// `git init` fixtures. The plan (step 9) calls for "tests with fixture Git
// repositories": end-to-end runs of Create -> edit -> Diff -> Patch on a
// real on-disk Git repo, with no mocking of git itself.
//
// We deliberately keep these tests at the workspace package level (rather
// than the CLI level) so they cover the strategy plumbing directly:
// CreateWorktree, ReadMetadata, Diff (worktree branch), and the protected
// matcher integration. Coverage of `ai-env new` end-to-end is the job of
// the CLI integration tests; this file covers what the manager-level API
// guarantees for Git sources.

// gitFixtureRepo seeds a real Git working tree with a couple of files and
// a single initial commit. It returns the absolute path to the repo root.
//
// We use the real git binary because the worktree strategy under test is a
// thin wrapper over real `git worktree add` and `git diff`; stubbing git
// out would defeat the point of an integration fixture.
func gitFixtureRepo(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not on PATH: %v", err)
	}

	repo := t.TempDir()

	// Pin the initial branch so the fixture does not depend on the host's
	// init.defaultBranch setting (which can be either "master" or "main"
	// depending on git version and user config).
	mustRunGit(t, repo, "init", "-b", "main")
	mustRunGit(t, repo, "config", "user.email", "fixture@example.com")
	mustRunGit(t, repo, "config", "user.name", "Fixture")

	writeFixtureFile(t, filepath.Join(repo, "README.md"), "hello\n")
	writeFixtureFile(t, filepath.Join(repo, "src/app.go"), "package main\n\nfunc main() {}\n")
	mustRunGit(t, repo, "add", ".")
	mustRunGit(t, repo, "commit", "-m", "initial")

	return repo
}

// TestManagerFlow_GitFixture_CreateDiffPatch exercises the full happy path
// on a Git fixture:
//
//  1. CreateWorktree materializes a worktree-backed env from the fixture.
//  2. A real edit lands inside the worktree and is committed.
//  3. Diff (with a default protected matcher) reports the change.
//  4. The unified diff body Diff returns is valid patch text (it carries
//     the file header and "+added line" content).
//
// The asserts are deliberately at the observable-effects level (paths
// exist, branch exists, diff text contains expected strings) so the test
// stays robust to refactors of the internals.
func TestManagerFlow_GitFixture_CreateDiffPatch(t *testing.T) {
	repo := gitFixtureRepo(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")

	envName := "fix-tests"
	now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

	// --- Step 1: Create -------------------------------------------------
	info, err := CreateWorktree(aiEnvDir, envName, repo, "go", now)
	if err != nil {
		t.Fatalf("CreateWorktree: %v", err)
	}
	if info.Strategy != StrategyWorktree {
		t.Fatalf("Strategy = %q, want worktree", info.Strategy)
	}
	if info.Branch != "ai-env/"+envName {
		t.Fatalf("Branch = %q, want ai-env/%s", info.Branch, envName)
	}

	// ReadMetadata round-trips so later commands can rediscover the env
	// without re-running detection.
	got, err := ReadMetadata(aiEnvDir, envName)
	if err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}
	if got.Strategy != StrategyWorktree {
		t.Errorf("ReadMetadata.Strategy = %q, want worktree", got.Strategy)
	}
	if got.Branch != info.Branch {
		t.Errorf("ReadMetadata.Branch = %q, want %q", got.Branch, info.Branch)
	}
	if got.Path != info.Path {
		t.Errorf("ReadMetadata.Path = %q, want %q", got.Path, info.Path)
	}
	if got.SourcePath != repo {
		t.Errorf("ReadMetadata.SourcePath = %q, want %q", got.SourcePath, repo)
	}

	// --- Step 2: edit + commit inside the worktree ----------------------
	writeFixtureFile(t, filepath.Join(info.Path, "README.md"), "hello\nadded line\n")
	writeFixtureFile(t, filepath.Join(info.Path, "src/feature.go"), "package main\n\nfunc Feature() {}\n")
	mustRunGit(t, info.Path, "add", ".")
	mustRunGit(t, info.Path, "commit", "-m", "agent change")

	// --- Step 3: Diff with default protected matcher --------------------
	matcher, err := NewProtectedMatcher(nil)
	if err != nil {
		t.Fatalf("NewProtectedMatcher(nil): %v", err)
	}
	result, err := Diff(aiEnvDir, envName, matcher)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if result.Strategy != StrategyWorktree {
		t.Errorf("Diff.Strategy = %q, want worktree", result.Strategy)
	}

	// Both changed files should appear in result.Files with sensible
	// change kinds.
	gotPaths := map[string]ChangeKind{}
	for _, fd := range result.Files {
		gotPaths[fd.Path] = fd.Change
	}
	if gotPaths["README.md"] != ChangeModified {
		t.Errorf("README.md change = %q, want modified", gotPaths["README.md"])
	}
	if gotPaths["src/feature.go"] != ChangeAdded {
		t.Errorf("src/feature.go change = %q, want added", gotPaths["src/feature.go"])
	}

	// The unified diff body should contain the line we added so callers
	// can hand it straight to patch(1).
	if !strings.Contains(result.Unified, "+added line") {
		t.Errorf("Diff.Unified missing '+added line':\n%s", result.Unified)
	}
	if !strings.Contains(result.Unified, "src/feature.go") {
		t.Errorf("Diff.Unified missing src/feature.go header:\n%s", result.Unified)
	}

	// Neither README.md nor src/feature.go matches a default protected
	// pattern, so ProtectedHits must be empty.
	if len(result.ProtectedHits) != 0 {
		t.Errorf("ProtectedHits = %v, want empty for non-protected edits", result.ProtectedHits)
	}
}

// TestManagerFlow_GitFixture_ProtectedPathIsFlagged confirms the matcher
// integration end to end on a Git fixture: an edit to a protected file
// (a fake CI workflow) is surfaced in DiffResult.ProtectedHits and the
// per-file entry is marked Protected. This is the path the CLI relies on
// to print warnings.
func TestManagerFlow_GitFixture_ProtectedPathIsFlagged(t *testing.T) {
	repo := gitFixtureRepo(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	envName := "ci-touch"
	now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

	// Seed a workflow file in the fixture so the change inside the
	// worktree is "modify a protected path" rather than "add one". Both
	// flag, but modifying an existing file is the more realistic agent
	// behavior we want to verify.
	writeFixtureFile(t, filepath.Join(repo, ".github/workflows/ci.yml"), "name: CI\n")
	mustRunGit(t, repo, "add", ".github/workflows/ci.yml")
	mustRunGit(t, repo, "commit", "-m", "add ci workflow")

	info, err := CreateWorktree(aiEnvDir, envName, repo, "", now)
	if err != nil {
		t.Fatalf("CreateWorktree: %v", err)
	}

	writeFixtureFile(t, filepath.Join(info.Path, ".github/workflows/ci.yml"), "name: CI\n# tampered\n")
	mustRunGit(t, info.Path, "add", ".github/workflows/ci.yml")
	mustRunGit(t, info.Path, "commit", "-m", "tamper")

	matcher, err := NewProtectedMatcher(nil)
	if err != nil {
		t.Fatalf("NewProtectedMatcher: %v", err)
	}
	result, err := Diff(aiEnvDir, envName, matcher)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(result.ProtectedHits) != 1 || result.ProtectedHits[0] != ".github/workflows/ci.yml" {
		t.Errorf("ProtectedHits = %v, want [.github/workflows/ci.yml]", result.ProtectedHits)
	}
	var flagged bool
	for _, fd := range result.Files {
		if fd.Path == ".github/workflows/ci.yml" && fd.Protected {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("expected ci.yml entry to be marked Protected, got Files=%+v", result.Files)
	}
}

// TestManagerFlow_GitFixture_EditsDoNotLeakToSource verifies the isolation
// guarantee plan 02's acceptance criterion 3 calls out: edits made inside
// the worktree must not appear in the original working tree. The check is
// the source repo's `git status` is still clean after the agent commits
// inside the worktree.
func TestManagerFlow_GitFixture_EditsDoNotLeakToSource(t *testing.T) {
	repo := gitFixtureRepo(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	envName := "isolate"
	now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

	info, err := CreateWorktree(aiEnvDir, envName, repo, "", now)
	if err != nil {
		t.Fatalf("CreateWorktree: %v", err)
	}

	writeFixtureFile(t, filepath.Join(info.Path, "README.md"), "hello\nfrom worktree\n")
	mustRunGit(t, info.Path, "add", "README.md")
	mustRunGit(t, info.Path, "commit", "-m", "worktree edit")

	// The source repo should still show a clean tree on its own branch.
	// `git status --porcelain` prints nothing when the tree is clean.
	out, err := exec.Command("git", "-C", repo, "status", "--porcelain").CombinedOutput()
	if err != nil {
		t.Fatalf("git status: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Errorf("source repo has dirty status after worktree edit:\n%s", out)
	}

	// README.md in the source repo should still hold the original line,
	// not the agent's edit.
	src := mustReadFile(t, filepath.Join(repo, "README.md"))
	if src != "hello\n" {
		t.Errorf("source README.md changed: got %q, want %q", src, "hello\n")
	}
}
