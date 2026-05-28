package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/workspace"
)

// timeNow returns a fixed deterministic timestamp the tests pass into the
// workspace package's create helpers. A fixed value keeps metadata files
// reproducible and avoids any clock-related flakiness when assertions ever
// need to look at created_at.
func timeNow(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
}

// mustCreateWorktree materializes a real worktree-backed workspace via the
// public workspace API and fails the test if anything goes wrong. Tests
// reuse this so the diff-specific assertions stay focused on output, not
// on the creation plumbing.
func mustCreateWorktree(t *testing.T, aiEnvDir, envName, sourcePath string, now time.Time) workspace.WorkspaceInfo {
	t.Helper()
	info, err := workspace.CreateWorktree(aiEnvDir, envName, sourcePath, "", now)
	if err != nil {
		t.Fatalf("CreateWorktree: %v", err)
	}
	return info
}

// mustCreateCopy materializes a real copy-backed workspace via the public
// workspace API. As with mustCreateWorktree, the helper exists to keep the
// diff tests focused on RunDiff output assertions.
//
// CreateCopy leaves the baseline tree read-only (mode 0o555/0o444), which is
// the production behavior plan 02 step 4 requires. t.TempDir's own cleanup
// hook calls os.RemoveAll, and that recursive remove cannot unlink children
// inside a read-only directory on macOS. We register an earlier cleanup that
// restores write bits across the baseline tree so the harness's removal can
// proceed. The chmod runs AFTER the test body's assertions because t.Cleanup
// runs in LIFO order and t.TempDir's cleanup was registered first.
func mustCreateCopy(t *testing.T, aiEnvDir, envName, sourcePath string, now time.Time) workspace.WorkspaceInfo {
	t.Helper()
	info, err := workspace.CreateCopy(aiEnvDir, envName, sourcePath, "", now)
	if err != nil {
		t.Fatalf("CreateCopy: %v", err)
	}
	t.Cleanup(func() {
		_ = filepath.Walk(workspace.BaselinePath(aiEnvDir, envName), func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			_ = os.Chmod(p, 0o755)
			return nil
		})
	})
	return info
}

// requireGit skips the test when git is not available. The diff command's
// worktree path is a thin wrapper over real git invocations, so without git
// we can only meaningfully exercise the copy strategy. Tests that need git
// skip cleanly instead of failing.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not on PATH: %v", err)
	}
}

// runGitInTest is a small wrapper that fails the test on git errors. It is
// intentionally minimal: we only need it to set up fixture state, not to be
// production-grade.
func runGitInTest(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

// writeFile is a small helper for writing fixture files with parent dirs
// auto-created. Tests use it both for seeding source repos and for making
// edits inside materialized workspaces.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// scaffoldAIEnv runs RunNew against cwd so a real .ai-env/ tree (including
// policy.yaml with default protected-path patterns) lives on disk. The diff
// command walks upward looking for that tree, so this scaffold is what the
// tests below diff against.
func scaffoldAIEnv(t *testing.T, cwd, envName string) {
	t.Helper()
	var out bytes.Buffer
	if err := RunNew(NewOptions{
		EnvName: envName,
		Cwd:     cwd,
		Stdout:  &out,
	}); err != nil {
		t.Fatalf("RunNew: %v\n%s", err, out.String())
	}
}

// TestRunDiff_WorktreeStrategy_ShowsChangedFiles is the end-to-end check for
// the worktree path of plan 02 step 5. It builds a real Git repo, runs
// `ai-env new` to scaffold the project's .ai-env/ tree, manually creates a
// worktree via the workspace package (RunNew does not yet materialize one),
// makes a real edit inside the worktree, and asserts that RunDiff:
//
//   - exits without error,
//   - emits the worktree strategy label,
//   - lists the changed file in its per-file summary,
//   - includes the unified-diff body for the change.
func TestRunDiff_WorktreeStrategy_ShowsChangedFiles(t *testing.T) {
	requireGit(t)

	repo := t.TempDir()
	runGitInTest(t, repo, "init", "-b", "main")
	runGitInTest(t, repo, "config", "user.email", "test@example.com")
	runGitInTest(t, repo, "config", "user.name", "Test")

	writeFile(t, filepath.Join(repo, "README.md"), "hello\n")
	writeFile(t, filepath.Join(repo, "src/app.go"), "package main\n\nfunc main() {}\n")
	runGitInTest(t, repo, "add", ".")
	runGitInTest(t, repo, "commit", "-m", "initial")

	// Scaffold the .ai-env/ tree at the repo root so RunDiff can find it
	// when we point Cwd inside the repo.
	scaffoldAIEnv(t, repo, "demo")

	// Materialize a worktree-backed env. We call the workspace package
	// directly because plan task 8 ("update ai-env new to call
	// WorkspaceManager.Create") is not yet wired up; the diff command does
	// not care how the workspace got there, only that its metadata exists.
	envName := "fix-tests"
	aiEnvDir := filepath.Join(repo, ".ai-env")
	now := timeNow(t)
	info := mustCreateWorktree(t, aiEnvDir, envName, repo, now)

	// Make a real edit inside the worktree so the diff has something to
	// show. We modify an existing file plus add a brand-new one to cover
	// both modify and add change kinds.
	writeFile(t, filepath.Join(info.Path, "README.md"), "hello\nadded line\n")
	writeFile(t, filepath.Join(info.Path, "src/feature.go"), "package main\n\nfunc Feature() {}\n")
	runGitInTest(t, info.Path, "add", ".")
	runGitInTest(t, info.Path, "commit", "-m", "agent change")

	var stdout, stderr bytes.Buffer
	err := RunDiff(DiffOptions{
		EnvName: envName,
		Cwd:     repo,
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunDiff: %v\nstderr:\n%s", err, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "strategy:  worktree") {
		t.Errorf("output missing worktree strategy label:\n%s", out)
	}
	if !strings.Contains(out, "README.md") {
		t.Errorf("output missing README.md in summary:\n%s", out)
	}
	if !strings.Contains(out, "src/feature.go") {
		t.Errorf("output missing src/feature.go in summary:\n%s", out)
	}
	// Unified-diff body must mention the added line so we know the body
	// (not just the summary) made it through. The git-diff header for the
	// modified file should also appear.
	if !strings.Contains(out, "+added line") {
		t.Errorf("unified diff missing added line:\n%s", out)
	}
	if !strings.Contains(out, "diff --git") {
		t.Errorf("unified diff missing git header:\n%s", out)
	}
}

// TestRunDiff_CopyStrategy_ShowsAddedAndModified is the end-to-end check for
// the copy path of plan 02 step 5. It seeds a non-Git source directory,
// scaffolds .ai-env/ in it, materializes a copy-backed env via the workspace
// package, makes a real edit inside the workspace, and asserts the same
// observable contract (header lines, per-file summary, unified-diff body).
func TestRunDiff_CopyStrategy_ShowsAddedAndModified(t *testing.T) {
	// Keep the source-to-copy tree and the project tree (where .ai-env/
	// lives) as siblings. If we used a single directory for both, CreateCopy
	// would recursively copy the workspace it just made into itself.
	root := t.TempDir()
	src := filepath.Join(root, "source")
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	writeFile(t, filepath.Join(src, "README.md"), "hello\n")
	writeFile(t, filepath.Join(src, "src/main.txt"), "alpha\nbeta\n")

	scaffoldAIEnv(t, project, "demo")

	envName := "fix-copy"
	aiEnvDir := filepath.Join(project, ".ai-env")
	now := timeNow(t)
	info := mustCreateCopy(t, aiEnvDir, envName, src, now)

	// Modify an existing file and add a new one inside the workspace so
	// the diff covers both change kinds. We deliberately do not touch the
	// baseline; the copy strategy compares workspace vs baseline.
	writeFile(t, filepath.Join(info.Path, "README.md"), "hello\nupdated\n")
	writeFile(t, filepath.Join(info.Path, "src/new.txt"), "brand new\n")

	var stdout, stderr bytes.Buffer
	err := RunDiff(DiffOptions{
		EnvName: envName,
		Cwd:     project,
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunDiff: %v\nstderr:\n%s", err, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "strategy:  copy") {
		t.Errorf("output missing copy strategy label:\n%s", out)
	}
	if !strings.Contains(out, "README.md") {
		t.Errorf("output missing README.md in summary:\n%s", out)
	}
	if !strings.Contains(out, "src/new.txt") {
		t.Errorf("output missing src/new.txt in summary:\n%s", out)
	}
	if !strings.Contains(out, "+updated") {
		t.Errorf("unified diff missing modified line:\n%s", out)
	}
	if !strings.Contains(out, "+brand new") {
		t.Errorf("unified diff missing added file body:\n%s", out)
	}
	if !strings.Contains(out, "diff --git a/README.md b/README.md") {
		t.Errorf("unified diff missing git-style header for README.md:\n%s", out)
	}
}

// TestRunDiff_CopyStrategy_FlagsProtectedPaths verifies plan 02 step 5's
// "highlight protected path changes in output" requirement against the
// default protected-path matcher (which policy.yaml's scaffolded defaults
// include, plus the workspace package's DefaultProtectedPaths fallback).
//
// We exercise the copy strategy because it is the simplest to set up
// without requiring git, and the protected-path check is strategy-
// independent: the same matcher runs after both diff engines.
func TestRunDiff_CopyStrategy_FlagsProtectedPaths(t *testing.T) {
	// As in the other copy test, keep source and project as siblings so
	// CreateCopy does not recursively copy the workspace into itself.
	root := t.TempDir()
	src := filepath.Join(root, "source")
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	writeFile(t, filepath.Join(src, "README.md"), "hello\n")
	// Seed a baseline file inside .github/workflows so the modified change
	// kind is exercised against a path the default matcher covers.
	writeFile(t, filepath.Join(src, ".github/workflows/ci.yml"), "name: ci\n")

	scaffoldAIEnv(t, project, "demo")

	// Remove the scaffolded policy.yaml so loadProtectedMatcher falls back
	// to DefaultProtectedPaths (which includes ".github/workflows/**").
	// That keeps the test focused on the protected-path *detection* without
	// re-encoding the entire policy schema here.
	if err := os.Remove(filepath.Join(project, ".ai-env", "policy.yaml")); err != nil {
		t.Fatalf("remove policy.yaml: %v", err)
	}

	envName := "with-protected"
	aiEnvDir := filepath.Join(project, ".ai-env")
	now := timeNow(t)
	info := mustCreateCopy(t, aiEnvDir, envName, src, now)

	// Edit a protected file and an unprotected one. The summary should
	// flag only the protected entry; the stderr warning should list it.
	writeFile(t, filepath.Join(info.Path, ".github/workflows/ci.yml"), "name: ci\nchanged: true\n")
	writeFile(t, filepath.Join(info.Path, "README.md"), "hello\nupdated\n")

	var stdout, stderr bytes.Buffer
	err := RunDiff(DiffOptions{
		EnvName: envName,
		Cwd:     project,
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunDiff: %v\nstderr:\n%s", err, stderr.String())
	}

	out := stdout.String()
	errOut := stderr.String()

	// The protected path must show up with the marker in the summary.
	if !strings.Contains(out, ".github/workflows/ci.yml") {
		t.Errorf("protected path missing from summary:\n%s", out)
	}
	if !strings.Contains(out, "[protected]") {
		t.Errorf("summary missing [protected] marker:\n%s", out)
	}
	// The README change is *not* protected; if our marker leaked onto its
	// line, the per-file flagging is broken. We check the specific line.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "README.md") && strings.Contains(line, "[protected]") {
			t.Errorf("README.md should not be flagged as protected: %q", line)
		}
	}
	// The stderr warning block must mention the protected file by path.
	if !strings.Contains(errOut, ".github/workflows/ci.yml") {
		t.Errorf("stderr warning missing protected path:\n%s", errOut)
	}
	if !strings.Contains(errOut, "protected paths changed") {
		t.Errorf("stderr missing protected-paths warning header:\n%s", errOut)
	}
}
