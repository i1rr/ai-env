package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunPatch_WorktreeStrategy_WritesUnifiedDiff exercises plan 02 step 6 for
// the worktree path end to end: a real Git repo is initialized, the .ai-env/
// tree is scaffolded, a worktree-backed env is materialized, real edits are
// committed inside the worktree, and RunPatch is invoked. We assert:
//
//   - the command exits without error,
//   - the patch file is created at --out,
//   - the file contains a unified diff body with the edited content,
//   - the per-file summary on stdout mentions the changed files and the
//     written path,
//   - stderr does not carry a protected-path warning when nothing protected
//     was touched.
func TestRunPatch_WorktreeStrategy_WritesUnifiedDiff(t *testing.T) {
	requireGit(t)

	repo := t.TempDir()
	runGitInTest(t, repo, "init", "-b", "main")
	runGitInTest(t, repo, "config", "user.email", "test@example.com")
	runGitInTest(t, repo, "config", "user.name", "Test")

	writeFile(t, filepath.Join(repo, "README.md"), "hello\n")
	writeFile(t, filepath.Join(repo, "src/app.go"), "package main\n\nfunc main() {}\n")
	runGitInTest(t, repo, "add", ".")
	runGitInTest(t, repo, "commit", "-m", "initial")

	scaffoldAIEnv(t, repo, "demo")

	envName := "fix-tests"
	aiEnvDir := filepath.Join(repo, ".ai-env")
	now := timeNow(t)
	info := mustCreateWorktree(t, aiEnvDir, envName, repo, now)

	// Real edits in the worktree so the patch is non-empty. We modify an
	// existing file and add a new one to cover both change kinds.
	writeFile(t, filepath.Join(info.Path, "README.md"), "hello\nadded line\n")
	writeFile(t, filepath.Join(info.Path, "src/feature.go"), "package main\n\nfunc Feature() {}\n")
	runGitInTest(t, info.Path, "add", ".")
	runGitInTest(t, info.Path, "commit", "-m", "agent change")

	outPath := filepath.Join(repo, "fix-tests.patch")
	var stdout, stderr bytes.Buffer
	if err := RunPatch(PatchOptions{
		EnvName:    envName,
		OutputPath: outPath,
		Cwd:        repo,
		Stdout:     &stdout,
		Stderr:     &stderr,
	}); err != nil {
		t.Fatalf("RunPatch: %v\nstderr:\n%s", err, stderr.String())
	}

	// The patch file must exist and carry the unified diff.
	patchBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read patch file: %v", err)
	}
	patch := string(patchBytes)
	if !strings.Contains(patch, "diff --git") {
		t.Errorf("patch file missing git diff header:\n%s", patch)
	}
	if !strings.Contains(patch, "+added line") {
		t.Errorf("patch file missing added line:\n%s", patch)
	}
	if !strings.Contains(patch, "src/feature.go") {
		t.Errorf("patch file missing new-file body for src/feature.go:\n%s", patch)
	}

	// Stdout summary should mention strategy, file count, file names, and
	// the written path with byte count.
	out := stdout.String()
	if !strings.Contains(out, "strategy:  worktree") {
		t.Errorf("stdout missing worktree strategy label:\n%s", out)
	}
	if !strings.Contains(out, "README.md") {
		t.Errorf("stdout summary missing README.md:\n%s", out)
	}
	if !strings.Contains(out, "src/feature.go") {
		t.Errorf("stdout summary missing src/feature.go:\n%s", out)
	}
	if !strings.Contains(out, "wrote:") || !strings.Contains(out, outPath) {
		t.Errorf("stdout missing wrote/outPath line:\n%s", out)
	}

	// Nothing protected was touched, so stderr should be empty.
	if errOut := stderr.String(); strings.TrimSpace(errOut) != "" {
		t.Errorf("stderr should be empty for non-protected diff, got:\n%s", errOut)
	}
}

// TestRunPatch_CopyStrategy_WritesFileLevelPatch exercises plan 02 step 6 for
// the copy path: a non-Git source is set up, the .ai-env/ tree is scaffolded
// in a sibling project dir, a copy-backed env is materialized, real edits are
// made inside the workspace, and RunPatch is invoked. We assert the patch
// file carries one file-level unified-diff block per changed file (per the
// plan's "emit file-level patch where possible" wording).
func TestRunPatch_CopyStrategy_WritesFileLevelPatch(t *testing.T) {
	// Keep src and project as siblings: a single dir would have CreateCopy
	// recursively copy the workspace into itself.
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

	// Real edits: modify an existing file, add a new one, delete an
	// existing one. All three change kinds should appear in the patch.
	writeFile(t, filepath.Join(info.Path, "README.md"), "hello\nupdated\n")
	writeFile(t, filepath.Join(info.Path, "src/new.txt"), "brand new\n")
	if err := os.Remove(filepath.Join(info.Path, "src/main.txt")); err != nil {
		t.Fatalf("remove src/main.txt: %v", err)
	}

	outPath := filepath.Join(project, "fix-copy.patch")
	var stdout, stderr bytes.Buffer
	if err := RunPatch(PatchOptions{
		EnvName:    envName,
		OutputPath: outPath,
		Cwd:        project,
		Stdout:     &stdout,
		Stderr:     &stderr,
	}); err != nil {
		t.Fatalf("RunPatch: %v\nstderr:\n%s", err, stderr.String())
	}

	patchBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read patch file: %v", err)
	}
	patch := string(patchBytes)

	// File-level: every changed file should have its own diff --git header
	// in the emitted patch. This is what "file-level patch where possible"
	// looks like for the copy strategy.
	for _, expected := range []string{
		"diff --git a/README.md b/README.md",
		"diff --git a/src/new.txt b/src/new.txt",
		"diff --git a/src/main.txt b/src/main.txt",
	} {
		if !strings.Contains(patch, expected) {
			t.Errorf("patch missing file-level header %q:\n%s", expected, patch)
		}
	}

	// Modified file should carry the added "+updated" line.
	if !strings.Contains(patch, "+updated") {
		t.Errorf("patch missing +updated line:\n%s", patch)
	}
	// Added file should be shown with /dev/null as the old side.
	if !strings.Contains(patch, "--- /dev/null") {
		t.Errorf("patch missing /dev/null marker for added file:\n%s", patch)
	}
	if !strings.Contains(patch, "+brand new") {
		t.Errorf("patch missing +brand new body:\n%s", patch)
	}
	// Deleted file should be shown with /dev/null as the new side.
	if !strings.Contains(patch, "+++ /dev/null") {
		t.Errorf("patch missing /dev/null marker for deleted file:\n%s", patch)
	}

	out := stdout.String()
	if !strings.Contains(out, "strategy:  copy") {
		t.Errorf("stdout missing copy strategy label:\n%s", out)
	}
	if !strings.Contains(out, "files:     3 changed") {
		t.Errorf("stdout missing 3-files summary:\n%s", out)
	}
	if !strings.Contains(out, "wrote:") || !strings.Contains(out, outPath) {
		t.Errorf("stdout missing wrote/outPath line:\n%s", out)
	}
}

// TestRunPatch_CopyStrategy_ProtectedPathWarning verifies plan 02 step 6's
// "warn on protected path changes" requirement. The patch is still written
// (the plan says warnings, not refusal: protected-path enforcement lives at
// the export gate, not at patch generation), but stderr must carry the
// warning block and the per-file summary must mark the protected entry.
func TestRunPatch_CopyStrategy_ProtectedPathWarning(t *testing.T) {
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
	if err := os.Remove(filepath.Join(project, ".ai-env", "policy.yaml")); err != nil {
		t.Fatalf("remove policy.yaml: %v", err)
	}

	envName := "with-protected"
	aiEnvDir := filepath.Join(project, ".ai-env")
	now := timeNow(t)
	info := mustCreateCopy(t, aiEnvDir, envName, src, now)

	// Touch both a protected and an unprotected file so the per-file
	// flagging discriminates correctly.
	writeFile(t, filepath.Join(info.Path, ".github/workflows/ci.yml"), "name: ci\nchanged: true\n")
	writeFile(t, filepath.Join(info.Path, "README.md"), "hello\nupdated\n")

	outPath := filepath.Join(project, "with-protected.patch")
	var stdout, stderr bytes.Buffer
	if err := RunPatch(PatchOptions{
		EnvName:    envName,
		OutputPath: outPath,
		Cwd:        project,
		Stdout:     &stdout,
		Stderr:     &stderr,
	}); err != nil {
		t.Fatalf("RunPatch: %v\nstderr:\n%s", err, stderr.String())
	}

	// The patch file must still exist and contain both changes; the plan
	// requires a warning, not a refusal.
	patchBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read patch file: %v", err)
	}
	patch := string(patchBytes)
	if !strings.Contains(patch, ".github/workflows/ci.yml") {
		t.Errorf("patch missing protected path body:\n%s", patch)
	}
	if !strings.Contains(patch, "README.md") {
		t.Errorf("patch missing unprotected path body:\n%s", patch)
	}

	// Summary must mark the protected entry and not mark the unprotected
	// one. We scan the README.md summary line specifically to make sure
	// the marker has not leaked.
	out := stdout.String()
	if !strings.Contains(out, "[protected]") {
		t.Errorf("stdout summary missing [protected] marker:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "README.md") && strings.Contains(line, "[protected]") {
			t.Errorf("README.md should not be flagged as protected: %q", line)
		}
	}

	// Stderr warning block must mention the protected path by name.
	errOut := stderr.String()
	if !strings.Contains(errOut, ".github/workflows/ci.yml") {
		t.Errorf("stderr warning missing protected path:\n%s", errOut)
	}
	if !strings.Contains(errOut, "protected paths") {
		t.Errorf("stderr missing protected-paths warning header:\n%s", errOut)
	}
}

// TestRunPatch_MissingOutFlag verifies that RunPatch rejects an empty
// OutputPath. The Cobra wiring marks --out required, but a programmatic
// caller (e.g. the CLI being driven from another Go process) could still
// forget it; the function should surface a clear error.
func TestRunPatch_MissingOutFlag(t *testing.T) {
	dir := t.TempDir()
	scaffoldAIEnv(t, dir, "demo")

	err := RunPatch(PatchOptions{
		EnvName: "demo",
		Cwd:     dir,
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected error when OutputPath is empty, got nil")
	}
	if !strings.Contains(err.Error(), "--out") {
		t.Errorf("error should mention --out flag, got: %v", err)
	}
}

// TestRunPatch_EmptyDiff_StillWritesFile verifies that a workspace with no
// changes still produces a (zero-byte) patch file. Downstream tooling that
// checks for file existence rather than parsing content should keep working
// across runs, and the "(no changes)" summary line tells the user what
// happened.
func TestRunPatch_EmptyDiff_StillWritesFile(t *testing.T) {
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

	scaffoldAIEnv(t, project, "demo")

	envName := "noop"
	aiEnvDir := filepath.Join(project, ".ai-env")
	now := timeNow(t)
	_ = mustCreateCopy(t, aiEnvDir, envName, src, now)

	outPath := filepath.Join(project, "noop.patch")
	var stdout, stderr bytes.Buffer
	if err := RunPatch(PatchOptions{
		EnvName:    envName,
		OutputPath: outPath,
		Cwd:        project,
		Stdout:     &stdout,
		Stderr:     &stderr,
	}); err != nil {
		t.Fatalf("RunPatch: %v\nstderr:\n%s", err, stderr.String())
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat patch file: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected zero-byte patch file, got %d bytes", info.Size())
	}
	if !strings.Contains(stdout.String(), "(no changes)") {
		t.Errorf("stdout missing (no changes) summary:\n%s", stdout.String())
	}
}
