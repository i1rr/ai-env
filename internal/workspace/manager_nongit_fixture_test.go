package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests in this file exercise the WorkspaceManager flow against real
// non-Git directory fixtures. The plan (step 10) calls for "tests with
// fixture non-Git directories": end-to-end runs of CreateCopy ->
// edit -> Diff (file-level) on a plain source tree, with no git involved.
//
// The intent mirrors the Git fixture suite but targets the copy strategy:
// baseline snapshots, file-level diffs, and protected-path matching all
// have to work without any git binary or .git directory in the source.

// nonGitFixtureSource seeds a small non-Git directory tree (no .git
// anywhere) with a representative mix of files and nested directories. It
// returns the absolute path to the root of the seed.
func nonGitFixtureSource(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "README.md"), "non-git project\n")
	writeFixtureFile(t, filepath.Join(root, "src/main.txt"), "alpha\nbeta\n")
	writeFixtureFile(t, filepath.Join(root, "src/util/helper.txt"), "helper one\n")
	writeFixtureFile(t, filepath.Join(root, "docs/notes.md"), "notes\n")

	// Sanity guard: the fixture must really be non-Git. If a future
	// refactor accidentally seeds a .git directory this assert catches it
	// so we do not silently test the wrong strategy.
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		t.Fatalf("non-Git fixture accidentally contains .git at %s", root)
	}
	return root
}

// TestManagerFlow_NonGitFixture_CreateDiff runs the full happy path of the
// copy strategy:
//
//  1. CreateCopy materializes a workspace + baseline from a non-Git
//     source tree.
//  2. Real edits land inside the workspace (modify one file, add one,
//     delete one).
//  3. Diff (with a default protected matcher) reports each change with
//     the correct ChangeKind.
//  4. The unified-diff body carries the file headers and the new content.
//  5. The baseline is left intact (read-only snapshot of the original
//     source); the agent's edits never touched it.
func TestManagerFlow_NonGitFixture_CreateDiff(t *testing.T) {
	source := nonGitFixtureSource(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")

	envName := "scratch"
	now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

	// --- Step 1: Create -------------------------------------------------
	info, err := CreateCopy(aiEnvDir, envName, source, "default", now)
	if err != nil {
		t.Fatalf("CreateCopy: %v", err)
	}
	// CreateCopy leaves the baseline tree read-only; register an early
	// cleanup so t.TempDir's recursive remove can unlink it on macOS.
	t.Cleanup(func() { restoreWriteBitsRecursive(info.BaselinePath) })

	if info.Strategy != StrategyCopy {
		t.Fatalf("Strategy = %q, want copy", info.Strategy)
	}
	if info.BaselinePath == "" {
		t.Fatalf("BaselinePath empty, want %s", BaselinePath(aiEnvDir, envName))
	}

	// ReadMetadata must rediscover the copy strategy and baseline path so
	// downstream commands (diff/patch) work from cold storage.
	got, err := ReadMetadata(aiEnvDir, envName)
	if err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}
	if got.Strategy != StrategyCopy {
		t.Errorf("ReadMetadata.Strategy = %q, want copy", got.Strategy)
	}
	if got.BaselinePath != info.BaselinePath {
		t.Errorf("ReadMetadata.BaselinePath = %q, want %q", got.BaselinePath, info.BaselinePath)
	}

	// --- Step 2: edits inside the workspace -----------------------------
	// modify an existing file...
	writeFixtureFile(t, filepath.Join(info.Path, "src/main.txt"), "alpha\nbeta\ngamma\n")
	// add a brand-new file...
	writeFixtureFile(t, filepath.Join(info.Path, "src/new.txt"), "fresh content\n")
	// and delete a file that existed in the baseline.
	if err := os.Remove(filepath.Join(info.Path, "docs/notes.md")); err != nil {
		t.Fatalf("remove docs/notes.md: %v", err)
	}

	// --- Step 3: Diff with default protected matcher --------------------
	matcher, err := NewProtectedMatcher(nil)
	if err != nil {
		t.Fatalf("NewProtectedMatcher(nil): %v", err)
	}
	result, err := Diff(aiEnvDir, envName, matcher)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if result.Strategy != StrategyCopy {
		t.Errorf("Diff.Strategy = %q, want copy", result.Strategy)
	}

	gotPaths := map[string]ChangeKind{}
	for _, fd := range result.Files {
		gotPaths[fd.Path] = fd.Change
	}
	if gotPaths["src/main.txt"] != ChangeModified {
		t.Errorf("src/main.txt change = %q, want modified", gotPaths["src/main.txt"])
	}
	if gotPaths["src/new.txt"] != ChangeAdded {
		t.Errorf("src/new.txt change = %q, want added", gotPaths["src/new.txt"])
	}
	if gotPaths["docs/notes.md"] != ChangeDeleted {
		t.Errorf("docs/notes.md change = %q, want deleted", gotPaths["docs/notes.md"])
	}

	// --- Step 4: Unified diff body is patch(1)-compatible ---------------
	if !strings.Contains(result.Unified, "+gamma") {
		t.Errorf("Diff.Unified missing '+gamma':\n%s", result.Unified)
	}
	if !strings.Contains(result.Unified, "+fresh content") {
		t.Errorf("Diff.Unified missing '+fresh content':\n%s", result.Unified)
	}
	// Deleted entries should emit the "-" body for the baseline content.
	if !strings.Contains(result.Unified, "-notes") {
		t.Errorf("Diff.Unified missing '-notes' (deleted file body):\n%s", result.Unified)
	}

	// --- Step 5: Baseline is untouched ---------------------------------
	// Reading the baseline copy of main.txt must still show the original
	// content (alpha\nbeta\n). The agent's "alpha\nbeta\ngamma\n" must
	// only live in the workspace.
	if got := mustReadFile(t, filepath.Join(info.BaselinePath, "src/main.txt")); got != "alpha\nbeta\n" {
		t.Errorf("baseline src/main.txt changed: got %q, want %q", got, "alpha\nbeta\n")
	}
	// docs/notes.md was deleted in the workspace; baseline still has it.
	if _, err := os.Stat(filepath.Join(info.BaselinePath, "docs/notes.md")); err != nil {
		t.Errorf("baseline docs/notes.md missing after workspace delete: %v", err)
	}
}

// TestManagerFlow_NonGitFixture_ProtectedPathIsFlagged confirms the matcher
// works on the copy-strategy diff path: editing a protected file inside
// the workspace surfaces in DiffResult.ProtectedHits and marks the per-
// file entry. This is the copy-side counterpart of the Git-fixture
// equivalent.
func TestManagerFlow_NonGitFixture_ProtectedPathIsFlagged(t *testing.T) {
	source := nonGitFixtureSource(t)
	// Seed a protected file in the source so it ends up in both the
	// workspace and the baseline.
	writeFixtureFile(t, filepath.Join(source, "package.json"), "{\"name\":\"x\"}\n")

	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	envName := "deps-touch"
	now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

	info, err := CreateCopy(aiEnvDir, envName, source, "", now)
	if err != nil {
		t.Fatalf("CreateCopy: %v", err)
	}
	t.Cleanup(func() { restoreWriteBitsRecursive(info.BaselinePath) })

	// Modify the protected file inside the workspace.
	writeFixtureFile(t, filepath.Join(info.Path, "package.json"), "{\"name\":\"x\",\"new\":true}\n")

	matcher, err := NewProtectedMatcher(nil)
	if err != nil {
		t.Fatalf("NewProtectedMatcher: %v", err)
	}
	result, err := Diff(aiEnvDir, envName, matcher)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(result.ProtectedHits) != 1 || result.ProtectedHits[0] != "package.json" {
		t.Errorf("ProtectedHits = %v, want [package.json]", result.ProtectedHits)
	}
	var flagged bool
	for _, fd := range result.Files {
		if fd.Path == "package.json" && fd.Protected {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("expected package.json entry to be marked Protected, got Files=%+v", result.Files)
	}
}

// TestManagerFlow_NonGitFixture_NoChangesYieldsEmptyDiff ensures the diff
// engine returns no entries when the workspace matches its baseline byte
// for byte. This is the "agent did nothing" case: Diff must not surface
// stale entries from earlier state.
func TestManagerFlow_NonGitFixture_NoChangesYieldsEmptyDiff(t *testing.T) {
	source := nonGitFixtureSource(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	envName := "untouched"
	now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

	info, err := CreateCopy(aiEnvDir, envName, source, "", now)
	if err != nil {
		t.Fatalf("CreateCopy: %v", err)
	}
	t.Cleanup(func() { restoreWriteBitsRecursive(info.BaselinePath) })

	matcher, err := NewProtectedMatcher(nil)
	if err != nil {
		t.Fatalf("NewProtectedMatcher: %v", err)
	}
	result, err := Diff(aiEnvDir, envName, matcher)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("Files = %+v, want empty for unmodified workspace", result.Files)
	}
	if strings.TrimSpace(result.Unified) != "" {
		t.Errorf("Unified = %q, want empty", result.Unified)
	}
	if len(result.ProtectedHits) != 0 {
		t.Errorf("ProtectedHits = %v, want empty", result.ProtectedHits)
	}
}
