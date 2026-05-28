package workspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedNonGitSource creates a real, non-Git source directory tree on disk with
// a mix of files in nested directories. It returns the absolute path to the
// root of that tree. The fixture is deliberately small but covers nested
// directories and multiple files so the copy strategy is exercised against
// something more interesting than a single flat directory.
//
// This is what plan 02 step 4 ("copy strategy for non-Git sources") needs to
// work against: a plain directory tree, no .git, just files.
func seedNonGitSource(t *testing.T) (string, map[string]string) {
	t.Helper()

	root := t.TempDir()

	// Use a content map so the assertions below can iterate the same data
	// the seed wrote. Keys are relative paths inside the source; values are
	// the exact bytes the file should contain after the copy.
	files := map[string]string{
		"README.md":              "non-git project\n",
		"src/main.go":            "package main\n\nfunc main() {}\n",
		"src/util/helper.go":     "package util\n\nfunc Helper() string { return \"ok\" }\n",
		"docs/notes.txt":         "some notes\nwith two lines\n",
		"config/settings.yaml":   "key: value\nnested:\n  inner: 1\n",
	}

	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}

	// Explicit sanity check: make sure the seed did not accidentally create
	// a .git directory. The copy strategy's contract is "non-Git source"; if
	// the fixture were a repo the test would silently test the wrong thing.
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		t.Fatalf("seed accidentally created a .git directory at %s", root)
	}

	return root, files
}

// TestCreateCopy_HappyPath is the end-to-end check for plan 02 step 4. It
// exercises the real CreateCopy against a real on-disk non-Git source tree
// and asserts the observable effects plan 02 step 4 requires:
//
//  1. The source directory is copied to .ai-env/workspaces/<env-name>/ and
//     every file's content matches the source byte for byte.
//  2. A baseline snapshot lives at .ai-env/baselines/<env-name>/ and is
//     read-only (regular files have no write bits).
//  3. The returned WorkspaceInfo records the strategy, paths, and metadata
//     the rest of the codebase relies on.
//  4. The on-disk .env-meta.json file carries the copy-strategy fields
//     (baseline_path, copy_time, hash_summary).
//
// No mocks: real filesystem, real directories, real content comparison.
func TestCreateCopy_HappyPath(t *testing.T) {
	source, files := seedNonGitSource(t)

	// aiEnvDir lives in its own temp dir so the workspace and baseline
	// directories CreateCopy is responsible for are observed in isolation.
	aiEnvDir := t.TempDir()

	envName := "fix-tests"
	template := "node"
	now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

	info, err := CreateCopy(aiEnvDir, envName, source, template, now)
	if err != nil {
		t.Fatalf("CreateCopy: %v", err)
	}

	// CreateCopy leaves the baseline tree read-only (mode 0o555/0o444), which
	// is the production behavior plan 02 step 4 requires. t.TempDir's own
	// cleanup hook calls os.RemoveAll on aiEnvDir at the end of the test, and
	// that recursive remove cannot unlink children inside a read-only
	// directory on macOS. Register an earlier cleanup that restores write
	// bits across the baseline tree so the harness's removal can proceed. The
	// chmod runs AFTER the test body's assertions because t.Cleanup runs in
	// LIFO order and t.TempDir's cleanup was registered first (so it runs
	// last). The assertion at (4) below still observes the read-only mode.
	t.Cleanup(func() {
		_ = filepath.Walk(BaselinePath(aiEnvDir, envName), func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			_ = os.Chmod(p, 0o755)
			return nil
		})
	})

	// (1) WorkspaceInfo carries the strategy and paths the rest of the
	// codebase relies on. Each field is checked explicitly so a regression
	// surfaces at the field it broke at, not at some downstream consumer.
	if info.Strategy != StrategyCopy {
		t.Errorf("Strategy = %q, want %q", info.Strategy, StrategyCopy)
	}
	if info.Name != envName {
		t.Errorf("Name = %q, want %q", info.Name, envName)
	}
	wantWS := WorkspacePath(aiEnvDir, envName)
	if info.Path != wantWS {
		t.Errorf("Path = %q, want %q", info.Path, wantWS)
	}
	wantBL := BaselinePath(aiEnvDir, envName)
	if info.BaselinePath != wantBL {
		t.Errorf("BaselinePath = %q, want %q", info.BaselinePath, wantBL)
	}
	if info.SourcePath != source {
		t.Errorf("SourcePath = %q, want %q", info.SourcePath, source)
	}
	if info.Branch != "" {
		t.Errorf("Branch = %q, want empty (copy strategy)", info.Branch)
	}
	if info.Template != template {
		t.Errorf("Template = %q, want %q", info.Template, template)
	}
	if !info.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", info.CreatedAt, now)
	}

	// (2) Every seeded file landed at the workspace path with its bytes
	// intact. This is the core copy-strategy guarantee: the agent's
	// workspace is a faithful clone of the source.
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(info.Path, rel))
		if err != nil {
			t.Errorf("workspace file %s missing: %v", rel, err)
			continue
		}
		if string(got) != want {
			t.Errorf("workspace file %s content mismatch:\n got: %q\nwant: %q", rel, string(got), want)
		}
	}

	// (3) The baseline is a byte-equal snapshot too. The baseline is what
	// Diff will compare the workspace against later, so it has to match the
	// same source the workspace was seeded from.
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(info.BaselinePath, rel))
		if err != nil {
			t.Errorf("baseline file %s missing: %v", rel, err)
			continue
		}
		if string(got) != want {
			t.Errorf("baseline file %s content mismatch:\n got: %q\nwant: %q", rel, string(got), want)
		}
	}

	// (4) Baseline files are read-only. The plan calls for a "read-only
	// baseline snapshot" so the agent (and accidental tooling) cannot edit
	// it in place. Checking the mode of a single representative file is
	// enough to catch a regression in the readOnly flag plumbing.
	st, err := os.Stat(filepath.Join(info.BaselinePath, "README.md"))
	if err != nil {
		t.Fatalf("stat baseline README.md: %v", err)
	}
	if st.Mode().Perm()&0o222 != 0 {
		t.Errorf("baseline file has write bits set: mode=%v", st.Mode().Perm())
	}

	// (5) Metadata file exists and carries the copy-strategy fields the
	// plan documents. We parse it through the same envMetadata struct the
	// production code uses so the test moves in lockstep with the schema.
	metaPath := MetadataPath(aiEnvDir, envName)
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read metadata %s: %v", metaPath, err)
	}
	var meta envMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("parse metadata: %v\n%s", err, string(raw))
	}
	if meta.Strategy != string(StrategyCopy) {
		t.Errorf("metadata strategy = %q, want %q", meta.Strategy, StrategyCopy)
	}
	if meta.BaselinePath != wantBL {
		t.Errorf("metadata baseline_path = %q, want %q", meta.BaselinePath, wantBL)
	}
	if meta.SourcePath != source {
		t.Errorf("metadata source_path = %q, want %q", meta.SourcePath, source)
	}
	if meta.CopyTime == "" {
		t.Errorf("metadata copy_time is empty; want RFC3339 timestamp")
	} else if _, err := time.Parse(time.RFC3339, meta.CopyTime); err != nil {
		t.Errorf("metadata copy_time %q not RFC3339: %v", meta.CopyTime, err)
	}
	if !strings.HasPrefix(meta.HashSummary, "sha256:") {
		t.Errorf("metadata hash_summary = %q, want sha256: prefix", meta.HashSummary)
	}
	if meta.Branch != "" {
		t.Errorf("metadata branch = %q, want empty for copy strategy", meta.Branch)
	}
}

// TestCreateCopy_RejectsNonExistentSource confirms the input-validation guard
// fires when the source path does not exist. This is the kind of misuse the
// CLI must surface cleanly rather than create a half-built workspace from.
func TestCreateCopy_RejectsNonExistentSource(t *testing.T) {
	aiEnvDir := t.TempDir()
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := CreateCopy(aiEnvDir, "env1", missing, "", time.Now())
	if err == nil {
		t.Fatalf("CreateCopy with missing source: want error, got nil")
	}

	// The workspace must not exist after a failed Create. A leftover
	// directory would block legitimate retries.
	if _, statErr := os.Stat(WorkspacePath(aiEnvDir, "env1")); !os.IsNotExist(statErr) {
		t.Errorf("workspace dir exists after failure: %v", statErr)
	}
}

// TestCreateCopy_RefusesToClobberExistingWorkspace confirms that CreateCopy
// stays conservative when a workspace already exists at the target path. The
// plan calls this out as a safety property: a retried run must not silently
// merge state with a previous attempt.
func TestCreateCopy_RefusesToClobberExistingWorkspace(t *testing.T) {
	source, _ := seedNonGitSource(t)
	aiEnvDir := t.TempDir()
	envName := "already-there"

	// Pre-create the workspace directory so CreateCopy's existence check
	// trips. We do not need to populate it; the check is "exists at all".
	if err := os.MkdirAll(WorkspacePath(aiEnvDir, envName), 0o755); err != nil {
		t.Fatalf("pre-create workspace dir: %v", err)
	}

	_, err := CreateCopy(aiEnvDir, envName, source, "", time.Now())
	if err == nil {
		t.Fatalf("CreateCopy over existing workspace: want error, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error %q does not mention 'already exists'", err.Error())
	}
}
