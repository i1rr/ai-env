package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Helpers shared by the manager_git_fixture_test.go and
// manager_nongit_fixture_test.go suites (plan 02 steps 9 and 10). They are
// intentionally minimal: enough to seed and inspect on-disk fixtures
// without pulling in a wider test harness. Keeping them in their own file
// avoids duplicating the helpers inside each suite while staying out of
// the production code path.

// mustRunGit invokes `git <args...>` inside dir and fails the test if git
// returns a non-zero exit code. Combined stdout+stderr is included in the
// failure message so a bad fixture surfaces the actual git error rather
// than just an exit status.
func mustRunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

// writeFixtureFile writes content to path, creating any missing parent
// directories. Used both for seeding source trees and for making edits
// inside materialized workspaces. We bias toward 0o644 on files and 0o755
// on directories because the workspace package's production code paths do
// the same; matching those bits avoids spurious mode-related test noise.
func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// mustReadFile reads the file at path and returns its content as a string.
// It fails the test on any read error so the assertion site stays focused
// on the value rather than error plumbing.
func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// restoreWriteBitsRecursive walks root and re-adds write bits to every
// directory and file under it. CreateCopy leaves the baseline tree
// read-only (mode 0o555/0o444), which is the production behavior; this
// helper reverses that just enough to let t.TempDir's recursive cleanup
// unlink children on macOS. Best-effort: walk errors are swallowed because
// the only consumer is test cleanup, which never propagates errors anyway.
func restoreWriteBitsRecursive(root string) {
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		_ = os.Chmod(p, 0o755)
		return nil
	})
}
