package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/config"
)

// --- Step 7: scaffold generation -----------------------------------------

// TestRunNew_GeneratesValidConfigs runs the full scaffold flow against a
// temp dir and then loads every emitted YAML back through the config
// loader. If the generator produces something the validator rejects, this
// test catches it.
func TestRunNew_GeneratesValidConfigs(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer

	err := RunNew(NewOptions{
		EnvName: "demo",
		Cwd:     dir,
		Stdout:  &out,
	})
	if err != nil {
		t.Fatalf("RunNew: %v", err)
	}

	aiEnvDir := filepath.Join(dir, ".ai-env")
	expected := []string{
		"ai-env.yaml",
		"policy.yaml",
		"agents.yaml",
		"secrets.example.yaml",
		"secrets.local.yaml",
	}
	for _, name := range expected {
		path := filepath.Join(aiEnvDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected %s to exist: %v", path, err)
		}
	}

	// Every generated file must round-trip through its loader.
	if _, err := config.LoadAIEnv(filepath.Join(aiEnvDir, "ai-env.yaml")); err != nil {
		t.Errorf("generated ai-env.yaml fails to load: %v", err)
	}
	if _, err := config.LoadPolicy(filepath.Join(aiEnvDir, "policy.yaml")); err != nil {
		t.Errorf("generated policy.yaml fails to load: %v", err)
	}
	if _, err := config.LoadAgents(filepath.Join(aiEnvDir, "agents.yaml")); err != nil {
		t.Errorf("generated agents.yaml fails to load: %v", err)
	}
	if _, err := config.LoadSecretsExample(filepath.Join(aiEnvDir, "secrets.example.yaml")); err != nil {
		t.Errorf("generated secrets.example.yaml fails to load: %v", err)
	}

	// Project name should reflect the requested env name.
	cfg, err := config.LoadAIEnv(filepath.Join(aiEnvDir, "ai-env.yaml"))
	if err != nil {
		t.Fatalf("re-load ai-env.yaml: %v", err)
	}
	if cfg.Project.Name != "demo" {
		t.Errorf("project.name = %q, want demo", cfg.Project.Name)
	}
	// Default template for an empty directory is "default".
	if cfg.Sandbox.Template != "default" {
		t.Errorf("sandbox.template = %q, want default", cfg.Sandbox.Template)
	}
}

// TestRunNew_SecretsLocalIsMode0600 verifies the gitignored stub has
// strict permissions (per acceptance criterion 5). POSIX-only because
// Windows file modes do not behave this way; the runtime guard makes the
// test portable.
func TestRunNew_SecretsLocalIsMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode test")
	}
	dir := t.TempDir()
	if err := RunNew(NewOptions{EnvName: "demo", Cwd: dir, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, ".ai-env", "secrets.local.yaml"))
	if err != nil {
		t.Fatalf("stat secrets.local.yaml: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("secrets.local.yaml mode = %o, want 0600", mode)
	}
}

// TestRunNew_RefusesOverwriteWithoutForce confirms a second invocation
// without --force fails and leaves files untouched (acceptance criterion 2).
func TestRunNew_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	if err := RunNew(NewOptions{EnvName: "demo", Cwd: dir, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("first RunNew: %v", err)
	}
	// Capture mtime of ai-env.yaml so we can prove it was not rewritten.
	path := filepath.Join(dir, ".ai-env", "ai-env.yaml")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat ai-env.yaml: %v", err)
	}

	err = RunNew(NewOptions{EnvName: "demo", Cwd: dir, Stdout: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected second RunNew without --force to fail")
	}
	if !strings.Contains(err.Error(), "force") {
		t.Errorf("error should mention --force: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("re-stat ai-env.yaml: %v", err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("ai-env.yaml was rewritten despite refusal")
	}
}

// TestRunNew_ForceOverwrites confirms --force replaces files cleanly.
func TestRunNew_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	if err := RunNew(NewOptions{EnvName: "demo", Cwd: dir, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("first RunNew: %v", err)
	}
	if err := RunNew(NewOptions{EnvName: "demo", Cwd: dir, Force: true, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew with --force: %v", err)
	}
	// File should still load.
	if _, err := config.LoadAIEnv(filepath.Join(dir, ".ai-env", "ai-env.yaml")); err != nil {
		t.Errorf("ai-env.yaml after --force fails to load: %v", err)
	}
}

func TestValidateEnvName(t *testing.T) {
	good := []string{"demo", "fix-tests", "v1.2.3", "abc_123", "a"}
	for _, n := range good {
		if err := ValidateEnvName(n); err != nil {
			t.Errorf("expected %q to be valid: %v", n, err)
		}
	}
	bad := []string{"", "-leading-dash", ".leading-dot", "white space", "has/slash", "has:colon", strings.Repeat("a", 65)}
	for _, n := range bad {
		if err := ValidateEnvName(n); err == nil {
			t.Errorf("expected %q to be invalid", n)
		}
	}
}

func TestRunNew_InvalidName(t *testing.T) {
	err := RunNew(NewOptions{EnvName: "bad name", Cwd: t.TempDir(), Stdout: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected invalid env name to fail")
	}
}

// TestDefaultGenerators_AllValid pins the in-memory defaults: every
// generator must produce a struct the validator accepts. If we ever break
// this contract the generator would write a file the loader cannot read.
func TestDefaultGenerators_AllValid(t *testing.T) {
	if err := config.ValidateAIEnv(defaultAIEnvConfig("demo", "..", "default")); err != nil {
		t.Errorf("defaultAIEnvConfig invalid: %v", err)
	}
	if err := config.ValidatePolicy(defaultPolicyConfig()); err != nil {
		t.Errorf("defaultPolicyConfig invalid: %v", err)
	}
	if err := config.ValidateAgents(defaultAgentsConfig()); err != nil {
		t.Errorf("defaultAgentsConfig invalid: %v", err)
	}
	if err := config.ValidateSecretsExample(defaultSecretsExampleConfig()); err != nil {
		t.Errorf("defaultSecretsExampleConfig invalid: %v", err)
	}
}

// --- Step 8: stack detection ---------------------------------------------

// TestDetectStack_KnownMarkers verifies each documented marker file maps
// to the right template. Fixtures are real files placed in t.TempDir()
// so we test the on-disk path the real CLI takes.
func TestDetectStack_KnownMarkers(t *testing.T) {
	cases := []struct {
		marker   string
		template string
	}{
		{"go.mod", "go"},
		{"Cargo.toml", "rust"},
		{"package.json", "node"},
		{"pyproject.toml", "python"},
		{"requirements.txt", "python"},
	}
	for _, tc := range cases {
		t.Run(tc.marker, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.marker), []byte("stub"), 0o644); err != nil {
				t.Fatalf("write marker: %v", err)
			}
			got := DetectStack(Source{Path: dir})
			if got != tc.template {
				t.Errorf("DetectStack(%s) = %q, want %q", tc.marker, got, tc.template)
			}
		})
	}
}

// TestDetectStack_NoMarkersReturnsDefault is the negative path: an empty
// directory should map to the "default" template.
func TestDetectStack_NoMarkersReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	if got := DetectStack(Source{Path: dir}); got != "default" {
		t.Errorf("DetectStack(empty) = %q, want default", got)
	}
}

// TestDetectStack_PrecedenceFollowsTableOrder confirms when multiple
// markers are present the first entry in stackMarkers wins. go.mod is
// listed first, so a directory with both go.mod and package.json must
// be detected as "go".
func TestDetectStack_PrecedenceFollowsTableOrder(t *testing.T) {
	dir := t.TempDir()
	for _, m := range []string{"go.mod", "package.json", "pyproject.toml"} {
		if err := os.WriteFile(filepath.Join(dir, m), []byte("stub"), 0o644); err != nil {
			t.Fatalf("write %s: %v", m, err)
		}
	}
	if got := DetectStack(Source{Path: dir}); got != "go" {
		t.Errorf("DetectStack(multi) = %q, want go (first in stackMarkers)", got)
	}
}

// TestDetectStack_MarkerAsDirectoryIgnored documents that a directory
// named like a marker (e.g. someone has a folder called package.json)
// is detected the same way because os.Stat succeeds for directories too.
// We assert the *current* behavior so a regression here is intentional.
func TestDetectStack_MarkerAsDirectoryIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "package.json"), 0o755); err != nil {
		t.Fatalf("mkdir marker: %v", err)
	}
	// Current implementation only checks existence, not file-vs-dir.
	if got := DetectStack(Source{Path: dir}); got != "node" {
		t.Errorf("DetectStack(dir-marker) = %q, want node (existence-only check)", got)
	}
}

// --- Step 9: .gitignore entry generation ---------------------------------

// TestUpdateGitignore_NoFileReturnsSuggestions covers the documented
// behavior: when no .gitignore exists, the plan says "list in terminal".
// We must not create the file.
func TestUpdateGitignore_NoFileReturnsSuggestions(t *testing.T) {
	dir := t.TempDir()
	res := updateGitignore(dir)

	if res.Existed {
		t.Error("Existed should be false when no .gitignore")
	}
	if len(res.Added) != 0 {
		t.Errorf("Added should be empty, got %v", res.Added)
	}
	if !sameStringSet(res.Suggested, gitignoreEntries) {
		t.Errorf("Suggested = %v, want %v", res.Suggested, gitignoreEntries)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); !os.IsNotExist(err) {
		t.Errorf(".gitignore should not have been created, stat err = %v", err)
	}
}

// TestUpdateGitignore_AppendsMissingToExisting drops an existing file
// with one unrelated entry and confirms the missing entries are appended
// without disturbing the pre-existing content.
func TestUpdateGitignore_AppendsMissingToExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	original := "node_modules/\n*.log\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatalf("write .gitignore: %v", err)
	}

	res := updateGitignore(dir)

	if !res.Existed {
		t.Error("Existed should be true")
	}
	if len(res.Added) != len(gitignoreEntries) {
		t.Errorf("Added len = %d, want %d", len(res.Added), len(gitignoreEntries))
	}
	if len(res.Suggested) != 0 {
		t.Errorf("Suggested should be empty when file exists, got %v", res.Suggested)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	got := string(data)
	if !strings.HasPrefix(got, original) {
		t.Errorf("original content was disturbed:\n%s", got)
	}
	for _, entry := range gitignoreEntries {
		if !strings.Contains(got, "\n"+entry+"\n") && !strings.HasSuffix(got, entry+"\n") {
			t.Errorf("missing entry %q in:\n%s", entry, got)
		}
	}
	// Header marker should also be present so future runs see the block.
	if !strings.Contains(got, gitignoreSectionHeader) {
		t.Errorf("section header %q missing from output:\n%s", gitignoreSectionHeader, got)
	}
}

// TestUpdateGitignore_NoOpWhenAllPresent ensures a second invocation
// against a complete .gitignore neither rewrites nor double-appends.
func TestUpdateGitignore_NoOpWhenAllPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(path, []byte("node_modules/\n"), 0o644); err != nil {
		t.Fatalf("seed .gitignore: %v", err)
	}
	// First call populates everything.
	if res := updateGitignore(dir); len(res.Added) != len(gitignoreEntries) {
		t.Fatalf("first call should have added entries, got %v", res.Added)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after first call: %v", err)
	}
	// Second call: nothing missing.
	res := updateGitignore(dir)
	if len(res.Added) != 0 {
		t.Errorf("Added should be empty on second call, got %v", res.Added)
	}
	if !res.Existed {
		t.Error("Existed should remain true")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after second call: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("file changed on no-op call:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestUpdateGitignore_HandlesMissingTrailingNewline guards against
// concatenation glitches: an existing file with no trailing newline
// must still get a properly separated new block.
func TestUpdateGitignore_HandlesMissingTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(path, []byte("node_modules/"), 0o644); err != nil {
		t.Fatalf("write .gitignore: %v", err)
	}
	res := updateGitignore(dir)
	if !res.Existed || len(res.Added) == 0 {
		t.Fatalf("expected append, got %+v", res)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	got := string(data)
	// Old entry must still be intact and not merged with the header.
	if !strings.Contains(got, "node_modules/\n") {
		t.Errorf("missing trailing newline was not normalized:\n%s", got)
	}
	if !strings.Contains(got, gitignoreSectionHeader) {
		t.Errorf("header missing:\n%s", got)
	}
}

// TestUpdateGitignore_RecognizesEntriesWithComments confirms commented
// lines in the existing file do not cause us to re-add covered entries.
// Comments must be ignored, but real entries (even after comments) must
// still register as present.
func TestUpdateGitignore_RecognizesEntriesWithComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	body := "# user stuff\nnode_modules/\n# ai-env\n" + strings.Join(gitignoreEntries, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write .gitignore: %v", err)
	}
	res := updateGitignore(dir)
	if !res.Existed {
		t.Error("Existed should be true")
	}
	if len(res.Added) != 0 {
		t.Errorf("Added should be empty when entries already present, got %v", res.Added)
	}
}

// TestRunNew_GitignoreIntegration confirms the full RunNew flow correctly
// updates an existing .gitignore in the source directory.
func TestRunNew_GitignoreIntegration(t *testing.T) {
	dir := t.TempDir()
	gi := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(gi, []byte("node_modules/\n"), 0o644); err != nil {
		t.Fatalf("seed .gitignore: %v", err)
	}
	// RunNew now materializes a workspace as part of plan 02 step 8.
	// For non-Git sources that means CreateCopy leaves a read-only
	// baseline behind. Restore write bits so t.TempDir's cleanup can
	// remove the tree on macOS (where unlink-on-read-only-dir fails).
	t.Cleanup(func() { restoreWriteBits(filepath.Join(dir, ".ai-env")) })

	if err := RunNew(NewOptions{EnvName: "demo", Cwd: dir, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	data, err := os.ReadFile(gi)
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	for _, entry := range gitignoreEntries {
		if !strings.Contains(string(data), entry) {
			t.Errorf("RunNew did not propagate gitignore entry %q; file:\n%s", entry, data)
		}
	}
}

// restoreWriteBits walks root and re-adds write bits to every directory
// and file under it. CreateCopy leaves the baseline tree read-only
// (mode 0o555/0o444), which is the production behavior; this helper
// reverses that just enough to let t.TempDir's recursive cleanup unlink
// the children. It is best-effort: walk errors are swallowed because the
// only consumer is test cleanup, which never propagates errors anyway.
func restoreWriteBits(root string) {
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		_ = os.Chmod(p, 0o755)
		return nil
	})
}

// sameStringSet compares two []string for equality ignoring order.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
