package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallShim_WritesOneWrapperPerProgram verifies that the
// wrapper count matches the program count and that every wrapper
// has the expected mode and body.
func TestInstallShim_WritesOneWrapperPerProgram(t *testing.T) {
	dir := t.TempDir()
	programs := []ShimProgram{"bash", "python3", "curl"}
	written, err := InstallShim(InstallShimOptions{
		ShimDir:   dir,
		HelperCmd: "/usr/local/bin/ai-env shim-helper",
		Programs:  programs,
	})
	if err != nil {
		t.Fatalf("InstallShim err = %v", err)
	}
	if len(written) != len(programs) {
		t.Fatalf("InstallShim wrote %d wrappers, want %d", len(written), len(programs))
	}

	for i, p := range programs {
		path := filepath.Join(dir, string(p))
		if written[i] != path {
			t.Errorf("written[%d] = %q, want %q", i, written[i], path)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat wrapper %s: %v", path, err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("wrapper %s mode = %v, want 0755", path, info.Mode().Perm())
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read wrapper %s: %v", path, err)
		}
		bodyStr := string(body)
		if !strings.HasPrefix(bodyStr, "#!/bin/sh\n") {
			t.Errorf("wrapper %s missing /bin/sh shebang: %q", path, bodyStr)
		}
		if !strings.Contains(bodyStr, "unset AI_ENV_CONTROL_SOCKET") {
			t.Errorf("wrapper %s missing unset AI_ENV_CONTROL_SOCKET", path)
		}
		wantExec := "exec /usr/local/bin/ai-env shim-helper shell " + string(p) + " \"$@\""
		if !strings.Contains(bodyStr, wantExec) {
			t.Errorf("wrapper %s missing exec line %q; body = %q", path, wantExec, bodyStr)
		}
	}
}

// TestInstallShim_DefaultsToCanonicalSet verifies that a nil
// Programs falls back to the full ShimProgramSet.
func TestInstallShim_DefaultsToCanonicalSet(t *testing.T) {
	dir := t.TempDir()
	written, err := InstallShim(InstallShimOptions{
		ShimDir:   dir,
		HelperCmd: "/usr/local/bin/ai-env shim-helper",
	})
	if err != nil {
		t.Fatalf("InstallShim err = %v", err)
	}
	if len(written) != len(ShimProgramSet) {
		t.Errorf("default install wrote %d wrappers, want %d (canonical set)", len(written), len(ShimProgramSet))
	}
}

// TestInstallShim_RejectsEmptyShimDir verifies the input-guard
// branches surface clear errors.
func TestInstallShim_RejectsEmptyShimDir(t *testing.T) {
	if _, err := InstallShim(InstallShimOptions{HelperCmd: "/usr/local/bin/ai-env shim-helper"}); err == nil {
		t.Errorf("InstallShim with empty ShimDir should error")
	}
}

func TestInstallShim_RejectsEmptyHelperCmd(t *testing.T) {
	dir := t.TempDir()
	if _, err := InstallShim(InstallShimOptions{ShimDir: dir}); err == nil {
		t.Errorf("InstallShim with empty HelperCmd should error")
	}
}

func TestInstallShim_RejectsNonDirectoryShimDir(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "regularfile")
	if err := os.WriteFile(tmp, []byte("x"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := InstallShim(InstallShimOptions{
		ShimDir:   tmp,
		HelperCmd: "/usr/local/bin/ai-env shim-helper",
	}); err == nil {
		t.Errorf("InstallShim against a regular file should error")
	}
}

// TestInstallShim_OverwritesExistingWrapper verifies that a stale
// wrapper from a previous run is replaced atomically.
func TestInstallShim_OverwritesExistingWrapper(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "bash")
	if err := os.WriteFile(stale, []byte("stale\n"), 0o600); err != nil {
		t.Fatalf("write stale wrapper: %v", err)
	}
	if _, err := InstallShim(InstallShimOptions{
		ShimDir:   dir,
		HelperCmd: "/usr/local/bin/ai-env shim-helper",
		Programs:  []ShimProgram{"bash"},
	}); err != nil {
		t.Fatalf("InstallShim err = %v", err)
	}
	body, err := os.ReadFile(stale)
	if err != nil {
		t.Fatalf("read wrapper: %v", err)
	}
	if strings.HasPrefix(string(body), "stale") {
		t.Errorf("wrapper not overwritten; body = %q", body)
	}
}
