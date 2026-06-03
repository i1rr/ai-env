package policy

import (
	"path/filepath"
	"testing"

	"github.com/i1rr/ai-env/internal/backend"
)

// TestBuildShimBindMounts_DefaultsCoverEveryCanonicalPath is the
// "TestSandboxShim_ShadowsAllCanonicalPaths" acceptance from Plan
// Batch 1.3: with default ShimProgramSet × ShimCanonicalPathPrefixes
// the helper emits one BindMount per (program, prefix) pair.
func TestBuildShimBindMounts_DefaultsCoverEveryCanonicalPath(t *testing.T) {
	mounts, err := BuildShimBindMounts(BuildShimBindMountsOptions{
		ShimDir: "/run/ai-env/shim",
	})
	if err != nil {
		t.Fatalf("BuildShimBindMounts: %v", err)
	}
	want := len(ShimProgramSet) * len(ShimCanonicalPathPrefixes)
	if len(mounts) != want {
		t.Fatalf("len(mounts) = %d, want %d (programs=%d, prefixes=%d)",
			len(mounts), want, len(ShimProgramSet), len(ShimCanonicalPathPrefixes))
	}

	// Build a set of (target) entries we expect.
	wantTargets := make(map[string]bool, want)
	for _, p := range ShimProgramSet {
		for _, prefix := range ShimCanonicalPathPrefixes {
			wantTargets[filepath.Join(prefix, string(p))] = true
		}
	}
	for _, m := range mounts {
		if !wantTargets[m.Target] {
			t.Errorf("unexpected mount target %q", m.Target)
		}
		delete(wantTargets, m.Target)
	}
	if len(wantTargets) > 0 {
		t.Errorf("missing %d expected targets, e.g. %v", len(wantTargets), wantTargets)
	}
}

// TestBuildShimBindMounts_PerEntryProperties pins ReadOnly+Source+Mode
// invariants: every entry must be read-only (plan locked decision),
// Source must be the wrapper path under ShimDir, and Mode must remain
// zero so the adapter inherits the source mode.
func TestBuildShimBindMounts_PerEntryProperties(t *testing.T) {
	mounts, err := BuildShimBindMounts(BuildShimBindMountsOptions{
		ShimDir:               "/host/shim",
		Programs:              []ShimProgram{"curl"},
		CanonicalPathPrefixes: []string{"/usr/bin", "/bin", "/usr/local/bin"},
	})
	if err != nil {
		t.Fatalf("BuildShimBindMounts: %v", err)
	}
	if len(mounts) != 3 {
		t.Fatalf("len(mounts) = %d, want 3", len(mounts))
	}
	wantSource := "/host/shim/curl"
	wantTargets := []string{"/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"}
	for i, m := range mounts {
		if m.Source != wantSource {
			t.Errorf("mounts[%d].Source = %q, want %q", i, m.Source, wantSource)
		}
		if m.Target != wantTargets[i] {
			t.Errorf("mounts[%d].Target = %q, want %q", i, m.Target, wantTargets[i])
		}
		if !m.ReadOnly {
			t.Errorf("mounts[%d].ReadOnly = false, want true", i)
		}
		if m.Mode != 0 {
			t.Errorf("mounts[%d].Mode = %v, want 0 (inherit source mode)", i, m.Mode)
		}
	}
}

// TestBuildShimBindMounts_DeterministicOrdering pins the
// program-outer-prefix-inner declaration order so a reviewer who reads
// lifecycle.jsonl sees the same per-program block across runs.
func TestBuildShimBindMounts_DeterministicOrdering(t *testing.T) {
	mounts, err := BuildShimBindMounts(BuildShimBindMountsOptions{
		ShimDir:               "/h",
		Programs:              []ShimProgram{"bash", "python3"},
		CanonicalPathPrefixes: []string{"/usr/bin", "/bin", "/usr/local/bin"},
	})
	if err != nil {
		t.Fatalf("BuildShimBindMounts: %v", err)
	}
	wantOrder := []string{
		"/usr/bin/bash", "/bin/bash", "/usr/local/bin/bash",
		"/usr/bin/python3", "/bin/python3", "/usr/local/bin/python3",
	}
	if len(mounts) != len(wantOrder) {
		t.Fatalf("len(mounts) = %d, want %d", len(mounts), len(wantOrder))
	}
	for i, m := range mounts {
		if m.Target != wantOrder[i] {
			t.Errorf("mounts[%d].Target = %q, want %q", i, m.Target, wantOrder[i])
		}
	}
}

// TestBuildShimBindMounts_RejectsEmptyShimDir pins the input validation:
// without a ShimDir there is nowhere to mount FROM, so the helper must
// not silently emit unanchored entries.
func TestBuildShimBindMounts_RejectsEmptyShimDir(t *testing.T) {
	if _, err := BuildShimBindMounts(BuildShimBindMountsOptions{}); err == nil {
		t.Fatalf("BuildShimBindMounts: expected error for empty ShimDir")
	}
}

// TestBuildShimBindMounts_RejectsRelativeShimDir pins that the helper
// refuses a relative ShimDir; the supervisor passes the absolute run
// directory path and a relative one would surprise the adapter.
func TestBuildShimBindMounts_RejectsRelativeShimDir(t *testing.T) {
	if _, err := BuildShimBindMounts(BuildShimBindMountsOptions{ShimDir: "shim"}); err == nil {
		t.Fatalf("BuildShimBindMounts: expected error for relative ShimDir")
	}
}

// TestBuildShimBindMounts_RejectsRelativePrefix pins that the helper
// refuses a non-absolute canonical path prefix; the plan pins the set
// to absolute paths only.
func TestBuildShimBindMounts_RejectsRelativePrefix(t *testing.T) {
	_, err := BuildShimBindMounts(BuildShimBindMountsOptions{
		ShimDir:               "/h",
		CanonicalPathPrefixes: []string{"bin"},
	})
	if err == nil {
		t.Fatalf("BuildShimBindMounts: expected error for relative prefix")
	}
}

// TestBuildShimBindMounts_TolerantOfMissingTarget is the second Batch
// 1.3 acceptance: BuildShimBindMounts does not stat the host-side
// Source or the in-sandbox Target; an entry whose target path does not
// exist in the image is still emitted, and the adapter / supervisor
// surface the per-entry failure as shim_coverage_degraded. The
// helper's job is to compose deterministic shadow entries, not to
// pre-validate the image layout (which would require probing — the
// plan's locked decision rules that out).
func TestBuildShimBindMounts_TolerantOfMissingTarget(t *testing.T) {
	// The Source path "/no/such/dir/curl" does not exist on the host.
	// BuildShimBindMounts must still emit the entry.
	mounts, err := BuildShimBindMounts(BuildShimBindMountsOptions{
		ShimDir:               "/no/such/dir",
		Programs:              []ShimProgram{"curl"},
		CanonicalPathPrefixes: []string{"/usr/bin"},
	})
	if err != nil {
		t.Fatalf("BuildShimBindMounts: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("len(mounts) = %d, want 1", len(mounts))
	}
	if mounts[0].Source != "/no/such/dir/curl" {
		t.Errorf("Source = %q, want /no/such/dir/curl", mounts[0].Source)
	}
	if mounts[0].Target != "/usr/bin/curl" {
		t.Errorf("Target = %q, want /usr/bin/curl", mounts[0].Target)
	}
}

// TestBuildShimBindMounts_ReturnTypeIsBackendBindMount confirms the
// emitted slice is a plain []backend.BindMount the supervisor can pass
// verbatim to EnvSpec.BindMounts.
func TestBuildShimBindMounts_ReturnTypeIsBackendBindMount(t *testing.T) {
	mounts, err := BuildShimBindMounts(BuildShimBindMountsOptions{
		ShimDir:               "/h",
		Programs:              []ShimProgram{"sh"},
		CanonicalPathPrefixes: []string{"/usr/bin"},
	})
	if err != nil {
		t.Fatalf("BuildShimBindMounts: %v", err)
	}
	var _ []backend.BindMount = mounts // compile-time pin
	if len(mounts) != 1 {
		t.Fatalf("len(mounts) = %d, want 1", len(mounts))
	}
}
