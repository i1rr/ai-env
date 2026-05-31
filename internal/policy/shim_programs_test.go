package policy

import (
	"sort"
	"testing"
)

// TestShimProgramSet_ContainsCanonicalPrograms locks the canonical
// list against accidental edits. The plan pins the exact set so a
// regression that drops `python3.11` or adds an un-vetted program
// fails this test first.
func TestShimProgramSet_ContainsCanonicalPrograms(t *testing.T) {
	want := []string{
		"sh", "bash", "dash", "zsh",
		"python", "python3", "python3.10", "python3.11", "python3.12",
		"perl", "ruby", "node",
		"curl", "wget", "nc", "ncat", "socat",
		"chmod", "osascript", "awk", "deno", "env",
	}
	got := make([]string, 0, len(ShimProgramSet))
	for _, p := range ShimProgramSet {
		got = append(got, string(p))
	}
	sortedWant := append([]string(nil), want...)
	sortedGot := append([]string(nil), got...)
	sort.Strings(sortedWant)
	sort.Strings(sortedGot)
	if len(sortedGot) != len(sortedWant) {
		t.Fatalf("ShimProgramSet has %d entries, want %d", len(sortedGot), len(sortedWant))
	}
	for i := range sortedWant {
		if sortedGot[i] != sortedWant[i] {
			t.Errorf("ShimProgramSet[%d] = %q, want %q", i, sortedGot[i], sortedWant[i])
		}
	}
}

// TestShimCanonicalPathPrefixes_PinnedSet locks the path prefixes
// against accidental edits. Plan pins {/usr/bin, /bin,
// /usr/local/bin}.
func TestShimCanonicalPathPrefixes_PinnedSet(t *testing.T) {
	want := []string{"/usr/bin", "/bin", "/usr/local/bin"}
	if len(ShimCanonicalPathPrefixes) != len(want) {
		t.Fatalf("ShimCanonicalPathPrefixes has %d entries, want %d", len(ShimCanonicalPathPrefixes), len(want))
	}
	for i, p := range ShimCanonicalPathPrefixes {
		if p != want[i] {
			t.Errorf("ShimCanonicalPathPrefixes[%d] = %q, want %q", i, p, want[i])
		}
	}
}

// TestShimCanonicalPaths_ReturnsCartesianProduct verifies the
// helper emits one entry per (prefix, program) pair in declared
// order.
func TestShimCanonicalPaths_ReturnsCartesianProduct(t *testing.T) {
	got := ShimCanonicalPaths("python3")
	want := []string{
		"/usr/bin/python3",
		"/bin/python3",
		"/usr/local/bin/python3",
	}
	if len(got) != len(want) {
		t.Fatalf("ShimCanonicalPaths(python3) returned %d entries, want %d", len(got), len(want))
	}
	for i, p := range got {
		if p != want[i] {
			t.Errorf("ShimCanonicalPaths(python3)[%d] = %q, want %q", i, p, want[i])
		}
	}
}

// TestShimCanonicalPaths_EmptyProgramReturnsNil verifies the
// guarded empty input.
func TestShimCanonicalPaths_EmptyProgramReturnsNil(t *testing.T) {
	if got := ShimCanonicalPaths(""); got != nil {
		t.Errorf("ShimCanonicalPaths(\"\") = %v, want nil", got)
	}
}

// TestIsShimmedProgram_AcceptsCanonical verifies the membership
// helper returns true for an entry from the canonical set and
// false for an unknown program.
func TestIsShimmedProgram_AcceptsCanonical(t *testing.T) {
	if !IsShimmedProgram("python3") {
		t.Errorf("IsShimmedProgram(python3) = false, want true")
	}
	if !IsShimmedProgram("bash") {
		t.Errorf("IsShimmedProgram(bash) = false, want true")
	}
	if IsShimmedProgram("notashim") {
		t.Errorf("IsShimmedProgram(notashim) = true, want false")
	}
	if IsShimmedProgram("") {
		t.Errorf("IsShimmedProgram(\"\") = true, want false")
	}
}
