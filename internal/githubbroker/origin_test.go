package githubbroker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseOriginRepo_AcceptsKnownShapes covers the three primary URL
// shapes the supervisor encounters in practice: HTTPS, SCP-style SSH,
// and ssh:// URLs. Each parse must yield the same (owner, name, host)
// because all four URLs reference the same repository — the test
// guarantees the parser does not distinguish on transport.
func TestParseOriginRepo_AcceptsKnownShapes(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want OriginPin
	}{
		{"https with .git", "https://github.com/octocat/hello-world.git", OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}},
		{"https without .git", "https://github.com/octocat/hello-world", OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}},
		{"http", "http://github.com/octocat/hello-world", OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}},
		{"https with port", "https://github.com:443/octocat/hello-world", OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}},
		{"https with userinfo", "https://user:token@github.com/octocat/hello-world.git", OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}},
		{"ssh scp-style", "git@github.com:octocat/hello-world.git", OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}},
		{"ssh url", "ssh://git@github.com/octocat/hello-world.git", OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}},
		{"git url", "git://github.com/octocat/hello-world.git", OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}},
		{"ghe host", "https://github.enterprise.local/team/repo.git", OriginPin{Owner: "team", Name: "repo", Host: "github.enterprise.local"}},
		{"mixed case host", "https://GitHub.COM/Octocat/Hello-World.git", OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseOriginRepo(tc.url)
			if err != nil {
				t.Fatalf("ParseOriginRepo(%q) err=%v, want nil", tc.url, err)
			}
			if got != tc.want {
				t.Fatalf("ParseOriginRepo(%q)=%+v, want %+v", tc.url, got, tc.want)
			}
		})
	}
}

// TestParseOriginRepo_RejectsBadShapes pins the ErrInvalidOrigin contract
// for every shape that does not match the documented HTTPS / SSH / git://
// vocabulary. We assert errors.Is matches ErrInvalidOrigin for each so a
// caller can pattern-match on the sentinel.
func TestParseOriginRepo_RejectsBadShapes(t *testing.T) {
	bad := []string{
		"",
		"github.com/octocat/hello-world",
		"https://github.com/octocat",
		"https://github.com/octocat/hello-world/extra",
		"git@github.com",
		"git@github.com:octocat",
		"file:///tmp/repo.git",
		"https:///no-host/octocat/hello",
		"https://github.com/ /name",
		"https://github.com/owner/ ",
	}
	for _, in := range bad {
		t.Run(in, func(t *testing.T) {
			_, err := ParseOriginRepo(in)
			if err == nil {
				t.Fatalf("ParseOriginRepo(%q) err=nil, want non-nil", in)
			}
			if !errors.Is(err, ErrInvalidOrigin) {
				t.Fatalf("ParseOriginRepo(%q) err=%v, want errors.Is(ErrInvalidOrigin)", in, err)
			}
		})
	}
}

// TestOriginPin_RecordAndLoadRoundtrip drives RecordOriginPin then
// LoadOriginPin and asserts the round-trip is loss-free for the
// (owner, name, host) triple.
func TestOriginPin_RecordAndLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	pin := OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}
	if err := RecordOriginPin(dir, pin); err != nil {
		t.Fatalf("RecordOriginPin: %v", err)
	}
	got, err := LoadOriginPin(dir)
	if err != nil {
		t.Fatalf("LoadOriginPin: %v", err)
	}
	if got != pin {
		t.Fatalf("LoadOriginPin=%+v, want %+v", got, pin)
	}

	// Re-recording must overwrite (atomic rename). Drift one byte to
	// confirm.
	pin2 := OriginPin{Owner: "acme", Name: "demo", Host: "github.enterprise.local"}
	if err := RecordOriginPin(dir, pin2); err != nil {
		t.Fatalf("RecordOriginPin (overwrite): %v", err)
	}
	got2, err := LoadOriginPin(dir)
	if err != nil {
		t.Fatalf("LoadOriginPin (after overwrite): %v", err)
	}
	if got2 != pin2 {
		t.Fatalf("LoadOriginPin=%+v, want %+v", got2, pin2)
	}
}

// TestOriginPin_LoadMissingReturnsPinNotFound asserts the ErrPinNotFound
// sentinel surfaces for a workspace that never recorded a pin (the
// pre-iter-4 fresh-workspace case the CLI handles as "refuse PR").
func TestOriginPin_LoadMissingReturnsPinNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadOriginPin(dir)
	if !errors.Is(err, ErrPinNotFound) {
		t.Fatalf("LoadOriginPin (missing) err=%v, want errors.Is(ErrPinNotFound)", err)
	}
}

// TestOriginPin_LoadIncompleteReturnsPinNotFound asserts that a YAML
// file with a missing field is treated as "no pin" rather than
// silently accepted, so a half-written file cannot mask a drift.
func TestOriginPin_LoadIncompleteReturnsPinNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, OriginPinFilename)
	if err := os.WriteFile(path, []byte("version: 1\norigin_pin:\n  owner: octocat\n  host: github.com\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := LoadOriginPin(dir)
	if !errors.Is(err, ErrPinNotFound) {
		t.Fatalf("LoadOriginPin (incomplete) err=%v, want errors.Is(ErrPinNotFound)", err)
	}
}

// TestOriginPin_LoadUnsupportedVersionFails asserts a future-versioned
// file is rejected so an older binary cannot mis-interpret a newer
// pin format.
func TestOriginPin_LoadUnsupportedVersionFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, OriginPinFilename)
	if err := os.WriteFile(path, []byte("version: 999\norigin_pin:\n  owner: o\n  name: n\n  host: h\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := LoadOriginPin(dir)
	if err == nil {
		t.Fatalf("LoadOriginPin (bad version) err=nil, want non-nil")
	}
	if errors.Is(err, ErrPinNotFound) {
		t.Fatalf("LoadOriginPin (bad version) should NOT be PinNotFound: %v", err)
	}
}

// TestBroker_OriginPinMatchesAtPR is the plan §4.1 acceptance: a
// workspace whose pin matches the live origin URL passes the
// CheckOriginPin gate.
func TestBroker_OriginPinMatchesAtPR(t *testing.T) {
	dir := t.TempDir()
	pin := OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}
	if err := RecordOriginPin(dir, pin); err != nil {
		t.Fatalf("RecordOriginPin: %v", err)
	}

	// HTTPS and SSH live URLs both must match the same recorded pin —
	// the parser strips transport differences so a workspace recorded
	// from HTTPS still matches a later SSH push.
	for _, live := range []string{
		"https://github.com/octocat/hello-world.git",
		"git@github.com:octocat/hello-world.git",
		"https://github.com/octocat/hello-world",
		"https://user:tok@github.com/Octocat/Hello-World.git",
	} {
		t.Run(live, func(t *testing.T) {
			got, err := CheckOriginPin(dir, live)
			if err != nil {
				t.Fatalf("CheckOriginPin(%q) err=%v, want nil", live, err)
			}
			if got != pin {
				t.Fatalf("CheckOriginPin(%q)=%+v, want %+v", live, got, pin)
			}
		})
	}
}

// TestBroker_OriginDriftBlocks is the plan §4.1 acceptance: any
// (owner, name, host) divergence between pin and live URL surfaces
// ErrOriginDrift so the broker refuses the push.
func TestBroker_OriginDriftBlocks(t *testing.T) {
	dir := t.TempDir()
	pin := OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}
	if err := RecordOriginPin(dir, pin); err != nil {
		t.Fatalf("RecordOriginPin: %v", err)
	}
	cases := []struct {
		name string
		live string
	}{
		{"owner drift", "https://github.com/evil/hello-world.git"},
		{"name drift", "https://github.com/octocat/world.git"},
		{"host drift", "https://github.enterprise.local/octocat/hello-world.git"},
		{"transport+host drift", "git@github.enterprise.local:octocat/hello-world.git"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckOriginPin(dir, tc.live)
			if err == nil {
				t.Fatalf("CheckOriginPin(%q) err=nil, want non-nil (drift expected)", tc.live)
			}
			if !errors.Is(err, ErrOriginDrift) {
				t.Fatalf("CheckOriginPin(%q) err=%v, want errors.Is(ErrOriginDrift)", tc.live, err)
			}
		})
	}
}

// TestOriginPin_ToRepo asserts the pin-to-Repo conversion produces a
// repo identifier the broker can push against. CloneURL is HTTPS even
// when the pin was recorded from an SSH URL, matching the
// "credentials embed via token-substitution in HTTPS" rule.
func TestOriginPin_ToRepo(t *testing.T) {
	pin := OriginPin{Owner: "octocat", Name: "hello-world", Host: "github.com"}
	repo := pin.ToRepo()
	if repo.Owner != "octocat" || repo.Name != "hello-world" {
		t.Fatalf("ToRepo owner/name=%s/%s, want octocat/hello-world", repo.Owner, repo.Name)
	}
	want := "https://github.com/octocat/hello-world.git"
	if repo.CloneURL != want {
		t.Fatalf("ToRepo.CloneURL=%q, want %q", repo.CloneURL, want)
	}
}

// TestWorkspaceOriginURL_NonGitDirReturnsEmpty exercises the
// "no origin available" path: a plain directory with no .git folder
// returns ("", nil) so the CLI can treat it as "skip the pin check"
// rather than as an error.
func TestWorkspaceOriginURL_NonGitDirReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	got, err := WorkspaceOriginURL(dir)
	if err != nil {
		// On systems without git installed this returns an exec.Error
		// instead. We accept both shapes; the only failure is "got a
		// URL out of a non-git directory".
		if !strings.Contains(err.Error(), "git") {
			t.Fatalf("WorkspaceOriginURL non-git dir err=%v, want git-related or nil", err)
		}
		return
	}
	if got != "" {
		t.Fatalf("WorkspaceOriginURL non-git dir=%q, want \"\"", got)
	}
}
