package scanners

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TestDiscoverExternal_MissingScannersDoNotCrash pins plan 06 step 11:
// when no optional scanner binary is present on PATH, DiscoverExternal
// must report each tool as Available=false with a human-readable
// Message and never return an error. The CLI surfaces these entries
// as warnings rather than failures, which is the contract the
// "missing optional scanners do not crash" acceptance criterion
// depends on.
func TestDiscoverExternal_MissingScannersDoNotCrash(t *testing.T) {
	b, err := NewBuiltIn(Config{})
	if err != nil {
		t.Fatalf("NewBuiltIn: %v", err)
	}

	allMissing := func(name string) (string, error) {
		return "", exec.ErrNotFound
	}
	b.SetLookPath(allMissing)

	entries := b.DiscoverExternal()
	if len(entries) == 0 {
		t.Fatalf("DiscoverExternal returned no entries; expected the full known-scanner registry")
	}

	for _, e := range entries {
		if e.Name == "" {
			t.Fatalf("entry has empty Name: %+v", e)
		}
		if e.Available {
			t.Fatalf("entry %q reported Available=true under all-missing lookPath", e.Name)
		}
		if e.BinaryPath != "" {
			t.Fatalf("entry %q has BinaryPath=%q under all-missing lookPath", e.Name, e.BinaryPath)
		}
		if e.Message == "" {
			t.Fatalf("entry %q missing Message under all-missing lookPath", e.Name)
		}
	}
}

// TestRunExternal_RefusesUnavailableScanner pins the runExternal half
// of the contract: a tool whose discovery returned Available=false
// must not be invoked. RunExternal returns an error containing the
// discovery Message so the CLI can render a single coherent warning.
func TestRunExternal_RefusesUnavailableScanner(t *testing.T) {
	b, err := NewBuiltIn(Config{})
	if err != nil {
		t.Fatalf("NewBuiltIn: %v", err)
	}

	missing := ExternalScanner{
		Name:      "gitleaks",
		Kind:      ScannerKindSecrets,
		Available: false,
		Message:   "gitleaks not found on PATH",
	}
	res, err := b.RunExternal(missing, t.TempDir())
	if err == nil {
		t.Fatalf("RunExternal returned no error for unavailable scanner; got %+v", res)
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Fatalf("RunExternal error %q does not mention availability", err.Error())
	}
}

// TestDiscoverExternal_AvailableAndMissingMix pins the partial-PATH
// case the CLI cares about: some optional tools resolve, others do
// not. The discovered tools must carry the resolved binary path and
// (for entries with no wired adapter today) a "driver not yet wired"
// message; the missing tools must remain Available=false with their
// "not found on PATH" message intact. Both halves coexist in the
// returned slice.
func TestDiscoverExternal_AvailableAndMissingMix(t *testing.T) {
	b, err := NewBuiltIn(Config{})
	if err != nil {
		t.Fatalf("NewBuiltIn: %v", err)
	}

	resolve := map[string]string{
		"gitleaks":    "/usr/local/bin/gitleaks",
		"osv-scanner": "/usr/local/bin/osv-scanner",
	}
	b.SetLookPath(func(cmd string) (string, error) {
		if p, ok := resolve[cmd]; ok {
			return p, nil
		}
		return "", errors.New("not found")
	})

	entries := b.DiscoverExternal()
	if len(entries) == 0 {
		t.Fatalf("DiscoverExternal returned no entries")
	}

	var sawGitleaks, sawOSV, sawMissing bool
	for _, e := range entries {
		switch e.Name {
		case "gitleaks":
			sawGitleaks = true
			if !e.Available {
				t.Fatalf("gitleaks reported Available=false despite resolved binary")
			}
			if e.BinaryPath != resolve["gitleaks"] {
				t.Fatalf("gitleaks BinaryPath=%q, want %q", e.BinaryPath, resolve["gitleaks"])
			}
		case "osv-scanner":
			sawOSV = true
			if !e.Available {
				t.Fatalf("osv-scanner reported Available=false despite resolved binary")
			}
			if e.Message == "" {
				t.Fatalf("osv-scanner has no driver wired yet; expected a non-empty Message")
			}
		default:
			if e.Available {
				t.Fatalf("entry %q reported Available=true unexpectedly", e.Name)
			}
			if e.Message == "" {
				t.Fatalf("entry %q missing Message under not-found lookPath", e.Name)
			}
			sawMissing = true
		}
	}
	if !sawGitleaks {
		t.Fatalf("expected gitleaks entry in discovery output")
	}
	if !sawOSV {
		t.Fatalf("expected osv-scanner entry in discovery output")
	}
	if !sawMissing {
		t.Fatalf("expected at least one missing-tool entry in discovery output")
	}
}
