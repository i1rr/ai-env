package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShimHelperCurrentDepth_ParsesEnv verifies that the depth
// counter reads the env var and treats malformed values as zero.
func TestShimHelperCurrentDepth_ParsesEnv(t *testing.T) {
	cases := []struct {
		name string
		set  string
		want int
	}{
		{"unset", "", 0},
		{"zero", "0", 0},
		{"two", "2", 2},
		{"negative", "-3", 0},
		{"non_numeric", "abc", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(shimHelperEnvDepth, tc.set)
			if got := shimHelperCurrentDepth(); got != tc.want {
				t.Errorf("shimHelperCurrentDepth() = %d, want %d (env=%q)", got, tc.want, tc.set)
			}
		})
	}
}

// TestShimHelperGuardDepth_TripsAtMax verifies the recursion guard
// fires at the cap.
func TestShimHelperGuardDepth_TripsAtMax(t *testing.T) {
	t.Setenv(shimHelperEnvDepth, "0")
	if err := shimHelperGuardDepth(); err != nil {
		t.Errorf("guard at depth 0 should pass, got %v", err)
	}
	t.Setenv(shimHelperEnvDepth, "4")
	if err := shimHelperGuardDepth(); err == nil {
		t.Errorf("guard at depth %d should trip", shimHelperMaxDepth)
	}
	t.Setenv(shimHelperEnvDepth, "100")
	if err := shimHelperGuardDepth(); err == nil {
		t.Errorf("guard at depth 100 should trip")
	}
}

// TestShimHelperLoadPrimaryToken_ReadsFile verifies the token file
// loader returns the trimmed token.
func TestShimHelperLoadPrimaryToken_ReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".helper-token")
	if err := os.WriteFile(path, []byte("hello-token\n"), 0o400); err != nil {
		t.Fatalf("write token: %v", err)
	}
	t.Setenv(shimHelperEnvHelperTokenPath, path)
	got, err := shimHelperLoadPrimaryToken()
	if err != nil {
		t.Fatalf("loader err = %v", err)
	}
	if got != "hello-token" {
		t.Errorf("loader = %q, want %q", got, "hello-token")
	}
}

// TestShimHelperLoadPrimaryToken_EmptyFileFails verifies the loader
// fails closed on an empty token file.
func TestShimHelperLoadPrimaryToken_EmptyFileFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".helper-token")
	if err := os.WriteFile(path, []byte("\n"), 0o400); err != nil {
		t.Fatalf("write token: %v", err)
	}
	t.Setenv(shimHelperEnvHelperTokenPath, path)
	if _, err := shimHelperLoadPrimaryToken(); err == nil {
		t.Errorf("loader should fail on empty token file")
	}
}

// TestShimHelperLoadPrimaryToken_MissingFileFails verifies the
// fail-closed default when the token file does not exist.
func TestShimHelperLoadPrimaryToken_MissingFileFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(shimHelperEnvHelperTokenPath, filepath.Join(dir, "does-not-exist"))
	if _, err := shimHelperLoadPrimaryToken(); err == nil {
		t.Errorf("loader should fail on missing token file")
	}
}

// TestShimHelperSocketPath_PrefersEnv verifies the env-var override.
func TestShimHelperSocketPath_PrefersEnv(t *testing.T) {
	t.Setenv(shimHelperEnvSocket, "/tmp/custom.sock")
	p, err := shimHelperSocketPath()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if p != "/tmp/custom.sock" {
		t.Errorf("path = %q, want %q", p, "/tmp/custom.sock")
	}
}

// TestShimHelperSocketPath_DefaultsToCanonical verifies the
// fallback when the env var is unset.
func TestShimHelperSocketPath_DefaultsToCanonical(t *testing.T) {
	t.Setenv(shimHelperEnvSocket, "")
	p, err := shimHelperSocketPath()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if p != shimHelperDefaultSocketPath {
		t.Errorf("path = %q, want default %q", p, shimHelperDefaultSocketPath)
	}
}

// TestTrimToken_StripsTrailingWhitespace verifies the helper strips
// CR/LF/spaces from the end without disturbing the body.
func TestTrimToken_StripsTrailingWhitespace(t *testing.T) {
	cases := map[string]string{
		"hello\n":          "hello",
		"hello\r\n":        "hello",
		"hello  ":          "hello",
		"hello":            "hello",
		"":                 "",
		"\n":               "",
		"some token  \r\n": "some token",
	}
	for in, want := range cases {
		got := trimToken([]byte(in))
		if got != want {
			t.Errorf("trimToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEnvWithDepth_ReplacesExistingEntry verifies the env helper.
func TestEnvWithDepth_ReplacesExistingEntry(t *testing.T) {
	env := []string{"PATH=/usr/bin", shimHelperEnvDepth + "=0", "HOME=/root"}
	out := envWithDepth(env, shimHelperEnvDepth+"=5")
	if got := findEnv(out, shimHelperEnvDepth); got != "5" {
		t.Errorf("depth = %q, want 5", got)
	}
	if len(out) != len(env) {
		t.Errorf("env len = %d, want %d (replace, not append)", len(out), len(env))
	}
}

func TestEnvWithDepth_AppendsWhenMissing(t *testing.T) {
	env := []string{"PATH=/usr/bin"}
	out := envWithDepth(env, shimHelperEnvDepth+"=1")
	if got := findEnv(out, shimHelperEnvDepth); got != "1" {
		t.Errorf("depth = %q, want 1", got)
	}
	if len(out) != len(env)+1 {
		t.Errorf("env len = %d, want %d (append)", len(out), len(env)+1)
	}
}

func findEnv(env []string, key string) string {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return strings.TrimPrefix(kv, prefix)
		}
	}
	return ""
}
