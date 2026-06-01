package workspace

import (
	"strings"
	"testing"
)

// TestProtectedMatcher_PatternFlavors is a table-driven test covering each
// pattern flavor the plan (step 11) calls out:
//
//   - exact file names (".env", "Dockerfile", "package.json", lock files)
//   - dotted-prefix wildcards (".env.*" matching ".env.local" etc.)
//   - directory recursion ("**" suffixes: ".git/**", "terraform/**",
//     "infra/**", "migrations/**", ".ai-env/**", ".github/workflows/**")
//   - mid-path "**" segments (e.g. "src/**/test_*.go") for completeness
//   - separator and prefix normalization (backslashes, leading "./" or "/")
//
// Each row carries a small description so a failure narrative tells the
// reader exactly which pattern flavor regressed.
func TestProtectedMatcher_PatternFlavors(t *testing.T) {
	type row struct {
		name      string
		patterns  []string
		path      string
		wantMatch bool
	}

	cases := []row{
		// --- Exact file-name patterns --------------------------------
		{
			name:      "exact .env at root matches",
			patterns:  []string{".env"},
			path:      ".env",
			wantMatch: true,
		},
		{
			name:      "exact .env does not match nested copy",
			patterns:  []string{".env"},
			path:      "subdir/.env",
			wantMatch: false,
		},
		{
			name:      "exact Dockerfile matches at root",
			patterns:  []string{"Dockerfile"},
			path:      "Dockerfile",
			wantMatch: true,
		},
		{
			name:      "exact package.json matches at root",
			patterns:  []string{"package.json"},
			path:      "package.json",
			wantMatch: true,
		},
		{
			name:      "exact yarn.lock matches at root",
			patterns:  []string{"yarn.lock"},
			path:      "yarn.lock",
			wantMatch: true,
		},

		// --- Dotted-prefix wildcard patterns -------------------------
		{
			name:      ".env.* matches .env.local",
			patterns:  []string{".env.*"},
			path:      ".env.local",
			wantMatch: true,
		},
		{
			name:      ".env.* matches .env.production",
			patterns:  []string{".env.*"},
			path:      ".env.production",
			wantMatch: true,
		},
		{
			name:      ".env.* does NOT match plain .env (no trailing dot+chars)",
			patterns:  []string{".env.*"},
			path:      ".env",
			wantMatch: false,
		},
		{
			name:      ".env.* does NOT match nested .env.local",
			patterns:  []string{".env.*"},
			path:      "dir/.env.local",
			wantMatch: false,
		},

		// --- Recursive ** directory patterns -------------------------
		{
			name:      ".git/** matches a top-level .git child",
			patterns:  []string{".git/**"},
			path:      ".git/HEAD",
			wantMatch: true,
		},
		{
			name:      ".git/** matches deeply nested .git children",
			patterns:  []string{".git/**"},
			path:      ".git/objects/aa/bbccdd",
			wantMatch: true,
		},
		{
			name:      ".git/** does NOT match a sibling named .gitignore",
			patterns:  []string{".git/**"},
			path:      ".gitignore",
			wantMatch: false,
		},
		{
			name:      "terraform/** matches main.tf",
			patterns:  []string{"terraform/**"},
			path:      "terraform/main.tf",
			wantMatch: true,
		},
		{
			name:      "infra/** matches nested kubernetes manifest",
			patterns:  []string{"infra/**"},
			path:      "infra/k8s/prod/deployment.yaml",
			wantMatch: true,
		},
		{
			name:      "migrations/** matches a sql file",
			patterns:  []string{"migrations/**"},
			path:      "migrations/001_init.sql",
			wantMatch: true,
		},
		{
			name:      ".ai-env/** matches policy.yaml",
			patterns:  []string{".ai-env/**"},
			path:      ".ai-env/policy.yaml",
			wantMatch: true,
		},
		{
			name:      ".github/workflows/** matches a workflow file",
			patterns:  []string{".github/workflows/**"},
			path:      ".github/workflows/ci.yml",
			wantMatch: true,
		},
		{
			name:      ".github/workflows/** does NOT match .github/dependabot.yml",
			patterns:  []string{".github/workflows/**"},
			path:      ".github/dependabot.yml",
			wantMatch: false,
		},

		// --- Mid-path ** segments ----------------------------------
		{
			name:      "src/**/test_*.go matches a deeply nested test file",
			patterns:  []string{"src/**/test_*.go"},
			path:      "src/foo/bar/test_thing.go",
			wantMatch: true,
		},
		{
			name:      "src/**/test_*.go matches a single-level test file (** = zero components)",
			patterns:  []string{"src/**/test_*.go"},
			path:      "src/test_thing.go",
			wantMatch: true,
		},
		{
			name:      "src/**/test_*.go does NOT match a non-test file",
			patterns:  []string{"src/**/test_*.go"},
			path:      "src/foo/main.go",
			wantMatch: false,
		},

		// --- Multiple patterns ------------------------------------
		{
			name:      "first matching pattern wins (Dockerfile + package.json)",
			patterns:  []string{"Dockerfile", "package.json"},
			path:      "package.json",
			wantMatch: true,
		},
		{
			name:      "no pattern matches plain source file",
			patterns:  []string{"Dockerfile", "package.json", ".env"},
			path:      "src/main.go",
			wantMatch: false,
		},

		// --- Input normalization ----------------------------------
		{
			name:      "backslash-separated input matches forward-slash pattern",
			patterns:  []string{".github/workflows/**"},
			path:      ".github\\workflows\\ci.yml",
			wantMatch: true,
		},
		{
			name:      "leading ./ on input does not break match",
			patterns:  []string{"Dockerfile"},
			path:      "./Dockerfile",
			wantMatch: true,
		},
		{
			name:      "leading / on input does not break match",
			patterns:  []string{"Dockerfile"},
			path:      "/Dockerfile",
			wantMatch: true,
		},
		{
			name:      "empty path never matches",
			patterns:  []string{".env"},
			path:      "",
			wantMatch: false,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			m, err := NewProtectedMatcher(c.patterns)
			if err != nil {
				t.Fatalf("NewProtectedMatcher(%v): %v", c.patterns, err)
			}
			got := m.Match(c.path)
			if got != c.wantMatch {
				t.Errorf("Match(%q) against patterns %v = %v, want %v",
					c.path, c.patterns, got, c.wantMatch)
			}
		})
	}
}

// TestProtectedMatcher_DefaultPatterns confirms that NewProtectedMatcher
// falls back to DefaultProtectedPaths when patterns is nil or empty, and
// that the documented baseline categories actually match the canonical
// paths the plan calls out. This is the "did the defaults regress" guard.
func TestProtectedMatcher_DefaultPatterns(t *testing.T) {
	for _, patterns := range [][]string{nil, {}} {
		m, err := NewProtectedMatcher(patterns)
		if err != nil {
			t.Fatalf("NewProtectedMatcher(%v): %v", patterns, err)
		}

		// Pattern set the matcher reports should equal the documented
		// defaults. We compare via SortedPatterns to avoid coupling to the
		// declaration order in DefaultProtectedPaths.
		gotSorted := m.SortedPatterns()
		wantSorted := append([]string(nil), DefaultProtectedPaths...)
		// Sort the want side too via the matcher's own helper so any
		// future normalization (e.g. trimming trailing slashes) is applied
		// uniformly to both sides.
		wm, _ := NewProtectedMatcher(wantSorted)
		wantSorted = wm.SortedPatterns()
		if strings.Join(gotSorted, "|") != strings.Join(wantSorted, "|") {
			t.Errorf("default patterns mismatch\n got=%v\nwant=%v", gotSorted, wantSorted)
		}

		// Spot-check that each baseline category actually matches a
		// realistic path from that category. A regression in matchSegments
		// would surface here even if the default list itself is intact.
		checks := map[string]string{
			".github/workflows/ci.yml": ".github/workflows/**",
			".git/HEAD":                ".git/**",
			".env":                     ".env",
			".env.local":               ".env.*",
			"package.json":             "package.json",
			"package-lock.json":        "package-lock.json",
			"yarn.lock":                "yarn.lock",
			"pnpm-lock.yaml":           "pnpm-lock.yaml",
			"Dockerfile":               "Dockerfile",
			"docker-compose.yml":       "docker-compose.yml",
			"terraform/main.tf":        "terraform/**",
			"infra/k8s/dep.yaml":       "infra/**",
			"migrations/001_init.sql":  "migrations/**",
			".ai-env/policy.yaml":      ".ai-env/**",
		}
		for path, why := range checks {
			if !m.Match(path) {
				t.Errorf("default matcher did not match %q (expected via %q)", path, why)
			}
		}
	}
}

// TestProtectedMatcher_ExplicitEmptyDisablesDefaults confirms the documented
// "explicit empty list disables defaults" behavior from
// NewProtectedMatcher's contract: passing a slice that is non-nil but
// reduces to empty after normalization (e.g. only blanks) yields a matcher
// that matches nothing, rather than silently re-enabling DefaultProtected
// Paths. This is a subtle policy escape hatch and a regression here would
// quietly force protection back on a user who opted out.
func TestProtectedMatcher_ExplicitEmptyDisablesDefaults(t *testing.T) {
	// A list of nothing-but-blank entries normalizes to empty. The matcher
	// must treat that as "no patterns configured" rather than fall back.
	m, err := NewProtectedMatcher([]string{"   ", ""})
	if err != nil {
		t.Fatalf("NewProtectedMatcher: %v", err)
	}
	for _, path := range []string{".env", "Dockerfile", ".git/HEAD", "package.json"} {
		if m.Match(path) {
			t.Errorf("explicit-empty matcher unexpectedly matched %q", path)
		}
	}
}

// TestProtectedMatcher_InvalidPatterns confirms that malformed patterns
// surface as errors at construction time. The patterns the plan documents
// are all well-formed; this test guards the failure path so a typo in
// policy.yaml does not silently degrade to "never matches".
func TestProtectedMatcher_InvalidPatterns(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    string
	}{
		{
			name:    "double-star mixed with literal inside a segment",
			pattern: "src/**.go",
			want:    "whole path segment",
		},
		{
			name:    "parent-directory escape rejected",
			pattern: "../outside",
			want:    "'..'",
		},
		{
			name:    "unterminated character class rejected",
			pattern: "[abc",
			want:    "syntax",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			_, err := NewProtectedMatcher([]string{c.pattern})
			if err == nil {
				t.Fatalf("expected error for pattern %q, got nil", c.pattern)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err.Error(), c.want)
			}
		})
	}
}

// TestProtectedMatcher_MatchAny confirms the convenience wrapper returns
// exactly the subset of inputs that match. This is the bulk API the
// diff/patch path uses to collect ProtectedHits in one call.
func TestProtectedMatcher_MatchAny(t *testing.T) {
	m, err := NewProtectedMatcher([]string{".env", "package.json", ".github/workflows/**"})
	if err != nil {
		t.Fatalf("NewProtectedMatcher: %v", err)
	}

	inputs := []string{
		"src/main.go",
		".env",
		"README.md",
		"package.json",
		".github/workflows/ci.yml",
		"docs/notes.md",
	}
	hits := m.MatchAny(inputs)

	wantHits := []string{".env", "package.json", ".github/workflows/ci.yml"}
	if strings.Join(hits, "|") != strings.Join(wantHits, "|") {
		t.Errorf("MatchAny = %v, want %v", hits, wantHits)
	}

	// Empty input returns nil (not an empty slice), letting callers write
	// `if hits := m.MatchAny(...); hits != nil { ... }` succinctly.
	if got := m.MatchAny(nil); got != nil {
		t.Errorf("MatchAny(nil) = %v, want nil", got)
	}
}
