package workspace

import (
	"errors"
	"path"
	"sort"
	"strings"
)

// DefaultProtectedPaths is the baseline list of patterns ai-env treats as
// protected when the user has not customized policy.yaml. The list comes
// directly from plan 02 step 7 and covers the categories most commonly
// "dangerous" for an autonomous agent to touch:
//
//   - CI/CD definitions (.github/workflows/**) where a malicious or buggy
//     edit can run arbitrary code on push.
//   - Git internals (.git/**) where edits bypass version control entirely.
//   - Secret-bearing files (.env, .env.*) that should almost never appear in
//     a patch.
//   - Dependency manifests and lock files where an unreviewed change pulls
//     in new code (package.json plus the common lock filenames).
//   - Container and infrastructure definitions (Dockerfile,
//     docker-compose.yml, terraform/**, infra/**, migrations/**) where a
//     change can move production.
//   - The ai-env directory itself (.ai-env/**) so an agent cannot quietly
//     edit its own policy or escape hatches.
//
// The slice is exported as a value (not a function) so callers can use it
// as a literal default while still being able to override it from policy.
// It is read-only; callers must not mutate the underlying array.
var DefaultProtectedPaths = []string{
	".github/workflows/**",
	".git/**",
	".env",
	".env.*",
	"package.json",
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"npm-shrinkwrap.json",
	"Gemfile.lock",
	"Pipfile.lock",
	"poetry.lock",
	"uv.lock",
	"go.sum",
	"Cargo.lock",
	"composer.lock",
	"Dockerfile",
	"docker-compose.yml",
	"terraform/**",
	"infra/**",
	"migrations/**",
	".ai-env/**",
}

// ProtectedMatcher decides whether a workspace-relative path matches any of
// a configured set of "protected" glob patterns. It is the single decision
// point used by Diff and Patch to flag changes that need extra human review
// (CI files, secrets, infrastructure, etc.).
//
// A matcher is built once per command invocation from the policy.yaml
// configuration and then queried per file. The zero value is unusable; use
// NewProtectedMatcher.
type ProtectedMatcher struct {
	// patterns holds the cleaned, deduplicated pattern list in the order it
	// will be evaluated. Order does not affect the boolean result but is
	// kept stable so debug output (e.g. Patterns) is deterministic.
	patterns []string

	// compiled is the per-pattern parsed form: each pattern split into
	// segments so Match does not re-parse on every call. It is index-
	// aligned with patterns.
	compiled [][]segment
}

// segment is one path component of a parsed pattern. Each pattern is split
// at '/' into segments; segments are matched against path components one
// for one, with a special case for the "**" segment (which matches any
// number of components, including zero).
type segment struct {
	// raw is the original component text (e.g. "*.go", "**", "src").
	raw string

	// doubleStar is true when raw == "**". It is precomputed so the hot
	// path in matchSegments does not re-compare strings.
	doubleStar bool
}

// NewProtectedMatcher builds a ProtectedMatcher from the user-configured
// patterns in policy.yaml (the `filesystem.protected_paths` field). When
// patterns is nil or empty, the matcher falls back to DefaultProtectedPaths
// so the baseline categories listed in plan 02 step 7 stay protected by
// default.
//
// Each pattern is normalized: backslashes are converted to forward slashes
// (Windows-style separators are accepted as input but the matcher itself
// works in POSIX form so a single pattern set is portable), leading "./"
// is stripped, and empty patterns are skipped. Patterns that fail to parse
// surface as errors so a typo in policy.yaml fails loudly at load time
// instead of silently never matching.
//
// The returned matcher is safe for concurrent use; it holds only immutable
// state after construction.
func NewProtectedMatcher(patterns []string) (*ProtectedMatcher, error) {
	src := patterns
	if len(src) == 0 {
		src = DefaultProtectedPaths
	}

	// Deduplicate while preserving first-occurrence order. A duplicated
	// pattern in policy.yaml is harmless but would slow Match down for no
	// reason and clutter Patterns output.
	seen := make(map[string]struct{}, len(src))
	cleaned := make([]string, 0, len(src))
	compiled := make([][]segment, 0, len(src))

	for _, raw := range src {
		p, err := normalizePattern(raw)
		if err != nil {
			return nil, err
		}
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}

		segs := splitPattern(p)
		if err := validateSegments(p, segs); err != nil {
			return nil, err
		}

		cleaned = append(cleaned, p)
		compiled = append(compiled, segs)
	}

	if len(cleaned) == 0 {
		// All inputs were blank. Treat this as an explicit "no protected
		// paths" rather than silently falling back to defaults: a user who
		// passed an explicit empty list (after deciding none apply) should
		// not have defaults forced back on them. We only fall back when the
		// caller passed nil or an actually-empty slice (handled above by
		// substituting DefaultProtectedPaths before the loop).
		return &ProtectedMatcher{}, nil
	}

	return &ProtectedMatcher{patterns: cleaned, compiled: compiled}, nil
}

// Match reports whether rel matches any of the matcher's patterns. rel is
// interpreted as a workspace-relative path; absolute paths or paths with a
// leading "./" are normalized before matching so callers do not have to
// pre-clean their input.
//
// Match is intentionally tolerant about separators: backslashes are
// converted to forward slashes so a caller on Windows that built a path
// with filepath.Join still gets the expected result.
func (m *ProtectedMatcher) Match(rel string) bool {
	if m == nil || len(m.compiled) == 0 {
		return false
	}

	cleaned := normalizeRel(rel)
	if cleaned == "" {
		// An empty path can never match a non-empty pattern; bail out
		// before we waste time splitting it.
		return false
	}
	parts := strings.Split(cleaned, "/")

	for _, segs := range m.compiled {
		if matchSegments(segs, parts) {
			return true
		}
	}
	return false
}

// MatchAny is a convenience wrapper that returns the subset of rels that
// match the matcher's patterns. The result preserves input order and is
// nil (not empty) when nothing matched, so callers can write
// `if hits := m.MatchAny(files); hits != nil { ... }`.
func (m *ProtectedMatcher) MatchAny(rels []string) []string {
	if m == nil || len(rels) == 0 || len(m.compiled) == 0 {
		return nil
	}
	var hits []string
	for _, r := range rels {
		if m.Match(r) {
			hits = append(hits, r)
		}
	}
	return hits
}

// Patterns returns a copy of the matcher's effective pattern list, in the
// order it was configured (after normalization and deduplication). It is
// useful for debug output and for tests that need to assert which patterns
// were actually loaded.
func (m *ProtectedMatcher) Patterns() []string {
	if m == nil {
		return nil
	}
	out := make([]string, len(m.patterns))
	copy(out, m.patterns)
	return out
}

// normalizePattern cleans a single pattern from policy.yaml so the matcher
// works against a consistent shape: forward slashes, no leading "./", no
// trailing slash (a trailing slash is dropped; the directory match is
// already expressed by matching the segment without it). It returns an
// error if the pattern contains a literal NUL or a path-escape sequence
// like ".." that the user almost certainly did not mean.
func normalizePattern(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", nil
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("workspace: protected pattern contains NUL byte")
	}

	// Accept Windows separators on input so users do not have to remember
	// the matcher's internal form; convert to forward slashes immediately.
	p = strings.ReplaceAll(p, "\\", "/")

	// Strip a leading "./". Workspace-relative paths never use it, so
	// allowing the user to write "./.env" and "<root>/.env" interchangeably
	// removes a footgun without adding ambiguity.
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}

	// A leading "/" would imply an absolute match, which is meaningless
	// for workspace-relative diffs. Trim it so "/foo/bar" and "foo/bar"
	// behave the same.
	p = strings.TrimPrefix(p, "/")

	// Trailing slash on a directory pattern: drop it. The user clearly
	// meant "match this directory"; the matcher does that whether the
	// pattern ends in "/" or not (and downstream matching against a path
	// like "terraform/main.tf" needs the "/**" form anyway, which the
	// user expresses explicitly).
	p = strings.TrimSuffix(p, "/")

	if p == "" {
		return "", nil
	}

	// ".." in a protected-path pattern is almost always a mistake; the
	// matcher does not resolve "..", so a pattern like "../foo" would
	// silently never match. Reject it so the user knows.
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return "", errors.New("workspace: protected pattern must not contain '..'")
		}
	}

	return p, nil
}

// splitPattern splits a normalized pattern into segments. It is a thin
// wrapper around strings.Split so callers do not repeat the same one-liner.
func splitPattern(p string) []segment {
	parts := strings.Split(p, "/")
	segs := make([]segment, len(parts))
	for i, part := range parts {
		segs[i] = segment{raw: part, doubleStar: part == "**"}
	}
	return segs
}

// validateSegments checks that each segment in segs is itself a valid glob
// component. The most important rule is that "**" must occupy a whole
// segment (e.g. "src/**" is fine; "src/**.go" is not, because "**" only
// means "any number of directory components", not "any characters"). This
// matches the behavior of established doublestar libraries and keeps
// patterns predictable.
func validateSegments(pattern string, segs []segment) error {
	for _, s := range segs {
		if !s.doubleStar && strings.Contains(s.raw, "**") {
			return errors.New("workspace: protected pattern " + pattern + ": '**' must be a whole path segment")
		}
		// path.Match's own grammar rejects unterminated character classes
		// like "[abc"; surface that here too so a bad pattern fails at
		// load time, not at first use.
		if _, err := path.Match(s.raw, ""); err != nil && !s.doubleStar {
			return errors.New("workspace: protected pattern " + pattern + ": " + err.Error())
		}
	}
	return nil
}

// normalizeRel returns the matcher's canonical form of a workspace-relative
// path: forward slashes, no leading "./" or "/", no trailing slash, no
// "." components. It is the input-side mirror of normalizePattern; the two
// must agree or matching silently breaks.
func normalizeRel(rel string) string {
	if rel == "" {
		return ""
	}
	p := strings.ReplaceAll(rel, "\\", "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	// Drop "." and empty components so "foo//bar" and "./foo/./bar" both
	// reduce to "foo/bar".
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		out = append(out, part)
	}
	return strings.Join(out, "/")
}

// matchSegments is the core glob-match routine. It walks segs against
// parts and returns true if the whole pattern consumes the whole path. The
// "**" segment matches zero or more path components, which is what makes
// patterns like ".git/**" match both ".git/HEAD" and ".git/objects/aa/bb".
//
// A pattern with no "**" components must match the same number of segments
// as the path; that is enforced naturally by the recursion terminating
// only when both lists are empty.
//
// The implementation uses recursion with early termination rather than the
// dynamic-programming form because patterns are short (a handful of
// segments) and short-circuiting on the first match is the common case.
func matchSegments(segs []segment, parts []string) bool {
	// Both empty: a successful consume of the entire pattern by the
	// entire path. This is the base case for a non-doublestar pattern.
	if len(segs) == 0 {
		return len(parts) == 0
	}

	head := segs[0]
	if head.doubleStar {
		// "**" is the only construct that needs to try multiple split
		// points. Trailing "**" matches the rest of the path
		// unconditionally (including the empty rest); a "**" followed by
		// more segments tries every possible position to consume zero or
		// more components from parts.
		rest := segs[1:]
		if len(rest) == 0 {
			return true
		}
		for i := 0; i <= len(parts); i++ {
			if matchSegments(rest, parts[i:]) {
				return true
			}
		}
		return false
	}

	// A non-doublestar segment consumes exactly one path component, so we
	// need at least one component left to consider it a match.
	if len(parts) == 0 {
		return false
	}

	ok, err := path.Match(head.raw, parts[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(segs[1:], parts[1:])
}

// SortedPatterns returns the matcher's patterns sorted lexicographically.
// It exists so test output and debug dumps can compare matchers built from
// the same set of inputs regardless of input order, without callers having
// to do the sort themselves.
func (m *ProtectedMatcher) SortedPatterns() []string {
	p := m.Patterns()
	sort.Strings(p)
	return p
}
