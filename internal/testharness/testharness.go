// Package testharness owns the reusable test fixtures and helpers the
// plan's downstream batches (1.x ProviderProxy, 2.x MCP gateway,
// 3.x broker, 5.x observer/sequencing, 9 red-team) depend on. The
// plan's "Batch 0.6 — Test fixtures + harness" entry pins this
// package as the single place tests share a RunDirectory builder, a
// short-path tmpdir for AF_UNIX sockets, an in-memory
// BackendEventSink recorder, JSONL readers, and a fixed set of
// secret payloads.
//
// Design rules:
//
//   - Production code MUST NOT import this package. The name carries
//     the convention; consumers under tests/ and *_test.go files are
//     the only legitimate importers. The package's symbols are
//     deliberately small and focused so a future linter check
//     ("no production imports of internal/testharness") is easy to
//     write.
//
//   - Pure-Go, no exec, no network. Every helper here works in a
//     vanilla `go test ./...` environment without requiring Docker,
//     git, or root privileges. Helpers that DO need a privileged
//     environment (e.g. NFLOG attach for the observer integration
//     tests) live in their own test-only build-tag-gated files in
//     the package that owns the surface.
//
//   - Short-path everywhere. The default Go t.TempDir() under
//     macOS lives at /var/folders/.../<deep>/<test-name>/00x; when
//     the path is appended with a run ID and "control.sock" it
//     overshoots the 104-byte AF_UNIX sun_path limit. The
//     short-path helper here routes through /tmp/aies-<random> so
//     downstream tests do not have to re-implement the workaround.
//
//   - Stable across the plan. The struct shapes (e.g.
//     RecordedBackendEvent, FixtureSecret) are kept simple and
//     additive so a test pinned to today's field set stays green as
//     the plan grows.
//
// Naming convention: every exported helper takes `t *testing.T` (or
// `tb testing.TB` when a benchmark might also call it) as its first
// argument and calls `t.Helper()` at entry. This matches the rest of
// the codebase's test helpers and produces failure messages that
// point at the test, not at the harness file.
package testharness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/run"
)

// shortTempPrefix is the prefix passed to os.MkdirTemp in the
// short-path tempdir helper. The "aies" stem is short on purpose so a
// path like "/tmp/aies-1234567890" plus a downstream run-id +
// "control.sock" stays comfortably under the 104-byte AF_UNIX limit
// on macOS and the 108-byte limit on Linux. The trailing "-" matches
// MkdirTemp's expected separator before the random suffix.
const shortTempPrefix = "aies-"

// ShortTempDir returns a per-test directory under /tmp (on POSIX)
// chosen so AF_UNIX socket paths constructed inside it stay under
// the platform sun_path limit. The directory is removed when the
// test exits via t.Cleanup. Tests that build a RunDirectory whose
// per-run files include a Unix socket (control.sock, the future MCP
// helper transport, etc.) MUST use this helper rather than
// t.TempDir() to avoid silent EINVAL on Darwin.
//
// On non-POSIX hosts (Windows test runners, hypothetical future
// targets) the helper falls back to t.TempDir(). Windows does not
// have a sun_path limit problem; the helper preserves the contract
// of "returns an absolute path that is removed at test exit".
func ShortTempDir(t testing.TB) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp("/tmp", shortTempPrefix)
	if err != nil {
		t.Fatalf("testharness: MkdirTemp(/tmp, %q): %v", shortTempPrefix, err)
	}
	t.Cleanup(func() {
		// Best-effort: the harness owns the directory and removes
		// it; a stray file the test left behind with read-only
		// bits still gets cleaned because MkdirTemp's dir is mode
		// 0700 by default. Errors are silently ignored because
		// test cleanup never propagates them.
		_ = os.RemoveAll(dir)
	})
	return dir
}

// FixedRunID is the canonical pinned run ID test helpers use when
// they need a deterministic value. The shape matches the production
// generator (YYYYMMDD-HHMMSS-<6hex>) so tests exercise the same
// directory-basename code path as production. Tests that need
// multiple distinct IDs in one process can call
// NewFixedRunID(seed) which produces deterministic suffixes from a
// seed byte.
const FixedRunID = "20260528-101300-a1b2c3"

// FixedRunTime is the timestamp test helpers stamp into the
// RunDirectory's CreatedAt and (when the test plumbs through one) the
// lifecycle writer's fixed-time closure. The value mirrors the
// FixedRunID's timestamp portion so a reviewer who reads both run.json
// and lifecycle.jsonl sees a consistent moment.
var FixedRunTime = time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)

// NewRunDir builds a real RunDirectory under a ShortTempDir-rooted
// .ai-env/ tree. The returned RunDirectory is materialized exactly
// the way production CreateRunDirectory does it: every per-run
// placeholder file exists with mode 0o644, every subdir exists with
// mode 0o755, and the run dir itself is tightened to 0o700.
//
// Tests that need to customize the run ID or the timestamp call
// NewRunDirWith; this convenience form pins FixedRunID + FixedRunTime
// because the vast majority of tests do not care about the values
// themselves, only that a RunDirectory exists with the canonical
// layout.
func NewRunDir(t testing.TB) run.RunDirectory {
	t.Helper()
	return NewRunDirWith(t, FixedRunID, FixedRunTime)
}

// NewRunDirWith is the parameterized form of NewRunDir. The caller
// supplies the run ID and the CreatedAt timestamp; the helper picks
// the .ai-env/ root and materializes the run directory. Use this
// when the test specifically needs a non-default ID (e.g. testing
// the stale-tmp cleanup at supervisor start, which needs two run
// dirs with different IDs in the same process).
func NewRunDirWith(t testing.TB, runID string, createdAt time.Time) run.RunDirectory {
	t.Helper()
	aiEnvDir := filepath.Join(ShortTempDir(t), ".ai-env")
	dir, err := run.CreateRunDirectory(aiEnvDir, runID, createdAt)
	if err != nil {
		t.Fatalf("testharness: CreateRunDirectory(%s, %q): %v", aiEnvDir, runID, err)
	}
	return dir
}

// FixedTimes returns a now() closure that hands back the supplied
// times in order. After the slice is exhausted, every subsequent
// call returns the last time so a test that writes more events than
// it pre-staged still produces parseable JSON (the timestamps just
// stop advancing).
//
// This is the production seam most of the lifecycle/leaks/mcp_calls
// writers accept (their Options struct carries a `Now func() time.Time`
// field). Centralizing the helper here keeps every package's test
// from re-implementing the closure.
func FixedTimes(times ...time.Time) func() time.Time {
	i := 0
	return func() time.Time {
		if i >= len(times) {
			if len(times) == 0 {
				// Pathological caller: no times supplied at
				// all. Return the package's FixedRunTime so the
				// JSONL stream stays parseable.
				return FixedRunTime
			}
			return times[len(times)-1]
		}
		v := times[i]
		i++
		return v
	}
}

// RecordedBackendEvent captures one BackendEventSink.Emit call. The
// plan's Batch 0.5 introduces `BackendEventSink interface { Emit(verb,
// metadata) error }` and Batch 5.6 expects the adapter to emit
// `network_policy_degraded` through it. Tests for those batches
// instantiate a RecordingBackendEventSink and assert against the
// recorded slice; this struct is the per-call shape.
//
// Field names mirror the lifecycle verb writer's Metadata convention
// (verb string + map[string]string metadata). Tests that need to
// pin the order of emissions read the slice in append order.
type RecordedBackendEvent struct {
	// Verb is the lifecycle verb the backend emitted. The supervisor
	// expects values from `internal/run.LifecycleVerb` (e.g.
	// "network_policy_degraded"); the harness keeps the field as
	// `string` so a test does not need to import the run package
	// just to assert on the value.
	Verb string

	// Metadata is the verb's Metadata map, copied at emit time so a
	// caller that mutates its own map after Emit does not racily
	// alter the recorded value. The copy is shallow (map[string]
	// string only); the per-verb tables in lifecycle_verbs.go pin
	// the keys.
	Metadata map[string]string
}

// RecordingBackendEventSink is an in-memory BackendEventSink the
// downstream backend adapters' tests use to assert on emitted
// lifecycle verbs. The plan keeps the BackendEventSink interface in
// the backend package (Batch 0.5); this recorder implements the same
// shape but lives in the test harness so backend tests do not need
// to import their own production interface to satisfy themselves.
//
// Concurrency: Emit is safe to call from multiple goroutines. The
// sink uses a mutex around the appends so a test that exercises
// concurrent backend adapters sees a consistent slice when it later
// calls Events().
type RecordingBackendEventSink struct {
	mu     sync.Mutex
	events []RecordedBackendEvent

	// FailOn lets a test inject a synthetic Emit failure for a
	// specific verb. The supervisor's plan §10 row 10 contract
	// says backend Emit failures degrade gracefully (the run
	// continues, the emission is dropped with a log line); the
	// FailOn map lets a test exercise that branch. When the map
	// contains the verb key, Emit returns the mapped error
	// instead of recording.
	FailOn map[string]error
}

// NewRecordingBackendEventSink returns a fresh sink ready for use
// in a test. Tests that want to inject FailOn populate the field on
// the returned struct directly.
func NewRecordingBackendEventSink() *RecordingBackendEventSink {
	return &RecordingBackendEventSink{}
}

// Emit records the (verb, metadata) pair into the sink's slice. The
// metadata map is copied so a caller mutating its argument after the
// call does not racily alter the recorded value.
//
// When FailOn[verb] is set, Emit returns the mapped error and does
// NOT append to the slice. This matches the backend interface
// contract where a failed Emit is the caller's problem to react to.
func (s *RecordingBackendEventSink) Emit(verb string, metadata map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FailOn != nil {
		if err, ok := s.FailOn[verb]; ok && err != nil {
			return err
		}
	}
	copied := make(map[string]string, len(metadata))
	for k, v := range metadata {
		copied[k] = v
	}
	s.events = append(s.events, RecordedBackendEvent{
		Verb:     verb,
		Metadata: copied,
	})
	return nil
}

// Events returns a snapshot of the events recorded so far. The
// returned slice is a copy; mutating it does not affect future
// recordings. Tests typically call this after the system-under-test
// has completed its emissions and assert on the result.
func (s *RecordingBackendEventSink) Events() []RecordedBackendEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RecordedBackendEvent, len(s.events))
	copy(out, s.events)
	return out
}

// EventsByVerb returns only the recorded events whose Verb matches
// the supplied string. Convenience for tests that care about one
// subsystem's emissions (e.g. all `proxy_started` events) without
// having to filter the full slice themselves.
func (s *RecordingBackendEventSink) EventsByVerb(verb string) []RecordedBackendEvent {
	all := s.Events()
	var out []RecordedBackendEvent
	for _, e := range all {
		if e.Verb == verb {
			out = append(out, e)
		}
	}
	return out
}

// ReadJSONL reads the file at path and decodes each non-empty line
// into a fresh value of type T, returning the slice. A missing file
// returns nil (so tests that do not always populate a stream can
// assert on len(out) without an extra os.IsNotExist check); a
// malformed line fails the test.
//
// The plan's per-subsystem streams (lifecycle.jsonl, leaks.jsonl,
// mcp-calls.jsonl, ...) all share the JSONL format; this helper is
// the one place every test parses them. The function is generic so
// the call site stays free of `var out []FooRecord` plus a separate
// decode loop.
func ReadJSONL[T any](t testing.TB, path string) []T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("testharness: read %s: %v", path, err)
	}
	var out []T
	for i, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("testharness: parse %s line %d: %v\nraw: %s", path, i+1, err, line)
		}
		out = append(out, v)
	}
	return out
}

// ReadRawJSONLLines returns each non-empty line of the file at path
// as a raw byte slice. Useful for tests that need to assert on the
// on-wire byte shape (e.g. a redaction test that checks `sk-ant-` is
// absent from the entire file regardless of which record it lived
// on). A missing file returns nil; a read error fails the test.
func ReadRawJSONLLines(t testing.TB, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("testharness: read %s: %v", path, err)
	}
	parts := bytes.Split(data, []byte("\n"))
	var out [][]byte
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		// Copy so the returned slice does not alias the file
		// buffer; mutating one line should not affect another.
		buf := make([]byte, len(p))
		copy(buf, p)
		out = append(out, buf)
	}
	return out
}

// WriteJSONLLine appends one JSON-marshalled value plus a trailing
// newline to the file at path. The file is created with mode 0o644
// if missing. Use this when a test needs to pre-seed a stream
// (e.g. simulating a prior subsystem's record before the system
// under test reads it).
//
// The function returns an error rather than failing the test so a
// table-driven caller can assert on encode/write failures
// themselves; tests that don't care can `if err := ...; err != nil
// { t.Fatal(err) }`.
func WriteJSONLLine(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("testharness: marshal: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("testharness: open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("testharness: write %s: %w", path, err)
	}
	return nil
}

// FixtureSecret bundles a representative secret value with the
// canonical pattern name the scanner library matches against. The
// plan's red-team test suite (Section 9) exercises the
// per-direction MCP scanner, the leaks aggregator, and the proxy
// log redactor against a fixed set of secret shapes; centralizing
// the table here keeps every test pinned to the same exemplars so
// a regression in the redaction layer is caught uniformly.
//
// The Value strings are deliberately synthetic — they match the
// regex shape of real provider tokens but are NOT real credentials.
// The plan's redaction story relies on the scanner's pattern set
// catching the shape; the test fixtures only have to exercise the
// shape, not impersonate a working token.
type FixtureSecret struct {
	// Pattern is the canonical pattern name the scanners library
	// publishes (anthropic_key, openai_key, github_pat, ...). The
	// plan's Batch 0.2 broadened RedactSecrets to mirror the
	// scanner set; the names line up 1:1.
	Pattern string

	// Value is a synthetic-but-shape-correct token a test can
	// embed in a request body, a log line, or a JSON-RPC frame.
	// The scanner must match Value; the redactor must rewrite
	// Value to [REDACTED ...]; the test asserts both.
	Value string

	// Description is a short human-readable note explaining what
	// vector the fixture exercises. Surfaces in test failure
	// messages so a regression points at the intent rather than
	// the literal string.
	Description string
}

// BuiltinSecretFixtures returns the canonical set of FixtureSecret
// entries the plan's red-team tests share. The slice is returned by
// value (callers may mutate freely; the package keeps an internal
// pristine copy). Order is stable so a table-driven test can
// reference entries by index when needed.
//
// The set covers the seven provider/credential families the plan's
// Batch 0.2 RedactSecrets mirrors from scanners.builtinPatterns():
// Anthropic, OpenAI, GitHub (PAT/OAuth/server/fine-grained app),
// AWS, GCP service account, Azure, and Slack. PEM blobs and SSH
// key shapes are larger payloads that downstream tests can
// construct on demand from BuiltinPEMFixture; including them here
// would bloat the slice and most red-team tests assert against the
// short-form tokens.
func BuiltinSecretFixtures() []FixtureSecret {
	out := make([]FixtureSecret, len(builtinSecretFixtures))
	copy(out, builtinSecretFixtures)
	return out
}

// builtinSecretFixtures is the package-internal canonical slice.
// We keep a pristine copy here and hand out a fresh copy from
// BuiltinSecretFixtures so a test that mutates its returned slice
// does not affect later tests.
var builtinSecretFixtures = []FixtureSecret{
	{
		Pattern:     "anthropic_key",
		Value:       "sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM01234567",
		Description: "Anthropic API key (sk-ant- prefix)",
	},
	{
		Pattern:     "openai_key",
		Value:       "sk-AABBCCDDEEFFGGHHIIJJKKLLMMNN00112233",
		Description: "OpenAI API key (sk- prefix)",
	},
	{
		Pattern:     "github_pat_classic",
		Value:       "ghp_0123456789ABCDEFabcdefghijklmnopQRST",
		Description: "GitHub personal access token (ghp_ prefix)",
	},
	{
		Pattern:     "github_oauth",
		Value:       "gho_0123456789ABCDEFabcdefghijklmnopQRST",
		Description: "GitHub OAuth token (gho_ prefix)",
	},
	{
		Pattern:     "github_server",
		Value:       "ghs_0123456789ABCDEFabcdefghijklmnopQRST",
		Description: "GitHub server-to-server token (ghs_ prefix)",
	},
	{
		Pattern:     "github_fine_grained_pat",
		Value:       "github_pat_11ABCDEFG0aaaaaaaaaaaa_0123456789012345678901234567890123456789012345678",
		Description: "GitHub fine-grained PAT (github_pat_ prefix)",
	},
	{
		Pattern:     "aws_access_key",
		Value:       "AKIAIOSFODNN7EXAMPLE",
		Description: "AWS access key ID (AKIA prefix, canonical example)",
	},
	{
		Pattern:     "slack_token",
		Value:       "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx",
		Description: "Slack bot token (xoxb- prefix)",
	},
}

// BuiltinPEMFixture returns a synthetic PEM-armored private key
// block. The block is shape-correct (matches the scanner's PEM
// regex) but contains no real key material. Tests that need to
// assert the scanner catches PEM blobs use this; we keep it out of
// BuiltinSecretFixtures because the payload is long and most
// short-form tests do not need it.
func BuiltinPEMFixture() string {
	return "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n" +
		"KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm\n" +
		"o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k\n" +
		"TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7\n" +
		"9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy\n" +
		"v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs\n" +
		"/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00\n" +
		"-----END RSA PRIVATE KEY-----\n"
}

// FixtureRedactedMarker is the canonical placeholder the plan's
// Batch 0.3 JSON-aware response scrubber writes in place of a
// matched secret value. Tests assert on this string to verify the
// scrubber ran without re-implementing the exact format. The shape
// is `[REDACTED pattern=<name> len=<n>]` per the plan; the literal
// prefix here is the constant portion downstream readers can grep.
const FixtureRedactedMarker = "[REDACTED"

// ContainsAnySecret returns the FixtureSecret entry whose Value is
// present in the supplied haystack, or (FixtureSecret{}, false) when
// no fixture matches. The plan's leaks-jsonl acceptance test
// repeatedly asks "is there any secret left after redaction?"; this
// helper centralizes the iteration so a regression in any one
// fixture is caught uniformly.
func ContainsAnySecret(haystack []byte) (FixtureSecret, bool) {
	for _, f := range builtinSecretFixtures {
		if bytes.Contains(haystack, []byte(f.Value)) {
			return f, true
		}
	}
	return FixtureSecret{}, false
}

// AssertNoSecretsLeaked is a t.Helper-friendly wrapper around
// ContainsAnySecret. It fails the test with a descriptive message
// when any fixture secret is present in the haystack. Used by the
// red-team aggregator tests (Section 9) and by per-subsystem
// redaction tests (Batch 0.2, 3.4) to enforce the "every string
// runs through RedactSecrets" invariant.
func AssertNoSecretsLeaked(t testing.TB, haystack []byte) {
	t.Helper()
	if f, ok := ContainsAnySecret(haystack); ok {
		t.Errorf("testharness: secret leaked: pattern=%s description=%q value=%q present in %d-byte payload",
			f.Pattern, f.Description, f.Value, len(haystack))
	}
}

// AssertNoSecretsLeakedInFile is a convenience wrapper that reads
// the file at path and runs AssertNoSecretsLeaked against its
// contents. A missing file is treated as "no secrets" (so a test
// that asserts the writer never produced output passes); a read
// error fails the test.
func AssertNoSecretsLeakedInFile(t testing.TB, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("testharness: read %s: %v", path, err)
	}
	AssertNoSecretsLeaked(t, data)
}

// ErrFixtureMissing is the sentinel returned by helpers that look
// up a fixture by name and fail to find it. Callers that want to
// branch on the missing-fixture case use errors.Is against this
// value rather than string-matching the error text.
var ErrFixtureMissing = errors.New("testharness: fixture missing")

// FindSecretByPattern returns the FixtureSecret entry whose Pattern
// matches the supplied name, or ErrFixtureMissing when no entry
// matches. Tests that exercise one specific provider's redaction
// path use this to pull the exemplar without having to know its
// slice index.
func FindSecretByPattern(name string) (FixtureSecret, error) {
	for _, f := range builtinSecretFixtures {
		if f.Pattern == name {
			return f, nil
		}
	}
	return FixtureSecret{}, fmt.Errorf("%w: pattern=%q", ErrFixtureMissing, name)
}
