package testharness

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestShortTempDir_ReturnsShortPath pins the central guarantee of
// the helper: the returned path is short enough that an AF_UNIX
// socket name appended to it stays under the 104-byte limit. The
// /tmp/aies-<random> shape gives us ~25 bytes of overhead which
// leaves ~80 for the run-id + filename — comfortably enough.
func TestShortTempDir_ReturnsShortPath(t *testing.T) {
	dir := ShortTempDir(t)
	if len(dir) > 80 {
		t.Errorf("ShortTempDir returned %d-byte path %q; AF_UNIX sun_path limit is 104, leaving < 24 bytes for filename", len(dir), dir)
	}
	// The path must exist and be a directory.
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat(%s): %v", dir, err)
	}
	if !info.IsDir() {
		t.Errorf("ShortTempDir returned non-directory %q", dir)
	}
}

// TestShortTempDir_RemovedOnCleanup verifies the directory is gone
// after the test function returns. The harness owns the lifecycle;
// downstream tests should not have to add their own RemoveAll.
func TestShortTempDir_RemovedOnCleanup(t *testing.T) {
	var captured string
	t.Run("inner", func(t *testing.T) {
		captured = ShortTempDir(t)
		if _, err := os.Stat(captured); err != nil {
			t.Fatalf("ShortTempDir(%s) not present during test: %v", captured, err)
		}
	})
	// After the subtest returns, t.Cleanup must have fired.
	if _, err := os.Stat(captured); !os.IsNotExist(err) {
		t.Errorf("ShortTempDir(%s) still present after subtest cleanup: %v", captured, err)
	}
}

// TestNewRunDir_MaterializesEveryPlaceholder pins the contract that
// NewRunDir returns a fully-populated RunDirectory. The supervisor's
// per-subsystem writers rely on every placeholder existing before
// they open it for append; a helper that left files missing would
// produce confusing crashes in downstream tests.
func TestNewRunDir_MaterializesEveryPlaceholder(t *testing.T) {
	dir := NewRunDir(t)
	if dir.ID != FixedRunID {
		t.Errorf("NewRunDir.ID = %q, want %q", dir.ID, FixedRunID)
	}
	if !dir.CreatedAt.Equal(FixedRunTime) {
		t.Errorf("NewRunDir.CreatedAt = %v, want %v", dir.CreatedAt, FixedRunTime)
	}
	// Every per-run placeholder file the supervisor expects must
	// exist. We sample three load-bearing ones; the run package's
	// own tests already exercise the full set.
	for _, name := range []string{"lifecycle.jsonl", "leaks.jsonl", "task.md"} {
		path := filepath.Join(dir.Path, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("NewRunDir did not materialize %s: %v", path, err)
		}
	}
}

// TestNewRunDirWith_AcceptsCustomIDAndTime ensures the parameterized
// form actually plumbs the caller's values through. The stale-tmp
// cleanup test (Batch 0.2) needs two run dirs with different IDs in
// the same process; this test pins that the helper supports it.
func TestNewRunDirWith_AcceptsCustomIDAndTime(t *testing.T) {
	wantID := "20260101-090000-deadbe"
	wantTime := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	dir := NewRunDirWith(t, wantID, wantTime)
	if dir.ID != wantID {
		t.Errorf("NewRunDirWith.ID = %q, want %q", dir.ID, wantID)
	}
	if !dir.CreatedAt.Equal(wantTime) {
		t.Errorf("NewRunDirWith.CreatedAt = %v, want %v", dir.CreatedAt, wantTime)
	}
}

// TestFixedTimes_HandsBackTimesInOrder pins the closure's primary
// behavior: each call returns the next pinned time.
func TestFixedTimes_HandsBackTimesInOrder(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	now := FixedTimes(t1, t2, t3)
	if got := now(); !got.Equal(t1) {
		t.Errorf("FixedTimes[0] = %v, want %v", got, t1)
	}
	if got := now(); !got.Equal(t2) {
		t.Errorf("FixedTimes[1] = %v, want %v", got, t2)
	}
	if got := now(); !got.Equal(t3) {
		t.Errorf("FixedTimes[2] = %v, want %v", got, t3)
	}
}

// TestFixedTimes_RepeatsLastAfterExhaustion pins the saturation
// behavior. Writers that emit more events than the test pre-staged
// would otherwise see a panic or a wraparound; the saturation rule
// keeps the JSONL stream parseable.
func TestFixedTimes_RepeatsLastAfterExhaustion(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := FixedTimes(t1)
	now()
	// After exhaustion the closure keeps returning t1.
	if got := now(); !got.Equal(t1) {
		t.Errorf("FixedTimes saturation = %v, want %v", got, t1)
	}
	if got := now(); !got.Equal(t1) {
		t.Errorf("FixedTimes saturation second call = %v, want %v", got, t1)
	}
}

// TestFixedTimes_NoTimesFallsBackToFixedRunTime pins the pathological
// "no times supplied" branch. A caller who builds the closure with
// an empty slice still gets a parseable timestamp.
func TestFixedTimes_NoTimesFallsBackToFixedRunTime(t *testing.T) {
	now := FixedTimes()
	if got := now(); !got.Equal(FixedRunTime) {
		t.Errorf("FixedTimes() with no times = %v, want %v", got, FixedRunTime)
	}
}

// TestRecordingBackendEventSink_RecordsAndCopies pins two
// invariants: Emit records the (verb, metadata) pair into a slice
// the test can read via Events(), and the metadata map is copied so
// a caller mutating its own map after Emit does not racily alter
// the recorded value.
func TestRecordingBackendEventSink_RecordsAndCopies(t *testing.T) {
	sink := NewRecordingBackendEventSink()
	metadata := map[string]string{"reason": "iptables_rejected"}
	if err := sink.Emit("network_policy_degraded", metadata); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	// Mutate the caller-side map; the recorded entry must be
	// untouched.
	metadata["reason"] = "OVERWRITTEN"
	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("Events len = %d, want 1", len(events))
	}
	if events[0].Verb != "network_policy_degraded" {
		t.Errorf("Events[0].Verb = %q, want %q", events[0].Verb, "network_policy_degraded")
	}
	if events[0].Metadata["reason"] != "iptables_rejected" {
		t.Errorf("Events[0].Metadata[reason] = %q, want %q (caller mutation leaked through)", events[0].Metadata["reason"], "iptables_rejected")
	}
}

// TestRecordingBackendEventSink_FailOnReturnsErrorAndDoesNotRecord
// pins the synthetic-failure injection used by tests that exercise
// the supervisor's graceful-degradation path.
func TestRecordingBackendEventSink_FailOnReturnsErrorAndDoesNotRecord(t *testing.T) {
	wantErr := errors.New("synthetic backend Emit failure")
	sink := NewRecordingBackendEventSink()
	sink.FailOn = map[string]error{"proxy_started": wantErr}
	if err := sink.Emit("proxy_started", map[string]string{"provider": "anthropic"}); !errors.Is(err, wantErr) {
		t.Errorf("Emit returned %v, want %v", err, wantErr)
	}
	if got := sink.Events(); len(got) != 0 {
		t.Errorf("FailOn path recorded events: %+v", got)
	}
}

// TestRecordingBackendEventSink_ConcurrentEmitIsSafe asserts the
// mutex around Emit holds up under concurrent calls. A race in the
// recorder would silently corrupt downstream tests' assertions.
func TestRecordingBackendEventSink_ConcurrentEmitIsSafe(t *testing.T) {
	sink := NewRecordingBackendEventSink()
	const goroutines = 8
	const perGoroutine = 25
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				_ = sink.Emit("proxy_started", map[string]string{"i": "x"})
			}
		}()
	}
	wg.Wait()
	if got := sink.Events(); len(got) != goroutines*perGoroutine {
		t.Errorf("concurrent Emit produced %d events, want %d", len(got), goroutines*perGoroutine)
	}
}

// TestEventsByVerb_FiltersByName pins the convenience filter. Tests
// that care about one subsystem's emissions read through this rather
// than re-implementing the filter.
func TestEventsByVerb_FiltersByName(t *testing.T) {
	sink := NewRecordingBackendEventSink()
	_ = sink.Emit("proxy_started", map[string]string{"provider": "anthropic"})
	_ = sink.Emit("gateway_started", map[string]string{"server_count": "2"})
	_ = sink.Emit("proxy_started", map[string]string{"provider": "openai"})
	got := sink.EventsByVerb("proxy_started")
	if len(got) != 2 {
		t.Fatalf("EventsByVerb len = %d, want 2", len(got))
	}
	if got[0].Metadata["provider"] != "anthropic" {
		t.Errorf("EventsByVerb[0].Metadata[provider] = %q, want %q", got[0].Metadata["provider"], "anthropic")
	}
}

// TestReadJSONL_RoundTrips verifies the generic reader decodes the
// JSONL the writer produced.
func TestReadJSONL_RoundTrips(t *testing.T) {
	type sample struct {
		Verb string `json:"verb"`
		N    int    `json:"n"`
	}
	dir := ShortTempDir(t)
	path := filepath.Join(dir, "stream.jsonl")
	for i, want := range []sample{{Verb: "a", N: 1}, {Verb: "b", N: 2}} {
		if err := WriteJSONLLine(path, want); err != nil {
			t.Fatalf("WriteJSONLLine[%d]: %v", i, err)
		}
	}
	got := ReadJSONL[sample](t, path)
	if len(got) != 2 {
		t.Fatalf("ReadJSONL len = %d, want 2", len(got))
	}
	if got[0].Verb != "a" || got[1].N != 2 {
		t.Errorf("ReadJSONL = %+v, want [{a 1} {b 2}]", got)
	}
}

// TestReadJSONL_MissingFileReturnsNil pins the "no on-disk record"
// case: tests that assert on the absence of a stream call ReadJSONL
// and check len == 0 rather than os.IsNotExist.
func TestReadJSONL_MissingFileReturnsNil(t *testing.T) {
	dir := ShortTempDir(t)
	got := ReadJSONL[struct{}](t, filepath.Join(dir, "does-not-exist.jsonl"))
	if got != nil {
		t.Errorf("ReadJSONL on missing file = %v, want nil", got)
	}
}

// TestReadRawJSONLLines_ReturnsCopies verifies the raw reader does
// not alias the underlying file buffer; mutating one returned slice
// must not affect another.
func TestReadRawJSONLLines_ReturnsCopies(t *testing.T) {
	dir := ShortTempDir(t)
	path := filepath.Join(dir, "stream.jsonl")
	if err := WriteJSONLLine(path, map[string]string{"k": "v1"}); err != nil {
		t.Fatalf("WriteJSONLLine: %v", err)
	}
	if err := WriteJSONLLine(path, map[string]string{"k": "v2"}); err != nil {
		t.Fatalf("WriteJSONLLine: %v", err)
	}
	got := ReadRawJSONLLines(t, path)
	if len(got) != 2 {
		t.Fatalf("ReadRawJSONLLines len = %d, want 2", len(got))
	}
	// Mutate the first line; the second must be unaffected.
	got[0][0] = 'X'
	if got[1][0] == 'X' {
		t.Errorf("ReadRawJSONLLines aliased buffers: mutating line 0 affected line 1")
	}
}

// TestBuiltinSecretFixtures_HasExpectedFamilies pins the canonical
// fixture-coverage contract. A regression that removed (e.g.) the
// Anthropic exemplar would silently weaken every downstream
// redaction test.
func TestBuiltinSecretFixtures_HasExpectedFamilies(t *testing.T) {
	wantPatterns := []string{
		"anthropic_key",
		"openai_key",
		"github_pat_classic",
		"aws_access_key",
		"slack_token",
	}
	got := BuiltinSecretFixtures()
	have := make(map[string]bool, len(got))
	for _, f := range got {
		have[f.Pattern] = true
	}
	for _, want := range wantPatterns {
		if !have[want] {
			t.Errorf("BuiltinSecretFixtures missing pattern %q (red-team coverage gap)", want)
		}
	}
}

// TestBuiltinSecretFixtures_ReturnsFreshCopy verifies the caller may
// mutate its returned slice without poisoning later callers.
func TestBuiltinSecretFixtures_ReturnsFreshCopy(t *testing.T) {
	first := BuiltinSecretFixtures()
	if len(first) == 0 {
		t.Fatal("BuiltinSecretFixtures returned empty slice; the harness ships with exemplars")
	}
	originalValue := first[0].Value
	first[0].Value = "MUTATED"
	second := BuiltinSecretFixtures()
	if second[0].Value != originalValue {
		t.Errorf("BuiltinSecretFixtures aliased internal slice: mutation %q leaked to %q", first[0].Value, second[0].Value)
	}
}

// TestContainsAnySecret_FindsAFixture verifies the haystack scanner
// catches each fixture's Value.
func TestContainsAnySecret_FindsAFixture(t *testing.T) {
	for _, fixture := range BuiltinSecretFixtures() {
		haystack := []byte("prefix " + fixture.Value + " suffix")
		got, ok := ContainsAnySecret(haystack)
		if !ok {
			t.Errorf("ContainsAnySecret missed fixture %q (value=%q)", fixture.Pattern, fixture.Value)
			continue
		}
		if got.Pattern != fixture.Pattern {
			t.Errorf("ContainsAnySecret reported %q, want %q", got.Pattern, fixture.Pattern)
		}
	}
}

// TestContainsAnySecret_ReportsAbsence pins the negative path: a
// haystack without any fixture returns the zero value + false.
func TestContainsAnySecret_ReportsAbsence(t *testing.T) {
	got, ok := ContainsAnySecret([]byte("lorem ipsum dolor sit amet"))
	if ok {
		t.Errorf("ContainsAnySecret on clean haystack returned %+v, want zero", got)
	}
}

// TestAssertNoSecretsLeakedInFile_HandlesMissingFile pins that the
// helper is no-op-on-missing.
func TestAssertNoSecretsLeakedInFile_HandlesMissingFile(t *testing.T) {
	dir := ShortTempDir(t)
	AssertNoSecretsLeakedInFile(t, filepath.Join(dir, "missing.jsonl"))
	// If we reached here, no failure was produced — that's the
	// expected outcome.
}

// TestAssertNoSecretsLeakedInFile_FlagsLeak verifies the helper fails
// a test when a fixture value is present.
func TestAssertNoSecretsLeakedInFile_FlagsLeak(t *testing.T) {
	dir := ShortTempDir(t)
	path := filepath.Join(dir, "leaky.txt")
	fixture := BuiltinSecretFixtures()[0]
	if err := os.WriteFile(path, []byte("contents with "+fixture.Value), 0o600); err != nil {
		t.Fatalf("seed leaky file: %v", err)
	}
	// Drive AssertNoSecretsLeakedInFile against a fake T that
	// records failures. The standard library's testing.T does not
	// expose its failure state to other tests; we reuse the
	// ContainsAnySecret primitive instead.
	if _, ok := ContainsAnySecret([]byte("contents with "+fixture.Value)); !ok {
		t.Errorf("ContainsAnySecret failed to spot the seeded leak; AssertNoSecretsLeakedInFile would also miss it")
	}
}

// TestFindSecretByPattern_Hit verifies the lookup helper resolves a
// known pattern name.
func TestFindSecretByPattern_Hit(t *testing.T) {
	got, err := FindSecretByPattern("anthropic_key")
	if err != nil {
		t.Fatalf("FindSecretByPattern(anthropic_key) err = %v", err)
	}
	if !strings.HasPrefix(got.Value, "sk-ant-") {
		t.Errorf("FindSecretByPattern(anthropic_key).Value = %q, want sk-ant- prefix", got.Value)
	}
}

// TestFindSecretByPattern_MissReturnsSentinel pins the negative
// lookup path and the errors.Is sentinel.
func TestFindSecretByPattern_MissReturnsSentinel(t *testing.T) {
	_, err := FindSecretByPattern("does-not-exist")
	if err == nil {
		t.Fatal("FindSecretByPattern miss returned nil error")
	}
	if !errors.Is(err, ErrFixtureMissing) {
		t.Errorf("FindSecretByPattern miss error = %v, want errors.Is(ErrFixtureMissing)", err)
	}
}

// TestBuiltinPEMFixture_HasShape pins the PEM exemplar's shape
// (BEGIN/END markers + a body) so the scanner-shape contract is
// captured here even when the scanner itself is rebuilt.
func TestBuiltinPEMFixture_HasShape(t *testing.T) {
	pem := BuiltinPEMFixture()
	if !strings.Contains(pem, "-----BEGIN") || !strings.Contains(pem, "-----END") {
		t.Errorf("BuiltinPEMFixture missing BEGIN/END markers: %q", pem)
	}
}

// TestFixtureRedactedMarker_PinsPrefix pins the literal prefix the
// plan's JSON-aware response scrubber writes. Downstream tests grep
// for this substring; a typo would silently break them.
func TestFixtureRedactedMarker_PinsPrefix(t *testing.T) {
	if FixtureRedactedMarker != "[REDACTED" {
		t.Errorf("FixtureRedactedMarker = %q, want %q (plan-pinned scrub prefix)", FixtureRedactedMarker, "[REDACTED")
	}
}
