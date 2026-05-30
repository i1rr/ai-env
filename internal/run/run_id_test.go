package run

// Dedicated step 15 test: "two runs in the same second produce distinct
// run IDs". Plan 03, line 156. This file exists as a separate suite
// (instead of folding the case into run_test.go's existing
// TestRunIDGenerator_SameSecondDistinctIDs) because the plan calls the
// check out as its own task in step 15 and because we want a stronger
// guarantee than the earlier test pins:
//
//   - The earlier test wires two distinct *staticReader* sources behind
//     two generators sharing a clock; that proves "different randomness
//     => different IDs" but does not exercise the production code path
//     where a single generator is queried twice within the same wall
//     clock second.
//   - The cases below pin the production path: one generator wired to the
//     real crypto/rand.Reader (via the package's randomReader default)
//     with the clock frozen at one moment, called many times in a tight
//     loop. The resulting IDs must all share the second-resolution prefix
//     yet have distinct random suffixes. The plan's acceptance criterion 2
//     ("two runs started in the same second receive distinct run IDs") is
//     the user-facing contract this enforces.

import (
	"strings"
	"testing"
	"time"
)

// TestStep15_RunIDGenerator_SameSecondProductionPathDistinct exercises
// the production generator path against a clock that never advances.
// Each Generate() call shares the same crypto/rand source the production
// CLI uses; the generated IDs must still be pairwise distinct. The loop
// is deliberately large (1024 iterations) so a regression that, say,
// seeded the random source from the clock and got the same suffix every
// time would fail with overwhelming probability rather than relying on
// the wall clock to advance between calls.
func TestStep15_RunIDGenerator_SameSecondProductionPathDistinct(t *testing.T) {
	// Pin the clock to a single moment. The production crypto/rand.Reader
	// remains the random source because we leave the Random field nil:
	// Generate falls back to the package-level randomReader, which is
	// crypto/rand.Reader in production. This is the path the CLI takes.
	pinned := time.Date(2026, 5, 30, 12, 34, 56, 0, time.UTC)
	gen := &RunIDGenerator{Clock: fixedClock{t: pinned}}

	const iterations = 1024
	seen := make(map[string]int, iterations)
	wantPrefix := pinned.Format(runIDTimeLayout) + "-"

	for i := 0; i < iterations; i++ {
		id, err := gen.Generate()
		if err != nil {
			t.Fatalf("Generate iter=%d: %v", i, err)
		}
		// Every ID's timestamp portion must match the frozen clock; this
		// is what makes the test a same-second test rather than relying
		// on the wall clock to advance between calls.
		if !strings.HasPrefix(id, wantPrefix) {
			t.Fatalf("Generate iter=%d: id %q does not have pinned-clock prefix %q", i, id, wantPrefix)
		}
		// runIDPattern is defined in run_test.go and matches the plan's
		// "YYYYMMDD-HHMMSS-<6-hex>" format.
		if !runIDPattern.MatchString(id) {
			t.Fatalf("Generate iter=%d: id %q does not match %s", i, id, runIDPattern)
		}
		if first, ok := seen[id]; ok {
			t.Fatalf("duplicate run ID %q at iter=%d (first seen at iter=%d)", id, i, first)
		}
		seen[id] = i
	}
	if len(seen) != iterations {
		t.Fatalf("collected %d unique IDs, want %d", len(seen), iterations)
	}
}

// TestStep15_TwoRunsInSameSecondDistinct is the literal restatement of
// the plan's acceptance criterion 2: two consecutive Generate calls,
// pinned to the same second, must produce different IDs. The loop above
// covers this in the limit; this case keeps the spirit of the plan's
// wording ("two runs in the same second") visible in the test name so a
// future reader does not have to dig through a stress-test to find the
// pinned semantics.
func TestStep15_TwoRunsInSameSecondDistinct(t *testing.T) {
	pinned := time.Date(2026, 5, 30, 12, 34, 56, 0, time.UTC)
	gen := &RunIDGenerator{Clock: fixedClock{t: pinned}}

	idA, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate a: %v", err)
	}
	idB, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate b: %v", err)
	}

	if idA[:len(runIDTimeLayout)] != idB[:len(runIDTimeLayout)] {
		t.Fatalf("expected identical timestamp prefixes (clock frozen), got %q vs %q", idA, idB)
	}
	if idA == idB {
		t.Fatalf("same-second IDs must differ, got %q twice", idA)
	}
	if !runIDPattern.MatchString(idA) || !runIDPattern.MatchString(idB) {
		t.Errorf("IDs %q / %q do not match %s", idA, idB, runIDPattern)
	}
}

// TestStep15_GenerateRunIDPackageHelperSameSecondDistinct repeats the
// same-second invariant against the package-level GenerateRunID helper
// (the one the CLI calls). The clock cannot be pinned in this path
// because GenerateRunID uses SystemClock, but the burst is tight enough
// that on every realistic host at least one pair of IDs lands inside the
// same wall-clock second; the assertion is simpler than picking the
// boundary: every produced ID must be unique. A regression that returned
// the same ID twice (e.g. by reusing a cached random buffer) would fail
// here without depending on clock granularity.
func TestStep15_GenerateRunIDPackageHelperSameSecondDistinct(t *testing.T) {
	const iterations = 256
	seen := make(map[string]int, iterations)
	for i := 0; i < iterations; i++ {
		id, err := GenerateRunID()
		if err != nil {
			t.Fatalf("GenerateRunID iter=%d: %v", i, err)
		}
		if !runIDPattern.MatchString(id) {
			t.Fatalf("GenerateRunID iter=%d: id %q does not match %s", i, id, runIDPattern)
		}
		if first, ok := seen[id]; ok {
			t.Fatalf("duplicate ID %q at iter=%d (first seen at %d)", id, i, first)
		}
		seen[id] = i
	}
}
