package run

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newLifecycleRunDir is a small helper that builds a real RunDirectory on
// disk so each test starts from the same scaffolded layout the supervisor
// will see in production. Using CreateRunDirectory (rather than a bare
// MkdirAll) keeps the writer tests honest against the placeholder file
// the directory creator left behind.
func newLifecycleRunDir(t *testing.T) RunDirectory {
	t.Helper()
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-a1b2c3"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return dir
}

// fixedTimes returns a now() closure that hands back the supplied times
// in order. After the slice is exhausted, every subsequent call returns
// the last time so a test that writes more events than it pre-staged
// still produces parseable JSON (the timestamps just stop advancing).
// The closure is the production seam OpenLifecycleWriter accepts.
func fixedTimes(times ...time.Time) func() time.Time {
	i := 0
	return func() time.Time {
		if i >= len(times) {
			return times[len(times)-1]
		}
		t := times[i]
		i++
		return t
	}
}

// TestLifecycleWriter_AppendsValidJSONL covers the writer's primary
// contract: every Write call appends exactly one valid JSON object
// followed by a newline, and the resulting file is well-formed JSONL
// (one record per line, all decodable).
//
// We walk a representative slice of the happy-path state sequence so the
// test also catches accidental drops or duplicates in the encode path.
func TestLifecycleWriter_AppendsValidJSONL(t *testing.T) {
	dir := newLifecycleRunDir(t)

	// Three distinct timestamps so a writer that accidentally reuses the
	// same timestamp across events shows up as identical lines.
	t1 := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	t2 := t1.Add(2 * time.Second)
	t3 := t1.Add(5 * time.Second)

	w, err := OpenLifecycleWriter(dir.Path, LifecycleWriterOptions{
		RunID:   dir.ID,
		Backend: "docker-sbx",
		Agent:   "claude",
		Now:     fixedTimes(t1, t2, t3),
	})
	if err != nil {
		t.Fatalf("OpenLifecycleWriter: %v", err)
	}

	states := []State{StatePreparingWorkspace, StateRunning, StateCompleted}
	for _, s := range states {
		if err := w.Write(s); err != nil {
			t.Fatalf("Write(%q): %v", s, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read the file back and decode every line independently. JSONL by
	// definition is one JSON value per line, so a parser failure on any
	// line is a fatal regression.
	path := filepath.Join(dir.Path, "lifecycle.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read lifecycle.jsonl: %v", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	var events []LifecycleEvent
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var evt LifecycleEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("unmarshal line %q: %v", line, err)
		}
		events = append(events, evt)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}

	if len(events) != len(states) {
		t.Fatalf("events = %d, want %d", len(events), len(states))
	}
	wantStamps := []time.Time{t1, t2, t3}
	for i, evt := range events {
		if evt.RunID != dir.ID {
			t.Errorf("event[%d].RunID = %q, want %q", i, evt.RunID, dir.ID)
		}
		if evt.State != states[i] {
			t.Errorf("event[%d].State = %q, want %q", i, evt.State, states[i])
		}
		if evt.Backend != "docker-sbx" {
			t.Errorf("event[%d].Backend = %q, want %q", i, evt.Backend, "docker-sbx")
		}
		if evt.Agent != "claude" {
			t.Errorf("event[%d].Agent = %q, want %q", i, evt.Agent, "claude")
		}
		if evt.Timestamp != wantStamps[i].Format(time.RFC3339) {
			t.Errorf("event[%d].Timestamp = %q, want %q", i, evt.Timestamp, wantStamps[i].Format(time.RFC3339))
		}
	}

	// The file must end on a newline so a downstream tail -f reader
	// does not block waiting for one. Also catches a stray trailing
	// garbage byte that the marshal path could have appended.
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		tailStart := len(raw) - 8
		if tailStart < 0 {
			tailStart = 0
		}
		t.Errorf("lifecycle.jsonl must end with newline; got tail=%q", string(raw[tailStart:]))
	}
}

// TestLifecycleWriter_MatchesPlanExampleByteForByte pins the on-disk
// shape against the plan's documented event format. A single event with
// the plan's exact field values must serialize to the plan's example
// (modulo whitespace, which JSONL does not allow). This catches a
// rename of a JSON tag or an accidental field reordering at review
// time rather than once it is in production audit logs.
func TestLifecycleWriter_MatchesPlanExampleByteForByte(t *testing.T) {
	dir := newLifecycleRunDir(t)

	// The plan's example uses "+10:00" UTC offset; build a FixedZone so
	// the marshalled timestamp matches.
	loc := time.FixedZone("+10:00", 10*3600)
	stamp := time.Date(2026, 5, 28, 10, 13, 0, 0, loc)

	w, err := OpenLifecycleWriter(dir.Path, LifecycleWriterOptions{
		RunID:   "20260528-101300-a1b2c3",
		Backend: "docker-sbx",
		Agent:   "claude",
		Now:     fixedTimes(stamp),
	})
	if err != nil {
		t.Fatalf("OpenLifecycleWriter: %v", err)
	}
	if err := w.Write(StateRunning); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir.Path, "lifecycle.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// We assert the JSON keys exactly so a renamed tag (e.g. "runId"
	// instead of "run_id") fails loud.
	want := `{"run_id":"20260528-101300-a1b2c3","state":"running","backend":"docker-sbx","agent":"claude","timestamp":"2026-05-28T10:13:00+10:00"}` + "\n"
	if string(raw) != want {
		t.Errorf("lifecycle.jsonl =\n%q\nwant\n%q", string(raw), want)
	}
}

// TestLifecycleWriter_ConcurrentWritesProduceDistinctLines locks down
// the concurrency contract. The supervisor's main loop and signal
// handler may both transition the state machine, and the lifecycle
// writer is the audit trail for both. Two goroutines writing
// simultaneously must produce two whole lines with no byte
// interleaving.
//
// We run many goroutines (more than the typical state-change frequency)
// to make any race show up under the race detector. Every emitted line
// must decode cleanly into a LifecycleEvent.
func TestLifecycleWriter_ConcurrentWritesProduceDistinctLines(t *testing.T) {
	dir := newLifecycleRunDir(t)

	w, err := OpenLifecycleWriter(dir.Path, LifecycleWriterOptions{
		RunID:   dir.ID,
		Backend: "docker-sbx",
		Agent:   "claude",
		Now:     time.Now, // production clock; uniqueness comes from per-event payload, not the timestamp
	})
	if err != nil {
		t.Fatalf("OpenLifecycleWriter: %v", err)
	}

	const goroutines = 32
	const eventsPer = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < eventsPer; i++ {
				if err := w.Write(StateRunning); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir.Path, "lifecycle.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	want := goroutines * eventsPer
	if len(lines) != want {
		t.Fatalf("lines = %d, want %d", len(lines), want)
	}
	for i, line := range lines {
		var evt LifecycleEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("line %d unmarshal: %v: %q", i, err, line)
		}
		if evt.State != StateRunning {
			t.Errorf("line %d: state = %q, want %q", i, evt.State, StateRunning)
		}
	}
}

// TestLifecycleWriter_RejectsWriteAfterClose makes sure a supervisor
// bug (Closing the writer too early) surfaces loudly instead of
// silently dropping the terminal event.
func TestLifecycleWriter_RejectsWriteAfterClose(t *testing.T) {
	dir := newLifecycleRunDir(t)

	w, err := OpenLifecycleWriter(dir.Path, LifecycleWriterOptions{
		RunID:   dir.ID,
		Backend: "docker-sbx",
		Agent:   "claude",
	})
	if err != nil {
		t.Fatalf("OpenLifecycleWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Write(StateRunning); err == nil {
		t.Error("Write after Close: expected error, got nil")
	}
	// A second Close is documented to be a no-op so the supervisor's
	// defer-close pattern stays safe.
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestLifecycleWriter_RequiresOptions checks the constructor refuses to
// build a writer that could emit incomplete event records. Missing any
// of RunID, Backend, Agent would surface in lifecycle.jsonl as an empty
// string for a plan-mandatory field; we want the failure at startup
// instead.
func TestLifecycleWriter_RequiresOptions(t *testing.T) {
	dir := newLifecycleRunDir(t)

	cases := []struct {
		name string
		opts LifecycleWriterOptions
	}{
		{"missing runID", LifecycleWriterOptions{Backend: "b", Agent: "a"}},
		{"missing backend", LifecycleWriterOptions{RunID: "r", Agent: "a"}},
		{"missing agent", LifecycleWriterOptions{RunID: "r", Backend: "b"}},
	}
	for _, c := range cases {
		if _, err := OpenLifecycleWriter(dir.Path, c.opts); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}

	if _, err := OpenLifecycleWriter("", LifecycleWriterOptions{RunID: "r", Backend: "b", Agent: "a"}); err == nil {
		t.Error("missing runDir: expected error")
	}
}

// TestLifecycleWriter_AppendsToExistingFile guards the recovery /
// replay path: a writer opened against a run directory that already
// has lifecycle events (because the supervisor restarted or because
// the file was carried over via --continue) must append rather than
// truncate. Truncation would erase the audit trail of the earlier
// segment.
func TestLifecycleWriter_AppendsToExistingFile(t *testing.T) {
	dir := newLifecycleRunDir(t)
	path := filepath.Join(dir.Path, "lifecycle.jsonl")

	// Seed an existing line so the test can verify it survives.
	seed := `{"run_id":"prev","state":"created","backend":"docker-sbx","agent":"claude","timestamp":"2026-05-28T10:00:00Z"}` + "\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	w, err := OpenLifecycleWriter(dir.Path, LifecycleWriterOptions{
		RunID:   dir.ID,
		Backend: "docker-sbx",
		Agent:   "claude",
		Now:     fixedTimes(time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("OpenLifecycleWriter: %v", err)
	}
	if err := w.Write(StateRunning); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(raw), seed) {
		t.Errorf("seed line was lost; file=%q", string(raw))
	}
	// Two non-empty lines total.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
}

// TestLifecycleWriter_DefaultsToTimeNow confirms the nil-clock fallback
// path produces a syntactically valid timestamp rather than a zero or
// empty string. The fallback is what production callers rely on; only
// tests bother injecting a clock.
func TestLifecycleWriter_DefaultsToTimeNow(t *testing.T) {
	dir := newLifecycleRunDir(t)

	w, err := OpenLifecycleWriter(dir.Path, LifecycleWriterOptions{
		RunID:   dir.ID,
		Backend: "docker-sbx",
		Agent:   "claude",
	})
	if err != nil {
		t.Fatalf("OpenLifecycleWriter: %v", err)
	}
	if err := w.Write(StateRunning); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir.Path, "lifecycle.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var evt LifecycleEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &evt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, err := time.Parse(time.RFC3339, evt.Timestamp); err != nil {
		t.Errorf("timestamp %q is not RFC3339: %v", evt.Timestamp, err)
	}
}

