package run

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedClock returns a deterministic clock that advances by one second
// per call. Used by the writer tests so the on-disk Timestamp values are
// stable across runs.
func fixedPolicyClock() func() time.Time {
	start := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	step := time.Duration(0)
	return func() time.Time {
		t := start.Add(step)
		step += time.Second
		return t
	}
}

// newRunDir builds a fresh run directory under a t.TempDir() and returns
// its absolute path. Centralized so each test does not re-run the
// CreateRunDirectory dance.
func newRunDir(t *testing.T, runID string) string {
	t.Helper()
	aiEnvDir := t.TempDir()
	rd, err := CreateRunDirectory(aiEnvDir, runID, time.Now())
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return rd.Path
}

// TestPolicyDecisionsWriter_WriteRoundTrip pins the canonical write +
// read path for a gate decision event followed by a broker action
// event. Both shapes must round-trip through the writer and parser
// without losing any field.
func TestPolicyDecisionsWriter_WriteRoundTrip(t *testing.T) {
	runDir := newRunDir(t, "20260531-120000-aaaaaa")
	w, err := OpenPolicyDecisionsWriter(runDir, PolicyDecisionsWriterOptions{
		RunID: "20260531-120000-aaaaaa",
		Now:   fixedPolicyClock(),
	})
	if err != nil {
		t.Fatalf("OpenPolicyDecisionsWriter: %v", err)
	}

	gateEvt := PolicyDecisionEvent{
		Event:    PolicyDecisionExportGate,
		Surface:  "pr",
		EnvName:  "fix-tests",
		Decision: PolicyDecisionAllow,
	}
	if err := w.Write(gateEvt); err != nil {
		t.Fatalf("Write gate: %v", err)
	}

	brokerEvt := PolicyDecisionEvent{
		Event:     PolicyDecisionBrokerAction,
		Action:    PolicyActionBrokerCreatePR,
		EnvName:   "fix-tests",
		Decision:  PolicyDecisionAllow,
		Branch:    "ai-env/fix-tests",
		Repo:      "acme/demo",
		TokenKind: "github_app",
		PRNumber:  42,
		PRURL:     "https://github.com/acme/demo/pull/42",
	}
	if err := w.Write(brokerEvt); err != nil {
		t.Fatalf("Write broker: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	events, err := ReadPolicyDecisions(runDir)
	if err != nil {
		t.Fatalf("ReadPolicyDecisions: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}

	if events[0].Event != PolicyDecisionExportGate {
		t.Errorf("events[0].Event=%q, want %q", events[0].Event, PolicyDecisionExportGate)
	}
	if events[0].Decision != PolicyDecisionAllow {
		t.Errorf("events[0].Decision=%q, want %q", events[0].Decision, PolicyDecisionAllow)
	}
	if events[0].RunID != "20260531-120000-aaaaaa" {
		t.Errorf("events[0].RunID=%q, want it to be filled in by writer", events[0].RunID)
	}
	if events[0].Timestamp == "" {
		t.Errorf("events[0].Timestamp must be filled in by writer")
	}

	if events[1].Action != PolicyActionBrokerCreatePR {
		t.Errorf("events[1].Action=%q, want %q", events[1].Action, PolicyActionBrokerCreatePR)
	}
	if events[1].PRNumber != 42 {
		t.Errorf("events[1].PRNumber=%d, want 42", events[1].PRNumber)
	}
	if events[1].PRURL != "https://github.com/acme/demo/pull/42" {
		t.Errorf("events[1].PRURL=%q, want PR url", events[1].PRURL)
	}
	if events[1].Repo != "acme/demo" {
		t.Errorf("events[1].Repo=%q, want %q", events[1].Repo, "acme/demo")
	}
}

// TestPolicyDecisionsWriter_RejectsEmptyEvent pins the input validation:
// an event with no verb cannot be written so a misconfigured caller
// surfaces a clear error rather than producing an unidentifiable record.
func TestPolicyDecisionsWriter_RejectsEmptyEvent(t *testing.T) {
	runDir := newRunDir(t, "20260531-120001-bbbbbb")
	w, err := OpenPolicyDecisionsWriter(runDir, PolicyDecisionsWriterOptions{
		RunID: "20260531-120001-bbbbbb",
		Now:   fixedPolicyClock(),
	})
	if err != nil {
		t.Fatalf("OpenPolicyDecisionsWriter: %v", err)
	}
	defer w.Close()

	err = w.Write(PolicyDecisionEvent{Decision: PolicyDecisionAllow})
	if err == nil {
		t.Fatalf("Write with empty Event=nil, want error")
	}
	if !strings.Contains(err.Error(), "Event verb") {
		t.Errorf("err=%v, want substring Event verb", err)
	}

	err = w.Write(PolicyDecisionEvent{Event: PolicyDecisionExportGate})
	if err == nil {
		t.Fatalf("Write with empty Decision=nil, want error")
	}
	if !strings.Contains(err.Error(), "Decision") {
		t.Errorf("err=%v, want substring Decision", err)
	}
}

// TestPolicyDecisionsWriter_CloseIdempotent pins the close contract: a
// double-close is a no-op (not an error) so a deferred close compounding
// with an explicit close stays safe. After close, Write fails with a
// clear error.
func TestPolicyDecisionsWriter_CloseIdempotent(t *testing.T) {
	runDir := newRunDir(t, "20260531-120002-cccccc")
	w, err := OpenPolicyDecisionsWriter(runDir, PolicyDecisionsWriterOptions{
		RunID: "20260531-120002-cccccc",
	})
	if err != nil {
		t.Fatalf("OpenPolicyDecisionsWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close (second): %v", err)
	}
	if err := w.Write(PolicyDecisionEvent{
		Event:    PolicyDecisionExportGate,
		Decision: PolicyDecisionAllow,
	}); err == nil {
		t.Fatalf("Write after Close=nil, want error")
	}
}

// TestReadPolicyDecisions_MissingFile pins the absence-tolerant read
// behavior: a missing or empty file produces (nil, nil) so callers can
// uniformly call the reader even before any decision has been recorded.
func TestReadPolicyDecisions_MissingFile(t *testing.T) {
	tmp := t.TempDir()
	events, err := ReadPolicyDecisions(tmp)
	if err != nil {
		t.Fatalf("ReadPolicyDecisions on bare dir: %v", err)
	}
	if events != nil {
		t.Errorf("got %v events from missing file, want nil", events)
	}
}

// TestReadPolicyDecisions_OnDiskShape asserts the on-disk file is JSONL
// (one JSON object per line) so external tooling (grep, jq) can consume
// the file without an explicit parser. The writer must not emit pretty-
// printed multi-line records.
func TestReadPolicyDecisions_OnDiskShape(t *testing.T) {
	runDir := newRunDir(t, "20260531-120003-dddddd")
	w, err := OpenPolicyDecisionsWriter(runDir, PolicyDecisionsWriterOptions{
		RunID: "20260531-120003-dddddd",
		Now:   fixedPolicyClock(),
	})
	if err != nil {
		t.Fatalf("OpenPolicyDecisionsWriter: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Write(PolicyDecisionEvent{
			Event:    PolicyDecisionExportGate,
			Surface:  "pr",
			EnvName:  "fix",
			Decision: PolicyDecisionAllow,
		}); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	w.Close()

	data, err := os.ReadFile(filepath.Join(runDir, policyDecisionsFileName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3 (one JSON object per line). file:\n%s", len(lines), string(data))
	}
	for i, ln := range lines {
		var got PolicyDecisionEvent
		if err := json.Unmarshal([]byte(ln), &got); err != nil {
			t.Fatalf("line %d not valid JSON: %v\nline=%s", i, err, ln)
		}
	}
}
