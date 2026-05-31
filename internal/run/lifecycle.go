package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// lifecycleFileName is the basename of the per-run lifecycle event log.
// It lives at the root of the run directory next to run.json so a reviewer
// reading a run on disk sees the event stream and the final-state snapshot
// side by side. The constant mirrors taskFileName / runFileNames; keeping
// it here rather than redeclaring it in run.go means the lifecycle writer
// is the single owner of the filename even though run.go materialized the
// placeholder.
const lifecycleFileName = "lifecycle.jsonl"

// LifecycleEvent is one record written to lifecycle.jsonl. The shape is
// pinned by plan 03's "Event formats" section and by the master plan's
// section 24 "Lifecycle event format": run_id, state, backend, agent, and
// timestamp. Every field is encoded in the order shown in the plan so the
// on-disk JSONL stays a byte-for-byte match against the documented schema
// (json.Marshal preserves struct field order).
//
// State-transition records have State set and Verb empty. Verb-event
// records (proxy_started, gateway_started, observer_started, etc., per
// Batch 0.1) have Verb set, an optional Metadata map carrying the per-
// verb key/value table documented in lifecycle_verbs.go, and State empty.
// The State and Verb tags both use omitempty so the on-disk record stays
// byte-for-byte compatible with the plan's example for the state path
// (Verb / Metadata simply do not appear) while still letting the same
// file carry the broader lifecycle verbs Batch 0.1 introduces. A reader
// switches on whether State or Verb is non-empty to pick the interesting
// field set; both being empty is rejected at write time.
//
// RunID, Backend, Agent, and Timestamp are required on every record. A
// missing value for backend or agent would point at a supervisor bug
// (the supervisor knows both before it ever emits the first event), and
// silently dropping fields would hide that.
//
// Timestamp is an RFC3339 string with timezone offset (matching the
// plan's "2026-05-28T10:13:00+10:00" example) rather than a time.Time
// value so the JSON serialization is stable across Go versions and
// matches a literal grep of the plan.
type LifecycleEvent struct {
	// RunID is the run this event belongs to. It is duplicated into every
	// record so a future aggregator can concatenate lifecycle.jsonl files
	// from many runs without losing attribution.
	RunID string `json:"run_id"`

	// State is the state the run is transitioning into when the event is
	// written. State strings come straight from the State constants in
	// state.go; the lifecycle writer does not validate them itself
	// because the state machine already rejected unknown values upstream.
	// Empty (omitted) on verb-event records (see Verb below); set on
	// state-transition records.
	State State `json:"state,omitempty"`

	// Verb identifies a non-state-transition lifecycle event. Pinned to
	// one of the LifecycleVerb* constants defined in lifecycle_verbs.go.
	// Empty (omitted) on state-transition records; set on verb-event
	// records. The Metadata field below carries the per-verb key/value
	// table documented next to each constant.
	Verb LifecycleVerb `json:"verb,omitempty"`

	// Backend is the backend identifier (e.g. "docker-sbx", "local-process")
	// the supervisor selected for this run. The plan calls this out
	// explicitly in the event format example.
	Backend string `json:"backend"`

	// Agent is the agent identifier (e.g. "claude", "codex") the
	// supervisor launched for this run. Like Backend, the plan pins it.
	Agent string `json:"agent"`

	// Timestamp is the moment the event was emitted, formatted as RFC3339
	// with a numeric timezone offset. The lifecycle writer fills this in
	// at write time using its clock; callers do not set it themselves.
	Timestamp string `json:"timestamp"`

	// Metadata is the per-verb key/value context table documented in
	// lifecycle_verbs.go alongside each LifecycleVerb constant. Empty
	// (omitted) on state-transition records and on verb records that
	// carry no per-verb payload. The map is shallow-copied at write time
	// so subsequent caller mutations do not affect the recorded value.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// LifecycleWriter appends LifecycleEvent records to lifecycle.jsonl.
//
// The plan calls for append-only newline-delimited JSON, one record per
// lifecycle event, flushed after every write so a crash does not lose
// events the supervisor believed were durable. The writer is safe for
// concurrent use: the supervisor's main loop and its signal handler may
// both call Write from different goroutines, and the resulting on-disk
// file must contain one well-formed JSON object per line with no
// interleaving.
//
// Construction goes through OpenLifecycleWriter so the file handle, the
// per-run metadata (run ID, backend, agent), and the clock are wired in
// once. The handle stays open for the lifetime of the run; Close is the
// only orderly shutdown path. The supervisor closes the writer as part
// of the post-run drain in step 10.
//
// Design notes:
//
//   - We open the underlying file with O_APPEND so even a multi-process
//     append (unlikely in v0.1, but defensive against future cross-process
//     event sources like the shell shim) lands as a whole record per write
//     rather than interleaving bytes mid-line.
//   - We Sync after every successful write rather than relying on the OS
//     buffer cache. lifecycle events are infrequent (state transitions, not
//     stdout chunks) so the cost is negligible, and a host crash between
//     event time and fsync time would otherwise erase the lifecycle trail
//     the audit logger depends on.
//   - The mutex serializes write+sync so two goroutines cannot interleave
//     bytes nor race on the file offset.
type LifecycleWriter struct {
	// mu serializes writes so concurrent callers cannot interleave bytes
	// inside a single JSON line, even though O_APPEND already protects the
	// file offset on POSIX. The encoder + sync sequence is a logical
	// write, not just a byte-level one, so the mutex covers both halves.
	mu sync.Mutex

	// file is the open lifecycle.jsonl handle. It is kept open for the
	// lifetime of the writer so we are not paying open/close for every
	// event; closed exactly once by Close().
	file *os.File

	// runID is the run identifier copied into every event's RunID field.
	// Stored on the writer rather than passed per-call because the
	// supervisor binds one writer per run and does not log events across
	// run boundaries.
	runID string

	// backend is the backend identifier copied into every event. Same
	// reasoning as runID: pinned per writer, not per call.
	backend string

	// agent is the agent identifier copied into every event. Same
	// reasoning as runID/backend.
	agent string

	// now produces the timestamp stamped on each event. It is a function
	// (rather than a clock interface) so tests can inject a deterministic
	// sequence of times without a separate type; production callers pass
	// time.Now.
	now func() time.Time

	// closed guards Close from racing with itself and prevents Write
	// after Close from panicking on a stale file handle.
	closed bool
}

// LifecycleWriterOptions bundles the per-run metadata a LifecycleWriter
// needs at construction. RunID, Backend, and Agent are required: the
// plan's event format makes all three mandatory and a writer that could
// emit empty values would silently corrupt the run record.
//
// Now is optional; the writer falls back to time.Now when it is nil.
// The plan does not allow event records without a timestamp, so the
// fallback is the only sane default rather than rejecting a nil clock.
type LifecycleWriterOptions struct {
	RunID   string
	Backend string
	Agent   string
	Now     func() time.Time
}

// OpenLifecycleWriter opens (or creates and appends to) the lifecycle.jsonl
// file for the run directory at runDir, wires it to the supplied options,
// and returns a LifecycleWriter ready to accept events.
//
// runDir is the absolute path to the run directory (the same value
// RunDirectory.Path carries). The file is opened with O_APPEND so the
// writer cooperates correctly with the empty placeholder
// CreateRunDirectory left in place, and so a reopen of an existing run
// (future replay tooling) adds to the trail rather than truncating it.
//
// Returns an error when the file cannot be opened or when any required
// option is empty. On error no file handle is leaked.
func OpenLifecycleWriter(runDir string, opts LifecycleWriterOptions) (*LifecycleWriter, error) {
	if runDir == "" {
		return nil, errors.New("run: OpenLifecycleWriter requires runDir")
	}
	if opts.RunID == "" {
		return nil, errors.New("run: OpenLifecycleWriter requires RunID")
	}
	if opts.Backend == "" {
		return nil, errors.New("run: OpenLifecycleWriter requires Backend")
	}
	if opts.Agent == "" {
		return nil, errors.New("run: OpenLifecycleWriter requires Agent")
	}

	path := filepath.Join(runDir, lifecycleFileName)
	// O_APPEND so concurrent writes (and the once-placeholder file
	// CreateRunDirectory left behind) compose cleanly; O_CREATE so a caller
	// that constructed the writer against a freshly-rmd directory still
	// gets a working handle rather than a confusing ENOENT.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, runFileMode)
	if err != nil {
		return nil, fmt.Errorf("run: open lifecycle log %s: %w", path, err)
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}

	return &LifecycleWriter{
		file:    f,
		runID:   opts.RunID,
		backend: opts.Backend,
		agent:   opts.Agent,
		now:     clock,
	}, nil
}

// Write appends a single state-transition lifecycle event for the given
// state to the underlying lifecycle.jsonl file. The event's RunID,
// Backend, and Agent are filled in from the writer's stored metadata;
// the Timestamp is stamped from the writer's clock at call time. Verb
// and Metadata are left zero so the on-disk shape matches Batch 0.0's
// byte-for-byte plan example for state records. The encoded line is a
// single JSON object followed by exactly one newline byte.
//
// The plan requires that no buffered event be lost on crash, so Write
// fsyncs the file after a successful append. The mutex makes the
// encode+sync pair atomic with respect to other callers: two goroutines
// transitioning concurrently produce two consecutive whole lines, never
// an interleaved one.
//
// Write returns an error when the writer has already been closed, when
// the state is empty (a zero-State record would carry neither a state
// nor a verb after Batch 0.1's omitempty change and would be ambiguous
// to readers), when JSON encoding fails, when the underlying append
// fails, or when the fsync fails.
func (w *LifecycleWriter) Write(state State) error {
	if state == "" {
		return errors.New("run: lifecycle write requires non-empty state")
	}

	evt := LifecycleEvent{
		RunID:     w.runID,
		State:     state,
		Backend:   w.backend,
		Agent:     w.agent,
		Timestamp: "", // filled in under lock by writeEvent
	}
	return w.writeEvent(evt)
}

// WriteVerb appends a single non-state-transition lifecycle event for
// the given verb to lifecycle.jsonl. Used by every supplemental
// subsystem the supervisor stands up (ProviderProxy, MCP Gateway,
// Network Observer, GitHub Broker, Control Socket, MCP-config
// neutralization, transcript parser, shim install, helper RPC
// audit, secrets-permission audit, network-policy degrade). Verbs
// are pinned to the LifecycleVerb constants in lifecycle_verbs.go;
// callers passing an empty verb are rejected at write time because
// a record with neither State nor Verb cannot be classified.
//
// metadata may be nil for verbs that carry no per-event payload. When
// non-nil, the writer takes a shallow defensive copy so subsequent
// caller mutations do not affect the recorded event. The key set is
// the per-verb table documented in lifecycle_verbs.go; the writer does
// not enforce it (that would couple the writer to every emitter's
// schema) — each emitter owns its completeness.
//
// The same fsync-per-event discipline as Write applies: a host crash
// between WriteVerb and the next event does not lose this verb.
func (w *LifecycleWriter) WriteVerb(verb LifecycleVerb, metadata map[string]string) error {
	if verb == "" {
		return errors.New("run: lifecycle WriteVerb requires non-empty verb")
	}

	// Defensive shallow copy so a caller that mutates its metadata map
	// after WriteVerb returns (or shares the same map across calls and
	// mutates between them) cannot retroactively change a recorded
	// event. The cost is negligible — Metadata maps in the plan's per-
	// verb tables top out at a handful of keys.
	var md map[string]string
	if len(metadata) > 0 {
		md = make(map[string]string, len(metadata))
		for k, v := range metadata {
			md[k] = v
		}
	}

	evt := LifecycleEvent{
		RunID:     w.runID,
		Verb:      verb,
		Backend:   w.backend,
		Agent:     w.agent,
		Timestamp: "", // filled in under lock by writeEvent
		Metadata:  md,
	}
	return w.writeEvent(evt)
}

// writeEvent is the shared append+fsync path used by Write and
// WriteVerb. Pulling the lock/marshal/sync sequence into one method
// keeps the two public entry points trivially equivalent in their
// durability and concurrency contract, and means a future third entry
// point cannot drift on fsync discipline.
func (w *LifecycleWriter) writeEvent(evt LifecycleEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("run: lifecycle writer is closed")
	}

	// Stamp the timestamp under the lock so the on-disk order of events
	// matches the timestamp order, even under heavy concurrent writes.
	evt.Timestamp = w.now().Format(time.RFC3339)

	// Marshal then a single Write keeps the JSON object + newline as one
	// syscall, which matters for the O_APPEND atomicity guarantee on
	// POSIX (writes up to PIPE_BUF are atomic; a typical event is well
	// under that). A streaming json.Encoder would emit its own newline
	// but would also stream in chunks under the hood.
	line, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("run: marshal lifecycle event: %w", err)
	}
	line = append(line, '\n')

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("run: append lifecycle event: %w", err)
	}
	// Sync after every event so a crash between events does not erase the
	// lifecycle trail. The plan's "no buffering data loss on crash" rule is
	// the explicit requirement here.
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("run: sync lifecycle log: %w", err)
	}
	return nil
}

// Close closes the underlying lifecycle.jsonl file. It is safe to call
// more than once; the second call is a no-op. Once Close returns, further
// Write calls fail with a clear error so a misbehaving caller cannot
// silently lose events against a closed handle.
//
// The supervisor calls Close from its post-run drain (step 10) after the
// final terminal state has been recorded; closing earlier would drop the
// terminal record.
func (w *LifecycleWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("run: close lifecycle log: %w", err)
	}
	return nil
}
