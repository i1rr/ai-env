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

// networkEventsFileName is the basename of the per-run network event log.
// It lives at the root of the run directory next to lifecycle.jsonl so a
// reviewer reading a run on disk sees the lifecycle trail and the network
// event stream side by side. The constant mirrors lifecycleFileName;
// keeping it here rather than redeclaring it in run.go means the network
// events writer is the single owner of the filename even though run.go
// materialized the placeholder.
const networkEventsFileName = "network-events.jsonl"

// Network event verbs recorded in network-events.jsonl. Pinned as
// constants so the supervisor, the backend adapters, and future
// `ai-env report` consumers compare against the canonical strings rather
// than retyping the literals. The plan's master section 24 calls these
// "events" and the plan 05 step 6 task names the file but does not pin a
// schema; the verbs below were chosen to:
//
//   - Cover the supervisor's own policy-install lifecycle
//     (attempt / applied / failed), so the on-disk record always shows
//     the supervisor's intent even when the backend cannot emit events.
//   - Match the master plan's "Always blocked by default" language
//     (NetworkEventOutboundBlocked / NetworkEventOutboundAllowed) so
//     backend adapters that surface per-destination decisions land on a
//     verb consumers already understand.
//   - Stay future-proof: a backend that emits a richer event (e.g. a TLS
//     SNI mismatch) can add a new verb without breaking decoders, because
//     consumers switch on the string.
const (
	// NetworkEventPolicyApplyAttempt is recorded just before the
	// NetworkPolicyAdapter.Apply call. It captures the policy snapshot
	// the supervisor is about to install so an operator inspecting a
	// failed run sees the intended policy even when Apply errored before
	// emitting its own event. Always followed by either a
	// NetworkEventPolicyApplied or a NetworkEventPolicyApplyFailed in the
	// same file (unless the supervisor crashes between the two writes).
	NetworkEventPolicyApplyAttempt = "policy_apply_attempt"

	// NetworkEventPolicyApplied is recorded immediately after a
	// successful NetworkPolicyAdapter.Apply call. It pairs with
	// NetworkEventPolicyApplyAttempt and is the durable record that the
	// adapter accepted the policy.
	NetworkEventPolicyApplied = "policy_applied"

	// NetworkEventPolicyApplyFailed is recorded when
	// NetworkPolicyAdapter.Apply returns a non-nil error. The supervisor
	// aborts the run with StateFailedPolicy after writing this event so
	// the on-disk record carries the policy-side error message even when
	// the supervisor's own stderr is lost.
	NetworkEventPolicyApplyFailed = "policy_apply_failed"

	// NetworkEventOutboundBlocked is the verb a backend adapter records
	// (via the supervisor's WriteNetworkEvent passthrough, once that
	// wiring lands) when it observes and denies an outbound destination.
	// Defined here so the constant is shared even though no current code
	// path emits it; future plan-05 batches that route backend events
	// through the writer use this token.
	NetworkEventOutboundBlocked = "outbound_blocked"

	// NetworkEventOutboundAllowed is the symmetric verb for an outbound
	// destination the backend allowed. Same intent as
	// NetworkEventOutboundBlocked: the constant is defined here so every
	// future emitter shares the spelling.
	NetworkEventOutboundAllowed = "outbound_allowed"
)

// NetworkEvent is one record written to network-events.jsonl. The shape
// is the supervisor-facing canonical event the writer marshals to JSONL.
// Fields are encoded in declaration order so the on-disk file is
// byte-stable across runs that emit the same event sequence.
//
// The struct intentionally mixes two record families:
//
//   - Supervisor-emitted policy lifecycle events (Event ==
//     NetworkEventPolicyApplyAttempt / Applied / Failed). These carry
//     the policy snapshot fields (Default, AllowDomains, BlockedCIDRs,
//     BlockedHosts) and, for the Failed case, an Error string.
//   - Backend-emitted per-destination decisions (Event ==
//     NetworkEventOutboundBlocked / Allowed). These carry Destination
//     and Decision; the policy snapshot fields are omitted via
//     omitempty so the on-disk line stays small.
//
// Keeping one struct (with omitempty everywhere optional) means
// consumers parse one JSON shape and switch on Event to pick the
// interesting fields, rather than maintaining a discriminated-union of
// half a dozen tiny shapes.
type NetworkEvent struct {
	// RunID is the run this event belongs to. Duplicated into every
	// record so a future aggregator can concatenate network-events.jsonl
	// files from many runs without losing attribution. Mirrors
	// LifecycleEvent.RunID.
	RunID string `json:"run_id"`

	// Timestamp is the moment the event was emitted, formatted as
	// RFC3339 with a numeric timezone offset. The writer fills this in
	// at write time using its clock; callers do not set it themselves.
	Timestamp string `json:"timestamp"`

	// Event is the verb identifying what happened. One of the
	// NetworkEvent* constants above; consumers switch on this field to
	// pick the interesting payload fields. Required.
	Event string `json:"event"`

	// Backend is the backend identifier (e.g. "docker-sbx") the event
	// originated from. Pinned per writer (mirrors LifecycleEvent.Backend)
	// so a reader who concatenates events across backends sees the
	// origin.
	Backend string `json:"backend"`

	// EnvID is the backend env identifier the event refers to. Empty for
	// events that pre-date a created env; populated for policy-apply
	// events (the adapter's envID) and for backend-emitted per-
	// destination events.
	EnvID string `json:"env_id,omitempty"`

	// Default is the policy's default outbound stance ("deny" / "allow").
	// Populated on policy-lifecycle events; omitted on per-destination
	// events.
	Default string `json:"default,omitempty"`

	// AllowDomains is the allow-list the policy was installed with.
	// Populated on policy-lifecycle events; omitted on per-destination
	// events. The supervisor copies the slice rather than aliasing it so
	// a later mutation of the policy does not leak into past records.
	AllowDomains []string `json:"allow_domains,omitempty"`

	// BlockedCIDRs is the expanded CIDR block list the policy installed.
	// Populated on policy-lifecycle events from
	// network.NetworkPolicy.BlockedCIDRs.
	BlockedCIDRs []string `json:"blocked_cidrs,omitempty"`

	// BlockedHosts is the expanded hostname block list the policy
	// installed. Populated on policy-lifecycle events from
	// network.NetworkPolicy.BlockedHosts.
	BlockedHosts []string `json:"blocked_hosts,omitempty"`

	// Destination is the outbound destination the backend allowed or
	// denied. Populated only on per-destination events; the value's
	// shape is whatever the backend reports (a domain, a "host:port",
	// or a raw CIDR).
	Destination string `json:"destination,omitempty"`

	// Decision is the verdict the backend reached for Destination
	// ("allow" / "deny"). Populated only on per-destination events.
	Decision string `json:"decision,omitempty"`

	// Error is the error string recorded on NetworkEventPolicyApplyFailed
	// (and any future failure verb). Empty on success events so the
	// on-disk line does not carry a misleading empty-string Error.
	Error string `json:"error,omitempty"`

	// Note is an optional short free-form annotation. Reserved for
	// adapter-specific context (e.g. "fallback to --network none") that
	// does not fit into the structured fields above. Omitted when empty
	// so the common case keeps the line compact.
	Note string `json:"note,omitempty"`
}

// NetworkEventsWriter appends NetworkEvent records to
// network-events.jsonl.
//
// The plan calls for append-only newline-delimited JSON, one record per
// network event, flushed after every write so a crash does not lose the
// policy-apply trail. The writer is safe for concurrent use: the
// supervisor's main loop, the policy-apply helper, and any future
// backend-event forwarder may all call Write from different goroutines,
// and the resulting on-disk file must contain one well-formed JSON
// object per line with no interleaving.
//
// Construction goes through OpenNetworkEventsWriter so the file handle,
// the per-run metadata (run ID, backend), and the clock are wired in
// once. The handle stays open for the lifetime of the run; Close is the
// only orderly shutdown path. The supervisor closes the writer as part
// of the post-run drain alongside the lifecycle writer.
//
// Design notes:
//
//   - We open the underlying file with O_APPEND so a future cross-
//     process append (the shell shim, an out-of-process backend event
//     forwarder) lands as whole records per write rather than
//     interleaving bytes mid-line. Mirrors LifecycleWriter.
//   - We Sync after every successful write rather than relying on the
//     OS buffer cache. Network events are infrequent (policy install,
//     occasional per-destination decisions) so the fsync cost is
//     negligible, and a host crash between event time and fsync time
//     would otherwise erase the trail an operator depends on for
//     post-mortem audit.
//   - The mutex serializes write+sync so two goroutines cannot
//     interleave bytes nor race on the file offset.
//
// The shape mirrors LifecycleWriter on purpose: a future refactor that
// unifies the per-run JSONL writers (lifecycle, network, shell, fs,
// policy decisions) can replace both with one generic implementation
// without touching call sites.
type NetworkEventsWriter struct {
	// mu serializes writes so concurrent callers cannot interleave
	// bytes inside a single JSON line, even though O_APPEND already
	// protects the file offset on POSIX. The encode + sync sequence is
	// a logical write, not just a byte-level one, so the mutex covers
	// both halves.
	mu sync.Mutex

	// file is the open network-events.jsonl handle. It is kept open for
	// the lifetime of the writer so we are not paying open/close for
	// every event; closed exactly once by Close.
	file *os.File

	// runID is the run identifier copied into every event's RunID
	// field. Stored on the writer rather than passed per-call because
	// the supervisor binds one writer per run and does not log events
	// across run boundaries.
	runID string

	// backend is the backend identifier copied into every event when
	// the caller did not override it. Same reasoning as runID: pinned
	// per writer, not per call.
	backend string

	// now produces the timestamp stamped on each event. A function
	// (rather than a clock interface) so tests can inject a
	// deterministic sequence of times without a separate type;
	// production callers pass time.Now.
	now func() time.Time

	// closed guards Close from racing with itself and prevents Write
	// after Close from panicking on a stale file handle.
	closed bool
}

// NetworkEventsWriterOptions bundles the per-run metadata a
// NetworkEventsWriter needs at construction. RunID and Backend are
// required: every record must carry both fields so a reader who
// concatenates events across runs sees attribution. Now is optional and
// falls back to time.Now when nil.
type NetworkEventsWriterOptions struct {
	// RunID is the run identifier this writer's events belong to.
	// Required.
	RunID string

	// Backend is the backend identifier (e.g. "docker-sbx") this
	// writer's events originate from. Required so a reader does not
	// have to cross-reference run.json to learn the origin.
	Backend string

	// Now is the clock the writer uses to stamp Timestamp on each
	// event. Nil falls back to time.Now. Tests inject a fixed-step
	// clock so the on-disk timestamps are deterministic.
	Now func() time.Time
}

// OpenNetworkEventsWriter opens (or creates and appends to) the
// network-events.jsonl file for the run directory at runDir, wires it
// to the supplied options, and returns a NetworkEventsWriter ready to
// accept events.
//
// runDir is the absolute path to the run directory (the same value
// RunDirectory.Path carries). The file is opened with O_APPEND so the
// writer cooperates correctly with the empty placeholder
// CreateRunDirectory left in place, and so a reopen of an existing run
// (future replay tooling) adds to the trail rather than truncating it.
//
// Returns an error when the file cannot be opened or when any required
// option is empty. On error no file handle is leaked.
func OpenNetworkEventsWriter(runDir string, opts NetworkEventsWriterOptions) (*NetworkEventsWriter, error) {
	if runDir == "" {
		return nil, errors.New("run: OpenNetworkEventsWriter requires runDir")
	}
	if opts.RunID == "" {
		return nil, errors.New("run: OpenNetworkEventsWriter requires RunID")
	}
	if opts.Backend == "" {
		return nil, errors.New("run: OpenNetworkEventsWriter requires Backend")
	}

	path := filepath.Join(runDir, networkEventsFileName)
	// O_APPEND so concurrent writes (and the once-placeholder file
	// CreateRunDirectory left behind) compose cleanly; O_CREATE so a
	// caller that constructed the writer against a freshly-rmd
	// directory still gets a working handle rather than a confusing
	// ENOENT.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, runFileMode)
	if err != nil {
		return nil, fmt.Errorf("run: open network events log %s: %w", path, err)
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}

	return &NetworkEventsWriter{
		file:    f,
		runID:   opts.RunID,
		backend: opts.Backend,
		now:     clock,
	}, nil
}

// Write appends a single network event to the underlying
// network-events.jsonl file. The event's RunID and Timestamp are filled
// in from the writer's stored metadata; Backend defaults to the
// writer's backend when evt.Backend is empty so the caller does not
// have to repeat it on every call (and so a backend-emitted forwarded
// event can override the default when it carries its own origin).
//
// The encoded line is a single JSON object followed by exactly one
// newline byte. The plan requires that no buffered event be lost on
// crash, so Write fsyncs the file after a successful append. The mutex
// makes the encode + sync pair atomic with respect to other callers:
// two goroutines emitting concurrently produce two consecutive whole
// lines, never an interleaved one.
//
// Write returns an error when the writer has already been closed, when
// JSON encoding fails (which would only happen on an unexpected
// reflect path; the NetworkEvent struct has no marshal hooks), when
// the underlying append fails, or when the fsync fails.
//
// Write rejects an empty Event verb so a misconfigured caller fails
// loudly rather than silently producing an unidentifiable record.
func (w *NetworkEventsWriter) Write(evt NetworkEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("run: network events writer is closed")
	}
	if evt.Event == "" {
		return errors.New("run: network event requires Event verb")
	}

	// Fill in the writer-pinned fields. We always overwrite RunID and
	// Timestamp so a caller cannot accidentally smuggle a different run's
	// ID through the writer. Backend is filled only when the caller did
	// not set it: a forwarded backend event may already carry its own
	// origin string, which we preserve verbatim.
	evt.RunID = w.runID
	if evt.Backend == "" {
		evt.Backend = w.backend
	}
	evt.Timestamp = w.now().Format(time.RFC3339)

	// Marshal then a single Write keeps the JSON object + newline as
	// one syscall, matching the O_APPEND atomicity guarantee on POSIX
	// (writes up to PIPE_BUF are atomic; a typical event is well under
	// that). A streaming json.Encoder would emit its own newline but
	// would also stream in chunks under the hood.
	line, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("run: marshal network event: %w", err)
	}
	line = append(line, '\n')

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("run: append network event: %w", err)
	}
	// Sync after every event so a crash between events does not erase
	// the network trail. The plan's "no buffering data loss on crash"
	// rule is the explicit requirement here, mirroring
	// LifecycleWriter.Write.
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("run: sync network events log: %w", err)
	}
	return nil
}

// Close closes the underlying network-events.jsonl file. It is safe to
// call more than once; the second call is a no-op. Once Close returns,
// further Write calls fail with a clear error so a misbehaving caller
// cannot silently lose events against a closed handle.
//
// The supervisor calls Close from its post-run drain after the final
// terminal state has been recorded; closing earlier would drop any
// late-arriving backend-emitted events (e.g. a forwarded outbound
// decision the adapter surfaced during teardown).
func (w *NetworkEventsWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("run: close network events log: %w", err)
	}
	return nil
}
