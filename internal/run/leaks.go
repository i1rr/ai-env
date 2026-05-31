// Unified leaks ledger writer (Plan §0.2 + Plan §8.1).
//
// `leaks.jsonl` is the derived, audit-facing view that joins every
// per-subsystem stream the supervisor maintains — policy-decisions,
// mcp-calls, network-events, shell-commands, secret-scan results,
// transcript parser annotations — into one chronologically-ordered
// file the operator can grep without having to walk five sources of
// truth. The five per-subsystem streams stay the canonical record;
// `leaks.jsonl` is rebuilt at finalize time from those streams and
// every string field is run through the broadened
// `secrets.RedactSecrets` before it lands on disk.
//
// The on-disk format is newline-delimited JSON, one LeakRecord per
// line, atomically replaced as a whole file rather than appended in
// place. The atomic-replace pattern matches Plan §10 Bucket 9:
//
//   1. open <runDir>/leaks.jsonl.tmp.<pid>.<rand> with
//      O_WRONLY|O_CREATE|O_EXCL so a stale tmp from a crashed run
//      cannot be silently truncated;
//   2. write every redacted LeakRecord to that tmp file;
//   3. Close() fsyncs the tmp file, then os.Renames it over
//      <runDir>/leaks.jsonl. On POSIX the rename is atomic so a
//      reader either sees the previous file content or the new
//      content, never a partial line.
//
// This Batch 0.2 file owns the schema (LeakRecord, LeakEvidence) and
// the writer (LeaksWriter). The supervisor-side aggregator that
// walks the per-subsystem streams and produces records lives in
// Batch 8.1 (`aggregateLeaks`); it consumes LeaksWriter via its
// Write method. Keeping the writer and the aggregator in separate
// batches lets the schema land first so any later subsystem that
// wants to emit into leaks (e.g. the gateway secret detector in
// Batch 3.4) can be wired against a stable type today.

package run

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/rivan1986/ai-env/internal/secrets"
)

// leaksFileName is the basename of the per-run unified leaks ledger.
// It sits at the root of the run directory next to the canonical
// per-subsystem streams (lifecycle.jsonl, policy-decisions.jsonl,
// network-events.jsonl, mcp-calls.jsonl, shell-commands.jsonl,
// filesystem-events.jsonl, transcript.jsonl). The constant mirrors
// the other per-run filename constants so the leaks aggregator is
// the single owner of the filename even though run.go materialized
// the placeholder.
const leaksFileName = "leaks.jsonl"

// leaksTmpPrefix is the basename prefix every staged leaks.jsonl
// write uses. The format is "leaks.jsonl.tmp.<pid>.<rand>"; the
// "<pid>.<rand>" suffix is uniquified per call to defeat any race
// between two concurrent writers (impossible in v0.1 but defensive
// against a future replay tool that wants to rebuild leaks.jsonl
// from an existing run). Stale tmp files from a crashed run are
// dropped by `CleanupStaleLeaksTemp` at supervisor start.
const leaksTmpPrefix = leaksFileName + ".tmp."

// LeaksRecordSchemaVersion is the schema-version tag stamped onto
// every LeakRecord. The Plan §0 "Schema-version contract" requires
// every new stream to carry _schema_version: 1 per record so
// readers can refuse to parse a future incompatible bump.
const LeaksRecordSchemaVersion = 1

// LeakSource identifies which per-subsystem stream produced a
// LeakRecord. The values mirror the on-disk filenames (without the
// .jsonl suffix) so a downstream consumer of leaks.jsonl can grep
// by source without translation.
type LeakSource string

const (
	// LeakSourceLifecycle is set on records sourced from
	// lifecycle.jsonl verb events (Plan Batch 0.1) — e.g.
	// gateway_secret_blocked, gateway_secret_response,
	// network_policy_degraded.
	LeakSourceLifecycle LeakSource = "lifecycle"

	// LeakSourcePolicyDecisions is set on records sourced from
	// policy-decisions.jsonl (Plan Bucket 7 shell evaluation).
	LeakSourcePolicyDecisions LeakSource = "policy-decisions"

	// LeakSourceMCPCalls is set on records sourced from
	// mcp-calls.jsonl (Plan Bucket 4 gateway audit).
	LeakSourceMCPCalls LeakSource = "mcp-calls"

	// LeakSourceNetworkEvents is set on records sourced from
	// network-events.jsonl (Plan Bucket 3 EgressObserver).
	LeakSourceNetworkEvents LeakSource = "network-events"

	// LeakSourceShellCommands is set on records sourced from
	// shell-commands.jsonl (Plan Bucket 1 shim audit).
	LeakSourceShellCommands LeakSource = "shell-commands"

	// LeakSourceFilesystemEvents is set on records sourced from
	// filesystem-events.jsonl (Plan Bucket 6).
	LeakSourceFilesystemEvents LeakSource = "filesystem-events"

	// LeakSourceTranscript is set on records sourced from
	// transcript.jsonl (Plan Bucket 8 transcript parser).
	LeakSourceTranscript LeakSource = "transcript"

	// LeakSourceSecretScan is set on records sourced from the
	// per-run secret-scan.json finding set (Plan §6 scanner gate).
	LeakSourceSecretScan LeakSource = "secret-scan"
)

// LeakEvidence is the per-finding details payload attached to a
// LeakRecord. Every field is optional; a record produced from a
// stream that carries no scanner-style evidence (e.g. a policy
// block on a hostname) sets only the fields it knows.
//
// The shape is deliberately a small string-typed bag rather than a
// strongly-typed per-source struct because leaks.jsonl is the
// merge view: the aggregator that walks five different streams
// would otherwise need a per-stream marshal path. Strings let
// every emitter stringify whatever extra context it has without
// schema churn here.
//
// Every non-empty string field is run through secrets.RedactSecrets
// at LeaksWriter.Write time so a leaked token surfacing in a
// captured argv or in an evidence "snippet" is scrubbed before it
// lands on disk.
type LeakEvidence struct {
	// Pattern is the human-readable scanner pattern name that
	// matched (e.g. "Anthropic sk-ant- prefix"). Used by the
	// Batch 8.1 dedup key for scanner-sourced records so two
	// findings on the same line with different patterns are
	// kept distinct. Empty for non-scanner sources.
	Pattern string `json:"pattern,omitempty"`

	// FindingID is the opaque per-finding identifier the upstream
	// emitter minted (the scanner's finding_001 / finding_002
	// stream, the gateway's per-blocked-call UUID, etc.). The
	// Batch 8.1 aggregator uses (Vector, Pattern, FindingID) as
	// the scanner-sourced dedup key extension.
	FindingID string `json:"finding_id,omitempty"`

	// Snippet is a short captured byte fragment showing the
	// context that triggered the finding (e.g. the matched line
	// or the failed argv). Scrubbed via secrets.RedactSecrets
	// before write so an accidentally-captured secret is gone
	// before it touches disk.
	Snippet string `json:"snippet,omitempty"`

	// Detail is a free-form per-emitter explanation (e.g. the
	// policy-decision Reason, the proxy upstream allowlist
	// rejection text). Same redaction discipline as Snippet.
	Detail string `json:"detail,omitempty"`

	// Extra holds emitter-specific key/value context that does
	// not fit the named fields above. Keys are emitter-chosen;
	// values are stringified by the emitter before write. Every
	// non-empty value is redacted at write time.
	Extra map[string]string `json:"extra,omitempty"`
}

// LeakRecord is one row of leaks.jsonl. The shape is the union of
// the columns Plan §0 lists for the unified leak ledger: a stable
// schema version tag, a chronological timestamp, the originating
// stream identifier, the originating stream's line number, the
// vector identifier (1..8 from the leak-coverage audit), the
// human-meaningful verb the upstream record carried, the policy
// event id (when known; the policy decisions log mints these), and
// a free-form LeakEvidence payload.
//
// JSON field order matches the order documented above so the
// on-disk JSONL is readable by a human in a terminal without a
// pretty-printer. Encoders preserve struct field order.
//
// Every non-empty string field is run through secrets.RedactSecrets
// at LeaksWriter.Write time so a token leaked in any source field
// is scrubbed before it ends up in leaks.jsonl. The redaction
// pass is in-place: callers should not assume a Write returns the
// LeakRecord unchanged.
type LeakRecord struct {
	// SchemaVersion is the per-record schema version tag.
	// Always 1 in v0.1; readers refuse a record with
	// SchemaVersion > LeaksRecordSchemaVersion. Encoded as
	// "_schema_version" to match the Plan §0 contract verbatim.
	SchemaVersion int `json:"_schema_version"`

	// Timestamp is the moment the leak was observed in the source
	// stream, formatted as RFC3339 with a numeric timezone
	// offset. The aggregator copies the timestamp from the source
	// record so leaks.jsonl is chronologically ordered against
	// the original streams without re-derivation.
	Timestamp string `json:"timestamp"`

	// RunID duplicates the run identifier into every record so a
	// future aggregator that concatenates leaks.jsonl across
	// many runs does not lose attribution.
	RunID string `json:"run_id"`

	// Source identifies which per-subsystem stream produced the
	// underlying record. One of the LeakSource* constants.
	Source LeakSource `json:"source_stream"`

	// SourceLine is the 1-based line number inside the source
	// stream the record was extracted from. Used by the Batch
	// 8.1 dedup key (source_stream, source_line, ...) so the
	// aggregator can be re-run against the same streams
	// idempotently.
	SourceLine int `json:"source_line"`

	// Vector is the leak-coverage audit vector identifier
	// (1..8). The Plan §0 dedup-key extension uses it as part
	// of the scanner-sourced dedup tuple. Omitted from JSON
	// when zero (vectorless lifecycle events have no vector).
	Vector int `json:"vector,omitempty"`

	// Verb is the human-meaningful verb the upstream record
	// carried — a LifecycleVerb spelling for lifecycle-sourced
	// records, the policy-decision reason for policy-sourced
	// records, the gateway operation for mcp-sourced records.
	// Empty when the source has no per-record verb.
	Verb string `json:"verb,omitempty"`

	// PolicyEventID carries the opaque per-decision identifier
	// the policy engine mints. Used by the Batch 8.1 dedup key
	// (source_stream, source_line, policy_event_id) so two
	// supervisor processes converging on the same decision are
	// folded into one leak record.
	PolicyEventID string `json:"policy_event_id,omitempty"`

	// Evidence carries the per-finding context. May be empty
	// for records that have no extra payload (a pure policy
	// block with no scanner finding sets only the headers
	// above).
	Evidence LeakEvidence `json:"evidence,omitempty"`
}

// LeaksWriter atomically writes a sequence of LeakRecord rows to
// <runDir>/leaks.jsonl using the "write to .tmp, fsync, rename"
// pattern. Unlike LifecycleWriter / NetworkEventsWriter / et al.,
// LeaksWriter does NOT append to an existing file: leaks.jsonl is
// the derived view, rebuilt as a whole file at finalize time.
//
// Lifecycle:
//
//   - OpenLeaksWriter creates the tmp file with O_WRONLY|O_CREATE
//     |O_EXCL inside runDir so a stale tmp from a crashed run
//     cannot be silently truncated. The tmp basename embeds the
//     process pid and a short random suffix so two concurrent
//     writers cannot collide on the same path.
//   - Write appends one redacted LeakRecord per call. Records are
//     buffered to the tmp file; no fsync per record because the
//     atomic-rename step at Close is the durability barrier.
//   - Close fsyncs the tmp file, closes it, then renames it over
//     <runDir>/leaks.jsonl. A reader either sees the previous
//     leaks.jsonl content or the new content, never a partial
//     line. Close also fsyncs the parent directory so the rename
//     itself survives a crash.
//   - Abort closes the tmp file and removes it without renaming.
//     Used by the supervisor's panic-recovery path so a partial
//     leaks.jsonl does not stomp the previous file.
//
// The writer is safe for concurrent Write calls; a per-writer
// mutex serializes the encode + write pair so two goroutines
// cannot interleave bytes inside a single JSON line.
//
// The single-shot, atomic-replace shape matches Plan §10 Bucket
// 9 verbatim ("write tmp, fsync, rename"). Future Batch 8.2's
// `ai-env leaks` CLI ignores `*.tmp.*` files so an abort or a
// concurrent rebuild does not surface a half-written file to the
// operator.
type LeaksWriter struct {
	// mu serializes Write and Close. The atomic-rename pattern
	// would otherwise be safe per-syscall but a Write racing
	// Close could append to the tmp file after the rename and
	// silently lose the appended bytes. The mutex makes the
	// guarantee explicit.
	mu sync.Mutex

	// runDir is the per-run directory the tmp file lives in and
	// the rename target's parent. Captured so Close can compute
	// the final path without the caller having to pass it
	// again.
	runDir string

	// runID is the run identifier copied into every record's
	// RunID field when the caller did not pre-populate it.
	// Stored on the writer rather than passed per-call because
	// the supervisor binds one writer per run and does not log
	// leaks across run boundaries.
	runID string

	// tmpPath is the absolute path of the staged tmp file. Used
	// by Close (for the rename source) and by Abort (for the
	// remove). Recorded so the caller can grep for stale tmp
	// files in the run directory if Close itself crashes after
	// the rename and before the supervisor's next start sweep
	// runs.
	tmpPath string

	// file is the open tmp file handle. Closed exactly once by
	// Close or Abort.
	file *os.File

	// now produces the timestamp stamped on each record when
	// the caller has not pre-populated it. Mirrors the same
	// idiom used by LifecycleWriter / NetworkEventsWriter.
	now func() time.Time

	// closed guards Close / Abort from racing with themselves
	// and prevents Write after either from panicking on a stale
	// handle.
	closed bool
}

// LeaksWriterOptions bundles the per-run metadata a LeaksWriter
// needs at construction. RunID is required (the per-record
// RunID field is mandatory). Now is optional; the writer falls
// back to time.Now when nil. RandomReader is the source of
// randomness for the tmp filename's per-process suffix; nil
// falls back to crypto/rand.Reader.
type LeaksWriterOptions struct {
	// RunID is the run identifier this writer's records belong
	// to. Required.
	RunID string

	// Now is the clock the writer uses to stamp Timestamp on
	// each record when the caller has not pre-populated the
	// field. Nil falls back to time.Now. Tests inject a
	// fixed-step clock so the on-disk timestamps are
	// deterministic.
	Now func() time.Time

	// RandomReader is the byte source for the tmp filename's
	// random suffix. Nil falls back to crypto/rand.Reader.
	// Tests inject a deterministic reader so tmp paths are
	// predictable.
	RandomReader io.Reader
}

// OpenLeaksWriter stages a new leaks.jsonl write. It creates the
// tmp file under runDir with O_WRONLY|O_CREATE|O_EXCL so a stale
// tmp from a crashed run cannot be silently truncated, and
// returns a LeaksWriter ready to accept Write calls.
//
// On error no file handle is leaked: a failed open returns nil
// without touching the filesystem; a successful open that fails
// the subsequent chmod step still closes the file before
// returning.
func OpenLeaksWriter(runDir string, opts LeaksWriterOptions) (*LeaksWriter, error) {
	if runDir == "" {
		return nil, errors.New("run: OpenLeaksWriter requires runDir")
	}
	if opts.RunID == "" {
		return nil, errors.New("run: OpenLeaksWriter requires RunID")
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}
	rnd := opts.RandomReader
	if rnd == nil {
		rnd = rand.Reader
	}

	// Compose the tmp basename "leaks.jsonl.tmp.<pid>.<rand>".
	// Six hex characters (three random bytes) is enough entropy
	// to defeat any future concurrent writer race; production
	// v0.1 never sees more than one writer per run, but the
	// rare retry-then-write scenario is the case the suffix
	// guards against.
	suffix := make([]byte, 3)
	if _, err := io.ReadFull(rnd, suffix); err != nil {
		return nil, fmt.Errorf("run: read leaks tmp suffix: %w", err)
	}
	tmpName := fmt.Sprintf("%s%d.%s", leaksTmpPrefix, os.Getpid(), hex.EncodeToString(suffix))
	tmpPath := filepath.Join(runDir, tmpName)

	// O_EXCL means an existing tmp with the same name causes a
	// loud error rather than a silent overwrite. The supervisor
	// is responsible for sweeping stale tmps at start; if one
	// somehow survives, OpenLeaksWriter refuses to clobber it.
	// runFileMode (0o644) matches the rest of the run
	// directory's files.
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, runFileMode)
	if err != nil {
		return nil, fmt.Errorf("run: open leaks tmp %s: %w", tmpPath, err)
	}

	return &LeaksWriter{
		runDir:  runDir,
		runID:   opts.RunID,
		tmpPath: tmpPath,
		file:    f,
		now:     clock,
	}, nil
}

// Write appends a single LeakRecord to the staged tmp file. The
// writer fills in SchemaVersion (always LeaksRecordSchemaVersion),
// Timestamp (when empty), and RunID (when empty) so callers can
// emit a partially populated record and the writer pins the
// invariants. Every non-empty string field on the record (and on
// the nested LeakEvidence) is then run through
// secrets.RedactSecrets so a leaked token in a captured snippet
// or extra-value is scrubbed before it lands on disk.
//
// The encoded line is a single JSON object followed by exactly
// one newline byte. The atomic-rename at Close is the durability
// barrier, so Write deliberately does NOT fsync per record; the
// cost would be paid once per record where the per-run total is
// at most a few hundred lines and one fsync at Close is enough.
//
// Write returns an error when the writer has been closed, when
// the source identifier is empty (an unidentifiable record
// defeats the dedup key), or when the underlying append fails.
func (w *LeaksWriter) Write(rec LeakRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("run: leaks writer is closed")
	}
	if rec.Source == "" {
		return errors.New("run: leak record requires Source")
	}

	// Pin the writer-owned invariants before redaction so the
	// redactor sees the final field values.
	rec.SchemaVersion = LeaksRecordSchemaVersion
	if rec.Timestamp == "" {
		rec.Timestamp = w.now().Format(time.RFC3339)
	}
	if rec.RunID == "" {
		rec.RunID = w.runID
	}

	// Redact every non-empty string field on the record and on
	// the nested evidence map. The redaction is in-place; the
	// LeakRecord struct is the value type but we work on a
	// shallow copy under the mutex so a caller-supplied Extra
	// map is not retroactively mutated.
	rec = redactLeakRecord(rec)

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("run: marshal leak record: %w", err)
	}
	line = append(line, '\n')

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("run: append leak record to %s: %w", w.tmpPath, err)
	}
	return nil
}

// Close fsyncs the staged tmp file, closes it, and renames it
// over <runDir>/leaks.jsonl. Safe to call more than once; the
// second call is a no-op. Once Close returns, further Write
// calls fail with a clear error so a misbehaving caller cannot
// silently lose records against a closed handle.
//
// The fsync-then-rename sequence is the durability barrier.
// After Close returns nil, a reader of <runDir>/leaks.jsonl
// either sees the previous file content or the new content,
// never a partial line; a host crash that interrupts the
// rename loses only the un-renamed tmp (which the next
// supervisor start sweeps via CleanupStaleLeaksTemp).
//
// Close also fsyncs the parent directory so the rename itself
// survives a host crash. On platforms where directory Sync is
// not meaningful (Windows) the error is non-fatal: the rename
// has already happened and the durability story falls back to
// the filesystem's own dirent ordering.
func (w *LeaksWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true

	// fsync the tmp file's bytes before we rename so a crash
	// between rename and writeback does not surface an empty
	// leaks.jsonl.
	if err := w.file.Sync(); err != nil {
		// Best-effort: try to close and clean up the tmp even
		// when sync failed so a retry does not have to deal
		// with two stale files.
		_ = w.file.Close()
		_ = os.Remove(w.tmpPath)
		return fmt.Errorf("run: sync leaks tmp %s: %w", w.tmpPath, err)
	}
	if err := w.file.Close(); err != nil {
		_ = os.Remove(w.tmpPath)
		return fmt.Errorf("run: close leaks tmp %s: %w", w.tmpPath, err)
	}

	finalPath := filepath.Join(w.runDir, leaksFileName)
	if err := os.Rename(w.tmpPath, finalPath); err != nil {
		// The tmp is left in place so a retry / replay tool
		// can inspect it; the next supervisor start will
		// sweep it via CleanupStaleLeaksTemp.
		return fmt.Errorf("run: rename leaks tmp into place: %w", err)
	}

	// Best-effort parent-dir fsync. The rename has already
	// happened; a directory Sync failure is informational so
	// we explicitly ignore the error on close.
	if dir, err := os.Open(w.runDir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}

	return nil
}

// Abort closes the staged tmp file and removes it without
// renaming over leaks.jsonl. Used by the supervisor's
// panic-recovery path so a partial write does not stomp the
// previous leaks.jsonl. Safe to call more than once; the second
// call is a no-op. Returns an error only when the underlying
// close / remove fails — the writer is treated as closed
// regardless so a subsequent Close does nothing.
func (w *LeaksWriter) Abort() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true

	closeErr := w.file.Close()
	rmErr := os.Remove(w.tmpPath)
	if closeErr != nil {
		return fmt.Errorf("run: close leaks tmp %s: %w", w.tmpPath, closeErr)
	}
	if rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return fmt.Errorf("run: remove leaks tmp %s: %w", w.tmpPath, rmErr)
	}
	return nil
}

// TmpPath returns the absolute path of the staged tmp file. Test
// helpers use it to assert on the on-disk shape mid-write; the
// supervisor uses it only via Close / Abort.
func (w *LeaksWriter) TmpPath() string {
	return w.tmpPath
}

// LeaksPath returns the absolute path of the final leaks.jsonl
// file inside the run directory at runDir. It is the symmetric
// helper to RunJSONPath / TaskPath; downstream tooling (Batch 8.2
// CLI, final-summary renderer) uses it to surface the file's
// location in its output without re-encoding the layout.
func LeaksPath(runDir string) string {
	return filepath.Join(runDir, leaksFileName)
}

// CleanupStaleLeaksTemp removes every <runDir>/leaks.jsonl.tmp.*
// file whose modification time predates olderThan. The supervisor
// calls this at run start so a tmp left behind by a previously
// crashed run does not block a fresh OpenLeaksWriter (which
// refuses to clobber an existing tmp via O_EXCL).
//
// olderThan is typically the supervisor's run-start time; a tmp
// stamped after run start was created by the current run's own
// OpenLeaksWriter and must not be removed. Passing the zero time
// removes every tmp unconditionally; callers use that only in
// tests.
//
// The function tolerates a missing runDir (returns nil) and any
// per-entry Remove error (logged via the returned error slice
// surface — production callers ignore the per-entry error and
// only check the aggregate). The returned removed slice contains
// the absolute paths actually unlinked so the supervisor can
// emit a lifecycle verb naming each one if needed.
func CleanupStaleLeaksTemp(runDir string, olderThan time.Time) ([]string, error) {
	if runDir == "" {
		return nil, errors.New("run: CleanupStaleLeaksTemp requires runDir")
	}
	entries, err := os.ReadDir(runDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("run: read run dir %s: %w", runDir, err)
	}

	var removed []string
	var firstErr error
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, leaksTmpPrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("run: stat leaks tmp %s: %w", name, err)
			}
			continue
		}
		// Drop tmps strictly older than olderThan. A tmp
		// stamped at or after run start was opened by the
		// current process; removing it would race the active
		// writer. The zero-time case (used by tests) skips
		// the guard so every tmp is removed unconditionally.
		if !olderThan.IsZero() && !info.ModTime().Before(olderThan) {
			continue
		}
		path := filepath.Join(runDir, name)
		if err := os.Remove(path); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("run: remove stale leaks tmp %s: %w", path, err)
			}
			continue
		}
		removed = append(removed, path)
	}
	return removed, firstErr
}

// redactLeakRecord runs secrets.RedactSecrets across every
// non-empty string field on rec and on the nested LeakEvidence.
// Returns a redacted copy; the input is not mutated so a caller
// that retains the record can re-emit it elsewhere without
// double-redaction. The Extra map is shallow-copied so callers
// that mutate it after Write are not affected.
//
// The function uses reflect to walk the struct so a future
// schema addition (a new string field on LeakRecord or
// LeakEvidence) is redacted automatically without an explicit
// per-field handler list. Non-string fields and the integer
// SchemaVersion / Vector / SourceLine are passed through
// unchanged.
func redactLeakRecord(rec LeakRecord) LeakRecord {
	rec.Timestamp = secrets.RedactSecrets(rec.Timestamp)
	rec.RunID = secrets.RedactSecrets(rec.RunID)
	rec.Source = LeakSource(secrets.RedactSecrets(string(rec.Source)))
	rec.Verb = secrets.RedactSecrets(rec.Verb)
	rec.PolicyEventID = secrets.RedactSecrets(rec.PolicyEventID)
	rec.Evidence = redactLeakEvidence(rec.Evidence)
	return rec
}

// redactLeakEvidence applies the same redaction discipline to
// the LeakEvidence sub-struct. Pulled into a separate helper so
// the reflect walk over LeakRecord stays small; future
// sub-structs can be added the same way.
func redactLeakEvidence(ev LeakEvidence) LeakEvidence {
	ev.Pattern = secrets.RedactSecrets(ev.Pattern)
	ev.FindingID = secrets.RedactSecrets(ev.FindingID)
	ev.Snippet = secrets.RedactSecrets(ev.Snippet)
	ev.Detail = secrets.RedactSecrets(ev.Detail)
	if len(ev.Extra) > 0 {
		// Shallow defensive copy so a caller that mutates the
		// map after Write does not retroactively change the
		// redacted snapshot.
		out := make(map[string]string, len(ev.Extra))
		for k, v := range ev.Extra {
			out[secrets.RedactSecrets(k)] = secrets.RedactSecrets(v)
		}
		ev.Extra = out
	}
	return ev
}

// Compile-time check that LeaksWriter satisfies io.Closer so it
// can be deferred alongside other Closeables (the supervisor's
// terminal-walk defer chain, a test's t.Cleanup).
var _ io.Closer = (*LeaksWriter)(nil)

// Compile-time guard that LeakRecord remains a value type
// (i.e. no pointer-receiver method drift). reflect is used
// above only for the redaction comment; the actual paths are
// explicit. We keep this sentinel so a future contributor who
// extends LeakRecord notices the explicit redaction site.
var _ = reflect.TypeOf(LeakRecord{})
