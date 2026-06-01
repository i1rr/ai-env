// Transcript writer + per-CLI advisory parsers (Plan §7 — Bucket 8).
//
// transcript.jsonl is the per-run stream of agent-CLI turn events the
// supervisor extracts from the agent's streaming stdout. Two CLIs are
// supported today:
//
//   - Claude Code, launched with `--output-format stream-json --verbose
//     -p`. Each stdout line is a JSON object carrying a "type"
//     ("system" / "user" / "assistant" / "tool_use" / "tool_result" /
//     "result") plus a "message" envelope. The parser pulls each line,
//     classifies it, and emits a TranscriptRecord.
//
//   - Codex, launched with `--json`. Each stdout line is a JSON object
//     carrying a "type" ("agent_message" / "tool_call" / "tool_result"
//     / "error" / "shutdown") plus per-event fields. The parser maps
//     each line to a TranscriptRecord.
//
// Both parsers are advisory: a malformed line or a line that exceeds
// the 1 MB scanner cap (the bufio.Scanner default is 64 KiB; we raise
// it to 1 MiB to absorb large tool-result payloads while still
// rejecting pathological input) drops one
// LifecycleVerbTranscriptParserError event into lifecycle.jsonl and
// continues. The supervisor never fails a run on transcript-parser
// error — the canonical per-subsystem streams (mcp-calls,
// policy-decisions, network-events, shell-commands, filesystem-events)
// stay the source of truth, and transcript.jsonl is the correlation
// surface the operator joins them on.
//
// Correlation key — TurnID is the supervisor-minted identifier
// (Plan Batch 3.3) the agent obtains via ControlSocket.BeginTurn. The
// parser consults a TurnSource (typically *run.ControlSocket via its
// CurrentTurnID method, same accessor MCPCallLogger uses) at line-read
// time and stamps the returned id onto every emitted record. A
// compromised agent that skips BeginTurn leaves TurnID empty;
// downstream readers interpret an empty TurnID as "unknown" rather
// than as a missing field. Plan §0 documents the "best-effort under
// non-compromised agent" caveat.
//
// The writer mirrors LifecycleWriter / NetworkEventsWriter /
// MCPCallsWriter / FilesystemEventsWriter in shape — append-only,
// fsync-after-write, mutex-protected, in-record _schema_version per
// the Plan §0 "Schema-version contract" — so a future refactor that
// unifies the per-run JSONL writers can replace them all with one
// generic implementation without touching call sites.
//
// Architectural note: this file deliberately does not import any
// CLI-specific package. The Claude / Codex stdout shapes are decoded
// against tiny anonymous structs local to ParseClaudeLine /
// ParseCodexLine; the run package owns the on-disk projection
// (TranscriptRecord) the same way it owns MCPCallRecord and
// FilesystemEventRecord.

package run

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// transcriptFileName is the basename of the per-run transcript stream.
// It sits at the root of the run directory next to the other
// per-subsystem streams (lifecycle.jsonl, network-events.jsonl,
// mcp-calls.jsonl, shell-commands.jsonl, filesystem-events.jsonl,
// policy-decisions.jsonl, leaks.jsonl). The constant mirrors the other
// per-run filename constants so the transcript writer is the single
// owner of the filename even though run.go materialized the
// placeholder.
const transcriptFileName = "transcript.jsonl"

// TranscriptRecordSchemaVersion is the schema-version tag stamped onto
// every TranscriptRecord. Per Plan §0 "Schema-version contract" the
// new streams introduced in this plan (leaks.jsonl, transcript.jsonl,
// filesystem-events.jsonl) carry their version per-record so readers
// can refuse a future incompatible bump without consulting
// Record.SchemaVersions. v0.1 ships at version 1; bumping the constant
// requires a coordinated reader update plus a runbook migration note.
const TranscriptRecordSchemaVersion = 1

// transcriptScannerMaxBuffer is the upper bound on a single stdout
// line the per-CLI parser will accept. Plan Bucket 8 pins it at 1 MiB
// — large enough to absorb a verbose tool-result payload without
// killing the run, small enough that a pathological producer cannot
// exhaust the supervisor's address space. A line that exceeds this
// cap surfaces as a "scan_overflow" LifecycleVerbTranscriptParserError
// and the parser continues at the next \n boundary.
const transcriptScannerMaxBuffer = 1 << 20 // 1 MiB

// TranscriptCLI identifies which agent CLI produced a record. The
// parser stamps the value on every emitted TranscriptRecord so a
// downstream consumer of transcript.jsonl can grep by CLI without
// joining against run.json's Agent field.
type TranscriptCLI string

const (
	// TranscriptCLIClaude tags records parsed from Claude Code's
	// `--output-format stream-json --verbose -p` stream.
	TranscriptCLIClaude TranscriptCLI = "claude"

	// TranscriptCLICodex tags records parsed from Codex's `--json`
	// stream.
	TranscriptCLICodex TranscriptCLI = "codex"
)

// Transcript event-kind tokens recorded on the Kind field of
// TranscriptRecord. Pinned as constants so every CLI parser uses the
// same spellings and an auditor can grep by kind without translating
// from the per-CLI vocabulary. Values mirror the policy-decisions /
// filesystem-events token shapes so a future aggregator can join
// across streams without translation.
const (
	// TranscriptKindSystem is recorded for system-prompt / init
	// frames (Claude's "system" type, Codex's "session_start" type).
	TranscriptKindSystem = "system"

	// TranscriptKindUser is recorded for user-message frames (Claude's
	// "user" type, Codex's "user_message" type). Used by the
	// correlation surface to mark the start of a turn.
	TranscriptKindUser = "user"

	// TranscriptKindAssistant is recorded for assistant text frames
	// (Claude's "assistant" type with a "message.content" text block,
	// Codex's "agent_message" type).
	TranscriptKindAssistant = "assistant"

	// TranscriptKindToolUse is recorded for tool-call frames (Claude's
	// "assistant" type with a "tool_use" content block, Codex's
	// "tool_call" type). The Tool / Args fields carry the per-call
	// context; the downstream leaks aggregator joins on Tool +
	// TurnID against mcp-calls.jsonl.
	TranscriptKindToolUse = "tool_use"

	// TranscriptKindToolResult is recorded for tool-result frames
	// (Claude's "user" type with a "tool_result" content block,
	// Codex's "tool_result" type).
	TranscriptKindToolResult = "tool_result"

	// TranscriptKindResult is recorded for terminal "result" frames
	// (Claude's "result" type, Codex's "shutdown" type). The Reason
	// field captures the CLI-supplied stop reason.
	TranscriptKindResult = "result"

	// TranscriptKindError is recorded for CLI-emitted error frames
	// (Codex's "error" type, Claude's "result" with subtype "error").
	// The Reason field captures the CLI-supplied error text.
	TranscriptKindError = "error"
)

// Transcript parser-error reason tokens recorded as the "reason" key on
// the LifecycleVerbTranscriptParserError lifecycle metadata. Plan
// Batch 0.1 documented the verb's metadata schema with these three
// canonical tokens.
const (
	// TranscriptParserErrorScanOverflow is emitted when a single
	// stdout line exceeded transcriptScannerMaxBuffer bytes. The
	// parser drops the line and continues at the next \n boundary;
	// the run continues, the transcript stream is marked degraded.
	TranscriptParserErrorScanOverflow = "scan_overflow"

	// TranscriptParserErrorJSONParse is emitted when a line did not
	// decode as a JSON object. The parser drops the line and
	// continues at the next \n boundary.
	TranscriptParserErrorJSONParse = "json_parse"

	// TranscriptParserErrorStreamError is emitted when the underlying
	// io.Reader returned a non-EOF error mid-scan. The parser stops
	// reading from this reader; the supervisor's stdout pump will
	// re-open or finalize as appropriate.
	TranscriptParserErrorStreamError = "stream_error"
)

// TranscriptRecord is one record written to transcript.jsonl. The
// shape unifies the per-CLI streams (Claude stream-json, Codex
// --json) into a single audit projection the leaks aggregator and the
// final-summary renderer consume. Every CLI-specific shape collapses
// into the (Kind, Role, Text, Tool, Args) tuple here; the per-CLI
// parsers are responsible for the translation.
//
// Every required field is enforced at Write time so a misconfigured
// emitter fails loudly rather than producing an unidentifiable record.
// Optional fields use omitempty so the common case keeps the line
// compact.
//
// Architectural note: defining TranscriptRecord here (rather than
// importing a per-CLI record shape) keeps the run package free of any
// CLI-vendor dependency, mirroring how MCPCallRecord and
// FilesystemEventRecord are defined here rather than imported from
// internal/mcp or internal/policy.
type TranscriptRecord struct {
	// SchemaVersion is the per-record schema version tag. Always 1 in
	// v0.1; readers refuse a record carrying SchemaVersion >
	// TranscriptRecordSchemaVersion. Encoded as "_schema_version" to
	// match the Plan §0 contract verbatim (the same tag spelling
	// LeakRecord and FilesystemEventRecord use).
	SchemaVersion int `json:"_schema_version"`

	// Timestamp is the moment the line was observed on the agent's
	// stdout, formatted as RFC3339 with a numeric offset. The writer
	// fills this in from its clock when the caller leaves it empty
	// (the per-CLI parsers stamp their own observed-time timestamps;
	// preserving a non-empty caller value keeps the on-disk timestamp
	// matched to the line rather than the append).
	Timestamp string `json:"timestamp"`

	// RunID duplicates the run identifier into every record so a
	// future aggregator that concatenates transcript.jsonl across
	// many runs does not lose attribution. The writer fills this in
	// when the caller leaves it empty.
	RunID string `json:"run_id"`

	// CLI identifies which agent CLI produced the line. One of the
	// TranscriptCLI* constants. Required so a downstream consumer can
	// dispatch to the right per-CLI dedup key without joining against
	// run.json.
	CLI TranscriptCLI `json:"cli"`

	// Kind is the canonical event kind (system / user / assistant /
	// tool_use / tool_result / result / error). One of the
	// TranscriptKind* constants. Required.
	Kind string `json:"kind"`

	// TurnID is the supervisor-minted turn identifier in effect at
	// the moment the line was read (Plan Batch 3.3 — Turn-ID flows).
	// The parser consults the per-run TurnSource (typically
	// *run.ControlSocket via CurrentTurnID, same accessor
	// MCPCallLogger uses) before stamping the record so an auditor
	// can correlate each transcript line against the agent turn
	// recorded in mcp-calls.jsonl / policy-decisions.jsonl /
	// filesystem-events.jsonl. Empty when no turn source is wired
	// (unit tests, dry-runs) or when the agent has not yet called
	// BeginTurn; readers treat an empty TurnID as "unknown" rather
	// than as a missing field.
	TurnID string `json:"turn_id,omitempty"`

	// Seq is the monotonic per-CLI line counter the parser
	// increments on every emitted record. Used by the leaks
	// aggregator to detect gaps in a long-lived stream (Plan §0
	// "correlation key" note: gap detection is robust only for the
	// long-lived MCP shim; for shell-mode helpers seq=1 always).
	// Starts at 1 on the first record; zero on a record means the
	// caller emitted out-of-band.
	Seq int `json:"seq,omitempty"`

	// Role is the speaker role the CLI reported ("user" /
	// "assistant" / "system"). Populated on system / user /
	// assistant records; empty on tool_use / tool_result / result /
	// error.
	Role string `json:"role,omitempty"`

	// Text is the rendered text payload (the assistant message text,
	// the user-prompt text, the system-prompt text, the
	// tool-result text body). Optional. Every leaked secret-shaped
	// substring is redacted by the downstream leaks aggregator at
	// leaks.jsonl write time, not here, so this field preserves the
	// original byte sequence for an auditor inspecting the raw
	// stream.
	Text string `json:"text,omitempty"`

	// Tool is the MCP / built-in tool name on tool_use / tool_result
	// records. Empty on system / user / assistant / result / error
	// records. The downstream aggregator joins on Tool + TurnID
	// against mcp-calls.jsonl so a tool-call decision and its
	// resulting transcript frame surface as one leak row.
	Tool string `json:"tool,omitempty"`

	// Args is the tool-call arguments blob the agent supplied,
	// stringified for the audit log. Populated on tool_use records.
	// Optional; large payloads should be truncated by the emitter
	// before forwarding (the 1 MiB scanner cap is the upper bound,
	// but the on-disk record stays compact).
	Args string `json:"args,omitempty"`

	// MessageID is the per-message identifier the CLI minted (Claude
	// stream-json includes "message.id"; Codex includes "id" on
	// agent_message frames). Optional; populated when the source
	// frame carried one so the downstream aggregator can join on it
	// when correlating sub-frames (e.g. an assistant message split
	// across multiple content blocks).
	MessageID string `json:"message_id,omitempty"`

	// Reason is a CLI-supplied stop reason / error text on result /
	// error records (Claude's "result.subtype" and "result.reason",
	// Codex's "error.message" / "shutdown.reason"). Empty on other
	// records.
	Reason string `json:"reason,omitempty"`

	// Snippet is a short captured byte fragment showing the context
	// that prompted the record (the matched JSON-RPC argument body
	// on a tool_use record, the first N bytes of a multi-block
	// assistant message). Optional; the emitter trims to a reasonable
	// size before forwarding.
	Snippet string `json:"snippet,omitempty"`
}

// TranscriptWriter appends TranscriptRecord values to transcript.jsonl.
//
// The plan calls for append-only newline-delimited JSON, one record
// per parsed CLI frame, flushed after every write so a crash does not
// lose the transcript audit trail. The writer is safe for concurrent
// use: the per-CLI parser, a future replay tool, and any test fake
// may all call Write from different goroutines, and the resulting on-
// disk file must contain one well-formed JSON object per line with no
// interleaving.
//
// Construction goes through OpenTranscriptWriter so the file handle,
// the per-run metadata (run ID), and the clock are wired in once. The
// handle stays open for the lifetime of the run; Close is the only
// orderly shutdown path. The supervisor closes the writer alongside
// the other per-subsystem writers in the post-run drain (Plan §5.5
// step 9).
//
// The shape mirrors LifecycleWriter / NetworkEventsWriter /
// MCPCallsWriter / FilesystemEventsWriter on purpose: a future
// refactor that unifies the per-run JSONL writers can replace them
// all with one generic implementation without touching call sites.
type TranscriptWriter struct {
	// mu serializes writes so concurrent callers cannot interleave
	// bytes inside a single JSON line, even though O_APPEND already
	// protects the file offset on POSIX. The encode + sync sequence
	// is a logical write, not just a byte-level one, so the mutex
	// covers both halves.
	mu sync.Mutex

	// file is the open transcript.jsonl handle. Kept open for the
	// lifetime of the writer so we are not paying open/close per
	// record; closed exactly once by Close.
	file *os.File

	// runID is the run identifier the writer was opened for. Copied
	// into every record's RunID field when the caller left it empty
	// so emitters can submit partially populated records.
	runID string

	// now produces the timestamp stamped on each record when the
	// caller has not pre-populated Timestamp. A function (rather
	// than a clock interface) so tests can inject a deterministic
	// sequence of times; production callers pass time.Now.
	now func() time.Time

	// closed guards Close from racing with itself and prevents Write
	// after Close from panicking on a stale file handle.
	closed bool
}

// TranscriptWriterOptions bundles the per-run metadata a
// TranscriptWriter needs at construction. RunID is required; Now is
// optional and falls back to time.Now when nil.
type TranscriptWriterOptions struct {
	// RunID is the run identifier this writer's records belong to.
	// Required.
	RunID string

	// Now is the clock the writer uses to stamp Timestamp on each
	// record when the caller has not pre-populated the field. Nil
	// falls back to time.Now. Tests inject a fixed-step clock so the
	// on-disk timestamps are deterministic.
	Now func() time.Time
}

// OpenTranscriptWriter opens (or creates and appends to) the
// transcript.jsonl file for the run directory at runDir, wires it to
// the supplied options, and returns a TranscriptWriter ready to accept
// records.
//
// runDir is the absolute path to the run directory (the same value
// RunDirectory.Path carries). The file is opened with O_APPEND so the
// writer cooperates correctly with the empty placeholder
// CreateRunDirectory left in place, and so a reopen of an existing
// run (future replay tooling) adds to the trail rather than truncating
// it.
//
// Returns an error when the file cannot be opened or when any required
// option is empty. On error no file handle is leaked.
func OpenTranscriptWriter(runDir string, opts TranscriptWriterOptions) (*TranscriptWriter, error) {
	if runDir == "" {
		return nil, errors.New("run: OpenTranscriptWriter requires runDir")
	}
	if opts.RunID == "" {
		return nil, errors.New("run: OpenTranscriptWriter requires RunID")
	}

	path := filepath.Join(runDir, transcriptFileName)
	// O_APPEND so concurrent writes (and the empty placeholder file
	// CreateRunDirectory left behind) compose cleanly; O_CREATE so a
	// caller that constructed the writer against a freshly-rmd
	// directory still gets a working handle rather than a confusing
	// ENOENT.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, runFileMode)
	if err != nil {
		return nil, fmt.Errorf("run: open transcript log %s: %w", path, err)
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}

	return &TranscriptWriter{
		file:  f,
		runID: opts.RunID,
		now:   clock,
	}, nil
}

// Write appends a single transcript record to the underlying
// transcript.jsonl file. The writer fills in SchemaVersion (always
// TranscriptRecordSchemaVersion), Timestamp (when empty), and RunID
// (when empty) so emitters can submit partially populated records and
// the writer pins the invariants.
//
// The encoded line is a single JSON object followed by exactly one
// newline byte. The plan requires that no buffered record be lost on
// crash, so Write fsyncs the file after a successful append. The
// mutex makes the encode + sync pair atomic with respect to other
// callers: two goroutines emitting concurrently produce two
// consecutive whole lines, never an interleaved one.
//
// Write rejects an empty CLI / Kind so a misconfigured caller fails
// loudly rather than silently producing an unidentifiable record.
// Those two fields together form the audit log's minimal identity;
// any one of them missing defeats the purpose of having the line on
// disk.
func (w *TranscriptWriter) Write(rec TranscriptRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("run: transcript writer is closed")
	}
	if rec.CLI == "" {
		return errors.New("run: transcript record requires CLI")
	}
	if rec.Kind == "" {
		return errors.New("run: transcript record requires Kind")
	}

	// Pin the writer-owned invariants before marshal so the encoded
	// line carries the final field values regardless of what the
	// emitter pre-populated.
	rec.SchemaVersion = TranscriptRecordSchemaVersion
	if rec.Timestamp == "" {
		rec.Timestamp = w.now().Format(time.RFC3339)
	}
	if rec.RunID == "" {
		rec.RunID = w.runID
	}

	// Marshal then a single Write keeps the JSON object + newline as
	// one syscall, matching the O_APPEND atomicity guarantee on POSIX
	// (writes up to PIPE_BUF are atomic; a typical record is well
	// under that).
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("run: marshal transcript record: %w", err)
	}
	line = append(line, '\n')

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("run: append transcript record: %w", err)
	}
	// Sync after every record so a crash between records does not
	// erase the transcript audit trail. The plan's "no buffering
	// data loss on crash" rule applies uniformly across every per-
	// run JSONL writer; mirroring the other writers here keeps the
	// contract uniform.
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("run: sync transcript log: %w", err)
	}
	return nil
}

// Close closes the underlying transcript.jsonl file. Safe to call
// more than once; the second call is a no-op. Once Close returns,
// further Write calls fail with a clear error so a misbehaving caller
// cannot silently lose records against a closed handle.
//
// The supervisor calls Close from its post-run drain (Plan §5.5 step
// 9) after the final terminal state has been recorded; closing
// earlier would drop any late-arriving parser records (e.g. a
// terminal "result" frame the agent emits during shutdown).
func (w *TranscriptWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("run: close transcript log: %w", err)
	}
	return nil
}

// TranscriptPath returns the absolute path of the transcript.jsonl
// file inside runDir. Mirrors LifecyclePath / NetworkEventsPath /
// MCPCallsPath / FilesystemEventsPath / LeaksPath so callers (status
// / report / final-summary, the leaks aggregator) have a single
// helper for the layout.
func TranscriptPath(runDir string) string {
	return filepath.Join(runDir, transcriptFileName)
}

// ReadTranscript loads every TranscriptRecord recorded in runDir's
// transcript.jsonl, in the order they were appended. Blank lines
// (e.g. a trailing newline at EOF) are skipped silently.
//
// ReadTranscript returns an empty slice and nil when the file exists
// but is empty (the post-CreateRunDirectory placeholder state) or
// absent. A malformed line returns the records read so far plus the
// parse error so a caller can still surface the partial trail.
//
// Mirrors ReadMCPCalls / ReadNetworkEvents / ReadPolicyDecisions /
// ReadFilesystemEvents: the file is small in practice (one record per
// agent CLI frame, a few hundred per run), so the whole-file read is
// preferable to a streaming parser.
func ReadTranscript(runDir string) ([]TranscriptRecord, error) {
	if runDir == "" {
		return nil, errors.New("run: ReadTranscript requires runDir")
	}
	path := TranscriptPath(runDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("run: read transcript %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	return parseTranscript(data, path)
}

// parseTranscript decodes data as JSONL transcript records. Split out
// so ReadTranscript can stay tiny and so tests can exercise the
// parser against in-memory byte slices.
func parseTranscript(data []byte, path string) ([]TranscriptRecord, error) {
	out := make([]TranscriptRecord, 0, 8)
	for i, line := range splitJSONLines(data) {
		if len(line) == 0 {
			continue
		}
		var rec TranscriptRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return out, fmt.Errorf("run: parse %s line %d: %w", path, i+1, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// TranscriptParserErrorSink is the tiny interface the per-CLI parsers
// use to surface advisory parse failures. *LifecycleWriter satisfies
// it via its WriteVerb method; tests pass a closure that records the
// metadata for assertion. Decoupling the parser from
// *LifecycleWriter keeps the package's import graph flat and lets a
// future supervisor wire a degraded-stream observer (e.g. a status
// flag in run.json) the same way.
//
// The parser calls Emit at most once per scan window per error reason
// (the de-duplication is per-parser, not per-sink) so a flood of
// malformed lines does not spam lifecycle.jsonl. The metadata table
// follows the schema documented on LifecycleVerbTranscriptParserError
// in lifecycle_verbs.go.
type TranscriptParserErrorSink interface {
	// Emit writes one LifecycleVerbTranscriptParserError event with
	// the supplied metadata. Returning an error is informational —
	// the parser logs and continues either way (the parser's
	// per-line advisory contract trumps a downstream sink failure).
	Emit(metadata map[string]string) error
}

// TranscriptParserErrorSinkFunc is a function adapter so a caller can
// pass a closure where a TranscriptParserErrorSink is required.
// Mirrors TurnSourceFunc / ShellEvaluatorFunc.
type TranscriptParserErrorSinkFunc func(metadata map[string]string) error

// Emit implements TranscriptParserErrorSink by forwarding to the
// underlying function.
func (f TranscriptParserErrorSinkFunc) Emit(metadata map[string]string) error {
	return f(metadata)
}

// LifecycleTranscriptErrorSink adapts a *LifecycleWriter into a
// TranscriptParserErrorSink by routing every Emit call through
// WriteVerb(LifecycleVerbTranscriptParserError, metadata). Returns
// nil when lw is nil so a caller that has not yet wired the
// lifecycle writer can still construct a parser (the dropped events
// surface only via the lifecycle stream — there is no other side
// effect to lose).
func LifecycleTranscriptErrorSink(lw *LifecycleWriter) TranscriptParserErrorSink {
	if lw == nil {
		return nil
	}
	return TranscriptParserErrorSinkFunc(func(metadata map[string]string) error {
		return lw.WriteVerb(LifecycleVerbTranscriptParserError, metadata)
	})
}

// TranscriptTurnSource is the per-run accessor the transcript parser
// consults at line-read time to stamp TranscriptRecord.TurnID.
// *run.ControlSocket satisfies the interface via its CurrentTurnID
// method (Plan Batch 3.3 — Turn-ID flows); a test fake substitutes
// a closure that returns canned values. The interface mirrors
// internal/cli.TurnSource so the gateway bridge (MCPCallLogger) and
// the transcript parser stamp the same per-role counter family when
// both forward from the same control socket; declaring it here keeps
// the run package free of an internal/cli dependency.
//
// Implementations:
//
//   - must be safe for concurrent CurrentTurnID calls (the parser is
//     called from the supervisor's stdout pump goroutine);
//   - must return "" when no turn has been allocated yet for the
//     requested role — the parser interprets the empty string as "no
//     turn id available" and leaves TranscriptRecord.TurnID empty;
//   - must never panic on an unknown role: the parser passes whatever
//     TranscriptParserOptions.TurnRole the caller supplied, and a
//     typo should yield an empty result, not a runtime failure.
type TranscriptTurnSource interface {
	// CurrentTurnID returns the most recent turn id allocated for
	// the supplied role. Empty when no turn has started yet. The
	// parser uses this value to stamp TranscriptRecord.TurnID at
	// line-read time.
	CurrentTurnID(role string) string
}

// TranscriptTurnSourceFunc is a function adapter so callers can pass
// a closure where a TranscriptTurnSource is required (mirrors the
// cli.TurnSourceFunc adapter used by MCPCallLogger).
type TranscriptTurnSourceFunc func(role string) string

// CurrentTurnID implements TranscriptTurnSource by forwarding to the
// underlying function.
func (f TranscriptTurnSourceFunc) CurrentTurnID(role string) string {
	return f(role)
}

// TranscriptParserOptions bundles the per-run wiring a per-CLI parser
// needs. Every field is optional; nil values fall back to a
// no-effect default so a unit test can exercise the parser shape
// without standing up a control socket or a lifecycle writer.
type TranscriptParserOptions struct {
	// CLI identifies which agent CLI is producing the stream. The
	// parser stamps the value onto every emitted TranscriptRecord.
	// Required for ParseClaude / ParseCodex.
	CLI TranscriptCLI

	// TurnSource is the per-run accessor the parser consults at
	// line-read time to stamp TranscriptRecord.TurnID. Nil leaves
	// TurnID empty on every record. The supervisor wires
	// *run.ControlSocket here; tests substitute a closure.
	TurnSource TranscriptTurnSource

	// TurnRole names the role the parser passes to
	// TurnSource.CurrentTurnID. Empty falls back to "agent" so the
	// in-process accessor agrees with the RPC handler's default
	// role handling (the control socket rewrites the empty string
	// to "agent" on both sides).
	TurnRole string

	// ErrorSink is the lifecycle-bound advisory sink the parser
	// notifies on a scan_overflow / json_parse / stream_error. Nil
	// drops the events on the floor (used by unit tests that
	// assert on counts of malformed inputs without standing up a
	// lifecycle writer).
	ErrorSink TranscriptParserErrorSink

	// Now produces the timestamp stamped on each emitted record.
	// Nil falls back to time.Now. Tests inject a fixed-step clock
	// so the on-disk timestamps are deterministic.
	Now func() time.Time
}

// transcriptDefaultTurnRole mirrors cli.DefaultTurnRole so the
// in-process transcript parser uses the same per-role counter as the
// MCP gateway bridge when both forward TurnID stamps from the same
// control socket. Hard-coding the value here (rather than importing
// from internal/cli) preserves the run-package decoupling.
const transcriptDefaultTurnRole = "agent"

// parseTranscriptOptions returns a copy of opts with defaults applied
// (TurnRole, Now). Split out so ParseClaude and ParseCodex share a
// single defaulting site and a future per-CLI knob is added in one
// place.
func parseTranscriptOptions(opts TranscriptParserOptions) TranscriptParserOptions {
	if opts.TurnRole == "" {
		opts.TurnRole = transcriptDefaultTurnRole
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}

// transcriptCurrentTurnID returns the turn id the parser stamps on a
// record. Pulls from opts.TurnSource when wired; otherwise returns
// the empty string (which the writer's omitempty tag drops from the
// on-disk record). Stateless helper to keep the per-CLI line-reader
// loop tiny.
func transcriptCurrentTurnID(opts TranscriptParserOptions) string {
	if opts.TurnSource == nil {
		return ""
	}
	return opts.TurnSource.CurrentTurnID(opts.TurnRole)
}

// ParseClaude reads Claude Code's `--output-format stream-json
// --verbose -p` stdout from reader, decodes each \n-delimited JSON
// frame into a TranscriptRecord, and forwards every record to writer.
//
// The function returns when reader hits EOF or returns a non-EOF
// error. A scanner overflow (single line > transcriptScannerMaxBuffer
// bytes) is advisory: the parser surfaces one
// LifecycleVerbTranscriptParserError via opts.ErrorSink (reason
// "scan_overflow") and continues at the next \n boundary. A JSON
// parse failure surfaces the same way (reason "json_parse") and the
// line is dropped. A reader error other than io.EOF surfaces with
// reason "stream_error" and the parser stops; the supervisor's
// stdout pump is responsible for the downstream cleanup.
//
// Returns nil on a clean drain (EOF reached, all writes succeeded);
// returns the first Write error otherwise (the lifecycle stream is
// the source of truth for parse-side failures, but a writer-side
// failure is fatal because it means transcript.jsonl is corrupt).
//
// The parser is single-shot: it does not retain state across calls.
// A caller that needs to resume parsing after a stream restart
// constructs a fresh ParseClaude call with the new reader.
func ParseClaude(reader io.Reader, writer *TranscriptWriter, opts TranscriptParserOptions) error {
	if reader == nil {
		return errors.New("run: ParseClaude requires reader")
	}
	if writer == nil {
		return errors.New("run: ParseClaude requires writer")
	}
	opts.CLI = TranscriptCLIClaude
	opts = parseTranscriptOptions(opts)
	return parseTranscriptStream(reader, writer, opts, parseClaudeFrame)
}

// ParseCodex reads Codex's `--json` stdout from reader, decodes each
// \n-delimited JSON frame into a TranscriptRecord, and forwards every
// record to writer.
//
// Same semantics as ParseClaude: scan_overflow / json_parse /
// stream_error surface via opts.ErrorSink; writer-side failures
// short-circuit the parse.
func ParseCodex(reader io.Reader, writer *TranscriptWriter, opts TranscriptParserOptions) error {
	if reader == nil {
		return errors.New("run: ParseCodex requires reader")
	}
	if writer == nil {
		return errors.New("run: ParseCodex requires writer")
	}
	opts.CLI = TranscriptCLICodex
	opts = parseTranscriptOptions(opts)
	return parseTranscriptStream(reader, writer, opts, parseCodexFrame)
}

// transcriptFrameParser is the per-CLI frame decoder. Returns the
// TranscriptRecord (without Timestamp / TurnID / RunID / SchemaVersion
// — the stream loop fills those in) and a bool indicating whether the
// frame should be forwarded. Returning (_, false, nil) drops a line
// silently (e.g. an unsupported frame type the parser does not know
// how to project — keeping these silent rather than as a parser
// error matches the "advisory" contract and lets a future CLI add a
// new frame type without spamming lifecycle.jsonl).
type transcriptFrameParser func(line []byte) (TranscriptRecord, bool, error)

// parseTranscriptStream is the shared scanner loop both ParseClaude
// and ParseCodex use. Owns the bufio.Scanner buffer sizing
// (transcriptScannerMaxBuffer), the per-error de-duplication map,
// the per-record Seq counter, and the writer fan-out. The per-CLI
// frame parser supplies the projection rule.
//
// The de-duplication is per-reason: scan_overflow / json_parse /
// stream_error each fire at most once per ParseClaude / ParseCodex
// call. This trades coverage of every malformed line for not
// flooding lifecycle.jsonl when a CLI starts misbehaving; the
// operator gets exactly one signal per failure mode and can inspect
// stdout.log for the gory detail.
func parseTranscriptStream(reader io.Reader, writer *TranscriptWriter, opts TranscriptParserOptions, parse transcriptFrameParser) error {
	scanner := bufio.NewScanner(reader)
	// Raise the per-line cap from bufio's 64 KiB default to 1 MiB so
	// a verbose tool-result payload does not surface as
	// scan_overflow on every line. The initial buffer stays at 64
	// KiB so the steady-state allocation is unchanged.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, transcriptScannerMaxBuffer)

	seen := map[string]bool{}
	emitErr := func(reason, detail string) {
		if seen[reason] || opts.ErrorSink == nil {
			seen[reason] = true
			return
		}
		seen[reason] = true
		md := map[string]string{
			"cli":    string(opts.CLI),
			"reason": reason,
		}
		if detail != "" {
			md["detail"] = detail
		}
		_ = opts.ErrorSink.Emit(md)
	}

	seq := 0
	for scanner.Scan() {
		raw := scanner.Bytes()
		// bufio.Scanner re-uses the underlying buffer; copy so a
		// later iteration cannot mutate a record's Snippet/Args.
		line := make([]byte, len(raw))
		copy(line, raw)

		trimmed := stripBytes(line)
		if len(trimmed) == 0 {
			continue
		}

		rec, ok, err := parse(trimmed)
		if err != nil {
			emitErr(TranscriptParserErrorJSONParse, err.Error())
			continue
		}
		if !ok {
			continue
		}

		seq++
		rec.CLI = opts.CLI
		rec.TurnID = transcriptCurrentTurnID(opts)
		rec.Seq = seq
		if rec.Timestamp == "" {
			rec.Timestamp = opts.Now().Format(time.RFC3339)
		}

		if err := writer.Write(rec); err != nil {
			return fmt.Errorf("run: transcript parser write: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		// bufio.ErrTooLong surfaces when a single line exceeded
		// transcriptScannerMaxBuffer bytes; the scanner refuses to
		// keep reading past the offending line. We treat this as
		// advisory (per the Plan §8 contract) and stop. The
		// supervisor's downstream pump may re-open the stream;
		// re-call ParseClaude/ParseCodex on the new reader.
		if errors.Is(err, bufio.ErrTooLong) {
			emitErr(TranscriptParserErrorScanOverflow, err.Error())
			return nil
		}
		emitErr(TranscriptParserErrorStreamError, err.Error())
		return nil
	}
	return nil
}

// stripBytes trims ASCII whitespace from both ends of b. Replaces
// bytes.TrimSpace at this call site so the parser stays free of
// import-bytes churn; the function is otherwise equivalent. Carrying
// our own helper keeps the parser self-contained for a future move.
func stripBytes(b []byte) []byte {
	start := 0
	for start < len(b) && isASCIISpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isASCIISpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

// isASCIISpace reports whether c is an ASCII whitespace byte. Mirrors
// unicode.IsSpace for the ASCII subset bufio.Scanner produces.
func isASCIISpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// claudeFrame is the union of the Claude stream-json frame shapes the
// parser projects. Only the fields the projection needs are decoded;
// every other key on the wire is ignored (Plan §0: "Readers ignore
// unknown fields").
//
// The shape mirrors the documented Claude Code stream-json schema
// (`type` is the discriminator; `message` is the envelope on
// "user" / "assistant" frames; `content` carries either a plain text
// string or a slice of content blocks; the per-block shape is
// `{type: text|tool_use|tool_result, ...}`). The parser tolerates
// both string and slice content shapes via a custom decoder helper.
type claudeFrame struct {
	Type    string          `json:"type"`
	Subtype string          `json:"subtype,omitempty"`
	Reason  string          `json:"reason,omitempty"`
	Message *claudeMessage  `json:"message,omitempty"`
	Content json.RawMessage `json:"content,omitempty"`
}

// claudeMessage is the envelope shape on Claude user / assistant /
// system frames. The Content field is decoded lazily because Claude
// sometimes ships a bare string ("hello") and sometimes a list of
// content blocks ([{type:text,text:"hello"},{type:tool_use,...}]).
type claudeMessage struct {
	ID      string          `json:"id,omitempty"`
	Role    string          `json:"role,omitempty"`
	Content json.RawMessage `json:"content,omitempty"`
}

// claudeContentBlock is one entry in the Claude content-block list.
// Used for both assistant tool_use frames and user tool_result frames;
// the discriminator is `type`, the per-type fields are decoded inline.
type claudeContentBlock struct {
	Type    string          `json:"type"`
	Text    string          `json:"text,omitempty"`
	ID      string          `json:"id,omitempty"`
	Name    string          `json:"name,omitempty"`
	Input   json.RawMessage `json:"input,omitempty"`
	Content json.RawMessage `json:"content,omitempty"`
}

// parseClaudeFrame is the per-line projection used by ParseClaude.
// Decodes the top-level type discriminator and dispatches to the
// per-frame projection. Returns (rec, true, nil) on a forwardable
// frame, (zero, false, nil) on an unsupported frame type (silently
// dropped per the advisory contract), and (zero, false, err) on a
// JSON-decode failure (the stream loop forwards err as
// TranscriptParserErrorJSONParse).
func parseClaudeFrame(line []byte) (TranscriptRecord, bool, error) {
	var f claudeFrame
	if err := json.Unmarshal(line, &f); err != nil {
		return TranscriptRecord{}, false, err
	}
	switch f.Type {
	case "system":
		rec := TranscriptRecord{Kind: TranscriptKindSystem, Role: "system"}
		if f.Message != nil {
			rec.MessageID = f.Message.ID
			rec.Text = decodeClaudeText(f.Message.Content)
		}
		return rec, true, nil
	case "user":
		rec := TranscriptRecord{Kind: TranscriptKindUser, Role: "user"}
		// A "user" frame can carry either a plain prompt or a
		// tool_result content block. Inspect the content shape.
		if f.Message != nil {
			rec.MessageID = f.Message.ID
			text, toolResult, ok := decodeClaudeUserContent(f.Message.Content)
			if ok && toolResult != nil {
				rec.Kind = TranscriptKindToolResult
				rec.Role = ""
				rec.Tool = toolResult.Name
				rec.Text = toolResult.Text
				rec.MessageID = toolResult.ID
				return rec, true, nil
			}
			rec.Text = text
		}
		return rec, true, nil
	case "assistant":
		rec := TranscriptRecord{Kind: TranscriptKindAssistant, Role: "assistant"}
		if f.Message != nil {
			rec.MessageID = f.Message.ID
			text, toolUse, ok := decodeClaudeAssistantContent(f.Message.Content)
			if ok && toolUse != nil {
				rec.Kind = TranscriptKindToolUse
				rec.Role = ""
				rec.Tool = toolUse.Name
				rec.MessageID = toolUse.ID
				if len(toolUse.Input) > 0 {
					rec.Args = string(toolUse.Input)
				}
				return rec, true, nil
			}
			rec.Text = text
		}
		return rec, true, nil
	case "result":
		rec := TranscriptRecord{Kind: TranscriptKindResult}
		if f.Subtype == "error" {
			rec.Kind = TranscriptKindError
		}
		rec.Reason = f.Reason
		if rec.Reason == "" {
			rec.Reason = f.Subtype
		}
		return rec, true, nil
	default:
		// Unknown frame types are dropped silently per the advisory
		// contract (a future Claude frame should not surface as a
		// parser error).
		return TranscriptRecord{}, false, nil
	}
}

// decodeClaudeText returns the rendered text for a Claude content
// payload that may be a bare string or a content-block array. The
// per-block "text" entries are concatenated with a single newline;
// non-text blocks are skipped.
func decodeClaudeText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Try the bare-string shape first; if that fails fall through to
	// the content-block array.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []claudeContentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// decodeClaudeUserContent inspects a Claude user-frame content
// payload and reports whether it carries a tool_result block. Returns
// (text, toolResult, ok). When ok && toolResult != nil, the caller
// emits a tool_result transcript record; otherwise the text return
// carries the plain user prompt.
func decodeClaudeUserContent(raw json.RawMessage) (string, *claudeContentBlock, bool) {
	if len(raw) == 0 {
		return "", nil, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil, true
	}
	var blocks []claudeContentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return "", nil, false
	}
	for i := range blocks {
		b := blocks[i]
		if b.Type == "tool_result" {
			tr := claudeContentBlock{
				Type: b.Type,
				ID:   b.ID,
				Name: b.Name,
				Text: decodeClaudeText(b.Content),
			}
			return "", &tr, true
		}
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n"), nil, true
}

// decodeClaudeAssistantContent inspects a Claude assistant-frame
// content payload and reports whether it carries a tool_use block.
// Returns (text, toolUse, ok); when ok && toolUse != nil the caller
// emits a tool_use transcript record.
func decodeClaudeAssistantContent(raw json.RawMessage) (string, *claudeContentBlock, bool) {
	if len(raw) == 0 {
		return "", nil, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil, true
	}
	var blocks []claudeContentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return "", nil, false
	}
	for i := range blocks {
		b := blocks[i]
		if b.Type == "tool_use" {
			tu := blocks[i]
			return "", &tu, true
		}
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n"), nil, true
}

// codexFrame is the union of the Codex `--json` frame shapes the
// parser projects. Only the fields the projection needs are decoded;
// every other key on the wire is ignored (Plan §0: "Readers ignore
// unknown fields").
//
// The shape mirrors the documented Codex JSON schema (`type` is the
// discriminator; per-type fields are flat siblings). The parser
// tolerates Codex's evolving schema by ignoring unknown frame types.
type codexFrame struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Role    string          `json:"role,omitempty"`
	Message string          `json:"message,omitempty"`
	Text    string          `json:"text,omitempty"`
	Content string          `json:"content,omitempty"`
	Name    string          `json:"name,omitempty"`
	Tool    string          `json:"tool,omitempty"`
	Args    json.RawMessage `json:"args,omitempty"`
	Output  string          `json:"output,omitempty"`
	Result  string          `json:"result,omitempty"`
	Reason  string          `json:"reason,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// parseCodexFrame is the per-line projection used by ParseCodex.
// Mirrors parseClaudeFrame's contract.
func parseCodexFrame(line []byte) (TranscriptRecord, bool, error) {
	var f codexFrame
	if err := json.Unmarshal(line, &f); err != nil {
		return TranscriptRecord{}, false, err
	}
	switch f.Type {
	case "session_start", "system":
		rec := TranscriptRecord{Kind: TranscriptKindSystem, Role: "system"}
		rec.Text = firstNonEmpty(f.Message, f.Text, f.Content)
		rec.MessageID = f.ID
		return rec, true, nil
	case "user_message", "user":
		rec := TranscriptRecord{Kind: TranscriptKindUser, Role: "user"}
		rec.Text = firstNonEmpty(f.Message, f.Text, f.Content)
		rec.MessageID = f.ID
		return rec, true, nil
	case "agent_message", "assistant":
		rec := TranscriptRecord{Kind: TranscriptKindAssistant, Role: "assistant"}
		rec.Text = firstNonEmpty(f.Message, f.Text, f.Content)
		rec.MessageID = f.ID
		return rec, true, nil
	case "tool_call":
		rec := TranscriptRecord{Kind: TranscriptKindToolUse}
		rec.Tool = firstNonEmpty(f.Tool, f.Name)
		if len(f.Args) > 0 {
			rec.Args = string(f.Args)
		}
		rec.MessageID = f.ID
		return rec, true, nil
	case "tool_result":
		rec := TranscriptRecord{Kind: TranscriptKindToolResult}
		rec.Tool = firstNonEmpty(f.Tool, f.Name)
		rec.Text = firstNonEmpty(f.Output, f.Result, f.Text)
		rec.MessageID = f.ID
		return rec, true, nil
	case "shutdown":
		rec := TranscriptRecord{Kind: TranscriptKindResult}
		rec.Reason = firstNonEmpty(f.Reason, f.Message)
		return rec, true, nil
	case "error":
		rec := TranscriptRecord{Kind: TranscriptKindError}
		rec.Reason = firstNonEmpty(f.Error, f.Reason, f.Message)
		return rec, true, nil
	default:
		// Unknown frame types are dropped silently per the advisory
		// contract.
		return TranscriptRecord{}, false, nil
	}
}

// firstNonEmpty returns the first non-empty string in the supplied
// list, or "" if every entry is empty. Used by the Codex parser to
// pick a payload from the per-type fallback chain (Codex's evolving
// schema has shipped `message` / `text` / `content` for the same
// concept across versions; the parser tolerates all three).
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Compile-time guard that *TranscriptWriter satisfies io.Closer so it
// can be deferred alongside other Closeables (the supervisor's
// terminal-walk defer chain, a test's t.Cleanup).
var _ io.Closer = (*TranscriptWriter)(nil)
