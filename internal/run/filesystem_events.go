// Filesystem events writer (Plan §6 — Bucket 6).
//
// filesystem-events.jsonl is the per-run event stream that records every
// filesystem operation an agent attempted that the supervisor's enforcers
// observed: MCP filesystem-scope decisions (read/write/list against the
// gateway's resolved-path enforcer), shell-shim file accesses (interpreter-
// via-file scans), and any future filesystem-touching emitter we wire in.
//
// It lives at the root of the run directory next to lifecycle.jsonl,
// network-events.jsonl, policy-decisions.jsonl, mcp-calls.jsonl, and
// shell-commands.jsonl so a reviewer reading a run on disk sees every
// per-subsystem event stream side by side. The leak-coverage audit
// flagged this as Vector-1's missing on-disk record ("the agent attempted
// to read $PATH but was blocked by the sandbox FS; only MCP-routed file
// ops land somewhere"); the writer here is the durable canvas that lets
// Vector-1 surface in leaks.jsonl via the Batch 8.1 aggregator (which
// already declares LeakSourceFilesystemEvents).
//
// The on-disk shape is newline-delimited JSON, one FilesystemEventRecord
// per line, appended in the order the supervisor's enforcers reached the
// decisions. Per Plan §0 "Schema-version contract" the stream is one of
// the three new writers (alongside leaks.jsonl and transcript.jsonl) that
// carries an in-record `_schema_version: 1` tag rather than registering
// into Record.SchemaVersions; readers refuse to parse a record whose
// version exceeds the constant they understand.
//
// The writer mirrors LifecycleWriter / NetworkEventsWriter /
// MCPCallsWriter / PolicyDecisionsWriter in shape — append-only,
// fsync-after-write, mutex-protected — so a future refactor that unifies
// the per-run JSONL writers can replace all five with one generic
// implementation without touching call sites.
//
// Architectural note: this file deliberately does not import internal/mcp
// or internal/policy. The emitters that satisfy the writer interface
// live at their respective construction sites (the gateway-side bridge
// for MCP filesystem decisions; the shim helper for shell-side file
// accesses). Keeping the run package free of those dependencies mirrors
// how MCPCallRecord is defined here rather than imported from
// internal/mcp.

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

// filesystemEventsFileName is the basename of the per-run filesystem
// event log. It sits at the root of the run directory next to the
// other per-subsystem streams; the constant mirrors lifecycleFileName /
// networkEventsFileName / mcpCallsFileName so the writer is the single
// owner of the filename even though run.go materialized the placeholder.
const filesystemEventsFileName = "filesystem-events.jsonl"

// FilesystemEventsRecordSchemaVersion is the schema-version tag stamped
// onto every FilesystemEventRecord. Per Plan §0 "Schema-version contract"
// the new streams introduced in this plan (leaks.jsonl, transcript.jsonl,
// filesystem-events.jsonl) carry their version per-record so readers can
// refuse a future incompatible bump without consulting Record.
// SchemaVersions. v0.1 ships at version 1; bumping the constant requires
// a coordinated reader update plus a runbook migration note.
const FilesystemEventsRecordSchemaVersion = 1

// Filesystem event source tokens recorded on the Source field of
// FilesystemEventRecord. Pinned as constants here so every emitter (the
// MCP gateway bridge, the shell shim, future scanners) shares the
// canonical spellings and an auditor can grep by source without
// translation. The values mirror the leaks.go LeakSource* token shapes
// so a future aggregator that walks filesystem-events.jsonl can map the
// Source field through directly.
const (
	// FilesystemEventSourceMCPGateway is recorded when the MCP gateway's
	// filesystem-scope enforcer reached a verdict on a tool-call body
	// that carried a path-shaped argument. The Operation / Path / Server
	// / Tool fields carry the per-call context; Program / Argv are
	// usually empty.
	FilesystemEventSourceMCPGateway = "mcp-gateway"

	// FilesystemEventSourceShim is recorded when the shell shim
	// (internal/policy/shim.go) reached a verdict on a file the agent
	// asked to execute or scan (interpreter-via-file rule, absolute-
	// path shadow). Program / Argv / Path carry the per-call context;
	// Server / Tool are usually empty.
	FilesystemEventSourceShim = "shim"

	// FilesystemEventSourceScanner is recorded when the secret / shell
	// scanner emitted a filesystem-scoped finding the supervisor wants
	// to surface alongside the MCP and shim trails. Reserved for future
	// scanner emitters; the constant is defined here so a downstream
	// consumer of filesystem-events.jsonl shares the spelling with
	// every other source.
	FilesystemEventSourceScanner = "scanner"
)

// Filesystem event operation tokens recorded on the Operation field of
// FilesystemEventRecord. The list is intentionally open-ended (callers
// pass a verb string), but the constants pin the canonical spellings the
// MCP filesystem scope enforcer and the shim use today so two emitters
// of the same verb do not drift on capitalization or pluralization. A
// future emitter for an exotic operation (e.g. "fchmod", "symlink_resolve")
// can pass its own string without breaking decoders, because consumers
// switch on the field.
const (
	// FilesystemEventOpRead is the canonical verb for an "open for read"
	// / "read file content" decision. Used by MCP filesystem read_file
	// tools and by shim interpreter-via-file content scans.
	FilesystemEventOpRead = "read"

	// FilesystemEventOpWrite is the canonical verb for any
	// content-mutating operation (write_file, append, truncate). The
	// MCP filesystem scope enforcer emits this on write-mode tool calls.
	FilesystemEventOpWrite = "write"

	// FilesystemEventOpList is the canonical verb for directory
	// enumeration decisions (list_directory). Distinguished from Read
	// so an auditor can tell apart "the agent opened ~/.ssh/id_rsa"
	// from "the agent listed ~/.ssh/".
	FilesystemEventOpList = "list"

	// FilesystemEventOpDelete is the canonical verb for unlink / rmdir
	// decisions. Pinned here so a future MCP delete tool's bridge and
	// a shim that observes `rm` share the spelling.
	FilesystemEventOpDelete = "delete"

	// FilesystemEventOpExec is the canonical verb for interpreter-via-
	// file scans the shim performs before SYS_EXECVEAT / /dev/fd
	// dispatch. The Path field carries the file the helper opened with
	// O_RDONLY | O_NOFOLLOW; the Decision reflects whether the content
	// scan allowed the subsequent exec.
	FilesystemEventOpExec = "exec"

	// FilesystemEventOpStat is the canonical verb for metadata-only
	// queries (stat, lstat, readlink). Reserved for future emitters;
	// kept here so the spelling stays canonical.
	FilesystemEventOpStat = "stat"
)

// Filesystem event decision tokens recorded on the Decision field of
// FilesystemEventRecord. The three values match the MCPCallDecision*
// and gateway outcome spellings ("allow" / "warn" / "block") so a
// downstream consumer that joins filesystem-events.jsonl against
// mcp-calls.jsonl or leaks.jsonl does not have to translate.
const (
	// FilesystemEventDecisionAllow indicates the enforcer permitted the
	// operation.
	FilesystemEventDecisionAllow = "allow"

	// FilesystemEventDecisionWarn indicates the enforcer allowed the
	// operation but flagged it (per-server warn policy on the MCP side,
	// shim warn-only patterns).
	FilesystemEventDecisionWarn = "warn"

	// FilesystemEventDecisionBlock indicates the enforcer refused the
	// operation. The Reason field carries the operator-readable
	// explanation (e.g. "filesystem path outside workspace", "interpreter-
	// via-file content matched high-risk pattern").
	FilesystemEventDecisionBlock = "block"
)

// FilesystemEventRecord is one record written to filesystem-events.jsonl.
// The shape unifies the per-subsystem evidence the leak-coverage audit's
// Vector-1 ("path escape") needs: which subsystem observed the access
// (Source), what the agent asked for (Operation, Path, ResolvedPath),
// who served the request (Server / Tool for MCP, Program / Argv for the
// shim), and what the enforcer decided (Decision, Reason).
//
// Two record families share the shape:
//
//   - Source == FilesystemEventSourceMCPGateway: the MCP gateway's
//     filesystem scope enforcer answered "may this tool-call read /
//     write this path?". Server / Tool carry the per-call context;
//     Program / Argv are usually empty.
//   - Source == FilesystemEventSourceShim: the shell shim answered "may
//     this program / file be executed or scanned?". Program / Argv
//     carry the per-call context; Server / Tool are usually empty.
//
// Every required field is enforced at Write time so a misconfigured
// emitter fails loudly rather than producing an unidentifiable record.
// Optional fields use omitempty so the common case keeps the line
// compact.
//
// Architectural note: defining FilesystemEventRecord here (rather than
// importing a per-subsystem record shape) keeps the run package free of
// internal/mcp and internal/policy dependencies, mirroring how
// MCPCallRecord and EngineDecision are defined here.
type FilesystemEventRecord struct {
	// SchemaVersion is the per-record schema version tag. Always 1 in
	// v0.1; readers refuse a record carrying SchemaVersion >
	// FilesystemEventsRecordSchemaVersion. Encoded as "_schema_version"
	// to match the Plan §0 contract verbatim (the same tag spelling
	// LeakRecord uses).
	SchemaVersion int `json:"_schema_version"`

	// Timestamp is the moment the enforcer reached the decision,
	// formatted as RFC3339 with a numeric offset. The writer fills this
	// in from its clock when the caller leaves it empty (the MCP
	// gateway and shim already stamp their own decision-time timestamps;
	// preserving a non-empty caller value keeps the on-disk timestamp
	// matched to the decision rather than the append).
	Timestamp string `json:"timestamp"`

	// RunID duplicates the run identifier into every record so a future
	// aggregator that concatenates filesystem-events.jsonl across many
	// runs does not lose attribution. The writer fills this in when the
	// caller leaves it empty.
	RunID string `json:"run_id"`

	// Source identifies which subsystem produced the record. One of
	// the FilesystemEventSource* constants. Required so the aggregator
	// can dispatch to the right per-source dedup key.
	Source string `json:"source"`

	// Operation is the verb the agent attempted (read / write / list /
	// delete / exec / stat or a future emitter-specific verb).
	// Required.
	Operation string `json:"operation"`

	// Path is the filesystem path the operation targeted (the value the
	// agent supplied, before any resolve / canonicalize pass). Required:
	// a record with no Path defeats the audit's purpose. Every leaked
	// secret-shaped substring is redacted by the aggregator at
	// leaks.jsonl write time, not here, so this field preserves the
	// original byte sequence for an auditor inspecting the raw stream.
	Path string `json:"path"`

	// ResolvedPath is the canonical / normalized path the enforcer
	// derived from Path (symlinks followed, ".." segments collapsed).
	// Populated when the enforcer resolved the path before deciding
	// (the MCP filesystem scope enforcer's
	// ErrFilesystemPathOutsideWorkspace path); empty when the enforcer
	// rejected on the raw path. Used by the Batch 8.1 aggregator to
	// surface "what the agent really asked for" in leaks.jsonl
	// evidence.
	ResolvedPath string `json:"resolved_path,omitempty"`

	// Decision is the enforcer verdict (FilesystemEventDecisionAllow /
	// Warn / Block). Required.
	Decision string `json:"decision"`

	// Reason is the human-readable explanation for the decision.
	// Required so the audit log is self-contained without joining
	// against the per-subsystem source.
	Reason string `json:"reason"`

	// Server is the MCP server name (when Source ==
	// FilesystemEventSourceMCPGateway). Empty for shim-sourced
	// records.
	Server string `json:"server,omitempty"`

	// Tool is the MCP tool name (when Source ==
	// FilesystemEventSourceMCPGateway). Empty for shim-sourced
	// records.
	Tool string `json:"tool,omitempty"`

	// Program is the resolved binary name the shim was asked to run
	// (when Source == FilesystemEventSourceShim). Empty for MCP-sourced
	// records.
	Program string `json:"program,omitempty"`

	// Argv is the shim-captured argument vector for the program (when
	// Source == FilesystemEventSourceShim). Empty for MCP-sourced
	// records. Encoded as a slice so a downstream parser does not have
	// to re-tokenize a flattened command line.
	Argv []string `json:"argv,omitempty"`

	// TurnID is the supervisor-minted turn identifier in effect at the
	// moment the enforcer reached this verdict (Plan Batch 3.3 — Turn-
	// ID flows). The emitter consults the per-run control socket's
	// CurrentTurnID before forwarding the record so an auditor can
	// correlate each filesystem decision against the agent turn
	// recorded in transcript.jsonl / policy-decisions.jsonl. Empty
	// when no turn source is wired (unit tests, early batches that
	// predate the field) or when the agent has not yet called
	// BeginTurn; readers treat an empty TurnID as "unknown" rather
	// than as a missing field.
	TurnID string `json:"turn_id,omitempty"`

	// PolicyEventID is the opaque per-decision identifier the policy
	// engine mints when the enforcer's verdict was routed through
	// EvaluateShellCommand or a future EvaluateFilesystemAccess. Used
	// by the Batch 8.1 leaks aggregator's dedup key so two writers
	// converging on the same decision are folded into one leak record.
	PolicyEventID string `json:"policy_event_id,omitempty"`

	// Snippet is a short captured byte fragment showing the context
	// that triggered the decision (the matched line of an interpreter-
	// via-file content scan, the offending JSON-RPC argument body). The
	// MCP gateway's secret detector already scrubs secrets out of
	// Snippet before forwarding the record here; the shim's
	// interpreter-via-file scanner does the same. Optional.
	Snippet string `json:"snippet,omitempty"`
}

// FilesystemEventsWriter appends FilesystemEventRecord values to
// filesystem-events.jsonl.
//
// The plan calls for append-only newline-delimited JSON, one record per
// observed filesystem decision, flushed after every write so a crash
// does not lose the FS audit trail. The writer is safe for concurrent
// use: the MCP gateway, the shell shim, and any future scanner emitter
// may all call Write from different goroutines, and the resulting on-
// disk file must contain one well-formed JSON object per line with no
// interleaving.
//
// Construction goes through OpenFilesystemEventsWriter so the file
// handle, the per-run metadata (run ID), and the clock are wired in
// once. The handle stays open for the lifetime of the run; Close is
// the only orderly shutdown path. The supervisor closes the writer
// alongside the lifecycle / network / mcp-calls / policy-decisions
// writers in the post-run drain.
//
// The shape mirrors LifecycleWriter / NetworkEventsWriter /
// MCPCallsWriter / PolicyDecisionsWriter on purpose: a future refactor
// that unifies the per-run JSONL writers can replace all five with one
// generic implementation without touching call sites.
type FilesystemEventsWriter struct {
	// mu serializes writes so concurrent callers cannot interleave
	// bytes inside a single JSON line, even though O_APPEND already
	// protects the file offset on POSIX. The encode + sync sequence is
	// a logical write, not just a byte-level one, so the mutex covers
	// both halves.
	mu sync.Mutex

	// file is the open filesystem-events.jsonl handle. Kept open for
	// the lifetime of the writer so we are not paying open/close per
	// record; closed exactly once by Close.
	file *os.File

	// runID is the run identifier the writer was opened for. Copied
	// into every record's RunID field when the caller left it empty so
	// emitters can submit partially populated records.
	runID string

	// now produces the timestamp stamped on each record when the caller
	// has not pre-populated Timestamp. A function (rather than a clock
	// interface) so tests can inject a deterministic sequence of times;
	// production callers pass time.Now.
	now func() time.Time

	// closed guards Close from racing with itself and prevents Write
	// after Close from panicking on a stale file handle.
	closed bool
}

// FilesystemEventsWriterOptions bundles the per-run metadata a
// FilesystemEventsWriter needs at construction. RunID is required; Now
// is optional and falls back to time.Now when nil.
type FilesystemEventsWriterOptions struct {
	// RunID is the run identifier this writer's records belong to.
	// Required.
	RunID string

	// Now is the clock the writer uses to stamp Timestamp on each
	// record when the caller has not pre-populated the field. Nil
	// falls back to time.Now. Tests inject a fixed-step clock so the
	// on-disk timestamps are deterministic.
	Now func() time.Time
}

// OpenFilesystemEventsWriter opens (or creates and appends to) the
// filesystem-events.jsonl file for the run directory at runDir, wires it
// to the supplied options, and returns a FilesystemEventsWriter ready to
// accept records.
//
// runDir is the absolute path to the run directory (the same value
// RunDirectory.Path carries). The file is opened with O_APPEND so the
// writer cooperates correctly with the empty placeholder
// CreateRunDirectory left in place, and so a reopen of an existing run
// (future replay tooling) adds to the trail rather than truncating it.
//
// Returns an error when the file cannot be opened or when any required
// option is empty. On error no file handle is leaked.
func OpenFilesystemEventsWriter(runDir string, opts FilesystemEventsWriterOptions) (*FilesystemEventsWriter, error) {
	if runDir == "" {
		return nil, errors.New("run: OpenFilesystemEventsWriter requires runDir")
	}
	if opts.RunID == "" {
		return nil, errors.New("run: OpenFilesystemEventsWriter requires RunID")
	}

	path := filepath.Join(runDir, filesystemEventsFileName)
	// O_APPEND so concurrent writes (and the empty placeholder file
	// CreateRunDirectory left behind) compose cleanly; O_CREATE so a
	// caller that constructed the writer against a freshly-rmd
	// directory still gets a working handle rather than a confusing
	// ENOENT.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, runFileMode)
	if err != nil {
		return nil, fmt.Errorf("run: open filesystem events log %s: %w", path, err)
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}

	return &FilesystemEventsWriter{
		file:  f,
		runID: opts.RunID,
		now:   clock,
	}, nil
}

// Write appends a single filesystem event record to the underlying
// filesystem-events.jsonl file. The writer fills in SchemaVersion
// (always FilesystemEventsRecordSchemaVersion), Timestamp (when empty),
// and RunID (when empty) so emitters can submit partially populated
// records and the writer pins the invariants.
//
// The encoded line is a single JSON object followed by exactly one
// newline byte. The plan requires that no buffered record be lost on
// crash, so Write fsyncs the file after a successful append. The mutex
// makes the encode + sync pair atomic with respect to other callers:
// two goroutines emitting concurrently produce two consecutive whole
// lines, never an interleaved one.
//
// Write rejects an empty Source / Operation / Path / Decision / Reason
// so a misconfigured caller fails loudly rather than silently producing
// an unidentifiable record. The five fields together form the audit
// log's "who, what, where, verdict, why" — any one of them missing
// defeats the purpose of having the line on disk.
func (w *FilesystemEventsWriter) Write(rec FilesystemEventRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("run: filesystem events writer is closed")
	}
	if rec.Source == "" {
		return errors.New("run: filesystem event record requires Source")
	}
	if rec.Operation == "" {
		return errors.New("run: filesystem event record requires Operation")
	}
	if rec.Path == "" {
		return errors.New("run: filesystem event record requires Path")
	}
	if rec.Decision == "" {
		return errors.New("run: filesystem event record requires Decision")
	}
	if rec.Reason == "" {
		return errors.New("run: filesystem event record requires Reason")
	}

	// Pin the writer-owned invariants before marshal so the encoded
	// line carries the final field values regardless of what the
	// emitter pre-populated.
	rec.SchemaVersion = FilesystemEventsRecordSchemaVersion
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
		return fmt.Errorf("run: marshal filesystem event record: %w", err)
	}
	line = append(line, '\n')

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("run: append filesystem event record: %w", err)
	}
	// Sync after every record so a crash between records does not
	// erase the FS audit trail. The plan's "no buffering data loss on
	// crash" rule applies uniformly across every per-run JSONL writer;
	// mirroring MCPCallsWriter / NetworkEventsWriter here keeps the
	// contract uniform.
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("run: sync filesystem events log: %w", err)
	}
	return nil
}

// Close closes the underlying filesystem-events.jsonl file. Safe to call
// more than once; the second call is a no-op. Once Close returns,
// further Write calls fail with a clear error so a misbehaving caller
// cannot silently lose records against a closed handle.
//
// The future supervisor-side wiring calls Close from its post-run drain
// after the final terminal state has been recorded; closing earlier
// would drop any late-arriving emitter records (e.g. a teardown-time
// MCP filesystem decision the agent runner emits during MCP server
// shutdown).
func (w *FilesystemEventsWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("run: close filesystem events log: %w", err)
	}
	return nil
}

// FilesystemEventsPath returns the absolute path of the
// filesystem-events.jsonl file inside runDir. Mirrors LifecyclePath /
// NetworkEventsPath / MCPCallsPath / PolicyDecisionsPath / LeaksPath so
// callers (status / report / final-summary, the leaks aggregator) have
// a single helper for the layout.
func FilesystemEventsPath(runDir string) string {
	return filepath.Join(runDir, filesystemEventsFileName)
}

// ReadFilesystemEvents loads every FilesystemEventRecord recorded in
// runDir's filesystem-events.jsonl, in the order they were appended.
// Blank lines (e.g. a trailing newline at EOF) are skipped silently.
//
// ReadFilesystemEvents returns an empty slice and nil when the file
// exists but is empty (the post-CreateRunDirectory placeholder state)
// or absent. A malformed line returns the records read so far plus the
// parse error so a caller can still surface the partial trail.
//
// Mirrors ReadMCPCalls / ReadNetworkEvents / ReadPolicyDecisions: the
// file is small in practice (a handful of decisions per run), so the
// whole-file read is preferable to a streaming parser.
func ReadFilesystemEvents(runDir string) ([]FilesystemEventRecord, error) {
	if runDir == "" {
		return nil, errors.New("run: ReadFilesystemEvents requires runDir")
	}
	path := FilesystemEventsPath(runDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("run: read filesystem events %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	return parseFilesystemEvents(data, path)
}

// parseFilesystemEvents decodes data as JSONL filesystem event records.
// Split out so ReadFilesystemEvents can stay tiny and so tests can
// exercise the parser against in-memory byte slices.
func parseFilesystemEvents(data []byte, path string) ([]FilesystemEventRecord, error) {
	out := make([]FilesystemEventRecord, 0, 8)
	for i, line := range splitJSONLines(data) {
		if len(line) == 0 {
			continue
		}
		var rec FilesystemEventRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return out, fmt.Errorf("run: parse %s line %d: %w", path, i+1, err)
		}
		out = append(out, rec)
	}
	return out, nil
}
