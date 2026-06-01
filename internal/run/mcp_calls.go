// MCP call audit writer (plan 09, step 7).
//
// Every gateway verdict produced by internal/mcp.Gateway lands as one
// JSON line in mcp-calls.jsonl at the root of the run directory. The
// file sits next to lifecycle.jsonl, network-events.jsonl, and
// policy-decisions.jsonl so a reviewer reading a run on disk sees the
// MCP audit trail alongside the other per-run event streams.
//
// The writer mirrors the LifecycleWriter / NetworkEventsWriter /
// PolicyDecisionsWriter pattern (append-only newline-delimited JSON,
// fsync after every record, concurrent-safe via a per-writer mutex)
// so a future refactor that unifies the per-run JSONL writers can
// replace all four with one generic implementation without touching
// call sites.
//
// Architectural note: this file deliberately does not import
// internal/mcp. internal/mcp.CallLogger is defined as a tiny
// interface (Log(CallRecord) error) precisely so the run package can
// own the on-disk shape (MCPCallRecord here) and the file I/O, while
// the mcp package owns the gateway semantics. The bridge that
// satisfies mcp.CallLogger by writing MCPCallRecord lines lives at
// the gateway construction site (today: internal/cli when the gateway
// is wired into an active run; tomorrow: the supervisor once it
// constructs a per-run gateway). The pattern mirrors how the run
// package defines EngineDecision rather than importing
// internal/policy.

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

// mcpCallsFileName is the basename of the per-run MCP call audit log.
// It lives at the root of the run directory next to lifecycle.jsonl,
// network-events.jsonl, and policy-decisions.jsonl so a reviewer
// reading a run on disk sees every event stream side by side. The
// constant mirrors the other per-run filename constants; keeping it
// here rather than redeclaring it in run.go means the MCP calls
// writer is the single owner of the filename even though run.go
// materialized the placeholder.
const mcpCallsFileName = "mcp-calls.jsonl"

// MCP call stage tokens recorded on the Stage field of MCPCallRecord.
// Pinned as constants here so the gateway-side bridge (which copies
// mcp.CallStage values verbatim) and any consumer of mcp-calls.jsonl
// share the canonical spellings. The two values match
// internal/mcp.CallStageLaunch / internal/mcp.CallStageCall on
// purpose; the duplication is the price of keeping the run package
// free of an mcp dependency, and a unit test enforces parity at the
// callsite where the bridge lives.
const (
	// MCPCallStageLaunch is recorded when the gateway answered "may
	// this server be launched?". The record carries the source /
	// digest / schema-hash decision context; Tool / Path / Repo /
	// Operation / ScopeKinds are usually empty.
	MCPCallStageLaunch = "launch"

	// MCPCallStageCall is recorded when the gateway answered "may
	// this tool call proceed?". The record carries the tool name and
	// the scope context the gateway evaluated; the launch-stage
	// fields (Source / Digest) are usually empty because they were
	// already recorded at launch time.
	MCPCallStageCall = "call"
)

// MCP call decision tokens recorded on the Decision field of
// MCPCallRecord. The three values match the gateway's
// GatewayOutcome.String() output ("allow" / "warn" / "block") so a
// future log consumer can grep on the same tokens the gateway emits
// without translation.
const (
	// MCPCallDecisionAllow indicates the gateway permitted the
	// launch / dispatch.
	MCPCallDecisionAllow = "allow"

	// MCPCallDecisionWarn indicates the gateway allowed the launch /
	// dispatch but flagged it (per-server warn policy, schema-hash
	// drift under a warn policy).
	MCPCallDecisionWarn = "warn"

	// MCPCallDecisionBlock indicates the gateway refused the launch
	// / dispatch. The Reason field carries the operator-readable
	// explanation.
	MCPCallDecisionBlock = "block"
)

// MCPCallRecord is one record written to mcp-calls.jsonl. The shape
// is the on-disk projection of internal/mcp.CallRecord; the field
// list, JSON tags, and ordering match byte-for-byte so a gateway-side
// bridge can copy fields one-to-one without translation.
//
// Two record families share the shape:
//
//   - Stage == MCPCallStageLaunch: the gateway answered "may this
//     server start?". Source / Digest / ExpectedHash / ActualHash
//     carry the pinning context. Tool / Path / Repo / Operation /
//     ScopeKinds are empty.
//   - Stage == MCPCallStageCall: the gateway answered "may this tool
//     call proceed?". Tool / Path / Repo / Operation / ScopeKinds
//     carry the scope context. The pinning fields are usually empty.
//
// The Decision field carries one of the MCPCallDecision* tokens; the
// Reason field carries the gateway's free-form explanation. Both are
// required for an operator-readable audit; a record with an empty
// Decision is rejected by the writer.
//
// Architectural note: defining MCPCallRecord here (rather than
// importing internal/mcp.CallRecord) keeps the run package free of an
// mcp dependency, mirroring how EngineDecision is defined here rather
// than imported from internal/policy. The bridge type that satisfies
// mcp.CallLogger lives at the gateway construction site and translates
// between the two shapes; both structs share the same JSON tags so the
// on-disk encoding is identical regardless of which struct produced
// the line.
type MCPCallRecord struct {
	// Timestamp is the moment the gateway reached the decision,
	// formatted as RFC3339 with a numeric offset. The writer fills
	// this in from its clock; callers do not set it themselves.
	Timestamp string `json:"timestamp"`

	// Stage identifies which gateway entry point produced the record.
	// One of MCPCallStageLaunch / MCPCallStageCall. Required.
	Stage string `json:"stage"`

	// Server is the registered server name the decision applies to.
	// Required; even an unknown-server record echoes the caller's
	// supplied name so the audit trail captures what the agent asked
	// for.
	Server string `json:"server"`

	// Decision is the verdict token (MCPCallDecisionAllow /
	// MCPCallDecisionWarn / MCPCallDecisionBlock). Required.
	Decision string `json:"decision"`

	// Reason is the human-readable explanation. Required so the
	// audit log is self-contained without joining against source.
	// Examples: "schema hash mismatch", "filesystem path outside
	// workspace", "unknown server", "server policy deny".
	Reason string `json:"reason"`

	// Tool is the MCP tool name the agent invoked. Populated on
	// MCPCallStageCall records; empty on MCPCallStageLaunch.
	Tool string `json:"tool,omitempty"`

	// Source is the npm: / oci: source the gateway compared against
	// the registered Source. Populated on MCPCallStageLaunch when the
	// caller supplied a candidate.
	Source string `json:"source,omitempty"`

	// Digest is the sha256: digest the gateway compared against the
	// registered Digest. Populated on MCPCallStageLaunch when the
	// caller supplied a candidate and the server has a registered
	// digest.
	Digest string `json:"digest,omitempty"`

	// ExpectedHash is the registered schema hash at decision time.
	// Populated on MCPCallStageLaunch when the caller supplied a
	// live schema hash. Empty for freshly-registered servers
	// (first-launch onboarding).
	ExpectedHash string `json:"expected_hash,omitempty"`

	// ActualHash is the freshly-computed schema hash the caller
	// supplied. Populated on MCPCallStageLaunch when the caller
	// supplied a live schema hash.
	ActualHash string `json:"actual_hash,omitempty"`

	// Path is the filesystem path the call targeted. Populated on
	// MCPCallStageCall when the scope kind is filesystem.
	Path string `json:"path,omitempty"`

	// Repo is the "owner/name" coordinate the call targeted.
	// Populated on MCPCallStageCall when the scope kind is github.
	Repo string `json:"repo,omitempty"`

	// Operation is the GitHub operation kind ("read" / "write").
	// Populated on MCPCallStageCall when the scope kind is github.
	Operation string `json:"operation,omitempty"`

	// ScopeKinds is the sorted list of scope kinds the gateway
	// evaluated for this call ("filesystem", "github"). Populated on
	// MCPCallStageCall so an auditor can see at a glance which
	// enforcers participated in the decision.
	ScopeKinds []string `json:"scope_kinds,omitempty"`

	// TurnID is the supervisor-minted turn identifier in effect at the
	// moment the gateway reached this verdict (Plan Batch 3.3 — Turn-ID
	// flows). The bridge that wires the gateway into a live run
	// consults the per-run control socket's CurrentTurnID(role) before
	// forwarding the record here and stamps the result so an auditor
	// reading mcp-calls.jsonl can correlate each MCP decision against
	// the agent turn recorded in transcript.jsonl /
	// policy-decisions.jsonl. Empty when no turn source is wired (CLI
	// dry-runs via `ai-env mcp scan`, unit tests, or the early plan-09
	// batches that predate the field) or when the agent has not yet
	// called BeginTurn for this run; readers treat an empty TurnID as
	// "unknown" rather than as a missing field. Plan §0 documents the
	// "best-effort under non-compromised agent" caveat: a compromised
	// agent that skips BeginTurn will leave this empty.
	TurnID string `json:"turn_id,omitempty"`

	// ResolvedPath is the canonical / normalized filesystem path the
	// gateway derived from Path. Plan Batch 3.4 enumerates this as one
	// of the payload-derived CallRecord fields the request-direction
	// secret detector must redact when blocking a body that carries a
	// matched secret pattern.
	ResolvedPath string `json:"resolved_path,omitempty"`

	// Snippet is a short captured byte fragment showing the context
	// that triggered the gateway-side decision. Plan Batch 3.4
	// enumerates this as one of the payload-derived CallRecord fields
	// the request-direction secret detector must redact. The on-disk
	// value is the post-redaction string when a secret was detected;
	// raw secrets never reach the audit log.
	Snippet string `json:"snippet,omitempty"`

	// Args is the agent-supplied tool-call arguments blob the gateway
	// forwarded to the enforcer (typically the JSON-RPC "arguments"
	// member of a tools/call request, stringified for the audit log).
	// Plan Batch 3.4 enumerates Args as the highest-risk payload-
	// derived CallRecord field: the request-direction secret detector
	// scans the body and on match rewrites Args to the sentinel
	// before the record is logged.
	Args string `json:"args,omitempty"`
}

// MCPCallsWriter appends MCPCallRecord values to mcp-calls.jsonl.
//
// The plan calls for append-only newline-delimited JSON, one record
// per gateway decision, flushed after every write so a crash does not
// lose the MCP audit trail. The writer is safe for concurrent use:
// the gateway promises serialized Log calls in its own interface
// contract, but a future caller that adopts the writer directly may
// still race two goroutines on it, so the mutex covers the encode +
// sync pair regardless.
//
// Construction goes through OpenMCPCallsWriter so the file handle,
// the per-run metadata (run ID), and the clock are wired in once.
// The handle stays open for the lifetime of the run; Close is the
// only orderly shutdown path. A future supervisor-side wiring closes
// the writer alongside the lifecycle / network / policy-decisions
// writers in the post-run drain.
//
// The shape mirrors LifecycleWriter / NetworkEventsWriter /
// PolicyDecisionsWriter on purpose: a future refactor that unifies
// the per-run JSONL writers can replace all four with one generic
// implementation without touching call sites.
type MCPCallsWriter struct {
	// mu serializes writes so concurrent callers cannot interleave
	// bytes inside a single JSON line, even though O_APPEND already
	// protects the file offset on POSIX. The encode + sync sequence
	// is a logical write, not just a byte-level one, so the mutex
	// covers both halves.
	mu sync.Mutex

	// file is the open mcp-calls.jsonl handle. Kept open for the
	// lifetime of the writer so we are not paying open/close for
	// every record; closed exactly once by Close.
	file *os.File

	// runID is the run identifier the writer was opened for. The
	// per-record MCPCallRecord shape does not carry RunID (it
	// mirrors mcp.CallRecord, which is per-call rather than per-run)
	// but the value is retained here for future expansion and so the
	// constructor can reject a misconfigured caller that omitted the
	// run identifier.
	runID string

	// now produces the timestamp stamped on each record when the
	// caller has not pre-populated MCPCallRecord.Timestamp. A
	// function (rather than a clock interface) so tests can inject a
	// deterministic sequence of times without a separate type;
	// production callers pass time.Now.
	now func() time.Time

	// closed guards Close from racing with itself and prevents Write
	// after Close from panicking on a stale file handle.
	closed bool
}

// MCPCallsWriterOptions bundles the per-run metadata an MCPCallsWriter
// needs at construction. RunID is required; Now is optional and falls
// back to time.Now when nil.
type MCPCallsWriterOptions struct {
	// RunID is the run identifier this writer's records belong to.
	// Required.
	RunID string

	// Now is the clock the writer uses to stamp Timestamp on each
	// record when the caller has not pre-populated the field. Nil
	// falls back to time.Now. Tests inject a fixed-step clock so the
	// on-disk timestamps are deterministic.
	Now func() time.Time
}

// OpenMCPCallsWriter opens (or creates and appends to) the
// mcp-calls.jsonl file for the run directory at runDir, wires it to
// the supplied options, and returns an MCPCallsWriter ready to
// accept records.
//
// runDir is the absolute path to the run directory (the same value
// RunDirectory.Path carries). The file is opened with O_APPEND so
// the writer cooperates correctly with the empty placeholder
// CreateRunDirectory left in place, and so a reopen of an existing
// run (future replay tooling) adds to the trail rather than
// truncating it.
//
// Returns an error when the file cannot be opened or when any
// required option is empty. On error no file handle is leaked.
func OpenMCPCallsWriter(runDir string, opts MCPCallsWriterOptions) (*MCPCallsWriter, error) {
	if runDir == "" {
		return nil, errors.New("run: OpenMCPCallsWriter requires runDir")
	}
	if opts.RunID == "" {
		return nil, errors.New("run: OpenMCPCallsWriter requires RunID")
	}

	path := filepath.Join(runDir, mcpCallsFileName)
	// O_APPEND so concurrent writes (and the once-placeholder file
	// CreateRunDirectory left behind) compose cleanly; O_CREATE so a
	// caller that constructed the writer against a freshly-rmd
	// directory still gets a working handle rather than a confusing
	// ENOENT.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, runFileMode)
	if err != nil {
		return nil, fmt.Errorf("run: open mcp calls log %s: %w", path, err)
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}

	return &MCPCallsWriter{
		file:  f,
		runID: opts.RunID,
		now:   clock,
	}, nil
}

// Write appends a single MCP call record to the underlying
// mcp-calls.jsonl file. The writer fills in Timestamp from its clock
// when the caller did not pre-populate it (the gateway already stamps
// its own Timestamp, so the typical bridge passes the value through);
// every other field comes from the caller's rec verbatim.
//
// The encoded line is a single JSON object followed by exactly one
// newline byte. The plan requires that no buffered record be lost on
// crash, so Write fsyncs the file after a successful append. The
// mutex makes the encode + sync pair atomic with respect to other
// callers: two goroutines emitting concurrently produce two
// consecutive whole lines, never an interleaved one.
//
// Write rejects an empty Stage, Server, or Decision so a
// misconfigured caller fails loudly rather than silently producing
// an unidentifiable record. Reason is also required because an audit
// log without a per-record explanation defeats the purpose of having
// it on disk.
func (w *MCPCallsWriter) Write(rec MCPCallRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("run: mcp calls writer is closed")
	}
	if rec.Stage == "" {
		return errors.New("run: mcp call record requires Stage")
	}
	if rec.Server == "" {
		return errors.New("run: mcp call record requires Server")
	}
	if rec.Decision == "" {
		return errors.New("run: mcp call record requires Decision")
	}
	if rec.Reason == "" {
		return errors.New("run: mcp call record requires Reason")
	}

	// Fill in Timestamp only when the caller has not already pinned
	// it. The gateway stamps its own RFC3339 timestamp before
	// constructing the CallRecord, and the bridge copies it through
	// verbatim; preserving a non-empty caller-supplied value means
	// the on-disk timestamp matches the gateway's decision time
	// exactly rather than the writer's append time (which could be
	// slightly later under load).
	if rec.Timestamp == "" {
		rec.Timestamp = w.now().Format(time.RFC3339)
	}

	// Marshal then a single Write keeps the JSON object + newline as
	// one syscall, matching the O_APPEND atomicity guarantee on
	// POSIX (writes up to PIPE_BUF are atomic; a typical record is
	// well under that). A streaming json.Encoder would emit its own
	// newline but would also stream in chunks under the hood.
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("run: marshal mcp call record: %w", err)
	}
	line = append(line, '\n')

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("run: append mcp call record: %w", err)
	}
	// Sync after every record so a crash between records does not
	// erase the MCP audit trail. The plan's "no buffering data loss
	// on crash" rule applies uniformly across every per-run JSONL
	// writer; mirroring LifecycleWriter / NetworkEventsWriter /
	// PolicyDecisionsWriter here keeps the contract uniform.
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("run: sync mcp calls log: %w", err)
	}
	return nil
}

// Close closes the underlying mcp-calls.jsonl file. Safe to call
// more than once; the second call is a no-op. Once Close returns,
// further Write calls fail with a clear error so a misbehaving
// caller cannot silently lose records against a closed handle.
//
// The future supervisor-side wiring calls Close from its post-run
// drain after the final terminal state has been recorded; closing
// earlier would drop any late-arriving gateway records (e.g. a
// teardown-time AuthorizeCall the agent runner emits during MCP
// server shutdown).
func (w *MCPCallsWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("run: close mcp calls log: %w", err)
	}
	return nil
}

// MCPCallsPath returns the absolute path of the mcp-calls.jsonl file
// inside runDir. Mirrors LifecyclePath / NetworkEventsPath /
// PolicyDecisionsPath so callers (status / report / final-summary)
// have a single helper for the layout.
func MCPCallsPath(runDir string) string {
	return filepath.Join(runDir, mcpCallsFileName)
}

// ReadMCPCalls loads every MCPCallRecord recorded in runDir's
// mcp-calls.jsonl, in the order they were appended. Blank lines
// (e.g. a trailing newline at EOF) are skipped silently.
//
// ReadMCPCalls returns an empty slice and nil when the file exists
// but is empty (the post-CreateRunDirectory placeholder state) or
// absent. A malformed line returns the records read so far plus the
// parse error so a caller can still surface the partial trail.
//
// Mirrors ReadLifecycleEvents / ReadNetworkEvents /
// ReadPolicyDecisions: the file is small in practice (a handful of
// launches plus per-call decisions), so the whole-file read is
// preferable to a streaming parser.
func ReadMCPCalls(runDir string) ([]MCPCallRecord, error) {
	if runDir == "" {
		return nil, errors.New("run: ReadMCPCalls requires runDir")
	}
	path := MCPCallsPath(runDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("run: read mcp calls %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	return parseMCPCalls(data, path)
}

// parseMCPCalls decodes data as JSONL MCP call records. Split out so
// ReadMCPCalls can stay tiny and so tests can exercise the parser
// against in-memory byte slices.
func parseMCPCalls(data []byte, path string) ([]MCPCallRecord, error) {
	out := make([]MCPCallRecord, 0, 8)
	for i, line := range splitJSONLines(data) {
		if len(line) == 0 {
			continue
		}
		var rec MCPCallRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return out, fmt.Errorf("run: parse %s line %d: %w", path, i+1, err)
		}
		out = append(out, rec)
	}
	return out, nil
}
