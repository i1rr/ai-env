// MCP gateway audit-logger bridge (plan 09, step 7).
//
// internal/mcp.Gateway logs every decision through the small
// mcp.CallLogger interface (Log(mcp.CallRecord) error). The on-disk
// audit stream lives in run.MCPCallsWriter, which is owned by
// internal/run and intentionally does not import internal/mcp (the
// two packages stay decoupled so a refactor of either side does not
// drag the other in). The bridge defined here is the glue: it
// satisfies mcp.CallLogger, accepts mcp.CallRecord values, copies the
// fields one-to-one into run.MCPCallRecord, and forwards them to the
// underlying MCPCallsWriter.
//
// Field mapping rule: every field on mcp.CallRecord has a same-named
// counterpart on run.MCPCallRecord with an identical JSON tag, so the
// on-disk encoding is byte-identical regardless of which struct the
// line was marshaled from. The Stage and Decision fields are typed
// strings on mcp.CallRecord (mcp.CallStage / token from
// GatewayOutcome.String()); the bridge unwraps each to its underlying
// string so the run-package shape stays primitive.
//
// Lifecycle: a caller constructs the bridge once per run (alongside
// the supervisor's other per-run writers), holds the returned
// *MCPCallLogger for the lifetime of the run, passes it into
// mcp.GatewayOptions.Logger when constructing the gateway, and closes
// the underlying writer in the post-run drain. The bridge itself is
// stateless beyond its writer reference; closing the writer is the
// only cleanup needed.

package cli

import (
	"errors"

	"github.com/i1rr/ai-env/internal/mcp"
	"github.com/i1rr/ai-env/internal/run"
)

// MCPCallLogger is the bridge that satisfies internal/mcp.CallLogger
// by forwarding every record to a run.MCPCallsWriter. Construct one
// per run with NewMCPCallLogger and pass it into
// mcp.GatewayOptions.Logger so every AuthorizeLaunch / AuthorizeCall
// verdict lands in mcp-calls.jsonl.
//
// The bridge is safe for concurrent use: it adds no state beyond the
// writer pointer, and MCPCallsWriter.Write is already concurrent-safe
// (it serializes through its own mutex). Two gateway goroutines
// calling Log concurrently produce two consecutive whole lines, never
// an interleaved one.
type MCPCallLogger struct {
	// writer is the run-scoped audit sink the bridge forwards records
	// to. Never nil after NewMCPCallLogger; the constructor rejects a
	// nil writer rather than substituting a no-op so a misconfigured
	// caller fails loudly.
	writer *run.MCPCallsWriter

	// turnSource, when non-nil, is the per-run turn-id source the
	// bridge consults at log time to stamp MCPCallRecord.TurnID. Wired
	// by BuildRunGateway from the supervisor's ControlSocket so every
	// gateway decision lands the same turn id the transcript writer
	// (Plan §0 / Plan §7) sees. Nil for dry-run / unit-test bridges
	// that have no control socket; in that case TurnID stays empty,
	// which readers treat as "unknown" per the field doc.
	turnSource TurnSource

	// turnRole names the per-role counter the bridge reads from
	// turnSource. Defaults to DefaultTurnRole when empty so the legacy
	// per-run callers do not have to thread the role through every
	// call. Non-empty matches the role string the supervisor passed to
	// BeginTurn (the control socket isolates counters per role so
	// multi-agent runs do not collide on a single sequence).
	turnRole string
}

// DefaultTurnRole is the default role string the gateway bridge passes
// to TurnSource.CurrentTurnID when MCPCallLoggerOptions.TurnRole is
// empty. Matches the control socket's default role on the BeginTurn /
// CurrentTurn handlers (run.ControlSocket): the empty string is
// rewritten to "agent" on the socket side, and the bridge mirrors the
// convention so both ends of the bridge see the same counter family.
// Exported so the supervisor wiring site can override it explicitly
// without retyping the literal.
const DefaultTurnRole = "agent"

// TurnSource is the supervisor-side accessor MCPCallLogger consults to
// stamp a turn id on every record. *run.ControlSocket satisfies the
// interface via its CurrentTurnID method (Plan Batch 3.3 — Turn-ID
// flows); a test fake can substitute a closure that returns canned
// values.
//
// Implementations:
//
//   - must be safe for concurrent CurrentTurnID calls (the bridge is
//     called from gateway goroutines servicing parallel tool calls);
//   - must return "" when no turn has been allocated yet for the
//     requested role — the bridge interprets the empty string as
//     "no turn id available" and leaves MCPCallRecord.TurnID empty;
//   - must never panic on an unknown role: the bridge passes whatever
//     MCPCallLoggerOptions.TurnRole the caller supplied, and a typo
//     should yield an empty result, not a runtime failure.
type TurnSource interface {
	// CurrentTurnID returns the most recent turn id allocated for the
	// supplied role. Empty when no turn has started yet. The bridge
	// uses this value to stamp MCPCallRecord.TurnID at log time.
	CurrentTurnID(role string) string
}

// TurnSourceFunc is a function adapter so callers can pass a closure
// where a TurnSource is required (mirrors http.HandlerFunc / the
// existing ShellEvaluatorFunc on the control socket).
type TurnSourceFunc func(role string) string

// CurrentTurnID implements TurnSource by forwarding to the underlying
// function.
func (f TurnSourceFunc) CurrentTurnID(role string) string {
	return f(role)
}

// MCPCallLoggerOptions bundles the optional construction inputs the
// bridge consumes. Pass nil to NewMCPCallLogger for the legacy "writer-
// only, no turn stamping" behavior; pass a populated value to wire the
// turn-id source (Plan Batch 3.3).
type MCPCallLoggerOptions struct {
	// TurnSource is the per-run accessor the bridge consults at log
	// time to stamp MCPCallRecord.TurnID. Nil leaves TurnID empty on
	// every record (the legacy plan-09 behavior); the supervisor's
	// BuildRunGateway wires *run.ControlSocket here once Plan Batch
	// 3.3 lands.
	TurnSource TurnSource

	// TurnRole is the role string the bridge passes to
	// TurnSource.CurrentTurnID. Empty falls back to DefaultTurnRole so
	// the production path does not have to repeat the literal. Test
	// fixtures that drive a custom role (e.g. "subagent") set this
	// explicitly.
	TurnRole string
}

// NewMCPCallLogger wraps writer in a bridge that satisfies
// mcp.CallLogger. writer must be non-nil; passing a nil writer is a
// programming error (the supervisor calls OpenMCPCallsWriter
// up-front, just like the other per-run writers, and a nil here means
// the call site forgot to wire it in).
//
// The bridge does not take ownership of writer's lifetime: the caller
// is responsible for calling writer.Close in the post-run drain. This
// matches the LifecycleWriter / NetworkEventsWriter / PolicyDecisionsWriter
// pattern (the supervisor owns the file handles; helpers receive the
// writer by reference).
func NewMCPCallLogger(writer *run.MCPCallsWriter) (*MCPCallLogger, error) {
	return NewMCPCallLoggerWithOptions(writer, nil)
}

// NewMCPCallLoggerWithOptions is the Plan Batch 3.3 entry point: it
// constructs a bridge wired with an optional TurnSource so every Log
// call stamps the current turn id on the on-disk MCPCallRecord. The
// supervisor's BuildRunGateway calls this constructor with the
// run-scoped *run.ControlSocket as the TurnSource; legacy / unit-test
// callers continue to call NewMCPCallLogger (opts == nil) and see the
// pre-3.3 behavior (TurnID stays empty).
//
// writer must be non-nil; passing a nil writer is a programming error
// regardless of whether opts is supplied. opts may be nil to mean "no
// turn stamping, default role" (identical to NewMCPCallLogger).
//
// The bridge does not take ownership of writer's lifetime: the caller
// is responsible for calling writer.Close in the post-run drain, same
// as NewMCPCallLogger.
func NewMCPCallLoggerWithOptions(writer *run.MCPCallsWriter, opts *MCPCallLoggerOptions) (*MCPCallLogger, error) {
	if writer == nil {
		return nil, errors.New("cli: NewMCPCallLogger requires a non-nil writer")
	}
	logger := &MCPCallLogger{writer: writer, turnRole: DefaultTurnRole}
	if opts != nil {
		logger.turnSource = opts.TurnSource
		if opts.TurnRole != "" {
			logger.turnRole = opts.TurnRole
		}
	}
	return logger, nil
}

// Log implements mcp.CallLogger by translating rec into the on-disk
// MCPCallRecord shape and forwarding it to the underlying writer.
//
// Field-by-field mapping:
//
//   - mcp.CallStage (typed string) -> MCPCallRecord.Stage (plain
//     string).
//   - mcp.CallRecord.Decision (already a plain string with values
//     "allow" / "warn" / "block") -> MCPCallRecord.Decision verbatim.
//   - Every other field is copied through unchanged; the JSON tags
//     match on both structs so the on-disk encoding is identical to
//     what a direct mcp.CallRecord marshal would produce.
//
// The writer's own validation enforces Stage / Server / Decision /
// Reason non-emptiness; the gateway always populates those, so the
// bridge does not duplicate the check.
//
// A non-nil error means the underlying file write failed; the
// gateway surfaces this to the supervisor so a missing audit trail
// can abort the run rather than continue silently.
func (l *MCPCallLogger) Log(rec mcp.CallRecord) error {
	// Plan Batch 3.3 (Turn-ID flows): when a TurnSource is wired the
	// bridge stamps the supervisor-minted turn id onto the record at
	// log time. The gateway itself is turn-unaware (it would otherwise
	// have to import a run-package handle); the bridge owns the
	// correlation because it already owns the run-scoped translation.
	//
	// Precedence: a caller that pre-populated rec.TurnID (e.g. an MCP
	// helper that received a turn id on its own RPC and forwarded it
	// via the GatewayRequest) wins. The fallback consults the
	// per-bridge TurnSource against the per-bridge Role; an empty
	// result leaves rec.TurnID empty so an auditor reading the file
	// can distinguish "no turn yet" from "turn unknown".
	turnID := rec.TurnID
	if turnID == "" && l.turnSource != nil {
		turnID = l.turnSource.CurrentTurnID(l.turnRole)
	}
	return l.writer.Write(run.MCPCallRecord{
		Timestamp:    rec.Timestamp,
		Stage:        string(rec.Stage),
		Server:       rec.Server,
		Decision:     rec.Decision,
		Reason:       rec.Reason,
		Tool:         rec.Tool,
		Source:       rec.Source,
		Digest:       rec.Digest,
		ExpectedHash: rec.ExpectedHash,
		ActualHash:   rec.ActualHash,
		Path:         rec.Path,
		Repo:         rec.Repo,
		Operation:    rec.Operation,
		ScopeKinds:   rec.ScopeKinds,
		TurnID:       turnID,
		// Plan Batch 3.4 — payload-derived fields. The gateway-side
		// secret detector populates these from the agent-supplied body
		// (already redacted when a secret was matched) so the on-disk
		// audit record carries the structural shape without the leaked
		// value.
		ResolvedPath: rec.ResolvedPath,
		Snippet:      rec.Snippet,
		Args:         rec.Args,
	})
}

// Compile-time guard: MCPCallLogger must satisfy mcp.CallLogger so a
// future refactor of the interface surfaces here rather than at the
// call site that passes the bridge into GatewayOptions.Logger.
var _ mcp.CallLogger = (*MCPCallLogger)(nil)
