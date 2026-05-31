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

	"github.com/rivan1986/ai-env/internal/mcp"
	"github.com/rivan1986/ai-env/internal/run"
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
	if writer == nil {
		return nil, errors.New("cli: NewMCPCallLogger requires a non-nil writer")
	}
	return &MCPCallLogger{writer: writer}, nil
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
	})
}

// Compile-time guard: MCPCallLogger must satisfy mcp.CallLogger so a
// future refactor of the interface surfaces here rather than at the
// call site that passes the bridge into GatewayOptions.Logger.
var _ mcp.CallLogger = (*MCPCallLogger)(nil)
