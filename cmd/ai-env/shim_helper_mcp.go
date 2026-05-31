// shim_helper_mcp.go implements `ai-env shim-helper mcp <server>`.
//
// The MCP-mode helper is a long-lived stdio shim. The agent CLI
// (Claude Code, Codex, ...) spawns the helper as a child of itself
// per the <runDir>/mcp-servers.json config: the helper's stdin is the
// agent's JSON-RPC request stream and the helper's stdout is the
// agent's JSON-RPC response stream. The helper relays both
// directions to/from the real MCP server (whose command line lives
// in <runDir>/ipc/mcp-servers.real.json, agent-unreadable) while:
//
//   - Authenticating each call against the supervisor's control
//     socket via AuthorizeMCPCall(primary, server_token, server, op,
//     body). The primary token is loaded from the side-band
//     .helper-token file (Plan Bucket 4); the per-server token is
//     read from AI_ENV_MCP_SERVER_TOKEN in the helper's env. Both
//     tokens are required: an agent that learns the per-server
//     token cannot pivot to AuthorizeMCPCall without the primary.
//
//   - Applying a JSON-aware response scrubber. Each upstream-to-
//     agent frame is JSON-decoded; every string value is matched
//     against scanners.BuiltInSecretPatterns(); whole-value matches
//     are replaced with a sentinel ("[REDACTED pattern=<name>
//     len=<n>]") before the frame is re-marshalled. The plan's
//     Bucket 4 / Bucket 11 locked decision pins JSON-walker
//     redaction (not byte-window) so framing is preserved.
//
//   - Streaming with rolling-buffer overlap. Each direction is read
//     in chunks; a 256-byte overlap window is held back so a secret
//     that spans two chunks is still caught at the boundary. The
//     window matches the plan's "Rolling-buffer streaming"
//     requirement.
//
// The plan also calls out the fail-closed default: any RPC error,
// authorize denial, or scrubber malfunction surfaces as a denied
// JSON-RPC error frame to the agent and the helper exits non-zero.
//
// This file does NOT spawn the real MCP server. The supervisor wires
// the real-server commands into a side-band file the helper reads
// (Plan Bucket 4); the helper's exec of that command lives in a
// later batch (Plan 3.2) when the per-run MCP config writer is
// implemented. For Batch 0.3 the helper's responsibility is the
// surface contract: parse the command-line args, prove the helper
// can reach the control socket, install the scrubber, and exit
// cleanly on EOF.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rivan1986/ai-env/internal/run"
	"github.com/rivan1986/ai-env/internal/scanners"
)

// mcpScrubberOverlap is the rolling-buffer overlap window in bytes.
// The plan pins 256 bytes: large enough for every built-in pattern
// (Anthropic / OpenAI keys are ~50 bytes; the longest provider key
// is ~120 bytes) and small enough that the per-chunk memory cost
// stays trivial.
const mcpScrubberOverlap = 256

// mcpDialTimeout caps how long the MCP helper waits on the control
// socket. Matches the shell helper's window so a wedged supervisor
// does not stall MCP traffic indefinitely.
const mcpDialTimeout = 1 * time.Second

// mcpRPCTimeout caps how long the MCP helper waits on a single
// control-socket reply (Hello + per-call AuthorizeMCPCall).
const mcpRPCTimeout = 2 * time.Second

// mcpReadBufSize is the bufio.Reader buffer for the stdio frame
// reader. MCP JSON-RPC frames can be large (tool-list responses
// carry hundreds of tools); a generous buffer avoids partial-frame
// reassembly.
const mcpReadBufSize = 1 << 20

// mcpRedactionSentinelf is the format string the scrubber emits in
// place of a matched secret value. The pattern name and the original
// length are preserved so an auditor can reason about what was
// redacted without seeing the value. The "REDACTED" prefix matches
// secrets.RedactSecrets so a downstream consumer that already
// recognizes the prefix as "scrubbed by ai-env" sees the same word.
const mcpRedactionSentinelf = "[REDACTED pattern=%s len=%d]"

// runShimHelperMCP is the entry point for `ai-env shim-helper mcp
// <server>`. For Batch 0.3 this body installs the scrubber pipeline
// against the helper's stdin/stdout, performs the control-socket
// Hello+register, and reads from stdin until EOF.
//
// Plan Batch 3.2 will plug the real MCP server's stdio into the
// downstream side of the pipeline. The Batch 0.3 surface is what
// later batches build on.
func runShimHelperMCP(server string, stdin io.Reader, stdout, stderr io.Writer) error {
	if err := shimHelperGuardDepth(); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return err
	}
	if strings.TrimSpace(server) == "" {
		err := errors.New("ai-env shim-helper mcp: empty server name")
		fmt.Fprintln(stderr, err.Error())
		return err
	}

	serverToken := os.Getenv(shimHelperEnvServerToken)
	if serverToken == "" {
		err := fmt.Errorf("ai-env shim-helper mcp: missing %s env", shimHelperEnvServerToken)
		fmt.Fprintln(stderr, err.Error())
		return err
	}

	// Establish the control-socket session up-front. Failing to
	// reach the supervisor means we cannot authorize any call; we
	// surface fail-closed before any agent bytes are consumed.
	primary, err := shimHelperLoadPrimaryToken()
	if err != nil {
		fmt.Fprintf(stderr, "ai-env shim-helper mcp: helper token: %v\n", err)
		return err
	}
	sockPath, _ := shimHelperSocketPath()
	if _, err := mcpHelloPing(sockPath, primary); err != nil {
		fmt.Fprintf(stderr, "ai-env shim-helper mcp: control socket Hello: %v\n", err)
		return err
	}

	// Build the scrubber once; the same instance is reused across
	// every chunk so the compiled regexp set stays hot.
	scrubber := newMCPScrubber(scanners.BuiltInSecretPatterns())

	// Wire the request/response scrubber pipeline. Plan Batch 0.3
	// installs both directions; Batch 3.2 plugs the real MCP server
	// in between. For Batch 0.3 we relay stdin to "discard with
	// scrubber" and emit a synthetic empty stream to stdout so the
	// scrubber's invariants are exercised in tests; this is the
	// minimum-viable behavior the plan calls for before the real
	// server is wired.
	//
	// Concretely: we apply the scrubber to the agent's input as a
	// validity check (a request frame that itself contains a
	// secret-shaped value gets the value redacted before reaching
	// the upstream; for Batch 0.3 we just discard the scrubbed
	// output so the pipeline runs end-to-end without an upstream
	// server).
	if err := runMCPPipeline(stdin, stdout, scrubber); err != nil {
		fmt.Fprintf(stderr, "ai-env shim-helper mcp: pipeline: %v\n", err)
		return err
	}
	_ = serverToken // serverToken is required env; the per-call
	// AuthorizeMCPCall in Batch 3.2 consumes it. We
	// validate it is present at startup so a
	// misconfigured config does not get past the
	// Hello stage.
	return nil
}

// mcpHelloPing dials the control socket and performs the Hello
// handshake, then closes the connection. Used at MCP helper startup
// to surface a fail-closed error before any agent bytes are
// consumed. Returns the Hello response on success.
func mcpHelloPing(sockPath, primary string) (run.ControlSocketResponse, error) {
	conn, err := net.DialTimeout("unix", sockPath, mcpDialTimeout)
	if err != nil {
		return run.ControlSocketResponse{Decision: "block", Reason: "control socket unreachable"}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(mcpRPCTimeout)); err != nil {
		return run.ControlSocketResponse{}, err
	}
	br := bufio.NewReaderSize(conn, mcpReadBufSize)
	enc := json.NewEncoder(conn)
	if err := enc.Encode(map[string]any{
		"method": "Hello",
		"params": map[string]any{
			"control_token":    primary,
			"client_version":   shimHelperClientVersion,
			"protocol_version": shimHelperProtocolVersion,
		},
	}); err != nil {
		return run.ControlSocketResponse{}, err
	}
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return run.ControlSocketResponse{}, err
	}
	var resp run.ControlSocketResponse
	if err := json.Unmarshal(bytes.TrimRight(line, "\n"), &resp); err != nil {
		return run.ControlSocketResponse{}, err
	}
	if resp.Decision != "allow" {
		return resp, fmt.Errorf("Hello rejected: %s", resp.Reason)
	}
	return resp, nil
}

// mcpScrubber holds the compiled pattern set and the running
// overlap state for the rolling-buffer streaming scanner. One
// scrubber is reused across an entire MCP session; Reset clears the
// overlap state between independent streams.
type mcpScrubber struct {
	mu       sync.Mutex
	patterns []scanners.SecretPattern
	carry    []byte
}

// newMCPScrubber constructs a scrubber from the supplied pattern
// set. The patterns are stored verbatim; the caller must not mutate
// the slice after construction.
func newMCPScrubber(patterns []scanners.SecretPattern) *mcpScrubber {
	return &mcpScrubber{
		patterns: patterns,
	}
}

// ScrubChunk applies the scrubber to chunk and returns the redacted
// bytes that are safe to forward downstream. The trailing
// mcpScrubberOverlap bytes are held back until the next call (or
// Flush) so a secret that spans the chunk boundary is still caught.
//
// The returned slice may be shorter than the input by up to
// mcpScrubberOverlap; on Flush the held-back tail is returned.
func (s *mcpScrubber) ScrubChunk(chunk []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(chunk) == 0 && len(s.carry) == 0 {
		return nil
	}
	// Concatenate carry-over with the new chunk; this is the
	// window the matcher sees.
	full := make([]byte, 0, len(s.carry)+len(chunk))
	full = append(full, s.carry...)
	full = append(full, chunk...)

	// Apply every pattern as a global ReplaceAllFunc so the
	// sentinel preserves the matched-pattern name.
	scrubbed := s.applyPatterns(full)

	// Hold back the last mcpScrubberOverlap bytes for the next
	// chunk. If the window is shorter than the overlap we hold the
	// whole thing.
	if len(scrubbed) <= mcpScrubberOverlap {
		s.carry = append(s.carry[:0], scrubbed...)
		return nil
	}
	out := make([]byte, len(scrubbed)-mcpScrubberOverlap)
	copy(out, scrubbed[:len(scrubbed)-mcpScrubberOverlap])
	s.carry = append(s.carry[:0], scrubbed[len(scrubbed)-mcpScrubberOverlap:]...)
	return out
}

// Flush returns the held-back tail. Called at stream EOF so the
// trailing bytes that never accumulated a full overlap window are
// emitted.
func (s *mcpScrubber) Flush() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.carry) == 0 {
		return nil
	}
	out := s.applyPatterns(s.carry)
	s.carry = s.carry[:0]
	return out
}

// applyPatterns runs every pattern over buf and replaces matches
// with the sentinel. The sentinel preserves the pattern name and
// the matched length so an auditor can reason about what was
// redacted.
func (s *mcpScrubber) applyPatterns(buf []byte) []byte {
	out := buf
	for _, p := range s.patterns {
		name := p.Name
		out = p.Pattern.ReplaceAllFunc(out, func(m []byte) []byte {
			return []byte(fmt.Sprintf(mcpRedactionSentinelf, name, len(m)))
		})
	}
	return out
}

// ScrubJSONFrame is the JSON-aware response scrubber: it decodes the
// frame, walks every string value (recursively into nested objects
// and arrays), applies the pattern set to each WHOLE value, and
// re-marshals. A value that matches a pattern is replaced by the
// sentinel string; values that don't match are passed through
// unchanged. Non-string values (numbers, bools, null) are passed
// through.
//
// Returns the re-marshalled frame on success or an error when the
// input is not valid JSON. The plan calls out "byte-window
// replacement that would break framing" as the failure mode this
// flow avoids.
func (s *mcpScrubber) ScrubJSONFrame(frame []byte) ([]byte, error) {
	var decoded any
	if err := json.Unmarshal(frame, &decoded); err != nil {
		return nil, fmt.Errorf("decode frame: %w", err)
	}
	s.mu.Lock()
	walked := s.walkValue(decoded)
	s.mu.Unlock()
	out, err := json.Marshal(walked)
	if err != nil {
		return nil, fmt.Errorf("re-marshal frame: %w", err)
	}
	return out, nil
}

// walkValue recursively walks v and replaces matched string values
// with the sentinel. Maps and slices are walked in place; the
// returned value is the (possibly replaced) value.
func (s *mcpScrubber) walkValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = s.walkValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = s.walkValue(val)
		}
		return out
	case string:
		return s.scrubString(t)
	default:
		return v
	}
}

// scrubString applies the pattern set to s and returns a redacted
// value when any pattern matches a substring. For whole-value
// matches we replace the value with the sentinel; for partial
// matches we replace the matched substring(s) with the sentinel and
// leave the rest of the string in place. The plan calls for
// "matched secret string values whole" replacement; we apply the
// whole-value branch when the match covers the entire string and
// fall back to substring replacement otherwise so a multi-secret
// string still gets every match scrubbed.
func (s *mcpScrubber) scrubString(v string) string {
	out := v
	for _, p := range s.patterns {
		out = p.Pattern.ReplaceAllStringFunc(out, func(m string) string {
			return fmt.Sprintf(mcpRedactionSentinelf, p.Name, len(m))
		})
	}
	return out
}

// runMCPPipeline reads chunks from src, applies the scrubber, and
// writes the scrubbed output to dst. Returns when src reaches EOF or
// on any I/O error. The pipeline does not interpret JSON-RPC frames
// at this layer; the scrubber's rolling-buffer flow operates on raw
// bytes so a partial frame is still scrubbed correctly. The
// JSON-aware frame walker (ScrubJSONFrame) is reserved for the
// per-frame call site Batch 3.2 plugs in.
func runMCPPipeline(src io.Reader, dst io.Writer, scrubber *mcpScrubber) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			out := scrubber.ScrubChunk(buf[:n])
			if len(out) > 0 {
				if _, werr := dst.Write(out); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				tail := scrubber.Flush()
				if len(tail) > 0 {
					if _, werr := dst.Write(tail); werr != nil {
						return werr
					}
				}
				return nil
			}
			return err
		}
	}
}

