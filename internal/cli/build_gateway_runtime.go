// Build the per-run MCP runtime surface (Plan Batch 3.2).
//
// build_gateway.go (Batch 3.1) constructs the in-memory mcp.Gateway,
// the on-disk audit writer, and the turn-id bridge. It deliberately
// did NOT mint per-server tokens, write `<runDir>/mcp-servers.json`,
// install the side-band helper-token file, or shadow workspace MCP
// configs — those concerns were left to this batch.
//
// What this file adds:
//
//   - GatewayMCPAuthorizer: the run.MCPAuthorizer adapter that lets
//     the control socket's AuthorizeMCPCall handler call into the
//     in-memory mcp.Gateway. The control socket has already verified
//     the (server_token, server) pair before calling Authorize; this
//     adapter just decodes the JSON-RPC body, maps it to an
//     mcp.CallRequest, and forwards to gw.AuthorizeCall.
//
//   - MaterializeRunGateway: the side-effecting writer the
//     supervisor's pre-launch step 9 (Plan §5.5) calls AFTER
//     BuildRunGateway. It mints one per-server token per registered
//     server via ControlSocket.MintServerToken, writes the agent-
//     visible `mcp-servers.json`, the host-only
//     `mcp-servers.real.json`, and the side-band `.helper-token`
//     file, and shadows workspace-local MCP configs so the agent
//     CLI's auto-merge cannot reintroduce a server bypassing the
//     supervisor.
//
// The two halves are intentionally separated: BuildRunGateway
// constructs the in-memory wiring that can be exercised in unit tests
// without standing up a real runDir / control socket / workspace;
// MaterializeRunGateway is the side-effecting wiring that needs all
// three. The supervisor's pre-launch step 9 calls both in sequence.

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/i1rr/ai-env/internal/mcp"
	"github.com/i1rr/ai-env/internal/run"
	"github.com/i1rr/ai-env/internal/scanners"
)

// osRemoveFunc and isNotExistFunc are stdlib wrappers exposed as
// package variables so the cleanup paths stay testable. Production
// callers use the stdlib values directly; a future test that wants
// to inject an os.Remove failure can rebind these.
var (
	osRemoveFunc   = os.Remove
	isNotExistFunc = os.IsNotExist
)

// GatewayMCPAuthorizer adapts an *mcp.Gateway to the run.MCPAuthorizer
// interface so the control socket's AuthorizeMCPCall handler can
// forward decoded calls into the in-memory gateway.
//
// The control socket has already verified the (server_token, server)
// pair before calling Authorize, so this adapter trusts the server
// name; it only needs to decode the JSON-RPC body, map the
// MCP-tool-call fields onto an mcp.CallRequest, and forward to
// gw.AuthorizeCall.
//
// Plan Batch 3.4 wires the request-direction secret detector inline
// with Authorize: before the body is forwarded to the in-memory
// gateway, every call's body is scanned via
// scanners.BuiltInSecretPatterns(). A match short-circuits the call
// with a block decision, emits a `gateway_secret_blocked` lifecycle
// verb, and logs an MCPCallRecord with every payload-derived field
// (Reason, Path, Operation, Repo, ResolvedPath, Snippet, Args)
// rewritten to the redaction sentinel.
//
// The adapter is safe for concurrent use because mcp.Gateway promises
// concurrent-safe AuthorizeCall and the secret detector is
// stateless beyond its immutable pattern set.
type GatewayMCPAuthorizer struct {
	// gw is the in-memory gateway forwarded to on every clean (no-
	// secret) call. Never nil after NewGatewayMCPAuthorizer.
	gw *mcp.Gateway

	// detector is the request-direction per-direction secret
	// scanner (Plan Batch 3.4). Never nil after construction; a
	// caller that does not want secret detection passes a detector
	// constructed against an empty pattern set so Scan is a no-op
	// without per-call nil checks.
	detector *gatewaySecretDetector

	// blockedLogger, when non-nil, receives the MCPCallRecord the
	// authorizer builds on a secret-block. Wired by BuildRunGateway
	// from the run-scoped MCPCallLogger so the on-disk audit log
	// records the block alongside the gateway's own AuthorizeCall
	// records. Nil falls back to a noop write (used by unit tests
	// that only assert on the returned ControlSocketResponse).
	blockedLogger mcp.CallLogger

	// eventSink, when non-nil, receives a `gateway_secret_blocked`
	// lifecycle verb per blocked request. Wired by the supervisor
	// (Plan §5.5 step 9) to its LifecycleWriter. Nil silences the
	// verb emission, which keeps unit tests that only need the
	// audit-record side effects from having to stand up a lifecycle
	// writer.
	eventSink func(verb run.LifecycleVerb, metadata map[string]string) error

	// now produces the timestamp the secret-block CallRecord stamps
	// onto its Timestamp field. Tests pin a fixedClock for stable
	// assertions; production callers pass time.Now via
	// GatewayMCPAuthorizerOptions.Now.
	now func() time.Time
}

// GatewayMCPAuthorizerOptions bundles the optional wiring inputs
// NewGatewayMCPAuthorizerWithOptions consumes. The zero value is a
// usable authorizer with the production defaults
// (scanners.BuiltInSecretPatterns(), no event sink, no blocked-call
// logger, time.Now clock).
type GatewayMCPAuthorizerOptions struct {
	// Patterns overrides the secret-detector pattern set. Nil falls
	// back to scanners.BuiltInSecretPatterns() so the production path
	// shares the same set as the workspace built-in scanner and the
	// shim helper's response-direction walker (Plan Bucket 11).
	Patterns []scanners.SecretPattern

	// BlockedLogger receives the on-disk MCPCallRecord the
	// authorizer builds on a secret-block. The same mcp.CallLogger
	// the gateway itself uses is the right wiring (so blocked-by-
	// detector and blocked-by-scope records sit in the same audit
	// stream); BuildRunGateway threads its run-scoped logger
	// through.
	BlockedLogger mcp.CallLogger

	// EventSink receives a `gateway_secret_blocked` lifecycle verb
	// per blocked request. Typed as a function (matching the
	// MaterializeRunGatewayOptions.EventSink shape) so the caller
	// can pass a closure that bridges to the supervisor's
	// LifecycleWriter without an import cycle.
	EventSink func(verb run.LifecycleVerb, metadata map[string]string) error

	// Now is the clock the authorizer uses to stamp the blocked
	// CallRecord's Timestamp. Nil falls back to time.Now. Tests
	// inject a fixed-step clock so the on-disk timestamps are
	// deterministic.
	Now func() time.Time

	// RandRead overrides the entropy source the detector's
	// finding-id minter uses. Nil falls back to crypto/rand.Read.
	// Tests pass a deterministic stream so the on-disk audit
	// record's finding_id is stable across runs.
	RandRead func([]byte) (int, error)
}

// NewGatewayMCPAuthorizer constructs the adapter. The gateway must
// be non-nil; the constructor rejects a nil gateway rather than
// substituting a no-op so a misconfigured caller fails loudly. The
// returned authorizer uses the production defaults (built-in secret
// patterns, no event sink, no blocked-call logger, time.Now clock);
// callers that need to wire those knobs use
// NewGatewayMCPAuthorizerWithOptions.
func NewGatewayMCPAuthorizer(gw *mcp.Gateway) (*GatewayMCPAuthorizer, error) {
	return NewGatewayMCPAuthorizerWithOptions(gw, nil)
}

// NewGatewayMCPAuthorizerWithOptions constructs the adapter with
// optional wiring knobs. Pass nil opts for the legacy "no detector
// hooks" behavior identical to NewGatewayMCPAuthorizer.
func NewGatewayMCPAuthorizerWithOptions(gw *mcp.Gateway, opts *GatewayMCPAuthorizerOptions) (*GatewayMCPAuthorizer, error) {
	if gw == nil {
		return nil, errors.New("cli: NewGatewayMCPAuthorizer requires non-nil gateway")
	}
	var (
		patterns      = scanners.BuiltInSecretPatterns()
		blockedLogger mcp.CallLogger
		sink          func(verb run.LifecycleVerb, metadata map[string]string) error
		clock         = time.Now
		randRead      func([]byte) (int, error)
	)
	if opts != nil {
		if opts.Patterns != nil {
			patterns = opts.Patterns
		}
		blockedLogger = opts.BlockedLogger
		sink = opts.EventSink
		if opts.Now != nil {
			clock = opts.Now
		}
		randRead = opts.RandRead
	}
	detector := newGatewaySecretDetector(patterns)
	detector.randRead = randRead
	return &GatewayMCPAuthorizer{
		gw:            gw,
		detector:      detector,
		blockedLogger: blockedLogger,
		eventSink:     sink,
		now:           clock,
	}, nil
}

// Authorize implements run.MCPAuthorizer. The control socket has
// verified the per-server token pair before invoking this method; we
// only need to decode the JSON-RPC body, build an mcp.CallRequest,
// and forward to the gateway.
//
// Body shape: the JSON-RPC payload the helper extracted from the
// agent's request. We expect a top-level object with optional `tool`,
// `path`, `repo`, `operation`, `args`, and `extra` keys. Missing keys
// mean "not applicable for this call kind"; the gateway's scope
// enforcers already handle the empty-field case. A malformed body
// produces a block with reason="malformed body" rather than the
// gateway's default error, so the helper-side reader has a clean
// signal.
//
// Plan Batch 3.4 — per-direction secret detector. Before the body is
// forwarded to the gateway it is scanned (raw bytes, no JSON decode
// required) against scanners.BuiltInSecretPatterns(). A match
// short-circuits with a block decision: the supervisor emits a
// `gateway_secret_blocked` lifecycle verb and logs an MCPCallRecord
// with every payload-derived field (Reason, Path, Operation, Repo,
// ResolvedPath, Snippet, Args) rewritten to the redaction sentinel.
// The block is recorded BEFORE any error path so an exfiltration
// attempt cannot regress into a "malformed body" record that hides
// the matched pattern.
//
// The op parameter is the JSON-RPC method name (e.g. "tools/call");
// the gateway does not currently consult it for the per-call verdict,
// but we forward it through the audit record's Tool field when the
// body's `tool` key is missing so the record is never blank.
func (a *GatewayMCPAuthorizer) Authorize(server, op string, body []byte) run.ControlSocketResponse {
	// Step 1: per-direction secret detector. Plan Batch 3.4 pins this
	// BEFORE the malformed-body check so a body that contains both
	// a secret and a JSON parse error still surfaces as a secret
	// block (the more-specific failure wins for audit clarity).
	if match := a.detector.Scan(body); match.Matched {
		return a.handleSecretBlock(server, op, body, match)
	}

	req := mcp.CallRequest{Server: server}
	if len(body) > 0 {
		var parsed struct {
			Tool      string            `json:"tool"`
			Path      string            `json:"path"`
			Repo      string            `json:"repo"`
			Operation string            `json:"operation"`
			Args      json.RawMessage   `json:"args"`
			Extra     map[string]string `json:"extra"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return run.ControlSocketResponse{
				Decision: "block",
				Reason:   fmt.Sprintf("malformed body: %v", err),
			}
		}
		req.Tool = parsed.Tool
		req.Path = parsed.Path
		req.Repo = parsed.Repo
		req.Operation = parsed.Operation
		req.Extra = parsed.Extra
	}
	if req.Tool == "" {
		// Use the op name when the body lacks an explicit tool so
		// the audit record is never blank. The gateway still
		// requires a non-empty tool for AuthorizeCall; an op-only
		// fallback at least keeps the audit trail traceable when
		// the helper's body parsing returns a thin record.
		req.Tool = op
	}

	dec, err := a.gw.AuthorizeCall(req)
	if err != nil {
		// The gateway's AuthorizeCall returns an error when the
		// logger fails (the verdict is still meaningful — finalize
		// stamped it onto the record before the log failure). We
		// surface the verdict and append the logger error to the
		// reason so the auditor can see both signals.
		return run.ControlSocketResponse{
			Decision: outcomeToken(dec.Outcome),
			Reason:   fmt.Sprintf("%s (logger error: %v)", dec.Reason, err),
		}
	}
	return run.ControlSocketResponse{
		Decision: outcomeToken(dec.Outcome),
		Reason:   dec.Reason,
	}
}

// handleSecretBlock is the per-direction secret detector's block
// path. Plan Batch 3.4 enumerates the responsibilities:
//
//  1. Build an MCPCallRecord (Stage = CallStageCall) with every
//     payload-derived field redacted via the detector's RedactString.
//     The enumeration is closed: Reason, Path, Operation, Repo,
//     ResolvedPath, Snippet, Args. The Tool field is populated from
//     the JSON-RPC method name (or the body's `tool` key when
//     present) so the audit record is never blank; Tool itself is
//     NOT redacted because it is a method-name identifier, not a
//     payload value.
//  2. Log the record through the blocked-call logger (typically the
//     same MCPCallLogger the gateway uses).
//  3. Emit a `gateway_secret_blocked` lifecycle verb so the
//     leaks.jsonl aggregator (Plan Bucket 9) picks the block up via
//     the supervisor's LifecycleWriter.
//  4. Return a block ControlSocketResponse to the control socket so
//     the supervisor refuses to forward the request to the upstream
//     MCP server.
//
// The function returns the response synchronously; the logger /
// sink callbacks are best-effort (a logger error does not change
// the block verdict, only the audit completeness).
func (a *GatewayMCPAuthorizer) handleSecretBlock(server, op string, body []byte, match gatewaySecretMatch) run.ControlSocketResponse {
	// Extract Tool / Path / Operation / Repo / Args from the body
	// for the audit record. We tolerate a parse error here (a body
	// that contains a secret AND is malformed JSON still gets the
	// secret-block record; the parse error is logged via the
	// Snippet field rather than upgrading to a "malformed body"
	// reason that would lose the secret-block signal).
	tool, path, repo, operation, args := decodePayloadFields(body)
	if tool == "" {
		tool = op
	}

	rawReason := fmt.Sprintf("request body contains secret matching pattern %q", match.PatternName)
	// Snippet captures the operation so an auditor can see what the
	// agent was trying to call; the body itself is NOT included
	// verbatim because the redactor would scrub the offending
	// substring but the surrounding bytes could still leak adjacent
	// PII. A bounded structural snippet is the right audit grain.
	rawSnippet := fmt.Sprintf("server=%s op=%s body_len=%d", server, op, len(body))

	rec := mcp.CallRecord{
		Timestamp: a.now().Format(time.RFC3339),
		Stage:     mcp.CallStageCall,
		Server:    server,
		Tool:      tool,
		Decision:  outcomeToken(mcp.GatewayOutcomeBlock),
		// Every payload-derived field is passed through the
		// detector's RedactString so a secret embedded in the
		// caller's body (which is then echoed into one of these
		// fields) does not leak into the on-disk record.
		Reason:       a.detector.RedactString(rawReason),
		Path:         a.detector.RedactString(path),
		Repo:         a.detector.RedactString(repo),
		Operation:    a.detector.RedactString(operation),
		ResolvedPath: a.detector.RedactString(path), // pre-resolution; same source field
		Snippet:      a.detector.RedactString(rawSnippet),
		Args:         a.detector.RedactString(args),
	}

	if a.blockedLogger != nil {
		_ = a.blockedLogger.Log(rec)
	}

	if a.eventSink != nil {
		_ = a.eventSink(
			run.LifecycleVerbGatewaySecretBlocked,
			run.GatewaySecretBlockedMetadata(server, op, match.PatternName, match.FindingID),
		)
	}

	return run.ControlSocketResponse{
		Decision: outcomeToken(mcp.GatewayOutcomeBlock),
		Reason:   rec.Reason,
	}
}

// decodePayloadFields extracts the payload-derived fields the
// secret-block CallRecord needs from a JSON-RPC body. Returns
// every field as an empty string on parse failure so the caller
// can still build a meaningful record (the parse error itself is
// implicitly captured by the empty fields). The Args field is
// stringified (json.RawMessage rendered back to its JSON text)
// so a redactor that operates on strings can scan it for secrets;
// nested objects / arrays land as their JSON encoding.
func decodePayloadFields(body []byte) (tool, path, repo, operation, args string) {
	if len(body) == 0 {
		return "", "", "", "", ""
	}
	var parsed struct {
		Tool      string          `json:"tool"`
		Path      string          `json:"path"`
		Repo      string          `json:"repo"`
		Operation string          `json:"operation"`
		Args      json.RawMessage `json:"args"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Tolerant fallback: return the body bytes as the Args
		// stringification so the secret detector still sees the
		// raw content for redaction. The parse error is implicitly
		// captured by the empty Tool / Path / Repo / Operation
		// fields.
		return "", "", "", "", string(body)
	}
	return parsed.Tool, parsed.Path, parsed.Repo, parsed.Operation, string(parsed.Args)
}

// outcomeToken maps mcp.GatewayOutcome to the control socket's
// decision token. The control socket's Decision field uses
// "allow"/"warn"/"block" exactly as mcp.GatewayOutcome.String()
// returns them, so the mapping is identity; centralizing it here so
// a future change to either side does not silently desync.
func outcomeToken(o mcp.GatewayOutcome) string {
	switch o {
	case mcp.GatewayOutcomeAllow:
		return "allow"
	case mcp.GatewayOutcomeWarn:
		return "warn"
	case mcp.GatewayOutcomeBlock:
		return "block"
	default:
		// Unknown outcomes should not occur (the enum is closed); we
		// fail closed by emitting block.
		return "block"
	}
}

// MaterializeRunGatewayOptions bundles the per-run inputs the
// MaterializeRunGateway side-effecting writer consumes. The required
// fields cover the minimum the materializer needs; the optional
// fields knob the in-sandbox paths embedded in the agent-visible
// config and the chown target on the host-only files.
//
// The shape mirrors PerRunMCPConfigOptions (the run-package writer
// the materializer delegates to) so a caller that already holds
// PerRunMCPConfigOptions can copy the fields verbatim.
type MaterializeRunGatewayOptions struct {
	// RunDir is the per-run directory. Required.
	RunDir string

	// ControlSocket is the per-run control socket. Required: the
	// materializer mints per-server tokens via
	// ControlSocket.MintServerToken and reads PrimaryToken for the
	// side-band file.
	ControlSocket *run.ControlSocket

	// RealServers maps registered server name to upstream launch
	// command. Required and non-empty: a run without any registered
	// MCP servers should not call this materializer.
	RealServers map[string]run.MCPRealServer

	// Workspace is the absolute workspace directory the supervisor
	// will mount into the sandbox. When non-empty the materializer
	// shadows workspace-local MCP configs (`.mcp.json`,
	// `.claude/settings.json#mcpServers`) so the agent CLI's auto-
	// merge cannot reintroduce a server bypassing the per-run
	// config. An empty Workspace skips the shadow step entirely; the
	// caller (a unit test that does not stand up a workspace) sees
	// an empty ShadowEntries slice.
	Workspace string

	// EventSink, when non-nil, is the lifecycle sink the materializer
	// emits one `mcp_config_neutralized` verb to per shadowed file.
	// Nil silences the verb emission, which keeps unit tests that
	// only need the shadow side effects from having to stand up a
	// lifecycle writer.
	//
	// Typed as a function value rather than an interface so the
	// caller can pass a closure that bridges to the supervisor's
	// LifecycleWriter (which is in the run package; threading an
	// interface here would import-cycle).
	EventSink func(verb run.LifecycleVerb, metadata map[string]string) error

	// HelperCommand is forwarded to PerRunMCPConfigOptions. Defaults
	// to "ai-env" when empty.
	HelperCommand string

	// InSandboxSocketPath is forwarded to PerRunMCPConfigOptions.
	// Defaults to the canonical /var/run/ai-env/control.sock when
	// empty.
	InSandboxSocketPath string

	// ContainerUID is forwarded to PerRunMCPConfigOptions as the
	// chown target on `mcp-servers.real.json` and `.helper-token`.
	// Nil leaves the chown unset (the right default for tests
	// running as the host user).
	ContainerUID *int
}

// MaterializedRunGateway is the bundle MaterializeRunGateway returns.
// The supervisor holds it for the lifetime of the run; at backend.
// Destroy the supervisor calls Restore so any shadowed workspace
// config is renamed back.
type MaterializedRunGateway struct {
	// PerRunConfig records the on-disk paths and the per-server
	// token map. The supervisor passes
	// PerRunConfig.AgentConfigPath to the agent CLI via the
	// per-CLI `--mcp-config` flag (or equivalent).
	PerRunConfig run.PerRunMCPConfig

	// ShadowEntries records the workspace-local MCP configs the
	// materializer renamed out of the way. Restore() iterates this
	// slice in reverse at teardown.
	ShadowEntries []run.ShadowEntry
}

// Restore renames each shadowed workspace MCP config back to its
// original path. Called by the supervisor at backend.Destroy. The
// per-run files (`mcp-servers.json`, `mcp-servers.real.json`,
// `.helper-token`) are NOT removed: they live in the runDir which is
// already cleaned up by the supervisor's higher-level finalize step.
func (m *MaterializedRunGateway) Restore() error {
	if m == nil {
		return nil
	}
	return run.RestoreWorkspaceMCPConfig(m.ShadowEntries)
}

// MaterializeRunGateway writes the per-run MCP config artifacts to
// disk, mints per-server tokens via ControlSocket.MintServerToken,
// and shadows workspace-local MCP configs. The supervisor's pre-
// launch step 9 (Plan §5.5) calls this once per run AFTER
// BuildRunGateway has constructed the in-memory gateway.
//
// On any error the partially-materialized state is rolled back:
//   - The per-run files (if any were written) are removed.
//   - The shadowed workspace files (if any were renamed) are renamed
//     back.
//
// Successful Materialize returns a bundle whose Restore method
// undoes the workspace shadow at teardown. The supervisor calls
// Restore exactly once.
func MaterializeRunGateway(opts MaterializeRunGatewayOptions) (*MaterializedRunGateway, error) {
	if opts.RunDir == "" {
		return nil, errors.New("cli: MaterializeRunGateway requires RunDir")
	}
	if opts.ControlSocket == nil {
		return nil, errors.New("cli: MaterializeRunGateway requires ControlSocket")
	}
	if len(opts.RealServers) == 0 {
		return nil, errors.New("cli: MaterializeRunGateway requires at least one RealServer")
	}

	// 1. Write the per-run files. This mints the per-server tokens
	//    into the ControlSocket registry as a side effect.
	cfg, err := run.MaterializePerRunMCPConfig(run.PerRunMCPConfigOptions{
		RunDir:              opts.RunDir,
		ControlSocket:       opts.ControlSocket,
		RealServers:         opts.RealServers,
		HelperCommand:       opts.HelperCommand,
		InSandboxSocketPath: opts.InSandboxSocketPath,
		ContainerUID:        opts.ContainerUID,
	})
	if err != nil {
		return nil, fmt.Errorf("cli: MaterializeRunGateway: %w", err)
	}

	// 2. Shadow workspace-local MCP configs (when a workspace is
	//    supplied). We do this AFTER the per-run files land so a
	//    failure in step 1 does not leave the workspace with a
	//    shadowed config but no per-run replacement.
	var shadowEntries []run.ShadowEntry
	if opts.Workspace != "" {
		shadowEntries, err = run.ShadowWorkspaceMCPConfig(opts.Workspace)
		if err != nil {
			// Roll back the per-run files: a workspace-shadow
			// failure means the supervisor will abort the run, so
			// the per-run files should not linger.
			_ = removePerRunFiles(cfg)
			return nil, fmt.Errorf("cli: MaterializeRunGateway: shadow workspace mcp config: %w", err)
		}
	}

	// 3. Emit the lifecycle verb for every shadow entry. Best-
	//    effort: a verb emission failure does NOT roll back the
	//    shadow (the run can still proceed without the audit
	//    signal; the supervisor logs the error itself).
	if opts.EventSink != nil {
		for _, e := range shadowEntries {
			_ = opts.EventSink(run.LifecycleVerbMCPConfigNeutralized, run.MCPConfigNeutralizedMetadata(e))
		}
	}

	return &MaterializedRunGateway{
		PerRunConfig:  cfg,
		ShadowEntries: shadowEntries,
	}, nil
}

// removePerRunFiles is the cleanup helper for the workspace-shadow
// failure path. We remove the three files individually rather than
// the whole runDir because the runDir holds other lifecycle
// artifacts (lifecycle.jsonl, run.json, etc.) the supervisor needs
// to record the failure on. Missing files are tolerated (a previous
// rollback may have removed them).
func removePerRunFiles(cfg run.PerRunMCPConfig) error {
	var firstErr error
	for _, path := range []string{cfg.AgentConfigPath, cfg.RealConfigPath, cfg.HelperTokenPath} {
		if path == "" {
			continue
		}
		if err := osRemoveIfExists(path); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// osRemoveIfExists is os.Remove with ENOENT tolerance. Centralized so
// the rollback path stays self-documenting.
func osRemoveIfExists(path string) error {
	err := osRemoveFunc(path)
	if err == nil {
		return nil
	}
	if isNotExistFunc(err) {
		return nil
	}
	return err
}
