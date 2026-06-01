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

	"github.com/rivan1986/ai-env/internal/mcp"
	"github.com/rivan1986/ai-env/internal/run"
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
// The adapter is safe for concurrent use because mcp.Gateway promises
// concurrent-safe AuthorizeCall.
type GatewayMCPAuthorizer struct {
	gw *mcp.Gateway
}

// NewGatewayMCPAuthorizer constructs the adapter. The gateway must
// be non-nil; the constructor rejects a nil gateway rather than
// substituting a no-op so a misconfigured caller fails loudly.
func NewGatewayMCPAuthorizer(gw *mcp.Gateway) (*GatewayMCPAuthorizer, error) {
	if gw == nil {
		return nil, errors.New("cli: NewGatewayMCPAuthorizer requires non-nil gateway")
	}
	return &GatewayMCPAuthorizer{gw: gw}, nil
}

// Authorize implements run.MCPAuthorizer. The control socket has
// verified the per-server token pair before invoking this method; we
// only need to decode the JSON-RPC body, build an mcp.CallRequest,
// and forward to the gateway.
//
// Body shape: the JSON-RPC payload the helper extracted from the
// agent's request. We expect a top-level object with optional `tool`,
// `path`, `repo`, `operation`, and `extra` keys. Missing keys mean
// "not applicable for this call kind"; the gateway's scope enforcers
// already handle the empty-field case. A malformed body produces a
// block with reason="malformed body" rather than the gateway's
// default error, so the helper-side reader has a clean signal.
//
// The op parameter is the JSON-RPC method name (e.g. "tools/call");
// the gateway does not currently consult it for the per-call verdict,
// but we forward it through the audit record's Tool field when the
// body's `tool` key is missing so the record is never blank.
func (a *GatewayMCPAuthorizer) Authorize(server, op string, body []byte) run.ControlSocketResponse {
	req := mcp.CallRequest{Server: server}
	if len(body) > 0 {
		var parsed struct {
			Tool      string            `json:"tool"`
			Path      string            `json:"path"`
			Repo      string            `json:"repo"`
			Operation string            `json:"operation"`
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
