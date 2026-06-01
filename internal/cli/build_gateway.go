// BuildRunGateway — Plan Batch 3.1.
//
// The supervisor needs one mcp.Gateway per run, wired with:
//
//   - the operator-authored Registry (loaded from .ai-env/mcp.yaml);
//   - the per-run audit sink (mcp-calls.jsonl through a
//     run.MCPCallsWriter, wrapped by the cli.MCPCallLogger bridge);
//   - the scope enforcers (FilesystemScopeEnforcer pinned to the run's
//     workspace root, GitHubScopeEnforcer pinned to the run's current
//     repo coordinate);
//   - the Plan Batch 3.3 turn-id bridge that stamps each on-disk
//     MCPCallRecord with the supervisor-minted turn id in effect at
//     decision time, when a ControlSocket is supplied.
//
// Earlier plan-09 batches constructed each of these one-off at the
// call site (the CLI's `ai-env mcp scan` dry-run, the unit-test fixtures
// in internal/cli/mcp_logger_test.go). The supervisor needs them
// together, and assembling them inline at the supervisor wire-up site
// would duplicate the bookkeeping (open writer → wrap with bridge →
// build enforcers → call mcp.NewGateway with the enforcers map → handle
// every per-step error path). BuildRunGateway centralizes the assembly
// so the supervisor's wire-up step (a future batch) only has to call
// BuildRunGateway once and consume the returned bundle.
//
// What this batch implements vs. what it defers:
//
//   - This batch (3.1) constructs the gateway, the on-disk writer, the
//     bridge, and the enforcers; it does NOT write
//     <runDir>/mcp-servers.json, mint per-server tokens, register the
//     tokens with the control socket, or shadow workspace MCP configs.
//     Those concerns belong to Batch 3.2 (per-run MCP config + per-
//     server tokens + workspace shadowing) and are deliberately left
//     out — the supervisor calling BuildRunGateway today receives a
//     gateway it can authorize calls against, even though no live
//     mcp-servers.json has been emitted yet.
//
//   - The Plan Batch 3.3 turn-id wiring is implemented here because the
//     supervisor's BuildRunGateway is the same site that already
//     consumes the run.ControlSocket (for AuthorizeMCPCall handler
//     wiring in later batches). The MCPCallLogger gains an optional
//     TurnSource, BuildRunGateway threads the control socket through,
//     and every MCPCallRecord landed by the gateway carries the active
//     turn id.
//
// Fail-closed shape:
//
//   - Required inputs (RunDir, RunID, Registry) are rejected when
//     missing so a misconfigured caller fails loudly. The scope
//     enforcers are constructed when their declared inputs are
//     non-empty; a caller that omits WorkspaceRoot / CurrentRepo
//     produces a gateway whose enforcers map only contains the kinds
//     it could build. mcp.Gateway's "deny unknown scope" rule then
//     blocks any server that declares an unconfigured scope, which is
//     the right default for a misconfigured run.
//
//   - If any step in the assembly fails (writer open error, enforcer
//     construction error, gateway construction error) BuildRunGateway
//     closes every partially-opened resource (the MCPCallsWriter
//     specifically) and returns the underlying error so the supervisor
//     can abort the run before the misconfigured gateway leaks file
//     handles.
//
// Returned bundle lifecycle:
//
//   - The caller (the supervisor's pre-launch step 9 wiring, Plan
//     §5.5) is responsible for calling RunGateway.Close at teardown so
//     the on-disk writer's file handle is flushed and released. The
//     bundle's other fields (gateway, enforcers, logger bridge) are
//     reference types that the supervisor either holds alongside the
//     bundle (the gateway feeds the AuthorizeMCPCall handler) or that
//     are pinned by mcp.Gateway internally (the enforcers).

package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/rivan1986/ai-env/internal/mcp"
	"github.com/rivan1986/ai-env/internal/run"
)

// BuildRunGatewayOptions bundles the per-run inputs BuildRunGateway
// consumes. The required fields (RunDir, RunID, Registry) cover the
// minimum the assembly needs to land a usable gateway on disk; the
// optional fields wire the scope enforcers (WorkspaceRoot,
// CurrentRepo) and the turn-id bridge (ControlSocket, TurnRole).
//
// The shape mirrors the other "Build*FromX" factories in the codebase
// (secrets.BuildProviderProxyFromSecrets, the future
// BuildBrokerFromSecrets): a value-typed options struct so a caller
// can build it incrementally and pass it by value without aliasing.
type BuildRunGatewayOptions struct {
	// RunDir is the absolute path of the run directory the MCP audit
	// log lives inside. The same value run.RunDirectory.Path carries.
	// Required.
	RunDir string

	// RunID is the per-run identifier the MCPCallsWriter stamps onto
	// internal bookkeeping (the writer's own runID field). Required
	// even though MCPCallRecord does not surface it: the writer's
	// constructor validates non-empty so a misconfigured caller fails
	// fast.
	RunID string

	// Registry is the loaded and validated mcp.Registry the gateway
	// consults for server registration, version / digest pinning, and
	// per-server scope declarations. Required: mcp.NewGateway rejects
	// a nil registry and BuildRunGateway propagates that rule one
	// frame closer to the misconfiguration so the supervisor sees the
	// error before it materializes any per-run resources.
	Registry *mcp.Registry

	// WorkspaceRoot is the absolute path of the run's workspace
	// directory. When non-empty BuildRunGateway constructs a
	// FilesystemScopeEnforcer pinned to this root and registers it
	// under the "filesystem" scope kind. Empty leaves the filesystem
	// enforcer unwired, which means any server declaring a filesystem
	// scope will be blocked by mcp.Gateway's "deny unknown scope"
	// rule — the right fail-closed default for a run that lacks a
	// workspace context.
	WorkspaceRoot string

	// CurrentRepo is the "owner/name" GitHub coordinate the run is
	// pinned against (the origin recorded at `ai-env new`, re-checked
	// at PR time per Plan Bucket 3). When non-empty BuildRunGateway
	// constructs a GitHubScopeEnforcer pinned to this coordinate and
	// registers it under the "github" scope kind. Empty leaves the
	// github enforcer unwired with the same fail-closed semantics as
	// WorkspaceRoot.
	CurrentRepo string

	// ControlSocket is the per-run control socket the supervisor
	// constructed at canonical pre-launch step 2 (Plan §5.5). When
	// non-nil BuildRunGateway threads it into the MCPCallLogger as a
	// TurnSource so every MCPCallRecord lands the current turn id
	// (Plan Batch 3.3). Nil leaves the bridge turn-unaware and every
	// record's TurnID stays empty — the right default for unit-test
	// callers that do not stand up a control socket.
	ControlSocket *run.ControlSocket

	// TurnRole is the role string the bridge passes to
	// ControlSocket.CurrentTurnID at log time. Empty falls back to
	// DefaultTurnRole so the production path matches the control
	// socket's own default role on BeginTurn / CurrentTurn.
	TurnRole string

	// Now, when non-nil, is the clock the MCPCallsWriter stamps on
	// records the caller did not pre-populate Timestamp on. The
	// gateway already stamps its own Timestamp via its own clock
	// option (mcp.GatewayOptions.Now), so in practice the writer
	// clock is only consulted by direct writer callers. Nil falls
	// back to the writer's default (time.Now). The same value is
	// forwarded to mcp.GatewayOptions.Now so the two clocks stay in
	// sync.
	Now func() time.Time

	// EventSink, when non-nil, is the lifecycle sink the per-direction
	// gateway secret detector (Plan Batch 3.4) emits
	// `gateway_secret_blocked` verbs through when an inbound MCP
	// request body matches a built-in secret pattern. Typed as a
	// function value rather than an interface so the caller can pass
	// a closure that bridges to the supervisor's LifecycleWriter (in
	// the run package) without an import cycle.
	//
	// Nil silences the verb emission, which keeps unit-test callers
	// from having to stand up a lifecycle writer; the detector still
	// blocks the request and writes the redacted on-disk CallRecord,
	// so the silence affects ONLY the lifecycle.jsonl side of the
	// audit trail.
	EventSink func(verb run.LifecycleVerb, metadata map[string]string) error
}

// RunGateway is the per-run bundle BuildRunGateway returns. The
// supervisor's wire-up step holds one of these for the lifetime of
// the run; the bundle's Close method tears down the on-disk writer
// at teardown (canonical step 6 in Plan §5.5).
//
// All fields are owned by the bundle: the supervisor reads them but
// does not Close them directly. Calling RunGateway.Close instead of
// closing the writer field by hand keeps the lifecycle in one place
// so a future addition (per-server token registration, a stop-time
// lifecycle verb) does not surprise an existing caller.
type RunGateway struct {
	// Gateway is the constructed mcp.Gateway. Pass into the
	// AuthorizeMCPCall handler the supervisor wires onto the control
	// socket so every helper-side authorization call flows through
	// the same gateway that the in-process `ai-env mcp scan` dry-run
	// uses.
	Gateway *mcp.Gateway

	// Writer is the on-disk audit sink the bridge forwards records
	// to. Exposed so the supervisor can introspect / close it
	// independently if a future code path needs to (today: Close on
	// the bundle is the single canonical entry point).
	Writer *run.MCPCallsWriter

	// Logger is the bridge that satisfies mcp.CallLogger. Already
	// installed in Gateway.logger; exposed here so a caller can swap
	// it onto a second gateway (the CLI's dry-run, for instance)
	// without re-opening the writer.
	Logger *MCPCallLogger

	// FilesystemEnforcer is the per-run filesystem scope enforcer the
	// gateway hands every "filesystem" scope kind to. Nil when
	// BuildRunGatewayOptions.WorkspaceRoot was empty (the run lacks
	// a workspace context); see the field doc on
	// BuildRunGatewayOptions.WorkspaceRoot for the fail-closed
	// behavior that produces.
	FilesystemEnforcer *mcp.FilesystemScopeEnforcer

	// GitHubEnforcer is the per-run GitHub scope enforcer. Nil when
	// BuildRunGatewayOptions.CurrentRepo was empty.
	GitHubEnforcer *mcp.GitHubScopeEnforcer

	// Authorizer is the run.MCPAuthorizer the supervisor wires onto
	// the control socket's AuthorizeMCPCall handler. It is the same
	// authorizer the supervisor would otherwise build by hand from
	// (Gateway, Logger, EventSink): centralizing the construction
	// here means a future call site only has to consume
	// RunGateway.Authorizer rather than re-deriving the wiring.
	//
	// The authorizer is wired with the per-direction secret detector
	// (Plan Batch 3.4): every body that reaches Authorize is scanned
	// via scanners.BuiltInSecretPatterns() and a match short-circuits
	// to a block decision with the redacted MCPCallRecord and a
	// `gateway_secret_blocked` lifecycle verb.
	Authorizer *GatewayMCPAuthorizer
}

// Close releases the bundle's on-disk resources. Specifically the
// MCPCallsWriter is closed so the file handle is flushed and the
// final fsync lands the last record on disk. Safe to call more than
// once (the underlying writer's Close is idempotent).
//
// Close does NOT emit a `gateway_stopped` lifecycle verb: the verb
// belongs to the supervisor's teardown sequence (Plan §5.5 step 6)
// which holds the run-scoped LifecycleWriter; the bundle does not
// import that surface so it stays free of run-package lifecycle
// semantics. The supervisor wires its own emit-verb call alongside
// this Close.
func (g *RunGateway) Close() error {
	if g == nil || g.Writer == nil {
		return nil
	}
	return g.Writer.Close()
}

// BuildRunGateway constructs the per-run MCP gateway bundle from the
// supplied options. It is the Plan Batch 3.1 entry point the
// supervisor's pre-launch step 9 (Plan §5.5) calls once per run.
//
// Assembly order:
//
//  1. Validate required inputs (RunDir, RunID, Registry).
//  2. Open the per-run MCPCallsWriter against RunDir; this is the
//     first resource the bundle owns, so a failure here returns
//     before any other state is created.
//  3. Construct the cli.MCPCallLogger bridge with the optional
//     ControlSocket / TurnRole knobs. Any failure here closes the
//     writer before returning so a partial-bundle never escapes.
//  4. Construct the scope enforcers (filesystem + github) for the
//     fields the caller populated. An empty input leaves the
//     enforcer unwired and the gateway will block any server that
//     declares the corresponding scope.
//  5. Call mcp.NewGateway with the enforcers map, the logger
//     bridge, and the supervisor-supplied clock.
//
// On any error the writer is closed before returning so the caller
// sees a clean error path; on success the caller is responsible for
// calling RunGateway.Close at teardown.
func BuildRunGateway(opts BuildRunGatewayOptions) (*RunGateway, error) {
	if opts.RunDir == "" {
		return nil, errors.New("cli: BuildRunGateway requires RunDir")
	}
	if opts.RunID == "" {
		return nil, errors.New("cli: BuildRunGateway requires RunID")
	}
	if opts.Registry == nil {
		return nil, errors.New("cli: BuildRunGateway requires Registry")
	}

	writer, err := run.OpenMCPCallsWriter(opts.RunDir, run.MCPCallsWriterOptions{
		RunID: opts.RunID,
		Now:   opts.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("cli: BuildRunGateway: open mcp calls writer: %w", err)
	}

	// Wrap the writer in the bridge. The bridge constructor wires the
	// optional TurnSource so every record stamps the active turn id
	// (Plan Batch 3.3). We pass the ControlSocket through as a
	// TurnSource because *run.ControlSocket satisfies the interface
	// via its CurrentTurnID method; a nil ControlSocket lands a nil
	// TurnSource on the bridge, which is the documented "no stamp"
	// behavior on MCPCallLogger.
	logger, err := NewMCPCallLoggerWithOptions(writer, &MCPCallLoggerOptions{
		TurnSource: turnSourceFromControlSocket(opts.ControlSocket),
		TurnRole:   opts.TurnRole,
	})
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("cli: BuildRunGateway: build call logger: %w", err)
	}

	// Build the scope enforcers for the kinds the caller wired. An
	// empty field leaves the enforcer unwired; mcp.Gateway's
	// AuthorizeCall then blocks any server that declares the missing
	// kind with ErrMissingScopeEnforcer, the master plan's "deny
	// unknown scope" rule.
	enforcers := map[string]mcp.ScopeEnforcer{}
	var (
		fsEnforcer *mcp.FilesystemScopeEnforcer
		ghEnforcer *mcp.GitHubScopeEnforcer
	)
	if opts.WorkspaceRoot != "" {
		fse, err := mcp.NewFilesystemScopeEnforcer(opts.WorkspaceRoot)
		if err != nil {
			_ = writer.Close()
			return nil, fmt.Errorf("cli: BuildRunGateway: build filesystem scope enforcer: %w", err)
		}
		fsEnforcer = fse
		enforcers[mcp.ScopeKindFilesystem] = fse
	}
	if opts.CurrentRepo != "" {
		ghe, err := mcp.NewGitHubScopeEnforcer(opts.CurrentRepo)
		if err != nil {
			_ = writer.Close()
			return nil, fmt.Errorf("cli: BuildRunGateway: build github scope enforcer: %w", err)
		}
		ghEnforcer = ghe
		enforcers[mcp.ScopeKindGitHub] = ghe
	}

	gw, err := mcp.NewGateway(opts.Registry, &mcp.GatewayOptions{
		Logger:    logger,
		Enforcers: enforcers,
		Now:       opts.Now,
	})
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("cli: BuildRunGateway: build gateway: %w", err)
	}

	// Plan Batch 3.4: construct the run.MCPAuthorizer adapter wired
	// with the per-direction secret detector. The detector's
	// blocked-call records go to the same logger the gateway uses
	// so secret-block and scope-block records share one stream; the
	// lifecycle verb is emitted via the caller's EventSink (nil when
	// the caller has not stood up a lifecycle writer, which keeps
	// the unit-test surface clean).
	authorizer, err := NewGatewayMCPAuthorizerWithOptions(gw, &GatewayMCPAuthorizerOptions{
		BlockedLogger: logger,
		EventSink:     opts.EventSink,
		Now:           opts.Now,
	})
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("cli: BuildRunGateway: build authorizer: %w", err)
	}

	return &RunGateway{
		Gateway:            gw,
		Writer:             writer,
		Logger:             logger,
		FilesystemEnforcer: fsEnforcer,
		GitHubEnforcer:     ghEnforcer,
		Authorizer:         authorizer,
	}, nil
}

// turnSourceFromControlSocket adapts a *run.ControlSocket (which may
// be nil) to the TurnSource interface the bridge consumes. Centralizing
// the nil-check here keeps BuildRunGateway's body readable: a nil
// ControlSocket yields a nil TurnSource (the documented "no turn
// stamping" behavior on MCPCallLogger), while a non-nil socket is
// wrapped in a tiny adapter so it satisfies the interface without
// circular-dependency gymnastics.
//
// The adapter is a function value (TurnSourceFunc) rather than a
// dedicated struct so the GC tracks one pointer rather than two; the
// function captures the socket by reference so any post-construction
// BeginTurn calls are observed by future CurrentTurnID lookups.
func turnSourceFromControlSocket(sock *run.ControlSocket) TurnSource {
	if sock == nil {
		return nil
	}
	return TurnSourceFunc(func(role string) string {
		return sock.CurrentTurnID(role)
	})
}
