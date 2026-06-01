// MCP gateway proxy (plan 09, step 3).
//
// The gateway is the single chokepoint every MCP request must pass
// through. The master plan's section 22 calls out that ai-env "cannot
// govern MCP calls that are not routed through its gateway", so the
// type defined here is the ground truth for "this request was checked".
// Every other layer of plan 09 plugs into it:
//
//   - Step 1 (registry.go) and step 2 (schema.go) provide the data the
//     gateway consults: which servers exist, what version / digest is
//     pinned, and whether the live tool schema matches the operator-
//     pinned hash.
//   - Step 4 (filesystem scope enforcement) and step 5 (GitHub scope
//     enforcement) plug ScopeEnforcer implementations into the gateway
//     so the proxy can refuse a filesystem path outside the workspace
//     or a GitHub call against a foreign repo without this file needing
//     to know what a workspace or a repo is.
//   - Step 6 (`ai-env mcp ...` CLI) builds Gateway instances from the
//     operator-authored mcp.yaml and uses them to dry-run a server
//     before launch (`ai-env mcp scan`).
//   - Step 7 (mcp-calls.jsonl) supplies the CallLogger implementation
//     that turns each AuthorizeLaunch / AuthorizeCall verdict into one
//     line in the per-run audit log.
//   - Acceptance tests in step 9 exercise the gateway end-to-end against
//     fixture registries.
//
// The gateway never performs network I/O of its own. It does not spawn
// the MCP server process, it does not transport tool calls to the
// server, and it does not parse on-wire MCP frames. Those are concerns
// of the agent runner (which the proxy wraps) and of future plan-09
// batches. The gateway's only job is to answer two questions:
//
//   1. AuthorizeLaunch: may this server be started at all? This combines
//      registration lookup, version pin, digest pin (when registered),
//      and schema-hash compare. The result is a GatewayDecision the
//      caller acts on (launch / refuse / warn) and a CallRecord the
//      caller writes to mcp-calls.jsonl.
//
//   2. AuthorizeCall: may this specific tool invocation proceed? This
//      consults the registered ScopeEnforcer for the call's scope kinds
//      (filesystem path validation, GitHub repo check) and combines
//      their verdicts with the server's per-server Policy field. The
//      result is again a GatewayDecision plus a CallRecord.
//
// Decision semantics (mirror master plan section 22 and 30):
//
//   - GatewayOutcomeAllow: launch the server / dispatch the call as-is.
//   - GatewayOutcomeWarn:  proceed, but flag the call in the audit log
//                          and in the run report. The master plan's
//                          "warn or block" rule for schema drift lands
//                          here; the per-server Policy "warn" token
//                          also produces this outcome on every call.
//   - GatewayOutcomeBlock: refuse the launch / refuse the call. The
//                          CallRecord carries the reason so an
//                          operator reading the audit log sees why.
//
// Fail-closed defaults:
//
//   - Unknown server names produce GatewayOutcomeBlock with
//     ErrUnknownServer. The deny-by-default rule from the registry
//     surfaces here verbatim.
//   - A nil Registry produces GatewayOutcomeBlock with an explicit
//     error. The constructor refuses to build a Gateway without a
//     registry so this only fires from a misuse.
//   - A nil CallLogger is replaced by a no-op so a caller who has not
//     wired the audit sink yet (e.g. unit tests) does not crash; in
//     production the supervisor wires the run-scoped logger before
//     creating the gateway.
//   - A nil ScopeEnforcer for a scope kind that the server declares is
//     treated as "no enforcement available" and produces Block. The
//     master plan forbids "allow unknown scope": if the operator
//     declared a scope, every implementation that the gateway hands to
//     a server must be able to evaluate it. This is the rule that
//     keeps step 4 / step 5 from accidentally regressing to allow-by-
//     default when an enforcer is missing.
//
// The Gateway methods are safe for concurrent use. Registry is read-
// only after construction (step 1 documents the contract); the
// ScopeEnforcer interface is documented to be safe for concurrent
// AuthorizeCall calls; the CallLogger interface promises serialization
// of its Log calls. The Gateway itself holds no mutable state beyond
// the immutable references it was constructed with.

package mcp

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// GatewayOutcome is the gateway-facing verdict for one AuthorizeLaunch
// or AuthorizeCall. The three values match the per-server Policy enum
// and the master plan's "allow / deny / warn" decision vocabulary;
// "deny" is spelled "block" here because the gateway's verb is "block
// this specific request" rather than "register this server as denied"
// (the registry already owns the latter token via ServerPolicyDeny).
type GatewayOutcome int

const (
	// GatewayOutcomeAllow is the happy path: the gateway has no
	// objection and the caller may launch the server / dispatch the
	// call. The CallRecord is still written to the audit log so the
	// operator can reconstruct what happened.
	GatewayOutcomeAllow GatewayOutcome = iota

	// GatewayOutcomeWarn is the soft-failure path: the gateway lets
	// the launch / call proceed but emits a warning. The two main
	// producers are (1) the per-server Policy field set to "warn",
	// which warns on every call against that server, and (2) a
	// schema-hash mismatch when the server's Policy is "warn",
	// surfaced via the schema-compare path in AuthorizeLaunch.
	GatewayOutcomeWarn

	// GatewayOutcomeBlock is the hard-failure path: the caller must
	// refuse to launch the server / dispatch the call. The
	// GatewayDecision.Err field wraps the underlying sentinel
	// (ErrUnknownServer, ErrVersionMismatch, ErrDigestMismatch,
	// ErrSchemaMismatch, ErrScopeViolation) so callers can match
	// with errors.Is to surface a specific operator-facing message.
	GatewayOutcomeBlock
)

// String returns the lowercase token used in mcp-calls.jsonl. The
// audit log (step 7) reuses these tokens verbatim so a future log
// consumer can grep on the same values the gateway emits.
func (o GatewayOutcome) String() string {
	switch o {
	case GatewayOutcomeAllow:
		return "allow"
	case GatewayOutcomeWarn:
		return "warn"
	case GatewayOutcomeBlock:
		return "block"
	default:
		return fmt.Sprintf("unknown(%d)", int(o))
	}
}

// CallStage identifies which gateway entry point produced a CallRecord.
// The audit log carries this field so an operator reading
// mcp-calls.jsonl can tell a "may we launch the server?" verdict from a
// "may we dispatch this tool call?" verdict in a single grep.
type CallStage string

const (
	// CallStageLaunch is recorded by AuthorizeLaunch. The CallRecord
	// carries the source / digest / schema-hash decision context
	// alongside the verdict; Tool and Arguments are empty because a
	// launch decision is not tool-specific.
	CallStageLaunch CallStage = "launch"

	// CallStageCall is recorded by AuthorizeCall. The CallRecord
	// carries the tool name and the scope context the gateway
	// evaluated; the launch-stage fields (Source, Digest) are
	// usually empty because they were already recorded at launch
	// time, but the caller may populate them if the audit consumer
	// benefits from the redundancy.
	CallStageCall CallStage = "call"
)

// ErrScopeViolation is returned inside a GatewayDecision when a
// ScopeEnforcer refuses the call. The gateway wraps the enforcer's
// own error with this sentinel so callers can match with errors.Is
// regardless of which scope enforcer (filesystem, github, future
// kinds) produced the verdict.
var ErrScopeViolation = errors.New("mcp: scope violation")

// ErrServerParked is returned when AuthorizeLaunch or AuthorizeCall is
// invoked against a server whose registered Policy is ServerPolicyDeny.
// "deny" in the registry means "registered but parked": the metadata
// is kept on file (so an operator does not lose the pinned version
// during an incident) but the gateway must refuse to use it. A separate
// sentinel from ErrUnknownServer keeps the audit trail unambiguous: an
// operator can tell "I never registered this" from "I registered this
// then parked it" in a single grep.
var ErrServerParked = errors.New("mcp: server policy is deny")

// ErrMissingScopeEnforcer is returned when a server declares a scope
// kind for which the gateway has no enforcer wired. The master plan
// rule "deny unknown scope" surfaces here: a server that asked for a
// scope the gateway cannot evaluate is treated as a configuration
// error, not as an implicit allow. The sentinel lets callers match
// with errors.Is and surface the specific kind in the operator
// message.
var ErrMissingScopeEnforcer = errors.New("mcp: no scope enforcer registered for kind")

// ScopeRequest is the per-call payload the gateway hands to a
// ScopeEnforcer. The shape is intentionally generic: a filesystem
// enforcer reads Path, a GitHub enforcer reads Repo / Operation, a
// future enforcer reads whatever it needs from the free-form Extra
// map. Fields irrelevant to a given enforcer are left empty; an
// enforcer must not panic on missing fields and should return a
// ScopeViolation when a required field is empty.
//
// The gateway does not interpret these fields itself: it forwards the
// ScopeRequest to the enforcer registered for the matching ScopeKind
// (filesystem / github) and trusts the enforcer's verdict. This keeps
// the gateway free of workspace-path or repo-coordinate semantics so
// step 4 / step 5 can land their enforcement logic without touching
// this file.
type ScopeRequest struct {
	// Tool is the MCP tool name the agent is trying to call (e.g.
	// "read_file", "create_issue"). Forwarded to the enforcer so the
	// enforcer can vary its behavior per tool (a read tool may have
	// different scope constraints than a write tool).
	Tool string

	// Path is the filesystem path the call targets, when the call is
	// against a filesystem-kind scope. Empty for non-filesystem
	// scopes. The path is whatever the agent supplied; the enforcer
	// is responsible for resolving symlinks, normalizing relatives,
	// and rejecting traversal.
	Path string

	// Repo is the "owner/name" coordinate the call targets, when the
	// call is against a github-kind scope. Empty for non-github
	// scopes.
	Repo string

	// Operation is the GitHub operation kind the call performs
	// ("read" / "write"). Forwarded so the enforcer can apply the
	// per-server read_only / read_write distinction the registry
	// records.
	Operation string

	// Extra is the catch-all field for future scope kinds. The
	// gateway does not inspect it; the enforcer reads only the keys
	// it understands. Nil is fine.
	Extra map[string]string
}

// ScopeEnforcer is the plugin point the gateway uses to evaluate a
// per-call scope constraint. Plan 09 step 4 supplies the filesystem
// enforcer and step 5 supplies the GitHub enforcer; both implement
// this interface. Future scope kinds add new implementations and
// register them by kind in NewGateway's enforcers map.
//
// Implementations:
//
//   - must be safe for concurrent calls (the gateway may evaluate two
//     tool calls in parallel against the same enforcer);
//   - must return nil when the request is allowed;
//   - must return a non-nil error when the request is refused; the
//     gateway wraps it with ErrScopeViolation so callers can match
//     either the specific enforcer error or the generic sentinel;
//   - must never panic on a missing Path / Repo / Operation: the
//     gateway forwards the request verbatim and the enforcer is the
//     one with the type knowledge to know which fields it needs.
type ScopeEnforcer interface {
	// EnforceScope evaluates req against the enforcer's policy for
	// server. The server argument is the registry-level entry the
	// gateway looked up; the enforcer reads server.Scope[<kind>] to
	// pick up its declarative configuration (e.g. the registered
	// workspace_only root, the current_repo_only flag).
	EnforceScope(server RegistryServer, kind string, req ScopeRequest) error
}

// CallRecord is the on-disk projection of one gateway verdict. The
// shape is the contract between the gateway and the per-run audit log
// (step 7's mcp-calls.jsonl writer): the gateway builds a CallRecord
// every time it makes a decision and hands it to the registered
// CallLogger. The fields are encoded in declaration order; the JSON
// tags pin the on-disk spelling so a future writer that round-trips
// records can decode them without translation.
//
// Two record families share this shape:
//
//   - Stage == CallStageLaunch: the gateway answered "may this server
//     start?". Source / Digest / ExpectedHash / ActualHash carry the
//     pinning context. Tool / Path / Repo / Operation are empty.
//   - Stage == CallStageCall: the gateway answered "may this tool
//     call proceed?". Tool / Path / Repo / Operation carry the scope
//     context. The pinning fields are usually empty (already recorded
//     at launch) but may be populated for callers that prefer
//     self-contained records.
//
// The Decision field carries the GatewayOutcome.String() token; the
// Reason field carries the gateway's free-form explanation (e.g.
// "schema hash mismatch", "filesystem path outside workspace"). Both
// are required for operator-readable audit; a CallRecord with an
// empty Decision is rejected by the logger.
type CallRecord struct {
	// Timestamp is the moment the gateway reached the decision,
	// formatted as RFC3339 with a numeric offset. The gateway fills
	// this in from its clock; callers do not set it themselves.
	Timestamp string `json:"timestamp"`

	// Stage identifies which gateway entry point produced the record.
	// One of CallStageLaunch / CallStageCall.
	Stage CallStage `json:"stage"`

	// Server is the registered server name the decision applies to.
	// Always populated, even for unknown-server records (the caller's
	// supplied name is echoed so the audit trail captures what the
	// agent asked for).
	Server string `json:"server"`

	// Decision is the verdict token ("allow" / "warn" / "block").
	// Required.
	Decision string `json:"decision"`

	// Reason is the human-readable explanation. Required so the
	// audit log is self-contained without joining against source.
	// Examples: "schema hash mismatch", "filesystem path outside
	// workspace", "unknown server", "server policy deny".
	Reason string `json:"reason"`

	// Tool is the MCP tool name the agent invoked. Populated on
	// CallStageCall records; empty on CallStageLaunch.
	Tool string `json:"tool,omitempty"`

	// Source is the npm: / oci: source the gateway compared against
	// the registered Source. Populated on CallStageLaunch when the
	// caller supplied a candidate; empty otherwise.
	Source string `json:"source,omitempty"`

	// Digest is the sha256: digest the gateway compared against the
	// registered Digest. Populated on CallStageLaunch when the caller
	// supplied a candidate and the server has a registered digest.
	Digest string `json:"digest,omitempty"`

	// ExpectedHash is the registered schema hash at decision time
	// (RegistryServer.SchemaHash). Populated on CallStageLaunch when
	// the caller supplied a live schema hash. Empty for
	// freshly-registered servers (first-launch onboarding).
	ExpectedHash string `json:"expected_hash,omitempty"`

	// ActualHash is the freshly-computed schema hash the caller
	// supplied. Populated on CallStageLaunch when the caller supplied
	// a live schema hash.
	ActualHash string `json:"actual_hash,omitempty"`

	// Path is the filesystem path the call targeted. Populated on
	// CallStageCall when the scope kind is filesystem.
	Path string `json:"path,omitempty"`

	// Repo is the "owner/name" coordinate the call targeted.
	// Populated on CallStageCall when the scope kind is github.
	Repo string `json:"repo,omitempty"`

	// Operation is the GitHub operation kind ("read" / "write").
	// Populated on CallStageCall when the scope kind is github.
	Operation string `json:"operation,omitempty"`

	// ScopeKinds is the sorted list of scope kinds the gateway
	// evaluated for this call ("filesystem", "github"). Populated on
	// CallStageCall so an auditor can see at a glance which
	// enforcers participated in the decision.
	ScopeKinds []string `json:"scope_kinds,omitempty"`

	// TurnID is the supervisor-minted turn identifier in effect at the
	// moment the gateway reached this verdict. Populated by the bridge
	// that wires the gateway into a live run (see plan Batch 3.3 —
	// Turn-ID flows): the bridge consults the per-run control socket's
	// CurrentTurnID(role) before forwarding the record to the on-disk
	// MCPCallsWriter and stamps the result here so an auditor reading
	// mcp-calls.jsonl can join each MCP decision to the same agent turn
	// recorded in transcript.jsonl / policy-decisions.jsonl. Empty when
	// no turn source is wired (CLI dry-runs via `ai-env mcp scan`, the
	// unit tests for the gateway itself, the early plan-09 batches that
	// predate this field) or when the agent has not yet called
	// BeginTurn for this run; readers must treat an empty TurnID as
	// "unknown" rather than as a missing field. Plan §0 documents the
	// "best-effort under non-compromised agent" caveat: a compromised
	// agent that skips BeginTurn will leave this empty.
	TurnID string `json:"turn_id,omitempty"`

	// ResolvedPath is the canonical / normalized filesystem path the
	// gateway derived from Path (e.g. after symlink resolution or
	// workspace-root rebasing). Plan Batch 3.4 enumerates ResolvedPath
	// as one of the payload-derived CallRecord fields the request-
	// direction secret detector must redact when blocking a body that
	// contains a matched secret pattern. Empty for records that did
	// not resolve a path; readers treat empty as "not applicable".
	ResolvedPath string `json:"resolved_path,omitempty"`

	// Snippet is a short captured byte fragment showing the context
	// that triggered the gateway-side decision (e.g. the matched
	// argument or the rejected body fragment). Plan Batch 3.4
	// enumerates Snippet as one of the payload-derived CallRecord
	// fields the request-direction secret detector must redact: a
	// caller that lands a Snippet containing a matched secret has the
	// value rewritten to the sentinel before the record is logged.
	Snippet string `json:"snippet,omitempty"`

	// Args is the agent-supplied tool-call arguments blob the gateway
	// forwarded to the enforcer (typically the JSON-RPC "arguments"
	// member of a tools/call request, stringified for the audit log).
	// Plan Batch 3.4 enumerates Args as the highest-risk payload-
	// derived CallRecord field for secret detection: a secret in the
	// raw args is the canonical exfiltration vector the gateway
	// detector blocks. When the request-direction detector finds a
	// match, Args is rewritten to the sentinel before the record is
	// logged so an auditor sees the structural shape without the
	// leaked value. Empty for non-tools/call records.
	Args string `json:"args,omitempty"`
}

// CallLogger is the gateway-side interface step 7's
// mcp-calls.jsonl writer implements. Defining the interface here
// (rather than importing internal/run) keeps the mcp package free of
// run-package dependencies, mirroring how internal/run defines
// EngineDecision rather than importing internal/policy. The
// supervisor wires a concrete writer into the gateway at run startup
// and the gateway only sees the interface.
//
// Implementations must be safe for concurrent Log calls (the gateway
// may make decisions on parallel tool calls); they must persist the
// record before returning so a crash after Log returns does not lose
// the audit trail.
type CallLogger interface {
	// Log appends the record to the audit sink. Returning a non-nil
	// error does not affect the gateway's verdict (the operator
	// asked for the verdict; failing to record it is a separate
	// failure mode), but the gateway surfaces the error to its
	// caller so the supervisor can decide whether to abort the run.
	Log(record CallRecord) error
}

// noopCallLogger drops every record. Used when NewGateway is
// constructed without a logger (e.g. unit tests, the CLI's dry-run
// `ai-env mcp scan`). Defining the noop here means every caller can
// rely on Gateway.logger being non-nil without per-call nil checks.
type noopCallLogger struct{}

// Log implements CallLogger by discarding the record.
func (noopCallLogger) Log(CallRecord) error { return nil }

// CallLoggerFunc is a function adapter so callers can pass a closure
// where a CallLogger is required (mirrors http.HandlerFunc / the
// existing ShellEvaluatorFunc on the control socket). The gateway's
// own production wiring uses the cli.MCPCallLogger bridge type
// rather than this adapter; CallLoggerFunc is the right shape for
// unit tests that want to capture records in a slice without
// declaring a one-off struct.
type CallLoggerFunc func(CallRecord) error

// Log implements CallLogger by forwarding to the underlying
// function.
func (f CallLoggerFunc) Log(rec CallRecord) error { return f(rec) }

// GatewayDecision is the gateway-facing verdict the caller acts on.
// Distinct from CallRecord on purpose: CallRecord is the on-disk
// shape, GatewayDecision is the in-memory shape. The two carry
// overlapping information but a refactor of either side does not
// force a refactor of the other.
type GatewayDecision struct {
	// Outcome is the verdict token (GatewayOutcomeAllow / Warn /
	// Block). The caller switches on this value to decide whether to
	// launch the server / dispatch the call.
	Outcome GatewayOutcome

	// Reason is the human-readable explanation. Identical to the
	// Reason field on the emitted CallRecord; surfaced here so
	// callers that did not retain the record can still log a
	// per-operator message without parsing Err.
	Reason string

	// Err carries the underlying sentinel for Block / Warn outcomes
	// so callers can match with errors.Is(err, ErrSchemaMismatch),
	// ErrScopeViolation, ErrUnknownServer, etc. Nil for the Allow
	// outcome.
	Err error
}

// LaunchRequest bundles the candidate metadata AuthorizeLaunch
// consults to decide whether a server may start. The shape mirrors
// the fields the registry pins (Source, Digest) plus the dynamic
// SchemaHash the caller computed at launch time from the live
// server. All three fields are optional in the sense that the
// gateway tolerates an empty value (it means "do not check this
// dimension"), but a caller that omits all three is effectively
// asking only "is this server registered?", which is still a
// meaningful (and cheap) question.
type LaunchRequest struct {
	// Server is the registered server name the caller wants to
	// launch. Required: AuthorizeLaunch returns ErrUnknownServer
	// when this is empty or when no server is registered under the
	// given name.
	Server string

	// Source is the runtime-resolved source string (npm: or oci:)
	// the launcher would actually use. When non-empty the gateway
	// compares it against the registered Source via
	// Registry.MatchVersion; a mismatch is GatewayOutcomeBlock with
	// ErrVersionMismatch. When empty the version dimension is
	// skipped.
	Source string

	// Digest is the runtime-resolved sha256 digest the launcher
	// would actually use. When non-empty (and the server has a
	// registered digest) the gateway compares via
	// Registry.MatchDigest; a mismatch is GatewayOutcomeBlock with
	// ErrDigestMismatch. When empty (or when the server has no
	// registered digest) the digest dimension is skipped per the
	// registry's "empty pinned digest = version-only pinning"
	// rule.
	Digest string

	// LiveSchemaHash is the sha256 the caller computed by hashing
	// the live server's advertised tool list (via
	// ComputeSchemaHash). When non-empty the gateway runs the full
	// CompareSchemaHash flow (Record / Allow / Warn / Block per the
	// per-server Policy). When empty the schema dimension is
	// skipped.
	LiveSchemaHash string
}

// CallRequest bundles the per-tool-call payload AuthorizeCall
// consults. The shape carries the tool name (for audit) plus the
// per-scope payload the gateway forwards to each registered
// ScopeEnforcer. The same CallRequest is forwarded to every enforcer
// the server's Scope map declares (each gets the same Tool / Path /
// Repo / Operation / Extra); enforcers only read the fields
// meaningful to their kind.
type CallRequest struct {
	// Server is the registered server name the call targets.
	// Required: AuthorizeCall returns ErrUnknownServer when this is
	// empty or unknown.
	Server string

	// Tool is the MCP tool name the agent is invoking. Required:
	// AuthorizeCall returns a block with a clear reason when this
	// is empty so a misconfigured caller fails loudly.
	Tool string

	// Path is the filesystem path the call targets. Forwarded to a
	// filesystem-kind enforcer.
	Path string

	// Repo is the "owner/name" GitHub coordinate the call targets.
	// Forwarded to a github-kind enforcer.
	Repo string

	// Operation is the GitHub operation kind ("read" / "write").
	// Forwarded to a github-kind enforcer.
	Operation string

	// Extra is a catch-all for future scope kinds. Forwarded
	// verbatim to every enforcer.
	Extra map[string]string
}

// Gateway is the runtime proxy callers use to govern MCP traffic. A
// Gateway is constructed once per run from the loaded Registry, the
// per-run CallLogger, and the kind-keyed map of ScopeEnforcers; the
// supervisor passes the same Gateway to every code path that may
// launch a server or dispatch a tool call.
//
// The Gateway is immutable after construction: the registry is read-
// only, the logger interface promises its own concurrency, and the
// enforcers map is copied at construction time so a caller cannot
// mutate the gateway through the original map. This means a single
// Gateway can be shared by every goroutine in the run without further
// synchronization.
type Gateway struct {
	// registry is the source of truth for server registration,
	// version / digest pinning, and per-server scope declarations.
	// Never nil after NewGateway; the constructor rejects a nil
	// registry.
	registry *Registry

	// logger is the audit sink the gateway writes every CallRecord
	// to. Never nil after NewGateway; the constructor substitutes a
	// noopCallLogger when the caller does not supply one.
	logger CallLogger

	// enforcers is the kind-keyed map of ScopeEnforcer plugins. The
	// gateway looks up the enforcer for each scope kind a server
	// declares and forwards the CallRequest verbatim. A missing
	// enforcer for a declared kind is treated as a configuration
	// error (ErrMissingScopeEnforcer) rather than an implicit allow.
	enforcers map[string]ScopeEnforcer

	// now produces the timestamp stamped on every CallRecord. A
	// function (rather than a clock interface) so tests can inject a
	// deterministic sequence of times without a separate type;
	// production callers pass time.Now.
	now func() time.Time
}

// GatewayOptions bundles the optional construction inputs. The
// constructor accepts a nil *GatewayOptions to mean "all defaults",
// which keeps simple call sites (CLI dry-runs, unit tests) terse.
type GatewayOptions struct {
	// Logger is the audit sink. Nil substitutes a noop logger so
	// dry-run / test callers do not need to invent one.
	Logger CallLogger

	// Enforcers is the kind-keyed map of ScopeEnforcer plugins. Nil
	// or empty means no enforcers are registered: any server that
	// declares a scope will be blocked with ErrMissingScopeEnforcer
	// on the corresponding AuthorizeCall. This matches the master
	// plan's "deny unknown scope" rule.
	Enforcers map[string]ScopeEnforcer

	// Now is the clock the gateway uses to stamp CallRecord.Timestamp.
	// Nil falls back to time.Now.
	Now func() time.Time
}

// NewGateway constructs a Gateway from the validated Registry plus
// the optional GatewayOptions. The registry must be non-nil; a nil
// registry is a programming error (the loader returns *Registry on
// success, so the only way to reach here with nil is to pass the
// zero value).
//
// The returned Gateway is safe for concurrent use. The options' maps
// and clock are copied/captured by reference; callers who mutate the
// map after construction will mutate the gateway too, which is
// almost certainly a bug, so do not do that.
func NewGateway(registry *Registry, opts *GatewayOptions) (*Gateway, error) {
	if registry == nil {
		return nil, errors.New("mcp: NewGateway requires a non-nil Registry")
	}
	var (
		logger    CallLogger          = noopCallLogger{}
		enforcers map[string]ScopeEnforcer
		clock     func() time.Time = time.Now
	)
	if opts != nil {
		if opts.Logger != nil {
			logger = opts.Logger
		}
		if len(opts.Enforcers) > 0 {
			enforcers = make(map[string]ScopeEnforcer, len(opts.Enforcers))
			for kind, e := range opts.Enforcers {
				enforcers[kind] = e
			}
		}
		if opts.Now != nil {
			clock = opts.Now
		}
	}
	return &Gateway{
		registry:  registry,
		logger:    logger,
		enforcers: enforcers,
		now:       clock,
	}, nil
}

// Registry returns the gateway's registry. Exposed so callers that
// hold a Gateway can read pinned metadata (the CLI's `ai-env mcp
// list` uses this) without re-loading mcp.yaml.
func (g *Gateway) Registry() *Registry { return g.registry }

// AuthorizeLaunch decides whether the named server may start. The
// decision is a four-step pipeline; the first failing step
// short-circuits to a GatewayOutcomeBlock so the audit log records
// the most-specific reason (not "schema mismatch" when the real
// problem was an unknown server).
//
// Pipeline:
//
//   1. Registry.Lookup(name): unknown server -> Block with
//      ErrUnknownServer. Master-plan deny-by-default rule.
//   2. RegistryServer.Policy == ServerPolicyDeny -> Block with
//      ErrServerParked. A parked server stays parked at launch.
//   3. Source / Digest checks against Registry.MatchVersion /
//      MatchDigest. Empty caller-supplied values skip the dimension;
//      a mismatch is Block with ErrVersionMismatch / ErrDigestMismatch.
//   4. Schema-hash compare via Registry.CompareSchemaHash when the
//      caller supplied a LiveSchemaHash. The compare returns one of
//      SchemaOutcomeAllow / Record / Warn / Block; the gateway maps
//      Record -> Allow (with a "first launch, please pin" Reason),
//      Warn -> Warn, Block -> Block (carries ErrSchemaMismatch),
//      Allow -> Allow.
//
// If steps 1-3 pass and step 4 is skipped (no live hash supplied),
// the gateway applies the per-server Policy: ServerPolicyWarn
// produces a launch-time warning (the operator pinned a server they
// want flagged on every launch); ServerPolicyAllow is the happy path;
// ServerPolicyDeny was already handled in step 2.
//
// Every code path emits exactly one CallRecord to the registered
// CallLogger before returning. A logger error does not change the
// decision returned to the caller but is surfaced as the second
// return value so the supervisor can decide whether to abort.
func (g *Gateway) AuthorizeLaunch(req LaunchRequest) (GatewayDecision, error) {
	rec := CallRecord{
		Timestamp: g.now().Format(time.RFC3339),
		Stage:     CallStageLaunch,
		Server:    req.Server,
		Source:    req.Source,
		Digest:    req.Digest,
	}

	// Step 1: deny-by-default for unknown servers.
	server, err := g.registry.Lookup(req.Server)
	if err != nil {
		return g.finalize(rec, GatewayDecision{
			Outcome: GatewayOutcomeBlock,
			Reason:  fmt.Sprintf("unknown server %q", req.Server),
			Err:     err,
		})
	}

	// Step 2: parked-server check.
	if server.Policy == ServerPolicyDeny {
		return g.finalize(rec, GatewayDecision{
			Outcome: GatewayOutcomeBlock,
			Reason:  fmt.Sprintf("server %q policy is deny (parked)", req.Server),
			Err:     fmt.Errorf("%w: %s", ErrServerParked, req.Server),
		})
	}

	// Step 3a: version pin (when caller supplied a candidate).
	if req.Source != "" {
		if err := g.registry.MatchVersion(req.Server, req.Source); err != nil {
			return g.finalize(rec, GatewayDecision{
				Outcome: GatewayOutcomeBlock,
				Reason:  fmt.Sprintf("server %q source mismatch", req.Server),
				Err:     err,
			})
		}
	}

	// Step 3b: digest pin (when caller supplied a candidate and the
	// server has a registered digest; MatchDigest already encodes the
	// "empty registered digest = accept anything" rule).
	if req.Digest != "" {
		if err := g.registry.MatchDigest(req.Server, req.Digest); err != nil {
			return g.finalize(rec, GatewayDecision{
				Outcome: GatewayOutcomeBlock,
				Reason:  fmt.Sprintf("server %q digest mismatch", req.Server),
				Err:     err,
			})
		}
	}

	// Step 4: schema-hash compare (when caller supplied a live hash).
	// CompareSchemaHash internally consults the per-server Policy to
	// decide between Warn and Block on a mismatch.
	if req.LiveSchemaHash != "" {
		sd := g.registry.CompareSchemaHash(req.Server, req.LiveSchemaHash)
		rec.ExpectedHash = sd.Expected
		rec.ActualHash = sd.Actual
		switch sd.Outcome {
		case SchemaOutcomeAllow:
			// Fall through to per-server Policy below.
		case SchemaOutcomeRecord:
			// First launch: allow but flag in the audit reason so
			// the operator knows they should pin the hash.
			return g.finalize(rec, GatewayDecision{
				Outcome: GatewayOutcomeAllow,
				Reason:  fmt.Sprintf("server %q first launch; pin schema hash %q", req.Server, sd.Actual),
			})
		case SchemaOutcomeWarn:
			return g.finalize(rec, GatewayDecision{
				Outcome: GatewayOutcomeWarn,
				Reason:  fmt.Sprintf("server %q schema hash drift (warn policy)", req.Server),
			})
		case SchemaOutcomeBlock:
			return g.finalize(rec, GatewayDecision{
				Outcome: GatewayOutcomeBlock,
				Reason:  fmt.Sprintf("server %q schema hash mismatch", req.Server),
				Err:     sd.Err,
			})
		}
	}

	// Steps 1-4 passed; apply per-server Policy. ServerPolicyAllow is
	// the happy path; ServerPolicyWarn produces a per-launch warning
	// so the operator sees the flagged server in the audit log every
	// time. ServerPolicyDeny was already handled in step 2.
	if server.Policy == ServerPolicyWarn {
		return g.finalize(rec, GatewayDecision{
			Outcome: GatewayOutcomeWarn,
			Reason:  fmt.Sprintf("server %q policy is warn", req.Server),
		})
	}
	return g.finalize(rec, GatewayDecision{
		Outcome: GatewayOutcomeAllow,
		Reason:  fmt.Sprintf("server %q allowed", req.Server),
	})
}

// AuthorizeCall decides whether the named tool call may be dispatched
// to the named server. The pipeline mirrors AuthorizeLaunch's
// registration / parked-server checks, then forwards a ScopeRequest
// to the enforcer registered for each scope kind the server declared.
// Any enforcer error short-circuits to GatewayOutcomeBlock with
// ErrScopeViolation wrapping the enforcer's error.
//
// Pipeline:
//
//   1. Registry.Lookup -> ErrUnknownServer on miss (Block).
//   2. ServerPolicyDeny -> ErrServerParked (Block).
//   3. req.Tool empty -> Block with explicit reason.
//   4. For each scope kind in server.Scope (in sorted order so the
//      audit record's ScopeKinds list is deterministic): look up the
//      enforcer; nil enforcer -> Block with ErrMissingScopeEnforcer;
//      enforcer error -> Block with ErrScopeViolation wrapping it.
//   5. If no scope was declared by the server, the call is judged by
//      the per-server Policy alone: warn -> Warn, allow -> Allow.
//
// The CallRecord written to the audit log carries Tool / Path / Repo /
// Operation / ScopeKinds so an auditor can reconstruct what the
// gateway evaluated.
func (g *Gateway) AuthorizeCall(req CallRequest) (GatewayDecision, error) {
	rec := CallRecord{
		Timestamp: g.now().Format(time.RFC3339),
		Stage:     CallStageCall,
		Server:    req.Server,
		Tool:      req.Tool,
		Path:      req.Path,
		Repo:      req.Repo,
		Operation: req.Operation,
	}

	// Step 1: deny-by-default for unknown servers.
	server, err := g.registry.Lookup(req.Server)
	if err != nil {
		return g.finalize(rec, GatewayDecision{
			Outcome: GatewayOutcomeBlock,
			Reason:  fmt.Sprintf("unknown server %q", req.Server),
			Err:     err,
		})
	}

	// Step 2: parked-server check.
	if server.Policy == ServerPolicyDeny {
		return g.finalize(rec, GatewayDecision{
			Outcome: GatewayOutcomeBlock,
			Reason:  fmt.Sprintf("server %q policy is deny (parked)", req.Server),
			Err:     fmt.Errorf("%w: %s", ErrServerParked, req.Server),
		})
	}

	// Step 3: tool must be named so the audit record is meaningful
	// and so the enforcer can vary behavior per tool.
	if req.Tool == "" {
		return g.finalize(rec, GatewayDecision{
			Outcome: GatewayOutcomeBlock,
			Reason:  fmt.Sprintf("server %q: tool name required", req.Server),
			Err:     errors.New("mcp: AuthorizeCall requires CallRequest.Tool"),
		})
	}

	// Step 4: enforce every declared scope. Sorting the kinds keeps
	// the audit log deterministic and means a multi-scope server's
	// first-failure reason is stable across runs.
	kinds := sortedScopeKinds(server.Scope)
	rec.ScopeKinds = kinds
	scopeReq := ScopeRequest{
		Tool:      req.Tool,
		Path:      req.Path,
		Repo:      req.Repo,
		Operation: req.Operation,
		Extra:     req.Extra,
	}
	for _, kind := range kinds {
		enforcer := g.enforcers[kind]
		if enforcer == nil {
			return g.finalize(rec, GatewayDecision{
				Outcome: GatewayOutcomeBlock,
				Reason:  fmt.Sprintf("server %q scope %q has no enforcer registered", req.Server, kind),
				Err:     fmt.Errorf("%w: %s", ErrMissingScopeEnforcer, kind),
			})
		}
		if err := enforcer.EnforceScope(server, kind, scopeReq); err != nil {
			return g.finalize(rec, GatewayDecision{
				Outcome: GatewayOutcomeBlock,
				Reason:  fmt.Sprintf("server %q scope %q rejected: %s", req.Server, kind, err.Error()),
				Err:     fmt.Errorf("%w: kind %s: %w", ErrScopeViolation, kind, err),
			})
		}
	}

	// Step 5: per-server Policy. warn -> Warn (every call flagged);
	// allow -> Allow.
	if server.Policy == ServerPolicyWarn {
		return g.finalize(rec, GatewayDecision{
			Outcome: GatewayOutcomeWarn,
			Reason:  fmt.Sprintf("server %q policy is warn (tool %q)", req.Server, req.Tool),
		})
	}
	return g.finalize(rec, GatewayDecision{
		Outcome: GatewayOutcomeAllow,
		Reason:  fmt.Sprintf("server %q tool %q allowed", req.Server, req.Tool),
	})
}

// finalize is the shared exit point for AuthorizeLaunch and
// AuthorizeCall. It stamps the decision onto the CallRecord, hands
// the record to the logger, and returns the decision plus any logger
// error. Centralizing this here keeps the two Authorize methods from
// having to remember the order (set Decision, set Reason, Log, return)
// and guarantees every code path emits exactly one record.
func (g *Gateway) finalize(rec CallRecord, dec GatewayDecision) (GatewayDecision, error) {
	rec.Decision = dec.Outcome.String()
	rec.Reason = dec.Reason
	if err := g.logger.Log(rec); err != nil {
		return dec, fmt.Errorf("mcp: log call record: %w", err)
	}
	return dec, nil
}

// sortedScopeKinds returns the keys of the scope map in sorted order.
// Used by AuthorizeCall so the audit log's ScopeKinds list and the
// scope-evaluation order are both deterministic regardless of map
// iteration order.
func sortedScopeKinds(scope map[string]ScopeSection) []string {
	if len(scope) == 0 {
		return nil
	}
	out := make([]string, 0, len(scope))
	for k := range scope {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
