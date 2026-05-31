// Lifecycle verbs (Plan 0.1, this plan's "Leak-coverage hardening" §0).
//
// The lifecycle stream lifecycle.jsonl has, up to and including Batch 0.0,
// carried only state-transition records (StateRunning, StateStopping, ...).
// Batch 0.1 broadens the same stream into the single chronologically-
// ordered record of every supervisor side-channel event: the supplemental
// subsystems the plan introduces (ProviderProxy, MCP Gateway, Network
// Observer, GitHub Broker, Control Socket, MCP-config neutralization, ...)
// each emit start/stop/degraded events into the same file the supervisor
// already opens and fsyncs per-event.
//
// Folding the verbs into lifecycle.jsonl (rather than minting a new file
// per subsystem) keeps three invariants the audit reviewer depends on:
//
//   - One chronological feed per run. A reviewer walking lifecycle.jsonl
//     sees state transitions and subsystem events in the order the
//     supervisor experienced them, without having to merge-sort by
//     timestamp across files.
//
//   - One fsync discipline. LifecycleWriter already syncs after every
//     append (a host crash between an event and the next would otherwise
//     erase the lifecycle trail). Verb records inherit that guarantee
//     for free, so e.g. an observer_unavailable verb survives even a
//     fast-following supervisor crash.
//
//   - One redaction surface. The Batch 0.2 leaks aggregator walks the
//     same single file when building leaks.jsonl. Adding a second
//     stream would force the aggregator to learn another shape.
//
// The two record kinds coexist in the same file because LifecycleEvent's
// State and Verb tags both carry `omitempty`. A state-transition record
// (Batch 0.0 byte-for-byte format) has State set and no Verb/Metadata; a
// verb-event record has Verb set, optional Metadata, and no State. The
// Batch 0.0 plan-example byte-for-byte test stays green because the new
// fields are simply absent on state records.
//
// Per-verb Metadata key tables
// ----------------------------
//
// Each LifecycleVerb constant below documents the Metadata keys the
// supervisor writes when emitting that verb. The keys are the contract:
// downstream readers (`leaks.jsonl` aggregator, final-summary renderer,
// audit reviewer) join on these names. The values are always strings to
// keep the on-disk JSON shape uniform (no per-key polymorphism); callers
// stringify numbers and booleans before writing.
//
// Required vs optional is called out per key. Required keys MUST appear
// on every emission of that verb; the lifecycle writer does not enforce
// this (it would couple the writer to per-verb policy), so each emitter
// owns its own per-key completeness.
package run

// LifecycleVerb identifies a non-state-transition lifecycle event. Verb
// strings are deliberately short snake_case so the on-wire JSON stays
// compact and a human reading lifecycle.jsonl can grep by verb.
//
// New verbs are added by extending the constant block below; readers
// MUST ignore unknown verbs (forward compatibility). The aggregator at
// `internal/run/leaks.go` joins on verb name to decide which records
// participate in leaks.jsonl.
type LifecycleVerb string

// The lifecycle verb constants below correspond one-to-one with the
// "Batch 0.1 — Lifecycle verbs + per-verb Metadata schema" list in the
// plan. Order is the plan's order to make grep-against-plan easy.
const (
	// LifecycleVerbProxyStarted records ProviderProxy listener start
	// (Plan §5.5 step 8). Emitted once per provider proxy after the
	// per-provider listener is bound and the upstream Host-header
	// allowlist is wired in.
	//
	// Metadata keys:
	//   - "provider"       (required) — provider name, e.g. "anthropic" / "openai"
	//   - "listen_addr"    (required) — host:port the proxy bound (sandbox-side)
	//   - "upstream_host"  (required) — canonical upstream host the allowlist pins
	//   - "reachability"   (required) — one of "setns_tcp" / "bridge_gateway" / "unix_socket"
	LifecycleVerbProxyStarted LifecycleVerb = "proxy_started"

	// LifecycleVerbProxyStopped records ProviderProxy listener stop
	// (Plan §5.5 teardown step 5). Emitted once per provider proxy.
	//
	// Metadata keys:
	//   - "provider" (required) — provider name; matches the start event
	//   - "reason"   (required) — short token: "teardown" / "error" / "shutdown"
	LifecycleVerbProxyStopped LifecycleVerb = "proxy_stopped"

	// LifecycleVerbGatewayStarted records the MCP Gateway coming up
	// (Plan §5.5 step 9). Emitted once per run.
	//
	// Metadata keys:
	//   - "server_count" (required) — number of registered MCP servers, stringified int
	//   - "config_path"  (required) — absolute path of <runDir>/mcp-servers.json
	LifecycleVerbGatewayStarted LifecycleVerb = "gateway_started"

	// LifecycleVerbGatewayStopped records the MCP Gateway going down
	// (Plan §5.5 teardown step 6). Emitted once per run.
	//
	// Metadata keys:
	//   - "reason" (required) — "teardown" / "error" / "shutdown"
	LifecycleVerbGatewayStopped LifecycleVerb = "gateway_stopped"

	// LifecycleVerbGatewaySecretBlocked records an MCP Gateway request
	// that the per-direction secret scanner blocked outbound (request
	// body, agent -> upstream). Emitted once per blocked request.
	//
	// Metadata keys:
	//   - "server"    (required) — MCP server name the request targeted
	//   - "operation" (required) — JSON-RPC method the request invoked
	//   - "pattern"   (required) — name of the matched scanners.builtinPatterns() rule
	//   - "finding_id"(required) — opaque per-finding id leaks.jsonl will dedupe on
	LifecycleVerbGatewaySecretBlocked LifecycleVerb = "gateway_secret_blocked"

	// LifecycleVerbGatewaySecretResponse records an MCP Gateway response
	// in which the per-direction secret scanner found and redacted
	// matched values (upstream -> agent direction). Emitted once per
	// scrubbed response (a single response with multiple matches still
	// emits one verb record; per-match details ride in leaks.jsonl).
	//
	// Metadata keys:
	//   - "server"    (required) — MCP server name that produced the response
	//   - "operation" (required) — JSON-RPC method the response answered
	//   - "pattern"   (required) — name of the matched rule (first match wins for naming)
	//   - "match_count"(required) — total redacted values in the response, stringified int
	//   - "finding_id"(required) — opaque per-finding id leaks.jsonl will dedupe on
	LifecycleVerbGatewaySecretResponse LifecycleVerb = "gateway_secret_response"

	// LifecycleVerbObserverStarted records the EgressObserver coming up
	// (Plan §5.5 step 5). Emitted once per run when NFLOG / pflog is
	// successfully attached.
	//
	// Metadata keys:
	//   - "mode"  (required) — "nflog" (Linux) / "pflog" (macOS)
	//   - "chain" (required) — per-run chain name "AIENV-EGR-<8hex>"
	LifecycleVerbObserverStarted LifecycleVerb = "observer_started"

	// LifecycleVerbObserverStopped records the EgressObserver going down
	// (Plan §5.5 teardown step 4). Emitted once per run.
	//
	// Metadata keys:
	//   - "reason" (required) — "teardown" / "error" / "shutdown"
	LifecycleVerbObserverStopped LifecycleVerb = "observer_stopped"

	// LifecycleVerbObserverUnavailable records that the EgressObserver
	// could not start in this run's environment (e.g. slirp4netns where
	// NFLOG is not reachable). Plan locks slirp4netns -> this verb. The
	// run continues; the verb is the audit signal that network-level
	// evidence is degraded.
	//
	// Metadata keys:
	//   - "reason" (required) — short token: "slirp4netns" / "no_capability" / other
	//   - "detail" (optional) — human-readable detail for the audit log
	LifecycleVerbObserverUnavailable LifecycleVerb = "observer_unavailable"

	// LifecycleVerbBrokerStarted records the GitHub broker coming up
	// (Plan §3, Bucket 3). Emitted once per run when broker construction
	// from .ai-env/secrets.local.yaml succeeds.
	//
	// Metadata keys:
	//   - "app_id"      (required) — GitHub App ID, stringified
	//   - "installation"(required) — installation id, stringified
	//   - "origin"      (required) — workspace origin URL (already redacted upstream)
	LifecycleVerbBrokerStarted LifecycleVerb = "broker_started"

	// LifecycleVerbBrokerStopped records the GitHub broker shutting down
	// (Plan teardown). Emitted once per run.
	//
	// Metadata keys:
	//   - "reason" (required) — "teardown" / "error" / "shutdown"
	LifecycleVerbBrokerStopped LifecycleVerb = "broker_stopped"

	// LifecycleVerbBrokerUnavailable records that the GitHub broker
	// could not start in this run (missing secrets, origin drift,
	// network failure on App-token mint). The run continues without
	// push capability; the verb is the audit signal.
	//
	// Metadata keys:
	//   - "reason" (required) — short token: "missing_secrets" / "origin_drift" / "mint_failed"
	//   - "detail" (optional) — human-readable detail
	LifecycleVerbBrokerUnavailable LifecycleVerb = "broker_unavailable"

	// LifecycleVerbControlSocketStarted records the control socket
	// listener binding (Plan §5.5 step 2). Emitted once per run.
	//
	// Metadata keys:
	//   - "path" (required) — absolute path of <runDir>/control.sock
	LifecycleVerbControlSocketStarted LifecycleVerb = "control_socket_started"

	// LifecycleVerbControlSocketStopped records the control socket
	// listener tearing down (Plan §5.5 teardown step 8). Emitted once
	// per run.
	//
	// Metadata keys:
	//   - "reason" (required) — "teardown" / "error" / "shutdown"
	LifecycleVerbControlSocketStopped LifecycleVerb = "control_socket_stopped"

	// LifecycleVerbNetworkPolicyDegraded records that the network policy
	// applied to the run is narrower than the configured policy. Plan §10
	// (locked decision row 10): emitted via BackendEventSink when the
	// adapter cannot enforce a portion of the policy (e.g. iptables rule
	// rejected, ipset unavailable). The run continues.
	//
	// Metadata keys:
	//   - "reason"  (required) — short token: "iptables_rejected" / "ipset_missing" / other
	//   - "missing" (optional) — comma-separated short tokens listing what was dropped
	//   - "detail"  (optional) — human-readable detail
	LifecycleVerbNetworkPolicyDegraded LifecycleVerb = "network_policy_degraded"

	// LifecycleVerbSecretsPermissionWarning records a permission anomaly
	// the secret-scan loader noticed (e.g. .ai-env/secrets.local.yaml
	// world-readable). Emitted before the secrets are used so a reviewer
	// can correlate later activity. The run continues; the verb is the
	// audit signal.
	//
	// Metadata keys:
	//   - "path"   (required) — absolute path of the offending file
	//   - "mode"   (required) — octal mode the file had, stringified ("0644")
	//   - "wanted" (required) — octal mode expected, stringified ("0600")
	LifecycleVerbSecretsPermissionWarning LifecycleVerb = "secrets_permission_warning"

	// LifecycleVerbShimCoverageDegraded records that one or more shim
	// wrappers could not be installed at every canonical path (Plan
	// Bucket 1: docker auto-creates non-existent targets, but a bind
	// mount that fails is non-fatal per-entry — the verb is the audit
	// signal that the shadow set is incomplete).
	//
	// Metadata keys:
	//   - "program" (required) — program name whose coverage is degraded ("python3")
	//   - "missing" (required) — comma-separated canonical paths that failed to mount
	//   - "reason"  (optional) — short token from the backend error
	LifecycleVerbShimCoverageDegraded LifecycleVerb = "shim_coverage_degraded"

	// LifecycleVerbHelperRPCAborted records a control-socket RPC the
	// supervisor refused mid-flight (token mismatch, version mismatch,
	// AcceptingShutdown gate). Emitted once per aborted RPC.
	//
	// Metadata keys:
	//   - "method" (required) — control-socket method name ("Hello" / "BeginTurn" / ...)
	//   - "reason" (required) — short token: "bad_token" / "version_mismatch" / "shutdown" / "no_handler"
	//   - "peer"   (optional) — remote address / pid identifier when known
	LifecycleVerbHelperRPCAborted LifecycleVerb = "helper_rpc_aborted"

	// LifecycleVerbTranscriptParserError records a per-CLI transcript
	// parser failure (Plan Bucket 8). Emitted at most once per scanner
	// error window (the parser de-duplicates inside a single run); the
	// run continues, the transcript stream is marked degraded.
	//
	// Metadata keys:
	//   - "cli"    (required) — agent CLI name ("claude" / "codex")
	//   - "reason" (required) — short token: "scan_overflow" / "json_parse" / "stream_error"
	//   - "detail" (optional) — human-readable detail (already redacted)
	LifecycleVerbTranscriptParserError LifecycleVerb = "transcript_parser_error"

	// LifecycleVerbMCPConfigNeutralized records that a workspace-local
	// MCP config (`.mcp.json` / `.claude/settings.json#mcpServers`) was
	// renamed to `.ai-env-shadowed` at backend.Create to prevent the
	// agent CLI from auto-merging the workspace config with the
	// supervisor-managed mcp-servers.json. Plan Bucket 4 locked
	// decision; emitted once per neutralized file.
	//
	// Metadata keys:
	//   - "original" (required) — absolute path before rename
	//   - "shadowed" (required) — absolute path after rename
	//   - "kind"     (required) — "mcp_json" / "claude_settings_mcp_servers"
	LifecycleVerbMCPConfigNeutralized LifecycleVerb = "mcp_config_neutralized"
)
