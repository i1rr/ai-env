# Changelog

This file records material changes to `ai-env`. Operator-facing
references live under `docs/`; this file is the chronological summary.

## Leak-coverage hardening (plan 10)

This drop wires every "wire" and "instrument" and "tighten"
leak-prevention surface identified by `.audit/leak-coverage.md` into
a single coherent run, with `internal/run/supervisor` as the central
wiring spot and a new derived `leaks.jsonl` as the unified evidence
view. Existing per-subsystem JSONL schemas are preserved.

### Added

- `internal/run/control_socket.go`: JSON-RPC control socket bound at
  `<runDir>/control.sock`, primary `control_token` plus per-MCP-server
  `server_token`s. `AuthorizeMCPCall` verifies `(server, token)`
  pairs; `BeginTurn` / `CurrentTurn` mint and read supervisor turn
  ids; `AcceptingShutdown` cleanly refuses new RPCs during teardown.
- Lifecycle verb constants and per-verb metadata schemas
  (`internal/run/lifecycle_verbs.go`) covering every subsystem the
  supervisor wires: `proxy_started/_stopped`,
  `gateway_started/_stopped/_secret_blocked/_secret_response`,
  `observer_started/_stopped/_unavailable`,
  `broker_started/_stopped/_unavailable`,
  `control_socket_started/_stopped`, `network_policy_degraded`,
  `secrets_permission_warning`, `shim_coverage_degraded`,
  `helper_rpc_aborted`, `transcript_parser_error`,
  `mcp_config_neutralized`.
- `internal/run/leaks.go`: `LeakRecord` and `LeakEvidence` schema
  carrying `_schema_version: 1`; `LeaksWriter` with atomic
  "write tmp, fsync, rename" semantics; `<runDir>/leaks.jsonl` as the
  unified derived view. Every non-empty string passes through the
  broadened `secrets.RedactSecrets`.
- `internal/run/leaks_aggregate.go`: walks every per-subsystem stream
  at finalize time and produces deduplicated `LeakRecord` rows.
- `cmd/ai-env shim-helper {shell,mcp}`: shim helper subcommand. Shell
  mode opens a single `O_RDONLY | O_NOFOLLOW` fd and execs via
  `SYS_EXECVEAT` on Linux or `/dev/fd/<n>` on macOS so the scan-and-exec
  flow is TOCTOU-safe. MCP mode runs a long-lived stdio shim with a
  JSON-aware response scrubber and a 256-byte rolling-buffer streaming
  scanner so secrets that straddle chunk boundaries are still caught.
  `argv[0]` is forced to the canonical program basename so `exec -a`
  spoofing is rejected.
- `internal/policy/shim_install.go` and
  `internal/policy/shim_programs.go`: canonical-path shadow set for
  every shim'd program (`/usr/bin/`, `/bin/`, `/usr/local/bin/` plus
  version-suffix variants).
- `internal/capability/`: capability detection (CAP_NET_ADMIN, setns,
  userns-remap on Linux; pflog availability on macOS).
- `internal/backend/backend.go`: `BindMount`, `EnvSpec.BindMounts`,
  `EnvSpec.UID`, `EnvSpec.HomeTarget`, `BackendEventSink`,
  `Backend.GatewayAddress`, `Backend.MappedUID`. The mount split
  separates the sensitive `<runDir>/` (host-only) from the
  `<runDir>/ipc/` agent-visible surface.
- `internal/secrets/local.go` and `internal/secrets/build.go`:
  `.ai-env/secrets.local.yaml` loader with mode-0600 check,
  `BuildProviderProxyFromSecrets`, `BuildBrokerFromSecrets`.
- `internal/secrets/proxy.go`: per-provider ProviderProxy with
  upstream Host-header allowlist (exact-match `api.anthropic.com` or
  `api.openai.com`), reachability mode selection
  (`SetnsTCP` / `BridgeGateway` / `UnixSocket`).
- `internal/mcp/`: BuildRunGateway, per-run `mcp-servers.json` with
  per-server short-lived tokens, workspace-MCP-config shadowing at
  `backend.Create`, per-direction JSON-aware secret detector.
- `internal/githubbroker/`: origin pin captured at `ai-env new`,
  re-checked at PR time and refused on `origin_drift`. Fresh
  `AcquireToken` per `PushBranch`; no mid-call refresh.
- `internal/egress/nflog/`: Linux NFLOG reader via
  `github.com/florianl/go-nflog/v2`.
- `internal/egress/pflog/`: macOS pflog reader via `tcpdump`.
- `internal/egress/rules/iptables_linux.go`: per-run chain
  `AIENV-EGR-<8hex>` rule lifecycle.
- `internal/egress/rules/pf_darwin.go`: macOS pf rule lifecycle.
- `internal/run/network_policy_degraded_metadata.go` plus adapter
  emission of `network_policy_degraded` via `BackendEventSink`.
- `internal/run/filesystem_events.go`:
  `FilesystemEventRecord` and `FilesystemEventsWriter`, with the MCP
  gateway and shell shim as emitters.
- `internal/run/transcript.go`: `TranscriptRecord` and per-CLI
  parsers for Claude Code stream-json and Codex `--json`, with the
  1 MiB scanner cap and the canonical `Kind` token set.
- `cmd/ai-env leaks`: reader for `leaks.jsonl` with `--format`,
  `--vector`, `--source` filters and `--run` pinning. Skips
  `*.tmp.*` files.
- `docs/leaks-jsonl-schema.md`,
  `docs/transcript-jsonl-schema.md`,
  `docs/filesystem-events-jsonl-schema.md`: on-disk schema references.
- `docs/platform-parity.md`: per-platform feature matrix for Linux
  and macOS.
- `docs/operator-runbook.md`: install, run, and troubleshoot guide.

### Changed

- `internal/secrets/proxy.go`: `secretPatterns` extended to mirror
  `scanners.builtinPatterns()` (sk-ant, sk-, ghp_/gho_/ghs_/github_pat_,
  AKIA, GCP svc-acct JSON, Azure, Slack, Stripe, PEM, SSH key blobs,
  `PASSWORD=...`, npm).
- `internal/run/run.go`: appended `leaks.jsonl` and `transcript.jsonl`
  to `runFileNames`. `CreateRunDirectory` ends with
  `chmod runDir 0700`. Stale `*.tmp.*` files older than the current
  run start are swept at supervisor start.
- `internal/run/record.go`: added `SchemaVersions map[string]int` to
  the per-run record. Populated at supervisor step 1 (lifecycle
  open), not at finalize, so mid-run readers see the map.
- `internal/run/supervisor.go`: canonical 11-step pre-launch and
  9-step teardown sequence (see plan §5.5). The observer starts
  post-`backend.Start` so the netns is valid; iptables rules install
  after that; the MCP Gateway and workspace shadowing happen at
  `backend.Create`.
- README.md: updated to document the new JSONL streams, the
  `ai-env leaks` subcommand, the operator runbook, and the platform
  parity matrix.

### Security

- Raw provider API keys never enter the sandbox. The ProviderProxy
  speaks plain HTTP on 127.0.0.1, the agent sees only
  `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`, and host-side authentication
  attaches the credential before the upstream HTTPS dial.
- GitHub broker tokens are held in an in-memory `TokenHolder` with TTL
  clamping and revocation; `RedactTokens` is the log-write backstop.
- MCP per-server tokens are scoped to a single server; the primary
  control token is delivered to helper processes via a side-band
  mechanism that the agent UID cannot read.
- `secrets.local.yaml` mode 0600 is enforced via load-time check; a
  permission anomaly is recorded as `secrets_permission_warning`
  before the credential is used.
- Workspace-local MCP configs are renamed to `*.ai-env-shadowed` at
  `backend.Create` so an agent CLI cannot auto-merge them with the
  supervisor-managed `mcp-servers.json`.

## Earlier plans (01-09)

See README.md "Status" section for the cumulative summary of plans
01 through 09 (workspace scaffolding, backends, supervisor and run
lifecycle, agent launchers, network policy, scanners, GitHub broker,
policy engine and shell-shim prototype, MCP gateway).
