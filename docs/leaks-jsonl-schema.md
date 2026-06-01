# leaks.jsonl schema

`leaks.jsonl` is the unified, derived view the supervisor writes at run
finalize time. It joins every per-subsystem evidence stream
(`lifecycle.jsonl`, `policy-decisions.jsonl`, `mcp-calls.jsonl`,
`network-events.jsonl`, `shell-commands.jsonl`,
`filesystem-events.jsonl`, `transcript.jsonl`, `secret-scan.json`) into
a single chronologically ordered file an auditor can grep without
walking every source of truth.

The five per-subsystem streams remain the canonical record;
`leaks.jsonl` is rebuilt as a whole file via the atomic
"write tmp, fsync, rename" pattern documented in plan Bucket 9 (see
`internal/run/leaks.go`). The `ai-env leaks` CLI is the operator entry
point for reading it.

This document is the on-disk schema reference. Read it together with
[`filesystem-events-jsonl-schema.md`](filesystem-events-jsonl-schema.md),
[`transcript-jsonl-schema.md`](transcript-jsonl-schema.md), and the
inline metadata schemas in `internal/run/lifecycle_verbs.go`.

## Schema-version contract

Every record in `leaks.jsonl` carries `_schema_version: 1`. The contract
is global across every new JSONL stream the leak-coverage plan
introduced:

- The current version is `1` (constant `LeaksRecordSchemaVersion` in
  `internal/run/leaks.go`).
- A reader that encounters `_schema_version > 1` must error out rather
  than continuing with the unknown shape.
- Unknown fields are tolerated forward (readers ignore them) so a
  future field addition does not require a version bump.
- The supervisor records a per-run `schema_versions` map inside
  `run.json` at step 1 of the pre-launch sequence so a mid-run reader
  can discover the versions in effect without scanning every JSONL.

## File layout

- Path: `<runDir>/leaks.jsonl`.
- Encoding: newline-delimited JSON (JSONL), one `LeakRecord` per line.
- Atomicity: written to `<runDir>/leaks.jsonl.tmp.<pid>.<rand>` with
  `O_WRONLY | O_CREATE | O_EXCL`, fsynced, then renamed over
  `leaks.jsonl`. Readers (including `ai-env leaks`) skip any
  `leaks.jsonl.tmp.*` file so an aborted rebuild does not surface a
  partial line.
- Redaction: every non-empty string field passes through
  `secrets.RedactSecrets` at write time. The pattern set mirrors the
  scanner's `builtinPatterns()` so a leaked token surfacing in any
  source field is scrubbed before it lands on disk.

## Record shape (LeakRecord)

| Field             | Type                | Required | Meaning |
|-------------------|---------------------|----------|---------|
| `_schema_version` | int                 | yes      | Always `1` in v0.1. |
| `timestamp`       | string (RFC3339 with numeric offset) | yes | Moment the leak was observed in the source stream. Copied verbatim from the source record so leaks.jsonl stays chronologically aligned with the originals. |
| `run_id`          | string              | yes      | Duplicated into every record so a future multi-run aggregator does not lose attribution. |
| `source_stream`   | string              | yes      | Which per-subsystem stream produced the underlying record. One of `lifecycle`, `policy-decisions`, `mcp-calls`, `network-events`, `shell-commands`, `filesystem-events`, `transcript`, `secret-scan`. |
| `source_line`     | int                 | yes      | 1-based line number inside the source stream. Used by the aggregator's dedup key so two passes against the same streams are idempotent. |
| `vector`          | int                 | optional | Leak-coverage audit vector identifier (1..8). Omitted (zero) for vectorless lifecycle events. |
| `verb`            | string              | optional | Human-meaningful verb the upstream record carried (a `LifecycleVerb` spelling, a policy-decision reason, an MCP gateway operation). |
| `policy_event_id` | string              | optional | Opaque per-decision identifier the policy engine mints. Part of the aggregator's dedup key. |
| `evidence`        | object (LeakEvidence) | optional | Per-finding context payload. See below. |

## Evidence shape (LeakEvidence)

Every field is optional; only the fields the source stream knew are set.

| Field         | Type               | Meaning |
|---------------|--------------------|---------|
| `pattern`     | string             | Human-readable scanner pattern name that matched (e.g. `Anthropic sk-ant- prefix`). Empty for non-scanner sources. |
| `finding_id`  | string             | Opaque per-finding identifier the upstream emitter minted (scanner `finding_001`, gateway per-blocked-call UUID, etc.). Part of the scanner-sourced dedup key. |
| `snippet`     | string             | Short captured byte fragment showing the context that triggered the finding. Always run through `RedactSecrets` before write. |
| `detail`      | string             | Free-form per-emitter explanation (policy-decision reason, proxy upstream allowlist rejection text). Same redaction. |
| `extra`       | map[string]string  | Emitter-specific key/value context. Keys are emitter-chosen; every value passes through `RedactSecrets`. |

## Dedup keys

The aggregator deduplicates so two emitters that converge on the same
underlying event produce one row. Two dedup variants exist:

- Generic: `(source_stream, source_line, policy_event_id)`.
- Scanner-sourced: extended to
  `(source_stream, source_line, vector, evidence.pattern, evidence.finding_id)`
  so two findings on the same line with different patterns stay
  distinct.

## Lifecycle verbs that feed leaks.jsonl

Every lifecycle verb the supervisor emits can be projected into
`leaks.jsonl` via `LeakSourceLifecycle`. The table below enumerates
every verb from `internal/run/lifecycle_verbs.go` plus the per-verb
metadata key set the supervisor writes. Required vs optional is called
out per key. Values are always strings on the wire (callers stringify
numbers and booleans). Readers ignore unknown keys.

The first column is the on-wire verb spelling (the JSONL `verb` field
on a state-record from `lifecycle.jsonl`). The second column lists the
keys the supervisor populates inside the lifecycle record's
`metadata` map; those become evidence on the leak row.

### proxy_started

Emitted once per provider proxy after the listener is bound (pre-launch
step 8).

| Key             | Required | Meaning |
|-----------------|----------|---------|
| `provider`      | yes | Provider name (`anthropic`, `openai`). |
| `listen_addr`   | yes | `host:port` the proxy bound on the sandbox side. |
| `upstream_host` | yes | Canonical upstream host the allowlist pins. |
| `reachability`  | yes | One of `setns_tcp`, `bridge_gateway`, `unix_socket`. |

### proxy_stopped

Emitted once per provider proxy on teardown step 5.

| Key        | Required | Meaning |
|------------|----------|---------|
| `provider` | yes | Matches the start event. |
| `reason`   | yes | `teardown`, `error`, or `shutdown`. |

### gateway_started

Emitted once per run when the MCP Gateway comes up (step 9).

| Key            | Required | Meaning |
|----------------|----------|---------|
| `server_count` | yes | Number of registered MCP servers (stringified int). |
| `config_path`  | yes | Absolute path of `<runDir>/mcp-servers.json`. |

### gateway_stopped

Emitted once per run on teardown step 6.

| Key      | Required | Meaning |
|----------|----------|---------|
| `reason` | yes | `teardown`, `error`, or `shutdown`. |

### gateway_secret_blocked

Emitted once per outbound MCP request the per-direction scanner blocked
(agent to upstream).

| Key          | Required | Meaning |
|--------------|----------|---------|
| `server`     | yes | MCP server name the request targeted. |
| `operation`  | yes | JSON-RPC method the request invoked. |
| `pattern`    | yes | Name of the matched `scanners.builtinPatterns()` rule. |
| `finding_id` | yes | Opaque per-finding id leaks.jsonl deduplicates on. |

### gateway_secret_response

Emitted once per response the helper's stdio middleware scrubbed
(upstream to agent). A response with multiple matches still emits one
verb record; per-match details ride in `leaks.jsonl` as separate rows.

| Key           | Required | Meaning |
|---------------|----------|---------|
| `server`      | yes | MCP server name that produced the response. |
| `operation`   | yes | JSON-RPC method the response answered. |
| `pattern`     | yes | Name of the matched rule (first match wins for naming). |
| `match_count` | yes | Total redacted values in the response (stringified int). |
| `finding_id`  | yes | Opaque per-finding id leaks.jsonl deduplicates on. |

### observer_started

Emitted once per run when NFLOG (Linux) or pflog (macOS) is attached
(step 5).

| Key     | Required | Meaning |
|---------|----------|---------|
| `mode`  | yes | `nflog` on Linux, `pflog` on macOS. |
| `chain` | yes | Per-run chain name `AIENV-EGR-<8hex>`. |

### observer_stopped

Emitted once per run on teardown step 4.

| Key      | Required | Meaning |
|----------|----------|---------|
| `reason` | yes | `teardown`, `error`, or `shutdown`. |

### observer_unavailable

Emitted when the observer cannot start in this run's environment
(slirp4netns, missing capability). The run continues; the verb is the
audit signal that network-level evidence is degraded.

| Key      | Required | Meaning |
|----------|----------|---------|
| `reason` | yes | Short token: `slirp4netns`, `no_capability`, or other. |
| `detail` | optional | Human-readable detail for the audit log. |

### broker_started

Emitted once per run when GitHub broker construction from
`.ai-env/secrets.local.yaml` succeeds.

| Key            | Required | Meaning |
|----------------|----------|---------|
| `app_id`       | yes | GitHub App ID (stringified). |
| `installation` | yes | Installation id (stringified). |
| `origin`       | yes | Workspace origin URL (already redacted upstream). |

### broker_stopped

Emitted once per run when the broker shuts down.

| Key      | Required | Meaning |
|----------|----------|---------|
| `reason` | yes | `teardown`, `error`, or `shutdown`. |

### broker_unavailable

Emitted when the broker cannot start in this run (missing secrets,
origin drift, network failure on App-token mint). The run continues
without push capability.

| Key      | Required | Meaning |
|----------|----------|---------|
| `reason` | yes | Short token: `missing_secrets`, `origin_drift`, `mint_failed`. |
| `detail` | optional | Human-readable detail. |

### control_socket_started

Emitted once per run when the control-socket listener binds (step 2).

| Key    | Required | Meaning |
|--------|----------|---------|
| `path` | yes | Absolute path of `<runDir>/control.sock`. |

### control_socket_stopped

Emitted once per run on teardown step 8.

| Key      | Required | Meaning |
|----------|----------|---------|
| `reason` | yes | `teardown`, `error`, or `shutdown`. |

### network_policy_degraded

Emitted via `BackendEventSink` when the adapter cannot enforce a
portion of the configured policy (iptables rule rejected, ipset
unavailable). The run continues.

| Key       | Required | Meaning |
|-----------|----------|---------|
| `reason`  | yes | Short token: `iptables_rejected`, `ipset_missing`, or other. |
| `missing` | optional | Comma-separated short tokens listing what was dropped. |
| `detail`  | optional | Human-readable detail. |

### secrets_permission_warning

Emitted before the secrets are used so a reviewer can correlate later
activity with the file's permission state at load time. The run
continues.

| Key      | Required | Meaning |
|----------|----------|---------|
| `path`   | yes | Absolute path of the offending file. |
| `mode`   | yes | Octal mode the file had (stringified, e.g. `0644`). |
| `wanted` | yes | Octal mode expected (stringified, e.g. `0600`). |

### shim_coverage_degraded

Emitted when one or more shim wrappers could not be installed at every
canonical path. Bind mounts that fail are non-fatal per-entry; the verb
is the audit signal that the shadow set is incomplete.

| Key       | Required | Meaning |
|-----------|----------|---------|
| `program` | yes | Program name whose coverage is degraded (e.g. `python3`). |
| `missing` | yes | Comma-separated canonical paths that failed to mount. |
| `reason`  | optional | Short token from the backend error. |

### helper_rpc_aborted

Emitted once per control-socket RPC the supervisor refused mid-flight
(token mismatch, version mismatch, `AcceptingShutdown` gate).

| Key      | Required | Meaning |
|----------|----------|---------|
| `method` | yes | Control-socket method name (`Hello`, `BeginTurn`, ...). |
| `reason` | yes | Short token: `bad_token`, `version_mismatch`, `shutdown`, `no_handler`. |
| `peer`   | optional | Remote address / pid identifier when known. |

### transcript_parser_error

Emitted at most once per scanner-error window per CLI. The parser
deduplicates inside a single run; the run continues and the transcript
stream is marked degraded.

| Key      | Required | Meaning |
|----------|----------|---------|
| `cli`    | yes | Agent CLI name (`claude`, `codex`). |
| `reason` | yes | Short token: `scan_overflow`, `json_parse`, `stream_error`. |
| `detail` | optional | Human-readable detail (already redacted). |

### mcp_config_neutralized

Emitted once per neutralized file at `backend.Create` to record that a
workspace-local MCP config was renamed to `*.ai-env-shadowed` to prevent
auto-merge with the supervisor-managed `mcp-servers.json`. Restored at
`backend.Destroy`.

| Key        | Required | Meaning |
|------------|----------|---------|
| `original` | yes | Absolute path before rename. |
| `shadowed` | yes | Absolute path after rename. |
| `kind`     | yes | `mcp_json` or `claude_settings_mcp_servers`. |

## See also

- `internal/run/leaks.go`: `LeakRecord`, `LeakEvidence`, `LeaksWriter`.
- `internal/run/leaks_aggregate.go`: aggregator that walks the
  per-subsystem streams and produces records.
- `internal/run/lifecycle_verbs.go`: authoritative per-verb metadata
  schemas with inline godoc.
- `ai-env leaks --help`: operator-facing reader.
