# MCP gateway security model

This document is the operator-facing reference for ai-env's Model Context
Protocol (MCP) gateway: what it defends against, what controls it adds,
where the controls live in the source, and the day-to-day playbook for
keeping the registry honest.

Read it together with [`threat-model.md`](threat-model.md) (which actors
the tool considers untrusted and why), [`enforcement-boundaries.md`](enforcement-boundaries.md)
(which package enforces which boundary at runtime), and
[`residual-risk.md`](residual-risk.md) (which classes of MCP risk the
gateway acknowledges but does not currently close).

The gateway is the v0.2 phase of plan 09. Plans 01-08 (workspace,
backend, network, scanners, broker, policy / shell hardening) remain the
boundary for everything outside MCP; this document only covers what
changes when an agent reaches an MCP server.

## The cardinal rule

> ai-env cannot govern an MCP call that does not pass through its
> gateway. Every control in this document depends on the agent's MCP
> client being pointed at the gateway proxy, not at the upstream server
> directly. The gateway is the single chokepoint; bypassing it bypasses
> the whole MCP security model.

The gateway is implemented in `internal/mcp/`. Three of its responsibilities
sit purely on the host (registry, schema-hash compare, audit log writes);
two are evaluated per call against operator-supplied configuration
(scope enforcement, per-server policy). Nothing in this document depends
on the agent's cooperation.

## Why MCP needs its own gateway

MCP servers extend an agent's capabilities with tools the operator did
not write. Each server advertises a list of named tools, each tool has a
JSON-schema input contract, and the agent decides which tools to call
based on the human-readable description the server returned. That
shape produces four risks the plans 01-08 controls do not address:

1. **Filesystem exfiltration through a "helpful" tool.** A filesystem
   MCP server exposes `read_file` / `write_file` / `list_directory`. The
   workspace isolation from plan 02 makes `~/.ssh/id_rsa` invisible to
   shell commands, but the agent can still ask a filesystem MCP server
   to read it if the server runs on the host with no scope check.
2. **Network egress through allowed MCP endpoints.** An MCP server that
   the operator added for the GitHub API can still be misused to file
   issues against an unrelated repository, or to read a private repo
   the operator's token has access to. The network policy from plan 05
   allowlists hosts, not the semantics of what those hosts are asked to
   do.
3. **Production-tool invocation.** An MCP server connected to a cloud
   provider or production database is a one-call path past every
   network and broker check in v0.1: the call is made by the host-side
   MCP server, not by a process inside the sandbox.
4. **MCP poisoning via tool-description drift.** A server release can
   silently change a tool's description ("read_file (now also reads
   /etc/passwd if requested)") or relax its input schema ("path is
   optional and defaults to /") and the agent will pick the change up
   on the next launch. The agent's behavior is driven by the natural-
   language description; an upstream change in that description is a
   change in the agent's effective behavior.

The master plan section 22 spells out the response: an MCP registry
with deny-by-default, version / digest pinning, schema-hash pinning,
scope enforcement, and an audit log. This document is how those rules
land in the code.

## Layered enforcement table

The table summarises every MCP enforcement layer in v0.2. The columns
match the convention in [`enforcement-boundaries.md`](enforcement-boundaries.md)
so an operator who knows the v0.1 enforcement model can read this one
the same way.

| Layer                       | Enforces                                                                      | Owning package                          | Bypassable from inside the sandbox?                                            |
|-----------------------------|-------------------------------------------------------------------------------|-----------------------------------------|--------------------------------------------------------------------------------|
| MCP registry                | Which server names are recognized; source / digest pinning                    | `internal/mcp/registry.go`              | No: read on the host before the gateway is built. Unknown name -> block.       |
| Schema-hash pin             | Tool list (name, description, input schema) frozen at registration time      | `internal/mcp/schema.go`                | No: compared on the host at launch; mismatch routes to warn / block per policy. |
| Gateway proxy               | Single chokepoint for AuthorizeLaunch / AuthorizeCall verdicts                | `internal/mcp/gateway.go`               | No: the proxy is on the host; the agent talks to it over a local socket.       |
| Filesystem scope            | Path target must resolve inside `.ai-env/workspaces/<env-name>/`              | `internal/mcp/scope_filesystem.go`      | No: the workspace root is captured on the host at construction.                |
| GitHub scope                | Repo coordinate must match the current repo; operations capped read / write   | `internal/mcp/scope_github.go`          | No: the current repo coordinate is captured on the host at construction.       |
| Per-server policy           | Registered allow / deny / warn token applied at launch and on every call      | `internal/mcp/registry.go` + gateway    | No: read from the validated registry on every call.                            |
| `mcp-calls.jsonl` audit log | Every AuthorizeLaunch / AuthorizeCall verdict appended as one JSON line       | `internal/run/mcp_calls.go`             | No: file lives in the per-run directory on the host; fsync after every record. |
| `ai-env mcp ...` CLI        | Operator-facing add / pin / scan / remove plus dry-run AuthorizeLaunch        | `internal/cli/mcp.go`                   | N/A (host-only command surface).                                               |

## Threat model deltas for MCP

The base threat model in [`threat-model.md`](threat-model.md) already
treats the agent, the repository content, and the dependencies as
untrusted. MCP adds three new untrusted actors that the gateway
enforces against:

### The MCP server process

Treated as untrusted. The server may be buggy, may have shipped an
upstream release that quietly broadened its tool descriptions, or may
have been replaced by a typosquat. The gateway assumes the server will:

- Advertise tools whose description has changed since the operator
  pinned the hash.
- Accept requests for paths or repository coordinates the operator did
  not intend the server to touch.
- Return responses that, if relayed verbatim, would convince the agent
  to take further actions outside the operator's intent.

The registry pin and the schema-hash pin handle the first item. The
scope enforcers handle the second. The third is not yet addressed in
v0.2 and is logged in [`residual-risk.md`](residual-risk.md).

### The MCP server's upstream source

Treated as untrusted. An npm package or OCI image can be revoked,
re-tagged, or republished by an attacker who compromised the upstream
account. The registry requires every server to pin a version through
its `source` field and may additionally pin a content `digest`.
Comparison is exact string equality (`Registry.MatchVersion`,
`Registry.MatchDigest`), so any drift between what mcp.yaml says and
what the launcher resolved is a block, not a warning.

### The agent's MCP client implementation

Treated as untrusted in the same sense the shell shim treats the agent:
the gateway controls one specific path (the proxy entry point) and
expects every MCP call to flow through it. The agent's MCP client could
in principle connect to a server directly; the only counter to that is
that the supervisor does not advertise direct server addresses to the
sandbox. Operators who configure agents with hard-coded server URLs
opt out of the gateway entirely; that opt-out is not detectable from
inside `ai-env` and is documented as a residual risk.

## The MCP registry (`.ai-env/mcp.yaml`)

The registry is the operator-authored YAML document that tells the
gateway which servers exist and how they should be pinned. The loader
lives in `internal/mcp/registry.go`; the CLI surface for editing it
lives in `internal/cli/mcp.go`.

### Format

```yaml
version: 1
default: deny
servers:
  filesystem:
    source: npm:@modelcontextprotocol/server-filesystem@1.2.3
    digest: sha256:abc123...
    schema_hash: sha256:def456...
    scope:
      filesystem:
        root: workspace_only
    policy: allow
  github:
    source: npm:@modelcontextprotocol/server-github@1.1.0
    digest: sha256:ghi789...
    schema_hash: sha256:jkl012...
    scope:
      github:
        repos: current_repo_only
        operations: read_only
    policy: allow
```

Every field is validated at load time:

- `version` must be `1` (`supportedVersion`).
- `default` must be `deny`. The loader rejects any other value. v0.2
  forbids "allow unknown servers" as a top-level mode; an operator who
  wants a new server must register it.
- `servers` must contain at least one entry.
- Each `source` must start with `npm:` (and contain `@<version>`) or
  `oci:` (and contain `:<tag>`).
- Each `digest`, when present, must be `sha256:<hex>`. Same for
  `schema_hash`.
- Each `policy` must be `allow`, `deny`, or `warn`.
- Each `scope.<kind>` must use only the fields meaningful for that kind
  (filesystem.root vs. github.repos / github.operations). Cross-kind
  field bleed (a filesystem block setting `repos`) is rejected.
- The only `filesystem.root` token is `workspace_only`.
- The only `github.repos` token is `current_repo_only`.
- `github.operations` is one of `read_only` / `read_write`.

YAML decoding is strict (`KnownFields(true)`): an unknown key surfaces
as a load error, not a silent drop. This matches the loader convention
shared with `policy.yaml`, `ai-env.yaml`, and `agents.yaml`.

### Deny by default

`Registry.Lookup` returns `ErrUnknownServer` for any name not in the
registry. The gateway translates that into `GatewayOutcomeBlock` with
the reason `"unknown server"`. The decision is recorded in
`mcp-calls.jsonl` so an auditor can see which server the agent asked
for; nothing about the upstream server (which version it would have
been, what its tools look like) is consulted, because the server is
not registered.

### Version and digest pinning

Every registered server must declare a `source` that pins to an exact
version. `Registry.MatchVersion` compares the runtime-resolved source
the launcher would actually use against the registered `source` with
exact string equality (including whitespace and case). Any drift is
`ErrVersionMismatch` and a block.

`Registry.MatchDigest` is the optional content-addressed counterpart.
When the registered digest is empty the operator is opting into
version-only pinning and any candidate digest is accepted. When the
registered digest is non-empty, any drift is `ErrDigestMismatch` and a
block.

The combination is "version always pinned, digest pinned when the
operator chose to". The CLI's `ai-env mcp add` accepts both as flags;
the `ai-env mcp scan` dry-run reports a clear mismatch reason for each
dimension.

## Schema-hash pinning

The schema-hash mechanism (`internal/mcp/schema.go`) is the defense
against MCP poisoning. The hash covers the operator-relevant subset of
the server's tool list: tool name, tool description, and the canonical
form of the tool's input schema.

### What gets hashed

```text
v1\n
<tool0.Name>\x00<tool0.Description>\x00<canonical-json>\n
<tool1.Name>\x00<tool1.Description>\x00<canonical-json>\n
...
```

Rules:

- Tools are sorted by name before hashing; reordering the upstream tool
  list does not flip the hash.
- The input schema is canonicalized via a recursive map-sort pass
  before JSON serialization so two semantically equal schemas produce
  the same bytes regardless of map iteration order or serializer
  quirks.
- A leading `v1\n` marker pins the canonicalization version. Bumping
  it (in `schemaCanonicalVersion`) is how a future canonicalization
  change can be rolled out without silently invalidating existing
  pinned hashes.
- The output shape is `sha256:<hex>`, identical to the `digest` shape
  the rest of ai-env uses. The same string round-trips through
  `mcp.yaml` without translation.

Server-side metadata that does not affect agent behavior (transport
hints, vendor extensions) is deliberately excluded so that a benign
patch release that only touches such metadata does not produce a
false-positive mismatch.

### Compare outcomes

`Registry.CompareSchemaHash(name, liveHash)` returns one of four
`SchemaOutcome` values that the gateway maps to a `GatewayDecision`:

| Pinned hash | Live hash matches? | Per-server policy | Outcome   | Gateway result                                          |
|-------------|--------------------|-------------------|-----------|---------------------------------------------------------|
| empty       | n/a                | any               | `Record`  | Allow; reason includes "first launch; pin schema hash". |
| non-empty   | yes                | any               | `Allow`   | Allow.                                                   |
| non-empty   | no                 | `warn`            | `Warn`    | Warn; reason "schema hash drift (warn policy)".         |
| non-empty   | no                 | `allow` / `deny`  | `Block`   | Block; `ErrSchemaMismatch` wrapped.                     |

"First launch" is the only outcome that auto-allows a new hash. The
gateway never auto-pins the hash inside `Record`: doing so would
silently accept whatever the server happened to advertise on the first
run, which may itself be malicious. The operator must run `ai-env mcp
pin <server> --schema-hash <hash>` to record the hash explicitly.

### `warn` vs. `allow` vs. `deny` on drift

The master plan rule is "warn or block on schema change". Per-server
`policy: warn` opts into the warn track: every drift is logged and
audited, but the launch proceeds. `policy: allow` is the strict
default: any drift is a hard block. `policy: deny` is the parked
state: the server is registered (so an operator does not lose the
pinned version while debugging an incident) but the gateway refuses to
launch or call it.

## Gateway authorization flow

The gateway has two entry points. Both emit exactly one
`mcp-calls.jsonl` record per invocation and both return a
`GatewayDecision` the caller acts on.

### `AuthorizeLaunch`

Called when the agent runner is about to start an MCP server. The
caller supplies the server name plus optional candidate `Source`,
`Digest`, and `LiveSchemaHash`. The pipeline short-circuits at the
first failure so the audit log records the most-specific reason:

1. **Registry lookup.** Unknown name -> Block with `ErrUnknownServer`.
2. **Parked server check.** `Policy == deny` -> Block with
   `ErrServerParked`. The audit reason distinguishes this from
   `ErrUnknownServer` so an auditor can tell "never registered" from
   "registered and parked".
3. **Source pin.** When the caller supplied a candidate source,
   `Registry.MatchVersion` is called. Mismatch -> Block with
   `ErrVersionMismatch`. Empty candidate skips the dimension.
4. **Digest pin.** When the caller supplied a candidate digest AND the
   server has a registered digest, `Registry.MatchDigest` is called.
   Mismatch -> Block with `ErrDigestMismatch`.
5. **Schema-hash compare.** When the caller supplied a live hash,
   `Registry.CompareSchemaHash` runs the four-state matrix above.
   Outcomes are translated to gateway outcomes: `Record` -> Allow
   (with a "pin me" reason), `Allow` -> Allow, `Warn` -> Warn, `Block`
   -> Block.
6. **Per-server policy.** If all of the above passed and the policy is
   `warn`, the launch is flagged: every launch produces a Warn so the
   operator sees the registered server in the audit log every time.
   `allow` is the happy path.

### `AuthorizeCall`

Called when the agent is about to dispatch a single tool call against
an already-launched server. The caller supplies the server name, the
tool name, and (per scope kind) the path / repo / operation the call
targets.

1. **Registry lookup.** Same as `AuthorizeLaunch`.
2. **Parked server check.** Same.
3. **Tool name.** Empty tool name -> Block. A misconfigured caller
   fails loudly; the audit record is not meaningful without a tool
   name.
4. **Scope enforcement.** For every scope kind the server declared,
   the gateway looks up the registered `ScopeEnforcer` and forwards
   the `ScopeRequest`. Kinds are evaluated in sorted order so the
   audit log's `scope_kinds` list and the first-failure reason are
   deterministic across runs. A missing enforcer for a declared kind
   is Block with `ErrMissingScopeEnforcer` (the "deny unknown scope"
   rule). An enforcer error is Block with `ErrScopeViolation` wrapping
   the enforcer's own error.
5. **Per-server policy.** If all scope enforcers passed, `warn`
   produces a Warn (flagged on every call) and `allow` produces an
   Allow.

### Fail-closed defaults

- A nil `Registry` makes `NewGateway` refuse to construct. There is no
  "gateway without a registry" mode.
- A nil `CallLogger` is replaced by a no-op so unit tests and the
  CLI's `ai-env mcp scan` dry-run do not need to invent a sink. In a
  real run the supervisor wires `internal/run/mcp_calls.go` as the
  logger.
- A nil `ScopeEnforcer` for a kind a server declares is treated as a
  configuration error (`ErrMissingScopeEnforcer`), not an implicit
  allow. This keeps the master plan's "deny unknown scope" rule honest
  if a future enforcer is added to the registry but not wired into the
  gateway.

## Scope enforcement

Scope enforcers are the per-kind plugins the gateway consults on each
`AuthorizeCall`. v0.2 ships two; the interface (`ScopeEnforcer`) is
the extension point for future kinds.

### Workspace-only filesystem scope

`internal/mcp/scope_filesystem.go` enforces "filesystem MCP scoped to
workspace only". Rules:

- The workspace root is captured at construction time, not read from
  mcp.yaml. The `root: workspace_only` token in the registry is a
  marker that says "use the workspace root the supervisor passed me",
  not a path. This keeps mcp.yaml host-independent (the same committed
  file works on any developer's machine) and means the enforcer cannot
  be widened mid-run by swapping in a different root.
- The root is canonicalized once at construction (`Abs` +
  `EvalSymlinks` when the directory exists, `Abs` + `Clean` otherwise)
  so a workspace that is itself a symlink does not produce spurious
  rejections.
- The per-call path is resolved relative to the workspace root. If the
  target does not yet exist (the agent is creating a new file), the
  enforcer resolves the nearest existing parent and appends the
  remaining components so a symlinked parent still anchors the check.
- The acceptance test is "resolved path is the root or a descendant
  of it". The check uses `filepath.Rel` + a "does not start with
  `..\<sep>`" guard, not `HasPrefix`, because `HasPrefix` on path
  strings has the classic `/workspace` vs. `/workspace2` false-positive
  bug.
- Empty path -> `ErrFilesystemEmptyPath` (Block). No-target is
  fail-closed, not an implicit allow.

The sentinels (`ErrFilesystemPathOutsideWorkspace`,
`ErrFilesystemEmptyPath`, `ErrFilesystemScopeUnsupported`) are
distinct so the audit log makes it unambiguous what kind of escape was
attempted.

### Current-repo-only GitHub scope

`internal/mcp/scope_github.go` enforces "GitHub MCP scoped to current
repo only" plus the read-only / read-write operations cap. Rules:

- The current repo coordinate (`owner/name`) is captured at
  construction. The `repos: current_repo_only` token in the registry
  is a marker, not a list. The same committed mcp.yaml works for every
  project the operator runs ai-env in.
- The coordinate is normalized at construction (lower-case, leading
  `github.com/` stripped, trailing `.git` stripped). Comparison is
  exact equality on the normalized form. GitHub coordinates are
  case-insensitive at the server, so a case-sensitive match would
  produce false rejections when the agent learned the coordinate from
  a different source than the supervisor.
- Empty repo -> `ErrGitHubEmptyRepo` (Block). Partial coordinates
  (`owner/` alone) are also rejected: they would allow every repo
  under the owner.
- Operations cap: `read_only` scopes reject any non-`read` operation
  (including an empty operation, treated as "could be a write");
  `read_write` scopes accept both. Unknown operation tokens fail
  closed (`ErrGitHubOperationUnknown`).
- Production cloud MCP is forbidden by master-plan rule; v0.2 simply
  does not register such servers. There is no "production" scope kind.

## The `mcp-calls.jsonl` audit trail

Every gateway verdict is appended as one JSON line to
`<run-dir>/mcp-calls.jsonl`. The writer (`internal/run/mcp_calls.go`)
mirrors the lifecycle / network-events / policy-decisions pattern:
append-only, fsync after every record, concurrent-safe via a per-writer
mutex. The file is materialized as a placeholder at run-directory
creation alongside `lifecycle.jsonl`, `network-events.jsonl`, and
`policy-decisions.jsonl` so a reviewer reading a run on disk sees every
event stream side by side.

### Record shape

Two record families share the shape; both are encoded with the same
struct (`MCPCallRecord` host-side, `mcp.CallRecord` gateway-side; the
JSON tags are byte-identical so the bridge translates field-by-field
without re-encoding).

**Launch record** (`stage: "launch"`):

| Field           | Meaning                                                        |
|-----------------|----------------------------------------------------------------|
| `timestamp`     | RFC3339 with a numeric offset; gateway's clock.                |
| `stage`         | Always `"launch"`.                                              |
| `server`        | Registered name the caller asked for (echoed even on unknown). |
| `decision`      | `"allow"`, `"warn"`, or `"block"`.                              |
| `reason`        | Operator-readable explanation.                                  |
| `source`        | Candidate source the gateway compared against the registry.    |
| `digest`        | Candidate digest, when supplied.                                |
| `expected_hash` | `RegistryServer.SchemaHash` at compare time.                    |
| `actual_hash`   | Freshly-computed hash the caller supplied.                      |

**Call record** (`stage: "call"`):

| Field         | Meaning                                                            |
|---------------|--------------------------------------------------------------------|
| `timestamp`   | Same.                                                              |
| `stage`       | Always `"call"`.                                                    |
| `server`      | Registered name.                                                    |
| `decision`    | `"allow"`, `"warn"`, or `"block"`.                                  |
| `reason`      | Operator-readable explanation.                                      |
| `tool`        | MCP tool name (e.g. `read_file`, `create_issue`).                   |
| `path`        | Filesystem path target, when the scope kind is filesystem.          |
| `repo`        | `owner/name` coordinate, when the scope kind is github.             |
| `operation`   | `"read"` or `"write"`, when the scope kind is github.               |
| `scope_kinds` | Sorted list of scope kinds the gateway evaluated.                   |

### What an auditor can answer with `mcp-calls.jsonl`

- "Did the agent try to launch a server I did not register?" -> grep
  `"decision":"block"` with `"reason":"unknown server"`.
- "Did the tool schema drift on any registered server?" -> grep
  `"stage":"launch"` with `expected_hash` and `actual_hash` differing.
- "Did the filesystem MCP try to read outside the workspace?" -> grep
  `"scope_kinds":["filesystem"]` with `"decision":"block"`.
- "Did the GitHub MCP try a foreign repo or an unauthorized write?" ->
  grep `"scope_kinds":["github"]` with `"decision":"block"`.
- "Which servers had `warn` policy on this run?" -> grep
  `"decision":"warn"` and look at the `server` field.

A record with an empty `decision` is rejected by the writer; the
writer fsyncs after every record so a crash after a verdict has been
returned to the caller does not lose the audit entry.

### Audit cross-references

The MCP gateway's evidence joins three other audit streams the
supervisor writes:

- `lifecycle.jsonl`: the gateway emits `gateway_started`,
  `gateway_stopped`, `gateway_secret_blocked`, and
  `gateway_secret_response` verbs. The per-verb metadata schemas are
  documented in [`leaks-jsonl-schema.md`](leaks-jsonl-schema.md).
  Workspace-config neutralization at `backend.Create` emits
  `mcp_config_neutralized` (one verb per renamed file).
- `filesystem-events.jsonl`: filesystem-scope decisions (allow / warn
  / block) emit a `FilesystemEventRecord` with `source: "mcp-gateway"`
  alongside the `mcp-calls.jsonl` entry. Schema in
  [`filesystem-events-jsonl-schema.md`](filesystem-events-jsonl-schema.md).
- `leaks.jsonl`: the derived unified view joins `mcp-calls.jsonl`
  records (via `LeakSourceMCPCalls`) and the gateway's lifecycle
  verbs (via `LeakSourceLifecycle`) into one chronologically-ordered
  evidence file. Schema in
  [`leaks-jsonl-schema.md`](leaks-jsonl-schema.md).

## Per-run gateway wiring

The gateway is wired per-run by the supervisor, not at workspace init.
Three artifacts cooperate:

- `<runDir>/mcp-servers.json`: the per-run config the agent CLI
  reads. Each server entry points at `ai-env shim-helper mcp <name>`
  with two env vars: `AI_ENV_CONTROL_SOCKET` (the in-sandbox path of
  the host control socket) and `AI_ENV_MCP_SERVER_TOKEN` (a per-server
  short-lived secret). The primary control token is NOT in this file;
  the supervisor delivers it to helper processes via a side-band
  mechanism the agent UID cannot read.
- `<runDir>/ipc/mcp-servers.real.json`: the real-server commands the
  helper invokes after the gateway authorizes a call. Mode 0600,
  owned by the container UID, not bind-mounted into the agent's view.
- Workspace-local MCP configs (`.mcp.json`,
  `.claude/settings.json#mcpServers`) are renamed to
  `*.ai-env-shadowed` at `backend.Create` to prevent the agent CLI
  from auto-merging them with the supervisor-managed config. The
  rename is recorded as `mcp_config_neutralized` and restored at
  `backend.Destroy`.

`AuthorizeMCPCall` requires both the primary control token and the
per-server token. An agent that reads `mcp-servers.json` sees the
per-server token but cannot use it without the primary control token,
which it never has access to.

The GitHub broker credentials and provider keys the MCP gateway might
in principle have access to live in
[`secrets-local-yaml.md`](secrets-local-yaml.md). The MCP gateway
does not read that file; the registry pin is independent of the
credential plumbing.

## CLI surface

`internal/cli/mcp.go` implements the operator-facing subcommands.
Every command works from any subdirectory of the project (the loader
walks up to find `.ai-env/`), mutations round-trip through
`mcp.ValidateRegistry` before writing, and the on-disk YAML is
rewritten with `yaml.Marshal` so the file is structurally stable
(no spurious merge conflicts when `mcp.yaml` is committed to git).

### `ai-env mcp list`

Prints a column-aligned table of every registered server (name,
source, digest, schema hash, scope kinds, policy). Sorted by name for
stability. Missing `mcp.yaml` is a hard error directing the operator
at `ai-env mcp add`. Empty cells render as `-` so the table stays
readable when an optional field is unset.

### `ai-env mcp add <name> --source ... [--digest ...] [--schema-hash ...] [--policy ...] [--scope-filesystem-root workspace_only] [--scope-github-repos current_repo_only] [--scope-github-operations read_only|read_write] [--force]`

Registers a new server. If `mcp.yaml` does not yet exist it is
scaffolded with `version: 1`, `default: deny`, and the new server as
its only entry. An existing entry under the same name is refused
unless `--force` is set, so a typo in a scripted invocation cannot
silently replace a tuned registration.

The default `--policy` is `allow`. The default `--scope-github-
operations` (when a github scope is declared without an explicit
choice) is `read_only` so the conservative default wins on
omission.

### `ai-env mcp pin <name> --schema-hash <sha256:hex>`

Sets (or replaces) the `schema_hash` field on an existing server.
Validation runs after the mutation, so a malformed hash never makes
it to disk. The same hash already pinned is a no-op (stderr notice,
exit 0) so a scripted caller treats "already pinned" as success. A
replacement surfaces the previous value on stderr so an operator who
re-pinned a server sees what changed.

### `ai-env mcp scan <name> [--source ...] [--digest ...] [--schema-hash ...]`

Dry-runs `Gateway.AuthorizeLaunch` against the operator-supplied
candidate metadata and prints the verdict. No network I/O: this is
safe to run in restrictive sandboxes. A Block verdict returns a
non-zero exit so the command is usable in CI ("fail the build if mcp
scan blocks any server"). A Warn verdict prints the warning on stderr
and exits 0.

The dry-run is the operator's primary tool for the schema-drift
workflow: compute the live hash externally, pass it via
`--schema-hash`, and let the gateway decide whether the change is a
record / allow / warn / block before the agent ever launches the
server.

### `ai-env mcp remove <name>`

Deregisters a server. The mutation round-trips through validation, so
a removal that would leave the registry empty (which the validator
rejects) is refused with a clear directive: delete `mcp.yaml`
directly if the intent is to disable MCP entirely.

## Operator playbook

The following recipes cover the day-to-day MCP workflow. Each maps to
the CLI surface above and points at the code path that enforces the
control.

### Add a new MCP server

1. Identify the upstream source. Either an npm package
   (`npm:<pkg>@<version>`) or an OCI image (`oci:<image>:<tag>`). The
   version is required; the digest is recommended.
2. Decide the scope. Filesystem servers should always declare
   `--scope-filesystem-root workspace_only`. GitHub servers should
   always declare `--scope-github-repos current_repo_only` and the
   conservative `--scope-github-operations read_only` unless the
   workflow genuinely needs writes.
3. Decide the policy. `allow` is the default and the right choice for
   most servers. `warn` adds a per-launch and per-call warning to the
   audit log; useful for newly-added servers you want flagged for a
   while. `deny` parks a server (keeps the pinned version on file but
   refuses to launch it); useful during an incident.
4. Run `ai-env mcp add <name> --source ... [flags]`. The command
   creates `mcp.yaml` if it does not exist and refuses to clobber an
   existing entry without `--force`.
5. Commit `mcp.yaml`. The registry is the operator's contract with the
   gateway; checking it into version control makes the contract
   reviewable.

Code path: `internal/cli/mcp.go::RunMCPAdd` ->
`internal/mcp/registry.go::ValidateRegistry`.

### Pin the schema hash after the first launch

1. Launch the agent once with the freshly-registered server. The
   gateway's `Record` outcome allows the launch and writes the
   live hash into `mcp-calls.jsonl` as the `actual_hash` field of the
   launch record.
2. Find the launch record: `grep '"stage":"launch"' mcp-calls.jsonl`
   for your server.
3. Run `ai-env mcp pin <name> --schema-hash <actual_hash>`. The
   command validates the hash shape, writes it into `mcp.yaml`, and
   surfaces a confirmation.
4. Commit the updated `mcp.yaml`.

From here on, any drift in the tool list will be a Warn or Block (per
the server's `policy`) instead of a silent first-launch Record.

Code path: `internal/cli/mcp.go::RunMCPPin` ->
`internal/mcp/schema.go::CompareSchemaHash`.

### Scan for drift before launching

1. Compute the live hash externally (run the server in a one-shot
   tool that enumerates its tool list and pipe the result through
   `ComputeSchemaHash`-compatible canonicalization, or use a wrapper
   the operator wrote for the workflow).
2. Run `ai-env mcp scan <name> --schema-hash <live-hash>`. The
   gateway's dry-run reports Allow / Warn / Block with the same
   reasons it would have used during a real launch.
3. If the verdict is Block, decide whether the change is intentional.
   If yes, run `ai-env mcp pin` with the new hash and re-commit
   `mcp.yaml`. If no, treat the server as compromised: do not launch
   it; investigate.

Code path: `internal/cli/mcp.go::RunMCPScan` ->
`internal/mcp/gateway.go::AuthorizeLaunch`.

### Park a server during an incident

1. Edit `mcp.yaml` and set the server's `policy` to `deny`. (There is
   no dedicated `ai-env mcp park` command in v0.2; the edit is the
   workflow.)
2. Re-run `ai-env mcp list` to confirm the change.
3. The next launch of that server will Block with `ErrServerParked`;
   the audit log will distinguish the parked state from an unknown
   server.
4. When the incident is resolved, set the policy back to `allow` (or
   `warn` if the operator wants per-call flagging during recovery).

Code path: `internal/cli/mcp.go::RunMCPList` (for verification) ->
`internal/mcp/gateway.go::AuthorizeLaunch` step 2 (the parked check).

### Remove a server

1. Run `ai-env mcp remove <name>`. The command validates after the
   removal so it refuses to leave the registry in an invalid state.
2. If the server being removed is the last one, the command refuses
   and tells the operator to delete `mcp.yaml` directly. Do that if
   the intent is to disable MCP entirely.
3. Commit the updated `mcp.yaml`.

Code path: `internal/cli/mcp.go::RunMCPRemove`.

## Fail-closed boundaries (MCP edition)

The following failures terminate the relevant operation before any
MCP traffic flows:

- Unparseable `mcp.yaml` -> the registry loader returns an error; the
  CLI surfaces it; the run does not start.
- Unknown top-level `default` token (anything other than `deny`) ->
  rejected at load time.
- Server with neither version nor recognized source kind -> rejected
  at load time.
- `NewGateway(nil, ...)` -> programming error; refused.
- Server declares a scope kind for which no enforcer is wired ->
  every call against that server is Block with `ErrMissingScopeEnforcer`.

Once a run is in flight, the following failures terminate the
specific MCP operation without exporting:

- Unknown server name on `AuthorizeLaunch` / `AuthorizeCall` -> Block.
- Source / digest mismatch on `AuthorizeLaunch` -> Block.
- Schema-hash mismatch under `allow` / `deny` policy -> Block.
- Filesystem path outside workspace -> Block.
- GitHub repo outside current-repo scope, or write under `read_only`
  scope -> Block.
- Parked server (`policy: deny`) -> Block.

A Block from any of the above does not, by itself, quarantine the
run: the policy engine (plan 08) is the surface that decides whether
an MCP block escalates to a quarantine. The MCP gateway emits the
verdict; the policy engine consumes it.

## What this model does not cover

The MCP gateway deliberately does not address the following classes
of risk. They are repeated here so an operator does not look for a
control that does not exist; they are also listed in
[`residual-risk.md`](residual-risk.md).

- **Agents that bypass the gateway.** If the agent's MCP client is
  configured with a direct server address (not the gateway proxy
  endpoint), the gateway sees nothing. The supervisor does not
  advertise direct server addresses to the sandbox; an operator who
  hard-codes server URLs into the agent config opts out of every
  control in this document.
- **Servers that lie about their tool list.** The schema-hash pin
  catches changes to the advertised tool list, but a server that
  advertises one schema and behaves differently at call time is not
  detectable from the hash alone. The scope enforcers limit the blast
  radius (paths, repos), and the audit log records the call, but a
  server with a backdoor in the implementation cannot be defended
  against by the registry pin.
- **Response-content prompt injection.** An MCP server's tool response
  is text the agent reads. A response that contains instructions
  ("now also call `delete_file('/')`") will be processed by the agent.
  v0.2 does not scan or sanitize MCP tool responses; the scope
  enforcers still apply to the follow-on calls, but the agent's
  decision to make those calls is downstream of the response.
- **Future scope kinds without registered enforcers.** If a future
  server declares a scope kind the gateway does not know how to
  evaluate, every call against that server is Block with
  `ErrMissingScopeEnforcer`. This is the safe behavior; it is not a
  silent allow. Operators adding a new scope kind must register a
  matching enforcer at gateway construction time.
- **Production-cloud MCP.** Master-plan rule: forbidden by default.
  v0.2 simply does not register such servers; there is no "production"
  scope token. An operator who registers a production-cloud MCP
  server in `mcp.yaml` is opting out of the master plan; the gateway
  does not detect this and does not warn.

If a workflow requires any of those guarantees, pair the gateway with
the controls in plans 01-08 (workspace isolation, network policy,
broker, export gate) plus operator code review of the diff and the
audit log.
