# filesystem-events.jsonl schema

`filesystem-events.jsonl` is the per-run audit projection of every
filesystem-decision the supervisor's enforcers reached. It unifies the
evidence the leak-coverage audit's Vector-1 (path escape) needs:

- which subsystem observed the access (`source`),
- what the agent asked for (`operation`, `path`, `resolved_path`),
- who served the request (`server` / `tool` for the MCP gateway,
  `program` / `argv` for the shell shim),
- what the enforcer decided (`decision`, `reason`).

The writer (`internal/run/filesystem_events.go`) opens the file with
`O_APPEND | O_CREATE | O_WRONLY` against the placeholder
`CreateRunDirectory` left in place. Writes are serialized by a
per-writer mutex and fsynced after every record so a crash does not
lose the FS audit trail.

## Schema-version contract

Every record carries `_schema_version: 1` (constant
`FilesystemEventsRecordSchemaVersion`). Same contract as the other
new streams: readers refuse `_schema_version > 1`, tolerate unknown
fields, and consult `run.json.schema_versions` for the per-run version
map written at supervisor step 1.

## Two record families share the shape

Both families serialize via the same `FilesystemEventRecord` struct.
The `source` field disambiguates:

- `source: "mcp-gateway"`: the MCP gateway's filesystem-scope enforcer
  answered "may this tool call read / write this path?". The
  `server` / `tool` fields carry the per-call context; `program` /
  `argv` are usually empty.
- `source: "shim"`: the shell shim's interpreter-via-file or argv check
  answered "may this program or file be executed or scanned?". The
  `program` / `argv` fields carry the per-call context; `server` /
  `tool` are usually empty.

## File layout

- Path: `<runDir>/filesystem-events.jsonl`.
- Encoding: newline-delimited JSON (JSONL), one `FilesystemEventRecord`
  per line.
- Open mode: `O_APPEND | O_CREATE | O_WRONLY`.
- Concurrency: per-writer mutex serializes encode + sync.
- Redaction: this file preserves the original byte sequence the agent
  supplied. The downstream `leaks.jsonl` aggregator scrubs secrets at
  the leaks-write step. Operators who need a sanitized copy should
  read `leaks.jsonl`.

## Record shape (FilesystemEventRecord)

| Field             | Type              | Required | Meaning |
|-------------------|-------------------|----------|---------|
| `_schema_version` | int               | yes      | Always `1` in v0.1. |
| `timestamp`       | string (RFC3339 with numeric offset) | yes | Moment the enforcer reached the decision. The writer fills this in when the caller leaves it empty; emitter timestamps are preserved otherwise. |
| `run_id`          | string            | yes      | Duplicated into every record. |
| `source`          | string            | yes      | `mcp-gateway` or `shim`. Required so the aggregator can dispatch to the right per-source dedup key. |
| `operation`       | string            | yes      | Verb the agent attempted (`read`, `write`, `list`, `delete`, `exec`, `stat`, or a future emitter-specific verb). |
| `path`            | string            | yes      | Filesystem path the operation targeted (value the agent supplied, before any resolve / canonicalize pass). Required: a record with no `path` defeats the audit's purpose. |
| `resolved_path`   | string            | optional | Canonical / normalized path the enforcer derived from `path` (symlinks followed, `..` segments collapsed). Populated when the enforcer resolved the path before deciding; empty when the enforcer rejected on the raw path. |
| `decision`        | string            | yes      | Enforcer verdict: `allow`, `warn`, or `block`. |
| `reason`          | string            | yes      | Human-readable explanation (e.g. "filesystem path outside workspace", "interpreter-via-file content matched high-risk pattern"). |
| `server`          | string            | optional | MCP server name (when `source: "mcp-gateway"`). |
| `tool`            | string            | optional | MCP tool name (when `source: "mcp-gateway"`). |
| `program`         | string            | optional | Resolved binary name the shim was asked to run (when `source: "shim"`). |
| `argv`            | array of strings  | optional | Shim-captured argument vector (when `source: "shim"`). Encoded as a slice so a downstream parser does not have to re-tokenize a flattened command line. |
| `turn_id`         | string            | optional | Supervisor-minted turn identifier in effect when the verdict was reached. The emitter consults `CurrentTurn` on the control socket before forwarding. Empty when no turn source is wired or when the agent has not yet called `BeginTurn`. |
| `policy_event_id` | string            | optional | Opaque per-decision identifier the policy engine mints when the verdict was routed through `EvaluateShellCommand` or a future `EvaluateFilesystemAccess`. Used by the leaks aggregator's dedup key. |
| `snippet`         | string            | optional | Short captured byte fragment showing the context that triggered the decision (matched line of an interpreter-via-file content scan, offending JSON-RPC argument body). The MCP gateway's secret detector already scrubs secrets out of `snippet` before forwarding; the shim's interpreter-via-file scanner does the same. |

## Decision tokens

| Token   | Meaning |
|---------|---------|
| `allow` | The enforcer let the operation proceed. |
| `warn`  | The operation proceeded but the supervisor flagged it for review. |
| `block` | The operation was refused; the agent receives an error. |

## Source-specific notes

### `source: "mcp-gateway"`

Records emitted by the MCP gateway's filesystem scope enforcer
(`internal/mcp/scope_filesystem.go`). The enforcer's per-call rules
are documented in [`mcp-security.md`](mcp-security.md): paths are
resolved relative to the workspace root captured at construction,
symlinks are followed via `EvalSymlinks`, and an escape produces
`ErrFilesystemPathOutsideWorkspace` (a `block` record with the
`outside workspace root` reason).

A record with `source: "mcp-gateway"` will always set `server` and
`tool`; `program` and `argv` are absent.

### `source: "shim"`

Records emitted by the shell shim helper
(`cmd/ai-env/shim_helper_shell.go`). The shim scans interpreter-via-file
invocations (`bash <(curl ...)`, `python /tmp/script.py`) and produces a
`block` decision when the content matches a `HighRiskShellPatterns`
rule. The single-fd TOCTOU-safe flow (`O_RDONLY | O_NOFOLLOW` for both
scan and exec via `execveat` on Linux or `/dev/fd/<n>` on macOS) means
the `path` and `resolved_path` fields refer to the same fd's content.

A record with `source: "shim"` will always set `program` and `argv`;
`server` and `tool` are absent.

## See also

- `internal/run/filesystem_events.go`: `FilesystemEventRecord`,
  `FilesystemEventsWriter`, source / decision constants.
- `internal/mcp/scope_filesystem.go`: filesystem scope enforcer that
  emits gateway-sourced records.
- `cmd/ai-env/shim_helper_shell.go`: shell shim that emits
  shim-sourced records.
- [`leaks-jsonl-schema.md`](leaks-jsonl-schema.md): the unified view
  joins filesystem events with the other streams via the dedup key
  `(source_stream, source_line, policy_event_id)`.
