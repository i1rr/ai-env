# transcript.jsonl schema

`transcript.jsonl` is the per-run audit projection of the agent CLI's
output stream. The supervisor's per-CLI parsers
(`internal/run/transcript.go`) consume the agent's structured stdout
(Claude Code's `--output-format stream-json --verbose -p`, Codex's
`--json`) and translate each frame into a uniform `TranscriptRecord`
that downstream consumers (`leaks.jsonl` aggregator, final-summary
renderer, audit reviewer) can read without per-CLI translation.

The file is append-only, fsynced after every record. Its on-disk shape
matches the convention shared with `lifecycle.jsonl`,
`network-events.jsonl`, `mcp-calls.jsonl`,
`policy-decisions.jsonl`, and `filesystem-events.jsonl`. The supervisor
opens it as an empty placeholder at run-directory creation so emitters
do not have to do their own first-write-creates dance.

## Schema-version contract

Every record carries `_schema_version: 1` (constant
`TranscriptRecordSchemaVersion`). The contract is identical to the one
documented in [`leaks-jsonl-schema.md`](leaks-jsonl-schema.md):
readers refuse a record with `_schema_version > 1`, ignore unknown
fields forward, and consult `run.json.schema_versions` for the per-run
version map written at supervisor step 1.

## File layout

- Path: `<runDir>/transcript.jsonl`.
- Encoding: newline-delimited JSON (JSONL), one `TranscriptRecord` per
  line.
- Open mode: `O_APPEND | O_CREATE | O_WRONLY`. Empty placeholder at
  run-directory creation; the parser appends as frames arrive.
- Concurrency: writes are serialized by a per-writer mutex so two
  emitters cannot interleave bytes inside a single JSON line.
- Redaction: this file preserves the original byte sequence so an
  auditor sees what the CLI emitted. The downstream `leaks.jsonl`
  aggregator scrubs leaked secrets at the leaks-write step. Operators
  who need a sanitized copy should read `leaks.jsonl`.

## Per-CLI parsers

The plan pins one parser per supported CLI. Each translates the
vendor-specific frame vocabulary into the canonical `Kind` token set
documented below:

- `claude`: parses Claude Code's `--output-format stream-json --verbose
  -p` stream. Frames carry `type` plus optional `message`, `content`,
  and `result.subtype` fields.
- `codex`: parses Codex's `--json` stream. Frames carry `type`,
  optional `role`, `message`, `text`, `tool`, and `name` fields.

A line that exceeds the 1 MiB scanner cap, or fails to decode as JSON,
or comes off the stream with a non-EOF error surfaces as a
`transcript_parser_error` lifecycle verb (see
[`leaks-jsonl-schema.md`](leaks-jsonl-schema.md) for the metadata
schema). The parser drops the line and continues at the next `\n`
boundary; the run continues.

## Canonical Kind tokens

The `Kind` field is one of:

| Token         | Meaning |
|---------------|---------|
| `system`      | System-prompt / init frame (Claude `system`, Codex `session_start`). |
| `user`        | User-message frame. Marks the start of a turn for the correlation surface. |
| `assistant`   | Assistant text frame. |
| `tool_use`    | Tool-call frame (Claude `assistant` with `tool_use` content block, Codex `tool_call`). Carries `Tool` and `Args`. |
| `tool_result` | Tool-result frame. |
| `result`      | Terminal "result" frame (Claude `result`, Codex `shutdown`). `Reason` carries the CLI-supplied stop reason. |
| `error`       | CLI-emitted error frame (Codex `error`, Claude `result` with `subtype: error`). `Reason` carries the error text. |

## Record shape (TranscriptRecord)

| Field             | Type              | Required | Meaning |
|-------------------|-------------------|----------|---------|
| `_schema_version` | int               | yes      | Always `1` in v0.1. |
| `timestamp`       | string (RFC3339 with numeric offset) | yes | Moment the line was observed on the agent's stdout. The parser stamps its own observed-time timestamp; an emitter-supplied value is preserved. |
| `run_id`          | string            | yes      | Duplicated into every record. |
| `cli`             | string            | yes      | `claude` or `codex`. |
| `kind`            | string            | yes      | One of the canonical tokens above. |
| `turn_id`         | string            | optional | Supervisor-minted turn identifier in effect when the line was read. Empty when no turn source is wired or when the agent has not called `BeginTurn`. Readers treat empty as "unknown". |
| `seq`             | int               | optional | Monotonic per-CLI line counter starting at 1. Used by the leaks aggregator to detect gaps in a long-lived stream. Gap detection is only robust for the long-lived MCP shim; shell-mode helpers emit `seq=1` always. |
| `role`            | string            | optional | Speaker role (`user`, `assistant`, `system`). Set on system / user / assistant records; empty on tool / result / error. |
| `text`            | string            | optional | Rendered text payload (assistant message text, user-prompt text, system-prompt text, tool-result text body). Preserved raw; the leaks aggregator redacts at its write step. |
| `tool`            | string            | optional | MCP or built-in tool name on `tool_use` / `tool_result`. The leaks aggregator joins on `(tool, turn_id)` against `mcp-calls.jsonl`. |
| `args`            | string            | optional | Tool-call arguments blob the agent supplied, stringified for the audit log. Set on `tool_use`. Emitters truncate large payloads before forwarding (the 1 MiB scanner cap is the upper bound). |
| `message_id`      | string            | optional | Per-message identifier the CLI minted (Claude `message.id`, Codex `id` on `agent_message`). Used by the leaks aggregator to join sub-frames of one message. |
| `reason`          | string            | optional | CLI-supplied stop reason / error text on `result` / `error` records. |
| `snippet`         | string            | optional | Short captured byte fragment showing the context that prompted the record. Emitters trim to a reasonable size before forwarding. |

## Correlation key (best-effort)

The plan's "correlation key" note pins the semantics:

- Turn IDs are supervisor-minted over the control socket via
  `BeginTurn` and read via `CurrentTurn`. The parser consults the
  per-run `TurnSource` (typically `*run.ControlSocket`) before stamping
  each record.
- Gap detection is robust only for the long-lived MCP shim. Shell-mode
  helpers always emit `seq=1`.
- A compromised agent can call `BeginTurn` out of order or delay it,
  so vector-8 evidence quality is "best-effort under non-compromised
  agent". Auditors should treat correlation as advisory.

## Parser-error reasons

Lines that the parser cannot process trigger a
`transcript_parser_error` lifecycle verb. Three canonical tokens:

| Token            | Trigger |
|------------------|---------|
| `scan_overflow`  | A single stdout line exceeded `transcriptScannerMaxBuffer` (1 MiB). The parser drops the line and continues at the next `\n`. |
| `json_parse`     | A line did not decode as a JSON object. |
| `stream_error`   | The underlying `io.Reader` returned a non-EOF error mid-scan. The parser stops reading; the supervisor's stdout pump will re-open or finalize. |

The full metadata schema for `transcript_parser_error` is documented
in [`leaks-jsonl-schema.md`](leaks-jsonl-schema.md#transcript_parser_error).

## See also

- `internal/run/transcript.go`: `TranscriptRecord`, `TranscriptWriter`,
  `TranscriptCLI`, parser implementation.
- `internal/run/control_socket.go`: `BeginTurn` / `CurrentTurn` RPCs
  the parser consults for `TurnID`.
- [`leaks-jsonl-schema.md`](leaks-jsonl-schema.md): the unified view
  joins on `(cli, turn_id, tool)`.
