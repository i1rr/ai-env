# Operator runbook

This document is the day-to-day operator reference for installing,
running, and troubleshooting `ai-env`. It assumes a workstation or CI
host on Linux (`GOOS=linux`) or macOS (`GOOS=darwin`); see
[`platform-parity.md`](platform-parity.md) for the per-platform
behaviour notes.

Read it alongside:

- [`backends.md`](backends.md): adapter selection and isolation
  strength.
- [`threat-model.md`](threat-model.md): which actors ai-env distrusts.
- [`enforcement-boundaries.md`](enforcement-boundaries.md): what each
  layer enforces.
- [`mcp-security.md`](mcp-security.md): MCP gateway and registry.
- [`unsafe-modes.md`](unsafe-modes.md): the flags an operator opts
  into and what they trade away.
- [`leaks-jsonl-schema.md`](leaks-jsonl-schema.md),
  [`transcript-jsonl-schema.md`](transcript-jsonl-schema.md),
  [`filesystem-events-jsonl-schema.md`](filesystem-events-jsonl-schema.md):
  the audit-stream schemas.

## Install

### From source

```sh
# Go 1.22 or newer is required (see go.mod).
go install github.com/rivan1986/ai-env/cmd/ai-env@latest
```

The binary lands in `$(go env GOBIN)` or `$(go env GOPATH)/bin`. Put
that directory on your `PATH`. The binary is self-contained; there is
no daemon and no system state outside the per-project `.ai-env/`
directory.

### Local build (development)

```sh
git clone https://github.com/rivan1986/ai-env.git
cd ai-env
go build -o ai-env ./cmd/ai-env
./ai-env --help
```

### Optional host tooling

Most flows work with the Go binary alone. The following host tools add
optional capabilities; ai-env warns when one is missing rather than
crashing:

- `docker` or `podman`: reduced-isolation fallback backends. The
  primary `docker_sbx` adapter targets the Docker Sandboxes runtime.
- `gitleaks`: optional secret scanner. Missing scanners warn rather
  than crash; the built-in pattern scanner always runs.
- `git`: workspaces scaffolded from Git repositories use
  `git worktree`. Non-Git sources fall back to a filtered copy.
- `tcpdump`: macOS pflog-based egress observation requires it.
- Linux capabilities `CAP_NET_ADMIN` plus a real netns (not
  slirp4netns) for NFLOG-based egress observation. Without them the
  supervisor emits `observer_unavailable` with the documented reason.

## First run

```sh
# In your project root
ai-env new demo                       # scaffold .ai-env/ + workspace for "demo"
ai-env policy init                    # write a conservative default policy.yaml (if missing)
ai-env agents doctor                  # confirm the agent CLI is installed and credentialed
ai-env mcp list                       # confirm the MCP registry shape (if you use MCP)

# Once `ai-env run` is wired (later plan), the supervised run will look like:
# ai-env run demo --agent claude --task "fix the failing tests"

# Review the result
ai-env status demo                    # current/last run state
ai-env logs   demo                    # captured stdout/stderr for the latest run
ai-env diff   demo                    # baseline -> workspace diff
ai-env report demo                    # human-readable run report (incl. network summary)
ai-env leaks  demo                    # unified leak-coverage view across every audit stream

# Export
ai-env scan  demo                     # run secret + dependency scanners on the workspace
ai-env patch demo --out demo.patch    # export the diff as a unified-diff patch (export-gated)
ai-env pr    demo --draft             # open a brokered draft PR (export-gated, no raw token in sandbox)
```

Each command operates on the env's latest run by default. Pass
`--run <id>` to pin a historical run under
`.ai-env/runs/<run-id>/`.

## Configuration files

Every successful `ai-env new` writes the following files into
`.ai-env/`:

| File                   | Mode | Purpose |
|------------------------|------|---------|
| `ai-env.yaml`          | 0644 | Project identity, workspace strategy, sandbox backend, supervision and logging limits. |
| `policy.yaml`          | 0644 | Network, filesystem, command, dependency, secret, scanner, and review policy defaults. Conservative defaults. |
| `agents.yaml`          | 0644 | Registry of agent adapters. Defaults to a single `claude` entry with autonomous and interactive modes. |
| `secrets.example.yaml` | 0644 | Documents required secret providers. Never contains real credentials. |
| `secrets.local.yaml`   | 0600 | Gitignored stub for machine-local secret values. Contains only comments by default. |
| `mcp.yaml`             | 0644 | MCP server registry. See [`mcp-security.md`](mcp-security.md). |
| `env.yaml`             | 0644 | Per-env workspace metadata, including the origin pin. |

The mode-0600 check on `secrets.local.yaml` runs at every load; a
world-readable or group-readable file produces a
`secrets_permission_warning` lifecycle event. The run continues; fix
the mode with `chmod 0600`.

## Run directory layout

A supervised run materializes the following under
`.ai-env/runs/<run-id>/`:

```
.ai-env/runs/<run-id>/
  task.md
  run.json                # atomic-replace snapshot of the run record
  lifecycle.jsonl         # state transitions + every subsystem verb
  stdout.log              # captured agent stdout
  stderr.log              # captured agent stderr
  agent-command.txt
  transcript.md           # rendered transcript
  transcript.jsonl        # structured per-CLI transcript (see transcript-jsonl-schema.md)
  shell-commands.jsonl    # shim-captured shell invocations
  filesystem-events.jsonl # MCP + shim filesystem decisions (see filesystem-events-jsonl-schema.md)
  network-events.jsonl    # per-egress decision
  policy-decisions.jsonl  # export-gate + broker + shell-policy decisions
  mcp-calls.jsonl         # MCP gateway AuthorizeLaunch / AuthorizeCall verdicts
  git-diff.patch          # partial diff on stop
  secret-scan.json
  dependency-report.json
  security-report.md
  final-summary.md        # human-readable terminal summary
  leaks.jsonl             # derived, atomic-written unified view (see leaks-jsonl-schema.md)
  scan-results/
```

Every file is materialized as an empty placeholder up front so
emitters do not have to do their own first-write-creates dance. The
run directory itself is `chmod 0700` so other accounts on the host
cannot read the sensitive evidence.

## Inspecting a finished run

```sh
ai-env status demo                    # state, agent, backend, timings
ai-env report demo                    # one-shot human-readable report
ai-env logs   demo --stream both      # captured stdout/stderr
ai-env leaks  demo                    # cross-stream unified leak view
ai-env leaks  demo --format json      # JSONL pass-through for pipelines
ai-env leaks  demo --vector 4         # filter to one leak-coverage audit vector
ai-env leaks  demo --source mcp-calls # filter to one source stream
```

The leak-coverage audit vectors (1..8) are:

1. Path escape (workspace boundary).
2. GitHub repo / branch escape (origin pin and broker prepare).
3. Network egress to a non-allowlisted destination.
4. Provider proxy abuse (Host-header allowlist and upstream pin).
5. GitHub broker token leakage (raw token visibility).
6. MCP gateway scope escape (filesystem / GitHub scopes, schema-hash
   drift).
7. Shell shim bypass (high-risk patterns, interpreter-via-file).
8. Transcript / MCP correlation (turn-id mismatch, gap detection).

`ai-env leaks --vector N` filters to a single vector;
`ai-env leaks --source <stream>` filters by source stream name
(`policy-decisions`, `mcp-calls`, `secret-scan`, etc.).

## Troubleshooting

### `observer_unavailable` in the audit trail

The egress observer could not attach. Cause depends on the `reason`
metadata key:

- `slirp4netns`: the backend selected slirp4netns networking and
  NFLOG cannot attach inside it. On Linux, run with a real netns
  (rootful Docker or the primary `docker_sbx` backend). On macOS the
  observer mode is pflog, not NFLOG; this token should not appear on
  darwin.
- `no_capability`: the host lacks `CAP_NET_ADMIN` (Linux) or the
  pflog tooling (macOS). Confirm `tcpdump` is on `PATH` for macOS
  hosts; for Linux ensure the supervisor runs with the required
  capability set.

The run continues; network-level evidence is degraded for this run.

### `network_policy_degraded`

The adapter could not enforce a portion of the configured policy
(iptables rule rejected, ipset missing). Check the `reason` and
`missing` metadata keys on the lifecycle event for what was dropped.
The remaining policy still applies; verify the run's
`network-events.jsonl` after the run to confirm no destination outside
the intended allowlist was reached.

### `shim_coverage_degraded`

One or more shim wrappers could not be installed at every canonical
path. The `program` and `missing` metadata keys identify which program
and which canonical paths failed. PATH-relative coverage still
applies; an agent that invokes `python` via PATH still goes through
the wrapper. An agent that invokes `/usr/bin/python3` directly while
the bind-mount overlay failed bypasses the wrapper.

### `secrets_permission_warning`

`.ai-env/secrets.local.yaml` has a permission anomaly (world- or
group-readable). The expected mode is `0600`. Fix with:

```sh
chmod 0600 .ai-env/secrets.local.yaml
```

The run still loaded the file; the warning is the audit signal.

### `helper_rpc_aborted`

The supervisor refused a control-socket RPC mid-flight. The `method`
and `reason` metadata keys identify which. Common causes:

- `bad_token`: an agent process tried to call the control socket with
  the wrong token (or without one). This is the expected behaviour
  for an agent attempting to bypass the per-server token scoping.
- `version_mismatch`: helper version skew with the supervisor. Rebuild
  the binary so the helper and supervisor share a build.
- `shutdown`: the supervisor was in `AcceptingShutdown` state when the
  RPC arrived. Expected during teardown.
- `no_handler`: the RPC method is not registered. Indicates an
  out-of-tree helper or a stale binary.

### `transcript_parser_error`

The per-CLI transcript parser dropped a line. The `cli` and `reason`
metadata keys identify which:

- `scan_overflow`: a single stdout line exceeded 1 MiB. The line is
  dropped; the parser continues at the next `\n`. Expected for some
  pathological tool outputs.
- `json_parse`: a line did not decode as a JSON object. The line is
  dropped. Indicates the agent CLI emitted non-JSON onto its stream.
- `stream_error`: the underlying reader returned a non-EOF error
  mid-scan. The parser stops reading; the supervisor's stdout pump
  re-opens or finalizes.

### `gateway_secret_blocked` / `gateway_secret_response`

The MCP gateway's per-direction secret scanner blocked an outbound
request (`gateway_secret_blocked`) or scrubbed an inbound response
(`gateway_secret_response`). The `pattern` metadata key identifies
which `scanners.builtinPatterns()` rule matched. A blocked outbound
call is the expected response to an agent trying to ship a credential
through an MCP tool; investigate which tool the agent invoked
(`server`, `operation` metadata).

### `mcp_config_neutralized`

A workspace-local MCP config (`.mcp.json`,
`.claude/settings.json#mcpServers`) was renamed to `*.ai-env-shadowed`
at `backend.Create` to prevent the agent CLI from auto-merging it
with the supervisor-managed `mcp-servers.json`. The original file is
restored at `backend.Destroy`. If the run crashed mid-flight, the
shadowed file is still on disk: rename it back manually.

### `origin_drift`

The GitHub broker refused at PR time because the workspace's origin no
longer matches the origin pin recorded at `ai-env new`. Either restore
the original remote or run `ai-env new` again to capture a new pin.
This is the expected response to an agent that changed `git remote
set-url` mid-run.

### `broker_unavailable`

The GitHub broker could not start in this run. The `reason` metadata
key identifies which:

- `missing_secrets`: `.ai-env/secrets.local.yaml` does not contain a
  GitHub App or PAT entry. Fill it in or skip `ai-env pr`.
- `origin_drift`: see above.
- `mint_failed`: the App-token mint endpoint returned an error.
  Inspect the broker log for the redacted error; common causes are
  installation-id mismatch or App-private-key shape mismatch.

### `leaks.jsonl.tmp.*` files left in a run directory

A previous supervisor crashed mid-rebuild. The next supervisor start
sweeps stale tmp files older than its own start time. If a tmp file
is in a directory whose supervisor never restarted, remove it
manually:

```sh
rm .ai-env/runs/<run-id>/leaks.jsonl.tmp.*
```

`ai-env leaks` already skips `*.tmp.*` files at read time, so the
stale tmp does not show in the operator view.

## Re-running a failed or interrupted run

`ai-env new` does not need to be repeated; the workspace persists. To
start a continuation run that inherits the previous run's task:

```sh
# Once `ai-env run` is wired (later plan):
# ai-env run demo --continue
```

Continuation rules:

- The previous run must be in `killed_by_user`, `timed_out`, or
  `killed_idle`. Other terminals refuse continuation.
- The new run inherits the previous `task.md` unless `--task` is set.
- The workspace is left untouched: no checkout, no reset, no clean.
- The new `run.json` records the previous run's id in
  `linked_previous_run`.

## Common operator tasks

### Add a new MCP server

See [`mcp-security.md` operator playbook](mcp-security.md#operator-playbook).
The short version:

```sh
ai-env mcp add my-server \
  --source npm:@example/server@1.2.3 \
  --digest sha256:abc... \
  --scope-filesystem-root workspace_only \
  --policy allow
# Launch once to capture the live schema hash from mcp-calls.jsonl.
ai-env mcp pin my-server --schema-hash sha256:def...
```

### Rotate a GitHub broker credential

Edit `.ai-env/secrets.local.yaml` and replace the `github.app` or
`github.pat` block. The broker constructs a fresh `TokenSource` on
every run, so the next `ai-env pr` picks up the new credential.
Existing tokens in flight expire naturally at their TTL.

### Park a server during an incident

Edit `mcp.yaml` and set the server's `policy` to `deny`. The next
launch of that server blocks with `ErrServerParked` and the audit log
distinguishes the parked state from an unknown server. Restore to
`allow` (or `warn`) when the incident resolves.

### Tear down an env

```sh
ai-env destroy demo
```

Removes the workspace, the baseline (copy strategy), and the per-env
worktree branch. Run records under `.ai-env/runs/` and the shared
`.ai-env/*.yaml` config files are intentionally kept so the audit
trail of past runs survives env reuse. Running destroy twice is a
no-op: the second invocation exits 0 with an "already absent" notice.

## When to escalate

Escalate to maintainers when:

- The supervisor crashes during a run (no `final-summary.md`, no
  `run.json` `state: completed`). Attach the run directory.
- `ai-env leaks` reports a vector you did not expect (e.g. vector 5
  GitHub-broker leak with a non-empty token in any field). The
  redaction pass should make this impossible; a hit is a bug.
- A bind-mount in the canonical-path shadow set fails on a baseline
  image you expected to work (`shim_coverage_degraded`). The
  canonical set is defined in `internal/policy/shim_programs.go`;
  extending it is the maintainer's job.
- The MCP gateway emits a `Block` outcome with a reason you cannot
  map to one of the documented sentinels. The gateway should always
  produce one of the known errors; a "missing scope enforcer" hit on
  a scope kind that should be registered is a bug.
