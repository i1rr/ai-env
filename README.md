# ai-env

`ai-env` is a Go CLI that scaffolds isolated sandbox environments for AI coding agents (Claude Code, Codex). Each environment lives under `.ai-env/` in your project: its own workspace, its own configuration, its own policy, its own run trail, all separate from your active working copy. The goal is to let an autonomous agent edit code, run commands, and reach the network on your behalf without trusting it with your shell, your repo's main branch, your SSH keys, your Docker socket, or arbitrary internet egress.

## Quickstart

Build the binary, scaffold an environment for the current project, look at what was generated, and export the agent's changes back to your tree.

```sh
# 1. Build (Go 1.22+ required)
go install github.com/rivan1986/ai-env/cmd/ai-env@latest

# 2. From inside your project repo, create an environment named "demo"
cd path/to/your/project
ai-env new demo

# 3. Inspect what was scaffolded under .ai-env/
ai-env list
ai-env policy check demo

# 4. (Run the agent against the workspace -- see "First run" below)

# 5. Review the agent's changes
ai-env diff demo
ai-env status demo
ai-env logs demo

# 6. Scan the workspace and export the changes as a patch
ai-env scan demo
ai-env patch demo --out demo.patch
```

The `.ai-env/` directory holds every environment's workspace, configs, policy, and run artifacts. Each environment also gets a per-run trail under `.ai-env/workspaces/<env-name>/.runs/<run-id>/` containing the captured stdout / stderr, partial diff, `network-events.jsonl`, `policy-decisions.jsonl`, and `final-summary.md`.

## Install

### From source (recommended)

```sh
go install github.com/rivan1986/ai-env/cmd/ai-env@latest
```

The binary lands in `$(go env GOBIN)` or `$(go env GOPATH)/bin`. Add that directory to your `PATH` if it is not there already.

### Local build (development)

```sh
git clone https://github.com/rivan1986/ai-env.git
cd ai-env
go build -o ai-env ./cmd/ai-env
./ai-env --help
```

Go 1.22 or newer is required (see `go.mod`). The binary is self-contained: there is no daemon and no system state outside the per-project `.ai-env/` directory.

### Optional host tooling

Most flows work with the Go binary alone. A few features become available when their host tools are installed and discoverable on `PATH`:

- `docker` or `podman` for the reduced-isolation fallback backends. The primary `docker_sbx` adapter targets a Docker Sandboxes-compatible runtime.
- `gitleaks` for the optional gitleaks scanner adapter. Missing scanners warn rather than crash; the built-in pattern scanner always runs.
- `git` for environments scaffolded from Git repositories (workspaces are materialized via `git worktree`).

## First run

A first end-to-end run looks like this. The example uses `claude` as the agent; `codex` works the same way.

```sh
# In your project root
ai-env new demo                       # scaffold .ai-env/ + workspace for "demo"
ai-env policy init                    # write a conservative default policy.yaml (if missing)
ai-env agents doctor                  # confirm the agent CLI is installed and credentialed

# Once `ai-env run` is wired (later plan), the supervised run will look like:
ai-env run demo --agent claude --task "fix the failing tests"

# Review the result
ai-env status demo                    # current/last run state
ai-env logs   demo                    # captured stdout/stderr for the latest run
ai-env diff   demo                    # baseline -> workspace diff
ai-env report demo                    # human-readable run report (incl. network summary)

# Export
ai-env scan  demo                     # run secret + dependency scanners on the workspace
ai-env patch demo --out demo.patch    # export the diff as a unified-diff patch (export-gated)
ai-env pr    demo --draft             # open a brokered draft PR (export-gated, no raw token in sandbox)
```

Each command operates on the env's latest run by default. Pass `--run <id>` to pin one of the historical runs under `.ai-env/workspaces/demo/.runs/`.

Note: the user-facing `ai-env run` and `ai-env destroy` subcommands wire the supervisor, backend, network adapter, provider proxy, and scan hook together end-to-end. The supervisor, backends, network policy adapters, scanners, export gate, and GitHub broker that those commands compose are already in tree (see the "Run lifecycle", "Backend abstraction", "Network policy enforcement", "Scanning", "Export gate", and "GitHub broker" sections below); the `run` / `destroy` Cobra wiring lands in a later plan.

## Supported agents

`ai-env` ships with launchers for the two AI coding agents below. The launcher detects the binary, probes its version, picks the right autonomous flag, and resolves how credentials should be supplied (host env var passthrough, file mount, or provider-proxy injection).

| Agent       | CLI binary | Launcher package                  |
| ----------- | ---------- | --------------------------------- |
| Claude Code | `claude`   | `internal/agents/claude`          |
| Codex       | `codex`    | `internal/agents/codex`           |

Use `ai-env agents list` to see which launchers are registered and what versions are detected on this host, `ai-env agents doctor` to run health + credential checks for every registered agent, and `ai-env agents probe <agent>` to probe a single agent's version, autonomous flags, and `--help` output.

Adding a new agent means writing a `Launcher` implementation in `internal/agents/<name>/` and registering it in `internal/cli/agents.go::LauncherFactory`. There is no plugin system; agents are first-class in the binary so the supervisor can enforce its contracts on every launch.

## Security summary

`ai-env`'s security model is **defense in depth, fail-closed**. The threat model assumes the AI agent is untrusted: it may be buggy, prompt-injected, or actively adversarial. The CLI's job is to give the agent enough room to do useful work while making it expensive or impossible to exfiltrate secrets, mutate the host, or push unreviewed code.

The MVP enforces, at minimum:

- **Workspace isolation.** Each env is materialized in its own directory under `.ai-env/workspaces/<env-name>/`, via `git worktree` for Git sources or a filtered copy for non-Git sources. The agent never sees your active working tree.
- **Protected paths.** The supervisor refuses to scaffold or expose files matched by the project's protected-path patterns (SSH keys, cloud credentials, `.env`, etc.). The same patterns gate diff/patch export.
- **Policy engine.** Every run consults `.ai-env/policy.yaml` for allowed network domains, denied command patterns, and per-env overrides. Decisions are written to `policy-decisions.jsonl` and recoverable via `ai-env policy explain`.
- **Network policy, fail-closed.** The supervisor refuses to start a run if the configured network adapter rejects the policy. Egress is constrained to an explicit allow-list of provider domains; everything else is blocked at the backend level. A host-side provider proxy fronts Anthropic / OpenAI traffic with redacted logs so raw API keys never reach the sandbox.
- **Backend sandbox.** The default backend is the Docker Sandboxes (`sbx`) runtime; rootless Docker and Podman are supported as reduced-isolation fallbacks, gated behind explicit `--accept-reduced-isolation` and `--unsafe-host-network` flags. The host Docker socket and SSH agent socket are never mounted into the sandbox.
- **Optional shell shim.** With `--shell-shim`, the agent's `bash` / `sh` invocations are routed through a wrapper that logs each command, denies obvious high-risk patterns (curl-pipe-shell, SSH paths, cloud metadata IP), and consults the policy for the rest.
- **Scanning + export gate.** `ai-env scan` runs a built-in pattern-only secret scanner (provider API keys, PEM headers, `.env` assignments), an entropy-only warn analyzer, and optional adapters (gitleaks, external scanners). The `ExportGate` blocks `ai-env patch` / `ai-env pr` on high-confidence secret findings; entropy-only findings warn but do not block.
- **Brokered PRs.** `ai-env pr` opens draft pull requests via a host-side GitHub broker. The agent never sees a raw GitHub token: the broker holds the credential in an in-memory `TokenHolder` with TTL clamping and revocation, redacts token-like strings from logs, and enforces branch-prefix / protected-branch / path-gate / metadata-scan checks before opening the PR.
- **Auditable run trail.** Every run produces `network-events.jsonl`, `policy-decisions.jsonl`, captured stdout/stderr, a partial diff, and a `final-summary.md`. `ai-env report` and `ai-env logs` surface them.

Detailed treatments live under `docs/` (`threat-model.md`, `enforcement-boundaries.md`, `residual-risk.md`, `model-credentials.md`, `backends.md`, `unsafe-modes.md`). Read those before relying on `ai-env` for anything you would not run yourself in a coffee shop.

## Status

Plans 01, 02, 03, 04, 05, 06, and 07 complete. The CLI builds and runs on macOS and Linux, has unit and integration tests for config, scaffold, stack detection, gitignore handling, workspace materialization (Git and non-Git fixtures), diff and patch generation, protected path patterns, run-ID uniqueness within the same second, max-runtime timeout, SIGINT log/diff preservation, `sbx` version compatibility, agent flag selection, credential-mode resolution, the network policy validator, the `docker_sbx` policy adapter, the docker / podman fallback adapters (including the `--accept-reduced-isolation` and `--unsafe-host-network` gates), the provider proxy (loopback bind, upstream domain pin, host-side auth injection, log redaction, shutdown), the `network-events.jsonl` writer and summary, the `ai-env report` renderer, the `final-summary.md` writer, the built-in pattern scanner (provider API keys, PEM private-key headers, `.env`-style assignments, allowlist comments), the warn-only entropy analyzer, the gitleaks adapter, external-scanner discovery (missing tools warn rather than crash), the `ai-env scan` subcommand, the `ExportGate` (hard vs. configurable blockers, `ModePatch` vs. `ModePR`), the scan hook wired into the supervisor's `StateScanning` step, branch-prefix and protected-branch validation, broker path-gate checks, PR metadata scanning, broker-generated PR body, GitHub App installation token + PAT fallback selection, `TokenHolder` TTL clamping and revocation, broker log redaction (`RedactTokens`, `RedactingWriter`), the `ai-env pr` broker lifecycle (gate, prepare, acquire, push, scan, create, revoke) with raw-token-invisibility and revocation acceptance tests, and the per-run `policy-decisions.jsonl` writer wired into both `ai-env patch` and `ai-env pr`. CI runs `gofmt`, `go vet`, `go test -race`, `staticcheck`, and `govulncheck` via GitHub Actions. Real-backend and real-agent integration tests are gated behind `AI_ENV_BACKEND_INTEGRATION=1` and skip cleanly when their host prerequisites are absent.

## Installation

### From source (recommended for now)

```sh
go install github.com/rivan1986/ai-env/cmd/ai-env@latest
```

The binary lands in `$(go env GOBIN)` or `$(go env GOPATH)/bin`.

### Local build

```sh
git clone https://github.com/rivan1986/ai-env.git
cd ai-env
go build -o ai-env ./cmd/ai-env
./ai-env --help
```

Requires Go 1.22 or newer (see `go.mod`).

## Commands

### `ai-env new <env-name> [--from <path>] [--force]`

Scaffolds an `.ai-env/` directory in the current working directory, writes the four configuration files plus a gitignored secrets stub, and materializes a workspace under `.ai-env/workspaces/<env-name>/` using the strategy that matches the source layout.

Arguments and flags:

- `<env-name>`: required. 1 to 64 characters, ASCII letters, digits, `.`, `_`, `-`. Must start with a letter or digit. Used as the environment name, a directory component, and a Git branch suffix.
- `--from <path>`: optional. Source project path used for Git detection and stack detection. Defaults to the current directory. `.ai-env/` is always created in the current directory regardless of `--from`.
- `--force`: optional. Overwrite existing configuration files in `.ai-env/`. Without `--force`, the command refuses to clobber any of the generated files. If a workspace at `.ai-env/workspaces/<env-name>/` already exists, it is left untouched even with `--force`, so agent work in progress is not lost.

What it does:

1. Validates the env name.
2. Resolves the source project (current directory or `--from`).
3. Detects whether the source is a Git repository (`.git` present) and picks the workspace strategy: `worktree` for Git sources, `copy` for non-Git.
4. Detects the project stack from marker files at the source root and selects a template name.
5. Creates `.ai-env/` (mode `0755`) and writes the configuration files listed below.
6. Writes `.ai-env/secrets.local.yaml` with mode `0600`. This file contains a commented stub only, never raw credentials.
7. Materializes the workspace via the workspace package:
   - Worktree strategy: creates branch `ai-env/<env-name>` from the current HEAD and a Git worktree at `.ai-env/workspaces/<env-name>/`.
   - Copy strategy: copies the source directory to `.ai-env/workspaces/<env-name>/` and stores a read-only baseline snapshot at `.ai-env/baselines/<env-name>/` for later diffing.
   - Writes `.env-meta.json` inside the workspace recording strategy, branch (worktree), or baseline path and copy time (copy).
8. If a `.gitignore` exists at the source root, appends any missing required entries under an `# ai-env` section. If no `.gitignore` exists, prints the suggested entries to stdout and lets you add them.
9. Prints a summary with source path, strategy, template, workspace path, branch (when applicable), written files, and the `.gitignore` outcome.

### `ai-env list`

Walks upward from the current directory to find the nearest `.ai-env/ai-env.yaml`, then enumerates workspaces under `.ai-env/workspaces/`. For each workspace it prints `NAME`, `STRATEGY`, `TEMPLATE`, and `LAST RUN`.

The `LAST RUN` column is rendered as `<state> (<run-id>)` for the env's most recent run under `.ai-env/runs/`. Workspaces with no recorded run are rendered as `-`. The runs tree is walked once per `list` invocation (not once per workspace), and runs whose `run.json` is still the empty post-create placeholder are skipped so a half-written run does not mask an older completed one.

`ai-env list` never starts a backend process. It only reads files. If no `.ai-env/workspaces/` directory exists yet (fresh project), it prints a friendly empty-state message.

### `ai-env diff <env-name> [--name-only]`

Shows the changes a workspace has accumulated against its baseline.

- Worktree strategy: emits the `git diff` between the env branch (`ai-env/<env-name>`) and the source repo's HEAD.
- Copy strategy: emits a file-level unified diff against the read-only baseline snapshot at `.ai-env/baselines/<env-name>/`.

Output has two stable sections: a header with the env name, strategy, and a per-file summary (each line tagged `[protected]` when the path matches a protected pattern), followed by the unified-diff body. The body is suppressed when `--name-only` is set. Protected-path hits are also re-emitted on stderr as a warning block so scripts piping stdout into a reviewer still get the diff body unchanged. Like `ai-env list`, this command walks upward from the current directory to find the project's `.ai-env/`.

### `ai-env patch <env-name> --out <file> [--run <id>]`

Exports the same diff as `ai-env diff` to a unified-diff patch file suitable for `git apply` or `patch -p1`.

- `--out <file>`: required. Output path for the patch file (resolved relative to the current working directory). The file is always written when the gate allows the export, even when there are no changes, so callers that test for file existence behave consistently.
- `--run <id>`: optional. Pin the export gate to a specific historical run's scan and quarantine inputs. Defaults to the env's latest run.
- The export gate (see "Export gate" below) is consulted under `ModePatch` before the patch file is written. A hard block (e.g. a high-confidence secret leak, an `.ai-env/**` change, or a quarantined run) refuses the export with a non-zero exit and prints the blocking reasons to stderr; warning-level reasons (e.g. a `.github/workflows/**` change, lockfile change, or large diff) are surfaced but allow the patch through.
- Protected-path changes do not block export by default but trigger a stderr warning so reviewers see them; setting `review.require_diff_review: true` in `policy.yaml` upgrades them to a block.
- The copy strategy emits a per-file unified diff so the patch remains applicable even though there is no underlying Git history.

On success the command prints a per-file summary plus a `wrote: <path> (<n> bytes)` line, followed by any gate warnings.

### `ai-env scan <env-name> [--run <id>]`

Runs the built-in pattern-only secret scanner against the workspace diff plus every available external scanner, writes the consolidated artifacts into the env's run directory, and prints a summary. The command is the user-facing surface of plan 06.

- `--run <id>`: optional. Pin the scan artifacts to a specific historical run by its directory basename. Defaults to the env's latest run. The command requires at least one run to exist for the env (`ai-env run` will land in a later plan; until then a placeholder run directory must be present, typically from a previous `ai-env run`-equivalent test).
- The built-in scanner inspects only the files in the workspace diff (not the whole workspace) and flags high-confidence matches against the pattern classes documented in "Scanning" below. Every built-in finding carries `confidence: high` and `blocks_export: true`, so a single match is enough to refuse a later `ai-env patch` / `ai-env pr` export.
- Entropy warnings are written into the `entropy_warnings` array of `secret-scan.json`. They are surfaced in the summary but never block export by default; the entropy analyzer is intentionally warn-only in v0.1 to avoid false positives on UUIDs, checksums, generated IDs, and committed test fixtures.
- External scanners are probed via `exec.LookPath`. Available scanners that have a wired driver (gitleaks today) run automatically; available scanners whose driver lands in a later plan are listed in the summary but not invoked. Unavailable scanners produce a stderr warning ("install to enable") rather than aborting the scan.
- Two artifacts are written atomically (temp + rename) into `.ai-env/runs/<run-id>/`:
  - `secret-scan.json`: built-in findings, entropy warnings, and any gitleaks findings.
  - `dependency-report.json`: list of probed vulnerability / SAST scanners and the findings from the ones that successfully ran.

The summary block is stable (one label per line) and ends with a `result:` line that names the number of blocking findings the gate will see, so `ai-env scan` and a subsequent `ai-env patch` always agree on the verdict.

### `ai-env pr <env-name> [--run <id>] [--draft]`

Opens a brokered draft pull request for an env. The export gate is evaluated first under `ModePR`; if it allows, the `GitHubBroker` (see "GitHub broker" below) runs the prepare / acquire-token / push / metadata-scan / create / revoke sequence the plan's "Token lifecycle" diagram fixes.

- `--run <id>`: same semantics as `ai-env patch --run`.
- `--draft`: defaults to `true`. Plan 07 fixes draft-only as the v0.1 surface; the flag exists so a future non-draft opt-in can be added without changing the call site, but for now passing `--draft=false` still produces a draft PR.
- The gate runs under `ModePR`, which upgrades a `.github/workflows/**` change from a warning (under `ModePatch`) to a hard block. Every other hard blocker (`secret_finding`, `external_secret_finding`, `ai_env_change`, `policy_change`, `quarantine`) fires identically across the two modes. A block verdict prints the blocking reasons to stderr and exits non-zero; the broker is neither constructed nor invoked, so no credential is acquired and no GitHub API call is made.
- When the gate allows and a broker is configured, the broker runs in the order the plan pins: `Prepare` (branch prefix, protected branch, path gate), `AcquireToken` (short-lived GitHub App installation token or PAT fallback), `PushBranch` (host-side push with the credential injected into the git transport, never into shell history or the agent's environment), `ScanMetadata` (built-in scanner over PR title, body, branch name, and commit messages), `CreateDraftPR`, and `RevokeToken`. `RevokeToken` is always attempted via a deferred call so a mid-lifecycle failure still scrubs the credential.
- When the gate allows but no broker is configured, the command falls back to a preview-only verdict (per-file summary, any warnings, and a `note: broker not configured; PR push skipped (gate verdict only)` line) so an operator on a workstation without a GitHub App or PAT can still inspect the gate decision locally.
- Every gate verdict and every broker-lifecycle stage outcome (`broker_prepare`, `broker_acquire_token`, `broker_push_branch`, `broker_scan_metadata`, `broker_create_pr`, `broker_revoke_token`) is appended to `.ai-env/runs/<run-id>/policy-decisions.jsonl` as a single-line JSON record. The on-disk file is the audit trail for "why did this run not produce a PR" and survives across processes; see "Policy decisions" below.

### `ai-env status <env-name>`

Prints a one-shot, human-readable snapshot of an env's most recent run. Locates `.ai-env/` by walking upward from the current directory (same lookup as `list`/`diff`/`patch`), reads the latest run's `run.json` and the tail of its `lifecycle.jsonl`, and prints:

1. Env handle: env name, run ID, current state.
2. Identity: agent, backend, model credential mode (and a `reduced safety: yes` line when applicable).
3. Timing: `started`, `stopped` (when terminal) or `elapsed (running)` for in-flight runs.
4. Exit info: `exit code`, `stop reason`, `linked previous run` (when this run was started with `--continue`), and the first line of the task description.
5. On-disk artifacts: paths to `run dir`, `run.json`, `lifecycle.jsonl`, `stdout.log`, `stderr.log`, and `git-diff.patch`.
6. The last five lifecycle events, oldest first, so the flow is visible without opening `lifecycle.jsonl`.

`status` is read-only and atomic against a live supervisor: `run.json` is written via temp-file + rename, so concurrent readers always see either the previous or the new whole file. An env with no recorded runs yet exits 0 with a friendly "no runs yet" message.

### `ai-env logs <env-name> [--run <id>] [--stream stdout|stderr|both] [--follow]`

Prints captured stdout and/or stderr for an env's latest run. Flags:

- `--run <id>`: pick a specific historical run by its directory basename instead of the latest. When the run's recorded env name disagrees with the positional `<env-name>` a warning is printed on stderr but the dump still happens.
- `--stream <stdout|stderr|both>`: select which captured stream to print. Defaults to `both`, which concatenates `stdout.log` and `stderr.log` under `==> stdout <==` / `==> stderr <==` banners when both files are non-empty. Banners are suppressed when only one stream has bytes so an empty header is never printed.
- `--follow`: after the initial dump, keep tailing the underlying log file(s) for newly-appended bytes (poll-based, dependency-free, cross-platform). The loop exits when the run reaches a terminal state on disk or when the operator cancels (the supervisor wires SIGINT into the cancel channel).

An env with no recorded runs yet exits 0 with a friendly "no runs recorded" message. The log files are opaque text (whatever the agent wrote); `ai-env logs` does not parse them.

### `ai-env report <env-name> [--run <id>]`

Prints a one-shot report for an env's latest run (or for a specific historical run when `--run` is set), folding the network section into the same view the supervisor writes to `final-summary.md`. The output has four stable blocks rendered in this order:

1. Env handle: env name, run id, state, agent, backend (each line omitted when the corresponding field is absent, so a run that aborted before recording, for example, an agent does not surface a blank line).
2. Timing: `started`, `stopped`, `elapsed` for terminal runs; `elapsed (running)` for in-flight runs.
3. Network section: `network policy: applied | not attempted | failed`, the resolved `default`, the normalized allow-domain list, the blocked CIDRs and hosts the policy enforced, the total / allowed / denied event counts read from `network-events.jsonl`, and a "top allowed" / "top denied" destination breakdown when events are present. When `policy.yaml` could not be applied (the supervisor's `failed_policy` terminal) the same line includes the adapter's error so an operator can debug without opening JSONL by hand.
4. Artifacts: absolute paths to `run dir`, `run.json`, `lifecycle.jsonl`, `network-events.jsonl`, `final-summary.md`, and `git-diff.patch`.

`report` is a one-shot read (no tail), reads `run.json` via atomic snapshot so a live supervisor never produces a torn record, and exits 0 with a friendly "no runs recorded" message for an env that has never been run. Malformed lines in `network-events.jsonl` produce a stderr warning but do not block the rest of the report.

### `ai-env agents list`

Loads the project's `.ai-env/agents.yaml`, unions its keys with the launchers registered in code, and prints a four-column table: `NAME`, `BINARY`, `VERSION`, `STATUS`. Every probe runs with a short host-side timeout (10 seconds) so a wedged agent CLI cannot stall the table. Status values are descriptive strings (`ok`, `binary not found`, `version unsupported (<constraint>)`, `probe failed`, `no launcher registered`, `no contract in agents.yaml`, `unknown agent`) rather than booleans, so the operator can spot the precise mismatch at a glance. `list` never trial-runs autonomous flags; it only invokes the version subcommand.

### `ai-env agents doctor`

Runs the four-check health report for every registered agent: binary on `PATH`, parsed version satisfies the contract's `version_constraint`, the requested autonomous flag candidate appears in `--help`, and a credential mode is plausibly available. Each check renders as a `PASS  <check>: <reason>` or `FAIL  <check>: <reason>` line so the output is grep-friendly. `doctor` exits non-zero when any check fails, so it is safe to wire into CI. The credential check is host-side and best-effort: `backend_managed` is reported as "verified at run time" (it requires an active backend), `provider_proxy` is reported as available when the host has plausibly configured the proxy (the full host-side credential plumbing lands with the secret store in a later plan), and `raw_env_explicit` reports whether the conventional raw-token env var (`ANTHROPIC_API_KEY` for Claude, `OPENAI_API_KEY` for Codex) is present. The supervisor enforces the real fail-closed check at run time.

### `ai-env agents probe <agent>`

Runs the full `Probe` pipeline for a single agent and prints a detailed report: contract command, version constraint, resolved binary path, detected version (with a supported-yes/no flag), the autonomous-flag candidates from the contract plus the one that was selected, the credential mode preference order, and the first 20 lines of the captured `--help` text. `probe` never trial-runs the agent's autonomous flags against the workspace; it only invokes the version subcommand and `--help`. Exits non-zero when the probe produced an error.

## Run lifecycle

When the supervisor (`internal/run`) drives a run, it materializes everything under `.ai-env/runs/<run-id>/`. Run IDs follow the format `YYYYMMDD-HHMMSS-<6-hex>`. The six-hex suffix guarantees same-second uniqueness on a single host (~16M distinct suffixes per second).

### Run directory layout

```
.ai-env/runs/<run-id>/
  task.md              # verbatim --task content (set by WriteTask)
  run.json             # atomic-replace snapshot of the run record
  lifecycle.jsonl      # append-only state-change log (one JSON object per line)
  stdout.log           # disk-streamed agent stdout (not memory-buffered)
  stderr.log           # disk-streamed agent stderr (not memory-buffered)
  agent-command.txt    # placeholder for the launched agent command
  transcript.md        # placeholder for the rendered transcript
  shell-commands.jsonl # populated by the optional shell shim when `--shell-shim` is wired (plan 08)
  filesystem-events.jsonl
  network-events.jsonl # one JSON object per network decision (plan 05)
  policy-decisions.jsonl # one JSON object per export-gate verdict and broker stage (plan 07)
  git-diff.patch       # partial diff collected on stop
  secret-scan.json     # built-in + gitleaks scan output (plan 06)
  dependency-report.json # discovered vulnerability scanners + their results (plan 06)
  security-report.md
  final-summary.md     # written on terminal by the supervisor (plan 05)
  scan-results/        # scanner output subdirectory
```

All files are created up front as empty placeholders so later append-writers do not have to do their own first-write-creates dance. `run.json` is the canonical record schema; it is written via temp-file + `rename` + parent-dir `fsync`, so a crashed write never surfaces partial JSON.

### State machine

The run.State enum mirrors the plan's state diagram exactly:

```
created -> preparing_workspace -> starting_backend -> applying_policy ->
starting_agent -> running -> stopping -> scanning -> reporting -> completed

failure / terminal states:
  failed_backend, failed_agent, failed_policy, failed_scan,
  timed_out, killed_by_user, killed_oom, killed_idle, quarantined
```

Terminal states have no outgoing transitions. `Machine` (in `internal/run/state.go`) is safe for concurrent use; `Transition` returns `*InvalidTransitionError` on a forbidden move so a stale signal arriving after the run already terminated fails loudly rather than silently rewinding state.

### Supervisor terminal states

`Supervisor.Run` enforces two host-side budgets and three signals, each producing a specific terminal:

- `MaxRuntime` exceeded: the run lands in `timed_out` with `stop_reason: timeout`. Default in `ai-env.yaml`: `supervision.max_runtime_minutes: 120`.
- `IdleTimeout` exceeded while in `running`: the run lands in `killed_idle` with `stop_reason: idle_timeout`. Default: `supervision.idle_timeout_minutes: 20`.
- `SIGINT` or `SIGTERM`: forwarded to the agent, then after `shutdown_grace_seconds` escalated to `SIGKILL`; the run lands in `killed_by_user` with `stop_reason: signal`.
- `SIGHUP`: marked interrupted, treated as a stop request for non-interactive runs (same terminal as SIGINT/SIGTERM in v0.1).
- Agent exit (zero or non-zero): lands in `completed` with `stop_reason: agent_exit` and the recorded exit code.

stdout and stderr are streamed to disk by `StreamCapture` (not buffered in memory); a small bounded tail buffer is kept for terminal display and idle detection.

### Stop sequence and partial diff

On every terminal the supervisor's finalizer runs an orderly shutdown:

1. Drains and closes the stdout/stderr capture so `stdout.log` and `stderr.log` are flushed.
2. Invokes the configured `DiffCollector` with a bounded timeout and writes the bytes into `git-diff.patch`. The collector is advisory: an error is logged but does not change the terminal state. With no collector wired, the empty placeholder is left in place.
3. Writes the closing `run.json` snapshot (atomic replace).
4. When the terminal is one of `killed_by_user`, `timed_out`, or `killed_idle`, prints the `--continue` suggestion to `UserOutput` and records it on `SupervisorResult.ContinueSuggestion`. Other terminals (`completed`, `failed_*`, `killed_oom`, `quarantined`) get their own remediation path and do not surface the suggestion.

### `--continue` semantics

`PrepareContinuation` (in `internal/run/continue.go`) is the helper invoked when a fresh run is started with `--continue`. It:

1. Locates the env's latest run and reads its `run.json`.
2. Refuses if there is no previous run, the previous run is still in flight, the previous terminal is not continuation-eligible, or the previous `run.json` is missing/malformed. Each refusal returns a typed `*ContinueError` so the CLI can map it to a precise message.
3. Generates a fresh run ID and materializes a new run directory next to the previous one under the same `.ai-env/runs/` parent.
4. Populates `task.md`: the new `--task` flag wins when non-empty (`TaskSourceFresh`); otherwise the previous run's task body is copied verbatim (`TaskSourceInherited`).
5. Records the previous run's ID in the new run's `run.json` as `linked_previous_run`.

The previous run's workspace is left exactly as the agent left it: no checkout, no reset, no clean. The supervisor's main loop opens the workspace via `workspace.ReadMetadata` at wire time, and that metadata was written once by `ai-env new`, so the agent on the new run sees the workspace in the same state as the previous run left it. The continuation relationship lives only in `run.json`'s `linked_previous_run` field; no special lifecycle event is emitted.

Note: the supervisor primitives, status, logs, list-with-run-state, and `--continue` plumbing all landed in plan 03. The Backend interface, agent launchers, and `ai-env agents` subcommands documented below landed in plan 04 alongside the supervisor's optional `BackendAdapter` seam. Plan 05 added the canonical `NetworkPolicy`, the `NetworkPolicyAdapter` interface, the docker_sbx network adapter, the rootless docker / podman fallback backends, the host-side provider proxy, the `network-events.jsonl` writer, the `ai-env report` subcommand, and the `final-summary.md` writer (with the network section). Plan 06 added the built-in pattern-only secret scanner, the warn-only entropy analyzer, the gitleaks adapter, optional external scanner discovery, the `ai-env scan` subcommand, the `ExportGate` (wired into `ai-env patch` and `ai-env pr`), and the `ScanHook` seam the supervisor invokes during `StateScanning`. Plan 07 added the GitHub broker (`internal/githubbroker/`): the `GitHubBroker` interface, the GitHub App installation token and PAT-fallback `TokenSource` implementations, the in-memory `TokenHolder` with TTL clamping and revocation, branch-prefix / protected-branch / path-gate validation, PR-metadata secret scanning, broker-generated PR body, log redaction (`RedactTokens`, `NewRedactingLogger`, `NewRedactingWriter`), the `ai-env pr` broker wiring with the `ExportGate` running first, and the `PolicyDecisionsWriter` that persists gate verdicts and broker lifecycle outcomes into `policy-decisions.jsonl`. The user-facing `ai-env run` subcommand that wires the supervisor, the backend, the network adapter, the provider proxy, and the scan hook together end-to-end is tracked in a later plan.

## Backend abstraction

The `Backend` interface in `internal/backend/backend.go` is the contract every sandbox implementation satisfies. It exposes nine methods (`Detect`, `Create`, `Start`, `Exec`, `Stop`, `CopyIn`, `CopyOut`, `ApplyNetworkPolicy`, `Stats`, `Destroy`) the supervisor drives through a run's lifecycle. Backends are addressed by an opaque `envID` returned from `Create`; `Detect` reports `BackendStatus` (name, availability, version, whether the version is in the tested range, and a short diagnostic message) without ever returning an error.

Four implementations ship today:

- `internal/backend/mock` is an in-memory no-op backend used by unit tests. It records every method call against an internal log so tests can assert that the supervisor invoked the backend in the expected order without spawning processes.
- `internal/backend/docker_sbx` wraps the Docker Sandboxes `sbx` CLI. `Detect` shells out to `sbx version`, parses a semver-ish token, and compares it against the inclusive range in `internal/backend/docker_sbx/compat.go` (`MinTestedVersion`..`MaxTestedVersion`, currently `0.1.0 - 0.9.99`). Versions outside that range surface as `VersionSupported=false`, and the operator must opt in with `--allow-untested-backend-version` to proceed. The adapter parses minimally: it relies on exit codes, the version probe, and known workspace paths rather than scraping interactive `sbx` stdout for state transitions, so if upstream output formatting changes but exit codes and paths still work, `ai-env` keeps working. The `docker_sbx` adapter also implements `NetworkPolicyAdapter` by translating the canonical runtime policy into `sbx network apply` flags (`--default-policy deny`, `--allow-domain`, `--block-cidr` per always-blocked range, `--block-host` per always-blocked name); see "Network policy enforcement" below.
- `internal/backend/docker` and `internal/backend/podman` are the reduced-isolation fallback backends. Each shells out to the respective host CLI (rootless or rooted: the adapters do not distinguish, but the master plan recommends rootless), brings up a container per env with `--network none` by default, and refuses to mark itself `Available` in autonomous mode unless the operator passes `--accept-reduced-isolation`. Both fallbacks print the verbatim reduced-isolation warning text from the plan the first time `Detect` observes acceptance. Their `ApplyNetworkPolicy` implementation is a structural validator only: `network none` honors every policy trivially (the container has no outbound network), and `--unsafe-host-network` (which requires both `--accept-reduced-isolation` and an explicit `--unsafe-host-network` toggle) accepts only policies with `default: allow` or with no allow-domain list, because the rootless fallback has no per-destination firewall. See "Reduced-isolation fallback backends" below.

The supervisor in `internal/run/supervisor.go` exposes an optional `BackendAdapter` field on its options. When non-nil, the supervisor routes the child process through `Backend.Exec` against the supplied `BackendEnvID` instead of spawning host-side via `exec.Command`. The fallback path (no `BackendAdapter`) keeps the legacy host-exec wiring so the pre-plan-04 lifecycle, signal, and timeout tests continue to drive real subprocesses without constructing a backend. Production code paths (the forthcoming `ai-env run` CLI) always supply a backend. The supervisor also exposes an optional `NetworkPolicyAdapter` plus a `NetworkPolicy` value: when both are set the supervisor calls `Adapter.Apply` during `StateApplyingPolicy` and aborts the run with `StateFailedPolicy` / `stop_reason: policy_failure` on any error, satisfying the master plan's fail-closed contract.

## Optional shell shim (`--shell-shim`)

Plan 08 step 8 introduced an experimental shell-shim prototype in `internal/policy/shim.go`: when an operator passes `--shell-shim` to the future `ai-env run` subcommand the supervisor will wrap the agent's `bash` / `sh` invocations through a thin wrapper binary that logs each command attempt, denies obvious high-risk patterns (curl-pipe-shell, access to SSH paths, cloud metadata IP), and forwards the rest to the real binary.

Plan 08 step 9 wires the supervisor side of that flag. Two new fields on `run.SupervisorOptions` opt the supervisor into the prototype:

- `ShellShim bool`: enables shim wiring. When true the supervisor opens `shell-commands.jsonl` in the run directory and prepends `ShellShimDir` to the child's PATH so the wrapper resolves before the real system binary. Requires `PolicyEngine` or `PolicyEnginePath`; without an engine the supervisor fails fast at construction rather than silently degrading into "log every command, deny none."
- `ShellShimDir string`: absolute path of the directory holding the wrapper binary. The supervisor does not invent the directory: the caller (the future CLI or a test fixture) materializes the wrapper there before the run starts.

`run.InjectShimPath(env, shimDir)` is the exported helper the supervisor (and the future CLI) use to mutate the PATH entry: it prepends `shimDir` to an existing `PATH=` entry or appends a fresh `PATH=<shimDir>` when the env did not carry one.

The shim is an experimental, cooperative interception point, not the primary boundary. The same four limitations the master plan documents apply:

1. **Agents may invoke absolute paths.** An agent that calls `/usr/bin/curl` directly bypasses the wrapper; the shim only catches commands that resolve through PATH.
2. **Static binaries bypass shell wrappers.** The shim intercepts shells (`bash`, `sh`), not arbitrary executables.
3. **Interpreters can execute code internally.** A `python -c "..."` call is one command to the shim; the shim cannot see the inner statements.
4. **Kernel-level and network-level controls remain the real boundary.** Filesystem isolation (the backend), the network policy adapter, and the credential broker are the surfaces that actually enforce policy; the shim is defense-in-depth, not the primary enforcement point.

The user-facing CLI flag itself (`ai-env run --shell-shim`) lands in a later plan that introduces the `ai-env run` subcommand; the `SupervisorOptions.ShellShim` field and the shell-shim wiring are the underlying primitives that flag will toggle.

## Agent launchers

Agent launchers live under `internal/agents/`. The shared `Launcher` interface (`internal/agents/agents.go`) has two methods, `Probe` and `Plan`:

- `Probe` resolves the binary on `PATH`, runs the contract's version subcommand, validates the parsed version against the contract's `version_constraint`, captures `<binary> --help`, and picks the first autonomous flag candidate every flag of which appears literally in the help text. The result is a `ProbeResult` carrying `BinaryPath`, `Version`, `VersionSupported`, `SelectedFlags`, and `HelpOutput` (plus an `Error` when any step failed).
- `Plan` turns a high-level `Request` (mode, task body, workspace dir, credential preferences, extra env, extra args) plus a successful `ProbeResult` into a `backend.Command` the supervisor hands to `Backend.Exec`. The task body is piped on the agent's stdin via `LaunchPlan.StdinBody` so the supervisor never has to drop a prompt file into the workspace.

Two launchers ship today, both following the same five-step structure (resolve binary, probe version, select autonomous flags, detect credential mode, build launch command):

- `internal/agents/claude` wraps the `claude` binary. Autonomous mode passes `--dangerously-skip-permissions` (verified against `claude --help`). Provider proxy and raw-env injection use `ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY` respectively.
- `internal/agents/codex` wraps the `codex` binary. Autonomous mode passes `--dangerously-bypass-approvals-and-sandbox`. Provider proxy and raw-env injection use `OPENAI_BASE_URL` and `OPENAI_API_KEY`.

Launchers are stateless: every method takes the inputs it needs explicitly, and a `ProbeDeps` struct lets tests inject fakes for `exec.LookPath` and the runner that backs the version and `--help` probes. The flag-selection check is a substring test against the captured help, not a full help parser; per the plan's "parse minimally" rule, that trade-off is acceptable because we only ever check candidates that the contract author put in `agents.yaml`.

## Credential modes

The three canonical model-credential modes are defined as constants on `internal/agents/agents.go` and matched verbatim against the strings in `agents.yaml` and `run.json`:

- `backend_managed` is the safe default: the backend injects the provider credential per call, the raw token never enters the agent process environment. Selected when the supervisor's `EnvironmentProbe.BackendManaged` is true.
- `provider_proxy` points the agent at a host-side provider-compatible proxy. The raw token stays on the host; the sandbox only sees the proxy URL. Selected when the agent supports a custom base URL (Claude and Codex both do) and a proxy URL is configured. Plan 05 shipped the proxy implementation itself in `internal/secrets/proxy.go` and the launcher wire-up in `internal/agents/proxy.go`; the supervisor wires the running proxy into the `EnvironmentProbe` via `WireProviderProxy` before calling `Plan`. See "Provider proxy" below.
- `raw_env_explicit` injects the raw provider token into the agent's process environment. Selection requires the operator to pass `--allow-raw-model-token-in-sandbox` at run time and to have populated `EnvironmentProbe.RawTokenEnv`. The supervisor records the mode in `run.json` and prints a `reduced safety: yes` warning banner; `ai-env status` surfaces the same line for past runs.

`ResolveCredentialMode` and the lower-level `ResolveCredentialModeDetailed` walk the contract's `Default + FallbackOrder` list in order and return the first mode the host can satisfy. Resolution is fail-closed: when no mode is available, the returned `*CredentialResolutionError` wraps `ErrCredentialModeUnavailable` and carries a per-mode trace explaining why each candidate was rejected (so `ai-env agents doctor` and the supervisor's diagnostics can print every mechanism that was tried). An unknown mode name in `agents.yaml` returns `ErrUnknownCredentialMode` rather than silently skipping the check.

## Network policy enforcement

The canonical runtime view of the outbound network policy lives in `internal/network/`. `NetworkPolicy` is built from the YAML-shaped `config.NetworkPolicy` via `NewNetworkPolicy`, which forces the always-blocked defaults on regardless of what `policy.yaml` says: RFC1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), the cloud metadata IP (`169.254.169.254/32`), localhost (`127.0.0.0/8` and the hostname `localhost`), and `host.docker.internal`. The operator may widen the allow-domain list in `policy.yaml`; they may not turn off the metadata-IP, private-range, localhost, or `host.docker.internal` block in autonomous mode.

`NetworkPolicy.Validate` enforces the master plan's "fail closed" rule: `default` must be `deny` (autonomous mode rejects `allow`), and all four always-block flags must be true. The supervisor only calls `Adapter.Apply` after `Validate` succeeds; any error from `Apply` lands the run in `StateFailedPolicy` with `stop_reason: policy_failure` so a backend that cannot honor the requested policy never silently degrades into a permissive configuration.

The `NetworkPolicyAdapter` interface lives next to the policy struct so adapters in `internal/backend/*` implement a single small contract (`Name()` plus `Apply(envID, policy)`). Adapters that ship today:

| Adapter | Behavior |
| ------- | -------- |
| `docker_sbx.NetworkPolicyAdapter` | Translates the policy into `sbx network apply` flags. Default `deny`, allow domains pinned per entry, always-blocked CIDRs and hosts emitted as explicit block rules. |
| `docker.NetworkPolicyAdapter` / `podman.NetworkPolicyAdapter` | Structural validator only. `network none` honors every policy trivially; `--unsafe-host-network` rejects deny + allowlist policies because the fallback cannot enforce them. |
| `mock` backend | Records the `Apply` call so unit tests can assert on supervisor interaction without spawning processes. |

Per-run network events (one JSON object per line: timestamp, destination, decision, source, optional reason and rule) are written into `.ai-env/runs/<run-id>/network-events.jsonl`. `internal/run/network_events.go` is the writer; `internal/run/network_summary.go` aggregates the file into a `NetworkSummary` (totals, allowed / denied counts, top-N destination breakdown) that `ai-env report` and the supervisor's `final-summary.md` writer both consume so the two views agree.

## Provider proxy

The host-side provider proxy in `internal/secrets/proxy.go` keeps raw Anthropic / OpenAI tokens out of the sandbox while still letting the agent reach the real provider. It is NOT a TLS MITM: it speaks plain HTTP on `127.0.0.1` (port picked by the OS unless the caller pins one), the agent inside the sandbox is pointed at it via `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` (selected by `internal/agents/proxy.go` based on which provider the proxy fronts), and the proxy itself opens the HTTPS connection upstream so the token only ever travels host -> provider.

Each `ProviderProxy` fronts exactly one provider (one host:scheme tuple, pinned from a short allowlist). A request whose Host header or URL targets a different upstream is rejected with HTTP 502, so an agent cannot pivot through the proxy to an unintended destination. Authentication is host-side: for Anthropic the proxy sets `x-api-key` (and `Authorization: Bearer <token>` for forward compatibility); for OpenAI it sets `Authorization: Bearer <token>`. Every log line the proxy emits passes through a redactor that replaces token-like values with `REDACTED` before the line is written.

Lifecycle is per-run: the supervisor starts the proxy before the agent launches and stops it after the run ends (the default shutdown timeout is two seconds, matching the supervisor's signal grace vocabulary). When the proxy is active, `internal/agents/proxy.go` exposes `WireProviderProxy` which folds the proxy URL plus the provider identifier into the `EnvironmentProbe` the launcher consumes, so the resolver picks `provider_proxy` and the launcher emits exactly one base-URL env var (Anthropic when the proxy fronts Anthropic, OpenAI when it fronts OpenAI).

## Reduced-isolation fallback backends

The `internal/backend/docker` and `internal/backend/podman` adapters are the reduced-isolation fallbacks the master plan calls out when the primary `docker_sbx` adapter is unavailable. Both follow the same posture:

- `Detect` reports `Available=true` only when the binary is on `PATH`, the version probe (`docker version --format ...` or `podman version --format ...`) succeeds, and (for autonomous mode) the operator has passed `--accept-reduced-isolation`. Without acceptance, autonomous mode produces a clear "fallback backend requires --accept-reduced-isolation" message and the verbatim reduced-isolation warning text fixed in the plan.
- `Start` runs the container with `--network none` by default. `--unsafe-host-network` switches the network mode to `host`, but only when `--accept-reduced-isolation` is also true; without both flags the container is locked to `none` regardless of what `policy.yaml` requests.
- `ApplyNetworkPolicy` is a structural validator. With `network none` every policy is honored trivially. With `network host` the adapter accepts `default: allow` policies, accepts `default: deny` policies with an empty `allow_domains` list, and rejects `default: deny` + non-empty `allow_domains` (the fallback has no per-destination firewall, so the supervisor fails closed via `failed_policy` rather than silently widening the network).
- The reduced-isolation warning text (literally `"WARNING: This backend provides reduced isolation. ..."` from plan 05) is printed to the configured warning writer (defaults to stderr) the first time `Detect` observes a state that triggers it. Subsequent `Detect` calls in the same process are no-ops so `ai-env doctor` does not repeat the warning.

The fallbacks are suitable for development and testing on a host without the Docker Sandboxes runtime; they are explicitly NOT recommended for high-risk autonomous execution with untrusted dependencies or secrets.

## Scanning

The scanning stack lives in `internal/scanners/` and is exposed end-to-end through `ai-env scan`. It is designed to be useful on a host with no external tools installed: the built-in scanner runs in-process, and missing optional scanners warn rather than crash.

### Built-in pattern scanner

The built-in scanner walks the changed files in the workspace diff (not the full workspace; legacy data committed before the env was created stays out of the v0.1 output) and emits a `Finding` for each line that matches one of:

- Provider API keys: OpenAI (`sk-...`), Anthropic (`sk-ant-...`), GitHub (`ghp_...`, `github_pat_...`), npm, PyPI, AWS (`AKIA...`), Google Cloud, Azure, Slack, Stripe.
- PEM-style private key headers: `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, `-----BEGIN OPENSSH PRIVATE KEY-----`, and the generic `-----BEGIN PRIVATE KEY-----` header.
- `.env`-style assignments whose key name strongly implies a secret (`*_SECRET=`, `*_TOKEN=`, `*_KEY=`, `PASSWORD=`) with a non-empty value.
- User-configured custom regex patterns from `policy.yaml`'s `scanners.custom_patterns` list (additive: the built-in classes always remain in effect).

Every built-in finding is stamped `confidence: high` and `blocks_export: true`. There are no medium- or low-confidence findings in v0.1: a built-in match is, by construction, a hard block. Two allowlist channels suppress a finding before it is emitted:

- An inline `# ai-env-scan-ignore` comment on the same line (the marker is matched as a substring so `// ai-env-scan-ignore` or `<!-- ai-env-scan-ignore -->` work too).
- A regex in `policy.yaml`'s `scanners.allowlist` list.

The scanner reads at most a fixed cap of bytes per file so a hostile agent cannot wedge a scan by dropping a huge binary into the diff; files larger than the cap are flagged as `entropy_only=false` informational entries rather than scanned in full.

### Entropy analyzer (warn-only)

A separate entropy pass runs alongside the pattern scanner and flags string literals whose Shannon entropy exceeds a built-in threshold. Hits land in the `entropy_warnings` array of `secret-scan.json`; they are surfaced by `ai-env scan` and the export gate's render but never block export by default. This is the plan's "warn vs. block" split: entropy alone is too noisy to gate on (UUIDs, hashes, base64 fixtures, generated IDs) so the analyzer is informational in v0.1.

### External scanner discovery

`internal/scanners/external.go` keeps a registry of optional tools and probes each with `exec.LookPath` at discovery time (no `tool --version` call: discovery must stay cheap and a wedged binary on PATH must not stall `ai-env scan`). The current registry covers:

| Tool          | Kind             | Status in v0.1                          |
| ------------- | ---------------- | --------------------------------------- |
| `gitleaks`    | secrets          | wired (`gitleaks detect` JSON adapter)  |
| `osv-scanner` | vulnerabilities  | discovered only, driver lands in plan 07 |
| `trivy`       | vulnerabilities  | discovered only, driver lands in plan 07 |
| `semgrep`     | SAST             | discovered only, driver lands in plan 07 |
| `npm-audit`   | vulnerabilities  | discovered only, driver lands in plan 07 |
| `pip-audit`   | vulnerabilities  | discovered only, driver lands in plan 07 |
| `cargo-audit` | vulnerabilities  | discovered only, driver lands in plan 07 |
| `govulncheck` | vulnerabilities  | discovered only, driver lands in plan 07 |

Each entry reports `available: true|false` plus a human-readable message. The CLI summary lists available scanners with findings counts and prints a single stderr warning block listing the unavailable ones; a missing tool is never an error. Gitleaks findings are normalized into the same `Finding` shape the built-in scanner uses (one `finding_NNN` ID per hit, `confidence: high`, `blocks_export: true`), so the export gate treats them as a hard secret block regardless of source.

The default external-scanner timeout is ten minutes per tool; the supervisor's own scan-hook deadline (five minutes default for the whole hook) bounds the worst case more aggressively when scans run inline from the run lifecycle.

## Export gate

The export gate in `internal/export/` is the single decision point sitting between a finished run and the user-visible export surfaces. `ai-env patch` calls it under `ModePatch`; `ai-env pr` calls it under `ModePR`. The gate is a pure function: the caller assembles an `export.Input` from disk (workspace diff, scan artifacts, policy, run record) and the gate returns a `GateResult` carrying a `Decision` (`allow` or `block`) and an ordered slice of `Reason` entries.

### Hard blockers (cannot be overridden by default)

| ReasonCode                  | Trigger                                                                 |
| --------------------------- | ----------------------------------------------------------------------- |
| `secret_finding`            | Any built-in scanner finding with `blocks_export: true`.                |
| `external_secret_finding`   | Any gitleaks finding with `blocks_export: true`.                        |
| `ai_env_change`             | Diff touches any path under `.ai-env/`.                                 |
| `policy_change`             | Diff touches `.ai-env/policy.yaml` specifically (also fires `ai_env_change`, surfaced separately so the CLI can render a more specific message). |
| `workflow_change`           | Diff touches `.github/workflows/**`. Block under `ModePR`, warn under `ModePatch` so a local patch can still be inspected. |
| `quarantine`                | The run record's state is `quarantined`.                                |

### Configurable blockers (toggled from `policy.yaml`)

These rules always fire as a `Reason`; what changes is whether the severity is `block` or `warn`. The current v0.1 wiring ties them to `policy.review.require_diff_review` (a single switch flips all four to `block`); `policy.review.fail_on_high_vulnerability` governs the vulnerability rule independently and defaults to `true`.

| ReasonCode                    | Default severity | Configured via                          |
| ----------------------------- | ---------------- | --------------------------------------- |
| `high_severity_vulnerability` | block            | `policy.review.fail_on_high_vulnerability` |
| `protected_path`              | warn             | `policy.review.require_diff_review`     |
| `large_diff`                  | warn (>1000 lines threshold) | `policy.review.require_diff_review` |
| `lockfile_change`             | warn             | `policy.review.require_diff_review`     |
| `new_executable_file`         | warn             | `policy.review.require_diff_review`     |

A `Reason` carries `Hard: true` for hard blockers and `Hard: false` for configurable blockers so the CLI can render the "this is a default-on rule" vs. "your policy says to block on this" distinction. `GateResult.Blocked()`, `GateResult.BlockingReasons()`, and `GateResult.Warnings()` are the helpers the CLI uses to render the verdict in the same shape both `ai-env patch` and `ai-env pr` print.

### Scan hook in the run lifecycle

`internal/run/scan_hook.go` exposes a `ScanHook func(ctx, runDir) error` seam on `SupervisorOptions`. When non-nil the supervisor invokes the hook exactly once during `StateScanning`, after the agent stopped and before `StateReporting`. The hook is responsible for materializing `secret-scan.json` and `dependency-report.json` inside the run directory; the export gate reads them afterwards via `run.SecretScanPath` so the on-disk shape stays the single source of truth.

The contract is deliberate:

- Findings are not failures. A scanner that wrote `secret-scan.json` with blocking findings returns `nil`; the run still ends in `StateCompleted` and remains inspectable. The gate (consulted later by `ai-env patch` / `ai-env pr`) is the surface that refuses the diff.
- Infrastructure failures are. A non-nil hook error diverts the run to `StateFailedScan` with `stop_reason: scan_failure`.
- The hook only runs on the happy path. Timeouts, idle kills, SIGINT, `failed_agent`, `failed_backend`, and `failed_policy` transitions never reach `StateScanning`, by design: the agent never produced a completion edge there is nothing to scan.
- The hook is bounded by `SupervisorOptions.ScanTimeout` (default five minutes). A wedged external scanner cannot block the supervisor's terminal walk indefinitely.

## GitHub broker

The GitHub broker in `internal/githubbroker/` is the host-side component `ai-env pr` uses to open a draft pull request without ever putting a raw GitHub token inside the sandbox. The package defines a single `GitHubBroker` interface plus the supporting validation, scanning, body-generation, auth, token-lifecycle, and redaction helpers; the CLI invokes the lifecycle in the exact order the master plan's "Token lifecycle" diagram pins.

### Interface and lifecycle

`GitHubBroker` has six methods, one per lifecycle stage:

1. `Prepare(envName, branchName, repo)` validates the static rules that do not need a token or a network round-trip: branch prefix (`ai-env/`), protected branch (`main`, `master`, `Repo.DefaultBranch`, plus any policy extras), and the path-gate check (workspace diff touching `.github/workflows/**`, `.ai-env/**`, `infra/**`, `terraform/**`, or any other path the policy's `block_auto_pr_on_paths` list covers). On success it returns an immutable `BrokerContext` snapshot threaded through every later call.
2. `AcquireToken(ctx)` obtains a short-lived credential from the configured `TokenSource` and returns an opaque `BrokerToken` handle (Kind, Handle, IssuedAt, TTL). The raw secret is held in the broker's in-memory `TokenHolder`; callers never see the bytes.
3. `PushBranch(ctx, token)` ships the workspace branch to the remote. The broker materializes the credential into the git transport (HTTPS clone URL or authorization header) and immediately discards its local copy; the credential never enters the agent's process environment, shell history, or any user-visible string.
4. `ScanMetadata(ctx, title, body, commitMessages)` runs the Plan 06 built-in secret scanner over every human-visible PR field (title, body, branch name, each commit message) and returns a `scanners.ScanResult`. The broker does not decide whether findings block submission; the CLI inspects `Finding.BlocksExport` and refuses `CreateDraftPR` when a blocking finding is present.
5. `CreateDraftPR(ctx, token, title, body)` opens the draft PR via the GitHub REST API and returns a `PRResult` (Number, URL, Draft, CreatedAt). The broker requires the title and body to be the sanitized, broker-generated values; it never echoes the raw agent transcript.
6. `RevokeToken(token)` returns the credential to its issuer (DELETE on `/installation/token` for a GitHub App token, no-op at the issuer for a PAT) and zeroes the in-memory copy via `TokenHolder.Forget`. Revocation is best-effort: a failed issuer call is logged as a warning, but the local scrub still runs and the credential expires naturally at `IssuedAt + TTL`. `ai-env destroy` re-invokes `RevokeToken` so a credential that survived a crashed `ai-env pr` is still torn down.

`Prepare` returns one of the package's sentinel errors (`ErrInvalidBranchPrefix`, `ErrProtectedBranch`, `ErrProtectedPath`, `ErrRepoUnconfigured`) on a policy refusal; `Materialize` / `PushBranch` / `CreateDraftPR` return `ErrTokenExpired` or `ErrTokenRevoked` when the supplied handle is no longer valid. The CLI matches against these with `errors.Is` so the operator-visible message is precise.

### Authentication

`auth.go` defines a narrow `TokenSource` interface (`Kind`, `Acquire`) with two implementations:

- `GitHubAppSource` is the primary credential path. `NewGitHubAppSource` parses the App's PEM-encoded RSA private key (PKCS#1 or PKCS#8) once, and every `Acquire` call signs a fresh App JWT (`alg: RS256`, `iat: now-60s`, `exp: now+9min`, `iss: AppID`) using only `crypto/rsa` and `encoding/base64` (no third-party JWT or GitHub SDK dependency). The JWT is exchanged at `POST /app/installations/<id>/access_tokens` for an installation token; the response's `expires_at` becomes the holder's TTL (clamped by `ClampTTL`). Revocation is `DELETE /installation/token` authenticated with the installation token itself; a 401 response is treated as a no-op so the idempotent revoke path stays clean.
- `PATSource` is the development fallback. Construction requires `PATConfig.Enabled=true` and a non-empty `Token`; the source copies the token into a `[]byte` so `Forget` can zero it in place. Revocation is a no-op at the issuer (the legacy authorizations endpoint is gone and fine-grained PATs are not deletable by an API token), but `TokenHolder.Revoke` still scrubs the local copy.

`SelectTokenSource(SelectorConfig)` picks the path: if `App` is non-nil, `NewGitHubAppSource` runs and any error bubbles up so a misconfigured App never silently degrades to PAT; otherwise the PAT fallback is consulted; otherwise `ErrNoTokenSource` is returned and the CLI tells the operator to configure one path or the other.

### Token lifecycle

`token.go` owns the in-memory store. `TokenHolder` maps a `BrokerToken.Handle` (a 16-byte hex string from `crypto/rand`) to a `tokenSlot` carrying the raw secret as a `[]byte` so `Revoke` and `Forget` can overwrite it in place; `string` would leave the backing bytes around for an indeterminate time. The lifecycle constants are policy-fixed:

- `DefaultTokenTTL = 300s` (the broker's default request to an issuer).
- `MaxTokenTTL = 1800s` (the ceiling; `ClampTTL` caps any longer request).
- `MinTokenTTL = 60s` (the floor; requests below it are rounded up so the holder never returns an already-expired handle).

`Issue` records the credential and returns a `BrokerToken` carrying only Kind / Handle / IssuedAt / TTL (the raw secret is not on the value). `Materialize` returns a fresh copy of the bytes for a single HTTP / git request and returns `ErrTokenExpired` or `ErrTokenRevoked` for a stale handle. `Revoke` invokes the issuer-side callback (if any), zeroes the slot, and marks it revoked; the mutex is dropped across the network round trip so a slow issuer does not block other callers. `Forget` drops the slot entirely; `ForgetAll` is the deferred cleanup the broker runs so a panic between `AcquireToken` and the run finalizer still scrubs the credential. `Inspect` returns a `TokenStatus` snapshot (Kind, IssuedAt, TTL, ExpiresAt, Revoked, Expired) the run lifecycle marshals into `run.json`'s `broker.token` block; the raw secret is never returned.

### PR body generation

`body.go`'s `BuildPRBody(BodyInput)` is the canonical PR body builder. The body is rendered from the sanitized `run.Record` (run ID, agent, task summary), the scan results (count and highest severity), the `export.GateResult` (protected-path warnings), and the workspace diff (top-N changed-file list), plus an explicit "this PR was created by an automated agent" notice. The builder never copies the raw agent transcript into the body and never includes a value that matches a secret pattern; the CLI hands the resulting body to `ScanMetadata` as a defence-in-depth check before `CreateDraftPR` is allowed to run.

### Log redaction

`redact.go` implements the "raw token never appears in a log line" guarantee. `RedactTokens(s)` rewrites recognizable GitHub token shapes (`ghp_*`, `gho_*`, `ghu_*`, `ghs_*`, `ghr_*`, `github_pat_*`, App JWT-shaped triples, the `x-access-token:<secret>` URL form, and `Authorization: token <secret>` headers) to `[REDACTED]` and is the pure-function backstop callers use before constructing any log line, error message, or `PolicyDecisionEvent.Error` string. `NewRedactingLogger(inner Logger)` wraps a `Logger` interface so every line the broker emits passes through the redactor; `NewRedactingWriter(io.Writer)` adapts the same primitive to an `io.Writer` (line-buffered, flushed on `\n`) for stderr / stdout sinks where a logger interface would be overkill. The redactor is the second line of defence behind the "no raw bytes on `BrokerToken`" rule: even if a future code path accidentally formats a raw token into a string, the redactor scrubs it before the bytes leave the process.

## Policy decisions

`policy-decisions.jsonl` is the per-run append-only audit log every export-gate verdict and broker lifecycle stage lands in. The writer in `internal/run/policy_decisions.go` (`PolicyDecisionsWriter`) mirrors the lifecycle and network event writers: one JSON object per line, fsync after every write, mutex-serialized so concurrent emitters cannot interleave bytes. Each event carries the run ID, an RFC3339 timestamp, an `event` verb (`export_gate` or `broker_action`), a `decision` (`allow`, `block`, or `fail`), the env name, and the per-event payload fields (gate reasons, broker action name, branch, repo, token kind, PR number, PR URL, error string).

The CLI emits events at six points during `ai-env pr` and one point during `ai-env patch`:

- `export_gate` (verb): `ai-env patch` and `ai-env pr` both record their gate verdict here. Surface is `patch` or `pr`. `BlockingReasons` are folded into the `reasons` field; warnings are surfaced to the operator via the CLI but are not persisted (the file stays focused on decisions).
- `broker_action` (verb), one per lifecycle stage. Action names mirror the lifecycle: `broker_prepare`, `broker_acquire_token`, `broker_push_branch`, `broker_scan_metadata`, `broker_create_pr`, `broker_revoke_token`. `decision` is `allow` when the stage proceeded, `block` when a sentinel error refused it on policy grounds (branch prefix, protected branch, protected path, token expired, token revoked, blocking metadata finding), or `fail` when the stage errored at the infrastructure level (network failure, missing credential, API 5xx). The `block` vs. `fail` split is the load-bearing distinction for an operator: `block` means "fix your inputs", `fail` means "retry or check connectivity".

Token-bearing fields (today only the `error` string can echo a header) pass through `githubbroker.RedactTokens` at the emission site before the event is constructed; the writer does not re-redact. `ReadPolicyDecisions(runDir)` is the helper that loads the whole file in order; the file is small in practice (one gate decision plus a handful of broker outcomes per run), so the whole-file read is preferable to a streaming parser. The file is created up front as an empty placeholder by `CreateRunDirectory`, so a run that never reached the broker (a `ai-env patch` invocation or an `ai-env pr` that the gate blocked) still produces a well-formed JSONL file with the gate verdict and nothing else.

## Final summary

The supervisor writes `.ai-env/runs/<run-id>/final-summary.md` from `finalizeTerminal` after the closing `run.json` snapshot and the partial-diff collection. The file is atomic (temp + rename) and idempotent (a re-run of the finalize step overwrites it with the latest snapshot). It contains:

1. A header with env name, run id, terminal state, and started / stopped timestamps.
2. A `## Network` section rendered by `RenderNetworkSummaryMarkdown` from the same `NetworkSummary` `ai-env report` prints: policy status (`applied`, `not attempted`, or `failed` plus the adapter error), default policy, allow domains, blocked CIDRs and hosts, total / allowed / denied event counts, and a top-N destination breakdown.

When the run aborted before the policy stage (the supervisor records `network policy: not attempted`) the section still produces a well-formed block instead of an empty hole. The same renderer feeds the network block of `ai-env report`, so the on-disk markdown and the CLI report cannot drift.

## Generated configuration files

Every successful `ai-env new` writes the following files into `.ai-env/`:

| File                   | Mode  | Purpose                                                              |
| ---------------------- | ----- | -------------------------------------------------------------------- |
| `ai-env.yaml`          | 0644  | Project identity, workspace strategy, sandbox backend, supervision and logging limits. |
| `policy.yaml`          | 0644  | Network, filesystem, command, dependency, secret, scanner, and review policy defaults. Starts conservative. |
| `agents.yaml`          | 0644  | Registry of agent adapters. Defaults to a single `claude` entry with autonomous and interactive modes. |
| `secrets.example.yaml` | 0644  | Documents required secret providers. Never contains real credentials. |
| `secrets.local.yaml`   | 0600  | Gitignored stub for machine-local secret values. Contains only comments. |

A minimal `ai-env.yaml` looks like the sample in `plan.md` ("Config files generated by ai-env new"). All generated files are validated against the loader before being written, so a freshly scaffolded project is guaranteed to round-trip through `LoadAIEnv`, `LoadPolicy`, `LoadAgents`, and `LoadSecretsExample` without error.

In addition to the config files, `ai-env new` creates these workspace artifacts:

| Path                                       | Purpose                                                              |
| ------------------------------------------ | -------------------------------------------------------------------- |
| `.ai-env/workspaces/<env-name>/`           | Materialized workspace (Git worktree or copy of the source).         |
| `.ai-env/workspaces/<env-name>/.env-meta.json` | Per-env metadata: strategy, branch (worktree) or baseline path + copy time (copy), template, source path, created timestamp. |
| `.ai-env/baselines/<env-name>/`            | Read-only baseline snapshot used by `ai-env diff` and `ai-env patch` for copy-strategy envs. Not created for worktree envs (Git history is the baseline). |

## Stack detection

`ai-env new` inspects the source root for the following marker files, in order. The first match wins and is recorded as `sandbox.template` in `ai-env.yaml`.

| Marker             | Template  |
| ------------------ | --------- |
| `go.mod`           | `go`      |
| `Cargo.toml`       | `rust`    |
| `package.json`     | `node`    |
| `pyproject.toml`   | `python`  |
| `requirements.txt` | `python`  |
| (none of the above) | `default` |

## `.gitignore` entries

When `.gitignore` exists at the source root, `ai-env new` appends any of the following entries that are missing:

```gitignore
.ai-env/workspaces/
.ai-env/baselines/
.ai-env/runs/
.ai-env/cache/
.ai-env/tmp/
.ai-env/secrets.local.yaml
.ai-env/*.token
.ai-env/*.pem
```

When `.gitignore` does not exist, the same entries are printed as suggestions so you can decide where the file should live (some monorepos prefer a parent `.gitignore`).

## Protected paths

`ai-env diff` and `ai-env patch` flag changes to files matched by the patterns in `policy.yaml` under `filesystem.protected_paths`. Protected hits are tagged `[protected]` in the per-file summary and emitted as a separate warning block on stderr; they never block the diff or patch from being produced. When `policy.yaml` is missing or its `protected_paths` list is empty (nil), the matcher falls back to a built-in default covering the categories below.

Default patterns (see `internal/workspace/protected.go` for the authoritative list):

```
.github/workflows/**     # CI/CD definitions
.git/**                  # Git internals
.env, .env.*             # Secret-bearing dotenv files
package.json + common lock files (package-lock.json, yarn.lock, pnpm-lock.yaml,
  npm-shrinkwrap.json, Gemfile.lock, Pipfile.lock, poetry.lock, uv.lock,
  go.sum, Cargo.lock, composer.lock)
Dockerfile, docker-compose.yml
terraform/**, infra/**, migrations/**
.ai-env/**               # ai-env's own state
```

Patterns use POSIX-style separators and support `**` as a whole-segment wildcard (matching zero or more path components). Backslashes in user input are converted to forward slashes; leading `./` and `/`, trailing `/`, and `.` components are normalized away. A pattern containing `..` or unterminated character classes is rejected at load time so typos in `policy.yaml` fail loudly rather than silently never matching.

To customize, set `filesystem.protected_paths` in `policy.yaml`. An explicitly empty list (`protected_paths: []`) disables protection; omitting the field falls back to the defaults.

## Project layout

```
ai-env/
  cmd/ai-env/                 # CLI entry point (Cobra wiring)
  internal/cli/               # Command implementations (RunNew, RunList, RunDiff, RunPatch,
                              # RunPR, RunScan, RunStatus, RunLogs, RunReport,
                              # RunAgentsList/Doctor/Probe)
  internal/config/            # Config structs, YAML loader, validators
  internal/workspace/         # Workspace strategies (worktree, copy), diff, patch, protected matcher
  internal/run/               # Run IDs, run directory layout, state machine, lifecycle.jsonl,
                              # run.json, stream capture, supervisor main loop (with optional
                              # BackendAdapter / NetworkPolicyAdapter / ScanHook seams),
                              # signal handling, finalizer, partial-diff collection,
                              # --continue helper, network-events.jsonl writer, network
                              # summary, final-summary.md, scan-hook driver,
                              # policy-decisions.jsonl writer (plan 07)
  internal/network/           # Canonical runtime NetworkPolicy + NetworkPolicyAdapter interface,
                              # always-blocked CIDR / host slices, Validate, ToBackendPolicy
  internal/backend/           # Backend interface and supporting types
  internal/backend/mock/      # In-memory mock backend used by unit tests
  internal/backend/docker_sbx/ # Docker Sandboxes adapter (sbx CLI wrapper, compat.go,
                              # network_adapter.go)
  internal/backend/docker/    # Rootless Docker fallback backend (reduced isolation)
  internal/backend/podman/    # Rootless Podman fallback backend (reduced isolation)
  internal/secrets/           # Provider proxy (loopback HTTP, host-side auth header injection,
                              # log redaction, per-run lifecycle)
  internal/agents/            # Launcher interface, version/help probes, credential resolver,
                              # provider-proxy wire-up (proxy.go)
  internal/agents/claude/     # Claude Code launcher
  internal/agents/codex/      # Codex launcher
  internal/scanners/          # ScanRunner interface, built-in pattern scanner,
                              # warn-only entropy analyzer, external scanner
                              # discovery, gitleaks adapter
  internal/export/            # ExportGate (hard + configurable blockers,
                              # ModePatch / ModePR, GateResult)
  internal/githubbroker/      # GitHubBroker interface, branch / protected-branch /
                              # path-gate validation, PR metadata scanning, broker-
                              # generated PR body, GitHub App + PAT TokenSource,
                              # TokenHolder (TTL clamping, revocation), token / log
                              # redaction (plan 07)
  .github/workflows/          # CI pipeline
  plan.md                     # Current plan in progress
  plans/                      # Historical planning artifacts
  archive/                    # Archived plans (informational)
```

## Development

```sh
go build ./...
go vet ./...
go test ./...
```

The CI workflow additionally runs `staticcheck` and `govulncheck`. Both should pass locally before pushing:

```sh
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
staticcheck ./...
govulncheck ./...
```

### Integration tests

The default `go test ./...` run is hermetic: it never requires `sbx`, `claude`, or `codex` to be installed on the host. The integration tests that exercise those real binaries are gated behind the `AI_ENV_BACKEND_INTEGRATION` environment variable. They live alongside the unit tests under their respective packages (`internal/backend/docker_sbx/integration_test.go`, `internal/agents/claude/integration_test.go`, `internal/agents/codex/integration_test.go`) and use a two-stage skip: first the env-var check, then an `exec.LookPath` for the binary so a missing prerequisite produces a clear "binary not on PATH" skip rather than a failure.

To run them:

```sh
AI_ENV_BACKEND_INTEGRATION=1 go test ./internal/backend/docker_sbx/...
AI_ENV_BACKEND_INTEGRATION=1 go test ./internal/agents/...
```

Prerequisites the gate assumes when on:

- `internal/backend/docker_sbx`: a working `sbx` CLI on `PATH`, plus whatever daemon (Docker, sandbox runtime) it needs to bring environments up. The lifecycle test exercises `Detect`, `Create`, `Start`, `Exec`, `Stop`, and `Destroy` against a real environment.
- `internal/agents/claude` and `internal/agents/codex`: the corresponding agent CLI on `PATH`. The probes invoke only the version subcommand and `--help`; they never trial-run autonomous flags.

### Environment variables

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `AI_ENV_BACKEND_INTEGRATION` | unset | When set to `1`, enables the gated backend and agent integration tests. Unset is the default and keeps `go test ./...` hermetic. |

## License

Not yet specified.
