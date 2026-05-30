# ai-env

`ai-env` is a Go CLI that scaffolds isolated sandbox environments for AI coding agents. It keeps each agent's work in its own workspace and configuration tree under `.ai-env/`, separate from your active working copy.

This repository contains plans 01 through 06: project scaffolding, configuration loading and validation, workspace isolation via Git worktrees or directory copies, diff and patch export, protected path matching, the run-lifecycle supervisor (run IDs, run directory layout, lifecycle state machine, disk-streamed stdout/stderr capture, max-runtime and signal handling, partial-diff collection, and the `--continue` link), the Backend interface with a Docker Sandboxes (`sbx`) adapter, rootless Docker and Podman fallback backends, and an in-memory mock, agent launchers for Claude Code and Codex with version, flag, and credential probing, the `ai-env agents` family of subcommands, the canonical runtime `NetworkPolicy` plus `NetworkPolicyAdapter` interface with fail-closed supervisor wiring, a host-side provider proxy that fronts Anthropic / OpenAI traffic with redacted logs, per-run `network-events.jsonl`, the `ai-env report` subcommand, the per-run `final-summary.md` that includes the network section, and the scanning and export-gate stack (built-in pattern-only secret scanner, warn-only entropy analyzer, gitleaks adapter, optional external scanner discovery, `ai-env scan` subcommand, and the `ExportGate` wired into `ai-env patch` and `ai-env pr`).

## Status

Plans 01, 02, 03, 04, 05, and 06 complete. The CLI builds and runs on macOS and Linux, has unit and integration tests for config, scaffold, stack detection, gitignore handling, workspace materialization (Git and non-Git fixtures), diff and patch generation, protected path patterns, run-ID uniqueness within the same second, max-runtime timeout, SIGINT log/diff preservation, `sbx` version compatibility, agent flag selection, credential-mode resolution, the network policy validator, the `docker_sbx` policy adapter, the docker / podman fallback adapters (including the `--accept-reduced-isolation` and `--unsafe-host-network` gates), the provider proxy (loopback bind, upstream domain pin, host-side auth injection, log redaction, shutdown), the `network-events.jsonl` writer and summary, the `ai-env report` renderer, the `final-summary.md` writer, the built-in pattern scanner (provider API keys, PEM private-key headers, `.env`-style assignments, allowlist comments), the warn-only entropy analyzer, the gitleaks adapter, external-scanner discovery (missing tools warn rather than crash), the `ai-env scan` subcommand, the `ExportGate` (hard vs. configurable blockers, `ModePatch` vs. `ModePR`), and the scan hook wired into the supervisor's `StateScanning` step. CI runs `gofmt`, `go vet`, `go test -race`, `staticcheck`, and `govulncheck` via GitHub Actions. Real-backend and real-agent integration tests are gated behind `AI_ENV_BACKEND_INTEGRATION=1` and skip cleanly when their host prerequisites are absent.

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

### `ai-env pr <env-name> [--run <id>]`

Evaluates the export gate for an env under `ModePR`. The actual brokered PR push lands with plan 07; until then the command is the gate-only preview a user runs locally before shipping.

- `--run <id>`: same semantics as `ai-env patch --run`.
- The gate is run under `ModePR`, which upgrades a `.github/workflows/**` change from a warning (under `ModePatch`) to a hard block. Every other hard blocker (`secret_finding`, `external_secret_finding`, `ai_env_change`, `policy_change`, `quarantine`) fires identically across the two modes.
- A block verdict prints the blocking reasons to stderr and exits non-zero; an allow verdict prints a per-file preview, any warnings, and a `note: PR push is not yet implemented (wired in plan 07); gate verdict only` line so the operator knows no network call was made.

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
  shell-commands.jsonl # populated by shell shim (later plans)
  filesystem-events.jsonl
  network-events.jsonl # one JSON object per network decision (plan 05)
  policy-decisions.jsonl
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

Note: the supervisor primitives, status, logs, list-with-run-state, and `--continue` plumbing all landed in plan 03. The Backend interface, agent launchers, and `ai-env agents` subcommands documented below landed in plan 04 alongside the supervisor's optional `BackendAdapter` seam. Plan 05 added the canonical `NetworkPolicy`, the `NetworkPolicyAdapter` interface, the docker_sbx network adapter, the rootless docker / podman fallback backends, the host-side provider proxy, the `network-events.jsonl` writer, the `ai-env report` subcommand, and the `final-summary.md` writer (with the network section). Plan 06 added the built-in pattern-only secret scanner, the warn-only entropy analyzer, the gitleaks adapter, optional external scanner discovery, the `ai-env scan` subcommand, the `ExportGate` (wired into `ai-env patch` and `ai-env pr`), and the `ScanHook` seam the supervisor invokes during `StateScanning`. The user-facing `ai-env run` subcommand that wires the supervisor, the backend, the network adapter, the provider proxy, and the scan hook together end-to-end is tracked in a later plan.

## Backend abstraction

The `Backend` interface in `internal/backend/backend.go` is the contract every sandbox implementation satisfies. It exposes nine methods (`Detect`, `Create`, `Start`, `Exec`, `Stop`, `CopyIn`, `CopyOut`, `ApplyNetworkPolicy`, `Stats`, `Destroy`) the supervisor drives through a run's lifecycle. Backends are addressed by an opaque `envID` returned from `Create`; `Detect` reports `BackendStatus` (name, availability, version, whether the version is in the tested range, and a short diagnostic message) without ever returning an error.

Four implementations ship today:

- `internal/backend/mock` is an in-memory no-op backend used by unit tests. It records every method call against an internal log so tests can assert that the supervisor invoked the backend in the expected order without spawning processes.
- `internal/backend/docker_sbx` wraps the Docker Sandboxes `sbx` CLI. `Detect` shells out to `sbx version`, parses a semver-ish token, and compares it against the inclusive range in `internal/backend/docker_sbx/compat.go` (`MinTestedVersion`..`MaxTestedVersion`, currently `0.1.0 - 0.9.99`). Versions outside that range surface as `VersionSupported=false`, and the operator must opt in with `--allow-untested-backend-version` to proceed. The adapter parses minimally: it relies on exit codes, the version probe, and known workspace paths rather than scraping interactive `sbx` stdout for state transitions, so if upstream output formatting changes but exit codes and paths still work, `ai-env` keeps working. The `docker_sbx` adapter also implements `NetworkPolicyAdapter` by translating the canonical runtime policy into `sbx network apply` flags (`--default-policy deny`, `--allow-domain`, `--block-cidr` per always-blocked range, `--block-host` per always-blocked name); see "Network policy enforcement" below.
- `internal/backend/docker` and `internal/backend/podman` are the reduced-isolation fallback backends. Each shells out to the respective host CLI (rootless or rooted: the adapters do not distinguish, but the master plan recommends rootless), brings up a container per env with `--network none` by default, and refuses to mark itself `Available` in autonomous mode unless the operator passes `--accept-reduced-isolation`. Both fallbacks print the verbatim reduced-isolation warning text from the plan the first time `Detect` observes acceptance. Their `ApplyNetworkPolicy` implementation is a structural validator only: `network none` honors every policy trivially (the container has no outbound network), and `--unsafe-host-network` (which requires both `--accept-reduced-isolation` and an explicit `--unsafe-host-network` toggle) accepts only policies with `default: allow` or with no allow-domain list, because the rootless fallback has no per-destination firewall. See "Reduced-isolation fallback backends" below.

The supervisor in `internal/run/supervisor.go` exposes an optional `BackendAdapter` field on its options. When non-nil, the supervisor routes the child process through `Backend.Exec` against the supplied `BackendEnvID` instead of spawning host-side via `exec.Command`. The fallback path (no `BackendAdapter`) keeps the legacy host-exec wiring so the pre-plan-04 lifecycle, signal, and timeout tests continue to drive real subprocesses without constructing a backend. Production code paths (the forthcoming `ai-env run` CLI) always supply a backend. The supervisor also exposes an optional `NetworkPolicyAdapter` plus a `NetworkPolicy` value: when both are set the supervisor calls `Adapter.Apply` during `StateApplyingPolicy` and aborts the run with `StateFailedPolicy` / `stop_reason: policy_failure` on any error, satisfying the master plan's fail-closed contract.

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
                              # summary, final-summary.md, scan-hook driver
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
