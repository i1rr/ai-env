# Backends

This document is the operator reference for the sandbox backends
`ai-env` supports in v0.1. It covers each adapter, the isolation
strength it offers, its prerequisites, how to switch between them,
and what falls back to what when the primary is unavailable.

Read this together with [`threat-model.md`](threat-model.md) (which
treats the backend as the primary kernel boundary) and
[`enforcement-boundaries.md`](enforcement-boundaries.md) (which lists
the backend layer's bypassability for each adapter).

## The cardinal rule

> The backend is the security boundary. `docker_sbx` is the only v0.1
> adapter the threat model considers a real kernel boundary. The
> rootless `docker` and `podman` fallbacks share the host kernel and
> are documented as reduced-isolation: they exist for development and
> CI of `ai-env` itself, not for high-risk autonomous execution.

Every entry below either gives you the primary boundary or explicitly
flags itself as a reduced-isolation fallback that requires operator
opt-in.

## The four adapters

The `Backend` contract is defined in `internal/backend/backend.go`. Four
adapters implement it in v0.1:

| Adapter         | Package                              | Isolation strength      | When the threat model trusts it |
|-----------------|--------------------------------------|--------------------------|----------------------------------|
| `docker-sbx`    | `internal/backend/docker_sbx/`       | microVM (Docker Sandboxes) | Yes: primary boundary.           |
| `docker`        | `internal/backend/docker/`           | rootless container        | Reduced: shares host kernel.    |
| `podman`        | `internal/backend/podman/`           | rootless container        | Reduced: shares host kernel.    |
| `mock`          | `internal/backend/mock/`             | in-memory no-op           | Never: tests only.              |

The adapter names mirror what the operator writes in `.ai-env/ai-env.yaml`
under `sandbox.backend` and `sandbox.fallback_backend`. The default
config written by `ai-env new` (see `internal/cli/new.go`
`Sandbox` section) is:

```yaml
sandbox:
  backend: docker-sbx
  fallback_backend: none
  accept_reduced_isolation: false
```

`fallback_backend: none` means the run aborts if `docker-sbx` is
unavailable; setting it to `docker` or `podman` opts the operator into
the reduced-isolation path.

## `docker-sbx` (primary)

The primary adapter targets a Docker-Sandboxes-compatible runtime via
the `sbx` CLI. It is the only v0.1 adapter the threat model considers
a real kernel boundary.

### Isolation

- microVM-backed. The agent process runs in a microVM the runtime
  manages; the host kernel is not the agent's kernel.
- Host filesystem is not mounted by default. The workspace is the
  only path the agent sees.
- Host Docker socket is not mounted. The agent cannot spawn sibling
  containers on the host.
- SSH agent socket, `$HOME`, browser profiles, cloud credential
  directories: not mounted.
- Network policy is installed via `internal/backend/docker_sbx/network_adapter.go`
  before the agent starts. A failure to apply the policy ends the run
  in `StateFailedPolicy` (see `internal/run/supervisor.go`).

### Prerequisites

- The `sbx` CLI on `PATH`. `Detect()` runs `exec.LookPath("sbx")`
  (see `internal/backend/docker_sbx/docker_sbx.go::Name` and
  `defaultBinary`).
- An `sbx` version in the tested range. The pinned range is in
  `internal/backend/docker_sbx/compat.go`:
  - `MinTestedVersion = "0.1.0"`.
  - `MaxTestedVersion = "0.9.99"`.
  - `TestedVersionRange = "0.1.0 - 0.9.99"`.
- A microVM-capable host (macOS or Linux with the runtime's
  prerequisites; see the Docker Sandboxes documentation for what
  qualifies).

An unknown `sbx` version fails closed with the message
`"sbx version <version> is outside the tested range <range>; pass
--allow-untested-backend-version to proceed"`. See `unsafe-modes.md`
for the explicit opt-in flag.

### Trade-offs

- **Strong isolation.** The threat model's "Backend / kernel
  boundary" in [`threat-model.md`](threat-model.md) applies here in
  full.
- **Heaviest startup.** microVM startup is slower than a rootless
  container; expect a few seconds before the agent is ready.
- **Runtime is a dependency.** The host needs a working Docker
  Sandboxes runtime. Operators without one fall back to `docker` or
  `podman` (see below) or run on a different host.

## `docker` (reduced-isolation fallback)

The rootless Docker fallback. Shares the host kernel.

### Isolation

- Rootless container. The host kernel is the agent's kernel.
- Container runs with `--network none` by default. The adapter
  refuses to enforce an allowlist policy unless the operator also
  passes `UnsafeHostNetwork=true`; see the explicit error in
  `internal/backend/docker/docker.go`:
  `"docker: cannot enforce allowlist on rootless fallback with
  --unsafe-host-network; remove allow_domains or run on the docker-sbx
  backend"`.
- Workspace is mounted into the container; the host's other
  filesystem is not.
- Host Docker socket is not mounted by the adapter.

### Prerequisites

- The `docker` CLI on `PATH` with the rootless daemon configured.
- `Options.AcceptReducedIsolation=true` (wired from the operator's
  `--accept-reduced-isolation` flag / `sandbox.accept_reduced_isolation:
  true` in `ai-env.yaml`). Without it, `Detect()` returns
  `Available: false` with the message `"docker fallback backend
  requires --accept-reduced-isolation for autonomous mode (reduced
  isolation: see WARNING below)\n" + ReducedIsolationWarning`.

The verbatim warning printed on every `Detect` that observes
acceptance is in `internal/backend/docker/docker.go::ReducedIsolationWarning`:

```text
WARNING: This backend provides reduced isolation. It is suitable for
development and testing, but not for high-risk autonomous execution
with untrusted dependencies or secrets.
```

### Trade-offs

- **Faster startup.** Rootless containers start in fractions of a
  second.
- **Reduced isolation.** A kernel or container-runtime exploit
  reaches the host directly. Not equivalent to the primary backend.
- **Network policy is constrained.** The default is `--network none`
  (no egress). An allowlist requires `--unsafe-host-network`, which
  reaches the entire host network and defeats the egress policy.
  Operators who need both an allowlist and reachable network should
  use `docker-sbx`.

## `podman` (reduced-isolation fallback)

The rootless Podman fallback. Shares the host kernel. Mirrors the
docker adapter's contract; the implementation differences are in
process management (Podman's API surface), not in policy.

### Isolation

Identical posture to the `docker` adapter:

- Rootless container, host kernel.
- `--network none` by default; allowlist enforcement requires
  `UnsafeHostNetwork=true` (`internal/backend/podman/podman.go`
  returns the same explicit error wording, scoped to podman:
  `"podman: cannot enforce allowlist on rootless fallback with
  --unsafe-host-network; remove allow_domains or run on the docker-sbx
  backend"`).
- Workspace mounted; host filesystem otherwise unmounted; host Docker
  socket never mounted.

### Prerequisites

- The `podman` CLI on `PATH`.
- `Options.AcceptReducedIsolation=true`. The unavailable-mode
  message is `"podman fallback backend requires
  --accept-reduced-isolation for autonomous mode (reduced isolation:
  see WARNING below)\n" + ReducedIsolationWarning`.

The verbatim warning text is identical
(`internal/backend/podman/podman.go::ReducedIsolationWarning`).

### Trade-offs

Identical to the `docker` adapter. Choose between them based on which
runtime the host actually has installed; from `ai-env`'s threat-model
perspective the two are interchangeable reduced-isolation fallbacks.

## `mock` (tests only)

`internal/backend/mock/` is an in-memory no-op implementation used by
the supervisor's unit tests. It does not isolate anything: there is no
kernel, no namespace, no network. Operators must never select it; it
is not exposed through the default config. Listed here for
completeness.

## How to switch backends

The backend choice lives in `.ai-env/ai-env.yaml`. The default file
`ai-env new` writes (`internal/cli/new.go::defaultAIEnvConfig`) is:

```yaml
sandbox:
  backend: docker-sbx
  fallback_backend: none
  template: <picked by the new command>
  destroy_on_exit: false
  private_docker_daemon: true
  host_docker_socket: false
  mount_home: false
  accept_reduced_isolation: false
```

To switch to a reduced-isolation backend explicitly:

```yaml
sandbox:
  backend: docker            # or "podman"
  fallback_backend: none
  accept_reduced_isolation: true   # required; see unsafe-modes.md
```

The CLI flag equivalents are `--accept-reduced-isolation` and
`--unsafe-host-network`. Both are wired into the backend
`Options.AcceptReducedIsolation` / `Options.UnsafeHostNetwork` fields
(see `internal/backend/docker/docker.go` and
`internal/backend/podman/podman.go`). For the full enumeration of
unsafe-mode flags and what each weakens, see
[`unsafe-modes.md`](unsafe-modes.md).

## Fallback chain

The supervisor selects `backend`, falling back to `fallback_backend`
only if both:

1. `Detect()` on the primary returns `Available: false`.
2. `fallback_backend` is not `none`.

If both detects fail, or if the primary is unavailable and
`fallback_backend: none`, the run aborts before the agent launches.
The `BackendStatus.Message` field carries the verbatim diagnostic so
the operator sees exactly what was missing (binary not on PATH, daemon
not running, version outside the tested range, reduced-isolation flag
not set).

When the primary is `docker-sbx` and the fallback is `docker` or
`podman`, the operator must explicitly opt into the reduced-isolation
posture by setting `accept_reduced_isolation: true`. The supervisor
does not silently downgrade; the fallback adapter's `Detect()`
refuses to advertise availability without the acknowledgement.

## What does NOT fall back

The following are intentionally not in the fallback chain:

- **`mock` is never reachable as a fallback.** It is wired up only by
  test code that constructs `mock.New(...)` directly. There is no
  operator path that selects it.
- **`docker-sbx` does not fall back to itself with looser settings.**
  If the runtime is broken, the run aborts; there is no
  "best-effort" mode.
- **A backend's `ApplyNetworkPolicy` failure does not fall back to no
  policy.** The supervisor terminates the run with
  `StateFailedPolicy`. The agent never starts.
- **A backend version outside the tested range does not silently
  fall back.** `internal/backend/docker_sbx/compat.go` refuses to
  launch unless the operator passes `--allow-untested-backend-version`
  (see [`unsafe-modes.md`](unsafe-modes.md) for the risks).

## Network adapter pairing

Each backend ships its own `NetworkPolicyAdapter`:

- `internal/backend/docker_sbx/network_adapter.go` translates the
  policy into `sbx network apply` invocations.
- The `docker` and `podman` adapters install policy through their
  container network mode (`--network none` by default; `--network
  host` when `UnsafeHostNetwork=true`).
- The `mock` adapter accepts the policy and records it without
  enforcement.

The supervisor only sees the `NetworkPolicyAdapter` interface (see
`internal/network/network.go`); it fails closed uniformly via
`StateFailedPolicy` regardless of which backend is in use.

## Quick checklist for operators

Before relying on a backend:

1. Did `ai-env doctor` (or equivalent `Detect()`-driven check)
   report `Available: true` for your configured backend, and is
   `VersionSupported: true`?
2. If you set `accept_reduced_isolation: true`, did you re-read
   `ReducedIsolationWarning` and confirm the run does not need
   primary-grade isolation?
3. If you set `--unsafe-host-network`, did you confirm that the
   network policy you wrote in `policy.yaml` is acceptable to defeat
   (because that is what the flag does)?
4. Is your `fallback_backend` setting intentional? `none` is the safe
   default; anything else means "downgrade silently in some
   conditions".
5. Did you confirm that the backend version is inside
   `TestedVersionRange` (or that you intend to opt in with
   `--allow-untested-backend-version`)?

If any answer is "I do not know", stop and address it before relying
on the run.
