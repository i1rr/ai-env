# Platform parity matrix

`ai-env` is developed for two host platforms: Linux (`GOOS=linux`) and
macOS (`GOOS=darwin`). The two platforms expose different kernel and
syscall surfaces, so a handful of subsystems are unavoidably one-sided.
This document is the operator reference for "which feature works
where, and how degrades": the same enforcement still runs on both
platforms, but the evidence quality and the kernel-level surface area
differ.

Read it together with [`backends.md`](backends.md) (which adapter to
pick on which host) and
[`enforcement-boundaries.md`](enforcement-boundaries.md) (what each
layer enforces).

## Legend

| Marker | Meaning |
|--------|---------|
| supported   | The feature works as designed on this platform. |
| degraded    | The feature works but with documented residual gaps. The lifecycle stream emits the relevant `*_degraded` or `*_unavailable` verb so an auditor can see when the run was reduced. |
| unsupported | The feature does not run on this platform at all. The lifecycle stream emits an `*_unavailable` verb. |

`go build` and `go vet` pass on both platforms; `go test ./...` is
hermetic and platform-clean on both. Platform-gated tests live next to
their implementations with `_linux.go` / `_darwin.go` build tags.

## Subsystem matrix

| Subsystem                                  | Linux       | macOS       | Notes |
|--------------------------------------------|-------------|-------------|-------|
| `docker_sbx` backend                       | supported   | supported   | Both rely on the same `sbx` CLI; no kernel-syscall divergence. |
| `docker` rootless fallback                 | supported   | supported   | Reduced isolation on both. |
| `podman` rootless fallback                 | supported   | degraded    | Podman on macOS runs inside a Linux VM, so `--network host` semantics are a VM gateway, not the actual host. Treat as functionally equivalent to the Linux path. |
| Workspace isolation (`git worktree` / copy)| supported   | supported   | Pure filesystem operations. |
| Network policy validator                   | supported   | supported   | The canonical `NetworkPolicy` lives in `internal/network/` and validates identically. |
| Provider proxy (host-side, loopback HTTP)  | supported   | supported   | Pure Go; the upstream Host-header allowlist works the same on both. |
| `EgressObserver`: NFLOG mode               | supported   | unsupported | Linux-only (`github.com/florianl/go-nflog/v2`). `observer_unavailable` with `reason: no_capability` on darwin. |
| `EgressObserver`: pflog mode               | unsupported | supported   | macOS-only via `tcpdump`. Requires `pf` rules; ai-env installs them under a per-run chain. |
| `EgressObserver`: slirp4netns hosts        | degraded    | unsupported | Slirp4netns cannot expose NFLOG. The supervisor emits `observer_unavailable` with `reason: slirp4netns`; the run continues without network-level evidence. |
| iptables rule installation (`AIENV-EGR-<8hex>`) | supported | unsupported | The Linux-only path. On macOS the equivalent is pf. |
| pf rule installation                       | unsupported | supported   | macOS-only equivalent of iptables. |
| Netns setns via `ns.WithNetNSPath`         | supported   | unsupported | Linux container netns concept. macOS runs unprivileged HTTP listeners directly. |
| Network capability detection (CAP_NET_ADMIN, setns) | supported | n/a | The capability map in `internal/capability` reports `OS: darwin` and the Linux-specific bits are zero. |
| Userns-remap detection                     | supported   | n/a         | Linux-only. `MappedUID` returns the input UID on macOS. |
| Shell shim: `O_RDONLY \| O_NOFOLLOW` open  | supported   | supported   | POSIX flag, identical semantics. |
| Shell shim: content scan + exec via same fd | supported via `SYS_EXECVEAT` (Linux 3.19+) | supported via `/dev/fd/<n>` (`shim_helper_exec_other.go`) | Residual TOCTOU window on filesystems without `/dev/fd` (rare on macOS; the helper logs the platform on the `helper_rpc_aborted` lifecycle record when the substitution is unavailable). |
| Shell shim: canonical-path bind-mount shadows | supported | degraded   | The shim wrappers are installed in `shimDir` and on `PATH` on both. The canonical-path overlays (`/usr/bin/<prog>` and friends) work inside the Docker sandbox on both hosts; bare-host runs on macOS emit `shim_coverage_degraded` because the host's `/usr/bin` is not writable without `csrutil disable`. |
| MCP gateway + registry                     | supported   | supported   | Pure Go on both. |
| GitHub broker                              | supported   | supported   | HTTPS-only. No kernel surface. |
| Control socket (`net.UnixListener`)        | supported   | supported   | Standard POSIX UDS. |
| `secrets.local.yaml` mode 0600 check       | supported   | supported   | Stat + warn on both; `secrets_permission_warning` lifecycle verb fires identically. |
| Lifecycle / network / mcp-calls / policy-decisions / filesystem-events / transcript / shell-commands / leaks writers | supported | supported | Pure Go fsync-on-write; identical behaviour. |
| `ai-env leaks` CLI                         | supported   | supported   | Pure Go. |

## Lifecycle-verb degradation tokens by platform

The supervisor emits `*_unavailable` or `*_degraded` verbs so an
auditor can see when a run was reduced. The tokens are platform-aware:

- `observer_unavailable` with `reason: no_capability`: emitted on
  macOS hosts running the Linux-only NFLOG path, or on Linux hosts
  without `CAP_NET_ADMIN`.
- `observer_unavailable` with `reason: slirp4netns`: emitted on Linux
  hosts where the backend selected slirp4netns networking.
- `network_policy_degraded` with `reason: iptables_rejected` /
  `ipset_missing`: Linux-only; the adapter could not enforce a portion
  of the configured policy.
- `shim_coverage_degraded`: emitted on either host when one or more
  canonical bind-mount targets could not be created (Docker refused,
  target nonexistent in image, host root filesystem read-only on
  macOS).
- `helper_rpc_aborted` with platform context in `peer`: same on both
  hosts.

## Test coverage by platform

| Test target                                | Linux       | macOS       |
|--------------------------------------------|-------------|-------------|
| `go test ./...`                            | passes      | passes      |
| `go vet ./...`                             | passes      | passes      |
| `GOOS=linux go vet ./...`                  | n/a         | passes      |
| `GOOS=darwin go vet ./...` from a Linux host | passes    | n/a         |
| `AI_ENV_BACKEND_INTEGRATION=1 go test ./internal/backend/docker_sbx/...` | gated on the sbx CLI being present | gated on the sbx CLI being present |
| `tests/acceptance` (integration tag)       | gated on a privileged runner; NFLOG + iptables exercised | unsupported (Linux-only assumptions in the suite) |

## Reduced-isolation fallback notes

The two reduced-isolation fallback backends share the host kernel on
both platforms; see [`backends.md`](backends.md) for the operator opt-in
gates (`--accept-reduced-isolation`, `--unsafe-host-network`). The
fallbacks do not change platform-parity for the egress observer: the
NFLOG / pflog choice is host-OS-driven, not backend-driven.

## What this means for an operator

- A macOS workstation can run every ai-env feature except NFLOG-based
  egress observation. Use the pflog mode when egress evidence matters,
  or accept the degraded `observer_unavailable` audit signal.
- A Linux workstation gets the full feature set when the run executes
  with `CAP_NET_ADMIN` and a real netns. Slirp4netns and unprivileged
  containers degrade gracefully via the documented lifecycle verbs.
- CI: run the hermetic test suite on both platforms; gate the
  integration tests to a privileged Linux runner.
