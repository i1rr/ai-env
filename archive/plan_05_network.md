# Plan 05: Network Policy and Provider Proxy

Master plan reference: sections 18, 19 (provider proxy), 20, 30 (Milestone 5), 31 (Week 5)

## Objective

Implement backend network policy enforcement, provider proxy lifecycle for model credentials, rootless Docker/Podman fallback in offline mode, and network event logging. After this phase, unknown outbound destinations are blocked in the primary backend.

## Dependencies

Plans 01-04 must be complete. The backend adapter must support `ApplyNetworkPolicy`.

## Key decisions from master plan

**No TLS MITM in v0.1.** Enforcement is destination-based via the sandbox backend. HTTP method enforcement only for brokered APIs.

**Fail closed**: if the backend cannot apply the requested network policy, autonomous mode must fail. Not silently degrade.

**Fallback backend**: rootless Docker or Podman defaults to `--network none`. Outbound network in fallback mode requires explicit `--unsafe-host-network --accept-reduced-isolation`.

**Provider proxy**: not a TLS MITM proxy. It is a provider-compatible HTTP endpoint on the host that adds authorization headers server-side. The agent sees it as the provider base URL. Binds to localhost, exposed to sandbox only through backend-approved path.

## Always blocked by default

```
127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.169.254
localhost
host.docker.internal
unknown domains
```

## Default allow domains (from policy.yaml)

```
api.openai.com
api.anthropic.com
api.github.com
github.com
registry.npmjs.org
pypi.org
files.pythonhosted.org
crates.io
proxy.golang.org
sum.golang.org
```

## Network phases

| Phase  | Network                                  | Secrets                            |
|--------|------------------------------------------|------------------------------------|
| init   | Minimal                                  | None                               |
| setup  | Package registries + source hosts        | No production secrets              |
| agent  | Model APIs + approved docs + Git read    | Brokered only                      |
| test   | Offline by default                       | None                               |
| export | GitHub broker only                       | Short-lived broker action          |

## Provider proxy mechanics

1. Started per-run by host supervisor before agent launches.
2. Binds to localhost on host; exposed to sandbox only through backend-approved network alias.
3. Agent discovers it via `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` environment variable (or agent-specific config where supported).
4. Accepts requests only from active run identity or sandbox route.
5. Adds provider `Authorization` header on host side.
6. Redacts request and response logs (no raw tokens).
7. Enforces only the configured provider domain as the upstream target.
8. Stopped when the run stops, times out, is killed, or is destroyed.
9. If the agent cannot use backend-managed credentials or the proxy, autonomous mode fails closed unless `--allow-raw-model-token-in-sandbox` is explicit.

## Tasks

1. Implement `NetworkPolicy` struct (allow domains, block private ranges, block metadata services, block localhost).
2. Implement `NetworkPolicyAdapter` interface in `internal/network/`.
3. Implement Docker Sandboxes network policy adapter: translate `NetworkPolicy` to `sbx` network config.
4. Implement fail-closed behavior: if `ApplyNetworkPolicy` fails, abort run with `failed_policy` state.
5. Implement private range and metadata service blocking config.
6. Implement `network-events.jsonl` writer (receives events from backend where available).
7. Implement network summary output in `ai-env report`.
8. Implement provider proxy in `internal/secrets/proxy.go`:
   - HTTP reverse proxy bound to localhost.
   - Adds provider authorization header from host-side credential store.
   - Per-run lifecycle: start before agent, stop after run.
   - Redacts token-like values in proxy request/response logs.
   - Validates upstream domain matches configured provider.
9. Wire provider proxy into agent launcher (Plan 04): set `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` when proxy mode is active.
10. Implement rootless Docker/Podman fallback backend in `internal/backend/docker/` and `internal/backend/podman/`:
    - Detect `docker` or `podman` availability.
    - Default to `--network none`.
    - Require `--accept-reduced-isolation` for autonomous mode.
    - Print reduced-isolation warning.
11. Add tests for fallback offline behavior (no outbound network).
12. Add network summary to `final-summary.md` and `ai-env report`.

## Reduced-isolation fallback warning (required text)

```
WARNING: This backend provides reduced isolation. It is suitable for development
and testing, but not for high-risk autonomous execution with untrusted dependencies
or secrets.
```

## Acceptance criteria

1. Unknown domain is blocked in primary Docker Sandboxes backend.
2. Metadata IP `169.254.169.254` is blocked.
3. Private network ranges are blocked.
4. Allowed package registry is reachable in setup phase.
5. If network policy cannot be applied, autonomous run fails closed.
6. Fallback backend defaults to `--network none`.
7. Fallback backend with outbound network requires explicit unsafe flags.
8. Provider proxy starts per-run, stops on run end, and adds auth headers on host side.
9. Network event log records available events.
10. Network summary appears in run report.
