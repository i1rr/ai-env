# Plan 04: Docker Sandboxes Backend

Master plan reference: sections 14, 17, 30 (Milestone 4), 31 (Week 4)

## Objective

Implement the Docker Sandboxes backend adapter through the `sbx` CLI, agent launchers for Claude and Codex, version compatibility checks, and model credential mode detection. After this phase, `ai-env run` launches a real agent inside an isolated sandbox.

## Dependencies

Plans 01, 02, and 03 must be complete. The supervisor must be able to call `Backend.Exec`.

## Critical decisions from master plan

**Parsing principle**: the adapter must parse minimally. Rely on exit codes, known workspace paths, version checks, and explicitly created files. Do not scrape interactive `sbx` stdout for control-flow state transitions. If `sbx` output formatting changes but exit codes and known paths still work, `ai-env` must keep working.

**Version gating**: maintain a tested version range in `internal/backend/docker_sbx/compat.go`. Fail closed on unknown versions unless `--allow-untested-backend-version` is passed.

**Model credentials**: default is `backend_managed`. If that is not supported, try `provider_proxy`. Fall back to `raw_env_explicit` only with explicit flag `--allow-raw-model-token-in-sandbox`. Missing credential mechanism fails closed.

**Fallback**: if `sbx` is not installed, offer reduced-isolation offline fallback only. Never silently switch an autonomous networked run to plain Docker or Podman.

## Backend interface

```go
type Backend interface {
    Detect() BackendStatus
    Create(spec EnvSpec) (envID string, err error)
    Start(envID string) (RuntimeInfo, error)
    Exec(envID string, cmd Command, opts ExecOptions) (ExecResult, error)
    Stop(envID string, signal os.Signal, timeout time.Duration) error
    CopyIn(envID, src, dest string) error
    CopyOut(envID, src, dest string) error
    ApplyNetworkPolicy(envID string, policy NetworkPolicy) error
    Stats(envID string) (ResourceStats, error)
    Destroy(envID string) error
}
```

## `sbx` integration rules

1. Detect with `exec.LookPath("sbx")`.
2. Run `sbx version`, parse only the version string.
3. Compare against tested range in `compat.go`. Fail closed on unknown version.
4. Wrap `sbx` as subprocess: capture stdout, stderr, exit code, timing.
5. Treat `sbx` stdout/stderr as logs, not machine API.
6. Store exact `sbx` command in `agent-command.txt`.
7. Add integration tests gated by `AI_ENV_BACKEND_INTEGRATION=1` env var.

## Agent contract registry (`agents.yaml`)

```yaml
version: 1
agents:
  claude:
    command: claude
    version_constraint: ">=1.0.0"
    probe:
      args: ["--version"]
      parse: "semver"
    modes:
      autonomous:
        args_candidates:
          - ["--dangerously-skip-permissions"]
    credential_mode:
      default: backend_managed
      fallback_order:
        - provider_proxy
        - raw_env_explicit
    requires:
      - anthropic
  codex:
    command: codex
    version_constraint: ">=0.0.0"
    probe:
      args: ["--version"]
      parse: "semver"
    modes:
      autonomous:
        args_candidates:
          - ["--dangerously-bypass-approvals-and-sandbox"]
    credential_mode:
      default: backend_managed
      fallback_order:
        - provider_proxy
        - raw_env_explicit
    requires:
      - openai
```

## Agent probing

`ai-env agents doctor` and `ai-env agents probe <agent>`:

1. Binary exists.
2. Version can be parsed.
3. Required flags are supported (probe via versioned contract first, then `--help` output for known flags and known version ranges).
4. Required credentials are available (backend-managed, proxy, or explicit raw-env).
5. Backend template contains required runtime dependencies.
6. Do not trial-run dangerous autonomous flags against user workspace.
7. Fail closed if required flags cannot be verified, show tested version range.

## Tasks

1. [x] Implement `Backend` interface in `internal/backend/`.
2. [x] Implement mock backend in `internal/backend/mock/` (no-op, used in unit tests).
3. [x] Implement `internal/backend/docker_sbx/` adapter:
   - `sbx` detection.
   - `sbx version` compatibility check with version range.
   - `Create`: `sbx create` or equivalent.
   - `Start`: `sbx start` or equivalent.
   - `Exec`: `sbx exec` wrapping agent launch command.
   - `Stop`: `sbx stop`.
   - `Destroy`: `sbx destroy` or equivalent.
   - `CopyIn` / `CopyOut`: workspace mount or `sbx cp`.
   - `Stats`: stats endpoint if available, else no-op with warning.
4. [x] Implement agent launcher for Claude:
   - Resolve binary path.
   - Probe version.
   - Select autonomous flags from contract.
   - Detect credential mode.
   - Build launch command.
5. [x] Implement agent launcher for Codex (same structure).
6. [x] Implement `ai-env agents list`, `ai-env agents doctor`, `ai-env agents probe <agent>`.
7. [x] Implement model credential mode resolution:
   - `backend_managed`: verify backend supports it.
   - `provider_proxy`: verify agent supports custom base URL (stub: wire up in Plan 05).
   - `raw_env_explicit`: require `--allow-raw-model-token-in-sandbox` flag; record in `run.json`; print warning.
   - Fail closed if no mode is available.
8. [x] Wire backend into supervisor from Plan 03: replace stub exec with `Backend.Exec`.
9. [x] Add integration tests gated by environment variable.
10. [x] Add unit tests for version compatibility check.
11. [x] Add unit tests for agent flag probe logic.

## Unsafe modes (explicit flags only)

```
--unsafe-direct-workspace
--unsafe-host-network
--unsafe-mount-home
--unsafe-host-docker-socket
--accept-reduced-isolation
--allow-untested-backend-version
--allow-raw-model-token-in-sandbox
```

None of these are defaults. All must print a visible warning when used.

## Acceptance criteria

1. `ai-env run fix-tests --agent claude --task "..."` launches Claude Code inside Docker Sandbox.
2. `ai-env run fix-tests --agent codex --task "..."` launches Codex inside Docker Sandbox.
3. Agent sees the isolated workspace, not the host working tree.
4. Agent cannot access host home directory.
5. Agent cannot access host Docker socket.
6. `ai-env destroy fix-tests` removes the sandbox environment.
7. Unknown `sbx` version fails closed unless `--allow-untested-backend-version` is passed.
8. Adapter does not depend on scraping interactive `sbx` stdout for state transitions.
9. Missing model credential mechanism fails closed unless `--allow-raw-model-token-in-sandbox` is passed.
10. `sbx` not installed reports actionable guidance, does not silently fall back to plain Docker for autonomous runs.
