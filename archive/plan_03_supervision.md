# Plan 03: Process Supervision

Master plan reference: sections 16, 24, 30 (Milestone 3), 31 (Week 3)

## Objective

Implement the run lifecycle state machine, unique run directories, signal handling, timeout handling, disk-streamed stdout/stderr capture, and lifecycle event logging. After this phase, `ai-env run` can track a process end-to-end even without a real backend.

## Dependencies

Plans 01 and 02 must be complete. Workspace paths must be resolvable.

## Decisions from master plan

- Run IDs: `YYYYMMDD-HHMMSS-<6+ random hex chars>` to avoid collisions within the same second.
- stdout and stderr are streamed to disk, not buffered in memory. A bounded tail buffer may be kept for terminal display and idle detection.
- Stats polling is observational only. Preventive limits come from backend resource controls.
- Supervisor owns a process on the host. It wraps `Backend.Exec` which is a stub in this phase.
- `--continue` reuses existing workspace and creates a new linked run directory.
- SIGINT: forward to agent, wait grace period, then stop.
- SIGTERM: forward to agent, wait grace period, then stop.
- SIGHUP: mark interrupted, stop if non-interactive.

## Run state machine

```
created
  -> preparing_workspace
  -> starting_backend
  -> applying_policy
  -> starting_agent
  -> running
  -> stopping
  -> scanning
  -> reporting
  -> completed

failure states:
  failed_backend
  failed_agent
  failed_policy
  failed_scan
  timed_out
  killed_by_user
  killed_oom
  killed_idle
  quarantined
```

## Run directory layout

```
.ai-env/runs/<run-id>/
  task.md
  run.json
  agent-command.txt
  transcript.md
  stdout.log
  stderr.log
  lifecycle.jsonl
  shell-commands.jsonl          # populated by shell shim (later)
  filesystem-events.jsonl       # populated by backend events (later)
  network-events.jsonl          # populated by network adapter (later)
  policy-decisions.jsonl
  git-diff.patch
  scan-results/
  secret-scan.json
  dependency-report.json
  security-report.md
  final-summary.md
```

## Event formats

Lifecycle event:

```json
{
  "run_id": "20260528-101300-a1b2c3",
  "state": "running",
  "backend": "docker-sbx",
  "agent": "claude",
  "timestamp": "2026-05-28T10:13:00+10:00"
}
```

Stats event:

```json
{
  "run_id": "20260528-101300-a1b2c3",
  "cpu_percent": 82.1,
  "memory_mb": 2048,
  "workspace_bytes": 91827364,
  "last_output_at": "2026-05-28T10:14:10+10:00",
  "timestamp": "2026-05-28T10:14:20+10:00"
}
```

`run.json` schema (minimal):

```json
{
  "run_id": "20260528-101300-a1b2c3",
  "env_name": "fix-tests",
  "agent": "claude",
  "task": "Fix the failing tests",
  "state": "completed",
  "exit_code": 0,
  "started_at": "2026-05-28T10:13:00+10:00",
  "stopped_at": "2026-05-28T10:24:00+10:00",
  "stop_reason": "agent_exit",
  "backend": "docker-sbx",
  "model_credential_mode": "backend_managed",
  "reduced_safety": false,
  "linked_previous_run": null
}
```

## Default timeouts

```yaml
supervision:
  max_runtime_minutes: 120
  idle_timeout_minutes: 20
  shutdown_grace_seconds: 15
  kill_grace_seconds: 5
  max_stdout_bytes: 50000000
  max_stderr_bytes: 50000000
  stream_output_to_disk: true
  max_processes: 1024
  max_workspace_bytes: 5000000000
```

## Tasks

1. [x] Implement run ID generator: `YYYYMMDD-HHMMSS-<6-random-hex>`.
2. [x] Implement `RunDirectory` creator: creates all required files and subdirs under `.ai-env/runs/<run-id>/`.
3. [x] Write `task.md` from `--task` flag content.
4. [x] Implement run state machine with transitions and failure states.
5. [x] Implement `lifecycle.jsonl` writer.
6. [x] Implement `run.json` writer with full schema.
7. [x] Implement disk-streamed stdout/stderr capture (bounded tail buffer for terminal display).
8. [x] Implement supervisor main loop:
   - Launch backend exec (stub: echo process in this phase).
   - Poll stats every 10 seconds.
   - Detect idle timeout (no output + no diff for `idle_timeout_minutes`).
   - Enforce `max_runtime_minutes`.
   - Record exit code and stop reason.
9. [x] Implement signal handling (SIGINT, SIGTERM, SIGHUP).
10. [x] On stop: collect partial diff, write final state to `run.json`, print `--continue` suggestion.
11. [x] Implement `ai-env status <env-name>`: show current or last run state.
12. [x] Implement `ai-env logs <env-name>`: tail or display `stdout.log` and `stderr.log`.
13. [x] Update `ai-env list` to show latest run state per environment.
14. [x] Implement `--continue`: create new run directory linked to previous run, reuse same worktree.
15. [x] Add tests: two runs in the same second produce distinct run IDs.
16. [x] Add tests: max runtime timeout stops the supervisor.
17. [x] Add tests: SIGINT preserves logs and partial diff.

## Acceptance criteria

1. `ai-env run fix-tests --agent claude --task "..."` creates a unique run directory.
2. Two runs started in the same second receive distinct run IDs.
3. Hung agent is stopped by idle timeout.
4. Long-running agent is stopped by max runtime.
5. SIGINT preserves run logs and marks state as `killed_by_user`.
6. `ai-env status fix-tests` shows current run state.
7. stdout and stderr are streamed to disk, not buffered in memory.
8. `--continue` reuses the existing workspace and links to the previous run.
9. `ai-env list` shows latest run state per environment.
