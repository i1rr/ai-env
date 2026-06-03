# Plan 08: Policy Engine, Shell and Hardening

Master plan reference: sections 21, 22, 23, 26, 30 (Milestone 8), 31 (Week 8), 32, 37

## Objective

Implement the policy engine, policy decision logging, optional shell shim prototype, acceptance test fixtures, release dry-run, and all required documentation. After this phase, v0.1 MVP is feature-complete and testable against real repositories.

## Dependencies

Plans 01-07 must be complete.

## Policy engine scope in v0.1

Policy applies to:

1. Environment creation (workspace strategy, backend selection).
2. Network policy (already enforced in Plan 05).
3. Export gates (already enforced in Plan 06).
4. GitHub broker actions (already enforced in Plan 07).
5. Scanner thresholds.
6. Protected path changes.
7. Commands launched through `ai-env shell` or shell shim.

Policy does not apply to arbitrary commands inside a third-party agent's internal shell unless shimmed.

## Decision types

| Decision    | Meaning                                              |
|-------------|------------------------------------------------------|
| allow       | Execute or export immediately                        |
| ask         | Require user or reviewer approval                    |
| deny        | Block action                                         |
| quarantine  | Stop session and preserve evidence                   |
| warn        | Allow but highlight in report                        |

## Tasks

### Policy engine

1. [x] Implement `PolicyEngine` in `internal/policy/`:
   - Load and validate `policy.yaml`.
   - Evaluate events: environment creation, export, broker actions, shell commands (when shimmed).
   - Return `PolicyDecision` with type, reason, and event ID.
2. [x] Implement `policy-decisions.jsonl` writer (extend stub from Plan 07).
3. [x] Implement `ai-env policy init`: write default `policy.yaml` for current project.
4. [x] Implement `ai-env policy check <env-name>`: show current policy summary and any warnings.
5. [x] Implement `ai-env policy explain <env-name> --event <event-id>`: explain a logged decision.
6. [x] Implement `ai-env policy allow-domain / deny-domain / allow-tool / deny-tool`.
7. [x] Wire policy engine into run startup: validate config before starting sandbox.

### Shell shim (prototype)

8. [x] Implement shell shim prototype in `internal/policy/shim.go`:
   - Intercept commands launched through `ai-env shell`.
   - Log command attempts to `shell-commands.jsonl`.
   - Deny obvious high-risk patterns (curl-pipe-shell, access to SSH paths, cloud metadata).
   - Forward allowed commands to real binaries.
9. [x] Wire shim when `--shell-shim` flag is passed to `ai-env run`.
10. [x] Document shim limitations clearly: agents may use absolute paths, static binaries bypass wrappers, kernel-level controls remain the real boundary.

### Acceptance tests and fixtures

11. [x] Write fixture repositories: minimal Node project, minimal Python project.
12. [x] Write acceptance test for each item in master plan section 32:
    - Isolation tests (SSH key not readable, Docker socket not accessible, etc.).
    - Supervision tests (timeout, SIGINT, OOM marker, continue, distinct run IDs).
    - Network tests (unknown domain blocked, metadata IP blocked, fallback offline).
    - Git tests (branch prefix, no push to main, draft PR, workflow gate, patch export, PR scan).
    - Prompt injection fixture tests.
    - Dependency tests (ignore-scripts default, no secrets during setup).
    - Scanner tests (fake secrets detected, missing scanners don't crash, entropy warns).
    - Model credential tests (backend-managed default, raw mode requires flag, run.json records decision).
    - Backend compatibility tests (unknown sbx version fails closed, missing sbx guidance).

### CI hardening

13. [x] Add race detector CI job for selected packages.
14. [x] Add integration CI job gated by `AI_ENV_BACKEND_INTEGRATION=1`.
15. [x] Add release dry-run workflow.

### Documentation

16. [x] Write `README.md`: quickstart, install, first run, supported agents, security summary.
17. [x] Write `docs/threat-model.md`.
18. [x] Write `docs/enforcement-boundaries.md`.
19. [x] Write `docs/residual-risk.md`.
20. [x] Write `docs/model-credentials.md`.
21. [x] Write `docs/backends.md`.
22. [x] Write `docs/unsafe-modes.md`.

### MVP demonstration

23. [x] Test `ai-env new demo` against a real Node repository.
24. [x] Test `ai-env run demo --agent claude --task "fix failing tests"` end-to-end.
25. [x] Verify: attempted read of host SSH key fails.
26. [x] Verify: attempted access to host Docker socket fails.
27. [x] Verify: attempted unknown network egress fails in primary backend.
28. [x] Verify: attempted push to main fails.
29. [x] Verify: hung agent stopped by timeout.
30. [x] Verify: `ai-env scan demo` runs without user-installed scanners.
31. [x] Verify: high-confidence secret finding blocks export.
32. [x] Verify: entropy-only finding warns but does not block.
33. [x] Verify: workflow file change blocks brokered PR.
34. [x] Verify: `ai-env patch demo --out demo.patch` exports a valid patch.
35. [x] Verify: `ai-env new nongit --from ./some-non-git-dir` uses copy mode and exports a diff.
36. [x] Verify: `ai-env destroy demo` removes environment resources.

## Acceptance criteria

All 19 items from master plan section 37 (Definition of done for MVP) must pass.

Key summary:

1. Autonomous coding agent runs against real repository with no direct host execution.
2. Developer receives reviewable patch.
3. Host SSH keys, Docker socket, unknown network, and protected branches are inaccessible.
4. Timeout stops hung agents.
5. Scan runs without external tools, blocks on secrets, warns on entropy.
6. Workflow changes block brokered PR.
7. Copy mode works for non-Git sources.
8. Destroy is clean.
