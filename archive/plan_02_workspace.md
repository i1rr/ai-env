# Plan 02: Workspace Isolation

Master plan reference: sections 15, 30 (Milestone 2), 31 (Week 2)

## Objective

Implement Git worktree isolation, copy strategy for non-Git sources, diff generation, patch export, and protected path detection. After this phase, agent changes never touch the active working tree by default.

## Dependencies

Plan 01 must be complete. Config structs and YAML loading must be working.

## Decisions from master plan

- Default strategy: `worktree` for Git repos, `copy` for non-Git.
- Worktree branch name format: `ai-env/<env-name>`.
- Worktree path: `.ai-env/workspaces/<env-name>/`.
- Copy baseline for non-Git diff: `.ai-env/baselines/<env-name>/` (gitignored).
- Protected path changes are not blocked but trigger warnings and export gates.
- `direct` mode exists only behind explicit unsafe flag, not in this phase.

## Tasks

1. [x] Implement `WorkspaceManager` interface:
   ```
   Create(envName, sourcePath, strategy) -> WorkspaceInfo
   Diff(envName) -> DiffResult
   Patch(envName, outputPath) -> error
   Strategy(envName) -> StrategyType
   ```
2. [x] Implement Git detection (`git rev-parse --is-inside-work-tree`).
3. [x] Implement worktree strategy:
   - Create branch `ai-env/<env-name>` from current HEAD.
   - Create worktree at `.ai-env/workspaces/<env-name>/`.
   - Record branch name and worktree path in env metadata.
4. [x] Implement copy strategy:
   - Copy source directory to `.ai-env/workspaces/<env-name>/`.
   - Store read-only baseline snapshot at `.ai-env/baselines/<env-name>/`.
   - Record source path, copy time, and file hash summary in env metadata.
5. [x] Implement `ai-env diff <env-name>`:
   - Worktree source: `git diff` between `ai-env/<env-name>` branch and base.
   - Copy source: file-level diff against `.ai-env/baselines/<env-name>/`.
   - Highlight protected path changes in output.
6. [x] Implement `ai-env patch <env-name> --out <file>`:
   - Emit unified diff patch.
   - Warn on protected path changes.
   - For copy strategy, emit file-level patch where possible.
7. [x] Implement protected path matcher:
   - Match against configured `protected_paths` from `policy.yaml`.
   - Default protected paths: `.github/workflows/**`, `.git/**`, `.env`, `.env.*`, `package.json`, lock files, `Dockerfile`, `docker-compose.yml`, `terraform/**`, `infra/**`, `migrations/**`, `.ai-env/**`.
8. [x] Update `ai-env new` to call `WorkspaceManager.Create` (replacing the stub from Plan 01).
9. [x] Add tests with fixture Git repositories.
10. [x] Add tests with fixture non-Git directories.
11. [x] Add tests for protected path matcher patterns.

## Env metadata file

Each environment stores a metadata file at `.ai-env/workspaces/<env-name>/.env-meta.json`:

```json
{
  "name": "fix-tests",
  "strategy": "worktree",
  "branch": "ai-env/fix-tests",
  "source_path": "/path/to/repo",
  "created_at": "2026-05-28T10:00:00+10:00",
  "template": "node"
}
```

For copy strategy, additional fields:

```json
{
  "strategy": "copy",
  "baseline_path": ".ai-env/baselines/fix-tests",
  "copy_time": "2026-05-28T10:00:00+10:00",
  "hash_summary": "sha256:abcdef..."
}
```

## Acceptance criteria

1. `ai-env new fix-tests` in a Git repo creates branch `ai-env/fix-tests` and worktree at `.ai-env/workspaces/fix-tests/`.
2. `ai-env new scratch --from ./some-dir` where `some-dir` is not a Git repo uses copy strategy automatically.
3. Edits inside the worktree do not appear in the original working tree.
4. `ai-env diff fix-tests` shows changes as a Git diff.
5. `ai-env diff scratch` shows changes against the initial baseline copy.
6. Protected path changes are highlighted in diff output.
7. `ai-env patch fix-tests --out fix-tests.patch` exports a valid unified diff.
8. Direct workspace mode is not available without explicit unsafe flag.
