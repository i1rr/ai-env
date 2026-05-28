# ai-env

`ai-env` is a Go CLI that scaffolds isolated sandbox environments for AI coding agents. It keeps each agent's work in its own workspace and configuration tree under `.ai-env/`, separate from your active working copy.

This repository contains plans 01 and 02: project scaffolding, configuration loading and validation, workspace isolation via Git worktrees or directory copies, diff and patch export, and protected path matching. Sandbox backends and the supervisor are tracked in later plans.

## Status

Plans 01 and 02 complete. The CLI builds and runs on macOS and Linux, has unit and integration tests for config, scaffold, stack detection, gitignore handling, workspace materialization (Git and non-Git fixtures), diff and patch generation, and protected path patterns. CI runs `gofmt`, `go vet`, `go test -race`, `staticcheck`, and `govulncheck` via GitHub Actions.

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

`ai-env list` never starts a backend process. It only reads files. If no `.ai-env/workspaces/` directory exists yet (fresh project), it prints a friendly empty-state message.

### `ai-env diff <env-name> [--name-only]`

Shows the changes a workspace has accumulated against its baseline.

- Worktree strategy: emits the `git diff` between the env branch (`ai-env/<env-name>`) and the source repo's HEAD.
- Copy strategy: emits a file-level unified diff against the read-only baseline snapshot at `.ai-env/baselines/<env-name>/`.

Output has two stable sections: a header with the env name, strategy, and a per-file summary (each line tagged `[protected]` when the path matches a protected pattern), followed by the unified-diff body. The body is suppressed when `--name-only` is set. Protected-path hits are also re-emitted on stderr as a warning block so scripts piping stdout into a reviewer still get the diff body unchanged. Like `ai-env list`, this command walks upward from the current directory to find the project's `.ai-env/`.

### `ai-env patch <env-name> --out <file>`

Exports the same diff as `ai-env diff` to a unified-diff patch file suitable for `git apply` or `patch -p1`.

- `--out <file>`: required. Output path for the patch file (resolved relative to the current working directory). The file is always written, even when there are no changes, so callers that test for file existence behave consistently.
- Protected-path changes do not block export but trigger a stderr warning so reviewers see them.
- The copy strategy emits a per-file unified diff so the patch remains applicable even though there is no underlying Git history.

On success the command prints a per-file summary plus a `wrote: <path> (<n> bytes)` line.

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
  cmd/ai-env/         # CLI entry point (Cobra wiring)
  internal/cli/       # Command implementations (RunNew, RunList, RunDiff, RunPatch)
  internal/config/    # Config structs, YAML loader, validators
  internal/workspace/ # Workspace strategies (worktree, copy), diff, patch, protected matcher
  .github/workflows/  # CI pipeline
  plan.md             # Current plan in progress
  plans/              # Historical planning artifacts
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

## License

Not yet specified.
