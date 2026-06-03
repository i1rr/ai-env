# Wire up 'ai-env run' CLI plus 4 small UX fixes

## Overview

Создать недостающий cobra-сабкоманд `ai-env run`, который собирает уже готовые primitives (Supervisor, BackendAdapter, NetworkPolicyAdapter, ProviderProxy, MCP gateway, control socket, observer, scan hook, GitHubBroker) в полный жизненный цикл запуска агента. Параллельно зачистить четыре известных UX-дефекта CLI: stale hint в `status`, ложное предупреждение `workspace has no ai-env.yaml` в `list`, FAIL `(unknown mode)` для `brokered` в `agents doctor`, и неконсистентную папку `plans/`. После всего этого 7 из 19 MVP пунктов в `archive/full_plan.md` §37 разблокируются и три CLI-дефекта закроются.

## Context

- Files involved:
  - Create: `internal/cli/run.go`, `internal/cli/run_test.go`
  - Modify: `cmd/ai-env/main.go` (AddCommand + newRunCmd cobra-shell)
  - Modify: `internal/cli/status.go` + `internal/cli/status_test.go` (hint wording)
  - Modify: `internal/cli/list.go` + `internal/cli/list_test.go` (.env-meta.json fallback)
  - Modify: `internal/cli/agents.go` + `internal/cli/agents_test.go` (brokered mode)
  - Delete: `plans/README.md` (smaller fix per task description)

- Related patterns:
  - Cobra-builder: `newDoctorCmd`, `newDestroyCmd`, `newNewCmd` в `cmd/ai-env/main.go`; body живёт в `internal/cli/<cmd>.go` (`RunDoctor`, `RunDestroy`, `RunNew`).
  - Supervisor-wiring: `internal/run/supervisor.go` `SupervisorOptions` (BackendAdapter, NetworkPolicyAdapter, ProviderProxies, ControlSocket, EgressObserver, EgressRules, MCPGatewayMaterializer, ScanHook, DiffCollector).
  - Готовые сборщики: `secrets.BuildProviderProxyFromSecrets` (`internal/secrets/build.go`), `githubbroker.BuildBrokerFromSecrets` (`internal/githubbroker/build.go`), `cli.BuildRunGateway` / `cli.MaterializeRunGateway` (`internal/cli/build_gateway*.go`), `run.MaterializePerRunMCPConfig` (`internal/run/mcp_per_run_config.go`), `run.NewControlSocket` (`internal/run/control_socket.go`), `run.CreateRunDirectory` / `RunIDGenerator` (`internal/run/run.go`).
  - Backend adapters: `internal/backend/docker_sbx/.New`, `docker/.New`, `podman/.New`, `mock/.New` (общий interface `backend.Backend`).
  - Agent launchers: `internal/agents/claude` и `internal/agents/codex` (`Plan(req, probe, env) -> backend.Command + StdinBody`).
  - Workspace metadata: `internal/workspace/worktree.go` `envMetadata` + `MetadataPath(aiEnvDir, envName)`, файл `.env-meta.json` под `.ai-env/workspaces/<env>/`.

- Dependencies: `spf13/cobra`, `gopkg.in/yaml.v3` (уже в go.mod). Никаких новых внешних библиотек.

## Development Approach

- Testing approach: Regular (code first, then tests per файл).
- Сначала закрыть мелкие баги (Tasks 1-3) чтобы их регрессии не маскировались работой над `run`.
- Затем самая объёмная работа, `internal/cli/run.go` (Task 4), с собственным `run_test.go`, мокающим backend через `internal/backend/mock`.
- CRITICAL: каждый task ОБЯЗАТЕЛЬНО включает новые/обновлённые тесты.
- CRITICAL: перед началом следующего task все тесты должны проходить (`go test -race ./internal/cli/... ./internal/run/...`).
- Acceptance suite (`tests/acceptance/*.go` с build-tag `acceptance` и `AI_ENV_ACCEPTANCE=1`) требует docker и относится к Post-Completion, не к чекбоксам тасков.

## Implementation Steps

### Task 1: Fix 'ai-env agents doctor' brokered credential mode

**Files:**
- Modify: `internal/cli/agents.go`
- Modify: `internal/cli/agents_test.go`

- [x] В `evaluateCredentialMode` (`agents.go` ~ строка 332) добавить case `"brokered"` в switch: ставит `pass = true` и note `"brokered (validated at run time)"` (по аналогии с `backend_managed`).
- [x] Поправить `defaultAgentsConfig` в `internal/cli/new.go` если требуется, там `Default: "brokered"` уже стоит (verify).
- [x] Добавить unit-test в `agents_test.go`: контракт с `CredentialMode.Default = "brokered"` должен дать PASS, не FAIL.
- [x] `go test -race ./internal/cli/...`, должен проходить.

### Task 2: Fix 'ai-env list' to fall back to .env-meta.json

**Files:**
- Modify: `internal/cli/list.go`
- Modify: `internal/cli/list_test.go`

- [ ] В `readWorkspaceEntry` (`list.go` ~ строка 230) при отсутствии `ai-env.yaml` читать `.env-meta.json` через `workspace.MetadataPath(aiEnvDir, envName)` или прямой `filepath.Join(dir, ".env-meta.json")`. Заполнить `Strategy` и `Template` из metadata; убрать ложный warning `workspace has no ai-env.yaml` когда meta-файл присутствует.
- [ ] Если оба файла отсутствуют, warning остаётся (но текст переформулировать: «no ai-env.yaml or .env-meta.json»).
- [ ] Добавить test-case в `list_test.go`: workspace-каталог с только `.env-meta.json` (без `ai-env.yaml`), таблица показывает реальную стратегию и шаблон, warning не печатается.
- [ ] `go test -race ./internal/cli/...`, должен проходить.

### Task 3: Clean up plans/README.md

**Files:**
- Delete: `plans/README.md` (smaller fix per task description)

- [ ] Удалить `plans/README.md`. Файл ссылается на `plan_v3_1.md` и `plan_01_foundation.md` (не существуют); каноничные планы живут в `archive/plan_01_cli.md` … `archive/plan_10_leak_coverage_hardening.md` и упоминаются из README/CHANGELOG.
- [ ] Никаких тестов не требуется (доковый файл). Но проверить grep по репо: нет ли других файлов, которые ссылаются на `plans/README.md` или `plans/plan_*.md`. Если есть, заменить ссылку на `archive/`.
- [ ] `go test ./...` (быстрая sanity-проверка) должен проходить.

### Task 4: Wire up 'ai-env run' CLI subcommand

**Files:**
- Create: `internal/cli/run.go`
- Create: `internal/cli/run_test.go`
- Modify: `cmd/ai-env/main.go` (add `newRunCmd` builder + `root.AddCommand(newRunCmd())`)

- [ ] В `cmd/ai-env/main.go` добавить `newRunCmd()` cobra-builder с флагами:
  - `--agent` (string, default из `ai-env.yaml` `project.default_agent`)
  - `--task` (string, required)
  - `--continue` (bool)
  - `--shell-shim` (bool, прокидывается в `SupervisorOptions.ShellShim`)
  - `--observer-mode` (string, `auto|strict`, default `auto`)
  Зарегистрировать через `root.AddCommand(newRunCmd())`.
- [ ] В `internal/cli/run.go` создать `RunOptions` (`EnvName`, `Agent`, `Task`, `Continue`, `ShellShim`, `ObserverMode`, `Cwd`, `Stdout`, `Stderr`) и функцию `RunRun(opts RunOptions) error`.
- [ ] Внутри `RunRun`:
  - (a) `ValidateEnvName(opts.EnvName)`
  - (b) `findAIEnvDir(opts.Cwd)` → корень `.ai-env`
  - (c) `config.LoadAIEnv(.ai-env/ai-env.yaml)` для resolve `project.default_agent`, `sandbox.backend`, `sandbox.fallback_backend`, `sandbox.template`, supervision-таймауты
  - (d) Резолвить workspace path и metadata через `workspace.MetadataPath` (читать `.env-meta.json`)
  - (e) Загрузить `secrets.LocalConfig` (`secrets.local.yaml`) и собрать `ProviderProxies` через `secrets.BuildProviderProxyFromSecrets`
  - (f) Собрать broker через `githubbroker.BuildBrokerFromSecrets` (опциональный, может вернуть `ErrNoTokenSource`, тогда продолжать без broker)
  - (g) Выбрать backend по `sandbox.backend`: switch `docker-sbx|docker|podman|mock` → соответствующий `<backend>.New(...)`; на ошибку health-check падать на `sandbox.fallback_backend` если задан и не `none`
  - (h) `run.CreateRunDirectory(aiEnvDir, runID, time.Now())`, runID через `RunIDGenerator`
  - (i) Собрать MCP gateway через `BuildRunGateway` + `MaterializeRunGateway` + `MaterializePerRunMCPConfig`; зарегистрировать в `MCPGatewayMaterializer` + `MCPGatewayCloser`
  - (j) Создать `ControlSocket` через `run.NewControlSocket`
  - (k) Выбрать observer через `egress.ChooseObserver` (mode из флага)
  - (l) Построить `CommandSpec` через выбранный launcher (`claude.New().Plan(req, probe, env)` или `codex.New().Plan(...)`); прокинуть `StdinBody` в `SupervisorOptions.Stdin`
  - (m) `NewSupervisor(SupervisorOptions{...})` → `supervisor.Run(ctx)`
  - (n) При `--continue` подкладывать `LinkedPreviousRun` из последнего run id для env (через walk `.ai-env/runs/`)
  - (o) Маппить `SupervisorResult.FinalState` в exit-code (0 для `StateCompleted`, ненулевой для всех failure-terminals)
  - (p) Выводить путь к run directory и подсказку `--continue` (из `SupervisorResult.ContinueSuggestion`) в Stdout
- [ ] Канонические артефакты `lifecycle.jsonl`, `leaks.jsonl`, `transcript.jsonl`, `network-events.jsonl`, `final-summary.md` пишутся самим supervisor, `RunRun` ничего дополнительного не материализует, только проверяет наличие в логе на завершении.
- [ ] В `internal/cli/run_test.go` написать unit-тесты по образцу `new_test.go` / `doctor_test.go`:
  1. валидация флагов (отсутствует `--task` → ошибка)
  2. неизвестное env-имя → ошибка
  3. happy-path с `internal/backend/mock`: задаётся через test hook (LauncherFactory-аналог или прямой `BackendFactory` var на уровне пакета), проверяется создание run-каталога, наличие `lifecycle.jsonl`, exit-code 0
  4. fallback backend: основной backend Create возвращает ошибку → подхватывается fallback из `ai-env.yaml`
  5. `--continue` с предыдущим run → `LinkedPreviousRun` непустой в `run.json`
- [ ] Прогон `go test -race ./internal/cli/... ./internal/run/... ./internal/secrets/...` должен проходить.

### Task 5: Update 'ai-env status' hint after run is shipped

**Files:**
- Modify: `internal/cli/status.go`
- Modify: `internal/cli/status_test.go`

- [ ] В `RunStatus` (`status.go` строка 105) подкорректировать строку hint так, чтобы она отражала фактический UX shipped-команды `ai-env run`: упомянуть `--shell-shim`/`--observer-mode` опционально или хотя бы убедиться что текст не вводит в заблуждение (сейчас: `Start one with ai-env run <env> --agent <agent> --task "..."`). Оставить минимальный hint, но проверить что точно соответствует реальному cobra-Usage из Task 4.
- [ ] Если в Task 4 список флагов отличается, синхронизировать.
- [ ] Обновить `status_test.go`: snapshot test на «no runs yet» должен ловить новую строку.
- [ ] `go test -race ./internal/cli/...`, должен проходить.

### Task 6: Verify acceptance criteria

- [ ] Прогон `go build ./...`.
- [ ] Прогон `go test -race ./...`, все юнит-тесты зелёные.
- [ ] Прогон `go vet ./...` и `staticcheck ./...` (если в репо настроен), нет новых предупреждений.
- [ ] `go test -tags=acceptance -count=1 ./tests/acceptance/...` локально с `AI_ENV_ACCEPTANCE=1`, фиксируем какие из тестов теперь действительно прогоняются (не SKIP), какие требуют docker. Это manual smoke step, не строгий чекбокс.
- [ ] Сверить CLI с `archive/full_plan.md` §36 шаги 1-18 и §37 пункт 4-10, каждая lifecycle-фаза supervisor отражается в `lifecycle.jsonl`.

### Task 7: Update documentation

- [ ] В `README.md` обновить раздел «Manual smoke test» step 5: добавить пример `ai-env run demo --agent claude --task "..."` после `ai-env status demo`.
- [ ] В `README.md` обновить упоминания на строках 402/414/418/434 о том, что `ai-env run` всё ещё deferred, теперь это shipped; переписать соответствующие абзацы.
- [ ] `CHANGELOG.md`, добавить запись о новом `ai-env run` и трёх UX-фиксах.
- [ ] Не требуется обновлять `CLAUDE.md` (внутренние паттерны не менялись).
