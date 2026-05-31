# Model credentials

This document is the operator reference for how `ai-env` handles model
provider credentials (Anthropic, OpenAI). It covers where the
credential lives, how it reaches the agent, what the provider proxy
does and does not do, what gets logged, and how rotation works.

Read this together with [`threat-model.md`](threat-model.md) (which
treats the provider as a trusted infrastructure dependency, not a
security boundary) and
[`enforcement-boundaries.md`](enforcement-boundaries.md) (which lists
the provider proxy as a partially-bypassable preventive control: the
agent can use the proxy URL but never sees the token).

## The cardinal rule

> The raw provider token lives on the host. The sandbox sees a loopback
> proxy URL, not the secret. The agent never receives the token unless
> the operator explicitly opts into raw-env injection.

Every credential mode below is one implementation of that rule, or an
explicit exception to it.

## The three credential modes

`ai-env` understands three credential-injection modes. The canonical
names live in `internal/agents/agents.go` (`CredentialModeBackendManaged`,
`CredentialModeProviderProxy`, `CredentialModeRawEnvExplicit`) and the
run-record mirror lives in `internal/run/record.go`
(`ModelCredentialBackendManaged`, `ModelCredentialProviderProxy`,
`ModelCredentialRawEnvExplicit`). The same strings show up verbatim in
`.ai-env/secrets.example.yaml`, `.ai-env/agents.yaml`, the resolver
diagnostics, and the per-run `run.json` field `model_credential_mode`.

### 1. `backend_managed` (safest)

The backend brokers the provider credential per-call. The token never
enters the agent's process environment. The supervisor records the
mode in `run.json` as `"backend_managed"` and the resolver returns
`InjectedEnv: nil`.

This mode requires the backend to advertise managed-credential support
via `EnvironmentProbe.BackendManaged=true`. The primary `docker_sbx`
backend does not advertise this in v0.1 (the field is reserved for
future per-call brokering); the resolver falls back to
`provider_proxy` when `backend_managed` is not available.

Selection logic: `internal/agents/agents.go`
`ResolveCredentialModeDetailed` — case `CredentialModeBackendManaged`.

### 2. `provider_proxy` (v0.1 default for agents that support a custom base URL)

The host runs a loopback HTTP reverse proxy that fronts exactly one
provider (Anthropic or OpenAI). The agent is pointed at the proxy via
`ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL`, the proxy injects the
provider's auth header server-side, and the raw token never crosses
into the sandbox.

This is the mode the registered agents (`internal/agents/claude/claude.go`,
`internal/agents/codex/codex.go`) prefer when `backend_managed` is
unavailable: both declare
`FallbackOrder: []string{agents.CredentialModeProviderProxy,
agents.CredentialModeRawEnvExplicit}`.

The proxy implementation is `internal/secrets/proxy.go`
(`ProviderProxy`). What it does is documented in detail below.

### 3. `raw_env_explicit` (reduced safety, opt-in)

The supervisor injects the raw provider token into the agent's process
environment (e.g., `ANTHROPIC_API_KEY=sk-...`). This defeats the proxy
boundary: every process running inside the sandbox can read the
variable.

Selection requires three things to all be true:

1. The agent contract lists `raw_env_explicit` in its
   `credential_mode.default` or `fallback_order`.
2. The operator passes `--allow-raw-model-token-in-sandbox` (wired as
   `allowRawToken` to `ResolveCredentialModeDetailed`).
3. The conventional host env var (`ANTHROPIC_API_KEY` for Claude,
   `OPENAI_API_KEY` for Codex; see
   `internal/cli/agents.go::rawTokenEnvForAgent`) is set.

When this mode is selected, the resolver sets `RequiresWarning=true`,
the supervisor flips `Record.ReducedSafety` to `true`, the per-run
`run.json` records `model_credential_mode: "raw_env_explicit"`, and a
reduced-safety banner is printed. Plain-text discovery later in the
audit trail is therefore one `jq` query on every run.

`agents.IsRawTokenMode` is the canonical check; the supervisor and
doctor surfaces use it instead of comparing the literal string.

## Where credentials live

| Location                                | What is there                                                                                          | Notes                                                                                          |
|-----------------------------------------|--------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| `.ai-env/secrets.local.yaml`            | Operator-edited credential values (e.g., `anthropic.api_key`).                                         | Gitignored. `ai-env new` writes a 0600-mode stub via `writeSecretsLocalStub` and re-chmods on overwrite. |
| `.ai-env/secrets.example.yaml`          | Provider list + mode declarations. Never holds real credentials.                                       | Validator (`internal/config/loader.go::ValidateSecretsExample`) enforces structural fields only. |
| Host process environment (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) | Operator-managed raw tokens, used only when `raw_env_explicit` is selected.                            | Read by the supervisor on the host; not normally copied into the sandbox env.                  |
| Provider proxy memory (`ProviderProxy.token`) | The token used by the active run, held only while the proxy is running.                                | Lives in host process memory only. Zeroed when the proxy stops.                                |
| Sandbox environment                     | `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` pointing at the proxy.                                        | The token itself is NOT present unless `raw_env_explicit` was selected.                        |

`.ai-env/secrets.local.yaml` is added to `.gitignore` automatically by
`internal/cli/new.go` (see `gitignoreEntries` and the
`updateGitignore` flow). If the project has no `.gitignore`, the
entries are printed as suggestions; they are not written silently.

## How the credential reaches the agent

The flow for the default (`provider_proxy`) mode:

1. **Host startup.** The supervisor reads the credential from
   `secrets.local.yaml` or the conventional host env var (depending on
   the operator's configuration). The credential never leaves the
   host process.
2. **Proxy construction.** `secrets.NewProviderProxy` is called with
   `Options{Provider, Token, ...}`. Construction validates the
   provider against `providerHosts` (the pinned upstream map) and
   rejects an empty token. The proxy has not bound a listener yet;
   construction failure aborts the run before the agent starts.
3. **Proxy bind.** `ProviderProxy.Start` calls `net.Listen` on a
   loopback address (default `127.0.0.1:0`). A non-loopback
   `ListenAddr` is rejected by `validateLoopbackAddr` so a typo like
   `0.0.0.0:0` fails closed instead of exposing the proxy to the host
   network. The OS-picked port is read back via `URL()`.
4. **Sandbox env injection.** The supervisor calls the agent launcher
   with the resolver's `InjectedEnv`, which is one of:
   - `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>` (for Anthropic), or
   - `OPENAI_BASE_URL=http://127.0.0.1:<port>` (for OpenAI), or
   - both (when the proxy provider is unspecified).
   See `internal/agents/agents.go::providerProxyEnv` for the exact
   mapping.
5. **Request flow.** The agent inside the sandbox issues an HTTPS-shaped
   request to the proxy URL (the request is actually plain HTTP because
   the base URL is `http://`). The proxy's `director` rewrites the
   request:
   - `Scheme` set to `https`, `Host` set to the pinned upstream
     (`api.anthropic.com` for Anthropic, `api.openai.com` for OpenAI).
   - Any inbound `Authorization` and `x-api-key` headers are deleted.
     A sandbox-side credential cannot smuggle itself through.
   - The host-side credential is installed: `x-api-key: <token>` plus
     `Authorization: Bearer <token>` for Anthropic, `Authorization:
     Bearer <token>` for OpenAI.
   - `X-Forwarded-For` / `X-Forwarded-Host` / `X-Forwarded-Proto` are
     stripped so the upstream sees only the proxy.
6. **Upstream call.** The proxy opens an HTTPS connection to the pinned
   upstream and forwards the request. Response bytes stream back to
   the agent unbuffered (so SSE / line-delimited JSON works).
7. **Shutdown.** When the run ends, the supervisor calls
   `ProviderProxy.Stop`. The HTTP server drains in-flight requests
   (bounded by `ShutdownTimeout`, default 2 seconds) and the listener
   closes. `ProviderProxy.Close` is an alias for `Stop` so the proxy
   can be deferred like any other `io.Closer`.

## What the provider proxy is and is not

The proxy is a deliberately narrow shim. Reading
`internal/secrets/proxy.go`'s package doc is the authoritative source;
the summary below is for quick reference.

The proxy **is**:

- **A plain HTTP server on loopback.** No TLS termination toward the
  sandbox; the agent talks to `http://127.0.0.1:<port>`. Upstream
  traffic is HTTPS.
- **Single-upstream.** Each proxy fronts exactly one provider host.
  A request whose `Host` header / URL targets a different host is
  rewritten to the configured upstream; the proxy is a one-upstream
  device and accepts that contract.
- **Host-side auth.** The provider auth header is injected on the
  host, from the host's view of the token. The sandbox never holds the
  bytes.
- **Per-run.** The supervisor starts a fresh proxy per run and stops
  it on terminal transition. Two concurrent runs get two ports.

The proxy is **not**:

- **A TLS-MITM proxy.** The plan's "No TLS MITM in v0.1" rule is the
  constraint; the proxy speaks plain HTTP to the sandbox and HTTPS
  upstream. The sandbox does not receive a fabricated cert.
- **A general egress proxy.** The proxy only forwards to one
  provider. It is not a substitute for the network egress policy in
  `internal/network/network.go`.
- **An identity check.** Plan section 19's "accepts requests only
  from the active run identity or sandbox route" is partially deferred
  to v0.2; in v0.1 the route side is enforced by the backend's network
  adapter (the proxy is reachable only via the backend-approved alias
  / loopback).
- **A per-request audit log.** The redacted log line is the v0.1 audit
  trail. A structured per-request event log is a future plan.

## What is and is not logged

Every proxy log line passes through
`secrets.RedactSecrets` before it is written. The patterns are
inlined in `secrets/proxy.go::secretPatterns`:

- `sk-ant-...` (Anthropic-style keys).
- `sk-...` (OpenAI / generic 20+ char keys).
- `Authorization: Bearer <...>` headers (the whole header is
  replaced).
- `x-api-key: <...>` headers (the whole header is replaced).

The proxy emits one line per request lifecycle event:

- On start: `provider_proxy: started provider=<name> url=<loopback> upstream=<host>`.
- On every request: `provider_proxy: request method=<verb> path=<path>`.
- On every response: `provider_proxy: response status=<code> path=<path>`.
- On upstream failure: `provider_proxy: upstream error path=<path>: <redacted error>`.
- On stop: `provider_proxy: stopped provider=<name>`.

The path itself passes through `RedactSecrets`, so a streamed token in
a query string is scrubbed too. The lines land in the host-side
writer the supervisor wires up (today: the run's stderr stream); they
are not visible inside the sandbox because the sandbox has no path to
the host log file.

What is **never** logged:

- The raw token value (constructed-into-headers in `director`,
  scrubbed if it ever appears in an error body).
- The Authorization or x-api-key header value (always replaced with
  `REDACTED`).
- The agent's full request body or response body (the proxy forwards
  bytes verbatim without logging them).

What **is** visible to the agent:

- The proxy URL (`ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`).
- The upstream's response (status, headers, body).
- Whatever error the proxy emits on upstream failure: a generic
  `"upstream error"` body with HTTP 502.

What is visible to other processes on the host:

- The proxy's loopback port (any process running as the same OS user
  can `curl http://127.0.0.1:<port>/...`).
- The proxy's log file (whatever the supervisor's writer wrote to).
- The proxy's process memory (`/proc/<pid>/mem` for the same OS user).

This is one of the residual risks documented in
[`residual-risk.md`](residual-risk.md) §8 ("Provider token theft from
the host"): `ai-env` does not isolate the proxy from co-tenant
processes on the host.

## Per-run record of the credential mode

Every run records its credential mode in `run.json`:

```json
{
  "model_credential_mode": "provider_proxy",
  "reduced_safety": false,
  ...
}
```

`reduced_safety: true` is set only when `model_credential_mode ==
"raw_env_explicit"`. The combination is the audit trail's hook for
finding raw-token runs: a periodic `jq '.reduced_safety == true'`
sweep across all runs surfaces every run that used the reduced-safety
mode.

The agent doctor (`ai-env agents doctor`) also surfaces the credential
mode each registered agent will use, including which raw-env variable
must be set (`ANTHROPIC_API_KEY` for Claude, `OPENAI_API_KEY` for
Codex) and whether that variable is currently present. See
`internal/cli/agents.go::rawTokenEnvForAgent` and the surrounding
notes block.

## Key rotation guidance

`ai-env` does not rotate model provider tokens for you. The rotation
contract sits entirely on the host:

1. **Rotate at the provider.** Issue a new key in the provider's
   console, mark the old one for revocation.
2. **Update `secrets.local.yaml` or the host env var.** Write the new
   value into whichever source `secrets.local.yaml` or the host env
   var maps to for your operator setup.
3. **Restart in-flight runs.** The proxy reads the token at
   construction (`Options.Token`); a new value takes effect on the
   next `NewProviderProxy` call. A run that is already running keeps
   the token it started with until it stops.
4. **Revoke the old key.** After confirming the new key works, revoke
   the old key at the provider.
5. **Audit `run.json` for `reduced_safety: true`.** If any historical
   run used `raw_env_explicit`, treat the token as having been
   present in every process inside that run's sandbox (including any
   dependency `npm install`/`pip install` ran).

Recommended cadence: rotate provider keys on the same schedule you
rotate any other long-lived cloud credential (90 days is a common
default). Rotate immediately if:

- A run with `reduced_safety: true` consumed a dependency you no
  longer trust.
- A host that ran `ai-env` was compromised by another process.
- A `secrets.local.yaml` was accidentally committed (the gitignore
  entries `ai-env new` adds are meant to prevent this; verify after
  the fact).

The threat model does not promise a leaked or compromised provider
token can be recovered without rotation. Rotation is the boundary; the
proxy reduces the surface that touches the token, but it cannot undo
exposure.

## GitHub credentials are NOT model credentials

This document covers model API credentials (Anthropic, OpenAI). GitHub
credentials follow a separate path through `internal/githubbroker/`
(`TokenHolder`, `PATSource`, the broker lifecycle). The agent never
receives a GitHub token in the sandbox; pushes and PR-creates happen
on the host via the broker. See `internal/githubbroker/auth.go` and
the enforcement-boundaries doc for the broker's contract.

## Quick checklist for operators

Before starting a run that hits a model provider:

1. Is `secrets.local.yaml` the only place your raw token lives, and
   is it gitignored? (`ai-env new` should have done this; verify with
   `git check-ignore .ai-env/secrets.local.yaml`.)
2. Does `ai-env agents doctor` report the credential mode you expect
   (`provider_proxy`, not `raw_env_explicit`)?
3. Are you about to pass `--allow-raw-model-token-in-sandbox`? If so,
   the run will record `reduced_safety: true`; check whether that is
   what you want.
4. When the run finishes, does `run.json`'s
   `model_credential_mode` field match your intent?
5. Is your rotation schedule live? Tokens that never rotate are
   tokens an attacker has indefinite time to find.

If any answer is "I do not know", stop and address it before relying
on the run's output.
