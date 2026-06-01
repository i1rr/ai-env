# `.ai-env/secrets.local.yaml`

`.ai-env/secrets.local.yaml` is the gitignored file every operator
edits to wire host-side credentials into a run. The host-side
ProviderProxy reads it to learn the raw provider API key it injects
upstream; the GitHub broker reads it for the App private key (or PAT
fallback) it uses to mint a short-lived push token. The agent inside
the sandbox never sees this file.

This document is the schema reference, the permission contract, and
the day-to-day operator playbook.

Read it together with [`model-credentials.md`](model-credentials.md)
(how the raw credential gets turned into an in-sandbox env var or a
proxy URL), [`mcp-security.md`](mcp-security.md) (MCP servers do not
read this file; they have their own registry), and the
[`operator-runbook.md`](operator-runbook.md) (the broader workflow).

## File location

- Path: `.ai-env/secrets.local.yaml` at the project root (next to
  `policy.yaml` / `ai-env.yaml`).
- Owner: the operator. `ai-env new` writes a documentation-only stub;
  the operator is expected to fill in real values out of band.
- Git: must be gitignored. `ai-env new` appends the gitignore entries
  under an `# ai-env` section when `.gitignore` exists; when it does
  not, the suggested entries are printed to stdout.

## Permissions

- Required mode: `0600` (constant `DesiredLocalConfigMode` in
  `internal/secrets/local.go`).
- Mode check: the loader stat's the file on every load. If any
  group / other bit is set the loader still returns the parsed config
  but attaches a `PermissionWarning`. The supervisor turns each
  warning into a `secrets_permission_warning` lifecycle event so a
  reviewer can correlate later activity with the permission state at
  load time.
- The warning is not a hard error. Refusing to load would shift the
  leak surface, not reduce it: the run would proceed with no provider
  credential and the agent would have to be supplied a credential by
  some other path. Fix the mode with:

```sh
chmod 0600 .ai-env/secrets.local.yaml
```

- Windows skips the mode check (file modes mean little there).

## Schema

```yaml
version: 1
secrets:
  providers:
    anthropic:
      api_key: "sk-ant-..."
    openai:
      api_key: "sk-..."
  github:
    app:
      app_id: 12345
      installation_id: 67890
      private_key_pem: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----
      api_base_url: "https://api.github.com"  # optional
    pat:
      enabled: true
      token: "ghp_..."
      ttl_seconds: 1800                       # optional
```

### Top-level keys

| Key       | Type   | Required | Meaning |
|-----------|--------|----------|---------|
| `version` | int    | yes      | Schema version. Must equal `1` (`LocalConfigSchemaVersion`). Any other value is a hard error so a corrupt file cannot be silently ignored. |
| `secrets` | object | yes      | Container for the credential maps. |

### `secrets.providers.<name>`

A map of lower-cased provider identifiers to per-provider credential
blocks. The recognized names today are `anthropic` and `openai`.
Unknown keys are tolerated at decode time but ignored by
`BuildProviderProxyFromSecrets` so a typo does not silently wire a
non-existent provider.

| Field     | Type   | Required | Meaning |
|-----------|--------|----------|---------|
| `api_key` | string | yes (per provider you want enabled) | The raw provider API key. Empty means "operator has not filled this in yet"; the proxy skips the provider rather than wiring an empty token. |

### `secrets.github`

Optional. nil means "no GitHub credential configured"; the broker's
`SelectTokenSource` surfaces that as `ErrNoTokenSource` at
`AcquireToken` time.

| Field | Type   | Meaning |
|-------|--------|---------|
| `app` | object | GitHub App installation credential (preferred). |
| `pat` | object | Personal Access Token fallback. |

Both may be set. `SelectTokenSource` picks `app` when present and
falls back to `pat`; the precedence rule is fixed in code.

### `secrets.github.app`

| Field             | Type   | Required | Meaning |
|-------------------|--------|----------|---------|
| `app_id`          | int    | yes      | GitHub App ID. |
| `installation_id` | int    | yes      | Installation id. |
| `private_key_pem` | string | yes      | The verbatim private-key PEM body (multi-line YAML literal). PKCS#1 or PKCS#8. |
| `api_base_url`    | string | optional | Defaults to `https://api.github.com`. Override for GitHub Enterprise. |

The broker signs a fresh App JWT (`alg: RS256`, `iat: now-60s`,
`exp: now+9min`, `iss: AppID`) on every `AcquireToken` call using only
`crypto/rsa` and `encoding/base64` (no third-party JWT or GitHub SDK
dependency). The JWT is exchanged at
`POST /app/installations/<id>/access_tokens` for an installation
token; the response's `expires_at` becomes the holder's TTL (clamped
by `ClampTTL`).

### `secrets.github.pat`

| Field         | Type   | Required | Meaning |
|---------------|--------|----------|---------|
| `enabled`     | bool   | yes      | Must be `true` for the source to be considered. |
| `token`       | string | yes (when `enabled: true`) | The personal-access token. |
| `ttl_seconds` | int    | optional | Holder-side TTL clamp. Defaults to 1800s; floor 60s, ceiling 1800s. |

Revocation at the issuer is a no-op (the legacy authorizations
endpoint is gone and fine-grained PATs are not deletable by an API
token), but `TokenHolder.Revoke` still scrubs the local copy of the
byte slice in place.

## Loader contract

The loader is `LoadLocal` in `internal/secrets/local.go`. The contract
matches the rest of `internal/config`'s pattern:

- Missing file: not an error. A fresh workspace has the stub on disk
  with mode 0600 and the operator has not filled it in yet. The
  supervisor fans out from there: "no anthropic credential
  configured" surfaces downstream as a launcher resolution failure,
  not a file-read error.
- Empty file (the YAML-comment-only stub `ai-env new` writes): treated
  as "no credentials". The loader returns a non-nil `*LocalConfig`
  with the default version stamped so the upstream caller does not
  need a nil check.
- YAML parse errors: hard error.
- Schema-version mismatch (any value other than `1`): hard error.
- Unknown top-level keys: hard error (the decoder uses
  `KnownFields(true)`). A misspelled `providors:` surfaces as a parse
  error rather than a silent no-credentials state.
- Permission anomaly (mode broader than 0600): warning, not error.
  See the "Permissions" section above.

## How the credentials are used

### Provider credentials

`BuildProviderProxyFromSecrets` (in `internal/secrets/build.go`) walks
`secrets.providers` and constructs one `ProviderProxy` per provider
with a non-empty `api_key`. Each proxy:

- Binds on `127.0.0.1` with an OS-picked port.
- Pins exactly one upstream host (`api.anthropic.com` for Anthropic,
  `api.openai.com` for OpenAI); requests targeting any other Host are
  refused with HTTP 502.
- Attaches the configured `api_key` to the request as a host-side
  authorization header (`x-api-key` for Anthropic, `Authorization:
  Bearer ...` for OpenAI).
- Logs every request through `RedactSecrets` so the raw token never
  appears in `network-events.jsonl` or any captured log line.

The agent inside the sandbox sees the proxy URL via
`ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` (one env var per active
provider). The raw token never enters the sandbox process
environment.

### GitHub broker

`BuildBrokerFromSecrets` consumes `secrets.github` and constructs the
broker's `TokenSource`. The selection rule is fixed: when
`secrets.github.app` is non-nil the App source is used and any error
parsing the PEM bubbles up so a misconfigured App never silently
degrades to PAT; otherwise the PAT fallback is consulted; otherwise
`ErrNoTokenSource` is returned and the CLI tells the operator to
configure one path or the other.

Token lifecycle:

- `AcquireToken` runs at every `PushBranch` entry. App tokens are 1
  hour, non-renewable; mid-call refresh is out of scope.
- The raw bytes live in an in-memory `TokenHolder` as a `[]byte` so
  `Revoke` / `Forget` can overwrite in place. The agent never sees
  the raw bytes.
- `RevokeToken` runs at exit (via a deferred call so a mid-lifecycle
  failure still scrubs the credential). Best-effort: a failed issuer
  call is logged as a redacted warning, but the local scrub still
  runs and the credential expires naturally at `IssuedAt + TTL`.

## Rotation

There is no daemon. The broker constructs a fresh `TokenSource` on
every run, so the next `ai-env pr` picks up the new credential after
a simple file edit:

```sh
# Anthropic / OpenAI key rotation
$EDITOR .ai-env/secrets.local.yaml      # replace api_key
chmod 0600 .ai-env/secrets.local.yaml   # if your editor reset mode

# GitHub App key rotation
$EDITOR .ai-env/secrets.local.yaml      # replace private_key_pem
chmod 0600 .ai-env/secrets.local.yaml
```

Tokens already in flight expire naturally at their TTL; new runs use
the new credential immediately.

## Common pitfalls

- The agent CLI is configured with `ANTHROPIC_API_KEY` in its own
  environment outside ai-env. The supervisor scrubs the raw env var
  before launching the agent: the agent sees only the proxy URL.
  Setting `ANTHROPIC_API_KEY` in the operator's shell does not bypass
  the proxy; it just leaks the credential into the operator's
  process tree.
- `secrets.local.yaml` lives at the project root, not at `$HOME`. A
  per-project file is the contract so two projects on the same host
  can hold different credentials.
- The example file `.ai-env/secrets.example.yaml` is committed; the
  actual credential file `secrets.local.yaml` is gitignored. Do not
  rename the example to populate it.
- The mode check is loose by design (group / other bits trigger a
  warning, not a refusal). Operators who want stricter enforcement
  should add an audit check to their CI.

## See also

- `internal/secrets/local.go`: `LocalConfig`, `LoadLocal`,
  `PermissionWarning`, `DesiredLocalConfigMode`.
- `internal/secrets/build.go`: `BuildProviderProxyFromSecrets`,
  `BuildBrokerFromSecrets`, `ErrNoProviderCredentials`.
- `internal/secrets/proxy.go`: the `ProviderProxy` itself.
- `internal/githubbroker/auth.go`: `GitHubAppSource`, `PATSource`,
  `SelectTokenSource`.
- [`model-credentials.md`](model-credentials.md): the three canonical
  credential modes and selection rules.
- [`operator-runbook.md`](operator-runbook.md): broader workflow,
  including credential rotation.
