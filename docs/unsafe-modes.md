# Unsafe modes

This document enumerates every operator-facing flag, config field, or
opt-in that relaxes one of the threat model's defaults. Each entry
names the real flag, points at the code that consumes it, describes
exactly what it weakens, and gives the explicit "do not use in
production" guidance the threat model relies on.

Read this together with [`threat-model.md`](threat-model.md) (which
defaults the tool to the safe posture), [`backends.md`](backends.md)
(which describes the primary and fallback backends the flags below
toggle between), and [`residual-risk.md`](residual-risk.md) §11
("Operator opts into unsafe modes"), which summarises the audit trail
each opt-in leaves behind.

## The cardinal rule

> The safe posture is the default. Every flag in this document is an
> explicit operator decision to weaken one boundary. None of them
> should appear in a production-facing autonomous workflow without a
> documented justification and a recorded audit trail.

Every flag below is consumed by code we can point at. If a flag is not
in this document, it does not weaken the threat model.

## Summary table

| Opt-in                                | What it weakens                                                                | Owning code                                                                                                                       |
|---------------------------------------|--------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `--accept-reduced-isolation` / `sandbox.accept_reduced_isolation: true` | Enables the rootless `docker` / `podman` fallback backends; shares host kernel. | `internal/backend/docker/docker.go` (`Options.AcceptReducedIsolation`), `internal/backend/podman/podman.go` (same), `internal/config/ai_env.go` (`SandboxSection.AcceptReducedIsolation`). |
| `--unsafe-host-network`               | Lets the fallback backend reach the host network; defeats the egress policy.   | `internal/backend/docker/docker.go` and `internal/backend/podman/podman.go` (`Options.UnsafeHostNetwork`).                          |
| `--allow-untested-backend-version`    | Lets the `docker-sbx` adapter launch on an `sbx` version outside the tested range. | `internal/backend/docker_sbx/docker_sbx.go` and `internal/backend/docker_sbx/compat.go` (the `TestedVersionRange` gate).             |
| `--allow-raw-model-token-in-sandbox`  | Injects the raw provider token into the agent's process environment.            | `internal/agents/agents.go` (`ResolveCredentialModeDetailed`, the `allowRawToken` parameter; `RequiresWarning=true` on selection). |
| `secrets.raw_env_injection: true` (in `policy.yaml`) | Permits raw-env credential injection at the policy level; surfaced by `ai-env policy check` as a warning. | `internal/config/policy.go` (`SecretsPolicy.RawEnvInjection`), `internal/cli/policy.go` (warning emitter).                          |
| `secrets.providers.<name>.mode: raw_env_explicit` / `raw_env_explicit_only` | Declares the provider's preferred credential path as raw-env injection in `secrets.example.yaml`. | `internal/config/loader.go::ValidateSecretsExample` (the mode allowlist).                                                          |
| `--shell-shim` (opt-in, prototype)    | Does NOT weaken anything. Listed for completeness because its absence is the default and its limitations are easy to misread. | `internal/run/supervisor.go` (`SupervisorOptions.ShellShim`), `internal/policy/shim.go` (`Shim`).                                  |

The remainder of this document is one section per opt-in.

## `--accept-reduced-isolation` / `sandbox.accept_reduced_isolation`

### What it does

Enables the rootless `docker` or `podman` fallback backend for
autonomous mode. Without it, `Detect()` on either fallback returns
`Available: false` with a message that names the missing flag and
includes the verbatim `ReducedIsolationWarning`.

The CLI flag is wired into the backend constructor's
`Options.AcceptReducedIsolation` (`internal/backend/docker/docker.go`
and `internal/backend/podman/podman.go`); the config field is
`SandboxSection.AcceptReducedIsolation` in
`internal/config/ai_env.go`. The default value in the config written
by `ai-env new` (`internal/cli/new.go::defaultAIEnvConfig`) is
`false`.

### What it weakens

- **Backend kernel boundary.** The rootless fallbacks share the host
  kernel. A container-runtime or kernel exploit reaches the host
  directly.
- **The primary-vs-fallback contract.** The threat model considers
  only `docker-sbx` a real kernel boundary; opting into a fallback
  moves the run into the "reduced isolation" residual-risk bucket
  (see `residual-risk.md` §1 and §11).

The verbatim warning the adapter prints on `Detect()` once the flag
is acknowledged is in both fallback adapters'
`ReducedIsolationWarning` constant:

```text
WARNING: This backend provides reduced isolation. It is suitable for
development and testing, but not for high-risk autonomous execution
with untrusted dependencies or secrets.
```

### Do not use in production

Do not pass this flag for:

- Untrusted dependencies you have not seen before.
- Autonomous runs with real production-adjacent credentials.
- Multi-tenant workstations.

Use it for local development of `ai-env` itself, for CI of `ai-env`,
or on a fully scratch host you are willing to treat as compromised
after the run. See `backends.md` for the trade-off matrix.

## `--unsafe-host-network`

### What it does

Wires `Options.UnsafeHostNetwork=true` into the `docker` or `podman`
fallback adapter. Without it, the fallback container runs with
`--network none` (no egress at all). With it, the container is brought
up on the host network (`--network host`) so the agent can reach
hosts the network policy might otherwise allowlist.

This flag is **only** meaningful in combination with
`--accept-reduced-isolation`: without that, the fallback backend
refuses to start at all.

### What it weakens

- **Network egress policy.** With `--network host` the container
  shares the host's network namespace. The egress allowlist cannot
  meaningfully constrain the agent at the container layer.
- **Always-blocked CIDRs.** The fallback explicitly refuses to install
  an allowlist policy when `UnsafeHostNetwork=true` is set, returning
  the error
  `"docker: cannot enforce allowlist on rootless fallback with
  --unsafe-host-network; remove allow_domains or run on the docker-sbx
  backend"` (and the symmetric podman variant). The flag is therefore
  incompatible with operators who want both an allowlist AND fallback
  isolation; the only way to have both is the `docker-sbx` backend.

The four forced-block flags `BlockPrivateRanges`,
`BlockMetadataServices`, `BlockLocalhost`, and
`BlockHostDockerInternal` from `internal/network/network.go` are still
true at the policy layer, but the backend adapter has no place to
install them when the container shares the host network.

### Do not use in production

Do not pass this flag for any autonomous run that touches:

- Credentials that resolve through the host's DNS or routing.
- Internal services on the host's RFC1918 network.
- A multi-tenant network (corporate VPN, cloud VPC, shared CI runner).

Use it only when both the host's network is itself a sandbox AND you
have already accepted the reduced-isolation posture.

## `--allow-untested-backend-version`

### What it does

Lets the `docker-sbx` adapter launch on an `sbx` CLI version outside
the tested range pinned in
`internal/backend/docker_sbx/compat.go`:

- `MinTestedVersion = "0.1.0"`.
- `MaxTestedVersion = "0.9.99"`.
- `TestedVersionRange = "0.1.0 - 0.9.99"`.

Without the flag, `Detect()` returns
`Available: false` with the message
`"sbx version <version> is outside the tested range <range>; pass
--allow-untested-backend-version to proceed"`. With the flag, the
adapter proceeds as if the version were supported.

### What it weakens

- **The compat gate.** Version pinning exists because `sbx`'s CLI
  surface and JSON output may change between runtime versions
  (`residual-risk.md` §2). An untested version may have flag renames,
  JSON shape changes, or silently-relaxed isolation. The adapter
  parses minimally to reduce the blast radius of a small change, but
  it cannot defend against a release that, for example, no longer
  honours the `--network` flag the adapter passes.
- **The "fail closed on unknown" rule.** With the flag, the adapter
  fails open on the version check: an unknown future version is
  treated as good.

### Do not use in production

Do not pass this flag unless you have:

- Manually re-run `tests/acceptance/` against the untested version
  and confirmed the suite passes.
- Reviewed the `sbx` release notes since `MaxTestedVersion` for
  isolation-impacting changes.
- Updated `MinTestedVersion`/`MaxTestedVersion` in
  `internal/backend/docker_sbx/compat.go` to cover the new version
  so the bypass becomes unnecessary.

The flag is a short-term escape hatch, not a long-term operating
mode. Pin the new version in the adapter rather than relying on the
flag in CI.

## `--allow-raw-model-token-in-sandbox`

### What it does

Allows the credential resolver to select the `raw_env_explicit` mode.
Wired as the `allowRawToken` parameter on
`internal/agents/agents.go::ResolveCredentialModeDetailed`. Without
it, every attempt to select `raw_env_explicit` fails with the
diagnostic `"raw token not allowed: pass
--allow-raw-model-token-in-sandbox"`.

When `raw_env_explicit` is selected:

- The resolver sets `RequiresWarning=true`.
- The supervisor sets `Record.ReducedSafety=true` and writes
  `model_credential_mode: "raw_env_explicit"` into `run.json`.
- The supervisor injects the conventional env var
  (`ANTHROPIC_API_KEY` for Claude, `OPENAI_API_KEY` for Codex; see
  `internal/cli/agents.go::rawTokenEnvForAgent`) into the agent
  process.

### What it weakens

- **The provider credential boundary.** The raw token is present in
  the agent's process environment. Every process the agent spawns
  inside the sandbox can read the variable, including `npm install` /
  `pip install` postinstall scripts and anything else with read
  access to `/proc/<pid>/environ`.
- **The proxy-as-redactor posture.** The redaction patterns in
  `secrets/proxy.go::secretPatterns` cannot scrub a value the agent
  exfiltrates directly through the network (the proxy is not on the
  path).
- **The "raw token never crosses into the sandbox" promise.** It is
  the explicit exception. See `docs/model-credentials.md` for the
  three credential modes and what each does.

### Do not use in production

Do not pass this flag for any run that:

- Installs dependencies you have not vendored yourself.
- Runs against a production-credentialed model account.
- Will be replayed via `--continue` (the workspace can carry
  instructions; once the token has been in the sandbox, treat it as
  exposed).

Use it only for short, fully-supervised diagnostic runs when the
provider proxy or backend-managed path is genuinely unavailable.
Rotate the provider key immediately after.

## `secrets.raw_env_injection: true` (policy)

### What it does

Sets the policy-level acknowledgement that raw-env credential
injection is permitted for this project. Stored in
`internal/config/policy.go::SecretsPolicy.RawEnvInjection`. The CLI
surface `ai-env policy check` (in `internal/cli/policy.go`) prints
the warning line:

```
secrets.raw_env_injection is true; raw credentials may be exposed to the agent
```

The default policy `ai-env new` writes
(`internal/cli/new.go::defaultPolicyConfig`) sets the field to
`false`.

### What it weakens

- **The policy-level prohibition on raw injection.** The field is the
  static side of the operator's intent; the runtime side is
  `--allow-raw-model-token-in-sandbox`. Both must agree before
  `raw_env_explicit` actually selects.
- **The principle of least surprise.** A run that uses raw injection
  will succeed silently if both the policy and the flag say so; the
  policy's `true` value removes one of the two questions the system
  would otherwise ask.

### Do not use in production

Do not set this to `true` in a `policy.yaml` that is checked into
version control without an accompanying note in the project README
explaining why. The warning at `ai-env policy check` time is the
visible audit; a silent `true` defeats the warning's purpose.

## `secrets.providers.<name>.mode: raw_env_explicit` / `raw_env_explicit_only`

### What it does

Sets the named provider's mode in `secrets.example.yaml` to
`raw_env_explicit` (the resolver's `raw_env_explicit` mode is
selectable when other modes fail) or `raw_env_explicit_only` (only
raw-env is allowed for this provider). The valid set is enforced by
`internal/config/loader.go::ValidateSecretsExample`:

```go
requireOneOf(..., "backend_managed", "brokered", "provider_proxy",
             "raw_env_explicit", "raw_env_explicit_only")
```

### What it weakens

- **The default-safe credential chain.** The intended default for new
  projects is `backend_managed` or `provider_proxy`; selecting the
  raw-env modes here is the static configuration counterpart of the
  runtime opt-in.
- **The `_only` variant additionally forbids fallback.** With
  `raw_env_explicit_only`, the resolver cannot try the safer modes
  first; any run that proceeds is a raw-token run.

### Do not use in production

Set the mode to `backend_managed` (when the backend supports it) or
`provider_proxy` (the v0.1 default for the registered agents). Use
the raw modes only in environments where the provider exposes no
other API surface; document the choice next to the field in your
checked-in `secrets.example.yaml`.

## `--shell-shim` (opt-in, prototype)

### What it does

Wires the shell shim prototype (`internal/policy/shim.go::Shim`) into
the supervisor (`internal/run/supervisor.go::SupervisorOptions.ShellShim`).
The shim binary is placed in front of `bash` and `sh` on the agent's
`PATH` and consults the policy engine for every shell command.

### What it does NOT weaken

This flag is listed for completeness because operators sometimes treat
it as a security feature; it is more accurately described as
"defense in depth that exists only when explicitly opted into".

- **Default state.** `--shell-shim` defaults to **off**. When off, the
  shim is not present; the agent's shell commands run unwrapped.
- **When on, it adds an audit trail and a conservative deny list.**
  See `enforcement-boundaries.md` "Shell shim limitations" for the
  exact set the shim cannot intercept (absolute paths, static
  binaries, interpreter-internal shell-outs, syscall-level execve).

### Do not rely on this as a security control

The shim is labelled "prototype" in the source. It is not the boundary
for shell behaviour; the network policy, the filesystem isolation, and
the backend isolation are. Treat the shim as a useful audit signal,
not as a substitute for any other layer.

## What is NOT an unsafe mode

The following are sometimes mistaken for unsafe modes; they are
documented here so operators do not look for a corresponding "safe
default".

- **`fallback_backend: docker` / `fallback_backend: podman`** in
  `ai-env.yaml`. The field by itself does nothing: the fallback's
  `Detect()` still requires `accept_reduced_isolation: true`. The
  field opts the run into the fallback chain only when the
  acknowledgement is also set.
- **The default policy's `commands.default: allow_in_sandbox`.** The
  default policy (`internal/cli/new.go::defaultPolicyConfig`) allows
  arbitrary commands inside the sandbox; the boundary is the sandbox
  isolation, not the command pattern. This is by design (the shim is
  opt-in; the backend is the boundary).
- **`policy.yaml` `network.tls_mitm: false`.** The runtime does not
  implement TLS MITM in v0.1 (the plan's "No TLS MITM in v0.1" rule);
  the field is documented in `config.NetworkPolicy.TLSMITM` but
  ignored by the runtime. Setting it to `true` does not enable MITM;
  it does not change behaviour at all.
- **`policy.yaml` `network.enforcement: backend`.** The default
  enforcement mode. The field is descriptive; the actual enforcement
  surface is the per-backend network adapter
  (`internal/network/network.go`).

## Forensic trail every unsafe opt-in leaves behind

| Opt-in                                | Visible in `run.json`                                  | Visible in stderr at run start                 |
|---------------------------------------|--------------------------------------------------------|------------------------------------------------|
| `--accept-reduced-isolation`          | `backend: docker` or `backend: podman`.                | `ReducedIsolationWarning` printed by `Detect`. |
| `--unsafe-host-network`               | (Inferred from backend choice.)                        | Backend logs the host-network mode at startup. |
| `--allow-untested-backend-version`    | (Inferred from `sbx` version field.)                   | `Detect` no longer aborts; supervisor proceeds. |
| `--allow-raw-model-token-in-sandbox`  | `model_credential_mode: "raw_env_explicit"`, `reduced_safety: true`. | Reduced-safety banner from the supervisor.     |
| `secrets.raw_env_injection: true`     | (Not in `run.json`; in `policy.yaml`.)                 | `ai-env policy check` warning before run.      |
| `--shell-shim`                        | (Not currently in `run.json`.)                         | None: the shim is silent on commands it allows. |

A periodic audit of historical runs can spot any unsafe opt-in by
greping `run.json` for `reduced_safety: true` or
`model_credential_mode: "raw_env_explicit"`, and by greping
`policy.yaml` for `raw_env_injection: true`. The plan's intent (see
`residual-risk.md` §11) is that every run that uses any unsafe mode
records the choice; this table is the operator's reference for what
to grep for.

## Quick checklist for operators

Before passing any flag in this document:

1. Have I read the corresponding section above and understood what
   the flag weakens?
2. Is there a primary-backend / safe-mode alternative that would
   work? (`docker-sbx` instead of the fallback; `provider_proxy`
   instead of raw env; pinning the new `sbx` version in
   `compat.go` instead of `--allow-untested-backend-version`.)
3. Will the run record the choice so an audit later can find it?
4. Am I prepared to rotate any credential that touched the run?
5. Is this run going to a production-facing artifact (a brokered PR,
   a release tag, a deployable image)? If yes, stop and use the safe
   defaults instead.

If any answer is "I do not know" or "no", do not pass the flag.
