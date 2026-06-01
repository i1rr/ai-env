package run

// shim_wire.go wires the optional shell-shim prototype (internal/policy)
// into the supervisor lifecycle. Plan 08 step 9 calls for exactly this
// piece: when an operator opts in via the future `ai-env run --shell-shim`
// CLI flag, the supervisor must:
//
//  1. Open a shell-commands.jsonl writer in the run directory so every
//     intercepted command lands on disk alongside the lifecycle and
//     policy-decisions trails.
//  2. Prepend a shim directory to the child process's PATH so the
//     wrapper binary (replacing bash / sh / etc.) is resolved before the
//     real system binary. The shim binary itself is constructed by the
//     caller (the future `ai-env run` CLI) and placed in ShellShimDir
//     before the supervisor is started; this file owns only the PATH
//     mutation and the log lifetime.
//
// The wiring is deliberately conservative:
//
//   - It is opt-in. ShellShim defaults to false; legacy supervisor
//     callers (plan-03 / plan-04 / plan-05 / plan-06 / plan-07 tests) see
//     no behavioral change.
//   - It requires a configured policy engine. Without an engine the
//     shim has no rule source, so NewSupervisor refuses ShellShim=true
//     without a PolicyEngine / PolicyEnginePath.
//   - It does NOT build the shim binary. The supervisor owns the wiring
//     surface (PATH injection, log open / close); the binary itself
//     lands in a later CLI batch when `ai-env run --shell-shim`
//     materializes the wrapper in ShellShimDir.
//
// Limitations the operator must understand are documented at the top of
// internal/policy/shim.go and surfaced in the README; the rule of thumb
// is "agents may use absolute paths, static binaries bypass wrappers,
// kernel-level controls remain the real boundary."

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rivan1986/ai-env/internal/policy"
)

// shimPathEnvKey is the name of the PATH environment variable the
// supervisor mutates when ShellShim is enabled. Defined as a constant so
// the test fixtures and the production wiring agree on the casing
// (POSIX) and so a future port that needs a different key (e.g. a
// case-insensitive Windows PATH) has a single place to switch.
const shimPathEnvKey = "PATH"

// DefaultShimHelperCmd is the in-sandbox command the supervisor writes
// into each wrapper's `exec` line at canonical pre-launch step 10 (Plan
// §5.5). The plan pins the `ai-env` binary's in-sandbox path to
// `/usr/local/bin/ai-env` (bind-mounted from the host-side binary at
// Create), so the wrapper invokes the helper subcommand via the same
// absolute path on every backend. Host-mode runs (BackendAdapter == nil)
// have no sandbox; the wrapper line still points at the in-sandbox path
// because the wrappers are NOT executed in host mode (the supervisor
// emits `shim_coverage_degraded` instead). Callers that want to drive
// the wrapper from a real host-side helper for a test can override the
// command via SupervisorOptions.ShimHelperCmd.
const DefaultShimHelperCmd = "/usr/local/bin/ai-env shim-helper"

// InjectShimPath returns a copy of env with the PATH entry rewritten so
// shimDir is the first directory the child sees. The helper is exported
// so the future `ai-env run` CLI can compose its own env construction
// without re-implementing the prepend rule.
//
// Rules:
//
//  1. If env already contains a PATH entry, the helper replaces it with
//     "<shimDir>:<existing_path>" so the original PATH is preserved
//     after the shim directory.
//  2. If env does not contain a PATH entry, the helper appends
//     "PATH=<shimDir>". The supervisor relies on inherited PATH only
//     when the caller passed env=nil; an explicit non-nil env with no
//     PATH means "child runs with PATH=<shimDir>" rather than "splice
//     the host PATH in." That keeps the behavior predictable for the
//     opt-in supervisor caller that hands the supervisor an explicit
//     env slice.
//  3. shimDir is inserted verbatim. Callers must pass an absolute path;
//     the helper does not resolve relative paths against the run dir
//     because the shim wrapper's location is the caller's concern.
//  4. A nil env returns a freshly allocated slice with one entry
//     ("PATH=<shimDir>"). A non-nil env is copied so the caller's
//     underlying array is never mutated.
//
// An empty shimDir returns env unchanged so a misconfigured caller
// (ShellShim=true but ShellShimDir="") does not produce a malformed
// PATH; NewSupervisor rejects that combination at construction time
// before this helper is reached, but the defensive return keeps the
// helper usable from other call sites.
func InjectShimPath(env []string, shimDir string) []string {
	if strings.TrimSpace(shimDir) == "" {
		// Defensive: see doc comment. NewSupervisor's validation is the
		// primary fence; this branch protects the helper from misuse.
		return env
	}

	// Copy first so the caller's slice is never mutated. A nil env
	// returns a fresh slice owned by the helper.
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, kv := range env {
		// PATH= or PATH=... per POSIX. We match the key exactly
		// (case-sensitive) so a child-only "Path=" entry on a
		// hypothetical case-preserving host is not silently rewritten.
		if strings.HasPrefix(kv, shimPathEnvKey+"=") {
			existing := strings.TrimPrefix(kv, shimPathEnvKey+"=")
			if existing == "" {
				out = append(out, shimPathEnvKey+"="+shimDir)
			} else {
				out = append(out, shimPathEnvKey+"="+shimDir+":"+existing)
			}
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, shimPathEnvKey+"="+shimDir)
	}
	return out
}

// validateShellShimOptions returns an error when the supervisor was
// asked to wire the shim but the surrounding options are insufficient.
// Pulled out of NewSupervisor so the error surface is testable in
// isolation and so the validation rule lives next to the helper that
// performs the wiring.
//
// Rules:
//
//  1. ShellShim requires ShellShimDir. The supervisor does not invent a
//     wrapper directory: the caller controls where the shim binary
//     lives so a future `ai-env run` CLI that places the wrapper
//     alongside the run directory and a future test harness that
//     points at a fixture directory can both wire it explicitly.
//  2. ShellShim requires an engine. Without a policy engine the shim
//     has no source of verdicts, and wiring it would silently degrade
//     into "log every command, deny none" which is the wrong default
//     for the prototype.
func validateShellShimOptions(opts SupervisorOptions, engine PolicyEngine) error {
	if !opts.ShellShim {
		return nil
	}
	if strings.TrimSpace(opts.ShellShimDir) == "" {
		return errors.New("run: NewSupervisor: ShellShim requires ShellShimDir")
	}
	if engine == nil {
		return errors.New("run: NewSupervisor: ShellShim requires PolicyEngine or PolicyEnginePath")
	}
	return nil
}

// openShellCommandsLog opens the shim's shell-commands.jsonl writer in
// the run directory and returns the handle the supervisor stores for
// its deferred close. Pulled into this file so the policy package
// import lives next to the only call site in internal/run and so the
// supervisor body does not have to learn the construction shape.
//
// The supervisor's clock is forwarded so the on-disk timestamps match
// the lifecycle / policy-decisions trails that already pass the same
// clock through their writers; a nil now falls back to time.Now inside
// policy.OpenShellCommandsLog.
func openShellCommandsLog(runDir, runID string, now func() time.Time) (*policy.ShellCommandsLog, error) {
	log, err := policy.OpenShellCommandsLog(runDir, policy.ShellCommandsLogOptions{
		RunID: runID,
		Now:   now,
	})
	if err != nil {
		return nil, fmt.Errorf("run: open shell commands log: %w", err)
	}
	return log, nil
}

// installShimWrappers materializes the per-program wrapper scripts in
// shimDir by delegating to policy.InstallShim. The function is the
// Plan §5.5 step 10 / Batch 1.4 wiring point: the supervisor owns the
// install side of the shim because the wrapper templates and the
// canonical program set are pinned in internal/policy, and the
// supervisor is the only caller that knows when the shim has been
// opted into for a run.
//
// helperCmd is the `exec` target the wrapper writes into each wrapper
// script. An empty helperCmd falls back to DefaultShimHelperCmd so
// production callers (the future `ai-env run --shell-shim` CLI) do
// not have to repeat the in-sandbox path; tests pass an explicit
// command (often a host-side stub) when they want to drive the
// wrapper end-to-end without standing up a backend.
//
// Errors propagate verbatim from policy.InstallShim so a missing
// shimDir or a non-directory at the path surfaces with the same
// message the policy package produces. The supervisor turns a non-nil
// return into a construction failure rather than a degraded run: a
// shim that cannot be installed at all is qualitatively different
// from a shim that lost coverage on individual canonical paths
// (which is what the shim_coverage_degraded lifecycle verb is for).
func installShimWrappers(shimDir, helperCmd string) error {
	cmd := strings.TrimSpace(helperCmd)
	if cmd == "" {
		cmd = DefaultShimHelperCmd
	}
	if _, err := policy.InstallShim(policy.InstallShimOptions{
		ShimDir:   shimDir,
		HelperCmd: cmd,
		// Programs left nil so InstallShim falls back to the canonical
		// ShimProgramSet. The supervisor never installs a partial set
		// in production: the canonical fixed list is the defense-in-
		// depth surface the plan's Bucket 1 locked decision pins.
	}); err != nil {
		return fmt.Errorf("run: install shim wrappers: %w", err)
	}
	return nil
}

// emitShimHostModeDegraded writes the `shim_coverage_degraded` lifecycle
// verb to the supervisor's lifecycle writer when the run is in host
// mode (BackendAdapter == nil). Plan Batch 1.3 calls for the emission:
// host-mode runs have no sandbox to install the canonical absolute-
// path shadow bind-mounts into, so the shim's coverage is limited to
// PATH-relative wrapper resolution. The verb makes that degradation
// auditable so a reviewer can correlate post-mortem behavior to the
// missing absolute-path shadow set.
//
// Metadata keys (per lifecycle_verbs.go's documented table):
//
//   - "program" = "*" — the degradation affects every shimmed program
//     uniformly because the missing surface is the entire canonical-
//     path mount layer, not a per-program failure. The "*" sentinel
//     distinguishes the host-mode emission from the per-entry adapter
//     emission (which carries a concrete program name) so the
//     aggregator can dedupe correctly.
//   - "missing" = the comma-separated canonical-path prefix set
//     (`/usr/bin,/bin,/usr/local/bin` by default) so a remediation
//     reader sees exactly which paths the shim cannot shadow.
//   - "reason" = "host_mode" — the short token the doctor's
//     remediation table joins on.
//
// Returns the lifecycle writer's error verbatim so the caller (the
// NewSupervisor wiring block) can abort construction when the
// audit record cannot be made durable.
func emitShimHostModeDegraded(lcWri *LifecycleWriter) error {
	if lcWri == nil {
		return errors.New("run: emit shim_coverage_degraded requires a lifecycle writer")
	}
	missing := strings.Join(policy.ShimCanonicalPathPrefixes, ",")
	return lcWri.WriteVerb(LifecycleVerbShimCoverageDegraded, map[string]string{
		"program": "*",
		"missing": missing,
		"reason":  "host_mode",
	})
}
