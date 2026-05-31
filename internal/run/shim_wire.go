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
