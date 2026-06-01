// shim_bindmounts.go builds the per-(program × canonical-path) bind-mount
// list the supervisor hands to backend.Create at Plan §5.5 step 3 so the
// sandbox sees the shim wrapper at every canonical absolute path. The
// helper is the "Batch 1.3 — Sandbox absolute-path shadow (canonical
// fixed set)" surface: it does NOT probe the base image (per the plan's
// Bucket 1 locked decision: probing trusts untrusted output), and it
// does NOT install the wrappers themselves (InstallShim owns that side).
// Instead, it iterates ShimProgramSet × ShimCanonicalPathPrefixes and
// emits one BindMount per pair, each pointing the canonical absolute
// path inside the sandbox (e.g. /usr/bin/curl) at the host-side wrapper
// (e.g. <shimDir>/curl).
//
// What this file owns:
//
//   - The Cartesian product (program × canonical path) the supervisor
//     hands to EnvSpec.BindMounts. The product is deterministic: outer
//     loop is ShimProgramSet, inner loop is ShimCanonicalPathPrefixes,
//     so a downstream operator who reads lifecycle.jsonl sees the
//     entries appear in the same order across runs.
//   - The per-entry ReadOnly + Mode policy. Every canonical-path shadow
//     is read-only (an agent that gains write access to the shadow
//     could rewrite the wrapper); Mode is left zero so the adapter
//     falls back to the source file's mode (the 0755 InstallShim wrote).
//
// What this file does NOT own:
//
//   - The wrapper script's content. That is renderShimWrapper in
//     shim_install.go.
//   - The wrapper file's host-side existence. The supervisor calls
//     InstallShim before backend.Create so the BindMount Source paths
//     are real files on disk; this helper just composes paths.
//   - The auxiliary mounts the canonical pre-launch step 3 list also
//     covers (runDir/ipc, the ai-env binary itself, the HOME shadow).
//     Those are built directly by the supervisor; this file is scoped
//     to the per-program shadow set so a future change to the
//     auxiliary mount list does not have to touch this surface.
//
// Tolerance of missing targets:
//
// Per the plan's Bucket 1 locked decision, "Bind-mounts that overlay
// non-existent target paths are tolerated (Docker auto-creates;
// failures are non-fatal for individual entries but the supervisor
// logs each)". This helper does NOT enforce per-entry tolerance —
// that is the adapter's call when it walks BindMounts and the
// supervisor's call when it sees a per-entry failure surface as a
// shim_coverage_degraded lifecycle event (see internal/run/shim_wire.go).

package policy

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/rivan1986/ai-env/internal/backend"
)

// BuildShimBindMountsOptions bundles the per-call knobs
// BuildShimBindMounts consumes. All fields are required except
// Programs, which defaults to the canonical ShimProgramSet when nil.
type BuildShimBindMountsOptions struct {
	// ShimDir is the absolute host-side path of the directory that
	// holds the wrapper scripts InstallShim produced. Each BindMount's
	// Source field is filepath.Join(ShimDir, program). Required; an
	// empty value returns an error.
	//
	// The supervisor invariant the caller upholds: InstallShim was
	// called against this same directory before BuildShimBindMounts,
	// so every Source path the helper emits already exists on disk.
	// BuildShimBindMounts does NOT stat the paths itself: the test
	// fixtures pass directories that do not contain every wrapper
	// (smaller program lists), and the production adapter tolerates
	// per-entry mount failures via the documented
	// shim_coverage_degraded lifecycle.
	ShimDir string

	// Programs is the list of shim programs to compose canonical-path
	// shadows for. Nil falls back to ShimProgramSet (the canonical
	// fixed list); tests pass a smaller list to keep fixtures small.
	// The slice is iterated as the outer loop so the resulting entries
	// group by program: every program's three canonical-path entries
	// appear consecutively.
	Programs []ShimProgram

	// CanonicalPathPrefixes is the list of canonical absolute-path
	// prefixes to shadow. Nil falls back to ShimCanonicalPathPrefixes
	// (the plan-pinned `{/usr/bin, /bin, /usr/local/bin}` set); tests
	// pass a smaller list to keep fixtures small. A non-absolute entry
	// is rejected at build time so a caller does not silently install
	// a workspace-relative shadow.
	CanonicalPathPrefixes []string
}

// BuildShimBindMounts returns the per-(program × canonical-path)
// BindMount slice the supervisor adds to EnvSpec.BindMounts before
// calling backend.Create. The slice is the canonical absolute-path
// shadow set described in the plan's Bucket 1 locked decision:
// every shim program is shadowed at /usr/bin/<prog>, /bin/<prog>,
// and /usr/local/bin/<prog>, with the Source path pointing at the
// wrapper script in opts.ShimDir.
//
// Returns:
//
//   - On success, the slice of BindMounts in (program, prefix)
//     declaration order. With the canonical defaults that is
//     len(ShimProgramSet) * len(ShimCanonicalPathPrefixes) entries
//     (today: 22 * 3 = 66).
//   - On bad input (empty ShimDir, non-absolute prefix, empty program
//     name) an error explaining the misconfiguration; the supervisor
//     refuses to start the run because Plan Bucket 1's defense-in-
//     depth argument requires the shadow set to be present.
//
// Per-entry properties:
//
//   - Source = filepath.Join(opts.ShimDir, programName). The
//     supervisor's InstallShim writes wrappers at this exact path.
//   - Target = filepath.Join(prefix, programName). The plan pins the
//     three canonical-path prefixes; the result is the absolute
//     sandbox-side path the bind-mount lands at.
//   - ReadOnly = true. An agent that gained write access to the
//     wrapper could rewrite the script content and escape the shim;
//     the host-side wrapper is supervisor-managed and must not be
//     mutable from inside the sandbox.
//   - Mode = 0 (unset). The adapter falls back to the source file's
//     mode (the 0755 InstallShim writes). Carrying a non-zero mode
//     here would invite a mismatch between the wrapper's host-side
//     mode and the in-sandbox view.
//
// Determinism:
//
// The outer loop is opts.Programs, the inner loop is
// opts.CanonicalPathPrefixes. A reader of lifecycle.jsonl sees the
// resulting "shim_coverage_degraded" verbs (when any entry fails to
// mount) emitted in the same per-program order across runs.
func BuildShimBindMounts(opts BuildShimBindMountsOptions) ([]backend.BindMount, error) {
	if strings.TrimSpace(opts.ShimDir) == "" {
		return nil, errors.New("policy: BuildShimBindMounts requires ShimDir")
	}
	if !filepath.IsAbs(opts.ShimDir) {
		return nil, errors.New("policy: BuildShimBindMounts requires absolute ShimDir")
	}

	programs := opts.Programs
	if programs == nil {
		programs = ShimProgramSet
	}
	prefixes := opts.CanonicalPathPrefixes
	if prefixes == nil {
		prefixes = ShimCanonicalPathPrefixes
	}

	// Validate the prefix list up front so the caller does not have to
	// inspect each emitted BindMount to learn that a non-absolute prefix
	// silently slipped through. The plan pins the absolute-path-shadow
	// nature of the set; a relative prefix would defeat that.
	for i, p := range prefixes {
		if strings.TrimSpace(p) == "" {
			return nil, errors.New("policy: BuildShimBindMounts refuses empty canonical path prefix")
		}
		if !filepath.IsAbs(p) {
			return nil, errors.New("policy: BuildShimBindMounts requires absolute canonical path prefix at index " + itoa(i))
		}
	}

	out := make([]backend.BindMount, 0, len(programs)*len(prefixes))
	for _, p := range programs {
		name := strings.TrimSpace(string(p))
		if name == "" {
			return nil, errors.New("policy: BuildShimBindMounts refuses empty program name")
		}
		source := filepath.Join(opts.ShimDir, name)
		for _, prefix := range prefixes {
			target := filepath.Join(prefix, name)
			out = append(out, backend.BindMount{
				Source:   source,
				Target:   target,
				ReadOnly: true,
			})
		}
	}
	return out, nil
}

// itoa is a tiny helper avoiding strconv to keep the import surface
// minimal; the values it formats are small index integers (< 100).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
