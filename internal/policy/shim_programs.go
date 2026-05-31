// shim_programs.go declares the single canonical list of programs that
// the supervisor shadows with shim wrappers inside the sandbox, and the
// fixed set of canonical absolute paths that each program is shadowed
// at. The plan's "Bucket 1" locked decision pins this surface here so
// every consumer (the backend bind-mount builder in Batch 0.5, the
// shim-helper subcommand in Batch 0.3, the policy engine's shim
// validation in Batch 1.3) sees the same list and refuses to drift.
//
// Why a fixed list and not a runtime probe of the base image?
//
// The plan's Bucket 1 locked decision rules out probing the base image
// at runtime: probing trusts untrusted output (a compromised image can
// hide or rename programs to evade the shim), and the canonical fixed
// set is defense-in-depth that does not depend on the image being
// honest. Any program present in the image at a canonical path that is
// NOT in this list is still subject to the network policy, the policy
// engine's deny patterns, and the egress observer; the shim is one
// layer among many.
//
// Adding a program here is a versioning change: every operator that
// upgrades sees the new wrappers installed. The plan's "Batch 0.3"
// entry pins the list; future changes go through a plan iteration so
// the audit trail records the decision rationale.

package policy

// ShimProgram is the basename of a program the supervisor shadows
// with a shim wrapper. It is a typed string so callers cannot pass an
// arbitrary path; the supervisor uses this type when iterating the
// list to make the bind-mount builder's signature self-documenting.
type ShimProgram string

// ShimProgramSet is the canonical set of program basenames the
// supervisor shadows inside the sandbox. The plan's Batch 0.3 entry
// pins the list verbatim; the order is the order the bind-mount
// builder iterates so a downstream operator who reads
// lifecycle.jsonl sees the wrappers installed in a deterministic
// sequence.
//
// Notes on individual entries:
//
//   - sh/bash/dash/zsh: every interactive shell the policy engine
//     evaluates against the high-risk-pattern list (curl-pipe-shell,
//     SSH key paths, metadata-IP). Wrapping these is the primary
//     shell-shim surface.
//
//   - python / python3 / python3.10 / python3.11 / python3.12: the
//     plan calls out the version-suffix variants explicitly because
//     base images frequently ship a versioned binary as the "real"
//     entry point and the unsuffixed `python` is a symlink. Shadowing
//     all four canonical paths ensures the helper intercepts the
//     versioned form too.
//
//   - perl / ruby / node / deno: interpreters that can fork an
//     arbitrary command from inline source. The shim's tokenizer
//     hardening (Batch 1.2) catches the inline-source form via the
//     interpreter-via-file rule.
//
//   - curl / wget / nc / ncat / socat: the canonical egress tools
//     the policy engine's HighRiskShellPatterns hard-deny in
//     "curl-pipe-shell" form. Wrapping them in the shim lets the
//     helper enforce the patterns even when the agent constructs the
//     argv programmatically (bypassing a bash one-liner).
//
//   - chmod: the "make this writable then execute it" gadget. Wrapping
//     chmod lets the helper deny obvious "chmod +x /tmp/<rand>" /
//     "chmod 777 ~/.ssh/" patterns at the shim layer.
//
//   - osascript: macOS-only; the canonical way to drive AppleScript
//     from a sandboxed agent. Wrapping it keeps macOS hosts honest
//     even when the rest of the policy is Linux-tuned.
//
//   - awk: the "awk 'BEGIN{system("...")}' " gadget. The interpreter-
//     ban rule (Batch 1.2) refuses inline-source forms.
//
//   - env: the "env -i ..." gadget that runs a binary with a stripped
//     environment, bypassing any AI_ENV_* envvar guards. The
//     interpreter-ban rule treats `env` as a re-exec candidate.
var ShimProgramSet = []ShimProgram{
	"sh",
	"bash",
	"dash",
	"zsh",
	"python",
	"python3",
	"python3.10",
	"python3.11",
	"python3.12",
	"perl",
	"ruby",
	"node",
	"curl",
	"wget",
	"nc",
	"ncat",
	"socat",
	"chmod",
	"osascript",
	"awk",
	"deno",
	"env",
}

// ShimCanonicalPathPrefixes is the fixed set of canonical absolute
// path prefixes the supervisor's bind-mount builder shadows for each
// program. The plan pins the list as
// `{/usr/bin/<prog>, /bin/<prog>, /usr/local/bin/<prog>}` so an agent
// that hard-codes one of those absolute paths is still routed through
// the shim.
//
// Entries are absolute directories (no trailing slash) so callers can
// compose `prefix + "/" + program` deterministically. The set is small
// and not expected to grow; an image whose canonical binaries live at
// a different prefix (e.g. /opt/.../bin/) is shadowed via the
// PATH-relative wrapper directory the supervisor places ahead of the
// inherited PATH (see internal/run/shim_wire.go's InjectShimPath).
var ShimCanonicalPathPrefixes = []string{
	"/usr/bin",
	"/bin",
	"/usr/local/bin",
}

// ShimCanonicalPaths returns the fixed list of canonical absolute
// paths the bind-mount builder shadows for the named program. The
// result is the Cartesian product `prefix x program`, in the order
// ShimCanonicalPathPrefixes is declared, so two callers iterating the
// same program see the same order. An empty program returns nil.
//
// The slice is freshly allocated on every call so the caller can
// append to it without aliasing into the package's state.
func ShimCanonicalPaths(program ShimProgram) []string {
	name := string(program)
	if name == "" {
		return nil
	}
	out := make([]string, 0, len(ShimCanonicalPathPrefixes))
	for _, prefix := range ShimCanonicalPathPrefixes {
		out = append(out, prefix+"/"+name)
	}
	return out
}

// IsShimmedProgram reports whether the program basename is in the
// canonical ShimProgramSet. The shim-helper subcommand uses this to
// refuse a re-exec request whose canonical target is not in the
// shadowed set (a defense-in-depth check; a request that reaches the
// helper but names an un-shadowed program means the helper is being
// invoked from a path the supervisor did not install).
func IsShimmedProgram(program string) bool {
	for _, p := range ShimProgramSet {
		if string(p) == program {
			return true
		}
	}
	return false
}
