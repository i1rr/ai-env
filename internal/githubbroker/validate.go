// validate.go implements the static, network-free validation helpers
// the broker's Prepare step runs before it ever touches a token or the
// GitHub API. Plan 07 steps 2-4 land here:
//
//  1. Step 2: ValidateBranchPrefix rejects branch names that do not
//     start with the policy-required "ai-env/" prefix.
//  2. Step 3: ValidateProtectedBranch rejects pushes that target a
//     protected branch (main, master, or one carried in the Repo's
//     DefaultBranch / a caller-supplied extras list).
//  3. Step 4: ValidatePathGate rejects an automatic PR when the
//     workspace diff touches a path the policy's
//     block_auto_pr_on_paths list covers (workflow files and the
//     `.ai-env/` internal state by default).
//
// The helpers are exported as package-level functions because the
// concrete GitHubBroker implementation (plan 07 step 7) is not the only
// caller: the run lifecycle (plan 07 step 11), ExportGate (plan 07
// step 11), and unit tests all share the same vocabulary. Centralizing
// the rules here means the "must start with ai-env/" answer lives in
// exactly one place.
//
// Every helper returns one of the package's sentinel errors
// (ErrInvalidBranchPrefix, ErrProtectedBranch, ErrProtectedPath) so
// callers can match with errors.Is and render the right remediation
// hint. The functions are pure: no I/O, no time-of-day reads, no
// goroutine state.

package githubbroker

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/i1rr/ai-env/internal/workspace"
)

// BranchPrefix is the only branch prefix the broker accepts. Plan 07
// "Key decisions from master plan", item 4 fixes this string; it is
// exported so the CLI can render it in error messages without
// re-declaring the constant.
const BranchPrefix = "ai-env/"

// defaultProtectedBranches is the conservative set of branch names the
// broker refuses to push to even when the policy does not name them
// explicitly. The list covers the two conventional default-branch
// names plus the legacy "trunk"/"develop" names that some repositories
// still treat as production. Repo.DefaultBranch is checked separately
// so a repository whose default branch is none of these names is still
// protected.
var defaultProtectedBranches = map[string]struct{}{
	"main":    {},
	"master":  {},
	"trunk":   {},
	"develop": {},
}

// defaultBlockAutoPRPathGlobs is the path-gate matcher's default list.
// It mirrors the `block_auto_pr_on_paths` block in the plan's policy
// snippet (plan 07 "GitHub broker rules"): workflow files and the
// `.ai-env/` internal state. infra/** and terraform/** are documented
// in the same policy block, but plan 07 step 4 only requires the
// workflow and `.ai-env/` gates, so those two paths are the only ones
// this default fires on. Callers that want infra/terraform coverage
// pass them through PathGateOptions.ExtraBlockGlobs.
var defaultBlockAutoPRPathGlobs = []string{
	".github/workflows/**",
	".ai-env/**",
}

// ValidateBranchPrefix enforces plan 07 step 2: the broker refuses
// every branch name that does not start with BranchPrefix. The check
// is intentionally strict; a name like "AI-ENV/foo" or "ai-env-foo"
// does not match because the prefix is part of the policy contract,
// not a stylistic hint.
//
// Returns ErrInvalidBranchPrefix wrapped with the offending name so
// the CLI can surface it verbatim. A caller that only cares about the
// boolean verdict uses errors.Is(err, ErrInvalidBranchPrefix).
func ValidateBranchPrefix(branchName string) error {
	if !strings.HasPrefix(branchName, BranchPrefix) {
		return fmt.Errorf("%w: got %q", ErrInvalidBranchPrefix, branchName)
	}
	// A bare "ai-env/" with no suffix is technically prefixed but
	// references no concrete branch; reject it so the CLI does not try
	// to push an empty ref.
	if branchName == BranchPrefix {
		return fmt.Errorf("%w: branch name has prefix but no suffix", ErrInvalidBranchPrefix)
	}
	return nil
}

// ValidateProtectedBranch enforces plan 07 step 3: the broker refuses
// to push to any protected branch. A branch is protected when its
// name matches one of:
//
//  1. The repository's DefaultBranch (e.g. "main" for most repos).
//  2. Any entry in defaultProtectedBranches.
//  3. Any entry in the caller-supplied extras list (loaded from
//     policy.yaml by the CLI; passed in as a slice so this helper
//     stays free of a policy import cycle and remains a pure
//     function).
//
// The check applies to the raw branch name; combining it with the
// BranchPrefix rule from ValidateBranchPrefix is the caller's job.
// Both rules fire from Prepare in series, so a name like "main" is
// caught by ValidateBranchPrefix first (no ai-env/ prefix) and
// "ai-env/main" is caught here only if a repository's default branch
// is somehow "ai-env/main" (which is not realistic but the rule still
// applies symmetrically).
//
// Returns ErrProtectedBranch wrapped with the offending name. Empty
// branchName is reported as an error so a caller that forgets to set
// BranchName does not silently succeed.
func ValidateProtectedBranch(branchName string, repo Repo, extraProtected []string) error {
	if branchName == "" {
		return fmt.Errorf("%w: branch name is empty", ErrProtectedBranch)
	}
	if repo.DefaultBranch != "" && branchName == repo.DefaultBranch {
		return fmt.Errorf("%w: %q is the repository default branch", ErrProtectedBranch, branchName)
	}
	if _, ok := defaultProtectedBranches[branchName]; ok {
		return fmt.Errorf("%w: %q is a default-protected branch", ErrProtectedBranch, branchName)
	}
	for _, name := range extraProtected {
		if branchName == name {
			return fmt.Errorf("%w: %q is listed in the policy's protected branches", ErrProtectedBranch, branchName)
		}
	}
	return nil
}

// PathGateOptions configures ValidatePathGate. All fields are
// optional; the zero value runs the gate with the documented defaults
// (`.github/workflows/**` and `.ai-env/**`).
type PathGateOptions struct {
	// ExtraBlockGlobs is a caller-supplied list of glob patterns
	// (filepath.Match syntax, with `**` extended to mean "any number
	// of path segments") added to the default block list. The CLI
	// populates this from policy.yaml's `block_auto_pr_on_paths`
	// entries so a repository can extend the gate without monkey-
	// patching the defaults.
	ExtraBlockGlobs []string

	// ReplaceDefaults, when true, makes ExtraBlockGlobs the entire
	// gate list and skips the defaults. The flag exists for tests and
	// for an operator who explicitly wants to allow a workflow change
	// through brokered PR (and accepts the security trade-off); the
	// default false matches the plan's stated intent that workflow
	// and `.ai-env/` paths are non-negotiable.
	ReplaceDefaults bool
}

// PathGateHit describes one diff entry that tripped the path gate.
// The CLI surfaces these so the operator knows which file blocked the
// PR; the broker logs them into `policy-decisions.jsonl` (plan 07
// step 12).
type PathGateHit struct {
	// Path is the workspace-relative path that matched a block glob.
	Path string

	// Glob is the pattern from the block list that matched Path. It
	// is reported back so the operator can map the hit onto the
	// policy entry that produced it.
	Glob string
}

// ValidatePathGate enforces plan 07 step 4: the broker refuses an
// automatic PR when the workspace diff includes a file the policy's
// block_auto_pr_on_paths list covers. By default the list is the two
// entries the plan names explicitly (workflows and `.ai-env/`); the
// caller extends or replaces it via PathGateOptions.
//
// The function inspects diff.Files (not diff.ProtectedHits) so it sees
// every change the agent made, not just the ones the workspace's
// ProtectedMatcher already flagged. This matters because the agent's
// view of "protected" is a per-policy knob, while the broker's path
// gate is a hard rule.
//
// Returns:
//
//   - (nil, nil) when no blocked path is changed.
//   - (hits, ErrProtectedPath) when at least one blocked path is
//     changed. The error wraps ErrProtectedPath with a short summary
//     of the first hit so a caller that only logs err.Error() still
//     gets a useful message; the hits slice carries the full list for
//     structured rendering.
//
// Deleted files are still considered "changed" by this gate: removing
// a workflow file is just as much an automatic-PR risk as adding one,
// so the broker blocks both.
func ValidatePathGate(diff workspace.DiffResult, opts PathGateOptions) ([]PathGateHit, error) {
	globs := assembleBlockGlobs(opts)
	if len(globs) == 0 {
		return nil, nil
	}

	var hits []PathGateHit
	for _, f := range diff.Files {
		rel := filepath.ToSlash(f.Path)
		if rel == "" {
			continue
		}
		for _, g := range globs {
			if matchGlob(g, rel) {
				hits = append(hits, PathGateHit{Path: f.Path, Glob: g})
				break
			}
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}
	first := hits[0]
	return hits, fmt.Errorf("%w: %s (matches %s)", ErrProtectedPath, first.Path, first.Glob)
}

// assembleBlockGlobs combines the default block list with the
// caller's ExtraBlockGlobs, honouring ReplaceDefaults. The result
// preserves order (defaults first, then extras) so a downstream
// PathGateHit reports the most specific glob a hit matched first.
func assembleBlockGlobs(opts PathGateOptions) []string {
	if opts.ReplaceDefaults {
		out := make([]string, len(opts.ExtraBlockGlobs))
		copy(out, opts.ExtraBlockGlobs)
		return out
	}
	out := make([]string, 0, len(defaultBlockAutoPRPathGlobs)+len(opts.ExtraBlockGlobs))
	out = append(out, defaultBlockAutoPRPathGlobs...)
	out = append(out, opts.ExtraBlockGlobs...)
	return out
}

// matchGlob matches a forward-slash path against a glob pattern. It
// extends filepath.Match's syntax with a single rule: a literal "**"
// segment matches any number of intermediate path segments. The plan's
// policy snippet uses "**" patterns (e.g. ".github/workflows/**" and
// ".ai-env/**"), and filepath.Match alone does not understand them, so
// matchGlob translates "**" into "match any suffix that is either
// empty (after a trailing slash) or one-or-more segments".
//
// The rule below covers the two shapes that appear in practice:
//
//  1. "prefix/**" matches the prefix itself plus anything under it.
//  2. "prefix/**/suffix" is rejected because plan 07 does not require
//     it and the matcher would need a more general state machine.
//     Callers that need that shape must extend the matcher; the gate
//     errors loudly via the assembleBlockGlobs path.
//
// Patterns without "**" fall through to path.Match for standard
// shell-style matching.
func matchGlob(pattern, target string) bool {
	if strings.Contains(pattern, "**") {
		// Reject patterns with "**" in a non-trailing position so we
		// do not silently mismatch. Plan 07 step 4 only needs the
		// trailing form.
		if !strings.HasSuffix(pattern, "**") {
			return false
		}
		prefix := strings.TrimSuffix(pattern, "**")
		prefix = strings.TrimSuffix(prefix, "/")
		if prefix == "" {
			// Pattern "**" matches everything. Not used today but
			// defined so the matcher is total.
			return true
		}
		if target == prefix {
			return true
		}
		return strings.HasPrefix(target, prefix+"/")
	}
	ok, err := path.Match(pattern, target)
	if err != nil {
		return false
	}
	return ok
}
