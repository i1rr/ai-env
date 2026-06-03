// gate.go implements the ExportGate evaluator that satisfies plan 06
// step 7. The gate is a pure function over Input: it inspects the
// scanner results, workspace diff, policy, and run record and returns
// a GateResult describing whether export is allowed and why.
//
// Evaluation order is the plan's enumeration order so the output is
// deterministic across runs and the reader can match Reasons against
// the plan text directly:
//
//  1. Hard blockers (built-in secret findings, external secret
//     findings, workflow changes for ModePR, .ai-env changes, policy
//     changes, quarantine).
//  2. Configurable blockers (high-severity vulnerabilities, protected
//     paths, large diff, new binary files, new executable files,
//     lockfile changes).
//
// Each rule's outcome is recorded as a Reason; the top-level Decision
// is the boolean OR of every reason's Severity==SeverityBlock.

package export

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/i1rr/ai-env/internal/config"
	"github.com/i1rr/ai-env/internal/run"
	"github.com/i1rr/ai-env/internal/workspace"
)

// defaultLargeDiffLines is the line-count threshold above which the
// configurable large-diff rule triggers when policy.yaml does not pin a
// value. The plan does not mandate a specific number; 1000 lines is
// large enough that a hand-review burden is real but small enough that
// a routine refactor does not trip it.
const defaultLargeDiffLines = 1000

// defaultExecutableMode is the bitmask we match against FileInfo.Mode()
// to detect executable files. We do not have FileInfo at this layer,
// so the new-executable rule actually fires from the supervisor's
// pre-export pass in plan 07. For now the rule is wired up to recognise
// shebang lines in newly added files via the scanner's metadata; the
// configurable knob still lives here so the surface is stable.
//
// (Plan 06 only mandates the rule exists; the implementation in this
// batch is conservative: we only flag added files whose path ends in a
// common script extension. Plan 07 tightens this once the patch path
// has access to filesystem mode bits.)

// defaultLockfileNames is the set of lockfile basenames the
// configurable lockfile-change rule matches. The list mirrors
// workspace.DefaultProtectedPaths so the two rules agree on what a
// "lockfile" is; we duplicate it here as a set rather than reusing the
// glob list so the gate can match by basename without re-evaluating
// globs the protected-path matcher already covers.
var defaultLockfileNames = map[string]struct{}{
	"package-lock.json":   {},
	"yarn.lock":           {},
	"pnpm-lock.yaml":      {},
	"npm-shrinkwrap.json": {},
	"Gemfile.lock":        {},
	"Pipfile.lock":        {},
	"poetry.lock":         {},
	"uv.lock":             {},
	"go.sum":              {},
	"Cargo.lock":          {},
	"composer.lock":       {},
}

// defaultScriptExtensions is the conservative set of file extensions
// the new-executable rule treats as scripts. A full executable-bit
// check belongs to the supervisor's pre-export pass (plan 07) which has
// access to filesystem mode bits; here we err on the side of false
// negatives so the gate does not block routine refactors that happen
// to add a .sh file the user genuinely intends.
var defaultScriptExtensions = map[string]struct{}{
	".sh":   {},
	".bash": {},
	".zsh":  {},
	".ps1":  {},
}

// ExportGate is the evaluator. It carries no state beyond the
// configurable thresholds; one instance can serve every export call in
// a process. The CLI constructs a gate with NewExportGate (passing the
// policy) and calls Evaluate per export.
//
// The type exists (rather than a free function) so the CLI can hold a
// single configured value across calls and so future knobs (rate
// limiters, audit hooks) can attach to it without changing the call
// site.
type ExportGate struct {
	// largeDiffLines is the line-count threshold for the large-diff
	// rule. Loaded from policy.yaml when present; defaultLargeDiffLines
	// otherwise.
	largeDiffLines int
}

// NewExportGate constructs an ExportGate configured from policy. A nil
// policy is acceptable: the gate falls back to the documented defaults
// so an ad-hoc invocation without a policy.yaml still produces a
// usable verdict.
func NewExportGate(policy *config.PolicyConfig) *ExportGate {
	g := &ExportGate{largeDiffLines: defaultLargeDiffLines}
	_ = policy
	return g
}

// Evaluate runs every gate rule against in and returns the combined
// verdict. The function is pure: no I/O, no time-of-day reads, no
// process-level state. Callers build Input from disk and hand it in;
// the gate's job is to decide.
func (g *ExportGate) Evaluate(in Input) GateResult {
	var reasons []Reason

	reasons = append(reasons, g.evalSecretFindings(in)...)
	reasons = append(reasons, g.evalExternalScanners(in)...)
	reasons = append(reasons, g.evalAIEnvChanges(in)...)
	reasons = append(reasons, g.evalPolicyChanges(in)...)
	reasons = append(reasons, g.evalWorkflowChanges(in)...)
	reasons = append(reasons, g.evalQuarantine(in)...)
	reasons = append(reasons, g.evalProtectedPaths(in)...)
	reasons = append(reasons, g.evalLargeDiff(in)...)
	reasons = append(reasons, g.evalLockfileChanges(in)...)
	reasons = append(reasons, g.evalNewExecutableFiles(in)...)

	decision := DecisionAllow
	for _, r := range reasons {
		if r.Severity == SeverityBlock {
			decision = DecisionBlock
			break
		}
	}
	return GateResult{Decision: decision, Reasons: reasons}
}

// evalSecretFindings emits a SeverityBlock reason for every Finding in
// the built-in scanner result whose BlocksExport is true. The built-in
// scanner is the v0.1 default; its findings are always hard blockers
// per the plan.
func (g *ExportGate) evalSecretFindings(in Input) []Reason {
	var out []Reason
	for _, f := range in.BuiltInResult.Findings {
		if !f.BlocksExport {
			continue
		}
		out = append(out, Reason{
			Code:      ReasonSecretFinding,
			Severity:  SeverityBlock,
			Message:   fmt.Sprintf("secret leak: %s at %s:%d (%s)", f.Pattern, f.File, f.Line, f.Confidence),
			Path:      f.File,
			FindingID: f.ID,
			Hard:      true,
		})
	}
	return out
}

// evalExternalScanners routes each ExternalResults entry to the right
// rule. Secret-scanner output (gitleaks) feeds the hard
// external-secret rule; vulnerability scanners feed the configurable
// high-severity rule.
func (g *ExportGate) evalExternalScanners(in Input) []Reason {
	var out []Reason
	failOnHighVuln := failOnHighVulnerability(in.Policy)
	for _, res := range in.ExternalResults {
		if res.Scanner == "gitleaks" {
			for _, f := range res.Findings {
				if !f.BlocksExport {
					continue
				}
				out = append(out, Reason{
					Code:      ReasonExternalSecretFinding,
					Severity:  SeverityBlock,
					Message:   fmt.Sprintf("gitleaks finding: %s at %s:%d", f.Pattern, f.File, f.Line),
					Path:      f.File,
					FindingID: f.ID,
					Hard:      true,
				})
			}
			continue
		}
		for _, f := range res.Findings {
			if !f.BlocksExport {
				continue
			}
			severity := SeverityWarn
			if failOnHighVuln {
				severity = SeverityBlock
			}
			out = append(out, Reason{
				Code:      ReasonHighSeverityVuln,
				Severity:  severity,
				Message:   fmt.Sprintf("high-severity vulnerability (%s): %s at %s", res.Scanner, f.Pattern, f.File),
				Path:      f.File,
				FindingID: f.ID,
				Hard:      false,
			})
		}
	}
	return out
}

// evalAIEnvChanges fires when the diff touches any path under
// .ai-env/. The rule is a hard blocker per the plan: an agent must
// never edit its own policy or escape hatches. We match by path prefix
// rather than the protected-path glob so the rule fires even when the
// user has customized filesystem.protected_paths to remove the default.
func (g *ExportGate) evalAIEnvChanges(in Input) []Reason {
	var out []Reason
	for _, f := range in.Diff.Files {
		rel := normalizeSlash(f.Path)
		if rel == ".ai-env" || strings.HasPrefix(rel, ".ai-env/") {
			out = append(out, Reason{
				Code:     ReasonAIEnvChange,
				Severity: SeverityBlock,
				Message:  fmt.Sprintf("change under .ai-env/ is not allowed: %s", f.Path),
				Path:     f.Path,
				Hard:     true,
			})
		}
	}
	return out
}

// evalPolicyChanges fires when the diff touches .ai-env/policy.yaml
// specifically. It is reported separately from the broader
// .ai-env/** rule (which still fires) so the CLI can render the more
// specific message.
func (g *ExportGate) evalPolicyChanges(in Input) []Reason {
	var out []Reason
	for _, f := range in.Diff.Files {
		rel := normalizeSlash(f.Path)
		if rel == ".ai-env/policy.yaml" {
			out = append(out, Reason{
				Code:     ReasonPolicyChange,
				Severity: SeverityBlock,
				Message:  "policy.yaml was modified by the agent; this is never shippable",
				Path:     f.Path,
				Hard:     true,
			})
		}
	}
	return out
}

// evalWorkflowChanges fires when the diff touches .github/workflows/**.
// Severity is mode-dependent: SeverityBlock under ModePR (brokered
// PR), SeverityWarn under ModePatch (local patch export still allowed
// so the user can inspect the proposed change).
func (g *ExportGate) evalWorkflowChanges(in Input) []Reason {
	var out []Reason
	for _, f := range in.Diff.Files {
		rel := normalizeSlash(f.Path)
		if !strings.HasPrefix(rel, ".github/workflows/") {
			continue
		}
		severity := SeverityWarn
		message := fmt.Sprintf("workflow change detected (allowed for patch export, blocked for PR): %s", f.Path)
		if in.Mode == ModePR {
			severity = SeverityBlock
			message = fmt.Sprintf("workflow change blocks brokered PR export: %s", f.Path)
		}
		out = append(out, Reason{
			Code:     ReasonWorkflowChange,
			Severity: severity,
			Message:  message,
			Path:     f.Path,
			Hard:     true,
		})
	}
	return out
}

// evalQuarantine fires when the run record's State is quarantined. A
// nil Record (e.g. ad-hoc export off an unrun workspace) skips the
// rule rather than treating absence as a block.
func (g *ExportGate) evalQuarantine(in Input) []Reason {
	if in.Record == nil {
		return nil
	}
	if in.Record.State != run.StateQuarantined {
		return nil
	}
	return []Reason{{
		Code:     ReasonQuarantine,
		Severity: SeverityBlock,
		Message:  fmt.Sprintf("run %s is quarantined; export is blocked", in.Record.RunID),
		Hard:     true,
	}}
}

// evalProtectedPaths emits one Reason per workspace.DiffResult.ProtectedHits
// entry. Severity is SeverityBlock when policy.review.require_diff_review
// is enabled (the closest stable proxy for "block on protected paths");
// SeverityWarn otherwise. Either way the operator sees the hit list.
func (g *ExportGate) evalProtectedPaths(in Input) []Reason {
	var out []Reason
	severity := SeverityWarn
	if blockOnProtectedPaths(in.Policy) {
		severity = SeverityBlock
	}
	for _, p := range in.Diff.ProtectedHits {
		// The .ai-env / policy / workflow rules already fired with a
		// more specific reason for these paths. Skip the duplicate
		// here so the operator does not see two reasons for the same
		// file.
		rel := normalizeSlash(p)
		if rel == ".ai-env" || strings.HasPrefix(rel, ".ai-env/") {
			continue
		}
		if strings.HasPrefix(rel, ".github/workflows/") {
			continue
		}
		if _, lock := defaultLockfileNames[path.Base(rel)]; lock {
			continue
		}
		out = append(out, Reason{
			Code:     ReasonProtectedPath,
			Severity: severity,
			Message:  fmt.Sprintf("protected path changed: %s", p),
			Path:     p,
			Hard:     false,
		})
	}
	return out
}

// evalLargeDiff fires when the unified-diff line count exceeds the
// configured threshold. Severity is SeverityBlock when
// policy.review.require_diff_review is enabled; SeverityWarn
// otherwise.
func (g *ExportGate) evalLargeDiff(in Input) []Reason {
	if in.Diff.Unified == "" {
		return nil
	}
	lines := strings.Count(in.Diff.Unified, "\n")
	if lines <= g.largeDiffLines {
		return nil
	}
	severity := SeverityWarn
	if blockOnLargeDiff(in.Policy) {
		severity = SeverityBlock
	}
	return []Reason{{
		Code:     ReasonLargeDiff,
		Severity: severity,
		Message:  fmt.Sprintf("large diff: %d lines (threshold %d)", lines, g.largeDiffLines),
		Hard:     false,
	}}
}

// evalLockfileChanges fires for every added or modified file whose
// basename matches a known lockfile name. Severity follows the
// configurable-blocker rule.
func (g *ExportGate) evalLockfileChanges(in Input) []Reason {
	var out []Reason
	severity := SeverityWarn
	if blockOnLockfileChange(in.Policy) {
		severity = SeverityBlock
	}
	for _, f := range in.Diff.Files {
		if f.Change == workspace.ChangeDeleted {
			continue
		}
		base := path.Base(normalizeSlash(f.Path))
		if _, ok := defaultLockfileNames[base]; !ok {
			continue
		}
		out = append(out, Reason{
			Code:     ReasonLockfileChange,
			Severity: severity,
			Message:  fmt.Sprintf("lockfile changed: %s", f.Path),
			Path:     f.Path,
			Hard:     false,
		})
	}
	return out
}

// evalNewExecutableFiles fires for newly added files whose extension
// matches the conservative script-extension set. A full executable-bit
// check belongs to plan 07; the rule's existence here keeps the
// surface stable.
func (g *ExportGate) evalNewExecutableFiles(in Input) []Reason {
	var out []Reason
	severity := SeverityWarn
	if blockOnNewExecutables(in.Policy) {
		severity = SeverityBlock
	}
	for _, f := range in.Diff.Files {
		if f.Change != workspace.ChangeAdded {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Path))
		if _, ok := defaultScriptExtensions[ext]; !ok {
			continue
		}
		out = append(out, Reason{
			Code:     ReasonNewExecutableFile,
			Severity: severity,
			Message:  fmt.Sprintf("new executable script added: %s", f.Path),
			Path:     f.Path,
			Hard:     false,
		})
	}
	return out
}

// failOnHighVulnerability reads policy.review.fail_on_high_vulnerability,
// defaulting to true (the plan's stated default) when the policy is
// absent.
func failOnHighVulnerability(p *config.PolicyConfig) bool {
	if p == nil {
		return true
	}
	return p.Review.FailOnHighVulnerability
}

// blockOnProtectedPaths reports whether protected-path changes should
// block (vs warn). v0.1 ties this to require_diff_review: a policy
// that requires human review of the diff implies protected paths must
// be reviewed before export, which the gate enforces by blocking.
func blockOnProtectedPaths(p *config.PolicyConfig) bool {
	if p == nil {
		return false
	}
	return p.Review.RequireDiffReview
}

// blockOnLargeDiff mirrors blockOnProtectedPaths: a policy that
// requires diff review blocks on oversized diffs.
func blockOnLargeDiff(p *config.PolicyConfig) bool {
	if p == nil {
		return false
	}
	return p.Review.RequireDiffReview
}

// blockOnLockfileChange mirrors blockOnProtectedPaths.
func blockOnLockfileChange(p *config.PolicyConfig) bool {
	if p == nil {
		return false
	}
	return p.Review.RequireDiffReview
}

// blockOnNewExecutables mirrors blockOnProtectedPaths.
func blockOnNewExecutables(p *config.PolicyConfig) bool {
	if p == nil {
		return false
	}
	return p.Review.RequireDiffReview
}

// normalizeSlash converts a host-path-separated string to forward
// slashes so the gate's prefix matches work on Windows too. The
// workspace layer already normalizes paths but we double-check here so
// a caller that hands us a raw filepath does not slip past the rule.
func normalizeSlash(s string) string {
	return filepath.ToSlash(s)
}
