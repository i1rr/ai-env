// Package export owns the export gate that sits between a finished run
// and the user-visible export paths (`ai-env patch`, `ai-env pr`). The
// gate is plan 06 step 7: it consumes the scan results from
// internal/scanners (step 2-6), the workspace diff from
// internal/workspace, the policy document from internal/config, and the
// run record from internal/run, then returns a single GateResult the
// CLI consults to decide whether the diff is allowed out.
//
// Design rules this package enforces:
//
//  1. One decision point. Every export surface (`ai-env patch` today,
//     `ai-env pr` in plan 07) must call ExportGate.Evaluate and respect
//     its verdict. The CLI never reimplements blocker logic so a future
//     policy tweak is a one-file change.
//  2. Hard vs. configurable. The plan splits blockers into two buckets:
//     hard blockers cannot be overridden by default (a high-confidence
//     secret leak is never shippable), configurable blockers can be
//     adjusted from policy.yaml (large diffs, lockfile changes, etc.).
//     Reasons carry that distinction explicitly so the CLI can render
//     the difference and the user knows what an override would relax.
//  3. Mode-aware. The same diff is gated differently for `patch` and
//     `pr`: a .github/workflows change is fatal for a brokered PR but
//     only a warning for a local patch export. Mode parameterizes the
//     gate so both call sites share one code path.
//  4. Pure evaluator. Evaluate is a pure function over Input. It does
//     no I/O: the CLI is responsible for loading scan-results,
//     workspace diff, policy, and run record from disk and handing
//     them in. This keeps the gate trivially testable and lets the
//     caller decide where artifacts live.
//  5. Stable reasons. ReasonCode values are the protocol the CLI
//     pattern-matches on (e.g. to decide whether to suggest a specific
//     override flag). They never change meaning; new categories add
//     new codes.
package export

import (
	"github.com/rivan1986/ai-env/internal/config"
	"github.com/rivan1986/ai-env/internal/run"
	"github.com/rivan1986/ai-env/internal/scanners"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// Mode identifies which export surface is asking for a decision. The
// gate's rules differ between the two: a workflow-file change is a hard
// block for a brokered PR but only a warning for a local patch export.
type Mode string

const (
	// ModePatch is `ai-env patch`: the diff is written to a local file
	// the user reviews and applies manually. The gate still blocks on
	// secret leaks and quarantine, but workflow changes degrade to a
	// warning so the user can see the proposed change in context.
	ModePatch Mode = "patch"

	// ModePR is `ai-env pr`: the diff is shipped through the brokered
	// PR path (plan 07). All hard blockers apply, including workflow
	// changes and protected branch pushes.
	ModePR Mode = "pr"
)

// Decision is the top-level allow/block verdict the gate produces. The
// CLI consults it first; the per-Reason detail is for rendering and for
// distinguishing hard blocks from warnings.
type Decision string

const (
	// DecisionAllow means the diff may be exported. There may still be
	// warning-level Reasons in the result; the CLI surfaces them but
	// does not abort.
	DecisionAllow Decision = "allow"

	// DecisionBlock means the diff must not be exported. The Reasons
	// slice contains at least one entry with Severity=SeverityBlock
	// explaining why.
	DecisionBlock Decision = "block"
)

// Severity categorizes a single Reason. The gate's Decision is Block
// iff any Reason has SeverityBlock; SeverityWarn entries never flip the
// top-level verdict but are surfaced to the user so they know what the
// gate noticed.
type Severity string

const (
	// SeverityBlock means the reason prevents export. At least one
	// SeverityBlock reason forces Decision=DecisionBlock.
	SeverityBlock Severity = "block"

	// SeverityWarn means the reason is informational. It is surfaced
	// to the user but does not flip the decision; configurable
	// blockers that are disabled in policy.yaml degrade to this level
	// rather than disappearing entirely so the user still sees them.
	SeverityWarn Severity = "warn"
)

// ReasonCode is the stable identifier for a category of blocker. CLI
// code that wants to render a specific override hint (e.g. "pass
// --allow-protected-paths") pattern-matches on this rather than parsing
// Message text. Values must stay stable across versions; deprecate by
// adding a new code rather than reusing an old one.
type ReasonCode string

const (
	// --- hard blockers --------------------------------------------------

	// ReasonSecretFinding identifies a high-confidence secret match
	// produced by the built-in pattern scanner. Always SeverityBlock.
	ReasonSecretFinding ReasonCode = "secret_finding"

	// ReasonExternalSecretFinding identifies a finding produced by an
	// external secret scanner (gitleaks today). Always SeverityBlock.
	ReasonExternalSecretFinding ReasonCode = "external_secret_finding"

	// ReasonWorkflowChange identifies a change to .github/workflows/**.
	// SeverityBlock under ModePR; SeverityWarn under ModePatch so the
	// user can still inspect the proposed change locally.
	ReasonWorkflowChange ReasonCode = "workflow_change"

	// ReasonAIEnvChange identifies a change under .ai-env/**. The
	// agent must never edit its own policy or escape hatches; always
	// SeverityBlock.
	ReasonAIEnvChange ReasonCode = "ai_env_change"

	// ReasonQuarantine identifies a run whose record's State is
	// quarantined. The artifacts stay on disk for inspection but
	// never make it out; always SeverityBlock.
	ReasonQuarantine ReasonCode = "quarantine"

	// ReasonPolicyChange identifies a change to policy.yaml itself
	// (a sub-case of the .ai-env/** rule, surfaced separately so the
	// CLI can render a specific message). Always SeverityBlock.
	ReasonPolicyChange ReasonCode = "policy_change"

	// --- configurable blockers ------------------------------------------

	// ReasonHighSeverityVuln identifies a high-severity dependency
	// vulnerability reported by an external scanner. Severity is
	// SeverityBlock when policy.review.fail_on_high_vulnerability is
	// true, SeverityWarn otherwise.
	ReasonHighSeverityVuln ReasonCode = "high_severity_vulnerability"

	// ReasonProtectedPath identifies a workspace-relative file the
	// configured ProtectedMatcher flagged. Severity follows the
	// configurable-blocker rule: SeverityBlock when policy enables
	// the gate, SeverityWarn otherwise.
	ReasonProtectedPath ReasonCode = "protected_path"

	// ReasonLargeDiff identifies a diff whose total line count
	// exceeds the policy threshold. Severity follows the
	// configurable-blocker rule.
	ReasonLargeDiff ReasonCode = "large_diff"

	// ReasonNewBinaryFile identifies a newly added file the scanner
	// flagged as binary. Severity follows the configurable-blocker
	// rule.
	ReasonNewBinaryFile ReasonCode = "new_binary_file"

	// ReasonNewExecutableFile identifies a newly added file the
	// scanner flagged as executable. Severity follows the
	// configurable-blocker rule.
	ReasonNewExecutableFile ReasonCode = "new_executable_file"

	// ReasonLockfileChange identifies a change to a known lockfile.
	// Severity follows the configurable-blocker rule.
	ReasonLockfileChange ReasonCode = "lockfile_change"
)

// Reason is one entry in a GateResult: a single blocker the gate
// observed, with enough metadata for the CLI to render it and for the
// caller to distinguish hard from configurable rules.
type Reason struct {
	// Code is the stable identifier for the blocker category. CLI
	// pattern-matches on this; see ReasonCode for the enumeration.
	Code ReasonCode

	// Severity is the per-reason verdict. SeverityBlock entries force
	// the gate's overall Decision to DecisionBlock; SeverityWarn
	// entries are surfaced but do not flip the verdict.
	Severity Severity

	// Message is a short human-readable explanation suitable for
	// rendering verbatim in the CLI's output. It includes the
	// specific file path / finding ID / count that triggered the
	// reason so the user does not have to cross-reference artifacts
	// to understand it.
	Message string

	// Path is the workspace-relative file path the reason refers to,
	// when the reason is file-scoped. Empty for reasons that apply to
	// the run as a whole (quarantine, large diff size).
	Path string

	// FindingID is the scanner finding ID this reason corresponds to,
	// when the reason originated from a scanner finding. Empty for
	// non-scanner reasons.
	FindingID string

	// Hard reports whether this reason comes from a hard blocker
	// (cannot be overridden by default policy) or a configurable
	// blocker (can be adjusted in policy.yaml). The CLI uses this to
	// render the "this is a default-on rule" vs. "your policy says
	// to block on this" distinction.
	Hard bool
}

// Input is the bundle of data Evaluate consults. The caller assembles
// it from the run directory and policy.yaml; the gate never reads from
// disk itself so tests can drive it with synthetic input and the CLI
// can decide where artifacts live.
//
// Every field is optional in the sense that a zero value is meaningful:
// a nil ScanResults slice means "no scan ran"; a zero workspace.DiffResult
// means "no diff"; a nil Record means "no run record" (e.g. an ad-hoc
// patch export off a workspace that has never been run). Evaluate
// handles each absence sensibly rather than treating it as an error.
type Input struct {
	// Mode selects which export surface is asking. The gate's rules
	// for workflow changes differ between patch and pr.
	Mode Mode

	// Diff is the workspace diff the export would ship. The gate
	// inspects Files (for path-scoped rules), ProtectedHits (for the
	// protected-path rule), and the unified body length (for the
	// large-diff rule).
	Diff workspace.DiffResult

	// BuiltInResult is the built-in pattern-only scanner's result.
	// The gate treats every Finding with BlocksExport=true as a hard
	// secret-leak block.
	BuiltInResult scanners.ScanResult

	// ExternalResults is the per-tool result list from external
	// scanners (gitleaks, osv-scanner, trivy, etc.). The gate routes
	// each entry by its Scanner name: gitleaks findings are hard
	// secret blocks, vulnerability scanners feed the high-severity
	// dependency rule.
	ExternalResults []scanners.ScanResult

	// Policy is the parsed policy.yaml. The gate consults the Review
	// section for configurable-blocker toggles and the Filesystem
	// section for the protected-path list. A nil Policy means "no
	// policy loaded": the gate falls back to the documented defaults.
	Policy *config.PolicyConfig

	// Record is the run.json record for the run the export is
	// shipping. The gate inspects Record.State for the quarantine
	// rule. A nil Record means "no run yet" (e.g. an ad-hoc patch off
	// an unrun workspace); the quarantine rule is skipped in that
	// case rather than treated as a block.
	Record *run.Record
}

// GateResult is the structured verdict Evaluate produces. The CLI
// renders Reasons (Decision is a derived field from the per-reason
// severities); tests assert on both Decision and the Reason slice.
type GateResult struct {
	// Decision is the top-level verdict. DecisionBlock iff any Reason
	// has Severity=SeverityBlock; DecisionAllow otherwise.
	Decision Decision

	// Reasons is the ordered list of per-blocker observations. Hard
	// blockers come first, then configurable blockers, then warnings.
	// Within a category the order is the gate's evaluation order so
	// the output is deterministic across runs.
	Reasons []Reason
}

// Blocked reports whether the result's Decision is DecisionBlock. It
// is a convenience method for CLI code that only cares about the
// boolean verdict ("if gate.Blocked() { return ... }") without having
// to compare strings.
func (r GateResult) Blocked() bool {
	return r.Decision == DecisionBlock
}

// BlockingReasons returns the subset of Reasons whose Severity is
// SeverityBlock. The CLI prints these as the "export blocked because"
// list; warning-level reasons are rendered separately so users can
// distinguish "this prevented export" from "this is something to
// notice".
func (r GateResult) BlockingReasons() []Reason {
	out := make([]Reason, 0, len(r.Reasons))
	for _, reason := range r.Reasons {
		if reason.Severity == SeverityBlock {
			out = append(out, reason)
		}
	}
	return out
}

// Warnings returns the subset of Reasons whose Severity is
// SeverityWarn. Symmetric helper to BlockingReasons.
func (r GateResult) Warnings() []Reason {
	out := make([]Reason, 0, len(r.Reasons))
	for _, reason := range r.Reasons {
		if reason.Severity == SeverityWarn {
			out = append(out, reason)
		}
	}
	return out
}
