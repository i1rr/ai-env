package cli

import (
	"fmt"

	"github.com/i1rr/ai-env/internal/export"
	"github.com/i1rr/ai-env/internal/githubbroker"
	"github.com/i1rr/ai-env/internal/run"
	"github.com/i1rr/ai-env/internal/scanners"
)

// policy_events.go implements Plan 07 step 12: the pure event-shaping
// helpers that translate gate verdicts and broker action outcomes into
// run.PolicyDecisionEvent values. The functions are pure (no I/O, no
// time-of-day reads, no goroutine state) so they can be unit tested in
// isolation; the CLI wires the resulting events through a
// run.PolicyDecisionsWriter at call time.
//
// Design rules:
//
//  1. One function per emission point. RunPR has a small number of
//     well-defined emission points (gate verdict, each broker stage's
//     outcome) and pushing each into a named helper keeps the call site
//     readable.
//
//  2. Token-bearing fields pass through githubbroker.RedactTokens
//     before they land on the event. The writer itself does not redact
//     because the responsibility lives at the emission site where the
//     payload shape is known. Today only the Error field can carry a
//     token-looking substring (a transport-level error may echo a
//     header), so that is the only field we redact; if a future field
//     can carry credential material the new emission helper must
//     redact it before construction.
//
//  3. Reasons are short human-readable strings, not structured codes.
//     The on-disk file is for operators reading the log directly; a
//     downstream consumer that wants to switch on a reason code will
//     have to read the Event verb and the Decision pair, which uniquely
//     identifies the rule category.

// gateDecisionEvent builds a run.PolicyDecisionEvent describing the
// outcome of an ExportGate evaluation. surface is "patch" or "pr"
// (matching export.Mode); envName is the workspace the verdict was
// rendered for; verdict carries the gate's Decision and Reasons.
//
// Only block-severity reasons are folded into Event.Reasons; warnings
// are surfaced to the operator via the CLI's stderr/stdout but are not
// persisted here so the file stays focused on decisions. Callers that
// want the warning list separately should read the verdict directly.
func gateDecisionEvent(surface, envName string, verdict export.GateResult) run.PolicyDecisionEvent {
	decision := run.PolicyDecisionAllow
	if verdict.Blocked() {
		decision = run.PolicyDecisionBlock
	}
	var reasons []string
	for _, r := range verdict.BlockingReasons() {
		reasons = append(reasons, fmt.Sprintf("[%s] %s", r.Code, r.Message))
	}
	return run.PolicyDecisionEvent{
		Event:    run.PolicyDecisionExportGate,
		Surface:  surface,
		EnvName:  envName,
		Decision: decision,
		Reasons:  reasons,
	}
}

// brokerActionEvent builds a run.PolicyDecisionEvent describing the
// outcome of a single broker lifecycle stage. action is one of the
// run.PolicyActionBroker* constants. decision is one of
// run.PolicyDecisionAllow / PolicyDecisionBlock / PolicyDecisionFail.
//
// envName, branch, and repoOwner / repoName populate the corresponding
// event fields so an operator reading the file sees enough context to
// trace the event back to a workspace and a target without joining
// against run.json. repoOwner and repoName may be empty (e.g. on a
// Prepare-stage failure that has no Repo coordinates yet).
//
// errMsg is the error string when decision is PolicyDecisionFail. It is
// passed through githubbroker.RedactTokens so a transport-level error
// that echoes a credential header (e.g. "Authorization: token ghs_...
// returned 401") does not land on disk verbatim. An empty errMsg is
// preserved as empty.
//
// reasons is the per-blocker explanation slice when decision is
// PolicyDecisionBlock. The caller passes the already-formatted strings;
// brokerActionEvent does not parse them.
func brokerActionEvent(action, decision, envName, branch, repoOwner, repoName, errMsg string, reasons []string) run.PolicyDecisionEvent {
	evt := run.PolicyDecisionEvent{
		Event:    run.PolicyDecisionBrokerAction,
		Action:   action,
		Decision: decision,
		EnvName:  envName,
		Branch:   branch,
		Reasons:  reasons,
	}
	if repoOwner != "" || repoName != "" {
		evt.Repo = fmt.Sprintf("%s/%s", repoOwner, repoName)
	}
	if errMsg != "" {
		evt.Error = githubbroker.RedactTokens(errMsg)
	}
	return evt
}

// brokerCreatePREvent is the specialized helper for the successful
// CreateDraftPR path. It carries the PR coordinates (number, URL) that
// other broker-stage events do not; pulling it into its own constructor
// keeps brokerActionEvent's signature short.
func brokerCreatePREvent(envName, branch, repoOwner, repoName string, pr githubbroker.PRResult, tokenKind githubbroker.TokenKind) run.PolicyDecisionEvent {
	evt := brokerActionEvent(
		run.PolicyActionBrokerCreatePR,
		run.PolicyDecisionAllow,
		envName, branch, repoOwner, repoName,
		"", nil,
	)
	evt.PRNumber = pr.Number
	evt.PRURL = pr.URL
	if tokenKind != "" {
		evt.TokenKind = string(tokenKind)
	}
	return evt
}

// brokerMetadataScanBlockEvent is the specialized helper for the
// ScanMetadata block path: a scan that surfaced one or more
// BlocksExport findings refuses CreateDraftPR and writes a
// broker_scan_metadata block event with one Reason per finding.
//
// The finding's user-visible fields (Type, Pattern, File, Line) are
// folded into the reason string; the finding's raw matched text is not
// included because the scanner already redacted the high-confidence
// part and we do not want to re-leak the surrounding context.
func brokerMetadataScanBlockEvent(envName, branch, repoOwner, repoName string, findings []scanners.Finding, tokenKind githubbroker.TokenKind) run.PolicyDecisionEvent {
	reasons := make([]string, 0, len(findings))
	for _, f := range findings {
		reasons = append(reasons, fmt.Sprintf("[%s][%s] %s at %s:%d", f.Type, f.Pattern, f.Confidence, f.File, f.Line))
	}
	evt := brokerActionEvent(
		run.PolicyActionBrokerScanMetadata,
		run.PolicyDecisionBlock,
		envName, branch, repoOwner, repoName,
		"", reasons,
	)
	if tokenKind != "" {
		evt.TokenKind = string(tokenKind)
	}
	return evt
}
