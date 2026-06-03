package cli

import (
	"strings"
	"testing"

	"github.com/i1rr/ai-env/internal/export"
	"github.com/i1rr/ai-env/internal/githubbroker"
	"github.com/i1rr/ai-env/internal/run"
	"github.com/i1rr/ai-env/internal/scanners"
)

// TestGateDecisionEvent_Allow pins the shape of a gate-allow event: the
// Decision must be "allow", the Surface must echo the caller's value,
// and Reasons must be empty (warnings are intentionally not persisted).
func TestGateDecisionEvent_Allow(t *testing.T) {
	verdict := export.GateResult{
		Decision: export.DecisionAllow,
		Reasons: []export.Reason{
			{Code: export.ReasonLargeDiff, Severity: export.SeverityWarn, Message: "large diff"},
		},
	}
	evt := gateDecisionEvent("pr", "fix-tests", verdict)

	if evt.Event != run.PolicyDecisionExportGate {
		t.Errorf("Event=%q, want %q", evt.Event, run.PolicyDecisionExportGate)
	}
	if evt.Decision != run.PolicyDecisionAllow {
		t.Errorf("Decision=%q, want %q", evt.Decision, run.PolicyDecisionAllow)
	}
	if evt.Surface != "pr" {
		t.Errorf("Surface=%q, want %q", evt.Surface, "pr")
	}
	if evt.EnvName != "fix-tests" {
		t.Errorf("EnvName=%q, want %q", evt.EnvName, "fix-tests")
	}
	if len(evt.Reasons) != 0 {
		t.Errorf("Reasons=%v, want empty (warnings are not persisted)", evt.Reasons)
	}
}

// TestGateDecisionEvent_Block pins the shape of a gate-block event: the
// Decision must be "block" and Reasons must carry the per-blocker
// messages so the on-disk log is self-contained.
func TestGateDecisionEvent_Block(t *testing.T) {
	verdict := export.GateResult{
		Decision: export.DecisionBlock,
		Reasons: []export.Reason{
			{Code: export.ReasonSecretFinding, Severity: export.SeverityBlock, Message: "leak at foo.go:1"},
			{Code: export.ReasonWorkflowChange, Severity: export.SeverityBlock, Message: ".github/workflows/ci.yml changed"},
			{Code: export.ReasonLargeDiff, Severity: export.SeverityWarn, Message: "large diff"},
		},
	}
	evt := gateDecisionEvent("pr", "fix-tests", verdict)

	if evt.Decision != run.PolicyDecisionBlock {
		t.Errorf("Decision=%q, want %q", evt.Decision, run.PolicyDecisionBlock)
	}
	if len(evt.Reasons) != 2 {
		t.Fatalf("Reasons len=%d, want 2 (block-severity only)", len(evt.Reasons))
	}
	if !strings.Contains(evt.Reasons[0], "secret_finding") {
		t.Errorf("Reasons[0]=%q, want substring 'secret_finding'", evt.Reasons[0])
	}
	if !strings.Contains(evt.Reasons[1], "workflow_change") {
		t.Errorf("Reasons[1]=%q, want substring 'workflow_change'", evt.Reasons[1])
	}
}

// TestBrokerActionEvent_Allow pins the simple-stage success shape:
// Action / Decision / EnvName / Branch / Repo round-trip onto the
// event without an Error or Reasons.
func TestBrokerActionEvent_Allow(t *testing.T) {
	evt := brokerActionEvent(
		run.PolicyActionBrokerPushBranch,
		run.PolicyDecisionAllow,
		"fix-tests", "ai-env/fix-tests", "acme", "demo",
		"", nil,
	)
	if evt.Event != run.PolicyDecisionBrokerAction {
		t.Errorf("Event=%q, want %q", evt.Event, run.PolicyDecisionBrokerAction)
	}
	if evt.Action != run.PolicyActionBrokerPushBranch {
		t.Errorf("Action=%q, want %q", evt.Action, run.PolicyActionBrokerPushBranch)
	}
	if evt.Decision != run.PolicyDecisionAllow {
		t.Errorf("Decision=%q, want %q", evt.Decision, run.PolicyDecisionAllow)
	}
	if evt.Branch != "ai-env/fix-tests" {
		t.Errorf("Branch=%q, want %q", evt.Branch, "ai-env/fix-tests")
	}
	if evt.Repo != "acme/demo" {
		t.Errorf("Repo=%q, want %q", evt.Repo, "acme/demo")
	}
	if evt.Error != "" {
		t.Errorf("Error=%q, want empty on success", evt.Error)
	}
	if len(evt.Reasons) != 0 {
		t.Errorf("Reasons=%v, want empty on success", evt.Reasons)
	}
}

// TestBrokerActionEvent_FailRedactsToken pins the security contract: an
// error string that echoes a token-like substring (e.g. a transport
// error that quoted a credential header) must be passed through the
// broker's redactor before it lands on disk.
func TestBrokerActionEvent_FailRedactsToken(t *testing.T) {
	leaked := "push failed: Authorization: token ghp_abcdefghijklmnopqrstuvwxyz0123456789 returned 401"
	evt := brokerActionEvent(
		run.PolicyActionBrokerPushBranch,
		run.PolicyDecisionFail,
		"fix-tests", "ai-env/fix-tests", "acme", "demo",
		leaked, nil,
	)
	if evt.Error == leaked {
		t.Fatalf("Error was not redacted, got %q", evt.Error)
	}
	if strings.Contains(evt.Error, "ghp_") {
		t.Errorf("Error still contains raw token: %q", evt.Error)
	}
	if !strings.Contains(evt.Error, githubbroker.RedactedPlaceholder) && !strings.Contains(evt.Error, "REDACTED") {
		t.Errorf("Error should contain a redaction marker, got %q", evt.Error)
	}
}

// TestBrokerActionEvent_NoRepoCoordinates pins the optional-field
// behavior: when neither Owner nor Name is set the Repo field stays
// empty so a Prepare-stage failure that has no Repo coordinates yet
// does not write a misleading "/" string.
func TestBrokerActionEvent_NoRepoCoordinates(t *testing.T) {
	evt := brokerActionEvent(
		run.PolicyActionBrokerPrepare,
		run.PolicyDecisionBlock,
		"fix-tests", "ai-env/fix-tests", "", "",
		"branch prefix invalid", nil,
	)
	if evt.Repo != "" {
		t.Errorf("Repo=%q, want empty when both owner+name are missing", evt.Repo)
	}
}

// TestBrokerCreatePREvent_CarriesPRCoords pins the specialized
// constructor: it must carry the PR number, URL, and token kind on the
// event so a successful create is fully described in the audit log.
func TestBrokerCreatePREvent_CarriesPRCoords(t *testing.T) {
	pr := githubbroker.PRResult{
		Number: 7,
		URL:    "https://github.com/acme/demo/pull/7",
		Draft:  true,
	}
	evt := brokerCreatePREvent(
		"fix-tests", "ai-env/fix-tests", "acme", "demo",
		pr, githubbroker.TokenKindGitHubApp,
	)
	if evt.Action != run.PolicyActionBrokerCreatePR {
		t.Errorf("Action=%q, want %q", evt.Action, run.PolicyActionBrokerCreatePR)
	}
	if evt.Decision != run.PolicyDecisionAllow {
		t.Errorf("Decision=%q, want %q", evt.Decision, run.PolicyDecisionAllow)
	}
	if evt.PRNumber != 7 {
		t.Errorf("PRNumber=%d, want 7", evt.PRNumber)
	}
	if evt.PRURL != "https://github.com/acme/demo/pull/7" {
		t.Errorf("PRURL=%q, want the PR URL", evt.PRURL)
	}
	if evt.TokenKind != string(githubbroker.TokenKindGitHubApp) {
		t.Errorf("TokenKind=%q, want %q", evt.TokenKind, githubbroker.TokenKindGitHubApp)
	}
}

// TestBrokerMetadataScanBlockEvent_FoldsFindings pins the scan-block
// constructor: each blocking finding must produce a Reasons entry that
// names the finding's type, pattern, confidence, and location.
func TestBrokerMetadataScanBlockEvent_FoldsFindings(t *testing.T) {
	findings := []scanners.Finding{
		{
			ID:           "f1",
			Type:         "api_key",
			Pattern:      "Anthropic sk-ant- prefix",
			Confidence:   scanners.ConfidenceHigh,
			File:         "pr_title",
			Line:         1,
			BlocksExport: true,
		},
		{
			ID:           "f2",
			Type:         "github_token",
			Pattern:      "ghp_ prefix",
			Confidence:   scanners.ConfidenceHigh,
			File:         "commit_message[0]",
			Line:         3,
			BlocksExport: true,
		},
	}
	evt := brokerMetadataScanBlockEvent(
		"fix-tests", "ai-env/fix-tests", "acme", "demo",
		findings, githubbroker.TokenKindGitHubApp,
	)
	if evt.Decision != run.PolicyDecisionBlock {
		t.Errorf("Decision=%q, want %q", evt.Decision, run.PolicyDecisionBlock)
	}
	if evt.Action != run.PolicyActionBrokerScanMetadata {
		t.Errorf("Action=%q, want %q", evt.Action, run.PolicyActionBrokerScanMetadata)
	}
	if len(evt.Reasons) != 2 {
		t.Fatalf("Reasons len=%d, want 2", len(evt.Reasons))
	}
	if !strings.Contains(evt.Reasons[0], "api_key") || !strings.Contains(evt.Reasons[0], "pr_title") {
		t.Errorf("Reasons[0]=%q, want substrings 'api_key' and 'pr_title'", evt.Reasons[0])
	}
	if !strings.Contains(evt.Reasons[1], "github_token") || !strings.Contains(evt.Reasons[1], "commit_message[0]") {
		t.Errorf("Reasons[1]=%q, want substrings 'github_token' and 'commit_message[0]'", evt.Reasons[1])
	}
}

// TestClassifyBrokerErr_PolicyErrorsBlock pins the broker-side error
// classifier: a wrap of one of the broker's sentinel errors must map to
// "block"; an unknown error maps to "fail". The distinction matters
// because an operator reading policy-decisions.jsonl uses it to tell a
// policy refusal from a transient outage.
func TestClassifyBrokerErr_PolicyErrorsBlock(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, run.PolicyDecisionAllow},
		{"branch_prefix", githubbroker.ErrInvalidBranchPrefix, run.PolicyDecisionBlock},
		{"protected_branch", githubbroker.ErrProtectedBranch, run.PolicyDecisionBlock},
		{"protected_path", githubbroker.ErrProtectedPath, run.PolicyDecisionBlock},
		{"token_expired", githubbroker.ErrTokenExpired, run.PolicyDecisionBlock},
		{"token_revoked", githubbroker.ErrTokenRevoked, run.PolicyDecisionBlock},
		{"infra_failure", errSentinel("network unreachable"), run.PolicyDecisionFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyBrokerErr(tc.err)
			if got != tc.want {
				t.Errorf("classifyBrokerErr(%v)=%q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// errSentinel is a tiny error type the classifier test uses to stand in
// for a non-sentinel infrastructure error.
type errSentinel string

func (e errSentinel) Error() string { return string(e) }
