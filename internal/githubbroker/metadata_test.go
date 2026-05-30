package githubbroker

import (
	"errors"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/scanners"
)

// newRealScanner builds a real *scanners.BuiltIn so ScanMetadata is
// exercised end-to-end through the same built-in pattern set that
// gates workspace exports. The tests deliberately avoid mocking
// MetadataScanner: plan 07 step 5 hinges on the broker reusing Plan
// 06's vocabulary, so the meaningful contract is "the same patterns
// that block a workspace file also block a PR title".
func newRealScanner(t *testing.T) *scanners.BuiltIn {
	t.Helper()
	b, err := scanners.NewBuiltIn(scanners.Config{})
	if err != nil {
		t.Fatalf("scanners.NewBuiltIn: %v", err)
	}
	return b
}

// fakeAnthropicKey is a non-live secret shape that matches the
// "Anthropic sk-ant- prefix" pattern. It is reused across tests for
// the title/body/branch/commit channels so any change to the pattern
// surface lights up every metadata field at once.
const fakeAnthropicKey = "sk-ant-AAAAAAAAAAAAAAAAAAAA1234567890"

// fakeGitHubPAT is a second fake-shape token reused for cases that
// need a different pattern in the same Metadata bundle (so the
// finding_NNN renumbering is observable).
const fakeGitHubPAT = "ghp_AAAAAAAAAAAAAAAAAAAA12345678901234"

// TestScanMetadata_TitleSecretBlocksExport pins the contract from plan
// 07 step 5: a fake secret in the PR title produces a finding whose
// BlocksExport=true so the downstream ExportGate refuses submission.
func TestScanMetadata_TitleSecretBlocksExport(t *testing.T) {
	scanner := newRealScanner(t)
	md := Metadata{
		Title:      "fix login " + fakeAnthropicKey,
		Body:       "Clean body.",
		BranchName: "ai-env/fix-login",
	}
	res, err := ScanMetadata(scanner, md)
	if err != nil {
		t.Fatalf("ScanMetadata err=%v, want nil", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("len(Findings)=%d, want 1; findings=%+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.File != LabelPRTitle {
		t.Fatalf("Finding.File=%q, want %q", f.File, LabelPRTitle)
	}
	if !f.BlocksExport {
		t.Fatalf("Finding.BlocksExport=false, want true (ExportGate must block)")
	}
	if f.Confidence != scanners.ConfidenceHigh {
		t.Fatalf("Finding.Confidence=%q, want %q", f.Confidence, scanners.ConfidenceHigh)
	}
	if f.ID != "finding_001" {
		t.Fatalf("Finding.ID=%q, want finding_001", f.ID)
	}
	if res.Scanner != "built-in-patterns" {
		t.Fatalf("Scanner=%q, want built-in-patterns", res.Scanner)
	}
}

// TestScanMetadata_BodySecretBlocksExport pins the same rule for the
// PR body field; line numbers are propagated so a multi-line body
// produces a localized finding.
func TestScanMetadata_BodySecretBlocksExport(t *testing.T) {
	scanner := newRealScanner(t)
	body := strings.Join([]string{
		"## Summary",
		"This PR refactors auth.",
		"oops " + fakeAnthropicKey,
		"## Test plan",
	}, "\n")
	md := Metadata{
		Title:      "Refactor auth",
		Body:       body,
		BranchName: "ai-env/refactor-auth",
	}
	res, err := ScanMetadata(scanner, md)
	if err != nil {
		t.Fatalf("ScanMetadata err=%v, want nil", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("len(Findings)=%d, want 1; findings=%+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.File != LabelPRBody {
		t.Fatalf("Finding.File=%q, want %q", f.File, LabelPRBody)
	}
	if f.Line != 3 {
		t.Fatalf("Finding.Line=%d, want 3 (1-based line within body)", f.Line)
	}
	if !f.BlocksExport {
		t.Fatalf("Finding.BlocksExport=false, want true")
	}
}

// TestScanMetadata_CommitMessageSecretBlocksExport pins the commit
// message channel: a fake secret in commit message index 1 (the
// second commit) lights up with a commit_message[1] label so the
// operator can trace the leak back to the offending commit.
func TestScanMetadata_CommitMessageSecretBlocksExport(t *testing.T) {
	scanner := newRealScanner(t)
	md := Metadata{
		Title:      "Refactor auth",
		Body:       "Clean.",
		BranchName: "ai-env/refactor-auth",
		CommitMessages: []string{
			"refactor: rename middleware",
			"chore: rotate key " + fakeAnthropicKey,
			"docs: note migration",
		},
	}
	res, err := ScanMetadata(scanner, md)
	if err != nil {
		t.Fatalf("ScanMetadata err=%v, want nil", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("len(Findings)=%d, want 1; findings=%+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	wantLabel := LabelCommitMessage(1)
	if f.File != wantLabel {
		t.Fatalf("Finding.File=%q, want %q", f.File, wantLabel)
	}
	if !f.BlocksExport {
		t.Fatalf("Finding.BlocksExport=false, want true")
	}
	if !strings.HasPrefix(f.File, "commit_message[") {
		t.Fatalf("Finding.File=%q lacks commit_message[ prefix", f.File)
	}
}

// TestScanMetadata_BranchNameSecretBlocksExport confirms the branch
// name field is also scanned. The plan calls this out in step 5; a
// clever agent that embedded a key in a branch name would otherwise
// leak it through the git push refspec.
func TestScanMetadata_BranchNameSecretBlocksExport(t *testing.T) {
	scanner := newRealScanner(t)
	md := Metadata{
		Title:      "Refactor auth",
		Body:       "Clean.",
		BranchName: "ai-env/leak-" + fakeAnthropicKey,
	}
	res, err := ScanMetadata(scanner, md)
	if err != nil {
		t.Fatalf("ScanMetadata err=%v, want nil", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("len(Findings)=%d, want 1; findings=%+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].File != LabelPRBranch {
		t.Fatalf("Finding.File=%q, want %q", res.Findings[0].File, LabelPRBranch)
	}
	if !res.Findings[0].BlocksExport {
		t.Fatalf("Finding.BlocksExport=false, want true")
	}
}

// TestScanMetadata_CleanMetadataReturnsNoFindings pins the negative
// case: when every field is clean, the scan produces a ScanResult with
// zero findings and a nil error. ExportGate sees an empty findings
// slice and lets the PR through.
func TestScanMetadata_CleanMetadataReturnsNoFindings(t *testing.T) {
	scanner := newRealScanner(t)
	md := Metadata{
		Title:      "Refactor auth middleware",
		Body:       "## Summary\nMove auth into its own package.\n## Test plan\n- run unit tests",
		BranchName: "ai-env/refactor-auth",
		CommitMessages: []string{
			"refactor: extract auth package",
			"test: add coverage for the new entry point",
		},
	}
	res, err := ScanMetadata(scanner, md)
	if err != nil {
		t.Fatalf("ScanMetadata err=%v, want nil", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("len(Findings)=%d, want 0; findings=%+v", len(res.Findings), res.Findings)
	}
	if res.Scanner != "built-in-patterns" {
		t.Fatalf("Scanner=%q, want built-in-patterns", res.Scanner)
	}
}

// TestScanMetadata_NilScannerErrors pins the contract that a caller
// who forgets to wire the scanner gets a clear error rather than a
// silent "clean" ScanResult. The error wraps ErrMetadataScanBlocked so
// the CLI can render the right remediation hint.
func TestScanMetadata_NilScannerErrors(t *testing.T) {
	md := Metadata{Title: "anything"}
	_, err := ScanMetadata(nil, md)
	if err == nil {
		t.Fatalf("ScanMetadata(nil, ...) = nil error, want error")
	}
	if !errors.Is(err, ErrMetadataScanBlocked) {
		t.Fatalf("error %v, want errors.Is ErrMetadataScanBlocked", err)
	}
}

// TestScanMetadata_FindingNumberingIsStable pins the finding_NNN
// renumbering rule. When secrets appear in multiple fields the merged
// ScanResult must produce finding_001, finding_002, ... in field order
// (title, body, branch, commits) so downstream consumers can cite an
// ID without having to know which field produced it.
func TestScanMetadata_FindingNumberingIsStable(t *testing.T) {
	scanner := newRealScanner(t)
	md := Metadata{
		Title:      "fix " + fakeAnthropicKey,
		Body:       "body " + fakeGitHubPAT,
		BranchName: "ai-env/leak-" + fakeAnthropicKey,
		CommitMessages: []string{
			"refactor: rotate " + fakeGitHubPAT,
		},
	}
	res, err := ScanMetadata(scanner, md)
	if err != nil {
		t.Fatalf("ScanMetadata err=%v, want nil", err)
	}
	if len(res.Findings) != 4 {
		t.Fatalf("len(Findings)=%d, want 4; findings=%+v", len(res.Findings), res.Findings)
	}
	wantOrder := []string{
		LabelPRTitle,
		LabelPRBody,
		LabelPRBranch,
		LabelCommitMessage(0),
	}
	for i, f := range res.Findings {
		wantID := []string{"finding_001", "finding_002", "finding_003", "finding_004"}[i]
		if f.ID != wantID {
			t.Fatalf("Findings[%d].ID=%q, want %q", i, f.ID, wantID)
		}
		if f.File != wantOrder[i] {
			t.Fatalf("Findings[%d].File=%q, want %q (field-order merge)", i, f.File, wantOrder[i])
		}
		if !f.BlocksExport {
			t.Fatalf("Findings[%d].BlocksExport=false, want true", i)
		}
	}
}

// TestScanMetadata_EmptyFieldsSkipped confirms an empty Body or
// BranchName produces no findings for those fields: ScanMetadata
// skips the scanner call rather than feeding an empty string and
// emitting a noise log line per brokered PR.
func TestScanMetadata_EmptyFieldsSkipped(t *testing.T) {
	scanner := newRealScanner(t)
	md := Metadata{
		Title:      "Refactor auth",
		Body:       "",
		BranchName: "",
	}
	res, err := ScanMetadata(scanner, md)
	if err != nil {
		t.Fatalf("ScanMetadata err=%v, want nil", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("len(Findings)=%d, want 0; findings=%+v", len(res.Findings), res.Findings)
	}
}

// TestLabelCommitMessage_FormatIsZeroBased pins the commit-message
// label format the CLI pattern-matches on. Changing this string would
// break the rendering of "secret found in commit message N" without
// any compile-time signal, so it gets its own test.
func TestLabelCommitMessage_FormatIsZeroBased(t *testing.T) {
	if got := LabelCommitMessage(0); got != "commit_message[0]" {
		t.Fatalf("LabelCommitMessage(0)=%q, want commit_message[0]", got)
	}
	if got := LabelCommitMessage(7); got != "commit_message[7]" {
		t.Fatalf("LabelCommitMessage(7)=%q, want commit_message[7]", got)
	}
}
