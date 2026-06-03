// metadata.go implements plan 07 step 5: the GitHub broker scans
// every human-visible PR metadata field with the Plan 06 built-in
// secret scanner before the broker is willing to push a branch or open
// a pull request. The plan calls the rule out in two places:
//
//  1. "Key decisions from master plan", item 9: "PR title, body, branch
//     name, and commit messages must pass the secret scanner before
//     submission."
//  2. "Token lifecycle": ScanMetadata sits between PushBranch and
//     CreateDraftPR so the broker cannot ship metadata it has not yet
//     screened.
//
// The helper is exported as a package-level function (mirroring
// ValidateBranchPrefix / ValidatePathGate in validate.go) for two
// reasons. First, the concrete GitHubBroker implementation lands in a
// later step; the helper has to be callable from a fake broker today so
// the CLI's `ai-env pr` stub and the run lifecycle hook can be wired
// against a stable contract. Second, ExportGate (plan 07 step 11) and
// unit tests share the same vocabulary; centralizing the scan call here
// means the "what counts as PR metadata" answer lives in exactly one
// place.
//
// The helper is intentionally policy-free: it does not decide whether
// findings block submission. The plan reuses the Plan 06 secret-scan
// contract verbatim (see the package doc, design rule 5), so the
// caller (ExportGate / CLI) compares ScanResult.Findings against
// Finding.BlocksExport the same way it does for workspace files. The
// broker's job is only to surface a ScanResult; the gate decides.
//
// The label scheme on findings is shared with internal/scanners and
// designed to be human-readable in the CLI's "export blocked because"
// rendering: a leak in the PR title appears as "pr_title:1", a leak in
// the body as "pr_body:N" (N is the line within the body), the branch
// name as "pr_branch:1", and a commit message as "commit_message[i]:N".
// These labels are stable; downstream tooling that filters findings by
// origin pattern-matches on them.

package githubbroker

import (
	"fmt"
	"time"

	"github.com/i1rr/ai-env/internal/scanners"
)

// MetadataScanner is the narrow contract ScanMetadata depends on. A
// full *scanners.BuiltIn satisfies it; tests inject a fake to drive
// the broker's metadata path without standing up the full scanner.
//
// The interface is intentionally smaller than scanners.ScanRunner: the
// broker's metadata scan never touches a filesystem path or an
// external scanner. Keeping the contract minimal lets the broker be
// tested with a one-method fake and signals to future maintainers
// that metadata scanning is a pure text operation, not a workspace
// walk.
type MetadataScanner interface {
	// ScanText runs the built-in pattern set against an in-memory text
	// payload labeled with the supplied identifier. See the
	// internal/scanners package for the contract; ScanMetadata calls
	// it once per metadata field.
	ScanText(label, text string) (scanners.ScanResult, error)
}

// Metadata is the bundle of human-visible PR fields ScanMetadata
// inspects. The plan enumerates these four explicitly: title, body,
// branch name, commit messages. They are grouped into a struct (rather
// than passed as four separate arguments) so a caller that adds a new
// metadata field (e.g. PR labels in a future revision) extends the
// struct in one place and ScanMetadata grows one more scan call to
// match.
//
// Every field is optional in the sense that the zero value is
// meaningful: an empty Title or BranchName is rejected by Prepare's
// other rules, not by ScanMetadata; ScanMetadata treats an empty
// string as "no text to scan" and produces no findings for that field.
type Metadata struct {
	// Title is the PR title the broker plans to submit. Single line;
	// embedded newlines are preserved for the scan but the GitHub API
	// would reject a multi-line title.
	Title string

	// Body is the broker-generated PR body. Plan 07 step 6 fixes the
	// body's content (sanitized run metadata, scan summary, file
	// list); ScanMetadata runs after the body has been assembled so
	// any leak that survived sanitization is caught here.
	Body string

	// BranchName is the workspace branch the broker plans to push.
	// Plan 07 step 2 fixes the "ai-env/" prefix; ScanMetadata does
	// not re-enforce the prefix (that is ValidateBranchPrefix's job)
	// but does scan the branch name for secrets. A clever agent that
	// embedded an API key in a branch name would otherwise leak it
	// through the git push refspec.
	BranchName string

	// CommitMessages is the list of commit message bodies the broker
	// plans to push. The list is scanned in order; each entry becomes
	// one label in the resulting ScanResult.
	CommitMessages []string
}

// Label constants name the per-field identifiers ScanMetadata stamps
// into Finding.File. They are exported so the CLI can pattern-match on
// them when rendering "secret found in PR title" vs. "secret found in
// commit message" without parsing free-form text.
//
// The commit-message label is parameterized by index because a single
// brokered PR can ship multiple commits; we want the operator to know
// which commit the leak is in, not just "a commit message somewhere".
const (
	// LabelPRTitle is the Finding.File value used for matches in the
	// PR title field.
	LabelPRTitle = "pr_title"

	// LabelPRBody is the Finding.File value used for matches in the
	// PR body field.
	LabelPRBody = "pr_body"

	// LabelPRBranch is the Finding.File value used for matches in the
	// branch name field.
	LabelPRBranch = "pr_branch"

	// labelCommitMessageFormat is the printf format ScanMetadata uses
	// to build a per-commit label. The "%d" is the zero-based index of
	// the commit in Metadata.CommitMessages. The format string is
	// unexported because the CLI matches on the LabelCommitMessage
	// helper below rather than parsing the format directly.
	labelCommitMessageFormat = "commit_message[%d]"
)

// LabelCommitMessage returns the Finding.File value ScanMetadata
// stamps onto matches in the i-th commit message (zero-based). The CLI
// uses it to map a finding back onto the operator's commit list. It is
// a one-line helper so the format string stays in one place; callers
// that want to match on the family pattern-match on the "commit_message["
// prefix instead.
func LabelCommitMessage(i int) string {
	return fmt.Sprintf(labelCommitMessageFormat, i)
}

// ScanMetadata runs scanner against every field in md and returns a
// single merged ScanResult. The merge is field-order deterministic:
// title first, then body, then branch name, then each commit message
// in list order. Finding IDs are re-numbered finding_001, finding_002,
// ... across the whole result so a caller can cite an ID without
// having to know which field it came from.
//
// The function is policy-free: it does not consult any "should this
// block" rule. The caller (ExportGate, plan 07 step 11) inspects
// ScanResult.Findings and applies the Plan 06 BlocksExport contract
// the same way it does for workspace files. ScanMetadata's only job
// is to produce the findings.
//
// The returned error wraps ErrMetadataScanBlocked when the underlying
// scanner reports a non-nil error on any field; this matches the
// interface doc on GitHubBroker.ScanMetadata, which reserves
// ErrMetadataScanBlocked for scanner infrastructure failures (not
// clean scans that found secrets). A nil scanner is reported as an
// error so a caller that forgets to wire the scanner does not silently
// produce a clean ScanResult.
func ScanMetadata(scanner MetadataScanner, md Metadata) (scanners.ScanResult, error) {
	if scanner == nil {
		return scanners.ScanResult{}, fmt.Errorf("%w: scanner is nil", ErrMetadataScanBlocked)
	}

	merged := scanners.ScanResult{
		Scanner:         "built-in-patterns",
		Findings:        []scanners.Finding{},
		EntropyWarnings: []scanners.EntropyWarning{},
	}

	// fields is the ordered list of (label, text) pairs we feed to the
	// scanner. Building the slice up-front keeps the merge loop a
	// single straight-line walk and makes the scan order explicit; a
	// reader can see at a glance what ScanMetadata covers.
	type fieldScan struct {
		label string
		text  string
	}
	fields := []fieldScan{
		{label: LabelPRTitle, text: md.Title},
		{label: LabelPRBody, text: md.Body},
		{label: LabelPRBranch, text: md.BranchName},
	}
	for i, msg := range md.CommitMessages {
		fields = append(fields, fieldScan{label: LabelCommitMessage(i), text: msg})
	}

	for _, fs := range fields {
		if fs.text == "" {
			// Empty fields produce no findings; skip the scanner call
			// to avoid a noise log line for every brokered PR that
			// happens to omit a body.
			continue
		}
		res, err := scanner.ScanText(fs.label, fs.text)
		if err != nil {
			return scanners.ScanResult{}, fmt.Errorf("%w: scanning %s: %v", ErrMetadataScanBlocked, fs.label, err)
		}
		merged.Findings = append(merged.Findings, res.Findings...)
		merged.EntropyWarnings = append(merged.EntropyWarnings, res.EntropyWarnings...)
		// We deliberately ignore res.Scanner (it is the same string for
		// every field; the merged result carries it once) and
		// res.ScannedAt (set at the end of the merge so the timestamp
		// reflects the whole metadata scan, not the last field).
	}

	// Re-stamp finding IDs so the merged result follows the
	// finding_001 / finding_002 / ... convention the rest of the
	// scanner output uses. The per-field scan numbers IDs starting at
	// 001 inside its own ScanResult, which would collide if we just
	// concatenated.
	for i := range merged.Findings {
		merged.Findings[i].ID = fmt.Sprintf("finding_%03d", i+1)
	}

	merged.ScannedAt = nowFunc()
	return merged, nil
}

// nowFunc is the time source ScanMetadata stamps onto ScannedAt. It is
// a package variable so tests can pin a deterministic timestamp without
// the test needing access to internal scanner state. Production code
// leaves it pointing at time.Now; tests rebind it for the duration of
// the test.
var nowFunc = time.Now
