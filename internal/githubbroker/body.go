// body.go implements plan 07 step 6: the GitHub broker generates the
// pull-request description body from a sanitized run.json snapshot and
// the scan/diff results that accompany it. The plan calls the rule out
// in two places:
//
//  1. "Key decisions from master plan", item 8: "PR body is generated
//     by the host-side broker from sanitized run metadata, not copied
//     directly from raw agent output."
//  2. "PR body format (broker-generated)": the body must include the
//     run ID, agent and task description, scan summary (count and
//     highest severity), protected path warnings, list of changed files
//     (top N, truncated if large diff), and an explicit notice that
//     this is an automated agent run. The same section forbids two
//     things: copying the raw agent transcript into the body and
//     including any value that matches a secret pattern.
//
// The helper is exported as a package-level function (mirroring
// ValidateBranchPrefix / ValidatePathGate / ScanMetadata) for the same
// reasons documented in those files: the concrete GitHubBroker
// implementation lands in a later step, and the CLI / ExportGate /
// tests all need a stable contract to call against today. Centralizing
// the body generation here means the "what does a broker PR body look
// like" answer lives in exactly one place.
//
// The function is deterministic: given the same inputs it produces the
// same bytes. The order of sections, the file-list ordering (verbatim
// from the diff), and the timestamp source (Record.StartedAt /
// Record.StoppedAt, not time.Now) are all chosen so two runs that
// produced the same record and scan result produce the same body. The
// rest of the broker pipeline (ScanMetadata, ExportGate) relies on the
// body being a pure function of its inputs.
//
// Sanitization is performed by routing every operator-supplied string
// (task description, file paths, scan-finding patterns, reason
// messages) through secrets.RedactSecrets before it is written into
// the body. That helper is the same one the secret proxy and the log
// writer use; reusing it means the broker uses the same regex set the
// rest of the host uses, so a leak shape that is masked in logs is
// masked in the PR body too. The downstream ScanMetadata pass (plan 07
// step 5) is the second line of defence: if a pattern survives
// redaction it lights up there and ExportGate refuses submission.

package githubbroker

import (
	"fmt"
	"strings"

	"github.com/rivan1986/ai-env/internal/export"
	"github.com/rivan1986/ai-env/internal/run"
	"github.com/rivan1986/ai-env/internal/scanners"
	"github.com/rivan1986/ai-env/internal/secrets"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// MaxFileListEntries caps the file list section so a large diff does
// not produce a PR body GitHub refuses to accept (the API limits the
// body to 65,536 characters). The plan's "list of changed files (top
// N, truncated if large diff)" requirement is satisfied by truncating
// at this many entries and appending a "and X more" summary line so
// the operator still sees the total file count. The constant is
// exported so tests and downstream renderers can pin the same number.
const MaxFileListEntries = 50

// AutomatedRunNotice is the verbatim line the body appends as the
// "explicit notice that this is an automated agent run" the plan
// requires. It is exported as a constant so tests can assert on the
// exact text and so downstream renderers (status command, report
// command) can show the same notice without re-typing it.
const AutomatedRunNotice = "This pull request was generated automatically by an ai-env agent run. " +
	"Review the diff, scan summary, and listed files before merging."

// BodyInput bundles the inputs BuildPRBody consults. It mirrors the
// shape of export.Input in spirit (a single struct of the artifacts
// the host already loaded for the gate decision) so the CLI can build
// one input value and reuse it for both ExportGate.Evaluate and
// BuildPRBody. Every field is optional in the sense that the zero
// value is meaningful: an empty Diff means "no changed files", a nil
// Record means "no run record" (e.g. a dry-run preview), an empty
// ProtectedHits means "no protected paths touched".
//
// The struct exists (rather than a long positional argument list) so
// adding a future input (e.g. a links-to-related-runs slice) is a
// one-line extension and the call site stays readable.
type BodyInput struct {
	// Record is the sanitized run.json snapshot. Fields used by the
	// body: RunID, EnvName, Agent, Task, State, StartedAt, StoppedAt,
	// Backend, ModelCredentialMode, ReducedSafety. Other fields are
	// ignored by BuildPRBody; the broker does not surface them.
	//
	// A nil Record causes BuildPRBody to emit "(no run record
	// available)" placeholders rather than panicking. This keeps the
	// helper safe to call from the CLI's dry-run path where the
	// workspace has not been run yet.
	Record *run.Record

	// Diff is the workspace diff the PR would ship. BuildPRBody
	// renders the changed-file list from Diff.Files (truncated at
	// MaxFileListEntries) and surfaces Diff.ProtectedHits in the
	// protected-paths section. The full unified diff text is not
	// included in the body; that is what the PR diff view itself is
	// for.
	Diff workspace.DiffResult

	// BuiltInResult is the built-in secret scanner's result for the
	// run. BuildPRBody uses it to render the "scan summary" section:
	// total finding count and the highest severity present. The
	// findings themselves are not enumerated in the body (only their
	// count and severity) because the scanner output already lives in
	// secret-scan.json and ExportGate would have blocked submission if
	// any finding had BlocksExport=true. The summary in the body is a
	// confidence signal for the reviewer.
	BuiltInResult scanners.ScanResult

	// ExternalResults is the per-tool external scanner result list.
	// BuildPRBody aggregates these into the same scan-summary section
	// so an operator sees one combined "N findings (highest: high)"
	// line rather than having to add them up.
	ExternalResults []scanners.ScanResult

	// GateResult is the ExportGate verdict for this export. BuildPRBody
	// uses GateResult.Reasons to render the protected-paths section
	// (entries with Code=ReasonProtectedPath, ReasonAIEnvChange,
	// ReasonPolicyChange, ReasonWorkflowChange) and to detect a
	// blocked verdict (in which case the body would normally not be
	// generated, but the helper still produces a coherent document so
	// it round-trips through the scanner). A zero GateResult is
	// treated as "no gate reasons recorded".
	GateResult export.GateResult
}

// BuildPRBody assembles the broker-generated PR body from in. The
// returned string is deterministic (byte-stable for identical inputs),
// human-readable Markdown, and contains only fields routed through
// the secret-redactor. Plan 07's "broker must not copy raw agent
// transcript" rule is satisfied trivially: BuildPRBody does not accept
// the transcript and the run.Record snapshot it consults does not
// carry one.
//
// The section order matches plan 07's "PR body format (broker-
// generated)" enumeration:
//
//  1. Run summary (run ID, agent, task, env, state).
//  2. Scan summary (total findings, highest severity).
//  3. Protected path warnings (one entry per gate hit).
//  4. Changed files (top MaxFileListEntries; "and N more" if
//     truncated).
//  5. Automated-run notice (verbatim AutomatedRunNotice text).
//
// Every operator-supplied string passes through secrets.RedactSecrets
// before being written so a token-shaped value that survived earlier
// sanitization is still scrubbed at the body-render boundary. The
// downstream ScanMetadata pass scans the assembled body as the second
// line of defence.
func BuildPRBody(in BodyInput) string {
	var b strings.Builder

	writeRunSummary(&b, in.Record)
	writeScanSummary(&b, in.BuiltInResult, in.ExternalResults)
	writeProtectedPaths(&b, in.Diff, in.GateResult)
	writeChangedFiles(&b, in.Diff)
	writeAutomatedNotice(&b)

	return b.String()
}

// writeRunSummary renders the "Run summary" section. A nil Record is
// rendered as a placeholder block rather than skipped so the body's
// section order stays stable across runs with and without a record.
func writeRunSummary(b *strings.Builder, rec *run.Record) {
	b.WriteString("## Run summary\n\n")
	if rec == nil {
		b.WriteString("- run id: (no run record available)\n")
		b.WriteString("- agent: (no run record available)\n")
		b.WriteString("- task: (no run record available)\n\n")
		return
	}
	// Every field is redacted before being written. RunID, EnvName,
	// Agent, Backend, and the credential mode are not expected to
	// carry secrets in practice, but routing them through the
	// redactor costs nothing and keeps the contract "every operator-
	// supplied string in the body has passed through RedactSecrets"
	// uniform: a reader does not have to audit which fields skipped
	// the pass.
	fmt.Fprintf(b, "- run id: %s\n", secrets.RedactSecrets(rec.RunID))
	fmt.Fprintf(b, "- env: %s\n", secrets.RedactSecrets(rec.EnvName))
	fmt.Fprintf(b, "- agent: %s\n", secrets.RedactSecrets(rec.Agent))
	fmt.Fprintf(b, "- task: %s\n", secrets.RedactSecrets(sanitizeTask(rec.Task)))
	fmt.Fprintf(b, "- state: %s\n", secrets.RedactSecrets(string(rec.State)))
	if rec.Backend != "" {
		fmt.Fprintf(b, "- backend: %s\n", secrets.RedactSecrets(rec.Backend))
	}
	if rec.ModelCredentialMode != "" {
		fmt.Fprintf(b, "- model credential mode: %s\n", secrets.RedactSecrets(string(rec.ModelCredentialMode)))
	}
	if rec.ReducedSafety {
		// The reduced-safety flag is the operator-visible signal that
		// the run used a relaxed credential / mount path. Plan 07
		// expects every brokered PR to surface it so reviewers know
		// the run was not the default-safe shape.
		b.WriteString("- reduced safety: true\n")
	}
	b.WriteString("\n")
}

// sanitizeTask trims and single-line-folds the task description so the
// PR body does not embed a multi-paragraph block (which would make the
// body harder to scan and could include incidental newlines from the
// agent's task file). The fold uses a simple newline -> space
// replacement; the result still passes through RedactSecrets before it
// reaches the body.
//
// Empty tasks render as a placeholder so the body's bullet list stays
// well-formed.
func sanitizeTask(task string) string {
	t := strings.TrimSpace(task)
	if t == "" {
		return "(no task description)"
	}
	// Replace any run of whitespace (newlines, tabs, repeated spaces)
	// with a single space so a multi-line task block becomes one line.
	t = strings.Join(strings.Fields(t), " ")
	return t
}

// writeScanSummary renders the "Scan summary" section: total finding
// count across the built-in scanner and every external scanner, plus
// the highest severity present. The plan does not require enumerating
// individual findings here; secret-scan.json carries the per-finding
// detail and ExportGate would have blocked submission on a hard
// blocker. The summary in the body is the reviewer's confidence
// signal.
func writeScanSummary(b *strings.Builder, builtIn scanners.ScanResult, external []scanners.ScanResult) {
	b.WriteString("## Scan summary\n\n")
	total := len(builtIn.Findings)
	entropyTotal := len(builtIn.EntropyWarnings)
	for _, r := range external {
		total += len(r.Findings)
		entropyTotal += len(r.EntropyWarnings)
	}
	highest := highestSeverity(builtIn, external)
	fmt.Fprintf(b, "- findings: %d\n", total)
	fmt.Fprintf(b, "- highest severity: %s\n", highest)
	if entropyTotal > 0 {
		// Entropy warnings are warn-only per Plan 06 so they never
		// block export; we still surface the count so a reviewer who
		// wants to look at them can find the artifact.
		fmt.Fprintf(b, "- entropy warnings: %d\n", entropyTotal)
	}
	// Enumerate the scanners that ran so a reviewer can see what
	// coverage the broker had. Order is deterministic: built-in
	// first, then external scanners in the order they were supplied.
	scannerNames := []string{}
	if builtIn.Scanner != "" {
		scannerNames = append(scannerNames, builtIn.Scanner)
	}
	for _, r := range external {
		if r.Scanner != "" {
			scannerNames = append(scannerNames, r.Scanner)
		}
	}
	if len(scannerNames) > 0 {
		fmt.Fprintf(b, "- scanners: %s\n", strings.Join(scannerNames, ", "))
	}
	b.WriteString("\n")
}

// highestSeverity returns the highest scan severity present across the
// built-in result and every external result. Severity ranking matches
// the scanner package's Confidence enum: high > medium > low. When no
// finding is present the function returns "none" so the body always
// shows a concrete word rather than an empty cell.
func highestSeverity(builtIn scanners.ScanResult, external []scanners.ScanResult) string {
	rank := func(c scanners.Confidence) int {
		switch c {
		case scanners.ConfidenceHigh:
			return 3
		case scanners.ConfidenceMedium:
			return 2
		case scanners.ConfidenceLow:
			return 1
		}
		return 0
	}
	best := 0
	for _, f := range builtIn.Findings {
		if r := rank(f.Confidence); r > best {
			best = r
		}
	}
	for _, res := range external {
		for _, f := range res.Findings {
			if r := rank(f.Confidence); r > best {
				best = r
			}
		}
	}
	switch best {
	case 3:
		return string(scanners.ConfidenceHigh)
	case 2:
		return string(scanners.ConfidenceMedium)
	case 1:
		return string(scanners.ConfidenceLow)
	}
	return "none"
}

// writeProtectedPaths renders the "Protected path warnings" section.
// Sources are unioned in a stable order: Diff.ProtectedHits first
// (workspace-level), then the export-gate reasons whose codes
// correspond to protected paths (workflow change, .ai-env change,
// policy change, protected path). Each entry is rendered once even if
// it shows up in both sources.
//
// An empty result is rendered as "(none)" so the section header still
// appears and the body's outline stays stable.
func writeProtectedPaths(b *strings.Builder, diff workspace.DiffResult, gate export.GateResult) {
	b.WriteString("## Protected path warnings\n\n")

	// Use a map to dedupe entries that show up in both the workspace
	// hit list and the gate reasons. Insertion order is preserved by
	// the slice alongside so the rendered output is deterministic.
	seen := map[string]struct{}{}
	var ordered []string

	add := func(path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		ordered = append(ordered, path)
	}

	for _, p := range diff.ProtectedHits {
		add(p)
	}
	for _, r := range gate.Reasons {
		switch r.Code {
		case export.ReasonProtectedPath,
			export.ReasonAIEnvChange,
			export.ReasonPolicyChange,
			export.ReasonWorkflowChange:
			add(r.Path)
		}
	}

	if len(ordered) == 0 {
		b.WriteString("- (none)\n\n")
		return
	}
	for _, p := range ordered {
		fmt.Fprintf(b, "- %s\n", secrets.RedactSecrets(p))
	}
	b.WriteString("\n")
}

// writeChangedFiles renders the "Changed files" section: a bullet
// list of file paths with a change-kind marker, capped at
// MaxFileListEntries entries. When the diff has more files than the
// cap, the section appends an "...and N more changed files" summary
// so the operator sees the total count without the body growing
// unbounded.
//
// File order is preserved verbatim from diff.Files: the workspace
// layer already sorts the slice deterministically, and re-sorting
// here would break the round-trip between the diff and the body.
func writeChangedFiles(b *strings.Builder, diff workspace.DiffResult) {
	b.WriteString("## Changed files\n\n")
	if len(diff.Files) == 0 {
		b.WriteString("- (no changes)\n\n")
		return
	}
	limit := len(diff.Files)
	truncated := false
	if limit > MaxFileListEntries {
		limit = MaxFileListEntries
		truncated = true
	}
	for i := 0; i < limit; i++ {
		f := diff.Files[i]
		marker := changeMarker(f.Change)
		protectedTag := ""
		if f.Protected {
			protectedTag = "  [protected]"
		}
		fmt.Fprintf(b, "- %s %s%s\n", marker, secrets.RedactSecrets(f.Path), protectedTag)
	}
	if truncated {
		more := len(diff.Files) - MaxFileListEntries
		fmt.Fprintf(b, "- ...and %d more changed files (truncated at %d)\n", more, MaxFileListEntries)
	}
	b.WriteString("\n")
}

// changeMarker returns the short human-readable token BuildPRBody
// stamps next to each changed file. It mirrors the marker the CLI's
// patch / pr preview uses so the rendered body and the operator's
// terminal preview agree on the vocabulary. An unknown ChangeKind
// falls through to "?" so a future kind does not break rendering.
func changeMarker(k workspace.ChangeKind) string {
	switch k {
	case workspace.ChangeAdded:
		return "added"
	case workspace.ChangeModified:
		return "modified"
	case workspace.ChangeDeleted:
		return "deleted"
	}
	return "?"
}

// writeAutomatedNotice writes the closing "explicit notice that this
// is an automated agent run" the plan requires. The text is fixed
// (AutomatedRunNotice) so the body's terminal section is byte-stable
// regardless of inputs.
func writeAutomatedNotice(b *strings.Builder) {
	b.WriteString("---\n\n")
	b.WriteString(AutomatedRunNotice)
	b.WriteString("\n")
}
