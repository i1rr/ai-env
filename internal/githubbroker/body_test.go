package githubbroker

import (
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/export"
	"github.com/rivan1986/ai-env/internal/run"
	"github.com/rivan1986/ai-env/internal/scanners"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// fakeAnthropicKeyForBody is a non-live secret shape that matches the
// "sk-ant-" pattern enforced by secrets.RedactSecrets. We use a body-
// local copy (rather than reusing metadata_test.go's constant) so this
// file remains self-contained when read in isolation.
const fakeAnthropicKeyForBody = "sk-ant-AAAAAAAAAAAAAAAAAAAA1234567890"

// realisticRecord returns a populated run.Record approximating what the
// supervisor would write to run.json after a normal completed run. It
// is used by body tests that want the "happy path" record shape.
func realisticRecord() *run.Record {
	started := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	stopped := started.Add(7 * time.Minute)
	exit := 0
	return &run.Record{
		RunID:               "20260528-101300-a1b2c3",
		EnvName:             "fix-tests",
		Agent:               "claude-code",
		Task:                "Fix the failing login regression tests",
		State:               run.StateCompleted,
		ExitCode:            &exit,
		StartedAt:           &started,
		StoppedAt:           &stopped,
		Backend:             "docker",
		ModelCredentialMode: run.ModelCredentialBackendManaged,
		ReducedSafety:       false,
	}
}

// TestBuildPRBody_ContainsAllRequiredSections pins plan 07's "PR body
// format (broker-generated)" enumeration: the body MUST contain run
// summary, scan summary, protected path warnings, changed files, and
// the explicit automated-run notice.
func TestBuildPRBody_ContainsAllRequiredSections(t *testing.T) {
	rec := realisticRecord()
	in := BodyInput{
		Record: rec,
		Diff: workspace.DiffResult{
			Files: []workspace.FileDiff{
				{Path: "auth/login.go", Change: workspace.ChangeModified},
				{Path: "auth/login_test.go", Change: workspace.ChangeAdded},
			},
		},
		BuiltInResult: scanners.ScanResult{
			RunID:   rec.RunID,
			Scanner: "built-in-patterns",
		},
	}
	body := BuildPRBody(in)

	requiredSections := []string{
		"## Run summary",
		"## Scan summary",
		"## Protected path warnings",
		"## Changed files",
		AutomatedRunNotice,
	}
	for _, section := range requiredSections {
		if !strings.Contains(body, section) {
			t.Errorf("body missing required section %q\nbody:\n%s", section, body)
		}
	}
}

// TestBuildPRBody_DeterministicByteStable pins the implementation's
// "deterministic: given the same inputs it produces the same bytes"
// promise. The downstream ScanMetadata pass and the audit log both
// require the body to be a pure function of its inputs.
func TestBuildPRBody_DeterministicByteStable(t *testing.T) {
	rec := realisticRecord()
	in := BodyInput{
		Record: rec,
		Diff: workspace.DiffResult{
			Files: []workspace.FileDiff{
				{Path: "auth/login.go", Change: workspace.ChangeModified},
				{Path: "README.md", Change: workspace.ChangeModified},
			},
			ProtectedHits: []string{"README.md"},
		},
		BuiltInResult: scanners.ScanResult{Scanner: "built-in-patterns"},
		GateResult: export.GateResult{
			Decision: export.DecisionAllow,
		},
	}
	a := BuildPRBody(in)
	b := BuildPRBody(in)
	if a != b {
		t.Fatalf("BuildPRBody not deterministic\nfirst:\n%s\nsecond:\n%s", a, b)
	}
}

// TestBuildPRBody_RunSummaryIncludesRecordFields pins the run-summary
// section's required fields: run id, env, agent, task, state, backend,
// and model credential mode are all rendered. This catches a regression
// where a Record field stops being surfaced.
func TestBuildPRBody_RunSummaryIncludesRecordFields(t *testing.T) {
	rec := realisticRecord()
	body := BuildPRBody(BodyInput{Record: rec})

	wantSubstrings := []string{
		rec.RunID,
		rec.EnvName,
		rec.Agent,
		rec.Task,
		string(rec.State),
		rec.Backend,
		string(rec.ModelCredentialMode),
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(body, want) {
			t.Errorf("body missing run-summary substring %q\nbody:\n%s", want, body)
		}
	}
}

// TestBuildPRBody_NilRecordRendersPlaceholder pins the "nil Record
// causes BuildPRBody to emit placeholders rather than panicking"
// promise. The CLI's dry-run path depends on this.
func TestBuildPRBody_NilRecordRendersPlaceholder(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BuildPRBody panicked with nil Record: %v", r)
		}
	}()
	body := BuildPRBody(BodyInput{Record: nil})
	if !strings.Contains(body, "(no run record available)") {
		t.Errorf("nil Record body missing placeholder marker\nbody:\n%s", body)
	}
	// Section order must remain stable even with a nil record.
	for _, section := range []string{
		"## Run summary",
		"## Scan summary",
		"## Protected path warnings",
		"## Changed files",
	} {
		if !strings.Contains(body, section) {
			t.Errorf("nil Record body missing section %q", section)
		}
	}
}

// TestBuildPRBody_RedactsSecretInTask is the load-bearing test for the
// "every operator-supplied string passes through secrets.RedactSecrets
// before being written" contract. A token-shaped value in the task
// description must NOT appear verbatim in the body.
func TestBuildPRBody_RedactsSecretInTask(t *testing.T) {
	rec := realisticRecord()
	rec.Task = "Fix login bug, key was " + fakeAnthropicKeyForBody + " by accident"

	body := BuildPRBody(BodyInput{Record: rec})

	if strings.Contains(body, fakeAnthropicKeyForBody) {
		t.Fatalf("body contains raw secret value %q (must be REDACTED)\nbody:\n%s",
			fakeAnthropicKeyForBody, body)
	}
	if !strings.Contains(body, "REDACTED") {
		t.Errorf("body does not contain REDACTED marker; redactor did not fire\nbody:\n%s", body)
	}
}

// TestBuildPRBody_RedactsSecretInFilePath pins the same contract for
// the changed-files section: a file path that itself contains a token-
// shaped substring must be redacted before rendering.
func TestBuildPRBody_RedactsSecretInFilePath(t *testing.T) {
	in := BodyInput{
		Diff: workspace.DiffResult{
			Files: []workspace.FileDiff{
				{Path: "configs/" + fakeAnthropicKeyForBody + ".yaml", Change: workspace.ChangeAdded},
			},
		},
	}
	body := BuildPRBody(in)
	if strings.Contains(body, fakeAnthropicKeyForBody) {
		t.Fatalf("body file-list contains raw secret %q\nbody:\n%s", fakeAnthropicKeyForBody, body)
	}
}

// TestBuildPRBody_MultilineTaskFoldsToSingleLine pins the
// sanitizeTask behavior: a multi-paragraph task description is folded
// to a single space-separated line so the bullet list stays readable.
func TestBuildPRBody_MultilineTaskFoldsToSingleLine(t *testing.T) {
	rec := realisticRecord()
	rec.Task = "Line one.\n\nLine two.\nLine three."

	body := BuildPRBody(BodyInput{Record: rec})

	// The folded task should appear on a single bullet line.
	if !strings.Contains(body, "- task: Line one. Line two. Line three.") {
		t.Errorf("task not folded to single line\nbody:\n%s", body)
	}
}

// TestBuildPRBody_EmptyTaskRendersPlaceholder pins the "empty tasks
// render as a placeholder" rule so the bullet list stays well-formed.
func TestBuildPRBody_EmptyTaskRendersPlaceholder(t *testing.T) {
	rec := realisticRecord()
	rec.Task = "   \n\n   "

	body := BuildPRBody(BodyInput{Record: rec})

	if !strings.Contains(body, "(no task description)") {
		t.Errorf("empty task missing placeholder\nbody:\n%s", body)
	}
}

// TestBuildPRBody_ReducedSafetyFlag pins the reduced-safety surface:
// when ReducedSafety=true the body MUST tell the reviewer; when it is
// false the line MUST NOT appear (so reviewers do not get noise on
// default-safe runs).
func TestBuildPRBody_ReducedSafetyFlag(t *testing.T) {
	tests := []struct {
		name          string
		reducedSafety bool
		wantSubstring string
		mustNotHave   string
	}{
		{
			name:          "reduced_safety_true",
			reducedSafety: true,
			wantSubstring: "reduced safety: true",
		},
		{
			name:          "reduced_safety_false",
			reducedSafety: false,
			mustNotHave:   "reduced safety",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := realisticRecord()
			rec.ReducedSafety = tc.reducedSafety
			body := BuildPRBody(BodyInput{Record: rec})
			if tc.wantSubstring != "" && !strings.Contains(body, tc.wantSubstring) {
				t.Errorf("missing %q\nbody:\n%s", tc.wantSubstring, body)
			}
			if tc.mustNotHave != "" && strings.Contains(body, tc.mustNotHave) {
				t.Errorf("unexpected %q present\nbody:\n%s", tc.mustNotHave, body)
			}
		})
	}
}

// TestBuildPRBody_ScanSummaryCounts pins the scan-summary section's
// content: total finding count is the sum across built-in and external
// scanner results, and the highest severity is correctly ranked
// (high > medium > low).
func TestBuildPRBody_ScanSummaryCounts(t *testing.T) {
	in := BodyInput{
		BuiltInResult: scanners.ScanResult{
			Scanner: "built-in-patterns",
			Findings: []scanners.Finding{
				{ID: "finding_001", Confidence: scanners.ConfidenceMedium},
				{ID: "finding_002", Confidence: scanners.ConfidenceLow},
			},
		},
		ExternalResults: []scanners.ScanResult{
			{
				Scanner: "gitleaks",
				Findings: []scanners.Finding{
					{ID: "gl_1", Confidence: scanners.ConfidenceHigh},
				},
			},
		},
	}
	body := BuildPRBody(in)

	if !strings.Contains(body, "- findings: 3") {
		t.Errorf("expected 'findings: 3'\nbody:\n%s", body)
	}
	if !strings.Contains(body, "- highest severity: high") {
		t.Errorf("expected 'highest severity: high'\nbody:\n%s", body)
	}
	if !strings.Contains(body, "built-in-patterns") {
		t.Errorf("expected built-in scanner name\nbody:\n%s", body)
	}
	if !strings.Contains(body, "gitleaks") {
		t.Errorf("expected external scanner name\nbody:\n%s", body)
	}
}

// TestBuildPRBody_ScanSummaryNoFindings pins the empty-scan case:
// "highest severity: none" so the body shows a concrete word.
func TestBuildPRBody_ScanSummaryNoFindings(t *testing.T) {
	body := BuildPRBody(BodyInput{
		BuiltInResult: scanners.ScanResult{Scanner: "built-in-patterns"},
	})
	if !strings.Contains(body, "- findings: 0") {
		t.Errorf("expected 'findings: 0'\nbody:\n%s", body)
	}
	if !strings.Contains(body, "- highest severity: none") {
		t.Errorf("expected 'highest severity: none'\nbody:\n%s", body)
	}
}

// TestBuildPRBody_EntropyWarningsSurface pins the entropy-warnings
// surface: warn-only entropy hits must appear so a reviewer can find
// the artifact, but they never flip the gate.
func TestBuildPRBody_EntropyWarningsSurface(t *testing.T) {
	in := BodyInput{
		BuiltInResult: scanners.ScanResult{
			Scanner: "built-in-patterns",
			EntropyWarnings: []scanners.EntropyWarning{
				{File: "secrets.txt", Line: 5, Entropy: 4.7, Reason: "base64-like"},
				{File: "blob.txt", Line: 1, Entropy: 5.0, Reason: "hex-like"},
			},
		},
	}
	body := BuildPRBody(in)
	if !strings.Contains(body, "- entropy warnings: 2") {
		t.Errorf("expected 'entropy warnings: 2'\nbody:\n%s", body)
	}
}

// TestBuildPRBody_EntropyWarningsHiddenWhenZero pins the inverse: when
// no entropy warnings exist, the line MUST NOT appear (avoiding noise
// on clean runs).
func TestBuildPRBody_EntropyWarningsHiddenWhenZero(t *testing.T) {
	body := BuildPRBody(BodyInput{
		BuiltInResult: scanners.ScanResult{Scanner: "built-in-patterns"},
	})
	if strings.Contains(body, "entropy warnings") {
		t.Errorf("entropy warnings line should not appear on clean runs\nbody:\n%s", body)
	}
}

// TestBuildPRBody_ProtectedPathsFromDiff pins the protected-path
// section when entries come from workspace-level ProtectedHits.
func TestBuildPRBody_ProtectedPathsFromDiff(t *testing.T) {
	in := BodyInput{
		Diff: workspace.DiffResult{
			Files: []workspace.FileDiff{
				{Path: "policy.yaml", Change: workspace.ChangeModified, Protected: true},
			},
			ProtectedHits: []string{"policy.yaml"},
		},
	}
	body := BuildPRBody(in)
	if !strings.Contains(body, "- policy.yaml") {
		t.Errorf("expected protected-path bullet for policy.yaml\nbody:\n%s", body)
	}
}

// TestBuildPRBody_ProtectedPathsFromGateReasons pins the second source
// for the protected-paths section: ExportGate reasons whose codes are
// ReasonProtectedPath / ReasonAIEnvChange / ReasonPolicyChange /
// ReasonWorkflowChange must be rendered.
func TestBuildPRBody_ProtectedPathsFromGateReasons(t *testing.T) {
	in := BodyInput{
		GateResult: export.GateResult{
			Decision: export.DecisionBlock,
			Reasons: []export.Reason{
				{Code: export.ReasonWorkflowChange, Path: ".github/workflows/ci.yml", Severity: export.SeverityBlock},
				{Code: export.ReasonAIEnvChange, Path: ".ai-env/agents.yaml", Severity: export.SeverityBlock},
				{Code: export.ReasonPolicyChange, Path: ".ai-env/policy.yaml", Severity: export.SeverityBlock},
				{Code: export.ReasonProtectedPath, Path: "README.md", Severity: export.SeverityBlock},
				// A reason whose code is NOT a protected-path category
				// should NOT appear under "Protected path warnings".
				{Code: export.ReasonLargeDiff, Path: "ignored.go", Severity: export.SeverityWarn},
			},
		},
	}
	body := BuildPRBody(in)
	wantProtected := []string{
		".github/workflows/ci.yml",
		".ai-env/agents.yaml",
		".ai-env/policy.yaml",
		"README.md",
	}
	// Slice the body to just the protected-paths section so we are not
	// fooled by a path that appears elsewhere.
	start := strings.Index(body, "## Protected path warnings")
	if start < 0 {
		t.Fatalf("body missing protected paths section\n%s", body)
	}
	rest := body[start:]
	end := strings.Index(rest[len("## Protected path warnings"):], "## ")
	section := rest
	if end >= 0 {
		section = rest[:len("## Protected path warnings")+end]
	}

	for _, want := range wantProtected {
		if !strings.Contains(section, want) {
			t.Errorf("protected paths section missing %q\nsection:\n%s", want, section)
		}
	}
	if strings.Contains(section, "ignored.go") {
		t.Errorf("non-protected reason should not appear under protected paths\nsection:\n%s", section)
	}
}

// TestBuildPRBody_ProtectedPathsDedupe pins the "Each entry is
// rendered once even if it shows up in both sources" rule.
func TestBuildPRBody_ProtectedPathsDedupe(t *testing.T) {
	in := BodyInput{
		Diff: workspace.DiffResult{
			ProtectedHits: []string{"policy.yaml"},
		},
		GateResult: export.GateResult{
			Reasons: []export.Reason{
				{Code: export.ReasonPolicyChange, Path: "policy.yaml", Severity: export.SeverityBlock},
			},
		},
	}
	body := BuildPRBody(in)
	count := strings.Count(body, "- policy.yaml")
	if count != 1 {
		t.Errorf("policy.yaml appears %d times in body, want 1\nbody:\n%s", count, body)
	}
}

// TestBuildPRBody_NoProtectedPathsRendersNone pins the "(none)"
// placeholder so the body's outline stays stable when no protected
// paths were touched.
func TestBuildPRBody_NoProtectedPathsRendersNone(t *testing.T) {
	body := BuildPRBody(BodyInput{})
	idx := strings.Index(body, "## Protected path warnings")
	if idx < 0 {
		t.Fatalf("body missing protected paths section")
	}
	tail := body[idx:]
	end := strings.Index(tail[len("## Protected path warnings"):], "## ")
	section := tail
	if end >= 0 {
		section = tail[:len("## Protected path warnings")+end]
	}
	if !strings.Contains(section, "- (none)") {
		t.Errorf("protected paths section missing '(none)' placeholder\nsection:\n%s", section)
	}
}

// TestBuildPRBody_ChangedFilesListed pins the change markers
// (added/modified/deleted) and that file paths appear verbatim in the
// order supplied (matching the workspace layer's deterministic order).
func TestBuildPRBody_ChangedFilesListed(t *testing.T) {
	in := BodyInput{
		Diff: workspace.DiffResult{
			Files: []workspace.FileDiff{
				{Path: "alpha.go", Change: workspace.ChangeAdded},
				{Path: "beta.go", Change: workspace.ChangeModified},
				{Path: "gamma.go", Change: workspace.ChangeDeleted},
			},
		},
	}
	body := BuildPRBody(in)
	for _, want := range []string{
		"- added alpha.go",
		"- modified beta.go",
		"- deleted gamma.go",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("changed files missing %q\nbody:\n%s", want, body)
		}
	}
	// Order should be preserved: alpha < beta < gamma in body order.
	alphaIdx := strings.Index(body, "alpha.go")
	betaIdx := strings.Index(body, "beta.go")
	gammaIdx := strings.Index(body, "gamma.go")
	if !(alphaIdx < betaIdx && betaIdx < gammaIdx) {
		t.Errorf("changed files order not preserved: alpha=%d beta=%d gamma=%d", alphaIdx, betaIdx, gammaIdx)
	}
}

// TestBuildPRBody_ChangedFilesProtectedTag pins the "[protected]" tag
// for files in the changed-files list that match a protected pattern.
func TestBuildPRBody_ChangedFilesProtectedTag(t *testing.T) {
	in := BodyInput{
		Diff: workspace.DiffResult{
			Files: []workspace.FileDiff{
				{Path: ".github/workflows/ci.yml", Change: workspace.ChangeModified, Protected: true},
				{Path: "main.go", Change: workspace.ChangeModified, Protected: false},
			},
		},
	}
	body := BuildPRBody(in)
	if !strings.Contains(body, ".github/workflows/ci.yml") {
		t.Fatalf("body missing protected file\nbody:\n%s", body)
	}
	// The [protected] tag should be on the workflow line only.
	lines := strings.Split(body, "\n")
	for _, l := range lines {
		if strings.Contains(l, ".github/workflows/ci.yml") && !strings.Contains(l, "[protected]") {
			t.Errorf("workflow line missing [protected] tag: %q", l)
		}
		if strings.Contains(l, "main.go") && strings.Contains(l, "[protected]") {
			t.Errorf("non-protected file should not carry [protected] tag: %q", l)
		}
	}
}

// TestBuildPRBody_ChangedFilesNoChanges pins the "(no changes)"
// placeholder for an empty diff so the section stays well-formed.
func TestBuildPRBody_ChangedFilesNoChanges(t *testing.T) {
	body := BuildPRBody(BodyInput{})
	if !strings.Contains(body, "- (no changes)") {
		t.Errorf("empty diff body missing '(no changes)' placeholder\nbody:\n%s", body)
	}
}

// TestBuildPRBody_ChangedFilesTruncation pins the MaxFileListEntries
// cap: when the diff exceeds the cap the body MUST cap the list and
// append an "...and N more" summary so the operator still sees the
// total file count.
func TestBuildPRBody_ChangedFilesTruncation(t *testing.T) {
	totalFiles := MaxFileListEntries + 17
	files := make([]workspace.FileDiff, totalFiles)
	for i := 0; i < totalFiles; i++ {
		files[i] = workspace.FileDiff{
			Path:   "file_" + paddedIndex(i) + ".go",
			Change: workspace.ChangeModified,
		}
	}
	body := BuildPRBody(BodyInput{
		Diff: workspace.DiffResult{Files: files},
	})

	// Files within the cap should appear.
	if !strings.Contains(body, "file_"+paddedIndex(MaxFileListEntries-1)+".go") {
		t.Errorf("last in-cap file missing\nbody:\n%s", body)
	}
	// Files past the cap should NOT appear.
	if strings.Contains(body, "file_"+paddedIndex(MaxFileListEntries)+".go") {
		t.Errorf("file at cap+1 should be truncated\nbody:\n%s", body)
	}
	// The summary must include the count of remaining files.
	wantTrunc := "...and 17 more changed files"
	if !strings.Contains(body, wantTrunc) {
		t.Errorf("expected truncation summary %q\nbody:\n%s", wantTrunc, body)
	}
}

// paddedIndex returns a zero-padded 3-digit string so the synthetic
// file names sort in numeric order under a lexicographic comparator.
func paddedIndex(i int) string {
	switch {
	case i < 10:
		return "00" + itoa(i)
	case i < 100:
		return "0" + itoa(i)
	}
	return itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for n := i; n > 0; n /= 10 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
	}
	return string(digits)
}

// TestBuildPRBody_AutomatedNoticeTerminal pins the closing notice:
// AutomatedRunNotice appears verbatim, the body ends with a newline,
// and the notice is the last meaningful content (so a downstream
// consumer can rely on the body shape).
func TestBuildPRBody_AutomatedNoticeTerminal(t *testing.T) {
	body := BuildPRBody(BodyInput{Record: realisticRecord()})

	if !strings.Contains(body, AutomatedRunNotice) {
		t.Fatalf("body missing AutomatedRunNotice\nbody:\n%s", body)
	}
	noticeIdx := strings.Index(body, AutomatedRunNotice)
	tail := body[noticeIdx+len(AutomatedRunNotice):]
	if strings.TrimSpace(tail) != "" {
		t.Errorf("content found after AutomatedRunNotice: %q", tail)
	}
}

// TestBuildPRBody_NoRawTranscript pins plan 07's "raw agent transcript
// must not be copied into the body" rule. BodyInput does not have a
// transcript field, so the test asserts that nothing in the body looks
// like a typical chat transcript marker. This is a structural test:
// future fields cannot accidentally smuggle transcript text in.
func TestBuildPRBody_NoRawTranscript(t *testing.T) {
	rec := realisticRecord()
	body := BuildPRBody(BodyInput{Record: rec})

	transcriptMarkers := []string{
		"\nUser:",
		"\nAssistant:",
		"```json",
		"<tool_use>",
		"<tool_result>",
	}
	for _, marker := range transcriptMarkers {
		if strings.Contains(body, marker) {
			t.Errorf("body contains transcript-shaped marker %q\nbody:\n%s", marker, body)
		}
	}
}

// TestBuildPRBody_SectionOrder pins the documented section order:
// run summary -> scan summary -> protected paths -> changed files ->
// automated notice. A future refactor that swaps the order would
// break downstream renderers that rely on the document outline.
func TestBuildPRBody_SectionOrder(t *testing.T) {
	body := BuildPRBody(BodyInput{
		Record: realisticRecord(),
		Diff: workspace.DiffResult{
			Files: []workspace.FileDiff{{Path: "main.go", Change: workspace.ChangeModified}},
		},
	})
	markers := []string{
		"## Run summary",
		"## Scan summary",
		"## Protected path warnings",
		"## Changed files",
		AutomatedRunNotice,
	}
	prev := -1
	for _, m := range markers {
		idx := strings.Index(body, m)
		if idx < 0 {
			t.Fatalf("section marker %q missing from body", m)
		}
		if idx <= prev {
			t.Fatalf("section %q out of order (idx=%d, prev=%d)\nbody:\n%s", m, idx, prev, body)
		}
		prev = idx
	}
}

// TestBuildPRBody_RealisticEndToEnd is the integration-style table
// driver: it feeds a realistic sanitized run.json snapshot plus a
// realistic diff and scan result through BuildPRBody and asserts on
// the combined output. This catches regressions where any one section
// quietly loses content.
func TestBuildPRBody_RealisticEndToEnd(t *testing.T) {
	rec := realisticRecord()
	in := BodyInput{
		Record: rec,
		Diff: workspace.DiffResult{
			Name: rec.EnvName,
			Files: []workspace.FileDiff{
				{Path: "auth/login.go", Change: workspace.ChangeModified},
				{Path: "auth/login_test.go", Change: workspace.ChangeAdded},
				{Path: ".github/workflows/ci.yml", Change: workspace.ChangeModified, Protected: true},
			},
			ProtectedHits: []string{".github/workflows/ci.yml"},
		},
		BuiltInResult: scanners.ScanResult{
			RunID:   rec.RunID,
			Scanner: "built-in-patterns",
			Findings: []scanners.Finding{
				{ID: "finding_001", Type: "env_assignment", File: "auth/login.go", Line: 42, Confidence: scanners.ConfidenceMedium},
			},
		},
		ExternalResults: []scanners.ScanResult{
			{Scanner: "gitleaks"},
		},
		GateResult: export.GateResult{
			Decision: export.DecisionBlock,
			Reasons: []export.Reason{
				{Code: export.ReasonWorkflowChange, Path: ".github/workflows/ci.yml", Severity: export.SeverityBlock},
			},
		},
	}

	body := BuildPRBody(in)

	wantSubstrings := []string{
		rec.RunID,
		rec.EnvName,
		rec.Agent,
		rec.Task,
		"## Scan summary",
		"- findings: 1",
		"- highest severity: medium",
		"built-in-patterns",
		"gitleaks",
		"## Protected path warnings",
		".github/workflows/ci.yml",
		"## Changed files",
		"- modified auth/login.go",
		"- added auth/login_test.go",
		"[protected]",
		AutomatedRunNotice,
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(body, want) {
			t.Errorf("end-to-end body missing %q\nbody:\n%s", want, body)
		}
	}
}
