package export

import (
	"testing"

	"github.com/i1rr/ai-env/internal/scanners"
	"github.com/i1rr/ai-env/internal/workspace"
)

// TestExportGate_SecretFindingsBlock pins plan 06 step 12: a
// high-confidence secret finding in the built-in scanner result must
// flip the gate's verdict to DecisionBlock and surface a
// SeverityBlock Reason with Code=ReasonSecretFinding. The reason
// carries the offending file/finding metadata so the CLI can render
// it verbatim without re-reading the scanner output.
func TestExportGate_SecretFindingsBlock(t *testing.T) {
	gate := NewExportGate(nil)
	in := Input{
		Mode: ModePatch,
		BuiltInResult: scanners.ScanResult{
			Scanner: "built-in-patterns",
			Findings: []scanners.Finding{
				{
					ID:           "finding_001",
					Type:         "api_key",
					Pattern:      "Anthropic sk-ant- prefix",
					File:         "config.go",
					Line:         42,
					Confidence:   scanners.ConfidenceHigh,
					BlocksExport: true,
				},
			},
		},
	}

	res := gate.Evaluate(in)
	if !res.Blocked() {
		t.Fatalf("expected Decision=Block, got %s", res.Decision)
	}

	blocking := res.BlockingReasons()
	if len(blocking) == 0 {
		t.Fatalf("expected at least one blocking reason; got %+v", res.Reasons)
	}

	var found bool
	for _, r := range blocking {
		if r.Code == ReasonSecretFinding {
			found = true
			if r.Severity != SeverityBlock {
				t.Fatalf("secret reason has Severity=%s, want %s", r.Severity, SeverityBlock)
			}
			if !r.Hard {
				t.Fatalf("secret reason has Hard=false, want true")
			}
			if r.FindingID != "finding_001" {
				t.Fatalf("secret reason FindingID=%q, want finding_001", r.FindingID)
			}
			if r.Path != "config.go" {
				t.Fatalf("secret reason Path=%q, want config.go", r.Path)
			}
		}
	}
	if !found {
		t.Fatalf("no Reason with Code=%s in blocking reasons; got %+v", ReasonSecretFinding, blocking)
	}
}

// TestExportGate_GitleaksFindingBlocks confirms an external secret
// scanner result (gitleaks) is treated as a hard blocker, mirroring
// the built-in scanner's contract. Step 12 explicitly mentions
// "secret findings" without scoping to one source; both sources must
// block.
func TestExportGate_GitleaksFindingBlocks(t *testing.T) {
	gate := NewExportGate(nil)
	in := Input{
		Mode: ModePatch,
		ExternalResults: []scanners.ScanResult{
			{
				Scanner: "gitleaks",
				Findings: []scanners.Finding{
					{
						ID:           "finding_001",
						Type:         "gitleaks",
						Pattern:      "aws-access-token",
						File:         "secrets.yaml",
						Line:         7,
						Confidence:   scanners.ConfidenceHigh,
						BlocksExport: true,
					},
				},
			},
		},
	}

	res := gate.Evaluate(in)
	if !res.Blocked() {
		t.Fatalf("expected Decision=Block, got %s", res.Decision)
	}

	var found bool
	for _, r := range res.BlockingReasons() {
		if r.Code == ReasonExternalSecretFinding {
			found = true
			if !r.Hard {
				t.Fatalf("external secret reason Hard=false, want true")
			}
		}
	}
	if !found {
		t.Fatalf("expected Code=%s in blocking reasons; got %+v", ReasonExternalSecretFinding, res.BlockingReasons())
	}
}

// TestExportGate_EntropyOnlyDoesNotBlock pins plan 06 step 13:
// entropy-only matches live in EntropyWarnings, never in Findings,
// and so cannot flip the gate's Decision. The gate must produce
// DecisionAllow with no blocking reasons for an input whose only
// scanner output is entropy warnings. This is the load-bearing
// invariant the acceptance criterion 5 ("entropy-only findings warn
// but do not block export by default") depends on.
func TestExportGate_EntropyOnlyDoesNotBlock(t *testing.T) {
	gate := NewExportGate(nil)
	in := Input{
		Mode: ModePatch,
		BuiltInResult: scanners.ScanResult{
			Scanner:  "built-in-patterns",
			Findings: []scanners.Finding{},
			EntropyWarnings: []scanners.EntropyWarning{
				{
					File:    "data.json",
					Line:    3,
					Entropy: 4.73,
					Reason:  "base64-like, 48 chars, entropy 4.73",
				},
			},
		},
	}

	res := gate.Evaluate(in)
	if res.Blocked() {
		t.Fatalf("expected Decision=Allow with only entropy warnings; got %s with reasons %+v", res.Decision, res.Reasons)
	}
	for _, r := range res.BlockingReasons() {
		if r.Code == ReasonSecretFinding || r.Code == ReasonExternalSecretFinding {
			t.Fatalf("entropy-only input produced secret blocker %s: %+v", r.Code, r)
		}
	}
}

// TestExportGate_NonBlockingFindingDoesNotBlock guards the BlocksExport
// gate on Finding itself: a Finding flagged EntropyOnly=true with
// BlocksExport=false (the shape an external scanner uses when it
// conflates entropy and pattern matches) must not cause the gate to
// block. Together with TestExportGate_EntropyOnlyDoesNotBlock this
// covers both ways an entropy-only result can reach the gate.
func TestExportGate_NonBlockingFindingDoesNotBlock(t *testing.T) {
	gate := NewExportGate(nil)
	in := Input{
		Mode: ModePatch,
		BuiltInResult: scanners.ScanResult{
			Scanner: "built-in-patterns",
			Findings: []scanners.Finding{
				{
					ID:           "finding_001",
					Type:         "entropy",
					Pattern:      "base64-like",
					File:         "blob.txt",
					Line:         1,
					Confidence:   scanners.ConfidenceLow,
					EntropyOnly:  true,
					BlocksExport: false,
				},
			},
		},
	}

	res := gate.Evaluate(in)
	if res.Blocked() {
		t.Fatalf("expected Decision=Allow with non-blocking finding; got %s with reasons %+v", res.Decision, res.Reasons)
	}
}

// TestExportGate_CleanInputAllows is the baseline counter-test: a
// gate run with no findings, no diff, and no policy must return
// DecisionAllow with no reasons at all. Without this, a regression
// that emits spurious reasons would still pass the more specific
// tests above because they only assert on the absence of *secret*
// blockers.
func TestExportGate_CleanInputAllows(t *testing.T) {
	gate := NewExportGate(nil)
	res := gate.Evaluate(Input{Mode: ModePatch})
	if res.Blocked() {
		t.Fatalf("expected Decision=Allow on empty input; got %s with reasons %+v", res.Decision, res.Reasons)
	}
	if len(res.Reasons) != 0 {
		t.Fatalf("expected no reasons on empty input; got %+v", res.Reasons)
	}
}

// TestExportGate_SecretFindingBlocksAcrossModes confirms a secret
// finding blocks under both ModePatch and ModePR. Workflow-change
// blocking is mode-dependent (warn for patch, block for PR), but the
// secret rule must not be mode-dependent: a leaked key is never
// shippable regardless of export surface.
func TestExportGate_SecretFindingBlocksAcrossModes(t *testing.T) {
	gate := NewExportGate(nil)
	for _, mode := range []Mode{ModePatch, ModePR} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			in := Input{
				Mode: mode,
				BuiltInResult: scanners.ScanResult{
					Findings: []scanners.Finding{
						{
							ID:           "finding_001",
							Type:         "api_key",
							Pattern:      "Anthropic sk-ant- prefix",
							File:         "x.go",
							Line:         1,
							Confidence:   scanners.ConfidenceHigh,
							BlocksExport: true,
						},
					},
				},
			}
			res := gate.Evaluate(in)
			if !res.Blocked() {
				t.Fatalf("mode=%s: expected Decision=Block, got %s", mode, res.Decision)
			}
		})
	}
}

// TestExportGate_EntropyWarningsCoexistWithCleanDiff is the
// integrated entropy/clean-diff case: a Diff with no protected paths
// and an EntropyWarning-only scanner result should produce
// DecisionAllow. This matches the run-lifecycle path: the scanner
// drops secret-scan.json with entropy warnings, the gate reads it,
// and export proceeds while the CLI surfaces the warnings.
func TestExportGate_EntropyWarningsCoexistWithCleanDiff(t *testing.T) {
	gate := NewExportGate(nil)
	in := Input{
		Mode: ModePatch,
		Diff: workspace.DiffResult{
			Files: []workspace.FileDiff{
				{Path: "src/main.go", Change: workspace.ChangeModified},
			},
		},
		BuiltInResult: scanners.ScanResult{
			Scanner: "built-in-patterns",
			EntropyWarnings: []scanners.EntropyWarning{
				{File: "src/main.go", Line: 10, Entropy: 4.8, Reason: "base64-like, 40 chars, entropy 4.80"},
			},
		},
	}
	res := gate.Evaluate(in)
	if res.Blocked() {
		t.Fatalf("expected Decision=Allow with entropy warnings + clean diff; got %s with reasons %+v", res.Decision, res.Reasons)
	}
}
