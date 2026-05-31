//go:build acceptance

// Package acceptance MVP-demonstration scan + export-gate verifications.
//
// This file implements plan.md lines 101-103 (master plan section "MVP
// demonstration", verification bullets 30-32):
//
//   - Verify: `ai-env scan demo` runs without user-installed scanners.
//   - Verify: high-confidence secret finding blocks export.
//   - Verify: entropy-only finding warns but does not block.
//
// The three scenarios share the same shape as the batch 13 / 14
// verifications: each test exercises the runtime decision point an
// operator would observe and asserts both the visible verdict (CLI
// exit, gate Decision, written artifacts) and the load-bearing on-disk
// or in-memory shape so the audit trail an operator inspects after the
// demo carries the right evidence.
//
// Why this layer (and not a fully scripted demo run):
//
//   - The plan's "no external scanners required" guarantee belongs to
//     the built-in pattern scanner and the external-discovery code path;
//     both surfaces are exercised verbatim here against the freshly
//     built `ai-env` binary. We do NOT mock the scanner: every test
//     uses internal/scanners directly (or via the CLI's RunScan path)
//     so a regression in the matcher, the entropy analyzer, or the
//     gate's evaluation order surfaces immediately.
//   - For step 31 / 32 we drive scanners.BuiltIn.RunBuiltIn against a
//     real on-disk workspace containing the seeded fixture content,
//     then feed its ScanResult straight into export.ExportGate.Evaluate.
//     This is the same pipeline `ai-env patch` / `ai-env pr` consult
//     before exporting, so a verdict change here mirrors the user-
//     visible blocked / allowed outcome the demo advertises.
//
// Gating mirrors section32_test.go and the other mvp_demo_* files: the
// build tag `acceptance` is the static gate and AI_ENV_ACCEPTANCE=1
// (via TestMain in section32_test.go) is the dynamic gate. The binary
// is built once by section32_test.go's TestMain and reused via suite.binPath.

package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/export"
	"github.com/rivan1986/ai-env/internal/run"
	"github.com/rivan1986/ai-env/internal/scanners"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// seedRunDirectoryForEnv stages a minimal but valid run directory under
// the project's .ai-env/runs/<runID>/ tree and writes a run.json that
// carries env_name=envName. The CLI's `ai-env scan` command locates the
// run directory via run.LatestRunForEnv, which scans run.json for the
// env_name match; without a recorded run.json the env would appear
// unscanned (ErrNoRuns) and the scan would refuse to start.
//
// Returned value is the absolute run directory path so the caller can
// read back the secret-scan.json / dependency-report.json artifacts the
// scan writes there.
func seedRunDirectoryForEnv(t *testing.T, aiEnvDir, envName string) string {
	t.Helper()
	runID, err := run.GenerateRunID()
	if err != nil {
		t.Fatalf("GenerateRunID: %v", err)
	}
	dir, err := run.CreateRunDirectory(aiEnvDir, runID, time.Now())
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	rec := run.Record{
		RunID:               dir.ID,
		EnvName:             envName,
		Agent:               "claude",
		Task:                "MVP scan verification",
		State:               run.StateCompleted,
		Backend:             "local-process",
		ModelCredentialMode: run.ModelCredentialBackendManaged,
	}
	if err := run.WriteRecord(dir.Path, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	return dir.Path
}

// TestAcceptance_ScanDemoNoExternalScanners implements plan.md line 101
// (master plan section "MVP demonstration", verification bullet 30):
// `ai-env scan demo` must run to completion against a freshly created
// env even when no third-party scanner binaries (gitleaks, semgrep,
// osv-scanner, trivy, npm-audit, pip-audit, cargo-audit, govulncheck)
// are installed on the host.
//
// The test:
//
//  1. Scaffolds a demo env from the Python fixture using copy strategy
//     (the fixture is intentionally not a git repo so `ai-env new`
//     selects copy mode; the scan path supports both strategies). The
//     fixture is also pristine, so the built-in pattern scanner produces
//     zero findings and the gate would allow export.
//  2. Manually creates a run directory with env_name=demo so the CLI
//     can locate it via run.LatestRunForEnv.
//  3. Runs `ai-env scan demo` against a PATH containing only an empty
//     scratch directory so exec.LookPath cannot find gitleaks et al.
//     This is the load-bearing manipulation: it proves the scanner
//     code path treats missing optional tools as warnings (not errors).
//  4. Asserts exit 0, that secret-scan.json + dependency-report.json
//     landed in the run directory, and that the rendered summary
//     mentions a non-zero count of missing external scanners (so a
//     regression that silently dropped the discovery warning surfaces).
func TestAcceptance_ScanDemoNoExternalScanners(t *testing.T) {
	// 1. Scaffold the env from the python-app fixture under a fresh
	// project directory. We use python-app (without `git init`) so
	// `ai-env new` lands on copy strategy and the workspace.Diff call
	// inside RunScan does not require git on the host. The fixture's
	// pristine content means the built-in pattern matcher finds nothing.
	src := copyFixture(t, "python-app")
	project := t.TempDir()
	// CreateCopy leaves the baseline directory read-only; restore write
	// bits so t.TempDir's recursive cleanup can unlink children on macOS.
	t.Cleanup(func() {
		restoreWriteBitsRecursive(filepath.Join(project, ".ai-env"))
	})
	if _, _, err := runAIEnvWithOutput(t, project, "new", "demo", "--from", src); err != nil {
		t.Fatalf("ai-env new demo --from %s: %v", src, err)
	}

	aiEnvDir := filepath.Join(project, ".ai-env")
	runDirPath := seedRunDirectoryForEnv(t, aiEnvDir, "demo")

	// 2. Run `ai-env scan demo` with a PATH that excludes every host
	// binary so the external-scanner discovery cannot locate gitleaks /
	// semgrep / osv-scanner / etc. We still need the binary itself to
	// be locatable; we invoke it by absolute path (suite.binPath) so the
	// stripped PATH does not break the launch.
	emptyPathDir := t.TempDir()
	scrubbedPath := emptyPathDir
	t.Setenv("PATH", scrubbedPath)
	stdout, stderr, err := runAIEnvWithOutput(t, project, "scan", "demo")
	if err != nil {
		t.Fatalf("ai-env scan demo: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	// 3. The scan summary must report at least one missing external
	// scanner (since PATH was scrubbed). The renderer writes this list
	// to stderr; a regression that crashed on a missing binary would
	// have already failed the err check above, but the message contents
	// pin the user-facing guidance.
	if !strings.Contains(stderr, "optional scanners unavailable") {
		t.Errorf("stderr missing 'optional scanners unavailable' notice; got:\n%s", stderr)
	}

	// 4. secret-scan.json + dependency-report.json must land in the run
	// directory. Their presence proves the scan ran to completion and
	// did not abort partway because of a missing external scanner.
	secretPath := filepath.Join(runDirPath, "secret-scan.json")
	depPath := filepath.Join(runDirPath, "dependency-report.json")
	if _, statErr := os.Stat(secretPath); statErr != nil {
		t.Fatalf("expected secret-scan.json at %s, got: %v", secretPath, statErr)
	}
	if _, statErr := os.Stat(depPath); statErr != nil {
		t.Fatalf("expected dependency-report.json at %s, got: %v", depPath, statErr)
	}

	// 5. The built-in scanner result inside secret-scan.json must carry
	// the canonical built-in scanner name and an empty findings slice
	// against the pristine fixture (a regression that planted a false
	// positive on README.md or pyproject.toml would surface here).
	body, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read secret-scan.json: %v", err)
	}
	var scanFile struct {
		Scanner  string             `json:"scanner"`
		Findings []scanners.Finding `json:"findings"`
	}
	if err := json.Unmarshal(body, &scanFile); err != nil {
		t.Fatalf("parse secret-scan.json: %v\nraw: %s", err, body)
	}
	if scanFile.Scanner != "built-in-patterns" {
		t.Errorf("Scanner = %q, want built-in-patterns", scanFile.Scanner)
	}
	for _, f := range scanFile.Findings {
		if f.BlocksExport {
			t.Errorf("pristine fixture produced a blocking finding: %+v", f)
		}
	}

	// 6. The dependency report's discovered_tools list must include
	// each known external scanner with Available=false (since PATH is
	// scrubbed). This is the operator-visible artifact for "we looked
	// but did not find these tools"; a regression that silenced
	// discovery would leave the slice empty.
	depBody, err := os.ReadFile(depPath)
	if err != nil {
		t.Fatalf("read dependency-report.json: %v", err)
	}
	var depFile struct {
		DiscoveredTools []scanners.ExternalScanner `json:"discovered_tools"`
		Results         []scanners.ScanResult      `json:"results"`
	}
	if err := json.Unmarshal(depBody, &depFile); err != nil {
		t.Fatalf("parse dependency-report.json: %v\nraw: %s", err, depBody)
	}
	if len(depFile.DiscoveredTools) == 0 {
		t.Errorf("dependency-report.json discovered_tools empty; expected entries with Available=false")
	}
	for _, tool := range depFile.DiscoveredTools {
		if tool.Available {
			t.Errorf("discovered_tools entry %q reports Available=true despite scrubbed PATH; got %+v",
				tool.Name, tool)
		}
	}
	if len(depFile.Results) != 0 {
		t.Errorf("dependency-report.json Results = %d entries, want 0 (no scanner could run)", len(depFile.Results))
	}

	// 7. The summary must mention the env handle so a human running the
	// demo sees the scaffolding succeeded.
	if !strings.Contains(stdout, "demo") {
		t.Errorf("scan summary did not mention env name 'demo'; stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "no blocking findings") {
		t.Errorf("scan summary did not report 'no blocking findings' for clean fixture; stdout:\n%s", stdout)
	}
}

// TestAcceptance_HighConfidenceSecretBlocksExport implements plan.md
// line 102 (master plan section "MVP demonstration", verification
// bullet 31): a workspace whose changed files contain a high-confidence
// secret (here an AWS access key ID, matched by the AKIA pattern in
// builtinPatterns) must be refused by the export gate.
//
// The test wires the real built-in scanner against a real on-disk file
// containing the seeded secret and feeds the resulting ScanResult
// directly into export.ExportGate.Evaluate. This is the exact pipeline
// `ai-env patch` / `ai-env pr` consult before exporting; a verdict
// change here mirrors the user-visible blocked outcome the demo
// advertises.
//
// Assertions:
//   - The built-in scanner produces at least one Finding with
//     BlocksExport=true (the AKIA pattern hit).
//   - export.ExportGate.Evaluate returns Decision=DecisionBlock.
//   - The blocking reason carries Code=ReasonSecretFinding (so the CLI
//     can render the specific override guidance) and a Message that
//     mentions the secret-pattern name.
func TestAcceptance_HighConfidenceSecretBlocksExport(t *testing.T) {
	// 1. Materialize a workspace whose tracked file content contains a
	// real-looking AWS access key ID. The AKIA prefix + 16 uppercase
	// alphanumeric chars matches the built-in api_key rule with
	// Confidence=High and BlocksExport=true.
	workspaceRoot := t.TempDir()
	secretLine := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(workspaceRoot, "config.env"), []byte(secretLine), 0o644); err != nil {
		t.Fatalf("write config.env: %v", err)
	}
	// Add a benign file too so the scanner has more than one target and
	// a regression that mis-attributed findings would be visible.
	if err := os.WriteFile(filepath.Join(workspaceRoot, "README.md"), []byte("# fixture\n"), 0o644); err != nil {
		t.Fatalf("write README.md: %v", err)
	}

	// 2. Drive the real built-in scanner. We pass a synthetic
	// DiffResult whose Files list pins the two test files so the
	// scanner targets exactly what we seeded (RunBuiltIn would walk
	// the whole directory if Files were empty; pinning the list keeps
	// the test deterministic across future fixture additions).
	bi, err := scanners.NewBuiltIn(scanners.Config{})
	if err != nil {
		t.Fatalf("NewBuiltIn: %v", err)
	}
	res, err := bi.RunBuiltIn(workspaceRoot, workspace.DiffResult{
		Files: []workspace.FileDiff{
			{Path: "config.env", Change: workspace.ChangeAdded},
			{Path: "README.md", Change: workspace.ChangeAdded},
		},
	})
	if err != nil {
		t.Fatalf("RunBuiltIn: %v", err)
	}

	// 3. The scanner must have flagged the AKIA secret in config.env
	// and left README.md alone.
	if len(res.Findings) == 0 {
		t.Fatalf("built-in scanner produced no findings; expected an AKIA hit")
	}
	var sawAKIA bool
	for _, f := range res.Findings {
		if f.File != "config.env" {
			t.Errorf("finding attributed to wrong file: %+v", f)
		}
		if !f.BlocksExport {
			t.Errorf("finding %s did not mark BlocksExport=true: %+v", f.ID, f)
		}
		if f.Confidence != scanners.ConfidenceHigh {
			t.Errorf("finding %s Confidence = %q, want %q", f.ID, f.Confidence, scanners.ConfidenceHigh)
		}
		if strings.Contains(strings.ToUpper(f.Pattern), "AKIA") {
			sawAKIA = true
		}
	}
	if !sawAKIA {
		t.Errorf("no AKIA-named finding in %+v", res.Findings)
	}

	// 4. Feed the scan result into the real export gate. This is the
	// pipeline `ai-env patch` and `ai-env pr` consult before exporting;
	// a verdict change here mirrors the user-visible blocked outcome.
	gate := export.NewExportGate(nil)
	verdict := gate.Evaluate(export.Input{
		Mode:          export.ModePatch,
		BuiltInResult: res,
		Diff: workspace.DiffResult{
			Files: []workspace.FileDiff{
				{Path: "config.env", Change: workspace.ChangeAdded},
				{Path: "README.md", Change: workspace.ChangeAdded},
			},
		},
	})

	// 5. The verdict must be Block and the blocking reason must
	// reference the secret-finding code path so the CLI can render the
	// specific override guidance.
	if verdict.Decision != export.DecisionBlock {
		t.Fatalf("gate Decision = %q, want %q. Reasons=%+v",
			verdict.Decision, export.DecisionBlock, verdict.Reasons)
	}
	if !verdict.Blocked() {
		t.Errorf("verdict.Blocked() = false; want true")
	}
	blocking := verdict.BlockingReasons()
	if len(blocking) == 0 {
		t.Fatalf("verdict has no blocking reasons; full Reasons=%+v", verdict.Reasons)
	}
	var sawSecret bool
	for _, r := range blocking {
		if r.Code != export.ReasonSecretFinding {
			continue
		}
		sawSecret = true
		if !r.Hard {
			t.Errorf("secret-finding reason Hard = false; want true (hard blocker)")
		}
		if r.FindingID == "" {
			t.Errorf("secret-finding reason FindingID empty; CLI cannot cross-reference the artifact")
		}
		if !strings.Contains(strings.ToLower(r.Message), "secret leak") {
			t.Errorf("secret-finding Message = %q, want substring 'secret leak'", r.Message)
		}
	}
	if !sawSecret {
		t.Errorf("no ReasonSecretFinding in blocking reasons; got %+v", blocking)
	}
}

// TestAcceptance_EntropyOnlyFindingWarnsButAllowsExport implements
// plan.md line 103 (master plan section "MVP demonstration",
// verification bullet 32): a workspace whose changed files contain only
// a high-entropy substring (no pattern-matching secret) must produce
// an entropy warning but must NOT block export. This is the v0.1
// false-positive lightning rod: lockfile checksums, content hashes,
// UUIDs, and the like generate entropy warnings without refusing the
// patch.
//
// The test wires the real built-in scanner against a real on-disk file
// containing a high-entropy base64-shaped substring whose surrounding
// context does NOT trigger any pattern rule (the variable name is
// `data`, not `*_TOKEN=` / `*_KEY=` / `*_SECRET=` so the env-assignment
// rule cannot fire). The scanner's EntropyWarnings slice must populate
// and Findings must stay empty; the gate must Allow.
//
// Assertions:
//   - res.Findings is empty (no pattern hit).
//   - res.EntropyWarnings has at least one entry attributed to the
//     seeded file (warning is surfaced, not silenced).
//   - export.ExportGate.Evaluate returns Decision=DecisionAllow.
//   - verdict.Warnings() may be non-empty (other configurable rules
//     could fire warnings on a real diff), but no Reason with Code
//     ReasonSecretFinding is present.
func TestAcceptance_EntropyOnlyFindingWarnsButAllowsExport(t *testing.T) {
	// 1. Stage a workspace file whose content contains a high-entropy
	// base64-shaped substring but no pattern-class metadata. We use
	// the variable name `data` (not *_KEY / *_TOKEN / *_SECRET) so the
	// env_assignment rule cannot fire, and we keep the surrounding text
	// free of provider prefixes (sk-, AKIA, ghp_, etc.) so no API-key
	// rule fires either. The string itself is a 64-char random-looking
	// base64 sequence that the entropy analyzer flags.
	workspaceRoot := t.TempDir()
	// 64 chars of mixed base64 alphabet; entropy well above the
	// defaultEntropyThreshold (4.5 bits/char) so the analyzer flags it.
	highEntropyBlob := "aB3xY9zPqWvLmNkRsTuVcDfGhJ4tYn7QbW2eR1aZ5oP8sH6kL0jM3iX9wU4vC2"
	body := "data = \"" + highEntropyBlob + "\"\n"
	relPath := "blob.txt"
	if err := os.WriteFile(filepath.Join(workspaceRoot, relPath), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", relPath, err)
	}

	// 2. Drive the real built-in scanner. Empty Config so default
	// thresholds apply.
	bi, err := scanners.NewBuiltIn(scanners.Config{})
	if err != nil {
		t.Fatalf("NewBuiltIn: %v", err)
	}
	res, err := bi.RunBuiltIn(workspaceRoot, workspace.DiffResult{
		Files: []workspace.FileDiff{
			{Path: relPath, Change: workspace.ChangeAdded},
		},
	})
	if err != nil {
		t.Fatalf("RunBuiltIn: %v", err)
	}

	// 3. The scanner must NOT have produced any pattern-class Finding;
	// it must have populated EntropyWarnings instead. A regression that
	// promoted entropy hits to Findings (or one that silenced the
	// entropy analyzer entirely) would surface here.
	if len(res.Findings) != 0 {
		t.Fatalf("expected zero pattern findings on entropy-only fixture; got %+v", res.Findings)
	}
	if len(res.EntropyWarnings) == 0 {
		t.Fatalf("expected at least one EntropyWarning on the seeded high-entropy blob; got none. result=%+v", res)
	}
	var sawWarning bool
	for _, w := range res.EntropyWarnings {
		if w.File != relPath {
			t.Errorf("entropy warning attributed to wrong file: %+v", w)
		}
		if w.Entropy <= 0 {
			t.Errorf("entropy warning carries non-positive entropy: %+v", w)
		}
		sawWarning = true
	}
	if !sawWarning {
		t.Errorf("no entropy warning attributed to %s; got %+v", relPath, res.EntropyWarnings)
	}

	// 4. Feed the result into the real export gate. The gate must
	// Allow (entropy-only findings are warn-only per the v0.1 policy)
	// and must NOT carry a ReasonSecretFinding entry (which would
	// imply the entropy hit was misclassified as a blocking secret).
	gate := export.NewExportGate(nil)
	verdict := gate.Evaluate(export.Input{
		Mode:          export.ModePatch,
		BuiltInResult: res,
		Diff: workspace.DiffResult{
			Files: []workspace.FileDiff{
				{Path: relPath, Change: workspace.ChangeAdded},
			},
		},
	})
	if verdict.Decision != export.DecisionAllow {
		t.Fatalf("gate Decision = %q, want %q. Reasons=%+v",
			verdict.Decision, export.DecisionAllow, verdict.Reasons)
	}
	if verdict.Blocked() {
		t.Errorf("verdict.Blocked() = true; want false")
	}
	if len(verdict.BlockingReasons()) != 0 {
		t.Errorf("entropy-only result produced blocking reasons: %+v", verdict.BlockingReasons())
	}
	for _, r := range verdict.Reasons {
		if r.Code == export.ReasonSecretFinding {
			t.Errorf("entropy-only result surfaced a ReasonSecretFinding: %+v", r)
		}
	}
}
