// Package scanners owns the secret and dependency scanning surface that
// ai-env runs before exporting an agent's diff. The ScanRunner interface
// defined here is the single contract every concrete scanner (the
// built-in pattern-only secret scanner from step 2, the entropy
// analyzer from step 3, the gitleaks integration from step 4, and the
// optional external scanners discovered in step 5) plugs into so the
// CLI and the export gate can treat them uniformly.
//
// Design rules this package enforces:
//
//  1. Useful without external tools. RunBuiltIn must succeed on any
//     workspace even when no third-party scanner is installed on the
//     host. The plan's "useful without external tools" rule is the
//     reason RunBuiltIn and RunExternal live behind the same interface:
//     the CLI runs the built-in first and treats external results as
//     additive.
//  2. Pattern-only blocking in v0.1. Findings flagged with
//     ConfidenceHigh and BlocksExport=true are the only ones the export
//     gate refuses to ship. Entropy-only matches go in EntropyWarnings
//     so callers can render them as warnings without blocking export.
//  3. Discovery never fails. DiscoverExternal probes PATH for each
//     optional binary and returns a status per tool; a missing binary
//     is reported as Available=false rather than an error so the CLI
//     can surface a single "X scanners available, Y missing" summary.
//  4. Stable JSON shape. ScanResult marshals to the secret-scan.json
//     contract documented in plan 06 (run_id, scanner, findings[],
//     entropy_warnings[], scanned_at). The field tags on ScanResult,
//     Finding, and EntropyWarning are the source of truth; downstream
//     consumers (export gate, ai-env report) read this shape directly.
//
// Implementations of ScanRunner land in later steps of plan 06. This
// file defines only the public surface so the CLI command, the export
// gate, and the run-lifecycle hook can be wired against a stable type.
package scanners

import (
	"time"

	"github.com/i1rr/ai-env/internal/workspace"
)

// ScanRunner is the contract every scanner adapter satisfies. A single
// ScanRunner is constructed per run by the CLI; the same instance is
// reused across RunBuiltIn, RunExternal, and DiscoverExternal calls so
// the scanner can share configuration (allowlist, custom patterns,
// entropy threshold) loaded once from policy.yaml.
//
// Methods on ScanRunner are not required to be safe for concurrent use
// by multiple goroutines. The CLI invokes them sequentially: discover
// first, then built-in, then each external scanner in turn.
type ScanRunner interface {
	// RunBuiltIn scans the workspace at workspacePath using the
	// built-in pattern-only secret scanner and the warn-only entropy
	// analyzer. diff narrows the scan to files that actually changed
	// in this run; a zero DiffResult means "scan every regular file
	// under workspacePath". The returned ScanResult carries
	// Scanner="built-in-patterns" and is always populated, even when
	// no findings are produced.
	RunBuiltIn(workspacePath string, diff workspace.DiffResult) (ScanResult, error)

	// RunExternal invokes the external scanner described by scanner
	// against workspacePath and returns its findings normalized into
	// the ScanResult shape. scanner must come from DiscoverExternal:
	// passing a tool that is not Available causes RunExternal to
	// return an error rather than guess at the binary location.
	RunExternal(scanner ExternalScanner, workspacePath string) (ScanResult, error)

	// DiscoverExternal probes the host for every optional external
	// scanner ai-env knows about (gitleaks, osv-scanner, trivy,
	// semgrep, npm audit, pip-audit, cargo audit, govulncheck) and
	// returns one ExternalScanner entry per tool. Tools whose binary
	// is missing from PATH are reported with Available=false; the
	// CLI surfaces them as warnings instead of errors.
	DiscoverExternal() []ExternalScanner
}

// ScanResult is the structured output of a single scanner invocation.
// Its JSON shape is the secret-scan.json contract documented in plan
// 06; the CLI's scan command writes one ScanResult per scanner to the
// run directory and the export gate reads them back to decide whether
// to allow the diff out.
type ScanResult struct {
	// RunID is the run identifier the scan was performed under (e.g.
	// "20260528-101300-a1b2c3"). The supervisor passes this through
	// when invoking the scanner so all artifacts from a single run
	// share an ID.
	RunID string `json:"run_id"`

	// Scanner identifies which scanner produced this result. The
	// built-in scanner uses "built-in-patterns"; external scanners
	// use their CLI name (e.g. "gitleaks", "osv-scanner"). Always
	// populated.
	Scanner string `json:"scanner"`

	// Findings is the list of high-confidence pattern matches the
	// scanner found. Each finding carries enough metadata for the
	// export gate to decide whether it blocks export.
	Findings []Finding `json:"findings"`

	// EntropyWarnings is the list of strings that exceeded the
	// entropy threshold but did not match any known pattern class.
	// These are reported as warnings only and never block export
	// under the v0.1 policy.
	EntropyWarnings []EntropyWarning `json:"entropy_warnings"`

	// ScannedAt is the wall-clock time the scan completed, in the
	// local time zone. Persisted in RFC3339 form in the on-disk JSON.
	ScannedAt time.Time `json:"scanned_at"`
}

// Finding is a single high-confidence secret match. Findings flow from
// the scanner into the export gate, where BlocksExport decides whether
// the diff is allowed out. The JSON shape mirrors the secret-scan.json
// example in plan 06 so external tooling can consume it directly.
type Finding struct {
	// ID is a stable identifier for this finding within the
	// ScanResult (e.g. "finding_001"). It lets the CLI cross-reference
	// a finding between the scan output and the gate's block reason.
	ID string `json:"id"`

	// Type is the pattern class the finding belongs to (e.g.
	// "api_key", "private_key", "env_assignment"). Used by the CLI
	// to group findings in the summary view.
	Type string `json:"type"`

	// Pattern is the human-readable name of the specific pattern that
	// matched (e.g. "ANTHROPIC_API_KEY", "OpenAI sk- prefix",
	// "BEGIN RSA PRIVATE KEY"). Empty when the scanner does not
	// distinguish patterns within a Type.
	Pattern string `json:"pattern"`

	// File is the workspace-relative path of the file the match was
	// found in. Always populated.
	File string `json:"file"`

	// Line is the 1-based line number inside File where the match
	// occurred. Zero when the scanner cannot localize the match to a
	// line (some external scanners only report file-level findings).
	Line int `json:"line"`

	// Confidence reports how certain the scanner is that the finding
	// is a real secret. Only ConfidenceHigh blocks export by default;
	// lower confidences are surfaced for human review.
	Confidence Confidence `json:"confidence"`

	// EntropyOnly reports whether the match was produced by the
	// entropy analyzer alone (no pattern match). Entropy-only
	// findings are recorded in EntropyWarnings, not Findings; this
	// field is kept on Finding so an external scanner that conflates
	// entropy and pattern matches can still report the distinction.
	EntropyOnly bool `json:"entropy_only"`

	// BlocksExport reports whether this finding should block export.
	// The built-in scanner sets it to true for high-confidence
	// pattern matches and false for entropy-only matches; external
	// scanners normalize their severity to this boolean.
	BlocksExport bool `json:"blocks_export"`
}

// EntropyWarning is a single warn-only entropy match. It mirrors the
// shape of Finding minus the export-blocking fields so callers can
// render it in the same UI affordance without confusion about whether
// it blocks the gate.
type EntropyWarning struct {
	// File is the workspace-relative path of the file the high-entropy
	// string was found in.
	File string `json:"file"`

	// Line is the 1-based line number the string starts on. Zero
	// when the analyzer cannot localize the match.
	Line int `json:"line"`

	// Entropy is the Shannon entropy (in bits per character) the
	// analyzer measured for the matched substring.
	Entropy float64 `json:"entropy"`

	// Reason is a short human-readable explanation of why the string
	// was flagged (e.g. "base64-like, 48 chars, entropy 4.7").
	Reason string `json:"reason"`
}

// Confidence enumerates how certain a scanner is that a finding is a
// real secret. The export gate consults Confidence (and BlocksExport)
// to decide whether to refuse the diff.
type Confidence string

const (
	// ConfidenceHigh means the scanner matched a known provider
	// pattern (e.g. an OpenAI sk- prefix with the right length) and
	// the finding should block export by default.
	ConfidenceHigh Confidence = "high"

	// ConfidenceMedium means the scanner matched a heuristic that is
	// usually but not always a secret (e.g. an env-style assignment
	// with a long value). The finding is reported but does not block
	// export without explicit policy opt-in.
	ConfidenceMedium Confidence = "medium"

	// ConfidenceLow means the scanner has weak evidence (e.g.
	// entropy alone). Low-confidence findings are surfaced as
	// warnings and never block export under the v0.1 policy.
	ConfidenceLow Confidence = "low"
)

// String makes Confidence satisfy fmt.Stringer so it formats cleanly
// in log lines and CLI output without an explicit conversion.
func (c Confidence) String() string { return string(c) }

// ExternalScanner describes a single optional third-party scanner ai-env
// can drive. DiscoverExternal returns one entry per known tool; the CLI
// runs every Available scanner and reports the unavailable ones as
// warnings to the user.
type ExternalScanner struct {
	// Name is the scanner's CLI name (e.g. "gitleaks", "osv-scanner",
	// "trivy", "semgrep", "npm", "pip-audit", "cargo", "govulncheck").
	// Always populated.
	Name string `json:"name"`

	// Kind is the category of analysis the scanner performs
	// ("secrets" for gitleaks, "vulnerabilities" for osv-scanner /
	// trivy / *audit / govulncheck, "sast" for semgrep). The CLI uses
	// Kind to group the discovery output.
	Kind ScannerKind `json:"kind"`

	// Available reports whether the scanner's binary was found on
	// PATH. False means RunExternal will refuse to invoke it; the CLI
	// surfaces these entries as warnings.
	Available bool `json:"available"`

	// BinaryPath is the absolute path to the binary that was
	// discovered. Empty when Available is false.
	BinaryPath string `json:"binary_path,omitempty"`

	// Version is the scanner's reported version string, when the
	// scanner exposes a version probe. Empty when no version is
	// available; the CLI does not gate on this field.
	Version string `json:"version,omitempty"`

	// Message is a short human-readable diagnostic the CLI surfaces
	// verbatim alongside the discovery summary. Typically empty when
	// Available is true; used to explain why an unavailable scanner
	// could not be located.
	Message string `json:"message,omitempty"`
}

// ScannerKind enumerates the analysis category an ExternalScanner
// performs. The CLI groups discovery output by Kind so users see
// "secrets scanners: gitleaks (available)" / "vulnerability scanners:
// ..." rather than a flat list.
type ScannerKind string

const (
	// ScannerKindSecrets identifies scanners whose primary purpose is
	// secret detection (e.g. gitleaks).
	ScannerKindSecrets ScannerKind = "secrets"

	// ScannerKindVulnerabilities identifies scanners that detect
	// dependency or package vulnerabilities (e.g. osv-scanner, trivy,
	// npm audit, pip-audit, cargo audit, govulncheck).
	ScannerKindVulnerabilities ScannerKind = "vulnerabilities"

	// ScannerKindSAST identifies static-analysis scanners that look
	// for code-level issues (e.g. semgrep).
	ScannerKindSAST ScannerKind = "sast"
)

// String makes ScannerKind satisfy fmt.Stringer so it formats cleanly
// in log lines and CLI output without an explicit conversion.
func (k ScannerKind) String() string { return string(k) }
