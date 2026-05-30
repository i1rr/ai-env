// external.go implements optional external scanner discovery (plan 06
// step 5) and the first concrete external adapter, gitleaks (plan 06
// step 4). Both pieces share a single registry so adding a new external
// tool is one entry in knownExternalScanners plus, optionally, a
// runScanner implementation if the CLI driver lives here rather than in
// a later plan.
//
// Scope rules this file enforces:
//
//  1. Missing optional scanners never crash. DiscoverExternal probes
//     PATH for every entry in knownExternalScanners and stamps a
//     per-tool Available flag; a missing binary becomes Available=false
//     with a human-readable Message, not an error. RunExternal refuses
//     to invoke a tool whose ExternalScanner.Available is false rather
//     than re-resolving the binary itself, so the discovery output is
//     the single source of truth for "can we run this".
//  2. Discovery is cheap and pure. The probe is exec.LookPath only; we
//     do not run `tool --version` here. A wedged binary on PATH should
//     not slow `ai-env scan` startup, and the version field is reserved
//     for the per-tool adapter to populate after a successful run.
//  3. Adapter contract. Each tool's run logic lives behind a
//     runScanner function pointer on the registry entry. The function
//     receives an injected runner so tests can intercept the subprocess
//     without touching PATH. Entries with a nil run function (the
//     vulnerability scanners gated to later plans) are still discovered
//     but RunExternal reports them as not yet wired.
//  4. JSON normalization. Each adapter parses its tool's native output
//     and normalizes findings into the ScanResult shape. The ID format
//     ("finding_001", "finding_002", ...) matches the built-in scanner
//     so secret-scan.json reads uniformly regardless of source.

package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// scannerNameGitleaks is the Scanner identifier the gitleaks adapter
// stamps into every ScanResult it emits. The CLI and export gate
// recognize this string when grouping findings by source.
const scannerNameGitleaks = "gitleaks"

// defaultExternalTimeout caps how long any single external scanner is
// allowed to run. External tools (especially trivy and semgrep) can
// take minutes on a large workspace; the plan's scan command surfaces
// progress to the user, so an unbounded scan would freeze the CLI. The
// cap is generous: ten minutes is enough for a slow scan on a slow
// machine and well under the supervisor's overall run watchdog.
const defaultExternalTimeout = 10 * time.Minute

// externalRunner is the subprocess seam the adapters share. It mirrors
// the signature used by agents.ProbeRunner so the production wiring
// (exec.CommandContext) and the test fakes are interchangeable.
// stdout and stderr are mandatory; nil writers are replaced with
// io.Discard inside the runner.
type externalRunner func(ctx context.Context, binary string, args []string, dir string, stdout, stderr io.Writer) (exitCode int, err error)

// scannerAdapter is the per-tool driver. It is invoked by RunExternal
// after discovery has confirmed the binary is available. The adapter
// owns argv construction, exit-code interpretation, and output parsing
// for its tool; the return value is already in the normalized
// ScanResult shape the CLI writes to disk.
//
// A nil adapter on a registry entry means "discovery only": the tool
// is probed and reported but RunExternal refuses to invoke it. The
// vulnerability scanners (osv-scanner, trivy, *audit, govulncheck)
// land in plan 07; their entries ship with a nil adapter today so
// discovery is correct and the CLI summary can show them as
// available-but-not-wired.
type scannerAdapter func(ctx context.Context, runner externalRunner, binary, workspacePath string) (ScanResult, error)

// externalScannerEntry is one row in the registry. Name, Kind, and
// Command drive discovery; adapter drives execution.
type externalScannerEntry struct {
	// Name is the user-facing identifier (e.g. "gitleaks",
	// "osv-scanner"). It matches the ExternalScanner.Name returned to
	// the CLI.
	Name string

	// Kind is the analysis category surfaced in the discovery summary.
	Kind ScannerKind

	// Command is the binary the entry resolves on PATH. It may differ
	// from Name (e.g. "npm audit" lives behind the "npm" binary).
	Command string

	// adapter is the per-tool driver. Nil means the tool is discovered
	// only; RunExternal refuses to invoke it with a clear message.
	adapter scannerAdapter
}

// knownExternalScanners is the v0.1 registry. The plan's "Optional
// external scanners" section enumerates the tools; adding a new one is
// one entry here plus, optionally, a non-nil adapter. The vulnerability
// scanners ship with a nil adapter because their CLI drivers land in
// plan 07; discovery is still correct today.
func knownExternalScanners() []externalScannerEntry {
	return []externalScannerEntry{
		{
			Name:    "gitleaks",
			Kind:    ScannerKindSecrets,
			Command: "gitleaks",
			adapter: runGitleaks,
		},
		{
			Name:    "osv-scanner",
			Kind:    ScannerKindVulnerabilities,
			Command: "osv-scanner",
		},
		{
			Name:    "trivy",
			Kind:    ScannerKindVulnerabilities,
			Command: "trivy",
		},
		{
			Name:    "semgrep",
			Kind:    ScannerKindSAST,
			Command: "semgrep",
		},
		{
			Name:    "npm-audit",
			Kind:    ScannerKindVulnerabilities,
			Command: "npm",
		},
		{
			Name:    "pip-audit",
			Kind:    ScannerKindVulnerabilities,
			Command: "pip-audit",
		},
		{
			Name:    "cargo-audit",
			Kind:    ScannerKindVulnerabilities,
			Command: "cargo",
		},
		{
			Name:    "govulncheck",
			Kind:    ScannerKindVulnerabilities,
			Command: "govulncheck",
		},
	}
}

// discoverExternal implements ScanRunner.DiscoverExternal. It walks
// knownExternalScanners and stamps each entry with the result of an
// exec.LookPath probe. A missing binary is reported as Available=false
// with a human-readable Message; the function never returns an error.
//
// lookPath is the injected seam used by tests; nil falls back to
// exec.LookPath. Keeping the seam explicit lets the discovery test fix
// the "missing optional scanners do not crash" guarantee without
// poking at the host PATH.
func discoverExternal(lookPath func(string) (string, error)) []ExternalScanner {
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	entries := knownExternalScanners()
	out := make([]ExternalScanner, 0, len(entries))
	for _, e := range entries {
		es := ExternalScanner{
			Name: e.Name,
			Kind: e.Kind,
		}
		path, err := lookPath(e.Command)
		if err != nil || path == "" {
			es.Available = false
			es.Message = fmt.Sprintf("%s not found on PATH (looked for %q)", e.Name, e.Command)
		} else {
			es.Available = true
			es.BinaryPath = path
			if e.adapter == nil {
				es.Message = fmt.Sprintf("%s discovered but driver not yet wired in v0.1", e.Name)
			}
		}
		out = append(out, es)
	}
	return out
}

// runExternal implements ScanRunner.RunExternal. It looks the requested
// scanner up in the registry, refuses to invoke a tool whose discovery
// reported Available=false, and delegates to the per-tool adapter. The
// returned ScanResult always carries Scanner=scanner.Name and a
// populated ScannedAt timestamp; the adapter fills Findings and
// EntropyWarnings.
//
// runner is the injected subprocess seam; nil falls back to the
// os/exec-backed default. Tests pass a fake to intercept argv and
// supply canned tool output without a real binary on PATH.
func runExternal(runner externalRunner, scanner ExternalScanner, workspacePath string) (ScanResult, error) {
	if scanner.Name == "" {
		return ScanResult{}, errors.New("scanners: external scanner name is empty")
	}
	if !scanner.Available {
		return ScanResult{}, fmt.Errorf("scanners: external scanner %q is not available: %s", scanner.Name, scanner.Message)
	}
	if scanner.BinaryPath == "" {
		return ScanResult{}, fmt.Errorf("scanners: external scanner %q has no binary path", scanner.Name)
	}
	if workspacePath == "" {
		return ScanResult{}, fmt.Errorf("scanners: workspacePath is empty for %q", scanner.Name)
	}

	var entry externalScannerEntry
	for _, e := range knownExternalScanners() {
		if e.Name == scanner.Name {
			entry = e
			break
		}
	}
	if entry.Name == "" {
		return ScanResult{}, fmt.Errorf("scanners: unknown external scanner %q", scanner.Name)
	}
	if entry.adapter == nil {
		return ScanResult{}, fmt.Errorf("scanners: external scanner %q driver not yet wired", scanner.Name)
	}

	if runner == nil {
		runner = defaultExternalRunner
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultExternalTimeout)
	defer cancel()

	return entry.adapter(ctx, runner, scanner.BinaryPath, workspacePath)
}

// defaultExternalRunner is the production externalRunner. A clean
// non-zero exit is reported through exitCode rather than err so the
// adapter can distinguish "tool ran and found something" (gitleaks
// returns 1 on findings) from "tool failed to spawn".
func defaultExternalRunner(ctx context.Context, binary string, args []string, dir string, stdout, stderr io.Writer) (int, error) {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return cmd.ProcessState.ExitCode(), nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return -1, err
}

// gitleaksReport is the on-disk shape gitleaks emits with
// `--report-format json`. We only decode the fields the normalizer
// needs; gitleaks adds new fields between releases and an unknown
// field would otherwise break the adapter on every upgrade.
type gitleaksReport struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
}

// runGitleaks is the gitleaks adapter. It invokes `gitleaks detect`
// with a JSON report written to a pipe (--report-path=/dev/stdout via
// the no-banner / no-color flags is gitleaks's documented way of
// capturing output without a temp file). The adapter parses the JSON
// array and normalizes each entry into a high-confidence Finding;
// gitleaks's own rule engine is treated as authoritative so every hit
// gets Confidence=ConfidenceHigh and BlocksExport=true, matching the
// plan's "gitleaks finding (if installed)" hard blocker.
//
// Exit codes:
//
//	0   no findings
//	1   findings reported; output JSON on stdout
//	>1  tool error (config invalid, repo unreadable, ...); surfaced
//	    through the returned error
//
// A non-zero exit with valid JSON on stdout is treated as findings,
// not as a tool error. Other failures bubble up so the CLI can warn
// the operator without silently dropping the scanner.
func runGitleaks(ctx context.Context, runner externalRunner, binary, workspacePath string) (ScanResult, error) {
	result := ScanResult{
		Scanner:         scannerNameGitleaks,
		Findings:        []Finding{},
		EntropyWarnings: []EntropyWarning{},
		ScannedAt:       time.Now(),
	}

	var stdout, stderr bytes.Buffer
	args := []string{
		"detect",
		"--source", workspacePath,
		"--report-format", "json",
		"--report-path", "/dev/stdout",
		"--no-banner",
		"--no-color",
		"--exit-code", "1",
	}
	exitCode, err := runner(ctx, binary, args, workspacePath, &stdout, &stderr)
	if err != nil {
		return result, fmt.Errorf("scanners: gitleaks spawn failed: %w", err)
	}

	// gitleaks writes its JSON report to stdout in addition to any
	// human banner the --no-banner flag suppresses. The report is the
	// outer JSON array; extract it so a stray log line on stdout does
	// not break the decoder.
	payload := extractJSONArray(stdout.Bytes())

	switch {
	case exitCode == 0:
		// No findings. Return the empty result; stderr is ignored
		// because gitleaks routes its progress lines through there.
		return result, nil
	case exitCode == 1:
		// Findings present. Fall through to parsing.
	default:
		errText := strings.TrimSpace(stderr.String())
		if errText == "" {
			errText = strings.TrimSpace(stdout.String())
		}
		return result, fmt.Errorf("scanners: gitleaks exited %d: %s", exitCode, errText)
	}

	if len(payload) == 0 {
		// Exit code 1 with no parseable JSON is unusual but not
		// necessarily fatal; treat it as zero findings and let the
		// CLI surface the gitleaks stderr verbatim if needed.
		return result, nil
	}

	var entries []gitleaksReport
	if err := json.Unmarshal(payload, &entries); err != nil {
		return result, fmt.Errorf("scanners: gitleaks output parse failed: %w", err)
	}

	for i, e := range entries {
		pattern := e.RuleID
		if pattern == "" {
			pattern = e.Description
		}
		result.Findings = append(result.Findings, Finding{
			ID:           fmt.Sprintf("finding_%03d", i+1),
			Type:         "gitleaks",
			Pattern:      pattern,
			File:         e.File,
			Line:         e.StartLine,
			Confidence:   ConfidenceHigh,
			EntropyOnly:  false,
			BlocksExport: true,
		})
	}
	return result, nil
}

// extractJSONArray returns the slice of buf that starts at the first
// '[' and ends at the matching ']', or nil if no balanced array is
// found. gitleaks occasionally prefixes the report with a progress
// line that survives --no-banner; locating the array bounds explicitly
// is more robust than feeding the whole buffer to json.Unmarshal.
func extractJSONArray(buf []byte) []byte {
	start := bytes.IndexByte(buf, '[')
	if start < 0 {
		return nil
	}
	depth := 0
	inString := false
	escape := false
	for i := start; i < len(buf); i++ {
		c := buf[i]
		if inString {
			if escape {
				escape = false
				continue
			}
			if c == '\\' {
				escape = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return buf[start : i+1]
			}
		}
	}
	return nil
}
