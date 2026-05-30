// builtin.go implements the built-in pattern-only secret scanner that
// satisfies ScanRunner.RunBuiltIn. It is plan 06 step 2: a scanner that
// must work on any host with zero external tools installed, and whose
// findings are the only ones the export gate refuses to ship in v0.1.
//
// Scope rules this file enforces:
//
//  1. Pattern-only blocking. Every Finding this file emits carries
//     Confidence=ConfidenceHigh and BlocksExport=true. The patterns
//     below are limited to provider-format API keys, PEM-style private
//     key headers, and .env-style assignments whose key name strongly
//     implies a secret. Anything weaker (entropy alone, generic long
//     strings) is left to the entropy analyzer in step 3.
//  2. Changed files only. Scanning operates on the FileDiff entries in
//     the workspace.DiffResult passed to RunBuiltIn. The plan's "Scan
//     all changed files in the diff" requirement is the contract; we
//     do not walk the whole workspace because most files are unchanged
//     and a full scan would re-flag committed legacy data on every run.
//  3. Allowlist is non-negotiable. The two allowlist channels (inline
//     "# ai-env-scan-ignore" comments and Config.Allowlist regexes)
//     short-circuit the matcher before a Finding is emitted. The plan
//     calls allowlisting out explicitly so users can keep test fixtures
//     and documentation examples committed without re-tripping the
//     scanner each run.
//  4. Custom patterns are additive. Config.CustomPatterns is layered on
//     top of the built-in pattern set rather than replacing it; users
//     can add a regex for an internal token format without losing the
//     OpenAI / Anthropic / GitHub coverage.

package scanners

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rivan1986/ai-env/internal/workspace"
)

// scannerNameBuiltIn is the Scanner identifier the built-in scanner
// stamps into every ScanResult it emits. The CLI and export gate
// recognize this exact string so it lives in one place.
const scannerNameBuiltIn = "built-in-patterns"

// allowlistComment is the inline marker that suppresses a finding on
// the matched line. Matching is substring-based (case sensitive) so a
// user can write either "// ai-env-scan-ignore" or
// "# ai-env-scan-ignore" without per-language ceremony.
const allowlistComment = "ai-env-scan-ignore"

// maxScannedFileBytes caps how much of any single file we read into
// memory. Secrets are short and live near the top of a file; reading
// gigabyte assets line-by-line just to flag a key is wasteful and a
// DoS vector if a hostile agent drops a huge binary into the diff.
const maxScannedFileBytes = 2 * 1024 * 1024

// Config bundles the policy-driven knobs the built-in scanner needs.
// It is loaded once per run by the CLI from policy.yaml and handed to
// NewBuiltIn so the scanner does not re-read configuration mid-scan.
// All fields are optional; the zero value is a usable scanner that
// runs the built-in pattern set with no allowlist and no custom
// patterns.
type Config struct {
	// CustomPatterns is a list of user-supplied regular expressions
	// (RE2 syntax) layered on top of the built-in pattern set. Each
	// match is reported as Type="custom" with Confidence=ConfidenceHigh
	// so the export gate treats it the same as a built-in match.
	CustomPatterns []string

	// Allowlist is a list of regular expressions (RE2 syntax). A line
	// whose text matches any Allowlist entry is skipped before the
	// pattern matchers run. The plan documents this as the "entries in
	// policy.yaml" half of the allowlist contract.
	Allowlist []string

	// EntropyThreshold overrides the bits-per-character cutoff the
	// warn-only entropy analyzer uses for base64-shaped substrings. A
	// zero value means "use the built-in default" (see entropy.go).
	// The analyzer never produces a blocking finding regardless of
	// threshold; this knob only tunes how aggressively warnings are
	// emitted.
	EntropyThreshold float64

	// HexEntropyThreshold overrides the bits-per-character cutoff for
	// hex-only substrings. A zero value means "use the built-in
	// default". Same warn-only contract as EntropyThreshold.
	HexEntropyThreshold float64
}

// BuiltIn is the concrete ScanRunner used when no external scanner is
// configured. It is constructed once per run by the CLI; the same
// instance is reused across RunBuiltIn, RunExternal, and
// DiscoverExternal so allowlist and custom-pattern compilation costs
// are paid once.
//
// The external-scanner surface (RunExternal, DiscoverExternal) is
// delegated to the registry in external.go. BuiltIn carries optional
// hooks (lookPath, runner) so tests can drive discovery and gitleaks
// without a real binary on PATH; production code leaves them nil and
// the package falls back to exec.LookPath plus an os/exec-backed
// runner.
type BuiltIn struct {
	patterns       []patternRule
	customPatterns []patternRule
	allowlist      []*regexp.Regexp
	entropy        *entropyAnalyzer

	lookPath func(string) (string, error)
	runner   externalRunner
}

// Compile-time check that *BuiltIn satisfies ScanRunner. Step 2 only
// fills RunBuiltIn meaningfully; the other two methods are stubs in
// this file and get their real bodies in later batches, but the
// interface contract is honored from the start so callers can wire
// against a ScanRunner today.
var _ ScanRunner = (*BuiltIn)(nil)

// patternRule is one entry in the built-in pattern set. It carries
// enough metadata for Finding to be populated without a per-rule
// switch in the matcher loop.
type patternRule struct {
	// re is the compiled regular expression that matches the secret.
	// It is anchored where appropriate; see builtinPatterns for the
	// concrete shape of each rule.
	re *regexp.Regexp

	// kind is the Finding.Type the rule emits (e.g. "api_key",
	// "private_key", "env_assignment", "custom").
	kind string

	// name is the human-readable Finding.Pattern the rule emits
	// (e.g. "OpenAI sk- prefix", "BEGIN RSA PRIVATE KEY"). Empty for
	// rules whose Type already uniquely identifies them.
	name string
}

// NewBuiltIn constructs a BuiltIn from cfg. It compiles every regex
// up-front so a malformed Config.CustomPatterns or Config.Allowlist
// entry fails the run before any file is read, rather than mid-scan.
//
// A non-nil error is returned only for compile failures. A zero Config
// is valid: the resulting BuiltIn runs the built-in pattern set with
// no allowlist and no custom patterns.
func NewBuiltIn(cfg Config) (*BuiltIn, error) {
	b := &BuiltIn{
		patterns: builtinPatterns(),
		entropy:  newEntropyAnalyzer(cfg),
	}

	for i, expr := range cfg.CustomPatterns {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("scanners: compile custom pattern %d: %w", i, err)
		}
		b.customPatterns = append(b.customPatterns, patternRule{
			re:   re,
			kind: "custom",
			name: expr,
		})
	}

	for i, expr := range cfg.Allowlist {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("scanners: compile allowlist pattern %d: %w", i, err)
		}
		b.allowlist = append(b.allowlist, re)
	}

	return b, nil
}

// RunBuiltIn implements ScanRunner. It scans every changed file in
// diff (or every regular file under workspacePath when diff is the
// zero value) and returns one ScanResult populated with the
// high-confidence pattern matches found.
//
// Files that are deleted in the diff are skipped: there is no file
// content left in the workspace to read, and a secret that was removed
// is not a secret leak we need to block on. Binary files (detected by
// a NUL byte in the first 512 bytes) are also skipped so the scanner
// does not chew through compiled artifacts or images.
//
// The returned error is non-nil only for unrecoverable I/O failures
// (e.g. workspacePath does not exist); a file we cannot open is
// recorded as zero findings rather than aborting the whole scan.
func (b *BuiltIn) RunBuiltIn(workspacePath string, diff workspace.DiffResult) (ScanResult, error) {
	if workspacePath == "" {
		return ScanResult{}, fmt.Errorf("scanners: workspacePath is empty")
	}
	if info, err := os.Stat(workspacePath); err != nil {
		return ScanResult{}, fmt.Errorf("scanners: stat workspace %s: %w", workspacePath, err)
	} else if !info.IsDir() {
		return ScanResult{}, fmt.Errorf("scanners: workspace %s is not a directory", workspacePath)
	}

	targets := b.targets(workspacePath, diff)

	result := ScanResult{
		RunID:           "",
		Scanner:         scannerNameBuiltIn,
		Findings:        []Finding{},
		EntropyWarnings: []EntropyWarning{},
		ScannedAt:       time.Now(),
	}

	for _, rel := range targets {
		abs := filepath.Join(workspacePath, rel)
		findings, warnings := b.scanFile(abs, rel, len(result.Findings)+1)
		result.Findings = append(result.Findings, findings...)
		result.EntropyWarnings = append(result.EntropyWarnings, warnings...)
	}

	return result, nil
}

// RunExternal implements ScanRunner. It delegates to runExternal in
// external.go, which looks the requested scanner up in the registry,
// refuses to invoke a tool whose discovery reported Available=false,
// and dispatches to the per-tool adapter (gitleaks today; other
// vulnerability scanners land in plan 07). The runner seam on BuiltIn
// is forwarded so tests can intercept the subprocess.
func (b *BuiltIn) RunExternal(scanner ExternalScanner, workspacePath string) (ScanResult, error) {
	return runExternal(b.runner, scanner, workspacePath)
}

// DiscoverExternal implements ScanRunner. It delegates to
// discoverExternal in external.go, which probes PATH for every entry
// in knownExternalScanners and stamps a per-tool Available flag. A
// missing binary is reported as Available=false with a Message; the
// call never returns an error, satisfying the plan's "missing optional
// scanners do not crash" rule.
func (b *BuiltIn) DiscoverExternal() []ExternalScanner {
	return discoverExternal(b.lookPath)
}

// SetLookPath installs the exec.LookPath seam used by DiscoverExternal.
// Production callers leave the hook nil; tests inject a fake to assert
// discovery behavior without touching the host PATH.
func (b *BuiltIn) SetLookPath(fn func(string) (string, error)) {
	b.lookPath = fn
}

// SetExternalRunner installs the subprocess seam used by RunExternal.
// Production callers leave the hook nil; tests inject a fake to drive
// the per-tool adapters with canned stdout / stderr / exit codes.
func (b *BuiltIn) SetExternalRunner(fn func(ctx context.Context, binary string, args []string, dir string, stdout, stderr io.Writer) (int, error)) {
	if fn == nil {
		b.runner = nil
		return
	}
	b.runner = externalRunner(fn)
}

// targets resolves the list of workspace-relative file paths the
// scanner should read. When diff carries FileDiff entries we use those
// (skipping deletions); when diff is zero we walk workspacePath. The
// walk path is the fallback for callers that want to scan a workspace
// before any baseline exists (e.g. ad-hoc invocations).
func (b *BuiltIn) targets(workspacePath string, diff workspace.DiffResult) []string {
	if len(diff.Files) > 0 {
		out := make([]string, 0, len(diff.Files))
		for _, f := range diff.Files {
			if f.Change == workspace.ChangeDeleted {
				continue
			}
			out = append(out, f.Path)
		}
		return out
	}

	var out []string
	_ = filepath.Walk(workspacePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			// .git is never scanned: it is full of high-entropy object
			// blobs that would generate spurious findings on every run.
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(workspacePath, path)
		if err != nil {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	return out
}

// scanFile runs every pattern rule against the file at abs and
// returns the matched Findings plus the warn-only EntropyWarnings the
// entropy analyzer produced for the same file. nextID is the running
// counter the caller threads through so finding_001 / finding_002 /
// ... are stable across the whole ScanResult.
//
// Entropy analysis runs after the pattern matcher on each line. If
// the line already produced a pattern Finding we skip the entropy
// pass for that line so callers do not get one Finding and one
// EntropyWarning for the same secret. Allowlisted lines suppress
// both channels.
//
// Errors reading the file are swallowed: an unreadable file is
// reported as zero findings rather than aborting the run. The CLI
// surfaces the broader scan summary; a single skipped file is not
// worth failing the whole gate over.
func (b *BuiltIn) scanFile(abs, rel string, nextID int) ([]Finding, []EntropyWarning) {
	f, err := os.Open(abs)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil
	}
	if info.Size() > maxScannedFileBytes {
		return nil, nil
	}

	// Peek the first 512 bytes to skip binary files. A NUL byte in
	// the prefix is the cheapest reliable signal that the rest of the
	// file is not text; we do not need a full MIME sniff for this.
	head := make([]byte, 512)
	n, _ := f.Read(head)
	if isBinary(head[:n]) {
		return nil, nil
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, nil
	}

	var findings []Finding
	var warnings []EntropyWarning
	scanner := bufio.NewScanner(f)
	// Allow long lines (minified JS, generated configs) without
	// truncation; the default 64 KiB token cap silently drops the
	// tail of a long line, which would hide a secret near EOL.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		if b.lineAllowlisted(line) {
			continue
		}

		patternHit := false
		for _, rule := range b.patterns {
			if rule.re.MatchString(line) {
				findings = append(findings, Finding{
					ID:           fmt.Sprintf("finding_%03d", nextID),
					Type:         rule.kind,
					Pattern:      rule.name,
					File:         rel,
					Line:         lineNo,
					Confidence:   ConfidenceHigh,
					EntropyOnly:  false,
					BlocksExport: true,
				})
				nextID++
				patternHit = true
			}
		}
		for _, rule := range b.customPatterns {
			if rule.re.MatchString(line) {
				findings = append(findings, Finding{
					ID:           fmt.Sprintf("finding_%03d", nextID),
					Type:         rule.kind,
					Pattern:      rule.name,
					File:         rel,
					Line:         lineNo,
					Confidence:   ConfidenceHigh,
					EntropyOnly:  false,
					BlocksExport: true,
				})
				nextID++
				patternHit = true
			}
		}

		if patternHit || b.entropy == nil {
			continue
		}
		warnings = append(warnings, b.entropy.analyzeLine(rel, lineNo, line)...)
	}

	return findings, warnings
}

// lineAllowlisted reports whether line is excused from matching. A
// line is allowlisted when it carries the inline comment marker or
// when any user-supplied allowlist regex matches the line. Both
// channels live behind one helper so the matcher loop calls it once.
func (b *BuiltIn) lineAllowlisted(line string) bool {
	if strings.Contains(line, allowlistComment) {
		return true
	}
	for _, re := range b.allowlist {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// isBinary reports whether b looks like a binary blob. A NUL byte in
// the inspected prefix is the signal; this is the same heuristic git
// uses for "Binary files differ" output.
func isBinary(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

// builtinPatterns returns the fixed set of high-confidence secret
// patterns the v0.1 scanner ships with. Adding a pattern here means
// committing to it blocking export by default; entries should match a
// documented provider format or a key shape strong enough that a
// random hit is unlikely to be a false positive.
//
// Pattern classes mirror the plan 06 enumeration:
//
//	1. Provider API keys: OpenAI, Anthropic, GitHub, npm, PyPI, AWS,
//	   Google Cloud, Azure, Slack, Stripe.
//	2. Private key headers: RSA, EC, OPENSSH (and the generic
//	   "BEGIN PRIVATE KEY" form).
//	3. .env-style assignments where the key name implies a secret
//	   (*_SECRET=, *_TOKEN=, *_KEY=, PASSWORD=) with a non-empty
//	   value.
func builtinPatterns() []patternRule {
	rules := []patternRule{
		// --- provider API keys -----------------------------------------
		{
			re:   regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}`),
			kind: "api_key",
			name: "Anthropic sk-ant- prefix",
		},
		{
			// OpenAI keys are sk-... but the Anthropic rule above is
			// matched first; this rule is intentionally restricted so a
			// generic "sk-foo" string in a stack trace does not trip it.
			re:   regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9]{20,}`),
			kind: "api_key",
			name: "OpenAI sk- prefix",
		},
		{
			re:   regexp.MustCompile(`\bghp_[A-Za-z0-9]{30,}`),
			kind: "api_key",
			name: "GitHub personal access token (ghp_)",
		},
		{
			re:   regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
			kind: "api_key",
			name: "GitHub fine-grained PAT (github_pat_)",
		},
		{
			re:   regexp.MustCompile(`\bgho_[A-Za-z0-9]{30,}`),
			kind: "api_key",
			name: "GitHub OAuth token (gho_)",
		},
		{
			re:   regexp.MustCompile(`\bghs_[A-Za-z0-9]{30,}`),
			kind: "api_key",
			name: "GitHub server token (ghs_)",
		},
		{
			re:   regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}`),
			kind: "api_key",
			name: "npm token (npm_)",
		},
		{
			re:   regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}`),
			kind: "api_key",
			name: "PyPI token (pypi-)",
		},
		{
			re:   regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			kind: "api_key",
			name: "AWS access key ID (AKIA)",
		},
		{
			re:   regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`),
			kind: "api_key",
			name: "AWS temporary access key ID (ASIA)",
		},
		{
			re:   regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
			kind: "api_key",
			name: "Google Cloud API key (AIza)",
		},
		{
			// Azure storage account keys are 88-char base64 strings;
			// we anchor on the conventional account_key= prefix to
			// avoid false positives on generic base64 blobs.
			re:   regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+/]{60,}={0,2}`),
			kind: "api_key",
			name: "Azure AccountKey",
		},
		{
			re:   regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9\-]{10,}`),
			kind: "api_key",
			name: "Slack token (xox)",
		},
		{
			re:   regexp.MustCompile(`\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}`),
			kind: "api_key",
			name: "Stripe key",
		},

		// --- private key headers ---------------------------------------
		{
			re:   regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			kind: "private_key",
			name: "BEGIN RSA PRIVATE KEY",
		},
		{
			re:   regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			kind: "private_key",
			name: "BEGIN EC PRIVATE KEY",
		},
		{
			re:   regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			kind: "private_key",
			name: "BEGIN OPENSSH PRIVATE KEY",
		},
		{
			re:   regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
			kind: "private_key",
			name: "BEGIN DSA PRIVATE KEY",
		},
		{
			re:   regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			kind: "private_key",
			name: "BEGIN PGP PRIVATE KEY BLOCK",
		},
		{
			re:   regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
			kind: "private_key",
			name: "BEGIN PRIVATE KEY",
		},

		// --- .env-style assignments ------------------------------------
		//
		// The shape is "<KEY>=<value>" where <KEY> ends in _SECRET,
		// _TOKEN, _KEY, _API_KEY, _PASSWORD, or is exactly PASSWORD.
		// The value must be non-empty and at least 8 characters long
		// so empty assignments (KEY=) and obvious placeholders (KEY=x)
		// do not block export. Surrounding quotes are tolerated.
		{
			re: regexp.MustCompile(
				`(?i)\b[A-Z][A-Z0-9_]*(?:_SECRET|_TOKEN|_KEY|_API_KEY|_PASSWORD)\s*[:=]\s*["']?[^\s"'#]{8,}["']?`,
			),
			kind: "env_assignment",
			name: "Secret-shaped env assignment",
		},
		{
			re: regexp.MustCompile(
				`(?i)\bPASSWORD\s*[:=]\s*["']?[^\s"'#]{8,}["']?`,
			),
			kind: "env_assignment",
			name: "PASSWORD assignment",
		},
	}
	return rules
}
