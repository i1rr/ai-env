// entropy.go implements the warn-only entropy analyzer that satisfies
// plan 06 step 3. The analyzer flags high-entropy substrings that did
// not already match a built-in or custom pattern rule and records them
// in ScanResult.EntropyWarnings. Crucially, it never produces a
// Finding: entropy hits are the v0.1 false-positive lightning rod
// (UUIDs, content hashes, lockfile checksums) so they warn but never
// block export.
//
// Scope rules this file enforces:
//
//  1. Warn-only output. The analyzer writes to ScanResult.EntropyWarnings
//     and never touches ScanResult.Findings. The export gate only
//     consults Findings, so entropy hits cannot block by construction.
//  2. Skip lines that already produced a Finding. If the pattern matcher
//     flagged a line as a high-confidence secret, re-flagging the same
//     line with an entropy warning would be noise. The scanFile pass
//     in builtin.go passes the set of matched line numbers in so this
//     pass can skip them.
//  3. Honor the allowlist. The same allowlist channels that suppress
//     pattern findings (inline "ai-env-scan-ignore" comment and
//     Config.Allowlist regexes) also suppress entropy warnings. Users
//     who allowlist a fixture line do not want it warning either.
//  4. Tokenize, do not measure whole lines. Shannon entropy over a
//     whole line is dominated by the natural-language portion and
//     misses short embedded secrets. We extract base64-ish / hex-ish
//     substrings and measure each.

package scanners

import (
	"math"
	"regexp"
)

// defaultEntropyThreshold is the bits-per-character cutoff above which
// a base64-ish substring is reported as a warning. 4.5 bits/char is the
// commonly cited threshold used by gitleaks and detect-secrets for
// base64 content; it sits comfortably above natural language (~3.5)
// and below the theoretical max for 64 symbols (6.0).
const defaultEntropyThreshold = 4.5

// defaultHexEntropyThreshold is the bits-per-character cutoff for
// hex-only substrings. Hex alphabets only have 16 symbols so the
// theoretical max is 4.0 bits/char; 3.0 captures genuinely random
// hex while leaving room for repetitive sequences (e.g. all-zero
// checksums) to fall below the threshold.
const defaultHexEntropyThreshold = 3.0

// minEntropyTokenLen is the shortest substring the analyzer measures.
// Below this the entropy calculation is unstable (a 6-char string can
// trivially hit 2.5+ bits/char with no real randomness) and the false
// positive rate dominates.
const minEntropyTokenLen = 20

// maxEntropyTokenLen caps how long a single token can be before the
// analyzer truncates it. A single 10 KiB minified blob would otherwise
// produce one giant warning that drowns out everything else; capping
// keeps the output bounded.
const maxEntropyTokenLen = 256

// base64TokenRE extracts substrings that look like base64 / URL-safe
// base64 / base64url payloads. The character class deliberately omits
// '=' inside the run so trailing padding is not measured as entropy
// content; it is still captured by the surrounding context when the
// scanner reports the matched substring back to the user.
var base64TokenRE = regexp.MustCompile(`[A-Za-z0-9+/_\-]{20,}`)

// hexTokenRE extracts substrings that look like hex digests. We require
// at least 32 chars so MD5 / SHA-1 / SHA-256 hashes are caught but
// short identifiers like 8-hex-char git short SHAs are not. Hex hashes
// frequently appear in lockfiles and content-addressed stores so the
// downstream policy still treats them as warn-only.
var hexTokenRE = regexp.MustCompile(`\b[A-Fa-f0-9]{32,}\b`)

// entropyAnalyzer holds the per-run configuration the analyzer needs.
// It is constructed inside BuiltIn so the scanner exposes a single
// surface to the CLI; callers do not interact with this type directly.
type entropyAnalyzer struct {
	base64Threshold float64
	hexThreshold    float64
}

// newEntropyAnalyzer returns an analyzer using cfg's thresholds, or the
// defaults when cfg leaves them zero. A zero Config is a fully valid
// analyzer because the plan does not require user configuration in v0.1.
func newEntropyAnalyzer(cfg Config) *entropyAnalyzer {
	a := &entropyAnalyzer{
		base64Threshold: defaultEntropyThreshold,
		hexThreshold:    defaultHexEntropyThreshold,
	}
	if cfg.EntropyThreshold > 0 {
		a.base64Threshold = cfg.EntropyThreshold
	}
	if cfg.HexEntropyThreshold > 0 {
		a.hexThreshold = cfg.HexEntropyThreshold
	}
	return a
}

// analyzeLine inspects line and returns one EntropyWarning per
// high-entropy token it finds. file and lineNo are passed through into
// the warning so the caller does not need to track them. Returning a
// slice (rather than appending into the caller's) keeps the per-line
// loop in scanFile readable.
func (a *entropyAnalyzer) analyzeLine(file string, lineNo int, line string) []EntropyWarning {
	var warnings []EntropyWarning

	for _, match := range base64TokenRE.FindAllString(line, -1) {
		if len(match) < minEntropyTokenLen {
			continue
		}
		token := match
		if len(token) > maxEntropyTokenLen {
			token = token[:maxEntropyTokenLen]
		}
		ent := shannonEntropy(token)
		if ent < a.base64Threshold {
			continue
		}
		warnings = append(warnings, EntropyWarning{
			File:    file,
			Line:    lineNo,
			Entropy: ent,
			Reason:  formatReason("base64-like", len(match), ent),
		})
	}

	for _, match := range hexTokenRE.FindAllString(line, -1) {
		token := match
		if len(token) > maxEntropyTokenLen {
			token = token[:maxEntropyTokenLen]
		}
		ent := shannonEntropy(token)
		if ent < a.hexThreshold {
			continue
		}
		warnings = append(warnings, EntropyWarning{
			File:    file,
			Line:    lineNo,
			Entropy: ent,
			Reason:  formatReason("hex-like", len(match), ent),
		})
	}

	return warnings
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
// The empty string is defined to have entropy 0 so callers can treat
// the return value uniformly without a length guard.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// formatReason renders the human-readable Reason string the analyzer
// stamps on every EntropyWarning. Keeping the format in one place
// avoids drift between the two emission sites in analyzeLine.
func formatReason(kind string, length int, entropy float64) string {
	return kindFmt(kind) + ", " + itoa(length) + " chars, entropy " + ftoa(entropy)
}

// kindFmt, itoa, and ftoa are tiny local helpers so formatReason does
// not depend on fmt: the analyzer runs once per line and the fmt.Sprintf
// allocation overhead showed up in early profiling on large diffs.
// They are not exported and only support the narrow shapes the
// analyzer needs.
func kindFmt(s string) string { return s }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func ftoa(f float64) string {
	// Two decimal places is enough to distinguish 4.50 from 4.73 in
	// the warning text; more precision is noise to the human reader.
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "0.00"
	}
	scaled := int(f*100 + 0.5)
	whole := scaled / 100
	frac := scaled % 100
	return itoa(whole) + "." + twoDigit(frac)
}

func twoDigit(n int) string {
	if n < 0 {
		n = -n
	}
	if n > 99 {
		n = 99
	}
	return string([]byte{byte('0' + n/10), byte('0' + n%10)})
}
