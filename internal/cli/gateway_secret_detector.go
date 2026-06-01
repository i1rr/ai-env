// Gateway-side per-direction secret detector (Plan Batch 3.4).
//
// The plan splits MCP secret detection into two streaming, JSON-aware
// surfaces:
//
//   - Request direction (THIS FILE). The gateway sits on the
//     supervisor side of every JSON-RPC call the agent makes. Before
//     forwarding a call to the in-memory mcp.Gateway, the supervisor
//     scans the raw body for known provider-secret patterns. A match
//     short-circuits the call: the supervisor returns block, emits a
//     `gateway_secret_blocked` lifecycle verb, and logs an
//     MCPCallRecord with every payload-derived field rewritten to a
//     redaction sentinel so the audit trail captures the structural
//     shape of the attempted exfiltration without the leaked value.
//
//   - Response direction. Handled by the shim helper's JSON-aware
//     walker (cmd/ai-env/shim_helper_mcp.go). The walker decodes each
//     upstream JSON-RPC frame, replaces matched string values with
//     the sentinel, and re-marshals so framing stays intact. The
//     plan deliberately keeps that surface in the helper (not the
//     gateway) because the helper sits inline on the agent-bound
//     stdio stream and is the only spot the gateway-internal decoder
//     could observe the upstream bytes before they cross into the
//     agent's address space.
//
// Both surfaces use the same scanners.BuiltInSecretPatterns() set so
// the "what counts as a secret" question has a single source of
// truth across the run.
//
// This file implements ONLY the request-direction detector. The
// response-direction walker lives in the shim helper because the
// supervisor-side gateway has no upstream-bytes surface (the shim
// owns the stdio pipe). The gateway-side authorizer (the existing
// GatewayMCPAuthorizer in build_gateway_runtime.go) wires this
// detector in front of every Authorize call so the supervisor never
// forwards an exfiltrating body to the in-memory gateway.

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/rivan1986/ai-env/internal/scanners"
)

// gatewaySecretSentinelf is the format string the request-direction
// detector uses when redacting a matched value. The pattern name and
// the original length are preserved so an auditor reading the on-disk
// CallRecord can reason about what was redacted without seeing the
// value. The "REDACTED" prefix matches the shim helper's response-
// direction sentinel (mcpRedactionSentinelf in shim_helper_mcp.go)
// AND the secrets.RedactSecrets prefix so downstream consumers that
// already recognize the prefix as "scrubbed by ai-env" see the same
// word regardless of which surface produced the redaction.
const gatewaySecretSentinelf = "[REDACTED pattern=%s len=%d]"

// gatewaySecretFindingIDBytes is the byte length of the per-blocked-
// request finding id the detector mints. 8 bytes hex-encoded = 16
// printable characters, which is long enough to make collisions
// vanishingly unlikely across a single run's lifecycle.jsonl while
// keeping the audit-log line readable.
const gatewaySecretFindingIDBytes = 8

// gatewaySecretDetector is the request-direction per-direction
// detector. One detector is constructed per gateway authorizer; the
// pattern set is shared (the underlying *regexp.Regexp values inside
// scanners.SecretPattern are concurrent-safe) so a single detector
// can serve every Authorize goroutine in the run.
//
// The detector is stateless beyond its pattern set: matching is a
// pure function over the input bytes. This is the right shape for
// the request direction because each Authorize call carries the
// whole body as a single byte slice (the control socket has already
// reassembled the JSON-RPC frame before invoking the supervisor's
// MCPAuthorizer). The response direction needs the rolling-buffer
// streaming scanner in the shim helper because the helper sees
// raw stdio chunks; the request side doesn't.
type gatewaySecretDetector struct {
	// patterns is the immutable pattern set shared with every other
	// surface that consumes scanners.BuiltInSecretPatterns()
	// (response-direction shim helper, secrets.RedactSecrets, the
	// workspace built-in scanner). Stored by value because the
	// underlying *regexp.Regexp pointers are safe to share.
	patterns []scanners.SecretPattern

	// randRead is the entropy source the finding-id minter uses.
	// Injected so tests can pin a deterministic id stream; production
	// callers leave it nil and the constructor wires crypto/rand.
	randRead func([]byte) (int, error)
}

// newGatewaySecretDetector constructs a detector wired against the
// supplied pattern set. Production callers pass
// scanners.BuiltInSecretPatterns(); tests can pin a narrower set so
// the assertion is targeted.
//
// The constructor is private (the detector is an implementation
// detail of the cli-package gateway runtime) but the type is exported
// indirectly via GatewayMCPAuthorizerOptions so a future external
// caller can plug a custom set without touching this file.
func newGatewaySecretDetector(patterns []scanners.SecretPattern) *gatewaySecretDetector {
	return &gatewaySecretDetector{
		patterns: patterns,
		randRead: nil,
	}
}

// gatewaySecretMatch is the per-body verdict the detector returns.
// Matched reports whether any pattern fired; when true, PatternName
// carries the first-match pattern's human-readable name (the rule's
// scanners.SecretPattern.Name) so the supervisor can stamp the
// lifecycle verb's `pattern` metadata key without re-running the
// match. FindingID is the opaque per-blocked-request identifier the
// detector minted; leaks.jsonl uses it as part of its dedup key so a
// blocked request's lifecycle verb and the audit-log CallRecord can
// be joined.
type gatewaySecretMatch struct {
	// Matched is true when the detector found at least one secret
	// pattern in the input. False means the body was clean and the
	// caller proceeds with normal Authorize processing.
	Matched bool

	// PatternName is the human-readable label of the first matched
	// pattern (e.g. "Anthropic sk-ant- prefix"). Empty when Matched
	// is false. Used by the supervisor for the
	// `gateway_secret_blocked` lifecycle verb's `pattern` metadata
	// key AND for the on-disk CallRecord's Reason field.
	PatternName string

	// FindingID is the opaque per-blocked-request identifier the
	// detector minted at match time. Empty when Matched is false.
	// The leaks.jsonl aggregator uses (Vector, Pattern, FindingID)
	// as the scanner-sourced dedup key per Plan Bucket 9.
	FindingID string
}

// Scan runs the detector against the supplied body bytes. The body
// is typically the JSON-RPC frame the agent submitted; the detector
// does NOT decode it (no JSON parsing at the request-side) because
// the plan's "match → block" rule fires regardless of where in the
// body the secret lives — the value could be inside a string literal
// inside an args object, inside a nested params blob, or even inside
// a non-JSON wrapper field. Treating the body as opaque bytes catches
// every embedding.
//
// First-match-wins on pattern ordering matches scanners.SecretPattern
// ordering, which mirrors the plan's "Provider API keys" enumeration
// order. The choice of "first match" rather than "all matches" is
// intentional: the supervisor's response is the same regardless of
// how many patterns fired (block + lifecycle verb), so iterating
// past the first match would only cost CPU.
func (d *gatewaySecretDetector) Scan(body []byte) gatewaySecretMatch {
	if len(body) == 0 || len(d.patterns) == 0 {
		return gatewaySecretMatch{}
	}
	for _, p := range d.patterns {
		if p.Pattern.Match(body) {
			return gatewaySecretMatch{
				Matched:     true,
				PatternName: p.Name,
				FindingID:   d.mintFindingID(),
			}
		}
	}
	return gatewaySecretMatch{}
}

// RedactString applies the pattern set to s and returns a string with
// every matched span replaced by the redaction sentinel. The output
// is byte-stable when s contains no matches; when at least one
// pattern fires every matched substring is replaced (not just the
// first) so a payload field that carries two secrets has both
// scrubbed in a single pass.
//
// Used by the supervisor to redact every payload-derived CallRecord
// field (Reason, Path, Operation, Repo, ResolvedPath, Snippet, Args)
// before logging the audit record. The enumeration is closed: the
// plan calls out the fields explicitly so a future addition to
// CallRecord that the supervisor cannot anticipate is the right
// place to extend this redaction list.
func (d *gatewaySecretDetector) RedactString(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, p := range d.patterns {
		name := p.Name
		out = p.Pattern.ReplaceAllStringFunc(out, func(m string) string {
			return formatGatewaySecretSentinel(name, len(m))
		})
	}
	return out
}

// RedactBytes is the []byte analog of RedactString. Used when the
// caller is rewriting a byte buffer (e.g. the request body itself
// for downstream debug logging) rather than a single string field.
// The behavior is byte-identical to RedactString: a sentinel
// replacement preserves the structural shape of the surrounding
// bytes so a downstream consumer that parses the result still sees
// valid JSON (or whatever the surrounding format was) as long as
// the matched span did not straddle a delimiter.
func (d *gatewaySecretDetector) RedactBytes(buf []byte) []byte {
	if len(buf) == 0 {
		return buf
	}
	out := buf
	for _, p := range d.patterns {
		name := p.Name
		out = p.Pattern.ReplaceAllFunc(out, func(m []byte) []byte {
			return []byte(formatGatewaySecretSentinel(name, len(m)))
		})
	}
	return out
}

// mintFindingID returns a fresh opaque finding identifier for a
// blocked request. Defaults to crypto/rand-backed hex so production
// runs land cryptographically-unguessable ids; tests pin
// detector.randRead to a deterministic stream for stable assertions.
//
// The output is the lower-case hex encoding of gatewaySecretFindingIDBytes
// random bytes. Returning a fallback string on RNG failure (rather
// than panicking) keeps the gateway available under degraded RNG: a
// missing finding_id is a lower-severity audit gap than a crashed
// gateway.
func (d *gatewaySecretDetector) mintFindingID() string {
	buf := make([]byte, gatewaySecretFindingIDBytes)
	reader := d.randRead
	if reader == nil {
		reader = rand.Read
	}
	if _, err := reader(buf); err != nil {
		return "rng_unavailable"
	}
	return hex.EncodeToString(buf)
}

// formatGatewaySecretSentinel composes the redaction sentinel
// string. Factored out so RedactString, RedactBytes, and any future
// per-field caller share the exact same byte sequence.
func formatGatewaySecretSentinel(patternName string, length int) string {
	// strings.Builder so the formatted result avoids fmt.Sprintf's
	// reflection cost on the hot redaction path; a JSON-RPC body can
	// carry hundreds of values, and the sentinel is short and
	// constant-shape.
	var b strings.Builder
	b.Grow(len(gatewaySecretSentinelf) + len(patternName) + 8)
	b.WriteString("[REDACTED pattern=")
	b.WriteString(patternName)
	b.WriteString(" len=")
	b.WriteString(itoaUnsigned(length))
	b.WriteString("]")
	return b.String()
}

// itoaUnsigned is a tiny non-negative integer formatter. Used by
// formatGatewaySecretSentinel rather than strconv.Itoa so the
// allocation footprint stays the strings.Builder + result rather
// than the intermediate strconv slice.
func itoaUnsigned(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
