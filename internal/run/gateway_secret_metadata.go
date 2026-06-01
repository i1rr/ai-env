// Per-verb Metadata constructors for the MCP gateway secret detector
// (Plan Batch 3.4 — Gateway secret detector). The two verbs
// (`gateway_secret_blocked` for request-direction blocks, and
// `gateway_secret_response` for response-direction redactions) carry
// the same operator-readable schema documented inline on the
// LifecycleVerb constants in lifecycle_verbs.go; collecting the
// constructors here keeps the supervisor's emit-verb call sites from
// having to re-derive the key names every time a verb is emitted.
//
// The helpers stringify the integer match_count field so the metadata
// map stays uniformly `map[string]string`, matching every other
// per-verb metadata helper in this package (e.g.
// MCPConfigNeutralizedMetadata). Operators reading lifecycle.jsonl
// already expect string-only metadata values; the leaks.jsonl
// aggregator treats unknown values verbatim so the stringification is
// load-bearing for downstream readers.

package run

import "strconv"

// GatewaySecretBlockedMetadata returns the Metadata map for a single
// `gateway_secret_blocked` lifecycle verb emission. The plan pins the
// keys: server, operation, pattern, finding_id. All four are required
// per the inline schema on LifecycleVerbGatewaySecretBlocked; an empty
// value is passed through verbatim so an emitter that knows it lacks
// (e.g.) a finding_id is the one that owns the audit-completeness
// decision rather than this helper.
func GatewaySecretBlockedMetadata(server, operation, pattern, findingID string) map[string]string {
	return map[string]string{
		"server":     server,
		"operation":  operation,
		"pattern":    pattern,
		"finding_id": findingID,
	}
}

// GatewaySecretResponseMetadata returns the Metadata map for a single
// `gateway_secret_response` lifecycle verb emission. matchCount is
// stringified so the on-disk JSON encoding keeps the
// `map[string]string` shape every other lifecycle verb uses; a
// downstream consumer that wants the integer back parses it with
// strconv.Atoi.
//
// The plan pins the keys: server, operation, pattern (first match
// wins for naming), match_count, finding_id.
func GatewaySecretResponseMetadata(server, operation, pattern string, matchCount int, findingID string) map[string]string {
	return map[string]string{
		"server":      server,
		"operation":   operation,
		"pattern":     pattern,
		"match_count": strconv.Itoa(matchCount),
		"finding_id":  findingID,
	}
}
