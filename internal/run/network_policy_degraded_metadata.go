// Per-verb Metadata constructor for `network_policy_degraded`
// (Plan §10 locked decision row 10, Batch 5.6). The plan documents
// `network_policy_degraded` as the audit signal the supervisor (or a
// backend adapter via `BackendEventSink`) emits when the configured
// network policy could not be enforced in full and the run proceeds
// with reduced guarantees. The two canonical emission paths the
// supervisor itself drives are:
//
//   - The EgressObserver fails to attach in auto mode (the supervisor
//     still emits `observer_unavailable`; `network_policy_degraded`
//     is the parallel "the network controls themselves are now
//     degraded" signal so an operator does not have to cross-reference
//     two verbs to know the policy is no longer fully enforced).
//   - The EgressRules lifecycle returns `rules.ErrUnsupportedOS` (the
//     supervisor's graceful-skip path on a non-Linux/non-Darwin host).
//
// Centralizing the constructor here keeps the supervisor's emit-verb
// call sites from re-deriving the canonical key names from the
// LifecycleVerbNetworkPolicyDegraded comment in lifecycle_verbs.go.
// The keys match the schema documented there:
//
//	reason  (required) — short token: e.g. "observer_unavailable",
//	                     "rules_unsupported_os", "iptables_rejected"
//	missing (optional) — comma-separated short tokens listing what
//	                     was dropped (e.g. "egress_rules,observer")
//	detail  (optional) — human-readable detail for the audit reader
//
// An empty `missing` or `detail` is omitted from the returned map so
// the on-disk lifecycle.jsonl record carries only the keys the caller
// populated (matching the rest of the per-verb metadata helpers,
// which expect callers to own the audit-completeness decision rather
// than emitting empty-string placeholders).
package run

// NetworkPolicyDegradedMetadata returns the metadata map for a single
// `network_policy_degraded` lifecycle verb emission. `reason` is the
// required short token; `missing` and `detail` are optional and are
// omitted from the returned map when empty.
func NetworkPolicyDegradedMetadata(reason, missing, detail string) map[string]string {
	m := map[string]string{
		"reason": reason,
	}
	if missing != "" {
		m["missing"] = missing
	}
	if detail != "" {
		m["detail"] = detail
	}
	return m
}
