// Cross-run aggregator that derives the unified leaks.jsonl view from
// every per-subsystem stream the supervisor maintains (Plan §8.1).
//
// The per-subsystem streams (lifecycle.jsonl, policy-decisions.jsonl,
// mcp-calls.jsonl, network-events.jsonl, shell-commands.jsonl,
// filesystem-events.jsonl, transcript.jsonl, plus the secret-scan.json
// finding set) stay the canonical record. AggregateLeaks walks each
// one in append order, translates the records into the unified
// LeakRecord shape (with vector / source_stream / source_line / verb
// columns the audit reviewer can grep on), runs every string through
// the broadened secrets.RedactSecrets pass via LeaksWriter.Write, and
// emits the merged view atomically through LeaksWriter (write tmp,
// fsync, rename).
//
// Dedup discipline (Plan §0 locked decision row 9):
//
//   - The base dedup key is (source_stream, source_line, policy_event_id).
//     Two emitters converging on the same supervisor-side decision (the
//     policy engine writing policy-decisions.jsonl AND a downstream shim
//     mirror) carry the same policy_event_id and collapse to one leak
//     row.
//   - The scanner-sourced dedup extension adds (vector, evidence.pattern,
//     evidence.finding_id). Two findings on the same line of the same
//     source stream stay distinct when the pattern names differ — a
//     line that matches both "Anthropic sk-ant- prefix" and "PASSWORD=
//     assign" produces two leak rows, not one collapsed row that hides
//     the second pattern. Per Plan §8.1: the pattern name in the dedup
//     key is what defeats the collapse.
//
// Vector assignment mirrors the leak-coverage audit's per-vector
// matrix (.audit/leak-coverage.md). Every record that participates in
// leaks.jsonl is stamped with the audit vector its enforcer belongs to
// so an operator running `jq '.vector' leaks.jsonl | sort -u` produces
// the eight vector strings the plan's red-team suite asserts on
// (acceptance criterion §10 step 5).
//
// AggregateLeaks is invoked at supervisor finalize time (Plan §5.5
// teardown step 9) after every per-subsystem writer has been closed,
// so the per-stream files are flushed and the walk sees the complete
// trail. The aggregator itself opens no other writer than LeaksWriter
// and reads each stream exactly once; it is safe to call against a
// directory whose per-stream files are empty or absent (the resulting
// leaks.jsonl is then empty too, but is still atomically replaced so
// the on-disk file is the canonical zero-row view rather than the
// CreateRunDirectory placeholder).

package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/i1rr/ai-env/internal/scanners"
)

// AggregateLeaksOptions bundles the per-run metadata AggregateLeaks
// needs at invocation time. RunID is required (every emitted LeakRecord
// carries RunID for cross-run attribution); Now is optional and falls
// back to time.Now for records that lack their own timestamp.
// RandomReader is optional and is threaded through to LeaksWriter for
// the tmp filename's per-process random suffix; tests inject a
// deterministic reader so the tmp path is predictable.
type AggregateLeaksOptions struct {
	// RunID is the run identifier copied into every emitted
	// LeakRecord. Required: the broadened leaks.jsonl carries
	// run attribution per-record so a future cross-run aggregator
	// (Plan §10) can concatenate without losing the run.
	RunID string

	// Now is the clock LeaksWriter uses to stamp Timestamp on
	// records that lack their own timestamp. Source records
	// already carry RFC3339 timestamps; this fallback exists for
	// completeness and for tests that emit synthetic records
	// without their own timestamp.
	Now func() time.Time

	// RandomReader is the byte source for the tmp filename's
	// random suffix. Nil falls back to crypto/rand.Reader inside
	// LeaksWriter.
	RandomReader io.Reader
}

// AggregateLeaks walks every per-subsystem stream under runDir, builds
// the unified leaks.jsonl view in chronological order with dedup, and
// atomically replaces <runDir>/leaks.jsonl with the merged content via
// LeaksWriter.
//
// Behavior:
//
//   - Each source stream is read in its on-disk order (which mirrors
//     the supervisor's emission order). Records are translated into
//     LeakRecord rows with the appropriate vector, verb, evidence
//     payload, and 1-based source_line column.
//   - The combined slice is sorted by RFC3339 timestamp (lex sort —
//     RFC3339 with a fixed-offset numeric zone is lex-stable so a
//     string compare gives chronological order). Ties keep the
//     original per-source order via a stable sort.
//   - The dedup pass folds rows that share the base key
//     (source_stream, source_line, policy_event_id), with the scanner
//     extension (vector, evidence.pattern, evidence.finding_id) for
//     records sourced from secret-scan.json or whose evidence carries
//     a non-empty Pattern. Earlier rows win — a second emitter on the
//     same key contributes nothing.
//   - The merged, dedup'd, chronologically-ordered slice is written to
//     LeaksWriter, which redacts every non-empty string field via the
//     broadened secrets.RedactSecrets before bytes land on disk.
//   - On any error mid-write LeaksWriter.Abort() is invoked so a
//     partial leaks.jsonl does not stomp the previous file; the
//     previous (or placeholder) leaks.jsonl stays in place.
//
// Returns the count of LeakRecord rows written (after dedup) and any
// error from the read / write pipeline. An empty per-stream set is not
// an error: the function returns (0, nil) and still atomically
// replaces leaks.jsonl with an empty file so the on-disk view is
// uniformly the rendered-from-streams form.
func AggregateLeaks(runDir string, opts AggregateLeaksOptions) (int, error) {
	if runDir == "" {
		return 0, errors.New("run: AggregateLeaks requires runDir")
	}
	if opts.RunID == "" {
		return 0, errors.New("run: AggregateLeaks requires RunID")
	}

	// Read each per-subsystem stream. A missing or empty file is
	// fine — the corresponding builder simply contributes no rows.
	records, err := collectLeakRecords(runDir, opts.RunID)
	if err != nil {
		return 0, err
	}

	// Stable sort by Timestamp so the merged view is chronological
	// across sources. RFC3339 with a numeric zone sorts lex-stable.
	// A stable sort preserves the original per-source order on ties
	// (two events with identical timestamps emitted by the same
	// stream stay in append order).
	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Timestamp < records[j].Timestamp
	})

	// Dedup. The base key is (source_stream, source_line,
	// policy_event_id); the scanner extension adds (vector,
	// evidence.pattern, evidence.finding_id) for records sourced
	// from secret-scan.json or carrying a non-empty Evidence.Pattern.
	records = dedupLeakRecords(records)

	// Stage the atomic write. LeaksWriter handles the tmp filename,
	// the O_EXCL open, the per-record encode + redact, the fsync,
	// and the rename. Abort is called on any error so a partial tmp
	// is not promoted to leaks.jsonl.
	w, err := OpenLeaksWriter(runDir, LeaksWriterOptions(opts))
	if err != nil {
		return 0, fmt.Errorf("run: open leaks writer: %w", err)
	}

	count := 0
	for _, rec := range records {
		if err := w.Write(rec); err != nil {
			// Abort cleans up the tmp; the previous leaks.jsonl
			// (or placeholder) stays in place.
			_ = w.Abort()
			return count, fmt.Errorf("run: write leak record: %w", err)
		}
		count++
	}

	if err := w.Close(); err != nil {
		return count, fmt.Errorf("run: close leaks writer: %w", err)
	}
	return count, nil
}

// collectLeakRecords reads every per-subsystem stream under runDir and
// translates the records into a single unified slice of LeakRecord
// rows. Each source's translator runs even when sibling sources fail
// to read (missing-file is not an error; a malformed line is reported
// as a wrapped error so the caller can decide whether to abort the
// aggregate or continue with a partial trail — we choose to abort so
// the operator notices the corruption).
//
// The per-source translators are intentionally small: each one walks
// its source slice with an index counter (i+1 maps to the 1-based
// source_line column the dedup key joins on) and emits one LeakRecord
// per relevant source record. "Relevant" varies per source: lifecycle
// only contributes verb-event records that participate in a leak (the
// audit vector mapping enumerates them); policy-decisions contributes
// every blocking decision; mcp-calls contributes every gateway
// decision; network-events contributes outbound-blocked records;
// shell-commands contributes every deny / ask / quarantine; etc.
func collectLeakRecords(runDir, runID string) ([]LeakRecord, error) {
	var out []LeakRecord

	lifecycleEvents, err := ReadLifecycleEvents(runDir)
	if err != nil {
		return nil, fmt.Errorf("run: read lifecycle events: %w", err)
	}
	out = append(out, leakRecordsFromLifecycle(runID, lifecycleEvents)...)

	policyEvents, err := ReadPolicyDecisions(runDir)
	if err != nil {
		return nil, fmt.Errorf("run: read policy decisions: %w", err)
	}
	out = append(out, leakRecordsFromPolicyDecisions(runID, policyEvents)...)

	mcpCalls, err := ReadMCPCalls(runDir)
	if err != nil {
		return nil, fmt.Errorf("run: read mcp calls: %w", err)
	}
	out = append(out, leakRecordsFromMCPCalls(runID, mcpCalls)...)

	netEvents, err := ReadNetworkEvents(runDir)
	if err != nil {
		return nil, fmt.Errorf("run: read network events: %w", err)
	}
	out = append(out, leakRecordsFromNetworkEvents(runID, netEvents)...)

	shellLines, err := readShellCommandLines(runDir)
	if err != nil {
		return nil, fmt.Errorf("run: read shell commands: %w", err)
	}
	out = append(out, leakRecordsFromShellCommands(runID, shellLines)...)

	fsEvents, err := ReadFilesystemEvents(runDir)
	if err != nil {
		return nil, fmt.Errorf("run: read filesystem events: %w", err)
	}
	out = append(out, leakRecordsFromFilesystemEvents(runID, fsEvents)...)

	transcript, err := ReadTranscript(runDir)
	if err != nil {
		return nil, fmt.Errorf("run: read transcript: %w", err)
	}
	out = append(out, leakRecordsFromTranscript(runID, transcript)...)

	scanRows, err := readSecretScanRows(runDir, runID)
	if err != nil {
		return nil, fmt.Errorf("run: read secret scan: %w", err)
	}
	out = append(out, scanRows...)

	return out, nil
}

// dedupLeakRecords folds records that share the dedup key. Earlier
// records win — a second emitter on the same key contributes nothing,
// which mirrors the supervisor's "first writer is canonical" stance
// (the policy engine emits before any downstream mirror).
//
// The base key is (source_stream, source_line, policy_event_id). The
// scanner extension adds (vector, evidence.pattern, evidence.finding_id)
// for records whose Source is LeakSourceSecretScan OR whose
// Evidence.Pattern is non-empty (gateway secret_blocked /
// secret_response verbs carry a Pattern on a non-scan source). The
// extension keeps two findings on the same line with different
// patterns distinct.
func dedupLeakRecords(records []LeakRecord) []LeakRecord {
	type key struct {
		source    LeakSource
		line      int
		policyEvt string
		vector    int
		pattern   string
		findingID string
	}
	seen := make(map[key]struct{}, len(records))
	out := make([]LeakRecord, 0, len(records))
	for _, rec := range records {
		k := key{
			source:    rec.Source,
			line:      rec.SourceLine,
			policyEvt: rec.PolicyEventID,
		}
		if rec.Source == LeakSourceSecretScan || rec.Evidence.Pattern != "" {
			k.vector = rec.Vector
			k.pattern = rec.Evidence.Pattern
			k.findingID = rec.Evidence.FindingID
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, rec)
	}
	return out
}

// leakRecordsFromLifecycle builds LeakRecord rows for the lifecycle
// verbs that participate in the unified leaks ledger. The mapping
// mirrors the leak-coverage audit's per-vector matrix:
//
//   - gateway_secret_blocked / gateway_secret_response → vector 4
//     (secret exfiltration), Evidence.Pattern / FindingID from the
//     verb's Metadata.
//   - network_policy_degraded → vector 3 (network egress) so the
//     auditor sees the degraded-policy event in the same merged view
//     as the underlying outbound_blocked records.
//   - mcp_config_neutralized → vector 6 (MCP supply-chain drift).
//   - shim_coverage_degraded → vector 7 (shell escape).
//   - transcript_parser_error → vector 8 (prompt-injection
//     correlation) so a parser failure is visible alongside the
//     transcript-sourced leaks the auditor would otherwise miss.
//   - observer_unavailable / broker_unavailable / proxy_started/_stopped
//     and the control_socket / observer / broker / gateway start-stop
//     verbs are NOT emitted into leaks.jsonl: they are infrastructure
//     events with no per-record leak content. The lifecycle stream
//     stays the canonical source for those.
//
// State-transition records (Verb empty, State non-empty) are skipped
// entirely — the unified leak view is verb-driven.
func leakRecordsFromLifecycle(runID string, events []LifecycleEvent) []LeakRecord {
	if len(events) == 0 {
		return nil
	}
	out := make([]LeakRecord, 0, len(events))
	for i, ev := range events {
		if ev.Verb == "" {
			continue
		}
		vector, ok := lifecycleVerbVector(ev.Verb)
		if !ok {
			continue
		}
		rec := LeakRecord{
			Timestamp:  ev.Timestamp,
			RunID:      runID,
			Source:     LeakSourceLifecycle,
			SourceLine: i + 1,
			Vector:     vector,
			Verb:       string(ev.Verb),
		}
		// Per-verb evidence extraction. The Metadata keys are pinned
		// in lifecycle_verbs.go alongside each verb constant; we
		// mirror those names here.
		if pattern, present := ev.Metadata["pattern"]; present {
			rec.Evidence.Pattern = pattern
		}
		if findingID, present := ev.Metadata["finding_id"]; present {
			rec.Evidence.FindingID = findingID
		}
		if detail, present := ev.Metadata["detail"]; present {
			rec.Evidence.Detail = detail
		}
		if reason, present := ev.Metadata["reason"]; present && rec.Evidence.Detail == "" {
			// Fall back to "reason" as detail when no explicit
			// "detail" field is present so the merged view always
			// surfaces the verb's explanation.
			rec.Evidence.Detail = reason
		}
		// Preserve every other metadata key on Evidence.Extra so a
		// downstream consumer of leaks.jsonl can rebuild the original
		// verb context without joining against lifecycle.jsonl.
		extra := make(map[string]string)
		for k, v := range ev.Metadata {
			switch k {
			case "pattern", "finding_id", "detail", "reason":
				continue
			}
			extra[k] = v
		}
		if len(extra) > 0 {
			rec.Evidence.Extra = extra
		}
		out = append(out, rec)
	}
	return out
}

// lifecycleVerbVector maps a LifecycleVerb to the leak-coverage audit
// vector it participates in. The bool result distinguishes "verb
// participates in leaks.jsonl" (true) from "verb is infrastructure-
// only and stays in lifecycle.jsonl alone" (false).
//
// The mapping is the single source of truth for which lifecycle verbs
// contribute to the unified view. New verbs default to "not in leaks"
// until they are added here.
func lifecycleVerbVector(v LifecycleVerb) (int, bool) {
	switch v {
	case LifecycleVerbGatewaySecretBlocked,
		LifecycleVerbGatewaySecretResponse:
		// Vector 4 — Secret exfiltration via MCP gateway.
		return 4, true
	case LifecycleVerbNetworkPolicyDegraded:
		// Vector 3 — Network egress. A degraded policy is a leak
		// signal because the configured allowlist was narrowed at
		// install time.
		return 3, true
	case LifecycleVerbMCPConfigNeutralized:
		// Vector 6 — MCP supply-chain drift. A workspace-local
		// .mcp.json was renamed; the operator sees the rename in
		// the merged view as a supply-chain anomaly.
		return 6, true
	case LifecycleVerbShimCoverageDegraded:
		// Vector 7 — Shell escape. A program whose shadow set is
		// incomplete is a partial-coverage leak signal.
		return 7, true
	case LifecycleVerbTranscriptParserError:
		// Vector 8 — Prompt-injection correlation. A parser failure
		// means the per-turn correlation is degraded; surfacing it
		// in the merged view lets the auditor know.
		return 8, true
	case LifecycleVerbSecretsPermissionWarning:
		// Vector 4 — Secret exfiltration. A loose-permission
		// secrets file is a leak precondition.
		return 4, true
	case LifecycleVerbHelperRPCAborted:
		// Vector 8 — Prompt-injection correlation. An aborted
		// control-socket RPC is a tampering signal.
		return 8, true
	case LifecycleVerbObserverUnavailable:
		// Vector 3 — Network egress evidence degraded.
		return 3, true
	case LifecycleVerbBrokerUnavailable:
		// Vector 2 — Cross-repo writes. A missing broker means
		// the prepare-stage validation never ran.
		return 2, true
	}
	return 0, false
}

// leakRecordsFromPolicyDecisions builds LeakRecord rows for
// policy-decisions.jsonl. Every blocking / fail / deny / quarantine
// decision contributes one row; allow / warn / ask records are NOT
// emitted (allow is the happy path; warn is informational; ask is an
// operator-prompt that has no leak content).
//
// Vector assignment uses the record's EventType (when present) and
// falls back to the verb's family:
//
//   - EventType == policy.EventShellCommand → vector 7 (shell escape).
//   - EventType == policy.EventEnvironmentCreate → vector 1 (path
//     escape — the env-create verdict is the path-scoped one).
//   - Event == PolicyDecisionExportGate → vector 4 (secret
//     exfiltration is the gate's primary block reason; secret-scan
//     rows contribute their own evidence so the gate row is the
//     summary).
//   - Event == PolicyDecisionBrokerAction → vector 5 (push to main /
//     protected; the broker validates branch + repo).
//
// PolicyEventID is forwarded so the dedup pass folds the engine row
// with any downstream mirror (e.g. a shim-side shell-commands record
// carrying the same id).
func leakRecordsFromPolicyDecisions(runID string, events []PolicyDecisionEvent) []LeakRecord {
	if len(events) == 0 {
		return nil
	}
	out := make([]LeakRecord, 0, len(events))
	for i, ev := range events {
		if !policyDecisionParticipates(ev.Decision) {
			continue
		}
		vector := policyDecisionVector(ev)
		rec := LeakRecord{
			Timestamp:     ev.Timestamp,
			RunID:         runID,
			Source:        LeakSourcePolicyDecisions,
			SourceLine:    i + 1,
			Vector:        vector,
			Verb:          ev.Event,
			PolicyEventID: ev.PolicyEventID,
		}
		rec.Evidence.Detail = ev.Reason
		if rec.Evidence.Detail == "" && len(ev.Reasons) > 0 {
			rec.Evidence.Detail = ev.Reasons[0]
		}
		if ev.Error != "" {
			if rec.Evidence.Detail == "" {
				rec.Evidence.Detail = ev.Error
			} else {
				rec.Evidence.Detail = rec.Evidence.Detail + "; " + ev.Error
			}
		}
		extra := make(map[string]string)
		if ev.Action != "" {
			extra["action"] = ev.Action
		}
		if ev.Branch != "" {
			extra["branch"] = ev.Branch
		}
		if ev.Repo != "" {
			extra["repo"] = ev.Repo
		}
		if ev.Target != "" {
			extra["target"] = ev.Target
		}
		if ev.EventType != "" {
			extra["event_type"] = ev.EventType
		}
		if ev.Decision != "" {
			extra["decision"] = ev.Decision
		}
		if ev.Surface != "" {
			extra["surface"] = ev.Surface
		}
		for k, v := range ev.Metadata {
			if _, taken := extra[k]; taken {
				continue
			}
			extra[k] = v
		}
		if len(extra) > 0 {
			rec.Evidence.Extra = extra
		}
		out = append(out, rec)
	}
	return out
}

// policyDecisionParticipates reports whether a policy decision verdict
// belongs in leaks.jsonl. We keep block / fail / deny / quarantine and
// drop allow / warn / ask: only the blocking verdicts are leak-relevant.
func policyDecisionParticipates(decision string) bool {
	switch decision {
	case PolicyDecisionBlock, PolicyDecisionFail, PolicyDecisionDeny, PolicyDecisionQuarantine:
		return true
	}
	return false
}

// policyDecisionVector picks the leak-coverage audit vector for a
// policy-decision event. The mapping is deliberately conservative: an
// unrecognized event family defaults to vector 0 (no vector) so the
// merged view still surfaces the row but the operator's vector grep
// is not polluted with mis-bucketed entries.
func policyDecisionVector(ev PolicyDecisionEvent) int {
	switch ev.Event {
	case PolicyDecisionExportGate:
		// Vector 4 — the export gate's primary blocker is a secret
		// finding; lower-priority blockers (workflow changes,
		// quarantine) still belong with vector 4 because the gate
		// is the single decision point.
		return 4
	case PolicyDecisionBrokerAction:
		// Vector 5 — the broker validates branch prefix /
		// protected branch / path-gate; vector 2 (cross-repo) and
		// vector 5 (push to main) both surface here but vector 5
		// is the primary one the plan's red-team suite asserts on.
		return 5
	case PolicyDecisionEngineEvaluate:
		switch ev.EventType {
		case "shell_command":
			return 7
		case "environment_create":
			return 1
		case "broker_action":
			return 5
		}
	}
	return 0
}

// leakRecordsFromMCPCalls builds LeakRecord rows for mcp-calls.jsonl.
// Every block / warn record contributes (the gateway uses warn for a
// "permit but log" verdict on schema-drift; both are leak-relevant for
// the audit reviewer). Vector 1 is used for filesystem-path
// rejections; vector 2 for repo-scope rejections; vector 6 for
// schema-drift / source / digest mismatches; vector 4 when the
// gateway's secret detector matched.
func leakRecordsFromMCPCalls(runID string, calls []MCPCallRecord) []LeakRecord {
	if len(calls) == 0 {
		return nil
	}
	out := make([]LeakRecord, 0, len(calls))
	for i, rec := range calls {
		if rec.Decision == MCPCallDecisionAllow {
			continue
		}
		vector := mcpCallVector(rec)
		lr := LeakRecord{
			Timestamp:  rec.Timestamp,
			RunID:      runID,
			Source:     LeakSourceMCPCalls,
			SourceLine: i + 1,
			Vector:     vector,
			Verb:       rec.Stage,
		}
		lr.Evidence.Detail = rec.Reason
		lr.Evidence.Snippet = rec.Snippet
		extra := make(map[string]string)
		if rec.Server != "" {
			extra["server"] = rec.Server
		}
		if rec.Tool != "" {
			extra["tool"] = rec.Tool
		}
		if rec.Path != "" {
			extra["path"] = rec.Path
		}
		if rec.ResolvedPath != "" {
			extra["resolved_path"] = rec.ResolvedPath
		}
		if rec.Repo != "" {
			extra["repo"] = rec.Repo
		}
		if rec.Operation != "" {
			extra["operation"] = rec.Operation
		}
		if rec.TurnID != "" {
			extra["turn_id"] = rec.TurnID
		}
		if rec.ExpectedHash != "" {
			extra["expected_hash"] = rec.ExpectedHash
		}
		if rec.ActualHash != "" {
			extra["actual_hash"] = rec.ActualHash
		}
		if rec.Source != "" {
			extra["source"] = rec.Source
		}
		if rec.Digest != "" {
			extra["digest"] = rec.Digest
		}
		if rec.Args != "" {
			extra["args"] = rec.Args
		}
		if rec.Decision != "" {
			extra["decision"] = rec.Decision
		}
		if len(extra) > 0 {
			lr.Evidence.Extra = extra
		}
		out = append(out, lr)
	}
	return out
}

// mcpCallVector picks the leak-coverage audit vector for an MCP call
// record. The mapping mirrors the audit's per-vector matrix: filesystem
// scope → vector 1; github scope → vector 2; schema / source / digest
// pin mismatches → vector 6.
func mcpCallVector(rec MCPCallRecord) int {
	switch rec.Stage {
	case MCPCallStageLaunch:
		// A launch decision that mentions a hash, source, or digest
		// is supply-chain drift (vector 6); a launch refusal for
		// any other reason still belongs to vector 6 because the
		// gateway's launch path is the supply-chain enforcer.
		return 6
	case MCPCallStageCall:
		// A call-time decision joins on ScopeKinds: filesystem
		// implies vector 1, github implies vector 2. We pick the
		// first applicable scope (the gateway never produces a
		// record with both scope kinds populated for a single
		// decision).
		for _, kind := range rec.ScopeKinds {
			switch kind {
			case "filesystem":
				return 1
			case "github":
				return 2
			}
		}
	}
	return 0
}

// leakRecordsFromNetworkEvents builds LeakRecord rows for
// network-events.jsonl. Only outbound_blocked / policy_apply_failed
// records contribute: policy_apply_attempt / _applied are
// infrastructure events; outbound_allowed is the happy path.
func leakRecordsFromNetworkEvents(runID string, events []NetworkEvent) []LeakRecord {
	if len(events) == 0 {
		return nil
	}
	out := make([]LeakRecord, 0, len(events))
	for i, ev := range events {
		if !networkEventParticipates(ev.Event) {
			continue
		}
		rec := LeakRecord{
			Timestamp:  ev.Timestamp,
			RunID:      runID,
			Source:     LeakSourceNetworkEvents,
			SourceLine: i + 1,
			Vector:     3,
			Verb:       ev.Event,
		}
		if ev.Destination != "" {
			rec.Evidence.Detail = "destination=" + ev.Destination
		} else if ev.Error != "" {
			rec.Evidence.Detail = ev.Error
		}
		extra := make(map[string]string)
		if ev.Destination != "" {
			extra["destination"] = ev.Destination
		}
		if ev.Decision != "" {
			extra["decision"] = ev.Decision
		}
		if ev.Backend != "" {
			extra["backend"] = ev.Backend
		}
		if ev.EnvID != "" {
			extra["env_id"] = ev.EnvID
		}
		if ev.Note != "" {
			extra["note"] = ev.Note
		}
		if ev.Error != "" && rec.Evidence.Detail != ev.Error {
			extra["error"] = ev.Error
		}
		if len(extra) > 0 {
			rec.Evidence.Extra = extra
		}
		out = append(out, rec)
	}
	return out
}

// networkEventParticipates reports whether a network event verb
// belongs in leaks.jsonl. outbound_blocked and policy_apply_failed are
// leak-relevant; outbound_allowed / policy_apply_attempt / _applied
// are infrastructure.
func networkEventParticipates(verb string) bool {
	switch verb {
	case NetworkEventOutboundBlocked, NetworkEventPolicyApplyFailed:
		return true
	}
	return false
}

// shellCommandLine is the lightweight projection of policy.ShellCommandRecord
// the aggregator needs. We decode the JSONL directly here (rather
// than depending on internal/policy and pulling in a circular import)
// because shell-commands.jsonl is a fixed JSON shape and only a small
// subset of the fields drives the leak row.
type shellCommandLine struct {
	Timestamp     string   `json:"timestamp"`
	Program       string   `json:"program"`
	Argv          []string `json:"argv"`
	CmdLine       string   `json:"cmd_line"`
	Phase         string   `json:"phase,omitempty"`
	Decision      string   `json:"decision"`
	PolicyEventID string   `json:"policy_event_id"`
	Reason        string   `json:"reason,omitempty"`
	Forwarded     bool     `json:"forwarded"`
	ExitCode      int      `json:"exit_code,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// readShellCommandLines reads <runDir>/shell-commands.jsonl as a slice
// of shellCommandLine values. A missing or empty file is fine; a
// malformed line surfaces as a wrapped error so the aggregate aborts
// loudly on corruption.
//
// The reader lives in this file (rather than in internal/policy)
// because the run package owns leaks.jsonl and importing
// internal/policy here would create a cycle (policy → run is fine but
// run → policy is not). The JSON shape is the same on-disk
// representation policy.ShellCommandRecord produces.
func readShellCommandLines(runDir string) ([]shellCommandLine, error) {
	path := filepath.Join(runDir, "shell-commands.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("run: read shell-commands.jsonl %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	out := make([]shellCommandLine, 0, 16)
	for i, line := range splitJSONLines(data) {
		if len(line) == 0 {
			continue
		}
		var rec shellCommandLine
		if err := json.Unmarshal(line, &rec); err != nil {
			return out, fmt.Errorf("run: parse shell-commands.jsonl line %d: %w", i+1, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// leakRecordsFromShellCommands builds LeakRecord rows for the shim's
// shell-commands.jsonl. Every deny / ask / quarantine record
// contributes; allow / warn / forwarded-only records do not. The
// PolicyEventID is forwarded so the dedup pass folds the shim row
// with the engine's policy-decisions row that minted the id.
//
// Vector 7 for every shell-commands record: the shim is the shell-
// escape boundary by definition.
func leakRecordsFromShellCommands(runID string, lines []shellCommandLine) []LeakRecord {
	if len(lines) == 0 {
		return nil
	}
	out := make([]LeakRecord, 0, len(lines))
	for i, line := range lines {
		if !shellCommandParticipates(line.Decision) {
			continue
		}
		rec := LeakRecord{
			Timestamp:     line.Timestamp,
			RunID:         runID,
			Source:        LeakSourceShellCommands,
			SourceLine:    i + 1,
			Vector:        7,
			Verb:          line.Decision,
			PolicyEventID: line.PolicyEventID,
		}
		rec.Evidence.Detail = line.Reason
		rec.Evidence.Snippet = line.CmdLine
		extra := make(map[string]string)
		if line.Program != "" {
			extra["program"] = line.Program
		}
		if line.Phase != "" {
			extra["phase"] = line.Phase
		}
		if line.Error != "" {
			extra["error"] = line.Error
		}
		if len(line.Argv) > 0 {
			extra["argv"] = fmt.Sprintf("%v", line.Argv)
		}
		if len(extra) > 0 {
			rec.Evidence.Extra = extra
		}
		out = append(out, rec)
	}
	return out
}

// shellCommandParticipates reports whether a shim decision belongs in
// leaks.jsonl. deny / ask / quarantine are leak-relevant; allow / warn
// are not.
func shellCommandParticipates(decision string) bool {
	switch decision {
	case PolicyDecisionDeny, PolicyDecisionAsk, PolicyDecisionQuarantine, PolicyDecisionBlock, PolicyDecisionFail:
		return true
	}
	return false
}

// leakRecordsFromFilesystemEvents builds LeakRecord rows for
// filesystem-events.jsonl. Every block / warn record contributes. The
// vector is 1 (path escape) for shim / MCP-gateway filesystem scope
// records; the PolicyEventID is forwarded for the dedup pass.
func leakRecordsFromFilesystemEvents(runID string, events []FilesystemEventRecord) []LeakRecord {
	if len(events) == 0 {
		return nil
	}
	out := make([]LeakRecord, 0, len(events))
	for i, ev := range events {
		if ev.Decision == FilesystemEventDecisionAllow {
			continue
		}
		rec := LeakRecord{
			Timestamp:     ev.Timestamp,
			RunID:         runID,
			Source:        LeakSourceFilesystemEvents,
			SourceLine:    i + 1,
			Vector:        1,
			Verb:          ev.Operation,
			PolicyEventID: ev.PolicyEventID,
		}
		rec.Evidence.Detail = ev.Reason
		rec.Evidence.Snippet = ev.Snippet
		extra := make(map[string]string)
		if ev.Source != "" {
			extra["source"] = ev.Source
		}
		if ev.Path != "" {
			extra["path"] = ev.Path
		}
		if ev.ResolvedPath != "" {
			extra["resolved_path"] = ev.ResolvedPath
		}
		if ev.Server != "" {
			extra["server"] = ev.Server
		}
		if ev.Tool != "" {
			extra["tool"] = ev.Tool
		}
		if ev.Program != "" {
			extra["program"] = ev.Program
		}
		if ev.Decision != "" {
			extra["decision"] = ev.Decision
		}
		if ev.TurnID != "" {
			extra["turn_id"] = ev.TurnID
		}
		if len(ev.Argv) > 0 {
			extra["argv"] = fmt.Sprintf("%v", ev.Argv)
		}
		if len(extra) > 0 {
			rec.Evidence.Extra = extra
		}
		out = append(out, rec)
	}
	return out
}

// leakRecordsFromTranscript builds LeakRecord rows for
// transcript.jsonl. Only error-kind frames contribute (a regular
// assistant / user / tool_use frame is not a leak on its own; the
// leak surfaces when the per-CLI parser observed a frame it could
// not parse). Vector 8 (prompt-injection correlation) because the
// transcript is the per-turn evidence stream.
func leakRecordsFromTranscript(runID string, records []TranscriptRecord) []LeakRecord {
	if len(records) == 0 {
		return nil
	}
	out := make([]LeakRecord, 0)
	for i, ev := range records {
		if ev.Kind != "error" {
			continue
		}
		rec := LeakRecord{
			Timestamp:  ev.Timestamp,
			RunID:      runID,
			Source:     LeakSourceTranscript,
			SourceLine: i + 1,
			Vector:     8,
			Verb:       ev.Kind,
		}
		rec.Evidence.Detail = ev.Text
		extra := make(map[string]string)
		if ev.CLI != "" {
			extra["cli"] = string(ev.CLI)
		}
		if ev.TurnID != "" {
			extra["turn_id"] = ev.TurnID
		}
		if ev.Role != "" {
			extra["role"] = ev.Role
		}
		if ev.Tool != "" {
			extra["tool"] = ev.Tool
		}
		if ev.Args != "" {
			extra["args"] = ev.Args
		}
		if ev.Seq > 0 {
			extra["seq"] = fmt.Sprintf("%d", ev.Seq)
		}
		if len(extra) > 0 {
			rec.Evidence.Extra = extra
		}
		out = append(out, rec)
	}
	return out
}

// secretScanFileShape mirrors the on-disk JSON layout of
// secret-scan.json. We re-declare the shape here (rather than
// importing internal/cli.secretScanFile, which is unexported) so
// the run package stays free of an internal/cli dependency.
type secretScanFileShape struct {
	RunID            string                `json:"run_id"`
	Scanner          string                `json:"scanner"`
	Findings         []scanners.Finding    `json:"findings"`
	ScannedAt        string                `json:"scanned_at"`
	ExternalScanners []scanners.ScanResult `json:"external_scanners,omitempty"`
}

// readSecretScanRows reads <runDir>/secret-scan.json and projects
// every high-confidence Finding (and every external-scanner Finding
// that BlocksExport) into a LeakRecord row. Vector 4 (secret
// exfiltration); evidence carries Pattern + FindingID for the
// scanner-extension dedup key.
func readSecretScanRows(runDir, runID string) ([]LeakRecord, error) {
	path := SecretScanPath(runDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("run: read secret-scan.json %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var doc secretScanFileShape
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("run: parse secret-scan.json %s: %w", path, err)
	}

	// Each finding gets a deterministic 1-based source_line index so
	// the dedup key can fold two emitter passes over the same scan
	// file. We do not use the file's literal byte offsets because
	// secret-scan.json is a JSON document, not a JSONL stream.
	timestamp := doc.ScannedAt
	out := make([]LeakRecord, 0, len(doc.Findings))
	for i, f := range doc.Findings {
		out = append(out, secretScanLeakRecord(runID, timestamp, i+1, doc.Scanner, f))
	}
	for _, ext := range doc.ExternalScanners {
		for i, f := range ext.Findings {
			ts := timestamp
			if !ext.ScannedAt.IsZero() {
				ts = ext.ScannedAt.Format(time.RFC3339)
			}
			out = append(out, secretScanLeakRecord(runID, ts, i+1, ext.Scanner, f))
		}
	}
	return out, nil
}

// secretScanLeakRecord builds a single LeakRecord row from a scanners.Finding.
// scannerName identifies the emitter for the audit log; line is the
// 1-based per-emitter index used in the dedup key.
func secretScanLeakRecord(runID, timestamp string, line int, scannerName string, f scanners.Finding) LeakRecord {
	rec := LeakRecord{
		Timestamp:  timestamp,
		RunID:      runID,
		Source:     LeakSourceSecretScan,
		SourceLine: line,
		Vector:     4,
		Verb:       string(f.Confidence),
	}
	rec.Evidence.Pattern = f.Pattern
	rec.Evidence.FindingID = f.ID
	rec.Evidence.Detail = fmt.Sprintf("%s:%d (%s)", f.File, f.Line, f.Type)
	extra := make(map[string]string)
	if scannerName != "" {
		extra["scanner"] = scannerName
	}
	if f.File != "" {
		extra["file"] = f.File
	}
	if f.Line > 0 {
		extra["line"] = fmt.Sprintf("%d", f.Line)
	}
	if f.Type != "" {
		extra["type"] = f.Type
	}
	if f.Confidence != "" {
		extra["confidence"] = string(f.Confidence)
	}
	if f.BlocksExport {
		extra["blocks_export"] = "true"
	}
	if len(extra) > 0 {
		rec.Evidence.Extra = extra
	}
	return rec
}
