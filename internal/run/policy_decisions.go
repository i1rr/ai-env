package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// policyDecisionsFileName is the basename of the per-run policy-decisions
// event log. It lives at the root of the run directory next to
// lifecycle.jsonl and network-events.jsonl so a reviewer reading a run on
// disk sees the lifecycle trail, the network trail, and the policy
// decision trail side by side. The constant mirrors lifecycleFileName and
// networkEventsFileName; keeping it here rather than redeclaring it in
// run.go means the policy-decisions writer is the single owner of the
// filename even though run.go materialized the placeholder.
const policyDecisionsFileName = "policy-decisions.jsonl"

// Policy-decision event verbs recorded in policy-decisions.jsonl. Pinned
// as constants so every emitter (ExportGate, the broker lifecycle, future
// callers) compares against the canonical strings rather than retyping
// the literals. Plan 07 step 12 acceptance criterion 8 only requires that
// "blocked or failed broker actions appear in policy-decisions.jsonl";
// the verbs below cover both the gate-side decisions (so an operator
// reading the file sees why the broker was or was not invoked) and the
// broker-side action outcomes (per the lifecycle diagram).
//
// New events extend this set; existing values keep their meaning so a
// downstream consumer (status / report) that switches on these strings
// does not break across releases.
const (
	// PolicyDecisionExportGate is the verb recorded when the
	// ExportGate evaluator returns a verdict for a brokered PR (or
	// patch) export. The Decision field carries "allow" or "block",
	// matching export.Decision; the Reasons field carries the
	// human-readable per-reason messages so the on-disk record is
	// self-contained even when the workspace gate package is not
	// available at read time.
	PolicyDecisionExportGate = "export_gate"

	// PolicyDecisionBrokerAction is the verb recorded when the broker
	// lifecycle finishes a discrete stage (Prepare / AcquireToken /
	// PushBranch / ScanMetadata / CreateDraftPR / RevokeToken). The
	// Action field names the stage and the Decision field carries
	// "allow" (the stage proceeded) or "block" / "fail" (the stage
	// refused or errored). A failed stage carries the error string on
	// the Error field; a blocked stage (e.g. a metadata scan that
	// surfaced a high-confidence secret) carries the reason on the
	// Reasons field.
	PolicyDecisionBrokerAction = "broker_action"

	// PolicyDecisionEngineEvaluate is the verb recorded for every
	// PolicyDecision produced by the Plan 08 PolicyEngine.Evaluate
	// call. The Action / Target / EventType / Reason / Metadata fields
	// are the engine's own Event/PolicyDecision projection; Decision
	// carries the engine verdict ("allow" / "ask" / "deny" /
	// "quarantine" / "warn"); PolicyEventID carries the engine's
	// unique "evt_<ts>_<hex>" identifier so `ai-env policy explain`
	// can look the record up by ID.
	//
	// The engine verb is distinct from PolicyDecisionExportGate and
	// PolicyDecisionBrokerAction because the engine is the global
	// decision point; the gate and broker verbs predate the engine
	// (plan 07) and remain in use so an operator reading an old run
	// directory still sees the surface that emitted each record. Once
	// the engine is wired into the export and broker surfaces (plan 08
	// step 7), every gate / broker decision is also mirrored as an
	// engine_evaluate record so the on-disk trail is uniform.
	PolicyDecisionEngineEvaluate = "engine_evaluate"
)

// Policy-decision decision values. Mirrors export.Decision plus a "fail"
// value the broker uses when a stage errors at the infrastructure level
// (e.g. AcquireToken failed because the issuer was unreachable). Pinned
// as constants for the same reason as the event verbs.
const (
	// PolicyDecisionAllow indicates the gate or the broker stage
	// proceeded.
	PolicyDecisionAllow = "allow"

	// PolicyDecisionBlock indicates the gate refused the export, or
	// the broker stage refused because policy said no (e.g. branch
	// prefix mismatch, metadata scan finding).
	PolicyDecisionBlock = "block"

	// PolicyDecisionFail indicates the stage errored at the
	// infrastructure level (network failure, missing credential, API
	// returned 5xx). Distinguished from "block" so an operator can
	// tell a policy refusal from a transient outage.
	PolicyDecisionFail = "fail"

	// PolicyDecisionDeny mirrors the policy engine's DecisionDeny
	// verdict on engine_evaluate records. Distinct from
	// PolicyDecisionBlock (which is the export gate / broker stage
	// verb) so a consumer can tell a generic engine refusal from a
	// gate-side refusal in a single grep. The two values agree
	// semantically (action is refused); the on-disk distinction is
	// purely a provenance marker.
	PolicyDecisionDeny = "deny"

	// PolicyDecisionAsk mirrors the policy engine's DecisionAsk
	// verdict: the action requires user or reviewer approval before
	// proceeding. v0.1 surfaces this verdict to the CLI which prompts
	// the operator; an autonomous run treats it as a soft block. Only
	// recorded on engine_evaluate events.
	PolicyDecisionAsk = "ask"

	// PolicyDecisionQuarantine mirrors the policy engine's
	// DecisionQuarantine verdict: the run must stop and preserve its
	// artifacts for inspection. Only recorded on engine_evaluate
	// events.
	PolicyDecisionQuarantine = "quarantine"

	// PolicyDecisionWarn mirrors the policy engine's DecisionWarn
	// verdict: the action proceeds but is highlighted in the run
	// report. Recorded on engine_evaluate events; the broker also
	// uses the warn-class internally but surfaces it via the
	// PolicyDecisionFail string (so the broker's transient-error
	// distinction stays visible).
	PolicyDecisionWarn = "warn"
)

// Broker action names recorded on PolicyDecisionBrokerAction events.
// Pinned as constants so the broker, the CLI, and any future consumer
// agree on the exact spelling.
const (
	// PolicyActionBrokerPrepare names the Prepare stage outcome.
	PolicyActionBrokerPrepare = "broker_prepare"

	// PolicyActionBrokerAcquireToken names the AcquireToken stage
	// outcome.
	PolicyActionBrokerAcquireToken = "broker_acquire_token"

	// PolicyActionBrokerPushBranch names the PushBranch stage
	// outcome.
	PolicyActionBrokerPushBranch = "broker_push_branch"

	// PolicyActionBrokerScanMetadata names the ScanMetadata stage
	// outcome.
	PolicyActionBrokerScanMetadata = "broker_scan_metadata"

	// PolicyActionBrokerCreatePR names the CreateDraftPR stage
	// outcome.
	PolicyActionBrokerCreatePR = "broker_create_pr"

	// PolicyActionBrokerRevokeToken names the RevokeToken stage
	// outcome. Recorded as PolicyDecisionAllow on success or
	// PolicyDecisionFail on revoke error (a revocation failure is a
	// warning, not a policy block, so it never carries "block").
	PolicyActionBrokerRevokeToken = "broker_revoke_token"
)

// PolicyDecisionEvent is one record written to policy-decisions.jsonl.
// The shape is the supervisor-facing canonical event the writer marshals
// to JSONL. Fields are encoded in declaration order so the on-disk file
// is byte-stable across runs that emit the same event sequence.
//
// The struct intentionally mixes two record families behind one shape so
// consumers parse one JSON envelope and switch on Event to pick the
// interesting fields:
//
//   - Gate decisions (Event == PolicyDecisionExportGate). Carry Decision
//     ("allow" / "block") and the per-reason messages on Reasons.
//   - Broker action outcomes (Event == PolicyDecisionBrokerAction).
//     Carry Action (one of the PolicyActionBroker* constants), Decision
//     ("allow" / "block" / "fail"), and optionally Reasons / Error /
//     Branch / Repo / TokenKind for richer context.
//
// All token-bearing fields are passed through the broker's redactor
// (githubbroker.RedactTokens) by the caller before the event is written;
// the writer does not redact on its own so the responsibility lives at
// the emission site where the token shape is known.
type PolicyDecisionEvent struct {
	// RunID is the run this event belongs to. Duplicated into every
	// record so a future aggregator can concatenate
	// policy-decisions.jsonl files from many runs without losing
	// attribution. Mirrors LifecycleEvent.RunID and
	// NetworkEvent.RunID.
	RunID string `json:"run_id"`

	// Timestamp is the moment the event was emitted, formatted as
	// RFC3339 with a numeric timezone offset. The writer fills this in
	// at write time using its clock; callers do not set it themselves.
	Timestamp string `json:"timestamp"`

	// Event is the verb identifying what happened. One of the
	// PolicyDecision* constants above; consumers switch on this field
	// to pick the interesting payload fields. Required.
	Event string `json:"event"`

	// Surface identifies which export surface produced the event
	// ("patch" / "pr"). Optional on broker-action events that are
	// always PR-scoped; populated on gate events so a reader can tell
	// a patch verdict from a PR verdict in a single grep.
	Surface string `json:"surface,omitempty"`

	// EnvName is the ai-env environment the decision was made for
	// (e.g. "fix-tests"). Populated on every event so an operator can
	// filter the file by env without joining against run.json.
	EnvName string `json:"env_name,omitempty"`

	// Decision is the verdict for this event ("allow" / "block" /
	// "fail"). Required on every event. For broker-action events the
	// value distinguishes a policy refusal ("block") from an
	// infrastructure error ("fail").
	Decision string `json:"decision"`

	// Action names the broker lifecycle stage the event records. One
	// of the PolicyActionBroker* constants. Required on broker-action
	// events; empty on gate events.
	Action string `json:"action,omitempty"`

	// Reasons is the per-blocker explanation list. On gate events
	// this is the ExportGate Reason.Message slice (block reasons
	// only; warnings are surfaced via the CLI but not written here so
	// the file stays focused on decisions). On broker-action events
	// this carries the metadata-scan finding summaries (one per
	// blocking finding).
	Reasons []string `json:"reasons,omitempty"`

	// Error is the error string recorded when Decision == "fail". The
	// caller is responsible for redacting any token-like substrings
	// before constructing the event; the writer does not re-redact.
	Error string `json:"error,omitempty"`

	// Branch is the workspace branch the broker action targeted
	// (e.g. "ai-env/fix-tests"). Populated on broker-action events;
	// omitted on gate events.
	Branch string `json:"branch,omitempty"`

	// Repo is the "owner/name" coordinate of the repository the
	// broker action targeted. Populated on broker-action events;
	// omitted on gate events.
	Repo string `json:"repo,omitempty"`

	// TokenKind is the broker's TokenKind string ("github_app" /
	// "pat") when the event records a token-related stage. Optional;
	// omitted on stages that did not involve a credential or on
	// events that pre-date AcquireToken (e.g. Prepare).
	TokenKind string `json:"token_kind,omitempty"`

	// PRNumber is the GitHub PR number returned on a successful
	// CreateDraftPR. Zero / omitted on every other event. Optional
	// even on a successful CreateDraftPR if the API did not return a
	// number (dry-run paths).
	PRNumber int `json:"pr_number,omitempty"`

	// PRURL is the GitHub PR URL returned on a successful
	// CreateDraftPR. Empty / omitted on every other event. The URL is
	// not a credential and is not redacted.
	PRURL string `json:"pr_url,omitempty"`

	// PolicyEventID is the policy engine's unique
	// "evt_<timestamp>_<hex>" identifier for an engine_evaluate event.
	// Plan 08's `ai-env policy explain --event <id>` looks decisions
	// up by this field, so the writer never overwrites a non-empty
	// value supplied by the caller (in contrast to RunID and
	// Timestamp, which the writer pins for provenance). Empty /
	// omitted on gate and broker-action events.
	PolicyEventID string `json:"policy_event_id,omitempty"`

	// EventType is the policy engine's Event family identifier on an
	// engine_evaluate record (one of policy.EventEnvironmentCreate,
	// EventExport, EventBrokerAction, EventShellCommand). Empty /
	// omitted on gate and broker-action events because their Event
	// verb already encodes the family.
	EventType string `json:"event_type,omitempty"`

	// Target identifies the resource the policy engine evaluated
	// against (env name for environment_create, branch for export,
	// "owner/repo:branch" for broker_action, command line for
	// shell_command). Empty / omitted on gate and broker-action
	// records (those carry the same context on Branch / Repo). The
	// target is informational only; the engine's decision logic does
	// not switch on it after evaluation.
	Target string `json:"target,omitempty"`

	// Reason is the policy engine's human-readable explanation for an
	// engine_evaluate verdict. It is the string `ai-env policy
	// explain` prints verbatim. Distinct from Reasons (which is a
	// per-blocker list on gate events) so a JSON consumer can pick
	// the engine's single-line reason without joining with Reasons.
	// Empty / omitted on gate and broker-action records.
	Reason string `json:"reason,omitempty"`

	// Metadata is the policy engine's per-decision context map
	// (workspace_strategy, gate_decision, outcome, etc.). Surfaced on
	// the on-disk record so an auditor reading
	// policy-decisions.jsonl sees the same context the engine
	// evaluated against. Empty / omitted on gate and broker-action
	// records, and on engine_evaluate records that carried no
	// metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PolicyDecisionsWriter appends PolicyDecisionEvent records to
// policy-decisions.jsonl.
//
// The plan calls for append-only newline-delimited JSON, one record per
// policy decision, flushed after every write so a crash does not lose
// the decision trail. The writer is safe for concurrent use: the CLI's
// gate evaluation and the broker lifecycle calls may run from different
// goroutines (today they are sequential, but a future async destroy hook
// will need this), and the resulting on-disk file must contain one
// well-formed JSON object per line with no interleaving.
//
// Construction goes through OpenPolicyDecisionsWriter so the file
// handle, the per-run metadata (run ID), and the clock are wired in
// once. The handle stays open for the lifetime of the run; Close is the
// only orderly shutdown path.
//
// The shape mirrors LifecycleWriter / NetworkEventsWriter on purpose: a
// future refactor that unifies the per-run JSONL writers (lifecycle,
// network, shell, fs, policy decisions) can replace all three with one
// generic implementation without touching call sites.
type PolicyDecisionsWriter struct {
	// mu serializes writes so concurrent callers cannot interleave
	// bytes inside a single JSON line, even though O_APPEND already
	// protects the file offset on POSIX. The encode + sync sequence
	// is a logical write, not just a byte-level one, so the mutex
	// covers both halves.
	mu sync.Mutex

	// file is the open policy-decisions.jsonl handle. It is kept open
	// for the lifetime of the writer so we are not paying open/close
	// for every event; closed exactly once by Close.
	file *os.File

	// runID is the run identifier copied into every event's RunID
	// field. Stored on the writer rather than passed per-call because
	// the supervisor binds one writer per run and does not log
	// decisions across run boundaries.
	runID string

	// now produces the timestamp stamped on each event. A function
	// (rather than a clock interface) so tests can inject a
	// deterministic sequence of times without a separate type;
	// production callers pass time.Now.
	now func() time.Time

	// closed guards Close from racing with itself and prevents Write
	// after Close from panicking on a stale file handle.
	closed bool
}

// PolicyDecisionsWriterOptions bundles the per-run metadata a
// PolicyDecisionsWriter needs at construction. RunID is required; Now is
// optional and falls back to time.Now when nil.
type PolicyDecisionsWriterOptions struct {
	// RunID is the run identifier this writer's events belong to.
	// Required.
	RunID string

	// Now is the clock the writer uses to stamp Timestamp on each
	// event. Nil falls back to time.Now. Tests inject a fixed-step
	// clock so the on-disk timestamps are deterministic.
	Now func() time.Time
}

// OpenPolicyDecisionsWriter opens (or creates and appends to) the
// policy-decisions.jsonl file for the run directory at runDir, wires it
// to the supplied options, and returns a PolicyDecisionsWriter ready to
// accept events.
//
// runDir is the absolute path to the run directory (the same value
// RunDirectory.Path carries). The file is opened with O_APPEND so the
// writer cooperates correctly with the empty placeholder
// CreateRunDirectory left in place, and so a reopen of an existing run
// (future replay tooling) adds to the trail rather than truncating it.
//
// Returns an error when the file cannot be opened or when any required
// option is empty. On error no file handle is leaked.
func OpenPolicyDecisionsWriter(runDir string, opts PolicyDecisionsWriterOptions) (*PolicyDecisionsWriter, error) {
	if runDir == "" {
		return nil, errors.New("run: OpenPolicyDecisionsWriter requires runDir")
	}
	if opts.RunID == "" {
		return nil, errors.New("run: OpenPolicyDecisionsWriter requires RunID")
	}

	path := filepath.Join(runDir, policyDecisionsFileName)
	// O_APPEND so concurrent writes (and the once-placeholder file
	// CreateRunDirectory left behind) compose cleanly; O_CREATE so a
	// caller that constructed the writer against a freshly-rmd
	// directory still gets a working handle rather than a confusing
	// ENOENT.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, runFileMode)
	if err != nil {
		return nil, fmt.Errorf("run: open policy decisions log %s: %w", path, err)
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}

	return &PolicyDecisionsWriter{
		file:  f,
		runID: opts.RunID,
		now:   clock,
	}, nil
}

// Write appends a single policy decision event to the underlying
// policy-decisions.jsonl file. The event's RunID and Timestamp are
// filled in from the writer's stored metadata; every other field comes
// from the caller's evt verbatim so a caller that wants to log a
// specific shape (gate decision, broker action, etc.) controls the
// payload directly.
//
// The encoded line is a single JSON object followed by exactly one
// newline byte. The plan requires that no buffered event be lost on
// crash, so Write fsyncs the file after a successful append. The mutex
// makes the encode + sync pair atomic with respect to other callers:
// two goroutines emitting concurrently produce two consecutive whole
// lines, never an interleaved one.
//
// Write returns an error when the writer has already been closed, when
// JSON encoding fails (which would only happen on an unexpected reflect
// path; PolicyDecisionEvent has no marshal hooks), when the underlying
// append fails, or when the fsync fails.
//
// Write rejects an empty Event verb so a misconfigured caller fails
// loudly rather than silently producing an unidentifiable record. It
// also rejects an empty Decision because a decision event with no
// verdict carries no useful information.
func (w *PolicyDecisionsWriter) Write(evt PolicyDecisionEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("run: policy decisions writer is closed")
	}
	if evt.Event == "" {
		return errors.New("run: policy decision requires Event verb")
	}
	if evt.Decision == "" {
		return errors.New("run: policy decision requires Decision")
	}

	// Fill in the writer-pinned fields. We always overwrite RunID and
	// Timestamp so a caller cannot accidentally smuggle a different
	// run's ID through the writer.
	evt.RunID = w.runID
	evt.Timestamp = w.now().Format(time.RFC3339)

	// Marshal then a single Write keeps the JSON object + newline as
	// one syscall, matching the O_APPEND atomicity guarantee on POSIX
	// (writes up to PIPE_BUF are atomic; a typical event is well
	// under that).
	line, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("run: marshal policy decision event: %w", err)
	}
	line = append(line, '\n')

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("run: append policy decision event: %w", err)
	}
	// Sync after every event so a crash between events does not erase
	// the policy decision trail. The plan's "no buffering data loss on
	// crash" rule is the explicit requirement here, mirroring
	// LifecycleWriter.Write and NetworkEventsWriter.Write.
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("run: sync policy decisions log: %w", err)
	}
	return nil
}

// EngineDecision is the writer-facing projection of a policy engine
// PolicyDecision. The shape carries every field the engine produces,
// expressed in primitives (no policy package dependency) so the run
// package does not import internal/policy. Callers that hold a
// policy.PolicyDecision build an EngineDecision at the call site (the
// CLI and the future run-startup wiring do this) and pass it through
// WriteEngineDecision.
//
// The inversion (writer owns the on-disk shape; engine owns the
// in-memory shape; caller bridges) is deliberate: it keeps the
// internal/run package free of policy semantics and the
// internal/policy package free of file I/O, which matches the
// fail-closed / pure-evaluator rules documented on
// policy.PolicyEngine.
type EngineDecision struct {
	// EventID is the engine's "evt_<ts>_<hex>" identifier. Copied
	// verbatim onto the on-disk record's PolicyEventID field.
	// Required: an engine decision without an EventID cannot be
	// looked up by `ai-env policy explain --event <id>` and is
	// rejected by WriteEngineDecision.
	EventID string

	// Decision is the engine verdict string ("allow" / "ask" /
	// "deny" / "quarantine" / "warn"). Required. WriteEngineDecision
	// does not normalize: the caller is responsible for converting
	// policy.Decision (a typed string) to its underlying value with
	// string(dec.Type).
	Decision string

	// Reason is the engine's human-readable explanation. Required so
	// the on-disk record is informative without joining against the
	// engine source code; an empty Reason is rejected.
	Reason string

	// EventType is the engine Event family identifier
	// (policy.EventType cast to string). Optional but recommended;
	// the on-disk explain command groups records by this field.
	EventType string

	// Action mirrors policy.Event.Action ("create", "patch", "pr",
	// "broker_push_branch", "exec", ...). Optional; omitted records
	// still parse but lose the verb context.
	Action string

	// Target mirrors policy.Event.Target. Optional; omitted records
	// still parse.
	Target string

	// EnvName is the ai-env environment the decision applies to.
	// Optional; supplied at the call site (the engine itself is
	// environment-agnostic) so an operator can filter the on-disk
	// trail by env without joining against run.json.
	EnvName string

	// Metadata is the engine decision's metadata map. Optional. The
	// writer takes a shallow copy at Write time so a caller that
	// reuses the map for the next event does not leak across
	// records.
	Metadata map[string]string
}

// WriteEngineDecision appends one engine_evaluate event recording the
// policy engine's verdict for one Event. The method exists alongside
// Write so engine-produced decisions get a stable, dedicated entry
// point: callers that hold a policy.PolicyDecision do not have to
// learn the PolicyDecisionEvent envelope's field-by-field mapping
// (PolicyEventID vs EventID, Reason vs Reasons) and the writer can
// stamp the engine_evaluate verb and the writer-pinned fields in one
// place.
//
// Validation:
//
//   - dec.EventID must be non-empty so `ai-env policy explain` can
//     look the record up by ID.
//   - dec.Decision must be non-empty so the verdict is recoverable
//     from the on-disk record.
//   - dec.Reason must be non-empty so the explain output is
//     informative.
//
// The RunID and Timestamp fields are filled in from the writer's
// stored metadata; the caller cannot override them (matching Write's
// existing behaviour). The Metadata map is shallow-copied so a caller
// that mutates the map after WriteEngineDecision returns does not
// retroactively alter the on-disk record's structural contents (the
// JSON encoding is already finalized, but defending the in-memory
// shape removes a subtle pitfall).
//
// WriteEngineDecision is safe for concurrent use; it serializes
// through the same mutex as Write.
func (w *PolicyDecisionsWriter) WriteEngineDecision(dec EngineDecision) error {
	if dec.EventID == "" {
		return errors.New("run: engine decision requires EventID")
	}
	if dec.Decision == "" {
		return errors.New("run: engine decision requires Decision")
	}
	if dec.Reason == "" {
		return errors.New("run: engine decision requires Reason")
	}

	evt := PolicyDecisionEvent{
		Event:         PolicyDecisionEngineEvaluate,
		EnvName:       dec.EnvName,
		Decision:      dec.Decision,
		Action:        dec.Action,
		PolicyEventID: dec.EventID,
		EventType:     dec.EventType,
		Target:        dec.Target,
		Reason:        dec.Reason,
		Metadata:      copyDecisionMetadata(dec.Metadata),
	}
	return w.Write(evt)
}

// copyDecisionMetadata returns a shallow copy of in. Mirrors the
// engine's own copyMetadata helper; duplicated here so the run
// package does not import internal/policy just for one helper.
// A nil or empty map returns nil (rather than an empty allocated
// map) so the on-disk record's omitempty produces a compact line.
func copyDecisionMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Close closes the underlying policy-decisions.jsonl file. It is safe to
// call more than once; the second call is a no-op. Once Close returns,
// further Write calls fail with a clear error so a misbehaving caller
// cannot silently lose events against a closed handle.
func (w *PolicyDecisionsWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("run: close policy decisions log: %w", err)
	}
	return nil
}

// PolicyDecisionsPath returns the absolute path of the
// policy-decisions.jsonl file inside runDir. Mirrors LifecyclePath /
// NetworkEventsPath so callers (status / report / final-summary) have a
// single helper for the layout.
func PolicyDecisionsPath(runDir string) string {
	return filepath.Join(runDir, policyDecisionsFileName)
}

// ReadPolicyDecisions loads every PolicyDecisionEvent recorded in
// runDir's policy-decisions.jsonl, in the order they were appended.
// Blank lines (e.g. a trailing newline at EOF) are skipped silently.
//
// ReadPolicyDecisions returns an empty slice and nil when the file
// exists but is empty (the post-CreateRunDirectory placeholder state)
// or absent. A malformed line returns the events read so far plus the
// parse error so a caller can still surface the partial trail.
//
// Mirrors ReadLifecycleEvents / ReadNetworkEvents: the file is small in
// practice (one or two gate decisions plus a handful of broker action
// outcomes per run), so the whole-file read is preferable to a
// streaming parser.
func ReadPolicyDecisions(runDir string) ([]PolicyDecisionEvent, error) {
	if runDir == "" {
		return nil, errors.New("run: ReadPolicyDecisions requires runDir")
	}
	path := PolicyDecisionsPath(runDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("run: read policy decisions %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	return parsePolicyDecisions(data, path)
}

// parsePolicyDecisions decodes data as JSONL policy decision events.
// Split out so ReadPolicyDecisions can stay tiny and so tests can
// exercise the parser against in-memory byte slices.
func parsePolicyDecisions(data []byte, path string) ([]PolicyDecisionEvent, error) {
	out := make([]PolicyDecisionEvent, 0, 8)
	for i, line := range splitJSONLines(data) {
		if len(line) == 0 {
			continue
		}
		var evt PolicyDecisionEvent
		if err := json.Unmarshal(line, &evt); err != nil {
			return out, fmt.Errorf("run: parse %s line %d: %w", path, i+1, err)
		}
		out = append(out, evt)
	}
	return out, nil
}
