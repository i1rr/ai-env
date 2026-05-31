// Package policy implements the v0.1 policy engine: the single point
// every enforcement surface in ai-env consults before letting an agent
// action proceed.
//
// The package sits between three layers:
//
//   - Above it, internal/config exposes the YAML-shaped policy.yaml
//     document (see config.PolicyConfig). That struct mirrors the file
//     faithfully; the policy engine here is the only place that turns
//     it into runtime decisions.
//   - Below it, the surfaces the master plan enumerates (environment
//     creation, export, GitHub broker actions, shell commands launched
//     through ai-env shell or the shell shim) call Evaluate with an
//     Event describing what is about to happen and respect the returned
//     PolicyDecision.
//   - Alongside it, internal/run owns the on-disk policy-decisions.jsonl
//     trail (PolicyDecisionsWriter). The engine returns decisions; the
//     writer persists them. Plan 08 step 2 reuses the writer from plan
//     07 to record every PolicyDecision the engine produces.
//
// Design rules this package enforces:
//
//  1. One decision point per event family. Every Event flowing through
//     Evaluate gets exactly one PolicyDecision. Callers do not combine
//     multiple decisions on their own; if a surface (e.g. export) wants
//     to feed several rules through the engine, it raises one Event per
//     rule and lets the caller aggregate. This keeps the on-disk
//     decision trail one-event-per-line and lets `ai-env policy
//     explain` print a single coherent record.
//
//  2. Fail closed. An unknown EventType returns DecisionDeny with a
//     clear reason rather than silently allowing the action. The plan
//     enumerates exactly four event types for v0.1; new ones must be
//     added explicitly.
//
//  3. Pure evaluator. Evaluate does no I/O, no clock reads beyond the
//     injected clock (used only to stamp the decision's Timestamp), and
//     no logging. Callers that want to persist a decision pass it to
//     internal/run's PolicyDecisionsWriter; the engine is trivially
//     testable.
//
//  4. Stable Decision and EventType strings. Both enumerations are the
//     protocol the on-disk policy-decisions.jsonl trail and the CLI's
//     explain command pattern-match on. Values never change meaning;
//     new categories add new values.
//
// The PolicyDecision shape mirrors the master plan's policy-decision
// event format (section 24): every decision carries a unique EventID,
// a verdict, a human-readable reason, and a snapshot of the originating
// event so the on-disk trail is self-contained.
package policy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rivan1986/ai-env/internal/config"
)

// Decision is the policy verdict for one Event. The five values mirror
// the master plan's "Decision types" table (section 21) verbatim; the
// strings are the canonical tokens the on-disk policy-decisions.jsonl
// trail and `ai-env policy explain` switch on.
//
// New verdicts add new constants; existing values keep their meaning so
// downstream consumers do not break across releases.
type Decision string

const (
	// DecisionAllow means the action proceeds immediately.
	DecisionAllow Decision = "allow"

	// DecisionAsk means the action requires user or reviewer approval
	// before proceeding. v0.1 surfaces this verdict to the CLI which
	// prompts the operator; an autonomous run treats it as a soft
	// block.
	DecisionAsk Decision = "ask"

	// DecisionDeny means the action is blocked. The caller must abort
	// the action and surface Reason to the operator.
	DecisionDeny Decision = "deny"

	// DecisionQuarantine means the run must stop and preserve its
	// artifacts for inspection. The run's lifecycle transitions to
	// the quarantined state; export is blocked by ExportGate's
	// quarantine rule.
	DecisionQuarantine Decision = "quarantine"

	// DecisionWarn means the action proceeds but the engine highlights
	// it in the run's report. The caller logs the decision and
	// continues.
	DecisionWarn Decision = "warn"
)

// EventType identifies which surface raised the event. The enumeration
// mirrors plan 08 step 1's scope list (environment creation, export,
// broker actions, shell commands when shimmed). Network policy and
// scanner thresholds are evaluated separately by their owning packages
// (internal/network, internal/scanners, internal/export) and pass their
// outcomes to the engine as Events when they need a recorded decision;
// they are not first-class EventTypes because their decision logic is
// not policy.yaml-driven in v0.1.
type EventType string

const (
	// EventEnvironmentCreate is raised when `ai-env new` (or the
	// equivalent programmatic entry point) is about to create a new
	// environment. The engine validates the requested workspace
	// strategy and backend selection against policy.yaml.
	EventEnvironmentCreate EventType = "environment_create"

	// EventExport is raised when an export surface (`ai-env patch`,
	// `ai-env pr`) is about to ship a workspace diff. The engine
	// records the ExportGate verdict; the gate itself remains the
	// authoritative rule evaluator (it owns the per-blocker logic).
	EventExport EventType = "export"

	// EventBrokerAction is raised by the GitHub broker lifecycle
	// (Prepare / AcquireToken / PushBranch / ScanMetadata /
	// CreateDraftPR / RevokeToken). The engine inspects the action
	// name and target to decide whether the broker may proceed.
	EventBrokerAction EventType = "broker_action"

	// EventShellCommand is raised by the shell shim (plan 08 steps
	// 8-9) when an agent invokes a command through `ai-env shell` or
	// the optional shim wrapper. The engine matches the command line
	// against commands.deny_patterns and the default commands.default
	// rule.
	EventShellCommand EventType = "shell_command"
)

// Event is the input to PolicyEngine.Evaluate. The caller fills in the
// fields the engine needs for its event family:
//
//   - EventEnvironmentCreate: Action="create", Target=env name, Metadata
//     carries workspace.strategy and sandbox.backend.
//   - EventExport: Action="patch" or "pr", Target=branch name, Metadata
//     carries the ExportGate decision ("allow"/"block") and a
//     comma-joined reason list.
//   - EventBrokerAction: Action one of the run.PolicyActionBroker*
//     constants, Target="owner/repo:branch", Metadata may carry
//     "branch", "repo", "token_kind".
//   - EventShellCommand: Action="exec", Target=command line (first
//     token), Metadata may carry "argv" (space-joined argv) and
//     "phase" ("setup"/"agent").
//
// Metadata is read-only inside Evaluate; the engine copies values it
// needs onto the returned PolicyDecision but never mutates the input
// map. A nil Metadata is fine; the engine treats absent keys as the
// empty string.
type Event struct {
	// Type identifies the event family. Required; an empty Type
	// produces DecisionDeny because the engine cannot route the event
	// to a rule.
	Type EventType

	// Action is the specific verb inside the family. Required.
	// Examples: "create" (environment_create), "patch"/"pr" (export),
	// "broker_push_branch" (broker_action), "exec" (shell_command).
	Action string

	// Target identifies the resource the action operates on. The
	// format is event-family specific; see the EventType comments.
	// Optional but recommended: the audit trail is much more useful
	// when every record carries a Target.
	Target string

	// Metadata carries free-form contextual fields the engine's
	// per-family rule logic reads. Keys are convention; see the
	// EventType comments for the documented set. Unknown keys are
	// ignored by the rule code but preserved on the returned decision
	// so an auditor can read them later.
	Metadata map[string]string
}

// PolicyDecision is the engine's verdict on one Event. The shape
// mirrors the master plan's policy-decision event format (section 24):
// every decision carries a unique EventID, a verdict (Type), a
// human-readable Reason, the originating event for context, and a
// timestamp the writer stamps into the on-disk trail.
//
// The struct is the protocol the CLI's `ai-env policy explain` command
// uses to render a recorded decision; field names are JSON-stable so
// the on-disk record and the in-memory struct round-trip cleanly.
type PolicyDecision struct {
	// EventID is the unique identifier for this decision. The format
	// is "evt_<timestamp>_<hex>" where timestamp is the engine's
	// clock time formatted as YYYYMMDDHHMMSS and hex is six random
	// hex characters. The format is sortable so an operator listing
	// decisions can scan them chronologically without parsing JSON.
	EventID string `json:"event_id"`

	// Type is the verdict (one of the Decision* constants). Required.
	Type Decision `json:"decision"`

	// Reason is the short human-readable explanation. It is the
	// string the CLI prints verbatim ("workflow files changed and
	// automatic PR creation is blocked"). Required.
	Reason string `json:"reason"`

	// Action mirrors Event.Action. Duplicated onto the decision so
	// the on-disk record is self-contained.
	Action string `json:"action,omitempty"`

	// Target mirrors Event.Target. Duplicated for the same reason as
	// Action.
	Target string `json:"target,omitempty"`

	// EventType mirrors Event.Type. Duplicated so a consumer reading
	// the on-disk trail does not need to infer the family from the
	// Action string.
	EventType EventType `json:"event_type,omitempty"`

	// Timestamp is the moment the engine produced the decision,
	// formatted as RFC3339 with a numeric timezone offset. The engine
	// stamps this using its injected clock so tests are
	// deterministic.
	Timestamp string `json:"timestamp"`

	// Metadata is a copy of the input Event.Metadata, surfaced on the
	// decision so a downstream auditor reading policy-decisions.jsonl
	// sees the same context the engine evaluated against.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PolicyEngine evaluates Events against a loaded policy.yaml document.
// One engine is constructed per process (the CLI builds it during
// startup wiring) and shared across surfaces; Evaluate is safe for
// concurrent use because the engine holds no mutable state beyond the
// EventID generator's lock.
//
// Construction goes through Load (the production path: parse and
// validate policy.yaml on disk) or NewEngine (the dependency-injection
// path: pass an already-parsed *config.PolicyConfig, used by tests and
// by callers that loaded the policy themselves).
type PolicyEngine struct {
	// cfg is the parsed and validated policy.yaml. A nil cfg is
	// permitted: the engine falls back to documented defaults so an
	// ad-hoc Evaluate call without policy.yaml still produces a
	// usable verdict. Production callers always supply a cfg.
	cfg *config.PolicyConfig

	// now produces the timestamp stamped on each decision. A function
	// (rather than a clock interface) so tests can inject a
	// deterministic sequence of times without a separate type;
	// production callers pass time.Now.
	now func() time.Time

	// random is the byte source for the EventID's hex suffix. Three
	// bytes are read per call (six hex characters). Defaults to
	// crypto/rand.Reader when nil.
	random io.Reader

	// mu serializes EventID generation so two concurrent Evaluate
	// calls cannot collide on the random source. The lock is held
	// only across the rand.Read; rule evaluation runs outside it.
	mu sync.Mutex
}

// Option mutates a PolicyEngine at construction. Used by NewEngine and
// (less commonly) by Load when the caller needs a custom clock or
// random source.
type Option func(*PolicyEngine)

// WithClock pins the engine's clock to fn. Production callers do not
// need this; tests use it to make Timestamp deterministic.
func WithClock(fn func() time.Time) Option {
	return func(e *PolicyEngine) {
		if fn != nil {
			e.now = fn
		}
	}
}

// WithRandom pins the engine's randomness source to r. Production
// callers do not need this; tests use it to make EventID deterministic.
func WithRandom(r io.Reader) Option {
	return func(e *PolicyEngine) {
		if r != nil {
			e.random = r
		}
	}
}

// NewEngine constructs a PolicyEngine around an already-parsed policy
// config. The CLI and tests both use this path: the CLI loads the
// config once during startup wiring (so it can share the parsed value
// with other consumers like internal/network) and hands it here; tests
// build a *config.PolicyConfig literal.
//
// A nil cfg is acceptable: the engine falls back to documented
// defaults. The Validate step is the caller's responsibility when this
// path is used; Load is the only entry point that validates.
func NewEngine(cfg *config.PolicyConfig, opts ...Option) *PolicyEngine {
	e := &PolicyEngine{
		cfg:    cfg,
		now:    time.Now,
		random: rand.Reader,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Load reads and validates the policy.yaml file at path, then returns a
// PolicyEngine wired to the parsed document. This is the production
// entry point for the CLI when the engine is owned by a single
// command; callers that load the policy themselves (and need to share
// it with other consumers) use NewEngine instead.
//
// Returns the engine plus the parsed PolicyConfig so the caller can
// thread the same parsed document into other consumers
// (internal/network, ExportGate) without re-reading the file.
//
// An empty path is rejected so a misconfigured caller fails loudly
// rather than silently using defaults. A file that exists but cannot
// be parsed or validated returns the underlying error from
// internal/config, prefixed with the package name.
func Load(path string, opts ...Option) (*PolicyEngine, *config.PolicyConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, errors.New("policy: Load requires a non-empty path")
	}
	cfg, err := config.LoadPolicy(path)
	if err != nil {
		return nil, nil, fmt.Errorf("policy: load %s: %w", filepath.Clean(path), err)
	}
	return NewEngine(cfg, opts...), cfg, nil
}

// Config returns the parsed policy.yaml the engine was constructed
// with. It is the read-only accessor the CLI's `ai-env policy check`
// command uses to render the policy summary; callers must not mutate
// the returned pointer.
func (e *PolicyEngine) Config() *config.PolicyConfig {
	return e.cfg
}

// Evaluate routes evt to the right rule family and returns the
// engine's PolicyDecision. The decision's EventID, Timestamp, and the
// echoed Event* fields are filled in by Evaluate itself; the verdict
// (Type) and Reason come from the rule that fired.
//
// Evaluate never returns an empty Decision: an unknown EventType
// produces DecisionDeny with a "policy engine cannot route" reason so
// the caller's "if dec.Type == Allow" check fails closed.
//
// Evaluate is safe for concurrent use.
func (e *PolicyEngine) Evaluate(evt Event) PolicyDecision {
	dec := PolicyDecision{
		EventID:   e.nextEventID(),
		Action:    evt.Action,
		Target:    evt.Target,
		EventType: evt.Type,
		Timestamp: e.now().Format(time.RFC3339),
		Metadata:  copyMetadata(evt.Metadata),
	}

	switch evt.Type {
	case EventEnvironmentCreate:
		dec.Type, dec.Reason = e.evalEnvironmentCreate(evt)
	case EventExport:
		dec.Type, dec.Reason = e.evalExport(evt)
	case EventBrokerAction:
		dec.Type, dec.Reason = e.evalBrokerAction(evt)
	case EventShellCommand:
		dec.Type, dec.Reason = e.evalShellCommand(evt)
	default:
		dec.Type = DecisionDeny
		dec.Reason = fmt.Sprintf("policy engine cannot route unknown event type %q", evt.Type)
	}
	return dec
}

// evalEnvironmentCreate evaluates an environment_create event. v0.1's
// policy.yaml does not gate environment creation directly (the master
// plan section 21 lists it under "Policy applies to" but the rules
// are encoded in ai-env.yaml's workspace/sandbox blocks, not in
// policy.yaml). The engine therefore allows every environment_create
// event by default; future versions that add explicit
// environment-creation rules to policy.yaml extend this function.
//
// The function still returns a non-empty Reason so the on-disk trail
// is informative even when the decision is allow.
func (e *PolicyEngine) evalEnvironmentCreate(evt Event) (Decision, string) {
	if evt.Action == "" {
		return DecisionDeny, "environment_create event missing action"
	}
	return DecisionAllow, "environment creation permitted by policy"
}

// evalExport evaluates an export event. The export surface
// (internal/export.ExportGate) is the authoritative rule evaluator for
// export blockers; the engine here records the gate's verdict so the
// on-disk policy-decisions.jsonl trail carries one record per export.
//
// The caller passes the gate's decision string ("allow"/"block") in
// Metadata["gate_decision"] and the comma-joined block reasons in
// Metadata["gate_reasons"]. The engine maps "block" to DecisionDeny
// and "allow" to DecisionAllow; an absent or unknown gate_decision
// falls back to DecisionDeny so the engine fails closed.
func (e *PolicyEngine) evalExport(evt Event) (Decision, string) {
	gate := strings.TrimSpace(evt.Metadata["gate_decision"])
	switch gate {
	case "allow":
		return DecisionAllow, "export gate allowed the diff"
	case "block":
		reasons := strings.TrimSpace(evt.Metadata["gate_reasons"])
		if reasons == "" {
			reasons = "see scan-results/ for details"
		}
		return DecisionDeny, fmt.Sprintf("export gate blocked: %s", reasons)
	case "":
		return DecisionDeny, "export event missing gate_decision metadata"
	default:
		return DecisionDeny, fmt.Sprintf("export event has unknown gate_decision %q", gate)
	}
}

// evalBrokerAction evaluates a broker_action event. The action names
// mirror internal/run.PolicyActionBroker* (broker_prepare,
// broker_acquire_token, broker_push_branch, broker_scan_metadata,
// broker_create_pr, broker_revoke_token). The caller passes the
// stage's outcome in Metadata["outcome"] ("allow"/"block"/"fail") and,
// when the outcome is "block", the reason in Metadata["reason"].
//
// The engine maps:
//
//   - outcome=allow  -> DecisionAllow
//   - outcome=block  -> DecisionDeny (policy refusal)
//   - outcome=fail   -> DecisionWarn (infrastructure error, not a
//     policy refusal; the broker surfaces the error to the operator)
//
// An absent or unknown outcome falls back to DecisionDeny so the
// engine fails closed.
func (e *PolicyEngine) evalBrokerAction(evt Event) (Decision, string) {
	outcome := strings.TrimSpace(evt.Metadata["outcome"])
	reason := strings.TrimSpace(evt.Metadata["reason"])
	switch outcome {
	case "allow":
		if reason == "" {
			reason = fmt.Sprintf("broker stage %s permitted", evt.Action)
		}
		return DecisionAllow, reason
	case "block":
		if reason == "" {
			reason = fmt.Sprintf("broker stage %s blocked by policy", evt.Action)
		}
		return DecisionDeny, reason
	case "fail":
		if reason == "" {
			reason = fmt.Sprintf("broker stage %s failed", evt.Action)
		}
		return DecisionWarn, reason
	case "":
		return DecisionDeny, fmt.Sprintf("broker_action event %q missing outcome metadata", evt.Action)
	default:
		return DecisionDeny, fmt.Sprintf("broker_action event %q has unknown outcome %q", evt.Action, outcome)
	}
}

// evalShellCommand evaluates a shell_command event. The engine matches
// the command line against:
//
//  1. The high-risk patterns the shim recognizes (curl-pipe-shell,
//     SSH path access, cloud metadata IP). These are hard denies the
//     engine enforces even when policy.commands.deny_patterns does
//     not list them; plan 08 step 8 makes the shim deny these.
//  2. policy.commands.deny_patterns from policy.yaml. Each entry is a
//     substring match against the command line (case-insensitive).
//  3. policy.commands.default ("allow"/"deny"/"allow_in_sandbox").
//     "allow" and "allow_in_sandbox" produce DecisionAllow; "deny"
//     produces DecisionDeny.
//
// The command line is read from Target (the convention for shell
// commands per the Event doc comment); Metadata["argv"] is preserved on
// the decision but is not consulted by the rule logic (a future
// refactor that tokenizes argv at the call site can change this).
func (e *PolicyEngine) evalShellCommand(evt Event) (Decision, string) {
	cmd := strings.TrimSpace(evt.Target)
	if cmd == "" {
		return DecisionDeny, "shell_command event missing Target (command line)"
	}
	lower := strings.ToLower(cmd)

	// High-risk patterns the shim hard-denies. Mirrors plan 08 step
	// 8's "deny obvious high-risk patterns" list. These fire ahead of
	// the user's policy.commands rules so a misconfigured operator
	// cannot accidentally allow them.
	for _, pat := range HighRiskShellPatterns {
		if strings.Contains(lower, pat) {
			return DecisionDeny, fmt.Sprintf("shell command matches high-risk pattern %q", pat)
		}
	}

	// User-configured deny patterns from policy.yaml. Substring match
	// is the v0.1 contract; future versions may upgrade to a glob or
	// regex matcher.
	if e.cfg != nil {
		for _, pat := range e.cfg.Commands.DenyPatterns {
			p := strings.ToLower(strings.TrimSpace(pat))
			if p == "" {
				continue
			}
			if strings.Contains(lower, p) {
				return DecisionDeny, fmt.Sprintf("shell command matches policy.commands.deny_patterns %q", pat)
			}
		}
	}

	// Default rule.
	def := "allow"
	if e.cfg != nil {
		def = strings.TrimSpace(e.cfg.Commands.Default)
	}
	switch def {
	case "allow", "allow_in_sandbox", "":
		return DecisionAllow, "shell command permitted by policy.commands.default"
	case "deny":
		return DecisionDeny, "shell command blocked by policy.commands.default=deny"
	default:
		return DecisionDeny, fmt.Sprintf("shell command default %q is not recognized", def)
	}
}

// HighRiskShellPatterns is the v0.1 hard-deny list the shell shim and
// the policy engine consult before falling back to policy.yaml's
// commands rules. The list mirrors plan 08 step 8's "deny obvious
// high-risk patterns" enumeration:
//
//   - curl-pipe-shell (and the wget equivalent): the canonical
//     supply-chain compromise vector for agent installs.
//   - SSH key paths: ~/.ssh/, /etc/ssh/, id_rsa, id_ed25519,
//     known_hosts. Direct read attempts are denied at the policy
//     level in addition to the filesystem isolation; this is
//     defense-in-depth, not the primary boundary.
//   - Cloud metadata IP: 169.254.169.254. Mirrors the network
//     policy's MetadataServiceCIDRs block; an agent that constructs
//     a curl call against the metadata IP is denied here even when
//     the network policy is not yet active.
//
// Entries are lower-cased substrings matched against a lower-cased
// command line. Order is not significant; the matcher walks the slice
// once and stops at the first hit. The slice is exported so the shim
// (internal/policy/shim.go, future step 8) can reuse it without
// retyping the list.
var HighRiskShellPatterns = []string{
	"curl ",
	"wget ",
	"| sh",
	"| bash",
	"|sh ",
	"|bash ",
	".ssh/",
	"id_rsa",
	"id_ed25519",
	"known_hosts",
	"169.254.169.254",
}

// nextEventID returns a fresh "evt_<timestamp>_<hex>" identifier. The
// timestamp portion is the engine's clock formatted as YYYYMMDDHHMMSS
// (sortable, punctuation-free); the hex suffix is six lowercase hex
// characters drawn from the engine's random source.
//
// nextEventID is safe for concurrent callers: the random read is
// serialized under mu. The format is documented on PolicyDecision.EventID.
func (e *PolicyEngine) nextEventID() string {
	e.mu.Lock()
	defer e.mu.Unlock()

	ts := e.now().UTC().Format("20060102150405")
	buf := make([]byte, 3)
	if _, err := io.ReadFull(e.random, buf); err != nil {
		// The crypto/rand reader does not return errors in practice;
		// a test that injects a short reader still wants a usable ID,
		// so we fall back to a deterministic "000000" suffix rather
		// than panicking. The on-disk trail still gets a valid record.
		return fmt.Sprintf("evt_%s_%s", ts, "000000")
	}
	return fmt.Sprintf("evt_%s_%s", ts, hex.EncodeToString(buf))
}

// copyMetadata returns a shallow copy of in so the engine never holds a
// reference to the caller's map. A nil in returns nil so an Event with
// no metadata produces a decision with no metadata (rather than an
// empty allocated map that would litter the on-disk trail with "{}").
func copyMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
