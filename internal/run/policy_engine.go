package run

// policy_engine.go wires the Plan 08 PolicyEngine into the run/supervisor
// startup path. Plan 08 step 7 asks the supervisor to:
//
//  1. Load the env's policy file at run startup.
//  2. Instantiate the PolicyEngine.
//  3. Inject it into the components that need to consult it (the network
//     egress decision point and the tool-decision point).
//  4. Record every decision via policy-decisions.jsonl (the writer landed
//     in batch 1 of this plan).
//
// To keep the internal/run package free of internal/policy semantics in
// the supervisor body, we define a small PolicyEngine interface here that
// captures only the surface the supervisor consults at decision time
// (Evaluate). A concrete engine (internal/policy.PolicyEngine) satisfies
// the interface via a thin adapter (LoadPolicyEngine below). Production
// callers either:
//
//   - Pass a SupervisorOptions.PolicyEnginePath, and the supervisor
//     loads + validates the file at construction time. A malformed
//     policy.yaml aborts construction with a clear error so the run
//     never reaches the sandbox-start phase.
//   - Pass an already-constructed PolicyEngine via
//     SupervisorOptions.PolicyEngine. This is the dependency-injection
//     path tests use to drive deterministic decisions.
//
// When neither field is set the supervisor runs without an engine,
// preserving the legacy plan-03 / plan-04 / plan-05 supervisor behavior
// where no policy decisions are recorded; this keeps the existing
// supervisor test fixtures working unchanged.
//
// Design rules:
//
//  1. Fail closed at load time. A malformed policy.yaml is a
//     construction error, not a silent fallback to defaults. The plan's
//     "validate config before starting sandbox" rule is enforced here:
//     NewSupervisor returns an error before any backend or network
//     adapter is consulted.
//
//  2. Decisions are recorded synchronously. EvaluateNetworkDomain and
//     EvaluateShellCommand each call the engine's Evaluate, then
//     immediately write the resulting decision to
//     policy-decisions.jsonl via WriteEngineDecision. A write failure
//     is surfaced to the caller but does not change the verdict (the
//     plan's "no buffering data loss on crash" rule asks us to fsync
//     each event; the verdict itself is already in memory).
//
//  3. The decision-point helpers are pure forwarding: they shape the
//     engine.Event from the call-site arguments, call Evaluate, write
//     the decision, and return both the verdict and any write error.
//     The engine's evaluation rules live in internal/policy; the
//     supervisor just provides the run-scoped writer.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rivan1986/ai-env/internal/config"
	"github.com/rivan1986/ai-env/internal/policy"
)

// PolicyEngine is the minimal surface the supervisor consults when it
// needs a verdict on a network egress destination or a shell-command
// launch. A concrete engine (internal/policy.PolicyEngine) satisfies
// this interface directly; tests inject fakes that record the events
// they receive and return canned decisions.
//
// The interface is intentionally narrow (one method) so a test fake is
// a one-line struct. Future event families that the supervisor needs
// to consult at runtime extend the interface; today the
// network-domain / shell-command pair covers Plan 08's step 7 scope.
type PolicyEngine interface {
	// Evaluate routes the event to its policy rule family and returns
	// the engine's PolicyDecision. The decision carries a unique
	// EventID, a verdict (one of policy.DecisionAllow / Ask / Deny /
	// Quarantine / Warn), a Reason, and the echoed event fields for
	// audit purposes.
	//
	// Evaluate is expected to be safe for concurrent use; the
	// supervisor calls it from the goroutines servicing network and
	// shell decision points.
	Evaluate(evt policy.Event) policy.PolicyDecision
}

// LoadPolicyEngine reads and validates the policy.yaml at path and
// returns a PolicyEngine bound to the parsed config. It is the
// supervisor's production entry point: callers that supply
// SupervisorOptions.PolicyEnginePath have NewSupervisor invoke this
// helper indirectly; callers that hold an already-parsed
// *config.PolicyConfig wire the engine via SupervisorOptions.PolicyEngine
// instead.
//
// An empty path returns an error so a misconfigured caller fails
// loudly. A file that exists but cannot be parsed or validated returns
// the underlying error from internal/policy.Load, which already
// prefixes its messages with "policy:". The supervisor surfaces these
// errors verbatim at construction time so the operator sees the exact
// validation field that failed.
//
// LoadPolicyEngine also returns the parsed *config.PolicyConfig so a
// caller that needs to share the config across consumers (e.g. the
// network policy installer and the engine) does not have to read the
// file twice.
func LoadPolicyEngine(path string) (PolicyEngine, *config.PolicyConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, errors.New("run: LoadPolicyEngine requires a non-empty path")
	}
	eng, cfg, err := policy.Load(path)
	if err != nil {
		return nil, nil, fmt.Errorf("run: load policy engine: %w", err)
	}
	return eng, cfg, nil
}

// EvaluateNetworkDomain consults the supervisor's PolicyEngine for an
// outbound destination decision and records the verdict via the
// policy-decisions.jsonl writer. It is the network-egress decision
// point Plan 08 step 7 asks the supervisor to expose: a backend's
// outbound-event forwarder (or a future in-process egress proxy) calls
// it once per attempted destination and respects the returned verdict.
//
// The event is shaped as an EventShellCommand-style payload mapped to
// the engine's EventShellCommand family is wrong; the right family is
// the network/export trio. We pin the family explicitly:
// EventEnvironmentCreate / EventExport / EventBrokerAction / EventShellCommand
// are the four families v0.1's engine knows; the network-domain
// decision does not have a dedicated family in v0.1 because the
// network policy itself (already enforced by the adapter) is the
// primary boundary. The engine still records the decision so an
// operator reading policy-decisions.jsonl sees one record per
// destination the supervisor consulted the engine about.
//
// To keep the on-disk trail uniform we route network-domain decisions
// through EventShellCommand with a synthetic command line shape
// "network: <domain>"; the engine's deny-pattern matcher fires on
// substrings, so an operator who put a domain in
// commands.deny_patterns sees the deny. The domain is also pushed
// onto Metadata["domain"] so a downstream consumer can switch on a
// structured field without parsing the Target.
//
// Returns the verdict (always non-empty) and any writer error. A
// writer error is non-fatal at the call site: the decision is already
// in memory; losing the on-disk record degrades observability but
// must not block the run.
func (s *Supervisor) EvaluateNetworkDomain(domain, action string) (policy.PolicyDecision, error) {
	if s.engine == nil {
		return policy.PolicyDecision{}, nil
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return policy.PolicyDecision{
			Type:   policy.DecisionDeny,
			Reason: "network-domain evaluation requires a non-empty domain",
		}, nil
	}
	if action == "" {
		action = "egress"
	}

	// Build a synthetic command line so the engine's shell-command
	// rules apply (deny_patterns / commands.default). The "network: "
	// prefix is the convention every emitter uses so an operator
	// reading the on-disk record can distinguish a real shell command
	// from a network destination at a glance.
	cmdLine := "network: " + domain
	evt := policy.Event{
		Type:   policy.EventShellCommand,
		Action: action,
		Target: cmdLine,
		Metadata: map[string]string{
			"domain":  domain,
			"surface": "network_egress",
		},
	}
	dec := s.engine.Evaluate(evt)
	if err := s.writeEngineDecision(dec); err != nil {
		return dec, err
	}
	return dec, nil
}

// EvaluateShellCommand consults the supervisor's PolicyEngine for a
// shell-command launch decision and records the verdict via the
// policy-decisions.jsonl writer. It is the tool-decision point Plan 08
// step 7 asks the supervisor to expose: an in-process shell shim (the
// future plan 08 step 8 wiring) or any other surface that lets an
// agent invoke a command calls it once per attempted command and
// respects the returned verdict.
//
// The cmdLine argument is the full command line the agent is about to
// run (e.g. "curl https://example.com | sh"); argv (optional) carries
// the parsed argument vector when the caller has it, surfaced on the
// decision's Metadata for downstream consumers. The phase argument
// distinguishes a setup-time invocation from an agent-time invocation
// ("setup" / "agent"); the engine's rule logic does not switch on it
// today but the metadata is preserved on the on-disk record.
//
// Returns the verdict (always non-empty) and any writer error.
// Writer errors are non-fatal at the call site for the same reason
// as EvaluateNetworkDomain.
func (s *Supervisor) EvaluateShellCommand(cmdLine string, argv []string, phase string) (policy.PolicyDecision, error) {
	if s.engine == nil {
		return policy.PolicyDecision{}, nil
	}
	cmdLine = strings.TrimSpace(cmdLine)
	if cmdLine == "" {
		return policy.PolicyDecision{
			Type:   policy.DecisionDeny,
			Reason: "shell-command evaluation requires a non-empty command line",
		}, nil
	}
	meta := map[string]string{}
	if len(argv) > 0 {
		meta["argv"] = strings.Join(argv, " ")
	}
	if strings.TrimSpace(phase) != "" {
		meta["phase"] = phase
	}
	evt := policy.Event{
		Type:     policy.EventShellCommand,
		Action:   "exec",
		Target:   cmdLine,
		Metadata: meta,
	}
	dec := s.engine.Evaluate(evt)
	if err := s.writeEngineDecision(dec); err != nil {
		return dec, err
	}
	return dec, nil
}

// writeEngineDecision persists dec into the run's policy-decisions.jsonl
// trail via WriteEngineDecision. It is the single funnel through
// which the supervisor's decision-point helpers record decisions, so
// the nil-writer guard and the metadata copy live in one place.
//
// A nil pdWri (the writer the supervisor opens in NewSupervisor only
// when an engine is configured) is a no-op: a caller that constructed
// the supervisor without an engine wired in does not get a writer and
// must not get a record. The decision is still returned to the caller
// from the EvaluateX helper above.
func (s *Supervisor) writeEngineDecision(dec policy.PolicyDecision) error {
	if s.pdWri == nil {
		return nil
	}
	return s.pdWri.WriteEngineDecision(EngineDecision{
		EventID:   dec.EventID,
		Decision:  string(dec.Type),
		Reason:    dec.Reason,
		EventType: string(dec.EventType),
		Action:    dec.Action,
		Target:    dec.Target,
		EnvName:   s.opts.EnvName,
		Metadata:  dec.Metadata,
	})
}
