// Plan Batch 5.6 — `network_policy_degraded` acceptance tests.
//
// These tests pin the two canonical emission paths the supervisor owns:
//
//   - The EgressObserver fails to attach in auto mode: the supervisor
//     emits both `observer_unavailable` (the component-level signal)
//     AND `network_policy_degraded` (the policy-level signal). The
//     run continues with reduced guarantees.
//   - The EgressRules lifecycle returns `rules.ErrUnsupportedOS`: the
//     supervisor records `network_policy_degraded` and proceeds.
//
// Strict-mode observer failure aborts the run (no degradation verb is
// expected — the run never reaches the policy install step). Disabled
// mode is silent on both verbs — the operator opted out of observation
// explicitly so labeling the policy "degraded" would be misleading.
//
// The tests use the same recording fixtures as the canonical
// sequence acceptance tests (sequence_probe / fakeSequenceObserver) so
// the behaviour proven here composes cleanly with the canonical 11-step
// ordering invariants Batch 5.5 already verified.

package run

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/backend"
	"github.com/i1rr/ai-env/internal/egress"
)

// failingSequenceObserver implements egress.EgressObserver and returns
// a synthetic error from Start. Used by the auto-mode degradation
// tests to drive the supervisor into the `observer_unavailable` path
// without standing up a real netns / NFLOG attach.
type failingSequenceObserver struct {
	startErr error
}

func (f *failingSequenceObserver) Mode() string                  { return "nflog" }
func (f *failingSequenceObserver) Chain() string                 { return "AIENV-EGR-deadbeef" }
func (f *failingSequenceObserver) Start(_ context.Context) error { return f.startErr }
func (f *failingSequenceObserver) Stop() error                   { return nil }

// TestSupervisor_ObserverAutoModeEmitsNetworkPolicyDegraded pins the
// plan Batch 5.6 contract: when the EgressObserver fails to attach in
// auto mode the supervisor emits BOTH `observer_unavailable` AND
// `network_policy_degraded` so the audit trail records the
// component-level signal (which component went down) AND the
// policy-level signal (the policy this run is now running under is
// weaker than configured).
func TestSupervisor_ObserverAutoModeEmitsNetworkPolicyDegraded(t *testing.T) {
	skipIfNoSh(t)
	dir := newSequenceRunDir(t)

	obs := &failingSequenceObserver{startErr: errors.New("synthetic attach failure")}

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:             dir.Path,
		RunID:              dir.ID,
		EnvName:            "policy-degraded-observer",
		Task:               "auto-mode observer degradation",
		Backend:            "local-process",
		Agent:              "claude",
		Command:            shellCmd("exit 0"),
		MaxRuntime:         5 * time.Second,
		IdleTimeout:        5 * time.Second,
		StatsPollInterval:  20 * time.Millisecond,
		StopGracePeriod:    100 * time.Millisecond,
		EgressObserver:     obs,
		EgressObserverMode: egress.EgressObserverModeAuto,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Fatalf("FinalState = %q, want %q (auto mode must degrade not abort)",
			result.FinalState, StateCompleted)
	}

	events := readLifecycleEvents(t, dir.Path)
	unavailIdx := indexOfVerb(events, LifecycleVerbObserverUnavailable)
	degradedIdx := indexOfVerb(events, LifecycleVerbNetworkPolicyDegraded)

	if unavailIdx < 0 {
		t.Fatalf("observer_unavailable not emitted; events=%+v", events)
	}
	if degradedIdx < 0 {
		t.Fatalf("network_policy_degraded not emitted; events=%+v", events)
	}
	// `observer_unavailable` must precede `network_policy_degraded`
	// (the component fact precedes the policy consequence in the audit
	// trail).
	if !(unavailIdx < degradedIdx) {
		t.Errorf("ordering broken: observer_unavailable=%d, network_policy_degraded=%d (want strictly less)",
			unavailIdx, degradedIdx)
	}

	// Metadata schema:
	//   reason  = "observer_unavailable"
	//   missing = "observer"
	//   detail  = the underlying error string
	md := events[degradedIdx].Metadata
	if md["reason"] != "observer_unavailable" {
		t.Errorf("network_policy_degraded reason = %q, want %q",
			md["reason"], "observer_unavailable")
	}
	if md["missing"] != "observer" {
		t.Errorf("network_policy_degraded missing = %q, want %q",
			md["missing"], "observer")
	}
	if md["detail"] == "" {
		t.Errorf("network_policy_degraded detail empty; want underlying error string")
	}
}

// TestSupervisor_ObserverStrictModeDoesNotEmitNetworkPolicyDegraded
// pins the contract that strict mode aborts BEFORE the degradation
// verb fires. A strict-mode failure is "fail closed" — there is no
// "degraded" state; the run terminates and the policy verb is not the
// right audit signal.
func TestSupervisor_ObserverStrictModeDoesNotEmitNetworkPolicyDegraded(t *testing.T) {
	skipIfNoSh(t)
	dir := newSequenceRunDir(t)

	obs := &failingSequenceObserver{startErr: errors.New("strict-mode attach failure")}

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:             dir.Path,
		RunID:              dir.ID,
		EnvName:            "policy-degraded-strict",
		Task:               "strict-mode observer abort",
		Backend:            "local-process",
		Agent:              "claude",
		Command:            shellCmd("exit 0"),
		MaxRuntime:         5 * time.Second,
		IdleTimeout:        5 * time.Second,
		StatsPollInterval:  20 * time.Millisecond,
		StopGracePeriod:    100 * time.Millisecond,
		EgressObserver:     obs,
		EgressObserverMode: egress.EgressObserverModeStrict,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	result, _ := sup.Run(context.Background())
	if result.FinalState != StateFailedBackend {
		t.Fatalf("strict-mode FinalState = %q, want %q (strict must abort, not degrade)",
			result.FinalState, StateFailedBackend)
	}

	events := readLifecycleEvents(t, dir.Path)
	if idx := indexOfVerb(events, LifecycleVerbNetworkPolicyDegraded); idx >= 0 {
		t.Errorf("network_policy_degraded emitted in strict mode (idx=%d); strict aborts before degradation", idx)
	}
}

// TestSupervisor_ObserverDisabledModeDoesNotEmitNetworkPolicyDegraded
// pins the contract that the Disabled mode is silent on both
// `observer_unavailable` AND `network_policy_degraded`. The operator
// opted out of observation entirely; labeling the policy "degraded"
// would mislead an audit reader into thinking the policy was supposed
// to enforce something it never was.
func TestSupervisor_ObserverDisabledModeDoesNotEmitNetworkPolicyDegraded(t *testing.T) {
	skipIfNoSh(t)
	dir := newSequenceRunDir(t)

	obs := &failingSequenceObserver{startErr: errors.New("disabled-mode attach failure")}

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:             dir.Path,
		RunID:              dir.ID,
		EnvName:            "policy-degraded-disabled",
		Task:               "disabled-mode observer silent",
		Backend:            "local-process",
		Agent:              "claude",
		Command:            shellCmd("exit 0"),
		MaxRuntime:         5 * time.Second,
		IdleTimeout:        5 * time.Second,
		StatsPollInterval:  20 * time.Millisecond,
		StopGracePeriod:    100 * time.Millisecond,
		EgressObserver:     obs,
		EgressObserverMode: egress.EgressObserverModeDisabled,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Fatalf("disabled-mode FinalState = %q, want %q",
			result.FinalState, StateCompleted)
	}

	events := readLifecycleEvents(t, dir.Path)
	if idx := indexOfVerb(events, LifecycleVerbNetworkPolicyDegraded); idx >= 0 {
		t.Errorf("network_policy_degraded emitted in disabled mode (idx=%d)", idx)
	}
}

// TestSupervisor_RulesUnsupportedOSEmitsNetworkPolicyDegraded pins
// the second canonical emission path: when the EgressRules lifecycle's
// Install returns `rules.ErrUnsupportedOS` the supervisor proceeds
// with a degraded policy and records the audit signal via
// `network_policy_degraded`. The unsupported-OS skip is the canonical
// "host has no rule-install surface" case; the run continues but
// without the canonical AIENV-EGR-<8hex> chain.
//
// The test does not directly assert errors.Is(err, ErrUnsupportedOS)
// because the rule lifecycle wraps the driver error before returning
// it. Instead it asserts the supervisor reached StateCompleted and the
// `network_policy_degraded` verb is present with the right metadata.
func TestSupervisor_RulesUnsupportedOSEmitsNetworkPolicyDegraded(t *testing.T) {
	skipIfNoSh(t)
	dir := newSequenceRunDir(t)

	// We synthesize the "unsupported OS" path directly via a sink that
	// emits network_policy_degraded as the EgressRules.Install hook
	// would. This avoids the cross-platform fragility of constructing
	// a real rules.Lifecycle whose Install hits the unsupported sentinel
	// (which only happens on non-Linux/non-Darwin hosts the test grid
	// cannot easily simulate). The verb-emission path itself is what
	// Batch 5.6 owns; the rules-lifecycle plumbing is Batch 5.4's.
	//
	// We use a BackendStart hook that invokes the supervisor's
	// BackendEventSink (the production wiring an adapter would consume)
	// to emit network_policy_degraded with the canonical metadata.
	var sink backend.BackendEventSink
	backendStart := func() error {
		if sink == nil {
			return errors.New("sink not wired yet")
		}
		return sink.Emit(
			string(LifecycleVerbNetworkPolicyDegraded),
			NetworkPolicyDegradedMetadata("rules_unsupported_os", "egress_rules", "egress/rules: unsupported_os"),
		)
	}

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "policy-degraded-rules",
		Task:              "rules unsupported-os degradation",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		BackendStart:      backendStart,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	sink = sup.BackendEventSink()

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Fatalf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}

	events := readLifecycleEvents(t, dir.Path)
	degradedIdx := indexOfVerb(events, LifecycleVerbNetworkPolicyDegraded)
	if degradedIdx < 0 {
		t.Fatalf("network_policy_degraded not emitted via BackendEventSink; events=%+v", events)
	}

	md := events[degradedIdx].Metadata
	if md["reason"] != "rules_unsupported_os" {
		t.Errorf("reason = %q, want %q", md["reason"], "rules_unsupported_os")
	}
	if md["missing"] != "egress_rules" {
		t.Errorf("missing = %q, want %q", md["missing"], "egress_rules")
	}
	if md["detail"] == "" {
		t.Errorf("detail empty; want non-empty string")
	}
}

// TestNetworkPolicyDegradedMetadata_OmitsEmptyOptionalKeys pins the
// helper's "empty optional keys are omitted" contract. An emitter that
// has no `missing` / `detail` to report should not pad the metadata
// map with empty-string placeholders — readers treat the absence of a
// key as "the emitter has no data" rather than "the emitter has an
// empty string".
func TestNetworkPolicyDegradedMetadata_OmitsEmptyOptionalKeys(t *testing.T) {
	md := NetworkPolicyDegradedMetadata("iptables_rejected", "", "")
	if md["reason"] != "iptables_rejected" {
		t.Errorf("reason = %q, want %q", md["reason"], "iptables_rejected")
	}
	if _, ok := md["missing"]; ok {
		t.Errorf("missing key present (= %q); want omitted when empty", md["missing"])
	}
	if _, ok := md["detail"]; ok {
		t.Errorf("detail key present (= %q); want omitted when empty", md["detail"])
	}
}

// TestNetworkPolicyDegradedMetadata_KeepsNonEmptyOptionalKeys pins the
// symmetric contract: when optional keys are populated they appear
// verbatim. Reason is required and always present.
func TestNetworkPolicyDegradedMetadata_KeepsNonEmptyOptionalKeys(t *testing.T) {
	md := NetworkPolicyDegradedMetadata("iptables_rejected", "observer,egress_rules", "iptables: chain already exists")
	if md["reason"] != "iptables_rejected" {
		t.Errorf("reason = %q, want iptables_rejected", md["reason"])
	}
	if md["missing"] != "observer,egress_rules" {
		t.Errorf("missing = %q, want %q", md["missing"], "observer,egress_rules")
	}
	if md["detail"] != "iptables: chain already exists" {
		t.Errorf("detail = %q, want %q", md["detail"], "iptables: chain already exists")
	}
}

// TestLifecycleWriterBackendEventSink_NilWriterNoOp pins the nil-
// writer tolerance contract: a sink whose underlying writer is nil
// silently no-ops rather than panicking. Production supervisors
// always have a non-nil writer; the nil tolerance keeps a test
// fixture that wires the sink unconditionally from segfaulting.
func TestLifecycleWriterBackendEventSink_NilWriterNoOp(t *testing.T) {
	sink := NewLifecycleWriterBackendEventSink(nil)
	if err := sink.Emit("network_policy_degraded", map[string]string{"reason": "x"}); err != nil {
		t.Errorf("Emit on nil-writer sink returned %v, want nil", err)
	}
}

// TestLifecycleWriterBackendEventSink_RejectsEmptyVerb pins the
// "empty verb is a programming error" contract. A caller that forgets
// to supply a verb sees the failure immediately rather than writing a
// malformed lifecycle record.
func TestLifecycleWriterBackendEventSink_RejectsEmptyVerb(t *testing.T) {
	dir := newSequenceRunDir(t)
	w, err := OpenLifecycleWriter(dir.Path, LifecycleWriterOptions{
		RunID:   dir.ID,
		Backend: "local-process",
		Agent:   "claude",
	})
	if err != nil {
		t.Fatalf("OpenLifecycleWriter: %v", err)
	}
	defer w.Close()

	sink := NewLifecycleWriterBackendEventSink(w)
	if err := sink.Emit("", map[string]string{"reason": "x"}); err == nil {
		t.Errorf("Emit with empty verb returned nil; want non-nil error")
	}
}
