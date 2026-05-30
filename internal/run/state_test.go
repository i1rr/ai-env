package run

import (
	"errors"
	"sync"
	"testing"
)

// TestNewMachine_StartsAtCreated verifies the production seed used by
// every run: the supervisor builds a Machine at StateCreated, and the
// first observation must agree.
func TestNewMachine_StartsAtCreated(t *testing.T) {
	m, err := NewMachine(StateCreated)
	if err != nil {
		t.Fatalf("NewMachine: %v", err)
	}
	if got := m.Current(); got != StateCreated {
		t.Errorf("Current = %q, want %q", got, StateCreated)
	}
	if m.IsTerminal() {
		t.Errorf("StateCreated should not be terminal")
	}
}

// TestNewMachine_RejectsUnknownInitial guards against typo'd seeds.
// Constructing a Machine at an unknown state would leave the transition
// table without an entry for the current state, so the constructor
// refuses the value up front.
func TestNewMachine_RejectsUnknownInitial(t *testing.T) {
	if _, err := NewMachine(State("bogus")); err == nil {
		t.Fatal("expected error for unknown initial state")
	}
}

// TestMachine_HappyPath walks the entire happy-path sequence the plan
// documents (created -> preparing_workspace -> ... -> completed). Each
// step must be accepted and Current() must reflect the new state.
//
// This is the canonical run-to-success transcript and the most
// important behavior for the supervisor's main loop in step 8 to rely
// on.
func TestMachine_HappyPath(t *testing.T) {
	m, err := NewMachine(StateCreated)
	if err != nil {
		t.Fatalf("NewMachine: %v", err)
	}

	happy := []State{
		StatePreparingWorkspace,
		StateStartingBackend,
		StateApplyingPolicy,
		StateStartingAgent,
		StateRunning,
		StateStopping,
		StateScanning,
		StateReporting,
		StateCompleted,
	}
	for _, next := range happy {
		if err := m.Transition(next); err != nil {
			t.Fatalf("Transition to %q: %v", next, err)
		}
		if got := m.Current(); got != next {
			t.Errorf("after Transition(%q): Current = %q", next, got)
		}
	}
	if !m.IsTerminal() {
		t.Errorf("StateCompleted should be terminal")
	}
}

// TestMachine_RejectsInvalidTransition exercises the explicit-rejection
// requirement: a move the table does not allow returns a typed
// *InvalidTransitionError with the From/To fields populated.
//
// We pick a clearly illegal jump (created -> completed) because skipping
// the entire pipeline is the kind of bug a future refactor of the
// supervisor could introduce, and the machine has to catch it.
func TestMachine_RejectsInvalidTransition(t *testing.T) {
	m, err := NewMachine(StateCreated)
	if err != nil {
		t.Fatalf("NewMachine: %v", err)
	}

	err = m.Transition(StateCompleted)
	if err == nil {
		t.Fatal("expected error for created -> completed")
	}
	var ite *InvalidTransitionError
	if !errors.As(err, &ite) {
		t.Fatalf("expected *InvalidTransitionError, got %T: %v", err, err)
	}
	if ite.From != StateCreated || ite.To != StateCompleted {
		t.Errorf("InvalidTransitionError fields = (%q -> %q), want (%q -> %q)",
			ite.From, ite.To, StateCreated, StateCompleted)
	}

	// The rejected transition must leave the machine untouched: a
	// successful rollback is what lets the signal-handler retry path in
	// later batches stay simple.
	if got := m.Current(); got != StateCreated {
		t.Errorf("after rejected transition: Current = %q, want %q", got, StateCreated)
	}
}

// TestMachine_RejectsUnknownDestination covers the typo case for the
// destination side: an unknown state must be rejected the same way an
// illegal-but-known one is. The signal handler in step 9 passes string-
// derived states in some paths and the machine has to refuse to land in
// a state with no transition-table row.
func TestMachine_RejectsUnknownDestination(t *testing.T) {
	m, err := NewMachine(StateRunning)
	if err != nil {
		t.Fatalf("NewMachine: %v", err)
	}
	if err := m.Transition(State("nonsense")); err == nil {
		t.Fatal("expected error for unknown destination state")
	}
	if got := m.Current(); got != StateRunning {
		t.Errorf("after rejected transition: Current = %q, want %q", got, StateRunning)
	}
}

// TestMachine_TerminalStatesReject ensures every terminal state refuses
// every outbound transition. The plan's terminal definition is "no
// further transitions"; verifying it as a property (rather than ad-hoc)
// keeps the table honest against future additions.
func TestMachine_TerminalStatesReject(t *testing.T) {
	for _, term := range []State{
		StateCompleted,
		StateFailedBackend,
		StateFailedAgent,
		StateFailedPolicy,
		StateFailedScan,
		StateTimedOut,
		StateKilledByUser,
		StateKilledOOM,
		StateKilledIdle,
		StateQuarantined,
	} {
		m, err := NewMachine(term)
		if err != nil {
			t.Fatalf("NewMachine(%q): %v", term, err)
		}
		if !m.IsTerminal() {
			t.Errorf("%q should be terminal", term)
		}
		// Try transitioning to every other state and make sure each is
		// rejected.
		for _, next := range States() {
			if err := m.Transition(next); err == nil {
				t.Errorf("from terminal %q: transition to %q should fail", term, next)
				// Stop on the first leak so a broken terminal does not
				// drown the output.
				break
			}
		}
	}
}

// TestMachine_FailureBranches confirms each failure state is reachable
// from the stage the plan assigns it to. This is the rejection-side
// safety net: if a future change accidentally drops one of these
// transitions, the run cannot record the right outcome.
func TestMachine_FailureBranches(t *testing.T) {
	cases := []struct {
		from State
		to   State
	}{
		{StatePreparingWorkspace, StateFailedBackend},
		{StateStartingBackend, StateFailedBackend},
		{StateApplyingPolicy, StateFailedPolicy},
		{StateStartingAgent, StateFailedAgent},
		{StateRunning, StateFailedAgent},
		{StateRunning, StateTimedOut},
		{StateRunning, StateKilledByUser},
		{StateRunning, StateKilledOOM},
		{StateRunning, StateKilledIdle},
		{StateScanning, StateFailedScan},
		{StateScanning, StateQuarantined},
		{StateReporting, StateQuarantined},
	}
	for _, c := range cases {
		m, err := NewMachine(c.from)
		if err != nil {
			t.Fatalf("NewMachine(%q): %v", c.from, err)
		}
		if err := m.Transition(c.to); err != nil {
			t.Errorf("from %q -> %q: %v", c.from, c.to, err)
			continue
		}
		if got := m.Current(); got != c.to {
			t.Errorf("from %q -> %q: Current = %q", c.from, c.to, got)
		}
	}
}

// TestMachine_Can_MirrorsTransition is a property-style check that the
// read-only Can predicate agrees with the mutating Transition. Drift
// between the two would let the supervisor query a transition,
// believe it is legal, and then have Transition reject it (or vice
// versa).
func TestMachine_Can_MirrorsTransition(t *testing.T) {
	for _, from := range States() {
		for _, to := range States() {
			pred, err := NewMachine(from)
			if err != nil {
				t.Fatalf("NewMachine(%q): %v", from, err)
			}
			canSay := pred.Can(to)

			act, err := NewMachine(from)
			if err != nil {
				t.Fatalf("NewMachine(%q): %v", from, err)
			}
			actDid := act.Transition(to) == nil

			if canSay != actDid {
				t.Errorf("Can(%q -> %q) = %v but Transition succeeded = %v",
					from, to, canSay, actDid)
			}
		}
	}
}

// TestMachine_AllowedNext_DeterministicOrder makes sure AllowedNext
// produces a stable, plan-ordered slice so diagnostics that print it
// stay readable across runs.
func TestMachine_AllowedNext_DeterministicOrder(t *testing.T) {
	m, err := NewMachine(StateRunning)
	if err != nil {
		t.Fatalf("NewMachine: %v", err)
	}
	first := m.AllowedNext()
	for i := 0; i < 5; i++ {
		got := m.AllowedNext()
		if len(got) != len(first) {
			t.Fatalf("AllowedNext length drift: %d vs %d", len(got), len(first))
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("AllowedNext order drift at %d: %q vs %q", i, got[i], first[i])
			}
		}
	}
	// The slice must be a copy: mutating it must not affect later calls.
	if len(first) > 0 {
		first[0] = State("scrambled")
		again := m.AllowedNext()
		if again[0] == State("scrambled") {
			t.Errorf("AllowedNext returned an aliased slice")
		}
	}
}

// TestMachine_ConcurrentTransitions exercises the "two callers race to
// land the same terminal" scenario the supervisor will face when the
// signal handler and the main loop both notice the agent should stop.
// Two goroutines race to drive the machine from StateRunning to
// StateKilledByUser; exactly one should win and the other must observe
// the resulting terminal and be rejected.
//
// We pick the same destination on both sides deliberately: it removes
// the possibility that the table's "stopping can also escalate to a
// terminal" forgiveness lets both calls succeed sequentially. The point
// of the test is to lock the mutex behavior in.
func TestMachine_ConcurrentTransitions(t *testing.T) {
	m, err := NewMachine(StateRunning)
	if err != nil {
		t.Fatalf("NewMachine: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errs := make([]error, 2)
	go func() {
		defer wg.Done()
		errs[0] = m.Transition(StateKilledByUser)
	}()
	go func() {
		defer wg.Done()
		errs[1] = m.Transition(StateKilledByUser)
	}()
	wg.Wait()

	successes := 0
	for _, e := range errs {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		// Either both succeeded (we left the machine in an inconsistent
		// state, double-emitting the terminal) or both failed (we lost
		// the transition entirely). Both are bugs.
		t.Fatalf("expected exactly one successful transition, got %d (errs=%v)", successes, errs)
	}

	if final := m.Current(); final != StateKilledByUser {
		t.Errorf("unexpected final state %q", final)
	}

	// The loser must have surfaced a typed InvalidTransitionError so the
	// supervisor's signal-handler can errors.As against it cleanly.
	for _, e := range errs {
		if e == nil {
			continue
		}
		var ite *InvalidTransitionError
		if !errors.As(e, &ite) {
			t.Errorf("loser err = %v, want *InvalidTransitionError", e)
		}
	}
}

// TestStates_ReturnsCopy confirms States() hands back a fresh slice
// callers can mutate without corrupting the package-level table.
func TestStates_ReturnsCopy(t *testing.T) {
	a := States()
	if len(a) == 0 {
		t.Fatal("States returned empty slice")
	}
	a[0] = State("scrambled")
	b := States()
	if b[0] == State("scrambled") {
		t.Errorf("States returned an aliased slice")
	}
}

// TestState_IsTerminal_KnownSet pins the terminal-state set down at the
// type level. Any future contributor who adds a new state has to decide
// explicitly whether it is terminal; this test will flag a missing
// classification.
func TestState_IsTerminal_KnownSet(t *testing.T) {
	wantTerminal := map[State]bool{
		StateCompleted:     true,
		StateFailedBackend: true,
		StateFailedAgent:   true,
		StateFailedPolicy:  true,
		StateFailedScan:    true,
		StateTimedOut:      true,
		StateKilledByUser:  true,
		StateKilledOOM:     true,
		StateKilledIdle:    true,
		StateQuarantined:   true,
	}
	for _, s := range States() {
		got := s.IsTerminal()
		want := wantTerminal[s]
		if got != want {
			t.Errorf("State(%q).IsTerminal = %v, want %v", s, got, want)
		}
	}
}
