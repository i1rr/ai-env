package run

import (
	"fmt"
	"sync"
)

// State is the lifecycle state of a single run. The set of values mirrors
// the run state machine documented in plan 03 verbatim: every happy-path
// state from `created` through `completed`, plus the failure / terminal
// states (`failed_backend`, `failed_agent`, `failed_policy`, `failed_scan`,
// `timed_out`, `killed_by_user`, `killed_oom`, `killed_idle`, `quarantined`).
//
// State is a string so the value persists straight into run.json and
// lifecycle.jsonl without an intermediate encoding step. Later batches
// (the lifecycle.jsonl writer in step 5, the run.json writer in step 6)
// marshal State as-is; downstream tools (`ai-env status`, `ai-env list`)
// match on the same string constants.
type State string

const (
	// StateCreated is the initial state assigned the moment a RunDirectory
	// is materialized. Nothing has happened yet beyond the on-disk
	// scaffolding; the supervisor will transition out of it as soon as it
	// starts preparing the workspace.
	StateCreated State = "created"

	// StatePreparingWorkspace covers the workspace.WorkspaceManager calls
	// that copy/worktree the source repo into .ai-env/workspaces/<env>/.
	// A failure here is recorded against the backend bucket (no dedicated
	// `failed_workspace` exists in the plan) because workspace prep is
	// effectively the first half of starting the backend container.
	StatePreparingWorkspace State = "preparing_workspace"

	// StateStartingBackend is the window in which the backend (docker-sbx,
	// local-process, etc.) is being brought up around the workspace.
	// Failures here transition to StateFailedBackend.
	StateStartingBackend State = "starting_backend"

	// StateApplyingPolicy is the window in which network policy, secret
	// scrubbing, and environment guards are installed inside the backend
	// before the agent is allowed to run. Failures transition to
	// StateFailedPolicy.
	StateApplyingPolicy State = "applying_policy"

	// StateStartingAgent is the window in which the agent process is being
	// exec'd inside the backend. Failures (binary missing, immediate
	// crash) transition to StateFailedAgent.
	StateStartingAgent State = "starting_agent"

	// StateRunning is the steady-state window during which the agent is
	// actively executing. Most terminal transitions originate from here:
	// the agent finishing cleanly (-> StateStopping), a timeout firing
	// (-> StateTimedOut), a signal arriving (-> StateKilledByUser /
	// StateKilledOOM / StateKilledIdle), or an unexpected agent crash
	// (-> StateFailedAgent).
	StateRunning State = "running"

	// StateStopping is the post-exit cleanup window: the agent has signaled
	// completion (or has been signaled to stop) and the supervisor is
	// flushing buffers, collecting the partial diff, and recording the
	// stop reason before moving on to scanning.
	StateStopping State = "stopping"

	// StateScanning is the post-run scan window: secret scan, dependency
	// report, and the other static-analysis passes documented in the run
	// directory layout. Failures transition to StateFailedScan; a scan
	// that finds disqualifying content transitions to StateQuarantined.
	StateScanning State = "scanning"

	// StateReporting is the window during which scan output is folded into
	// final-summary.md and the human-facing artifacts are written. A
	// reporting-time discovery of disqualifying content can still escalate
	// to StateQuarantined; anything else transitions to StateCompleted.
	StateReporting State = "reporting"

	// StateCompleted is the success terminal. The run finished, scans
	// passed, the report was written, and no signal forced an early stop.
	StateCompleted State = "completed"

	// StateFailedBackend is the terminal for backend bring-up failures
	// (workspace prep included, since that is the half-step before the
	// backend container exists).
	StateFailedBackend State = "failed_backend"

	// StateFailedAgent is the terminal for agent start or runtime
	// failures: the binary refuses to launch, or the running process
	// dies with a non-zero exit code outside the user's control.
	StateFailedAgent State = "failed_agent"

	// StateFailedPolicy is the terminal for policy-install failures
	// (network policy refuses to apply, secret scrubber errors out).
	StateFailedPolicy State = "failed_policy"

	// StateFailedScan is the terminal for post-run scan infrastructure
	// failures: the scanner binary errored, not "the scanner found bad
	// content" (that case is StateQuarantined).
	StateFailedScan State = "failed_scan"

	// StateTimedOut is the terminal for max-runtime timeouts. The
	// supervisor enforces max_runtime_minutes from the supervision config
	// and lands here when the budget is exhausted.
	StateTimedOut State = "timed_out"

	// StateKilledByUser is the terminal for SIGINT / SIGTERM stops. The
	// signal handler forwards the signal to the agent, waits the
	// shutdown-grace window, then lands the run here.
	StateKilledByUser State = "killed_by_user"

	// StateKilledOOM is the terminal for memory-pressure stops. The
	// supervisor's stats poller notices the backend (or host) reporting
	// the run's memory budget exceeded and lands here.
	StateKilledOOM State = "killed_oom"

	// StateKilledIdle is the terminal for idle-timeout stops. The
	// supervisor enforces idle_timeout_minutes (no output, no diff) and
	// lands here when the threshold is crossed.
	StateKilledIdle State = "killed_idle"

	// StateQuarantined is the terminal for runs whose scan output flagged
	// the workspace as unsafe to surface (leaked secrets, malicious
	// dependency, etc.). The artifacts stay on disk but are kept out of
	// the normal `ai-env list` view by later batches.
	StateQuarantined State = "quarantined"
)

// allStates is the canonical ordering of every defined state. It is
// exposed via States() so reporting and CLI code (status, list) can
// iterate without re-deriving the set, and it is the source of truth
// stateValid() consults when validating an incoming State value.
//
// The order is the plan's order: happy-path first (top-to-bottom of the
// state diagram), then failure / terminal states grouped by origin
// (backend, agent, policy, scan) and finally the kill / quarantine
// terminals.
var allStates = []State{
	StateCreated,
	StatePreparingWorkspace,
	StateStartingBackend,
	StateApplyingPolicy,
	StateStartingAgent,
	StateRunning,
	StateStopping,
	StateScanning,
	StateReporting,
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
}

// States returns a copy of every State the run package recognizes, in
// the canonical (plan) order. Callers that want to render a state list
// (CLI help text, debug dumps, tests that iterate the full set) use this
// rather than reaching into the package-level slice.
func States() []State {
	out := make([]State, len(allStates))
	copy(out, allStates)
	return out
}

// terminalStates is the set of states from which no further transition
// is allowed. It is consulted by IsTerminal() and by the transition
// table check in canTransition().
//
// The plan calls these "failure / terminal" plus the explicit
// "completed" success terminal. The set is fixed (not derived from the
// transition table) so a future contributor adding a transition into a
// terminal state cannot accidentally turn it non-terminal.
var terminalStates = map[State]struct{}{
	StateCompleted:     {},
	StateFailedBackend: {},
	StateFailedAgent:   {},
	StateFailedPolicy:  {},
	StateFailedScan:    {},
	StateTimedOut:      {},
	StateKilledByUser:  {},
	StateKilledOOM:     {},
	StateKilledIdle:    {},
	StateQuarantined:   {},
}

// IsTerminal reports whether s is a state from which no further
// transition is allowed. Callers (status reporting, the supervisor's
// main loop exit check) use this rather than enumerating the terminal
// set themselves.
func (s State) IsTerminal() bool {
	_, ok := terminalStates[s]
	return ok
}

// stateValid reports whether s is one of the known State constants. It
// guards Machine.Transition and NewMachine against typo'd or future
// states that have not been folded into the transition table yet.
func stateValid(s State) bool {
	for _, k := range allStates {
		if k == s {
			return true
		}
	}
	return false
}

// transitions encodes the run state machine's legal moves. The keys are
// the current state; the values are the set of states that current state
// is allowed to transition to.
//
// The happy path is the linear walk from StateCreated through
// StateCompleted documented in plan 03. The branching rules layer on
// the failure / terminal escapes:
//
//   - Each transient stage that owns a dedicated failure terminal
//     (preparing_workspace + starting_backend -> failed_backend,
//     applying_policy -> failed_policy, starting_agent / running ->
//     failed_agent, scanning -> failed_scan) can transition to that
//     terminal directly.
//   - Stop-by-signal (killed_by_user) can fire from any active state
//     because SIGINT / SIGTERM is honoured throughout the run, not just
//     once the agent is in StateRunning. The same applies to the host-
//     enforced kill terminals (killed_oom) and to timed_out, both of
//     which the supervisor may trip while the run is still in a setup
//     stage.
//   - killed_idle is restricted to StateRunning because the idle timer
//     only meaningfully ticks once the agent is actually executing.
//   - quarantined originates from the scan/report stages, where a
//     scanner flags the workspace as unsafe.
//   - StateStopping is reachable both as the normal post-run drain and
//     from a signal-handler-driven graceful stop, so several active
//     states can transition into it directly.
//
// transitions is read-only after init; callers go through Machine to
// mutate state.
var transitions = map[State]map[State]struct{}{
	StateCreated: setOf(
		StatePreparingWorkspace,
		// A run can be killed before it even starts work (a SIGINT
		// arriving in the same tick the directory was created).
		StateKilledByUser,
	),
	StatePreparingWorkspace: setOf(
		StateStartingBackend,
		// Workspace prep failures map onto the backend bucket because
		// the plan does not define a dedicated failed_workspace state.
		StateFailedBackend,
		StateKilledByUser,
		StateTimedOut,
	),
	StateStartingBackend: setOf(
		StateApplyingPolicy,
		StateFailedBackend,
		StateKilledByUser,
		StateTimedOut,
	),
	StateApplyingPolicy: setOf(
		StateStartingAgent,
		StateFailedPolicy,
		StateKilledByUser,
		StateTimedOut,
	),
	StateStartingAgent: setOf(
		StateRunning,
		StateFailedAgent,
		StateKilledByUser,
		StateTimedOut,
	),
	StateRunning: setOf(
		StateStopping,
		// Direct-to-terminal escapes that bypass the normal stopping
		// drain: a fatal agent crash, a host-side OOM kill, or any of
		// the supervisor-enforced limits firing during steady state.
		StateFailedAgent,
		StateTimedOut,
		StateKilledByUser,
		StateKilledOOM,
		StateKilledIdle,
	),
	StateStopping: setOf(
		StateScanning,
		// Failures the stopping drain itself discovers (agent crashed
		// during flush, signal arrived mid-stop) still surface as the
		// appropriate terminal so the run record reflects what actually
		// happened.
		StateFailedAgent,
		StateTimedOut,
		StateKilledByUser,
		StateKilledOOM,
	),
	StateScanning: setOf(
		StateReporting,
		StateFailedScan,
		StateQuarantined,
		StateKilledByUser,
		StateTimedOut,
	),
	StateReporting: setOf(
		StateCompleted,
		// A reporting-time discovery (scanner output collation flags a
		// secret) can still escalate to quarantine.
		StateQuarantined,
		StateKilledByUser,
		StateTimedOut,
	),
	// Terminal states have no outbound transitions. They are present in
	// the map with empty sets so Machine.AllowedNext can return an empty
	// slice for them without a missing-key fallback.
	StateCompleted:     {},
	StateFailedBackend: {},
	StateFailedAgent:   {},
	StateFailedPolicy:  {},
	StateFailedScan:    {},
	StateTimedOut:      {},
	StateKilledByUser:  {},
	StateKilledOOM:     {},
	StateKilledIdle:    {},
	StateQuarantined:   {},
}

// setOf is a small helper that builds the inner map[State]struct{}
// values used by the transitions table. Using a helper rather than
// inline literals keeps the table readable: each row reads as a list
// of destination states rather than a wall of struct-tagged map keys.
func setOf(states ...State) map[State]struct{} {
	m := make(map[State]struct{}, len(states))
	for _, s := range states {
		m[s] = struct{}{}
	}
	return m
}

// InvalidTransitionError is returned by Machine.Transition when the
// requested move is not allowed by the transition table. It carries the
// from/to pair so callers can log a precise diagnostic without
// re-deriving the states themselves.
//
// Defined as a named type (rather than a bare fmt.Errorf) because the
// supervisor's signal-handling code in later batches will want to
// distinguish "the transition was rejected" (likely a programming bug
// to investigate) from "the underlying I/O failed" (often a transient
// runtime failure). errors.As against InvalidTransitionError is the
// intended seam.
type InvalidTransitionError struct {
	From State
	To   State
}

// Error implements the error interface. The message format is stable;
// tests match on it and the lifecycle log will eventually surface it.
func (e *InvalidTransitionError) Error() string {
	return fmt.Sprintf("run: invalid transition %s -> %s", e.From, e.To)
}

// Machine is the per-run state machine. It owns the current State and
// rejects transitions that the table forbids. Construction goes through
// NewMachine so the initial state is validated up front.
//
// Machine is safe for concurrent use: the supervisor's main loop and
// its signal handler both call Transition, sometimes from different
// goroutines, and a race between "the agent exited cleanly" and
// "SIGINT arrived" must be resolved deterministically (whichever wins
// the lock wins the transition; the loser sees InvalidTransitionError
// because the machine is already in a terminal state). A sync.Mutex is
// sufficient here; transitions are infrequent and short.
//
// Machine deliberately stays tiny in this batch: no event log, no
// callbacks, no run.json mirror. Those live in steps 5 and 6, which
// take a *Machine as input and observe its current state. Keeping the
// machine concern-free means the lifecycle and run.json writers can be
// added without rewriting it.
type Machine struct {
	mu      sync.Mutex
	current State
}

// NewMachine returns a Machine seeded at the given initial state.
// Production callers pass StateCreated because every run starts there;
// the parameter is exported (rather than hardcoded) so future replay
// tooling can rehydrate a Machine from a persisted run.json without
// having to fake an initial-then-transition sequence.
//
// Returns an error if initial is not a known State. A zero-value
// Machine (i.e. one constructed via &Machine{}) is intentionally
// rejected so misuse is loud: every Machine in the codebase should
// flow through NewMachine.
func NewMachine(initial State) (*Machine, error) {
	if !stateValid(initial) {
		return nil, fmt.Errorf("run: NewMachine: unknown initial state %q", initial)
	}
	return &Machine{current: initial}, nil
}

// Current returns the machine's current state. It takes the mutex so a
// reader that races a writer sees a consistent value rather than a
// torn read (string assignment is not atomic across all architectures
// Go targets).
func (m *Machine) Current() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// IsTerminal reports whether the machine is in a terminal state. It is
// a convenience over m.Current().IsTerminal() that takes the mutex once
// rather than twice.
func (m *Machine) IsTerminal() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current.IsTerminal()
}

// AllowedNext returns the set of states the machine may currently
// transition to, in canonical (plan) order. It is intended for
// diagnostics and tests; the supervisor itself does not gate on this
// because the legal next state is implied by the supervisor stage that
// called Transition.
//
// The returned slice is freshly allocated; callers may sort or mutate
// it without affecting the machine.
func (m *Machine) AllowedNext() []State {
	m.mu.Lock()
	defer m.mu.Unlock()
	allowed := transitions[m.current]
	out := make([]State, 0, len(allowed))
	// Iterate allStates (canonical order) rather than the map (random
	// order) so the result is deterministic.
	for _, s := range allStates {
		if _, ok := allowed[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// Can reports whether transitioning to next is allowed from the
// machine's current state. It is read-only; callers that want to
// commit the move use Transition.
//
// Can returns false for unknown next states as well: an undefined
// destination is by definition not a permitted transition.
func (m *Machine) Can(next State) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.canLocked(next)
}

// canLocked is the mutex-held check both Can and Transition use. It
// looks up the current state's transition set and reports membership.
// Transitions from terminal states are always rejected because the
// terminal-state rows of the table are explicitly empty.
func (m *Machine) canLocked(next State) bool {
	if !stateValid(next) {
		return false
	}
	allowed, ok := transitions[m.current]
	if !ok {
		// Defensive: every defined state has an entry (terminal states
		// have empty maps), so a missing key here is a programming bug.
		return false
	}
	_, ok = allowed[next]
	return ok
}

// Transition moves the machine from its current state to next. It
// returns *InvalidTransitionError if the move is not allowed, including
// the case where the machine is already in a terminal state.
//
// On success the machine's current state is next; subsequent Current()
// and IsTerminal() calls observe the new value. The transition itself
// is atomic with respect to other Transition / Current / Can callers:
// callers that race always see one of the two states, never an
// intermediate.
//
// Note that Transition does not emit lifecycle events; the lifecycle.
// jsonl writer (step 5) wraps the call site and is responsible for
// persisting state-change records. Keeping the state machine free of
// I/O dependencies means it can be exercised in unit tests without a
// filesystem and stays cheap to call from the signal handler.
func (m *Machine) Transition(next State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.canLocked(next) {
		return &InvalidTransitionError{From: m.current, To: next}
	}
	m.current = next
	return nil
}
