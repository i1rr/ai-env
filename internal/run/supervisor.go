package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// defaultStatsPollInterval is how often the supervisor's stats / idle /
// runtime poll fires while the agent is in StateRunning. The plan asks
// for "Poll stats every 10 seconds"; that cadence is the production
// default. Tests inject a shorter interval through SupervisorOptions so
// the idle and max-runtime paths are exercisable without sleeping for
// minutes at a time.
const defaultStatsPollInterval = 10 * time.Second

// defaultStopGracePeriod is how long the supervisor waits between asking
// the child process to stop (Process.Signal SIGTERM via Cancel / timeout
// path) and escalating to a hard kill. The plan documents
// shutdown_grace_seconds = 15 and kill_grace_seconds = 5 as the
// configured defaults; here we expose them via SupervisorOptions so the
// signal-handling step (step 9) can wire the configured values in
// without reworking this file. A zero value falls back to a short
// constant so tests that do not care about the grace path still
// terminate promptly.
const defaultStopGracePeriod = 5 * time.Second

// StopReasonForState returns the canonical StopReason that pairs with a
// terminal State. It is exported so later batches (the signal handler,
// the `--continue` formatter) do not have to keep their own copy of the
// mapping.
//
// Returns the empty StopReason for non-terminal states; the supervisor
// only records a reason once it actually reaches a terminal.
func StopReasonForState(s State) StopReason {
	switch s {
	case StateCompleted:
		return StopReasonAgentExit
	case StateFailedAgent:
		return StopReasonAgentFailure
	case StateFailedBackend:
		return StopReasonBackendFailure
	case StateFailedPolicy:
		return StopReasonPolicyFailure
	case StateFailedScan:
		return StopReasonScanFailure
	case StateTimedOut:
		return StopReasonTimeout
	case StateKilledByUser:
		return StopReasonSignal
	case StateKilledOOM:
		return StopReasonOOM
	case StateKilledIdle:
		return StopReasonIdle
	case StateQuarantined:
		return StopReasonQuarantine
	}
	return ""
}

// CommandSpec describes how to launch the agent process. The plan calls
// the launch path "backend exec (stub: echo process in this phase)";
// CommandSpec is the value type that the supervisor consumes today and
// that a real Backend.Exec will populate later. Keeping the spec narrow
// (program, args, dir, env) means swapping in a docker-sbx launcher in
// plan 04 only touches the construction site, not the supervisor body.
type CommandSpec struct {
	// Program is the executable name or absolute path the supervisor
	// runs. It is the first argv element, not a shell string; quoting
	// is the caller's concern.
	Program string

	// Args is the rest of argv (without the program). May be nil.
	Args []string

	// Dir is the working directory the child runs in. Typically the
	// workspace path. Empty means "inherit the supervisor's cwd",
	// matching exec.Cmd's default.
	Dir string

	// Env is the environment passed to the child. Nil means "inherit
	// the supervisor's environment", matching exec.Cmd's default. The
	// supervisor does not splice host env vars when this is nil; the
	// caller decides whether the child sees the parent env.
	Env []string
}

// SupervisorOptions bundles every knob the supervisor needs at
// construction. The required fields (RunDir, Command, EnvName, Backend,
// Agent, Task) are load-bearing for lifecycle.jsonl and run.json; the
// optional fields fall back to plan defaults so a production call site
// can omit them.
//
// The options struct lets the supervisor stay constructor-light: tests
// that need a fixed clock, a tight idle window, or a tiny stats poll
// interval flip just those fields and leave the rest at their defaults.
type SupervisorOptions struct {
	// RunDir is the run directory the supervisor writes lifecycle.jsonl,
	// run.json, stdout.log, and stderr.log into. Typically
	// RunDirectory.Path; required.
	RunDir string

	// RunID is the run identifier. Required so lifecycle events and
	// run.json carry the same string everywhere.
	RunID string

	// EnvName is the environment name this run targets. Required for
	// run.json's env_name field.
	EnvName string

	// Task is the verbatim --task content. Stored on the supervisor and
	// copied into run.json so a reader of run.json alone sees what the
	// agent was asked to do. Required (matches WriteTask's contract).
	Task string

	// Backend is the backend identifier (e.g. "docker-sbx",
	// "local-process") the supervisor reports in lifecycle.jsonl and
	// run.json. Required.
	Backend string

	// Agent is the agent identifier (e.g. "claude") the supervisor
	// reports in lifecycle.jsonl and run.json. Required.
	Agent string

	// Command is the spec for the child process. Required; Program may
	// not be empty.
	Command CommandSpec

	// ModelCredentialMode records how the agent obtains its model
	// credentials. Defaults to ModelCredentialBackendManaged when
	// empty: the safe default the plan documents.
	ModelCredentialMode ModelCredentialMode

	// ReducedSafety is recorded verbatim in run.json. The supervisor
	// does not interpret it.
	ReducedSafety bool

	// LinkedPreviousRun is the predecessor run ID for --continue runs;
	// nil for a fresh run. Recorded verbatim in run.json.
	LinkedPreviousRun *string

	// MaxRuntime is the budget the supervisor enforces for the entire
	// run. The plan documents max_runtime_minutes = 120 as the default;
	// callers convert that to a Duration before passing it. A zero
	// value disables the timeout (used by tests that exercise the
	// happy path without racing the budget).
	MaxRuntime time.Duration

	// IdleTimeout is the no-output budget the supervisor enforces while
	// the run is in StateRunning. The plan documents
	// idle_timeout_minutes = 20 as the default. A zero value disables
	// the idle detector. The supervisor only counts time spent in
	// StateRunning; setup states do not consume the budget.
	IdleTimeout time.Duration

	// StatsPollInterval is the cadence of the supervisor's stats /
	// idle / runtime poll. Defaults to defaultStatsPollInterval when
	// zero. Tests override it to a few milliseconds.
	StatsPollInterval time.Duration

	// StopGracePeriod is how long the supervisor waits between asking
	// the child to stop (SIGTERM) and escalating to SIGKILL. Defaults
	// to defaultStopGracePeriod when zero. Wired here in step 8 so the
	// signal-handling step can pass the configured value through; the
	// timeout / cancel paths share the same grace window so a hung
	// child still terminates.
	StopGracePeriod time.Duration

	// Now is the clock the supervisor uses for lifecycle timestamps,
	// run.json started_at / stopped_at, and the idle / runtime
	// computations. Defaults to time.Now when nil. Tests inject a
	// fixed-step clock so the on-disk timestamps are deterministic.
	Now func() time.Time

	// StreamOptions are forwarded to OpenStreamCapture. Zero-valued
	// fields fall through to OpenStreamCapture's own defaults so a
	// supervisor caller does not have to wire stream options unless it
	// cares about the tail buffer size or a custom stream clock.
	StreamOptions StreamOptions

	// DiffCollector, when non-nil, is invoked on terminal so the
	// supervisor can fetch the workspace's partial diff and write it
	// into runDir/git-diff.patch before the closing run.json snapshot
	// lands. This is the seam step 10 ("collect partial diff") uses; the
	// CLI wires a workspace-aware collector here (typically built via
	// NewGitWorktreeDiffCollector for a worktree-strategy env). Leaving
	// it nil skips the collection step and leaves the empty git-diff.patch
	// placeholder in place, which is the right v0.1 default for tests
	// and for non-workspace-aware callers.
	//
	// The collector is invoked once per run from the supervisor's
	// terminal path. Errors are advisory: they do NOT change the
	// terminal state. See DiffCollector for the full contract.
	DiffCollector DiffCollector

	// DiffTimeout caps how long DiffCollector is allowed to run. Zero
	// falls back to defaultDiffTimeout (10s). The cap matters because a
	// stuck `git diff` (corrupt index, missing base ref, detached
	// worktree) would otherwise block the supervisor's terminal walk
	// past the user's expectation; the plan's "preserve logs, collect
	// partial diff if possible" sequence treats the diff as advisory,
	// so a timeout is the right escape hatch rather than waiting
	// indefinitely.
	DiffTimeout time.Duration

	// UserOutput is the io.Writer the supervisor uses for user-visible
	// terminal output. Today it is used by step 10 to print the
	// `ai-env run <env-name> --continue` suggestion when the run lands
	// in a continuation-eligible terminal (killed_by_user, timed_out,
	// killed_idle). Nil is legal: the supervisor still records the
	// suggestion on SupervisorResult.ContinueSuggestion so a programmatic
	// caller can surface it without a writer. Production callers pass
	// os.Stdout; tests pass a bytes.Buffer to assert on the printed
	// text.
	UserOutput io.Writer
}

// SupervisorResult is the outcome the supervisor reports back from Run.
// It mirrors the run.json snapshot at terminal time but is materialized
// as a Go value so a caller (the CLI) can branch on it without re-
// reading the file. Every field is filled in by the time Run returns,
// regardless of whether the terminal was a success or a failure.
type SupervisorResult struct {
	// FinalState is the terminal state the run landed in. The CLI maps
	// this to an exit code; tests assert on it directly.
	FinalState State

	// StopReason is the StopReason recorded in run.json. Mirrors
	// StopReasonForState(FinalState) under normal circumstances; kept
	// as a field so future custom reasons (a specific scanner verdict)
	// can override the default mapping without breaking callers.
	StopReason StopReason

	// ExitCode is the child process exit code. Negative when the
	// process never produced one (signal kill, exec failure); the
	// caller decides how to surface that. Pointer-free here because
	// the supervisor always knows whether a child ran by the time
	// Run returns.
	ExitCode int

	// HasExitCode reports whether ExitCode reflects a real os.exec
	// reported value. False when the process was force-killed before
	// it reported, or when launch itself failed.
	HasExitCode bool

	// StartedAt is when the run transitioned out of StateCreated, i.e.
	// the wall-clock the lifecycle's first non-created event was
	// stamped. Zero when the supervisor failed before that transition.
	StartedAt time.Time

	// StoppedAt is when the run reached its terminal state. Always
	// non-zero by the time Run returns.
	StoppedAt time.Time

	// ContinueSuggestion is the exact `--continue` command the user can
	// re-run when the terminal supports continuation. Empty for
	// terminals that do not (StateCompleted, the failure terminals).
	// The supervisor also writes the same text to UserOutput when it is
	// non-nil; the result field exists so programmatic callers (a
	// future TUI, a structured-output CLI mode) can surface the
	// suggestion without scraping stdout.
	ContinueSuggestion string

	// PartialDiffPath is the absolute path of the run directory's
	// git-diff.patch file. The supervisor always populates this on
	// terminal so a caller can locate the diff without re-deriving the
	// layout. The file may be zero bytes (no collector configured, or
	// collector returned no changes); it is always present.
	PartialDiffPath string
}

// Supervisor owns one run's main loop. It is constructed once per run
// (see NewSupervisor) and driven exactly once by Run. After Run returns
// the Supervisor is consumed: further calls to Run return an error.
//
// Concurrency: Cancel is safe to call from any goroutine, before or
// during Run. Stop is the alias the signal-handling step (step 9) will
// hook into; both reduce to the same internal request, namely "land on
// StateKilledByUser as soon as you can". Multiple Cancel calls collapse
// to the first one.
//
// What the supervisor deliberately does NOT do in this batch:
//
//   - implement `ai-env status` / `logs` / `list` (those are batch 7).
//   - re-link to a previous run beyond echoing the field through
//     LinkedPreviousRun (that is step 14).
//
// Each of those leaves a clean extension point on this type but no
// behaviour today.
//
// OS signal handlers are installed by InstallSignalHandlers (step 9),
// which routes SIGINT / SIGTERM / SIGHUP into Cancel. Partial-diff
// collection and the `--continue` suggestion (step 10) run inside
// finalizeTerminal so they share the orderly shutdown path; see the
// DiffCollector and UserOutput fields on SupervisorOptions for the
// extension seams.
type Supervisor struct {
	opts SupervisorOptions

	machine *Machine
	lcWri   *LifecycleWriter
	streams *StreamCapture

	now func() time.Time

	// cancelCh is closed by Cancel to ask the main loop to stop. The
	// loop selects on this channel from every blocking operation that
	// can sensibly be interrupted. A channel is used (rather than a
	// context.Context only) because the supervisor accepts both a
	// caller-supplied context and a host-side Cancel, and merging them
	// into one signal upstream keeps the loop's select statements
	// readable.
	cancelCh   chan struct{}
	cancelOnce sync.Once

	// stopReason is set by whichever path (timeout, idle, cancel, exit)
	// decides the run's terminal. The main loop reads it after the
	// child exits to choose the right terminal state. atomic.Value
	// because the timer goroutine and the wait goroutine race on it.
	terminalCause atomic.Value // holds terminalCause

	// ran reports whether Run has been called. The supervisor is
	// single-shot; a second Run would race with the first's file
	// handles and lifecycle writer.
	ranMu sync.Mutex
	ran   bool

	// childMu serializes access to the running exec.Cmd's Process
	// handle across the main loop and the kill paths. The std library
	// already protects exec.Cmd against most races, but signalling
	// Process directly while the wait goroutine reaps it is a known
	// edge case; the mutex collapses both sides onto one path.
	childMu  sync.Mutex
	child    *exec.Cmd
	childErr error
	childDone chan struct{}
	waitOnce  sync.Once

	// startedAt and stoppedAt are stamped by the main loop and
	// surfaced via the result.
	startedAt time.Time
	stoppedAt time.Time
}

// terminalCause is the internal reason the main loop will pick for the
// terminal state when the child finally exits or is killed. Captured by
// the timer / cancel goroutines before they signal the child so the
// post-wait code can map "we killed it" back to the right terminal.
type terminalCause struct {
	// state is the terminal State to record. Used by the post-wait
	// code instead of inferring from exit code alone.
	state State

	// reason is the StopReason to record alongside state.
	reason StopReason

	// note is a short human-readable note that ends up in the run's
	// log for debugging; not persisted anywhere user-visible today.
	note string
}

// NewSupervisor constructs a Supervisor from the supplied options. It
// performs option validation and the per-run resource setup (lifecycle
// writer, stream capture) that Run will consume.
//
// On any failure the partially-opened resources are torn down so a
// retry can start from a clean slate. Callers that get an error must
// not call Run on the returned (zero) Supervisor.
func NewSupervisor(opts SupervisorOptions) (*Supervisor, error) {
	if opts.RunDir == "" {
		return nil, errors.New("run: NewSupervisor requires RunDir")
	}
	if opts.RunID == "" {
		return nil, errors.New("run: NewSupervisor requires RunID")
	}
	if opts.EnvName == "" {
		return nil, errors.New("run: NewSupervisor requires EnvName")
	}
	if opts.Backend == "" {
		return nil, errors.New("run: NewSupervisor requires Backend")
	}
	if opts.Agent == "" {
		return nil, errors.New("run: NewSupervisor requires Agent")
	}
	if opts.Task == "" {
		return nil, errors.New("run: NewSupervisor requires Task")
	}
	if opts.Command.Program == "" {
		return nil, errors.New("run: NewSupervisor requires Command.Program")
	}
	if opts.MaxRuntime < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: MaxRuntime must be non-negative, got %v", opts.MaxRuntime)
	}
	if opts.IdleTimeout < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: IdleTimeout must be non-negative, got %v", opts.IdleTimeout)
	}
	if opts.StatsPollInterval < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: StatsPollInterval must be non-negative, got %v", opts.StatsPollInterval)
	}
	if opts.StopGracePeriod < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: StopGracePeriod must be non-negative, got %v", opts.StopGracePeriod)
	}
	if opts.DiffTimeout < 0 {
		return nil, fmt.Errorf("run: NewSupervisor: DiffTimeout must be non-negative, got %v", opts.DiffTimeout)
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if opts.ModelCredentialMode == "" {
		opts.ModelCredentialMode = ModelCredentialBackendManaged
	}
	if opts.StatsPollInterval == 0 {
		opts.StatsPollInterval = defaultStatsPollInterval
	}
	if opts.StopGracePeriod == 0 {
		opts.StopGracePeriod = defaultStopGracePeriod
	}

	machine, err := NewMachine(StateCreated)
	if err != nil {
		return nil, fmt.Errorf("run: NewSupervisor: %w", err)
	}

	lcWri, err := OpenLifecycleWriter(opts.RunDir, LifecycleWriterOptions{
		RunID:   opts.RunID,
		Backend: opts.Backend,
		Agent:   opts.Agent,
		Now:     now,
	})
	if err != nil {
		return nil, err
	}

	streamOpts := opts.StreamOptions
	if streamOpts.Now == nil {
		streamOpts.Now = now
	}
	streams, err := OpenStreamCapture(opts.RunDir, streamOpts)
	if err != nil {
		_ = lcWri.Close()
		return nil, err
	}

	return &Supervisor{
		opts:     opts,
		machine:  machine,
		lcWri:    lcWri,
		streams:  streams,
		now:      now,
		cancelCh: make(chan struct{}),
	}, nil
}

// Cancel asks the supervisor to terminate the run as if a user-driven
// signal had arrived. It is safe to call from any goroutine, before or
// during Run, and from multiple goroutines concurrently. Only the first
// call has any effect; later calls are no-ops.
//
// Cancel returns immediately; the actual terminal landing happens on
// the main loop's next select. The terminal state will be
// StateKilledByUser unless an earlier cause (timeout, idle, exit)
// already won the race.
//
// Step 9 (signal handling) installs OS signal handlers and points them
// at Cancel; nothing in step 8 invokes it from production code yet.
func (s *Supervisor) Cancel() {
	s.cancelOnce.Do(func() {
		// Record an intent to land on StateKilledByUser. If a competing
		// cause (timeout, idle, exit) has already recorded its own
		// terminalCause, this CompareAndSwap loses the race and we keep
		// the earlier reason; that mirrors the plan's "whichever wins
		// first decides the terminal" rule.
		s.recordTerminalCause(terminalCause{
			state:  StateKilledByUser,
			reason: StopReasonSignal,
			note:   "cancel requested",
		})
		close(s.cancelCh)
	})
}

// Stop is the alias step 9 (signal handling) will wire into. Today it
// is exactly Cancel; we expose it under the second name so the signal
// handler does not have to import "Cancel" by another spelling and so
// callers reading the public surface see both the "user cancelled"
// (Cancel) and "graceful stop" (Stop) intents the plan distinguishes.
// They have the same semantics in step 8; step 9 may differentiate.
func (s *Supervisor) Stop() {
	s.Cancel()
}

// Run drives the main loop end to end. It walks the state machine from
// StateCreated through every transient stage to a terminal state,
// writes lifecycle.jsonl events on every transition, rewrites run.json
// on every transition, launches the child process during
// StateStartingAgent, enforces the max-runtime and idle timeouts during
// StateRunning, and tears down resources (streams, lifecycle writer)
// before returning.
//
// Run is single-shot. A second call returns an error rather than
// re-driving the loop, because the lifecycle writer and stream capture
// resources have already been closed.
//
// The supplied context.Context is honored as a cancellation source in
// addition to s.Cancel(); a context cancellation lands on
// StateKilledByUser the same way an explicit Cancel does. Pass
// context.Background() for callers that have no upstream cancellation.
//
// Run returns an error only when the supervisor itself cannot make
// progress (lifecycle writer failure, stream writer failure, missing
// run directory). A terminal that records a failure state
// (StateFailedAgent, StateTimedOut, ...) is NOT returned as an error;
// the caller inspects SupervisorResult.FinalState to learn the outcome.
// This split mirrors the rest of the project: errors are "the
// supervisor could not do its job"; failure states are "the supervisor
// did its job and the run failed".
func (s *Supervisor) Run(ctx context.Context) (SupervisorResult, error) {
	if err := s.markRan(); err != nil {
		return SupervisorResult{}, err
	}
	// Resource cleanup always happens, even on the error paths. Close
	// is idempotent on both sides so the deferred Close inside Run does
	// not double-free if Run already closed explicitly.
	defer func() {
		_ = s.streams.Close()
		_ = s.lcWri.Close()
	}()

	// Wire the caller's context into the same cancel signal Cancel()
	// drives. We spawn one goroutine that waits on ctx.Done and calls
	// Cancel if the context cancels before the run finishes. The
	// goroutine exits as soon as either the context fires or the
	// supervisor's local done channel closes (which happens when Run
	// returns), so it does not leak.
	runDone := make(chan struct{})
	defer close(runDone)
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				s.Cancel()
			case <-runDone:
			}
		}()
	}

	// Walk the setup stages. Each transition is a single helper call
	// that handles the lifecycle event + run.json snapshot. If any
	// stage transition fails (lifecycle write failure, run.json write
	// failure) the supervisor surfaces it: we cannot proceed without
	// the lifecycle trail being durable.
	if err := s.enterSetup(StatePreparingWorkspace); err != nil {
		return s.finalizeTerminal(terminalCause{state: StateFailedBackend, reason: StopReasonBackendFailure, note: "lifecycle write failed during preparing_workspace"}, exitInfo{}), err
	}
	if s.checkCancel() {
		return s.finalizeTerminal(s.takeTerminalCause(terminalCause{state: StateKilledByUser, reason: StopReasonSignal}), exitInfo{}), nil
	}
	if err := s.enterSetup(StateStartingBackend); err != nil {
		return s.finalizeTerminal(terminalCause{state: StateFailedBackend, reason: StopReasonBackendFailure, note: "lifecycle write failed during starting_backend"}, exitInfo{}), err
	}
	if s.checkCancel() {
		return s.finalizeTerminal(s.takeTerminalCause(terminalCause{state: StateKilledByUser, reason: StopReasonSignal}), exitInfo{}), nil
	}
	if err := s.enterSetup(StateApplyingPolicy); err != nil {
		return s.finalizeTerminal(terminalCause{state: StateFailedPolicy, reason: StopReasonPolicyFailure, note: "lifecycle write failed during applying_policy"}, exitInfo{}), err
	}
	if s.checkCancel() {
		return s.finalizeTerminal(s.takeTerminalCause(terminalCause{state: StateKilledByUser, reason: StopReasonSignal}), exitInfo{}), nil
	}
	if err := s.enterSetup(StateStartingAgent); err != nil {
		return s.finalizeTerminal(terminalCause{state: StateFailedAgent, reason: StopReasonAgentFailure, note: "lifecycle write failed during starting_agent"}, exitInfo{}), err
	}
	if s.checkCancel() {
		return s.finalizeTerminal(s.takeTerminalCause(terminalCause{state: StateKilledByUser, reason: StopReasonSignal}), exitInfo{}), nil
	}

	// Launch the child. A launch failure (e.g. binary missing) is a
	// StateFailedAgent terminal: the supervisor did its job, but the
	// run could not get off the ground.
	if err := s.launchChild(); err != nil {
		cause := terminalCause{state: StateFailedAgent, reason: StopReasonAgentFailure, note: fmt.Sprintf("exec failed: %v", err)}
		return s.finalizeTerminal(cause, exitInfo{}), nil
	}

	// Transition to StateRunning now that the child is in flight.
	if err := s.enterSetup(StateRunning); err != nil {
		// We are mid-run with a child process holding our streams. Kill
		// it so we do not leak; the resulting terminal is StateFailedAgent
		// because we never managed to record the run state cleanly.
		s.hardKillChild()
		_, _ = s.waitChild()
		cause := terminalCause{state: StateFailedAgent, reason: StopReasonAgentFailure, note: "lifecycle write failed during running"}
		return s.finalizeTerminal(cause, s.collectExit()), err
	}

	// Main loop: poll stats, wait for the child to exit, enforce
	// max-runtime and idle timeouts, honor Cancel. The loop returns the
	// terminalCause that won the race; the post-loop code maps it to
	// the final state.
	cause := s.runLoop()

	// Wait for the child to actually exit (it may already have done so;
	// waitChild collapses both cases).
	exit := s.collectExit()

	// Transition through the rest of the state machine. The exact path
	// depends on the terminal cause: a clean exit walks
	// running -> stopping -> scanning -> reporting -> completed; a
	// timeout / kill / idle goes running -> <terminal> directly.
	final := s.driveTerminalSequence(cause, exit)

	result := s.finalizeTerminal(final, exit)
	return result, nil
}

// markRan flips the single-shot guard. The second caller sees an
// error rather than racing with the first call's file handles.
func (s *Supervisor) markRan() error {
	s.ranMu.Lock()
	defer s.ranMu.Unlock()
	if s.ran {
		return errors.New("run: Supervisor.Run already called")
	}
	s.ran = true
	return nil
}

// recordTerminalCause atomically stores cause if no earlier cause has
// been recorded. First writer wins; later writers are dropped. The
// supervisor's main loop reads the stored cause via takeTerminalCause.
func (s *Supervisor) recordTerminalCause(cause terminalCause) {
	// CompareAndSwap-style logic: only set if nothing is set yet.
	// atomic.Value rejects nil so we use a zero value sentinel via the
	// stored interface{}.
	s.terminalCause.CompareAndSwap(nil, cause)
}

// takeTerminalCause returns the stored cause, falling back to def when
// none has been recorded. Does not consume the value; later reads see
// the same result. Callers that need to know whether a cause was
// recorded compare the result to def.
func (s *Supervisor) takeTerminalCause(def terminalCause) terminalCause {
	v := s.terminalCause.Load()
	if v == nil {
		return def
	}
	c, ok := v.(terminalCause)
	if !ok {
		return def
	}
	return c
}

// checkCancel reports whether Cancel has been requested. Used between
// setup stages so a cancel during workspace prep lands on
// StateKilledByUser instead of marching all the way to StateRunning.
func (s *Supervisor) checkCancel() bool {
	select {
	case <-s.cancelCh:
		return true
	default:
		return false
	}
}

// enterSetup transitions the machine into next and writes the
// corresponding lifecycle event + run.json snapshot. It is the shared
// helper for every non-terminal transition the supervisor performs
// during the setup phase. Returns an error if the machine refuses the
// transition (programming bug) or if the lifecycle write fails (I/O).
//
// run.json writes are NOT fatal in the same sense: a failure here
// surfaces as an error, but the run continues; the next run.json
// snapshot will land the latest state. The lifecycle event must be
// durable because the post-mortem audit log depends on it.
func (s *Supervisor) enterSetup(next State) error {
	if err := s.machine.Transition(next); err != nil {
		return err
	}
	if s.startedAt.IsZero() {
		// First non-created transition stamps the run's start time. We
		// use the supervisor's clock so tests can pin it.
		s.startedAt = s.now()
	}
	if err := s.lcWri.Write(next); err != nil {
		return err
	}
	if err := s.writeRecordSnapshot(next, nil, nil, nil); err != nil {
		// run.json failure is informational here; we do not stop the
		// run. The next snapshot will overwrite the broken file.
		return nil
	}
	return nil
}

// launchChild starts the configured command, wires stdout/stderr to the
// stream capture, and stores the resulting exec.Cmd on the supervisor.
// Returns an error if the launch itself fails (binary missing, dir
// invalid). On success the child is running and a single background
// goroutine is reaping it; callers observe its completion via the
// childDone channel and read childErr (under childMu) afterwards.
//
// We own the Wait call here (rather than letting individual stop
// helpers spawn their own) because exec.Cmd.Wait can only be called
// once and races with any other observer touching ProcessState. The
// single waiter writes the result; everyone else reads via the
// done channel.
func (s *Supervisor) launchChild() error {
	cmd := exec.Command(s.opts.Command.Program, s.opts.Command.Args...)
	cmd.Dir = s.opts.Command.Dir
	cmd.Env = s.opts.Command.Env
	cmd.Stdout = s.streams.Stdout()
	cmd.Stderr = s.streams.Stderr()
	// Stdin is intentionally nil: the child reads from /dev/null so a
	// stuck read on an uninitialised stdin can never deadlock the
	// supervisor. The agent's interactive mode (later milestones) will
	// route a PTY through here instead.
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return err
	}
	s.childMu.Lock()
	s.child = cmd
	s.childDone = make(chan struct{})
	s.childMu.Unlock()

	// Start the single waiter. It writes childErr under the mutex and
	// closes childDone exactly once so any number of observers (the
	// runLoop, stopChildGracefully) can wait without racing on the
	// std library's ProcessState writes.
	go func() {
		err := cmd.Wait()
		s.childMu.Lock()
		s.childErr = err
		s.childMu.Unlock()
		close(s.childDone)
	}()
	return nil
}

// runLoop is the supervisor's StateRunning loop. It selects on the
// child's exit, the cancel channel, the max-runtime deadline, and the
// stats poll ticker. The returned terminalCause is the reason the loop
// is exiting; the post-loop code drives the state machine to the
// matching terminal.
//
// The loop deliberately does NOT close the streams or transition the
// machine; that is the caller's job (driveTerminalSequence) so the
// terminal sequence can vary (completed vs killed) without duplicating
// the close logic here.
func (s *Supervisor) runLoop() terminalCause {
	pollInterval := s.opts.StatsPollInterval
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var deadline <-chan time.Time
	if s.opts.MaxRuntime > 0 {
		// time.After is sufficient here: we never need to reset the
		// timer. The supervisor's deadline is the wall-clock budget
		// from the moment the child started running.
		deadline = time.After(s.opts.MaxRuntime)
	}

	// runningSince marks the start of the StateRunning window. The
	// idle detector measures against the most recent stream output;
	// before any output arrives, runningSince is the reference.
	runningSince := s.now()

	// childDone is owned by launchChild's single-waiter goroutine and
	// closes when the child has been reaped. The runLoop selects on it
	// alongside cancel / timeout / poll; the waiter wrote childErr
	// before closing the channel so post-loop code reads it safely.
	s.childMu.Lock()
	childDone := s.childDone
	s.childMu.Unlock()

	for {
		select {
		case <-childDone:
			// Child exited on its own. The terminalCause depends on
			// whether the exit was clean. We let the post-loop code
			// inspect the recorded exit status; here we just pick the
			// state.
			s.childMu.Lock()
			waitErr := s.childErr
			s.childMu.Unlock()
			if waitErr == nil {
				return terminalCause{state: StateCompleted, reason: StopReasonAgentExit, note: "child exited 0"}
			}
			// Non-zero exit: a recorded terminalCause (set by an
			// earlier timer / cancel that we beat to the select) wins;
			// otherwise this is a StateFailedAgent terminal because
			// the agent itself returned non-zero.
			recorded := s.takeTerminalCause(terminalCause{})
			if recorded.state != "" {
				return recorded
			}
			return terminalCause{state: StateFailedAgent, reason: StopReasonAgentFailure, note: fmt.Sprintf("child exit: %v", waitErr)}

		case <-s.cancelCh:
			// Cancel arrived. Record the intended terminal (Cancel's
			// own goroutine already did this, but recording here is
			// idempotent) and ask the child to stop. The waiter
			// goroutine will then close childDone.
			s.recordTerminalCause(terminalCause{state: StateKilledByUser, reason: StopReasonSignal, note: "cancel"})
			s.stopChildGracefully()
			<-childDone
			return s.takeTerminalCause(terminalCause{state: StateKilledByUser, reason: StopReasonSignal, note: "cancel"})

		case <-deadline:
			// Max-runtime budget exhausted. Record the intent, stop
			// the child gracefully, wait for the exit, and return.
			s.recordTerminalCause(terminalCause{state: StateTimedOut, reason: StopReasonTimeout, note: "max_runtime exceeded"})
			s.stopChildGracefully()
			<-childDone
			return s.takeTerminalCause(terminalCause{state: StateTimedOut, reason: StopReasonTimeout, note: "max_runtime exceeded"})

		case <-ticker.C:
			// Idle check. The plan's idle definition is "no output +
			// no diff for idle_timeout_minutes". We implement the "no
			// output" half here (LastOutputAt against the stream
			// capture); the "no diff" half is wired in step 10 when
			// the partial-diff collector lands. The plan permits this
			// staging: step 8 says "Detect idle timeout (no output +
			// no diff)" and step 10 owns the diff side, so the v0.1
			// behavior is conservative (output-only).
			if s.opts.IdleTimeout > 0 {
				ref := s.streams.LastOutputAt()
				if ref.IsZero() {
					ref = runningSince
				}
				if s.now().Sub(ref) >= s.opts.IdleTimeout {
					s.recordTerminalCause(terminalCause{state: StateKilledIdle, reason: StopReasonIdle, note: "idle timeout"})
					s.stopChildGracefully()
					<-childDone
					return s.takeTerminalCause(terminalCause{state: StateKilledIdle, reason: StopReasonIdle, note: "idle timeout"})
				}
			}
			// Stats poll: this is observational only in v0.1. A future
			// step writes a stats.jsonl event here. We deliberately do
			// not crash on missing stats so the loop stays robust if
			// the backend has no stats endpoint yet.
		}
	}
}

// exitInfo bundles the exit code (or its absence) and the wait error
// for the post-loop terminal sequence. Kept tiny so the caller does
// not have to thread three return values through every helper.
type exitInfo struct {
	code    int
	hasCode bool
	err     error
}

// collectExit returns the child's exit info. By the time runLoop
// returns the waiter goroutine has closed childDone and written
// childErr, so reading ProcessState here cannot race with Wait. We
// guard the read with childMu for paranoia and to keep the access
// patterns consistent with launchChild.
func (s *Supervisor) collectExit() exitInfo {
	s.childMu.Lock()
	c := s.child
	done := s.childDone
	s.childMu.Unlock()
	if c == nil {
		return exitInfo{code: -1, hasCode: false}
	}
	if done != nil {
		<-done
	}
	s.childMu.Lock()
	st := c.ProcessState
	s.childMu.Unlock()
	if st == nil {
		return exitInfo{code: -1, hasCode: false}
	}
	if !st.Exited() {
		// Killed by signal; no canonical exit code. Use -1 sentinel
		// and HasExitCode=false; the result struct exposes that to the
		// caller for accurate reporting.
		return exitInfo{code: -1, hasCode: false}
	}
	return exitInfo{code: st.ExitCode(), hasCode: true}
}

// driveTerminalSequence walks the state machine through the right
// terminal sequence given the cause and exit info. For a clean exit
// (StateCompleted) we walk the full happy-path post-running stages
// (stopping -> scanning -> reporting -> completed); for any other
// terminal we transition directly to the terminal state.
//
// Each transition emits a lifecycle event and a run.json snapshot. A
// failure on any of those is logged via run.json (best effort) but
// does NOT change the terminal: we already know what state we want to
// land in, and the supervisor's job at this point is to land there
// regardless of partial I/O failures.
func (s *Supervisor) driveTerminalSequence(cause terminalCause, exit exitInfo) terminalCause {
	switch cause.state {
	case StateCompleted:
		// Happy path: walk stopping -> scanning -> reporting -> completed.
		// Each stage's body (scanning, reporting) is a no-op today; the
		// supervisor still transitions through them so the lifecycle.jsonl
		// is the full record the plan documents.
		for _, next := range []State{StateStopping, StateScanning, StateReporting, StateCompleted} {
			if err := s.machine.Transition(next); err != nil {
				// If we cannot transition (e.g. the machine is already
				// terminal because Cancel landed first), give up on
				// the happy walk and return whatever terminal we are
				// stuck on. We never silently skip a terminal.
				return terminalCause{state: s.machine.Current(), reason: StopReasonForState(s.machine.Current())}
			}
			if err := s.lcWri.Write(next); err != nil {
				// Lifecycle write failure on the happy-path drain is a
				// hard signal that something is wrong with disk. We
				// degrade to StateFailedAgent so the operator sees the
				// failure rather than a confused "completed" record.
				_ = s.machine.Transition(StateFailedAgent)
				_ = s.lcWri.Write(StateFailedAgent)
				cause := terminalCause{state: StateFailedAgent, reason: StopReasonAgentFailure, note: fmt.Sprintf("lifecycle write failed in %s", next)}
				_ = s.writeRecordSnapshot(StateFailedAgent, &exit.code, &cause.reason, nil)
				return cause
			}
			_ = s.writeRecordSnapshot(next, &exit.code, nil, nil)
		}
		reason := StopReasonAgentExit
		// Final run.json snapshot includes stop_reason and exit_code.
		_ = s.writeRecordSnapshot(StateCompleted, &exit.code, &reason, nil)
		return terminalCause{state: StateCompleted, reason: reason, note: cause.note}

	default:
		// Non-happy terminal: transition directly. The state machine's
		// transition table allows running -> <terminal> for every
		// terminal we set here; if a future cause picks an
		// unreachable state, Transition returns an error and we let
		// the current state stand.
		next := cause.state
		if err := s.machine.Transition(next); err != nil {
			next = s.machine.Current()
		}
		_ = s.lcWri.Write(next)
		reason := cause.reason
		if reason == "" {
			reason = StopReasonForState(next)
		}
		var codePtr *int
		if exit.hasCode {
			codePtr = &exit.code
		}
		_ = s.writeRecordSnapshot(next, codePtr, &reason, nil)
		return terminalCause{state: next, reason: reason, note: cause.note}
	}
}

// finalizeTerminal is the single exit gate for Run. It ensures the
// state machine has landed in cause.state (transitioning + writing the
// lifecycle event if it has not already), stamps stoppedAt, collects
// the partial diff into runDir/git-diff.patch, writes the closing
// run.json snapshot with exit code + stop reason + stopped_at, prints
// the `--continue` suggestion to UserOutput when the terminal supports
// it, and returns the SupervisorResult.
//
// The ordering matters: we land the state first (so an operator
// inspecting lifecycle.jsonl mid-shutdown sees the terminal), then
// collect the partial diff (so the closing run.json snapshot is written
// after the on-disk diff is durable, never the other way around), then
// rewrite run.json one last time, and finally surface the suggestion.
// A failure on any step except the lifecycle transition is logged via
// UserOutput (when set) but does NOT change the terminal: the plan
// treats post-terminal artifacts as advisory.
//
// driveTerminalSequence may have already written some of these
// transitions; in that case Transition returns an error which we
// silently swallow because the machine is already at the desired state
// (or a related one that wins by being terminal). The closing run.json
// snapshot is unconditional: it is the record an operator inspects
// after the fact, and a failure to write it is non-fatal because the
// per-transition snapshots already captured the state on disk.
func (s *Supervisor) finalizeTerminal(cause terminalCause, exit exitInfo) SupervisorResult {
	final := cause.state
	if final == "" {
		final = s.machine.Current()
	}
	// If the machine has not yet reached the terminal state (an early
	// setup failure, a launch failure, or a lifecycle write failure)
	// drive it there now and emit the corresponding lifecycle event so
	// the audit trail records the terminal even on the error paths.
	if s.machine.Current() != final {
		if err := s.machine.Transition(final); err == nil {
			_ = s.lcWri.Write(final)
		} else {
			// The transition was rejected (e.g. the machine is already
			// in a different terminal because Cancel won the race).
			// Land on whatever terminal the machine actually holds and
			// trust the recorded events; a confused operator is better
			// served by an honest record than by a forged one.
			final = s.machine.Current()
		}
	}

	if s.stoppedAt.IsZero() {
		s.stoppedAt = s.now()
	}
	reason := cause.reason
	if reason == "" {
		reason = StopReasonForState(final)
	}
	var codePtr *int
	if exit.hasCode {
		code := exit.code
		codePtr = &code
	}
	stopped := s.stoppedAt

	// Step 10 (collect partial diff): invoke the configured collector
	// against runDir/git-diff.patch with a context-bound timeout so a
	// stuck git process cannot block the supervisor's terminal walk.
	// The plan's "Collect partial diff if possible" rule treats the
	// diff as advisory; we surface collector failures via UserOutput
	// and via the supervisor's stderr equivalent but never escalate
	// them to a different terminal state. The file is always present
	// on disk after this call (it was created empty by
	// CreateRunDirectory; the helper overwrites it on success and
	// leaves the empty placeholder on the no-collector path).
	if err := collectPartialDiff(s.opts.RunDir, s.opts.DiffCollector, s.opts.DiffTimeout); err != nil {
		// Best-effort warning. Writing to UserOutput here is consistent
		// with how the supervisor surfaces the --continue hint below;
		// callers who left UserOutput nil simply do not see the
		// warning. Nothing else in the codebase consumes this string
		// today, so we keep the format human-readable rather than
		// inventing a structured event.
		if s.opts.UserOutput != nil {
			_, _ = fmt.Fprintf(s.opts.UserOutput, "ai-env: warning: partial diff collection failed: %v\n", err)
		}
	}

	// Closing run.json snapshot. Written after the partial diff lands
	// so the snapshot reflects the run's true post-diff state on disk;
	// a reader who opens run.json then git-diff.patch is guaranteed to
	// see the diff that corresponds to the recorded terminal. Failures
	// here are non-fatal: the per-transition snapshots already captured
	// the state on disk, so the operator still sees the run in its
	// terminal record even if this rewrite fails.
	_ = s.writeRecordSnapshot(final, codePtr, &reason, &stopped)

	// Print the `--continue` suggestion if the terminal supports it.
	// The exact line is the master plan's "ai-env run <env-name>
	// --continue"; we record it on the result so a programmatic caller
	// can surface the same text without scraping stdout. Non-eligible
	// terminals (StateCompleted, the failure states) get an empty
	// suggestion both on stdout (nothing printed) and on the result.
	suggestion := printContinueSuggestion(s.opts.UserOutput, s.opts.EnvName, final)

	return SupervisorResult{
		FinalState:         final,
		StopReason:         reason,
		ExitCode:           exit.code,
		HasExitCode:        exit.hasCode,
		StartedAt:          s.startedAt,
		StoppedAt:          s.stoppedAt,
		ContinueSuggestion: suggestion,
		PartialDiffPath:    GitDiffPath(s.opts.RunDir),
	}
}

// writeRecordSnapshot rewrites run.json with the latest state. The
// pointer arguments let the caller choose which optional fields to set
// for this snapshot: a setup-stage snapshot leaves exit code and stop
// reason nil; a terminal snapshot fills them in. The fields stamped
// once (run id, env, agent, etc.) are sourced from the supervisor
// options.
//
// A failure to write run.json is returned to the caller; the caller
// decides whether it is fatal (lifecycle stage transitions) or a soft
// warning (terminal snapshots).
func (s *Supervisor) writeRecordSnapshot(state State, exitCode *int, stopReason *StopReason, stoppedAt *time.Time) error {
	var startedAtPtr *time.Time
	if !s.startedAt.IsZero() {
		t := s.startedAt
		startedAtPtr = &t
	}
	rec := Record{
		RunID:               s.opts.RunID,
		EnvName:             s.opts.EnvName,
		Agent:               s.opts.Agent,
		Task:                s.opts.Task,
		State:               state,
		ExitCode:            exitCode,
		StartedAt:           startedAtPtr,
		StoppedAt:           stoppedAt,
		StopReason:          stopReason,
		Backend:             s.opts.Backend,
		ModelCredentialMode: s.opts.ModelCredentialMode,
		ReducedSafety:       s.opts.ReducedSafety,
		LinkedPreviousRun:   s.opts.LinkedPreviousRun,
	}
	return WriteRecord(s.opts.RunDir, rec)
}

// stopChildGracefully asks the child process to terminate, waits the
// configured grace period for it to exit on its own, and then escalates
// to a hard kill if the child is still running.
//
// This is the path the cancel / timeout / idle terminals use to bring
// the child down. Step 9 (signal handling) will reuse the same helper
// when an OS signal arrives; keeping it in one place means there is
// one piece of code to audit for the kill semantics.
//
// stopChildGracefully does NOT call Wait; launchChild owns the single
// Wait goroutine. We observe child exit via the shared childDone
// channel, which the waiter closes after Wait returns.
func (s *Supervisor) stopChildGracefully() {
	s.childMu.Lock()
	c := s.child
	done := s.childDone
	s.childMu.Unlock()
	if c == nil || c.Process == nil {
		return
	}
	// SIGINT is the polite ask. signalInterrupt is the platform-
	// specific Signal value; on POSIX it is os.Interrupt.
	_ = signalChild(c, signalInterrupt)
	// Wait the grace window for the child to exit. If it does, the
	// childDone channel closes and we exit promptly. If it does not,
	// we escalate to a hard kill (the waiter goroutine still reaps
	// the child afterwards, so callers blocking on childDone unblock
	// regardless).
	t := time.NewTimer(s.opts.StopGracePeriod)
	defer t.Stop()
	select {
	case <-t.C:
		s.hardKillChild()
	case <-done:
	}
}

// hardKillChild forces the child down with SIGKILL (or its Windows
// equivalent). Used after the grace window in stopChildGracefully and
// in error paths that cannot afford to wait.
func (s *Supervisor) hardKillChild() {
	s.childMu.Lock()
	c := s.child
	s.childMu.Unlock()
	if c == nil || c.Process == nil {
		return
	}
	_ = c.Process.Kill()
}

// waitChild blocks until the child exits and returns the exit code.
// Used only by the error fallback in Run (a lifecycle failure between
// launch and StateRunning). It reads off the same waiter the runLoop
// uses, so calling it does not race with Wait.
func (s *Supervisor) waitChild() (int, error) {
	s.childMu.Lock()
	c := s.child
	done := s.childDone
	s.childMu.Unlock()
	if c == nil {
		return -1, errors.New("run: no child to wait on")
	}
	if done != nil {
		<-done
	}
	s.childMu.Lock()
	st := c.ProcessState
	werr := s.childErr
	s.childMu.Unlock()
	if st != nil && st.Exited() {
		return st.ExitCode(), werr
	}
	return -1, werr
}
