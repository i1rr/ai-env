package run

import (
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
)

// signalInterrupt is the polite-stop request the supervisor sends to a
// running child before escalating to a hard kill. Defined as a package-
// level variable so platform-specific files (a future Windows port)
// can swap in the appropriate constant without touching call sites.
// On POSIX hosts it is os.Interrupt (SIGINT), which is what the plan's
// signal-handling step (step 9) will forward when the user hits ^C.
var signalInterrupt os.Signal = os.Interrupt

// signalChild sends sig to the given exec.Cmd's process. It is a thin
// wrapper around c.Process.Signal that defends against nil Process
// (the child was never started or has already been reaped) so the
// supervisor's stop path is robust against being called twice.
//
// Returns the underlying Signal error so the caller can log it; the
// supervisor today ignores the result because a signal failure is
// usually "process already exited", which is exactly the state the
// caller wanted anyway.
func signalChild(c *exec.Cmd, sig os.Signal) error {
	if c == nil || c.Process == nil {
		return nil
	}
	return c.Process.Signal(sig)
}

// supervisedSignals is the canonical set of OS signals the supervisor's
// host-side handler reacts to. The plan (plan 03 "Decisions from master
// plan") names exactly three:
//
//   - SIGINT  : forward to agent, wait grace period, then stop.
//   - SIGTERM : forward to agent, wait grace period, then stop.
//   - SIGHUP  : mark interrupted, stop if non-interactive.
//
// All three reduce to "route into the supervisor's Cancel() hook" in
// this batch: Cancel records StateKilledByUser as the intended terminal
// and triggers the supervisor's existing graceful-stop path, which
// already forwards SIGINT to the child and escalates to SIGKILL after
// the configured StopGracePeriod (the "wait grace period, then stop"
// part). SIGHUP's "stop if non-interactive" disposition collapses onto
// the same Cancel because the supervisor is a non-interactive process
// in v0.1.
//
// Defined as a package-level slice so a test or a future platform port
// can read it without re-deriving the set; the handler installs them
// via signal.Notify(ch, supervisedSignals...).
var supervisedSignals = []os.Signal{
	syscall.SIGINT,
	syscall.SIGTERM,
	syscall.SIGHUP,
}

// SupervisedSignals returns the set of OS signals the supervisor's
// host-side handler reacts to. The slice is freshly allocated so the
// caller may sort or mutate it without affecting the handler.
//
// The function exists so tests and external callers (a future CLI that
// wants to surface "we trap these signals" in --help) can discover the
// set without copying the literal from supervisor_signal.go.
func SupervisedSignals() []os.Signal {
	out := make([]os.Signal, len(supervisedSignals))
	copy(out, supervisedSignals)
	return out
}

// signalHandlerChanBuffer is the buffer size of the channel that
// signal.Notify writes into. The Go runtime drops signals when the
// channel is full; one slot per supervised signal plus headroom for a
// repeat (e.g. user mashing ^C) is enough for our delivery semantics
// without forcing the runtime to drop signals it queued back to back.
const signalHandlerChanBuffer = 4

// InstallSignalHandlers wires OS signal delivery into sup.Cancel() for
// the lifetime of the returned stop function. While the handlers are
// installed, the process's default behavior for SIGINT, SIGTERM, and
// SIGHUP is suppressed; on stop(), the previous default behavior is
// restored via signal.Stop and signal.Reset.
//
// Contract:
//
//   - SIGINT, SIGTERM, SIGHUP are all routed into sup.Cancel(). Cancel
//     records the intended terminal as StateKilledByUser /
//     StopReasonSignal and triggers the supervisor's existing graceful
//     stop path (forward SIGINT to the child, wait StopGracePeriod,
//     escalate to SIGKILL). The supervisor's cancellation event is the
//     same the rest of the code records; no new lifecycle event is
//     invented for "a signal arrived".
//
//   - The handler goroutine drains the channel for the lifetime of the
//     returned stop. A second signal that arrives after Cancel has
//     already fired collapses through sup.Cancel()'s sync.Once and
//     becomes a no-op; this is intentional, the supervisor's loop is
//     already on the way down.
//
//   - stop() is idempotent and safe to call from any goroutine. It
//     calls signal.Stop on the channel (so the runtime stops delivering
//     supervised signals to it), closes the internal channel, and waits
//     for the handler goroutine to exit. After stop() returns, no
//     goroutine spawned by InstallSignalHandlers is still alive: this
//     is what lets tests install handlers across many runs without
//     leaking goroutines. The runtime's default disposition for a
//     supervised signal is restored automatically once no channel
//     remains registered for it; stop() does NOT call signal.Reset
//     because Reset would clobber any other handlers a different
//     subsystem in the same process registered.
//
//   - Installation is safe to interleave across multiple supervisors:
//     each call creates its own channel and its own handler goroutine.
//     Stopping one set of handlers does not affect another. (Two
//     concurrent sets would both receive every signal; production
//     callers install at most one set per process, which is the
//     `ai-env run` invocation.)
//
//   - Returns a non-nil error only if sup is nil. signal.Notify itself
//     never errors; the error return is reserved for misuse and for
//     future platform ports that may need to validate the signal set
//     up front.
//
// Example (the `ai-env run` command will use this shape):
//
//	stop, err := run.InstallSignalHandlers(sup)
//	if err != nil { return err }
//	defer stop()
//	result, err := sup.Run(ctx)
func InstallSignalHandlers(sup *Supervisor) (stop func(), err error) {
	if sup == nil {
		return nil, errNilSupervisor
	}
	ch := make(chan os.Signal, signalHandlerChanBuffer)
	signal.Notify(ch, supervisedSignals...)

	var stopOnce sync.Once
	done := make(chan struct{})

	// The handler goroutine routes every received signal into Cancel.
	// It exits when the channel is closed by stop(): signal.Stop drains
	// no further deliveries to ch, and the explicit close terminates
	// the for-range, after which the goroutine signals done.
	go func() {
		defer close(done)
		for sig := range ch {
			// Cancel collapses repeats through its own sync.Once, so a
			// second SIGINT (or any later signal) is a no-op at the
			// supervisor level. The handler still drains the channel
			// for those repeats so signal.Notify does not start
			// dropping queued deliveries; we just have nothing more to
			// do at the Cancel layer.
			_ = sig
			sup.Cancel()
		}
	}()

	stop = func() {
		stopOnce.Do(func() {
			// Stop telling the runtime to deliver supervised signals to
			// ch. After this call returns the runtime will not write any
			// more values into ch; this is the precondition for closing
			// ch without racing the runtime's send path. signal.Stop is
			// preferred over signal.Reset here because Reset clobbers
			// every channel any code in the process registered for these
			// signals, while Stop only detaches our own channel. The
			// runtime restores the process's default disposition on its
			// own once no channel remains registered for a given signal.
			signal.Stop(ch)
			close(ch)
			<-done
		})
	}
	return stop, nil
}

// errNilSupervisor is the sentinel returned by InstallSignalHandlers
// when its sup argument is nil. Exposed as a package-level value so
// tests can assert via errors.Is without coupling to a string match.
var errNilSupervisor = &nilSupervisorError{}

// nilSupervisorError is the concrete error type for errNilSupervisor.
// Implemented as a struct (rather than a bare errors.New) so future
// callers can errors.As against the type if they want to special-case
// the misuse beyond the sentinel comparison.
type nilSupervisorError struct{}

// Error implements the error interface. Message format is stable; tests
// match on it via errors.Is(err, errNilSupervisor).
func (e *nilSupervisorError) Error() string {
	return "run: InstallSignalHandlers: nil supervisor"
}
