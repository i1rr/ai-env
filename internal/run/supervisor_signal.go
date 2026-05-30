package run

import (
	"os"
	"os/exec"
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
