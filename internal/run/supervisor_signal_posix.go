//go:build !windows

package run

import (
	"os"
	"os/exec"
	"syscall"
)

// applyProcessGroup configures cmd so the child runs in its own
// process group whose pgid equals the child's pid. This is the
// precondition for signaling the full child + grandchildren tree via
// signalChildGroup below.
//
// Why this matters: a child like `sh -c "sleep 5"` is often a shell
// that fork+execs the inner command (bash on macos, busybox on some
// distros, etc). If the supervisor signals only the shell's pid, the
// inner command stays alive after the shell exits and continues
// holding the supervisor's stdout pipe open. cmd.Wait then blocks
// until the inner command exits naturally, which is the 5.01s "Run
// took 5s" symptom the slow-runner CI surfaces. Putting the shell in
// its own process group and signaling the group reliably terminates
// both shell and the inner command.
//
// Setpgid is a POSIX-only construct; the windows-build counterpart in
// supervisor_signal_windows.go is a no-op and the call sites below
// fall back to per-pid signalling on that platform.
func applyProcessGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// signalChildGroup sends sig to every process in the child's process
// group. Requires applyProcessGroup to have run before cmd.Start; on
// success the child's pgid equals its pid so the group target
// translates to -pid (negative-pid Kill is the POSIX idiom for
// "deliver to every member of the group").
//
// Falls back to signalChild's per-pid delivery if the cmd was never
// started, the pid is unknown, or we cannot resolve a signal value to
// a syscall.Signal. The fallback preserves the legacy behavior so
// callers that never opt into Setpgid (a future code path that
// chooses single-pid mode) keep working.
//
// Returns the underlying syscall.Kill error; callers today ignore it
// because a non-existent group typically means "already exited",
// which is exactly the state the caller wanted.
func signalChildGroup(c *exec.Cmd, sig os.Signal) error {
	if c == nil || c.Process == nil {
		return nil
	}
	signum, ok := sig.(syscall.Signal)
	if !ok {
		return c.Process.Signal(sig)
	}
	// Negative pid targets the whole process group on POSIX. If the
	// group does not exist (Setpgid was not applied or every member
	// already exited) Kill returns ESRCH and the caller ignores it.
	if err := syscall.Kill(-c.Process.Pid, signum); err != nil {
		// Fall back to single-pid delivery so we still send the signal
		// somewhere when the group is gone. This is the path a child
		// running outside a group (Setpgid skipped) hits.
		return c.Process.Signal(sig)
	}
	return nil
}
