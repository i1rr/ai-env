//go:build windows

package run

import (
	"os"
	"os/exec"
	"syscall"
)

// applyProcessGroup is a no-op on windows. Setpgid does not exist on
// that platform; the windows code path falls back to per-pid signal
// delivery via signalChildGroup below.
func applyProcessGroup(cmd *exec.Cmd) {
	// no-op on windows
}

// signalChildGroup on windows degrades to per-pid delivery. SIGKILL
// is routed through c.Process.Kill (which on windows calls
// TerminateProcess) because Process.Signal does not implement SIGKILL
// on that platform; every other signal value falls through to the
// shared signalChild helper.
func signalChildGroup(c *exec.Cmd, sig os.Signal) error {
	if c == nil || c.Process == nil {
		return nil
	}
	if sig == syscall.SIGKILL {
		return c.Process.Kill()
	}
	return signalChild(c, sig)
}
