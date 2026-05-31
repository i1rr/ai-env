//go:build !linux

// shim_helper_exec_other.go provides the non-Linux exec surface for
// the shell-mode helper. macOS (darwin) and other POSIX systems do
// not have execveat(2); the plan's Bucket 7 locked decision pins the
// `/dev/fd/<n>` substitute. The same fd that was used to scan the
// script bytes is referenced via `/dev/fd/<n>` so the interpreter
// reads the bytes the helper scanned; this is TOCTOU-safe on
// filesystems that expose /dev/fd, which is the macOS default.
//
// The Plan's platform-matrix documents the residual TOCTOU window on
// filesystems without /dev/fd; the shell helper logs the platform on
// the helper-rpc-aborted lifecycle record so an operator can spot
// the degraded mode.

package main

import (
	"fmt"
	"os"
	"syscall"
)

// fcntlClearCloexec clears the FD_CLOEXEC flag on fd via raw fcntl
// syscall. The stdlib `syscall` package does not export a stable
// FcntlInt across platforms; we drop to the raw syscall to keep the
// helper portable.
func fcntlClearCloexec(fd int) error {
	const fSetFD = 2 // POSIX F_SETFD
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(fSetFD), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// atEmptyPath is unused on non-Linux but defined for parity so the
// shared shell-mode helper can reference it without per-platform
// guards in the call site. The value matches the Linux constant for
// consistency.
const atEmptyPath = 0x1000

// openScriptForScan opens path with O_RDONLY|O_NOFOLLOW. Same
// rationale as the Linux variant: a symlink swap into path between
// open and exec cannot redirect the read.
func openScriptForScan(path string) (int, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

// closeFD closes a raw fd.
func closeFD(fd int) error {
	return syscall.Close(fd)
}

// preadFD reads from fd at offset. macOS supports pread; we use it
// to avoid moving the fd cursor before the exec.
func preadFD(fd int, buf []byte, offset int64) (int, error) {
	return syscall.Pread(fd, buf, offset)
}

// scriptFdPath returns the /dev/fd/<n> path the interpreter reads.
// macOS resolves /dev/fd entries via the fdesc filesystem (mounted
// by default).
func scriptFdPath(fd int) string {
	return fmt.Sprintf("/dev/fd/%d", fd)
}

// execScriptViaFD execs realBinaryPath with the supplied argv, which
// already contains the /dev/fd/<n> path for the script argument.
// The fd's CLOEXEC bit is cleared so the interpreter inherits the
// open file description.
func execScriptViaFD(realBinaryPath string, scriptFd int, argv, env []string) error {
	if err := fcntlClearCloexec(scriptFd); err != nil {
		return fmt.Errorf("clear CLOEXEC on script fd: %w", err)
	}
	return syscall.Exec(realBinaryPath, argv, env)
}

// execBinaryDirect execs realBinaryPath with the supplied argv. The
// non-Linux helper does NOT have execveat; the fall-back is a plain
// syscall.Exec by path. The plan's "residual TOCTOU on macOS" note
// covers this case.
func execBinaryDirect(realBinaryPath string, argv, env []string) error {
	if _, err := os.Stat(realBinaryPath); err != nil {
		return os.NewSyscallError("stat", err)
	}
	return syscall.Exec(realBinaryPath, argv, env)
}
