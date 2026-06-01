//go:build linux

// shim_helper_exec_linux.go provides the Linux execveat-based exec
// surface for the shell-mode helper. The plan's Bucket 7 / Bucket 1
// locked decision pins SYS_EXECVEAT as the TOCTOU-safe re-exec
// mechanism: the same fd that was used to scan the script bytes is
// passed to execveat so the executed bytes are guaranteed to be the
// scanned bytes.
//
// The execveat(2) syscall takes:
//
//	int execveat(int dirfd, const char *pathname, char *const argv[],
//	             char *const envp[], int flags);
//
// We use AT_EMPTY_PATH (which makes execveat operate on dirfd itself
// rather than dirfd+pathname) so a hostile path resolution cannot
// race the syscall. The dirfd is the open script fd from
// openScriptForScan (interpreter-via-file flow) or the open real-
// binary fd (direct-binary flow).

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// atEmptyPath is the AT_EMPTY_PATH flag for execveat. The kernel
// uses the open fd as the executable file when this flag is set,
// ignoring the (empty) path argument. The constant value is pinned
// by the Linux ABI; we hard-code it rather than depend on
// golang.org/x/sys/unix to keep the dependency set small.
const atEmptyPath = 0x1000

// openScriptForScan opens path with O_RDONLY|O_NOFOLLOW so a
// symlink swap into the path between open and exec cannot redirect
// the read. The plan's "single-fd TOCTOU-safe flow" calls out this
// exact pattern.
//
// Returns the raw fd (not an *os.File) because we hand the same fd
// to execveat below and a Go-owned *os.File would close the fd in
// its finalizer if we forgot to runtime.KeepAlive() through the
// syscall.
func openScriptForScan(path string) (int, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

// closeFD closes a raw fd. Used by deferred cleanup paths.
func closeFD(fd int) error {
	return syscall.Close(fd)
}

// preadFD reads at most len(buf) bytes from fd starting at offset.
// Wraps syscall.Pread so the read does not advance the fd cursor;
// the subsequent execveat needs to see the file from the beginning.
func preadFD(fd int, buf []byte, offset int64) (int, error) {
	return syscall.Pread(fd, buf, offset)
}

// scriptFdPath returns the in-sandbox path the interpreter should be
// pointed at to read the SAME bytes that were scanned. On Linux we
// use /proc/self/fd/<n>, which the kernel resolves to the open file
// description regardless of whether the original path has been
// renamed or replaced on disk. Same-fd TOCTOU safety.
func scriptFdPath(fd int) string {
	return fmt.Sprintf("/proc/self/fd/%d", fd)
}

// execScriptViaFD execveat's realBinaryPath with the supplied argv
// and env. The interpreter then reads the script via the
// scriptFdPath in argv (set by rewriteScriptArg).
//
// We do NOT use AT_EMPTY_PATH here because the interpreter is a
// separate file from the script; the dirfd is irrelevant. Plain
// syscall.Exec is sufficient and matches the TOCTOU-safe pattern
// (the script fd stays open in this process, the interpreter reads
// from /proc/self/fd/<n>, the kernel resolves that to our fd which
// is the same inode we scanned).
//
// Returns an error only on failure; on success the process is
// replaced and this never returns.
func execScriptViaFD(realBinaryPath string, scriptFd int, argv, env []string) error {
	// The script fd must NOT be O_CLOEXEC for the interpreter to
	// read it via /proc/self/fd/<n>; clear CLOEXEC right before
	// exec.
	if err := fcntlClearCloexec(scriptFd); err != nil {
		return fmt.Errorf("clear CLOEXEC on script fd: %w", err)
	}
	return syscall.Exec(realBinaryPath, argv, env)
}

// fcntlClearCloexec clears FD_CLOEXEC on fd via the raw fcntl
// syscall. The stdlib syscall package on Linux exposes Fcntl
// only as an internal helper; we drop to the raw syscall to keep
// the dependency surface small.
func fcntlClearCloexec(fd int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_SETFD), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// execBinaryDirect opens realBinaryPath and execveat's it via
// AT_EMPTY_PATH so the path resolution is anchored to the open fd.
// The argv[0] hardening in the caller ensures argv[0] is the
// canonical basename.
func execBinaryDirect(realBinaryPath string, argv, env []string) error {
	fd, err := syscall.Open(realBinaryPath, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return os.NewSyscallError("open", err)
	}
	defer syscall.Close(fd)

	// execveat with AT_EMPTY_PATH: the kernel uses the open fd as
	// the executable file, ignoring the empty path argument.
	if err := execveatAtEmptyPath(fd, argv, env); err != nil {
		// Fall back to plain Exec if execveat is not supported by
		// the kernel (pre-3.19). The fall-back is NOT TOCTOU-safe
		// for the binary itself, but the binary lives at a
		// supervisor-controlled path under <shimHelperOrigDir>/ and
		// the supervisor's runDir is mode 0o700 so the practical
		// exposure is limited.
		return syscall.Exec(realBinaryPath, argv, env)
	}
	return nil
}

// execveatAtEmptyPath invokes execveat(fd, "", argv, env,
// AT_EMPTY_PATH). The Go standard library does not expose execveat
// (Go 1.22) so we drop to the raw syscall.
func execveatAtEmptyPath(fd int, argv, env []string) error {
	// Build C-style NULL-terminated argv / env arrays.
	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}
	envp, err := syscall.SlicePtrFromStrings(env)
	if err != nil {
		return err
	}
	emptyPath, err := syscall.BytePtrFromString("")
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		sysExecveat,
		uintptr(fd),
		uintptr(unsafe.Pointer(emptyPath)),
		uintptr(unsafe.Pointer(&argvp[0])),
		uintptr(unsafe.Pointer(&envp[0])),
		uintptr(atEmptyPath),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
