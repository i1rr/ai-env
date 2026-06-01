//go:build linux && arm64

package main

// sysExecveat is the execveat(2) syscall number on linux/arm64.
// Pinned locally so the source does not depend on
// syscall.SYS_EXECVEAT, which the Go stdlib only exposes for a subset
// of Linux architectures. 281 has been the arm64 execveat number
// since the syscall was introduced.
const sysExecveat = 281
