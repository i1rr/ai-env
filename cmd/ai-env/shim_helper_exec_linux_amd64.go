//go:build linux && amd64

package main

// sysExecveat is the execveat(2) syscall number on linux/amd64.
//
// We pin the value here rather than referencing syscall.SYS_EXECVEAT
// because the Go stdlib does not define that constant for amd64 in
// every release. The kernel ABI is stable: 322 has been the amd64
// execveat number since the syscall was introduced in Linux 3.19, so
// the local pin will not drift.
const sysExecveat = 322
