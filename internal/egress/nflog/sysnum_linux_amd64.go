//go:build linux && amd64

package nflog

// sysSetns is the setns(2) syscall number on linux/amd64.
//
// Pinned locally because syscall.SYS_SETNS is not defined for amd64
// in the Go stdlib (only certain Linux arches expose it). The amd64
// number 308 has been stable in the kernel ABI since setns landed in
// Linux 3.0, so the local pin will not drift.
const sysSetns = 308
