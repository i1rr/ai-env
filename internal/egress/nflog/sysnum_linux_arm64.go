//go:build linux && arm64

package nflog

// sysSetns is the setns(2) syscall number on linux/arm64. Pinned
// locally so the source does not depend on syscall.SYS_SETNS, whose
// stdlib coverage is uneven across Linux arches. 268 has been the
// arm64 setns number since the syscall was introduced.
const sysSetns = 268
