//go:build !linux

package nflog

import "context"

// platformSourceFactory is nil on non-Linux hosts: the NFLOG
// observer cannot bind a netlink socket on a kernel that does not
// have NETLINK_NETFILTER. `Observer.Start` checks for nil and
// returns `ErrUnsupportedOS` so the supervisor's "skip + emit
// observer_unavailable" path engages without an OS-specific
// branch at the call site.
var platformSourceFactory func(ctx context.Context, opts Options) (kernelSource, error)
