//go:build !darwin

package pflog

import "context"

// platformSourceFactory is nil on non-Darwin hosts: the pflog
// observer cannot bind to a BPF interface on a non-macOS kernel.
// `Observer.Start` checks for nil and returns `ErrUnsupportedOS`
// so the supervisor's "skip + emit observer_unavailable" path
// engages without an OS-specific branch at the call site.
var platformSourceFactory func(ctx context.Context, opts Options) (kernelSource, error)
