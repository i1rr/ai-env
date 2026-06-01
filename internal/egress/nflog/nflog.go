// Package nflog implements the Linux NFLOG variant of the
// `egress.EgressObserver` interface declared in Plan Batch 5.1.
//
// The observer attaches to the netfilter log multicast group the
// rule-installer (Plan Batch 5.4, `egress/rules`) binds to via
// `--nflog-group <n>`. The NFLOG protocol is part of the
// `NETLINK_NETFILTER` (subsystem id 5, family `NFNL_SUBSYS_ULOG`)
// netlink family on Linux 2.6.14+. Each packet matched by an
// iptables `-j NFLOG --nflog-group <n>` rule is mirrored to user
// space as a `nfgenmsg` framed inside a netlink message; the
// observer parses the frame's TLV attributes for the captured IP /
// TCP / UDP header bytes and forwards a structured `Event` to the
// constructor-supplied `Sink`.
//
// Plan locks the package to two callers:
//
//   - The supervisor at §5.5 step 5: builds the observer with the
//     run's per-run chain name (`AIENV-EGR-<8hex>`), the run-derived
//     NFLOG group id, the per-run sandbox netns path, and the
//     network-events writer sink. The supervisor calls `Start` once
//     and `Stop` once at teardown step 4. The observer itself does
//     NOT install the iptables rules; that is `egress/rules`'s job
//     and the two halves agree only on the chain name (and the
//     group id the rules target).
//
//   - The `egress.ChooseObserver` factory: returns this adapter on
//     Linux when `capability.ObserverModeAvailable()` is true.
//
// Design rules (mirrored from `internal/egress` package doc):
//
//   - No I/O at construction. `New` validates options and returns
//     an observer; no sockets are opened, no goroutine is started.
//     `Start` does both.
//
//   - The platform-specific kernel attach lives behind a build tag.
//     This file (`nflog.go`) holds the cross-platform contract:
//     `Observer`, `Options`, `New`, `Mode`, `Chain`. The Linux-only
//     `nflog_linux.go` file holds the actual netlink socket wiring
//     and is built only on `GOOS=linux`. The non-Linux stub
//     (`nflog_other.go`) returns `egress.ObserverUnsupportedOSError`
//     from `Start` so a macOS developer machine still compiles the
//     package and the supervisor's call site stays unconditional.
//
//   - The sink is the only event-delivery surface. The observer
//     does not write to disk directly; the supervisor wires the
//     sink to `run.NetworkEventsWriter.Write` so all per-run JSONL
//     writers share one append/sync path.
//
//   - Tests use a fake kernel source. The package exposes
//     `SetKernelSourceForTest` (in tests only via the `_test.go`
//     file) so a test can stub the netlink read loop without root.
//     The plan's "no root in CI" constraint requires this.
//
// The package depends only on the standard library and
// `internal/egress` (for the `EgressObserver` interface and the
// shared "unsupported os" error sentinel).
package nflog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Mode is the short token the supervisor records in
// `observer_started` Metadata. Plan Batch 0.1 locks `"nflog"` as the
// canonical value; the constant lives here so a future eBPF variant
// (a separate package) can pick its own token without renaming this
// one.
const Mode = "nflog"

// MaxNFLOGGroupID is the upper bound on the NFLOG group id the
// kernel accepts. The netfilter ULOG family uses a 16-bit group id;
// the supervisor derives the per-run id from the run's id so
// concurrent runs do not collide.
const MaxNFLOGGroupID = 0xFFFF

// Options bundles every per-run input the observer needs at
// construction. The supervisor populates this struct once at
// §5.5 step 5 from the run's metadata; the observer copies the
// fields onto its own struct so a caller can mutate the source
// after `New` returns without affecting the running observer.
type Options struct {
	// Chain is the per-run iptables chain name the rule installer
	// (Plan Batch 5.4) installs the `-j NFLOG` rule into. Format:
	// `AIENV-EGR-<8hex>`. The observer does NOT touch iptables; it
	// only carries the name so `EgressObserver.Chain()` matches the
	// rule installer's view.
	Chain string

	// GroupID is the NFLOG `--nflog-group` the rule installer
	// targets and the observer binds. Must be 0..MaxNFLOGGroupID.
	// Plan derives it from the run id (lower 16 bits of the hex
	// chain suffix) so the rule installer and the observer agree
	// without a separate handshake.
	GroupID uint16

	// NetNSPath is the absolute path to the sandbox network
	// namespace (`/proc/<pid>/ns/net` for the backend's pid). The
	// Linux observer enters this netns via `setns(2)` before
	// binding the netlink socket so the captured packets come from
	// the sandbox, not the supervisor's namespace. Empty means
	// "use the current netns"; the supervisor passes the sandbox
	// path so the observer captures the right traffic.
	NetNSPath string

	// Sink is the per-event delivery function. The observer calls
	// Sink synchronously from its background goroutine for every
	// parsed packet; a Sink that blocks blocks the reader, so the
	// supervisor's writer wrapper applies a bounded queue. Sink
	// MUST NOT be nil; `New` rejects an empty value.
	Sink func(Event)

	// OnError is an optional per-error callback. The observer
	// invokes it for non-fatal parse errors (a malformed netlink
	// message, an unknown attribute) so the supervisor can log
	// them via the lifecycle writer. nil is tolerated: errors are
	// silently dropped when the supervisor does not care about the
	// per-error breakdown.
	OnError func(error)
}

// Event is the structured packet record the observer hands to the
// Sink. The shape is intentionally narrow: every field is one of
// the things the supervisor's `network-events.jsonl` schema
// (Plan §5.5 step 5 observer wiring) needs. Per-packet payload
// bytes are NOT carried; the observer captures only the 5-tuple
// plus a verdict so the on-disk record stays bounded.
type Event struct {
	// Protocol is the IP layer-4 protocol name ("tcp" / "udp" /
	// "icmp" / "other"). Anything the parser does not recognise
	// falls through to "other"; a future caller that needs a
	// numeric protocol can add a field without breaking decoders.
	Protocol string

	// SrcIP / DstIP are the captured packet's source / destination
	// IP addresses, rendered as the canonical "1.2.3.4" / "::1"
	// strings. Empty when the parser could not extract them (a
	// fragmented packet or a non-IPv4/v6 frame); the supervisor's
	// writer skips empty-destination events.
	SrcIP string
	DstIP string

	// SrcPort / DstPort are the layer-4 port numbers when the
	// protocol carries them (tcp / udp); zero for icmp / other.
	SrcPort uint16
	DstPort uint16

	// Verdict is the NFLOG action token the kernel applied. The
	// canonical values are "accept" / "drop"; an empty string
	// means the kernel did not report a verdict (e.g. the rule
	// was `LOG` rather than `NFLOG` with a verdict). The
	// supervisor's `outbound_blocked` / `outbound_allowed` event
	// mapping uses this field.
	Verdict string
}

// Observer is the Linux NFLOG implementation of
// `egress.EgressObserver`. The cross-platform fields and the
// lifecycle bookkeeping live in this file; the actual netlink
// socket attach lives in `nflog_linux.go` (build-tagged).
type Observer struct {
	// opts is the validated set of construction options. We store
	// a copy rather than a pointer so a caller mutating the
	// original `Options` after `New` returns cannot affect the
	// running observer.
	opts Options

	// mu serializes Start/Stop so a buggy caller cannot start an
	// already-started observer or stop one twice concurrently.
	// The mutex also protects the started / stopped flags so the
	// idempotence guarantee `Stop` documents is honoured.
	mu sync.Mutex

	// started is true after a successful `Start`. A second
	// `Start` call on a started observer is an error so a caller
	// double-attaching does not silently leak a goroutine.
	started bool

	// stopped is true after `Stop` returns. A second `Stop` call
	// is a no-op (plan's idempotence requirement).
	stopped bool

	// cancel cancels the background reader goroutine started by
	// `Start`. Set by `Start`, called by `Stop`. nil before
	// `Start` is called.
	cancel context.CancelFunc

	// done is closed by the reader goroutine on exit so `Stop`
	// can block until the goroutine has drained pending events.
	// The plan's `Stop` contract says "returns only after the
	// background goroutine has drained pending events".
	done chan struct{}

	// source is the kernel-attach surface the goroutine reads
	// from. On Linux this is a real netlink connection; in tests
	// (via `SetKernelSourceForTest`) it is a fake that replays a
	// fixed sequence of frames. The interface keeps the
	// production code path identical to the test path so a
	// regression in the parser is caught without root.
	source kernelSource

	// sourceFactory builds a kernel source for the current
	// platform. Set by the Linux build-tag init; replaced by
	// tests via `SetKernelSourceForTest`. nil means "the current
	// platform has no real kernel source" and `Start` returns
	// `ErrUnsupportedOS`.
	sourceFactory func(ctx context.Context, opts Options) (kernelSource, error)
}

// kernelSource is the per-platform contract the reader goroutine
// depends on. The real Linux implementation wraps a netlink socket
// bound to NETLINK_NETFILTER + NFNL_SUBSYS_ULOG; the test fake is
// an in-memory queue. Keeping the interface narrow (Read + Close)
// means the reader loop is identical across platforms.
type kernelSource interface {
	// Read returns the next decoded Event or an error. A clean
	// shutdown returns `io.EOF`; a transient parse error returns
	// a non-EOF error so the reader can log it and continue.
	// Implementations MUST honour ctx cancellation: a cancelled
	// ctx returns ctx.Err() so the reader loop exits promptly.
	Read(ctx context.Context) (Event, error)

	// Close releases the underlying socket / handle. Idempotent.
	// The reader goroutine calls Close on the way out so the
	// kernel surface is released exactly once.
	Close() error
}

// ErrUnsupportedOS is returned from `Start` on a host where the
// NFLOG observer cannot run (anything not Linux). The supervisor
// pairs this with the configured `EgressObserverMode` to decide
// whether to abort (strict) or degrade (auto).
var ErrUnsupportedOS = errors.New("egress/nflog: unsupported_os")

// ErrAlreadyStarted is returned from `Start` when the observer is
// already running. Callers should not double-attach; this error
// surfaces the regression at the call site rather than silently
// leaking a goroutine.
var ErrAlreadyStarted = errors.New("egress/nflog: observer already started")

// New constructs an NFLOG observer from the supplied options. It
// validates the required fields and returns an error rather than
// panicking on a misconfigured caller; no kernel surface is
// opened.
//
// `New` does not start the observer; the supervisor calls
// `Start(ctx)` once after `New` returns successfully.
func New(opts Options) (*Observer, error) {
	if opts.Chain == "" {
		return nil, errors.New("egress/nflog: New requires Chain")
	}
	if opts.Sink == nil {
		return nil, errors.New("egress/nflog: New requires Sink")
	}
	if int(opts.GroupID) > MaxNFLOGGroupID {
		return nil, fmt.Errorf("egress/nflog: GroupID %d exceeds MaxNFLOGGroupID %d", opts.GroupID, MaxNFLOGGroupID)
	}
	return &Observer{
		opts:          opts,
		sourceFactory: platformSourceFactory,
	}, nil
}

// Mode returns the lifecycle-event metadata token the supervisor
// records in `observer_started`. Plan Batch 0.1: `"nflog"`.
func (o *Observer) Mode() string { return Mode }

// Chain returns the per-run iptables chain name the observer's
// rule-installer counterpart targets. Plan Batch 5.4 installs the
// `-j NFLOG --nflog-group <GroupID>` rule into this chain.
func (o *Observer) Chain() string { return o.opts.Chain }

// Start binds the netlink socket inside the sandbox netns and
// launches the background reader goroutine. It returns once the
// kernel surface is ready; the goroutine then forwards events to
// the Sink until `Stop` is called or `ctx` is cancelled.
//
// On non-Linux hosts `Start` returns `ErrUnsupportedOS` and does
// not start a goroutine.
//
// A double-`Start` on an already-running observer returns
// `ErrAlreadyStarted`; this surfaces a regression at the call site
// rather than silently double-attaching.
func (o *Observer) Start(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.started {
		return ErrAlreadyStarted
	}
	if o.sourceFactory == nil {
		return ErrUnsupportedOS
	}

	runCtx, cancel := context.WithCancel(ctx)
	src, err := o.sourceFactory(runCtx, o.opts)
	if err != nil {
		cancel()
		return fmt.Errorf("egress/nflog: open kernel source: %w", err)
	}
	o.source = src
	o.cancel = cancel
	o.done = make(chan struct{})
	o.started = true

	go o.run(runCtx)
	return nil
}

// Stop tears down the netlink socket and waits for the background
// reader to drain pending events. Idempotent: a second call is a
// no-op. Safe to call before `Start` (returns nil so the
// supervisor's teardown path can call `Stop` unconditionally).
func (o *Observer) Stop() error {
	o.mu.Lock()
	if !o.started || o.stopped {
		o.stopped = true
		o.mu.Unlock()
		return nil
	}
	o.stopped = true
	cancel := o.cancel
	done := o.done
	source := o.source
	o.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if source != nil {
		// Closing the source unblocks any in-flight Read so the
		// goroutine exits promptly even when the netlink read
		// would otherwise sit in `recvfrom`.
		_ = source.Close()
	}
	if done != nil {
		<-done
	}
	return nil
}

// run is the background reader goroutine. It loops over
// `source.Read`, forwards every event to the Sink, and exits when
// the context is cancelled, the source returns `io.EOF`, or
// `source.Read` returns a fatal error.
//
// Transient parse errors are reported via `OnError` (when
// configured) and the loop continues; the plan locks "best-effort
// under non-compromised agent" so a single bad frame must not
// blow up the whole observer.
func (o *Observer) run(ctx context.Context) {
	defer close(o.done)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		evt, err := o.source.Read(ctx)
		if err != nil {
			if isReaderShutdown(err) {
				return
			}
			if o.opts.OnError != nil {
				o.opts.OnError(err)
			}
			// Transient errors fall through; the loop tries
			// again. A genuinely broken source surfaces as a
			// shutdown error on the next read (the netlink
			// socket close maps to EBADF / EINTR).
			continue
		}
		// Synchronous Sink call; the supervisor's writer wrapper
		// applies bounded queuing so a slow disk does not stall
		// the reader indefinitely.
		o.opts.Sink(evt)
	}
}

// isReaderShutdown reports whether err is a "stop reading" signal:
// context cancellation, EOF, or a closed-source error. Centralized
// so a future kernel source can plug its own shutdown sentinel in
// without scattering the check.
func isReaderShutdown(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, errReaderClosed) {
		return true
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	return false
}

// errReaderClosed is the sentinel a kernel source returns from
// `Read` after `Close` has been called. Exported package-internal
// so the fake source used in tests and the real Linux source can
// share one shutdown signal.
var errReaderClosed = errors.New("egress/nflog: reader closed")
