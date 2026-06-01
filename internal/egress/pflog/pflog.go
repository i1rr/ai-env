// Package pflog implements the macOS pflog variant of the
// `egress.EgressObserver` interface declared in Plan Batch 5.1.
//
// On macOS the canonical packet-log surface is the `pflog0`
// pseudo-interface the kernel's pf (packet filter) maintains for
// rules tagged with the `log` action. The observer attaches a
// BPF (`/dev/bpfN`) reader to `pflog0`, parses the per-packet
// frames (DLT_PFLOG link layer + IPv4 / IPv6 header) and forwards
// a structured `Event` to the constructor-supplied sink.
//
// The plan's Bucket 5 row locks the macOS path to a `tcpdump`-on-
// `pflog0` adapter; this implementation uses BPF directly so the
// supervisor does not have to shell out to an external binary
// (which would race the binary's bind-mount overlay if the agent
// has somehow shadowed it). The BPF surface is the same one
// `tcpdump` uses internally so the precision is equivalent.
//
// Design rules (mirror the package doc on `internal/egress`):
//
//   - No I/O at construction. `New` validates options; `Start`
//     opens `/dev/bpfN` and binds the interface. A nil sink is
//     rejected at construction time.
//
//   - Build-tagged kernel surface. The cross-platform contract
//     (Options, Observer, New, Mode, Chain) lives in this file
//     and compiles on every OS. `pflog_darwin.go` provides the
//     real BPF wiring; `pflog_other.go` is the non-darwin stub
//     that returns `ErrUnsupportedOS` from `Start`.
//
//   - Sink is the only event-delivery surface. The supervisor
//     wires the sink to the per-run `network-events.jsonl`
//     writer at §5.5 step 5; the observer never touches disk
//     directly.
//
//   - Tests use a fake kernel source. The package exposes the
//     internal `sourceFactory` field so tests substitute an
//     in-memory queue without root / BPF privileges.
//
// The package depends only on the standard library and
// `internal/egress` (for the `EgressObserver` interface).
package pflog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Mode is the short token the supervisor records in
// `observer_started` Metadata. Plan Batch 0.1 locks `"pflog"` as
// the canonical value for the macOS adapter.
const Mode = "pflog"

// DefaultDevice is the canonical macOS pf logging interface. The
// plan's macOS path attaches a BPF reader to this interface; an
// operator can override the device via `Options.Device` for a
// future test rig that uses a different name.
const DefaultDevice = "pflog0"

// Options bundles every per-run input the observer needs at
// construction. The supervisor populates this struct once at
// §5.5 step 5; the observer copies the fields onto its own struct
// so a caller mutating the source after `New` returns cannot
// affect the running observer.
type Options struct {
	// Chain is the per-run pf anchor / chain name the rule
	// installer (Plan Batch 5.4) installs the `log` rule into.
	// Format: `AIENV-EGR-<8hex>` (the same format as the Linux
	// nflog chain). The observer does NOT touch pf; it only
	// carries the name so `EgressObserver.Chain()` matches the
	// rule installer's view.
	Chain string

	// Device is the pf logging interface to attach to. Empty
	// falls back to `DefaultDevice` (`pflog0`). The field exists
	// so a future test rig can point at a synthetic interface
	// without modifying the package default.
	Device string

	// Sink is the per-event delivery function. The observer
	// calls Sink synchronously from its background goroutine for
	// every parsed packet; a Sink that blocks blocks the reader,
	// so the supervisor's writer wrapper applies a bounded queue.
	// Sink MUST NOT be nil.
	Sink func(Event)

	// OnError is an optional per-error callback. The observer
	// invokes it for non-fatal parse errors (a malformed BPF
	// frame, an unknown link-layer type) so the supervisor can
	// log them via the lifecycle writer. nil is tolerated.
	OnError func(error)
}

// Event is the structured packet record the observer hands to
// the Sink. The shape mirrors the NFLOG `Event` so the
// supervisor's per-run `network-events.jsonl` writer can consume
// both adapters through one path.
type Event struct {
	// Protocol is the IP layer-4 protocol name ("tcp" / "udp" /
	// "icmp" / "other"). Anything not recognised falls through
	// to "other".
	Protocol string

	// SrcIP / DstIP are the captured packet's source / destination
	// IP addresses, rendered as the canonical "1.2.3.4" / "::1"
	// strings. Empty when the parser could not extract them.
	SrcIP string
	DstIP string

	// SrcPort / DstPort are the layer-4 port numbers when the
	// protocol carries them; zero for icmp / other.
	SrcPort uint16
	DstPort uint16

	// Verdict is the pf action token recorded in the pflog
	// header (DLT_PFLOG `action` field): "pass" / "block" / "rdr"
	// / "nat" / "scrub". Empty when the parser could not extract
	// it. The supervisor's `outbound_blocked` / `outbound_allowed`
	// event mapping uses this field.
	Verdict string
}

// ErrUnsupportedOS is returned from `Start` on a host where the
// pflog observer cannot run (anything not macOS). The supervisor
// pairs this with the configured `EgressObserverMode` to decide
// whether to abort (strict) or degrade (auto).
var ErrUnsupportedOS = errors.New("egress/pflog: unsupported_os")

// ErrAlreadyStarted is returned from `Start` when the observer is
// already running. Surfaces a regression at the call site rather
// than silently leaking a goroutine.
var ErrAlreadyStarted = errors.New("egress/pflog: observer already started")

// Observer is the macOS pflog implementation of the cross-
// platform `egress.EgressObserver`. The lifecycle bookkeeping
// lives in this file; the BPF / DLT_PFLOG decoding lives in
// `pflog_darwin.go` (build-tagged).
type Observer struct {
	opts          Options
	mu            sync.Mutex
	started       bool
	stopped       bool
	cancel        context.CancelFunc
	done          chan struct{}
	source        kernelSource
	sourceFactory func(ctx context.Context, opts Options) (kernelSource, error)
}

// kernelSource is the per-platform contract. On macOS it wraps a
// BPF file descriptor bound to pflog0; in tests it is an
// in-memory queue. The interface is identical in shape to the
// nflog package's so a future refactor that unifies the two
// adapters can do so without re-deriving the surface.
type kernelSource interface {
	Read(ctx context.Context) (Event, error)
	Close() error
}

// errReaderClosed is the sentinel a kernel source returns from
// `Read` after `Close` has been called. Shared between the
// production BPF source and the test fake so the reader loop
// recognises one shutdown signal.
var errReaderClosed = errors.New("egress/pflog: reader closed")

// New constructs a pflog observer from the supplied options. It
// validates the required fields and returns an error rather than
// panicking on a misconfigured caller; no BPF surface is opened.
func New(opts Options) (*Observer, error) {
	if opts.Chain == "" {
		return nil, errors.New("egress/pflog: New requires Chain")
	}
	if opts.Sink == nil {
		return nil, errors.New("egress/pflog: New requires Sink")
	}
	if opts.Device == "" {
		opts.Device = DefaultDevice
	}
	return &Observer{
		opts:          opts,
		sourceFactory: platformSourceFactory,
	}, nil
}

// Mode returns the lifecycle-event metadata token. Plan Batch
// 0.1: `"pflog"`.
func (o *Observer) Mode() string { return Mode }

// Chain returns the per-run pf chain name the observer's
// rule-installer counterpart (Plan Batch 5.4) targets.
func (o *Observer) Chain() string { return o.opts.Chain }

// Start opens the BPF surface, binds it to the pf log device,
// and launches the background reader goroutine. On non-Darwin
// hosts Start returns `ErrUnsupportedOS` and does not start a
// goroutine.
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
		return fmt.Errorf("egress/pflog: open kernel source: %w", err)
	}
	o.source = src
	o.cancel = cancel
	o.done = make(chan struct{})
	o.started = true

	go o.run(runCtx)
	return nil
}

// Stop tears down the BPF surface and waits for the background
// reader to drain pending events. Idempotent: a second call is a
// no-op. Safe to call before `Start`.
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
		_ = source.Close()
	}
	if done != nil {
		<-done
	}
	return nil
}

// run is the background reader goroutine. Mirrors the nflog
// adapter: loop until ctx is done / source returns EOF /
// errReaderClosed; transient errors flow through OnError and the
// loop continues.
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
			continue
		}
		o.opts.Sink(evt)
	}
}

// isReaderShutdown reports whether err is a "stop reading"
// signal: context cancellation, EOF, or the package's
// errReaderClosed sentinel.
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
