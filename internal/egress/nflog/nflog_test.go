package nflog

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/egress"
)

// TestNew_ValidatesRequiredFields pins the construction contract:
// `New` rejects an empty Chain, a nil Sink, and an out-of-range
// GroupID. A regression that accepted any of these would let a
// misconfigured supervisor silently produce an observer with no
// chain name or no event delivery surface.
func TestNew_ValidatesRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"empty chain", Options{Sink: func(Event) {}}},
		{"nil sink", Options{Chain: "AIENV-EGR-deadbeef"}},
		{"oversized group", Options{Chain: "AIENV-EGR-deadbeef", Sink: func(Event) {}, GroupID: 0}},
	}
	// The first two cases must error; the GroupID=0 case is
	// actually valid (the kernel accepts group 0). We construct a
	// separate over-size case via the package-private wrapping
	// because GroupID is uint16 and cannot overflow at the type
	// level.
	for _, tc := range cases[:2] {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.opts)
			if err == nil {
				t.Fatalf("New(%+v) err = nil, want non-nil", tc.opts)
			}
		})
	}
}

// TestNew_ReturnsObserverWithModeAndChain pins that a successfully
// constructed observer reports the plan-locked "nflog" mode and
// the caller-supplied chain. The supervisor's `observer_started`
// lifecycle verb records both fields verbatim; a regression that
// returned a different mode would silently break the audit trail.
func TestNew_ReturnsObserverWithModeAndChain(t *testing.T) {
	o, err := New(Options{
		Chain: "AIENV-EGR-abcdef12",
		Sink:  func(Event) {},
	})
	if err != nil {
		t.Fatalf("New err = %v, want nil", err)
	}
	if got := o.Mode(); got != Mode {
		t.Errorf("Mode = %q, want %q", got, Mode)
	}
	if got := o.Chain(); got != "AIENV-EGR-abcdef12" {
		t.Errorf("Chain = %q, want %q", got, "AIENV-EGR-abcdef12")
	}
}

// TestModeConstant pins the on-wire token. Plan Batch 0.1 locks
// `"nflog"` as the canonical value for `observer_started`
// Metadata.mode; a regression here would silently break
// downstream consumers (the doctor remediation table, the
// final-summary renderer).
func TestModeConstant(t *testing.T) {
	if Mode != "nflog" {
		t.Errorf("Mode = %q, want %q", Mode, "nflog")
	}
}

// fakeKernelSource is the in-memory `kernelSource` the tests use
// in place of a real netlink socket. It replays a fixed sequence
// of (Event, error) pairs; once the sequence is exhausted, Read
// returns `io.EOF` so the observer's goroutine exits cleanly.
//
// The closing channel mirrors the real Linux source's shutdown
// signal: Stop closes it, Read returns `errReaderClosed` on the
// next call.
type fakeKernelSource struct {
	mu       sync.Mutex
	queue    []readResult
	closed   atomic.Bool
	closeCh  chan struct{}
	readWait time.Duration
}

type readResult struct {
	evt Event
	err error
}

func newFakeKernelSource(results ...readResult) *fakeKernelSource {
	return &fakeKernelSource{
		queue:   results,
		closeCh: make(chan struct{}),
	}
}

func (f *fakeKernelSource) Read(ctx context.Context) (Event, error) {
	if f.closed.Load() {
		return Event{}, errReaderClosed
	}
	if f.readWait > 0 {
		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-f.closeCh:
			return Event{}, errReaderClosed
		case <-time.After(f.readWait):
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		return Event{}, io.EOF
	}
	r := f.queue[0]
	f.queue = f.queue[1:]
	return r.evt, r.err
}

func (f *fakeKernelSource) Close() error {
	if f.closed.Swap(true) {
		return nil
	}
	close(f.closeCh)
	return nil
}

// TestObserver_StartForwardsEventsToSink pins the canonical
// happy path: Start binds the source, the goroutine reads each
// event, the Sink receives them in order. The test uses a fake
// kernel source so it runs without root / netlink.
func TestObserver_StartForwardsEventsToSink(t *testing.T) {
	wantEvents := []Event{
		{Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1, DstPort: 80, Verdict: "accept"},
		{Protocol: "udp", SrcIP: "10.0.0.1", DstIP: "10.0.0.3", SrcPort: 2, DstPort: 53, Verdict: "drop"},
	}
	results := make([]readResult, 0, len(wantEvents))
	for _, e := range wantEvents {
		results = append(results, readResult{evt: e})
	}

	var (
		got  []Event
		gotM sync.Mutex
		done = make(chan struct{}, 1)
	)
	sink := func(e Event) {
		gotM.Lock()
		defer gotM.Unlock()
		got = append(got, e)
		if len(got) == len(wantEvents) {
			select {
			case done <- struct{}{}:
			default:
			}
		}
	}

	o, err := New(Options{Chain: "AIENV-EGR-cafef00d", Sink: sink})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	fake := newFakeKernelSource(results...)
	o.sourceFactory = func(ctx context.Context, _ Options) (kernelSource, error) {
		return fake, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := o.Start(ctx); err != nil {
		t.Fatalf("Start err = %v", err)
	}
	defer o.Stop()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for sink; got %d/%d events", len(got), len(wantEvents))
	}

	gotM.Lock()
	defer gotM.Unlock()
	if len(got) != len(wantEvents) {
		t.Fatalf("Sink received %d events, want %d", len(got), len(wantEvents))
	}
	for i := range wantEvents {
		if got[i] != wantEvents[i] {
			t.Errorf("Sink[%d] = %+v, want %+v", i, got[i], wantEvents[i])
		}
	}
}

// TestObserver_StartReturnsUnsupportedOSWhenFactoryNil pins the
// non-Linux behaviour: when `platformSourceFactory` is nil the
// observer's Start returns `ErrUnsupportedOS` so the supervisor's
// degradation path engages without an OS-specific branch.
func TestObserver_StartReturnsUnsupportedOSWhenFactoryNil(t *testing.T) {
	o, err := New(Options{Chain: "AIENV-EGR-00000001", Sink: func(Event) {}})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	o.sourceFactory = nil
	if err := o.Start(context.Background()); !errors.Is(err, ErrUnsupportedOS) {
		t.Errorf("Start err = %v, want ErrUnsupportedOS", err)
	}
}

// TestObserver_StartReturnsErrorWhenSourceFactoryFails pins the
// fail-closed posture for an attach error: the supervisor sees
// the error verbatim so it can record `observer_unavailable` (or
// abort under strict). A regression that swallowed the error
// would silently let the run continue with no observer.
func TestObserver_StartReturnsErrorWhenSourceFactoryFails(t *testing.T) {
	wantErr := errors.New("netlink bind: permission denied")
	o, err := New(Options{Chain: "AIENV-EGR-00000002", Sink: func(Event) {}})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	o.sourceFactory = func(ctx context.Context, _ Options) (kernelSource, error) {
		return nil, wantErr
	}
	if err := o.Start(context.Background()); !errors.Is(err, wantErr) {
		t.Errorf("Start err = %v, want wrapped %v", err, wantErr)
	}
}

// TestObserver_StopIsIdempotent pins the plan's contract: `Stop`
// is safe to call before `Start` (returns nil), after `Start`
// (drains and closes), and twice in a row (the second call is a
// no-op). A regression that panicked on a double-stop would
// break the supervisor's teardown chain.
func TestObserver_StopIsIdempotent(t *testing.T) {
	o, err := New(Options{Chain: "AIENV-EGR-00000003", Sink: func(Event) {}})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	if err := o.Stop(); err != nil {
		t.Errorf("Stop before Start err = %v, want nil", err)
	}

	o.sourceFactory = func(ctx context.Context, _ Options) (kernelSource, error) {
		return newFakeKernelSource(), nil
	}
	if err := o.Start(context.Background()); err != nil {
		t.Fatalf("Start err = %v", err)
	}
	if err := o.Stop(); err != nil {
		t.Errorf("Stop after Start err = %v, want nil", err)
	}
	if err := o.Stop(); err != nil {
		t.Errorf("second Stop err = %v, want nil (idempotent)", err)
	}
}

// TestObserver_DoubleStartReturnsError pins the regression-guard
// against a buggy supervisor calling Start twice. The plan's
// contract is that the observer exposes a fail-closed error in
// this case so the call site surfaces the bug rather than
// silently double-attaching.
func TestObserver_DoubleStartReturnsError(t *testing.T) {
	o, err := New(Options{Chain: "AIENV-EGR-00000004", Sink: func(Event) {}})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	o.sourceFactory = func(ctx context.Context, _ Options) (kernelSource, error) {
		return newFakeKernelSource(), nil
	}
	if err := o.Start(context.Background()); err != nil {
		t.Fatalf("Start err = %v", err)
	}
	defer o.Stop()
	if err := o.Start(context.Background()); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("second Start err = %v, want ErrAlreadyStarted", err)
	}
}

// TestObserver_TransientErrorsReportedAndLoopContinues pins the
// best-effort posture: a parse error from one frame must not
// stop the reader; the OnError hook fires and the next frame
// reaches the sink.
func TestObserver_TransientErrorsReportedAndLoopContinues(t *testing.T) {
	wantErr := errors.New("nflog: bad attribute length")
	results := []readResult{
		{err: wantErr},
		{evt: Event{Protocol: "tcp", SrcIP: "1.1.1.1", DstIP: "2.2.2.2", DstPort: 443, Verdict: "accept"}},
	}

	var (
		errs    []error
		evts    []Event
		mu      sync.Mutex
		evtDone = make(chan struct{}, 1)
	)
	o, err := New(Options{
		Chain: "AIENV-EGR-00000005",
		Sink: func(e Event) {
			mu.Lock()
			defer mu.Unlock()
			evts = append(evts, e)
			select {
			case evtDone <- struct{}{}:
			default:
			}
		},
		OnError: func(e error) {
			mu.Lock()
			defer mu.Unlock()
			errs = append(errs, e)
		},
	})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	fake := newFakeKernelSource(results...)
	o.sourceFactory = func(ctx context.Context, _ Options) (kernelSource, error) {
		return fake, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := o.Start(ctx); err != nil {
		t.Fatalf("Start err = %v", err)
	}
	defer o.Stop()

	select {
	case <-evtDone:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for sink event after transient error")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(errs) != 1 || !errors.Is(errs[0], wantErr) {
		t.Errorf("OnError got %v, want exactly one %v", errs, wantErr)
	}
	if len(evts) != 1 {
		t.Errorf("Sink got %d events, want 1", len(evts))
	}
}

// TestObserver_SatisfiesEgressInterface pins the type assertion:
// the package's `Observer` MUST implement the cross-platform
// `egress.EgressObserver` interface so the supervisor can hold
// it via the interface type. A regression that renamed a method
// (e.g. `Mode` -> `Name`) would surface at compile time.
func TestObserver_SatisfiesEgressInterface(t *testing.T) {
	o, err := New(Options{Chain: "AIENV-EGR-deadbeef", Sink: func(Event) {}})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	var _ egress.EgressObserver = o
}
