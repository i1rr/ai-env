package pflog

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/egress"
)

// TestNew_ValidatesRequiredFields pins the construction
// contract: New rejects an empty Chain and a nil Sink. A
// regression here would let a misconfigured supervisor silently
// produce an observer with no event delivery surface.
func TestNew_ValidatesRequiredFields(t *testing.T) {
	if _, err := New(Options{Sink: func(Event) {}}); err == nil {
		t.Errorf("New(empty chain) err = nil, want non-nil")
	}
	if _, err := New(Options{Chain: "AIENV-EGR-deadbeef"}); err == nil {
		t.Errorf("New(nil sink) err = nil, want non-nil")
	}
}

// TestNew_DefaultsDevice pins the documented default: a caller
// who does not set Options.Device gets `pflog0` automatically.
// A regression that left the field empty would cause the BPF
// bind to error out at Start time on a real macOS host.
func TestNew_DefaultsDevice(t *testing.T) {
	o, err := New(Options{Chain: "AIENV-EGR-00000001", Sink: func(Event) {}})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	if o.opts.Device != DefaultDevice {
		t.Errorf("Device = %q, want %q", o.opts.Device, DefaultDevice)
	}
}

// TestNew_RespectsCustomDevice pins the override path: an
// operator pointing at a synthetic interface gets their value
// through to the kernel source factory.
func TestNew_RespectsCustomDevice(t *testing.T) {
	o, err := New(Options{Chain: "AIENV-EGR-00000002", Device: "pflog1", Sink: func(Event) {}})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	if o.opts.Device != "pflog1" {
		t.Errorf("Device = %q, want %q", o.opts.Device, "pflog1")
	}
}

// TestModeConstant pins the on-wire token. Plan Batch 0.1 locks
// `"pflog"` as the canonical value for the macOS adapter.
func TestModeConstant(t *testing.T) {
	if Mode != "pflog" {
		t.Errorf("Mode = %q, want %q", Mode, "pflog")
	}
}

// fakeKernelSource is the in-memory `kernelSource` used in
// tests. Identical to the nflog package's fake (intentionally:
// the two adapters share a kernelSource shape so tests can
// reuse the same pattern without confusion).
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
// happy path: the goroutine reads each fake event and the Sink
// receives them in order.
func TestObserver_StartForwardsEventsToSink(t *testing.T) {
	wantEvents := []Event{
		{Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1, DstPort: 80, Verdict: "pass"},
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
// non-Darwin behaviour: when `platformSourceFactory` is nil the
// observer's Start returns `ErrUnsupportedOS`.
func TestObserver_StartReturnsUnsupportedOSWhenFactoryNil(t *testing.T) {
	o, err := New(Options{Chain: "AIENV-EGR-00000010", Sink: func(Event) {}})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	o.sourceFactory = nil
	if err := o.Start(context.Background()); !errors.Is(err, ErrUnsupportedOS) {
		t.Errorf("Start err = %v, want ErrUnsupportedOS", err)
	}
}

// TestObserver_StartReturnsErrorWhenSourceFactoryFails pins the
// fail-closed posture: the supervisor sees the factory error
// verbatim.
func TestObserver_StartReturnsErrorWhenSourceFactoryFails(t *testing.T) {
	wantErr := errors.New("bpf bind: operation not permitted")
	o, err := New(Options{Chain: "AIENV-EGR-00000011", Sink: func(Event) {}})
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

// TestObserver_StopIsIdempotent pins the plan's idempotence
// contract: Stop is safe before Start, after Start, and twice.
func TestObserver_StopIsIdempotent(t *testing.T) {
	o, err := New(Options{Chain: "AIENV-EGR-00000012", Sink: func(Event) {}})
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

// TestObserver_DoubleStartReturnsError pins the regression-
// guard: a buggy supervisor calling Start twice sees a fail-
// closed error rather than silently leaking goroutines.
func TestObserver_DoubleStartReturnsError(t *testing.T) {
	o, err := New(Options{Chain: "AIENV-EGR-00000013", Sink: func(Event) {}})
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
// stop the reader.
func TestObserver_TransientErrorsReportedAndLoopContinues(t *testing.T) {
	wantErr := errors.New("pflog: short pflog header")
	results := []readResult{
		{err: wantErr},
		{evt: Event{Protocol: "tcp", SrcIP: "1.1.1.1", DstIP: "2.2.2.2", DstPort: 443, Verdict: "pass"}},
	}

	var (
		errs    []error
		evts    []Event
		mu      sync.Mutex
		evtDone = make(chan struct{}, 1)
	)
	o, err := New(Options{
		Chain: "AIENV-EGR-00000014",
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

// TestObserver_SatisfiesEgressInterface pins the type
// assertion: the macOS Observer MUST implement the cross-
// platform `egress.EgressObserver` interface.
func TestObserver_SatisfiesEgressInterface(t *testing.T) {
	o, err := New(Options{Chain: "AIENV-EGR-deadbeef", Sink: func(Event) {}})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	var _ egress.EgressObserver = o
}
