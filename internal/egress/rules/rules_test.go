package rules

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// TestChainNameRegexp pins the format Plan §5.5 step 7 locks.
// A regression that loosened the pattern (e.g. accepting upper-
// case hex) would let two runs collide because the supervisor
// derives the suffix deterministically and only the lower-case
// 8-hex form is collision-free across the codebase.
func TestChainNameRegexp(t *testing.T) {
	valid := []string{
		"AIENV-EGR-deadbeef",
		"AIENV-EGR-00000000",
		"AIENV-EGR-abcdef12",
	}
	invalid := []string{
		"",
		"aienv-egr-deadbeef",     // wrong case for the prefix
		"AIENV-EGR-DEADBEEF",     // uppercase hex
		"AIENV-EGR-cafebabe1",    // 9 hex chars
		"AIENV-EGR-cafebab",      // 7 hex chars
		"AIENV-EGR-cafebabz",     // non-hex char
		"AIENV-OTHER-deadbeef",   // wrong infix
		"AIENV-EGR-deadbeef\nx",  // injection attempt
		"AIENV-EGR-deadbeef; ls", // shell injection attempt
	}
	for _, s := range valid {
		if !ChainNameRegexp.MatchString(s) {
			t.Errorf("ChainNameRegexp.MatchString(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if ChainNameRegexp.MatchString(s) {
			t.Errorf("ChainNameRegexp.MatchString(%q) = true, want false", s)
		}
	}
}

// TestNew_ValidatesChain pins the construction contract: New
// rejects malformed chain names and unknown verdicts.
func TestNew_ValidatesChain(t *testing.T) {
	if _, err := New(Options{Chain: ""}); err == nil {
		t.Errorf("New(empty chain) err = nil, want non-nil")
	}
	if _, err := New(Options{Chain: "not-a-chain"}); err == nil {
		t.Errorf("New(bad chain) err = nil, want non-nil")
	}
	if _, err := New(Options{Chain: "AIENV-EGR-deadbeef", Verdict: Verdict("ambivalent")}); err == nil {
		t.Errorf("New(unknown verdict) err = nil, want non-nil")
	}
}

// TestNew_DefaultsVerdict pins the documented default: a caller
// who does not set Options.Verdict gets `VerdictReject`. Plan
// locks reject as the default so a leaked packet is dropped, not
// allowed.
func TestNew_DefaultsVerdict(t *testing.T) {
	l, err := New(Options{Chain: "AIENV-EGR-00000001"})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	if l.opts.Verdict != VerdictReject {
		t.Errorf("Verdict = %q, want %q", l.opts.Verdict, VerdictReject)
	}
}

// recordingCommander captures every invocation so tests can
// assert the exact command sequence the driver emits. It is the
// test seam Commander; the production execCommander shells out
// via os/exec.
type recordingCommander struct {
	mu          sync.Mutex
	calls       []recordedCall
	existsFor   map[string]bool
	runResponse map[string][]byte
	runError    map[string]error
}

type recordedCall struct {
	Name string
	Args []string
}

func newRecordingCommander() *recordingCommander {
	return &recordingCommander{
		existsFor:   make(map[string]bool),
		runResponse: make(map[string][]byte),
		runError:    make(map[string]error),
	}
}

func (r *recordingCommander) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recordedCall{Name: name, Args: append([]string(nil), args...)})

	// Convert to a comparable key so tests can stub specific
	// argument patterns. The key is the program name plus a
	// space-joined args slice.
	key := name + " " + strings.Join(args, " ")
	if err, ok := r.runError[key]; ok {
		return r.runResponse[key], err
	}
	if data, ok := r.runResponse[key]; ok {
		return data, nil
	}
	return nil, nil
}

// CallSummaries returns one human-readable line per recorded
// call so a test's failure message can show the actual sequence.
func (r *recordingCommander) CallSummaries() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	for i, c := range r.calls {
		out[i] = c.Name + " " + strings.Join(c.Args, " ")
	}
	return out
}

// fakeDriver is the cross-platform test seam for the Lifecycle.
// On hosts where the production platformDriver is the unsupported
// stub (or an OS-specific driver we cannot exercise here), the
// fakeDriver lets us pin the Lifecycle's flow control without
// touching the kernel.
type fakeDriver struct {
	mode       Mode
	exists     bool
	existsErr  error
	installErr error
	uninstErr  error

	mu         sync.Mutex
	installed  bool
	calls      []string
	rollbacks  int
}

func (f *fakeDriver) Mode() Mode {
	if f.mode == "" {
		return ModeIptables
	}
	return f.mode
}

func (f *fakeDriver) Exists(ctx context.Context, cmd Commander, chain string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Exists "+chain)
	return f.exists, f.existsErr
}

func (f *fakeDriver) Install(ctx context.Context, cmd Commander, opts Options) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Install "+opts.Chain)
	if f.installErr != nil {
		return f.installErr
	}
	f.installed = true
	return nil
}

func (f *fakeDriver) Uninstall(ctx context.Context, cmd Commander, chain string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Uninstall "+chain)
	if !f.installed {
		f.rollbacks++
	}
	f.installed = false
	return f.uninstErr
}

// withFakeDriver wraps the supplied driver onto a freshly-built
// Lifecycle so tests do not need to re-derive the options
// validation logic.
func withFakeDriver(t *testing.T, fd ruleDriver, opts Options) *Lifecycle {
	t.Helper()
	if opts.Chain == "" {
		opts.Chain = "AIENV-EGR-deadbeef"
	}
	l, err := New(opts)
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	l.driver = fd
	return l
}

// TestLifecycle_InstallRefusesPreexistingChain pins the
// idempotence + crash-safety rule: if a chain with the same
// name already exists on the host (e.g. left over by a previous
// crashed run), Install returns ErrChainAlreadyExists rather
// than overwriting. The supervisor's crash-recovery handler is
// expected to call Uninstall first.
func TestLifecycle_InstallRefusesPreexistingChain(t *testing.T) {
	fd := &fakeDriver{exists: true}
	l := withFakeDriver(t, fd, Options{})

	err := l.Install(context.Background())
	if !errors.Is(err, ErrChainAlreadyExists) {
		t.Fatalf("Install err = %v, want ErrChainAlreadyExists", err)
	}
	if fd.installed {
		t.Errorf("driver state installed = true, want false (refusal must not modify state)")
	}
}

// TestLifecycle_InstallRollsBackOnDriverError pins the rollback
// guarantee: when the driver's Install returns an error, the
// Lifecycle calls Uninstall to clean up partial state before
// surfacing the error.
func TestLifecycle_InstallRollsBackOnDriverError(t *testing.T) {
	wantErr := errors.New("iptables: rule failed")
	fd := &fakeDriver{installErr: wantErr}
	l := withFakeDriver(t, fd, Options{})

	err := l.Install(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Install err = %v, want wrap of %v", err, wantErr)
	}
	if l.Installed() {
		t.Errorf("Lifecycle.Installed() = true after rollback, want false")
	}
	// Driver's Uninstall must be called for the cleanup pass.
	var sawUninstall bool
	for _, c := range fd.calls {
		if strings.HasPrefix(c, "Uninstall ") {
			sawUninstall = true
		}
	}
	if !sawUninstall {
		t.Errorf("driver calls = %v, want one Uninstall call (rollback)", fd.calls)
	}
}

// TestLifecycle_InstallFiresOnInstalledCallback pins the audit-
// hook: a successful Install calls OnInstalled with the chain
// name and driver Mode. The supervisor relies on this to emit
// the `observer_started` lifecycle verb at the exact moment the
// rules are in the kernel.
func TestLifecycle_InstallFiresOnInstalledCallback(t *testing.T) {
	var (
		gotChain string
		gotMode  Mode
		fired    bool
	)
	fd := &fakeDriver{mode: ModeIptables}
	opts := Options{
		Chain: "AIENV-EGR-12345678",
		OnInstalled: func(chain string, mode Mode) {
			gotChain = chain
			gotMode = mode
			fired = true
		},
	}
	l := withFakeDriver(t, fd, opts)

	if err := l.Install(context.Background()); err != nil {
		t.Fatalf("Install err = %v", err)
	}
	if !fired {
		t.Fatalf("OnInstalled not fired")
	}
	if gotChain != opts.Chain {
		t.Errorf("OnInstalled chain = %q, want %q", gotChain, opts.Chain)
	}
	if gotMode != ModeIptables {
		t.Errorf("OnInstalled mode = %q, want %q", gotMode, ModeIptables)
	}
}

// TestLifecycle_DoubleInstallReturnsAlreadyExists pins the
// double-install guard: a buggy supervisor calling Install twice
// on the same Lifecycle sees ErrChainAlreadyExists rather than
// silently producing duplicate rules.
func TestLifecycle_DoubleInstallReturnsAlreadyExists(t *testing.T) {
	fd := &fakeDriver{}
	l := withFakeDriver(t, fd, Options{})

	if err := l.Install(context.Background()); err != nil {
		t.Fatalf("first Install err = %v", err)
	}
	if err := l.Install(context.Background()); !errors.Is(err, ErrChainAlreadyExists) {
		t.Errorf("second Install err = %v, want ErrChainAlreadyExists", err)
	}
}

// TestLifecycle_UninstallEmitsCallback pins the teardown audit
// hook: a successful Uninstall calls OnUninstalled with the
// chain, mode, and reason. The supervisor wires this to
// `LifecycleVerbObserverStopped`.
func TestLifecycle_UninstallEmitsCallback(t *testing.T) {
	var (
		gotChain  string
		gotMode   Mode
		gotReason string
		fired     bool
	)
	fd := &fakeDriver{}
	opts := Options{
		Chain: "AIENV-EGR-12345678",
		OnUninstalled: func(chain string, mode Mode, reason string) {
			gotChain = chain
			gotMode = mode
			gotReason = reason
			fired = true
		},
	}
	l := withFakeDriver(t, fd, opts)
	if err := l.Install(context.Background()); err != nil {
		t.Fatalf("Install err = %v", err)
	}
	if err := l.Uninstall(context.Background(), "teardown"); err != nil {
		t.Fatalf("Uninstall err = %v", err)
	}
	if !fired {
		t.Fatalf("OnUninstalled not fired")
	}
	if gotChain != opts.Chain {
		t.Errorf("OnUninstalled chain = %q, want %q", gotChain, opts.Chain)
	}
	if gotMode != ModeIptables {
		t.Errorf("OnUninstalled mode = %q, want %q", gotMode, ModeIptables)
	}
	if gotReason != "teardown" {
		t.Errorf("OnUninstalled reason = %q, want %q", gotReason, "teardown")
	}
}

// TestLifecycle_UninstallDefaultsReasonToTeardown pins the
// empty-reason default. The supervisor's common path passes "";
// a regression that left the field empty in the audit record
// would obscure the canonical "shutdown happened" signal.
func TestLifecycle_UninstallDefaultsReasonToTeardown(t *testing.T) {
	var gotReason string
	fd := &fakeDriver{}
	opts := Options{
		Chain: "AIENV-EGR-deadbeef",
		OnUninstalled: func(_ string, _ Mode, reason string) {
			gotReason = reason
		},
	}
	l := withFakeDriver(t, fd, opts)
	if err := l.Install(context.Background()); err != nil {
		t.Fatalf("Install err = %v", err)
	}
	if err := l.Uninstall(context.Background(), ""); err != nil {
		t.Fatalf("Uninstall err = %v", err)
	}
	if gotReason != "teardown" {
		t.Errorf("default reason = %q, want %q", gotReason, "teardown")
	}
}

// TestLifecycle_UninstallReturnsChainNotFound pins the
// idempotence-on-clean-state contract: calling Uninstall when
// the chain was never installed (and does not exist on the
// host) returns ErrChainNotFound so the supervisor can
// distinguish "we cleaned up" from "it was never there".
func TestLifecycle_UninstallReturnsChainNotFound(t *testing.T) {
	fd := &fakeDriver{exists: false}
	l := withFakeDriver(t, fd, Options{})
	if err := l.Uninstall(context.Background(), "teardown"); !errors.Is(err, ErrChainNotFound) {
		t.Errorf("Uninstall on uninstalled lifecycle err = %v, want ErrChainNotFound", err)
	}
}

// TestLifecycle_UninstallStaleChainEvenWhenNeverInstalled pins
// the crash-recovery scenario: the supervisor restarts after a
// crash that left a stale chain on the host; the new Lifecycle
// has installed=false but Exists reports true; Uninstall must
// clean up the stale chain so a subsequent Install succeeds.
func TestLifecycle_UninstallStaleChainEvenWhenNeverInstalled(t *testing.T) {
	fd := &fakeDriver{exists: true}
	l := withFakeDriver(t, fd, Options{})
	if err := l.Uninstall(context.Background(), "crash_recovery"); err != nil {
		t.Errorf("Uninstall stale chain err = %v, want nil", err)
	}
	var sawUninstall bool
	for _, c := range fd.calls {
		if strings.HasPrefix(c, "Uninstall ") {
			sawUninstall = true
		}
	}
	if !sawUninstall {
		t.Errorf("driver calls = %v, want one Uninstall", fd.calls)
	}
}

// TestLifecycle_ModeReportsDriverMode pins the Mode getter: the
// Lifecycle proxies through to the driver so the supervisor
// records the right Metadata.mode token (iptables vs pf vs
// unsupported_os).
func TestLifecycle_ModeReportsDriverMode(t *testing.T) {
	cases := []struct {
		drv  ruleDriver
		want Mode
	}{
		{&fakeDriver{mode: ModeIptables}, ModeIptables},
		{&fakeDriver{mode: ModePF}, ModePF},
		{unsupportedDriver{}, ModeUnsupported},
	}
	for _, tc := range cases {
		l := withFakeDriver(t, tc.drv, Options{})
		if got := l.Mode(); got != tc.want {
			t.Errorf("Mode = %q, want %q", got, tc.want)
		}
	}
}

// TestLifecycle_ChainGetter pins the trivial accessor; included
// so a regression that returned a different value (e.g. an
// internal redacted form) surfaces here.
func TestLifecycle_ChainGetter(t *testing.T) {
	l, err := New(Options{Chain: "AIENV-EGR-aaaaaaaa"})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	if got := l.Chain(); got != "AIENV-EGR-aaaaaaaa" {
		t.Errorf("Chain = %q, want %q", got, "AIENV-EGR-aaaaaaaa")
	}
}

// TestUnsupportedDriver_InstallReturnsUnsupportedOS pins the
// non-Linux / non-Darwin behaviour: when the platform driver is
// the stub, Install returns ErrUnsupportedOS so the supervisor's
// strict-abort / auto-skip path engages.
func TestUnsupportedDriver_InstallReturnsUnsupportedOS(t *testing.T) {
	l, err := New(Options{Chain: "AIENV-EGR-deadbeef"})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	l.driver = unsupportedDriver{}
	if err := l.Install(context.Background()); !errors.Is(err, ErrUnsupportedOS) {
		t.Errorf("Install on unsupported driver err = %v, want ErrUnsupportedOS", err)
	}
}

// TestUnsupportedDriver_UninstallReturnsUnsupportedOS pins the
// symmetric teardown behaviour.
func TestUnsupportedDriver_UninstallReturnsUnsupportedOS(t *testing.T) {
	l, err := New(Options{Chain: "AIENV-EGR-deadbeef"})
	if err != nil {
		t.Fatalf("New err = %v", err)
	}
	l.driver = unsupportedDriver{}
	if err := l.Uninstall(context.Background(), "teardown"); !errors.Is(err, ErrUnsupportedOS) {
		t.Errorf("Uninstall on unsupported driver err = %v, want ErrUnsupportedOS", err)
	}
}

// TestCommanderFunc_AdaptsFunctionToInterface pins that the
// CommanderFunc shim correctly implements Commander; otherwise
// tests substituting a one-off function would silently fall
// back to the production commander.
func TestCommanderFunc_AdaptsFunctionToInterface(t *testing.T) {
	var got string
	var c Commander = CommanderFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		got = name + ":" + strings.Join(args, ",")
		return []byte("ok"), nil
	})
	out, err := c.Run(context.Background(), "iptables", "-L")
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	if string(out) != "ok" {
		t.Errorf("Run stdout = %q, want %q", string(out), "ok")
	}
	if got != "iptables:-L" {
		t.Errorf("got = %q, want %q", got, "iptables:-L")
	}
}

// TestRecordingCommander_CapturesCallSequence is a sanity test
// for the test helper itself: a misbehaving recordingCommander
// would silently let other tests pass with wrong assertions.
func TestRecordingCommander_CapturesCallSequence(t *testing.T) {
	c := newRecordingCommander()
	_, _ = c.Run(context.Background(), "iptables", "-N", "foo")
	_, _ = c.Run(context.Background(), "iptables", "-F", "foo")
	summaries := c.CallSummaries()
	want := []string{"iptables -N foo", "iptables -F foo"}
	if len(summaries) != len(want) {
		t.Fatalf("got %d calls, want %d", len(summaries), len(want))
	}
	for i, s := range summaries {
		if s != want[i] {
			t.Errorf("call[%d] = %q, want %q", i, s, want[i])
		}
	}
}
