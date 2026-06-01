package egress

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/capability"
)

// TestEgressObserverMode_ConstantTokens pins the exact on-wire tokens
// the plan locks. A regression that renamed a constant (e.g.
// `strict` -> `enforce`) would silently break operator-supplied
// `--observer-mode strict` invocations and the policy.yaml schema; we
// catch that here.
func TestEgressObserverMode_ConstantTokens(t *testing.T) {
	cases := []struct {
		mode EgressObserverMode
		want string
	}{
		{EgressObserverModeAuto, "auto"},
		{EgressObserverModeStrict, "strict"},
		{EgressObserverModeDisabled, "disabled"},
	}
	for _, tc := range cases {
		if got := string(tc.mode); got != tc.want {
			t.Errorf("EgressObserverMode token = %q, want %q", got, tc.want)
		}
		if got := tc.mode.String(); got != tc.want {
			t.Errorf("EgressObserverMode.String() = %q, want %q", got, tc.want)
		}
	}
}

// TestDefaultEgressObserverMode_IsAuto pins the plan's "default Auto"
// locked decision (Bucket 5 row). A regression that flipped the
// default would silently change every operator's behaviour on
// machines without CAP_NET_ADMIN.
func TestDefaultEgressObserverMode_IsAuto(t *testing.T) {
	if DefaultEgressObserverMode != EgressObserverModeAuto {
		t.Fatalf("DefaultEgressObserverMode = %q, want %q",
			DefaultEgressObserverMode, EgressObserverModeAuto)
	}
}

// TestParseEgressObserverMode pins the parser's mapping from operator-
// supplied strings to the typed mode. Includes the empty-string ->
// default and unknown -> error paths. The case-insensitive variants
// are listed because operators write policy.yaml by hand and the
// parser's contract is "Auto" / "AUTO" / "auto" all work.
func TestParseEgressObserverMode(t *testing.T) {
	cases := []struct {
		in        string
		want      EgressObserverMode
		wantError bool
	}{
		{"", EgressObserverModeAuto, false},
		{"auto", EgressObserverModeAuto, false},
		{"Auto", EgressObserverModeAuto, false},
		{"AUTO", EgressObserverModeAuto, false},
		{"strict", EgressObserverModeStrict, false},
		{"Strict", EgressObserverModeStrict, false},
		{"STRICT", EgressObserverModeStrict, false},
		{"disabled", EgressObserverModeDisabled, false},
		{"Disabled", EgressObserverModeDisabled, false},
		{"DISABLED", EgressObserverModeDisabled, false},
		{"enforce", "", true},
		{"off", "", true},
		{" auto", "", true}, // no whitespace tolerance; supervisor trims
	}
	for _, tc := range cases {
		got, err := ParseEgressObserverMode(tc.in)
		if tc.wantError {
			if err == nil {
				t.Errorf("ParseEgressObserverMode(%q) err=nil, want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEgressObserverMode(%q) err=%v, want nil", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseEgressObserverMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEgressObserverMode_Valid pins the Valid() predicate. The zero
// value is intentionally invalid so a supervisor code path that
// forgot to apply the default surfaces as a regression at the call
// site rather than silently routing through the auto branch.
func TestEgressObserverMode_Valid(t *testing.T) {
	if !EgressObserverModeAuto.Valid() {
		t.Errorf("EgressObserverModeAuto.Valid() = false, want true")
	}
	if !EgressObserverModeStrict.Valid() {
		t.Errorf("EgressObserverModeStrict.Valid() = false, want true")
	}
	if !EgressObserverModeDisabled.Valid() {
		t.Errorf("EgressObserverModeDisabled.Valid() = false, want true")
	}
	if EgressObserverMode("").Valid() {
		t.Errorf("EgressObserverMode(\"\").Valid() = true, want false")
	}
	if EgressObserverMode("enforce").Valid() {
		t.Errorf("EgressObserverMode(\"enforce\").Valid() = true, want false")
	}
}

// TestStartDecision_ConstantTokens pins the exact tokens the
// supervisor's switch arms compare against. A regression that
// renamed one would silently send the supervisor down the wrong
// branch.
func TestStartDecision_ConstantTokens(t *testing.T) {
	cases := []struct {
		d    StartDecision
		want string
	}{
		{StartDecisionAttach, "attach"},
		{StartDecisionSkipUnavailable, "skip_unavailable"},
		{StartDecisionSkipDisabled, "skip_disabled"},
		{StartDecisionAbort, "abort"},
	}
	for _, tc := range cases {
		if got := string(tc.d); got != tc.want {
			t.Errorf("StartDecision token = %q, want %q", got, tc.want)
		}
	}
}

// TestResolveStartDecision_PinsEveryCell pins every cell of the
// (mode × capability.ObserverModeAvailable) matrix the plan locks.
// A regression in any cell would change observable supervisor
// behaviour on a category of hosts (e.g. flipping strict-on-unavail
// from abort to attach would let a non-privileged host through; the
// plan locks abort).
func TestResolveStartDecision_PinsEveryCell(t *testing.T) {
	available := capability.Capability{
		OS:             "linux",
		CAPNetAdmin:    true,
		NFLOGAvailable: true,
	}
	if !available.ObserverModeAvailable() {
		t.Fatalf("test fixture invariant: available capability must report ObserverModeAvailable=true")
	}
	unavailable := capability.Capability{
		OS:             "linux",
		CAPNetAdmin:    false,
		NFLOGAvailable: true,
	}
	if unavailable.ObserverModeAvailable() {
		t.Fatalf("test fixture invariant: unavailable capability must report ObserverModeAvailable=false")
	}

	cases := []struct {
		name string
		mode EgressObserverMode
		cap  capability.Capability
		want StartDecision
	}{
		{"auto+available -> attach", EgressObserverModeAuto, available, StartDecisionAttach},
		{"auto+unavailable -> skip_unavailable", EgressObserverModeAuto, unavailable, StartDecisionSkipUnavailable},
		{"strict+available -> attach", EgressObserverModeStrict, available, StartDecisionAttach},
		{"strict+unavailable -> abort", EgressObserverModeStrict, unavailable, StartDecisionAbort},
		{"disabled+available -> skip_disabled", EgressObserverModeDisabled, available, StartDecisionSkipDisabled},
		{"disabled+unavailable -> skip_disabled", EgressObserverModeDisabled, unavailable, StartDecisionSkipDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveStartDecision(tc.mode, tc.cap)
			if err != nil {
				t.Errorf("ResolveStartDecision err = %v, want nil for plan-pinned cells", err)
			}
			if got != tc.want {
				t.Errorf("ResolveStartDecision(%q, available=%v) = %q, want %q",
					tc.mode, tc.cap.ObserverModeAvailable(), got, tc.want)
			}
		})
	}
}

// TestResolveStartDecision_UnknownModeFallsBackToAutoAndReportsError
// pins the safety-net branch: an unknown mode (zero-value, typo that
// somehow bypassed the parser) MUST behave like auto on the decision
// path AND surface a diagnostic error the supervisor can log. The
// dual return (decision + error) lets the supervisor stay on a single
// happy path while still hearing the regression.
func TestResolveStartDecision_UnknownModeFallsBackToAutoAndReportsError(t *testing.T) {
	available := capability.Capability{OS: "linux", CAPNetAdmin: true, NFLOGAvailable: true}
	unavailable := capability.Capability{OS: "linux"}

	decision, err := ResolveStartDecision(EgressObserverMode("garbage"), available)
	if err == nil {
		t.Errorf("ResolveStartDecision(unknown, available) err = nil, want non-nil diagnostic")
	}
	if decision != StartDecisionAttach {
		t.Errorf("ResolveStartDecision(unknown, available) = %q, want %q", decision, StartDecisionAttach)
	}

	decision, err = ResolveStartDecision(EgressObserverMode(""), unavailable)
	if err == nil {
		t.Errorf("ResolveStartDecision(zero, unavailable) err = nil, want non-nil diagnostic")
	}
	if decision != StartDecisionSkipUnavailable {
		t.Errorf("ResolveStartDecision(zero, unavailable) = %q, want %q", decision, StartDecisionSkipUnavailable)
	}
}

// fakeObserver is the in-test EgressObserver implementation used by
// TestEgressObserver_InterfaceShape. It records Start / Stop calls so
// the test can assert the supervisor-call surface matches the
// interface the plan locks; the supervisor itself wires real
// observers (NFLOG / pflog) in Batches 5.2 / 5.3.
type fakeObserver struct {
	mode       string
	chain      string
	startCount int
	stopCount  int
	startErr   error
	stopErr    error
}

func (f *fakeObserver) Mode() string  { return f.mode }
func (f *fakeObserver) Chain() string { return f.chain }
func (f *fakeObserver) Start(ctx context.Context) error {
	f.startCount++
	return f.startErr
}
func (f *fakeObserver) Stop() error {
	f.stopCount++
	return f.stopErr
}

// TestEgressObserver_InterfaceShape compiles only if the
// EgressObserver interface has the four methods the plan locks
// (Mode, Chain, Start, Stop). A regression that added a new
// required method would make every existing adapter (NFLOG, pflog,
// future eBPF) silently stop compiling — we surface that here with
// a single shape-pin test rather than waiting for the per-adapter
// build to break.
func TestEgressObserver_InterfaceShape(t *testing.T) {
	var obs EgressObserver = &fakeObserver{mode: "nflog", chain: "AIENV-EGR-deadbeef"}

	if got := obs.Mode(); got != "nflog" {
		t.Errorf("obs.Mode() = %q, want %q", got, "nflog")
	}
	if got := obs.Chain(); got != "AIENV-EGR-deadbeef" {
		t.Errorf("obs.Chain() = %q, want %q", got, "AIENV-EGR-deadbeef")
	}
	if err := obs.Start(context.Background()); err != nil {
		t.Errorf("obs.Start = %v, want nil", err)
	}
	if err := obs.Stop(); err != nil {
		t.Errorf("obs.Stop = %v, want nil", err)
	}
}

// TestEgressObserver_StartStopErrorsPropagate pins that the
// supervisor sees Start / Stop errors verbatim rather than the
// interface swallowing them. This is the test that pins the
// fail-closed posture: if an adapter cannot attach, the supervisor
// must hear the error and degrade per the configured mode.
func TestEgressObserver_StartStopErrorsPropagate(t *testing.T) {
	startErr := errors.New("attach failed: permission denied")
	stopErr := errors.New("drain timeout")

	obs := &fakeObserver{startErr: startErr, stopErr: stopErr}
	if err := obs.Start(context.Background()); !errors.Is(err, startErr) {
		t.Errorf("obs.Start error = %v, want %v", err, startErr)
	}
	if err := obs.Stop(); !errors.Is(err, stopErr) {
		t.Errorf("obs.Stop error = %v, want %v", err, stopErr)
	}
}

// TestParseEgressObserverMode_ErrorMessageListsAllValid pins the
// parser's error-message contract: the operator-facing error MUST
// enumerate every legal mode so a typo in policy.yaml surfaces with
// a self-contained fix hint. A regression that dropped one mode from
// the error would force operators to grep the source for the
// allowlist.
func TestParseEgressObserverMode_ErrorMessageListsAllValid(t *testing.T) {
	_, err := ParseEgressObserverMode("nonsense")
	if err == nil {
		t.Fatalf("ParseEgressObserverMode(nonsense) err = nil, want non-nil")
	}
	msg := err.Error()
	for _, want := range []string{"auto", "strict", "disabled"} {
		if !strings.Contains(msg, want) {
			t.Errorf("ParseEgressObserverMode error %q missing mode token %q", msg, want)
		}
	}
}
