// Tests for the Plan §0.5 extensions to the mock backend
// (GatewayAddress / MappedUID / ProbeImage and the configurable
// overrides driving them). The existing supervisor tests under
// internal/run/ use the mock heavily; these tests pin the behavior
// the new mock surfaces so a future regression to e.g. "MappedUID
// defaults to 0 instead of EnvSpec.UID" is caught locally.
package mock

import (
	"errors"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/backend"
)

func newFixedTime() func() time.Time {
	t := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// TestGatewayAddress_DefaultsToEmpty pins the documented default
// for the Plan §0.5 GatewayAddress method on the mock: ("", nil)
// means "no bridge gateway", and the supervisor's ProviderProxy
// picker treats it as the UnixSocket fallback signal.
func TestGatewayAddress_DefaultsToEmpty(t *testing.T) {
	t.Parallel()
	b := New(newFixedTime())
	envID, err := b.Create(backend.EnvSpec{Name: "fix-tests", WorkspacePath: "/ws"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ip, err := b.GatewayAddress(envID)
	if err != nil {
		t.Fatalf("GatewayAddress: %v", err)
	}
	if ip != "" {
		t.Errorf("GatewayAddress default = %q, want empty", ip)
	}
}

// TestGatewayAddress_RespectsOverride pins the SetGatewayAddress
// override path tests use to drive the BridgeGateway ProviderProxy
// branch.
func TestGatewayAddress_RespectsOverride(t *testing.T) {
	t.Parallel()
	b := New(newFixedTime())
	envID, err := b.Create(backend.EnvSpec{Name: "fix-tests", WorkspacePath: "/ws"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	b.SetGatewayAddress("172.17.0.1", nil)
	ip, err := b.GatewayAddress(envID)
	if err != nil {
		t.Fatalf("GatewayAddress: %v", err)
	}
	if ip != "172.17.0.1" {
		t.Errorf("GatewayAddress = %q, want 172.17.0.1", ip)
	}

	wantErr := errors.New("bridge probe failed")
	b.SetGatewayAddress("", wantErr)
	if _, err := b.GatewayAddress(envID); !errors.Is(err, wantErr) {
		t.Errorf("GatewayAddress err = %v, want %v", err, wantErr)
	}
}

// TestGatewayAddress_UnknownEnvIDError verifies the supervisor's
// "env not created" path is still exercised even when the override
// is left at the default.
func TestGatewayAddress_UnknownEnvIDError(t *testing.T) {
	t.Parallel()
	b := New(newFixedTime())
	if _, err := b.GatewayAddress("does-not-exist"); err == nil {
		t.Errorf("GatewayAddress(unknown) err = nil, want non-nil")
	}
}

// TestMappedUID_DefaultsToEnvSpecUID pins Plan §0.5: when the
// backend does not implement userns-remap, MappedUID returns the
// EnvSpec.UID verbatim (or 0 when EnvSpec.UID was nil).
func TestMappedUID_DefaultsToEnvSpecUID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		uid  *int
		want int
	}{
		{name: "nil-uid-defaults-to-0", uid: nil, want: 0},
		{name: "root", uid: intPtr(0), want: 0},
		{name: "non-root", uid: intPtr(1000), want: 1000},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := New(newFixedTime())
			envID, err := b.Create(backend.EnvSpec{
				Name:          tc.name,
				WorkspacePath: "/ws",
				UID:           tc.uid,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, err := b.MappedUID(envID)
			if err != nil {
				t.Fatalf("MappedUID: %v", err)
			}
			if got != tc.want {
				t.Errorf("MappedUID = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestMappedUID_RespectsOverride pins the SetMappedUID override
// path tests use to simulate userns-remap.
func TestMappedUID_RespectsOverride(t *testing.T) {
	t.Parallel()
	b := New(newFixedTime())
	envID, err := b.Create(backend.EnvSpec{
		Name:          "fix-tests",
		WorkspacePath: "/ws",
		UID:           intPtr(0),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	b.SetMappedUID(envID, 100000)
	got, err := b.MappedUID(envID)
	if err != nil {
		t.Fatalf("MappedUID: %v", err)
	}
	if got != 100000 {
		t.Errorf("MappedUID = %d, want 100000 (host-mapped UID)", got)
	}
}

// TestMappedUID_ErrorOverride pins the SetMappedUIDError path that
// drives the supervisor's "remap probe failed" refuse-to-start
// branch.
func TestMappedUID_ErrorOverride(t *testing.T) {
	t.Parallel()
	b := New(newFixedTime())
	envID, err := b.Create(backend.EnvSpec{Name: "x", WorkspacePath: "/ws"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := errors.New("probe failed")
	b.SetMappedUIDError(want)
	if _, err := b.MappedUID(envID); !errors.Is(err, want) {
		t.Errorf("MappedUID err = %v, want %v", err, want)
	}
}

// TestProbeImage_DefaultsToEmpty pins the documented default:
// ("", nil) so the supervisor falls back to the policy default
// `/root` per Plan §0.5.
func TestProbeImage_DefaultsToEmpty(t *testing.T) {
	t.Parallel()
	b := New(newFixedTime())
	home, err := b.ProbeImage("node", intPtr(0))
	if err != nil {
		t.Fatalf("ProbeImage: %v", err)
	}
	if home != "" {
		t.Errorf("ProbeImage default = %q, want empty", home)
	}
}

// TestProbeImage_RespectsOverride pins the SetProbeImage path tests
// use to drive HomeTarget resolution.
func TestProbeImage_RespectsOverride(t *testing.T) {
	t.Parallel()
	b := New(newFixedTime())
	b.SetProbeImage("/home/agent", nil)
	home, err := b.ProbeImage("node", intPtr(1000))
	if err != nil {
		t.Fatalf("ProbeImage: %v", err)
	}
	if home != "/home/agent" {
		t.Errorf("ProbeImage = %q, want /home/agent", home)
	}
}

// TestCreate_RecordsBindMountsAndUID pins that the EnvSpec extension
// fields (BindMounts, UID, HomeTarget) round-trip through the mock's
// recorded Call so a downstream test that asserts on b.Calls() sees
// the values the supervisor passed in.
func TestCreate_RecordsBindMountsAndUID(t *testing.T) {
	t.Parallel()
	b := New(newFixedTime())
	uid := 1000
	spec := backend.EnvSpec{
		Name:          "fix-tests",
		WorkspacePath: "/ws",
		UID:           &uid,
		HomeTarget:    "/home/agent",
		BindMounts: []backend.BindMount{
			{Source: "/runDir/ipc", Target: "/var/run/ai-env", ReadOnly: false},
			{Source: "/runDir/shim", Target: "/var/run/ai-env/shim", ReadOnly: true},
		},
	}
	if _, err := b.Create(spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	calls := b.Calls()
	var createCall Call
	for _, c := range calls {
		if c.Method == "Create" {
			createCall = c
		}
	}
	if createCall.Method != "Create" {
		t.Fatalf("no Create call recorded; calls = %+v", calls)
	}
	if len(createCall.Spec.BindMounts) != 2 {
		t.Errorf("Spec.BindMounts len = %d, want 2", len(createCall.Spec.BindMounts))
	}
	if createCall.Spec.UID == nil || *createCall.Spec.UID != 1000 {
		t.Errorf("Spec.UID = %v, want pointer to 1000", createCall.Spec.UID)
	}
	if createCall.Spec.HomeTarget != "/home/agent" {
		t.Errorf("Spec.HomeTarget = %q, want /home/agent", createCall.Spec.HomeTarget)
	}
}

func intPtr(v int) *int { return &v }
