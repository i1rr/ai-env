package capability

import (
	"runtime"
	"strings"
	"testing"
)

// TestDetect_RecordsOS pins the cheapest invariant in the package: the
// detector always populates Capability.OS from runtime.GOOS. Every
// downstream consumer branches on this field; a regression that left
// it empty would make every OS-specific picker silently fall to the
// default branch.
func TestDetect_RecordsOS(t *testing.T) {
	got := Detect()
	if got.OS != runtime.GOOS {
		t.Fatalf("Detect().OS = %q, want %q", got.OS, runtime.GOOS)
	}
}

// TestDetect_DoesNotPanic asserts that the detector returns without
// panic on whatever host the test is running on. The plan's design
// rule is "probes are best-effort": a probe that cannot determine its
// answer records an error and falls through to the conservative
// default. A panic in any probe would defeat that guarantee.
func TestDetect_DoesNotPanic(t *testing.T) {
	// The defer/recover pattern surfaces a panic as a test failure
	// rather than killing the entire test binary; this also catches
	// regressions where a future probe forgets to nil-check a slice.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Detect panicked: %v", r)
		}
	}()
	_ = Detect()
}

// TestDetect_NonLinuxOSDoesNotReportLinuxCapabilities pins the cross-
// OS conservatism guarantee: when the supervisor runs on macOS, every
// Linux-specific flag is false. A macOS host reporting CAPNetAdmin /
// SetnsAvailable would route the supervisor down a code path that
// would crash at attach time.
func TestDetect_NonLinuxOSDoesNotReportLinuxCapabilities(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux host; the assertion in this test is for non-Linux only")
	}
	got := Detect()
	if got.CAPNetAdmin {
		t.Errorf("Detect().CAPNetAdmin = true on %s, want false", runtime.GOOS)
	}
	if got.CAPSysAdmin {
		t.Errorf("Detect().CAPSysAdmin = true on %s, want false", runtime.GOOS)
	}
	if got.SetnsAvailable {
		t.Errorf("Detect().SetnsAvailable = true on %s, want false", runtime.GOOS)
	}
	if got.NFLOGAvailable {
		t.Errorf("Detect().NFLOGAvailable = true on %s, want false", runtime.GOOS)
	}
	if got.Slirp4netns {
		t.Errorf("Detect().Slirp4netns = true on %s, want false", runtime.GOOS)
	}
	if got.UserNSRemap {
		t.Errorf("Detect().UserNSRemap = true on %s, want false", runtime.GOOS)
	}
	if got.BridgeGatewayLikely {
		t.Errorf("Detect().BridgeGatewayLikely = true on %s, want false", runtime.GOOS)
	}
}

// TestPickProviderProxyMode_SetnsTCPRequiresLinuxAndSysAdmin pins the
// top branch of the chain: SetnsTCP is the canonical Linux path
// gated by CAP_SYS_ADMIN. Any other combination falls through to one
// of the lower modes.
func TestPickProviderProxyMode_SetnsTCPRequiresLinuxAndSysAdmin(t *testing.T) {
	c := Capability{OS: "linux", CAPSysAdmin: true, SetnsAvailable: true}
	if got := c.PickProviderProxyMode(true); got != ProviderProxyModeSetnsTCP {
		t.Errorf("PickProviderProxyMode(linux+SYS_ADMIN+setns) = %q, want %q", got, ProviderProxyModeSetnsTCP)
	}
	// Without CAP_SYS_ADMIN, even on Linux, SetnsTCP must not be
	// picked: the supervisor would otherwise call ns.WithNetNSPath
	// and fail at runtime.
	c2 := Capability{OS: "linux", CAPSysAdmin: false, SetnsAvailable: true, BridgeGatewayLikely: true}
	if got := c2.PickProviderProxyMode(true); got == ProviderProxyModeSetnsTCP {
		t.Errorf("PickProviderProxyMode(linux+no-SYS_ADMIN) = %q, must not be %q", got, ProviderProxyModeSetnsTCP)
	}
}

// TestPickProviderProxyMode_BridgeGatewayRequiresGatewayAndProbe pins
// the middle branch: BridgeGateway is picked only when the backend
// reports a gateway IP AND the host's bridge probe came back positive.
// Either condition missing falls through to UnixSocket.
func TestPickProviderProxyMode_BridgeGatewayRequiresGatewayAndProbe(t *testing.T) {
	c := Capability{OS: "linux", CAPSysAdmin: false, BridgeGatewayLikely: true}
	if got := c.PickProviderProxyMode(true); got != ProviderProxyModeBridgeGateway {
		t.Errorf("PickProviderProxyMode(bridge+gateway-true) = %q, want %q", got, ProviderProxyModeBridgeGateway)
	}
	// Backend says "no gateway": fall through to UnixSocket.
	if got := c.PickProviderProxyMode(false); got != ProviderProxyModeUnixSocket {
		t.Errorf("PickProviderProxyMode(bridge+gateway-false) = %q, want %q", got, ProviderProxyModeUnixSocket)
	}
	// Host probe says "no bridge interface": fall through to
	// UnixSocket even when the backend reports a gateway.
	c2 := Capability{OS: "linux", CAPSysAdmin: false, BridgeGatewayLikely: false}
	if got := c2.PickProviderProxyMode(true); got != ProviderProxyModeUnixSocket {
		t.Errorf("PickProviderProxyMode(no-bridge-probe) = %q, want %q", got, ProviderProxyModeUnixSocket)
	}
}

// TestPickProviderProxyMode_DarwinFallsToUnixSocket pins the macOS
// behavior: no SetnsTCP, no BridgeGateway, only UnixSocket. The plan
// documents this in the platform matrix; the test pins it.
func TestPickProviderProxyMode_DarwinFallsToUnixSocket(t *testing.T) {
	c := Capability{OS: "darwin"}
	if got := c.PickProviderProxyMode(true); got != ProviderProxyModeUnixSocket {
		t.Errorf("PickProviderProxyMode(darwin) = %q, want %q", got, ProviderProxyModeUnixSocket)
	}
}

// TestObserverModeAvailable_LinuxRequiresNFLOGAndCapNetAdmin pins the
// Linux observer gate: NFLOG attach needs both the kernel module and
// CAP_NET_ADMIN. Either missing returns false.
func TestObserverModeAvailable_LinuxRequiresNFLOGAndCapNetAdmin(t *testing.T) {
	c := Capability{OS: "linux", CAPNetAdmin: true, NFLOGAvailable: true}
	if !c.ObserverModeAvailable() {
		t.Errorf("ObserverModeAvailable(linux+CAP+NFLOG) = false, want true")
	}
	c2 := Capability{OS: "linux", CAPNetAdmin: false, NFLOGAvailable: true}
	if c2.ObserverModeAvailable() {
		t.Errorf("ObserverModeAvailable(linux+no-CAP) = true, want false")
	}
	c3 := Capability{OS: "linux", CAPNetAdmin: true, NFLOGAvailable: false}
	if c3.ObserverModeAvailable() {
		t.Errorf("ObserverModeAvailable(linux+no-NFLOG) = true, want false")
	}
}

// TestObserverModeAvailable_Slirp4netnsShortCircuits pins the plan's
// locked decision: slirp4netns hosts always report observer
// unavailable regardless of other signals, because NFLOG cannot reach
// the userns-resident netns through the slirp4netns proxy.
func TestObserverModeAvailable_Slirp4netnsShortCircuits(t *testing.T) {
	c := Capability{OS: "linux", CAPNetAdmin: true, NFLOGAvailable: true, Slirp4netns: true}
	if c.ObserverModeAvailable() {
		t.Errorf("ObserverModeAvailable(slirp4netns) = true, want false (plan locks this)")
	}
	if c.ObserverUnavailableReason() != "slirp4netns" {
		t.Errorf("ObserverUnavailableReason(slirp4netns) = %q, want %q", c.ObserverUnavailableReason(), "slirp4netns")
	}
}

// TestObserverUnavailableReason_PinsTokens checks the exact tokens
// the supervisor will write into the lifecycle verb's Metadata.
// Downstream readers (Batch 10.5 doctor) join on these strings.
func TestObserverUnavailableReason_PinsTokens(t *testing.T) {
	cases := []struct {
		name string
		cap  Capability
		want string
	}{
		{
			name: "linux_no_capability",
			cap:  Capability{OS: "linux", CAPNetAdmin: false, NFLOGAvailable: true},
			want: "no_capability",
		},
		{
			name: "linux_no_nflog",
			cap:  Capability{OS: "linux", CAPNetAdmin: true, NFLOGAvailable: false},
			want: "no_nflog",
		},
		{
			name: "darwin_no_pflog",
			cap:  Capability{OS: "darwin", PFLogAvailable: false},
			want: "no_pflog",
		},
		{
			name: "unsupported_os",
			cap:  Capability{OS: "windows"},
			want: "unsupported_os",
		},
		{
			name: "linux_available_empty_reason",
			cap:  Capability{OS: "linux", CAPNetAdmin: true, NFLOGAvailable: true},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cap.ObserverUnavailableReason()
			if got != tc.want {
				t.Errorf("ObserverUnavailableReason() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRequiresMappedUID_OnlyLinuxAndOnlyWhenUserNSRemap pins the
// Batch 0.5 contract: the supervisor refuses to start when the host's
// userns-remap signal is true but the backend does not implement
// MappedUID. The detector's bit is the trigger; macOS always reports
// false (Docker Desktop's userns is behind the VM boundary).
func TestRequiresMappedUID_OnlyLinuxAndOnlyWhenUserNSRemap(t *testing.T) {
	c := Capability{OS: "linux", UserNSRemap: true}
	if !c.RequiresMappedUID() {
		t.Errorf("RequiresMappedUID(linux+userns) = false, want true")
	}
	c2 := Capability{OS: "linux", UserNSRemap: false}
	if c2.RequiresMappedUID() {
		t.Errorf("RequiresMappedUID(linux+no-userns) = true, want false")
	}
	c3 := Capability{OS: "darwin", UserNSRemap: true}
	if c3.RequiresMappedUID() {
		t.Errorf("RequiresMappedUID(darwin) = true, want false")
	}
}

// TestParseCapHex_Roundtrip pins the CapEff parser against the
// canonical hex shapes /proc/self/status emits. The parser is small
// but the bit math (CAP_NET_ADMIN=12, CAP_SYS_ADMIN=21) is load-
// bearing; a one-bit shift would silently misreport capabilities.
func TestParseCapHex_Roundtrip(t *testing.T) {
	cases := map[string]uint64{
		"0":                0,
		"1":                1,
		"ff":               0xff,
		"00000000a80425fb": 0x00000000a80425fb,
	}
	for in, want := range cases {
		got, err := parseCapHex(in)
		if err != nil {
			t.Errorf("parseCapHex(%q) err = %v, want nil", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseCapHex(%q) = %#x, want %#x", in, got, want)
		}
	}
}

// TestParseCapHex_RejectsNonHex verifies the parser refuses bad input
// rather than silently truncating. The detector pipes the result into
// a bit test; misreading the hex as a smaller number would silently
// flip a capability to false.
func TestParseCapHex_RejectsNonHex(t *testing.T) {
	cases := []string{"", "g", "0x12", "12 34"}
	for _, in := range cases {
		_, err := parseCapHex(in)
		if err == nil {
			t.Errorf("parseCapHex(%q) err = nil, want non-nil", in)
		}
	}
}

// TestParseCapHex_DetectsKnownCapabilities pins the bit math for the
// two capabilities the supervisor cares about: CAP_NET_ADMIN bit 12
// (0x1000) and CAP_SYS_ADMIN bit 21 (0x200000). A hex word with only
// those bits set must produce the right pair when run through the
// CapEff bit test.
func TestParseCapHex_DetectsKnownCapabilities(t *testing.T) {
	// Only CAP_NET_ADMIN: bit 12 = 0x1000.
	bits, err := parseCapHex("1000")
	if err != nil {
		t.Fatalf("parseCapHex: %v", err)
	}
	if bits&(uint64(1)<<12) == 0 {
		t.Errorf("CapEff 0x1000 does not include CAP_NET_ADMIN (bit 12)")
	}
	if bits&(uint64(1)<<21) != 0 {
		t.Errorf("CapEff 0x1000 incorrectly includes CAP_SYS_ADMIN (bit 21)")
	}
	// Only CAP_SYS_ADMIN: bit 21 = 0x200000.
	bits2, err := parseCapHex("200000")
	if err != nil {
		t.Fatalf("parseCapHex: %v", err)
	}
	if bits2&(uint64(1)<<21) == 0 {
		t.Errorf("CapEff 0x200000 does not include CAP_SYS_ADMIN (bit 21)")
	}
	if bits2&(uint64(1)<<12) != 0 {
		t.Errorf("CapEff 0x200000 incorrectly includes CAP_NET_ADMIN (bit 12)")
	}
}

// TestProviderProxyModeStrings pins the string values the picker
// returns. The supervisor writes these tokens into the
// `proxy_started` lifecycle verb's `reachability` Metadata key
// (lifecycle_verbs.go).
func TestProviderProxyModeStrings(t *testing.T) {
	cases := map[ProviderProxyMode]string{
		ProviderProxyModeSetnsTCP:      "setns_tcp",
		ProviderProxyModeBridgeGateway: "bridge_gateway",
		ProviderProxyModeUnixSocket:    "unix_socket",
	}
	for mode, want := range cases {
		if string(mode) != want {
			t.Errorf("ProviderProxyMode %q does not stringify to %q", mode, want)
		}
	}
}

// TestDetect_ErrorsSliceShape verifies the Errors slice is either nil
// or non-empty (never an empty non-nil slice that would confuse a
// caller's len check). The conservative-default rule means callers
// who don't care about errors can ignore the slice entirely; this
// test pins that they can also rely on `if len(c.Errors) == 0`.
func TestDetect_ErrorsSliceShape(t *testing.T) {
	c := Detect()
	if c.Errors != nil && len(c.Errors) == 0 {
		t.Errorf("Detect().Errors is non-nil but empty: %v", c.Errors)
	}
}

// TestDetect_LinuxReadsCapEff exercises the CapEff parser on a real
// Linux host. On non-Linux hosts the test is a no-op; on Linux it
// asserts that the parser at least populates the bool fields without
// error (the actual capability values depend on how the test binary
// was launched and we cannot assert them here without root).
func TestDetect_LinuxReadsCapEff(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Linux-only probe; skipping on %s", runtime.GOOS)
	}
	c := Detect()
	// The detector must not have failed reading /proc/self/status
	// on a default Linux host; if it did, the error would surface in
	// c.Errors with a "CapEff" mention.
	for _, e := range c.Errors {
		if strings.Contains(e.Error(), "CapEff") {
			t.Errorf("Detect recorded CapEff probe error: %v", e)
		}
	}
}
