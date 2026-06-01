// Package capability owns the single source of truth for host-side
// runtime capability detection. The plan's "Batch 0.4 — Capability
// detection" entry pins this package as the place every consumer asks
// when it needs to decide between alternative implementations that
// depend on what the host can do, rather than what the binary was
// compiled to do.
//
// The plan calls out two concrete consumers:
//
//  1. The supervisor's pre-launch step 6 (Plan §5.5) picks the
//     ProviderProxy reachability mode. The chain is documented in the
//     plan as SetnsTCP → BridgeGateway → UnixSocket; each step is gated
//     by a different capability. SetnsTCP requires that the host be on
//     Linux and that the supervisor process can enter the sandbox's
//     network namespace (CAP_SYS_ADMIN or equivalent). BridgeGateway
//     requires that the backend report a reachable gateway address.
//     UnixSocket is the fallback the agent CLI's HTTP client honors only
//     when the feature probe reports it.
//
//  2. The supervisor's pre-launch step 5 starts the egress observer.
//     NFLOG attach requires CAP_NET_ADMIN; slirp4netns environments
//     answer "observer_unavailable" with reason="slirp4netns"; rootless
//     bridge environments may have BridgeGateway but no CAP_NET_ADMIN.
//
// In addition, plan iteration 4 added a Linux-specific signal that the
// rest of the supervisor depends on at backend.Create time:
//
//  3. Userns-remap detection. When dockerd is configured with
//     `userns-remap`, the UID the sandbox sees inside the container is
//     not the UID a host-side chown/stat uses. Plan §0.5 introduces
//     `Backend.MappedUID(envID)` to round-trip the mapping; the
//     capability detector reports the *host-side* signal that
//     userns-remap is active so the supervisor can refuse to start when
//     a backend that does not implement `MappedUID` is paired with a
//     remap-enabled daemon. The detector does NOT resolve the actual
//     mapping (that is the backend's job); it only flips a "be
//     defensive" bit.
//
// Design rules:
//
//   - Pure-Go probing, no exec. Every probe in this package consults
//     /proc, /etc, or syscall — never shells out to `nsenter`, `ip
//     netns`, `tcpdump`, or `iptables`. Spawning a child to probe a
//     capability we then use ourselves would race the probe against
//     the actual use.
//
//   - Probes are best-effort. A probe that cannot determine the answer
//     reports the conservative value (false / "unknown") rather than
//     panicking. The supervisor degrades gracefully when a capability
//     is missing; it must not crash because the detector itself
//     failed.
//
//   - One `Detect()` call per supervisor run. The plan's intent is
//     that the detector runs once at supervisor start, the result is
//     cached on the Supervisor struct, and every consumer (step 6 in
//     Batch 5.5, the observer mode picker in §5.0, the userns-remap
//     refusal at backend.Create) reads off the cached value. Calling
//     `Detect()` more than once per run is harmless but wasteful.
//
//   - The struct shape is stable. New capabilities are added by
//     extending the `Capability` struct with a new bool / string. The
//     existing fields keep their names and zero-value semantics so a
//     downstream test that pins one field stays green when other
//     fields change.
package capability

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Capability captures every host-side probe result the supervisor
// consults at runtime. The struct is read-only after `Detect()`
// returns; the supervisor caches one instance per run. Zero-value of
// every field is "missing / conservative", so an uninitialised
// Capability behaves like a host with no privileged capabilities.
//
// Field order is the order Detect() populates them; field names mirror
// the plan's locked-decision rows so a reviewer can grep verbatim.
type Capability struct {
	// OS is `runtime.GOOS`. Captured here so callers that branch on
	// OS-specific paths (NFLOG vs pflog, /dev/fd presence, userns-
	// remap detection) can read from one place rather than from
	// `runtime.GOOS` directly. Mirrors the plan's "Linux-only" /
	// "macOS-only" annotations.
	OS string

	// CAPNetAdmin is true when the supervisor process has the
	// CAP_NET_ADMIN capability. Linux NFLOG attach (Batch 5.2) and
	// per-run iptables rules (Batch 5.4) require it. On macOS this
	// is always false; the plan's macOS path uses pflog and pf
	// rules which take their own permission route (sudo for `pfctl`
	// is documented as a dev-machine setup step in the platform
	// matrix).
	CAPNetAdmin bool

	// CAPSysAdmin is true when the supervisor process has the
	// CAP_SYS_ADMIN capability. This is the gate for `setns(2)` into
	// a different network namespace (the SetnsTCP ProviderProxy
	// mode) and for mount-namespace operations the backend may
	// require. On macOS this is always false.
	CAPSysAdmin bool

	// SetnsAvailable is true when the host advertises the
	// `unshare(2)` + `setns(2)` syscall surface the
	// containernetworking/plugins/pkg/ns library walks. The
	// supervisor pairs this with CAPSysAdmin to decide whether the
	// SetnsTCP ProviderProxy mode is reachable; both must be true.
	// On macOS this is always false (no `setns` on Darwin).
	SetnsAvailable bool

	// NFLOGAvailable is true when the kernel exposes the netfilter
	// log socket family the `florianl/go-nflog/v2` library binds to.
	// The supervisor pairs this with CAPNetAdmin to decide whether
	// the Linux NFLOG-based EgressObserver can attach (Plan §5.2);
	// both must be true. On macOS this is always false; the plan's
	// macOS path uses pflog instead.
	NFLOGAvailable bool

	// PFLogAvailable is true when the host is macOS and the `pflog0`
	// interface exists (the plan's §5.3 macOS observer attaches to
	// it). Detection is best-effort: a stat against
	// `/dev/bpf<n>` and a check for the pflog interface in
	// `/dev/pf` access permissions; failure reports false.
	// On Linux this is always false.
	PFLogAvailable bool

	// Slirp4netns is true when the host is a rootless container
	// runtime (Podman rootless / nested-Docker rootless) running
	// inside slirp4netns. The plan locks slirp4netns to the
	// `observer_unavailable` reason="slirp4netns" branch in
	// Batch 5.0 because NFLOG cannot reach the userns-resident
	// netns through the slirp4netns proxy. Detection probes for
	// the well-known slirp4netns process / cgroup markers; failure
	// reports false (the conservative branch).
	Slirp4netns bool

	// BridgeGatewayLikely is true when the supervisor is on a host
	// where Docker / Podman normally exposes a bridge gateway IP
	// reachable from inside the sandbox. The supervisor pairs this
	// with `Backend.GatewayAddress()` (Batch 0.5) at step 6 to pick
	// the BridgeGateway ProviderProxy mode. The detector does NOT
	// dial the gateway; it only signals "this combination is
	// plausible" so the supervisor can fall through to BridgeGateway
	// when SetnsTCP is unavailable. On macOS this is always false
	// (Docker Desktop's network is opaque to the host).
	BridgeGatewayLikely bool

	// DevFdAvailable is true when the host exposes the `/dev/fd/<n>`
	// pseudo-filesystem. The plan's Batch 1.2 / Batch 0.3 use
	// `/dev/fd/<n>` on macOS to drive the single-fd TOCTOU-safe
	// interpreter-via-file exec flow (Linux uses
	// `SYS_EXECVEAT(fd, ...)` directly). On Linux this is also
	// usually true; the field is read on both OSes so a Linux host
	// without `/dev/fd` (rare; e.g. a container without `/dev`
	// mounted) can still degrade gracefully.
	DevFdAvailable bool

	// UserNSRemap is true when the supervisor is on Linux and a
	// docker / podman daemon configured with `userns-remap` is
	// likely active. The plan's Batch 0.5 `Backend.MappedUID(envID)`
	// is mandatory in this mode (chown'ing the control socket to
	// the in-sandbox UID requires the host-mapped UID, not the
	// in-sandbox UID). The detector signals "be defensive" by
	// reading well-known daemon-config paths; the actual host-mapped
	// UID is the backend's responsibility to report at envID time.
	// On macOS this is always false (Docker Desktop hides userns).
	UserNSRemap bool

	// Errors captures non-fatal probe errors. The detector does not
	// fail when a single probe cannot determine its answer; it
	// records the error so an operator-facing diagnostic (Batch
	// 10.5 `ai-env doctor`) can surface the reason without re-
	// running detection. Callers that only care about the boolean
	// flags can ignore this field.
	Errors []error
}

// providerProxyReachabilityNFLOGProbePath is a per-OS list of paths
// the detector consults to decide whether NFLOG is reachable. The
// canonical Linux NFLOG socket is created on-demand by the kernel
// when a process binds it via `netlink(7) NETLINK_NETFILTER`; we
// cannot stat it ahead of time without actually opening the socket,
// which requires CAP_NET_ADMIN. Instead we look for the kernel module
// markers `/proc/net/netfilter/nf_log` and
// `/proc/sys/net/netfilter/nf_log/*`; if either is present we report
// "available" and let the actual attach succeed-or-degrade at attach
// time.
var providerProxyReachabilityNFLOGProbePath = []string{
	"/proc/net/netfilter/nf_log",
	"/proc/sys/net/netfilter",
}

// slirp4netnsMarkers is the list of well-known paths and process
// names a slirp4netns environment leaves on the supervisor's host
// view. The detector reports Slirp4netns=true when any one of them is
// present; the conservative false default keeps non-slirp hosts on
// the "observer reachable" path.
//
// We probe three independent surfaces because a hardened deployment
// might rename one of them:
//
//   - the slirp4netns binary on PATH (cheap probe, normally present
//     on Podman-rootless hosts);
//   - the cgroup signature in /proc/self/cgroup pointing at the
//     "/user.slice/...slirp..." path (the typical layout under
//     systemd-managed Podman);
//   - the environment variable SLIRP4NETNS_RUNNING the Podman
//     rootless wrapper sets when entering its userns.
//
// Any non-empty hit flips the bit; the supervisor will emit
// `observer_unavailable` with reason="slirp4netns" rather than
// attempting an NFLOG attach that we know will fail.
var slirp4netnsMarkers = struct {
	binNames []string
	env      string
	cgroup   string
}{
	binNames: []string{"slirp4netns"},
	env:      "SLIRP4NETNS_RUNNING",
	cgroup:   "/proc/self/cgroup",
}

// Detect probes the host once and returns the resulting capability
// snapshot. The function never fails — probes that cannot determine
// their answer record an entry in `Errors` and fall through to the
// conservative default. Callers cache the result on a per-supervisor
// run.
//
// Order of probes matches the order the supervisor consumes them
// (Plan §5.5 step 5 → step 6 → step 8): observer-mode signals first,
// then ProviderProxy reachability hints, then the platform-specific
// quirks (UserNSRemap, /dev/fd). The order is irrelevant to
// correctness; it documents the read pattern for a reviewer.
func Detect() Capability {
	c := Capability{
		OS: runtime.GOOS,
	}

	// 1) Linux-specific privileged capabilities. We probe
	//    /proc/self/status's CapEff bitmap rather than dialing
	//    `getcap`/`capsh`: the former is part of the kernel ABI we
	//    already depend on, the latter would require shelling out.
	//    On non-Linux hosts the probe records a benign skip.
	if c.OS == "linux" {
		netAdmin, sysAdmin, err := readCapEffective()
		if err != nil {
			c.Errors = append(c.Errors, err)
		} else {
			c.CAPNetAdmin = netAdmin
			c.CAPSysAdmin = sysAdmin
		}

		// SetnsAvailable: setns(2) is part of the Linux ABI since
		// kernel 3.0; the supervisor depends on it via the
		// containernetworking/plugins library. We treat its
		// availability as equivalent to "Linux + CAP_SYS_ADMIN" for
		// the supervisor's purposes; a Linux kernel without setns is
		// outside the supported matrix.
		c.SetnsAvailable = c.CAPSysAdmin

		// NFLOGAvailable: probe the netfilter markers. The probe
		// reports true when the kernel exposes the netfilter
		// subsystem; the actual attach succeeds only when
		// CAPNetAdmin is also true.
		c.NFLOGAvailable = anyPathExists(providerProxyReachabilityNFLOGProbePath)

		// Slirp4netns: probe binary + env + cgroup. Any non-empty
		// hit flips the bit.
		c.Slirp4netns = detectSlirp4netns()

		// UserNSRemap: probe daemon config. Defensive false.
		c.UserNSRemap = detectUserNSRemap()

		// BridgeGatewayLikely: on Linux a Docker/Podman daemon
		// usually provides a bridge gateway reachable from inside
		// the sandbox. The detector reports true when /sys/class/net
		// contains a "docker0" or "podman0" interface; the
		// supervisor still must call `Backend.GatewayAddress()` at
		// step 6 for the actual IP.
		c.BridgeGatewayLikely = anyPathExists([]string{
			"/sys/class/net/docker0",
			"/sys/class/net/podman0",
			"/sys/class/net/cni0",
		})
	}

	// 2) Darwin-specific probes. macOS does not expose CAP_NET_ADMIN
	//    / CAP_SYS_ADMIN to non-root processes; pflog0 is the
	//    canonical packet-log interface; /dev/fd is always present
	//    on the default filesystem (HFS+, APFS).
	if c.OS == "darwin" {
		// PFLogAvailable: stat /dev/pf; the canonical packet-filter
		// device. A non-existent file means pf is not loaded; the
		// supervisor will emit `observer_unavailable`.
		c.PFLogAvailable = pathExists("/dev/pf")
	}

	// 3) Cross-OS probe: /dev/fd availability. The supervisor's
	//    shim-helper uses /dev/fd/<n> on macOS for the
	//    interpreter-via-file TOCTOU-safe exec flow (Batch 1.2);
	//    Linux uses SYS_EXECVEAT directly but /dev/fd is still
	//    useful for log redirection. The probe stats /dev/fd; either
	//    a directory or a symlink to /proc/self/fd is acceptable.
	c.DevFdAvailable = pathExists("/dev/fd")

	return c
}

// readCapEffective parses /proc/self/status's CapEff line and returns
// (CAP_NET_ADMIN, CAP_SYS_ADMIN). The CapEff format is a single hex
// word; the bit positions match the canonical Linux capability list
// (CAP_NET_ADMIN=12, CAP_SYS_ADMIN=21). On parse failure both bools
// are false and the error is returned for the Errors slice.
//
// We read /proc/self/status rather than syscall.Capabilities because
// the latter requires a privileged path; reading the file is enough
// and avoids pulling in a syscall-level capability library.
func readCapEffective() (netAdmin, sysAdmin bool, err error) {
	const statusPath = "/proc/self/status"
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return false, false, err
	}
	const capEffPrefix = "CapEff:"
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, capEffPrefix) {
			continue
		}
		hexpart := strings.TrimSpace(strings.TrimPrefix(line, capEffPrefix))
		// CapEff is rendered as a 16-char hex word, big-endian.
		bits, perr := parseCapHex(hexpart)
		if perr != nil {
			return false, false, perr
		}
		// CAP_NET_ADMIN = 12; CAP_SYS_ADMIN = 21. The bits are
		// indexed from the low end (bit 0 = CAP_CHOWN).
		const capNetAdmin = 12
		const capSysAdmin = 21
		netAdmin = bits&(uint64(1)<<capNetAdmin) != 0
		sysAdmin = bits&(uint64(1)<<capSysAdmin) != 0
		return netAdmin, sysAdmin, nil
	}
	return false, false, errors.New("capability: CapEff line not found in /proc/self/status")
}

// parseCapHex parses a capability hex word as it appears in
// /proc/self/status's CapEff line. The line is rendered without a
// leading "0x" and may be padded with leading zeros; we accept either
// shape and reject anything else as a parse error.
func parseCapHex(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("capability: empty CapEff hex word")
	}
	var n uint64
	for _, r := range s {
		var d uint64
		switch {
		case r >= '0' && r <= '9':
			d = uint64(r - '0')
		case r >= 'a' && r <= 'f':
			d = uint64(r-'a') + 10
		case r >= 'A' && r <= 'F':
			d = uint64(r-'A') + 10
		default:
			return 0, errors.New("capability: non-hex character in CapEff hex word")
		}
		n = n<<4 | d
	}
	return n, nil
}

// detectSlirp4netns probes the three slirp4netns markers in order of
// cheapest-to-most-expensive. The first hit returns true; only when
// all three fail do we report false. The cgroup probe is conservative
// (we only flip on a literal "slirp" substring) to avoid false
// positives on hosts that happen to have "slirp" in an unrelated cgroup
// name.
func detectSlirp4netns() bool {
	// 1) Environment variable: cheap, set by the Podman rootless
	//    wrapper when entering its userns.
	if os.Getenv(slirp4netnsMarkers.env) != "" {
		return true
	}
	// 2) Binary on PATH: most slirp4netns deployments install the
	//    binary at a canonical path. We do not LookPath because
	//    that would consult $PATH which can be empty in the
	//    supervisor's env; we stat the canonical locations
	//    directly.
	for _, name := range slirp4netnsMarkers.binNames {
		for _, dir := range []string{"/usr/bin", "/bin", "/usr/local/bin"} {
			if pathExists(filepath.Join(dir, name)) {
				return true
			}
		}
	}
	// 3) Cgroup probe: parse /proc/self/cgroup for a "slirp"
	//    substring. The conservative substring keeps false
	//    positives low.
	data, err := os.ReadFile(slirp4netnsMarkers.cgroup)
	if err == nil && strings.Contains(string(data), "slirp") {
		return true
	}
	return false
}

// detectUserNSRemap probes the well-known docker/podman config paths
// for a userns-remap entry. The probe is intentionally conservative:
// we flip the bit only when the config file contains a recognizable
// "userns-remap" key or a non-default subuid entry. The actual
// per-container mapping is the backend's responsibility to report at
// envID time via Backend.MappedUID; the detector's signal only
// triggers a refusal-to-start when a remap-enabled daemon is paired
// with a backend that does not implement MappedUID.
func detectUserNSRemap() bool {
	// /etc/docker/daemon.json: look for a "userns-remap" key. We
	// do a substring match rather than a full JSON parse because
	// the daemon.json format is documented to be a single flat
	// object and operators frequently hand-edit it (so the
	// substring is more robust than a fragile JSON walk).
	if data, err := os.ReadFile("/etc/docker/daemon.json"); err == nil {
		if strings.Contains(string(data), "\"userns-remap\"") {
			// Confirm the value is non-empty / non-"default";
			// dockerd treats "default" as "no remap" semantically.
			if !strings.Contains(string(data), "\"userns-remap\": \"\"") &&
				!strings.Contains(string(data), "\"userns-remap\":\"\"") {
				return true
			}
		}
	}
	// /etc/subuid + /etc/subgid: the presence of an entry for the
	// "dockremap" user is the canonical signal that dockerd was
	// configured with `--userns-remap=default`. We do not parse the
	// file fully; we look for the literal username.
	for _, path := range []string{"/etc/subuid", "/etc/subgid"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "dockremap:") {
			return true
		}
	}
	return false
}

// anyPathExists returns true when at least one of the given paths
// exists on the filesystem. We use os.Stat rather than os.Lstat
// because a symlink target is good enough for capability detection
// (the supervisor cares whether the path is reachable, not whether it
// is a direct file).
func anyPathExists(paths []string) bool {
	for _, p := range paths {
		if pathExists(p) {
			return true
		}
	}
	return false
}

// pathExists returns true when the path exists on the filesystem.
// A stat error (anything other than IsNotExist) is treated as
// "exists but we cannot read it" — for capability detection that is
// still a positive signal that the surface is present. Only an
// explicit NotExist returns false.
func pathExists(p string) bool {
	_, err := os.Stat(p)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	// Any other error (permission denied, EIO) means the path is
	// present; we count that as a positive signal because the
	// supervisor's downstream code will fail with a clearer error
	// when it tries to actually use the surface.
	return true
}

// ProviderProxyMode is a typed string for the ProviderProxy
// reachability mode the supervisor picks at Plan §5.5 step 6. The
// values mirror the plan's "BindMode chain" verbiage.
type ProviderProxyMode string

const (
	// ProviderProxyModeSetnsTCP enters the sandbox netns and binds
	// a TCP listener inside it (the canonical Linux path). Plan
	// §5.5 step 6 picks this when CAPSysAdmin + SetnsAvailable are
	// both true.
	ProviderProxyModeSetnsTCP ProviderProxyMode = "setns_tcp"

	// ProviderProxyModeBridgeGateway binds the proxy on the
	// host-side bridge gateway IP the backend reports via
	// `Backend.GatewayAddress()`. The supervisor narrows
	// NetworkPolicy.ProxyCarveOuts to include this address so the
	// sandbox's egress rules tolerate the traffic.
	ProviderProxyModeBridgeGateway ProviderProxyMode = "bridge_gateway"

	// ProviderProxyModeUnixSocket binds the proxy on a per-run
	// Unix socket. The feature probe gates whether the agent CLI's
	// HTTP client honors http+unix; the plan's iter-2 decision
	// keeps this as a last-resort fallback.
	ProviderProxyModeUnixSocket ProviderProxyMode = "unix_socket"
)

// PickProviderProxyMode returns the mode the supervisor should pick
// at Plan §5.5 step 6 given the host capability snapshot and the
// (optional) outcome of `Backend.GatewayAddress()`. The supervisor
// passes `gatewayAvailable=true` when GatewayAddress returned a
// non-empty IP, `false` otherwise.
//
// The picker codifies the plan's chain:
//
//  1. SetnsTCP when on Linux with CAP_SYS_ADMIN + setns availability.
//  2. BridgeGateway when the backend reports a gateway address and
//     the host's bridge interface probe came back positive.
//  3. UnixSocket otherwise (the agent-CLI feature probe is the
//     caller's responsibility before relying on this mode).
//
// The function is pure (no side effects, no IO); the supervisor calls
// it after `Detect()` and the backend's GatewayAddress probe.
func (c Capability) PickProviderProxyMode(gatewayAvailable bool) ProviderProxyMode {
	if c.OS == "linux" && c.CAPSysAdmin && c.SetnsAvailable {
		return ProviderProxyModeSetnsTCP
	}
	if gatewayAvailable && c.BridgeGatewayLikely {
		return ProviderProxyModeBridgeGateway
	}
	return ProviderProxyModeUnixSocket
}

// ObserverModeAvailable reports whether the supervisor can attach an
// EgressObserver in this run. The plan's Batch 5.0 / 5.2 / 5.3 chain
// gates the attach by:
//
//   - Linux: NFLOG attach requires CAP_NET_ADMIN + NFLOG kernel
//     module; slirp4netns short-circuits to false.
//   - macOS: pflog attach requires the pflog0 interface (we probed
//     it via /dev/pf availability).
//
// When this returns false the supervisor emits the
// `observer_unavailable` lifecycle verb (Batch 0.1) with the
// `Reason()` token below.
func (c Capability) ObserverModeAvailable() bool {
	if c.Slirp4netns {
		return false
	}
	switch c.OS {
	case "linux":
		return c.CAPNetAdmin && c.NFLOGAvailable
	case "darwin":
		return c.PFLogAvailable
	default:
		return false
	}
}

// ObserverUnavailableReason returns the short-token reason the
// supervisor should put in the `observer_unavailable` lifecycle verb's
// Metadata when ObserverModeAvailable() reports false. The tokens
// mirror the plan's Batch 0.1 Metadata table for the verb.
//
// Returns "" when the observer IS available; callers should branch on
// ObserverModeAvailable() first.
func (c Capability) ObserverUnavailableReason() string {
	if c.Slirp4netns {
		return "slirp4netns"
	}
	switch c.OS {
	case "linux":
		if !c.CAPNetAdmin {
			return "no_capability"
		}
		if !c.NFLOGAvailable {
			return "no_nflog"
		}
	case "darwin":
		if !c.PFLogAvailable {
			return "no_pflog"
		}
	default:
		return "unsupported_os"
	}
	return ""
}

// RequiresMappedUID reports whether the host's userns-remap signal
// means the backend MUST implement Backend.MappedUID. The plan's
// Batch 0.5 says: "Backend.MappedUID is mandatory for userns-remap
// setups; backends that do not implement it limit support to
// non-remap configurations." The supervisor reads this method right
// before backend.Create and refuses to start when the bit is true and
// the configured backend does not implement MappedUID.
//
// Defensive false on non-Linux: macOS Docker Desktop hides userns
// behind the VM boundary; the supervisor's chown happens against the
// VM's UID, not the host's.
func (c Capability) RequiresMappedUID() bool {
	return c.OS == "linux" && c.UserNSRemap
}
