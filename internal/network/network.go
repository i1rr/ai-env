// Package network defines the canonical runtime view of the outbound
// network policy ai-env enforces on a sandboxed run, and the adapter
// contract concrete backends implement to install that policy.
//
// The package sits between two layers:
//
//   - Above it, internal/config exposes the YAML-shaped policy.yaml
//     network block (see config.NetworkPolicy). That struct mirrors
//     the file faithfully, including fields the runtime does not
//     enforce in v0.1 (TLSMITM, Enforcement). It is not safe to hand
//     directly to a backend.
//   - Below it, internal/backend (and its concrete adapters in
//     docker_sbx, docker, podman, mock) consumes backend.NetworkPolicy
//     through Backend.ApplyNetworkPolicy. That struct is the
//     backend-adapter-facing record of which flags the adapter must
//     translate into its sandbox's native network controls.
//
// internal/network owns the canonical runtime policy
// (NetworkPolicy in this package), the merge of operator-configured
// allow domains with the always-blocked defaults from the master plan
// (private RFC1918 ranges, the cloud metadata IP, localhost, the
// Docker host bridge), and the NetworkPolicyAdapter interface a
// supervisor calls to install a policy on a started environment.
//
// Concrete adapters live next to the backend they wrap (e.g.
// internal/backend/docker_sbx implements NetworkPolicyAdapter by
// translating to `sbx network apply`; the rootless docker / podman
// fallbacks implement it by defaulting to `--network none`). The
// supervisor depends only on the NetworkPolicyAdapter interface so it
// can fail closed uniformly when policy application fails, regardless
// of which backend is in use (see plan task 4: `failed_policy`).
//
// Design rules this package enforces:
//
//  1. Fail closed. NetworkPolicy.Validate rejects policies the runtime
//     cannot apply (e.g. an empty Default, an "allow" default without
//     an explicit operator acknowledgement). The supervisor surfaces
//     the error and aborts the run instead of silently degrading to
//     a permissive configuration.
//  2. Always-blocked defaults are not optional. NewNetworkPolicy
//     forces BlockPrivateRanges, BlockMetadataServices, BlockLocalhost,
//     and BlockHostDockerInternal on regardless of what the operator
//     wrote in policy.yaml. An operator may widen the allowlist; they
//     may not turn off the metadata-IP block in autonomous mode.
//  3. Allow domains are normalized (trimmed, lower-cased, deduped) so
//     downstream adapters see a canonical slice and tests can assert
//     on stable output. Empty entries are dropped.
//
// The struct mirrors the field names the master plan uses verbatim so
// audit logs, run.json, and policy.yaml stay legible side by side.
package network

import (
	"fmt"
	"sort"
	"strings"

	"github.com/i1rr/ai-env/internal/backend"
	"github.com/i1rr/ai-env/internal/config"
)

// DefaultPolicy is the literal string "deny": the only outbound default
// ai-env supports in v0.1 autonomous mode without explicit operator
// opt-in. Mirrored as a constant so call sites compare against the
// canonical value instead of retyping the literal.
const DefaultPolicy = "deny"

// AllowPolicy is the literal string "allow". An "allow" default is
// permitted only for interactive runs; the supervisor refuses to set
// it for autonomous mode. Defined as a constant so future call sites
// (Plan 06+) can compare against the canonical token.
const AllowPolicy = "allow"

// PrivateRangeCIDRs is the set of RFC1918 private network ranges plus
// 127.0.0.0/8 (loopback is lumped here because it is unreachable from
// outside the host and shares the "do not route off-box" intent). An
// adapter that honors NetworkPolicy.BlockPrivateRanges emits one block
// rule per entry. The list is the single source of truth for "private
// range" in ai-env: changing this slice changes what every backend
// adapter blocks when BlockPrivateRanges is true.
//
// 169.254.169.254/32 is NOT in this list: cloud metadata services live
// in their own MetadataServiceCIDRs slice so an operator who wants to
// keep RFC1918 reachable (e.g. a self-hosted CI runner) can still pin
// the metadata block on by itself.
//
// The slice is exported as a value (not a function returning a fresh
// slice) on purpose: callers iterate it and must not mutate it.
var PrivateRangeCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

// MetadataServiceCIDRs is the set of cloud-provider metadata-service IP
// ranges every NetworkPolicy with BlockMetadataServices=true must block.
// The master plan calls out 169.254.169.254 by name (the AWS / GCP /
// Azure link-local metadata endpoint); we encode it as a /32 so the
// adapter emits a single host-route block rather than the entire
// 169.254/16 link-local range.
//
// Kept separate from PrivateRangeCIDRs so operators can compose the
// blocks: an interactive session that allows RFC1918 must still block
// the metadata IP.
var MetadataServiceCIDRs = []string{
	"169.254.169.254/32",
}

// LocalhostCIDRs is the loopback range every NetworkPolicy with
// BlockLocalhost=true blocks from inside the environment. Kept distinct
// from PrivateRangeCIDRs even though both block flags include 127/8 in
// practice: an operator who turns BlockPrivateRanges off but leaves
// BlockLocalhost on still gets loopback closed.
var LocalhostCIDRs = []string{
	"127.0.0.0/8",
}

// LocalhostHosts is the set of hostnames every NetworkPolicy with
// BlockLocalhost=true blocks. "localhost" is the only entry today; it
// exists as a named host (not just a CIDR) because hostname-based
// allowlist backends resolve "localhost" against an internal table
// before consulting CIDR rules.
var LocalhostHosts = []string{
	"localhost",
}

// HostDockerInternalHosts is the set of hostnames every NetworkPolicy
// with BlockHostDockerInternal=true blocks. host.docker.internal is the
// Docker Desktop / Podman convention for "reach the host from inside a
// container"; an agent that can resolve it can talk to whatever service
// the operator happens to have listening on the host's bridge.
var HostDockerInternalHosts = []string{
	"host.docker.internal",
}

// AlwaysBlockedCIDRs is the union of every CIDR every NetworkPolicy
// built via NewNetworkPolicy blocks. It is the convenience aggregate
// audit code and the report renderer iterate to print "these are the
// CIDRs ai-env blocked on the run". Adapters should use the
// purpose-specific slices (PrivateRangeCIDRs, MetadataServiceCIDRs,
// LocalhostCIDRs) instead so an operator who turns one flag off does
// not accidentally see the others appear in the resulting rule set.
var AlwaysBlockedCIDRs = concat(PrivateRangeCIDRs, MetadataServiceCIDRs, LocalhostCIDRs)

// AlwaysBlockedHosts is the convenience union of every hostname every
// NetworkPolicy built via NewNetworkPolicy blocks. See
// AlwaysBlockedCIDRs for the policy on which slice adapters should use.
var AlwaysBlockedHosts = concat(LocalhostHosts, HostDockerInternalHosts)

// NetworkPolicy is the canonical runtime view of the outbound network
// policy a run is launched with. It is produced by NewNetworkPolicy
// from a config.NetworkPolicy plus the run mode, validated, and then
// either handed to a NetworkPolicyAdapter for installation or
// translated to backend.NetworkPolicy for adapters that go straight
// through Backend.ApplyNetworkPolicy.
//
// The struct mirrors the four enforcement knobs the plan calls out
// for step 1 (allow domains, block private ranges, block metadata
// services, block localhost) plus the host.docker.internal block the
// master plan lists in the same "always blocked" group. The Default
// field is kept here so the policy carries its own deny-by-default
// stance instead of relying on adapter conventions.
type NetworkPolicy struct {
	// Default is the outbound default. "deny" is the only value
	// permitted in autonomous mode; "allow" is rejected by Validate
	// unless the operator threaded an explicit acknowledgement
	// through (Plan 05 does not expose such a flag; future plans
	// may). An empty string is treated as "deny" by NewNetworkPolicy.
	Default string

	// AllowDomains is the explicit allowlist of fully-qualified domain
	// names the agent may reach. The slice is normalized by
	// NewNetworkPolicy (trimmed, lower-cased, deduped, sorted) so
	// downstream adapters and audit logs see a stable representation.
	// Ignored when Default is "allow"; the field still carries the
	// operator's intent so audit records can show the original list.
	AllowDomains []string

	// BlockPrivateRanges blocks the RFC1918 private ranges plus
	// 127.0.0.0/8. Forced true by NewNetworkPolicy regardless of the
	// operator's policy.yaml; the field exists so adapters can verify
	// they actually installed the block and so audit records can show
	// the policy that was enforced.
	BlockPrivateRanges bool

	// BlockMetadataServices blocks the cloud-provider metadata IP
	// (169.254.169.254). Forced true by NewNetworkPolicy: an agent
	// that can reach the metadata service can pivot to host IAM
	// credentials, which is exactly the threat model ai-env exists to
	// shut down.
	BlockMetadataServices bool

	// BlockLocalhost blocks the loopback interface inside the
	// environment so an agent cannot reach a co-tenant or a
	// supervisor-internal service by accident. Forced true by
	// NewNetworkPolicy.
	BlockLocalhost bool

	// BlockHostDockerInternal blocks host.docker.internal so an agent
	// inside a container cannot reach the host's Docker daemon or any
	// service the host happens to expose on the bridge. Forced true by
	// NewNetworkPolicy.
	BlockHostDockerInternal bool
}

// NewNetworkPolicy builds the canonical runtime NetworkPolicy from the
// YAML-shaped config.NetworkPolicy. It performs three jobs:
//
//  1. Defaults: an empty Default is treated as DefaultPolicy ("deny").
//     The four always-block flags are forced on regardless of what the
//     operator wrote, because the master plan's "Always blocked by
//     default" list is not negotiable in v0.1.
//  2. Normalization: AllowDomains is trimmed, lower-cased, and deduped
//     so adapters see a canonical slice. Empty entries are dropped.
//     The result is sorted so audit logs and tests are deterministic.
//  3. No validation. NewNetworkPolicy only shapes the data; call
//     Validate to assert the resulting policy is safe to apply for the
//     run's mode.
//
// NewNetworkPolicy returns a value (not a pointer): NetworkPolicy is
// small and the supervisor records the resolved policy in run.json by
// value to keep audit records immutable across goroutines.
func NewNetworkPolicy(cfg config.NetworkPolicy) NetworkPolicy {
	def := strings.TrimSpace(cfg.Default)
	if def == "" {
		def = DefaultPolicy
	}
	return NetworkPolicy{
		Default:                 def,
		AllowDomains:            normalizeDomains(cfg.AllowDomains),
		BlockPrivateRanges:      true,
		BlockMetadataServices:   true,
		BlockLocalhost:          true,
		BlockHostDockerInternal: true,
	}
}

// Validate reports whether the policy is safe to apply for a run in
// the supplied mode. It enforces the master plan's "fail closed" rule:
// a policy the runtime cannot honor is rejected instead of silently
// degraded.
//
// Current checks:
//
//   - Default must be "deny" or "allow". Any other value (including
//     an empty string, which NewNetworkPolicy normalizes but a raw
//     struct literal may not) is a configuration error.
//   - In autonomous mode ("autonomous"), Default must be "deny".
//     "allow" is rejected: a run that is allowed to reach any
//     destination defeats the egress controls the plan requires.
//   - All four always-block flags must be true. A caller that built
//     the policy with NewNetworkPolicy is safe by construction; this
//     guards adapter implementations that build NetworkPolicy values
//     directly (e.g. tests) from forgetting one.
//
// mode is the policy.yaml mode string ("autonomous", "interactive",
// "dry-run", "continue"). An empty mode is treated as "interactive"
// for the purpose of the autonomous-only checks.
func (p NetworkPolicy) Validate(mode string) error {
	switch p.Default {
	case DefaultPolicy, AllowPolicy:
		// ok
	default:
		return fmt.Errorf("network: invalid default policy %q (want %q or %q)",
			p.Default, DefaultPolicy, AllowPolicy)
	}
	if mode == "autonomous" && p.Default == AllowPolicy {
		return fmt.Errorf("network: default=%q is not permitted in autonomous mode; only %q is allowed",
			AllowPolicy, DefaultPolicy)
	}
	if !p.BlockPrivateRanges {
		return fmt.Errorf("network: BlockPrivateRanges must be true (always-blocked defaults)")
	}
	if !p.BlockMetadataServices {
		return fmt.Errorf("network: BlockMetadataServices must be true (always-blocked defaults)")
	}
	if !p.BlockLocalhost {
		return fmt.Errorf("network: BlockLocalhost must be true (always-blocked defaults)")
	}
	if !p.BlockHostDockerInternal {
		return fmt.Errorf("network: BlockHostDockerInternal must be true (always-blocked defaults)")
	}
	return nil
}

// ToBackendPolicy projects the canonical runtime policy onto the
// backend-adapter-facing struct in internal/backend. Adapters that
// implement Backend.ApplyNetworkPolicy directly consume the result;
// the docker_sbx adapter, for example, walks the backend.NetworkPolicy
// fields and emits the corresponding `sbx network apply` flags.
//
// The two structs share field names by design: a future refactor that
// folds them into a single type can replace this method with an
// identity conversion without touching call sites.
func (p NetworkPolicy) ToBackendPolicy() backend.NetworkPolicy {
	domains := make([]string, len(p.AllowDomains))
	copy(domains, p.AllowDomains)
	return backend.NetworkPolicy{
		Default:                 p.Default,
		AllowDomains:            domains,
		BlockPrivateRanges:      p.BlockPrivateRanges,
		BlockMetadataServices:   p.BlockMetadataServices,
		BlockLocalhost:          p.BlockLocalhost,
		BlockHostDockerInternal: p.BlockHostDockerInternal,
	}
}

// BlockedCIDRs returns the concrete CIDR ranges this policy expects the
// backend adapter to install block rules for. It expands the four
// always-block flags into the canonical per-purpose slices
// (PrivateRangeCIDRs, MetadataServiceCIDRs, LocalhostCIDRs) so the
// adapter does not have to know which CIDRs back which flag.
//
// The slice is freshly allocated on every call: callers may append to
// or sort the result without disturbing the package-level canonical
// slices. Duplicate entries (which arise when both BlockPrivateRanges
// and BlockLocalhost include 127.0.0.0/8) are NOT removed: an adapter
// emitting one --block-cidr per entry receives the same rule twice
// rather than silently dropping one. Backends that dedupe at apply time
// (sbx, iptables) are unaffected; backends that do not should dedupe
// themselves before installing rules.
//
// Entries are returned in the canonical order PrivateRange, Metadata,
// Localhost so audit logs and tests see a stable ordering.
func (p NetworkPolicy) BlockedCIDRs() []string {
	out := make([]string, 0, len(PrivateRangeCIDRs)+len(MetadataServiceCIDRs)+len(LocalhostCIDRs))
	if p.BlockPrivateRanges {
		out = append(out, PrivateRangeCIDRs...)
	}
	if p.BlockMetadataServices {
		out = append(out, MetadataServiceCIDRs...)
	}
	if p.BlockLocalhost {
		out = append(out, LocalhostCIDRs...)
	}
	return out
}

// BlockedHosts returns the concrete hostnames this policy expects the
// backend adapter to install block rules for. Like BlockedCIDRs, it
// expands the relevant always-block flags (BlockLocalhost,
// BlockHostDockerInternal) into the canonical per-purpose slices.
//
// The slice is freshly allocated on every call. Entries are returned in
// the canonical order Localhost, HostDockerInternal so audit logs and
// tests see a stable ordering.
func (p NetworkPolicy) BlockedHosts() []string {
	out := make([]string, 0, len(LocalhostHosts)+len(HostDockerInternalHosts))
	if p.BlockLocalhost {
		out = append(out, LocalhostHosts...)
	}
	if p.BlockHostDockerInternal {
		out = append(out, HostDockerInternalHosts...)
	}
	return out
}

// NetworkPolicyAdapter is the contract an adapter satisfies to install
// a NetworkPolicy on a started environment. It is intentionally smaller
// than backend.Backend: the supervisor depends on this interface (not
// on Backend) so a future split that hosts the network adapter outside
// the backend adapter is a single-file change.
//
// Implementations live next to the backend they wrap:
//
//   - internal/backend/docker_sbx implements NetworkPolicyAdapter by
//     translating NetworkPolicy into `sbx network apply` flags.
//   - internal/backend/docker and internal/backend/podman implement
//     NetworkPolicyAdapter by selecting the rootless fallback's
//     `--network none` default (or rejecting any policy that requires
//     allowlist enforcement, since the fallback cannot honor it).
//   - internal/backend/mock records the call so unit tests can assert
//     on the supervisor's interaction.
//
// Apply is fail-closed: a non-nil error from Apply must abort the run
// with the `failed_policy` lifecycle state per plan task 4. Adapters
// must not return nil after partial application; if any rule could not
// be installed the adapter rolls back what it can and returns an error
// describing what was attempted.
type NetworkPolicyAdapter interface {
	// Name is the short adapter identifier used in audit logs and run
	// reports (e.g. "docker-sbx", "podman", "docker", "mock"). It must
	// match the BackendStatus.Name of the backend the adapter wraps so
	// operators can correlate the network entry in run.json with the
	// backend entry.
	Name() string

	// Apply installs policy on the environment identified by envID.
	// The environment must already be created and started (the
	// supervisor calls Apply after Backend.Start; see plan section 13
	// "Runtime flow", step 6).
	//
	// Apply is fail-closed: a non-nil return aborts the run with the
	// `failed_policy` state. Implementations validate the policy
	// against their own capabilities (the fallback adapter rejects a
	// policy with a non-empty AllowDomains, for example, because it
	// cannot honor an allowlist) and return a descriptive error rather
	// than installing a weaker policy.
	//
	// Implementations are expected to be idempotent: calling Apply
	// twice with the same policy on the same envID must produce the
	// same result, so the supervisor can re-apply on resume without
	// special-casing.
	Apply(envID string, policy NetworkPolicy) error
}

// concat joins the supplied string slices into a single fresh slice in
// argument order. It is the helper AlwaysBlockedCIDRs and
// AlwaysBlockedHosts use at package init to assemble their convenience
// unions from the per-purpose slices; declaring it here keeps the
// package-level vars one-line and easy to scan.
func concat(parts ...[]string) []string {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]string, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// normalizeDomains trims whitespace, lower-cases, drops empty entries,
// dedupes, and sorts an allow-list slice. The result is stable so audit
// logs and tests do not depend on the order the operator wrote
// policy.yaml entries.
func normalizeDomains(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
