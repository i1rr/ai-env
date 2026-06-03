// Network-policy adapter for the docker-sbx backend.
//
// This file is the implementation of network.NetworkPolicyAdapter that
// translates a network.NetworkPolicy into concrete `sbx network apply`
// flags. The Backend type in docker_sbx.go already implements
// backend.Backend.ApplyNetworkPolicy (which takes backend.NetworkPolicy
// and emits the boolean --block-private-ranges / --block-metadata-
// services / --block-localhost / --block-host-docker-internal flags
// sbx exposes natively). The NetworkPolicyAdapter type defined here is
// the supervisor-facing seam plan 05 step 3 asks for: it accepts the
// richer network.NetworkPolicy, expands the always-block flags into the
// canonical CIDR / host lists (see plan step 5 / network.BlockedCIDRs,
// network.BlockedHosts), and invokes sbx with one explicit
// `--block-cidr` per range plus one `--block-host` per hostname.
//
// Why two code paths instead of one:
//
//  1. Backend.ApplyNetworkPolicy stays plumbed through the existing
//     backend.Backend interface so generic callers (the run supervisor's
//     fail-closed wrapper, the integration tests in plan 04) keep
//     working unchanged. The boolean-flag shape mirrors the sbx native
//     interface and is the right surface for "I trust sbx to expand the
//     well-known categories itself".
//
//  2. NetworkPolicyAdapter is the supervisor-facing contract from plan
//     05 step 2. It must:
//
//     - Accept the canonical runtime network.NetworkPolicy (not
//     backend.NetworkPolicy), so the supervisor only ever speaks one
//     policy shape and audit code can compare what the adapter saw
//     against what was recorded in run.json.
//
//     - Translate the always-block flags into concrete CIDR / host
//     entries (plan step 5). This is the explicit installation path
//     the master plan's acceptance criteria assume: a future sbx
//     release that drops a category shorthand still leaves the
//     adapter installing every individual range. The boolean-flag
//     path on Backend.ApplyNetworkPolicy stays as a fallback for
//     backends that prefer to delegate.
//
// Both code paths emit deny-by-default in autonomous-mode runs. The
// adapter never silently degrades: if any step fails, it returns an
// error and the supervisor must abort the run with the failed_policy
// state (plan step 4).
package docker_sbx

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/i1rr/ai-env/internal/network"
)

// applyNetworkPolicyTimeout caps the `sbx network apply` invocation. It
// is the same budget Backend.ApplyNetworkPolicy uses for the boolean-
// flag path: a wedged sbx network subcommand must surface as a clear
// error rather than hang the supervisor's start-time policy install.
const applyNetworkPolicyTimeout = 1 * time.Minute

// NetworkPolicyAdapter installs a network.NetworkPolicy on a started
// docker-sbx environment by invoking `sbx network apply` with the
// expanded CIDR / host block list.
//
// The adapter holds a pointer to the Backend it wraps so it can reuse
// the same Runner, binary path, and clock. This keeps the test seam
// uniform: a test that wires a fake Runner into Backend sees the
// adapter call the same Runner with the network-apply argv. It also
// means a NetworkPolicyAdapter is only valid for envIDs the Backend
// knows about: applying policy to an envID the Backend has not Created
// is rejected, the same way Backend.ApplyNetworkPolicy rejects it.
type NetworkPolicyAdapter struct {
	backend *Backend
}

// NewNetworkPolicyAdapter constructs an adapter that installs policies
// on environments owned by the supplied Backend. The Backend must
// already be initialized via New; passing a nil Backend is a
// programming error and the adapter panics on Apply (the supervisor
// builds the adapter eagerly at startup, so a nil here is a build-time
// bug, not a runtime condition).
func NewNetworkPolicyAdapter(b *Backend) *NetworkPolicyAdapter {
	return &NetworkPolicyAdapter{backend: b}
}

// Name returns the adapter identifier surfaced through audit logs and
// run reports. It mirrors docker_sbx.Name so operators can correlate
// the network entry in run.json with the backend entry: both read
// "docker-sbx".
func (a *NetworkPolicyAdapter) Name() string {
	return Name
}

// Apply installs the supplied policy on envID. It is the
// supervisor-facing entry point for plan step 3.
//
// Apply performs three jobs:
//
//  1. Validate the policy's structural invariants (Default in {deny,
//     allow}, always-block flags all true). This guards against a caller
//     that constructed a NetworkPolicy literal without going through
//     network.NewNetworkPolicy. We do not pass mode here: the supervisor
//     called Validate before reaching the adapter, and adapters must
//     treat the policy as already-mode-checked. The second call is a
//     belt-and-suspenders structural check, not a mode check, so we ask
//     for the lenient "interactive" mode that only enforces the
//     structural rules.
//
//  2. Expand the always-block flags into concrete CIDR (network.
//     BlockedCIDRs) and host (network.BlockedHosts) entries and emit
//     one --block-cidr / --block-host flag per entry. This is the plan
//     step 5 contract: the adapter installs the canonical block list,
//     not a category shorthand sbx might or might not honor on a
//     given release.
//
//  3. Add `--default deny` (or `--default allow` if the operator
//     opted in) and one `--allow-domain` per entry in
//     policy.AllowDomains.
//
// Apply is fail-closed: any non-nil return aborts the run with the
// failed_policy state per plan step 4. The adapter never returns nil
// after a partial install; sbx is responsible for rolling back rules on
// its own failure, so a non-zero exit from `sbx network apply` is
// reported as-is.
//
// Apply is idempotent on the sbx side: invoking `sbx network apply`
// twice with the same flags is documented to install the same rule set
// the second time. The supervisor relies on that idempotency when it
// re-applies on resume.
func (a *NetworkPolicyAdapter) Apply(envID string, policy network.NetworkPolicy) error {
	if a.backend == nil {
		return fmt.Errorf("docker-sbx: NetworkPolicyAdapter has nil Backend (programmer error)")
	}
	if envID == "" {
		return fmt.Errorf("docker-sbx: ApplyNetworkPolicy requires a non-empty envID")
	}

	// Structural validation only. The supervisor enforces the
	// autonomous-mode check (allow-default rejected); here we just
	// guard against a NetworkPolicy literal that forgot one of the
	// always-block flags.
	if err := policy.Validate("interactive"); err != nil {
		return fmt.Errorf("docker-sbx: invalid network policy: %w", err)
	}

	a.backend.mu.Lock()
	_, ok := a.backend.envs[envID]
	a.backend.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}

	args := a.buildArgs(envID, policy)

	ctx, cancel := context.WithTimeout(context.Background(), applyNetworkPolicyTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := a.backend.runner(ctx, a.backend.binary, args, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return fmt.Errorf("docker-sbx: sbx network apply spawn failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("docker-sbx: sbx network apply exited %d: %s",
			exitCode, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// buildArgs assembles the argv the adapter passes to sbx. It is split
// out from Apply so tests can assert on the exact flag sequence without
// having to wire a fake Runner.
//
// The argv shape is:
//
//	sbx network apply <envID>
//	    --default <deny|allow>
//	    --block-cidr <cidr> [--block-cidr ...]
//	    --block-host <host> [--block-host ...]
//	    --allow-domain <domain> [--allow-domain ...]
//
// The order is fixed (default, then blocks, then allows) so adapters in
// other backend packages that lift this argv shape see a stable
// contract and so audit logs are byte-stable across runs with the same
// policy.
func (a *NetworkPolicyAdapter) buildArgs(envID string, policy network.NetworkPolicy) []string {
	args := make([]string, 0, 8+
		2*len(policy.AllowDomains)+
		2*(len(network.PrivateRangeCIDRs)+len(network.MetadataServiceCIDRs)+len(network.LocalhostCIDRs))+
		2*(len(network.LocalhostHosts)+len(network.HostDockerInternalHosts)))

	args = append(args, "network", "apply", envID)

	def := policy.Default
	if def == "" {
		def = network.DefaultPolicy
	}
	args = append(args, "--default", def)

	for _, cidr := range policy.BlockedCIDRs() {
		args = append(args, "--block-cidr", cidr)
	}
	for _, host := range policy.BlockedHosts() {
		args = append(args, "--block-host", host)
	}
	for _, dom := range policy.AllowDomains {
		args = append(args, "--allow-domain", dom)
	}
	return args
}

// compile-time check that *NetworkPolicyAdapter satisfies
// network.NetworkPolicyAdapter. If this line stops compiling, the
// network package's interface drifted and the adapter must be updated
// in lockstep.
var _ network.NetworkPolicyAdapter = (*NetworkPolicyAdapter)(nil)
