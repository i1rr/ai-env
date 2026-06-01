// build.go implements Plan Batch 2.4: BuildProviderProxyFromSecrets.
// The factory walks a loaded *LocalConfig (Batch 2.1's product) and
// returns one ProviderProxy per known provider that has a non-empty
// credential. The supervisor calls this between LoadLocal and the
// per-run startup sequence (Batch 5.5 step 8) so the lifecycle stays:
//
//	cfg, warnings, err := secrets.LoadLocal(path)        // Batch 2.1
//	proxies, err       := secrets.BuildProviderProxyFromSecrets(cfg, opts)
//	for _, p := range proxies { p.Start() }              // Batch 5.5 step 8
//
// What the factory deliberately does NOT do today:
//
//   - Decide the BindMode (SetnsTCP / BridgeGateway / UnixSocket). That
//     decision lives at supervisor step 6 (Batch 2.2 / 2.3) which has
//     the capability probe and Backend.GatewayAddress() in hand. The
//     factory only produces the per-provider Options that those steps
//     will extend with the chosen ListenAddr.
//   - Touch the network namespace. NewProviderProxy is pure construction;
//     no listener binds until Start. Batch 2.2 / 2.3 wrap Start in
//     ns.WithNetNSPath at the call site.
//   - Carry the upstream-Host allowlist. That's a router decision baked
//     into ProviderProxy itself (Batch 2.2). The factory only picks
//     which providers to instantiate; the proxy enforces the host
//     allowlist at RoundTrip.
//
// The factory uses ProviderUpstream + the existing Provider* constants
// to filter unknown entries so a typo in the operator's YAML
// ("anthorpic:") does not silently produce a misconfigured proxy. The
// caller decides whether an unknown provider entry is a hard error or
// just a warning by inspecting BuildResult.SkippedProviders; the
// returned slice of *ProviderProxy contains only entries the
// secrets package recognizes.

package secrets

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// BuildOptions tunes every ProviderProxy the factory constructs. The
// fields mirror secrets.Options but apply uniformly across every proxy
// the factory returns; downstream batches (2.2 / 2.3) layer
// per-provider overrides on top before Start.
//
// Every field is optional. A zero BuildOptions produces proxies that
// bind to defaultLoopbackAddr (127.0.0.1:0) with the default shutdown
// timeout and no logger, which is exactly what the supervisor wants
// for the "factory only, supervisor decides ports / logging" call
// pattern.
type BuildOptions struct {
	// ListenAddr is the host:port every proxy binds to. The supervisor
	// normally leaves this empty so each proxy picks a fresh ephemeral
	// port (one listener per provider, distinct ports — Plan Batch 2.2's
	// MultiProvider_TwoListenersDistinctPorts acceptance). A non-empty
	// ListenAddr is permitted for tests that want a deterministic bind
	// but is rejected by NewProviderProxy if it is not loopback.
	ListenAddr string

	// Logger forwards every proxy's log lines to one destination. Nil
	// is allowed (proxies stay silent). Supervised runs wire this to
	// the per-run lifecycle stream so the lifecycle.jsonl entry is the
	// authoritative log of provider_proxy events.
	Logger func(line string)

	// ShutdownTimeout caps how long Stop waits for in-flight requests.
	// Zero falls through to defaultShutdownTimeout in NewProviderProxy.
	ShutdownTimeout time.Duration
}

// BuildResult bundles the outputs of BuildProviderProxyFromSecrets.
// Separating the proxies from the skipped-providers list lets the
// supervisor decide independently whether to:
//
//   - start each proxy (always);
//   - surface "skipped" entries as a warning (yes — useful audit
//     evidence);
//   - fail the run when there are zero proxies (Plan dictates "Hard
//     fail-closed on unreachable"; the factory does NOT enforce that
//     itself because a run with no provider credentials may still be
//     valid for, e.g., a shell-only continue-mode session).
type BuildResult struct {
	// Proxies is the list of constructed ProviderProxy instances, one
	// per provider with a non-empty credential. Ordered alphabetically
	// by provider identifier so the supervisor's per-run logs and
	// tests have a stable order.
	Proxies []*ProviderProxy

	// SkippedProviders lists every entry in the input config that the
	// factory recognized but skipped because it was incomplete (empty
	// APIKey). The supervisor surfaces these so an operator who left
	// an api_key blank sees a clear warning rather than silently
	// running without that provider.
	SkippedProviders []SkippedProvider

	// UnknownProviders lists every provider key in the input config
	// that the secrets package does not recognize. Useful for typo
	// detection ("anthorpic:" → an UnknownProviders entry with name
	// "anthorpic"). The supervisor logs these as warnings.
	UnknownProviders []string
}

// SkippedProvider describes one entry the factory recognized but did
// not construct a proxy for. The Reason is a short token suitable for
// a metadata field (matching the LifecycleVerbSecretsPermissionWarning
// convention).
type SkippedProvider struct {
	// Provider is the lower-cased provider identifier (one of the
	// Provider* constants).
	Provider string

	// Reason is a short token: "empty_api_key" today; future skips
	// (e.g., scoped-credential validation) would add new tokens.
	Reason string
}

// BuildProviderProxyFromSecrets is Plan Batch 2.4's primary entry
// point. It walks cfg.Secrets.Providers, constructs a ProviderProxy
// for each known provider with a non-empty API key, and returns them
// alongside a BuildResult that records what was skipped or unknown.
//
// Argument contract:
//
//   - cfg may be nil; the factory treats nil identically to an empty
//     config (no proxies, no skipped, no unknown) so a supervisor that
//     never read a secrets.local.yaml does not need a nil-guard.
//   - opts is consumed by value; mutations after the call do not
//     affect already-constructed proxies.
//
// Error contract:
//
//   - The only error path is a NewProviderProxy failure (e.g., the
//     supervisor passed an invalid ListenAddr). The factory wraps the
//     underlying error and aborts on the first failure so partial
//     construction never leaks half-built listeners.
//   - "No credentials configured" is NOT an error: the returned
//     BuildResult has zero Proxies. The supervisor decides whether
//     that's acceptable based on the run's contract (see the
//     Hard-fail-closed note in BuildResult).
func BuildProviderProxyFromSecrets(cfg *LocalConfig, opts BuildOptions) (BuildResult, error) {
	res := BuildResult{
		Proxies:          nil,
		SkippedProviders: nil,
		UnknownProviders: nil,
	}
	if cfg == nil {
		return res, nil
	}

	// Gather the known + unknown sets up front so we can iterate the
	// known set in deterministic (alphabetical) order. Unknown keys
	// are reported verbatim (no lower-casing) so an operator looking
	// at the log can find the exact line in their YAML.
	knownNames := make([]string, 0, len(cfg.Secrets.Providers))
	var unknown []string
	for name, cred := range cfg.Secrets.Providers {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if _, ok := ProviderUpstream(normalized); !ok {
			unknown = append(unknown, name)
			continue
		}
		_ = cred // cred is consumed below; this loop only sorts names
		knownNames = append(knownNames, normalized)
	}
	sort.Strings(knownNames)
	sort.Strings(unknown)
	res.UnknownProviders = unknown

	for _, name := range knownNames {
		cred := cfg.Secrets.Providers[name]
		token := strings.TrimSpace(cred.APIKey)
		if token == "" {
			res.SkippedProviders = append(res.SkippedProviders, SkippedProvider{
				Provider: name,
				Reason:   "empty_api_key",
			})
			continue
		}
		proxy, err := NewProviderProxy(Options{
			Provider:        name,
			Token:           token,
			ListenAddr:      opts.ListenAddr,
			Logger:          opts.Logger,
			ShutdownTimeout: opts.ShutdownTimeout,
		})
		if err != nil {
			return BuildResult{}, fmt.Errorf("secrets: BuildProviderProxyFromSecrets: provider %q: %w", name, err)
		}
		res.Proxies = append(res.Proxies, proxy)
	}

	return res, nil
}

// ErrNoProviderCredentials is the sentinel a supervisor MAY return up
// the stack when a run requires at least one provider proxy but the
// loaded secrets.local.yaml produced none. The factory itself does NOT
// return this error (see the "no credentials configured" rule above);
// it is exported so call sites that want the hard-fail-closed
// behaviour have a shared error to surface.
var ErrNoProviderCredentials = errors.New("secrets: no provider credentials configured in secrets.local.yaml")
