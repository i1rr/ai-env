// proxy.go is Plan 05 step 9's wire-up: a small helper that folds a
// running provider proxy (secrets.ProviderProxy) into the
// EnvironmentProbe the launcher's Plan call consumes.
//
// The agents package deliberately does NOT import internal/secrets
// here. Instead it defines a narrow ProviderProxyInfo interface that
// captures only the two methods the launcher cares about (URL and
// Provider). secrets.ProviderProxy already implements both, so a
// supervisor that has a running proxy passes it straight through to
// NewProviderProxyProbe without any adapter glue. Keeping the seam at
// an interface also lets tests inject a stub without standing up a
// real HTTP listener.
//
// The plan calls for the supervisor to "set ANTHROPIC_BASE_URL or
// OPENAI_BASE_URL when proxy mode is active" (plan 05 step 9). Today
// the launchers already pull a custom base URL out of EnvironmentProbe;
// this file's job is to populate that EnvironmentProbe from the
// runtime ProviderProxy the supervisor owns, and to tell the resolver
// which env var to emit (via EnvironmentProbe.ProviderProxyProvider)
// so we set exactly one variable, not both.
package agents

import "strings"

// ProviderProxyInfo is the narrow contract NewProviderProxyProbe needs
// from a running provider proxy. secrets.ProviderProxy satisfies it
// natively; tests pass any value implementing the same two methods.
//
// URL returns the http://host:port the agent inside the sandbox should
// be pointed at via PROVIDER_BASE_URL. The empty string is treated as
// "no proxy is running" so a caller that builds the probe before the
// proxy binds does not accidentally inject a stale value.
//
// Provider returns the provider identifier ("anthropic", "openai")
// the proxy fronts. The resolver uses it to pick the matching
// base-URL env var so a proxy that fronts only Anthropic does not also
// emit OPENAI_BASE_URL.
type ProviderProxyInfo interface {
	URL() string
	Provider() string
}

// NewProviderProxyProbe returns a partial EnvironmentProbe populated
// from a running provider proxy. Callers compose the result with the
// rest of the probe (BackendManaged, RawTokenEnv, ...) before passing
// it to Launcher.Plan.
//
// A nil proxy or a proxy whose URL is still empty (Start has not run
// yet) returns a zero EnvironmentProbe: the supervisor should not
// activate provider_proxy mode until the proxy has actually bound.
//
// The returned probe sets ProviderProxyURL and
// ProviderProxyProvider; AgentSupportsCustomBaseURL stays at the
// launcher's responsibility (Claude / Codex both set it themselves
// based on what their CLI honors).
func NewProviderProxyProbe(proxy ProviderProxyInfo) EnvironmentProbe {
	if proxy == nil {
		return EnvironmentProbe{}
	}
	url := strings.TrimSpace(proxy.URL())
	if url == "" {
		return EnvironmentProbe{}
	}
	return EnvironmentProbe{
		ProviderProxyURL:      url,
		ProviderProxyProvider: strings.ToLower(strings.TrimSpace(proxy.Provider())),
	}
}

// WireProviderProxy folds a running provider proxy into an existing
// EnvironmentProbe. It is the supervisor's typical entry point: build
// the base probe from the backend / raw-token state, then layer the
// proxy on top so the resolver sees both halves.
//
// When proxy is nil or has not bound yet (empty URL), base is returned
// unchanged. When it has bound, ProviderProxyURL and
// ProviderProxyProvider on base are overwritten; other fields
// (BackendManaged, AgentSupportsCustomBaseURL, RawTokenEnv) are left
// alone so the caller's earlier wiring wins for them.
func WireProviderProxy(base EnvironmentProbe, proxy ProviderProxyInfo) EnvironmentProbe {
	add := NewProviderProxyProbe(proxy)
	if add.ProviderProxyURL == "" {
		return base
	}
	base.ProviderProxyURL = add.ProviderProxyURL
	base.ProviderProxyProvider = add.ProviderProxyProvider
	return base
}
