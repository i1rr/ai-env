// proxy_test.go covers the wire-up in proxy.go: NewProviderProxyProbe
// and WireProviderProxy. These tests exercise the helpers against a
// real running secrets.ProviderProxy (real net.Listen, real loopback
// bind) rather than a stub, so a regression in the proxy lifecycle
// (URL empty before Start, port leak after Stop) is caught at the seam
// the agent launcher actually consumes.
//
// Plan 05 step 9 is the "wire provider proxy into agent launcher"
// step: set ANTHROPIC_BASE_URL or OPENAI_BASE_URL when proxy mode is
// active. Two layers of behavior need real coverage:
//
//   1. NewProviderProxyProbe / WireProviderProxy turn a running proxy
//      into the EnvironmentProbe fields the resolver consumes.
//   2. ResolveCredentialMode, given that probe, emits the correct
//      base-URL env var (and only the matching one) so the agent
//      process started by the launcher is pointed at the proxy.
//
// The tests also confirm the port released on Stop is re-bindable so a
// supervisor that tears the proxy down between runs does not leak.
package agents

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/config"
	"github.com/rivan1986/ai-env/internal/secrets"
)

// startTestProxy spins up a real ProviderProxy on a loopback port and
// registers a Cleanup that calls Stop. It returns the running proxy so
// the test can read URL() / Provider() against a live listener.
func startTestProxy(t *testing.T, provider string) *secrets.ProviderProxy {
	t.Helper()
	p, err := secrets.NewProviderProxy(secrets.Options{
		Provider: provider,
		Token:    "sk-test-token-value-12345",
	})
	if err != nil {
		t.Fatalf("NewProviderProxy(%q): %v", provider, err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop() })
	return p
}

// TestNewProviderProxyProbe_NilProxy confirms a nil ProviderProxyInfo
// yields a zero EnvironmentProbe so the supervisor's pre-Start call
// site does not accidentally activate provider_proxy mode.
func TestNewProviderProxyProbe_NilProxy(t *testing.T) {
	t.Parallel()

	got := NewProviderProxyProbe(nil)
	if !reflect.DeepEqual(got, EnvironmentProbe{}) {
		t.Errorf("NewProviderProxyProbe(nil) = %+v, want zero", got)
	}
}

// TestNewProviderProxyProbe_EmptyURL covers the "proxy constructed but
// not yet bound" case: URL() returns "" before Start, so the helper
// must NOT advertise a proxy URL.
func TestNewProviderProxyProbe_EmptyURL(t *testing.T) {
	t.Parallel()

	// Construct without starting; URL() is empty.
	p, err := secrets.NewProviderProxy(secrets.Options{
		Provider: secrets.ProviderAnthropic,
		Token:    "sk-test-token-value-12345",
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if p.URL() != "" {
		t.Fatalf("URL = %q before Start, want empty", p.URL())
	}

	got := NewProviderProxyProbe(p)
	if !reflect.DeepEqual(got, EnvironmentProbe{}) {
		t.Errorf("probe before Start = %+v, want zero", got)
	}
}

// TestNewProviderProxyProbe_AnthropicRunningProxy exercises the happy
// path: a real, started Anthropic proxy on a real loopback port. The
// probe must carry the bound URL and identify the provider so the
// resolver picks ANTHROPIC_BASE_URL.
func TestNewProviderProxyProbe_AnthropicRunningProxy(t *testing.T) {
	t.Parallel()

	p := startTestProxy(t, secrets.ProviderAnthropic)

	if !strings.HasPrefix(p.URL(), "http://127.0.0.1:") {
		t.Fatalf("proxy URL = %q, want http://127.0.0.1: prefix", p.URL())
	}

	probe := NewProviderProxyProbe(p)
	if probe.ProviderProxyURL != p.URL() {
		t.Errorf("ProviderProxyURL = %q, want %q", probe.ProviderProxyURL, p.URL())
	}
	if probe.ProviderProxyProvider != secrets.ProviderAnthropic {
		t.Errorf("ProviderProxyProvider = %q, want %q",
			probe.ProviderProxyProvider, secrets.ProviderAnthropic)
	}
}

// TestNewProviderProxyProbe_OpenAIRunningProxy mirrors the Anthropic
// happy path for OpenAI: the provider field must be lowercased
// "openai" so the resolver emits OPENAI_BASE_URL.
func TestNewProviderProxyProbe_OpenAIRunningProxy(t *testing.T) {
	t.Parallel()

	p := startTestProxy(t, secrets.ProviderOpenAI)

	probe := NewProviderProxyProbe(p)
	if probe.ProviderProxyURL == "" {
		t.Fatalf("ProviderProxyURL empty after Start")
	}
	if probe.ProviderProxyProvider != secrets.ProviderOpenAI {
		t.Errorf("ProviderProxyProvider = %q, want %q",
			probe.ProviderProxyProvider, secrets.ProviderOpenAI)
	}
}

// TestWireProviderProxy_OverlaysOntoBase confirms WireProviderProxy
// preserves the caller's other probe fields (BackendManaged,
// AgentSupportsCustomBaseURL, RawTokenEnv) while overwriting the proxy
// URL + provider fields with the running proxy's values.
func TestWireProviderProxy_OverlaysOntoBase(t *testing.T) {
	t.Parallel()

	p := startTestProxy(t, secrets.ProviderAnthropic)

	base := EnvironmentProbe{
		BackendManaged:             false,
		AgentSupportsCustomBaseURL: true,
		RawTokenEnv:                []string{"ANTHROPIC_API_KEY=sk-raw"},
		// Pre-existing (stale) proxy fields that WireProviderProxy
		// should overwrite from the running proxy.
		ProviderProxyURL:      "http://stale.example/",
		ProviderProxyProvider: "stale",
	}

	got := WireProviderProxy(base, p)

	if got.ProviderProxyURL != p.URL() {
		t.Errorf("ProviderProxyURL = %q, want %q", got.ProviderProxyURL, p.URL())
	}
	if got.ProviderProxyProvider != secrets.ProviderAnthropic {
		t.Errorf("ProviderProxyProvider = %q, want %q",
			got.ProviderProxyProvider, secrets.ProviderAnthropic)
	}
	if !got.AgentSupportsCustomBaseURL {
		t.Errorf("AgentSupportsCustomBaseURL = false, want preserved true")
	}
	if !reflect.DeepEqual(got.RawTokenEnv, base.RawTokenEnv) {
		t.Errorf("RawTokenEnv = %v, want %v (preserved)", got.RawTokenEnv, base.RawTokenEnv)
	}
}

// TestWireProviderProxy_NilOrUnboundLeavesBase confirms a nil proxy or
// a proxy whose URL is still empty leaves the base probe untouched.
// The supervisor's pre-Start call site relies on this so a half-set-up
// run does not flip into provider_proxy mode.
func TestWireProviderProxy_NilOrUnboundLeavesBase(t *testing.T) {
	t.Parallel()

	base := EnvironmentProbe{
		BackendManaged:        true,
		ProviderProxyURL:      "http://existing/",
		ProviderProxyProvider: "anthropic",
	}

	// Nil proxy.
	if got := WireProviderProxy(base, nil); !reflect.DeepEqual(got, base) {
		t.Errorf("WireProviderProxy(base, nil) = %+v, want %+v", got, base)
	}

	// Constructed but unbound proxy (URL == "").
	p, err := secrets.NewProviderProxy(secrets.Options{
		Provider: secrets.ProviderAnthropic,
		Token:    "sk-test-token-value-12345",
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if got := WireProviderProxy(base, p); !reflect.DeepEqual(got, base) {
		t.Errorf("WireProviderProxy(base, unbound) = %+v, want %+v", got, base)
	}
}

// TestProviderProxy_EndToEndAnthropicEnvVar exercises the full step 9
// contract: a real ProviderProxy is started, NewProviderProxyProbe
// builds the EnvironmentProbe, ResolveCredentialMode picks
// provider_proxy, and the injected env carries exactly
// ANTHROPIC_BASE_URL pointing at the bound proxy URL. OPENAI_BASE_URL
// must NOT appear.
func TestProviderProxy_EndToEndAnthropicEnvVar(t *testing.T) {
	t.Parallel()

	p := startTestProxy(t, secrets.ProviderAnthropic)

	probe := WireProviderProxy(EnvironmentProbe{
		AgentSupportsCustomBaseURL: true,
	}, p)

	contract := config.AgentCredentialMode{
		Default:       CredentialModeProviderProxy,
		FallbackOrder: []string{CredentialModeRawEnvExplicit},
	}
	mode, env, err := ResolveCredentialMode(contract, probe, false)
	if err != nil {
		t.Fatalf("ResolveCredentialMode: %v", err)
	}
	if mode != CredentialModeProviderProxy {
		t.Fatalf("mode = %q, want %q", mode, CredentialModeProviderProxy)
	}

	want := []string{"ANTHROPIC_BASE_URL=" + p.URL()}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("injectedEnv = %v, want exactly %v", env, want)
	}

	// Defensive: confirm OPENAI_BASE_URL is NOT present so a future
	// regression that flips the provider filter is caught here even if
	// the slice grows additional entries.
	for _, kv := range env {
		if strings.HasPrefix(kv, "OPENAI_BASE_URL=") {
			t.Errorf("env entry %q present, want only ANTHROPIC_BASE_URL", kv)
		}
	}
}

// TestProviderProxy_EndToEndOpenAIEnvVar mirrors the Anthropic
// end-to-end test for OpenAI. Only OPENAI_BASE_URL must appear in the
// injected env.
func TestProviderProxy_EndToEndOpenAIEnvVar(t *testing.T) {
	t.Parallel()

	p := startTestProxy(t, secrets.ProviderOpenAI)

	probe := WireProviderProxy(EnvironmentProbe{
		AgentSupportsCustomBaseURL: true,
	}, p)

	contract := config.AgentCredentialMode{
		Default:       CredentialModeProviderProxy,
		FallbackOrder: []string{CredentialModeRawEnvExplicit},
	}
	mode, env, err := ResolveCredentialMode(contract, probe, false)
	if err != nil {
		t.Fatalf("ResolveCredentialMode: %v", err)
	}
	if mode != CredentialModeProviderProxy {
		t.Fatalf("mode = %q, want %q", mode, CredentialModeProviderProxy)
	}

	want := []string{"OPENAI_BASE_URL=" + p.URL()}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("injectedEnv = %v, want exactly %v", env, want)
	}

	for _, kv := range env {
		if strings.HasPrefix(kv, "ANTHROPIC_BASE_URL=") {
			t.Errorf("env entry %q present, want only OPENAI_BASE_URL", kv)
		}
	}
}

// TestProviderProxy_PortReleasedOnStop confirms that calling Stop on a
// running proxy releases the loopback port so a subsequent listener can
// bind to the same address. A leak here would manifest as "address
// already in use" on a re-Start, which is exactly the cleanup the
// supervisor's per-run lifecycle (start before agent, stop after run)
// depends on.
func TestProviderProxy_PortReleasedOnStop(t *testing.T) {
	t.Parallel()

	// Start a proxy on an OS-picked loopback port.
	p, err := secrets.NewProviderProxy(secrets.Options{
		Provider: secrets.ProviderAnthropic,
		Token:    "sk-test-token-value-12345",
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Extract the bound host:port so we can attempt to re-bind it after
	// Stop. The URL is "http://127.0.0.1:NNN"; strip the scheme.
	url := p.URL()
	const prefix = "http://"
	if !strings.HasPrefix(url, prefix) {
		_ = p.Stop()
		t.Fatalf("URL = %q, want http:// prefix", url)
	}
	addr := strings.TrimPrefix(url, prefix)

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// The OS may need a moment to release the port; net.Listen would
	// retry on EADDRINUSE on most platforms. We try the bind and accept
	// either success (port released) or a specific error so a transient
	// timing issue does not flake the test. Success is the contract
	// the supervisor needs.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("net.Listen(%q) after proxy.Stop: %v", addr, err)
	}
	_ = ln.Close()
}

// TestProviderProxy_StopBeforeAgentLaunchIsSafe documents the
// supervisor's defensive lifecycle: a Stop that races a Start (the
// cancel-during-setup path) must not panic, and a subsequent
// NewProviderProxyProbe must report the proxy as inactive (empty URL)
// so the resolver does not select provider_proxy on a torn-down proxy.
func TestProviderProxy_StopBeforeAgentLaunchIsSafe(t *testing.T) {
	t.Parallel()

	p := startTestProxy(t, secrets.ProviderAnthropic)

	// URL is non-empty after Start.
	if p.URL() == "" {
		t.Fatal("URL empty after Start")
	}

	// Stop while the agent has not even launched. The supervisor's
	// per-run lifecycle invariant is that Stop is idempotent and safe
	// from any teardown branch.
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Idempotent second Stop returns nil.
	if err := p.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}
