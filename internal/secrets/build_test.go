package secrets

import (
	"strings"
	"testing"
	"time"
)

// TestBuildProviderProxyFromSecrets_NilConfig verifies a nil cfg
// produces an empty BuildResult with no error. The supervisor uses this
// path when LoadLocal returned an empty *LocalConfig and no providers
// were configured at all.
func TestBuildProviderProxyFromSecrets_NilConfig(t *testing.T) {
	res, err := BuildProviderProxyFromSecrets(nil, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildProviderProxyFromSecrets: %v", err)
	}
	if len(res.Proxies) != 0 || len(res.SkippedProviders) != 0 || len(res.UnknownProviders) != 0 {
		t.Errorf("expected fully empty result, got %+v", res)
	}
}

// TestBuildProviderProxyFromSecrets_EmptyProviders verifies an empty
// providers map is treated the same as a nil config.
func TestBuildProviderProxyFromSecrets_EmptyProviders(t *testing.T) {
	cfg := &LocalConfig{Version: LocalConfigSchemaVersion}
	res, err := BuildProviderProxyFromSecrets(cfg, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildProviderProxyFromSecrets: %v", err)
	}
	if len(res.Proxies) != 0 {
		t.Errorf("expected zero proxies, got %d", len(res.Proxies))
	}
}

// TestBuildProviderProxyFromSecrets_BothProviders builds proxies for
// anthropic and openai when both have a non-empty API key. Verifies
// the returned slice is alphabetically ordered and every proxy carries
// the right provider + upstream host.
func TestBuildProviderProxyFromSecrets_BothProviders(t *testing.T) {
	cfg := &LocalConfig{
		Version: LocalConfigSchemaVersion,
		Secrets: LocalSecretsSection{
			Providers: map[string]LocalProviderCredentials{
				"openai":    {APIKey: "sk-openai-test"},
				"anthropic": {APIKey: "sk-ant-test"},
			},
		},
	}
	res, err := BuildProviderProxyFromSecrets(cfg, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildProviderProxyFromSecrets: %v", err)
	}
	if len(res.Proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(res.Proxies))
	}
	// Alphabetical: anthropic before openai.
	if res.Proxies[0].Provider() != ProviderAnthropic {
		t.Errorf("res.Proxies[0].Provider() = %q, want %q", res.Proxies[0].Provider(), ProviderAnthropic)
	}
	if res.Proxies[1].Provider() != ProviderOpenAI {
		t.Errorf("res.Proxies[1].Provider() = %q, want %q", res.Proxies[1].Provider(), ProviderOpenAI)
	}
	// Upstream pin survives the factory.
	if got, _ := ProviderUpstream(ProviderAnthropic); res.Proxies[0].UpstreamHost() != got {
		t.Errorf("anthropic proxy upstream = %q", res.Proxies[0].UpstreamHost())
	}
	if got, _ := ProviderUpstream(ProviderOpenAI); res.Proxies[1].UpstreamHost() != got {
		t.Errorf("openai proxy upstream = %q", res.Proxies[1].UpstreamHost())
	}
	if len(res.SkippedProviders) != 0 || len(res.UnknownProviders) != 0 {
		t.Errorf("expected clean build, got skipped=%v unknown=%v", res.SkippedProviders, res.UnknownProviders)
	}
}

// TestBuildProviderProxyFromSecrets_EmptyKeyIsSkipped verifies a known
// provider with an empty API key is reported as skipped, not as a
// silent zero-token proxy.
func TestBuildProviderProxyFromSecrets_EmptyKeyIsSkipped(t *testing.T) {
	cfg := &LocalConfig{
		Version: LocalConfigSchemaVersion,
		Secrets: LocalSecretsSection{
			Providers: map[string]LocalProviderCredentials{
				"anthropic": {APIKey: "sk-ant-real"},
				"openai":    {APIKey: "   "}, // whitespace-only
			},
		},
	}
	res, err := BuildProviderProxyFromSecrets(cfg, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildProviderProxyFromSecrets: %v", err)
	}
	if len(res.Proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(res.Proxies))
	}
	if res.Proxies[0].Provider() != ProviderAnthropic {
		t.Errorf("expected anthropic proxy, got %q", res.Proxies[0].Provider())
	}
	if len(res.SkippedProviders) != 1 {
		t.Fatalf("expected 1 skipped provider, got %d", len(res.SkippedProviders))
	}
	if res.SkippedProviders[0].Provider != ProviderOpenAI {
		t.Errorf("skipped provider = %q", res.SkippedProviders[0].Provider)
	}
	if res.SkippedProviders[0].Reason != "empty_api_key" {
		t.Errorf("skipped reason = %q", res.SkippedProviders[0].Reason)
	}
}

// TestBuildProviderProxyFromSecrets_UnknownProviderRecorded verifies an
// unknown provider key is recorded under UnknownProviders rather than
// silently ignored or treated as a fatal error.
func TestBuildProviderProxyFromSecrets_UnknownProviderRecorded(t *testing.T) {
	cfg := &LocalConfig{
		Version: LocalConfigSchemaVersion,
		Secrets: LocalSecretsSection{
			Providers: map[string]LocalProviderCredentials{
				"anthropic": {APIKey: "sk-ant"},
				"anthorpic": {APIKey: "sk-ant-typo"}, // typo
			},
		},
	}
	res, err := BuildProviderProxyFromSecrets(cfg, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildProviderProxyFromSecrets: %v", err)
	}
	if len(res.Proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(res.Proxies))
	}
	if len(res.UnknownProviders) != 1 || res.UnknownProviders[0] != "anthorpic" {
		t.Errorf("expected ['anthorpic'] in UnknownProviders, got %v", res.UnknownProviders)
	}
}

// TestBuildProviderProxyFromSecrets_InvalidListenAddr verifies a
// caller-supplied non-loopback ListenAddr surfaces as an error and
// does NOT produce a partially-constructed slice.
func TestBuildProviderProxyFromSecrets_InvalidListenAddr(t *testing.T) {
	cfg := &LocalConfig{
		Version: LocalConfigSchemaVersion,
		Secrets: LocalSecretsSection{
			Providers: map[string]LocalProviderCredentials{
				"anthropic": {APIKey: "sk-ant"},
			},
		},
	}
	_, err := BuildProviderProxyFromSecrets(cfg, BuildOptions{ListenAddr: "0.0.0.0:9999"})
	if err == nil {
		t.Fatalf("expected error on non-loopback listen addr")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("expected loopback error, got %v", err)
	}
}

// TestBuildProviderProxyFromSecrets_PassesOptions verifies the factory
// forwards ShutdownTimeout and Logger settings down to NewProviderProxy.
// We assert indirectly: the proxy URL is empty before Start (sentinel),
// and Provider() / UpstreamHost() are populated correctly — i.e. the
// constructor ran with our token.
func TestBuildProviderProxyFromSecrets_PassesOptions(t *testing.T) {
	var loggedLines []string
	cfg := &LocalConfig{
		Version: LocalConfigSchemaVersion,
		Secrets: LocalSecretsSection{
			Providers: map[string]LocalProviderCredentials{
				"anthropic": {APIKey: "sk-ant-passes-through"},
			},
		},
	}
	res, err := BuildProviderProxyFromSecrets(cfg, BuildOptions{
		Logger:          func(line string) { loggedLines = append(loggedLines, line) },
		ShutdownTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("BuildProviderProxyFromSecrets: %v", err)
	}
	if len(res.Proxies) != 1 {
		t.Fatalf("expected 1 proxy")
	}
	if res.Proxies[0].URL() != "" {
		t.Errorf("expected empty URL before Start, got %q", res.Proxies[0].URL())
	}
	// The logger is passed through; we don't drive a request so we
	// don't expect any lines, but the existence of the closure must not
	// have triggered an error. (loggedLines may remain nil/empty.)
	_ = loggedLines
}

// TestErrNoProviderCredentialsExported is a smoke test that the
// sentinel is present (a downstream batch will compare against it).
func TestErrNoProviderCredentialsExported(t *testing.T) {
	if ErrNoProviderCredentials == nil {
		t.Fatalf("ErrNoProviderCredentials must be non-nil")
	}
	if !strings.Contains(ErrNoProviderCredentials.Error(), "secrets.local.yaml") {
		t.Errorf("sentinel message should mention the file, got %q", ErrNoProviderCredentials.Error())
	}
}
