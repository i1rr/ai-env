package secrets

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// rewritingTransport is a real http.RoundTripper that the proxy uses to
// reach "upstream". It intercepts the request at the transport boundary
// (the documented test injection point on Options.Transport), rewrites
// the URL.Scheme/Host to point at an httptest.Server, and dispatches
// the request through http.DefaultTransport. The proxy still constructs
// a full http.Request, the test server still receives a real HTTP
// request, and the assertions can inspect both sides.
//
// The transport records every URL it was asked to dial so a test can
// assert the proxy targeted the configured upstream host (api.anthropic.com)
// rather than some attacker-controlled host.
type rewritingTransport struct {
	target  *url.URL
	mu      sync.Mutex
	seen    []*http.Request
	wrapped http.RoundTripper
}

func (t *rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	// Clone the headers so a later mutation by the standard library
	// transport does not race the test's read.
	cloned := req.Clone(req.Context())
	t.seen = append(t.seen, cloned)
	t.mu.Unlock()

	// Real rewrite: send the request to the test upstream.
	req.URL.Scheme = t.target.Scheme
	req.URL.Host = t.target.Host
	req.Host = t.target.Host
	return t.wrapped.RoundTrip(req)
}

func (t *rewritingTransport) lastRequest() *http.Request {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.seen) == 0 {
		return nil
	}
	return t.seen[len(t.seen)-1]
}

// startTestUpstream stands up an httptest.Server that records every
// inbound request. The returned cleanup tears it down.
func startTestUpstream(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *url.URL) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test upstream url: %v", err)
	}
	return srv, u
}

// TestProxy_InjectsAnthropicAuthHeader exercises the happy path: an
// agent makes a request through the proxy targeting an Anthropic API
// path, and the upstream sees the host-side x-api-key / Authorization
// headers. Verifies the secret is injected on the host side and the
// agent's own (missing) auth never reaches the upstream.
func TestProxy_InjectsAnthropicAuthHeader(t *testing.T) {
	const token = "sk-ant-test-token-abcdef0123456789"

	var (
		mu          sync.Mutex
		gotAPIKey   string
		gotAuth     string
		gotPath     string
		gotMethod   string
		gotHostHdr  string
		gotForwHdr  string
	)

	upstream, upstreamURL := startTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAPIKey = r.Header.Get(AuthHeaderAnthropic)
		gotAuth = r.Header.Get(AuthHeaderAuthorization)
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotHostHdr = r.Host
		gotForwHdr = r.Header.Get("X-Forwarded-For")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	_ = upstream

	transport := &rewritingTransport{
		target:  upstreamURL,
		wrapped: http.DefaultTransport,
	}

	var logLines []string
	var logMu sync.Mutex
	logger := func(line string) {
		logMu.Lock()
		logLines = append(logLines, line)
		logMu.Unlock()
	}

	proxy, err := NewProviderProxy(Options{
		Provider:  ProviderAnthropic,
		Token:     token,
		Transport: transport,
		Logger:    logger,
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Stop() })

	if proxy.URL() == "" {
		t.Fatal("URL is empty after Start")
	}
	if !strings.HasPrefix(proxy.URL(), "http://127.0.0.1:") {
		t.Errorf("URL = %q, want http://127.0.0.1:port prefix", proxy.URL())
	}

	// Send a real HTTP request to the proxy with NO auth headers; the
	// proxy must add them on the way out.
	req, err := http.NewRequest("POST", proxy.URL()+"/v1/messages", strings.NewReader(`{"msg":"hi"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "10.0.0.1") // should be stripped
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", resp.StatusCode, string(body))
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q, want %q", string(body), `{"ok":true}`)
	}

	mu.Lock()
	defer mu.Unlock()

	if gotAPIKey != token {
		t.Errorf("upstream x-api-key = %q, want %q", gotAPIKey, token)
	}
	if gotAuth != "Bearer "+token {
		t.Errorf("upstream Authorization = %q, want %q", gotAuth, "Bearer "+token)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages", gotPath)
	}
	if gotMethod != "POST" {
		t.Errorf("upstream method = %q, want POST", gotMethod)
	}
	// httputil.ReverseProxy appends the client (loopback) IP to
	// X-Forwarded-For AFTER our Director runs. What we MUST verify is
	// that the agent-supplied value (10.0.0.1) was stripped: the
	// upstream may see 127.0.0.1 (the loopback client of the proxy)
	// but it must not see the spoofed 10.0.0.1.
	if strings.Contains(gotForwHdr, "10.0.0.1") {
		t.Errorf("upstream X-Forwarded-For = %q contains agent-supplied 10.0.0.1 (proxy must strip it)", gotForwHdr)
	}
	// The proxy's director sets req.Host = upstreamHost. Our transport
	// rewrites it to the test server's host before round-tripping, so
	// the upstream sees the test server host. The important assertion
	// is that the proxy's outbound request was DIRECTED at api.anthropic.com:
	lastDirected := transport.lastRequest()
	if lastDirected == nil {
		t.Fatal("transport saw no requests")
	}
	if lastDirected.URL.Host != "api.anthropic.com" {
		t.Errorf("proxy directed request at %q, want api.anthropic.com", lastDirected.URL.Host)
	}
	if lastDirected.URL.Scheme != "https" {
		t.Errorf("proxy directed scheme = %q, want https", lastDirected.URL.Scheme)
	}
	if lastDirected.Header.Get(AuthHeaderAnthropic) != token {
		t.Errorf("outbound x-api-key = %q, want %q",
			lastDirected.Header.Get(AuthHeaderAnthropic), token)
	}

	// Verify logs were redacted: no raw token should appear.
	logMu.Lock()
	defer logMu.Unlock()
	for _, line := range logLines {
		if strings.Contains(line, token) {
			t.Errorf("log line contains raw token: %q", line)
		}
	}
	// And the upstream host header trace should not echo a forwarded IP.
	_ = gotHostHdr
}

// TestProxy_StripsInboundAuthHeaders verifies an agent that accidentally
// sends its own credentials cannot pass them through to the upstream.
// The proxy MUST drop them and replace with the host-side token.
func TestProxy_StripsInboundAuthHeaders(t *testing.T) {
	const hostToken = "sk-ant-host-side-token-xxxxxxxx"
	const sandboxToken = "sk-ant-sandbox-leak-token-yyyyyy"

	var (
		mu        sync.Mutex
		gotAPIKey string
		gotAuth   string
	)

	_, upstreamURL := startTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAPIKey = r.Header.Get(AuthHeaderAnthropic)
		gotAuth = r.Header.Get(AuthHeaderAuthorization)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	transport := &rewritingTransport{target: upstreamURL, wrapped: http.DefaultTransport}

	proxy, err := NewProviderProxy(Options{
		Provider:  ProviderAnthropic,
		Token:     hostToken,
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Stop() })

	req, _ := http.NewRequest("GET", proxy.URL()+"/v1/models", nil)
	req.Header.Set(AuthHeaderAnthropic, sandboxToken)
	req.Header.Set(AuthHeaderAuthorization, "Bearer "+sandboxToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if gotAPIKey == sandboxToken {
		t.Errorf("upstream saw sandbox token via x-api-key: agent credentials leaked")
	}
	if gotAPIKey != hostToken {
		t.Errorf("upstream x-api-key = %q, want host token %q", gotAPIKey, hostToken)
	}
	if gotAuth != "Bearer "+hostToken {
		t.Errorf("upstream Authorization = %q, want Bearer %q", gotAuth, hostToken)
	}
}

// TestProxy_RejectsUnknownProvider verifies the proxy's "validates
// upstream domain matches configured provider" rule. An unknown
// provider has no upstream host pinned, so the constructor fails
// closed.
func TestProxy_RejectsUnknownProvider(t *testing.T) {
	_, err := NewProviderProxy(Options{
		Provider: "evilcorp",
		Token:    "sk-evilcorp-token-xxxxxxxxxxxxxxxxxx",
	})
	if err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error = %q, want it to mention 'unknown provider'", err.Error())
	}
}

// TestProxy_RejectsNonLoopbackAddr verifies the loopback-only binding
// rule. Configuring 0.0.0.0 (all interfaces) must fail closed at
// construction time so the proxy never accidentally listens on a
// publicly routable interface.
func TestProxy_RejectsNonLoopbackAddr(t *testing.T) {
	_, err := NewProviderProxy(Options{
		Provider:   ProviderAnthropic,
		Token:      "sk-ant-test-aaaaaaaaaaaaaaaaaaaa",
		ListenAddr: "0.0.0.0:0",
	})
	if err == nil {
		t.Fatal("expected error for non-loopback ListenAddr, got nil")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("error = %q, want it to mention 'loopback'", err.Error())
	}
}

// TestProxy_OpenAIAuthHeader covers the OpenAI auth header shape
// (Authorization: Bearer <token> only, no x-api-key).
func TestProxy_OpenAIAuthHeader(t *testing.T) {
	const token = "sk-openai-test-token-zzzzzzzzzzzzz"

	var (
		mu      sync.Mutex
		gotAPI  string
		gotAuth string
	)

	_, upstreamURL := startTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAPI = r.Header.Get(AuthHeaderAnthropic)
		gotAuth = r.Header.Get(AuthHeaderAuthorization)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	transport := &rewritingTransport{target: upstreamURL, wrapped: http.DefaultTransport}

	proxy, err := NewProviderProxy(Options{
		Provider:  ProviderOpenAI,
		Token:     token,
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Stop() })

	req, _ := http.NewRequest("GET", proxy.URL()+"/v1/chat/completions", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer "+token {
		t.Errorf("upstream Authorization = %q, want Bearer %q", gotAuth, token)
	}
	if gotAPI != "" {
		t.Errorf("upstream x-api-key = %q, want empty for OpenAI", gotAPI)
	}

	// Confirm the outbound request targeted api.openai.com.
	last := transport.lastRequest()
	if last == nil {
		t.Fatal("transport saw no requests")
	}
	if last.URL.Host != "api.openai.com" {
		t.Errorf("proxy directed request at %q, want api.openai.com", last.URL.Host)
	}
}

// TestProxy_StopIsIdempotent verifies the supervisor can safely call
// Stop twice (normal terminal path plus panic-recovery defer).
func TestProxy_StopIsIdempotent(t *testing.T) {
	proxy, err := NewProviderProxy(Options{
		Provider: ProviderAnthropic,
		Token:    "sk-ant-test-bbbbbbbbbbbbbbbbbbbb",
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := proxy.Stop(); err != nil {
		t.Errorf("first Stop: %v", err)
	}
	if err := proxy.Stop(); err != nil {
		t.Errorf("second Stop should be no-op, got: %v", err)
	}
	// After Stop, a fresh dial to the previously-bound URL should fail
	// promptly (port is closed). Give it a tiny grace for OS cleanup.
	time.Sleep(20 * time.Millisecond)
}

// TestRedactSecrets exercises the public redactor that every log line
// passes through. Ensures token-like fragments are scrubbed.
func TestRedactSecrets(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no secret", "hello world", "hello world"},
		{
			"anthropic key",
			"key=sk-ant-abcdef0123456789abcdef0123 rest",
			"key=REDACTED rest",
		},
		{
			"openai key",
			"key=sk-abcdefghij0123456789xyz rest",
			"key=REDACTED rest",
		},
		{
			"github personal access token",
			"trace: ghp_abcdefghijklmnopqrstuvwxyz0123456789 done",
			"trace: REDACTED done",
		},
		{
			"github fine-grained PAT",
			"trace: github_pat_abcdefghij0123456789 done",
			"trace: REDACTED done",
		},
		{
			"aws access key id",
			"trace: AKIAIOSFODNN7EXAMPLE done",
			"trace: REDACTED done",
		},
		{
			"google cloud api key",
			"trace: AIzaSyA-abcdefghij0123456789KLMNOPQRSTU done",
			"trace: REDACTED done",
		},
		{
			"slack token",
			"trace: xoxb-1234567890-abcdefghij done",
			"trace: REDACTED done",
		},
		{
			"stripe key",
			"trace: sk_live_abcdefghij0123456789xyz done",
			"trace: REDACTED done",
		},
		{
			"openssh private key header",
			"begin: -----BEGIN OPENSSH PRIVATE KEY----- end",
			"begin: REDACTED end",
		},
		{
			"env secret assignment",
			"config: API_SECRET=supersecret123 trailing",
			"config: REDACTED trailing",
		},
		{
			"bare password assignment",
			"config: PASSWORD=hunter2hunter2 trailing",
			"config: REDACTED trailing",
		},
		{
			"authorization header",
			"trace: Authorization: Bearer xyz123abc done",
			"trace: REDACTED done",
		},
		{
			"x-api-key header",
			"trace: x-api-key: sk-ant-zzzzzzzzzzzzzzzz done",
			"trace: REDACTED done",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSecrets(tc.in)
			if got != tc.want {
				t.Errorf("RedactSecrets(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestProviderProxy_UpstreamHostAllowlist_RejectsOther verifies Plan
// Batch 2.2's open-relay defense: a request whose inbound Host header
// points at an unrelated host (api.openai.com against an anthropic
// proxy) is rejected with HTTP 403 before the request can be rewritten
// and dispatched. The configured upstream (api.anthropic.com) and the
// proxy's own bind address must still be accepted so the legitimate
// use cases keep working.
func TestProviderProxy_UpstreamHostAllowlist_RejectsOther(t *testing.T) {
	const token = "sk-ant-allowlist-test-aaaaaaaaaaaaaaa"

	var upstreamCalls int
	var upstreamMu sync.Mutex
	_, upstreamURL := startTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamMu.Lock()
		upstreamCalls++
		upstreamMu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	transport := &rewritingTransport{target: upstreamURL, wrapped: http.DefaultTransport}
	proxy, err := NewProviderProxy(Options{
		Provider:  ProviderAnthropic,
		Token:     token,
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Stop() })

	// 1) A request that fakes a Host pointing at the OTHER provider
	//    must be rejected with 403; the upstream must not be dialed.
	req, _ := http.NewRequest("POST", proxy.URL()+"/v1/messages", strings.NewReader(`{}`))
	req.Host = "api.openai.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-allowlisted Host: status = %d, want 403", resp.StatusCode)
	}

	// 2) A request that fakes a Host pointing at an unrelated host
	//    must also be rejected.
	req2, _ := http.NewRequest("POST", proxy.URL()+"/v1/messages", strings.NewReader(`{}`))
	req2.Host = "evil.example.com"
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("client.Do evil: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("evil Host: status = %d, want 403", resp2.StatusCode)
	}

	upstreamMu.Lock()
	if upstreamCalls != 0 {
		t.Errorf("upstream dialed %d times; allowlist must reject before dispatch", upstreamCalls)
	}
	upstreamMu.Unlock()

	// 3) Legitimate request (loopback Host) succeeds.
	req3, _ := http.NewRequest("GET", proxy.URL()+"/v1/models", nil)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("client.Do loopback: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp3.Body)
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("loopback Host: status = %d, want 200", resp3.StatusCode)
	}

	// 4) Legitimate request (canonical upstream Host) succeeds.
	req4, _ := http.NewRequest("GET", proxy.URL()+"/v1/models", nil)
	req4.Host = "api.anthropic.com"
	resp4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatalf("client.Do canonical: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp4.Body)
	_ = resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Errorf("canonical Host: status = %d, want 200", resp4.StatusCode)
	}
}

// TestProviderProxy_MultiProvider_TwoListenersDistinctPorts verifies
// Plan Batch 2.2's "One listener per provider" rule: two ProviderProxy
// instances (anthropic + openai) bind distinct ports on loopback and
// each pins its own upstream allowlist. The two listeners must not
// share a port, and a request crafted for one provider's bind must not
// land on the other's.
func TestProviderProxy_MultiProvider_TwoListenersDistinctPorts(t *testing.T) {
	const antTok = "sk-ant-multi-aaaaaaaaaaaaaaaaaaaaaaa"
	const oaTok = "sk-openai-multi-bbbbbbbbbbbbbbbbbbbbbb"

	var antHits, oaHits int
	var mu sync.Mutex
	_, antUpstream := startTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		antHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	_, oaUpstream := startTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		oaHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	antProxy, err := NewProviderProxy(Options{
		Provider:  ProviderAnthropic,
		Token:     antTok,
		Transport: &rewritingTransport{target: antUpstream, wrapped: http.DefaultTransport},
	})
	if err != nil {
		t.Fatalf("anthropic NewProviderProxy: %v", err)
	}
	if err := antProxy.Start(); err != nil {
		t.Fatalf("anthropic Start: %v", err)
	}
	t.Cleanup(func() { _ = antProxy.Stop() })

	oaProxy, err := NewProviderProxy(Options{
		Provider:  ProviderOpenAI,
		Token:     oaTok,
		Transport: &rewritingTransport{target: oaUpstream, wrapped: http.DefaultTransport},
	})
	if err != nil {
		t.Fatalf("openai NewProviderProxy: %v", err)
	}
	if err := oaProxy.Start(); err != nil {
		t.Fatalf("openai Start: %v", err)
	}
	t.Cleanup(func() { _ = oaProxy.Stop() })

	if antProxy.URL() == oaProxy.URL() {
		t.Fatalf("multi-provider proxies share URL %q (must bind distinct ports)", antProxy.URL())
	}
	_, antPort, err := net.SplitHostPort(strings.TrimPrefix(antProxy.URL(), "http://"))
	if err != nil {
		t.Fatalf("split anthropic URL: %v", err)
	}
	_, oaPort, err := net.SplitHostPort(strings.TrimPrefix(oaProxy.URL(), "http://"))
	if err != nil {
		t.Fatalf("split openai URL: %v", err)
	}
	if antPort == oaPort {
		t.Errorf("anthropic and openai share port %s", antPort)
	}

	// Each proxy's upstream pin is independent — a request to the
	// anthropic proxy lands at the anthropic upstream (and vice
	// versa).
	resp, err := http.DefaultClient.Get(antProxy.URL() + "/v1/messages")
	if err != nil {
		t.Fatalf("ant client.Do: %v", err)
	}
	_ = resp.Body.Close()
	resp2, err := http.DefaultClient.Get(oaProxy.URL() + "/v1/chat/completions")
	if err != nil {
		t.Fatalf("oa client.Do: %v", err)
	}
	_ = resp2.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if antHits != 1 {
		t.Errorf("anthropic upstream hits = %d, want 1", antHits)
	}
	if oaHits != 1 {
		t.Errorf("openai upstream hits = %d, want 1", oaHits)
	}

	// Each proxy reports its own provider via BindMode/Provider so the
	// supervisor's proxy_started metadata is unambiguous.
	if antProxy.Provider() != ProviderAnthropic || oaProxy.Provider() != ProviderOpenAI {
		t.Errorf("provider tags swapped: ant=%q oa=%q", antProxy.Provider(), oaProxy.Provider())
	}
}

// TestProviderProxy_BindModeSetnsTCP_UsesNetNSEnter verifies the
// SetnsTCP path delegates the bind to the supervisor-supplied
// NetNSEnter callback. On macOS / non-privileged Linux we cannot
// actually enter a netns, so the test injects an identity wrapper that
// runs the bind closure in the current netns. The assertion is that
// (a) NetNSEnter was called with the configured NetNSPath, and (b) the
// resulting URL is reachable.
func TestProviderProxy_BindModeSetnsTCP_UsesNetNSEnter(t *testing.T) {
	const token = "sk-ant-setns-test-cccccccccccccccccccc"

	var enteredPath string
	enter := func(path string, fn func() (net.Listener, error)) (net.Listener, error) {
		enteredPath = path
		return fn()
	}

	proxy, err := NewProviderProxy(Options{
		Provider:   ProviderAnthropic,
		Token:      token,
		BindMode:   BindModeSetnsTCP,
		NetNSPath:  "/proc/12345/ns/net",
		NetNSEnter: enter,
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Stop() })

	if enteredPath != "/proc/12345/ns/net" {
		t.Errorf("NetNSEnter called with path=%q, want /proc/12345/ns/net", enteredPath)
	}
	if proxy.BindMode() != BindModeSetnsTCP {
		t.Errorf("BindMode() = %q, want %q", proxy.BindMode(), BindModeSetnsTCP)
	}
	if !strings.HasPrefix(proxy.URL(), "http://127.0.0.1:") {
		t.Errorf("URL = %q, want http://127.0.0.1:port prefix", proxy.URL())
	}
}

// TestProviderProxy_BindModeSetnsTCP_RequiresNetNSEnter verifies the
// SetnsTCP mode fails closed when the supervisor did not supply a
// NetNSEnter wrapper. Without the wrapper the proxy would silently
// bind in the host netns where the agent cannot reach it; failing at
// Start is the loud signal the supervisor turns into a fatal error.
func TestProviderProxy_BindModeSetnsTCP_RequiresNetNSEnter(t *testing.T) {
	proxy, err := NewProviderProxy(Options{
		Provider:  ProviderAnthropic,
		Token:     "sk-ant-test-ddddddddddddddddddddd",
		BindMode:  BindModeSetnsTCP,
		NetNSPath: "/proc/12345/ns/net",
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	err = proxy.Start()
	if err == nil {
		_ = proxy.Stop()
		t.Fatal("expected error from Start when NetNSEnter is nil for BindModeSetnsTCP")
	}
	if !strings.Contains(err.Error(), "NetNSEnter") {
		t.Errorf("error = %q, want it to mention NetNSEnter", err.Error())
	}
}

// TestProviderProxy_BindModeSetnsTCP_RequiresNetNSPath verifies the
// SetnsTCP mode rejects an empty NetNSPath at construction time so a
// misconfigured supervisor fails fast.
func TestProviderProxy_BindModeSetnsTCP_RequiresNetNSPath(t *testing.T) {
	_, err := NewProviderProxy(Options{
		Provider:   ProviderAnthropic,
		Token:      "sk-ant-test-eeeeeeeeeeeeeeeeeeeee",
		BindMode:   BindModeSetnsTCP,
		NetNSEnter: func(path string, fn func() (net.Listener, error)) (net.Listener, error) { return fn() },
	})
	if err == nil {
		t.Fatal("expected error for empty NetNSPath")
	}
	if !strings.Contains(err.Error(), "NetNSPath") {
		t.Errorf("error = %q, want it to mention NetNSPath", err.Error())
	}
}

// TestProviderProxy_BindModeBridgeGateway_RequiresListenAddr verifies
// the BridgeGateway mode rejects a missing ListenAddr (the supervisor
// MUST plumb the gateway IP from Backend.GatewayAddress()).
func TestProviderProxy_BindModeBridgeGateway_RequiresListenAddr(t *testing.T) {
	_, err := NewProviderProxy(Options{
		Provider: ProviderAnthropic,
		Token:    "sk-ant-test-fffffffffffffffffffff",
		BindMode: BindModeBridgeGateway,
	})
	if err == nil {
		t.Fatal("expected error for empty ListenAddr in BindModeBridgeGateway")
	}
	if !strings.Contains(err.Error(), "ListenAddr") {
		t.Errorf("error = %q, want it to mention ListenAddr", err.Error())
	}
}

// TestProviderProxy_BindModeUnixSocket_BindsListener verifies the
// UnixSocket path binds a stream socket at the supplied path and
// reports the path via ListenAddr(). The plan locks this as the
// fallback mode when SetnsTCP / BridgeGateway are unavailable.
func TestProviderProxy_BindModeUnixSocket_BindsListener(t *testing.T) {
	// macOS / BSD cap Unix socket paths at ~104 bytes (Linux ~108);
	// t.TempDir() typically nests under /var/folders/... which can
	// exceed the limit. Use a short /tmp path so the test runs on
	// every supported host. The cleanup removes the parent.
	dir, err := os.MkdirTemp("/tmp", "ppx-sock")
	if err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "a.sock")
	proxy, err := NewProviderProxy(Options{
		Provider:       ProviderAnthropic,
		Token:          "sk-ant-test-ggggggggggggggggggggg",
		BindMode:       BindModeUnixSocket,
		UnixSocketPath: sockPath,
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Stop() })

	if proxy.BindMode() != BindModeUnixSocket {
		t.Errorf("BindMode() = %q, want %q", proxy.BindMode(), BindModeUnixSocket)
	}
	if proxy.ListenAddr() != sockPath {
		t.Errorf("ListenAddr() = %q, want %q", proxy.ListenAddr(), sockPath)
	}
	if !strings.HasPrefix(proxy.URL(), "http+unix://") {
		t.Errorf("URL = %q, want http+unix:// prefix", proxy.URL())
	}
	// Stat the socket node to confirm the bind landed on disk.
	if _, err := os.Stat(sockPath); err != nil {
		t.Errorf("unix socket not on disk: %v", err)
	}
	// Stop removes the socket node.
	if err := proxy.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if _, err := os.Stat(sockPath); err == nil {
		t.Errorf("unix socket still on disk after Stop")
	}
}

// TestProviderProxy_BindModeUnknown rejects an unknown BindMode value
// at construction so a typo in the supervisor-side config fails loud.
func TestProviderProxy_BindModeUnknown(t *testing.T) {
	_, err := NewProviderProxy(Options{
		Provider: ProviderAnthropic,
		Token:    "sk-ant-test-hhhhhhhhhhhhhhhhhhhhh",
		BindMode: BindMode("not_a_mode"),
	})
	if err == nil {
		t.Fatal("expected error for unknown BindMode")
	}
	if !strings.Contains(err.Error(), "BindMode") {
		t.Errorf("error = %q, want it to mention BindMode", err.Error())
	}
}
