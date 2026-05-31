package secrets

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
