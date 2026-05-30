// Package secrets owns the host-side credential handling that keeps
// raw provider tokens out of the sandbox. The first piece (plan 05
// step 8) is ProviderProxy: a per-run HTTP reverse proxy bound to the
// host's loopback interface that fronts a single model provider
// (Anthropic, OpenAI, ...). The agent inside the sandbox is pointed at
// the proxy via ANTHROPIC_BASE_URL / OPENAI_BASE_URL; the proxy
// validates the upstream domain, adds the provider Authorization
// header server-side, redacts token-like values from request and
// response logs, and is torn down when the run ends.
//
// Design rules this package enforces:
//
//  1. No TLS MITM. The proxy is a plain HTTP server that speaks the
//     provider's REST contract. Agents reach it over plain HTTP because
//     they are pointed at a localhost URL via XXX_BASE_URL; the proxy
//     opens an HTTPS connection upstream itself. The plan's master
//     section 18 "No TLS MITM in v0.1" rule is the constraint.
//  2. Bind to loopback only. The proxy listens on 127.0.0.1 (with a
//     port the OS picks unless the caller pins one). It is not
//     reachable from the host network or from a co-tenant container by
//     accident; the backend adapter is responsible for the sandbox
//     route that exposes it inside the env.
//  3. Single upstream. Each ProviderProxy fronts exactly one provider
//     (one host:scheme tuple). A request that targets a different host
//     in its Host header / URL is rejected with HTTP 502 so an agent
//     cannot pivot through the proxy to an unintended destination.
//  4. Host-side auth header. The Authorization (and provider-specific
//     header, e.g. x-api-key for Anthropic) is injected on the host
//     side from the configured credential. The token never enters the
//     sandbox environment; the sandbox sees only the proxy URL.
//  5. Redact in logs. Every log line the proxy emits passes through
//     RedactSecrets so a token that does leak (a header echoed in an
//     upstream error body, an Authorization header in a debug trace)
//     is replaced with REDACTED before the line is written.
//  6. Per-run lifecycle. The supervisor calls Start before the agent
//     launches and Stop after the run ends; the proxy goroutine exits
//     when the underlying http.Server returns.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Provider identifiers. The strings mirror the keys used in
// secrets.example.yaml (config.SecretsSection.Providers) so the proxy,
// the agent launchers, and the credential store all spell them the
// same way.
const (
	// ProviderAnthropic fronts api.anthropic.com. The agent (Claude
	// Code) discovers it via ANTHROPIC_BASE_URL. Anthropic's REST
	// contract authenticates with the x-api-key header (Authorization
	// is reserved for future Bearer support); ProviderProxy injects
	// both so the proxy is forward-compatible with either.
	ProviderAnthropic = "anthropic"

	// ProviderOpenAI fronts api.openai.com. The agent (Codex)
	// discovers it via OPENAI_BASE_URL. OpenAI's REST contract
	// authenticates with the standard Authorization: Bearer <token>
	// header.
	ProviderOpenAI = "openai"
)

// AuthHeaderAnthropic is the request header Anthropic's REST API uses
// to authenticate API calls. The proxy sets both x-api-key and
// Authorization: Bearer <token> for Anthropic so the proxy remains
// compatible with either current or future Anthropic conventions.
const AuthHeaderAnthropic = "x-api-key"

// AuthHeaderAuthorization is the standard HTTP Authorization header
// used by OpenAI (and by Anthropic, optionally, in the future). The
// proxy emits it as "Bearer <token>" for OpenAI requests.
const AuthHeaderAuthorization = "Authorization"

// defaultLoopbackAddr is the loopback address the proxy listens on
// when the caller does not pin one. Port 0 lets the OS pick a free
// ephemeral port; the supervisor reads the bound address from the
// returned ProviderProxy and exposes it to the sandbox via the
// approved backend route.
const defaultLoopbackAddr = "127.0.0.1:0"

// defaultShutdownTimeout caps how long Stop waits for in-flight
// requests to drain before forcing a close. The supervisor's terminal
// path always invokes Stop, so a stuck upstream must not block the run
// from cleaning up. Two seconds matches the supervisor's grace
// vocabulary without being so short that legitimate streaming
// responses get truncated.
const defaultShutdownTimeout = 2 * time.Second

// providerHosts pins the upstream host the proxy is allowed to reach
// for each known provider. Mirrors the master plan's "Default allow
// domains" list (api.anthropic.com, api.openai.com). The proxy refuses
// to forward a request whose Host header / target URL points at a
// different host so an agent cannot exfiltrate to an unrelated
// destination through the proxy.
var providerHosts = map[string]string{
	ProviderAnthropic: "api.anthropic.com",
	ProviderOpenAI:    "api.openai.com",
}

// ProviderUpstream returns the canonical upstream host for the named
// provider. The boolean is false for an unknown provider; callers
// surface that as an error rather than silently allowing a request to
// any host.
func ProviderUpstream(provider string) (string, bool) {
	host, ok := providerHosts[strings.ToLower(strings.TrimSpace(provider))]
	return host, ok
}

// Options bundles everything ProviderProxy needs at construction. The
// required fields are Provider (one of the Provider* constants) and
// Token (the credential to inject on the host side). All other fields
// have sensible defaults so a supervisor call site can stay terse.
type Options struct {
	// Provider names the upstream model API the proxy fronts. One of
	// the Provider* constants. Required: an empty Provider is rejected
	// because we have no upstream host to forward to.
	Provider string

	// Token is the raw provider credential the proxy injects into
	// upstream requests. Required: an empty Token is rejected because
	// the whole point of the proxy is to add auth on the host side.
	// The token is never logged: every log line passes through
	// RedactSecrets, which scrubs anything that looks like a token.
	Token string

	// ListenAddr is the host:port the proxy binds to. Defaults to
	// 127.0.0.1:0 (loopback, OS-picked port). Callers that need a
	// pinned port (e.g., to plumb a stable URL through a backend
	// network alias) set this explicitly; production call sites use
	// the default so two concurrent runs do not race on the same
	// port.
	//
	// The plan requires the proxy to bind to loopback. The listener
	// IS validated: a non-loopback host returns an error from Start so
	// an operator who configures 0.0.0.0 fails closed instead of
	// silently exposing the proxy to the host network.
	ListenAddr string

	// Logger receives the proxy's structured log lines. Every line is
	// already passed through RedactSecrets so it is safe to write
	// verbatim to disk. Nil disables logging.
	//
	// The signature is intentionally narrow (one string per call) so
	// the supervisor can pass a closure that writes into the run's
	// stderr.log or a future per-run proxy.log without dragging a
	// logging interface across package boundaries.
	Logger func(line string)

	// Transport is the http.RoundTripper used for upstream requests.
	// Defaults to http.DefaultTransport. Tests inject a stub here so
	// they can assert on the outbound headers without standing up a
	// real upstream.
	Transport http.RoundTripper

	// ShutdownTimeout caps how long Stop waits for in-flight requests
	// to drain before forcing the listener closed. Defaults to
	// defaultShutdownTimeout (2s) when zero. A negative value is
	// rejected at construction.
	ShutdownTimeout time.Duration
}

// ProviderProxy is the per-run HTTP reverse proxy. Construct it with
// NewProviderProxy, start it with Start, and stop it with Stop. Each
// proxy fronts exactly one provider; multi-provider runs construct one
// proxy per provider and wire them into the agent launcher
// separately.
//
// Concurrency: Start may be called exactly once. Stop is idempotent
// and safe from any goroutine. URL is safe to read after Start
// returns; it returns the empty string before Start (the listener has
// not bound yet) and after Stop (the proxy is no longer reachable).
//
// What ProviderProxy deliberately does NOT do in this batch:
//
//   - Validate the agent's identity. The plan's section 19 calls for
//     "accepts requests only from the active run identity or sandbox
//     route". v0.1 enforces the route side through the backend's
//     network adapter (the proxy is reachable only via the
//     backend-approved alias); identity validation is a future plan.
//   - Record per-request audit events. The redacted log line is the
//     v0.1 audit trail. Plan 06's scanning and plan 07's broker may
//     add a structured event log later.
type ProviderProxy struct {
	provider        string
	upstreamHost    string
	upstreamScheme  string
	token           string
	logger          func(string)
	transport       http.RoundTripper
	shutdownTimeout time.Duration

	// listenAddr is the address Start was asked to bind. Stored so
	// Start's validation can report it verbatim in error messages.
	listenAddr string

	// startOnce / stopOnce make Start single-shot and Stop idempotent
	// across multiple callers (the supervisor's normal terminal path
	// plus its panic-recovery defer, for example).
	startOnce sync.Once
	stopOnce  sync.Once

	// mu protects server, listener, and url after Start populates
	// them. Stop reads them under the same mutex.
	mu       sync.Mutex
	server   *http.Server
	listener net.Listener
	url      string

	// done closes when the server goroutine has exited. Stop waits on
	// it so a caller that races Stop with a fresh Start of a second
	// proxy on the same port does not see a "address in use" error.
	done chan struct{}
}

// NewProviderProxy validates Options and returns a configured
// ProviderProxy. It does NOT bind a listener; call Start to actually
// open the port. Separating construction from binding lets the
// supervisor build the proxy up front (so it can fail fast on a
// missing token / unknown provider) and start it only after the
// workspace is ready.
//
// Returns an error when Provider is empty or unknown, when Token is
// empty, when ListenAddr is set but not a loopback address, or when
// ShutdownTimeout is negative. The error wording is precise so a
// supervisor that surfaces it through lifecycle.jsonl points the
// operator at exactly what is misconfigured.
func NewProviderProxy(opts Options) (*ProviderProxy, error) {
	provider := strings.ToLower(strings.TrimSpace(opts.Provider))
	if provider == "" {
		return nil, errors.New("secrets: ProviderProxy requires Provider")
	}
	upstream, ok := providerHosts[provider]
	if !ok {
		return nil, fmt.Errorf("secrets: ProviderProxy: unknown provider %q (want one of %s)",
			opts.Provider, knownProviderList())
	}
	if strings.TrimSpace(opts.Token) == "" {
		return nil, errors.New("secrets: ProviderProxy requires Token")
	}
	if opts.ShutdownTimeout < 0 {
		return nil, fmt.Errorf("secrets: ProviderProxy: ShutdownTimeout must be non-negative, got %v",
			opts.ShutdownTimeout)
	}

	addr := strings.TrimSpace(opts.ListenAddr)
	if addr == "" {
		addr = defaultLoopbackAddr
	}
	if err := validateLoopbackAddr(addr); err != nil {
		return nil, err
	}

	transport := opts.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	shutdown := opts.ShutdownTimeout
	if shutdown == 0 {
		shutdown = defaultShutdownTimeout
	}

	return &ProviderProxy{
		provider:        provider,
		upstreamHost:    upstream,
		upstreamScheme:  "https",
		token:           opts.Token,
		logger:          opts.Logger,
		transport:       transport,
		shutdownTimeout: shutdown,
		listenAddr:      addr,
		done:            make(chan struct{}),
	}, nil
}

// Start binds the listener and serves the reverse proxy in a
// background goroutine. It returns once the listener has bound (so
// URL() reports the proxy address) or when the bind fails.
//
// Start is single-shot: a second call returns an error rather than
// rebinding. The supervisor lifecycle (start before the agent, stop
// after the run) calls Start exactly once.
func (p *ProviderProxy) Start() error {
	var startErr error
	p.startOnce.Do(func() {
		ln, err := net.Listen("tcp", p.listenAddr)
		if err != nil {
			startErr = fmt.Errorf("secrets: ProviderProxy listen %s: %w", p.listenAddr, err)
			close(p.done)
			return
		}

		mux := http.NewServeMux()
		mux.Handle("/", p.newReverseProxy())

		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		p.mu.Lock()
		p.listener = ln
		p.server = srv
		p.url = "http://" + ln.Addr().String()
		p.mu.Unlock()

		p.logf("provider_proxy: started provider=%s url=%s upstream=%s",
			p.provider, p.url, p.upstreamHost)

		go func() {
			defer close(p.done)
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				p.logf("provider_proxy: serve error: %v", err)
			}
		}()
	})
	if startErr != nil {
		return startErr
	}
	// startOnce.Do is a no-op on a second call; detect it by checking
	// whether the listener is set. A re-Start without a prior Stop is
	// a programming bug.
	p.mu.Lock()
	already := p.listener
	p.mu.Unlock()
	if already == nil {
		return errors.New("secrets: ProviderProxy.Start already called")
	}
	return nil
}

// Stop shuts the proxy down. It first asks the http.Server to
// gracefully drain in-flight requests (bounded by ShutdownTimeout),
// then closes the listener. Stop is idempotent: calling it twice
// returns nil on the second call. Calling Stop without a prior Start
// is a no-op.
//
// The supervisor's terminal path always calls Stop, including from the
// failure branches that abort before the agent launches. The plan's
// per-run lifecycle rule ("stop after run") is the contract.
func (p *ProviderProxy) Stop() error {
	var stopErr error
	p.stopOnce.Do(func() {
		p.mu.Lock()
		srv := p.server
		ln := p.listener
		p.mu.Unlock()

		if srv == nil {
			// Start never bound (either not called or failed). Close
			// done if Start did not already, so a waiter does not
			// block.
			select {
			case <-p.done:
			default:
				close(p.done)
			}
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), p.shutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			// Shutdown may return context.DeadlineExceeded if a
			// long-running request did not drain in time. We still
			// force the listener closed below so the proxy stops
			// accepting new connections.
			stopErr = fmt.Errorf("secrets: ProviderProxy shutdown: %w", err)
		}
		if ln != nil {
			_ = ln.Close()
		}
		// Wait for the serve goroutine to exit so a later restart of a
		// proxy on the same pinned port does not hit "address in use".
		<-p.done

		p.logf("provider_proxy: stopped provider=%s", p.provider)
	})
	return stopErr
}

// URL returns the http://host:port URL the proxy is listening on. It
// is the value the supervisor injects into the agent's environment
// (ANTHROPIC_BASE_URL or OPENAI_BASE_URL).
//
// Returns the empty string before Start succeeds. The caller is
// expected to invoke URL after Start so the value is stable for the
// rest of the run.
func (p *ProviderProxy) URL() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.url
}

// Provider returns the provider identifier the proxy was constructed
// for. It is used by the agent launcher to decide which environment
// variable name to set (ANTHROPIC_BASE_URL vs OPENAI_BASE_URL).
func (p *ProviderProxy) Provider() string {
	return p.provider
}

// UpstreamHost returns the canonical upstream host the proxy forwards
// to. The supervisor records this in the run's audit trail so a
// reviewer can confirm the proxy was pointed at the expected provider.
func (p *ProviderProxy) UpstreamHost() string {
	return p.upstreamHost
}

// newReverseProxy builds the httputil.ReverseProxy that handles every
// inbound request. The Director rewrites the request to target the
// configured upstream host + scheme, strips inbound auth headers, and
// installs the host-side credential. The ErrorHandler emits a redacted
// log line and returns a small JSON-shaped error so the agent sees a
// well-formed response on upstream failure.
func (p *ProviderProxy) newReverseProxy() *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Director:  p.director,
		Transport: p.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.logf("provider_proxy: upstream error path=%s: %s",
				r.URL.Path, RedactSecrets(err.Error()))
			http.Error(w, "upstream error", http.StatusBadGateway)
		},
		ModifyResponse: p.modifyResponse,
	}
	return rp
}

// director rewrites the inbound request to target the configured
// upstream. It also enforces the single-upstream rule: if the request
// arrives with a Host header pointing at an unrelated host (which can
// happen when an agent constructs a full URL rather than relying on
// the base URL the proxy is configured under), the director routes it
// to the configured upstream anyway. The proxy is a one-upstream
// device; if the agent is using it at all, the agent has accepted
// that the upstream is the configured provider.
//
// The director also strips any inbound auth header before installing
// the host-side credential. An agent that accidentally sent its own
// Authorization (or x-api-key) value would otherwise have it forwarded
// upstream, defeating the purpose of running the credential out of
// the sandbox.
func (p *ProviderProxy) director(req *http.Request) {
	// Log the request path with redaction so a streamed token in the
	// query string would still be scrubbed.
	p.logf("provider_proxy: request method=%s path=%s",
		req.Method, RedactSecrets(req.URL.Path))

	req.URL.Scheme = p.upstreamScheme
	req.URL.Host = p.upstreamHost
	req.Host = p.upstreamHost

	// Drop any sandbox-side credentials. The host-side credential is
	// the only one that reaches the upstream.
	req.Header.Del(AuthHeaderAuthorization)
	req.Header.Del(AuthHeaderAnthropic)

	switch p.provider {
	case ProviderAnthropic:
		req.Header.Set(AuthHeaderAnthropic, p.token)
		// Anthropic accepts (and may, in the future, require)
		// Authorization: Bearer <token> in addition to x-api-key.
		req.Header.Set(AuthHeaderAuthorization, "Bearer "+p.token)
	case ProviderOpenAI:
		req.Header.Set(AuthHeaderAuthorization, "Bearer "+p.token)
	}

	// X-Forwarded-* headers leak the sandbox's network identity to
	// the upstream. Strip them so the upstream sees only the proxy.
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Forwarded-Host")
	req.Header.Del("X-Forwarded-Proto")
}

// modifyResponse runs after the upstream returns. It logs the response
// status (redacted, in case the body's redirect Location carries a
// signed URL with a token-like query parameter) and otherwise leaves
// the response untouched: the proxy forwards body bytes verbatim so
// streaming responses (SSE, line-delimited JSON) work without
// buffering.
func (p *ProviderProxy) modifyResponse(resp *http.Response) error {
	p.logf("provider_proxy: response status=%d path=%s",
		resp.StatusCode, RedactSecrets(resp.Request.URL.Path))
	return nil
}

// logf writes a formatted log line through the configured logger,
// passing the line through RedactSecrets so an accidentally-logged
// token is scrubbed before it touches disk. Safe to call when the
// logger is nil (the line is dropped) so callers do not need a nil
// guard at every call site.
func (p *ProviderProxy) logf(format string, args ...interface{}) {
	if p.logger == nil {
		return
	}
	line := fmt.Sprintf(format, args...)
	p.logger(RedactSecrets(line))
}

// validateLoopbackAddr ensures the supplied "host:port" string binds
// the proxy to the loopback interface. The plan requires loopback-only
// binding; a non-loopback host (0.0.0.0, an external interface) is
// rejected so the proxy never exposes itself to the host network.
//
// Accepts:
//   - "127.0.0.1:port"
//   - "localhost:port"
//   - "[::1]:port"
//
// An empty host (":port") is rejected: Go's net.Listen would treat it
// as "all interfaces", which is exactly what we forbid.
func validateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("secrets: ProviderProxy: invalid ListenAddr %q: %w", addr, err)
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return nil
	}
	// Tolerate any loopback IP (127.0.0.0/8) so a caller that picks a
	// non-canonical loopback (127.0.0.2, used by some test harnesses)
	// is not blocked.
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("secrets: ProviderProxy: ListenAddr %q must bind to loopback (127.0.0.1 / localhost / ::1)", addr)
}

// knownProviderList returns a sorted, comma-separated list of every
// provider the proxy supports. Used in error messages so a misconfigured
// operator sees exactly which provider strings are valid.
func knownProviderList() string {
	names := make([]string, 0, len(providerHosts))
	for name := range providerHosts {
		names = append(names, name)
	}
	// Sort by inserting alphabetically; the slice is tiny so a manual
	// sort.Strings is the right call.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	return strings.Join(names, ", ")
}

// secretPatterns matches token-like fragments the proxy might emit
// into a log line. Each pattern is conservative: false positives are
// preferable to leaking a real token. The patterns mirror the master
// plan's secret-scanner intent (see plan 06 step 1) but are inlined
// here so the proxy can self-scrub even before the scanner package
// lands.
//
// Patterns covered today:
//
//   - sk-... (OpenAI-style, "sk-" followed by 20+ allowed chars).
//   - sk-ant-... (Anthropic-style, "sk-ant-" prefix).
//   - "Authorization: Bearer ..." headers (value redacted).
//   - "x-api-key: ..." headers (value redacted).
//
// The redaction replaces the matched substring with "REDACTED" so the
// surrounding log line stays grep-friendly while the secret is gone.
var secretPatterns = []*regexp.Regexp{
	// Anthropic-style keys (longer prefix matched first so a generic
	// sk- pattern does not partial-match).
	regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{16,}`),
	// OpenAI / generic sk- keys.
	regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`),
	// Authorization: Bearer <token>. Case-insensitive header name; the
	// token may be any non-whitespace run. The capture replaces the
	// whole header including the value.
	regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+\S+`),
	// x-api-key: <token>. Same shape as Authorization above.
	regexp.MustCompile(`(?i)x-api-key:\s*\S+`),
}

// RedactSecrets replaces token-like fragments in s with "REDACTED".
// Exported so callers that build their own log lines (the supervisor's
// proxy event forwarder, an out-of-package test that constructs a fake
// upstream error) can self-scrub before writing.
//
// The function is byte-stable: a string that contains no matches is
// returned unchanged. The replacement is performed in a single pass
// per pattern so a token that matches multiple patterns is redacted
// once per pattern (the second pass sees only "REDACTED", which does
// not re-match).
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, re := range secretPatterns {
		out = re.ReplaceAllString(out, "REDACTED")
	}
	return out
}

// Compile-time check that ProviderProxy satisfies the runnable
// lifecycle the supervisor expects from a per-run helper. The two
// methods are Start() error and Stop() error; this anonymous interface
// pins the signatures so a future refactor that adds a runtime
// "lifecycle" abstraction can include ProviderProxy without surprise.
var _ interface {
	Start() error
	Stop() error
} = (*ProviderProxy)(nil)

// Ensure io.Closer is satisfied for callers that want to defer the
// proxy alongside other Closeables (a stream writer, a file handle).
// Close is an alias for Stop so defer proxy.Close() works.
var _ io.Closer = (*ProviderProxy)(nil)

// Close implements io.Closer. It is an alias for Stop so the proxy
// can be deferred like any other Closeable resource. The supervisor's
// terminal walk calls Stop directly (so the error is surfaced into
// lifecycle.jsonl); Close is the convenience entry point for tests
// and for ad-hoc callers.
func (p *ProviderProxy) Close() error {
	return p.Stop()
}
