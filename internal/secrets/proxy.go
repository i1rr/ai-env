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
	"os"
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

// BindMode names the reachability mode the ProviderProxy listener
// binds in. The values mirror `capability.ProviderProxyMode` (kept as a
// dedicated type here so the secrets package does not import the
// capability package and lift it into every consumer's dependency
// graph). The supervisor's canonical pre-launch step 6 picks one of
// these per run; the proxy honors the choice via Options.BindMode.
//
// Plan Batch 2.2 pins the chain: SetnsTCP → BridgeGateway → UnixSocket.
type BindMode string

const (
	// BindModeSetnsTCP binds the listener inside a target network
	// namespace (the sandbox netns). The supervisor wraps Start in
	// `ns.WithNetNSPath(NetNSPath, ...)` so the bound TCP listener is
	// reachable to the agent inside the sandbox without an external
	// route. Linux-only.
	BindModeSetnsTCP BindMode = "setns_tcp"

	// BindModeBridgeGateway binds the listener on a host-side bridge
	// gateway IP that the sandbox can dial. ListenAddr carries the
	// host:port the proxy must bind (typically the gateway IP the
	// backend reports via `Backend.GatewayAddress()`). The supervisor
	// narrows NetworkPolicy.ProxyCarveOuts to include the address so
	// the sandbox's egress rules tolerate the traffic.
	BindModeBridgeGateway BindMode = "bridge_gateway"

	// BindModeUnixSocket binds the listener on a per-run Unix socket
	// at UnixSocketPath. The agent CLI's HTTP client must honor
	// `http+unix://` for this mode to be reachable; the supervisor
	// only picks it when the feature probe succeeds.
	BindModeUnixSocket BindMode = "unix_socket"

	// BindModeLoopback is the legacy default for tests and call sites
	// that do not yet wire a per-run reachability mode. The listener
	// binds on the host's loopback interface with no namespace
	// wrapping. Mirrors the v0 behavior so the existing proxy_test.go
	// surface keeps passing.
	BindModeLoopback BindMode = "loopback"
)

// String returns the canonical token for the mode. Mirrors the values
// `capability.ProviderProxyMode` stringifies to so a verb's metadata
// reads the same regardless of which package authored the field.
func (b BindMode) String() string { return string(b) }

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

	// BindMode names the reachability mode the listener binds in. One
	// of the BindMode constants. Defaults to BindModeLoopback so the
	// pre-Batch-2.2 surface (proxy_test.go) keeps working unchanged.
	//
	// Plan Batch 2.2: the supervisor picks the mode at canonical
	// pre-launch step 6 (see capability.PickProviderProxyMode) and
	// passes it through here. SetnsTCP requires NetNSPath; UnixSocket
	// requires UnixSocketPath; BridgeGateway and Loopback use
	// ListenAddr (which is validated as a loopback or bridge-gateway
	// address depending on the mode).
	BindMode BindMode

	// NetNSPath is the absolute path of the target network namespace
	// the SetnsTCP listener binds in. Required when BindMode is
	// BindModeSetnsTCP; ignored otherwise. The supervisor obtains the
	// path from the backend (e.g. `/proc/<pid>/ns/net`) before calling
	// Start; the proxy itself does not interpret the path.
	NetNSPath string

	// NetNSEnter, when non-nil, wraps the listener-bind operation in
	// the caller's netns-entry function. The supervisor injects an
	// implementation backed by `ns.WithNetNSPath` (Plan §0.5 / tech
	// stack row) so the TCP listener is bound inside the sandbox netns
	// without the Go scheduler migrating the bind goroutine off the
	// locked OS thread. Tests pass a no-op (the func runs fn directly)
	// so the SetnsTCP path is exercisable on macOS / non-privileged
	// hosts where setns is unavailable.
	//
	// Contract:
	//   - fn is the listener-bind closure; it returns the bound
	//     net.Listener and an error.
	//   - NetNSEnter MUST invoke fn exactly once; the wrapper returns
	//     fn's outputs verbatim (the proxy expects the bound listener
	//     to be reachable from outside the netns once fn returns,
	//     which is the documented invariant for TCP listeners bound
	//     inside a netns).
	//
	// When BindMode is not BindModeSetnsTCP the field is ignored. When
	// it is BindModeSetnsTCP and NetNSEnter is nil the proxy reports
	// an error from Start so a misconfigured supervisor fails loud at
	// bind time rather than silently leaving the listener in the host
	// netns.
	NetNSEnter func(path string, fn func() (net.Listener, error)) (net.Listener, error)

	// UnixSocketPath is the absolute path of the Unix socket the proxy
	// binds when BindMode is BindModeUnixSocket. Required for that
	// mode; ignored otherwise. The supervisor chowns the socket to the
	// sandbox UID (via the runDir/ipc mount layer) after Start
	// returns; the proxy itself does not chmod or chown.
	UnixSocketPath string
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

	// bindMode names the reachability mode the listener uses. Plan
	// Batch 2.2 picks the mode at supervisor step 6; the proxy honors
	// the choice via the Options.BindMode field.
	bindMode BindMode

	// netNSPath is the absolute path of the target netns the
	// SetnsTCP listener binds in. Empty for other bind modes.
	netNSPath string

	// netNSEnter wraps the listener bind in the supervisor-supplied
	// netns-entry function. Nil for non-SetnsTCP modes.
	netNSEnter func(path string, fn func() (net.Listener, error)) (net.Listener, error)

	// unixSocketPath is the absolute path of the Unix socket the
	// UnixSocket mode binds. Empty for other bind modes.
	unixSocketPath string

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

	bindMode := opts.BindMode
	if bindMode == "" {
		bindMode = BindModeLoopback
	}

	addr := strings.TrimSpace(opts.ListenAddr)
	netNSPath := strings.TrimSpace(opts.NetNSPath)
	unixSocketPath := strings.TrimSpace(opts.UnixSocketPath)

	switch bindMode {
	case BindModeLoopback, BindModeSetnsTCP:
		// SetnsTCP also binds a TCP listener; the wrapper enters the
		// target netns before the bind so the address pins loopback
		// inside that netns (Plan Batch 2.2: "ns.WithNetNSPath at the
		// call site"). The validator therefore enforces the same
		// loopback rule for both modes — the listener is reachable
		// only inside the chosen netns regardless of mode.
		if addr == "" {
			addr = defaultLoopbackAddr
		}
		if err := validateLoopbackAddr(addr); err != nil {
			return nil, err
		}
		if bindMode == BindModeSetnsTCP {
			if netNSPath == "" {
				return nil, errors.New("secrets: ProviderProxy: BindModeSetnsTCP requires NetNSPath")
			}
		}
	case BindModeBridgeGateway:
		// BridgeGateway binds on a non-loopback host-side IP the
		// backend reports. Empty address is rejected because the
		// supervisor MUST plumb the gateway IP — defaulting to
		// loopback here would silently make the listener unreachable
		// from inside the sandbox.
		if addr == "" {
			return nil, errors.New("secrets: ProviderProxy: BindModeBridgeGateway requires ListenAddr")
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("secrets: ProviderProxy: invalid ListenAddr %q for BindModeBridgeGateway: %w", addr, err)
		}
	case BindModeUnixSocket:
		if unixSocketPath == "" {
			return nil, errors.New("secrets: ProviderProxy: BindModeUnixSocket requires UnixSocketPath")
		}
		// ListenAddr ignored in this mode; do not validate.
	default:
		return nil, fmt.Errorf("secrets: ProviderProxy: unknown BindMode %q", string(bindMode))
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
		bindMode:        bindMode,
		netNSPath:       netNSPath,
		netNSEnter:      opts.NetNSEnter,
		unixSocketPath:  unixSocketPath,
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
		ln, urlStr, err := p.bindListener()
		if err != nil {
			startErr = err
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
		p.url = urlStr
		p.mu.Unlock()

		p.logf("provider_proxy: started provider=%s url=%s upstream=%s mode=%s",
			p.provider, p.url, p.upstreamHost, p.bindMode)

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

// bindListener performs the per-BindMode listener bind. Returns the
// bound listener and the URL the supervisor should expose to the
// agent. Errors are wrapped with the bind mode so a supervisor that
// surfaces them through lifecycle.jsonl can attribute the failure to
// the right step.
//
// SetnsTCP wraps the bind in NetNSEnter so the TCP listener pins to
// loopback inside the target netns. BridgeGateway and Loopback bind
// directly in the host netns. UnixSocket binds a stream socket at
// UnixSocketPath.
func (p *ProviderProxy) bindListener() (net.Listener, string, error) {
	switch p.bindMode {
	case BindModeUnixSocket:
		// Remove any stale socket from a previous run so re-binding
		// the same path does not fail with EADDRINUSE. The plan's
		// per-run lifecycle pins the path inside <runDir>/ipc; an
		// orphan there can only come from a crashed predecessor.
		_ = os.Remove(p.unixSocketPath)
		ln, err := net.Listen("unix", p.unixSocketPath)
		if err != nil {
			return nil, "", fmt.Errorf("secrets: ProviderProxy listen unix %s: %w", p.unixSocketPath, err)
		}
		return ln, "http+unix://" + p.unixSocketPath, nil

	case BindModeSetnsTCP:
		if p.netNSEnter == nil {
			return nil, "", fmt.Errorf("secrets: ProviderProxy: BindModeSetnsTCP requires NetNSEnter (path=%s)", p.netNSPath)
		}
		bind := func() (net.Listener, error) {
			return net.Listen("tcp", p.listenAddr)
		}
		ln, err := p.netNSEnter(p.netNSPath, bind)
		if err != nil {
			return nil, "", fmt.Errorf("secrets: ProviderProxy listen tcp (setns netns=%s addr=%s): %w",
				p.netNSPath, p.listenAddr, err)
		}
		if ln == nil {
			return nil, "", fmt.Errorf("secrets: ProviderProxy: NetNSEnter returned nil listener (netns=%s)", p.netNSPath)
		}
		return ln, "http://" + ln.Addr().String(), nil

	case BindModeBridgeGateway, BindModeLoopback:
		ln, err := net.Listen("tcp", p.listenAddr)
		if err != nil {
			return nil, "", fmt.Errorf("secrets: ProviderProxy listen tcp %s (mode=%s): %w",
				p.listenAddr, p.bindMode, err)
		}
		return ln, "http://" + ln.Addr().String(), nil

	default:
		return nil, "", fmt.Errorf("secrets: ProviderProxy: unknown BindMode %q", string(p.bindMode))
	}
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

		// Unix-socket bind: remove the socket node from disk so a
		// subsequent run does not collide on the same path. The path
		// is supervisor-owned (inside <runDir>/ipc) so the cleanup is
		// safe even when the run is torn down out from under the
		// proxy.
		if p.bindMode == BindModeUnixSocket && p.unixSocketPath != "" {
			_ = os.Remove(p.unixSocketPath)
		}

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

// BindMode reports the reachability mode the listener bound in. The
// supervisor (Plan §5.5 step 8) records this in the
// proxy_started lifecycle verb's Metadata under the
// "reachability" key.
func (p *ProviderProxy) BindMode() BindMode {
	return p.bindMode
}

// ListenAddr returns the host:port the proxy bound (for TCP modes) or
// the unix-socket path (for BindModeUnixSocket). The supervisor uses
// this to populate the proxy_started verb's "listen_addr" metadata
// field. Returns the empty string before Start succeeds.
func (p *ProviderProxy) ListenAddr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return ""
	}
	if p.bindMode == BindModeUnixSocket {
		return p.unixSocketPath
	}
	return p.listener.Addr().String()
}

// newReverseProxy builds the httputil.ReverseProxy that handles every
// inbound request. The Director rewrites the request to target the
// configured upstream host + scheme, strips inbound auth headers, and
// installs the host-side credential. The ErrorHandler emits a redacted
// log line and returns a small JSON-shaped error so the agent sees a
// well-formed response on upstream failure.
//
// The returned http.Handler wraps the reverse proxy in an
// upstream-Host allowlist check so a request whose inbound Host /
// target URL points at a different provider's API (or any other host)
// is rejected with 403 before the request can be rewritten and
// dispatched. This is the "Defeats open relay" rule from Plan
// Batch 2.2: the proxy fronts exactly one provider; a Host header that
// points elsewhere is a misuse signal, not a silent-rewrite request.
func (p *ProviderProxy) newReverseProxy() http.Handler {
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.inboundHostAllowed(r) {
			p.logf("provider_proxy: forbidden host=%s path=%s upstream=%s",
				RedactSecrets(r.Host), RedactSecrets(r.URL.Path), p.upstreamHost)
			http.Error(w, "forbidden upstream host", http.StatusForbidden)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// inboundHostAllowed enforces the upstream-Host allowlist on the
// inbound request. A request is allowed when its Host header / URL.Host
// is one of:
//
//   - the proxy's own bind address (the typical case: agent dials
//     127.0.0.1:<port> with the loopback URL the supervisor injected
//     via ANTHROPIC_BASE_URL / OPENAI_BASE_URL);
//   - the configured upstream canonical host (api.anthropic.com /
//     api.openai.com — the case where the agent constructs a full URL
//     pointing at the provider's documented endpoint);
//   - an empty Host (HTTP/1.0 client without Host header — accepted
//     because the director rewrites the host to the canonical upstream
//     anyway, so the request is fully attributable on the host side).
//
// Any other Host is rejected with 403 in newReverseProxy. The check
// runs BEFORE the director so a forbidden Host never reaches the
// upstream-rewrite step where it would be silently masked.
func (p *ProviderProxy) inboundHostAllowed(r *http.Request) bool {
	host := strings.TrimSpace(r.Host)
	if host == "" && r.URL != nil {
		host = strings.TrimSpace(r.URL.Host)
	}
	if host == "" {
		return true
	}
	if strings.EqualFold(host, p.upstreamHost) {
		return true
	}
	// Loopback / bind-address pass: split off the port and check the
	// host portion against the configured listen address. For
	// SetnsTCP / Loopback the proxy binds 127.0.0.1:<port>; the agent
	// dials that exact address. For BridgeGateway the gateway IP is
	// the bound host. For UnixSocket the inbound Host is the
	// socket-path-derived sentinel HTTP clients use; we tolerate any
	// host in that mode (the socket itself is the auth surface).
	if p.bindMode == BindModeUnixSocket {
		return true
	}
	hostOnly, _, splitErr := net.SplitHostPort(host)
	if splitErr != nil {
		hostOnly = host
	}
	// Compare against the bound listener's address when available so
	// a SetnsTCP-mode proxy that the OS bound to an ephemeral port is
	// recognized verbatim.
	p.mu.Lock()
	bound := p.listener
	p.mu.Unlock()
	if bound != nil {
		boundHost, _, lerr := net.SplitHostPort(bound.Addr().String())
		if lerr == nil && strings.EqualFold(hostOnly, boundHost) {
			return true
		}
	}
	// Generic loopback acceptance (covers tests that dial via
	// proxy.URL() before the listener address is interrogated, and
	// covers IPv6 loopback notation).
	if isLoopbackHost(hostOnly) {
		return true
	}
	return false
}

// isLoopbackHost reports whether the given hostname / IP literal is
// the loopback interface. Mirrors the validateLoopbackAddr accept
// list so the allowlist and the bind-time validator agree on what
// "loopback" means.
func isLoopbackHost(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
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
// preferable to leaking a real token.
//
// The set is intentionally a mirror of `internal/scanners`.builtinPatterns()
// (kept inlined rather than imported so the secrets package stays a leaf
// of the dependency graph — every other package that wants self-redaction
// can call RedactSecrets without dragging the scanner registry along).
// Whenever scanners.builtinPatterns() grows a new provider rule, this
// list must grow the same rule; the Batch 0.2 acceptance covers the
// parity case.
//
// Patterns covered (per Plan §0.2):
//
//   - Anthropic API keys (sk-ant-...).
//   - OpenAI / generic sk- keys (including sk-proj-).
//   - GitHub tokens: ghp_, gho_, ghs_, github_pat_.
//   - npm tokens (npm_).
//   - PyPI tokens (pypi-AgEIcHlwaS5vcmc...).
//   - AWS access key IDs (AKIA / ASIA).
//   - Google Cloud API keys (AIza...).
//   - Azure storage account keys (AccountKey=...).
//   - Slack tokens (xox[abprs]-...).
//   - Stripe keys (sk|rk|pk_(live|test)_...).
//   - PEM private-key headers (RSA / EC / OPENSSH / DSA / PGP / generic).
//   - .env-style "<KEY>=<value>" assignments where <KEY> ends in
//     _SECRET / _TOKEN / _KEY / _API_KEY / _PASSWORD, plus a bare
//     PASSWORD= form.
//   - Authorization: Bearer <token> headers (header + value redacted).
//   - x-api-key: <token> headers (header + value redacted).
//
// SSH key blobs are folded into the PEM header rules (the "BEGIN
// OPENSSH PRIVATE KEY" / "BEGIN RSA PRIVATE KEY" headers are the
// canonical leading bytes of any leaked key blob; the body that
// follows is base64 and would re-match the entropy analyzer in the
// scanner package, which is out of scope for the proxy).
//
// The redaction replaces the matched substring with "REDACTED" so the
// surrounding log line stays grep-friendly while the secret is gone.
var secretPatterns = []*regexp.Regexp{
	// --- provider API keys (mirror scanners.builtinPatterns) -----------
	// Anthropic keys (longer prefix matched first so the generic sk-
	// rule below does not partial-match).
	regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}`),
	// OpenAI / generic sk- keys (including sk-proj-).
	regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9]{20,}`),
	// GitHub personal access tokens.
	regexp.MustCompile(`\bghp_[A-Za-z0-9]{30,}`),
	// GitHub fine-grained PATs.
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
	// GitHub OAuth tokens.
	regexp.MustCompile(`\bgho_[A-Za-z0-9]{30,}`),
	// GitHub server tokens.
	regexp.MustCompile(`\bghs_[A-Za-z0-9]{30,}`),
	// npm tokens.
	regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}`),
	// PyPI tokens.
	regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}`),
	// AWS access key IDs (long-lived).
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	// AWS temporary access key IDs.
	regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`),
	// Google Cloud API keys.
	regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
	// Azure storage AccountKey assignments. Match the conventional
	// AccountKey=<b64> prefix to avoid false positives on bare base64.
	regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+/]{60,}={0,2}`),
	// Slack tokens.
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9\-]{10,}`),
	// Stripe live / test keys.
	regexp.MustCompile(`\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}`),

	// --- private key headers ------------------------------------------
	regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
	regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
	regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),

	// --- .env-style assignments ---------------------------------------
	// "<KEY>=<value>" where <KEY> ends in _SECRET / _TOKEN / _KEY /
	// _API_KEY / _PASSWORD. Value must be at least 8 non-whitespace
	// chars so empty / obvious-placeholder lines do not trip the rule.
	regexp.MustCompile(
		`(?i)\b[A-Z][A-Z0-9_]*(?:_SECRET|_TOKEN|_KEY|_API_KEY|_PASSWORD)\s*[:=]\s*["']?[^\s"'#]{8,}["']?`,
	),
	// Bare PASSWORD=... assignment.
	regexp.MustCompile(
		`(?i)\bPASSWORD\s*[:=]\s*["']?[^\s"'#]{8,}["']?`,
	),

	// --- auth headers -------------------------------------------------
	// Authorization: Bearer <token>. The capture replaces the whole
	// header including the value so a header echoed back into a log
	// line is gone in one pass.
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
