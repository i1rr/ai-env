// Control socket (Plan 0.0, this plan's "Leak-coverage hardening" §0).
//
// The control socket is the single in-process RPC point the supervisor
// exposes to in-sandbox helper processes (the shell shim under Bucket 1,
// the MCP gateway helper under Bucket 4, the transcript turn-id minter
// under Bucket 8). It speaks newline-delimited JSON-RPC over a per-run
// AF_UNIX listener bound at "<runDir>/control.sock", mode 0600, chown'd
// to the in-sandbox `EnvSpec.UID` so the agent's process (which runs as
// the same UID) can connect, but no other user on the host can.
//
// This file is the canonical owner of the wire surface enumerated in
// the plan's "Batch 0.0 — Control socket" entry:
//
//   - Start(ctx) / Stop() / Path()
//   - AcceptingShutdown() — flips the gate; all NEW RPCs after this
//     return decision="block", reason="shutdown".
//   - Hello(control_token, client_version, protocol_version) — closes
//     the connection on missing/wrong token OR version mismatch.
//   - BeginTurn(control_token, role), CurrentTurn(control_token)
//   - EvaluateShellCommand(control_token, argv)
//   - AuthorizeMCPCall(control_token, server_token, server, op, body)
//
// Design rules:
//
//  1. Fail closed. The control_token check is the first thing every
//     method does. A missing or wrong token closes the connection
//     immediately (the helper has no way to retry on the same conn).
//     Constant-time comparison is used so a wrong-token attacker cannot
//     learn the prefix by timing.
//
//  2. Shutdown is a one-way gate. AcceptingShutdown() can be called at
//     most once; thereafter every NEW RPC (including ones from a
//     freshly-arriving conn) is answered with decision="block",
//     reason="shutdown" before the per-method handler runs. In-flight
//     RPCs continue; the gate matters for the "drain ≤2s" step in the
//     supervisor teardown sequence (Batch 5.5 step 2).
//
//  3. Per-server tokens are scoped. AuthorizeMCPCall verifies the
//     (server_token, server) pair against the per-run registry: an
//     attacker who learned one server's token cannot pivot to another
//     server's name. The token comparison is constant-time.
//
//  4. Handlers are pluggable. The supervisor wires concrete
//     EvaluateShellCommand / AuthorizeMCPCall handlers in via the
//     ControlSocketOptions; this file owns the framing, locking, and
//     token plumbing but stays free of policy/scope semantics so the
//     run package does not need to import internal/policy or
//     internal/mcp at construction time. Nil handlers degrade to a
//     deny: a helper that asks before the supervisor wires the
//     concrete handler in gets "no handler configured" rather than a
//     silent allow.
//
//  5. Turn IDs are supervisor-minted. BeginTurn allocates a new
//     monotonically-increasing ID per role (one counter per role
//     name); CurrentTurn returns the most recent ID for the requested
//     role (or "" when no turn has started). This is the authoritative
//     correlation key the transcript writer (Bucket 8) joins on. The
//     plan documents the best-effort nature: a compromised agent can
//     delay or skip BeginTurn — the supervisor cannot enforce ordering
//     from outside the sandbox.
//
//  6. The socket file is the only thing exposed to the agent. The
//     primary control_token is NOT in the agent's env or in
//     mcp-servers.json (Plan's Bucket 4 locked decision); helper
//     processes receive it via a side-band file in
//     <runDir>/ipc/.helper-token that the agent cannot read (different
//     UID). This file enforces that boundary by closing any conn that
//     does not present the primary token on Hello.
package run

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// controlSocketFileName is the basename of the per-run control socket.
// The supervisor binds this file inside <runDir>; helpers running in
// the sandbox reach it via the bind-mount at /var/run/ai-env/ (see
// Batch 0.5's mount split: control.sock lives in <runDir>/ipc/).
const controlSocketFileName = "control.sock"

// controlSocketProtocolVersion is the wire-protocol version the
// supervisor speaks. A helper that presents a different version on
// Hello is closed immediately. We bump this when the on-wire frame
// shape changes; new RPCs alone (added to an existing major) do not
// bump it because unknown methods are already rejected per-call.
const controlSocketProtocolVersion = 1

// controlTokenBytes is the entropy of the primary control_token. The
// plan specifies "32 random b64 bytes"; we read 32 random bytes from
// crypto/rand and base64-encode them, producing a 44-character token
// (43 chars + "=" pad). 32 bytes is 256 bits, comfortably above the
// brute-force threshold even against an attacker with billions of
// guesses per second.
const controlTokenBytes = 32

// controlServerTokenBytes is the entropy of each per-server token
// (the AI_ENV_MCP_SERVER_TOKEN values surfaced to the agent CLI
// through mcp-servers.json). 32 bytes matches the primary token; the
// per-server tokens are agent-visible by design (the agent CLI passes
// them through to the helper as env), so the only adversary that
// matters here is the network, and 256 bits is plenty.
const controlServerTokenBytes = 32

// ControlSocketResponse is the canonical shape of every RPC response.
// Pinned here so the wire format is the single source of truth across
// every method handler. The plan describes responses as
// `decision=block, reason=shutdown` (for the post-shutdown path) and
// the EvaluateShellCommand / AuthorizeMCPCall verdicts as
// allow/warn/block triples; we encode that as Decision + Reason plus
// per-method Data the handler fills in.
//
// Fields are ordered to keep the JSON encoding stable (json.Marshal
// honors struct field order): Decision first so a reader that only
// looks at the top of the line sees the verdict immediately.
type ControlSocketResponse struct {
	// Decision is the verdict token. One of "allow", "warn", "block".
	// The plan's wire surface uses "block" (not "deny") so a downstream
	// consumer reading wire frames sees the same word the shutdown
	// path uses; the policy engine's PolicyDecision.Type is mapped to
	// this set by the handler bridge ("deny" → "block").
	Decision string `json:"decision"`

	// Reason is the human-readable explanation. Required on every
	// non-allow verdict; the shutdown path sets it to "shutdown".
	Reason string `json:"reason,omitempty"`

	// TurnID is populated by BeginTurn / CurrentTurn responses. Other
	// handlers leave it empty.
	TurnID string `json:"turn_id,omitempty"`

	// EventID echoes the policy engine's PolicyDecision.EventID when
	// the handler routed through the engine. Empty otherwise.
	EventID string `json:"event_id,omitempty"`

	// Metadata is a free-form bag for per-method context (e.g.
	// EvaluateShellCommand surfaces the matched pattern name).
	// Optional.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// controlSocketRequest is the on-wire request envelope. Pinned here
// so every handler decodes the same shape; method-specific parameters
// live in Params which the handler decodes into its own struct.
type controlSocketRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// helloParams is the Hello method payload. The plan requires the
// helper to present the primary control_token, its own client
// version (informational; not enforced), and the protocol_version
// (enforced against controlSocketProtocolVersion).
type helloParams struct {
	ControlToken    string `json:"control_token"`
	ClientVersion   string `json:"client_version"`
	ProtocolVersion int    `json:"protocol_version"`
}

// beginTurnParams is the BeginTurn method payload. Role tags the
// turn family so a future correlation join (transcript writer)
// can distinguish e.g. "agent" turns from "subagent" turns.
type beginTurnParams struct {
	ControlToken string `json:"control_token"`
	Role         string `json:"role"`
}

// currentTurnParams is the CurrentTurn method payload. Same role
// scoping as BeginTurn.
type currentTurnParams struct {
	ControlToken string `json:"control_token"`
	Role         string `json:"role"`
}

// evaluateShellCommandParams is the EvaluateShellCommand method
// payload. Argv is the full argument vector the helper is about to
// execve; the supervisor's handler synthesizes a command line from it
// before delegating to the policy engine.
type evaluateShellCommandParams struct {
	ControlToken string   `json:"control_token"`
	Argv         []string `json:"argv"`
	// CmdLine is the helper's verbatim command line as the user
	// typed / the agent emitted it. Optional: when empty, the handler
	// reconstructs from Argv. Surfaced separately because the
	// tokenizer (Batch 1.1) wants the original to match deny patterns
	// against quoted strings exactly.
	CmdLine string `json:"cmd_line,omitempty"`
}

// authorizeMCPCallParams is the AuthorizeMCPCall method payload. The
// per-server token is presented alongside the primary control_token
// so the supervisor can verify (server_token, server) scoping in
// constant time without consulting the policy engine.
type authorizeMCPCallParams struct {
	ControlToken string          `json:"control_token"`
	ServerToken  string          `json:"server_token"`
	Server       string          `json:"server"`
	Operation    string          `json:"op"`
	Body         json.RawMessage `json:"body,omitempty"`
}

// ShellEvaluator is the supervisor-supplied handler for
// EvaluateShellCommand. The control socket owns the framing, locking,
// and token verification; this interface is the policy bridge.
//
// A nil ShellEvaluator (the default when the supervisor has not yet
// wired one in) makes EvaluateShellCommand return decision="block",
// reason="no handler configured". This is fail-closed: a helper that
// asks before the wiring is complete is denied rather than allowed.
type ShellEvaluator interface {
	// Evaluate returns a verdict for the given argv / cmdLine. The
	// returned decision must be one of "allow", "warn", "block". The
	// implementation is responsible for recording the decision in
	// policy-decisions.jsonl (the supervisor's EvaluateShellCommand
	// already does this); the control socket does not record on its
	// own to avoid double-logging.
	Evaluate(cmdLine string, argv []string) ControlSocketResponse
}

// MCPAuthorizer is the supervisor-supplied handler for
// AuthorizeMCPCall. The control socket has already verified the
// (server_token, server) pair before calling Authorize; the
// implementation just needs to apply scope/secret rules on the
// op + body and return the verdict.
//
// A nil MCPAuthorizer (the default when the supervisor has not yet
// wired one in) makes AuthorizeMCPCall return decision="block",
// reason="no handler configured", same fail-closed reasoning as
// ShellEvaluator.
type MCPAuthorizer interface {
	// Authorize returns a verdict for the given (server, op, body)
	// triple. The implementation must not re-check the token (the
	// control socket already did) and is responsible for recording
	// the decision in mcp-calls.jsonl.
	Authorize(server, op string, body []byte) ControlSocketResponse
}

// ShellEvaluatorFunc is a function adapter so callers can pass a
// closure where a ShellEvaluator is required (mirrors http.HandlerFunc).
type ShellEvaluatorFunc func(cmdLine string, argv []string) ControlSocketResponse

// Evaluate implements ShellEvaluator by forwarding to the underlying
// function.
func (f ShellEvaluatorFunc) Evaluate(cmdLine string, argv []string) ControlSocketResponse {
	return f(cmdLine, argv)
}

// MCPAuthorizerFunc is a function adapter so callers can pass a
// closure where an MCPAuthorizer is required.
type MCPAuthorizerFunc func(server, op string, body []byte) ControlSocketResponse

// Authorize implements MCPAuthorizer by forwarding to the underlying
// function.
func (f MCPAuthorizerFunc) Authorize(server, op string, body []byte) ControlSocketResponse {
	return f(server, op, body)
}

// ControlSocketOptions bundles every per-run knob the ControlSocket
// constructor needs. RunDir is the per-run directory the socket file
// lives inside; SocketUID is the in-sandbox UID we chown the socket
// to so the agent (which runs as that UID) can connect.
//
// PrimaryToken is the 32-byte primary control_token. The supervisor
// generates this at startup (step 2 in the canonical sequence) and
// passes it here; the same token is delivered to helper processes
// via the side-band <runDir>/ipc/.helper-token file (see Batch 0.5).
// Optional: when empty, NewControlSocket mints one via crypto/rand.
//
// ShellEvaluator and MCPAuthorizer are the policy bridges; see the
// interface docs above for the fail-closed default behavior.
//
// Logf is the optional structured logger the socket uses for
// in-band diagnostics (handshake failures, malformed frames). Nil
// silences logging; production wiring routes this to the supervisor's
// stderr.
type ControlSocketOptions struct {
	RunDir         string
	SocketUID      *int
	PrimaryToken   string
	ShellEvaluator ShellEvaluator
	MCPAuthorizer  MCPAuthorizer
	Logf           func(format string, args ...any)
}

// ControlSocket is the per-run JSON-RPC server. One instance per run;
// the supervisor constructs it at step 2 of the pre-launch sequence
// and stops it at step 8 of the teardown sequence. All exported
// methods are safe for concurrent use.
//
// The wire format is line-delimited JSON: each request is a single
// JSON object terminated by exactly one newline byte; each response
// is the same. We use bufio.Scanner with a generous buffer (the
// AuthorizeMCPCall body can be large) and json.NewEncoder for
// responses; one frame per encode call keeps the on-wire stream
// parseable by a streaming reader.
type ControlSocket struct {
	// opts carries the construction-time knobs; we keep a copy so
	// the handler methods can reach them without threading them
	// through every call.
	opts ControlSocketOptions

	// path is the absolute socket-file path. Cached so Path() does
	// not have to rebuild the join on every call.
	path string

	// primaryToken is the primary control_token (b64-encoded). The
	// constructor either copies opts.PrimaryToken or mints a fresh
	// one; in both cases this field is the single source of truth
	// for the Hello / per-method token check.
	primaryToken string

	// listener is the AF_UNIX listener. Created at Start, closed at
	// Stop. Nil before Start and after Stop.
	listener *net.UnixListener

	// wg tracks every per-conn handler goroutine so Stop can wait
	// for the in-flight ones to drain after the listener is closed.
	wg sync.WaitGroup

	// stopCh is closed by Stop to signal the ctx-watcher goroutine
	// to exit even when the parent ctx is still live. Without this,
	// a test that calls Stop without cancelling the ctx would
	// deadlock on the wg.Wait below (the watcher would never return).
	stopCh chan struct{}

	// shutdownGate is the post-AcceptingShutdown gate. Once flipped
	// to 1, every NEW RPC returns decision="block",
	// reason="shutdown" before the per-method handler runs. Atomic
	// so the gate check on the request path stays lock-free.
	shutdownGate atomic.Bool

	// serverTokensMu guards serverTokens. The supervisor calls
	// RegisterServerToken from a single setup goroutine in
	// production, but the read path is the AuthorizeMCPCall handler
	// which runs from per-conn goroutines, so the mutex is required.
	serverTokensMu sync.RWMutex

	// serverTokens maps server name → server token. AuthorizeMCPCall
	// looks the entry up by server name and constant-time compares
	// the supplied token against the registered one. An unknown
	// server name is rejected before the token compare so the
	// timing of "unknown server" vs "wrong token" is distinguishable
	// (intentional: the agent CLI legitimately needs to know whether
	// the server name is wrong vs whether its token is stale).
	serverTokens map[string]string

	// turnsMu guards turnCounter and currentTurns.
	turnsMu sync.Mutex

	// turnCounter is the monotonic per-role counter that BeginTurn
	// advances on every call. Per-role isolation is intentional: a
	// future "agent" + "subagent" pair can each have their own
	// sequence without colliding.
	turnCounter map[string]int

	// currentTurns maps role → most recently allocated turn ID.
	// CurrentTurn returns the entry; an empty role / unknown role
	// returns "".
	currentTurns map[string]string
}

// NewControlSocket constructs a ControlSocket bound to the supplied
// options. The constructor:
//
//   - Validates opts.RunDir is non-empty (a relative or empty path
//     would silently bind in the process's cwd, which is a
//     supervisor bug).
//   - Resolves opts.PrimaryToken (if empty, mints a fresh 32-byte
//     b64 token via crypto/rand).
//   - Initializes the per-server-token registry and the turn-id
//     counters.
//
// The listener is NOT created here; Start does that. Splitting
// construction from listen makes the supervisor's lifecycle simpler:
// it can construct the socket, register server tokens, then Start
// when the runDir is ready to host the socket file.
func NewControlSocket(opts ControlSocketOptions) (*ControlSocket, error) {
	if opts.RunDir == "" {
		return nil, errors.New("run: NewControlSocket requires RunDir")
	}

	token := opts.PrimaryToken
	if token == "" {
		minted, err := mintControlToken()
		if err != nil {
			return nil, fmt.Errorf("run: mint primary control_token: %w", err)
		}
		token = minted
	}

	return &ControlSocket{
		opts:         opts,
		path:         filepath.Join(opts.RunDir, controlSocketFileName),
		primaryToken: token,
		serverTokens: make(map[string]string),
		turnCounter:  make(map[string]int),
		currentTurns: make(map[string]string),
		stopCh:       make(chan struct{}),
	}, nil
}

// Path returns the absolute path of the socket file. The supervisor
// passes this into the env-spec builder so the bind-mount step (Batch
// 0.5) maps it into the sandbox at /var/run/ai-env/control.sock.
func (s *ControlSocket) Path() string {
	return s.path
}

// PrimaryToken returns the primary control_token. The supervisor
// uses this to write <runDir>/ipc/.helper-token (Batch 0.5) so
// helper processes can authenticate on Hello. It is NEVER written
// to the agent's env nor to mcp-servers.json — see the package doc
// for the side-band delivery rationale.
func (s *ControlSocket) PrimaryToken() string {
	return s.primaryToken
}

// RegisterServerToken records a per-server token for the named MCP
// server. The supervisor calls this once per registered server at
// step 9 of the pre-launch sequence; AuthorizeMCPCall then verifies
// (server_token, server) pairs against the registry.
//
// Each call OVERWRITES a previous entry for the same server name; in
// practice the supervisor only registers each server once per run
// (the runtime registry is built deterministically from the
// run-config), so the overwrite path is purely defensive.
//
// Returns an error when server is empty or token is empty: a
// registration with an empty field is a supervisor bug and we surface
// it rather than silently producing a record that can never match.
func (s *ControlSocket) RegisterServerToken(server, token string) error {
	if server == "" {
		return errors.New("run: RegisterServerToken requires server name")
	}
	if token == "" {
		return errors.New("run: RegisterServerToken requires token")
	}
	s.serverTokensMu.Lock()
	defer s.serverTokensMu.Unlock()
	s.serverTokens[server] = token
	return nil
}

// MintServerToken generates a fresh per-server token, registers it
// under the supplied server name, and returns the token. The
// supervisor uses this when building mcp-servers.json: it mints one
// token per server, embeds the token in the per-server config block
// (visible to the agent CLI), and the helper process presents the
// same token on AuthorizeMCPCall.
//
// Returns an error only when crypto/rand fails (effectively never)
// or when server is empty.
func (s *ControlSocket) MintServerToken(server string) (string, error) {
	if server == "" {
		return "", errors.New("run: MintServerToken requires server name")
	}
	tok, err := mintServerToken()
	if err != nil {
		return "", fmt.Errorf("run: mint server token: %w", err)
	}
	if err := s.RegisterServerToken(server, tok); err != nil {
		return "", err
	}
	return tok, nil
}

// Start creates the AF_UNIX listener, chmods the socket file to
// 0600, optionally chowns it to opts.SocketUID, and spawns the
// accept goroutine. Returns an error when the socket file already
// exists (a stale file from a crashed previous run would silently
// shadow our bind on POSIX; we surface that rather than overwrite),
// when the listen syscall fails, when chmod fails, or when chown
// fails.
//
// The ctx is used to cancel the accept loop: when ctx is done the
// listener is closed and accept returns. The supervisor passes its
// run-scoped context so a parent cancellation stops the socket
// alongside everything else.
func (s *ControlSocket) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("run: ControlSocket.Start requires non-nil ctx")
	}
	if s.listener != nil {
		return errors.New("run: ControlSocket already started")
	}

	// Stale socket files are a footgun: a previous run that crashed
	// before Stop leaves <runDir>/control.sock behind, and a bare
	// net.Listen would fail with EADDRINUSE. We tolerate that case
	// by removing the stale file iff it is a socket; any other file
	// type (regular file, dir, symlink) is a sign of corruption and
	// surfaces as a listen error rather than silent overwrite.
	if info, err := os.Lstat(s.path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("run: control socket path %s exists and is not a socket (mode=%v)", s.path, info.Mode())
		}
		if rmErr := os.Remove(s.path); rmErr != nil {
			return fmt.Errorf("run: remove stale control socket %s: %w", s.path, rmErr)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("run: stat control socket %s: %w", s.path, err)
	}

	addr, err := net.ResolveUnixAddr("unix", s.path)
	if err != nil {
		return fmt.Errorf("run: resolve control socket %s: %w", s.path, err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("run: listen control socket %s: %w", s.path, err)
	}

	// Mode 0600 so only the owning UID can connect, mirroring the
	// plan's "mode 0600, chown'd to EnvSpec.UID" requirement. We
	// chmod before chown so the post-chown permission check sees
	// the final mode; the order matters on systems where the chown
	// would otherwise clear suid bits (irrelevant here but the
	// canonical order regardless).
	if err := os.Chmod(s.path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(s.path)
		return fmt.Errorf("run: chmod control socket %s: %w", s.path, err)
	}
	if s.opts.SocketUID != nil {
		if err := os.Chown(s.path, *s.opts.SocketUID, -1); err != nil {
			_ = ln.Close()
			_ = os.Remove(s.path)
			return fmt.Errorf("run: chown control socket %s to uid %d: %w", s.path, *s.opts.SocketUID, err)
		}
	}

	s.listener = ln

	// Wire the listener's Close to ctx cancellation OR Stop. An
	// upstream ctx cancel stops the accept loop; Stop closes stopCh
	// so the watcher exits even if the ctx is still live. Without
	// the stopCh branch, a caller that Stops without cancelling
	// would deadlock on Stop's wg.Wait waiting for this goroutine
	// to return.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case <-ctx.Done():
		case <-s.stopCh:
		}
		// Best-effort close; Stop() also closes the listener so
		// double-close is possible — net.Listener.Close is documented
		// to return an error on double-close which we swallow here.
		_ = ln.Close()
	}()

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// AcceptingShutdown flips the shutdown gate. After this call every
// NEW RPC returns decision="block", reason="shutdown" before the
// per-method handler runs; in-flight RPCs continue. The plan
// describes this as the entry point of the post-run drain (Batch 5.5
// teardown step 2): the supervisor calls AcceptingShutdown to signal
// "no new work", waits ≤2s for in-flight RPCs to drain, then calls
// Stop().
//
// Idempotent: calling twice is a no-op.
func (s *ControlSocket) AcceptingShutdown() {
	s.shutdownGate.Store(true)
}

// Stop closes the listener (which makes the accept loop exit with
// ErrClosed), waits for every in-flight handler goroutine to drain,
// and removes the socket file. Safe to call without a prior Start
// (no-op). Safe to call multiple times (second call is a no-op).
//
// Stop deliberately does NOT flip AcceptingShutdown: the supervisor
// calls AcceptingShutdown first so in-flight RPCs see "block,
// shutdown" before being torn down, then calls Stop after drain.
// Stopping without an earlier AcceptingShutdown is supported (test
// fixtures use it) and just collapses to "close immediately".
func (s *ControlSocket) Stop() error {
	if s.listener == nil {
		// Either Start was never called or Stop was already called.
		// In either case we attempt to remove the socket file (in
		// case Start failed mid-chmod) and return.
		_ = os.Remove(s.path)
		return nil
	}

	// Signal the ctx-watcher goroutine to exit if it has not
	// already. We guard against double-close because Stop may be
	// called twice (second time is a no-op): use a select on send-
	// like semantics by checking listener was non-nil above.
	select {
	case <-s.stopCh:
		// Already closed by a previous Stop or a concurrent path;
		// nothing more to do.
	default:
		close(s.stopCh)
	}

	// Close the listener; this unblocks the accept loop. The
	// per-conn goroutines may still be servicing in-flight requests;
	// wg.Wait below catches them.
	closeErr := s.listener.Close()
	s.listener = nil

	s.wg.Wait()

	if rmErr := os.Remove(s.path); rmErr != nil && !os.IsNotExist(rmErr) {
		if closeErr != nil {
			return fmt.Errorf("run: stop control socket: %w (remove also failed: %v)", closeErr, rmErr)
		}
		return fmt.Errorf("run: remove control socket %s: %w", s.path, rmErr)
	}
	if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return fmt.Errorf("run: close control socket: %w", closeErr)
	}
	return nil
}

// acceptLoop is the per-listener accept goroutine. Every accepted
// connection is handed off to a per-conn goroutine; the loop exits
// when the listener is closed (ErrClosed).
func (s *ControlSocket) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient accept errors (file descriptor exhaustion,
			// etc.) are logged and the loop continues. We do not exit
			// on transient errors because the listener is still
			// valid; logging surfaces the issue to the operator.
			s.logf("run: control socket accept error: %v", err)
			continue
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// handleConn services one connection. The protocol is a sequence of
// JSON-RPC frames: each request is one JSON object + newline; each
// response is one JSON object + newline. The Hello handshake must be
// the first frame; subsequent frames may be any of the documented
// methods.
//
// The connection is closed on:
//   - Hello with a missing/wrong control_token (per plan)
//   - Hello with a protocol_version mismatch (per plan)
//   - Any non-Hello frame before Hello succeeds
//   - EOF or a transport error
//   - Decoder error (a malformed frame would otherwise leave the
//     stream offset out of sync; we close rather than try to
//     resync).
func (s *ControlSocket) handleConn(conn *net.UnixConn) {
	defer s.wg.Done()
	defer conn.Close()

	br := bufio.NewReaderSize(conn, 1<<16)
	enc := json.NewEncoder(conn)

	// Each connection is a sequential request-response stream. We
	// expect Hello first; anything else closes the conn.
	helloDone := false

	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				s.logf("run: control socket read error: %v", err)
			}
			return
		}
		if len(line) == 0 || (len(line) == 1 && line[0] == '\n') {
			continue
		}

		var req controlSocketRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.logf("run: control socket frame decode error: %v", err)
			return
		}

		if !helloDone {
			if req.Method != "Hello" {
				s.logf("run: control socket expected Hello as first method, got %q", req.Method)
				return
			}
			if !s.handleHello(req, enc) {
				return
			}
			helloDone = true
			continue
		}

		// Post-Hello: dispatch the method. The shutdown gate is
		// checked here so an in-flight conn that already said Hello
		// still sees "block, shutdown" for every NEW request that
		// arrives after AcceptingShutdown.
		if s.shutdownGate.Load() {
			_ = enc.Encode(ControlSocketResponse{
				Decision: "block",
				Reason:   "shutdown",
			})
			continue
		}

		switch req.Method {
		case "BeginTurn":
			s.handleBeginTurn(req, enc)
		case "CurrentTurn":
			s.handleCurrentTurn(req, enc)
		case "EvaluateShellCommand":
			s.handleEvaluateShellCommand(req, enc)
		case "AuthorizeMCPCall":
			s.handleAuthorizeMCPCall(req, enc)
		default:
			// Unknown method: respond with a block + reason so a
			// future client that probes the surface gets a clear
			// signal rather than a hang. We do not close the conn:
			// a typo on one frame should not kill the whole session.
			_ = enc.Encode(ControlSocketResponse{
				Decision: "block",
				Reason:   fmt.Sprintf("unknown method: %s", req.Method),
			})
		}
	}
}

// handleHello processes the Hello handshake. Returns true on
// success (the connection may continue); returns false on failure
// (the caller closes the connection).
//
// The plan requires Hello to close on missing/wrong token OR version
// mismatch. We send a response on the failure path so a debugging
// client gets a structured signal (rather than just a TCP RST), then
// the caller returns from handleConn which closes the underlying
// FD.
func (s *ControlSocket) handleHello(req controlSocketRequest, enc *json.Encoder) bool {
	var params helloParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "malformed Hello params"})
		return false
	}
	if !constantTimeEqual(params.ControlToken, s.primaryToken) {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "control_token mismatch"})
		return false
	}
	if params.ProtocolVersion != controlSocketProtocolVersion {
		_ = enc.Encode(ControlSocketResponse{
			Decision: "block",
			Reason:   fmt.Sprintf("protocol_version mismatch: got %d, want %d", params.ProtocolVersion, controlSocketProtocolVersion),
		})
		return false
	}
	_ = enc.Encode(ControlSocketResponse{Decision: "allow", Reason: "hello"})
	return true
}

// AllocateTurnID is the in-process counterpart of the RPC BeginTurn
// handler. It mints a fresh monotonic turn id for the given role,
// records it as the role's current turn, and returns it. The
// supervisor uses this when it needs to begin a turn from Go code
// (e.g. the transcript writer's pre-launch wiring) without
// round-tripping through the socket; the RPC handler itself
// (handleBeginTurn) delegates to the same bookkeeping via
// CurrentTurnID for the read side.
//
// An empty role is rewritten to "agent" so the in-process accessor
// agrees with the RPC handler's default role handling
// (handleBeginTurn / handleCurrentTurn).
//
// The method is safe for concurrent use: it takes the same turnsMu
// the RPC handlers do.
func (s *ControlSocket) AllocateTurnID(role string) string {
	if role == "" {
		role = "agent"
	}
	s.turnsMu.Lock()
	defer s.turnsMu.Unlock()
	s.turnCounter[role]++
	n := s.turnCounter[role]
	id := fmt.Sprintf("t-%s-%d", role, n)
	s.currentTurns[role] = id
	return id
}

// CurrentTurnID returns the most recent turn id allocated for the
// given role over the JSON-RPC BeginTurn surface, or the empty string
// when no BeginTurn has been called for that role yet. It is the
// supervisor-side, in-process accessor the Plan Batch 3.3 turn-id
// bridge (cli.MCPCallLogger via cli.TurnSource) consults to stamp
// MCPCallRecord.TurnID without round-tripping through the socket
// itself.
//
// An empty role is rewritten to "agent" so the in-process accessor
// agrees with the RPC handler's default role handling
// (handleBeginTurn / handleCurrentTurn). This keeps the bridge and
// the wire surface returning identical answers for the same caller.
//
// The method is safe for concurrent use: it takes the same turnsMu
// the RPC handlers do.
func (s *ControlSocket) CurrentTurnID(role string) string {
	if role == "" {
		role = "agent"
	}
	s.turnsMu.Lock()
	defer s.turnsMu.Unlock()
	return s.currentTurns[role]
}

// handleBeginTurn allocates a new monotonic turn ID for the given
// role and returns it. The plan does not enforce a particular
// numbering scheme; we use "t-<role>-<n>" so the on-disk transcript
// records carry a self-describing ID.
func (s *ControlSocket) handleBeginTurn(req controlSocketRequest, enc *json.Encoder) {
	var params beginTurnParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "malformed BeginTurn params"})
		return
	}
	if !constantTimeEqual(params.ControlToken, s.primaryToken) {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "control_token mismatch"})
		return
	}
	role := params.Role
	if role == "" {
		role = "agent"
	}
	s.turnsMu.Lock()
	s.turnCounter[role]++
	n := s.turnCounter[role]
	id := fmt.Sprintf("t-%s-%d", role, n)
	s.currentTurns[role] = id
	s.turnsMu.Unlock()
	_ = enc.Encode(ControlSocketResponse{Decision: "allow", TurnID: id})
}

// handleCurrentTurn returns the most recent turn ID for the given
// role. An unknown role returns an empty TurnID with decision=allow
// so a caller probing the surface can distinguish "no turn yet"
// from an error.
func (s *ControlSocket) handleCurrentTurn(req controlSocketRequest, enc *json.Encoder) {
	var params currentTurnParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "malformed CurrentTurn params"})
		return
	}
	if !constantTimeEqual(params.ControlToken, s.primaryToken) {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "control_token mismatch"})
		return
	}
	role := params.Role
	if role == "" {
		role = "agent"
	}
	s.turnsMu.Lock()
	id := s.currentTurns[role]
	s.turnsMu.Unlock()
	_ = enc.Encode(ControlSocketResponse{Decision: "allow", TurnID: id})
}

// handleEvaluateShellCommand delegates to the supervisor-supplied
// ShellEvaluator. A nil evaluator returns decision="block",
// reason="no handler configured" — fail-closed default.
func (s *ControlSocket) handleEvaluateShellCommand(req controlSocketRequest, enc *json.Encoder) {
	var params evaluateShellCommandParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "malformed EvaluateShellCommand params"})
		return
	}
	if !constantTimeEqual(params.ControlToken, s.primaryToken) {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "control_token mismatch"})
		return
	}
	if s.opts.ShellEvaluator == nil {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "no handler configured"})
		return
	}
	resp := s.opts.ShellEvaluator.Evaluate(params.CmdLine, params.Argv)
	if resp.Decision == "" {
		resp.Decision = "block"
		if resp.Reason == "" {
			resp.Reason = "evaluator returned empty decision"
		}
	}
	_ = enc.Encode(resp)
}

// handleAuthorizeMCPCall verifies (server_token, server) in
// constant time, then delegates to the supervisor-supplied
// MCPAuthorizer. The verification order is intentional: an unknown
// server name is rejected with reason="unknown server" before any
// token comparison; a known server with the wrong token is rejected
// with reason="server_token mismatch". The plan's locked decision
// for Bucket 4 calls this out: "unknown server names rejected,
// mismatched tokens rejected".
func (s *ControlSocket) handleAuthorizeMCPCall(req controlSocketRequest, enc *json.Encoder) {
	var params authorizeMCPCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "malformed AuthorizeMCPCall params"})
		return
	}
	if !constantTimeEqual(params.ControlToken, s.primaryToken) {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "control_token mismatch"})
		return
	}
	if params.Server == "" {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "server name required"})
		return
	}

	s.serverTokensMu.RLock()
	registered, known := s.serverTokens[params.Server]
	s.serverTokensMu.RUnlock()

	if !known {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "unknown server"})
		return
	}
	if !constantTimeEqual(params.ServerToken, registered) {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "server_token mismatch"})
		return
	}

	if s.opts.MCPAuthorizer == nil {
		_ = enc.Encode(ControlSocketResponse{Decision: "block", Reason: "no handler configured"})
		return
	}
	resp := s.opts.MCPAuthorizer.Authorize(params.Server, params.Operation, params.Body)
	if resp.Decision == "" {
		resp.Decision = "block"
		if resp.Reason == "" {
			resp.Reason = "authorizer returned empty decision"
		}
	}
	_ = enc.Encode(resp)
}

// logf forwards a formatted message to the supervisor-supplied Logf
// when set; otherwise drops it on the floor. Centralized so handler
// methods do not have to nil-check on every diagnostic.
func (s *ControlSocket) logf(format string, args ...any) {
	if s.opts.Logf != nil {
		s.opts.Logf(format, args...)
	}
}

// constantTimeEqual is a length-safe constant-time comparison. The
// subtle.ConstantTimeCompare contract requires the two slices to be
// the same length; we add the length check ourselves so callers with
// different-length inputs do not have to pre-pad.
//
// Returns false when either input is empty (a missing token is never
// the right token); returns false on length mismatch; otherwise
// delegates to subtle.ConstantTimeCompare.
func constantTimeEqual(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// mintControlToken reads controlTokenBytes random bytes from
// crypto/rand and base64-encodes them. Returns the encoded token or
// an error if the random source fails (effectively never).
func mintControlToken() (string, error) {
	buf := make([]byte, controlTokenBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// mintServerToken mints a per-server token. Same entropy as
// mintControlToken; kept as a separate helper so a future change to
// the per-server token shape (e.g. shorter for the agent-visible
// case) only touches one place.
func mintServerToken() (string, error) {
	buf := make([]byte, controlServerTokenBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}
