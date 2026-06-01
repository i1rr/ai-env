package run

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newControlSocketRunDir is the test-side counterpart to
// newLifecycleRunDir: it builds a real RunDirectory on disk so the
// socket file lives at the same place the supervisor will bind it in
// production. Using CreateRunDirectory keeps the layout honest against
// the rest of the run-package writers' expectations.
//
// We mount the ai-env tree under a short path (/tmp/aies-<random>)
// rather than t.TempDir() because the default test TempDir under
// macOS lives at /var/folders/.../<deep>/<test-name>/00x which
// overshoots the 104-byte AF_UNIX sun_path limit when we append
// "/.ai-env/runs/<run-id>/control.sock". Routing the run directory
// through /tmp keeps the socket path well under the platform limit
// while still exercising the real CreateRunDirectory layout.
func newControlSocketRunDir(t *testing.T) RunDirectory {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "aies-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	aiEnvDir := filepath.Join(base, ".ai-env")
	runID := "20260528-101300-c0c1c2"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return dir
}

// startControlSocket constructs and starts a ControlSocket against
// the supplied run directory. Returns the started socket plus a
// cancel hook the test caller uses to tear everything down. The
// helper centralizes the "open the listener, register the cleanup,
// fail fast on construction errors" boilerplate so each test method
// stays focused on its specific assertions.
func startControlSocket(t *testing.T, dir RunDirectory, opts ControlSocketOptions) (*ControlSocket, context.CancelFunc) {
	t.Helper()
	if opts.RunDir == "" {
		opts.RunDir = dir.Path
	}
	cs, err := NewControlSocket(opts)
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := cs.Start(ctx); err != nil {
		cancel()
		t.Fatalf("ControlSocket.Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cs.Stop()
	})
	return cs, cancel
}

// dialAndHello opens a Unix connection to the control socket, sends
// a Hello with the supplied token + protocol version, and returns
// the connection plus a buffered reader pinned to it. On Hello
// failure the helper closes the connection and reports the response.
// Test methods compose this with subsequent encode/decode calls to
// drive a multi-frame conversation.
func dialAndHello(t *testing.T, cs *ControlSocket, token string, proto int) (*net.UnixConn, *bufio.Reader, ControlSocketResponse) {
	t.Helper()
	addr, err := net.ResolveUnixAddr("unix", cs.Path())
	if err != nil {
		t.Fatalf("ResolveUnixAddr: %v", err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	br := bufio.NewReader(conn)

	enc := json.NewEncoder(conn)
	hello := controlSocketRequest{
		Method: "Hello",
	}
	hello.Params, _ = json.Marshal(helloParams{
		ControlToken:    token,
		ClientVersion:   "test",
		ProtocolVersion: proto,
	})
	if err := enc.Encode(hello); err != nil {
		t.Fatalf("encode Hello: %v", err)
	}
	line, err := br.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read Hello response: %v", err)
	}
	var resp ControlSocketResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode Hello response: %v", err)
	}
	return conn, br, resp
}

// sendRequest encodes a single JSON-RPC request frame to conn and
// decodes one response frame from br. It is the per-method primitive
// every test uses to drive the control socket.
func sendRequest(t *testing.T, conn *net.UnixConn, br *bufio.Reader, method string, params any) ControlSocketResponse {
	t.Helper()
	rawParams, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal %s params: %v", method, err)
	}
	req := controlSocketRequest{Method: method, Params: rawParams}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode %s: %v", method, err)
	}
	line, err := br.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read %s response: %v", method, err)
	}
	var resp ControlSocketResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode %s response: %v", method, err)
	}
	return resp
}

// TestControlSocket_HelloRequiresPrimaryToken covers the locked
// decision that the primary control_token is the only thing that
// authenticates a helper: a connection that omits the token or
// presents the wrong one is closed immediately.
func TestControlSocket_HelloRequiresPrimaryToken(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "primary-token-fixture"})

	conn, br, resp := dialAndHello(t, cs, "wrong-token", controlSocketProtocolVersion)
	defer conn.Close()
	if resp.Decision != "block" {
		t.Errorf("wrong-token Hello: Decision = %q, want block", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "control_token") {
		t.Errorf("wrong-token Hello: Reason = %q, want substring control_token", resp.Reason)
	}
	// After the failed Hello the server closes the connection. The
	// next read should hit EOF.
	if _, err := br.ReadByte(); err == nil {
		t.Errorf("server kept conn open after wrong-token Hello")
	}
}

// TestControlSocket_HelloVersionMismatch covers the locked-decision
// requirement that a protocol_version mismatch closes the conn.
func TestControlSocket_HelloVersionMismatch(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "primary-token-fixture"})

	conn, br, resp := dialAndHello(t, cs, "primary-token-fixture", controlSocketProtocolVersion+1)
	defer conn.Close()
	if resp.Decision != "block" {
		t.Errorf("version-mismatch Hello: Decision = %q, want block", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "protocol_version") {
		t.Errorf("version-mismatch Hello: Reason = %q, want substring protocol_version", resp.Reason)
	}
	if _, err := br.ReadByte(); err == nil {
		t.Errorf("server kept conn open after version-mismatch Hello")
	}
}

// TestControlSocket_HelloSucceedsAllowsSubsequentRPC covers the
// happy path: a Hello with the correct token + version unlocks the
// per-method RPCs.
func TestControlSocket_HelloSucceedsAllowsSubsequentRPC(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "primary-token-fixture"})

	conn, br, resp := dialAndHello(t, cs, "primary-token-fixture", controlSocketProtocolVersion)
	defer conn.Close()
	if resp.Decision != "allow" {
		t.Fatalf("Hello: Decision = %q, want allow (reason=%q)", resp.Decision, resp.Reason)
	}

	// BeginTurn should mint a fresh ID.
	r := sendRequest(t, conn, br, "BeginTurn", beginTurnParams{
		ControlToken: "primary-token-fixture",
		Role:         "agent",
	})
	if r.Decision != "allow" {
		t.Errorf("BeginTurn: Decision = %q, want allow", r.Decision)
	}
	if r.TurnID == "" {
		t.Errorf("BeginTurn: TurnID empty")
	}

	// CurrentTurn should echo the same ID.
	c := sendRequest(t, conn, br, "CurrentTurn", currentTurnParams{
		ControlToken: "primary-token-fixture",
		Role:         "agent",
	})
	if c.TurnID != r.TurnID {
		t.Errorf("CurrentTurn: TurnID = %q, want %q", c.TurnID, r.TurnID)
	}
}

// TestControlSocket_BeginTurnMonotonic covers BeginTurn's monotonic
// per-role allocation: each call yields a fresh ID and CurrentTurn
// always returns the most recent one.
func TestControlSocket_BeginTurnMonotonic(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "tok"})

	conn, br, resp := dialAndHello(t, cs, "tok", controlSocketProtocolVersion)
	defer conn.Close()
	if resp.Decision != "allow" {
		t.Fatalf("Hello: Decision = %q", resp.Decision)
	}

	ids := make([]string, 3)
	for i := 0; i < 3; i++ {
		r := sendRequest(t, conn, br, "BeginTurn", beginTurnParams{
			ControlToken: "tok", Role: "agent",
		})
		ids[i] = r.TurnID
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			t.Errorf("BeginTurn produced duplicate ID at index %d: %q", i, ids[i])
		}
	}
	cur := sendRequest(t, conn, br, "CurrentTurn", currentTurnParams{ControlToken: "tok", Role: "agent"})
	if cur.TurnID != ids[len(ids)-1] {
		t.Errorf("CurrentTurn = %q, want last BeginTurn %q", cur.TurnID, ids[len(ids)-1])
	}
}

// TestControlSocket_AcceptingShutdown_RejectsNewRPCs is one of the
// two acceptance tests called out in the plan's Batch 0.0 acceptance
// line. After AcceptingShutdown() is called, every NEW RPC returns
// decision="block", reason="shutdown".
func TestControlSocket_AcceptingShutdown_RejectsNewRPCs(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{
		PrimaryToken: "tok",
		ShellEvaluator: ShellEvaluatorFunc(func(cmdLine string, argv []string) ControlSocketResponse {
			return ControlSocketResponse{Decision: "allow", Reason: "ok"}
		}),
	})

	conn, br, resp := dialAndHello(t, cs, "tok", controlSocketProtocolVersion)
	defer conn.Close()
	if resp.Decision != "allow" {
		t.Fatalf("Hello: Decision = %q", resp.Decision)
	}

	// Pre-shutdown: EvaluateShellCommand should be allowed.
	r := sendRequest(t, conn, br, "EvaluateShellCommand", evaluateShellCommandParams{
		ControlToken: "tok",
		Argv:         []string{"echo", "hi"},
		CmdLine:      "echo hi",
	})
	if r.Decision != "allow" {
		t.Fatalf("pre-shutdown EvaluateShellCommand: Decision = %q, want allow", r.Decision)
	}

	// Flip the shutdown gate. The plan's contract: every NEW RPC
	// after this returns decision="block", reason="shutdown".
	cs.AcceptingShutdown()

	r = sendRequest(t, conn, br, "EvaluateShellCommand", evaluateShellCommandParams{
		ControlToken: "tok",
		Argv:         []string{"echo", "hi"},
		CmdLine:      "echo hi",
	})
	if r.Decision != "block" {
		t.Errorf("post-shutdown Decision = %q, want block", r.Decision)
	}
	if r.Reason != "shutdown" {
		t.Errorf("post-shutdown Reason = %q, want shutdown", r.Reason)
	}

	// A second method also sees the gate. Try BeginTurn.
	r = sendRequest(t, conn, br, "BeginTurn", beginTurnParams{ControlToken: "tok", Role: "agent"})
	if r.Decision != "block" || r.Reason != "shutdown" {
		t.Errorf("post-shutdown BeginTurn: Decision=%q Reason=%q, want block/shutdown", r.Decision, r.Reason)
	}

	// A NEW connection that Hellos after AcceptingShutdown also
	// sees the shutdown gate on its first non-Hello call. Hello
	// itself is still answered (the connection needs to handshake
	// before the gate applies); the first per-method call gets the
	// shutdown verdict.
	conn2, br2, resp2 := dialAndHello(t, cs, "tok", controlSocketProtocolVersion)
	defer conn2.Close()
	if resp2.Decision != "allow" {
		t.Fatalf("post-shutdown Hello: Decision = %q, want allow (Hello still handshakes)", resp2.Decision)
	}
	r = sendRequest(t, conn2, br2, "BeginTurn", beginTurnParams{ControlToken: "tok", Role: "agent"})
	if r.Decision != "block" || r.Reason != "shutdown" {
		t.Errorf("post-shutdown new-conn BeginTurn: Decision=%q Reason=%q, want block/shutdown", r.Decision, r.Reason)
	}
}

// TestControlSocket_PerServerTokenScoping is the second acceptance
// test called out in the plan. An agent-readable per-server token
// MUST NOT authorize calls to a different server: presenting
// server-A's token while naming server-B is rejected with
// decision="block", reason="server_token mismatch".
func TestControlSocket_PerServerTokenScoping(t *testing.T) {
	dir := newControlSocketRunDir(t)
	var authCalls int
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{
		PrimaryToken: "tok",
		MCPAuthorizer: MCPAuthorizerFunc(func(server, op string, body []byte) ControlSocketResponse {
			authCalls++
			return ControlSocketResponse{Decision: "allow", Reason: "ok"}
		}),
	})

	// Register two servers with distinct tokens. The supervisor
	// would do this once per server at step 9 of the pre-launch
	// sequence.
	tokA, err := cs.MintServerToken("server-A")
	if err != nil {
		t.Fatalf("MintServerToken A: %v", err)
	}
	tokB, err := cs.MintServerToken("server-B")
	if err != nil {
		t.Fatalf("MintServerToken B: %v", err)
	}
	if tokA == tokB {
		t.Fatalf("MintServerToken produced identical tokens for distinct servers")
	}

	conn, br, resp := dialAndHello(t, cs, "tok", controlSocketProtocolVersion)
	defer conn.Close()
	if resp.Decision != "allow" {
		t.Fatalf("Hello: Decision = %q", resp.Decision)
	}

	// Happy path: server-A with tokA is authorized.
	r := sendRequest(t, conn, br, "AuthorizeMCPCall", authorizeMCPCallParams{
		ControlToken: "tok",
		ServerToken:  tokA,
		Server:       "server-A",
		Operation:    "list_tools",
	})
	if r.Decision != "allow" {
		t.Errorf("server-A + tokA: Decision = %q, want allow", r.Decision)
	}

	// The plan's headline scoping test: server-A's token used with
	// server-B's name MUST be rejected. The authorizer hook must
	// NOT be called (the constant-time token compare rejects
	// before the policy bridge).
	authCallsBefore := authCalls
	r = sendRequest(t, conn, br, "AuthorizeMCPCall", authorizeMCPCallParams{
		ControlToken: "tok",
		ServerToken:  tokA, // wrong: this is server-A's token
		Server:       "server-B",
		Operation:    "list_tools",
	})
	if r.Decision != "block" {
		t.Errorf("cross-server token: Decision = %q, want block", r.Decision)
	}
	if r.Reason != "server_token mismatch" {
		t.Errorf("cross-server token: Reason = %q, want %q", r.Reason, "server_token mismatch")
	}
	if authCalls != authCallsBefore {
		t.Errorf("cross-server token: MCPAuthorizer was called %d times, want 0 (token check should reject before bridge)", authCalls-authCallsBefore)
	}

	// Unknown server name is also rejected, with a distinct reason
	// so the operator can tell "wrong name" from "wrong token".
	r = sendRequest(t, conn, br, "AuthorizeMCPCall", authorizeMCPCallParams{
		ControlToken: "tok",
		ServerToken:  tokA,
		Server:       "server-Z",
		Operation:    "list_tools",
	})
	if r.Decision != "block" {
		t.Errorf("unknown server: Decision = %q, want block", r.Decision)
	}
	if r.Reason != "unknown server" {
		t.Errorf("unknown server: Reason = %q, want %q", r.Reason, "unknown server")
	}
}

// TestControlSocket_EvaluateShellCommand_NoHandler covers the
// fail-closed default: a helper that asks before the supervisor has
// wired a ShellEvaluator in gets decision="block",
// reason="no handler configured".
func TestControlSocket_EvaluateShellCommand_NoHandler(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "tok"})

	conn, br, resp := dialAndHello(t, cs, "tok", controlSocketProtocolVersion)
	defer conn.Close()
	if resp.Decision != "allow" {
		t.Fatalf("Hello: Decision = %q", resp.Decision)
	}

	r := sendRequest(t, conn, br, "EvaluateShellCommand", evaluateShellCommandParams{
		ControlToken: "tok",
		Argv:         []string{"echo", "hi"},
		CmdLine:      "echo hi",
	})
	if r.Decision != "block" {
		t.Errorf("no-handler: Decision = %q, want block", r.Decision)
	}
	if r.Reason != "no handler configured" {
		t.Errorf("no-handler: Reason = %q, want %q", r.Reason, "no handler configured")
	}
}

// TestControlSocket_AuthorizeMCPCall_BridgeReceivesBody covers the
// bridge contract: when the (server_token, server) pair verifies,
// the authorizer receives the verbatim server / op / body the helper
// supplied.
func TestControlSocket_AuthorizeMCPCall_BridgeReceivesBody(t *testing.T) {
	dir := newControlSocketRunDir(t)
	var gotServer, gotOp string
	var gotBody []byte
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{
		PrimaryToken: "tok",
		MCPAuthorizer: MCPAuthorizerFunc(func(server, op string, body []byte) ControlSocketResponse {
			gotServer = server
			gotOp = op
			gotBody = append(gotBody[:0], body...)
			return ControlSocketResponse{Decision: "allow", Reason: "ok"}
		}),
	})
	srvTok, err := cs.MintServerToken("fs")
	if err != nil {
		t.Fatalf("MintServerToken: %v", err)
	}

	conn, br, resp := dialAndHello(t, cs, "tok", controlSocketProtocolVersion)
	defer conn.Close()
	if resp.Decision != "allow" {
		t.Fatalf("Hello: Decision = %q", resp.Decision)
	}

	body := json.RawMessage(`{"path":"/tmp/x"}`)
	r := sendRequest(t, conn, br, "AuthorizeMCPCall", authorizeMCPCallParams{
		ControlToken: "tok",
		ServerToken:  srvTok,
		Server:       "fs",
		Operation:    "read_file",
		Body:         body,
	})
	if r.Decision != "allow" {
		t.Fatalf("AuthorizeMCPCall: Decision = %q (Reason=%q)", r.Decision, r.Reason)
	}
	if gotServer != "fs" {
		t.Errorf("bridge server = %q, want fs", gotServer)
	}
	if gotOp != "read_file" {
		t.Errorf("bridge op = %q, want read_file", gotOp)
	}
	if string(gotBody) != string(body) {
		t.Errorf("bridge body = %s, want %s", string(gotBody), string(body))
	}
}

// TestControlSocket_StartChmodsSocket0600 covers the locked
// requirement: the socket file MUST be mode 0600 so only the owning
// UID can connect.
func TestControlSocket_StartChmodsSocket0600(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "tok"})

	info, err := os.Stat(cs.Path())
	if err != nil {
		t.Fatalf("stat control.sock: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("control.sock mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestControlSocket_PathUnderRunDir covers the layout invariant:
// the socket lives at <runDir>/control.sock so the supervisor's
// bind-mount step (Batch 0.5) can map it deterministically.
func TestControlSocket_PathUnderRunDir(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "tok"})

	want := filepath.Join(dir.Path, "control.sock")
	if cs.Path() != want {
		t.Errorf("Path = %q, want %q", cs.Path(), want)
	}
}

// TestControlSocket_StopRemovesSocketFile covers the teardown
// contract: Stop closes the listener AND removes the socket file so
// a subsequent Start can bind cleanly.
func TestControlSocket_StopRemovesSocketFile(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, err := NewControlSocket(ControlSocketOptions{RunDir: dir.Path, PrimaryToken: "tok"})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := cs.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := os.Stat(cs.Path()); err != nil {
		t.Fatalf("socket file missing after Start: %v", err)
	}
	if err := cs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := os.Stat(cs.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket file still present after Stop: err = %v", err)
	}
}

// TestControlSocket_StartTolerantOfStaleSocket covers the
// post-crash recovery path: a previous run that crashed before Stop
// leaves a stale socket file behind, and Start should remove it
// rather than fail with EADDRINUSE.
func TestControlSocket_StartTolerantOfStaleSocket(t *testing.T) {
	dir := newControlSocketRunDir(t)

	// First Start + (simulated crash: don't Stop) leaves the socket
	// file behind. We mimic that by binding a fresh listener and
	// dropping it without calling Stop.
	addr, err := net.ResolveUnixAddr("unix", filepath.Join(dir.Path, "control.sock"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("pre-listen: %v", err)
	}
	_ = ln.Close()
	// Even after Close the file may be cleaned by net; the test
	// must work whether the file is present or not. We re-create
	// it to simulate the stale case.
	if _, err := os.Create(filepath.Join(dir.Path, "control.sock")); err != nil {
		// If create fails (e.g. file still there as socket), that
		// is also fine: the Start path should tolerate either way.
	}
	// Drop any regular file and re-bind a real socket so the next
	// Start sees a socket-mode stale entry.
	_ = os.Remove(filepath.Join(dir.Path, "control.sock"))
	ln2, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("re-listen: %v", err)
	}
	_ = ln2.Close()
	// On some platforms Close removes the socket; we recreate as a
	// fresh socket entry so Start has something to delete.
	if _, err := os.Stat(filepath.Join(dir.Path, "control.sock")); errors.Is(err, os.ErrNotExist) {
		ln3, err := net.ListenUnix("unix", addr)
		if err != nil {
			t.Fatalf("third listen: %v", err)
		}
		// Intentionally leak the listener without Close so the
		// stale file persists.
		defer ln3.Close()
	}

	cs, err := NewControlSocket(ControlSocketOptions{RunDir: dir.Path, PrimaryToken: "tok"})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = cs.Stop()
	})
	if err := cs.Start(ctx); err != nil {
		t.Fatalf("Start tolerant-of-stale: %v", err)
	}
}

// TestControlSocket_NonHelloFirstFrameClosesConn covers the
// handshake contract: any non-Hello frame before Hello succeeds
// closes the connection.
func TestControlSocket_NonHelloFirstFrameClosesConn(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "tok"})

	addr, err := net.ResolveUnixAddr("unix", cs.Path())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send BeginTurn as the first frame. The server should close
	// the connection.
	enc := json.NewEncoder(conn)
	raw, _ := json.Marshal(beginTurnParams{ControlToken: "tok", Role: "agent"})
	if err := enc.Encode(controlSocketRequest{Method: "BeginTurn", Params: raw}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	br := bufio.NewReader(conn)
	if _, err := br.ReadByte(); err == nil {
		t.Errorf("server kept conn open after non-Hello first frame")
	}
}

// TestControlSocket_PrimaryTokenMintedWhenNotSupplied covers the
// constructor's default: when opts.PrimaryToken is empty, the
// constructor mints a 32-byte b64 token via crypto/rand. The token
// must be non-empty and stable for the socket's lifetime.
func TestControlSocket_PrimaryTokenMintedWhenNotSupplied(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, err := NewControlSocket(ControlSocketOptions{RunDir: dir.Path})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}
	tok := cs.PrimaryToken()
	if tok == "" {
		t.Errorf("PrimaryToken empty after mint")
	}
	// Two constructions yield distinct tokens (crypto/rand source).
	cs2, err := NewControlSocket(ControlSocketOptions{RunDir: dir.Path})
	if err != nil {
		t.Fatalf("NewControlSocket #2: %v", err)
	}
	if cs2.PrimaryToken() == tok {
		t.Errorf("two mints produced identical token (unlikely; possible regression)")
	}
}

// TestControlSocket_ConcurrentConns covers the per-conn goroutine
// model: many connections in flight at once should not interleave
// frames nor race on the shared turn counters.
func TestControlSocket_ConcurrentConns(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "tok"})

	const N = 10
	var wg sync.WaitGroup
	ids := make([]string, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, br, resp := dialAndHello(t, cs, "tok", controlSocketProtocolVersion)
			defer conn.Close()
			if resp.Decision != "allow" {
				t.Errorf("goroutine %d: Hello Decision = %q", i, resp.Decision)
				return
			}
			r := sendRequest(t, conn, br, "BeginTurn", beginTurnParams{
				ControlToken: "tok", Role: "agent",
			})
			if r.Decision != "allow" {
				t.Errorf("goroutine %d: BeginTurn Decision = %q", i, r.Decision)
				return
			}
			ids[i] = r.TurnID
		}(i)
	}
	wg.Wait()

	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" {
			t.Errorf("a concurrent BeginTurn produced empty TurnID")
			continue
		}
		if seen[id] {
			t.Errorf("duplicate concurrent TurnID %q", id)
		}
		seen[id] = true
	}
}

// TestControlSocket_UnknownMethodReturnsBlock covers the per-call
// validation: an unknown method gets decision="block" with a clear
// reason, but the connection is not closed (a typo on one frame
// must not kill the session).
func TestControlSocket_UnknownMethodReturnsBlock(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "tok"})

	conn, br, resp := dialAndHello(t, cs, "tok", controlSocketProtocolVersion)
	defer conn.Close()
	if resp.Decision != "allow" {
		t.Fatalf("Hello: Decision = %q", resp.Decision)
	}

	r := sendRequest(t, conn, br, "DoesNotExist", struct{}{})
	if r.Decision != "block" {
		t.Errorf("unknown method: Decision = %q, want block", r.Decision)
	}
	if !strings.Contains(r.Reason, "unknown method") {
		t.Errorf("unknown method: Reason = %q, want substring unknown method", r.Reason)
	}

	// The conn should still work for a known method.
	r = sendRequest(t, conn, br, "BeginTurn", beginTurnParams{ControlToken: "tok", Role: "agent"})
	if r.Decision != "allow" {
		t.Errorf("post-unknown-method BeginTurn: Decision = %q, want allow", r.Decision)
	}
}

// TestControlSocket_RegisterServerTokenValidation covers the
// constructor-side input validation: empty server name or token is
// rejected.
func TestControlSocket_RegisterServerTokenValidation(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, err := NewControlSocket(ControlSocketOptions{RunDir: dir.Path, PrimaryToken: "tok"})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}
	if err := cs.RegisterServerToken("", "tok"); err == nil {
		t.Errorf("RegisterServerToken with empty server: want error, got nil")
	}
	if err := cs.RegisterServerToken("fs", ""); err == nil {
		t.Errorf("RegisterServerToken with empty token: want error, got nil")
	}
	if _, err := cs.MintServerToken(""); err == nil {
		t.Errorf("MintServerToken with empty server: want error, got nil")
	}
}

// TestControlSocket_NewControlSocketValidation covers the
// constructor's input validation: empty RunDir is rejected.
func TestControlSocket_NewControlSocketValidation(t *testing.T) {
	if _, err := NewControlSocket(ControlSocketOptions{}); err == nil {
		t.Errorf("NewControlSocket with empty RunDir: want error, got nil")
	}
}

// TestControlSocket_AllocateAndCurrentTurnIDInProcess covers Plan
// Batch 3.3's in-process turn-id surface. AllocateTurnID mints a
// fresh monotonic id per role; CurrentTurnID returns the most recent
// one. The two methods are the supervisor-side bypass of the RPC
// handler used by the gateway turn-id bridge (cli.MCPCallLogger).
func TestControlSocket_AllocateAndCurrentTurnIDInProcess(t *testing.T) {
	cs, err := NewControlSocket(ControlSocketOptions{
		RunDir:       t.TempDir(),
		PrimaryToken: "tok",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}

	// No allocation yet: every role reports the empty string.
	if got := cs.CurrentTurnID("agent"); got != "" {
		t.Errorf("CurrentTurnID before alloc: got %q, want empty", got)
	}
	if got := cs.CurrentTurnID(""); got != "" {
		t.Errorf("CurrentTurnID empty role before alloc: got %q, want empty", got)
	}

	// Allocate a sequence under the default ("agent") and a custom
	// ("subagent") role; the counters must be independent.
	a1 := cs.AllocateTurnID("agent")
	a2 := cs.AllocateTurnID("agent")
	s1 := cs.AllocateTurnID("subagent")
	if a1 == "" || a2 == "" || s1 == "" {
		t.Fatalf("AllocateTurnID produced empty id (a1=%q a2=%q s1=%q)", a1, a2, s1)
	}
	if a1 == a2 {
		t.Errorf("AllocateTurnID(agent) twice returned identical ids %q", a1)
	}
	if a1 == s1 || a2 == s1 {
		t.Errorf("counter cross-talk: agent and subagent share an id (a1=%q a2=%q s1=%q)", a1, a2, s1)
	}

	if got := cs.CurrentTurnID("agent"); got != a2 {
		t.Errorf("CurrentTurnID(agent) = %q, want %q (most recent)", got, a2)
	}
	if got := cs.CurrentTurnID("subagent"); got != s1 {
		t.Errorf("CurrentTurnID(subagent) = %q, want %q", got, s1)
	}

	// Empty role on AllocateTurnID is rewritten to "agent" so the
	// in-process accessor agrees with the RPC handler.
	a3 := cs.AllocateTurnID("")
	if a3 == "" {
		t.Errorf("AllocateTurnID(empty) returned empty")
	}
	if got := cs.CurrentTurnID(""); got != a3 {
		t.Errorf("CurrentTurnID(empty) = %q, want %q (default role)", got, a3)
	}
	if got := cs.CurrentTurnID("agent"); got != a3 {
		t.Errorf("after AllocateTurnID(empty), CurrentTurnID(agent) = %q, want %q (shared default role)", got, a3)
	}
}

// TestControlSocket_RPCAndInProcessTurnIDAgree pins the contract that
// the in-process AllocateTurnID counter and the RPC BeginTurn counter
// share the same per-role state — i.e. the bridge that reads
// CurrentTurnID sees turns allocated via the RPC and vice versa.
func TestControlSocket_RPCAndInProcessTurnIDAgree(t *testing.T) {
	dir := newControlSocketRunDir(t)
	cs, _ := startControlSocket(t, dir, ControlSocketOptions{PrimaryToken: "tok"})

	// Allocate via RPC first.
	conn, br, resp := dialAndHello(t, cs, "tok", controlSocketProtocolVersion)
	defer conn.Close()
	if resp.Decision != "allow" {
		t.Fatalf("Hello: Decision = %q", resp.Decision)
	}
	r := sendRequest(t, conn, br, "BeginTurn", beginTurnParams{
		ControlToken: "tok", Role: "agent",
	})
	if r.TurnID == "" {
		t.Fatalf("BeginTurn produced empty id")
	}
	// In-process reader sees the same id.
	if got := cs.CurrentTurnID("agent"); got != r.TurnID {
		t.Errorf("in-process CurrentTurnID after RPC BeginTurn: got %q, want %q", got, r.TurnID)
	}

	// Allocate via in-process; the RPC CurrentTurn handler reports
	// the new id.
	a := cs.AllocateTurnID("agent")
	if a == "" || a == r.TurnID {
		t.Fatalf("AllocateTurnID after RPC BeginTurn: got %q (previous %q)", a, r.TurnID)
	}
	c := sendRequest(t, conn, br, "CurrentTurn", currentTurnParams{
		ControlToken: "tok", Role: "agent",
	})
	if c.TurnID != a {
		t.Errorf("RPC CurrentTurn after in-process AllocateTurnID: got %q, want %q", c.TurnID, a)
	}
}
