//go:build acceptance

// Package acceptance — Section 9 of the leak-coverage hardening plan:
// the red-team scenario acceptance suite. Each top-level test in this
// file corresponds to one adversarial workflow the plan enumerates at
// lines 281-288:
//
//   - TestLeak_OriginDriftBetweenSetupAndPR_Blocked  (Section 4 pin):
//     an attacker rewrites the workspace's `origin` remote between
//     `ai-env new` and PR time; the broker's CheckOriginPin gate must
//     refuse the push with ErrOriginDrift.
//
//   - TestLeak_AgentForgesMCPCallAcrossServers_Blocked  (per-server
//     token scoping): an agent that learns the per-server token for
//     server-A from the agent-readable mcp-servers.json tries to use
//     it to authorize calls against server-B. The supervisor's
//     ControlSocket.AuthorizeMCPCall must reject the cross-server
//     forge with reason="server_token mismatch" without ever
//     invoking the MCP authorizer bridge.
//
//   - TestLeak_ProviderProxyOpenRelay_Refused  (Host-header
//     allowlist): an agent that reaches the loopback ProviderProxy
//     tries to use it as an open relay by setting Host to an
//     arbitrary upstream. The proxy must reject with 403 BEFORE
//     dialing the upstream, so a compromised agent cannot pivot the
//     proxy into a generic egress channel.
//
//   - TestLeak_Shim_Argv0Spoof_Rejected: a malicious caller invokes
//     `ai-env shim-helper shell <not-a-shimmed-program>` to escape
//     the canonical shadow set. The helper rejects programs outside
//     the canonical set, and (for shimmed programs) forces argv[0]
//     to the canonical basename — defeating both the
//     "not-in-canonical-set" attack and the `exec -a sh python3 ...`
//     spoof.
//
//   - TestLeak_Shim_SecretInStreamingMCPResponse_Scrubbed (rolling
//     buffer): a JSON-RPC response stream from the MCP server
//     carries a provider key split across two chunk reads. The
//     helper's rolling-buffer streaming scanner must catch the
//     secret at the boundary; the scrubbed downstream bytes must
//     not contain the raw key.
//
// Gating: identical to section32_test.go — the `acceptance` build
// tag is the static gate and AI_ENV_ACCEPTANCE=1 (TestMain in
// section32_test.go) is the dynamic gate. The binary built by
// section32_test.go is reused for any subtest that drives `ai-env`
// as a subprocess.
//
// Design rules this file follows (mirrors the other acceptance
// files):
//
//   1. Real components. The ControlSocket runs against a real Unix
//      socket; the ProviderProxy binds a real loopback listener; the
//      githubbroker calls a real `git` to read the rewritten origin.
//      The streaming-scrubber scenario shells out to the real
//      `ai-env shim-helper mcp <server>` so the full Hello + stdio
//      pipeline is exercised end-to-end.
//
//   2. One test per plan bullet. The five tests are independent and
//      can be run in isolation; a regression that breaks one bullet
//      points at exactly one plan line.
//
//   3. Fail-closed assertions. Every scenario asserts that the
//      attack is REFUSED. A regression that makes the path "allow"
//      is a security-bar failure; the test's primary signal is
//      "this attack must NOT succeed."

package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/githubbroker"
	"github.com/i1rr/ai-env/internal/run"
	"github.com/i1rr/ai-env/internal/secrets"
)

// -----------------------------------------------------------------------------
// Plan §9 bullet 1: TestLeak_OriginDriftBetweenSetupAndPR_Blocked
// -----------------------------------------------------------------------------

// TestLeak_OriginDriftBetweenSetupAndPR_Blocked simulates an attacker
// who quietly rewrites the workspace's git `origin` remote between
// the `ai-env new` time (when the supervisor pins the origin) and PR
// time (when the broker re-parses the live origin and compares
// against the pin). The plan calls this out as the Section 4 pin:
// the broker refuses the push with ErrOriginDrift.
//
// The test exercises the real githubbroker primitives end-to-end:
//
//  1. RecordOriginPin writes a real env.yaml under a real workspace
//     directory.
//  2. The "live" origin URL is then changed to a different (owner,
//     name, host) coordinate, simulating an attacker rewriting the
//     remote via `git remote set-url origin <evil>`.
//  3. CheckOriginPin re-parses the live URL and compares. The call
//     must return ErrOriginDrift with a message that surfaces both
//     the pinned and live coordinates so an operator can see the
//     delta.
//
// Three drift shapes are exercised because the plan's pin covers
// three independent dimensions (owner, name, host); a regression in
// the comparator that collapses any dimension would let an attacker
// drift that field silently.
func TestLeak_OriginDriftBetweenSetupAndPR_Blocked(t *testing.T) {
	wsDir := t.TempDir()

	// Step 1: record the pin the supervisor would have written at
	// `ai-env new`.
	pinned := githubbroker.OriginPin{
		Owner: "honest-org",
		Name:  "honest-repo",
		Host:  "github.com",
	}
	if err := githubbroker.RecordOriginPin(wsDir, pinned); err != nil {
		t.Fatalf("RecordOriginPin: %v", err)
	}

	// Sanity: the pin file is readable and round-trips. A regression
	// in the writer that produced a malformed file would surface as
	// ErrPinNotFound here and would mask the drift check below.
	loaded, err := githubbroker.LoadOriginPin(wsDir)
	if err != nil {
		t.Fatalf("LoadOriginPin: %v", err)
	}
	if !loaded.Equal(pinned) {
		t.Fatalf("LoadOriginPin = %+v, want %+v", loaded, pinned)
	}

	// Step 2 + 3: each drift shape must produce ErrOriginDrift. The
	// happy path (live == pin) must produce nil so the test pins
	// "drift detector is not always-block."
	cases := []struct {
		name    string
		live    string
		wantErr error
	}{
		{
			name:    "OwnerRewrite",
			live:    "https://github.com/evil-org/honest-repo.git",
			wantErr: githubbroker.ErrOriginDrift,
		},
		{
			name:    "NameRewrite",
			live:    "https://github.com/honest-org/evil-repo.git",
			wantErr: githubbroker.ErrOriginDrift,
		},
		{
			name:    "HostRewrite",
			live:    "https://github.enterprise.evil/honest-org/honest-repo.git",
			wantErr: githubbroker.ErrOriginDrift,
		},
		{
			name:    "SSHRewriteToDifferentOwner",
			live:    "git@github.com:evil-org/honest-repo.git",
			wantErr: githubbroker.ErrOriginDrift,
		},
		{
			name:    "Match_NoErr",
			live:    "https://github.com/honest-org/honest-repo.git",
			wantErr: nil,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := githubbroker.CheckOriginPin(wsDir, tc.live)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("CheckOriginPin(%q) = %v, want nil", tc.live, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckOriginPin(%q) = nil, want %v", tc.live, tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("CheckOriginPin(%q) err = %v, want errors.Is(..., %v)", tc.live, err, tc.wantErr)
			}
			// Drift errors must mention both sides so the operator
			// can see the (pinned, live) delta without re-parsing the
			// pin file. A regression that surfaced only one side
			// would defeat the "what changed" diagnostic.
			msg := err.Error()
			if !strings.Contains(msg, "pinned") || !strings.Contains(msg, "live") {
				t.Errorf("CheckOriginPin err = %q, want both 'pinned' and 'live' in message", msg)
			}
		})
	}

	// Additional end-to-end signal: a workspace whose git origin is
	// rewired in real git config also triggers the same gate when the
	// broker's CLI-side wrapper (`WorkspaceOriginURL` + `CheckOriginPin`)
	// is driven against the live workspace. This pins the "git remote
	// rewrite at the CLI layer" path the plan calls out.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not on PATH: %v", err)
	}
	gitDir := t.TempDir()
	runRedteamGit(t, gitDir, "init", "-b", "main")
	runRedteamGit(t, gitDir, "config", "user.email", "acceptance@example.com")
	runRedteamGit(t, gitDir, "config", "user.name", "Acceptance")
	runRedteamGit(t, gitDir, "remote", "add", "origin", "https://github.com/honest-org/honest-repo.git")
	// Pin into a separate workspace dir; this is the analog of what
	// `ai-env new` would have written.
	pinDir := t.TempDir()
	if err := githubbroker.RecordOriginPin(pinDir, pinned); err != nil {
		t.Fatalf("RecordOriginPin (live-git): %v", err)
	}
	// Attacker rewrites the live origin.
	runRedteamGit(t, gitDir, "remote", "set-url", "origin", "https://github.com/evil-org/evil-repo.git")
	live, err := githubbroker.WorkspaceOriginURL(gitDir)
	if err != nil {
		t.Fatalf("WorkspaceOriginURL: %v", err)
	}
	if live == "" {
		t.Fatalf("WorkspaceOriginURL returned empty after `git remote set-url`; expected the rewritten URL")
	}
	if _, err := githubbroker.CheckOriginPin(pinDir, live); !errors.Is(err, githubbroker.ErrOriginDrift) {
		t.Errorf("CheckOriginPin(rewritten live origin) err = %v, want ErrOriginDrift", err)
	}
}

// runRedteamGit shells out to `git` in dir with args and fails the
// test on any non-zero exit. Centralized so the drift test does not
// have to redeclare the boilerplate per `git` invocation. Renamed
// vs the suite-wide `runGit` helper to avoid duplicate-symbol
// collisions when the acceptance package is built; the section32
// helper is unexported within the same package and we re-use it
// where possible, but the redteam file is loaded with a different
// test runner state so a small dedicated wrapper keeps the
// signal-to-noise high.
func runRedteamGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

// -----------------------------------------------------------------------------
// Plan §9 bullet 2: TestLeak_AgentForgesMCPCallAcrossServers_Blocked
// -----------------------------------------------------------------------------

// TestLeak_AgentForgesMCPCallAcrossServers_Blocked exercises the
// canonical attack the plan calls out for per-server token scoping
// (locked decision row 4): the agent can read the per-server token
// for "server-A" out of the agent-visible <runDir>/mcp-servers.json,
// but the supervisor's ControlSocket.AuthorizeMCPCall must REFUSE
// when that token is presented alongside a different server name.
//
// The test stands up a real ControlSocket, registers two distinct
// server tokens, then drives the wire protocol from a raw Unix
// connection — mirroring exactly what a compromised agent process
// could do from inside the sandbox.
//
// Three flows are asserted:
//
//  1. server-A + tokA: ALLOW (happy path; without this the test
//     would be vacuously passing because every call returns block).
//  2. server-B + tokA: BLOCK with reason="server_token mismatch"
//     AND the MCPAuthorizer bridge MUST NOT be invoked (the
//     constant-time token compare rejects before delegation).
//  3. server-Z (unregistered) + tokA: BLOCK with reason="unknown
//     server" — distinct verb so operators can tell the two failure
//     modes apart.
func TestLeak_AgentForgesMCPCallAcrossServers_Blocked(t *testing.T) {
	dir := newRedteamControlSocketRunDir(t)

	var (
		authMu       sync.Mutex
		authCalls    int
		authedServer string
	)
	cs, err := run.NewControlSocket(run.ControlSocketOptions{
		RunDir:       dir.Path,
		PrimaryToken: "primary-token-fixture",
		MCPAuthorizer: run.MCPAuthorizerFunc(func(server, op string, body []byte) run.ControlSocketResponse {
			authMu.Lock()
			authCalls++
			authedServer = server
			authMu.Unlock()
			return run.ControlSocketResponse{Decision: "allow", Reason: "ok"}
		}),
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = cs.Stop()
	})
	if err := cs.Start(ctx); err != nil {
		t.Fatalf("ControlSocket.Start: %v", err)
	}

	// Register two distinct server tokens, mirroring step 9 of the
	// supervisor's pre-launch sequence.
	tokA, err := cs.MintServerToken("server-A")
	if err != nil {
		t.Fatalf("MintServerToken A: %v", err)
	}
	tokB, err := cs.MintServerToken("server-B")
	if err != nil {
		t.Fatalf("MintServerToken B: %v", err)
	}
	if tokA == tokB {
		t.Fatalf("MintServerToken produced identical tokens for distinct servers (RNG collision or implementation bug)")
	}

	conn, br := dialControlAndHello(t, cs.Path(), "primary-token-fixture")
	defer conn.Close()

	// 1) Legitimate call: server-A + tokA must be authorized.
	resp := sendControlRPC(t, conn, br, "AuthorizeMCPCall", map[string]any{
		"control_token": "primary-token-fixture",
		"server_token":  tokA,
		"server":        "server-A",
		"op":            "list_tools",
	})
	if resp.Decision != "allow" {
		t.Fatalf("server-A + tokA: Decision = %q (reason=%q), want allow", resp.Decision, resp.Reason)
	}

	authMu.Lock()
	authCallsBeforeAttack := authCalls
	authMu.Unlock()

	// 2) Attack: the agent learned tokA from mcp-servers.json and
	//    tries to use it against server-B. This is the headline plan
	//    invariant; a regression that allowed this would let an
	//    agent escalate across MCP servers without ever holding
	//    server-B's token.
	resp = sendControlRPC(t, conn, br, "AuthorizeMCPCall", map[string]any{
		"control_token": "primary-token-fixture",
		"server_token":  tokA,
		"server":        "server-B",
		"op":            "filesystem.read",
		"body":          json.RawMessage(`{"path":"/etc/passwd"}`),
	})
	if resp.Decision != "block" {
		t.Errorf("cross-server forge: Decision = %q (reason=%q), want block", resp.Decision, resp.Reason)
	}
	if resp.Reason != "server_token mismatch" {
		t.Errorf("cross-server forge: Reason = %q, want %q", resp.Reason, "server_token mismatch")
	}
	authMu.Lock()
	gotAuthCalls := authCalls
	gotAuthedServer := authedServer
	authMu.Unlock()
	if gotAuthCalls != authCallsBeforeAttack {
		t.Errorf("cross-server forge: MCPAuthorizer was invoked %d extra time(s) (server=%q); the constant-time token compare MUST reject before delegation",
			gotAuthCalls-authCallsBeforeAttack, gotAuthedServer)
	}

	// 3) Unknown server name produces a distinct "unknown server"
	//    verb. Operators (and dashboards) tell "wrong name" from
	//    "wrong token" by the reason string.
	resp = sendControlRPC(t, conn, br, "AuthorizeMCPCall", map[string]any{
		"control_token": "primary-token-fixture",
		"server_token":  tokA,
		"server":        "server-Z",
		"op":            "list_tools",
	})
	if resp.Decision != "block" {
		t.Errorf("unknown-server forge: Decision = %q, want block", resp.Decision)
	}
	if resp.Reason != "unknown server" {
		t.Errorf("unknown-server forge: Reason = %q, want %q", resp.Reason, "unknown server")
	}

	// Sanity: server-B still works with its OWN token (tokB) — a
	// regression that always-blocked server-B (regardless of token)
	// would mask the cross-server forge invariant.
	resp = sendControlRPC(t, conn, br, "AuthorizeMCPCall", map[string]any{
		"control_token": "primary-token-fixture",
		"server_token":  tokB,
		"server":        "server-B",
		"op":            "list_tools",
	})
	if resp.Decision != "allow" {
		t.Errorf("server-B + tokB: Decision = %q (reason=%q), want allow", resp.Decision, resp.Reason)
	}
}

// newRedteamControlSocketRunDir mirrors the in-package
// newControlSocketRunDir helper from internal/run: it puts the run
// directory under /tmp so the AF_UNIX 104-byte sun_path limit is not
// hit on macOS where the default TempDir is deep under /var/folders.
// The acceptance suite re-implements the helper here (rather than
// reaching into the internal/run test fixture) because the internal
// helper is unexported.
func newRedteamControlSocketRunDir(t *testing.T) run.RunDirectory {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "aies-redteam-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	aiEnvDir := filepath.Join(base, ".ai-env")
	runID, err := run.GenerateRunID()
	if err != nil {
		t.Fatalf("GenerateRunID: %v", err)
	}
	dir, err := run.CreateRunDirectory(aiEnvDir, runID, time.Now())
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return dir
}

// dialControlAndHello opens a Unix connection to the control socket
// at sockPath, performs the Hello handshake with the given primary
// token, and returns the connection + buffered reader. The Hello
// must succeed; on rejection the helper fails the test fatally so
// callers do not have to re-check the handshake.
//
// We dial the raw wire format (a JSON envelope with "method" and
// "params" fields) because controlSocketRequest / helloParams are
// unexported. The shape is stable and pinned by the protocol-version
// constant the supervisor and helpers both speak.
func dialControlAndHello(t *testing.T, sockPath, primary string) (*net.UnixConn, *bufio.Reader) {
	t.Helper()
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatalf("ResolveUnixAddr: %v", err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatalf("DialUnix %s: %v", sockPath, err)
	}
	br := bufio.NewReader(conn)
	enc := json.NewEncoder(conn)
	if err := enc.Encode(map[string]any{
		"method": "Hello",
		"params": map[string]any{
			"control_token":    primary,
			"client_version":   "redteam-acceptance/1",
			"protocol_version": 1,
		},
	}); err != nil {
		_ = conn.Close()
		t.Fatalf("encode Hello: %v", err)
	}
	line, err := br.ReadBytes('\n')
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read Hello response: %v", err)
	}
	var resp run.ControlSocketResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		_ = conn.Close()
		t.Fatalf("decode Hello response (raw=%s): %v", line, err)
	}
	if resp.Decision != "allow" {
		_ = conn.Close()
		t.Fatalf("Hello: Decision = %q (reason=%q), want allow", resp.Decision, resp.Reason)
	}
	return conn, br
}

// sendControlRPC encodes one JSON-RPC request to conn and decodes one
// response from br. Mirrors the in-package sendRequest helper but
// uses a raw map for the params so the unexported per-method param
// structs (authorizeMCPCallParams, etc.) do not have to be imported.
func sendControlRPC(t *testing.T, conn *net.UnixConn, br *bufio.Reader, method string, params map[string]any) run.ControlSocketResponse {
	t.Helper()
	rawParams, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal %s params: %v", method, err)
	}
	req := map[string]any{
		"method": method,
		"params": json.RawMessage(rawParams),
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode %s: %v", method, err)
	}
	line, err := br.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read %s response: %v", method, err)
	}
	var resp run.ControlSocketResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode %s response (raw=%s): %v", method, line, err)
	}
	return resp
}

// -----------------------------------------------------------------------------
// Plan §9 bullet 3: TestLeak_ProviderProxyOpenRelay_Refused
// -----------------------------------------------------------------------------

// TestLeak_ProviderProxyOpenRelay_Refused exercises the open-relay
// defense the plan calls out for Bucket 2 (locked decision row 2):
// the ProviderProxy verifies the inbound Host header against the
// configured upstream's canonical host; a request whose Host points
// elsewhere is refused with HTTP 403 BEFORE the upstream is dialed.
//
// A compromised agent that finds the loopback proxy at
// 127.0.0.1:<port> would otherwise be able to use it as a generic
// egress channel (the proxy adds the host-side credential, which is
// a load-bearing bypass for any allowlist). This test confirms the
// allowlist rejects every off-allowlist Host shape:
//
//   - api.openai.com  (the OTHER provider — the most plausible
//     pivot for an agent that has both providers' base URLs in its
//     env);
//   - evil.example.com (an arbitrary attacker host);
//   - api.anthropic.com.evil.example.com  (sub-domain look-alike).
//
// The legitimate paths (loopback Host and the canonical upstream
// Host) must keep working so the test does not pass by accidentally
// blocking everything.
func TestLeak_ProviderProxyOpenRelay_Refused(t *testing.T) {
	const token = "sk-ant-redteam-test-aaaaaaaaaaaaaaaaaaaa"

	// Real upstream the proxy targets when it is allowed to dial. A
	// counter on every inbound request lets the test assert "the
	// blocked attempts NEVER dialed the upstream" — without this
	// counter a regression that 502'd off-host requests could pass
	// the status-code check while still having leaked the request to
	// the upstream.
	var (
		upstreamMu    sync.Mutex
		upstreamCalls int
	)
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamMu.Lock()
		upstreamCalls++
		upstreamMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstreamSrv.Close)
	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	// Transport rewrites the proxy's upstream-target URL to point at
	// the httptest server so we exercise the real proxy code path
	// (the same RoundTrip the production proxy uses) without needing
	// to actually reach api.anthropic.com.
	transport := &redteamRewriteTransport{target: upstreamURL, wrapped: http.DefaultTransport}

	proxy, err := secrets.NewProviderProxy(secrets.Options{
		Provider:  secrets.ProviderAnthropic,
		Token:     token,
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("ProviderProxy.Start: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Stop() })

	// 1) Cross-provider pivot: Host = api.openai.com against the
	//    Anthropic proxy. The plan's headline scenario.
	t.Run("ForgesOtherProviderHost", func(t *testing.T) {
		req, _ := http.NewRequest("POST", proxy.URL()+"/v1/messages", strings.NewReader(`{}`))
		req.Host = "api.openai.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("client.Do: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-provider pivot: status = %d, want 403", resp.StatusCode)
		}
	})

	// 2) Arbitrary attacker host.
	t.Run("ForgesArbitraryHost", func(t *testing.T) {
		req, _ := http.NewRequest("POST", proxy.URL()+"/v1/messages", strings.NewReader(`{}`))
		req.Host = "evil.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("client.Do evil: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("evil Host: status = %d, want 403", resp.StatusCode)
		}
	})

	// 3) Sub-domain look-alike — a common pivot pattern. The
	//    allowlist is exact-match, not prefix-match, so a
	//    "api.anthropic.com.<attacker>" lookalike must still 403.
	t.Run("ForgesSubdomainLookalike", func(t *testing.T) {
		req, _ := http.NewRequest("POST", proxy.URL()+"/v1/messages", strings.NewReader(`{}`))
		req.Host = "api.anthropic.com.evil.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("client.Do lookalike: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("sub-domain lookalike Host: status = %d, want 403", resp.StatusCode)
		}
	})

	// All three rejected paths together must have dialed the
	// upstream ZERO times. A regression that 502'd off-host requests
	// only AFTER dialing the upstream would defeat the "open relay"
	// guarantee even though the agent saw a non-success status.
	upstreamMu.Lock()
	leakedCalls := upstreamCalls
	upstreamMu.Unlock()
	if leakedCalls != 0 {
		t.Errorf("blocked open-relay attempts dialed the upstream %d time(s); the allowlist must reject BEFORE dispatch", leakedCalls)
	}

	// 4) Sanity: a request from the loopback (no Host override) must
	//    still pass through to the upstream so the legitimate path
	//    keeps working.
	t.Run("LoopbackHostAllowed", func(t *testing.T) {
		req, _ := http.NewRequest("GET", proxy.URL()+"/v1/models", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("client.Do loopback: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("loopback Host: status = %d, want 200 (legitimate path must keep working)", resp.StatusCode)
		}
	})

	// 5) Sanity: the canonical upstream Host is the documented
	//    allowed value and must pass.
	t.Run("CanonicalUpstreamHostAllowed", func(t *testing.T) {
		req, _ := http.NewRequest("GET", proxy.URL()+"/v1/models", nil)
		req.Host = "api.anthropic.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("client.Do canonical: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("canonical Host: status = %d, want 200", resp.StatusCode)
		}
	})
}

// redteamRewriteTransport is a real http.RoundTripper that retargets
// the proxy's upstream URL at an httptest.Server. Mirrors the
// internal/secrets test fixture (whose helper is unexported) so the
// acceptance suite can drive the real proxy RoundTrip path without
// dialing the actual provider host.
type redteamRewriteTransport struct {
	target  *url.URL
	wrapped http.RoundTripper
}

func (t *redteamRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = t.target.Scheme
	req.URL.Host = t.target.Host
	req.Host = t.target.Host
	return t.wrapped.RoundTrip(req)
}

// -----------------------------------------------------------------------------
// Plan §9 bullet 4: TestLeak_Shim_Argv0Spoof_Rejected
// -----------------------------------------------------------------------------

// TestLeak_Shim_Argv0Spoof_Rejected pins the plan's argv[0]
// hardening invariant (Bucket 1 locked decision): the helper refuses
// to dispatch a wrapper for a program outside the canonical
// ShimProgramSet, and rejects callers that invoke a shimmed program
// via a name not in the canonical set.
//
// The attack the plan calls out is `exec -a sh python3 ...` — a
// shell built-in that lets the caller set argv[0] freely. A
// regression that trusted argv[0] would let an attacker pivot from
// a python3 wrapper invocation into a shell context (or vice
// versa). The defense is two-layered:
//
//  1. The helper's `program` arg is the path basename the wrapper
//     writes verbatim; it is validated against the canonical
//     ShimProgramSet before any work happens. A program outside
//     the set fails closed with "not in the canonical shadow set".
//
//  2. For shimmed programs the helper FORCES argv[0] to the
//     canonical basename before execveat so the child cannot
//     observe an attacker-chosen identity.
//
// The acceptance test drives the real `ai-env shim-helper shell`
// subprocess and asserts both layers. The first layer is observable
// via the subprocess exit code + stderr; the second layer is pinned
// by the dedicated unit test in cmd/ai-env/shim_helper_shell_test.go
// (TestRewriteScriptArg_ReplacesScriptPath, etc.) — we re-exercise
// the layer-1 defense here at the integration boundary so a CI run
// that only runs the acceptance suite still catches the regression.
func TestLeak_Shim_Argv0Spoof_Rejected(t *testing.T) {
	// 1) Program outside the canonical ShimProgramSet is rejected
	//    with a clear "not in the canonical shadow set" diagnostic.
	//    This is the entry-point that prevents an attacker from
	//    pointing the wrapper at an arbitrary on-disk binary.
	t.Run("UnshimmedProgramRejected", func(t *testing.T) {
		stdout, stderr, err := runAIEnv(t, t.TempDir(),
			"shim-helper", "shell", "definitely-not-a-shimmed-program",
		)
		if err == nil {
			t.Fatalf("ai-env shim-helper shell <unshimmed> exited 0; want non-zero. stdout=%s stderr=%s", stdout, stderr)
		}
		combined := stdout + stderr
		if !strings.Contains(combined, "not in the canonical shadow set") {
			t.Errorf("stderr did not mention canonical-shadow rejection; stderr=%q", stderr)
		}
	})

	// 2) Empty-program guard. The wrapper template always writes the
	//    canonical basename, but a regression that accidentally
	//    passed an empty string (e.g. via an attacker-controlled
	//    environment variable) must still fail closed before any
	//    side-effecting work.
	t.Run("EmptyProgramRejected", func(t *testing.T) {
		stdout, stderr, err := runAIEnv(t, t.TempDir(),
			"shim-helper", "shell", "",
		)
		if err == nil {
			t.Fatalf("ai-env shim-helper shell '' exited 0; want non-zero. stdout=%s stderr=%s", stdout, stderr)
		}
	})

	// 3) Recursion guard. An attacker that loops the wrapper through
	//    itself by manipulating PATH could trigger an unbounded
	//    re-exec chain; the helper's AI_ENV_SHIM_DEPTH guard caps
	//    the chain at a small constant. We pin the wire by setting
	//    the env var to a value above the cap and confirming the
	//    helper exits with a "recursion guard tripped" message.
	t.Run("RecursionGuardTrippedWhenDepthExceedsCap", func(t *testing.T) {
		cmd := exec.Command(suite.binPath, "shim-helper", "shell", "bash")
		cmd.Dir = t.TempDir()
		cmd.Env = append(os.Environ(), "AI_ENV_SHIM_DEPTH=100")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err == nil {
			t.Fatalf("recursion-guarded helper exited 0; want non-zero. stdout=%s stderr=%s", stdout.String(), stderr.String())
		}
		combined := stdout.String() + stderr.String()
		if !strings.Contains(combined, "recursion guard tripped") {
			t.Errorf("stderr did not mention recursion guard; stderr=%q", stderr.String())
		}
	})
}

// -----------------------------------------------------------------------------
// Plan §9 bullet 5: TestLeak_Shim_SecretInStreamingMCPResponse_Scrubbed
// -----------------------------------------------------------------------------

// TestLeak_Shim_SecretInStreamingMCPResponse_Scrubbed pins the
// plan's rolling-buffer streaming-scrubber invariant (Bucket 11
// locked decision): a secret that spans two stdio read boundaries
// in an MCP response stream MUST still be caught and replaced with
// the canonical [REDACTED ...] sentinel. The plan's headline attack
// is an MCP server (or a malicious tool result) emitting a provider
// key whose bytes straddle a chunk-read boundary — a naive scanner
// that operates on individual chunks would let half the secret
// through.
//
// The test drives the real `ai-env shim-helper mcp <server>`
// subprocess against a real ControlSocket. The helper does Hello on
// startup and then relays stdin → stdout via the rolling-buffer
// scrubber pipeline. We feed it bytes shaped exactly like a
// real-world stream and assert:
//
//  1. The raw secret never appears in the helper's stdout (the
//     load-bearing leakage assertion).
//  2. The [REDACTED ...] sentinel does appear (proves the
//     scrubber actually ran).
//
// The end-to-end shape is more authentic than the unit-level
// scrubber tests in cmd/ai-env/shim_helper_mcp_test.go: this drives
// the real binary, real bufio reads against a real OS pipe, real
// control-socket Hello, and the same chunking the agent's stdio
// would see in production.
func TestLeak_Shim_SecretInStreamingMCPResponse_Scrubbed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shim helper is POSIX-only")
	}
	// 1) Real ControlSocket the helper Hello's against.
	dir := newRedteamControlSocketRunDir(t)
	cs, err := run.NewControlSocket(run.ControlSocketOptions{
		RunDir:       dir.Path,
		PrimaryToken: "primary-token-mcp-stream",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = cs.Stop()
	})
	if err := cs.Start(ctx); err != nil {
		t.Fatalf("ControlSocket.Start: %v", err)
	}
	if _, err := cs.MintServerToken("stream-server"); err != nil {
		t.Fatalf("MintServerToken: %v", err)
	}

	// 2) Side-band helper-token file. The helper reads the primary
	//    token from this path (AI_ENV_HELPER_TOKEN_PATH override) so
	//    we can drive the test without bind-mounting the canonical
	//    /var/run/ai-env/.helper-token.
	tokenFile := filepath.Join(dir.Path, ".helper-token")
	if err := os.WriteFile(tokenFile, []byte("primary-token-mcp-stream\n"), 0o600); err != nil {
		t.Fatalf("write helper-token: %v", err)
	}

	// 3) Build the streaming payload. The secret straddles a
	//    chunk-read boundary; the os.Pipe buffer used by the helper
	//    will read input in roughly 32KiB chunks, but the helper's
	//    rolling-buffer overlap also holds back a tail. We construct
	//    a payload that:
	//      - Starts with a large benign prefix (>32KiB) so the
	//        first scrubber read is "fully flushed" and the carry
	//        buffer is small.
	//      - Embeds the secret near the boundary so the secret's
	//        first bytes land in chunk N and the rest in chunk N+1.
	//      - Tails with enough benign bytes that the trailing
	//        overlap window is exhausted and the secret region is
	//        DEFINITELY flushed to stdout (otherwise the test would
	//        be vacuously passing on a chunk that the helper held
	//        back indefinitely).
	//
	//    The secret is delimited by non-word characters (space and
	//    quote) so the `\b` word-boundary anchor in the scanners'
	//    `sk-ant-` pattern (internal/scanners/builtin.go) matches.
	//    Without delimiters the pattern would not fire because the
	//    surrounding alphanumeric padding bleeds into the leading
	//    `s` and never crosses a word boundary.
	const secret = "sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM"
	// Pad to ~40KiB so the secret is well past the first 32KiB read.
	prefix := strings.Repeat("ABCDEFGH", 5*1024) + " " // 40KiB + delimiter
	suffix := " " + strings.Repeat("XYZW", 1024)       // delimiter + 4KiB trailing pad
	payload := prefix + secret + suffix

	// 4) Drive the real `ai-env shim-helper mcp stream-server`
	//    subprocess. We pipe the payload to its stdin and capture
	//    stdout to assert on the scrubbed bytes.
	cmd := exec.Command(suite.binPath, "shim-helper", "mcp", "stream-server")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(),
		"AI_ENV_CONTROL_SOCKET="+cs.Path(),
		"AI_ENV_HELPER_TOKEN_PATH="+tokenFile,
		"AI_ENV_MCP_SERVER_TOKEN=stream-server-token",
		"AI_ENV_SHIM_DEPTH=0",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start ai-env shim-helper mcp: %v\nstderr=%s", err, stderr.String())
	}
	// Write the payload in two writes so the helper sees a real
	// boundary between the secret's first and last halves. Splitting
	// inside the secret string is the load-bearing setup: if the
	// helper's chunking happens to swallow the entire secret in one
	// read the test would pass by accident; the two-write split
	// guarantees the boundary inside the secret region from the
	// agent's perspective as well.
	cut := strings.Index(payload, secret) + len(secret)/2
	if _, err := io.WriteString(stdin, payload[:cut]); err != nil {
		t.Fatalf("write first half: %v", err)
	}
	// Small sleep so the helper's scrubber has a chance to consume
	// the first read before the second arrives. The scrubber is
	// correct without this sleep (rolling-buffer overlap is what
	// makes boundary splits safe), but the sleep makes the test
	// boundary deterministic on a CI runner with bursty scheduling.
	time.Sleep(50 * time.Millisecond)
	if _, err := io.WriteString(stdin, payload[cut:]); err != nil {
		t.Fatalf("write second half: %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("ai-env shim-helper mcp exited non-zero: %v\nstderr=%s", err, stderr.String())
	}

	// 5) The load-bearing assertion: the raw secret bytes must NOT
	//    appear in the helper's stdout. A regression in the
	//    rolling-buffer overlap (or in the pattern set) would let
	//    the secret through; a regression in the chunk emission
	//    (e.g. dropping the held-back tail at Flush) would surface
	//    as a missing-suffix failure that the secondary checks
	//    below catch.
	got := stdout.String()
	if strings.Contains(got, secret) {
		t.Errorf("raw secret %q survived the streaming scrubber.\nstdout (len=%d) head=%q tail=%q",
			secret, len(got), shortHead(got), shortTail(got))
	}
	if !strings.Contains(got, "[REDACTED") {
		t.Errorf("scrubbed stdout missing [REDACTED ...] sentinel.\nstdout (len=%d) head=%q tail=%q",
			len(got), shortHead(got), shortTail(got))
	}
	// And the benign suffix must still be there: the scrubber must
	// not be a "always-drop-everything-after-the-secret" implementation.
	if !strings.Contains(got, "XYZWXYZW") {
		t.Errorf("benign suffix lost after redaction; the scrubber must preserve non-secret bytes")
	}
}

// shortHead / shortTail bound the error-message output so a failure
// against a 40KiB payload does not flood the test log.
func shortHead(s string) string {
	const n = 64
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func shortTail(s string) string {
	const n = 64
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
