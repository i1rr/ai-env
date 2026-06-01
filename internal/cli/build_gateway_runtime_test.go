// Tests for Plan Batch 3.2 (Per-run MCP config + per-server tokens +
// workspace shadowing). The Plan §3.2 acceptance criteria list four
// named tests:
//
//   - TestMCPConfigGeneration_WrapsEachServer
//   - TestMCPGateway_AgentCannotCallAcrossServers
//   - TestMCPGateway_PrimaryTokenNotInAgentEnv
//   - TestSupervisor_WorkspaceMCPConfigNeutralized
//
// All four live here because they exercise the cli-package
// materialization site (the seam the supervisor's pre-launch step 9
// drives). The lower-level run-package primitives (the file writers,
// the workspace-shadow rename) are exercised separately in
// internal/run/mcp_per_run_config_test.go.

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/mcp"
	"github.com/rivan1986/ai-env/internal/run"
)

// TestMCPConfigGeneration_WrapsEachServer is the first Plan §3.2
// acceptance test: the materializer wraps each registered MCP
// server with the shim helper command line and embeds the per-
// server token under the AI_ENV_MCP_SERVER_TOKEN env key. The shape
// must match the Plan example verbatim so the agent CLI can consume
// the file without further translation.
func TestMCPConfigGeneration_WrapsEachServer(t *testing.T) {
	dir := newTestRunDir(t)
	sock, err := run.NewControlSocket(run.ControlSocketOptions{
		RunDir:       dir,
		PrimaryToken: "primary-token-value",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}

	real := map[string]run.MCPRealServer{
		"filesystem": {Command: "/opt/mcp-fs", Args: []string{"--root", "/ws"}},
		"github":     {Command: "node", Args: []string{"/opt/mcp-gh.js"}},
	}

	mat, err := MaterializeRunGateway(MaterializeRunGatewayOptions{
		RunDir:        dir,
		ControlSocket: sock,
		RealServers:   real,
	})
	if err != nil {
		t.Fatalf("MaterializeRunGateway: %v", err)
	}

	agent, err := run.ReadMCPServersAgent(dir)
	if err != nil {
		t.Fatalf("ReadMCPServersAgent: %v", err)
	}
	if len(agent.MCPServers) != 2 {
		t.Fatalf("expected 2 server entries, got %d", len(agent.MCPServers))
	}

	for name, srv := range agent.MCPServers {
		// Plan example shape:
		//   "command": "ai-env",
		//   "args": ["shim-helper", "mcp", "<name>"]
		if srv.Command != "ai-env" {
			t.Errorf("server %q: command = %q, want %q", name, srv.Command, "ai-env")
		}
		want := []string{"shim-helper", "mcp", name}
		if len(srv.Args) != len(want) {
			t.Errorf("server %q: args = %v, want %v", name, srv.Args, want)
			continue
		}
		for i, a := range want {
			if srv.Args[i] != a {
				t.Errorf("server %q: args[%d] = %q, want %q", name, i, srv.Args[i], a)
			}
		}
		// Env shape: per-server token + control socket path.
		if srv.Env[run.MCPHelperEnvServerToken] == "" {
			t.Errorf("server %q: missing per-server token env entry", name)
		}
		if srv.Env[run.MCPHelperEnvControlSocket] != run.MCPHelperDefaultSocketPath {
			t.Errorf("server %q: socket path env = %q, want %q",
				name, srv.Env[run.MCPHelperEnvControlSocket], run.MCPHelperDefaultSocketPath)
		}
	}

	// PerRunConfig surfaces the same token map.
	if len(mat.PerRunConfig.ServerTokens) != 2 {
		t.Errorf("PerRunConfig.ServerTokens len = %d, want 2", len(mat.PerRunConfig.ServerTokens))
	}
}

// TestMCPGateway_AgentCannotCallAcrossServers is the second Plan
// §3.2 acceptance test: an agent that learns one server's token
// CANNOT use it against a different server name. The control
// socket's AuthorizeMCPCall handler verifies the (server_token,
// server) pair before forwarding to the gateway authorizer; this
// test drives the live socket end-to-end with a cross-server token
// to confirm the verdict is "block: server_token mismatch".
func TestMCPGateway_AgentCannotCallAcrossServers(t *testing.T) {
	// AF_UNIX socket paths are bounded (~104 bytes on macOS, ~108
	// on Linux). The newTestRunDir helper produces a deeply-nested
	// path under t.TempDir(); we use a shorter dir for the live-
	// socket test so the bind syscall stays within the platform
	// limit. The materializer's writes still land under this dir
	// (it carries no nested-path requirements).
	dir := newShortRunDir(t)

	// Stand up a real control socket so we exercise the full RPC
	// path (Hello + AuthorizeMCPCall). The MCPAuthorizer we wire is
	// a Permissive sentinel because we only need to confirm the
	// control socket's token-pair check rejects the cross-server
	// attack BEFORE reaching the authorizer.
	sock, err := run.NewControlSocket(run.ControlSocketOptions{
		RunDir:       dir,
		PrimaryToken: "primary-token",
		MCPAuthorizer: run.MCPAuthorizerFunc(func(server, op string, body []byte) run.ControlSocketResponse {
			// If the control socket ever called us, the
			// per-server pair check would have already passed —
			// the test asserts the OPPOSITE (the call must be
			// rejected before reaching here). We sentinel with an
			// "allow" so a regression where the cross-server
			// rejection is missing surfaces as a false positive
			// downstream.
			return run.ControlSocketResponse{Decision: "allow", Reason: "sentinel allow"}
		}),
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sock.Start(ctx); err != nil {
		t.Fatalf("ControlSocket.Start: %v", err)
	}
	t.Cleanup(func() { _ = sock.Stop() })

	// Materialize per-run config so two distinct per-server tokens
	// are minted into the registry.
	real := map[string]run.MCPRealServer{
		"alpha": {Command: "a"},
		"beta":  {Command: "b"},
	}
	mat, err := MaterializeRunGateway(MaterializeRunGatewayOptions{
		RunDir:        dir,
		ControlSocket: sock,
		RealServers:   real,
	})
	if err != nil {
		t.Fatalf("MaterializeRunGateway: %v", err)
	}

	alphaToken := mat.PerRunConfig.ServerTokens["alpha"]
	if alphaToken == "" {
		t.Fatal("alpha token empty")
	}

	// Drive an RPC: present alpha's token against "beta" name. The
	// control socket must reject with reason="server_token
	// mismatch".
	resp := sendAuthorizeMCPCall(t, sock.Path(), sock.PrimaryToken(), alphaToken, "beta", "tools/call", nil)
	if resp.Decision != "block" {
		t.Fatalf("decision = %q, want block (cross-server token must be rejected)", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "server_token mismatch") {
		t.Errorf("reason = %q, want substring %q", resp.Reason, "server_token mismatch")
	}

	// Sanity: alpha's token against alpha name passes the pair
	// check and reaches the sentinel authorizer (which returns
	// allow). This confirms the rejection above is targeted at the
	// pair mismatch, not at a broader plumbing bug.
	respGood := sendAuthorizeMCPCall(t, sock.Path(), sock.PrimaryToken(), alphaToken, "alpha", "tools/call", nil)
	if respGood.Decision != "allow" {
		t.Errorf("matching pair decision = %q, want allow (sentinel)", respGood.Decision)
	}
}

// TestMCPGateway_PrimaryTokenNotInAgentEnv is the third Plan §3.2
// acceptance test: the primary control_token MUST NOT appear in the
// agent-visible `mcp-servers.json` file (neither as a value nor as a
// key). The helper reads it from the side-band `.helper-token` file
// the agent cannot access.
func TestMCPGateway_PrimaryTokenNotInAgentEnv(t *testing.T) {
	dir := newTestRunDir(t)
	sock, err := run.NewControlSocket(run.ControlSocketOptions{
		RunDir:       dir,
		PrimaryToken: "super-secret-primary-control-token-value",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}

	mat, err := MaterializeRunGateway(MaterializeRunGatewayOptions{
		RunDir:        dir,
		ControlSocket: sock,
		RealServers: map[string]run.MCPRealServer{
			"filesystem": {Command: "/usr/bin/mcp-fs"},
		},
	})
	if err != nil {
		t.Fatalf("MaterializeRunGateway: %v", err)
	}

	// Read the file raw — bypass the decoder so a sneaky key whose
	// value embeds the primary token is still caught.
	raw, err := os.ReadFile(mat.PerRunConfig.AgentConfigPath)
	if err != nil {
		t.Fatalf("read agent config: %v", err)
	}
	if strings.Contains(string(raw), sock.PrimaryToken()) {
		t.Fatalf("agent config %s contains primary control token (Plan Bucket 4 violation)", mat.PerRunConfig.AgentConfigPath)
	}
	// The env key MUST also not match AI_ENV_CONTROL_TOKEN (the
	// primary's canonical key name in helper env).
	if strings.Contains(string(raw), "AI_ENV_CONTROL_TOKEN") {
		t.Fatalf("agent config contains AI_ENV_CONTROL_TOKEN env key (Plan Bucket 4 violation)")
	}

	// Helper-token file MUST contain the primary token (this is the
	// side-band delivery channel the helper consumes).
	helperBlob, err := os.ReadFile(mat.PerRunConfig.HelperTokenPath)
	if err != nil {
		t.Fatalf("read helper token: %v", err)
	}
	if !strings.Contains(string(helperBlob), sock.PrimaryToken()) {
		t.Fatalf("helper token file does not contain primary token (side-band delivery broken)")
	}
}

// TestSupervisor_WorkspaceMCPConfigNeutralized is the fourth Plan
// §3.2 acceptance test: a workspace with `.mcp.json` present pre-
// run gets the file renamed at Create-time (here, materialization),
// and the supervisor emits one `mcp_config_neutralized` lifecycle
// verb per neutralized file; Destroy-time (here, Restore) renames
// the file back.
func TestSupervisor_WorkspaceMCPConfigNeutralized(t *testing.T) {
	dir := newTestRunDir(t)
	workspace := t.TempDir()

	// Workspace carries .mcp.json pre-run.
	mcpPath := filepath.Join(workspace, ".mcp.json")
	if err := os.WriteFile(mcpPath, []byte(`{"mcpServers":{"foo":{}}}`), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	// Plus a .claude/settings.json with mcpServers key.
	claudeDir := filepath.Join(workspace, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	settingsBlob := []byte(`{"theme":"dark","mcpServers":{"bar":{}}}`)
	if err := os.WriteFile(settingsPath, settingsBlob, 0o644); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	sock, err := run.NewControlSocket(run.ControlSocketOptions{
		RunDir:       dir,
		PrimaryToken: "tok",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}

	// Capture verb emissions so we can assert on the
	// `mcp_config_neutralized` records the supervisor would land
	// against lifecycle.jsonl.
	var emitted []emittedVerb
	sink := func(verb run.LifecycleVerb, metadata map[string]string) error {
		emitted = append(emitted, emittedVerb{verb: verb, metadata: metadata})
		return nil
	}

	mat, err := MaterializeRunGateway(MaterializeRunGatewayOptions{
		RunDir:        dir,
		ControlSocket: sock,
		RealServers: map[string]run.MCPRealServer{
			"filesystem": {Command: "/usr/bin/mcp-fs"},
		},
		Workspace: workspace,
		EventSink: sink,
	})
	if err != nil {
		t.Fatalf("MaterializeRunGateway: %v", err)
	}

	// Both files must be renamed.
	if _, err := os.Stat(mcpPath); !os.IsNotExist(err) {
		t.Errorf(".mcp.json should be shadowed, stat err = %v", err)
	}
	if _, err := os.Stat(settingsPath); !os.IsNotExist(err) {
		t.Errorf("settings.json should be shadowed, stat err = %v", err)
	}
	if _, err := os.Stat(mcpPath + ".ai-env-shadowed"); err != nil {
		t.Errorf("shadowed .mcp.json missing: %v", err)
	}
	if _, err := os.Stat(settingsPath + ".ai-env-shadowed"); err != nil {
		t.Errorf("shadowed settings.json missing: %v", err)
	}

	// Two verbs emitted, both `mcp_config_neutralized`.
	if len(emitted) != 2 {
		t.Fatalf("emitted verbs = %d, want 2", len(emitted))
	}
	for _, e := range emitted {
		if e.verb != run.LifecycleVerbMCPConfigNeutralized {
			t.Errorf("verb = %q, want %q", e.verb, run.LifecycleVerbMCPConfigNeutralized)
		}
		if e.metadata["original"] == "" {
			t.Error("metadata missing original")
		}
		if e.metadata["shadowed"] == "" {
			t.Error("metadata missing shadowed")
		}
		if e.metadata["kind"] == "" {
			t.Error("metadata missing kind")
		}
	}

	// Restore at teardown renames both files back.
	if err := mat.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := os.Stat(mcpPath); err != nil {
		t.Errorf("Restore did not put .mcp.json back: %v", err)
	}
	if _, err := os.Stat(settingsPath); err != nil {
		t.Errorf("Restore did not put settings.json back: %v", err)
	}
	if _, err := os.Stat(mcpPath + ".ai-env-shadowed"); !os.IsNotExist(err) {
		t.Errorf("shadowed .mcp.json should be removed after Restore, stat err = %v", err)
	}
}

// TestGatewayMCPAuthorizer_ForwardsToGateway is a happy-path smoke
// test for the GatewayMCPAuthorizer adapter: a body that decodes to
// an mcp.CallRequest the gateway allows surfaces as
// decision="allow".
func TestGatewayMCPAuthorizer_ForwardsToGateway(t *testing.T) {
	registry := newTestRegistry(t)
	gw, err := mcp.NewGateway(registry, nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	authz, err := NewGatewayMCPAuthorizer(gw)
	if err != nil {
		t.Fatalf("NewGatewayMCPAuthorizer: %v", err)
	}

	// The fixture server "filesystem" has Policy="allow" and no
	// declared scope, so a call with a tool name passes through to
	// the Step 5 "allow" branch.
	body, _ := json.Marshal(map[string]any{"tool": "read_file"})
	resp := authz.Authorize("filesystem", "tools/call", body)
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}
}

// TestGatewayMCPAuthorizer_MalformedBodyBlocked verifies the adapter
// fails closed on a malformed JSON body rather than reaching the
// gateway with garbage fields.
func TestGatewayMCPAuthorizer_MalformedBodyBlocked(t *testing.T) {
	registry := newTestRegistry(t)
	gw, err := mcp.NewGateway(registry, nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	authz, err := NewGatewayMCPAuthorizer(gw)
	if err != nil {
		t.Fatalf("NewGatewayMCPAuthorizer: %v", err)
	}

	resp := authz.Authorize("filesystem", "tools/call", []byte("not json"))
	if resp.Decision != "block" {
		t.Errorf("decision = %q, want block (malformed body)", resp.Decision)
	}
}

// --- helpers ----------------------------------------------------------------

// emittedVerb records one lifecycle verb the materializer emitted
// through the test sink. Stored as a value type so the test slice
// stays simple.
type emittedVerb struct {
	verb     run.LifecycleVerb
	metadata map[string]string
}

// newShortRunDir materializes a runDir under a short path so the
// per-run control socket's AF_UNIX bind stays within the platform's
// path-length limit (~104 bytes on macOS, ~108 on Linux). t.TempDir
// produces a deeply-nested path that is fine for file writes but too
// long for a bind syscall.
func newShortRunDir(t *testing.T) string {
	t.Helper()
	// Use os.MkdirTemp directly with the small system tmp dir
	// (/tmp on POSIX). t.Cleanup removes it at test end.
	root, err := os.MkdirTemp("/tmp", "ai-env-rt-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	// We do NOT call run.CreateRunDirectory here because the
	// materializer does not depend on the per-run placeholder
	// files; the lighter-weight dir is enough.
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("mkdirall: %v", err)
	}
	return root
}

// sendAuthorizeMCPCall dials the supplied socket path, performs the
// Hello handshake, sends one AuthorizeMCPCall frame with the given
// (server_token, server, op, body), and returns the parsed
// response. Fails the test on any I/O error so the test bodies stay
// readable.
func sendAuthorizeMCPCall(t *testing.T, sockPath, primary, serverToken, server, op string, body []byte) run.ControlSocketResponse {
	t.Helper()
	conn, err := net.DialTimeout("unix", sockPath, 1*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", sockPath, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	br := bufio.NewReader(conn)
	enc := json.NewEncoder(conn)

	// Hello.
	if err := enc.Encode(map[string]any{
		"method": "Hello",
		"params": map[string]any{
			"control_token":    primary,
			"client_version":   "test/0.1",
			"protocol_version": 1,
		},
	}); err != nil {
		t.Fatalf("send Hello: %v", err)
	}
	if _, err := br.ReadBytes('\n'); err != nil {
		t.Fatalf("read Hello response: %v", err)
	}

	// AuthorizeMCPCall.
	params := map[string]any{
		"control_token": primary,
		"server_token":  serverToken,
		"server":        server,
		"op":            op,
	}
	if body != nil {
		params["body"] = json.RawMessage(body)
	}
	if err := enc.Encode(map[string]any{"method": "AuthorizeMCPCall", "params": params}); err != nil {
		t.Fatalf("send AuthorizeMCPCall: %v", err)
	}
	line, err := br.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read AuthorizeMCPCall response: %v", err)
	}
	var resp run.ControlSocketResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode AuthorizeMCPCall response: %v", err)
	}
	return resp
}
