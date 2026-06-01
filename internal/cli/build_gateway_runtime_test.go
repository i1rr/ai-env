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

// TestMCPGateway_AllPayloadFieldsRedacted is the Plan Batch 3.4
// acceptance test: an MCP request whose JSON-RPC body contains a
// secret is blocked by the gateway's per-direction detector, a
// `gateway_secret_blocked` lifecycle verb is emitted, and every
// payload-derived field on the on-disk MCPCallRecord (Reason, Path,
// Operation, Repo, ResolvedPath, Snippet, Args) is rewritten to the
// redaction sentinel before the record is logged.
//
// The test drives the GatewayMCPAuthorizer directly (the same adapter
// the control socket's AuthorizeMCPCall handler forwards to) so the
// full block path is exercised end-to-end. The body carries a
// canonical Anthropic key (sk-ant-...) embedded inside the
// "arguments" field of a tools/call payload — the highest-risk
// exfiltration vector per the plan.
func TestMCPGateway_AllPayloadFieldsRedacted(t *testing.T) {
	registry := newTestRegistry(t)

	// Capture every CallRecord the authorizer's blocked-call logger
	// receives so we can assert on the redacted on-disk shape. A
	// custom CallLogger is the right test surface because it sees
	// exactly the record the production MCPCallLogger would forward
	// to the run-scoped MCPCallsWriter, without the I/O.
	var logged []mcp.CallRecord
	logger := mcp.CallLoggerFunc(func(rec mcp.CallRecord) error {
		logged = append(logged, rec)
		return nil
	})

	gw, err := mcp.NewGateway(registry, &mcp.GatewayOptions{
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	// Capture lifecycle verbs so the test can assert that
	// `gateway_secret_blocked` is emitted with the canonical metadata
	// keys (server / operation / pattern / finding_id).
	var emitted []emittedVerb
	sink := func(verb run.LifecycleVerb, metadata map[string]string) error {
		emitted = append(emitted, emittedVerb{verb: verb, metadata: metadata})
		return nil
	}

	authz, err := NewGatewayMCPAuthorizerWithOptions(gw, &GatewayMCPAuthorizerOptions{
		BlockedLogger: logger,
		EventSink:     sink,
		Now: func() time.Time {
			return time.Date(2026, 6, 1, 12, 34, 56, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("NewGatewayMCPAuthorizerWithOptions: %v", err)
	}

	// Build a tools/call body whose payload carries a secret across
	// MULTIPLE payload-derived fields. The plan's enumeration covers
	// Reason / Path / Operation / Repo / ResolvedPath / Snippet /
	// Args; the body sits in args, plus we set path / repo /
	// operation so the test can verify each field is independently
	// redacted on the on-disk record.
	secret := "sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM"
	body, _ := json.Marshal(map[string]any{
		"tool":      "read_file",
		"path":      "/workspace/secret-" + secret + ".txt",
		"repo":      "owner/repo-with-" + secret,
		"operation": "write-" + secret,
		"args": map[string]any{
			"file_contents": "ANTHROPIC_KEY=" + secret,
		},
	})

	resp := authz.Authorize("filesystem", "tools/call", body)

	// 1. Decision must be block.
	if resp.Decision != "block" {
		t.Fatalf("decision = %q, want block", resp.Decision)
	}
	// Reason must reference the matched pattern by name and must
	// NOT carry the raw secret. The synthesized Reason text itself
	// does not embed a redactable substring (the block handler
	// references only the pattern name), so the absence of the
	// sentinel here is acceptable — the on-disk Path / Args fields
	// carry the sentinel where the secret-derived data landed.
	if strings.Contains(resp.Reason, secret) {
		t.Errorf("response Reason leaked the raw secret: %q", resp.Reason)
	}
	if !strings.Contains(resp.Reason, "Anthropic") {
		t.Errorf("response Reason should reference matched pattern name: %q", resp.Reason)
	}

	// 2. One CallRecord landed on the blocked-call logger.
	if len(logged) != 1 {
		t.Fatalf("expected 1 CallRecord, got %d", len(logged))
	}
	rec := logged[0]

	// 3. Every payload-derived field on the record must NOT carry
	//    the raw secret (Plan Batch 3.4 closes the enumeration:
	//    Reason / Path / Operation / Repo / ResolvedPath / Snippet
	//    / Args). Fields that sourced from a secret-carrying body
	//    fragment (Path, Repo, Operation, ResolvedPath, Args) must
	//    additionally contain the sentinel; Reason and Snippet are
	//    synthesized by the block handler and only carry the
	//    sentinel when the block handler's text itself embeds a
	//    redactable substring — but they MUST still be passed
	//    through the redactor (defense-in-depth) so a future
	//    addition that lets a secret leak into a synthesized field
	//    is caught.
	payloadFields := map[string]string{
		"Reason":       rec.Reason,
		"Path":         rec.Path,
		"Operation":    rec.Operation,
		"Repo":         rec.Repo,
		"ResolvedPath": rec.ResolvedPath,
		"Snippet":      rec.Snippet,
		"Args":         rec.Args,
	}
	// Fields sourced from body fragments that DO carry the secret;
	// these must contain the sentinel after redaction.
	sentinelRequired := map[string]bool{
		"Path":         true,
		"Operation":    true,
		"Repo":         true,
		"ResolvedPath": true,
		"Args":         true,
	}
	for name, value := range payloadFields {
		if value == "" {
			t.Errorf("payload-derived field %s is empty; want redacted value", name)
			continue
		}
		if strings.Contains(value, secret) {
			t.Errorf("payload-derived field %s leaked the raw secret: %q", name, value)
		}
		if sentinelRequired[name] && !strings.Contains(value, "[REDACTED") {
			t.Errorf("payload-derived field %s missing sentinel: %q", name, value)
		}
	}

	// 4. Stage is "call" (not "launch") and Decision is "block".
	if rec.Stage != mcp.CallStageCall {
		t.Errorf("Stage = %q, want %q", rec.Stage, mcp.CallStageCall)
	}
	if rec.Decision != "block" {
		t.Errorf("Decision = %q, want block", rec.Decision)
	}

	// 5. Lifecycle verb emitted with the canonical metadata keys.
	if len(emitted) != 1 {
		t.Fatalf("expected 1 lifecycle verb, got %d", len(emitted))
	}
	if emitted[0].verb != run.LifecycleVerbGatewaySecretBlocked {
		t.Errorf("verb = %q, want %q", emitted[0].verb, run.LifecycleVerbGatewaySecretBlocked)
	}
	for _, key := range []string{"server", "operation", "pattern", "finding_id"} {
		if emitted[0].metadata[key] == "" {
			t.Errorf("metadata missing required key %q", key)
		}
	}
	// The pattern name in the metadata must match a known built-in
	// rule (the matched Anthropic prefix).
	if !strings.Contains(emitted[0].metadata["pattern"], "Anthropic") {
		t.Errorf("metadata pattern = %q, want Anthropic-related match", emitted[0].metadata["pattern"])
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
