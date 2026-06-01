// Tests for Plan Batch 3.2's per-run MCP config materializer (the
// run-package side of the wiring). The cli-package tests in
// build_gateway_runtime_test.go cover the end-to-end materializer
// (workspace shadow + per-server token mint + agent/real config
// writes); this file covers the lower-level run-package primitives
// the cli wiring delegates to.

package run

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMaterializePerRunMCPConfig_WritesAgentAndRealConfigs verifies
// the materializer writes both files with the expected shapes: the
// agent-visible config wraps each server with the shim helper
// command, embeds the per-server token, and leaves the primary
// control token OUT; the host-only config carries the real upstream
// command.
func TestMaterializePerRunMCPConfig_WritesAgentAndRealConfigs(t *testing.T) {
	dir := newPerRunTestDir(t)
	sock, err := NewControlSocket(ControlSocketOptions{
		RunDir:       dir,
		PrimaryToken: "primary-token-value",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}

	real := map[string]MCPRealServer{
		"filesystem": {
			Command: "/usr/bin/mcp-fs",
			Args:    []string{"--root", "/workspace"},
			Env:     map[string]string{"FOO": "bar"},
		},
		"github": {
			Command: "node",
			Args:    []string{"/opt/mcp-github/index.js"},
		},
	}

	cfg, err := MaterializePerRunMCPConfig(PerRunMCPConfigOptions{
		RunDir:        dir,
		ControlSocket: sock,
		RealServers:   real,
	})
	if err != nil {
		t.Fatalf("MaterializePerRunMCPConfig: %v", err)
	}

	// 1. Agent-visible config exists and contains both servers,
	//    wraps each with the shim helper, embeds the per-server
	//    token, and does NOT contain the primary control token.
	agentCfg, err := ReadMCPServersAgent(dir)
	if err != nil {
		t.Fatalf("ReadMCPServersAgent: %v", err)
	}
	if len(agentCfg.MCPServers) != 2 {
		t.Fatalf("agent config: expected 2 servers, got %d", len(agentCfg.MCPServers))
	}
	for name, srv := range agentCfg.MCPServers {
		if srv.Command != "ai-env" {
			t.Errorf("server %q: command = %q, want %q", name, srv.Command, "ai-env")
		}
		if len(srv.Args) < 3 || srv.Args[0] != "shim-helper" || srv.Args[1] != "mcp" || srv.Args[2] != name {
			t.Errorf("server %q: args = %v, want [shim-helper mcp %s ...]", name, srv.Args, name)
		}
		if srv.Env[MCPHelperEnvControlSocket] != MCPHelperDefaultSocketPath {
			t.Errorf("server %q: socket path = %q, want %q", name, srv.Env[MCPHelperEnvControlSocket], MCPHelperDefaultSocketPath)
		}
		tok, ok := srv.Env[MCPHelperEnvServerToken]
		if !ok || tok == "" {
			t.Errorf("server %q: missing per-server token", name)
		}
		if tok == sock.PrimaryToken() {
			t.Errorf("server %q: per-server token equals primary token (must differ)", name)
		}
	}

	// 2. Agent config file MUST NOT contain the primary token as a
	//    string literal anywhere (Plan Bucket 4 hard requirement).
	rawAgent, err := os.ReadFile(cfg.AgentConfigPath)
	if err != nil {
		t.Fatalf("read agent config: %v", err)
	}
	if string(rawAgent) == "" {
		t.Fatal("agent config file empty")
	}
	if containsString(rawAgent, sock.PrimaryToken()) {
		t.Fatal("agent config contains primary control token (Plan Bucket 4 violation)")
	}

	// 3. Real-server config exists and carries the upstream
	//    commands verbatim.
	realCfg, err := ReadMCPServersReal(dir)
	if err != nil {
		t.Fatalf("ReadMCPServersReal: %v", err)
	}
	if got := realCfg.MCPServers["filesystem"].Command; got != "/usr/bin/mcp-fs" {
		t.Errorf("real filesystem command = %q, want %q", got, "/usr/bin/mcp-fs")
	}
	if got := realCfg.MCPServers["github"].Command; got != "node" {
		t.Errorf("real github command = %q, want %q", got, "node")
	}

	// 4. Real-config file mode is 0o600.
	st, err := os.Stat(cfg.RealConfigPath)
	if err != nil {
		t.Fatalf("stat real config: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("real config mode = %v, want 0600", st.Mode().Perm())
	}

	// 5. Helper-token file exists, mode 0o400, body equals the
	//    primary token (trailing newline allowed).
	tokBlob, err := os.ReadFile(cfg.HelperTokenPath)
	if err != nil {
		t.Fatalf("read helper token: %v", err)
	}
	st, err = os.Stat(cfg.HelperTokenPath)
	if err != nil {
		t.Fatalf("stat helper token: %v", err)
	}
	if st.Mode().Perm() != 0o400 {
		t.Errorf("helper token mode = %v, want 0400", st.Mode().Perm())
	}
	if string(trimTrailing(tokBlob)) != sock.PrimaryToken() {
		t.Errorf("helper token body = %q, want %q", string(tokBlob), sock.PrimaryToken())
	}

	// 6. ServerTokens map matches the agent config's embedded
	//    tokens.
	for name, tok := range cfg.ServerTokens {
		if agentCfg.MCPServers[name].Env[MCPHelperEnvServerToken] != tok {
			t.Errorf("server %q: ServerTokens %q != agent config token %q",
				name, tok, agentCfg.MCPServers[name].Env[MCPHelperEnvServerToken])
		}
	}
}

// TestMaterializePerRunMCPConfig_RejectsEmptyInput exercises the
// fail-loud guards: missing RunDir, missing ControlSocket, empty
// RealServers, empty server name.
func TestMaterializePerRunMCPConfig_RejectsEmptyInput(t *testing.T) {
	dir := newPerRunTestDir(t)
	sock, err := NewControlSocket(ControlSocketOptions{
		RunDir:       dir,
		PrimaryToken: "tok",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}

	good := map[string]MCPRealServer{"a": {Command: "x"}}

	cases := []struct {
		name string
		opts PerRunMCPConfigOptions
	}{
		{"missing RunDir", PerRunMCPConfigOptions{ControlSocket: sock, RealServers: good}},
		{"missing ControlSocket", PerRunMCPConfigOptions{RunDir: dir, RealServers: good}},
		{"empty RealServers", PerRunMCPConfigOptions{RunDir: dir, ControlSocket: sock, RealServers: map[string]MCPRealServer{}}},
		{"empty server name", PerRunMCPConfigOptions{
			RunDir:        dir,
			ControlSocket: sock,
			RealServers:   map[string]MCPRealServer{"": {Command: "x"}},
		}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, err := MaterializePerRunMCPConfig(c.opts); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestMaterializePerRunMCPConfig_RegistersTokensInControlSocket
// covers the per-server scoping requirement: minted tokens land in
// the ControlSocket registry so AuthorizeMCPCall can verify the
// (server_token, server) pair.
func TestMaterializePerRunMCPConfig_RegistersTokensInControlSocket(t *testing.T) {
	dir := newPerRunTestDir(t)
	sock, err := NewControlSocket(ControlSocketOptions{
		RunDir:       dir,
		PrimaryToken: "tok",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}

	real := map[string]MCPRealServer{
		"alpha": {Command: "a"},
		"beta":  {Command: "b"},
	}
	cfg, err := MaterializePerRunMCPConfig(PerRunMCPConfigOptions{
		RunDir:        dir,
		ControlSocket: sock,
		RealServers:   real,
	})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}

	// Sanity: each server got a unique token.
	if cfg.ServerTokens["alpha"] == cfg.ServerTokens["beta"] {
		t.Fatal("alpha and beta have the same token (must differ)")
	}

	// Each token must be registered against ITS server name, not a
	// different one. We can verify this only through the
	// ControlSocket public surface: serverTokens is private. The
	// per-server scoping invariant is exercised end-to-end by the
	// cli-package test that drives AuthorizeMCPCall over a live
	// socket; here we settle for the structural check (tokens
	// differ + tokens match the agent config's embedded values).
	agent, err := ReadMCPServersAgent(dir)
	if err != nil {
		t.Fatalf("ReadMCPServersAgent: %v", err)
	}
	if agent.MCPServers["alpha"].Env[MCPHelperEnvServerToken] != cfg.ServerTokens["alpha"] {
		t.Error("alpha agent token != cfg.ServerTokens[alpha]")
	}
}

// TestShadowWorkspaceMCPConfig_RenamesMCPJSON verifies the
// workspace-level .mcp.json is renamed on Shadow and restored on
// Restore.
func TestShadowWorkspaceMCPConfig_RenamesMCPJSON(t *testing.T) {
	ws := t.TempDir()
	mcpPath := filepath.Join(ws, ".mcp.json")
	if err := os.WriteFile(mcpPath, []byte(`{"mcpServers":{"foo":{}}}`), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	entries, err := ShadowWorkspaceMCPConfig(ws)
	if err != nil {
		t.Fatalf("ShadowWorkspaceMCPConfig: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Kind != ShadowEntryKindMCPJSON {
		t.Errorf("kind = %q, want %q", entries[0].Kind, ShadowEntryKindMCPJSON)
	}

	// Original file must be gone; shadowed must exist.
	if _, err := os.Stat(mcpPath); !os.IsNotExist(err) {
		t.Errorf("original file should be renamed away, got stat err = %v", err)
	}
	if _, err := os.Stat(mcpPath + ".ai-env-shadowed"); err != nil {
		t.Errorf("shadowed file missing: %v", err)
	}

	// Restore puts it back.
	if err := RestoreWorkspaceMCPConfig(entries); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := os.Stat(mcpPath); err != nil {
		t.Errorf("restored file missing: %v", err)
	}
	if _, err := os.Stat(mcpPath + ".ai-env-shadowed"); !os.IsNotExist(err) {
		t.Errorf("shadowed file should be gone after Restore, got stat err = %v", err)
	}
}

// TestShadowWorkspaceMCPConfig_RenamesClaudeSettings verifies the
// `.claude/settings.json` file is shadowed when it carries an
// `mcpServers` key, and left alone otherwise.
func TestShadowWorkspaceMCPConfig_RenamesClaudeSettings(t *testing.T) {
	t.Run("with mcpServers key", func(t *testing.T) {
		ws := t.TempDir()
		claudeDir := filepath.Join(ws, ".claude")
		if err := os.MkdirAll(claudeDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		settingsPath := filepath.Join(claudeDir, "settings.json")
		body := map[string]any{
			"theme":      "dark",
			"mcpServers": map[string]any{"foo": map[string]any{}},
		}
		blob, _ := json.Marshal(body)
		if err := os.WriteFile(settingsPath, blob, 0o644); err != nil {
			t.Fatalf("write settings.json: %v", err)
		}

		entries, err := ShadowWorkspaceMCPConfig(ws)
		if err != nil {
			t.Fatalf("Shadow: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		if entries[0].Kind != ShadowEntryKindClaudeSettingsMCPServers {
			t.Errorf("kind = %q, want %q", entries[0].Kind, ShadowEntryKindClaudeSettingsMCPServers)
		}
		if _, err := os.Stat(settingsPath); !os.IsNotExist(err) {
			t.Errorf("settings.json should be renamed away, got err = %v", err)
		}
	})

	t.Run("without mcpServers key", func(t *testing.T) {
		ws := t.TempDir()
		claudeDir := filepath.Join(ws, ".claude")
		if err := os.MkdirAll(claudeDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		settingsPath := filepath.Join(claudeDir, "settings.json")
		body := map[string]any{"theme": "dark"}
		blob, _ := json.Marshal(body)
		if err := os.WriteFile(settingsPath, blob, 0o644); err != nil {
			t.Fatalf("write settings.json: %v", err)
		}

		entries, err := ShadowWorkspaceMCPConfig(ws)
		if err != nil {
			t.Fatalf("Shadow: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("expected 0 entries (no mcpServers key), got %d", len(entries))
		}
		// Settings file must be untouched.
		if _, err := os.Stat(settingsPath); err != nil {
			t.Errorf("settings.json should be untouched, got err = %v", err)
		}
	})
}

// TestShadowWorkspaceMCPConfig_NoFiles verifies the no-files branch:
// a workspace with neither .mcp.json nor .claude/settings.json
// produces an empty slice.
func TestShadowWorkspaceMCPConfig_NoFiles(t *testing.T) {
	ws := t.TempDir()
	entries, err := ShadowWorkspaceMCPConfig(ws)
	if err != nil {
		t.Fatalf("Shadow: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// TestShadowWorkspaceMCPConfig_StaleShadowFails verifies the
// crashed-mid-run protection: if the workspace already carries a
// `.ai-env-shadowed` file (a previous run did not restore) AND a
// fresh `.mcp.json`, the next Shadow call fails rather than silently
// overwriting.
func TestShadowWorkspaceMCPConfig_StaleShadowFails(t *testing.T) {
	ws := t.TempDir()
	mcpPath := filepath.Join(ws, ".mcp.json")
	if err := os.WriteFile(mcpPath, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}
	if err := os.WriteFile(mcpPath+".ai-env-shadowed", []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write stale shadow: %v", err)
	}
	if _, err := ShadowWorkspaceMCPConfig(ws); err == nil {
		t.Fatal("expected error on stale shadow, got nil")
	}
}

// containsString is a substring check used by the test that asserts
// the primary token does not leak into the agent-visible config.
func containsString(haystack []byte, needle string) bool {
	if needle == "" {
		return false
	}
	return indexBytes(haystack, []byte(needle)) >= 0
}

// indexBytes is a tiny replacement for bytes.Index that avoids
// importing the bytes package in test files.
func indexBytes(hay, needle []byte) int {
	if len(needle) == 0 || len(hay) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// trimTrailing strips trailing whitespace bytes (newline / space /
// tab / cr) from buf so the token-equality assertion does not have
// to account for the trailing newline the materializer writes.
func trimTrailing(buf []byte) []byte {
	end := len(buf)
	for end > 0 {
		c := buf[end-1]
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			end--
			continue
		}
		break
	}
	return buf[:end]
}

// newPerRunTestDir materializes a run directory via the production
// helper. Centralized here so the tests share one fixture.
func newPerRunTestDir(t *testing.T) string {
	t.Helper()
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-200000-aaaaaa"
	dir, err := CreateRunDirectory(aiEnvDir, runID, time.Date(2026, 6, 1, 20, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return dir.Path
}
