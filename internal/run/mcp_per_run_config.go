// Per-run MCP config + helper-token materialization (Plan Batch 3.2).
//
// This file owns the on-disk artifacts the supervisor materializes at
// pre-launch step 9 (Plan §5.5) so the agent CLI's MCP-server-spawn
// machinery sees a per-run, ai-env-controlled config rather than the
// workspace-local `.mcp.json` it would otherwise read:
//
//   - `<runDir>/mcp-servers.json` (mode 0644, agent-visible). This is
//     the file the agent CLI consumes. Each entry points at the
//     `ai-env shim-helper mcp <name>` subcommand and embeds the
//     per-server `AI_ENV_MCP_SERVER_TOKEN`. The primary
//     `AI_ENV_CONTROL_TOKEN` is deliberately NOT in this file (Plan
//     Bucket 4 locked decision); the helper reads the primary token
//     from the side-band `.helper-token` file the agent cannot read.
//
//   - `<runDir>/ipc/mcp-servers.real.json` (mode 0600, container-UID-
//     owned, agent-unreadable). This file carries the REAL upstream
//     server commands the helper exec's after the AuthorizeMCPCall
//     handshake succeeds. The agent CLI never sees this file: it
//     lives under `<runDir>/ipc/` which the supervisor's bind-mount
//     split (Plan Batch 0.5) exposes under `/var/run/ai-env/` inside
//     the sandbox, BUT the file mode is 0600 owned by the container
//     UID, so the agent (which runs as a DIFFERENT UID) cannot read
//     it. The helper, which the supervisor spawns under the container
//     UID, can.
//
//   - `<runDir>/ipc/.helper-token` (mode 0400, container-UID-owned,
//     agent-unreadable). The side-band primary-token delivery file.
//     The helper reads it on Hello to present the primary
//     `control_token`; the agent, running as a different UID, gets
//     EPERM when it tries to open the same file.
//
// Lifecycle: the supervisor's pre-launch step 9 calls
// `MaterializePerRunMCPConfig` once per run AFTER the control socket
// is up (so per-server tokens can be minted via
// ControlSocket.MintServerToken). The returned bundle records the
// paths so the supervisor's teardown step 6 can emit
// `mcp_config_neutralized` reversal events if needed (the workspace
// shadow side of Batch 3.2 lives in workspace_mcp_shadow.go).
//
// Concurrency: these functions are NOT safe for concurrent use across
// the same runDir — the supervisor calls them serially at pre-launch
// time, never from multiple goroutines.

package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// mcpServersAgentFileName is the basename of the agent-visible per-run
// MCP config. The agent CLI's `--mcp-config` flag (or equivalent) is
// pointed at this file by the supervisor; the file lives at the run
// directory root (NOT under `<runDir>/ipc/`) because the supervisor
// passes its absolute path via env to the agent's launcher rather than
// surfacing it through a bind-mount.
const mcpServersAgentFileName = "mcp-servers.json"

// mcpServersAgentFileMode is the mode the agent-visible config is
// written with. 0644 because the per-server tokens it embeds are
// designed to be agent-readable (the agent CLI passes the token to the
// helper as an env var on spawn), and the file does NOT carry the
// primary control token. The fail-closed property is enforced by the
// `AuthorizeMCPCall` handler requiring BOTH tokens.
const mcpServersAgentFileMode os.FileMode = 0o644

// mcpServersRealFileName is the basename of the host-only real-server
// command map. Lives under `<runDir>/ipc/` (the directory the
// supervisor bind-mounts into the sandbox at /var/run/ai-env/), so the
// helper inside the sandbox can read it via the canonical path. Mode
// 0600 keeps the agent (different UID) out.
const mcpServersRealFileName = "mcp-servers.real.json"

// mcpServersRealFileMode is the mode the real-server map is written
// with. 0600 + chown to container UID is the Plan Bucket 4 locked
// requirement: only the helper (running as container UID) reads it.
const mcpServersRealFileMode os.FileMode = 0o600

// helperTokenFileName is the basename of the side-band primary-token
// file. The supervisor writes the primary `control_token` here so the
// helper (which spawns under container UID) can read it on Hello. The
// agent (different UID) gets EPERM.
const helperTokenFileName = ".helper-token"

// helperTokenFileMode is the mode the side-band token file is written
// with. 0400 + chown to container UID is the Plan Batch 0.5 / Bucket
// 4 locked requirement: read-only by the container UID, invisible to
// everyone else.
const helperTokenFileMode os.FileMode = 0o400

// ipcSubdir is the basename of the per-run IPC subdirectory under
// runDir. Mirrors the constant the BindMount split (Plan Batch 0.5)
// references; centralizing it here keeps the per-run MCP config writer
// and the workspace-shadow path agreeing on the layout without
// importing each other.
const ipcSubdir = "ipc"

// ipcSubdirMode is the mode the per-run IPC subdirectory is created
// with. 0o755 so the helper (container UID) can list the directory
// and read the entries within (the entries themselves are 0o600 /
// 0o400 with container-UID ownership). The directory mode is not
// sensitive: the sensitive bits are the file modes.
const ipcSubdirMode os.FileMode = 0o755

// MCPHelperEnvKey is the env-var name the helper consumes on spawn to
// know which per-server token to present alongside the primary
// control token on AuthorizeMCPCall. The supervisor embeds the token
// value under this key in the agent-visible `mcp-servers.json`.
// Mirrors `shimHelperEnvServerToken` in cmd/ai-env/shim_helper.go;
// duplicated here so the run package does not have to import cmd.
const MCPHelperEnvServerToken = "AI_ENV_MCP_SERVER_TOKEN"

// MCPHelperEnvControlSocket is the env-var name the helper consumes
// to know where the control socket is bound. The supervisor embeds
// the in-sandbox path under this key so the helper can connect
// without re-deriving the layout. Mirrors `shimHelperEnvSocket`.
const MCPHelperEnvControlSocket = "AI_ENV_CONTROL_SOCKET"

// MCPHelperDefaultSocketPath is the canonical in-sandbox path the
// supervisor bind-mounts the control socket at (Plan Batch 0.5). The
// agent-visible `mcp-servers.json` defaults to this value when the
// caller does not override it.
const MCPHelperDefaultSocketPath = "/var/run/ai-env/control.sock"

// MCPRealServer describes one upstream MCP server's launch command.
// The supervisor authors one of these per registered server in the
// per-run runtime registry (built from the loaded mcp.yaml plus the
// operator's resolved launch metadata) and the helper exec's the
// command after the AuthorizeMCPCall handshake succeeds.
//
// The struct intentionally mirrors the on-wire shape the agent CLI
// would have used for a workspace-local `.mcp.json` entry (command,
// args, env), so the helper's exec path can re-use the same plumbing
// the agent CLI would have used had we not interposed. The agent
// never reads this struct — it lives in the host-only
// `mcp-servers.real.json` file.
type MCPRealServer struct {
	// Command is the absolute path (or PATH-resolvable program name)
	// of the upstream MCP server binary. Required.
	Command string `json:"command"`

	// Args is the rest of argv (without the program). May be nil.
	Args []string `json:"args,omitempty"`

	// Env is the extra environment the helper splices into the
	// upstream server's launch env. Nil leaves the helper's inherited
	// env unchanged.
	Env map[string]string `json:"env,omitempty"`
}

// MCPAgentServer describes one entry under the `mcpServers` key in
// the agent-visible `mcp-servers.json` file. The shape matches the
// `mcp-servers.json` format the agent CLI consumes verbatim: command
// + args + env. The supervisor always sets `command = "ai-env"` and
// `args = ["shim-helper", "mcp", "<name>"]` so the helper interposes
// every call; the env carries the per-server token and the control
// socket path.
type MCPAgentServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// MCPAgentConfig is the top-level shape of the agent-visible
// `mcp-servers.json` file. The `mcpServers` map key is the server
// name (matches the registry); the value carries the helper's launch
// command. Mirrors the master plan's example verbatim so an operator
// who reads the plan can author the file without guessing at struct-
// field translations.
type MCPAgentConfig struct {
	MCPServers map[string]MCPAgentServer `json:"mcpServers"`
}

// MCPRealConfig is the top-level shape of the host-only
// `mcp-servers.real.json` file. Mirrors MCPAgentConfig's outer shape
// so a reader (the helper) can decode either file with the same
// envelope; the inner value differs (MCPRealServer vs MCPAgentServer)
// to keep the two surfaces type-safe.
type MCPRealConfig struct {
	MCPServers map[string]MCPRealServer `json:"mcpServers"`
}

// PerRunMCPConfig is the value type MaterializePerRunMCPConfig returns.
// The supervisor holds one of these for the lifetime of the run; the
// recorded paths feed the lifecycle verb metadata
// (`LifecycleVerbGatewayStarted.config_path`) and any future teardown
// cleanup.
type PerRunMCPConfig struct {
	// AgentConfigPath is the absolute path of the agent-visible
	// `mcp-servers.json` file. The supervisor passes this to the
	// agent CLI via the per-CLI `--mcp-config` flag (or equivalent).
	AgentConfigPath string

	// RealConfigPath is the absolute path of the host-only
	// `mcp-servers.real.json` file. The helper reads it from inside
	// the sandbox via the canonical
	// `/var/run/ai-env/mcp-servers.real.json` bind-mount target.
	RealConfigPath string

	// HelperTokenPath is the absolute path of the side-band
	// `.helper-token` file (under `<runDir>/ipc/`). The helper reads
	// it from inside the sandbox via `/var/run/ai-env/.helper-token`.
	HelperTokenPath string

	// ServerTokens is the per-server token map the supervisor minted
	// via ControlSocket.MintServerToken. Exposed so the supervisor's
	// tests can assert on the per-server scoping without re-reading
	// the on-disk file.
	ServerTokens map[string]string
}

// PerRunMCPConfigOptions bundles the inputs MaterializePerRunMCPConfig
// consumes. The required fields (RunDir, ControlSocket, RealServers)
// cover the minimum the materializer needs; the optional fields knob
// the in-sandbox paths embedded in the agent-visible config.
type PerRunMCPConfigOptions struct {
	// RunDir is the per-run directory the materialized files land
	// inside. Required.
	RunDir string

	// ControlSocket is the per-run control socket the supervisor
	// constructed at canonical pre-launch step 2. The materializer
	// mints one per-server token via
	// ControlSocket.MintServerToken per entry in RealServers, then
	// embeds the tokens in the agent-visible config. Required.
	ControlSocket *ControlSocket

	// RealServers is the map of registered server name to its real
	// upstream launch command. The materializer writes one entry per
	// key into both files; the agent-visible config points at the
	// shim helper, the host-only config carries the real command.
	// Required and non-empty: a run without any registered MCP
	// servers should not call this materializer at all.
	RealServers map[string]MCPRealServer

	// HelperCommand is the absolute (or PATH-resolvable) path of the
	// `ai-env` binary the agent CLI invokes to spawn the shim helper.
	// Defaults to "ai-env" when empty, which is the canonical
	// in-sandbox path the supervisor bind-mounts the binary to
	// (`/usr/local/bin/ai-env`) at Create time.
	HelperCommand string

	// InSandboxSocketPath is the path the helper uses to reach the
	// control socket. Defaults to MCPHelperDefaultSocketPath
	// (`/var/run/ai-env/control.sock`); tests override it to point at
	// a host-side temp directory.
	InSandboxSocketPath string

	// ContainerUID is the in-sandbox UID the helper runs as. When
	// non-nil the materializer chowns the host-only files
	// (`mcp-servers.real.json`, `.helper-token`) to this UID so the
	// helper (which spawns as this UID inside the sandbox) can read
	// them and the agent (running as a different UID) cannot. Nil
	// leaves the chown unset, which is the right default for tests
	// running as the host user.
	//
	// On userns-remap hosts the caller passes the host-mapped UID
	// (Backend.MappedUID) rather than the in-sandbox UID; see Plan
	// Batch 0.5 for the rationale.
	ContainerUID *int
}

// MaterializePerRunMCPConfig writes the three Batch 3.2 artifacts to
// disk: the agent-visible `mcp-servers.json`, the host-only
// `mcp-servers.real.json`, and the side-band `.helper-token` file.
// The function is idempotent in the sense that it overwrites any
// previous file at the same path — the supervisor calls it once per
// run, but the on-disk layout is left in a consistent state if a
// retry is ever needed.
//
// Returns a PerRunMCPConfig recording the absolute paths and the per-
// server token map. On any error the partially-written files are
// removed so the caller sees a clean error path; the per-server
// tokens minted into the ControlSocket registry are NOT rolled back
// because the supervisor's teardown step 8 stops the socket entirely.
func MaterializePerRunMCPConfig(opts PerRunMCPConfigOptions) (PerRunMCPConfig, error) {
	if opts.RunDir == "" {
		return PerRunMCPConfig{}, errors.New("run: MaterializePerRunMCPConfig requires RunDir")
	}
	if opts.ControlSocket == nil {
		return PerRunMCPConfig{}, errors.New("run: MaterializePerRunMCPConfig requires ControlSocket")
	}
	if len(opts.RealServers) == 0 {
		return PerRunMCPConfig{}, errors.New("run: MaterializePerRunMCPConfig requires at least one RealServer")
	}

	helperCmd := opts.HelperCommand
	if helperCmd == "" {
		helperCmd = "ai-env"
	}
	socketPath := opts.InSandboxSocketPath
	if socketPath == "" {
		socketPath = MCPHelperDefaultSocketPath
	}

	ipcDir := filepath.Join(opts.RunDir, ipcSubdir)
	if err := os.MkdirAll(ipcDir, ipcSubdirMode); err != nil {
		return PerRunMCPConfig{}, fmt.Errorf("run: create ipc subdir %s: %w", ipcDir, err)
	}

	// Mint a per-server token for every registered server. We sort
	// the keys so the mint order is deterministic — a retry of the
	// same materializer produces the same on-disk shape (modulo the
	// freshly-minted secret bytes, which are crypto/rand-sourced).
	names := make([]string, 0, len(opts.RealServers))
	for name := range opts.RealServers {
		if name == "" {
			return PerRunMCPConfig{}, errors.New("run: MaterializePerRunMCPConfig: empty server name in RealServers")
		}
		names = append(names, name)
	}
	sort.Strings(names)

	serverTokens := make(map[string]string, len(names))
	agentCfg := MCPAgentConfig{MCPServers: make(map[string]MCPAgentServer, len(names))}
	realCfg := MCPRealConfig{MCPServers: make(map[string]MCPRealServer, len(names))}

	for _, name := range names {
		token, err := opts.ControlSocket.MintServerToken(name)
		if err != nil {
			return PerRunMCPConfig{}, fmt.Errorf("run: mint server token for %q: %w", name, err)
		}
		serverTokens[name] = token

		agentCfg.MCPServers[name] = MCPAgentServer{
			Command: helperCmd,
			Args:    []string{"shim-helper", "mcp", name},
			Env: map[string]string{
				MCPHelperEnvControlSocket: socketPath,
				MCPHelperEnvServerToken:   token,
			},
		}
		realCfg.MCPServers[name] = opts.RealServers[name]
	}

	agentPath := filepath.Join(opts.RunDir, mcpServersAgentFileName)
	realPath := filepath.Join(ipcDir, mcpServersRealFileName)
	helperTokenPath := filepath.Join(ipcDir, helperTokenFileName)

	cleanup := func() {
		_ = os.Remove(agentPath)
		_ = os.Remove(realPath)
		_ = os.Remove(helperTokenPath)
	}

	// Agent-visible config: mode 0644 (the per-server tokens it
	// embeds are designed to be agent-readable). Marshaled with
	// MarshalIndent so the operator's debugging surface is readable.
	agentJSON, err := json.MarshalIndent(agentCfg, "", "  ")
	if err != nil {
		cleanup()
		return PerRunMCPConfig{}, fmt.Errorf("run: marshal agent mcp config: %w", err)
	}
	if err := writeFileAtomic(agentPath, agentJSON, mcpServersAgentFileMode); err != nil {
		cleanup()
		return PerRunMCPConfig{}, fmt.Errorf("run: write %s: %w", agentPath, err)
	}

	// Real-server config: mode 0600, chown'd to the container UID.
	// Marshaled with MarshalIndent so a host-side operator viewing
	// the file (as root, for debugging) sees readable JSON.
	realJSON, err := json.MarshalIndent(realCfg, "", "  ")
	if err != nil {
		cleanup()
		return PerRunMCPConfig{}, fmt.Errorf("run: marshal real mcp config: %w", err)
	}
	if err := writeFileAtomic(realPath, realJSON, mcpServersRealFileMode); err != nil {
		cleanup()
		return PerRunMCPConfig{}, fmt.Errorf("run: write %s: %w", realPath, err)
	}
	if opts.ContainerUID != nil {
		if err := os.Chown(realPath, *opts.ContainerUID, -1); err != nil {
			cleanup()
			return PerRunMCPConfig{}, fmt.Errorf("run: chown %s to uid %d: %w", realPath, *opts.ContainerUID, err)
		}
	}

	// Helper token file: mode 0400, chown'd to the container UID.
	// The token body is the primary control_token; the helper reads
	// it on Hello to authenticate. A trailing newline is appended so
	// the file is `cat`-friendly without disturbing the trimToken
	// helper on the helper side (which strips trailing whitespace).
	tokenBlob := []byte(opts.ControlSocket.PrimaryToken() + "\n")
	if err := writeFileAtomic(helperTokenPath, tokenBlob, helperTokenFileMode); err != nil {
		cleanup()
		return PerRunMCPConfig{}, fmt.Errorf("run: write %s: %w", helperTokenPath, err)
	}
	if opts.ContainerUID != nil {
		if err := os.Chown(helperTokenPath, *opts.ContainerUID, -1); err != nil {
			cleanup()
			return PerRunMCPConfig{}, fmt.Errorf("run: chown %s to uid %d: %w", helperTokenPath, *opts.ContainerUID, err)
		}
	}

	return PerRunMCPConfig{
		AgentConfigPath: agentPath,
		RealConfigPath:  realPath,
		HelperTokenPath: helperTokenPath,
		ServerTokens:    serverTokens,
	}, nil
}

// writeFileAtomic writes data to path with the supplied mode. We open
// with O_TRUNC because the per-run directory's placeholder file (set
// up by CreateRunDirectory) already exists with the same name; a
// straight O_CREATE | O_EXCL would conflict with the placeholder. The
// post-write Chmod ensures the mode lands even when the host umask
// would otherwise widen or narrow it. The function is "atomic" in the
// sense that an interrupted write leaves a partially-written file
// rather than a missing one — the supervisor's cleanup path removes
// the partial file on any error from the higher-level materializer,
// so the on-disk state never carries a half-written config.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Re-chmod in case umask narrowed the OpenFile mode.
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return nil
}

// ReadMCPServersAgent reads and decodes the agent-visible config at
// `<runDir>/mcp-servers.json`. Exposed so tests (and a future replay
// tool) can inspect the materialized file without re-deriving the
// path.
func ReadMCPServersAgent(runDir string) (MCPAgentConfig, error) {
	if runDir == "" {
		return MCPAgentConfig{}, errors.New("run: ReadMCPServersAgent requires runDir")
	}
	path := filepath.Join(runDir, mcpServersAgentFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return MCPAgentConfig{}, fmt.Errorf("run: read %s: %w", path, err)
	}
	var cfg MCPAgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return MCPAgentConfig{}, fmt.Errorf("run: decode %s: %w", path, err)
	}
	return cfg, nil
}

// ReadMCPServersReal reads and decodes the host-only real-server
// config at `<runDir>/ipc/mcp-servers.real.json`. Exposed so the shim
// helper (running inside the sandbox under the container UID) can
// read the upstream command after the AuthorizeMCPCall handshake
// succeeds.
func ReadMCPServersReal(runDir string) (MCPRealConfig, error) {
	if runDir == "" {
		return MCPRealConfig{}, errors.New("run: ReadMCPServersReal requires runDir")
	}
	path := filepath.Join(runDir, ipcSubdir, mcpServersRealFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return MCPRealConfig{}, fmt.Errorf("run: read %s: %w", path, err)
	}
	var cfg MCPRealConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return MCPRealConfig{}, fmt.Errorf("run: decode %s: %w", path, err)
	}
	return cfg, nil
}
