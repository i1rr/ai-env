// shim_helper.go wires the hidden `ai-env shim-helper {shell,mcp}`
// subcommand surface. The subcommand is invoked from inside the sandbox
// by the per-program wrappers the supervisor installs (see
// internal/policy/shim_install.go) and by the MCP gateway configs the
// supervisor writes at <runDir>/mcp-servers.json. Operators never run
// `shim-helper` directly; it is hidden from `--help` so a sandbox user
// listing top-level commands does not accidentally invoke it.
//
// What this file owns:
//
//   - The Cobra plumbing for `shim-helper shell <program>` and
//     `shim-helper mcp <server>`. Both subcommands are hidden.
//   - The recursion guard via AI_ENV_SHIM_DEPTH: if the helper is
//     re-entered (e.g. a wrapper re-execs the helper through PATH and
//     the helper re-execs the wrapper) the depth is bumped on every
//     hop and the helper fails closed when depth exceeds the small
//     cap. This is defense-in-depth on top of the supervisor's
//     argv[0] hardening; a single misconfigured wrapper should not
//     fork-bomb the sandbox.
//   - The fail-closed default. Any error reaching the control socket,
//     resolving the real binary, or scanning the command surfaces as
//     a non-zero exit with a clear message on stderr; the helper
//     never silently allows.
//
// What this file does NOT own:
//
//   - The control-socket protocol. The helper imports the
//     ControlSocketResponse / request shapes from internal/run and
//     speaks the same JSON-RPC the supervisor binds. The wire
//     framing lives in internal/run/control_socket.go.
//   - The policy engine. The helper presents the candidate command to
//     the supervisor's EvaluateShellCommand handler and respects the
//     returned verdict; rule logic lives in internal/policy.
//
// Per-mode bodies live in shim_helper_shell.go and shim_helper_mcp.go;
// the per-platform execveat / /dev/fd plumbing lives in
// shim_helper_exec_linux.go and shim_helper_exec_other.go.

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// shimHelperEnvSocket is the env-var key the supervisor writes into
// the per-program shim wrapper's env so the helper knows where to
// reach the control socket. The wrapper unsets this variable in the
// re-exec'd child's environment (see internal/policy/shim_install.go),
// so the helper that READS it is the wrapper-side instance only; the
// real binary the helper finally execveat's never sees this value.
//
// The default in-sandbox path (the fallback when the env var is
// unset) is /var/run/ai-env/control.sock, which is the bind-mount
// target Plan Batch 0.5 pins.
const shimHelperEnvSocket = "AI_ENV_CONTROL_SOCKET"

// shimHelperEnvDepth carries the recursion guard counter. Every hop
// through the helper bumps it; the helper fails closed when the
// counter exceeds shimHelperMaxDepth.
const shimHelperEnvDepth = "AI_ENV_SHIM_DEPTH"

// shimHelperEnvServerToken is the per-server token the MCP gateway
// helper presents alongside the primary control token on every
// AuthorizeMCPCall. The supervisor writes one per registered MCP
// server into <runDir>/mcp-servers.json (Plan Bucket 4); the agent
// CLI passes it to the helper as an env entry on spawn.
const shimHelperEnvServerToken = "AI_ENV_MCP_SERVER_TOKEN"

// shimHelperEnvHelperTokenPath is the env-var the supervisor uses to
// override the default in-sandbox path of the side-band helper-token
// file. The default (/var/run/ai-env/.helper-token) is pinned by
// Plan Batch 0.5; this override exists so tests can drive the helper
// against an arbitrary path without manipulating the sandbox's
// filesystem layout.
const shimHelperEnvHelperTokenPath = "AI_ENV_HELPER_TOKEN_PATH"

// shimHelperDefaultSocketPath is the stable in-sandbox path the
// control socket is bind-mounted at. The supervisor's mount split
// (Plan Batch 0.5) places <runDir>/ipc/control.sock under
// /var/run/ai-env/ inside the sandbox.
const shimHelperDefaultSocketPath = "/var/run/ai-env/control.sock"

// shimHelperDefaultHelperTokenPath is the stable in-sandbox path of
// the side-band helper-token file. Mode 0o400, chown'd to the
// container UID, NOT readable by the agent (the agent runs as a
// different UID; see Plan Bucket 4).
const shimHelperDefaultHelperTokenPath = "/var/run/ai-env/.helper-token"

// shimHelperOrigDir is the stable in-sandbox directory of "real
// binary" originals. The supervisor populates it at Create time
// (Plan Bucket 1: docker cp or a precomputed-per-image table). The
// helper resolves <prog> to <shimHelperOrigDir>/<prog> and execveat's
// that file descriptor rather than calling exec.LookPath (which would
// race the per-program canonical-path shadows).
const shimHelperOrigDir = "/var/run/ai-env/orig"

// shimHelperMaxDepth caps the recursion guard. A single legitimate
// re-exec hop bumps the counter to 1; anything beyond a handful of
// hops is a misconfiguration or an attempted recursion attack.
const shimHelperMaxDepth = 4

// shimHelperProtocolVersion is the protocol version the helper
// presents on Hello. Must equal the supervisor's
// controlSocketProtocolVersion (internal/run/control_socket.go).
const shimHelperProtocolVersion = 1

// shimHelperClientVersion is the informational client-version string
// the helper presents on Hello. The supervisor records it on the
// per-RPC audit trail; the value is informational only.
const shimHelperClientVersion = "ai-env-shim-helper/0.1"

// newShimHelperCmd builds the hidden `shim-helper` parent command and
// attaches the two mode subcommands.
func newShimHelperCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "shim-helper",
		Short:  "internal: shim helper used by the per-program wrappers and MCP configs",
		Hidden: true,
		Long: "Internal subcommand invoked by the per-program shim wrappers " +
			"and by the per-run mcp-servers.json configs. Operators do not " +
			"run this directly. The two modes are `shell <program>` (one-shot " +
			"interpose between the wrapper and the real binary) and `mcp " +
			"<server>` (long-lived JSON-RPC stdio shim that fronts an MCP " +
			"server).",
	}
	cmd.AddCommand(newShimHelperShellCmd())
	cmd.AddCommand(newShimHelperMCPCmd())
	return cmd
}

// newShimHelperShellCmd builds `ai-env shim-helper shell <program>`.
// Flag parsing lives here; the body lives in shim_helper_shell.go.
func newShimHelperShellCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "shell <program>",
		Short:  "internal: shell-mode helper invoked by a per-program wrapper",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShimHelperShell(args[0], os.Args[2:], cmd.ErrOrStderr())
		},
	}
}

// newShimHelperMCPCmd builds `ai-env shim-helper mcp <server>`. Flag
// parsing lives here; the body lives in shim_helper_mcp.go.
func newShimHelperMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "mcp <server>",
		Short:  "internal: MCP-mode long-lived JSON-RPC stdio shim",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShimHelperMCP(args[0], cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
}

// shimHelperCurrentDepth reads AI_ENV_SHIM_DEPTH from the process env,
// parses it as a small integer, and returns 0 when the env var is
// unset or malformed. The caller bumps the depth before re-exec.
func shimHelperCurrentDepth() int {
	raw := os.Getenv(shimHelperEnvDepth)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// shimHelperGuardDepth returns an error when the recursion guard is
// tripped. The caller invokes it once at entry to fail closed before
// any side-effecting work.
func shimHelperGuardDepth() error {
	if d := shimHelperCurrentDepth(); d >= shimHelperMaxDepth {
		return fmt.Errorf("ai-env shim-helper: recursion guard tripped (%s=%d, max=%d)", shimHelperEnvDepth, d, shimHelperMaxDepth)
	}
	return nil
}

// shimHelperSocketPath returns the absolute path of the control socket
// the helper should connect to. The supervisor's preferred override
// (AI_ENV_CONTROL_SOCKET) takes precedence over the default in-sandbox
// path. Returns an error when the path is empty AND the default is not
// reachable; the caller surfaces this as a fail-closed verdict.
func shimHelperSocketPath() (string, error) {
	if p := os.Getenv(shimHelperEnvSocket); p != "" {
		return p, nil
	}
	return shimHelperDefaultSocketPath, nil
}

// shimHelperLoadPrimaryToken reads the primary control token from the
// side-band helper-token file. The file's path is taken from the
// AI_ENV_HELPER_TOKEN_PATH env var when set; otherwise it falls back
// to the stable in-sandbox path. Returns an error if the file is
// missing, unreadable, or empty: the helper fails closed before any
// RPC.
func shimHelperLoadPrimaryToken() (string, error) {
	path := os.Getenv(shimHelperEnvHelperTokenPath)
	if path == "" {
		path = shimHelperDefaultHelperTokenPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read helper token at %s: %w", path, err)
	}
	tok := trimToken(data)
	if tok == "" {
		return "", errors.New("helper token file is empty")
	}
	return tok, nil
}

// trimToken strips trailing whitespace (LF/CRLF/spaces) from a token
// blob. The supervisor writes the token followed by a newline so the
// file is readable with `cat`; the helper tolerates that without
// passing the newline back over the wire.
func trimToken(buf []byte) string {
	end := len(buf)
	for end > 0 {
		c := buf[end-1]
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			end--
			continue
		}
		break
	}
	return string(buf[:end])
}
