// shim_helper_shell.go implements `ai-env shim-helper shell <program>`.
//
// The shell-mode helper is a one-shot interpose between the
// per-program wrapper (installed at <shimDir>/<program> by
// internal/policy.InstallShim and shadowed at the canonical absolute
// paths by Plan Batch 1.3) and the real binary the agent intended to
// invoke. The wrapper invokes the helper as:
//
//	ai-env shim-helper shell <program> <arg> <arg> ...
//
// The helper then:
//
//  1. Trips the recursion guard if AI_ENV_SHIM_DEPTH is too deep.
//  2. Connects to the supervisor's control socket and presents
//     Hello(primary_token, client_version, protocol_version).
//  3. Calls EvaluateShellCommand(primary_token, argv) to obtain a
//     verdict. The supervisor records the decision in
//     policy-decisions.jsonl and shell-commands.jsonl; the helper
//     does not write to either trail directly.
//  4. On decision=block (and any RPC failure) prints the reason to
//     stderr and exits non-zero. The plan's "fail-closed" rule.
//  5. On decision=allow / warn the helper applies the
//     interpreter-via-file TOCTOU-safe flow when the candidate argv
//     dispatches to a script path; otherwise the helper resolves the
//     real binary at /var/run/ai-env/orig/<program> and execveat's
//     it directly. argv[0] is forced to the canonical program name
//     (defeats `exec -a sh python3 ...` spoofing).
//
// On macOS the execveat flow is replaced by `/dev/fd/<n>` (the same
// file descriptor is used for both the content scan and the exec) so
// the TOCTOU-safe property holds on filesystems that expose /dev/fd.
// Platform-specific bodies live in shim_helper_exec_linux.go and
// shim_helper_exec_other.go.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rivan1986/ai-env/internal/policy"
	"github.com/rivan1986/ai-env/internal/run"
)

// shellModeName is the helper mode emitted on the helper-rpc-aborted
// lifecycle record when the supervisor logs an aborted RPC for the
// shell helper. The plan's lifecycle metadata table pins the name.
const shellModeName = "shell"

// shellHelperDialTimeout caps how long the helper waits for the
// supervisor's control socket to accept the connection. The plan
// pins "fail-closed on socket unreachable" without a specific
// numeric; we use a short window (1s) so a wedged supervisor does
// not stall the agent indefinitely. The supervisor binds the socket
// before any wrapper runs, so a real run never hits this timeout.
const shellHelperDialTimeout = 1 * time.Second

// shellHelperRPCTimeout caps how long the helper waits for a single
// EvaluateShellCommand response. Same fail-closed rationale.
const shellHelperRPCTimeout = 2 * time.Second

// shellHelperReadBufSize is the bufio.Reader buffer the helper uses
// when reading JSON-RPC responses. One frame is small (a verdict +
// reason); a generous buffer avoids a partial-frame reassembly bug.
const shellHelperReadBufSize = 1 << 16

// shellInterpreterPrograms enumerates the program basenames the
// helper treats as interpreters for the interpreter-via-file
// TOCTOU-safe flow. The list mirrors the canonical ShimProgramSet
// entries whose canonical use is "interpret a script file": running
// `python /tmp/foo.py` or `bash /tmp/foo.sh` reaches the helper as
// argv = ["python3", "/tmp/foo.py"]; the helper opens
// "/tmp/foo.py" with O_RDONLY|O_NOFOLLOW, scans for high-risk
// patterns (the policy engine's HighRiskShellPatterns set), and
// execveat's the SAME fd if the scan passes.
var shellInterpreterPrograms = map[string]struct{}{
	"sh":         {},
	"bash":       {},
	"dash":       {},
	"zsh":        {},
	"python":     {},
	"python3":    {},
	"python3.10": {},
	"python3.11": {},
	"python3.12": {},
	"perl":       {},
	"ruby":       {},
	"node":       {},
	"deno":       {},
	"awk":        {},
}

// runShimHelperShell is the entry point for `ai-env shim-helper shell
// <program>`. It is invoked from the wrapper's exec; the helper's
// argv from Cobra is the program basename followed by the agent's
// arguments (in os.Args[2:] form).
//
// The full argv passed to EvaluateShellCommand is
// [<program>] + agentArgs so the supervisor's policy engine sees the
// same shape it would see if the agent invoked the binary directly.
func runShimHelperShell(program string, agentArgs []string, stderr io.Writer) error {
	if err := shimHelperGuardDepth(); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return err
	}
	if strings.TrimSpace(program) == "" {
		err := errors.New("ai-env shim-helper shell: empty program")
		fmt.Fprintln(stderr, err.Error())
		return err
	}
	// Defense-in-depth: refuse to dispatch a wrapper for a program
	// outside the canonical ShimProgramSet. The supervisor only
	// installs wrappers for shadowed programs, so reaching this
	// branch means the helper is being driven from a path the
	// supervisor did not authorize. Fail closed.
	if !policy.IsShimmedProgram(program) {
		err := fmt.Errorf("ai-env shim-helper shell: program %q is not in the canonical shadow set", program)
		fmt.Fprintln(stderr, err.Error())
		return err
	}

	argv := append([]string{program}, agentArgs...)

	// argv[0] hardening: when the wrapper itself was invoked with a
	// path (e.g. /usr/bin/python3) the helper sees `program` as the
	// canonical name already because Cobra hands us args[0]; the
	// wrapper writes the canonical name in its `exec` line. We do
	// not trust the agent to set argv[0] when re-execing the real
	// binary; the canonical basename is forced below.
	canonical := filepath.Base(program)

	// Reach the control socket. A fail-closed default surfaces
	// errors as a non-zero exit with the redacted reason; the
	// supervisor's accept loop records every aborted RPC in
	// lifecycle.jsonl via helper_rpc_aborted.
	resp, err := shellEvaluateViaControlSocket(argv)
	if err != nil {
		fmt.Fprintf(stderr, "ai-env shim-helper shell: control socket: %v\n", err)
		return err
	}

	switch resp.Decision {
	case "allow", "warn":
		// continue to exec
	default:
		// Includes "block", "shutdown", and any non-allow verdict.
		reason := resp.Reason
		if reason == "" {
			reason = resp.Decision
		}
		fmt.Fprintf(stderr, "ai-env shim-helper shell: %s: %s\n", resp.Decision, reason)
		return fmt.Errorf("shim-helper shell denied: %s", reason)
	}

	// Bump the recursion guard before re-exec.
	bumpedDepth := shimHelperCurrentDepth() + 1
	depthEnv := shimHelperEnvDepth + "=" + strconv.Itoa(bumpedDepth)
	envOut := envWithDepth(os.Environ(), depthEnv)

	// Resolve the real binary. The shim NEVER calls exec.LookPath
	// (which would race the per-program canonical-path shadows).
	// The supervisor populates <shimHelperOrigDir>/<canonical> with
	// the image's actual binary at Create time.
	origPath := filepath.Join(shimHelperOrigDir, canonical)

	// Interpreter-via-file flow: when the program is an interpreter
	// and the first non-flag argument names a regular file, open
	// that file with O_RDONLY|O_NOFOLLOW, scan the content for
	// high-risk patterns, and execveat the SAME fd. Same-fd is the
	// TOCTOU-safe property: a swap-after-scan attacker cannot win
	// because the scanned bytes and the executed bytes are read
	// through the same kernel inode reference.
	scriptPath := candidateScriptPath(canonical, agentArgs)
	if scriptPath != "" {
		if err := execInterpreterViaFile(origPath, canonical, scriptPath, argv, envOut, stderr); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return err
		}
		// execInterpreterViaFile only returns on failure; on success
		// the helper process is replaced and never returns here.
		return errors.New("ai-env shim-helper shell: execve did not replace process")
	}

	// Non-interpreter (or interpreter without a script-path arg):
	// open the real binary's fd and execveat. argv[0] is forced to
	// the canonical basename so an `exec -a` spoof cannot mislead
	// the child about its name.
	finalArgv := append([]string{canonical}, agentArgs...)
	if err := execRealBinary(origPath, finalArgv, envOut, stderr); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return err
	}
	return errors.New("ai-env shim-helper shell: execve did not replace process")
}

// candidateScriptPath inspects argv and returns the first argument
// that names a regular file path. For interpreters the convention is
// "interpreter [flags] script.<ext> [args]"; we walk the args past
// flags (any arg starting with "-") and pick the first existing
// regular file. Returns "" when the program is not an interpreter or
// when no file argument is present (e.g. `python -c "..."` — the
// interpreter is consuming inline source, which the policy engine's
// interpreter-ban rule denies separately).
func candidateScriptPath(program string, agentArgs []string) string {
	if _, ok := shellInterpreterPrograms[program]; !ok {
		return ""
	}
	for _, a := range agentArgs {
		if strings.HasPrefix(a, "-") {
			continue
		}
		// Inline source (`-c "..."`) is consumed by the flag walk
		// above; the first non-flag arg is the candidate script.
		if info, err := os.Stat(a); err == nil && info.Mode().IsRegular() {
			return a
		}
		// First non-flag arg that isn't a regular file: not a
		// script invocation; bail out.
		return ""
	}
	return ""
}

// envWithDepth returns env with the AI_ENV_SHIM_DEPTH entry replaced
// by depthEntry. If the env had no prior depth entry the new one is
// appended. The result is a freshly allocated slice so the caller's
// env is never mutated.
func envWithDepth(env []string, depthEntry string) []string {
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, kv := range env {
		if strings.HasPrefix(kv, shimHelperEnvDepth+"=") {
			out = append(out, depthEntry)
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, depthEntry)
	}
	return out
}

// shellEvaluateViaControlSocket dials the supervisor's control
// socket, performs the Hello handshake, and calls
// EvaluateShellCommand with the supplied argv. Returns the verdict on
// success; any wire error or non-allow response surfaces to the
// caller as an error or as the response itself.
//
// The helper presents the primary control token loaded from the
// side-band <shimHelperDefaultHelperTokenPath> file (Plan Bucket 4).
// The primary token is NOT in the agent's env; an agent that reads
// the helper's process env at runtime can see the helper hold the
// token in memory but cannot extract it without root in the
// container's pid namespace, which the policy engine refuses
// separately.
func shellEvaluateViaControlSocket(argv []string) (run.ControlSocketResponse, error) {
	primary, err := shimHelperLoadPrimaryToken()
	if err != nil {
		return run.ControlSocketResponse{Decision: "block", Reason: "helper token unavailable"}, fmt.Errorf("helper token: %w", err)
	}
	sockPath, err := shimHelperSocketPath()
	if err != nil {
		return run.ControlSocketResponse{Decision: "block", Reason: "socket path unavailable"}, err
	}
	conn, err := net.DialTimeout("unix", sockPath, shellHelperDialTimeout)
	if err != nil {
		return run.ControlSocketResponse{Decision: "block", Reason: "control socket unreachable"}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	br := bufio.NewReaderSize(conn, shellHelperReadBufSize)
	enc := json.NewEncoder(conn)

	if err := conn.SetDeadline(time.Now().Add(shellHelperRPCTimeout)); err != nil {
		return run.ControlSocketResponse{Decision: "block", Reason: "set deadline failed"}, err
	}

	// Hello handshake.
	helloReq := map[string]any{
		"method": "Hello",
		"params": map[string]any{
			"control_token":    primary,
			"client_version":   shimHelperClientVersion,
			"protocol_version": shimHelperProtocolVersion,
		},
	}
	if err := enc.Encode(helloReq); err != nil {
		return run.ControlSocketResponse{Decision: "block", Reason: "Hello encode failed"}, err
	}
	helloResp, err := readControlResponse(br)
	if err != nil {
		return run.ControlSocketResponse{Decision: "block", Reason: "Hello read failed"}, err
	}
	if helloResp.Decision != "allow" {
		return helloResp, fmt.Errorf("Hello rejected: %s", helloResp.Reason)
	}

	// EvaluateShellCommand.
	cmdLine := strings.Join(argv, " ")
	evalReq := map[string]any{
		"method": "EvaluateShellCommand",
		"params": map[string]any{
			"control_token": primary,
			"argv":          argv,
			"cmd_line":      cmdLine,
		},
	}
	if err := enc.Encode(evalReq); err != nil {
		return run.ControlSocketResponse{Decision: "block", Reason: "EvaluateShellCommand encode failed"}, err
	}
	evalResp, err := readControlResponse(br)
	if err != nil {
		return run.ControlSocketResponse{Decision: "block", Reason: "EvaluateShellCommand read failed"}, err
	}
	return evalResp, nil
}

// readControlResponse reads one newline-delimited JSON frame from br
// and decodes it into a ControlSocketResponse. Returns an error on
// transport / decode failure; the caller surfaces it as a
// fail-closed verdict.
func readControlResponse(br *bufio.Reader) (run.ControlSocketResponse, error) {
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return run.ControlSocketResponse{}, fmt.Errorf("read frame: %w", err)
	}
	var resp run.ControlSocketResponse
	if err := json.Unmarshal(bytes.TrimRight(line, "\n"), &resp); err != nil {
		return run.ControlSocketResponse{}, fmt.Errorf("decode frame: %w", err)
	}
	return resp, nil
}

// execInterpreterViaFile applies the interpreter-via-file TOCTOU-safe
// flow. It opens the script path with O_RDONLY|O_NOFOLLOW (so a
// symlink swap into the path between scan and exec cannot redirect
// the read), scans the content for the policy engine's
// HighRiskShellPatterns, and on allow execveat's the real binary
// (Linux) or `/dev/fd/<n>`-execs (macOS) the same fd.
//
// The argv passed to the interpreter is rewritten so the script
// argument is the /dev/fd path (or /proc/self/fd path on Linux) of
// the opened fd; this guarantees the interpreter reads the exact
// bytes that were scanned, even if the original path on disk has
// since been replaced by an attacker.
//
// The runtime details (execveat / /dev/fd) live in
// shim_helper_exec_linux.go and shim_helper_exec_other.go.
func execInterpreterViaFile(realBinaryPath, canonical, scriptPath string, argv, env []string, stderr io.Writer) error {
	scriptFd, err := openScriptForScan(scriptPath)
	if err != nil {
		return fmt.Errorf("ai-env shim-helper shell: open script %s: %w", scriptPath, err)
	}
	defer func() {
		// On the success path the exec replaces the process and this
		// runs only if exec fails; double-close is harmless.
		_ = closeFD(scriptFd)
	}()

	// Scan the content. We read up to scanScriptLimit bytes; a
	// script longer than the limit is treated as "scan window
	// exhausted, allow the verdict the policy engine already
	// returned" — the supervisor's EvaluateShellCommand has the
	// final say.
	content, err := readScriptForScan(scriptFd)
	if err != nil {
		return fmt.Errorf("ai-env shim-helper shell: read script %s: %w", scriptPath, err)
	}
	if hit := scanScriptHighRisk(content); hit != "" {
		return fmt.Errorf("ai-env shim-helper shell: script content matches high-risk pattern %q", hit)
	}

	// Build the rewritten argv that points at the same fd.
	fdScriptPath := scriptFdPath(scriptFd)
	rewritten := rewriteScriptArg(argv, scriptPath, fdScriptPath, canonical)

	if err := execScriptViaFD(realBinaryPath, scriptFd, rewritten, env); err != nil {
		return fmt.Errorf("ai-env shim-helper shell: exec %s: %w", realBinaryPath, err)
	}
	return nil
}

// execRealBinary opens the real binary at realBinaryPath and
// execveat's it (Linux) or execs it directly (other) with the
// supplied argv and env. argv[0] is forced to the canonical basename
// by the caller before this is reached.
func execRealBinary(realBinaryPath string, argv, env []string, stderr io.Writer) error {
	if err := execBinaryDirect(realBinaryPath, argv, env); err != nil {
		return fmt.Errorf("ai-env shim-helper shell: exec %s: %w", realBinaryPath, err)
	}
	return nil
}

// rewriteScriptArg returns argv with scriptPath replaced by
// fdScriptPath. argv[0] is overridden to canonical so an `exec -a`
// spoof from the upstream wrapper cannot mislead the interpreter
// about its own name. The original args before/after the script
// argument are preserved.
func rewriteScriptArg(argv []string, scriptPath, fdScriptPath, canonical string) []string {
	out := make([]string, len(argv))
	copy(out, argv)
	if len(out) > 0 {
		out[0] = canonical
	}
	for i := 1; i < len(out); i++ {
		if out[i] == scriptPath {
			out[i] = fdScriptPath
			break
		}
	}
	return out
}

// scanScriptLimit caps how much of a script the helper reads into
// memory for the high-risk-pattern scan. 256 KiB is comfortably
// larger than any real CLI shell script and small enough that a
// hostile multi-megabyte file does not chew through helper memory.
const scanScriptLimit = 256 * 1024

// readScriptForScan reads up to scanScriptLimit bytes from fd. The
// read does NOT advance the fd cursor for the exec syscall: callers
// use Pread on Linux (lseek + read on macOS) so the exec sees the
// file from the beginning. We use a small wrapper to keep both
// platforms consistent.
func readScriptForScan(fd int) ([]byte, error) {
	buf := make([]byte, scanScriptLimit)
	n, err := preadFD(fd, buf, 0)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

// scanScriptHighRisk searches content for any of the policy
// engine's HighRiskShellPatterns. Returns the first matched pattern,
// or "" when no patterns match. The match is case-insensitive on the
// content (the engine lowercases its inputs); the patterns
// themselves are already lowercase.
func scanScriptHighRisk(content []byte) string {
	lower := strings.ToLower(string(content))
	for _, pat := range policy.HighRiskShellPatterns {
		if strings.Contains(lower, pat) {
			return pat
		}
	}
	return ""
}

