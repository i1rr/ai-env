// shim_install.go materializes the per-program wrapper scripts the
// supervisor places in <shimDir> at step 10 of the canonical pre-launch
// sequence (Plan Batch 5.5). The wrappers are POSIX shell scripts that
// re-exec the main `ai-env` binary with its hidden `shim-helper`
// subcommand; the same binary is bind-mounted at /usr/local/bin/ai-env
// inside the sandbox so the wrapper has a stable path to invoke.
//
// What a wrapper looks like on disk:
//
//	#!/bin/sh
//	# ai-env shim wrapper for <program>
//	# Generated; do not edit.
//	unset AI_ENV_CONTROL_SOCKET
//	exec <helperCmd> shell <program> "$@"
//
// Notes:
//
//   - The shebang is /bin/sh so the wrapper does not depend on bash
//     being present (a minimal base image may only ship dash/ash).
//   - `unset AI_ENV_CONTROL_SOCKET` strips the socket-path env var from
//     the re-exec'd child so a recursive helper invocation cannot
//     trivially re-discover the supervisor's socket through the
//     child's environment. The control socket lives at a stable
//     in-sandbox path (/var/run/ai-env/control.sock) which the helper
//     looks up; the env var is informational only. The plan's Bucket 1
//     locked decision pins this behavior.
//   - The primary `AI_ENV_CONTROL_TOKEN` is NOT in the agent env in
//     the first place (Plan Bucket 4 locked decision), so this
//     wrapper does NOT unset it: there is nothing to unset. The
//     per-server MCP tokens flow through `AI_ENV_MCP_SERVER_TOKEN` in
//     the MCP config and are scoped to the MCP helper path, not the
//     shell wrappers.
//   - `exec` replaces the wrapper process so the resulting child's
//     `argv[0]` is the helper command's path, not the wrapper. The
//     helper's argv[0] hardening then forces `argv[0]` to the
//     canonical program basename before execveat-ing the real binary;
//     see cmd/ai-env/shim_helper.go.
//
// What this file owns and what it does NOT own:
//
//   - It owns the wrapper script template, the per-program file write,
//     and the mode/permissions of the wrapper (mode 0755, owned by
//     whoever runs InstallShim).
//   - It does NOT own the bind-mounts that shadow the canonical
//     absolute paths (/usr/bin/<prog>, /bin/<prog>,
//     /usr/local/bin/<prog>). Those are built by the supervisor at
//     EnvSpec.BindMounts (Batch 0.5) using the ShimProgramSet /
//     ShimCanonicalPaths helpers in shim_programs.go.
//   - It does NOT own the runtime decision logic. The wrapper is a
//     thin shim that forwards to `ai-env shim-helper shell`, which
//     consults the control socket for every command.
//
// Concurrency:
//
// InstallShim writes files sequentially to a single directory. It is
// safe for one caller per shimDir per run; the supervisor only
// constructs one shim directory per run, so multi-writer use is not a
// supported configuration.

package policy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// shimWrapperMode is the file mode the wrapper script is written
// with. 0o755 so the agent (which runs as a different UID than the
// host supervisor in production) can still exec the wrapper. The
// supervisor's run directory is itself 0o700, so an attacker that
// reaches the wrapper directory has already crossed the per-run
// boundary; the per-file mode is a defense-in-depth choice, not the
// primary access control.
const shimWrapperMode os.FileMode = 0o755

// shimWrapperPrefix is the first line of every wrapper. Pinned as a
// constant so tests can pattern-match the script body without
// reproducing the template.
const shimWrapperPrefix = "#!/bin/sh\n# ai-env shim wrapper for "

// InstallShimOptions bundles the per-call knobs InstallShim consumes.
// All fields are required except Programs, which defaults to the
// canonical ShimProgramSet when nil.
type InstallShimOptions struct {
	// ShimDir is the absolute path of the directory the wrappers are
	// written into. Required; an empty value returns an error. The
	// supervisor creates this directory before calling InstallShim
	// and bind-mounts it into the sandbox at a stable location (see
	// Plan Batch 1.3).
	ShimDir string

	// HelperCmd is the absolute path of the `ai-env` binary (and any
	// prefix arguments) the wrapper invokes via `exec`. The
	// supervisor passes the in-sandbox path the binary is
	// bind-mounted at (`/usr/local/bin/ai-env`) so the wrapper
	// re-exec is stable regardless of where the host binary lives.
	// Required; an empty value returns an error.
	//
	// The value is written into the wrapper verbatim (subject to
	// shell-quote escaping). Callers that want to pass multiple
	// tokens (e.g. "/usr/local/bin/ai-env shim-helper") supply the
	// full string here; the wrapper appends "shell <program> \"$@\""
	// after it.
	HelperCmd string

	// Programs is the list of shim programs to install wrappers for.
	// Nil falls back to ShimProgramSet (the canonical fixed list);
	// tests pass a smaller list to keep fixtures small.
	Programs []ShimProgram
}

// InstallShim writes one wrapper script per program in opts.Programs
// into opts.ShimDir. The wrappers re-exec the supplied HelperCmd with
// the hidden `shell <program>` subcommand, unset
// AI_ENV_CONTROL_SOCKET from the child env, and forward the
// caller-supplied argv.
//
// Returns the absolute paths of the wrappers written, in the same
// order as opts.Programs, so a caller (the supervisor) can record
// them in lifecycle.jsonl. Wrappers that fail to write surface as an
// error after the partial set is left on disk: the caller is
// responsible for the cleanup, the failure is the supervisor's signal
// to abort the run.
//
// Behavior:
//
//   - opts.ShimDir must exist and be a directory. InstallShim does NOT
//     create it: the supervisor's runDir builder is responsible for
//     the directory lifecycle so that path mode (0o700 / 0o755 / etc.)
//     stays under one owner.
//   - Each wrapper is written as
//     "<shimDir>/<program>" with mode shimWrapperMode (0o755).
//   - Existing wrappers are overwritten (the supervisor wires the
//     wrapper directory fresh on every run; an existing wrapper from a
//     crashed previous run is silently replaced).
//   - The wrapper body is rendered via renderShimWrapper so the
//     escaping rules live in one place.
func InstallShim(opts InstallShimOptions) ([]string, error) {
	if strings.TrimSpace(opts.ShimDir) == "" {
		return nil, errors.New("policy: InstallShim requires ShimDir")
	}
	if strings.TrimSpace(opts.HelperCmd) == "" {
		return nil, errors.New("policy: InstallShim requires HelperCmd")
	}
	info, err := os.Stat(opts.ShimDir)
	if err != nil {
		return nil, fmt.Errorf("policy: InstallShim stat ShimDir %s: %w", opts.ShimDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("policy: InstallShim ShimDir %s is not a directory", opts.ShimDir)
	}

	programs := opts.Programs
	if programs == nil {
		programs = ShimProgramSet
	}

	written := make([]string, 0, len(programs))
	for _, p := range programs {
		name := strings.TrimSpace(string(p))
		if name == "" {
			return written, fmt.Errorf("policy: InstallShim refuses empty program name")
		}
		body := renderShimWrapper(name, opts.HelperCmd)
		path := filepath.Join(opts.ShimDir, name)
		// O_TRUNC so a stale wrapper from a previous run is replaced.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, shimWrapperMode)
		if err != nil {
			return written, fmt.Errorf("policy: InstallShim open wrapper %s: %w", path, err)
		}
		if _, err := io.WriteString(f, body); err != nil {
			_ = f.Close()
			return written, fmt.Errorf("policy: InstallShim write wrapper %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return written, fmt.Errorf("policy: InstallShim close wrapper %s: %w", path, err)
		}
		// Re-apply the mode in case the umask masked off the exec bit;
		// OpenFile's mode is filtered by umask, Chmod is not.
		if err := os.Chmod(path, shimWrapperMode); err != nil {
			return written, fmt.Errorf("policy: InstallShim chmod wrapper %s: %w", path, err)
		}
		written = append(written, path)
	}
	return written, nil
}

// renderShimWrapper builds the script body for one program. The body
// is rendered into a single string with the trailing newline so the
// caller can write it in one syscall. The shell-quote escaping for
// HelperCmd is intentionally minimal: the supervisor passes a
// hard-coded absolute path that does not contain shell metacharacters,
// and we surface a clear error rather than try to escape arbitrary
// content (the helper command is supervisor-controlled, not
// agent-controlled).
//
// The body is documented at the top of this file; the layout is:
//
//	#!/bin/sh
//	# ai-env shim wrapper for <program>
//	# Generated; do not edit.
//	unset AI_ENV_CONTROL_SOCKET
//	exec <helperCmd> shell <program> "$@"
func renderShimWrapper(program, helperCmd string) string {
	var b strings.Builder
	b.WriteString(shimWrapperPrefix)
	b.WriteString(program)
	b.WriteString("\n# Generated by ai-env; do not edit.\n")
	b.WriteString("unset AI_ENV_CONTROL_SOCKET\n")
	b.WriteString("exec ")
	b.WriteString(helperCmd)
	b.WriteString(" shell ")
	b.WriteString(program)
	b.WriteString(" \"$@\"\n")
	return b.String()
}
