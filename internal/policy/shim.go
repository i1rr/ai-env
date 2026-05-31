package policy

// shim.go implements the optional shell shim prototype (plan 08 step 8).
// The shim is the cooperative interception point the master plan
// (section 22) calls out: when an agent is launched with
// `ai-env run --shell-shim`, the supervisor places this wrapper in front
// of `bash`/`sh` (and any other binaries listed in the future). Every
// command the agent issues lands here first.
//
// The shim's job, per plan 08 step 8, is:
//
//  1. Log the command attempt to shell-commands.jsonl so an auditor can
//     read the full trail after the run.
//  2. Deny obvious high-risk patterns (curl-pipe-shell, SSH key paths,
//     cloud metadata IP). These are the patterns the policy engine's
//     HighRiskShellPatterns slice enumerates; the shim defers to the
//     engine so the canonical list lives in one place.
//  3. Forward allowed commands to the real binary the agent intended.
//
// What this package owns and what it does NOT own
//
// The shim owns:
//
//   - The shell-commands.jsonl record shape (ShellCommandRecord).
//   - The log writer (ShellCommandsLog), an append-only JSONL file in
//     the run directory. The shim is the only writer because every
//     intercepted command flows through one Run call per attempt.
//   - The decision-then-exec flow (Run): evaluate via the engine, log
//     the verdict, then either deny with an error or forward to the
//     real binary via exec.
//   - The "real binary" resolver: given the program name the agent
//     invoked (e.g. "bash"), the shim asks ExecLookPath to find the
//     real executable on PATH, taking care to skip its own location so
//     the wrapper does not recurse into itself.
//
// The shim does NOT own:
//
//   - The decision rules. Every verdict is the policy engine's; the
//     shim is a thin wrapper that calls Evaluate and respects the
//     returned PolicyDecision.
//   - The supervisor lifecycle. The shim is invoked one command at a
//     time; it does not manage subprocess timeouts, stdout streaming,
//     or signal forwarding (those belong to internal/run.Supervisor).
//     A future cooperative tool protocol may invoke the shim from a
//     long-running process; today every Run call is one-shot.
//   - The policy-decisions.jsonl writer. That is internal/run's
//     PolicyDecisionsWriter and lives in a higher layer. The shim
//     emits the shell-commands trail (the human-readable command log);
//     the run-side wiring (plan 08 step 9) is responsible for
//     forwarding the engine's PolicyDecision into the
//     policy-decisions trail when both are present.
//
// Limitations (plan 08 step 10 documents these to the operator; the
// notes below are the implementation rationale)
//
//   - Agents may invoke absolute paths. The shim only catches commands
//     that resolve through PATH; an agent that calls /usr/bin/curl
//     directly bypasses this wrapper. Filesystem isolation and the
//     network policy remain the real boundary.
//   - Static binaries bypass shell wrappers entirely. The shim
//     intercepts shells (bash / sh), not arbitrary executables.
//   - Interpreters can execute code internally. A python -c "..." call
//     is one command to the shim; the shim cannot see the inner
//     statements.
//   - Kernel-level and network-level controls remain the real
//     boundary. The shim is defense-in-depth, not the primary
//     enforcement surface.
//
// Concurrency
//
// Run is safe for concurrent use. ShellCommandsLog serializes its
// writes under a mutex so two goroutines emitting concurrent records
// cannot interleave bytes inside a JSON line. The exec call itself
// runs on the goroutine that called Run; the shim does not spawn
// background workers.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// shellCommandsFileName is the basename of the per-run shell-commands
// JSONL log the shim appends to. It lives at the root of the run
// directory next to lifecycle.jsonl and policy-decisions.jsonl so a
// reviewer reading a run on disk sees the lifecycle trail, the policy
// decision trail, and the shell command trail side by side. Mirrors the
// constants in internal/run that name the other per-run JSONL files.
const shellCommandsFileName = "shell-commands.jsonl"

// ShellCommandRecord is one entry in shell-commands.jsonl. The shape is
// deliberately small: the file is the human-readable command-attempt
// log, distinct from policy-decisions.jsonl (which carries the engine
// verdicts). An auditor reads shell-commands.jsonl to see what an agent
// tried to run; they cross-reference policy-decisions.jsonl by EventID
// to see why the engine ruled the way it did.
//
// Field order is the on-disk byte layout (encoding/json honors struct
// field order); keep new fields appended so historical records remain
// byte-stable.
type ShellCommandRecord struct {
	// Timestamp is the moment the shim observed the attempt, formatted
	// as RFC3339 with a numeric timezone offset. The writer fills this
	// in at write time using its clock; callers do not set it.
	Timestamp string `json:"timestamp"`

	// RunID is the run this record belongs to. Duplicated into every
	// record so a future aggregator can concatenate
	// shell-commands.jsonl files from many runs without losing
	// attribution. Required.
	RunID string `json:"run_id"`

	// Program is the binary the agent invoked (e.g. "bash", "curl").
	// This is the first token of the command line; argv[0] from the
	// caller's perspective. Required.
	Program string `json:"program"`

	// Argv is the parsed argument vector the agent supplied (including
	// Program at index 0). Stored as a slice so a consumer reading the
	// JSON can switch on individual arguments without re-tokenizing.
	// Required.
	Argv []string `json:"argv"`

	// CmdLine is the human-readable space-joined command line the
	// agent issued. Mirrors what the operator would type to reproduce
	// the attempt. The engine's deny_patterns match against this
	// string. Required.
	CmdLine string `json:"cmd_line"`

	// Phase distinguishes a setup-time invocation ("setup") from an
	// agent-time invocation ("agent"). The engine's rule logic does
	// not switch on phase today, but the record preserves it for
	// auditors. Optional; an empty phase records as the empty string.
	Phase string `json:"phase,omitempty"`

	// Decision is the engine verdict for this attempt, as a string
	// (one of "allow", "ask", "deny", "quarantine", "warn"). Required.
	Decision string `json:"decision"`

	// PolicyEventID is the engine's unique "evt_<ts>_<hex>" identifier
	// for the PolicyDecision that produced Decision. An auditor uses
	// it to look the full verdict up in policy-decisions.jsonl.
	// Required (the engine always stamps one).
	PolicyEventID string `json:"policy_event_id"`

	// Reason is the engine's human-readable explanation for the
	// verdict. Copied onto the shell-commands record so an operator
	// reading the file does not have to cross-reference
	// policy-decisions.jsonl for the common "why was this denied"
	// question. Required on deny / ask / quarantine; optional on
	// allow / warn.
	Reason string `json:"reason,omitempty"`

	// Forwarded is true when the shim actually invoked the real
	// binary after the engine returned allow (or warn). False on deny
	// / ask / quarantine, or on allow when the caller passed an
	// ExecRunner that declined to run. Distinguishes a successful
	// forward from a successful policy match that did not execute.
	Forwarded bool `json:"forwarded"`

	// ExitCode is the real binary's exit code when Forwarded is true.
	// Zero on a clean exit; non-zero on a child error. Omitted when
	// the shim did not forward (Forwarded == false).
	ExitCode int `json:"exit_code,omitempty"`

	// Error is the shim's own error string when the forward failed
	// (exec.LookPath could not find the binary, the child returned a
	// non-zero exit, etc.). Distinct from Reason (the engine's
	// verdict explanation) so a consumer can tell a policy refusal
	// from an execution failure. Optional.
	Error string `json:"error,omitempty"`
}

// ExecResult captures the outcome of forwarding a command to the real
// binary. The shim returns this so callers can render an operator-
// facing message ("command exited with code 1") without re-running the
// command. ExitCode is the child's exit status; Error carries any
// runtime failure (exec.LookPath miss, child crash, context
// cancellation).
type ExecResult struct {
	// ExitCode is the real binary's exit code. Zero on clean exit;
	// non-zero on any failure exit. -1 when the child was never
	// started (e.g. exec.LookPath failed).
	ExitCode int

	// Err is the runtime failure, if any. Distinct from "the child
	// exited non-zero": a child that ran and exited with code 1
	// returns ExitCode=1 and Err=nil. A child that could not be
	// started (binary missing, context canceled) returns ExitCode=-1
	// and Err non-nil.
	Err error
}

// ExecRunner is the function the shim calls to forward an allowed
// command to the real binary. It receives the resolved binary path
// (the absolute path exec.LookPath returned, with the shim's own
// location filtered out) and the original argv (argv[0] is the program
// name the agent invoked, NOT the resolved path; the runner can choose
// whether to preserve argv[0] for tools that switch on it).
//
// The runner returns an ExecResult so the shim can record the exit
// code on the shell-commands record. A nil runner falls back to the
// default exec.Command-based implementation (DefaultExecRunner) so
// production callers do not have to wire it.
//
// Tests inject a runner that records the call and returns a canned
// ExecResult without spawning a subprocess. The runner runs on the
// goroutine that called Run; it must respect ctx for cancellation.
type ExecRunner func(ctx context.Context, resolvedPath string, argv []string, stdin io.Reader, stdout, stderr io.Writer) ExecResult

// LookPathFunc resolves a program name to the absolute path of the real
// binary on PATH. The shim uses it to find the real bash / sh / curl
// the agent meant to invoke. The default implementation wraps
// exec.LookPath; tests inject a fake that returns a fixed path so the
// resolver tests do not depend on the host PATH.
//
// The resolved path is checked against the shim's own location
// (Shim.selfPath) before being used, so the wrapper cannot recurse
// into itself when an operator places it in front of the real binary
// on PATH.
type LookPathFunc func(program string) (string, error)

// DefaultExecRunner is the production ExecRunner. It uses os/exec to
// spawn the real binary, wires stdin / stdout / stderr from the
// caller, and translates the child's exit code into the ExecResult
// shape.
//
// The implementation is intentionally small: the shim is the policy
// boundary, not the supervision boundary. Production callers that
// need streaming output, signal forwarding, or timeouts compose those
// on top of the shim (or pass their own ExecRunner that delegates to
// the internal/run.Supervisor's launch path).
func DefaultExecRunner(ctx context.Context, resolvedPath string, argv []string, stdin io.Reader, stdout, stderr io.Writer) ExecResult {
	args := []string{}
	if len(argv) > 1 {
		args = argv[1:]
	}
	cmd := exec.CommandContext(ctx, resolvedPath, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		// exec.ExitError carries the child's exit code; wrap it so
		// the caller can distinguish a non-zero exit (still a clean
		// run) from a process-start failure.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return ExecResult{ExitCode: exitErr.ExitCode(), Err: nil}
		}
		return ExecResult{ExitCode: -1, Err: err}
	}
	return ExecResult{ExitCode: 0, Err: nil}
}

// ShellCommandsLog is the append-only JSONL writer for
// shell-commands.jsonl. The shim opens one per run during construction
// and closes it during shutdown; every Run call writes exactly one
// record.
//
// The shape mirrors internal/run's PolicyDecisionsWriter (mutex +
// O_APPEND file + injected clock) so the two writers behave
// identically from an operator's perspective: append-only,
// concurrency-safe, with timestamps stamped by the writer rather than
// the caller. Keeping the writer in internal/policy keeps the shim
// self-contained (no import cycle on internal/run); a future refactor
// that unifies the per-run JSONL writers can replace both with one
// generic implementation.
type ShellCommandsLog struct {
	// mu serializes writes so two concurrent Run calls cannot
	// interleave bytes inside a single JSON line. The encode + write
	// pair is logical, not just byte-level, so the mutex covers both
	// halves.
	mu sync.Mutex

	// w is the underlying writer (typically an *os.File opened with
	// O_APPEND). The shim does not own the close lifecycle when w is
	// an externally-supplied writer; OpenShellCommandsLog hands the
	// shim an *os.File and tracks it on file so Close can release it.
	w io.Writer

	// file is the underlying file handle when the log was opened via
	// OpenShellCommandsLog. Used by Close to release the OS resource.
	// Nil when the log was constructed with NewShellCommandsLog
	// against an externally-owned writer.
	file *os.File

	// runID is the run identifier copied into every record's RunID
	// field. Stored on the log rather than passed per-call because
	// the shim binds one log per run and does not log commands across
	// run boundaries.
	runID string

	// now produces the timestamp stamped on each record. A function
	// (rather than a clock interface) so tests can inject a
	// deterministic sequence of times without a separate type;
	// production callers pass time.Now.
	now func() time.Time

	// closed guards Close from racing with itself and prevents Write
	// after Close from panicking on a stale file handle.
	closed bool
}

// ShellCommandsLogOptions bundles the per-run metadata a
// ShellCommandsLog needs at construction. RunID is required; Now is
// optional and falls back to time.Now when nil.
type ShellCommandsLogOptions struct {
	// RunID is the run identifier this log's records belong to.
	// Required.
	RunID string

	// Now is the clock the writer uses to stamp Timestamp on each
	// record. Nil falls back to time.Now. Tests inject a fixed-step
	// clock so the on-disk timestamps are deterministic.
	Now func() time.Time
}

// OpenShellCommandsLog opens (or creates and appends to) the
// shell-commands.jsonl file for the run directory at runDir, wires it
// to the supplied options, and returns a ShellCommandsLog ready to
// accept records.
//
// runDir is the absolute path to the run directory (the same value
// RunDirectory.Path carries in internal/run). The file is opened with
// O_APPEND so the writer cooperates correctly with the empty
// placeholder CreateRunDirectory leaves behind, and so a reopen of an
// existing run (future replay tooling) adds to the trail rather than
// truncating it.
//
// Returns an error when the file cannot be opened or when any required
// option is empty. On error no file handle is leaked.
func OpenShellCommandsLog(runDir string, opts ShellCommandsLogOptions) (*ShellCommandsLog, error) {
	if strings.TrimSpace(runDir) == "" {
		return nil, errors.New("policy: OpenShellCommandsLog requires runDir")
	}
	if strings.TrimSpace(opts.RunID) == "" {
		return nil, errors.New("policy: OpenShellCommandsLog requires RunID")
	}

	path := filepath.Join(runDir, shellCommandsFileName)
	// 0o644: the run directory itself is already 0o700; the
	// placeholder file CreateRunDirectory left has the same mode. We
	// reuse the standard runFileMode value via the literal so the
	// shim package does not import internal/run for one constant.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("policy: open shell commands log %s: %w", path, err)
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}

	return &ShellCommandsLog{
		w:     f,
		file:  f,
		runID: opts.RunID,
		now:   clock,
	}, nil
}

// NewShellCommandsLog wraps an externally-supplied writer in a
// ShellCommandsLog. Tests use this path to drive the log against a
// bytes.Buffer; production code uses OpenShellCommandsLog. The caller
// owns the underlying writer's lifecycle: Close on the returned log
// does NOT close w when it was supplied via this constructor.
func NewShellCommandsLog(w io.Writer, opts ShellCommandsLogOptions) (*ShellCommandsLog, error) {
	if w == nil {
		return nil, errors.New("policy: NewShellCommandsLog requires a writer")
	}
	if strings.TrimSpace(opts.RunID) == "" {
		return nil, errors.New("policy: NewShellCommandsLog requires RunID")
	}
	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}
	return &ShellCommandsLog{
		w:     w,
		runID: opts.RunID,
		now:   clock,
	}, nil
}

// Write appends a single ShellCommandRecord to the underlying log. The
// record's Timestamp and RunID are filled in from the writer's stored
// metadata; every other field comes from the caller's rec verbatim so
// the shim controls the on-disk payload.
//
// The encoded line is a single JSON object followed by exactly one
// newline byte. The mutex makes the encode + write pair atomic with
// respect to other callers: two goroutines emitting concurrently
// produce two consecutive whole records rather than one interleaved
// line.
//
// Write is safe for concurrent use. A Write after Close returns an
// error rather than panicking.
func (l *ShellCommandsLog) Write(rec ShellCommandRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return errors.New("policy: write after close on shell commands log")
	}

	rec.RunID = l.runID
	rec.Timestamp = l.now().Format(time.RFC3339)

	if rec.Program == "" {
		return errors.New("policy: shell command record requires Program")
	}
	if rec.CmdLine == "" {
		return errors.New("policy: shell command record requires CmdLine")
	}
	if rec.Decision == "" {
		return errors.New("policy: shell command record requires Decision")
	}
	if rec.PolicyEventID == "" {
		return errors.New("policy: shell command record requires PolicyEventID")
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("policy: marshal shell command record: %w", err)
	}
	data = append(data, '\n')

	if _, err := l.w.Write(data); err != nil {
		return fmt.Errorf("policy: write shell command record: %w", err)
	}
	if l.file != nil {
		// Best-effort fsync so a supervisor crash does not lose the
		// most recent attempt. A sync failure is not fatal: the bytes
		// are already in the kernel page cache and survive a process
		// crash; only a host crash can lose them.
		_ = l.file.Sync()
	}
	return nil
}

// Close releases the underlying file handle (when the log was opened
// via OpenShellCommandsLog). A Close on a log constructed with
// NewShellCommandsLog is a no-op because the caller owns the writer.
// Close is safe to call more than once; the second call returns nil.
func (l *ShellCommandsLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			return fmt.Errorf("policy: close shell commands log: %w", err)
		}
	}
	return nil
}

// Shim is the shell-shim prototype. One Shim is constructed per run
// (the supervisor wires it during plan 08 step 9 setup) and used for
// every command the agent issues. Run is safe for concurrent use.
//
// The shim owns three collaborators:
//
//   - engine: the PolicyEngine that decides allow / deny.
//   - log: the ShellCommandsLog the shim appends each attempt to.
//   - exec / lookPath: the indirection points tests use to drive the
//     shim without spawning real subprocesses.
//
// selfPath is the absolute path of the shim binary itself (when the
// shim is installed as a PATH wrapper). If the shim's lookPath
// resolver returns selfPath for a given program, the shim treats it
// as an infinite-recursion attempt and returns an error rather than
// forwarding. Production callers pass os.Executable(); tests leave it
// empty to disable the recursion guard.
type Shim struct {
	engine   *PolicyEngine
	log      *ShellCommandsLog
	exec     ExecRunner
	lookPath LookPathFunc
	selfPath string
}

// ShimOptions bundles the construction parameters NewShim consumes.
// Engine is required; Log is optional (a shim without a log still
// evaluates and forwards, it just does not persist the attempt trail).
// Exec, LookPath, and SelfPath are dependency-injection points: nil /
// empty values fall back to documented defaults.
type ShimOptions struct {
	// Engine is the PolicyEngine the shim consults for every Run
	// call. Required; a nil Engine returns a construction error.
	Engine *PolicyEngine

	// Log is the shell-commands.jsonl writer. Optional: a nil Log
	// means the shim still evaluates and forwards but does not
	// persist the attempt trail. The supervisor always wires a Log
	// when it constructs a shim; tests that only care about the
	// decision path leave it nil.
	Log *ShellCommandsLog

	// Exec is the function the shim invokes to forward an allowed
	// command to the real binary. Nil falls back to
	// DefaultExecRunner; tests inject a recorder.
	Exec ExecRunner

	// LookPath resolves a program name to the real binary on PATH.
	// Nil falls back to exec.LookPath; tests inject a fake that
	// returns a fixed path so the resolver tests do not depend on the
	// host PATH.
	LookPath LookPathFunc

	// SelfPath is the absolute path of the shim binary itself. The
	// shim uses it to detect "lookPath returned my own path", which
	// would cause an infinite recursion if the shim forwarded to it.
	// Empty disables the recursion guard (the default for tests that
	// inject a LookPath returning a known-safe path).
	SelfPath string
}

// NewShim constructs a Shim from opts. Returns an error when Engine is
// nil or when any required field is empty; the shim does not silently
// substitute a default engine because a misconfigured caller's
// commands would otherwise be evaluated against an unknown ruleset.
func NewShim(opts ShimOptions) (*Shim, error) {
	if opts.Engine == nil {
		return nil, errors.New("policy: NewShim requires an Engine")
	}
	execFn := opts.Exec
	if execFn == nil {
		execFn = DefaultExecRunner
	}
	lookPath := opts.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	return &Shim{
		engine:   opts.Engine,
		log:      opts.Log,
		exec:     execFn,
		lookPath: lookPath,
		selfPath: strings.TrimSpace(opts.SelfPath),
	}, nil
}

// RunOptions bundles the per-call parameters Run consumes. Argv is
// required (Argv[0] is the program name); Phase, Stdin, Stdout, Stderr
// are optional and default to sensible empty / discard values.
type RunOptions struct {
	// Argv is the command and its arguments the agent issued. Argv[0]
	// is the program name; Argv[1:] are the arguments. The shim does
	// not split a CmdLine string for the caller (shell tokenization
	// is ambiguous); the supervisor passes a pre-parsed argv from
	// whatever shell-front it integrated with. Required and must be
	// non-empty.
	Argv []string

	// Phase distinguishes a setup-time invocation ("setup") from an
	// agent-time invocation ("agent"). Optional; an empty phase
	// records as the empty string on the on-disk record. The engine
	// does not switch on phase today, but the metadata is preserved
	// for auditors.
	Phase string

	// Stdin / Stdout / Stderr are the streams the shim wires into the
	// real binary when it forwards an allowed command. All three are
	// optional: nil Stdin maps to no input, nil Stdout / Stderr maps
	// to io.Discard so the child does not block on a missing
	// consumer.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Run is the shim's single entry point: it evaluates one command
// attempt against the engine, logs the verdict to shell-commands.jsonl,
// and either forwards to the real binary (on allow / warn) or returns
// an error (on deny / ask / quarantine).
//
// The return value is the PolicyDecision the engine produced plus the
// ExecResult from the forwarded child (zero value when the shim did
// not forward). A returned error indicates either a deny verdict
// (policy refusal: ErrShimDenied) or a runtime failure (engine
// missing, log write failed, exec lookup failed); callers
// distinguish them by errors.Is(err, ErrShimDenied).
//
// Run is safe for concurrent use; the engine and the log are both
// thread-safe and the exec call runs on the caller's goroutine.
func (s *Shim) Run(ctx context.Context, opts RunOptions) (PolicyDecision, ExecResult, error) {
	if s == nil {
		return PolicyDecision{}, ExecResult{}, errors.New("policy: nil shim")
	}
	if len(opts.Argv) == 0 {
		return PolicyDecision{}, ExecResult{}, errors.New("policy: Shim.Run requires a non-empty Argv")
	}
	if strings.TrimSpace(opts.Argv[0]) == "" {
		return PolicyDecision{}, ExecResult{}, errors.New("policy: Shim.Run requires a non-empty program name")
	}

	program := opts.Argv[0]
	cmdLine := strings.Join(opts.Argv, " ")

	// Evaluate first so the log record carries the verdict. The
	// engine's evalShellCommand fires the high-risk patterns ahead of
	// policy.commands.deny_patterns and the default rule, so an
	// agent that issues curl-pipe-shell sees DecisionDeny regardless
	// of the user's policy.yaml.
	evt := Event{
		Type:   EventShellCommand,
		Action: "exec",
		Target: cmdLine,
		Metadata: map[string]string{
			"argv":    cmdLine,
			"program": program,
		},
	}
	if phase := strings.TrimSpace(opts.Phase); phase != "" {
		evt.Metadata["phase"] = phase
	}
	dec := s.engine.Evaluate(evt)

	rec := ShellCommandRecord{
		Program:       program,
		Argv:          append([]string(nil), opts.Argv...),
		CmdLine:       cmdLine,
		Phase:         strings.TrimSpace(opts.Phase),
		Decision:      string(dec.Type),
		PolicyEventID: dec.EventID,
		Reason:        dec.Reason,
	}

	// Deny / ask / quarantine: refuse the command. The log is written
	// before the return so an operator reviewing the run sees the
	// attempt even when the supervisor crashes immediately after.
	if dec.Type != DecisionAllow && dec.Type != DecisionWarn {
		if err := s.writeLog(rec); err != nil {
			return dec, ExecResult{}, err
		}
		return dec, ExecResult{}, fmt.Errorf("%w: %s", ErrShimDenied, dec.Reason)
	}

	// Allow / warn: resolve the real binary and forward. A resolver
	// failure is recorded on the log so an auditor can tell a missing
	// binary apart from a policy refusal.
	resolved, err := s.lookPath(program)
	if err != nil {
		rec.Error = fmt.Sprintf("look up %s on PATH: %v", program, err)
		if writeErr := s.writeLog(rec); writeErr != nil {
			return dec, ExecResult{}, writeErr
		}
		return dec, ExecResult{ExitCode: -1, Err: err}, fmt.Errorf("policy: shim cannot resolve %q: %w", program, err)
	}

	// Recursion guard: when the shim's own binary is installed as a
	// PATH wrapper, lookPath may return the shim's own location.
	// Forwarding to it would recurse forever; we refuse here and
	// surface a clear error to the operator.
	if s.selfPath != "" && pathsEqual(resolved, s.selfPath) {
		rec.Error = fmt.Sprintf("resolved path %s is the shim itself", resolved)
		if writeErr := s.writeLog(rec); writeErr != nil {
			return dec, ExecResult{}, writeErr
		}
		return dec, ExecResult{ExitCode: -1, Err: ErrShimRecursion}, fmt.Errorf("policy: shim refuses to forward to itself at %s: %w", resolved, ErrShimRecursion)
	}

	stdout := opts.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = io.Discard
	}

	result := s.exec(ctx, resolved, opts.Argv, opts.Stdin, stdout, stderr)
	rec.Forwarded = true
	rec.ExitCode = result.ExitCode
	if result.Err != nil {
		rec.Error = result.Err.Error()
	}
	if err := s.writeLog(rec); err != nil {
		return dec, result, err
	}
	return dec, result, nil
}

// writeLog appends rec to the shim's ShellCommandsLog when one is
// configured. A nil log is a no-op so a shim constructed without a log
// (tests that only care about the decision path) still works. The
// helper exists so the nil-log guard lives in one place.
func (s *Shim) writeLog(rec ShellCommandRecord) error {
	if s.log == nil {
		return nil
	}
	return s.log.Write(rec)
}

// pathsEqual compares two filesystem paths for the recursion-guard
// check. It cleans both paths so "/usr/bin/./bash" and "/usr/bin/bash"
// compare equal; symlink resolution is intentionally not performed
// (the caller owns whether to pass an evaluated symlink target).
func pathsEqual(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// ErrShimDenied is the sentinel error Run returns when the engine
// produced a deny / ask / quarantine verdict. Callers test for it via
// errors.Is so a supervisor can distinguish a policy refusal from a
// runtime failure (missing binary, child crash) and surface the right
// message to the operator.
var ErrShimDenied = errors.New("policy: shim refused command")

// ErrShimRecursion is the sentinel error Run returns when the resolver
// returned the shim's own path. Callers test for it via errors.Is so a
// supervisor can surface a clear "shim installed in front of itself"
// diagnostic rather than a generic execution failure.
var ErrShimRecursion = errors.New("policy: shim would recurse into itself")
