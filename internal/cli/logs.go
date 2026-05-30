package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rivan1986/ai-env/internal/run"
)

// LogStream is the enum LogsOptions.Stream accepts. The plan asks for
// `ai-env logs <env-name>` to "tail or display stdout.log and stderr.log";
// in practice operators usually want one or the other (or both
// interleaved). The flag default is "both" so the command surfaces
// every captured byte without the operator having to remember which
// stream the agent wrote to.
type LogStream string

const (
	// LogStreamStdout limits the output to the run's stdout.log.
	LogStreamStdout LogStream = "stdout"

	// LogStreamStderr limits the output to the run's stderr.log.
	LogStreamStderr LogStream = "stderr"

	// LogStreamBoth prints stdout.log followed by stderr.log. The two
	// streams are concatenated rather than interleaved by timestamp
	// because the supervisor does not record per-byte timestamps; an
	// interleaved view would have to invent ordering. Concatenation is
	// honest and matches what `cat stdout.log stderr.log` would do.
	LogStreamBoth LogStream = "both"
)

// LogsOptions captures the parsed flags + positional argument for
// `ai-env logs`. The CLI wiring layer fills this in and passes it to
// RunLogs so the command body has no direct Cobra dependency.
type LogsOptions struct {
	// EnvName is the positional <env-name> argument identifying which
	// env's run logs to print. Required; ignored when RunID is set
	// (the operator picked a specific run by id).
	EnvName string

	// RunID, when non-empty, selects a specific historical run by its
	// directory basename rather than the latest run for EnvName. Used
	// by the --run flag so operators can inspect older runs without
	// re-running the env. When empty, RunLogs falls back to
	// run.LatestRunForEnv(aiEnvDir, EnvName).
	RunID string

	// Stream selects which captured stream(s) to print. Defaults to
	// LogStreamBoth when empty. Invalid values are rejected.
	Stream LogStream

	// Follow asks RunLogs to keep tailing the underlying log file(s)
	// after the initial dump, surfacing newly-appended bytes as they
	// land. Behavior:
	//
	//   - The initial pass dumps every byte currently on disk.
	//   - After that, RunLogs polls the file's size and writes any
	//     new tail to Stdout. Polling (rather than fsnotify) keeps the
	//     implementation cross-platform and dependency-free; the plan
	//     does not require a particular notification mechanism.
	//   - The poll exits when ctx-equivalent cancellation arrives via
	//     Cancel (closed from the signal handler in production) or
	//     when both streams have reached their terminal size (a
	//     terminal run.json state implies no more writes).
	//
	// In tests the --follow path is exercised with a tight FollowPoll
	// and a Cancel channel that the test closes once it has observed
	// the appended bytes.
	Follow bool

	// FollowPoll is the cadence at which the --follow loop checks for
	// newly-appended bytes. Defaults to defaultFollowPoll when zero;
	// negative values are rejected.
	FollowPoll time.Duration

	// Cancel is an optional channel the caller closes to stop a
	// --follow loop. The signal-handling wiring in `cmd/ai-env` will
	// close it on SIGINT once that wiring lands; today it is the only
	// way a unit test exits the loop.
	Cancel <-chan struct{}

	// Cwd is the working directory the command was invoked from.
	// RunLogs walks upward from Cwd looking for the project's
	// .ai-env/ directory (mirroring `ai-env list`/`diff`/`patch`).
	Cwd string

	// Stdout is the writer for the log output.
	Stdout io.Writer

	// Stderr is the writer for warnings (e.g. one of the two streams
	// is empty under LogStreamBoth). Warnings never abort the print.
	Stderr io.Writer
}

// defaultFollowPoll is the cadence at which the --follow loop polls
// the underlying log files for newly-appended bytes. 250ms is fast
// enough to feel live in a terminal while bounding the syscall rate.
// Tests override via LogsOptions.FollowPoll.
const defaultFollowPoll = 250 * time.Millisecond

// RunLogs is the entry point used by the Cobra wiring for
// `ai-env logs`. It locates the target run (by --run, or by the
// latest run for EnvName), opens the configured stream(s), and either
// prints the contents once or tails them when --follow is set.
//
// Errors are surfaced the same way as RunStatus: ErrNoRuns is a clean
// "no runs yet" message and a nil error so the command exits 0;
// everything else wraps with "ai-env logs:".
//
// The command does not parse the log files. They are opaque text
// (whatever the agent wrote). RunLogs is a thin printer that respects
// the operator's stream selection.
func RunLogs(opts LogsOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env logs: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if opts.Stream == "" {
		opts.Stream = LogStreamBoth
	}
	if !isValidLogStream(opts.Stream) {
		return fmt.Errorf("ai-env logs: invalid --stream %q (allowed: stdout, stderr, both)", opts.Stream)
	}
	if opts.FollowPoll < 0 {
		return fmt.Errorf("ai-env logs: --follow-poll must be non-negative, got %v", opts.FollowPoll)
	}
	if opts.RunID == "" {
		if err := ValidateEnvName(opts.EnvName); err != nil {
			return fmt.Errorf("ai-env logs: %w", err)
		}
	} else if opts.EnvName != "" {
		// EnvName is informational when RunID is set: it lets the
		// operator double-check they picked the right run. We still
		// validate it so a typo in the env name fails loudly rather
		// than being silently ignored.
		if err := ValidateEnvName(opts.EnvName); err != nil {
			return fmt.Errorf("ai-env logs: %w", err)
		}
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env logs: %w", err)
	}

	target, err := resolveLogTarget(aiEnvDir, opts.EnvName, opts.RunID)
	if err != nil {
		if errors.Is(err, run.ErrNoRuns) {
			label := opts.EnvName
			if opts.RunID != "" {
				label = opts.RunID
			}
			fmt.Fprintf(opts.Stdout, "no runs recorded for %s yet.\n", label)
			return nil
		}
		return fmt.Errorf("ai-env logs: %w", err)
	}

	// If a specific RunID was requested and an EnvName was also
	// supplied, warn (not fail) when the run.json env_name disagrees
	// so the operator notices a fat-fingered --run pointed at a
	// different env's run.
	if opts.RunID != "" && opts.EnvName != "" && target.EnvName != "" && target.EnvName != opts.EnvName {
		fmt.Fprintf(opts.Stderr,
			"warning: run %s belongs to env %q, but you asked about env %q\n",
			target.ID, target.EnvName, opts.EnvName)
	}

	if err := dumpLogs(opts.Stdout, opts.Stderr, target.Path, opts.Stream); err != nil {
		return fmt.Errorf("ai-env logs: %w", err)
	}

	if opts.Follow {
		poll := opts.FollowPoll
		if poll == 0 {
			poll = defaultFollowPoll
		}
		if err := followLogs(opts.Stdout, opts.Stderr, target.Path, opts.Stream, poll, opts.Cancel); err != nil {
			return fmt.Errorf("ai-env logs: %w", err)
		}
	}
	return nil
}

// resolveLogTarget picks the run directory RunLogs streams from. When
// runID is set, it tries that specific run; otherwise it falls back to
// the latest run for envName. Either branch surfaces ErrNoRuns when
// nothing exists so the caller can short-circuit to the empty-state
// message.
func resolveLogTarget(aiEnvDir, envName, runID string) (run.RunSummary, error) {
	if runID != "" {
		return run.FindRunByID(aiEnvDir, runID)
	}
	return run.LatestRunForEnv(aiEnvDir, envName)
}

// isValidLogStream gates the --stream flag's input.
func isValidLogStream(s LogStream) bool {
	switch s {
	case LogStreamStdout, LogStreamStderr, LogStreamBoth:
		return true
	}
	return false
}

// dumpLogs prints the requested stream(s) of the run directory at
// runPath to stdout. Both files are always present (they were
// materialized as empty placeholders by run.CreateRunDirectory), so
// stat-then-open succeeds even on a brand-new run; an empty file is
// dumped as zero bytes.
//
// For LogStreamBoth we print stdout then a small banner then stderr
// when both are non-empty, so a reader can tell where one ends and
// the other begins. If only one of the two has content under
// LogStreamBoth we skip the banner and just print the populated
// stream; emitting a "stderr:" header above an empty file is just
// noise.
func dumpLogs(stdout, stderr io.Writer, runPath string, stream LogStream) error {
	switch stream {
	case LogStreamStdout:
		return copyLog(stdout, run.StdoutLogPath(runPath))
	case LogStreamStderr:
		return copyLog(stdout, run.StderrLogPath(runPath))
	case LogStreamBoth:
		outPath := run.StdoutLogPath(runPath)
		errPath := run.StderrLogPath(runPath)
		outSize, _ := fileSize(outPath)
		errSize, _ := fileSize(errPath)
		printedAny := false
		if outSize > 0 {
			fmt.Fprintln(stdout, "==> stdout <==")
			if err := copyLog(stdout, outPath); err != nil {
				return err
			}
			printedAny = true
		}
		if errSize > 0 {
			if printedAny {
				fmt.Fprintln(stdout, "")
			}
			fmt.Fprintln(stdout, "==> stderr <==")
			if err := copyLog(stdout, errPath); err != nil {
				return err
			}
			printedAny = true
		}
		if !printedAny {
			fmt.Fprintln(stderr, "(no output captured yet)")
		}
		return nil
	}
	return fmt.Errorf("invalid stream %q", stream)
}

// copyLog opens the file at path and copies its full contents to dst.
// An ENOENT is reported as "log file missing" so a future replay tool
// that prunes individual files surfaces a precise diagnostic.
func copyLog(dst io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("log file missing: %s", path)
		}
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := io.Copy(dst, f); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

// fileSize returns the byte size of path, or 0 if the file does not
// exist. Errors other than ENOENT are returned so the caller can
// surface them; "file is empty / not yet written" is the common case
// and folds neatly into a zero result.
func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return info.Size(), nil
}

// followLogs polls the underlying log file(s) for newly-appended
// bytes and writes them to stdout as they appear. The loop exits when
// cancel fires (typically wired to a SIGINT signal) or, when the run
// has reached a terminal state on disk, after one quiet poll where
// neither stream grew.
//
// followLogs deliberately uses polling rather than fsnotify so the
// implementation stays dependency-free and works on every OS we care
// about. The poll interval is small (defaultFollowPoll) so the lag
// between an agent write and the user seeing it is dominated by the
// kernel's writeback, not by our cadence.
func followLogs(stdout, stderr io.Writer, runPath string, stream LogStream, poll time.Duration, cancel <-chan struct{}) error {
	// Snapshot the size of each followed file so the next poll only
	// copies bytes that arrived after the initial dump.
	outPath := run.StdoutLogPath(runPath)
	errPath := run.StderrLogPath(runPath)

	outOffset, err := fileSize(outPath)
	if err != nil {
		return err
	}
	errOffset, err := fileSize(errPath)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		select {
		case <-cancel:
			return nil
		case <-ticker.C:
		}

		grew := false
		if stream == LogStreamStdout || stream == LogStreamBoth {
			n, err := streamAppendedBytes(stdout, outPath, outOffset)
			if err != nil {
				return err
			}
			if n > 0 {
				outOffset += n
				grew = true
			}
		}
		if stream == LogStreamStderr || stream == LogStreamBoth {
			n, err := streamAppendedBytes(stdout, errPath, errOffset)
			if err != nil {
				return err
			}
			if n > 0 {
				errOffset += n
				grew = true
			}
		}

		// Exit condition for unattended scripts: if the run has
		// reached a terminal state and the latest poll saw no new
		// bytes, there is nothing more to follow.
		if !grew && isRunTerminal(runPath) {
			return nil
		}
	}
}

// streamAppendedBytes reads bytes after offset from path and writes
// them to dst. Returns the number of bytes written so the caller can
// advance its tracked offset. Files that have not yet grown past the
// offset return (0, nil) without opening anything.
func streamAppendedBytes(dst io.Writer, path string, offset int64) (int64, error) {
	size, err := fileSize(path)
	if err != nil {
		return 0, err
	}
	if size <= offset {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek %s: %w", path, err)
	}
	n, err := io.Copy(dst, f)
	if err != nil {
		return n, fmt.Errorf("read %s: %w", path, err)
	}
	return n, nil
}

// isRunTerminal reports whether the run at runPath has reached a
// terminal state per its on-disk run.json. Used by the --follow loop
// as a stop condition so an unattended script does not poll forever
// after the agent has completed. A missing or unreadable run.json
// returns false (we keep following), which is the conservative
// behavior: better to wait than to hang up too early.
func isRunTerminal(runPath string) bool {
	rec, err := run.ReadRecord(runPath)
	if err != nil {
		return false
	}
	return rec.State.IsTerminal()
}
