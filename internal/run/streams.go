package run

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// stdoutFileName and stderrFileName are the basenames of the per-run
// stdout/stderr capture files. They live at the root of the run
// directory next to lifecycle.jsonl and run.json so an operator
// reviewing a run on disk sees the agent's output side by side with the
// lifecycle trail and the snapshot record. The constants mirror
// lifecycleFileName / runJSONFileName; keeping the filenames in this
// file rather than redeclaring them means the stream writer is the
// single owner of the names even though run.go materialized the
// placeholders.
const (
	stdoutFileName = "stdout.log"
	stderrFileName = "stderr.log"
)

// defaultTailBufferBytes is the size of the in-memory tail buffer each
// stream keeps for terminal display and idle detection. The plan
// (section 16 of plan 03) says stdout/stderr are streamed to disk and
// "a bounded tail buffer may be kept for terminal display and idle
// detection"; 64 KiB per stream is enough to render a full xterm
// scrollback page without blowing up the supervisor's resident memory,
// while keeping the supervisor able to surface the most recent output
// without re-reading the on-disk log every poll cycle. Callers that
// need a larger or smaller tail can override via StreamOptions.TailSize.
const defaultTailBufferBytes = 64 * 1024

// StreamCapture owns the on-disk stdout.log and stderr.log files for a
// single run and exposes them as io.Writer endpoints the supervisor
// hooks into an exec.Cmd. It is the implementation of plan 03 step 7:
// stdout and stderr are streamed to disk as the child process writes
// them (no end-of-run buffering), the two streams are independent
// (slow consumers on one do not block the other), and the captured
// bytes survive a supervisor crash because every write lands in the
// kernel write path before Write returns.
//
// Design notes (why this looks the way it does):
//
//   - Two independent files, two independent mutexes. The supervisor
//     wires stdout to Stdout() and stderr to Stderr() and the runtime
//     keeps them independent: a 1 GiB stderr burst must not delay
//     stdout updates the user is watching live. exec.Cmd already calls
//     Write from two distinct goroutines (one per stream); we keep them
//     decoupled all the way down to the file handle.
//
//   - Append-mode file handles. We open with O_APPEND so a future
//     out-of-band writer (the shell shim, an external tee) appending to
//     the same file lands whole writes rather than racing on the file
//     offset. CreateRunDirectory already created the placeholder files,
//     so O_APPEND|O_WRONLY without O_CREATE would work too; we add
//     O_CREATE defensively to keep the constructor robust against a
//     supervisor that re-opens after manual cleanup.
//
//   - No internal buffering. We do NOT wrap the file in a bufio.Writer.
//     The plan's "stream to disk, not buffered in memory" rule and the
//     crash-safety requirement mean every write must be observable on
//     disk before Write returns to the caller. *os.File.Write goes
//     straight to the write syscall, which copies into the kernel page
//     cache; that is enough for "visible after a write without Close"
//     and survives a supervisor crash because the bytes are no longer
//     in our process's memory. We deliberately do NOT fsync on every
//     write: the agent process can produce stdout at MB/sec rates and
//     fsync-per-write would gate that on the disk's IOPS budget. A host
//     crash (not just a supervisor crash) can still lose a small tail
//     of bytes; that is the plan's documented trade-off in favour of
//     throughput. Lifecycle events, which are tiny and infrequent, do
//     fsync; stream output, which can be a firehose, does not.
//
//   - Bounded tail buffer per stream. The plan explicitly permits a
//     "bounded tail buffer for terminal display and idle detection".
//     We keep the last N bytes in a ring buffer per stream, accessible
//     via TailStdout / TailStderr, so step 8's supervisor can display
//     the tail in `ai-env status` and the idle detector can timestamp
//     the most recent write without re-reading the on-disk log.
//
//   - Last-output timestamp. The idle timeout (step 8) needs to know
//     when the most recent byte arrived on either stream. We record it
//     here under each stream's own mutex so the supervisor can read
//     LastOutputAt without taking a write-side lock.
//
//   - Close is idempotent. The supervisor's defer-close pattern and
//     the post-run drain may both reach Close; the second call must be
//     a no-op rather than a double-close panic.
//
// Construction goes through OpenStreamCapture so the file handles, the
// tail buffer sizes, and the clock are wired in once. The handles stay
// open for the lifetime of the run.
type StreamCapture struct {
	// stdout and stderr are the per-stream state. They are independent
	// so callers writing to one do not contend on the other's mutex.
	// Each holds its own file handle, mutex, tail buffer, byte counter,
	// and last-output timestamp.
	stdout *stream
	stderr *stream

	// closeOnce guards the Close path so concurrent or repeated Close
	// calls fan in to a single tear-down. The supervisor's deferred
	// Close and the post-run drain's explicit Close both reach this; a
	// sync.Once is the lightest way to make the second arrival a no-op.
	closeOnce sync.Once
	// closeErr is the error returned to every Close caller. Captured
	// inside closeOnce.Do so a later Close sees the same outcome the
	// first one observed.
	closeErr error
}

// stream is the per-channel state behind StreamCapture. Each direction
// (stdout, stderr) owns one. Splitting the state out into a tiny struct
// keeps the StreamCapture aggregate readable and makes the locking
// granularity explicit: write paths take stream.mu, never the sibling's
// mu, so the two streams really do progress independently.
type stream struct {
	// mu serializes Write, tail snapshot reads, and the byte counter
	// against the close path. POSIX O_APPEND already serializes the
	// file-offset side of concurrent writes; the mutex covers the
	// logical write (file.Write + tail.Write + bytesWritten increment +
	// lastOutput stamp) so a snapshot reader observes a consistent
	// state.
	mu sync.Mutex

	// file is the open per-stream log file (stdout.log or stderr.log).
	// Kept open for the lifetime of the StreamCapture so the hot path
	// is a single Write syscall; Close releases it exactly once via the
	// parent's closeOnce.
	file *os.File

	// path is the absolute path of the on-disk log file. It is held
	// for diagnostics (error messages) and for Path() accessors so
	// callers building "tail -f" commands do not have to re-derive the
	// path from the run directory.
	path string

	// closed reflects whether the file handle has been released. Read
	// paths consult it under mu so a Write-after-Close returns a clear
	// error rather than crashing on a stale descriptor.
	closed bool

	// tail is the bounded in-memory ring buffer holding the most recent
	// bytes written to this stream. Its size is fixed at construction.
	// The supervisor's status command reads the tail without disturbing
	// the file handle; the idle detector uses LastOutputAt alongside it.
	tail *tailBuffer

	// bytesWritten counts the total bytes written to this stream since
	// the StreamCapture was opened. The supervisor uses it to enforce
	// max_stdout_bytes / max_stderr_bytes (step 8); exposing it from
	// here means the supervisor does not have to stat the file.
	bytesWritten int64

	// lastOutput is the wall-clock time of the most recent successful
	// Write. Zero if no write has happened yet. The idle detector polls
	// it; the supervisor's stats event records it as last_output_at.
	lastOutput time.Time

	// now is the clock used to stamp lastOutput. Stored per stream so
	// tests can pin one stream's time without affecting the other,
	// although in production both streams share the same clock.
	now func() time.Time
}

// StreamOptions bundles the knobs OpenStreamCapture accepts. All fields
// are optional and have sensible defaults so the production call site
// is a single OpenStreamCapture(runDir, StreamOptions{}) when no
// customization is needed.
type StreamOptions struct {
	// TailSize is the size in bytes of each stream's in-memory tail
	// buffer. Zero (the typical value) falls back to
	// defaultTailBufferBytes. Negative values are rejected by the
	// constructor; explicitly disabling the tail buffer (e.g. for a
	// memory-constrained build) is done by setting a tiny value rather
	// than by toggling a flag, so the API surface stays small.
	TailSize int

	// Now is the clock used to stamp the per-stream LastOutputAt.
	// Defaults to time.Now when nil. Tests inject a fixed clock so the
	// idle-timer assertions are deterministic.
	Now func() time.Time
}

// OpenStreamCapture opens stdout.log and stderr.log under runDir,
// wires them through the StreamOptions, and returns a StreamCapture
// ready to feed an exec.Cmd's Stdout and Stderr fields. Both files are
// opened in append mode so the placeholders CreateRunDirectory left in
// place are extended, not truncated.
//
// runDir is the absolute path to the run directory (typically
// RunDirectory.Path). If either file cannot be opened, the other (if
// already open) is closed before the error is returned so no file
// handle is leaked on the failure path.
func OpenStreamCapture(runDir string, opts StreamOptions) (*StreamCapture, error) {
	if runDir == "" {
		return nil, errors.New("run: OpenStreamCapture requires runDir")
	}
	if opts.TailSize < 0 {
		return nil, fmt.Errorf("run: OpenStreamCapture: TailSize must be non-negative, got %d", opts.TailSize)
	}

	tailSize := opts.TailSize
	if tailSize == 0 {
		tailSize = defaultTailBufferBytes
	}
	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}

	stdout, err := openStream(filepath.Join(runDir, stdoutFileName), tailSize, clock)
	if err != nil {
		return nil, fmt.Errorf("run: open stdout capture: %w", err)
	}
	stderr, err := openStream(filepath.Join(runDir, stderrFileName), tailSize, clock)
	if err != nil {
		// Roll back the stdout handle so a constructor failure leaves
		// no descriptors leaked. The mutex is unnecessary here because
		// the caller has not been handed the StreamCapture yet.
		_ = stdout.file.Close()
		return nil, fmt.Errorf("run: open stderr capture: %w", err)
	}

	return &StreamCapture{
		stdout: stdout,
		stderr: stderr,
	}, nil
}

// openStream opens a single per-stream log file in append mode and
// wires the tail buffer + clock around it. It is shared by both
// streams so the open flags and mode stay in lockstep.
func openStream(path string, tailSize int, now func() time.Time) (*stream, error) {
	// O_APPEND so multiple writers (the agent process via exec.Cmd, a
	// future shell-shim contributor) compose atomically at the
	// filesystem layer; O_CREATE so a supervisor that re-opens against
	// a freshly-rmd run directory still works rather than failing with
	// a confusing ENOENT.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, runFileMode)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return &stream{
		file: f,
		path: path,
		tail: newTailBuffer(tailSize),
		now:  now,
	}, nil
}

// Stdout returns the io.Writer the caller assigns to exec.Cmd.Stdout.
// The returned value writes to stdout.log and to the stdout tail
// buffer; it does NOT contend with the stderr stream.
//
// The returned writer captures the StreamCapture instance, so multiple
// calls to Stdout return functionally equivalent writers (each routes
// to the same underlying stream). Production callers call it once and
// pass the result to exec.Cmd; tests may call it repeatedly.
func (s *StreamCapture) Stdout() io.Writer {
	return &streamWriter{stream: s.stdout, name: "stdout"}
}

// Stderr returns the io.Writer the caller assigns to exec.Cmd.Stderr.
// Symmetric to Stdout: writes land in stderr.log and the stderr tail
// buffer without touching the stdout stream's mutex.
func (s *StreamCapture) Stderr() io.Writer {
	return &streamWriter{stream: s.stderr, name: "stderr"}
}

// StdoutPath returns the absolute path of the stdout.log file. The
// supervisor's status / logs commands use this to point operators at
// the file without re-deriving the layout.
func (s *StreamCapture) StdoutPath() string { return s.stdout.path }

// StderrPath returns the absolute path of the stderr.log file.
// Symmetric to StdoutPath.
func (s *StreamCapture) StderrPath() string { return s.stderr.path }

// StdoutBytesWritten returns the number of bytes written to stdout.log
// since the StreamCapture was opened. Used by the supervisor to enforce
// max_stdout_bytes (step 8 / step 9) without statting the file.
func (s *StreamCapture) StdoutBytesWritten() int64 {
	s.stdout.mu.Lock()
	defer s.stdout.mu.Unlock()
	return s.stdout.bytesWritten
}

// StderrBytesWritten returns the number of bytes written to stderr.log
// since the StreamCapture was opened. Mirrors StdoutBytesWritten.
func (s *StreamCapture) StderrBytesWritten() int64 {
	s.stderr.mu.Lock()
	defer s.stderr.mu.Unlock()
	return s.stderr.bytesWritten
}

// TailStdout returns a snapshot of the most recent bytes written to
// stdout. The returned slice is a copy: the caller may sort, mutate, or
// retain it without affecting the live tail buffer. Returns up to
// TailSize bytes; an empty slice when nothing has been written yet.
//
// Provided so the supervisor's terminal renderer (step 8) and the
// `ai-env status` command (step 11) can surface recent output without
// re-reading the on-disk log on every refresh.
func (s *StreamCapture) TailStdout() []byte {
	s.stdout.mu.Lock()
	defer s.stdout.mu.Unlock()
	return s.stdout.tail.Bytes()
}

// TailStderr returns a snapshot of the most recent bytes written to
// stderr. Symmetric to TailStdout.
func (s *StreamCapture) TailStderr() []byte {
	s.stderr.mu.Lock()
	defer s.stderr.mu.Unlock()
	return s.stderr.tail.Bytes()
}

// LastOutputAt returns the wall-clock time of the most recent
// successful write on either stream. Returns the zero time if neither
// stream has been written to yet. The idle detector (step 8) uses this
// to enforce idle_timeout_minutes; the supervisor's stats event
// (last_output_at) reports it verbatim.
//
// Taking the max of the two stream timestamps means the idle detector
// resets on output from either stream, which matches the plan's
// "no output + no diff" idle definition.
func (s *StreamCapture) LastOutputAt() time.Time {
	s.stdout.mu.Lock()
	out := s.stdout.lastOutput
	s.stdout.mu.Unlock()
	s.stderr.mu.Lock()
	err := s.stderr.lastOutput
	s.stderr.mu.Unlock()
	if out.After(err) {
		return out
	}
	return err
}

// Close flushes any kernel buffers it can (best-effort fsync) and
// releases both file handles. Close is idempotent: subsequent calls are
// no-ops and return the first call's error. Writes that arrive after
// Close return an error rather than silently dropping their bytes.
//
// The supervisor calls Close from its post-run drain (step 10) after
// the agent process has exited and exec.Cmd.Wait has returned, so by
// the time we reach this code the only remaining writers are the
// supervisor's own bookkeeping goroutines. Holding the per-stream
// mutexes during Close is therefore safe: there is nothing left for
// them to wait on except this Close itself.
func (s *StreamCapture) Close() error {
	s.closeOnce.Do(func() {
		var firstErr error
		// Close stdout first, then stderr. The order is arbitrary but
		// fixed so a test that observes the error of a partial failure
		// gets a stable result. Each close fsyncs first because the
		// run is now finished and we want the final bytes durable on
		// disk before the file handle goes away; this fsync is cheap
		// (one per stream, not per write) and is the only fsync we
		// pay on the stream-capture path.
		if err := s.stdout.close(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := s.stderr.close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.closeErr = firstErr
	})
	return s.closeErr
}

// close releases this stream's file handle. It is the per-stream half
// of StreamCapture.Close. The mutex is acquired so a write that races
// the close sees a closed=true and returns a clear error rather than
// writing into a recycled descriptor.
func (s *stream) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	// Best-effort fsync. Failures here do not prevent the file Close;
	// they are propagated so the caller can log the partial-durability
	// case. On Windows fsync of an O_APPEND-opened file may surface
	// EBADF after a crash; treat as advisory and let the file Close
	// return the canonical error.
	var firstErr error
	if err := s.file.Sync(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("sync %s: %w", s.path, err)
	}
	if err := s.file.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("close %s: %w", s.path, err)
	}
	return firstErr
}

// streamWriter is the io.Writer implementation Stdout() and Stderr()
// return. It exists (rather than letting *stream implement io.Writer
// directly) so the public surface is a narrow io.Writer rather than the
// full *stream type, which would also expose close/last-output
// machinery the caller has no business calling.
//
// The name field is used only in error messages so a failure on the
// supervisor's side ("write to stdout capture failed") is immediately
// actionable without the caller having to compare against the path.
type streamWriter struct {
	stream *stream
	name   string
}

// Write appends p to the underlying file and the in-memory tail
// buffer, then updates the byte counter and last-output timestamp.
// Returns the number of bytes the underlying file write reported and
// any error from that write.
//
// Implementation notes:
//
//   - The file write is the first step. If it fails (disk full, EIO),
//     we do NOT update the tail buffer or the counter so the in-memory
//     view stays consistent with what actually landed on disk.
//   - The tail buffer is updated with the bytes the file write
//     reported, not the full p. On a short write the on-disk and
//     in-memory tail agree about how much was captured.
//   - LastOutput is stamped on a successful write only. A failed
//     write does not reset the idle clock; from the idle detector's
//     point of view the run produced no output.
//   - We do NOT call Sync on every write. See the StreamCapture
//     comment for the throughput rationale. The kernel buffers the
//     bytes; readers (tail -f, the status command) observe them via
//     the page cache without us calling fsync. A supervisor crash
//     does not lose them because they have already left our process.
func (w *streamWriter) Write(p []byte) (int, error) {
	w.stream.mu.Lock()
	defer w.stream.mu.Unlock()

	if w.stream.closed {
		return 0, fmt.Errorf("run: write to closed %s capture", w.name)
	}

	n, err := w.stream.file.Write(p)
	if n > 0 {
		// Tail buffer update is local-memory only so cheap even on a
		// hot path; the buffer drops the oldest bytes if it overflows.
		w.stream.tail.Write(p[:n])
		w.stream.bytesWritten += int64(n)
		w.stream.lastOutput = w.stream.now()
	}
	if err != nil {
		return n, fmt.Errorf("run: write %s capture: %w", w.name, err)
	}
	return n, nil
}

// tailBuffer is a fixed-capacity ring buffer that retains the most
// recent N bytes written to it. It is the bounded backing store for
// StreamCapture's TailStdout / TailStderr accessors.
//
// The buffer is not a general-purpose ring: it only supports Write
// (overwriting the oldest bytes when full) and Bytes (returning a
// chronologically ordered copy of the live contents). That is exactly
// what the terminal-display / idle-detection use case needs.
//
// Splitting the tail buffer into its own type keeps streamWriter.Write
// readable (one method call rather than an inline ring update) and
// makes the buffer trivially testable in isolation.
type tailBuffer struct {
	// buf holds the bytes. Its length equals capacity (allocated once
	// at construction); writes overwrite in place rather than appending.
	buf []byte

	// start is the index of the oldest byte once the buffer has wrapped.
	// While the buffer is not yet full it stays at 0 and size grows.
	start int

	// size is the number of live bytes in the buffer (<= len(buf)).
	// Once it reaches len(buf) the buffer is full and writes wrap.
	size int
}

// newTailBuffer returns a tailBuffer with the given capacity. A
// capacity of zero is legal: it disables the tail (every Write is a
// no-op and Bytes returns nil) without forcing the caller to add a
// nil-check at each write site.
func newTailBuffer(capacity int) *tailBuffer {
	if capacity <= 0 {
		return &tailBuffer{}
	}
	return &tailBuffer{buf: make([]byte, capacity)}
}

// Write appends p to the buffer, overwriting the oldest bytes if the
// buffer is full. It always reports len(p) written (the operation
// cannot fail). Callers ignore the count and the error; the signature
// matches io.Writer purely so a future test can wire it directly into
// an io.Copy if desired.
func (b *tailBuffer) Write(p []byte) (int, error) {
	if len(b.buf) == 0 || len(p) == 0 {
		return len(p), nil
	}
	// If p is larger than the buffer, only the trailing capacity bytes
	// matter; older bytes would be overwritten on the same call. This
	// short-circuit keeps the loop bound at len(b.buf) regardless of p.
	if len(p) >= len(b.buf) {
		copy(b.buf, p[len(p)-len(b.buf):])
		b.start = 0
		b.size = len(b.buf)
		return len(p), nil
	}
	// General case: copy p in two segments around the buffer wrap.
	// writeAt is the index where the next byte will land; it equals
	// (start + size) % cap when not full, or start when full (the
	// oldest byte gets overwritten).
	for _, c := range p {
		writeAt := (b.start + b.size) % len(b.buf)
		b.buf[writeAt] = c
		if b.size < len(b.buf) {
			b.size++
		} else {
			b.start = (b.start + 1) % len(b.buf)
		}
	}
	return len(p), nil
}

// Bytes returns a fresh, chronologically ordered copy of the live
// contents of the buffer. The returned slice's len is between 0 and
// the buffer's capacity; modifying it does not affect future Writes.
func (b *tailBuffer) Bytes() []byte {
	if b.size == 0 {
		return nil
	}
	out := make([]byte, b.size)
	if b.start+b.size <= len(b.buf) {
		// Live region is contiguous in buf.
		copy(out, b.buf[b.start:b.start+b.size])
		return out
	}
	// Live region wraps: copy tail then head.
	first := copy(out, b.buf[b.start:])
	copy(out[first:], b.buf[:b.size-first])
	return out
}
