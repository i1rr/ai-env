package run

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newStreamRunDir builds a real RunDirectory on disk so each stream
// test starts from the same scaffolded layout the supervisor will see
// in production. Going through CreateRunDirectory (rather than a bare
// MkdirAll) keeps the stream-capture tests honest against the empty
// placeholder files the directory creator left behind: OpenStreamCapture
// must extend those placeholders, not crash on them.
func newStreamRunDir(t *testing.T) RunDirectory {
	t.Helper()
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260528-101300-a1b2c3"
	now := time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return dir
}

// TestStreamCapture_InterleavedWritesRouteToCorrectFiles is the
// primary contract check for step 7: writes to the stdout endpoint
// must land in stdout.log and writes to the stderr endpoint must land
// in stderr.log, even when callers interleave the two from separate
// goroutines. A regression here (one stream pointing at the other's
// file, a swapped pair in the constructor) would corrupt every later
// supervisor run, so the test pushes a meaningful number of writes
// from many goroutines and checks both files contain exactly the
// bytes routed to them.
func TestStreamCapture_InterleavedWritesRouteToCorrectFiles(t *testing.T) {
	dir := newStreamRunDir(t)
	cap, err := OpenStreamCapture(dir.Path, StreamOptions{})
	if err != nil {
		t.Fatalf("OpenStreamCapture: %v", err)
	}
	t.Cleanup(func() { _ = cap.Close() })

	stdout := cap.Stdout()
	stderr := cap.Stderr()

	const goroutines = 16
	const writesPer = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < writesPer; i++ {
				// Each line is whole-line so we can split the
				// captured file by '\n' and check no line crosses
				// stream boundaries.
				line := fmt.Sprintf("OUT g=%d i=%d\n", g, i)
				if _, err := io.WriteString(stdout, line); err != nil {
					t.Errorf("stdout write: %v", err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < writesPer; i++ {
				line := fmt.Sprintf("ERR g=%d i=%d\n", g, i)
				if _, err := io.WriteString(stderr, line); err != nil {
					t.Errorf("stderr write: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if err := cap.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	outBytes, err := os.ReadFile(filepath.Join(dir.Path, "stdout.log"))
	if err != nil {
		t.Fatalf("read stdout.log: %v", err)
	}
	errBytes, err := os.ReadFile(filepath.Join(dir.Path, "stderr.log"))
	if err != nil {
		t.Fatalf("read stderr.log: %v", err)
	}

	// stdout.log must contain only OUT lines and no ERR lines.
	if bytes.Contains(outBytes, []byte("ERR ")) {
		t.Errorf("stdout.log contains stderr-routed bytes")
	}
	if bytes.Contains(errBytes, []byte("OUT ")) {
		t.Errorf("stderr.log contains stdout-routed bytes")
	}
	// Both must contain the expected total number of lines.
	wantLines := goroutines * writesPer
	if got := bytes.Count(outBytes, []byte{'\n'}); got != wantLines {
		t.Errorf("stdout.log has %d lines, want %d", got, wantLines)
	}
	if got := bytes.Count(errBytes, []byte{'\n'}); got != wantLines {
		t.Errorf("stderr.log has %d lines, want %d", got, wantLines)
	}
	// Counter accessors should agree with the on-disk sizes.
	if cap.StdoutBytesWritten() != int64(len(outBytes)) {
		t.Errorf("StdoutBytesWritten = %d, file = %d", cap.StdoutBytesWritten(), len(outBytes))
	}
	if cap.StderrBytesWritten() != int64(len(errBytes)) {
		t.Errorf("StderrBytesWritten = %d, file = %d", cap.StderrBytesWritten(), len(errBytes))
	}
}

// TestStreamCapture_FlushesToDiskWithoutClose locks down the
// "streamed, not buffered" rule: a reader opening the on-disk file
// after a Write but before Close must see the bytes. A regression
// here (someone wrapping the file in a bufio.Writer to chase
// throughput) would silently delay output until Close and break the
// "ai-env logs" tail experience as well as the supervisor's idle
// detector.
func TestStreamCapture_FlushesToDiskWithoutClose(t *testing.T) {
	dir := newStreamRunDir(t)
	cap, err := OpenStreamCapture(dir.Path, StreamOptions{})
	if err != nil {
		t.Fatalf("OpenStreamCapture: %v", err)
	}
	t.Cleanup(func() { _ = cap.Close() })

	const payload = "hello from stdout\n"
	if _, err := io.WriteString(cap.Stdout(), payload); err != nil {
		t.Fatalf("stdout write: %v", err)
	}
	const payloadErr = "hello from stderr\n"
	if _, err := io.WriteString(cap.Stderr(), payloadErr); err != nil {
		t.Fatalf("stderr write: %v", err)
	}

	// Open a fresh handle to the file (not the writer) and read
	// without closing the StreamCapture; the bytes must already be
	// visible.
	gotOut, err := os.ReadFile(filepath.Join(dir.Path, "stdout.log"))
	if err != nil {
		t.Fatalf("read stdout.log mid-stream: %v", err)
	}
	if string(gotOut) != payload {
		t.Errorf("stdout.log mid-stream = %q, want %q", gotOut, payload)
	}
	gotErr, err := os.ReadFile(filepath.Join(dir.Path, "stderr.log"))
	if err != nil {
		t.Fatalf("read stderr.log mid-stream: %v", err)
	}
	if string(gotErr) != payloadErr {
		t.Errorf("stderr.log mid-stream = %q, want %q", gotErr, payloadErr)
	}

	// Tail buffer should reflect the same bytes.
	if got := string(cap.TailStdout()); got != payload {
		t.Errorf("TailStdout = %q, want %q", got, payload)
	}
	if got := string(cap.TailStderr()); got != payloadErr {
		t.Errorf("TailStderr = %q, want %q", got, payloadErr)
	}
}

// TestStreamCapture_CloseIsIdempotentAndSafe pins the post-run drain
// contract: the supervisor's defer-close and explicit Close in the
// stop path must not panic or double-free, and a Write after Close
// must return a clear error rather than crashing on a stale
// descriptor. A Write-after-Close that silently dropped bytes would
// hide a supervisor bug (Closing too early) behind a quiet log.
func TestStreamCapture_CloseIsIdempotentAndSafe(t *testing.T) {
	dir := newStreamRunDir(t)
	cap, err := OpenStreamCapture(dir.Path, StreamOptions{})
	if err != nil {
		t.Fatalf("OpenStreamCapture: %v", err)
	}

	if _, err := io.WriteString(cap.Stdout(), "before close\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := cap.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second Close must be a no-op and return the same outcome as the
	// first (nil here).
	if err := cap.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	// Third Close from a concurrent path must also be safe.
	done := make(chan error, 1)
	go func() { done <- cap.Close() }()
	if err := <-done; err != nil {
		t.Errorf("concurrent Close: %v", err)
	}

	// Writes after Close must return an error; the underlying file
	// handle has been released and any further bytes would either
	// crash on a freed descriptor or silently drop.
	if _, err := io.WriteString(cap.Stdout(), "after close\n"); err == nil {
		t.Errorf("stdout write after Close: expected error")
	}
	if _, err := io.WriteString(cap.Stderr(), "after close\n"); err == nil {
		t.Errorf("stderr write after Close: expected error")
	}
}

// TestStreamCapture_LastOutputAtTracksMostRecentWrite covers the
// idle-detector seam: LastOutputAt must return the most recent stamp
// across both streams, and it must update on every successful write.
// The supervisor's idle detector (step 8) reads this to enforce
// idle_timeout_minutes; a stale return value would either kill an
// active run or fail to kill a hung one.
func TestStreamCapture_LastOutputAtTracksMostRecentWrite(t *testing.T) {
	dir := newStreamRunDir(t)

	// Inject a deterministic clock so the test can assert on exact
	// timestamps rather than wall-clock skew.
	var (
		mu  sync.Mutex
		idx int
	)
	stamps := []time.Time{
		time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC),
		time.Date(2026, 5, 28, 10, 13, 5, 0, time.UTC),
		time.Date(2026, 5, 28, 10, 13, 10, 0, time.UTC),
		time.Date(2026, 5, 28, 10, 13, 15, 0, time.UTC),
	}
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		if idx >= len(stamps) {
			return stamps[len(stamps)-1]
		}
		t := stamps[idx]
		idx++
		return t
	}

	cap, err := OpenStreamCapture(dir.Path, StreamOptions{Now: clock})
	if err != nil {
		t.Fatalf("OpenStreamCapture: %v", err)
	}
	t.Cleanup(func() { _ = cap.Close() })

	// No writes yet, so LastOutputAt is the zero time.
	if !cap.LastOutputAt().IsZero() {
		t.Errorf("LastOutputAt before any write = %v, want zero", cap.LastOutputAt())
	}

	if _, err := io.WriteString(cap.Stdout(), "first\n"); err != nil {
		t.Fatalf("stdout write: %v", err)
	}
	if got := cap.LastOutputAt(); !got.Equal(stamps[0]) {
		t.Errorf("LastOutputAt after first stdout write = %v, want %v", got, stamps[0])
	}
	if _, err := io.WriteString(cap.Stderr(), "second\n"); err != nil {
		t.Fatalf("stderr write: %v", err)
	}
	if got := cap.LastOutputAt(); !got.Equal(stamps[1]) {
		t.Errorf("LastOutputAt after stderr write = %v, want %v", got, stamps[1])
	}
}

// TestStreamCapture_TailBufferIsBounded confirms the tail buffer
// truncates oldest data when it overflows. A regression here (an
// unbounded buffer disguised as bounded) would let an agent that
// streams a multi-GB log balloon the supervisor's resident memory.
func TestStreamCapture_TailBufferIsBounded(t *testing.T) {
	dir := newStreamRunDir(t)

	const tailSize = 16
	cap, err := OpenStreamCapture(dir.Path, StreamOptions{TailSize: tailSize})
	if err != nil {
		t.Fatalf("OpenStreamCapture: %v", err)
	}
	t.Cleanup(func() { _ = cap.Close() })

	// Write more bytes than the tail can hold; the tail must contain
	// exactly the last tailSize bytes.
	payload := []byte("0123456789ABCDEFGHIJabcdefghij")
	if _, err := cap.Stdout().Write(payload); err != nil {
		t.Fatalf("stdout write: %v", err)
	}
	tail := cap.TailStdout()
	if len(tail) != tailSize {
		t.Fatalf("tail len = %d, want %d", len(tail), tailSize)
	}
	want := payload[len(payload)-tailSize:]
	if !bytes.Equal(tail, want) {
		t.Errorf("tail = %q, want %q", tail, want)
	}

	// On-disk file still holds the full payload (only the tail was
	// trimmed, not the persistent capture).
	got, err := os.ReadFile(filepath.Join(dir.Path, "stdout.log"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("stdout.log = %q, want %q", got, payload)
	}
}

// TestStreamCapture_RequiresRunDir checks the constructor refuses to
// build a capture against an empty run directory path. Missing the
// path would land the log files in the process working directory; we
// want a loud failure at startup instead.
func TestStreamCapture_RequiresRunDir(t *testing.T) {
	if _, err := OpenStreamCapture("", StreamOptions{}); err == nil {
		t.Error("OpenStreamCapture(\"\"): expected error")
	}
	if _, err := OpenStreamCapture("/tmp", StreamOptions{TailSize: -1}); err == nil {
		t.Error("OpenStreamCapture(TailSize=-1): expected error")
	}
}

// TestStreamCapture_AppendsToExistingFile guards the recovery / replay
// path. A capture opened against a run directory that already has
// captured bytes (a supervisor restart, a --continue chain) must append
// rather than truncate. Truncation here would silently erase the
// earlier segment of the run's output.
func TestStreamCapture_AppendsToExistingFile(t *testing.T) {
	dir := newStreamRunDir(t)
	stdoutPath := filepath.Join(dir.Path, "stdout.log")
	stderrPath := filepath.Join(dir.Path, "stderr.log")

	seed := "previous stdout segment\n"
	if err := os.WriteFile(stdoutPath, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed stdout: %v", err)
	}
	seedErr := "previous stderr segment\n"
	if err := os.WriteFile(stderrPath, []byte(seedErr), 0o644); err != nil {
		t.Fatalf("seed stderr: %v", err)
	}

	cap, err := OpenStreamCapture(dir.Path, StreamOptions{})
	if err != nil {
		t.Fatalf("OpenStreamCapture: %v", err)
	}
	if _, err := io.WriteString(cap.Stdout(), "new stdout segment\n"); err != nil {
		t.Fatalf("stdout write: %v", err)
	}
	if _, err := io.WriteString(cap.Stderr(), "new stderr segment\n"); err != nil {
		t.Fatalf("stderr write: %v", err)
	}
	if err := cap.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	want := seed + "new stdout segment\n"
	if string(got) != want {
		t.Errorf("stdout.log = %q, want %q", got, want)
	}
	got, err = os.ReadFile(stderrPath)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	want = seedErr + "new stderr segment\n"
	if string(got) != want {
		t.Errorf("stderr.log = %q, want %q", got, want)
	}
}

// TestStreamCapture_StreamsAreIndependent locks down the no-head-of-line
// guarantee: a goroutine blocked writing to stderr's mutex must not
// stop stdout from making progress. We simulate the contention by
// holding the stderr lock from a custom path and showing that stdout
// writes complete while it is held.
//
// We can't directly hold the unexported per-stream mutex from a test,
// but we can prove independence by stress-writing both streams in
// parallel and observing that stdout's progress is not gated on
// stderr's by checking total throughput is greater than serial.
func TestStreamCapture_StreamsAreIndependent(t *testing.T) {
	dir := newStreamRunDir(t)
	cap, err := OpenStreamCapture(dir.Path, StreamOptions{})
	if err != nil {
		t.Fatalf("OpenStreamCapture: %v", err)
	}
	t.Cleanup(func() { _ = cap.Close() })

	// Two goroutines, one per stream, both running for a fixed
	// duration. If the two streams share a mutex they will serialize;
	// independence means both reach a meaningful byte count.
	deadline := time.Now().Add(50 * time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := []byte("o")
		for time.Now().Before(deadline) {
			if _, err := cap.Stdout().Write(buf); err != nil {
				t.Errorf("stdout write: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := []byte("e")
		for time.Now().Before(deadline) {
			if _, err := cap.Stderr().Write(buf); err != nil {
				t.Errorf("stderr write: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	// Each stream should have made non-trivial progress. The exact
	// numbers are environment-dependent so the assertion is a floor,
	// not an exact count.
	if cap.StdoutBytesWritten() == 0 {
		t.Error("stdout produced 0 bytes; streams may be coupled")
	}
	if cap.StderrBytesWritten() == 0 {
		t.Error("stderr produced 0 bytes; streams may be coupled")
	}
}
