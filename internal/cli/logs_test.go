package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/run"
)

// scaffoldRunWithLogs creates a project with one run.json plus
// caller-supplied stdout/stderr captured bytes. Returns cwd, run id,
// and the run directory.
func scaffoldRunWithLogs(t *testing.T, envName string, state run.State, stdout, stderr string) (cwd, runID, runDir string) {
	t.Helper()
	cwd, runID = scaffoldProjectWithRun(t, envName, state)
	runDir = run.RunPath(filepath.Join(cwd, ".ai-env"), runID)
	if stdout != "" {
		if err := os.WriteFile(run.StdoutLogPath(runDir), []byte(stdout), 0o644); err != nil {
			t.Fatalf("write stdout.log: %v", err)
		}
	}
	if stderr != "" {
		if err := os.WriteFile(run.StderrLogPath(runDir), []byte(stderr), 0o644); err != nil {
			t.Fatalf("write stderr.log: %v", err)
		}
	}
	return cwd, runID, runDir
}

func TestRunLogs_NoRunsYet(t *testing.T) {
	cwd := t.TempDir()
	if err := RunNew(NewOptions{EnvName: "fix-tests", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	var out, errOut bytes.Buffer
	err := RunLogs(LogsOptions{
		EnvName: "fix-tests",
		Cwd:     cwd,
		Stdout:  &out,
		Stderr:  &errOut,
	})
	if err != nil {
		t.Fatalf("RunLogs on fresh project: %v", err)
	}
	if !strings.Contains(out.String(), "no runs") {
		t.Errorf("expected empty-state hint, got:\n%s", out.String())
	}
}

func TestRunLogs_Both_PrintsBothStreams(t *testing.T) {
	cwd, _, _ := scaffoldRunWithLogs(t, "fix-tests", run.StateCompleted, "hello stdout\n", "uh oh stderr\n")
	var out, errOut bytes.Buffer
	err := RunLogs(LogsOptions{
		EnvName: "fix-tests",
		Cwd:     cwd,
		Stream:  LogStreamBoth,
		Stdout:  &out,
		Stderr:  &errOut,
	})
	if err != nil {
		t.Fatalf("RunLogs: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "==> stdout <==") {
		t.Errorf("missing stdout banner:\n%s", s)
	}
	if !strings.Contains(s, "hello stdout") {
		t.Errorf("missing stdout body:\n%s", s)
	}
	if !strings.Contains(s, "==> stderr <==") {
		t.Errorf("missing stderr banner:\n%s", s)
	}
	if !strings.Contains(s, "uh oh stderr") {
		t.Errorf("missing stderr body:\n%s", s)
	}
}

func TestRunLogs_StdoutOnly(t *testing.T) {
	cwd, _, _ := scaffoldRunWithLogs(t, "fix-tests", run.StateCompleted, "only out\n", "should not appear\n")
	var out, errOut bytes.Buffer
	err := RunLogs(LogsOptions{
		EnvName: "fix-tests",
		Cwd:     cwd,
		Stream:  LogStreamStdout,
		Stdout:  &out,
		Stderr:  &errOut,
	})
	if err != nil {
		t.Fatalf("RunLogs: %v", err)
	}
	if !strings.Contains(out.String(), "only out") {
		t.Errorf("missing stdout body:\n%s", out.String())
	}
	if strings.Contains(out.String(), "should not appear") {
		t.Errorf("stderr leaked into stdout-only mode:\n%s", out.String())
	}
}

func TestRunLogs_StderrOnly(t *testing.T) {
	cwd, _, _ := scaffoldRunWithLogs(t, "fix-tests", run.StateCompleted, "stdout body\n", "stderr body\n")
	var out, errOut bytes.Buffer
	err := RunLogs(LogsOptions{
		EnvName: "fix-tests",
		Cwd:     cwd,
		Stream:  LogStreamStderr,
		Stdout:  &out,
		Stderr:  &errOut,
	})
	if err != nil {
		t.Fatalf("RunLogs: %v", err)
	}
	if !strings.Contains(out.String(), "stderr body") {
		t.Errorf("missing stderr body:\n%s", out.String())
	}
	if strings.Contains(out.String(), "stdout body") {
		t.Errorf("stdout leaked into stderr-only mode:\n%s", out.String())
	}
}

func TestRunLogs_RunFlagPicksSpecific(t *testing.T) {
	cwd, _, _ := scaffoldRunWithLogs(t, "fix-tests", run.StateCompleted, "first\n", "")
	// Add a newer run for the same env, with different stdout body.
	aiEnvDir := filepath.Join(cwd, ".ai-env")
	newerID := "20260528-200000-bbbbbb"
	now := time.Date(2026, 5, 28, 20, 0, 0, 0, time.UTC)
	rd, err := run.CreateRunDirectory(aiEnvDir, newerID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	rec := run.Record{
		RunID: newerID, EnvName: "fix-tests", Agent: "claude", Task: "x",
		State: run.StateCompleted, Backend: "local-process",
		ModelCredentialMode: run.ModelCredentialBackendManaged,
	}
	if err := run.WriteRecord(rd.Path, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := os.WriteFile(run.StdoutLogPath(rd.Path), []byte("newer\n"), 0o644); err != nil {
		t.Fatalf("write newer stdout.log: %v", err)
	}

	// Without --run we should see "newer".
	var out, errOut bytes.Buffer
	if err := RunLogs(LogsOptions{
		EnvName: "fix-tests", Cwd: cwd, Stream: LogStreamStdout, Stdout: &out, Stderr: &errOut,
	}); err != nil {
		t.Fatalf("RunLogs latest: %v", err)
	}
	if !strings.Contains(out.String(), "newer") || strings.Contains(out.String(), "first") {
		t.Errorf("default selection wrong: %q", out.String())
	}

	// With --run pointing at the older one we should see "first".
	out.Reset()
	errOut.Reset()
	if err := RunLogs(LogsOptions{
		EnvName: "fix-tests", RunID: "20260528-101300-aaaaaa",
		Cwd: cwd, Stream: LogStreamStdout, Stdout: &out, Stderr: &errOut,
	}); err != nil {
		t.Fatalf("RunLogs by id: %v", err)
	}
	if !strings.Contains(out.String(), "first") || strings.Contains(out.String(), "newer") {
		t.Errorf("--run selection wrong: %q", out.String())
	}
}

func TestRunLogs_InvalidStream(t *testing.T) {
	cwd, _, _ := scaffoldRunWithLogs(t, "fix-tests", run.StateCompleted, "x", "")
	err := RunLogs(LogsOptions{
		EnvName: "fix-tests", Cwd: cwd, Stream: LogStream("garbage"),
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected invalid stream to fail")
	}
}

// safeBuffer is a small thread-safe wrapper around bytes.Buffer for
// the follow tests, which read from the buffer concurrently with the
// goroutine running RunLogs. bytes.Buffer is not safe for concurrent
// Write/Read; this wrapper serialises both.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunLogs_Follow_StreamsNewBytes(t *testing.T) {
	cwd, _, runDir := scaffoldRunWithLogs(t, "fix-tests", run.StateRunning, "initial\n", "")

	out := &safeBuffer{}
	errOut := &safeBuffer{}
	cancel := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = RunLogs(LogsOptions{
			EnvName:    "fix-tests",
			Cwd:        cwd,
			Stream:     LogStreamStdout,
			Follow:     true,
			FollowPoll: 10 * time.Millisecond,
			Cancel:     cancel,
			Stdout:     out,
			Stderr:     errOut,
		})
	}()

	// Wait briefly to ensure the follow loop has captured the initial
	// snapshot before we append, then append more bytes.
	time.Sleep(40 * time.Millisecond)
	f, err := os.OpenFile(run.StdoutLogPath(runDir), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open stdout.log for append: %v", err)
	}
	if _, err := f.WriteString("appended\n"); err != nil {
		t.Fatalf("append stdout: %v", err)
	}
	f.Close()

	// Give the poller a few cycles to read it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "appended") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(cancel)
	wg.Wait()

	if !strings.Contains(out.String(), "initial") {
		t.Errorf("expected 'initial' in follow output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "appended") {
		t.Errorf("expected 'appended' in follow output:\n%s", out.String())
	}
}

func TestRunLogs_Follow_ExitsOnTerminalState(t *testing.T) {
	cwd, _, _ := scaffoldRunWithLogs(t, "fix-tests", run.StateCompleted, "done\n", "")
	out := &safeBuffer{}
	errOut := &safeBuffer{}
	cancel := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		_ = RunLogs(LogsOptions{
			EnvName:    "fix-tests",
			Cwd:        cwd,
			Stream:     LogStreamStdout,
			Follow:     true,
			FollowPoll: 10 * time.Millisecond,
			Cancel:     cancel,
			Stdout:     out,
			Stderr:     errOut,
		})
		close(doneCh)
	}()
	select {
	case <-doneCh:
		// Expected: follow exits quickly because the run is already
		// terminal and the poll observes no new bytes.
	case <-time.After(2 * time.Second):
		close(cancel)
		<-doneCh
		t.Fatal("follow did not exit on terminal state")
	}
	if !strings.Contains(out.String(), "done") {
		t.Errorf("expected initial dump body in output:\n%s", out.String())
	}
}
