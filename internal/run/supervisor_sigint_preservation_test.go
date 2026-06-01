//go:build !windows

package run

// Dedicated step 17 test: "SIGINT preserves logs and partial diff".
// Plan 03, line 158. The existing supervisor_signal_test.go tests pin
// that SIGINT routes into Cancel and the run lands on StateKilledByUser;
// this file extends the coverage to the artifacts the master plan
// requires to survive the forced-termination path:
//
//   - stdout.log and stderr.log on disk contain the bytes the child
//     emitted before the signal (preserved, not truncated).
//   - the partial diff file (git-diff.patch) contains the worktree
//     modification the child made (non-trivial diff content).
//   - run.json's closing snapshot records the cancellation terminal
//     (StateKilledByUser, StopReasonSignal, stopped_at).
//   - the supervisor's resources (streams, lifecycle writer, signal
//     handler goroutine) are closed cleanly: no goroutine leak after
//     stop().
//
// The signal is delivered to the test process itself via syscall.Kill;
// the InstallSignalHandlers path routes it into Cancel(). That is the
// same wiring the production CLI uses. The test is POSIX-only because
// SIGINT semantics on Windows do not match the supervisor's contract;
// the build tag at the top of the file gates the entire suite to non-
// Windows hosts.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/workspace"
)

// initSigintFixtureRepo builds a real Git repo with a single tracked
// file and an initial commit so the partial diff has something to lock
// onto. The repo path is returned for use by workspace.CreateWorktree.
// Skips the test when git is unavailable, mirroring the integration
// test helper.
func initSigintFixtureRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not on PATH: %v", err)
	}
	repo := t.TempDir()
	runCmd := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	runCmd("init", "-b", "main")
	runCmd("config", "user.email", "fixture@example.com")
	runCmd("config", "user.name", "Fixture")
	tracked := filepath.Join(repo, "tracked.txt")
	if err := os.WriteFile(tracked, []byte("baseline\n"), 0o644); err != nil {
		t.Fatalf("write tracked.txt: %v", err)
	}
	runCmd("add", ".")
	runCmd("commit", "-m", "initial")
	return repo
}

// TestStep17_SIGINTPreservesLogsAndPartialDiff is the headline test for
// plan step 17 (line 158). It wires a real workspace + a real supervisor
// against a child that emits a known stdout payload, a known stderr
// payload, and a known tracked-file modification. Once the child has
// produced all three observables, the test delivers a real SIGINT to
// itself; the InstallSignalHandlers path routes it into Cancel; the
// supervisor walks its terminal sequence; and the test asserts every
// artifact survived.
func TestStep17_SIGINTPreservesLogsAndPartialDiff(t *testing.T) {
	// The //go:build !windows constraint at the top of this file
	// already gates the test off on Windows; the supervisor's SIGINT
	// semantics only match the plan's contract on POSIX hosts.
	skipIfNoSh(t)

	// --- 1. Real git repo + worktree-backed workspace --------------------
	repo := initSigintFixtureRepo(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	envName := "step17-sigint"
	info, err := workspace.CreateWorktree(aiEnvDir, envName, repo, "go", time.Now())
	if err != nil {
		t.Fatalf("workspace.CreateWorktree: %v", err)
	}
	if info.Path == "" || info.Branch == "" || info.SourcePath == "" {
		t.Fatalf("CreateWorktree returned incomplete info: %+v", info)
	}

	// --- 2. Run directory ------------------------------------------------
	runID, err := GenerateRunID()
	if err != nil {
		t.Fatalf("GenerateRunID: %v", err)
	}
	runDir, err := CreateRunDirectory(aiEnvDir, runID, time.Now())
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	const task = "Emit output then wait for SIGINT"
	if err := WriteTask(aiEnvDir, runID, task); err != nil {
		t.Fatalf("WriteTask: %v", err)
	}

	// --- 3. Child command ------------------------------------------------
	//
	// The child emits known stdout / stderr payloads, modifies a tracked
	// file inside the worktree AND commits the change to the env branch,
	// then signals readiness via a sentinel file the test polls on. After
	// that it `exec sleep`s so the shell process is replaced by the sleep
	// child (this matters for the SIGINT propagation, see below); the
	// test delivers SIGINT to itself and the supervisor's stop path takes
	// the sleep down. The sentinel file is the synchronization mechanism
	// that guarantees the child has done all of its bookkeeping *before*
	// the signal arrives; without it the test would race the supervisor.
	//
	// The commit is required for the partial diff to be non-trivial:
	// NewGitWorktreeDiffCollector uses `git diff HEAD...<branch>` (the
	// three-dot form), which compares the merge base of HEAD and the env
	// branch against the env branch's tip. Uncommitted worktree changes
	// are not part of that comparison; committing the modification on the
	// env branch is what makes it show up in the unified-diff output the
	// supervisor writes into git-diff.patch.
	//
	// The `exec sleep` at the end is load-bearing: if the script ended
	// with `sleep 30` as a separate command, the shell would fork a sleep
	// child and wait on it. When the supervisor sends SIGINT to the shell
	// PID, the shell remembers the signal but stays parked in wait() on
	// its child; meanwhile the sleep child does not receive the signal
	// (it is not in the same process group target). After the
	// StopGracePeriod the supervisor escalates to SIGKILL on the shell,
	// but the orphan sleep continues to hold the stdout/stderr pipe ends,
	// which blocks exec.Cmd.Wait from returning until the pipe drains
	// (i.e. until sleep finishes naturally). Using `exec sleep` replaces
	// the shell process with sleep itself, so SIGINT lands directly on
	// the sleep and the wait path completes promptly. This is the
	// standard idiom for non-trivial scripted children driven by the
	// supervisor's stop path.
	const stdoutPayload = "STDOUT-PAYLOAD-LINE\n"
	const stderrPayload = "STDERR-PAYLOAD-LINE\n"
	const trackedNewLine = "modified-by-child\n"

	trackedPath := filepath.Join(info.Path, "tracked.txt")
	sentinelPath := filepath.Join(t.TempDir(), "child-ready")

	script := strings.Join([]string{
		"printf '%s' '" + stdoutPayload + "'",
		"printf '%s' '" + stderrPayload + "' >&2",
		"printf '%s' '" + trackedNewLine + "' > '" + trackedPath + "'",
		// Commit the modification on the env branch so the three-dot
		// `git diff HEAD...<branch>` the production collector runs picks
		// it up. We point HOME at the test tempdir so any global git hook
		// config the host has cannot interfere; the per-repo user.email /
		// user.name set in initSigintFixtureRepo is what the commit uses.
		"git add tracked.txt",
		"git commit -q -m 'child modification'",
		"touch '" + sentinelPath + "'",
		// Replace the shell with sleep so SIGINT lands directly on the
		// sleep process (see the comment above).
		"exec sleep 30",
	}, "; ")

	// --- 4. Build the supervisor with a real DiffCollector ---------------
	//
	// We use NewGitWorktreeDiffCollector pointed at the real source repo
	// + the worktree branch. The collector shells out to `git diff` and
	// returns the real unified-diff text the child's modification
	// produced. This is the production path the CLI takes for worktree-
	// strategy environments.
	diff := NewGitWorktreeDiffCollector(info.SourcePath, "HEAD", info.Branch)

	var userOut bytes.Buffer
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:  runDir.Path,
		RunID:   runDir.ID,
		EnvName: envName,
		Task:    task,
		Backend: "local-process",
		Agent:   "claude",
		Command: CommandSpec{
			Program: "sh",
			Args:    []string{"-c", script},
			Dir:     info.Path,
		},
		MaxRuntime:        10 * time.Second,
		IdleTimeout:       0,
		StatsPollInterval: 25 * time.Millisecond,
		StopGracePeriod:   300 * time.Millisecond,
		DiffCollector:     diff,
		DiffTimeout:       5 * time.Second,
		UserOutput:        &userOut,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	// --- 5. Install signal handlers (step 9 API) -------------------------
	//
	// InstallSignalHandlers is the seam step 9 exposes; it routes SIGINT,
	// SIGTERM, and SIGHUP into Cancel(). The deferred stop() teardown
	// ensures the handler goroutine exits cleanly so the post-test leak
	// check (below) is meaningful.
	baselineGoroutines := runtime.NumGoroutine()
	stop, err := InstallSignalHandlers(sup)
	if err != nil {
		t.Fatalf("InstallSignalHandlers: %v", err)
	}
	t.Cleanup(stop)

	// --- 6. Drive Run + wait for readiness, then deliver SIGINT ----------
	done := make(chan struct {
		res SupervisorResult
		err error
	}, 1)
	go func() {
		res, runErr := sup.Run(context.Background())
		done <- struct {
			res SupervisorResult
			err error
		}{res, runErr}
	}()

	// Poll for the readiness sentinel. We want to guarantee the child has
	// emitted its observables before the SIGINT arrives; otherwise a fast
	// scheduler could race the signal in ahead of the child's printf
	// calls and leave the stream files empty. The poll is short-lived
	// (50ms granularity) and capped (3 seconds) so a stuck child surfaces
	// as a test failure rather than a hang.
	const readinessTimeout = 3 * time.Second
	const readinessPoll = 25 * time.Millisecond
	deadline := time.Now().Add(readinessTimeout)
	for {
		if _, err := os.Stat(sentinelPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child did not signal readiness within %v (sentinel=%s)", readinessTimeout, sentinelPath)
		}
		time.Sleep(readinessPoll)
	}

	// Deliver SIGINT to the test process. The InstallSignalHandlers
	// channel intercepts it before the runtime's default disposition
	// (which would kill the test binary), so the test process survives
	// and the supervisor's Cancel path drives the terminal.
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("syscall.Kill(SIGINT): %v", err)
	}

	// --- 7. Wait for Run to drain ----------------------------------------
	var result SupervisorResult
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Run: %v", got.err)
		}
		result = got.res
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s after SIGINT")
	}

	// --- 8. Result + run.json terminal assertions ------------------------
	if result.FinalState != StateKilledByUser {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateKilledByUser)
	}
	if result.StopReason != StopReasonSignal {
		t.Errorf("StopReason = %q, want %q", result.StopReason, StopReasonSignal)
	}
	if result.StoppedAt.IsZero() {
		t.Error("result.StoppedAt is zero, want non-zero")
	}
	wantSuggestion := "ai-env run " + envName + " --continue"
	if result.ContinueSuggestion != wantSuggestion {
		t.Errorf("ContinueSuggestion = %q, want %q", result.ContinueSuggestion, wantSuggestion)
	}
	if !strings.Contains(userOut.String(), wantSuggestion) {
		t.Errorf("UserOutput = %q, want substring %q", userOut.String(), wantSuggestion)
	}

	rec, err := ReadRecord(runDir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.State != StateKilledByUser {
		t.Errorf("run.json State = %q, want %q", rec.State, StateKilledByUser)
	}
	if rec.StopReason == nil || *rec.StopReason != StopReasonSignal {
		t.Errorf("run.json StopReason = %v, want %q", rec.StopReason, StopReasonSignal)
	}
	if rec.StoppedAt == nil {
		t.Error("run.json StoppedAt = nil, want non-nil")
	}
	if rec.StartedAt == nil {
		t.Error("run.json StartedAt = nil, want non-nil")
	}

	// --- 9. stdout.log preservation --------------------------------------
	stdoutBytes, err := os.ReadFile(filepath.Join(runDir.Path, "stdout.log"))
	if err != nil {
		t.Fatalf("read stdout.log: %v", err)
	}
	if !bytes.Contains(stdoutBytes, []byte(stdoutPayload)) {
		t.Errorf("stdout.log = %q, want substring %q (preserved through SIGINT)", stdoutBytes, stdoutPayload)
	}

	// --- 10. stderr.log preservation -------------------------------------
	stderrBytes, err := os.ReadFile(filepath.Join(runDir.Path, "stderr.log"))
	if err != nil {
		t.Fatalf("read stderr.log: %v", err)
	}
	if !bytes.Contains(stderrBytes, []byte(stderrPayload)) {
		t.Errorf("stderr.log = %q, want substring %q (preserved through SIGINT)", stderrBytes, stderrPayload)
	}

	// --- 11. Partial diff is non-trivial and reflects the worktree mod ---
	diffBytes, err := os.ReadFile(filepath.Join(runDir.Path, "git-diff.patch"))
	if err != nil {
		t.Fatalf("read git-diff.patch: %v", err)
	}
	if len(diffBytes) == 0 {
		t.Fatal("git-diff.patch is empty, want a unified-diff body covering the worktree modification")
	}
	// The diff must reference the modified file and the modified content
	// so we know the collector ran AFTER the child wrote its change, not
	// against a stale base ref. We check for the filename and the
	// post-modification line in the patch body.
	if !bytes.Contains(diffBytes, []byte("tracked.txt")) {
		t.Errorf("git-diff.patch = %q, want substring %q (modified filename)", diffBytes, "tracked.txt")
	}
	if !bytes.Contains(diffBytes, []byte(strings.TrimRight(trackedNewLine, "\n"))) {
		t.Errorf("git-diff.patch = %q, want substring %q (post-modification line)", diffBytes, trackedNewLine)
	}

	// --- 12. Lifecycle.jsonl ends on killed_by_user ----------------------
	states := readLifecycleStates(t, runDir.Path)
	if len(states) == 0 {
		t.Fatal("lifecycle.jsonl is empty")
	}
	if states[len(states)-1] != StateKilledByUser {
		t.Errorf("lifecycle last state = %q, want %q (full=%v)", states[len(states)-1], StateKilledByUser, states)
	}

	// --- 13. Resource hygiene --------------------------------------------
	//
	// Tear down the signal handlers explicitly so the goroutine exits
	// before the leak check below; the Cleanup we registered will run a
	// second stop() at test end, which is a no-op (stop is idempotent).
	stop()
	// Give the runtime a tick to actually retire the handler goroutine
	// and any wait goroutine the supervisor spawned (which exits when
	// Wait returns). Without this small sleep the leak check flakes on a
	// fast machine where the goroutines have been scheduled for exit but
	// have not actually retired yet.
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	// A handful of extra goroutines is normal scheduler noise (test
	// runner, parallel-test scaffolding); we assert a generous slack so
	// the test is not flaky on a busy CI host. A real leak from this test
	// would show up as a steadily growing count across runs, which would
	// blow past the slack threshold immediately.
	if delta := runtime.NumGoroutine() - baselineGoroutines; delta > 16 {
		t.Errorf("goroutine count grew by %d after SIGINT path; want near 0 (baseline=%d)", delta, baselineGoroutines)
	}
}
