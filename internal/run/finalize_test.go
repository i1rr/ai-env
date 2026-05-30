package run

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// runFinalizeFixture is the shared setup the finalize tests use: a real
// on-disk RunDirectory plus the env / clock the supervisor will record
// in run.json. Tests pull a NewSupervisor off this with whatever extra
// fields they need on top.
type runFinalizeFixture struct {
	dir     RunDirectory
	envName string
	now     time.Time
}

func newRunFinalizeFixture(t *testing.T) runFinalizeFixture {
	t.Helper()
	return runFinalizeFixture{
		dir:     newSupervisorRunDir(t),
		envName: "fix-tests",
		now:     time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC),
	}
}

// readGitDiffFile reads the run directory's git-diff.patch file. Used
// by the partial-diff assertions; fails the test on read error so the
// assertion site stays focused on the value.
func readGitDiffFile(t *testing.T, runDir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(runDir, "git-diff.patch"))
	if err != nil {
		t.Fatalf("read git-diff.patch: %v", err)
	}
	return raw
}

// TestSupervisor_PartialDiffWrittenOnCompletion verifies that a
// successful run with a DiffCollector configured writes the collector's
// output verbatim into runDir/git-diff.patch. The plan's "On stop:
// collect partial diff" rule applies on completion as well as on forced
// termination: the file always exists, so a reviewer never has to guess
// whether the diff failed to collect or was simply never attempted.
func TestSupervisor_PartialDiffWrittenOnCompletion(t *testing.T) {
	skipIfNoSh(t)
	fx := newRunFinalizeFixture(t)

	wantDiff := []byte("diff --git a/foo b/foo\n--- a/foo\n+++ b/foo\n@@ -1 +1 @@\n-old\n+new\n")
	var collectorCalls int32

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            fx.dir.Path,
		RunID:             fx.dir.ID,
		EnvName:           fx.envName,
		Task:              "Run with a diff collector",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		DiffCollector: func(ctx context.Context) ([]byte, error) {
			atomic.AddInt32(&collectorCalls, 1)
			return wantDiff, nil
		},
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Fatalf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}
	if got := atomic.LoadInt32(&collectorCalls); got != 1 {
		t.Errorf("collector calls = %d, want 1", got)
	}
	if result.PartialDiffPath != filepath.Join(fx.dir.Path, "git-diff.patch") {
		t.Errorf("PartialDiffPath = %q, want %q", result.PartialDiffPath, filepath.Join(fx.dir.Path, "git-diff.patch"))
	}

	got := readGitDiffFile(t, fx.dir.Path)
	if !bytes.Equal(got, wantDiff) {
		t.Errorf("git-diff.patch = %q, want %q", got, wantDiff)
	}

	// run.json must reflect the final terminal AFTER the diff was
	// collected: the supervisor's contract is to write the closing
	// snapshot only once the diff is durable on disk. The check below
	// asserts that the run record carries the stop reason and exit
	// code (the closing-snapshot-only fields) so the closing write is
	// definitely the one we are reading back.
	rec, err := ReadRecord(fx.dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.State != StateCompleted {
		t.Errorf("run.json State = %q, want %q", rec.State, StateCompleted)
	}
	if rec.StopReason == nil || *rec.StopReason != StopReasonAgentExit {
		t.Errorf("run.json StopReason = %v, want %q", rec.StopReason, StopReasonAgentExit)
	}
	if rec.StoppedAt == nil {
		t.Error("run.json StoppedAt = nil, want non-nil")
	}
	if rec.ExitCode == nil || *rec.ExitCode != 0 {
		t.Errorf("run.json ExitCode = %v, want 0", rec.ExitCode)
	}

	// Completed terminals do not get the --continue suggestion: the
	// run did its job, the user has no reason to resume it. The
	// supervisor must neither print the line nor populate the result
	// field.
	if result.ContinueSuggestion != "" {
		t.Errorf("ContinueSuggestion = %q, want empty on StateCompleted", result.ContinueSuggestion)
	}
}

// TestSupervisor_PartialDiffWrittenOnCancel exercises the forced-
// termination path the master plan documents: SIGINT (here a direct
// sup.Cancel()) arrives, the run lands on StateKilledByUser, and the
// partial diff is still collected + written. The --continue suggestion
// must appear in UserOutput because killed_by_user is a continuation-
// eligible terminal.
func TestSupervisor_PartialDiffWrittenOnCancel(t *testing.T) {
	skipIfNoSh(t)
	fx := newRunFinalizeFixture(t)

	wantDiff := []byte("PARTIAL_DIFF_CONTENTS\n")
	var stdout bytes.Buffer

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            fx.dir.Path,
		RunID:             fx.dir.ID,
		EnvName:           fx.envName,
		Task:              "Sleep until cancelled",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("sleep 30"),
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
		DiffCollector: func(ctx context.Context) ([]byte, error) {
			return wantDiff, nil
		},
		UserOutput: &stdout,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	done := make(chan SupervisorResult, 1)
	go func() {
		res, runErr := sup.Run(context.Background())
		if runErr != nil {
			t.Errorf("Run: %v", runErr)
		}
		done <- res
	}()
	time.Sleep(100 * time.Millisecond)
	sup.Cancel()

	var result SupervisorResult
	select {
	case result = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Cancel within 5s")
	}

	if result.FinalState != StateKilledByUser {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateKilledByUser)
	}
	if got := readGitDiffFile(t, fx.dir.Path); !bytes.Equal(got, wantDiff) {
		t.Errorf("git-diff.patch = %q, want %q", got, wantDiff)
	}

	wantSuggestion := "ai-env run " + fx.envName + " --continue"
	if result.ContinueSuggestion != wantSuggestion {
		t.Errorf("ContinueSuggestion = %q, want %q", result.ContinueSuggestion, wantSuggestion)
	}
	if !strings.Contains(stdout.String(), wantSuggestion) {
		t.Errorf("UserOutput = %q, want substring %q", stdout.String(), wantSuggestion)
	}
}

// TestSupervisor_ContinueSuggestionStates pins which terminals print
// the --continue suggestion. The master plan ("On forced termination
// ... 4. Print `ai-env run <env-name> --continue` suggestion") lists
// killed_by_user, timed_out, and killed_idle; every other terminal must
// stay quiet. The table walks each terminal we can reach with a real
// child process; the supervisor's output is asserted directly.
func TestSupervisor_ContinueSuggestionStates(t *testing.T) {
	skipIfNoSh(t)
	envName := "continue-states"
	wantSuggestion := "ai-env run " + envName + " --continue"

	type tc struct {
		name      string
		opts      func(dir RunDirectory, stdout *bytes.Buffer) SupervisorOptions
		final     State
		wantPrint bool
	}
	cases := []tc{
		{
			name: "completed quiet",
			opts: func(dir RunDirectory, stdout *bytes.Buffer) SupervisorOptions {
				return SupervisorOptions{
					RunDir:            dir.Path,
					RunID:             dir.ID,
					EnvName:           envName,
					Task:              "Exit cleanly",
					Backend:           "local-process",
					Agent:             "claude",
					Command:           shellCmd("exit 0"),
					MaxRuntime:        5 * time.Second,
					StatsPollInterval: 20 * time.Millisecond,
					StopGracePeriod:   100 * time.Millisecond,
					UserOutput:        stdout,
				}
			},
			final:     StateCompleted,
			wantPrint: false,
		},
		{
			name: "failed_agent quiet",
			opts: func(dir RunDirectory, stdout *bytes.Buffer) SupervisorOptions {
				return SupervisorOptions{
					RunDir:            dir.Path,
					RunID:             dir.ID,
					EnvName:           envName,
					Task:              "Exit non-zero",
					Backend:           "local-process",
					Agent:             "claude",
					Command:           shellCmd("exit 7"),
					MaxRuntime:        5 * time.Second,
					StatsPollInterval: 20 * time.Millisecond,
					StopGracePeriod:   100 * time.Millisecond,
					UserOutput:        stdout,
				}
			},
			final:     StateFailedAgent,
			wantPrint: false,
		},
		{
			name: "timed_out prints",
			opts: func(dir RunDirectory, stdout *bytes.Buffer) SupervisorOptions {
				return SupervisorOptions{
					RunDir:            dir.Path,
					RunID:             dir.ID,
					EnvName:           envName,
					Task:              "Sleep forever",
					Backend:           "local-process",
					Agent:             "claude",
					Command:           shellCmd("sleep 30"),
					MaxRuntime:        100 * time.Millisecond,
					StatsPollInterval: 20 * time.Millisecond,
					StopGracePeriod:   200 * time.Millisecond,
					UserOutput:        stdout,
				}
			},
			final:     StateTimedOut,
			wantPrint: true,
		},
		{
			name: "killed_idle prints",
			opts: func(dir RunDirectory, stdout *bytes.Buffer) SupervisorOptions {
				return SupervisorOptions{
					RunDir:            dir.Path,
					RunID:             dir.ID,
					EnvName:           envName,
					Task:              "Sleep with no output",
					Backend:           "local-process",
					Agent:             "claude",
					Command:           shellCmd("sleep 30"),
					MaxRuntime:        5 * time.Second,
					IdleTimeout:       150 * time.Millisecond,
					StatsPollInterval: 30 * time.Millisecond,
					StopGracePeriod:   200 * time.Millisecond,
					UserOutput:        stdout,
				}
			},
			final:     StateKilledIdle,
			wantPrint: true,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			dir := newSupervisorRunDir(t)
			var stdout bytes.Buffer
			sup, err := NewSupervisor(c.opts(dir, &stdout))
			if err != nil {
				t.Fatalf("NewSupervisor: %v", err)
			}
			result, err := sup.Run(context.Background())
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if result.FinalState != c.final {
				t.Errorf("FinalState = %q, want %q", result.FinalState, c.final)
			}
			printed := strings.Contains(stdout.String(), wantSuggestion)
			if printed != c.wantPrint {
				t.Errorf("UserOutput contains suggestion = %v, want %v (out=%q)", printed, c.wantPrint, stdout.String())
			}
			gotSuggestion := result.ContinueSuggestion != ""
			if gotSuggestion != c.wantPrint {
				t.Errorf("ContinueSuggestion non-empty = %v, want %v", gotSuggestion, c.wantPrint)
			}
		})
	}
}

// TestSupervisor_PartialDiffEmptyWhenCollectorFails confirms the
// supervisor's "collect partial diff if possible" rule: a collector
// that returns an error still results in a present (but empty)
// git-diff.patch on disk, the final terminal still records correctly,
// and the supervisor surfaces a warning via UserOutput so the operator
// knows the diff is missing rather than silently zero-byte.
func TestSupervisor_PartialDiffEmptyWhenCollectorFails(t *testing.T) {
	skipIfNoSh(t)
	fx := newRunFinalizeFixture(t)
	var stdout bytes.Buffer

	collectorErr := errors.New("simulated git failure")
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            fx.dir.Path,
		RunID:             fx.dir.ID,
		EnvName:           fx.envName,
		Task:              "Collector blows up",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		DiffCollector: func(ctx context.Context) ([]byte, error) {
			return nil, collectorErr
		},
		UserOutput: &stdout,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}

	got := readGitDiffFile(t, fx.dir.Path)
	if len(got) != 0 {
		t.Errorf("git-diff.patch = %q, want empty", got)
	}
	// The warning is best-effort but must mention the failure so the
	// operator can react. We do not pin the exact format.
	if !strings.Contains(stdout.String(), "partial diff") {
		t.Errorf("UserOutput = %q, want a partial-diff warning", stdout.String())
	}

	rec, err := ReadRecord(fx.dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.State != StateCompleted {
		t.Errorf("run.json State = %q, want %q", rec.State, StateCompleted)
	}
	if rec.StoppedAt == nil {
		t.Error("run.json StoppedAt = nil, want non-nil")
	}
}

// TestSupervisor_NoDiffCollectorLeavesPlaceholder confirms that a
// supervisor wired without a DiffCollector still leaves the
// git-diff.patch placeholder on disk (created empty by
// CreateRunDirectory) and lands a clean StateCompleted terminal. This
// is the v0.1 default for callers that have not wired the workspace
// collector yet.
func TestSupervisor_NoDiffCollectorLeavesPlaceholder(t *testing.T) {
	skipIfNoSh(t)
	fx := newRunFinalizeFixture(t)
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            fx.dir.Path,
		RunID:             fx.dir.ID,
		EnvName:           fx.envName,
		Task:              "No collector wired",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}
	// The file exists by virtue of the placeholder and stays empty.
	got := readGitDiffFile(t, fx.dir.Path)
	if len(got) != 0 {
		t.Errorf("git-diff.patch = %q, want empty placeholder", got)
	}
}

// TestSupervisor_DiffCollectorTimeoutHonored exercises the supervisor's
// timeout cap on the DiffCollector. A collector that intentionally
// outlasts the configured DiffTimeout must observe ctx.Done() and the
// supervisor must still land a clean terminal afterwards. Without the
// cap a stuck git process could block the supervisor's terminal walk
// indefinitely.
func TestSupervisor_DiffCollectorTimeoutHonored(t *testing.T) {
	skipIfNoSh(t)
	fx := newRunFinalizeFixture(t)
	var stdout bytes.Buffer

	var collectorObservedCancel int32
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            fx.dir.Path,
		RunID:             fx.dir.ID,
		EnvName:           fx.envName,
		Task:              "Collector ignores ctx until deadline",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		DiffTimeout:       50 * time.Millisecond,
		DiffCollector: func(ctx context.Context) ([]byte, error) {
			select {
			case <-ctx.Done():
				atomic.StoreInt32(&collectorObservedCancel, 1)
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
				return nil, errors.New("collector did not observe cancel")
			}
		},
		UserOutput: &stdout,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	start := time.Now()
	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Run took %v; expected diff timeout to fire quickly", elapsed)
	}
	if result.FinalState != StateCompleted {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}
	if atomic.LoadInt32(&collectorObservedCancel) != 1 {
		t.Error("collector did not observe ctx.Done before timeout")
	}
	// Even on timeout the git-diff.patch file must exist; the supervisor
	// writes whatever bytes the collector produced (here zero).
	got := readGitDiffFile(t, fx.dir.Path)
	if len(got) != 0 {
		t.Errorf("git-diff.patch = %q, want empty on timeout", got)
	}
}

// TestSupervisor_HardKillStillFinalizes confirms the supervisor's
// orderly shutdown contract under a hard kill: the child process is
// dead before the runLoop returns, the DiffCollector still runs, the
// final run.json is written, the partial diff file is present, and
// UserOutput sees the suggestion. This pins the "on hard kill /
// git failure, finalization still completes" requirement from the
// plan-executor brief.
func TestSupervisor_HardKillStillFinalizes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard-kill test is POSIX-only")
	}
	skipIfNoSh(t)
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("sh not available: %v", err)
	}
	fx := newRunFinalizeFixture(t)
	var stdout bytes.Buffer

	// The child ignores SIGTERM/SIGINT (trap '' INT TERM) and then
	// busy-waits inside the shell itself (no `sleep` fork) so the
	// SIGKILL the supervisor sends after StopGracePeriod lands on a
	// process that actually responds to it. A `sleep` subprocess
	// would be reparented to PID 1 after the shell dies; using a
	// shell-level busy loop keeps the child PID == c.Process.Pid the
	// whole time so the supervisor's hardKillChild path is the only
	// one that ends the run, which is exactly the scenario we want to
	// exercise. The supervisor's finalization must still write the
	// diff and the closing snapshot.
	cmd := shellCmd("trap '' INT TERM; while true; do :; done")

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            fx.dir.Path,
		RunID:             fx.dir.ID,
		EnvName:           fx.envName,
		Task:              "Child ignores signals",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           cmd,
		MaxRuntime:        5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   150 * time.Millisecond,
		DiffCollector: func(ctx context.Context) ([]byte, error) {
			return []byte("collector ran after hard kill\n"), nil
		},
		UserOutput: &stdout,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	done := make(chan SupervisorResult, 1)
	go func() {
		res, runErr := sup.Run(context.Background())
		if runErr != nil {
			t.Errorf("Run: %v", runErr)
		}
		done <- res
	}()
	time.Sleep(100 * time.Millisecond)
	sup.Cancel()

	var result SupervisorResult
	select {
	case result = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after hard kill within 5s")
	}

	if result.FinalState != StateKilledByUser {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateKilledByUser)
	}
	got := readGitDiffFile(t, fx.dir.Path)
	if !bytes.Equal(got, []byte("collector ran after hard kill\n")) {
		t.Errorf("git-diff.patch = %q, want the collector output", got)
	}
	rec, err := ReadRecord(fx.dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.State != StateKilledByUser {
		t.Errorf("run.json State = %q, want %q", rec.State, StateKilledByUser)
	}
	if rec.StoppedAt == nil {
		t.Error("run.json StoppedAt = nil, want non-nil")
	}
	if !strings.Contains(stdout.String(), "ai-env run "+fx.envName+" --continue") {
		t.Errorf("UserOutput = %q, want --continue suggestion", stdout.String())
	}
}

// TestCollectPartialDiff_NoCollectorIsNoop directly exercises the
// helper to confirm the "no collector wired" branch leaves the
// placeholder alone. The supervisor depends on this for tests and for
// callers that have not yet wired a workspace-aware collector.
func TestCollectPartialDiff_NoCollectorIsNoop(t *testing.T) {
	dir := t.TempDir()
	// Pre-create an empty placeholder the way CreateRunDirectory does.
	if err := os.WriteFile(filepath.Join(dir, "git-diff.patch"), nil, 0o644); err != nil {
		t.Fatalf("seed placeholder: %v", err)
	}
	if err := collectPartialDiff(dir, nil, 0); err != nil {
		t.Errorf("collectPartialDiff(nil): %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "git-diff.patch"))
	if err != nil {
		t.Fatalf("read placeholder: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("placeholder = %q, want empty", got)
	}
}

// TestCollectPartialDiff_WritesBytesAtomically confirms the helper's
// atomic-write contract: the temp file is renamed into place, the
// final bytes match the collector output exactly, and the file has
// the canonical run mode.
func TestCollectPartialDiff_WritesBytesAtomically(t *testing.T) {
	dir := t.TempDir()
	body := []byte("hunk text\n")
	col := func(ctx context.Context) ([]byte, error) { return body, nil }
	if err := collectPartialDiff(dir, col, time.Second); err != nil {
		t.Fatalf("collectPartialDiff: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "git-diff.patch"))
	if err != nil {
		t.Fatalf("read git-diff.patch: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("git-diff.patch = %q, want %q", got, body)
	}
	st, err := os.Stat(filepath.Join(dir, "git-diff.patch"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0o644", st.Mode().Perm())
	}
	// No temp files should be left behind in the directory after the
	// rename.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "git-diff.patch.tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// TestContinueSuggestionText pins the exact format the master plan
// specifies. A regression that changed the spelling (e.g. dropped
// the env name or used --resume) would surface here rather than as a
// confused user.
func TestContinueSuggestionText(t *testing.T) {
	got := continueSuggestionText("fix-tests")
	want := "ai-env run fix-tests --continue"
	if got != want {
		t.Errorf("continueSuggestionText = %q, want %q", got, want)
	}
}

// TestTerminalSupportsContinue locks down the set of states that get
// the `--continue` suggestion. The plan's "On forced termination ...
// Print --continue suggestion" list is killed_by_user, timed_out,
// killed_idle; every other terminal must stay quiet so an operator
// does not see a misleading hint after, say, a successful run or a
// quarantined run.
func TestTerminalSupportsContinue(t *testing.T) {
	want := map[State]bool{
		StateKilledByUser:  true,
		StateTimedOut:      true,
		StateKilledIdle:    true,
		StateCompleted:     false,
		StateFailedAgent:   false,
		StateFailedBackend: false,
		StateFailedPolicy:  false,
		StateFailedScan:    false,
		StateKilledOOM:     false,
		StateQuarantined:   false,
	}
	for s, w := range want {
		if got := terminalSupportsContinue(s); got != w {
			t.Errorf("terminalSupportsContinue(%q) = %v, want %v", s, got, w)
		}
	}
}

// TestNewGitWorktreeDiffCollector_RequiresArgs pins the constructor's
// input validation. The supervisor relies on the collector returning
// an error rather than panicking on a missing branch or sourceDir, so
// the helper's error path must be reachable.
func TestNewGitWorktreeDiffCollector_RequiresArgs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := NewGitWorktreeDiffCollector("", "HEAD", "ai-env/foo")(ctx); err == nil {
		t.Error("missing sourceDir: expected error")
	}
	if _, err := NewGitWorktreeDiffCollector("/tmp", "HEAD", "")(ctx); err == nil {
		t.Error("missing branch: expected error")
	}
}
