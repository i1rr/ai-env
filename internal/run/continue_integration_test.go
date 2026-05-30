package run

// Integration tests for step 14 (`--continue`).
//
// These tests exercise PrepareContinuation end-to-end against:
//
//   - A real on-disk Git repository (created with `git init`).
//   - The real WorkspaceManager flow (workspace.CreateWorktree) so the
//     worktree the supervisor reuses is a genuine `git worktree`.
//   - The real run.Supervisor driving a real `sh` child for both the
//     previous and the continuation run.
//
// Nothing in this file mocks the supervisor, the workspace, the git
// binary, or the filesystem. The goal is to prove the helper coordinates
// run directory creation, workspace reuse, run.json linking, task.md
// inheritance, supervisor wiring (LinkedPreviousRun /
// LinkedPreviousRunPtr), and the error-path branches in a real
// end-to-end flow.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/workspace"
)

// integrationGitRepo creates a temp directory, runs `git init` inside it,
// configures a fixture identity, and commits a single README so the repo
// has a HEAD. Returns the absolute path to the new repo's working tree.
func integrationGitRepo(t *testing.T) string {
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
	readme := filepath.Join(repo, "README.md")
	if err := os.WriteFile(readme, []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runCmd("add", ".")
	runCmd("commit", "-m", "initial")
	return repo
}

// integrationSkipIfNoSh mirrors the supervisor tests' skip: the
// integration test drives a real sh child to keep the supervisor's
// stdout/stderr capture, wait path, and exit-code wiring on the live
// code path.
func integrationSkipIfNoSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("integration test uses POSIX sh; skipping on windows")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("sh not available: %v", err)
	}
}

// hashFile returns a SHA-256 hex of the file at path. Used as a sentinel
// to prove that a file is byte-for-byte unchanged across the
// continuation boundary.
func hashFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// runSupervisor drives a single supervisor.Run with the given options
// and returns the result. Failures fail the test rather than propagate.
func runSupervisor(t *testing.T, opts SupervisorOptions) SupervisorResult {
	t.Helper()
	sup, err := NewSupervisor(opts)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Supervisor.Run: %v", err)
	}
	return result
}

// TestContinueIntegration_EndToEnd is the headline integration test. It
// drives the full --continue flow against real filesystem and real
// subprocess execution:
//
//  1. Create a real Git repo and materialize a worktree-backed workspace
//     for it via workspace.CreateWorktree.
//  2. Drive a real supervisor against a short-lived sh child, asking it
//     to land in a continuation-eligible terminal (we use Cancel to
//     drive StateKilledByUser, which terminalSupportsContinue accepts).
//  3. Drop a sentinel file into the worktree so we can prove the
//     continuation does NOT touch it.
//  4. Capture the previous run dir's run.json + stdout.log hashes.
//  5. Call PrepareContinuation; assert new id > previous, fresh run dir
//     is a sibling of the previous, task.md is inherited.
//  6. Drive a SECOND real supervisor inside the new run dir (still
//     pointing at the same workspace.Path) with another short child.
//     Wire LinkedPreviousRunPtr(cont.PreviousRunID) into SupervisorOptions.
//  7. Assert the previous run directory's hashes are unchanged.
//  8. Assert the worktree sentinel is still present with its original
//     content.
//  9. Assert the new run.json has linked_previous_run set to the prior
//     run id and lands on StateCompleted.
func TestContinueIntegration_EndToEnd(t *testing.T) {
	integrationSkipIfNoSh(t)

	repo := integrationGitRepo(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	envName := "fix-tests"
	prevTask := "Resume the failing tests"

	// --- 1. Materialize the workspace -------------------------------------
	info, err := workspace.CreateWorktree(aiEnvDir, envName, repo, "go", time.Now())
	if err != nil {
		t.Fatalf("workspace.CreateWorktree: %v", err)
	}
	if info.Path == "" {
		t.Fatalf("CreateWorktree returned empty Path")
	}

	// --- 2. Create the previous run directory + drive a real supervisor --
	prevRunID, err := GenerateRunID()
	if err != nil {
		t.Fatalf("GenerateRunID prev: %v", err)
	}
	prevDir, err := CreateRunDirectory(aiEnvDir, prevRunID, time.Now())
	if err != nil {
		t.Fatalf("CreateRunDirectory prev: %v", err)
	}
	if err := WriteTask(aiEnvDir, prevRunID, prevTask); err != nil {
		t.Fatalf("WriteTask prev: %v", err)
	}

	// We want the previous run to land in a continuation-eligible
	// terminal (StateKilledByUser / StateTimedOut / StateKilledIdle).
	// Driving via MaxRuntime would race with the child; using Cancel
	// from a goroutine gives us a deterministic StateKilledByUser
	// landing and exercises the same finalize path the real CLI uses.
	prevSup, err := NewSupervisor(SupervisorOptions{
		RunDir:            prevDir.Path,
		RunID:             prevDir.ID,
		EnvName:           envName,
		Task:              prevTask,
		Backend:           "local-process",
		Agent:             "claude",
		// A child that produces some output, then sleeps long enough for
		// the goroutine below to send Cancel. The supervisor's stop
		// path will then signal the child and reap it.
		Command:           CommandSpec{Program: "sh", Args: []string{"-c", "echo first-run; sleep 10"}, Dir: info.Path},
		MaxRuntime:        30 * time.Second,
		IdleTimeout:       0,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor prev: %v", err)
	}
	// Cancel shortly after the supervisor has had time to launch the
	// child. 150ms is well clear of the StatsPollInterval and matches
	// the existing supervisor cancel tests' cadence.
	go func() {
		time.Sleep(150 * time.Millisecond)
		prevSup.Cancel()
	}()
	prevResult, err := prevSup.Run(context.Background())
	if err != nil {
		t.Fatalf("prev Supervisor.Run: %v", err)
	}
	if prevResult.FinalState != StateKilledByUser {
		t.Fatalf("prev FinalState = %q, want %q", prevResult.FinalState, StateKilledByUser)
	}
	if !terminalSupportsContinue(prevResult.FinalState) {
		t.Fatalf("prev terminal %q is not continuation-eligible", prevResult.FinalState)
	}

	// --- 3. Sentinel inside the worktree -----------------------------------
	sentinel := filepath.Join(info.Path, "agent-progress.txt")
	sentinelBody := []byte("agent-was-here\n")
	if err := os.WriteFile(sentinel, sentinelBody, 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	// --- 4. Capture hashes of the previous run's load-bearing files ------
	prevRunJSONHash := hashFile(t, filepath.Join(prevDir.Path, "run.json"))
	prevStdoutHash := hashFile(t, filepath.Join(prevDir.Path, "stdout.log"))
	prevTaskMDHash := hashFile(t, filepath.Join(prevDir.Path, "task.md"))

	// --- 5. PrepareContinuation -------------------------------------------
	contNow := time.Now()
	cont, err := PrepareContinuation(aiEnvDir, envName, "", contNow)
	if err != nil {
		t.Fatalf("PrepareContinuation: %v", err)
	}
	if cont.PreviousRunID != prevDir.ID {
		t.Errorf("PreviousRunID = %q, want %q", cont.PreviousRunID, prevDir.ID)
	}
	if cont.NewRun.ID == prevDir.ID {
		t.Errorf("NewRun.ID = %q, must differ from previous", cont.NewRun.ID)
	}
	if cont.NewRun.ID <= prevDir.ID {
		t.Errorf("NewRun.ID %q must sort strictly after previous %q", cont.NewRun.ID, prevDir.ID)
	}
	if filepath.Dir(cont.NewRun.Path) != filepath.Dir(prevDir.Path) {
		t.Errorf("NewRun parent = %q, want sibling of previous parent %q",
			filepath.Dir(cont.NewRun.Path), filepath.Dir(prevDir.Path))
	}
	if cont.TaskSource != TaskSourceInherited {
		t.Errorf("TaskSource = %q, want %q", cont.TaskSource, TaskSourceInherited)
	}
	newTaskBytes, err := os.ReadFile(TaskPath(aiEnvDir, cont.NewRun.ID))
	if err != nil {
		t.Fatalf("read new task.md: %v", err)
	}
	if !strings.Contains(string(newTaskBytes), prevTask) {
		t.Errorf("new task.md = %q, want to contain previous task %q", string(newTaskBytes), prevTask)
	}

	// Pointer helper -> SupervisorOptions wiring.
	linkedPtr := LinkedPreviousRunPtr(cont.PreviousRunID)
	if linkedPtr == nil || *linkedPtr != prevDir.ID {
		t.Fatalf("LinkedPreviousRunPtr = %v, want pointer to %q", linkedPtr, prevDir.ID)
	}

	// --- 6. Drive the SECOND supervisor inside the continued run dir -----
	secondCmd := CommandSpec{Program: "sh", Args: []string{"-c", "echo continuation-run; exit 0"}, Dir: info.Path}
	secondResult := runSupervisor(t, SupervisorOptions{
		RunDir:            cont.NewRun.Path,
		RunID:             cont.NewRun.ID,
		EnvName:           envName,
		Task:              string(newTaskBytes),
		Backend:           "local-process",
		Agent:             "claude",
		Command:           secondCmd,
		MaxRuntime:        10 * time.Second,
		IdleTimeout:       0,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
		LinkedPreviousRun: linkedPtr,
	})
	if secondResult.FinalState != StateCompleted {
		t.Errorf("second FinalState = %q, want %q", secondResult.FinalState, StateCompleted)
	}
	if !secondResult.HasExitCode || secondResult.ExitCode != 0 {
		t.Errorf("second ExitCode = %d (has=%v), want 0", secondResult.ExitCode, secondResult.HasExitCode)
	}

	// --- 7. Previous run directory must be byte-for-byte unchanged -------
	if got := hashFile(t, filepath.Join(prevDir.Path, "run.json")); got != prevRunJSONHash {
		t.Errorf("previous run.json hash changed: was %s now %s", prevRunJSONHash, got)
	}
	if got := hashFile(t, filepath.Join(prevDir.Path, "stdout.log")); got != prevStdoutHash {
		t.Errorf("previous stdout.log hash changed: was %s now %s", prevStdoutHash, got)
	}
	if got := hashFile(t, filepath.Join(prevDir.Path, "task.md")); got != prevTaskMDHash {
		t.Errorf("previous task.md hash changed: was %s now %s", prevTaskMDHash, got)
	}
	prevRecAfter, err := ReadRecord(prevDir.Path)
	if err != nil {
		t.Fatalf("ReadRecord(prev) after continuation: %v", err)
	}
	if prevRecAfter.State != StateKilledByUser {
		t.Errorf("previous state mutated to %q (want %q)", prevRecAfter.State, StateKilledByUser)
	}

	// --- 8. Worktree sentinel must be present and unchanged --------------
	gotSentinel, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("read sentinel after continuation: %v", err)
	}
	if string(gotSentinel) != string(sentinelBody) {
		t.Errorf("sentinel content = %q, want %q (worktree must not have been reset)",
			string(gotSentinel), string(sentinelBody))
	}
	// And the workspace metadata file must still be where CreateWorktree
	// put it: no helper should have rewritten it during the continuation.
	if _, err := os.Stat(workspace.MetadataPath(aiEnvDir, envName)); err != nil {
		t.Errorf("workspace metadata missing after continuation: %v", err)
	}

	// --- 9. linked_previous_run must be persisted in the new run.json ----
	newRec, err := ReadRecord(cont.NewRun.Path)
	if err != nil {
		t.Fatalf("ReadRecord(new): %v", err)
	}
	if newRec.LinkedPreviousRun == nil {
		t.Fatalf("new run.json linked_previous_run = nil, want %q", prevDir.ID)
	}
	if *newRec.LinkedPreviousRun != prevDir.ID {
		t.Errorf("new run.json linked_previous_run = %q, want %q",
			*newRec.LinkedPreviousRun, prevDir.ID)
	}
	if newRec.RunID != cont.NewRun.ID {
		t.Errorf("new run.json run_id = %q, want %q", newRec.RunID, cont.NewRun.ID)
	}
	if newRec.State != StateCompleted {
		t.Errorf("new run.json state = %q, want %q", newRec.State, StateCompleted)
	}
	if newRec.EnvName != envName {
		t.Errorf("new run.json env_name = %q, want %q", newRec.EnvName, envName)
	}
}

// TestContinueIntegration_FreshTaskAndContinuationLink is a smaller end-
// to-end test of the --task override path: even with a fresh task, the
// new run dir must still link back to the previous one, and the
// previous run must end up byte-for-byte untouched.
func TestContinueIntegration_FreshTaskAndContinuationLink(t *testing.T) {
	integrationSkipIfNoSh(t)

	repo := integrationGitRepo(t)
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	envName := "fresh-task-env"
	prevTask := "Original instruction"
	newTask := "Try a different approach"

	if _, err := workspace.CreateWorktree(aiEnvDir, envName, repo, "", time.Now()); err != nil {
		t.Fatalf("workspace.CreateWorktree: %v", err)
	}

	prevRunID, err := GenerateRunID()
	if err != nil {
		t.Fatalf("GenerateRunID prev: %v", err)
	}
	prevDir, err := CreateRunDirectory(aiEnvDir, prevRunID, time.Now())
	if err != nil {
		t.Fatalf("CreateRunDirectory prev: %v", err)
	}
	if err := WriteTask(aiEnvDir, prevRunID, prevTask); err != nil {
		t.Fatalf("WriteTask prev: %v", err)
	}

	// Drive previous supervisor and cancel it to land on StateKilledByUser.
	prevSup, err := NewSupervisor(SupervisorOptions{
		RunDir:            prevDir.Path,
		RunID:             prevDir.ID,
		EnvName:           envName,
		Task:              prevTask,
		Backend:           "local-process",
		Agent:             "claude",
		Command:           CommandSpec{Program: "sh", Args: []string{"-c", "echo prev; sleep 5"}},
		MaxRuntime:        30 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor prev: %v", err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		prevSup.Cancel()
	}()
	prevRes, err := prevSup.Run(context.Background())
	if err != nil {
		t.Fatalf("prev Supervisor.Run: %v", err)
	}
	if prevRes.FinalState != StateKilledByUser {
		t.Fatalf("prev FinalState = %q, want %q", prevRes.FinalState, StateKilledByUser)
	}

	prevTaskMDHash := hashFile(t, filepath.Join(prevDir.Path, "task.md"))

	cont, err := PrepareContinuation(aiEnvDir, envName, newTask, time.Now())
	if err != nil {
		t.Fatalf("PrepareContinuation: %v", err)
	}
	if cont.TaskSource != TaskSourceFresh {
		t.Errorf("TaskSource = %q, want %q", cont.TaskSource, TaskSourceFresh)
	}
	body, err := os.ReadFile(TaskPath(aiEnvDir, cont.NewRun.ID))
	if err != nil {
		t.Fatalf("read new task.md: %v", err)
	}
	if !strings.Contains(string(body), newTask) {
		t.Errorf("new task.md = %q, want to contain %q", string(body), newTask)
	}
	if strings.Contains(string(body), prevTask) {
		t.Errorf("new task.md = %q, must NOT contain prev task %q", string(body), prevTask)
	}
	// Previous task.md must still match what we wrote.
	if got := hashFile(t, filepath.Join(prevDir.Path, "task.md")); got != prevTaskMDHash {
		t.Errorf("previous task.md hash changed: was %s now %s", prevTaskMDHash, got)
	}

	// Second supervisor run for the continuation, exits cleanly.
	res := runSupervisor(t, SupervisorOptions{
		RunDir:            cont.NewRun.Path,
		RunID:             cont.NewRun.ID,
		EnvName:           envName,
		Task:              string(body),
		Backend:           "local-process",
		Agent:             "claude",
		Command:           CommandSpec{Program: "sh", Args: []string{"-c", "echo cont; exit 0"}},
		MaxRuntime:        10 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
		LinkedPreviousRun: LinkedPreviousRunPtr(cont.PreviousRunID),
	})
	if res.FinalState != StateCompleted {
		t.Errorf("second FinalState = %q, want %q", res.FinalState, StateCompleted)
	}

	newRec, err := ReadRecord(cont.NewRun.Path)
	if err != nil {
		t.Fatalf("ReadRecord(new): %v", err)
	}
	if newRec.LinkedPreviousRun == nil || *newRec.LinkedPreviousRun != prevDir.ID {
		t.Errorf("new run.json linked_previous_run = %v, want %q", newRec.LinkedPreviousRun, prevDir.ID)
	}
}

// TestContinueIntegration_NoPreviousRun exercises the
// ContinueErrNoPreviousRun branch end-to-end: a fresh aiEnvDir with no
// runs, no workspace, and a real call to PrepareContinuation.
func TestContinueIntegration_NoPreviousRun(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	_, err := PrepareContinuation(aiEnvDir, "fix-tests", "any task", time.Now())
	if err == nil {
		t.Fatalf("PrepareContinuation: expected error, got nil")
	}
	var ce *ContinueError
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want *ContinueError: %v", err, err)
	}
	if ce.Kind != ContinueErrNoPreviousRun {
		t.Errorf("ContinueError.Kind = %v, want %v", ce.Kind, ContinueErrNoPreviousRun)
	}
}

// TestContinueIntegration_PreviousRunActive exercises the
// ContinueErrPreviousRunActive branch: we simulate an active previous
// run by writing a non-terminal state into its run.json, then call
// PrepareContinuation. The helper must refuse rather than race with a
// still-running supervisor.
func TestContinueIntegration_PreviousRunActive(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	envName := "active-env"
	runID := "20260528-101000-aaaaaa"
	dir, err := CreateRunDirectory(aiEnvDir, runID, time.Now())
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	if err := WriteTask(aiEnvDir, runID, "Currently running"); err != nil {
		t.Fatalf("WriteTask: %v", err)
	}
	// Non-terminal state -> the helper must reject as "still active".
	rec := Record{
		RunID:               runID,
		EnvName:             envName,
		Agent:               "claude",
		Task:                "Currently running",
		State:               StateRunning,
		Backend:             "local-process",
		ModelCredentialMode: ModelCredentialBackendManaged,
	}
	if err := WriteRecord(dir.Path, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	_, err = PrepareContinuation(aiEnvDir, envName, "", time.Now())
	if err == nil {
		t.Fatalf("PrepareContinuation: expected error, got nil")
	}
	var ce *ContinueError
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want *ContinueError: %v", err, err)
	}
	if ce.Kind != ContinueErrPreviousRunActive {
		t.Errorf("ContinueError.Kind = %v, want %v", ce.Kind, ContinueErrPreviousRunActive)
	}
	if ce.PreviousID != runID {
		t.Errorf("ContinueError.PreviousID = %q, want %q", ce.PreviousID, runID)
	}
	if ce.PreviousState != StateRunning {
		t.Errorf("ContinueError.PreviousState = %q, want %q", ce.PreviousState, StateRunning)
	}
}

// TestContinueIntegration_PreviousRunNotContinuable exercises the
// ContinueErrPreviousRunNotContinuable branch: we simulate a previous
// run that terminated in a non-continuable terminal (StateCompleted)
// and assert PrepareContinuation refuses.
func TestContinueIntegration_PreviousRunNotContinuable(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	envName := "completed-env"
	runID := "20260528-101000-bbbbbb"
	dir, err := CreateRunDirectory(aiEnvDir, runID, time.Now())
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	if err := WriteTask(aiEnvDir, runID, "Already done"); err != nil {
		t.Fatalf("WriteTask: %v", err)
	}
	stopped := time.Now()
	reason := StopReasonForState(StateCompleted)
	rec := Record{
		RunID:               runID,
		EnvName:             envName,
		Agent:               "claude",
		Task:                "Already done",
		State:               StateCompleted,
		Backend:             "local-process",
		ModelCredentialMode: ModelCredentialBackendManaged,
		StoppedAt:           &stopped,
		StopReason:          &reason,
	}
	if err := WriteRecord(dir.Path, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	_, err = PrepareContinuation(aiEnvDir, envName, "", time.Now())
	if err == nil {
		t.Fatalf("PrepareContinuation: expected error, got nil")
	}
	var ce *ContinueError
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want *ContinueError: %v", err, err)
	}
	if ce.Kind != ContinueErrPreviousRunNotContinuable {
		t.Errorf("ContinueError.Kind = %v, want %v", ce.Kind, ContinueErrPreviousRunNotContinuable)
	}
	if ce.PreviousState != StateCompleted {
		t.Errorf("ContinueError.PreviousState = %q, want %q", ce.PreviousState, StateCompleted)
	}
}
