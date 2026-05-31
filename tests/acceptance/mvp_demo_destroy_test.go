//go:build acceptance

// Package acceptance MVP-demonstration destroy verification.
//
// This file implements plan.md line 107 (master plan section "MVP
// demonstration", verification bullet 36):
//
//   - Verify: `ai-env destroy demo` removes environment resources.
//
// The test mirrors the shape of the prior mvp_demo_* verifications:
// it scaffolds a real worktree-strategy env via `ai-env new`, snapshots
// the artifacts the new command produces (.env-meta.json, the workspace
// directory itself, and the per-env git branch on the source repo),
// then drives `ai-env destroy demo` and asserts each artifact is gone.
// A second destroy invocation confirms the idempotent contract: the
// command must exit 0 even when there is nothing left to reclaim,
// with an "already absent" notice on stderr.
//
// A second sub-test exercises the copy strategy so the baseline
// snapshot under .ai-env/baselines/<env>/ is also covered: that
// directory is created read-only by CreateCopy, so a destroy command
// that did not restore write bits before unlinking would fail on the
// second call. We use the python-app fixture (no `git init`) so the
// destroy path is the StrategyCopy branch of workspace.Destroy.
//
// Gating mirrors section32_test.go and the other mvp_demo_* files: the
// build tag `acceptance` is the static gate and AI_ENV_ACCEPTANCE=1
// (via TestMain in section32_test.go) is the dynamic gate. The binary
// is built once by section32_test.go's TestMain and reused via
// suite.binPath.
//
// Why test the CLI surface (not just workspace.Destroy directly):
//
//   - The plan bullet is phrased against the user-facing command name
//     (`ai-env destroy demo`), so the acceptance bar is that the
//     command exists, validates its argument, locates the project's
//     .ai-env/, and produces the visible effect (artifacts gone) plus
//     a stable summary. Driving the CLI exercises every layer of that
//     stack in one pass.
//   - The idempotency contract lives at the CLI layer (the workspace
//     layer returns ErrEnvNotFound on the second call; the CLI
//     translates that into exit 0 with a notice). Only an end-to-end
//     test pins that translation.

package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAcceptance_DestroyDemoRemovesEnvironmentResources implements
// plan.md line 107 (master plan section "MVP demonstration",
// verification bullet 36): `ai-env destroy demo` removes environment
// resources.
//
// The test runs in two phases. The first phase exercises the
// worktree-strategy destroy path (the production default for a Git
// source); the second phase exercises the copy-strategy destroy path
// against a non-Git source. Both phases assert:
//
//  1. Pre-destroy: every artifact the new command produces actually
//     exists on disk (workspace directory, metadata file, baseline /
//     branch as appropriate).
//  2. Destroy succeeds: the CLI exits 0 and prints a summary that
//     mentions the env name and the "removed" verb for the
//     reclaimed paths so an operator can verify the right resources
//     were targeted.
//  3. Post-destroy: every snapshotted artifact is gone. The
//     workspace dir, metadata file, and baseline dir must no longer
//     stat; the per-env branch must no longer appear in `git branch
//     --list`.
//  4. Idempotent re-run: a second `ai-env destroy demo` exits 0 with
//     an "already absent" notice on stderr so the command is safe to
//     put in cleanup scripts. The second run must not regress any of
//     the post-destroy invariants from step 3.
func TestAcceptance_DestroyDemoRemovesEnvironmentResources(t *testing.T) {
	t.Run("WorktreeStrategy", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skipf("git not on PATH: %v", err)
		}

		// 1. Scaffold a worktree env from the Node fixture. The new
		// command creates: the workspace dir, the .env-meta.json
		// inside it, and the ai-env/demo branch on the source repo.
		src := copyFixture(t, "node-app")
		initGitFixture(t, src)
		if _, _, err := runAIEnvWithOutput(t, src, "new", "demo"); err != nil {
			t.Fatalf("ai-env new demo: %v", err)
		}

		aiEnvDir := filepath.Join(src, ".ai-env")
		wsDir := filepath.Join(aiEnvDir, "workspaces", "demo")
		metaFile := filepath.Join(wsDir, ".env-meta.json")
		branchName := "ai-env/demo"

		// Pre-destroy snapshot: every artifact must exist before we
		// can meaningfully claim destroy removed them.
		if _, err := os.Stat(wsDir); err != nil {
			t.Fatalf("pre-destroy: workspace dir %s missing: %v", wsDir, err)
		}
		if _, err := os.Stat(metaFile); err != nil {
			t.Fatalf("pre-destroy: metadata %s missing: %v", metaFile, err)
		}
		if !gitBranchExists(t, src, branchName) {
			t.Fatalf("pre-destroy: branch %s missing from source repo %s", branchName, src)
		}

		// 2. Run `ai-env destroy demo` and assert success + a
		// summary that names the reclaimed resources.
		stdout, stderr, err := runAIEnvWithOutput(t, src, "destroy", "demo")
		if err != nil {
			t.Fatalf("ai-env destroy demo: %v\nstderr:\n%s", err, stderr)
		}
		if !strings.Contains(stdout, "demo") {
			t.Errorf("destroy summary missing env name 'demo'; got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "removed") {
			t.Errorf("destroy summary missing 'removed' verb; got:\n%s", stdout)
		}
		// The summary should advertise the strategy so an operator
		// can confirm the worktree branch (not just the dir) was
		// reclaimed.
		if !strings.Contains(stdout, "worktree") {
			t.Errorf("destroy summary missing strategy label 'worktree'; got:\n%s", stdout)
		}

		// 3. Post-destroy: every snapshotted artifact is gone.
		if _, err := os.Stat(wsDir); !os.IsNotExist(err) {
			t.Errorf("post-destroy: workspace dir %s still present (err=%v); want IsNotExist", wsDir, err)
		}
		if _, err := os.Stat(metaFile); !os.IsNotExist(err) {
			t.Errorf("post-destroy: metadata %s still present (err=%v); want IsNotExist", metaFile, err)
		}
		if gitBranchExists(t, src, branchName) {
			t.Errorf("post-destroy: branch %s still present on source repo %s", branchName, src)
		}

		// 4. Idempotent re-run: a second destroy must exit 0 and
		// emit the "already absent" notice on stderr so cleanup
		// scripts that loop over envs do not fail when an env was
		// already reclaimed.
		stdout2, stderr2, err := runAIEnv(t, src, "destroy", "demo")
		if err != nil {
			t.Fatalf("second ai-env destroy demo returned error %v; idempotent re-run must exit 0\nstdout:\n%s\nstderr:\n%s",
				err, stdout2, stderr2)
		}
		// The "already absent" notice lives on stderr so scripts
		// that key on stdout do not see noise from no-op runs.
		if !strings.Contains(stderr2, "already absent") {
			t.Errorf("second destroy stderr missing 'already absent' notice; got:\n%s", stderr2)
		}
		// And the post-destroy invariants must still hold after
		// the no-op second run.
		if _, err := os.Stat(wsDir); !os.IsNotExist(err) {
			t.Errorf("after idempotent re-run: workspace dir %s reappeared (err=%v)", wsDir, err)
		}
	})

	t.Run("CopyStrategy", func(t *testing.T) {
		// Copy-strategy envs own both the workspace and a read-only
		// baseline snapshot. The baseline is created with read-only
		// permissions; a destroy command that did not restore write
		// bits before unlinking would either fail (on some
		// filesystems) or leave the baseline behind. We pin both
		// the workspace removal and the baseline removal here.
		src := copyFixture(t, "python-app")
		if _, err := os.Stat(filepath.Join(src, ".git")); !os.IsNotExist(err) {
			t.Fatalf("fixture %s unexpectedly carries .git (err=%v); copy mode test cannot run", src, err)
		}

		project := t.TempDir()
		// CreateCopy leaves the baseline read-only. If destroy fails
		// partway through we still need t.TempDir cleanup to be
		// able to unlink the tree, so we re-arm write bits in a
		// deferred cleanup.
		t.Cleanup(func() {
			restoreWriteBitsRecursive(filepath.Join(project, ".ai-env"))
		})

		if _, _, err := runAIEnvWithOutput(t, project, "new", "demo", "--from", src); err != nil {
			t.Fatalf("ai-env new demo --from %s: %v", src, err)
		}

		aiEnvDir := filepath.Join(project, ".ai-env")
		wsDir := filepath.Join(aiEnvDir, "workspaces", "demo")
		metaFile := filepath.Join(wsDir, ".env-meta.json")
		blDir := filepath.Join(aiEnvDir, "baselines", "demo")

		// Pre-destroy: workspace, metadata, and baseline must all
		// exist. The baseline is the load-bearing extra for the
		// copy path; its absence would invalidate the whole
		// strategy.
		if _, err := os.Stat(wsDir); err != nil {
			t.Fatalf("pre-destroy: workspace dir %s missing: %v", wsDir, err)
		}
		if _, err := os.Stat(metaFile); err != nil {
			t.Fatalf("pre-destroy: metadata %s missing: %v", metaFile, err)
		}
		if _, err := os.Stat(blDir); err != nil {
			t.Fatalf("pre-destroy: baseline dir %s missing: %v", blDir, err)
		}

		// Destroy: must succeed and the summary must mention both
		// the workspace and the baseline (so an operator can
		// confirm the read-only snapshot was reclaimed too).
		stdout, stderr, err := runAIEnvWithOutput(t, project, "destroy", "demo")
		if err != nil {
			t.Fatalf("ai-env destroy demo (copy): %v\nstderr:\n%s", err, stderr)
		}
		if !strings.Contains(stdout, "copy") {
			t.Errorf("destroy summary missing strategy label 'copy'; got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "baseline") {
			t.Errorf("destroy summary missing 'baseline' mention; got:\n%s", stdout)
		}

		// Post-destroy: workspace, metadata, and baseline all gone.
		if _, err := os.Stat(wsDir); !os.IsNotExist(err) {
			t.Errorf("post-destroy: workspace dir %s still present (err=%v)", wsDir, err)
		}
		if _, err := os.Stat(metaFile); !os.IsNotExist(err) {
			t.Errorf("post-destroy: metadata %s still present (err=%v)", metaFile, err)
		}
		if _, err := os.Stat(blDir); !os.IsNotExist(err) {
			t.Errorf("post-destroy: baseline dir %s still present (err=%v)", blDir, err)
		}

		// Idempotent re-run: second destroy exits 0 with the
		// "already absent" stderr notice.
		stdout2, stderr2, err := runAIEnv(t, project, "destroy", "demo")
		if err != nil {
			t.Fatalf("second ai-env destroy demo (copy) returned error %v\nstdout:\n%s\nstderr:\n%s",
				err, stdout2, stderr2)
		}
		if !strings.Contains(stderr2, "already absent") {
			t.Errorf("second destroy (copy) stderr missing 'already absent' notice; got:\n%s", stderr2)
		}
	})
}

// gitBranchExists reports whether branch is present in repoDir's local
// branch list. Used by the worktree-strategy assertions to pin both
// the pre-destroy "branch is there" and the post-destroy "branch is
// gone" invariants. A git failure (repo missing, ref subsystem broken)
// fails the test loudly rather than returning false silently, because
// every caller relies on the answer being authoritative.
func gitBranchExists(t *testing.T, repoDir, branch string) bool {
	t.Helper()
	cmd := exec.Command("git", "-C", repoDir, "show-ref", "--verify", "--quiet",
		"refs/heads/"+branch)
	err := cmd.Run()
	if err == nil {
		return true
	}
	// show-ref exits 1 when the ref is absent; any other exit (signal,
	// missing git, etc.) is an environmental problem we want to fail
	// on so the test does not silently pass on a broken host.
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return false
	}
	t.Fatalf("git show-ref %s in %s: %v", branch, repoDir, err)
	return false
}
