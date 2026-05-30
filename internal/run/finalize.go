package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// gitDiffFileName is the basename of the partial-diff file the supervisor
// writes into the run directory on terminal. The plan's run directory
// layout (plan 03, "Run directory layout") names it git-diff.patch; it
// sits next to run.json so a reviewer reading a run on disk sees both the
// final-state snapshot and the workspace's partial diff side by side.
//
// The placeholder was created (empty) by CreateRunDirectory, so callers
// that never wire a DiffCollector still find the file in the documented
// layout. The supervisor overwrites it with the collector's output (or
// leaves it empty when the collector returns no bytes).
const gitDiffFileName = "git-diff.patch"

// defaultDiffTimeout is the upper bound the supervisor enforces on a
// DiffCollector call. The plan's "forced termination" sequence
// (preserve logs -> collect partial diff -> mark run -> print suggestion)
// must not hang on a stuck git process: a hung `git diff` against a
// detached worktree, a corrupt index, or a missing base ref could block
// the supervisor indefinitely otherwise. 10 seconds is comfortably above
// the runtime of a real `git diff` on a multi-thousand-file workspace
// while still being short enough that a stuck child does not delay the
// terminal walk past the user's expectation.
//
// Callers can override via SupervisorOptions.DiffTimeout when their
// collector is known to be slower (e.g. a copy-strategy diff of a very
// large workspace) or faster (a unit test that injects a synchronous
// stub).
const defaultDiffTimeout = 10 * time.Second

// DiffCollector is the seam the supervisor uses to fetch the partial
// diff for a terminating run. It is supplied by the caller (the
// `ai-env run` CLI in production, a test stub in unit tests) so the run
// package does not have to import internal/workspace and so the
// supervisor stays decoupled from the workspace strategy in play.
//
// Contract:
//
//   - The collector returns the unified-diff text the supervisor should
//     write into the run directory's git-diff.patch file. Returning
//     (nil, nil) is legal: it means "the workspace had no changes to
//     diff"; the supervisor still writes a (zero-byte) file so the run
//     directory layout is uniform.
//   - The collector is invoked with a context whose deadline is at most
//     SupervisorOptions.DiffTimeout in the future. Implementations that
//     shell out (e.g. via exec.CommandContext) should honor ctx so the
//     supervisor's terminal walk is not blocked by a stuck git process.
//   - The collector is invoked exactly once per run, from the
//     supervisor's terminal path. It is never invoked from concurrent
//     goroutines.
//   - An error returned from the collector is logged via the supervisor's
//     UserOutput (when set) but does NOT change the terminal state: the
//     plan's "Collect partial diff if possible" rule treats the diff as
//     advisory. The supervisor still writes an empty git-diff.patch so
//     the layout is consistent, and the closing run.json snapshot still
//     records the terminal the run actually landed in.
type DiffCollector func(ctx context.Context) ([]byte, error)

// NewGitWorktreeDiffCollector builds a DiffCollector that asks `git
// diff` for the worktree-strategy partial diff. It is the production
// path for `ai-env run` against a Git workspace: the supervisor calls
// the returned collector on terminal, the collector runs
// `git diff <base>...<branch>` inside sourceDir, and the resulting
// unified-diff text is written into git-diff.patch.
//
// The function lives here (rather than in internal/workspace) so the
// run package stays free of a workspace import. The workspace package
// already knows how to produce the equivalent diff via Diff(...).Unified;
// the CLI may use either path depending on whether it wants to share the
// workspace package's protected-path logic or just capture the raw text
// the supervisor needs.
//
// Inputs:
//
//   - sourceDir is the absolute path of the source Git repository
//     (workspace.WorkspaceInfo.SourcePath). `git diff` runs with this as
//     its working directory so it picks up the worktree and the source
//     branch in one invocation.
//   - base is the ref the diff is computed against (typically "HEAD" of
//     the source repo at the time the workspace was created). Empty
//     defaults to "HEAD" to match workspace.diffWorktree's convention.
//   - branch is the env branch the workspace runs on (e.g.
//     "ai-env/fix-tests"). Required; an empty branch makes `git diff`
//     ambiguous and the collector returns an error.
//
// The returned collector swallows the "missing base ref" / "detached
// HEAD" failures git surfaces in its stderr and returns (nil, err) so
// the supervisor can log the warning and still write an empty diff file.
// A non-existent git binary surfaces the same way.
func NewGitWorktreeDiffCollector(sourceDir, base, branch string) DiffCollector {
	return func(ctx context.Context) ([]byte, error) {
		if sourceDir == "" {
			return nil, errors.New("run: NewGitWorktreeDiffCollector requires sourceDir")
		}
		if branch == "" {
			return nil, errors.New("run: NewGitWorktreeDiffCollector requires branch")
		}
		ref := base
		if ref == "" {
			ref = "HEAD"
		}
		spec := ref + "..." + branch
		// CommandContext binds ctx so a supervisor-side deadline kills
		// the child if git hangs (e.g. on a corrupt index waiting for a
		// lock). --no-color keeps the output stable for patch(1) and for
		// downstream tests; the worktree diff path uses the same flags.
		cmd := exec.CommandContext(ctx, "git", "diff", "--no-color", spec)
		cmd.Dir = sourceDir
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			msg := stderr.String()
			if msg != "" {
				return stdout.Bytes(), fmt.Errorf("run: git diff %s in %s: %w: %s", spec, sourceDir, err, msg)
			}
			return stdout.Bytes(), fmt.Errorf("run: git diff %s in %s: %w", spec, sourceDir, err)
		}
		return stdout.Bytes(), nil
	}
}

// GitDiffPath returns the absolute path of the git-diff.patch file
// inside runDir. It is the symmetric helper to RunJSONPath; later
// callers (status / logs / list, batch 7) use it to point operators at
// the partial diff without re-encoding the layout.
func GitDiffPath(runDir string) string {
	return filepath.Join(runDir, gitDiffFileName)
}

// terminalSupportsContinue reports whether a run that ended in state s
// is eligible for the `--continue` suggestion the supervisor prints.
//
// The master plan's "On forced termination" sequence (section 16,
// supervision) lists three terminals that get the suggestion:
// killed_by_user, timed_out, killed_idle. The plan's wording is
// deliberately narrow: a clean StateCompleted run does not need a
// continuation hint (the user's task already finished), and a
// StateFailedAgent / StateFailedBackend / StateFailedPolicy /
// StateFailedScan / StateKilledOOM / StateQuarantined terminal carries
// its own remediation path (fix the agent, fix the backend, address the
// scanner verdict) that --continue cannot help with on its own. We mirror
// that triage here so the suggestion only shows up where it is actually
// actionable.
//
// Exported so the CLI (batch 8, which actually consumes --continue) can
// reuse the predicate without re-deriving the set.
func terminalSupportsContinue(s State) bool {
	switch s {
	case StateKilledByUser, StateTimedOut, StateKilledIdle:
		return true
	}
	return false
}

// continueSuggestionText returns the exact line the supervisor prints
// when a run lands in a continuation-eligible terminal. The plan
// (master plan section 16 "Signal handling", step 4) pins the format
// verbatim:
//
//	ai-env run <env-name> --continue
//
// We expose this as a helper so tests can assert on the exact string
// and so future callers (a richer status command, a `--help` page) can
// surface the same phrasing without re-deriving it.
func continueSuggestionText(envName string) string {
	return fmt.Sprintf("ai-env run %s --continue", envName)
}

// collectPartialDiff invokes the configured DiffCollector with a
// timeout-bound context and writes the result into runDir/git-diff.patch.
// It is the implementation of step 10's "collect partial diff" bullet.
//
// Behavior matrix:
//
//   - collector nil:  no DiffCollector configured; the function leaves
//     the (empty) placeholder git-diff.patch alone and returns nil. This
//     is the common path during early bring-up where the CLI has not yet
//     wired a workspace-aware collector.
//   - collector returns (nil, nil): the workspace had no changes. The
//     placeholder is truncated to zero bytes (already empty by default)
//     and the function returns nil.
//   - collector returns (bytes, nil): bytes are written to git-diff.patch
//     verbatim. The file is overwritten (not appended) so a re-run of
//     finalization on the same run directory (a future replay tool) sees
//     the latest snapshot rather than a concatenation.
//   - collector returns (bytes, err): bytes are still written (partial
//     output is more useful than no output), and the err is returned to
//     the caller so it can log a warning. The supervisor treats the
//     error as advisory: it does NOT change the terminal state.
//   - collector returns (nil, err): an empty git-diff.patch is written
//     (overwriting the placeholder, which is already empty, with itself)
//     and the err is returned. The file is still present so the run
//     directory layout stays uniform.
//   - context deadline elapses while the collector is running: the
//     collector returns ctx.Err() (or a wrapped form). The supervisor
//     surfaces it as a warning and writes whatever partial bytes the
//     collector produced before the deadline.
//
// timeout caps how long the collector is allowed to run. Zero falls
// back to defaultDiffTimeout; negative values are rejected up front by
// the SupervisorOptions validator, never reaching this helper.
func collectPartialDiff(runDir string, collector DiffCollector, timeout time.Duration) error {
	if runDir == "" {
		return errors.New("run: collectPartialDiff requires runDir")
	}
	path := filepath.Join(runDir, gitDiffFileName)

	if collector == nil {
		// No collector wired. Leave the placeholder in place so the on-
		// disk layout still has git-diff.patch (CreateRunDirectory
		// already materialized it as an empty file). Truncating to zero
		// bytes here is unnecessary because the placeholder is already
		// empty; callers that overwrite the file out of band are out of
		// scope for the supervisor's contract.
		return nil
	}

	if timeout <= 0 {
		timeout = defaultDiffTimeout
	}

	// Bind a fresh context with the configured deadline so a stuck
	// collector cannot block the supervisor's terminal walk past the
	// budget. cancel must always run so the timer goroutine the runtime
	// allocates for the deadline is released even on the happy path.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	body, collectErr := collector(ctx)

	// Write whatever bytes we got (which may be nil on the error paths)
	// using a temp file + rename so a concurrent reader (a future status
	// command) never observes a half-written diff. The file is
	// O_TRUNC'd via Rename's "replace the destination" semantics.
	if err := writeDiffFile(path, body); err != nil {
		// If we cannot land the bytes on disk surface that; the collector
		// error (if any) is folded in so the caller has the full picture.
		if collectErr != nil {
			return fmt.Errorf("%w (collect: %v)", err, collectErr)
		}
		return err
	}
	return collectErr
}

// writeDiffFile writes body into path using an atomic temp-file +
// rename. The file is created with runFileMode (0o644) to match the
// rest of the run directory's mode convention. body may be nil; the
// result is a zero-byte file in that case.
func writeDiffFile(path string, body []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "git-diff.patch.tmp-*")
	if err != nil {
		return fmt.Errorf("run: create git-diff.patch temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if len(body) > 0 {
		if _, err := tmp.Write(body); err != nil {
			_ = tmp.Close()
			cleanup()
			return fmt.Errorf("run: write git-diff.patch temp file %s: %w", tmpPath, err)
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("run: sync git-diff.patch temp file %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, runFileMode); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("run: chmod git-diff.patch temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("run: close git-diff.patch temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("run: rename git-diff.patch temp file into place: %w", err)
	}
	return nil
}

// printContinueSuggestion writes the `--continue` hint to out when the
// terminal state supports continuation. It is a no-op for terminals
// that do not (StateCompleted, the various failure states) and a no-op
// when no UserOutput was configured.
//
// The hint is the exact line the master plan specifies, terminated with
// a newline so subsequent shell prompts start cleanly. We deliberately
// do NOT prefix the line with anything: a downstream CLI may want to
// wrap it in a header ("Run was stopped early. Resume with:\n  ai-env
// run ... --continue"), but the supervisor's contract is to surface the
// exact command the user can re-run. Callers that want a richer message
// can read the suggestion via SupervisorResult.ContinueSuggestion (set
// alongside this print) and format their own banner.
func printContinueSuggestion(out io.Writer, envName string, terminal State) string {
	if !terminalSupportsContinue(terminal) {
		return ""
	}
	suggestion := continueSuggestionText(envName)
	if out != nil {
		// A failed write is intentionally swallowed: the suggestion is
		// advisory ("hey, you can resume this"), not load-bearing. A
		// broken stdout (closed pipe, full buffer) must not derail the
		// supervisor's terminal walk.
		_, _ = fmt.Fprintln(out, suggestion)
	}
	return suggestion
}
