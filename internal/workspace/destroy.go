package workspace

import (
	"errors"
	"fmt"
	"os"
)

// ErrEnvNotFound is returned by Destroy when the named env has no on-disk
// presence under aiEnvDir (no metadata file, no workspace directory, no
// baseline directory). Callers that want idempotent "destroy" semantics
// match on this with errors.Is and treat it as a no-op success.
var ErrEnvNotFound = errors.New("workspace: env not found")

// DestroyResult reports what Destroy actually reclaimed on disk. The CLI
// uses it to print a one-line summary so an operator can see whether the
// run removed a worktree, a copy baseline, or just a stray directory.
type DestroyResult struct {
	// Name is the env name that was destroyed.
	Name string
	// Strategy is the strategy the destroyed env was created under, as
	// recorded in its metadata. Empty when metadata was missing and the
	// destroy ran as a best-effort directory removal.
	Strategy StrategyType
	// WorkspacePath is the absolute path of the workspace directory that
	// was removed (or that was already absent). Always populated so the
	// caller can describe the reclaimed location even on the not-found
	// path.
	WorkspacePath string
	// BaselinePath is the absolute path of the baseline directory that
	// was removed. Populated only for copy-strategy envs.
	BaselinePath string
	// Branch is the git branch that was deleted from the source repo.
	// Populated only for worktree-strategy envs whose branch deletion
	// succeeded.
	Branch string
	// RemovedWorkspace reports whether the workspace directory actually
	// existed at the start of Destroy and was removed by this call.
	RemovedWorkspace bool
	// RemovedBaseline reports whether the baseline directory actually
	// existed at the start of Destroy and was removed by this call.
	// Always false for worktree-strategy envs.
	RemovedBaseline bool
	// RemovedBranch reports whether the worktree branch existed in the
	// source repo at the start of Destroy and was deleted by this call.
	// Always false for copy-strategy envs.
	RemovedBranch bool
}

// Destroy reclaims every on-disk resource the workspace package created
// for envName under aiEnvDir. It is the inverse of CreateWorktree /
// CreateCopy.
//
// Lifecycle:
//
//  1. Read the .env-meta.json to learn which strategy backs the env. A
//     missing metadata file produces ErrEnvNotFound UNLESS a workspace
//     directory still exists; in that "stranded directory" case Destroy
//     removes the directory and returns success so the operator can
//     reclaim half-created envs without manual rm.
//  2. For worktree-strategy envs: ask Git to drop the worktree (which
//     also handles the per-worktree administrative file under the source
//     repo's .git/worktrees/), then force-delete the ai-env/<env-name>
//     branch from the source repo. Both steps are best-effort: if Git
//     refuses (e.g. the source repo moved) we fall back to a direct
//     directory removal so the workspace path is reclaimed regardless.
//  3. For copy-strategy envs: remove the read-only baseline snapshot via
//     removeReadOnlyTree (which restores write bits before unlinking),
//     then remove the workspace directory.
//
// Destroy is idempotent: running it twice against the same env name
// returns ErrEnvNotFound the second time. Callers that want a silent
// idempotent surface check for that sentinel and treat it as success.
func Destroy(aiEnvDir, envName string) (DestroyResult, error) {
	if aiEnvDir == "" {
		return DestroyResult{}, errors.New("workspace: Destroy requires aiEnvDir")
	}
	if envName == "" {
		return DestroyResult{}, errors.New("workspace: Destroy requires envName")
	}

	wsPath := WorkspacePath(aiEnvDir, envName)
	blPath := BaselinePath(aiEnvDir, envName)

	res := DestroyResult{
		Name:          envName,
		WorkspacePath: wsPath,
	}

	// Step 1: load metadata. The metadata tells us which strategy backs
	// the env, which in turn tells us which on-disk artifacts to reclaim.
	// A missing metadata file is normally ErrEnvNotFound; if the
	// workspace directory still exists (a half-created env, or a
	// metadata file that was hand-deleted) we still fall through to the
	// best-effort cleanup path so the operator can reclaim the
	// directory.
	info, metaErr := ReadMetadata(aiEnvDir, envName)
	if metaErr != nil {
		wsExists := pathExists(wsPath)
		blExists := pathExists(blPath)
		if !wsExists && !blExists {
			return res, fmt.Errorf("%w: %s", ErrEnvNotFound, envName)
		}
		// Stranded directory path: no metadata, but a workspace and/or
		// baseline still on disk. Reclaim them both as a best-effort.
		if blExists {
			res.BaselinePath = blPath
			if err := removeReadOnlyTree(blPath); err != nil {
				return res, fmt.Errorf("workspace: Destroy baseline %s: %w", blPath, err)
			}
			res.RemovedBaseline = true
		}
		if wsExists {
			if err := os.RemoveAll(wsPath); err != nil {
				return res, fmt.Errorf("workspace: Destroy workspace %s: %w", wsPath, err)
			}
			res.RemovedWorkspace = true
		}
		return res, nil
	}

	res.Strategy = info.Strategy

	switch info.Strategy {
	case StrategyWorktree:
		// Ask Git to drop the worktree first so the per-worktree
		// administrative directory inside the source repo's
		// .git/worktrees/ is cleaned up as part of the same operation.
		// removeWorktree itself falls back to a direct os.RemoveAll on
		// Git failure so a moved or corrupted source repo does not
		// strand the workspace path.
		if pathExists(wsPath) {
			// We intentionally do not bubble removeWorktree's error
			// here: the fallback path inside it already unlinks the
			// workspace directory, which is the load-bearing
			// reclamation. A leftover .git/worktrees/<name>/ entry on
			// the source side is the operator's problem to clean up
			// (and `git worktree prune` handles it) but does not
			// block Destroy from reporting success.
			_ = removeWorktree(info.SourcePath, wsPath)
			res.RemovedWorkspace = true
		}
		// Best-effort branch delete. If the source repo is missing or
		// the branch never existed we swallow the error: the user's
		// load-bearing expectation is that the workspace tree is gone,
		// not that the branch metadata is also reclaimed.
		if info.Branch != "" && info.SourcePath != "" {
			if err := deleteBranch(info.SourcePath, info.Branch); err == nil {
				res.Branch = info.Branch
				res.RemovedBranch = true
			}
		}
		// Belt-and-suspenders: if the workspace dir somehow survived
		// (e.g. removeWorktree's fallback also failed), reach for
		// os.RemoveAll directly. A dangling directory after Destroy
		// would defeat the whole point of the command.
		if pathExists(wsPath) {
			if err := os.RemoveAll(wsPath); err != nil {
				return res, fmt.Errorf("workspace: Destroy workspace %s: %w", wsPath, err)
			}
			res.RemovedWorkspace = true
		}

	case StrategyCopy:
		// Copy-strategy envs own both the workspace and the read-only
		// baseline. The baseline is created with read-only permissions
		// so a plain os.RemoveAll fails on some filesystems;
		// removeReadOnlyTree restores write bits before unlinking.
		if pathExists(blPath) {
			res.BaselinePath = blPath
			if err := removeReadOnlyTree(blPath); err != nil {
				return res, fmt.Errorf("workspace: Destroy baseline %s: %w", blPath, err)
			}
			res.RemovedBaseline = true
		}
		if pathExists(wsPath) {
			if err := os.RemoveAll(wsPath); err != nil {
				return res, fmt.Errorf("workspace: Destroy workspace %s: %w", wsPath, err)
			}
			res.RemovedWorkspace = true
		}

	default:
		return res, fmt.Errorf("workspace: Destroy: unknown strategy %q for env %q", info.Strategy, envName)
	}

	return res, nil
}

// pathExists reports whether path resolves to an existing filesystem
// entry. A stat error other than IsNotExist is treated as "exists" so
// the caller still attempts removal and surfaces any underlying I/O
// failure from the remove step (rather than swallowing it here).
func pathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}
