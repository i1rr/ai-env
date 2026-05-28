// Package workspace implements the workspace isolation layer for ai-env.
//
// A workspace is the on-disk place where an agent makes edits. It is kept
// separate from the user's active working tree so the agent's changes never
// touch live files by default. Two strategies are supported:
//
//   - worktree: backed by a Git worktree on a dedicated branch
//     (used when the source project is a Git repository).
//   - copy:     backed by a recursive copy of the source directory plus a
//     baseline snapshot for diffing
//     (used when the source project is not a Git repository).
//
// This file defines the public surface (the WorkspaceManager interface and
// the value types it produces). Strategy implementations, the diff and patch
// engines, and the protected-path matcher are built in later steps of plan 02
// and plug into this interface.
package workspace

import "time"

// StrategyType identifies which isolation strategy backs a workspace.
//
// The zero value is intentionally invalid so a caller that forgets to set a
// strategy fails loudly instead of silently picking one.
type StrategyType string

const (
	// StrategyWorktree means the workspace is a Git worktree at
	// .ai-env/workspaces/<env-name>/ checked out on branch
	// ai-env/<env-name>. Diffs are computed via `git diff` against the base
	// branch.
	StrategyWorktree StrategyType = "worktree"

	// StrategyCopy means the workspace is a recursive copy of the source
	// project at .ai-env/workspaces/<env-name>/ with a read-only baseline
	// snapshot at .ai-env/baselines/<env-name>/. Diffs are computed file by
	// file against the baseline.
	StrategyCopy StrategyType = "copy"
)

// String makes StrategyType satisfy fmt.Stringer so it formats cleanly in
// log lines and CLI output without an explicit conversion.
func (s StrategyType) String() string { return string(s) }

// WorkspaceInfo describes a workspace that Create just materialized (or that
// Strategy looked up). It is the single value type the rest of the codebase
// consumes when it needs to know where a workspace lives and what backs it.
//
// All path fields are absolute. Fields not relevant to the active strategy
// are left at their zero value (e.g. Branch is empty for a copy workspace,
// BaselinePath is empty for a worktree workspace).
type WorkspaceInfo struct {
	// Name is the env name. It is also the workspace directory's basename
	// under .ai-env/workspaces/.
	Name string

	// Strategy is the isolation strategy backing this workspace.
	Strategy StrategyType

	// Path is the absolute path to the workspace directory itself
	// (.ai-env/workspaces/<env-name>/).
	Path string

	// SourcePath is the absolute path to the original source project the
	// workspace was created from. For a worktree this is the repo root; for
	// a copy this is the directory that was copied.
	SourcePath string

	// Branch is the Git branch the worktree is checked out on, e.g.
	// "ai-env/fix-tests". Empty for the copy strategy.
	Branch string

	// BaselinePath is the absolute path to the read-only baseline snapshot
	// used by the copy strategy's diff engine
	// (.ai-env/baselines/<env-name>/). Empty for the worktree strategy.
	BaselinePath string

	// Template is the sandbox template the env was created with (e.g.
	// "node", "go"). It is recorded here so the metadata file written by
	// Create can stay a single source of truth.
	Template string

	// CreatedAt is when the workspace was materialized, in the local time
	// zone. Persisted in RFC3339 form in the on-disk metadata file.
	CreatedAt time.Time
}

// DiffResult is the structured output of WorkspaceManager.Diff. It is
// designed so callers can both render a human view and reason about
// protected-path changes programmatically without re-parsing the unified
// diff text.
type DiffResult struct {
	// Name is the env name the diff was taken for.
	Name string

	// Strategy is the strategy the diff was produced under.
	Strategy StrategyType

	// Files is the per-file diff entries, in deterministic order.
	Files []FileDiff

	// Unified is the full unified-diff text as a single blob, suitable for
	// piping into patch(1) or displaying verbatim. It is the exact text
	// that Patch would emit for this state.
	Unified string

	// ProtectedHits lists the relative paths of changed files that match
	// the configured protected-path patterns. Diff and Patch never block
	// on these; the caller surfaces a warning and the export gate uses
	// this list to decide whether human review is required.
	ProtectedHits []string
}

// FileDiff is one entry in a DiffResult: a single changed file's path,
// change kind, and unified-diff hunks for that file.
type FileDiff struct {
	// Path is the workspace-relative path to the file.
	Path string

	// Change describes how the file changed relative to the baseline.
	Change ChangeKind

	// Unified is the unified-diff hunks scoped to just this file. It is a
	// subset of DiffResult.Unified.
	Unified string

	// Protected reports whether Path matched a protected-path pattern.
	Protected bool
}

// ChangeKind enumerates how a single file changed between baseline and
// workspace.
type ChangeKind string

const (
	// ChangeAdded means the file exists in the workspace but not the
	// baseline.
	ChangeAdded ChangeKind = "added"

	// ChangeModified means the file exists in both but its contents
	// differ.
	ChangeModified ChangeKind = "modified"

	// ChangeDeleted means the file exists in the baseline but not the
	// workspace.
	ChangeDeleted ChangeKind = "deleted"
)

// WorkspaceManager is the central interface for plan 02. Every command that
// needs an isolated workspace (new, diff, patch, run, etc.) goes through
// this interface so the strategy choice stays a single decision point.
//
// Implementations must be safe to call sequentially per env name. Concurrent
// calls against the same env name are not required to be safe; the CLI
// serializes them.
type WorkspaceManager interface {
	// Create materializes a workspace for envName whose source is
	// sourcePath. strategy selects the isolation strategy; pass the empty
	// StrategyType to let the implementation auto-detect (worktree for
	// Git sources, copy for non-Git). The returned WorkspaceInfo is also
	// persisted to the workspace's .env-meta.json file.
	Create(envName, sourcePath string, strategy StrategyType) (WorkspaceInfo, error)

	// Diff computes the current diff between the workspace for envName
	// and its baseline (the merge base for worktree, the baseline snapshot
	// for copy). It does not write any files.
	Diff(envName string) (DiffResult, error)

	// Patch writes a unified-diff patch for envName to outputPath. The
	// patch content is the same text DiffResult.Unified would carry; it
	// is written so callers can hand it to git apply or patch(1).
	Patch(envName, outputPath string) error

	// Strategy returns the strategy currently backing envName's
	// workspace, read from its persisted metadata. An error is returned
	// when no workspace exists for envName.
	Strategy(envName string) (StrategyType, error)
}
