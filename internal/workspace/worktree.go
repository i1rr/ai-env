package workspace

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// BranchPrefix is the namespace prepended to every branch ai-env creates so
// the user can recognize and exclude them with a single pattern. It matches
// the master plan's decision: branch name format is "ai-env/<env-name>".
const BranchPrefix = "ai-env/"

// workspaceSubdir is the directory under the host's .ai-env/ where every
// worktree (and copy) lives. Centralizing this string keeps Create, Diff,
// and Patch in agreement about the on-disk layout.
const workspaceSubdir = "workspaces"

// metadataFileName is the per-workspace metadata file's basename. The file
// holds the on-disk record of strategy, branch, source path, etc. so later
// commands (diff, patch, list) can recover what they need without re-running
// detection.
const metadataFileName = ".env-meta.json"

// BranchName returns the canonical Git branch name for envName, e.g.
// "ai-env/fix-tests". The same helper is used by Create (to make the branch)
// and Diff (to find it again) so the two cannot drift.
func BranchName(envName string) string {
	return BranchPrefix + envName
}

// WorkspacePath returns the absolute path of the worktree directory for
// envName under aiEnvDir. aiEnvDir is the host's .ai-env/ directory (the
// caller resolves it; this helper does not assume a working directory).
func WorkspacePath(aiEnvDir, envName string) string {
	return filepath.Join(aiEnvDir, workspaceSubdir, envName)
}

// MetadataPath returns the absolute path of the .env-meta.json file for
// envName under aiEnvDir.
func MetadataPath(aiEnvDir, envName string) string {
	return filepath.Join(WorkspacePath(aiEnvDir, envName), metadataFileName)
}

// envMetadata is the on-disk shape of .env-meta.json. It is a superset that
// covers both worktree and copy strategies; fields not relevant to the
// active strategy are omitted via the omitempty tag so the file stays
// readable.
//
// The JSON field names match the format documented in plan 02 ("Env
// metadata file" section).
type envMetadata struct {
	Name         string `json:"name"`
	Strategy     string `json:"strategy"`
	Branch       string `json:"branch,omitempty"`
	SourcePath   string `json:"source_path"`
	WorkspacePath string `json:"workspace_path"`
	CreatedAt    string `json:"created_at"`
	Template     string `json:"template,omitempty"`

	// Copy-strategy-only fields. Left empty for worktree workspaces.
	BaselinePath string `json:"baseline_path,omitempty"`
	CopyTime     string `json:"copy_time,omitempty"`
	HashSummary  string `json:"hash_summary,omitempty"`
}

// CreateWorktree materializes a worktree-backed workspace for envName.
//
// It performs the three actions plan 02 step 3 requires:
//
//  1. Create branch ai-env/<env-name> from sourcePath's current HEAD.
//  2. Create a Git worktree at aiEnvDir/workspaces/<env-name>/ checked out
//     on that branch.
//  3. Write a .env-meta.json file inside the worktree recording the branch
//     name and worktree path (plus identifying fields shared with the copy
//     strategy: name, strategy, source path, created_at, template).
//
// Inputs:
//   - aiEnvDir is the absolute path to the host's .ai-env/ directory. The
//     worktree is placed under aiEnvDir/workspaces/<env-name>/. The caller
//     is responsible for resolving this; CreateWorktree does not assume the
//     process working directory.
//   - envName is the workspace name. It is used both as the worktree's
//     directory basename and as the suffix of the branch.
//   - sourcePath is the absolute path to the Git repository the worktree is
//     created from. It must be a usable working tree (IsGitRepo returns
//     true). The caller already validated that before calling.
//   - template is the sandbox template label (e.g. "node") to record in the
//     metadata file. Pass "" when no template applies.
//   - now supplies the timestamp recorded as created_at. Pass time.Now in
//     production; tests pass a fixed time. now is taken as a value (not a
//     clock function) so the call site stays explicit about which time is
//     persisted.
//
// On success CreateWorktree returns a fully populated WorkspaceInfo
// (Strategy=StrategyWorktree, BaselinePath empty). On failure it makes a
// best-effort attempt to roll back partial state: a half-created worktree
// is removed and the freshly created branch is deleted, so a retry starts
// from a clean slate.
func CreateWorktree(aiEnvDir, envName, sourcePath, template string, now time.Time) (WorkspaceInfo, error) {
	if aiEnvDir == "" {
		return WorkspaceInfo{}, errors.New("workspace: CreateWorktree requires aiEnvDir")
	}
	if envName == "" {
		return WorkspaceInfo{}, errors.New("workspace: CreateWorktree requires envName")
	}
	if sourcePath == "" {
		return WorkspaceInfo{}, errors.New("workspace: CreateWorktree requires sourcePath")
	}

	branch := BranchName(envName)
	wtPath := WorkspacePath(aiEnvDir, envName)

	// Refuse to clobber an existing worktree directory. The caller's policy
	// (e.g. --force on ai-env new) is responsible for cleaning up first;
	// CreateWorktree itself stays conservative so a retried run cannot
	// silently merge state from a previous attempt.
	if _, err := os.Stat(wtPath); err == nil {
		return WorkspaceInfo{}, fmt.Errorf("workspace: worktree path %s already exists", wtPath)
	} else if !os.IsNotExist(err) {
		return WorkspaceInfo{}, fmt.Errorf("workspace: stat %s: %w", wtPath, err)
	}

	// Refuse to reuse a branch name. Git itself would fail on the create,
	// but checking up front lets us return a clearer error and skip the
	// rollback dance.
	if exists, err := branchExists(sourcePath, branch); err != nil {
		return WorkspaceInfo{}, err
	} else if exists {
		return WorkspaceInfo{}, fmt.Errorf("workspace: branch %s already exists in %s", branch, sourcePath)
	}

	// Resolve HEAD into a concrete commit so the new branch points at the
	// same commit even if the user re-checks-out HEAD afterwards. Using a
	// commit (rather than the symbolic "HEAD") also gives us a deterministic
	// starting point on detached-HEAD source repos.
	headCommit, err := resolveHead(sourcePath)
	if err != nil {
		return WorkspaceInfo{}, err
	}

	// Ensure the parent directory (.ai-env/workspaces/) exists before
	// asking git to drop a worktree into it. git worktree add creates the
	// leaf directory itself but does not create intermediate parents.
	if err := os.MkdirAll(filepath.Dir(wtPath), 0o755); err != nil {
		return WorkspaceInfo{}, fmt.Errorf("workspace: create worktree parent %s: %w", filepath.Dir(wtPath), err)
	}

	// `git worktree add -b <branch> <path> <commit>` does both step 1 and
	// step 2 in a single atomic git operation: it creates the branch at
	// <commit> and checks it out into <path>. Doing both in one command is
	// preferable to a separate `git branch` + `git worktree add` because
	// it avoids the window where the branch exists but no worktree owns
	// it (which would dirty the source repo if CreateWorktree crashed
	// between the two calls).
	if err := runGit(sourcePath, "worktree", "add", "-b", branch, wtPath, headCommit); err != nil {
		// Nothing to roll back: if `git worktree add` failed it either
		// did not create the branch or it cleaned up after itself. Best-
		// effort cleanup of an empty directory in case git left one
		// behind on a partial run.
		_ = os.RemoveAll(wtPath)
		return WorkspaceInfo{}, fmt.Errorf("workspace: git worktree add: %w", err)
	}

	info := WorkspaceInfo{
		Name:       envName,
		Strategy:   StrategyWorktree,
		Path:       wtPath,
		SourcePath: sourcePath,
		Branch:     branch,
		Template:   template,
		CreatedAt:  now,
	}

	// Persist metadata. If this fails we tear the worktree (and branch)
	// down so the next attempt is not blocked by leftover state. The user
	// only sees a successful workspace when its metadata exists too, so
	// later commands can rely on the file being present.
	if err := writeMetadata(aiEnvDir, info); err != nil {
		_ = removeWorktree(sourcePath, wtPath)
		_ = deleteBranch(sourcePath, branch)
		return WorkspaceInfo{}, err
	}

	return info, nil
}

// writeMetadata serializes info to the workspace's .env-meta.json file. It
// is exported via Create's callers (and reused by the copy strategy in
// step 4) so both strategies share a single on-disk schema.
func writeMetadata(aiEnvDir string, info WorkspaceInfo) error {
	meta := envMetadata{
		Name:          info.Name,
		Strategy:      string(info.Strategy),
		Branch:        info.Branch,
		SourcePath:    info.SourcePath,
		WorkspacePath: info.Path,
		CreatedAt:     info.CreatedAt.Format(time.RFC3339),
		Template:      info.Template,
		BaselinePath:  info.BaselinePath,
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("workspace: marshal metadata for %s: %w", info.Name, err)
	}
	// Trailing newline keeps the file POSIX-text-file friendly.
	data = append(data, '\n')

	path := MetadataPath(aiEnvDir, info.Name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("workspace: write metadata %s: %w", path, err)
	}
	return nil
}

// resolveHead returns the full commit SHA that HEAD points at in repoDir.
// We pin the new branch to a commit rather than the symbolic HEAD so the
// branch's starting point cannot shift if the user moves HEAD between the
// resolve call and the worktree add call.
func resolveHead(repoDir string) (string, error) {
	out, err := captureGit(repoDir, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("workspace: resolve HEAD in %s: %w", repoDir, err)
	}
	commit := strings.TrimSpace(out)
	if commit == "" {
		return "", fmt.Errorf("workspace: empty HEAD commit for %s", repoDir)
	}
	return commit, nil
}

// branchExists reports whether refs/heads/<branch> exists in repoDir. It
// uses `git show-ref --verify` because that command's exit code is the
// authoritative answer (0 = exists, non-zero = does not) and its output is
// not needed.
func branchExists(repoDir, branch string) (bool, error) {
	cmd := exec.Command(gitExecutable, "show-ref", "--verify", "--quiet", "refs/heads/"+branch)
	cmd.Dir = repoDir

	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, fmt.Errorf("workspace: check branch %s in %s: %w", branch, repoDir, err)
}

// removeWorktree asks Git to drop the worktree at wtPath. It is used as a
// rollback step when a later operation (metadata write) fails. --force is
// passed because the rollback path may run before Git has a chance to
// register the worktree as clean.
func removeWorktree(repoDir, wtPath string) error {
	if err := runGit(repoDir, "worktree", "remove", "--force", wtPath); err != nil {
		// Fall back to a direct directory removal so we do not leak the
		// path even if git refused (e.g. because it never finished
		// registering the worktree).
		_ = os.RemoveAll(wtPath)
		return err
	}
	return nil
}

// deleteBranch removes the branch ai-env created during a failed run.
// -D (force) is used because the branch was never merged anywhere; the
// goal is rollback, not safety against losing work.
func deleteBranch(repoDir, branch string) error {
	if err := runGit(repoDir, "branch", "-D", branch); err != nil {
		return fmt.Errorf("workspace: delete branch %s in %s: %w", branch, repoDir, err)
	}
	return nil
}

// runGit invokes git in repoDir with args, discarding stdout. stderr is
// captured and folded into the returned error so the caller sees what git
// complained about (e.g. "fatal: not a git repository"). repoDir must be
// non-empty; callers always know which repo they are operating on.
func runGit(repoDir string, args ...string) error {
	cmd := exec.Command(gitExecutable, args...)
	cmd.Dir = repoDir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

// captureGit runs git in repoDir with args and returns its stdout as a
// string. It is the read-equivalent of runGit; the two are kept separate
// so the common case (fire-and-check) does not pay for a stdout buffer.
func captureGit(repoDir string, args ...string) (string, error) {
	cmd := exec.Command(gitExecutable, args...)
	cmd.Dir = repoDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return stdout.String(), nil
}
