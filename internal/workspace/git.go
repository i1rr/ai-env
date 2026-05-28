package workspace

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// gitExecutable is the name of the git binary to invoke. It is a package
// variable (not a const) so tests can override it to point at a stub script
// when needed without touching PATH.
var gitExecutable = "git"

// IsGitRepo reports whether dir lives inside a Git working tree.
//
// It runs `git rev-parse --is-inside-work-tree` with dir as the working
// directory. That command exits 0 and prints "true" when invoked anywhere
// inside a working tree (including subdirectories of the repo root, Git
// worktrees, and submodules). It exits non-zero with a "not a git
// repository" message otherwise.
//
// We treat any non-zero exit as "not a Git repo" and never propagate that
// as an error to the caller; the function returns (false, nil) in that
// case. A non-nil error is reserved for situations the caller actually
// needs to react to: the git binary is missing from PATH, or it returned
// unexpected output we cannot classify.
func IsGitRepo(dir string) (bool, error) {
	if dir == "" {
		return false, errors.New("workspace: IsGitRepo requires a non-empty directory")
	}

	cmd := exec.Command(gitExecutable, "rev-parse", "--is-inside-work-tree")
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		out := strings.TrimSpace(stdout.String())
		switch out {
		case "true":
			return true, nil
		case "false":
			// `--is-inside-work-tree` prints "false" when the caller is
			// inside a bare repo's .git directory. Treat that as
			// "not a usable working tree" for our purposes.
			return false, nil
		default:
			return false, fmt.Errorf("workspace: unexpected git rev-parse output %q for %s", out, dir)
		}
	}

	// exec.ExitError: git ran but returned non-zero. That is the normal
	// "not a Git repository" path; surface it as (false, nil).
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}

	// Anything else (binary missing, permission denied, IO error) is a
	// real failure the caller should know about.
	return false, fmt.Errorf("workspace: run git rev-parse in %s: %w", dir, err)
}
