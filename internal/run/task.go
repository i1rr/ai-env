package run

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// WriteTask writes the content of the --task flag into the run's
// task.md file. It is the action plan 03 step 3 requires: capture the
// task description so the run directory is a self-contained record of
// what the agent was asked to do.
//
// Inputs:
//   - aiEnvDir is the absolute path to the host's .ai-env/ directory. It
//     is the same value the caller passed to CreateRunDirectory; WriteTask
//     does not assume the process working directory.
//   - runID identifies which run directory to write into. It must match
//     the ID of a previously created RunDirectory; WriteTask does not
//     create the directory itself because the caller already did that.
//   - task is the verbatim --task flag content. The caller is responsible
//     for collecting it from the CLI flag; WriteTask only enforces that
//     it is non-empty (an empty task description is almost certainly a
//     CLI error rather than a legitimate use case, and the plan's
//     example shows --task as carrying meaningful content).
//
// WriteTask overwrites whatever placeholder content CreateRunDirectory
// left in task.md. The placeholder was an empty file by construction,
// so there is nothing to merge with; overwriting keeps the on-disk
// content equal to the task argument byte-for-byte (modulo a single
// trailing newline appended when the task does not already end in one,
// so the file stays POSIX-text-file friendly and `cat` shows a clean
// prompt afterwards).
//
// Returns an error if aiEnvDir or runID is empty, if task is empty, or
// if the write itself fails (for example because the run directory does
// not exist). On error the file is left in whatever state the underlying
// os call left it; the run directory is the caller's responsibility to
// clean up if it wants to.
func WriteTask(aiEnvDir, runID, task string) error {
	if aiEnvDir == "" {
		return errors.New("run: WriteTask requires aiEnvDir")
	}
	if runID == "" {
		return errors.New("run: WriteTask requires runID")
	}
	if strings.TrimSpace(task) == "" {
		return errors.New("run: WriteTask requires a non-empty task description")
	}

	path := TaskPath(aiEnvDir, runID)
	content := normalizeTaskBody(task)
	if err := os.WriteFile(path, []byte(content), runFileMode); err != nil {
		return fmt.Errorf("run: write task.md %s: %w", path, err)
	}
	// WriteFile honours mode only on creation; chmod ensures the mode
	// applies even when the placeholder file is overwritten. The
	// placeholder was created at runFileMode, so this is normally a no-
	// op, but keeping the chmod here means a caller that calls WriteTask
	// against a pre-existing file with a stricter mode still ends up
	// with the documented permission.
	if err := os.Chmod(path, runFileMode); err != nil {
		return fmt.Errorf("run: chmod task.md %s: %w", path, err)
	}
	return nil
}

// normalizeTaskBody returns task with exactly one trailing newline. The
// raw --task flag may or may not end with a newline depending on how the
// shell passed it (a heredoc adds one; a `--task "..."` literal does not).
// Normalizing keeps every run's task.md ending the same way, which makes
// later diff/replay tooling that hashes the file's contents deterministic.
func normalizeTaskBody(task string) string {
	trimmed := strings.TrimRight(task, "\n")
	return trimmed + "\n"
}
