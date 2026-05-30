// Command ai-env is the CLI entry point for managing AI agent sandbox
// environments. This file contains the Cobra skeleton; subcommand
// implementations are added in later plan steps.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rivan1986/ai-env/internal/cli"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		// Cobra already prints the error; just exit non-zero.
		os.Exit(1)
	}
}

// newRootCmd builds the root `ai-env` command and attaches its subcommand
// stubs. Subcommand bodies will be filled in by later steps of plan 01.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "ai-env",
		Short:         "Manage isolated AI agent sandbox environments",
		Long:          "ai-env creates and manages isolated sandbox environments for AI coding agents, keeping their work separate from your active working tree.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	root.AddCommand(newNewCmd())
	root.AddCommand(newListCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newPatchCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newLogsCmd())

	return root
}

// newNewCmd builds the `ai-env new` subcommand. Flag parsing happens here;
// the actual scaffold logic lives in internal/cli so it can be tested
// without involving Cobra.
func newNewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new <env-name>",
		Short: "Create a new ai-env environment for the current project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fromPath, err := cmd.Flags().GetString("from")
			if err != nil {
				return fmt.Errorf("ai-env new: read --from: %w", err)
			}
			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return fmt.Errorf("ai-env new: read --force: %w", err)
			}
			return cli.RunNew(cli.NewOptions{
				EnvName:  args[0],
				FromPath: fromPath,
				Force:    force,
				Stdout:   cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().String("from", "", "Source project path (defaults to current directory)")
	cmd.Flags().Bool("force", false, "Overwrite existing .ai-env configuration")
	return cmd
}

// newListCmd builds the `ai-env list` subcommand. Like `new`, all logic
// lives in internal/cli so it can be exercised without Cobra wiring.
func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List ai-env environments under .ai-env/workspaces/",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunList(cli.ListOptions{
				Stdout: cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
		},
	}
}

// newDiffCmd builds the `ai-env diff` subcommand. Flag parsing happens
// here; the actual diff logic lives in internal/cli so it can be tested
// without involving Cobra.
func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <env-name>",
		Short: "Show changes between an ai-env workspace and its baseline",
		Long: "Show the diff between an ai-env workspace and its baseline. " +
			"For worktree-strategy envs this is the git diff between the env " +
			"branch and the source repo's HEAD; for copy-strategy envs it is " +
			"a file-level diff against the read-only baseline snapshot. " +
			"Protected paths are highlighted in the summary.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			nameOnly, err := cmd.Flags().GetBool("name-only")
			if err != nil {
				return fmt.Errorf("ai-env diff: read --name-only: %w", err)
			}
			return cli.RunDiff(cli.DiffOptions{
				EnvName:  args[0],
				NameOnly: nameOnly,
				Stdout:   cmd.OutOrStdout(),
				Stderr:   cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().Bool("name-only", false, "Print only the per-file summary; suppress the unified-diff body")
	return cmd
}

// newPatchCmd builds the `ai-env patch` subcommand. Flag parsing happens
// here; the actual export logic lives in internal/cli so it can be tested
// without involving Cobra.
func newPatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "patch <env-name> --out <file>",
		Short: "Export an ai-env workspace's changes as a unified-diff patch",
		Long: "Export the diff between an ai-env workspace and its baseline as " +
			"a unified-diff patch file. For worktree-strategy envs this is the " +
			"git diff between the env branch and the source repo's HEAD; for " +
			"copy-strategy envs it is a file-level unified diff against the " +
			"read-only baseline snapshot. Protected-path changes do not block " +
			"export but trigger a warning so reviewers see them.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outPath, err := cmd.Flags().GetString("out")
			if err != nil {
				return fmt.Errorf("ai-env patch: read --out: %w", err)
			}
			return cli.RunPatch(cli.PatchOptions{
				EnvName:    args[0],
				OutputPath: outPath,
				Stdout:     cmd.OutOrStdout(),
				Stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().String("out", "", "Path to write the unified-diff patch to (required)")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

// newStatusCmd builds the `ai-env status` subcommand. Flag parsing
// happens here; the actual report logic lives in internal/cli so it can
// be tested without involving Cobra.
func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status <env-name>",
		Short: "Show the current or last recorded run state for an env",
		Long: "Show the current or last recorded run state for an env. Reads " +
			"run.json (atomic-replace, so concurrent supervisor writes are " +
			"safe) and the lifecycle.jsonl tail for the env's most recent " +
			"run, then prints a stable human-readable report. Use `ai-env " +
			"logs <env-name>` to see captured stdout/stderr.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunStatus(cli.StatusOptions{
				EnvName: args[0],
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}
	return cmd
}

// newLogsCmd builds the `ai-env logs` subcommand. Flag parsing happens
// here; the actual streaming logic lives in internal/cli so it can be
// tested without involving Cobra.
func newLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs <env-name>",
		Short: "Print captured stdout/stderr for an env's latest run",
		Long: "Print captured stdout and/or stderr for an env's latest run, " +
			"or for a specific historical run when --run is given. With " +
			"--follow the command keeps tailing the underlying log files " +
			"until the run reaches a terminal state on disk or the operator " +
			"cancels with SIGINT.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID, err := cmd.Flags().GetString("run")
			if err != nil {
				return fmt.Errorf("ai-env logs: read --run: %w", err)
			}
			streamRaw, err := cmd.Flags().GetString("stream")
			if err != nil {
				return fmt.Errorf("ai-env logs: read --stream: %w", err)
			}
			follow, err := cmd.Flags().GetBool("follow")
			if err != nil {
				return fmt.Errorf("ai-env logs: read --follow: %w", err)
			}
			return cli.RunLogs(cli.LogsOptions{
				EnvName: args[0],
				RunID:   runID,
				Stream:  cli.LogStream(streamRaw),
				Follow:  follow,
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().String("run", "", "Specific run id to display (defaults to the env's latest run)")
	cmd.Flags().String("stream", "both", "Which stream to print: stdout, stderr, or both")
	cmd.Flags().Bool("follow", false, "Keep tailing the log file(s) until the run reaches a terminal state")
	return cmd
}
