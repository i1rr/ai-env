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
