// Command ai-env is the CLI entry point for managing AI agent sandbox
// environments. This file contains the Cobra skeleton; subcommand
// implementations are added in later plan steps.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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

	return root
}

// newNewCmd returns the stub for `ai-env new`. Implementation lands in
// step 5 of plan 01.
func newNewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new <env-name>",
		Short: "Create a new ai-env environment for the current project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("ai-env new: not yet implemented")
		},
	}
	cmd.Flags().String("from", "", "Source project path (defaults to current directory)")
	cmd.Flags().Bool("force", false, "Overwrite existing .ai-env configuration")
	return cmd
}

// newListCmd returns the stub for `ai-env list`. Implementation lands in
// step 6 of plan 01.
func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List ai-env environments under .ai-env/workspaces/",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("ai-env list: not yet implemented")
		},
	}
}
