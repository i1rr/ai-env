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
	root.AddCommand(newPRCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newLogsCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newAgentsCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newPolicyCmd())
	root.AddCommand(newDestroyCmd())

	return root
}

// newPolicyCmd builds the `ai-env policy` parent command and attaches
// its subcommands (init, check, explain, allow, deny). The parent has
// no body of its own; running it prints the standard Cobra help so
// operators can discover the subcommands via `ai-env policy -h` (plan
// 08 steps 3-6).
func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect and mutate the project's policy.yaml",
		Long: "Inspect and mutate the project's .ai-env/policy.yaml document. " +
			"Use `init` to scaffold a default policy, `check <env-name>` to " +
			"print the effective summary, `explain <env-name> --event <id>` " +
			"to look up a recorded policy decision from the run trail, and " +
			"`allow|deny domain|tool <env-name> <value>` to grant or refuse " +
			"a specific domain (network.allow_domains) or tool / command " +
			"pattern (commands.deny_patterns).",
	}
	cmd.AddCommand(newPolicyInitCmd())
	cmd.AddCommand(newPolicyCheckCmd())
	cmd.AddCommand(newPolicyExplainCmd())
	cmd.AddCommand(newPolicyAllowCmd())
	cmd.AddCommand(newPolicyDenyCmd())
	return cmd
}

// newPolicyInitCmd builds `ai-env policy init`. The body lives in
// internal/cli.RunPolicyInit; the Cobra layer is a thin pass-through.
func newPolicyInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold a default .ai-env/policy.yaml for the current project",
		Long: "Write a conservative default policy.yaml into the current " +
			"project's .ai-env/ directory. Refuses to overwrite an existing " +
			"file unless --force is passed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return fmt.Errorf("ai-env policy init: read --force: %w", err)
			}
			return cli.RunPolicyInit(cli.PolicyInitOptions{
				Force:  force,
				Stdout: cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().Bool("force", false, "Overwrite an existing .ai-env/policy.yaml")
	return cmd
}

// newPolicyCheckCmd builds `ai-env policy check <env-name>`.
func newPolicyCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check <env-name>",
		Short: "Print the effective policy.yaml summary for an env",
		Long: "Print a human-readable summary of the project's policy.yaml " +
			"and any structural warnings (missing required fields, " +
			"permissive defaults). The <env-name> argument identifies which " +
			"env the audit context applies to; v0.1 stores one policy.yaml " +
			"per project so the summary itself is project-wide.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunPolicyCheck(cli.PolicyCheckOptions{
				EnvName: args[0],
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}
	return cmd
}

// newPolicyExplainCmd builds `ai-env policy explain <env-name> --event <id>`.
func newPolicyExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <env-name> --event <event-id>",
		Short: "Look up a recorded policy decision from the env's run trail",
		Long: "Look up one record from the env's policy-decisions.jsonl " +
			"trail and render its fields (event id, action, decision, " +
			"reason, metadata, etc.) plus the raw JSON envelope so a " +
			"downstream consumer can pipe the output into jq. The lookup " +
			"matches the engine's `evt_<ts>_<hex>` id first and falls back " +
			"to the Action / Event verb so the operator can also ask for " +
			"e.g. `broker_push_branch`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eventID, err := cmd.Flags().GetString("event")
			if err != nil {
				return fmt.Errorf("ai-env policy explain: read --event: %w", err)
			}
			runID, err := cmd.Flags().GetString("run")
			if err != nil {
				return fmt.Errorf("ai-env policy explain: read --run: %w", err)
			}
			return cli.RunPolicyExplain(cli.PolicyExplainOptions{
				EnvName: args[0],
				EventID: eventID,
				RunID:   runID,
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().String("event", "", "Event id to look up (the engine's evt_<ts>_<hex> id, or an Action/Event verb)")
	cmd.Flags().String("run", "", "Specific run id whose trail to search (defaults to the env's latest run)")
	_ = cmd.MarkFlagRequired("event")
	return cmd
}

// newPolicyAllowCmd builds `ai-env policy allow domain|tool <env-name> <value>`.
func newPolicyAllowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "allow domain|tool <env-name> <value>",
		Short: "Grant a domain or tool pattern in policy.yaml",
		Long: "Mutate policy.yaml to grant a domain or tool pattern. " +
			"`allow domain <name>` appends <name> to network.allow_domains; " +
			"`allow tool <pattern>` removes <pattern> from " +
			"commands.deny_patterns (v0.1 has no per-tool allow list, so " +
			"allowing a tool means clearing its deny entry). A no-op " +
			"mutation exits 0 with a notice on stderr.",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunPolicyMutate(cli.PolicyMutateOptions{
				Action:  cli.PolicyMutateAllow,
				Kind:    cli.PolicyMutateKind(args[0]),
				EnvName: args[1],
				Value:   args[2],
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}
	return cmd
}

// newPolicyDenyCmd builds `ai-env policy deny domain|tool <env-name> <value>`.
func newPolicyDenyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deny domain|tool <env-name> <value>",
		Short: "Refuse a domain or tool pattern in policy.yaml",
		Long: "Mutate policy.yaml to refuse a domain or tool pattern. " +
			"`deny domain <name>` removes <name> from network.allow_domains " +
			"(under network.default=deny the absence is itself the deny); " +
			"`deny tool <pattern>` appends <pattern> to commands.deny_patterns. " +
			"A no-op mutation exits 0 with a notice on stderr.",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunPolicyMutate(cli.PolicyMutateOptions{
				Action:  cli.PolicyMutateDeny,
				Kind:    cli.PolicyMutateKind(args[0]),
				EnvName: args[1],
				Value:   args[2],
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}
	return cmd
}

// newScanCmd builds the `ai-env scan` subcommand. Flag parsing happens
// here; the actual scan logic lives in internal/cli so it can be
// exercised without Cobra wiring. The command runs the built-in
// pattern-only secret scanner plus every available optional external
// scanner against the env's workspace, writes secret-scan.json and
// dependency-report.json to the env's latest run directory, and prints
// a summary (plan 06 step 6).
func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan <env-name>",
		Short: "Scan an env's workspace for secrets and dependency issues",
		Long: "Scan an env's workspace for secrets and dependency issues. " +
			"Runs the built-in pattern-only secret scanner plus every available " +
			"optional external scanner (gitleaks, osv-scanner, trivy, semgrep, " +
			"npm-audit, pip-audit, cargo-audit, govulncheck). Writes " +
			"secret-scan.json and dependency-report.json into the env's run " +
			"directory and prints a summary. Missing optional scanners produce " +
			"warnings, not crashes.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID, err := cmd.Flags().GetString("run")
			if err != nil {
				return fmt.Errorf("ai-env scan: read --run: %w", err)
			}
			return cli.RunScan(cli.ScanOptions{
				EnvName: args[0],
				RunID:   runID,
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().String("run", "", "Specific run id to write scan artifacts into (defaults to the env's latest run)")
	return cmd
}

// newReportCmd builds the `ai-env report` subcommand. Flag parsing
// happens here; the report logic lives in internal/cli so it can be
// exercised without Cobra wiring. The command surfaces the network
// summary alongside the run handle so an operator who tails a run
// landing terminal can audit policy outcome + per-destination
// decisions without parsing JSONL by hand (plan 05 task 7 / task 12).
func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report <env-name>",
		Short: "Print a run report including the network summary",
		Long: "Print a run report for an env, summarizing the run's state, " +
			"timing, and the network policy outcome (allowed / denied " +
			"counts, top destinations). Reads network-events.jsonl and " +
			"folds it into the same summary the supervisor writes into " +
			"final-summary.md, so the two views agree.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID, err := cmd.Flags().GetString("run")
			if err != nil {
				return fmt.Errorf("ai-env report: read --run: %w", err)
			}
			return cli.RunReport(cli.ReportOptions{
				EnvName: args[0],
				RunID:   runID,
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().String("run", "", "Specific run id to report on (defaults to the env's latest run)")
	return cmd
}

// newAgentsCmd builds the `ai-env agents` parent command and attaches
// its three subcommands (list, doctor, probe). The parent has no body
// of its own; running it prints the standard Cobra help so operators
// can discover the subcommands via `ai-env agents -h`.
func newAgentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agents",
		Short: "Inspect registered agent CLIs and their health",
		Long: "Inspect the agent launchers ai-env knows about. " +
			"Use `list` for a one-line-per-agent table, `doctor` for a " +
			"pass/fail health report covering binary, version, " +
			"autonomous flags, and credential mode, and `probe <agent>` " +
			"for a detailed report including the captured --help output.",
	}
	cmd.AddCommand(newAgentsListCmd())
	cmd.AddCommand(newAgentsDoctorCmd())
	cmd.AddCommand(newAgentsProbeCmd())
	return cmd
}

// newAgentsListCmd builds the `ai-env agents list` subcommand. Flag
// parsing happens here; the actual table logic lives in internal/cli
// so it can be tested without involving Cobra.
func newAgentsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered agent launchers and detected versions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunAgentsList(cli.AgentsListOptions{
				Stdout: cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
		},
	}
}

// newAgentsDoctorCmd builds the `ai-env agents doctor` subcommand. It
// runs the same probes the supervisor uses and prints PASS/FAIL per
// check. Exits non-zero when any check fails so it is CI-friendly.
func newAgentsDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run health checks for every registered agent launcher",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunAgentsDoctor(cli.AgentsDoctorOptions{
				Stdout: cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
		},
	}
}

// newAgentsProbeCmd builds the `ai-env agents probe <agent>`
// subcommand. The probe runs the full Probe pipeline for one agent and
// prints the discovered version, selected autonomous flags, and the
// first lines of the captured --help output.
func newAgentsProbeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "probe <agent>",
		Short: "Probe a single agent CLI (version, autonomous flags, --help)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunAgentsProbe(cli.AgentsProbeOptions{
				AgentName: args[0],
				Stdout:    cmd.OutOrStdout(),
				Stderr:    cmd.ErrOrStderr(),
			})
		},
	}
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
			"export but trigger a warning so reviewers see them. The export " +
			"gate (plan 06) is consulted before the patch is written; a hard " +
			"blocker (e.g. a high-confidence secret leak) refuses the export.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outPath, err := cmd.Flags().GetString("out")
			if err != nil {
				return fmt.Errorf("ai-env patch: read --out: %w", err)
			}
			runID, err := cmd.Flags().GetString("run")
			if err != nil {
				return fmt.Errorf("ai-env patch: read --run: %w", err)
			}
			return cli.RunPatch(cli.PatchOptions{
				EnvName:    args[0],
				OutputPath: outPath,
				RunID:      runID,
				Stdout:     cmd.OutOrStdout(),
				Stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().String("out", "", "Path to write the unified-diff patch to (required)")
	cmd.Flags().String("run", "", "Specific run id whose scan / record the export gate consults (defaults to the env's latest run)")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

// newPRCmd builds the `ai-env pr` subcommand. Flag parsing happens here;
// the actual export logic lives in internal/cli so it can be tested
// without involving Cobra.
//
// Plan 07 step 10 wires the GitHubBroker into this command and plan 07
// step 11 keeps the ExportGate as the gate-keeper that runs before any
// broker action. The Cobra layer is intentionally thin: it parses
// --run and --draft, delegates to cli.RunPR, and leaves the lifecycle
// (gate -> broker prepare -> token -> push -> scan -> create PR ->
// revoke) to the internal package so the same flow is unit-testable
// without standing up Cobra.
//
// --draft defaults to true because plan 07 fixes draft-only as the
// v0.1 surface. The flag exists so a future operator opt-in for
// non-draft PRs can be added without changing the call site; for now
// passing --draft=false is accepted but the broker still opens a
// draft PR.
func newPRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pr <env-name> [--draft]",
		Short: "Open a brokered draft PR for an ai-env workspace",
		Long: "Open a brokered draft pull request for an ai-env workspace. " +
			"The export gate is evaluated first under ModePR: all hard " +
			"blockers (secret leaks, workflow changes, .ai-env modifications, " +
			"quarantine) refuse the export with a non-zero exit and the " +
			"broker is never invoked. If the gate allows, the GitHubBroker " +
			"prepares the PR (validating branch prefix and protected paths), " +
			"acquires a short-lived credential, pushes the workspace branch, " +
			"scans the PR metadata (title, body, branch, commit messages), " +
			"creates a draft PR, and revokes the credential. When no broker " +
			"is configured (no GitHub App or PAT fallback wired) the " +
			"command falls back to a preview-only verdict so an operator " +
			"can still inspect the gate decision locally.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID, err := cmd.Flags().GetString("run")
			if err != nil {
				return fmt.Errorf("ai-env pr: read --run: %w", err)
			}
			draft, err := cmd.Flags().GetBool("draft")
			if err != nil {
				return fmt.Errorf("ai-env pr: read --draft: %w", err)
			}
			return cli.RunPR(cli.PROptions{
				EnvName: args[0],
				RunID:   runID,
				Draft:   draft,
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().String("run", "", "Specific run id whose scan / record the export gate consults (defaults to the env's latest run)")
	cmd.Flags().Bool("draft", true, "Open the PR as a draft (default true; plan 07 fixes draft-only for v0.1)")
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

// newDestroyCmd builds the `ai-env destroy <env-name>` subcommand. Flag
// parsing happens here; the actual reclamation logic lives in
// internal/cli so it can be tested without involving Cobra.
//
// Destroy is the inverse of `ai-env new`: it removes the workspace
// directory under .ai-env/workspaces/<env-name>/, the read-only baseline
// snapshot under .ai-env/baselines/<env-name>/ (copy strategy only),
// and the per-env worktree branch ai-env/<env-name> from the source
// repo (worktree strategy only). Running it twice is a no-op: the
// second run prints an "already absent" notice on stderr and exits 0
// so the command is safe to put in cleanup scripts.
func newDestroyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "destroy <env-name>",
		Short: "Remove an ai-env environment's on-disk resources",
		Long: "Remove an ai-env environment's on-disk resources. The " +
			"workspace directory under .ai-env/workspaces/<env-name>/ is " +
			"reclaimed in every case; for copy-strategy envs the " +
			"read-only baseline at .ai-env/baselines/<env-name>/ is also " +
			"reclaimed, and for worktree-strategy envs the per-env " +
			"branch ai-env/<env-name> is deleted from the source repo. " +
			"Running destroy twice is a no-op: the second invocation " +
			"prints an 'already absent' notice and exits 0.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunDestroy(cli.DestroyOptions{
				EnvName: args[0],
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}
}
