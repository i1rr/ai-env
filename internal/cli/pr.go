package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/rivan1986/ai-env/internal/export"
	"github.com/rivan1986/ai-env/internal/githubbroker"
	"github.com/rivan1986/ai-env/internal/scanners"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// PROptions captures the parsed flags + positional argument for
// `ai-env pr`. The CLI wiring layer fills this in and passes it to
// RunPR so the command body has no direct Cobra dependency.
//
// Plan 07 step 10 wires the GitHubBroker into this command and plan 07
// step 11 pins the ExportGate as the gate-keeper that runs before any
// broker action. The flow is:
//
//  1. Resolve env, run record, scan artifacts, policy (loadExportInputs).
//  2. Evaluate ExportGate under ModePR; a blocked verdict short-circuits
//     the command with a non-zero exit and never constructs or invokes
//     the broker (separation of concerns: the broker stays unaware of
//     the gate's verdict).
//  3. If the gate allows and a broker is configured, run the broker
//     lifecycle in the order the plan's "Token lifecycle" diagram pins:
//     Prepare -> AcquireToken -> PushBranch -> ScanMetadata -> verify
//     scan findings do not include a blocker -> CreateDraftPR ->
//     RevokeToken. RevokeToken is always attempted (deferred) so a
//     mid-lifecycle failure still scrubs the credential.
//  4. If the gate allows but no broker is configured, fall back to the
//     preview-only behavior plan 06 step 8 wired (print the verdict and
//     the "broker not configured" notice). This keeps the command
//     usable on a workstation that has not yet provisioned a GitHub
//     App or PAT.
//
// The Broker field is injected (rather than constructed inside RunPR)
// so tests can drive the lifecycle with a fake. Production callers wire
// a CompositeBroker (see internal/githubbroker) from policy.yaml and
// the operator's credentials.
type PROptions struct {
	// EnvName is the positional <env-name> argument identifying which
	// workspace to ship a PR for. It must match the directory under
	// .ai-env/workspaces/ that was created by `ai-env new`.
	EnvName string

	// RunID, when non-empty, pins the export to a specific historical
	// run for the purposes of the gate's scan / quarantine inputs.
	// Defaults to the env's latest run.
	RunID string

	// Draft requests a draft PR. Plan 07 fixes draft-only as the
	// default; the flag is wired so a future non-draft surface can be
	// added without changing the call site, but for v0.1 the CLI
	// defaults to true and only the draft path is implemented.
	Draft bool

	// Cwd is the working directory the command was invoked from. Used
	// to locate the project's .ai-env/ directory.
	Cwd string

	// Broker is the optional GitHubBroker the CLI invokes after the
	// gate allows. A nil Broker keeps the preview-only behavior plan
	// 06 step 8 documented: print the verdict, do not push. Tests
	// inject a fake; production wires a CompositeBroker from policy.
	Broker githubbroker.GitHubBroker

	// Repo identifies the GitHub repository the broker targets. The
	// CLI normally resolves it from the workspace's git remote and
	// policy.yaml; tests pin it directly. Ignored when Broker is nil.
	Repo githubbroker.Repo

	// PRTitle and PRBody are the human-visible PR fields the broker
	// will scan and submit. The CLI wiring layer constructs PRTitle
	// from the run task and PRBody via githubbroker.BuildPRBody (plan
	// 07 step 6) before calling RunPR. Tests pin them directly so the
	// metadata scan path is exercised without re-running the full
	// body builder.
	PRTitle string
	PRBody  string

	// CommitMessages is the list of commit-message bodies the broker
	// will push and submit. Same scan path as PRTitle / PRBody; an
	// empty slice means "no commit messages to scan".
	CommitMessages []string

	Stdout io.Writer
	Stderr io.Writer
}

// RunPR is the entry point used by the Cobra wiring for `ai-env pr`.
//
// Behavior:
//
//   - Block verdict (from ExportGate): print the blocking reasons to
//     stderr and return a non-zero error. The broker is not constructed
//     and not invoked, so a blocked export never touches the GitHub
//     API or acquires a credential.
//   - Allow verdict + nil Broker: print the per-file summary, any gate
//     warnings, and a "broker not configured" notice so the operator
//     knows the gate said yes but no network call was made. This is
//     the plan 06 step 8 stub behavior preserved for development.
//   - Allow verdict + non-nil Broker: run the broker lifecycle. The
//     branch name is derived from workspace.BranchName(envName) so it
//     always carries the "ai-env/" prefix the broker enforces.
//     ScanMetadata findings with BlocksExport=true short-circuit the
//     submission (with the credential still being revoked); a clean
//     scan proceeds to CreateDraftPR. RevokeToken is always attempted
//     via a deferred call.
func RunPR(opts PROptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env pr: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env pr: %w", err)
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env pr: %w", err)
	}

	inputs, err := loadExportInputs(aiEnvDir, opts.EnvName, opts.RunID)
	if err != nil {
		return fmt.Errorf("ai-env pr: %w", err)
	}

	// Plan 07 step 11: the ExportGate runs before any broker action.
	// The gate decides whether the diff is shippable; the broker only
	// learns the answer indirectly (it is constructed and invoked only
	// when the gate says allow). This keeps the broker unaware of the
	// gate's policy logic.
	gate := export.NewExportGate(inputs.Policy)
	verdict := gate.Evaluate(export.Input{
		Mode:            export.ModePR,
		Diff:            inputs.Diff,
		BuiltInResult:   inputs.BuiltInResult,
		ExternalResults: inputs.ExternalResults,
		Policy:          inputs.Policy,
		Record:          inputs.Record,
	})

	if verdict.Blocked() {
		renderGateResult(opts.Stdout, opts.Stderr, "ai-env pr", verdict)
		return fmt.Errorf("ai-env pr: export blocked by %d reason(s); see stderr for details", len(verdict.BlockingReasons()))
	}

	renderPRPreview(opts.Stdout, inputs)
	renderGateResult(opts.Stdout, opts.Stderr, "ai-env pr", verdict)

	// Plan 07 step 10: if no broker is wired, retain the preview-only
	// behavior plan 06 step 8 documented. An operator on a workstation
	// without a configured GitHub App / PAT still gets a useful gate
	// verdict; the broker path lights up once credentials are wired.
	if opts.Broker == nil {
		fmt.Fprintln(opts.Stdout, "")
		fmt.Fprintln(opts.Stdout, "note:      broker not configured; PR push skipped (gate verdict only)")
		return nil
	}

	return runBrokerLifecycle(opts, inputs.Diff)
}

// runBrokerLifecycle executes the broker's Prepare/Acquire/Push/Scan/
// CreateDraftPR/Revoke sequence in the order the plan's "Token
// lifecycle" diagram fixes. It is a separate function so RunPR's gate
// branch stays readable; the lifecycle here is straight-line so a
// reader can map each call back to the plan step.
//
// The function is responsible for ensuring RevokeToken is attempted
// regardless of which mid-lifecycle step fails. AcquireToken's success
// transfers ownership of the credential to the broker's TokenHolder;
// from that point any return path must run RevokeToken (via defer) so
// the credential is scrubbed even when PushBranch or CreateDraftPR
// errors out.
func runBrokerLifecycle(opts PROptions, diff workspace.DiffResult) error {
	branch := workspace.BranchName(opts.EnvName)

	ctx, err := opts.Broker.Prepare(opts.EnvName, branch, opts.Repo)
	if err != nil {
		return fmt.Errorf("ai-env pr: broker prepare: %w", err)
	}

	token, err := opts.Broker.AcquireToken(ctx)
	if err != nil {
		return fmt.Errorf("ai-env pr: broker acquire token: %w", err)
	}
	// Always attempt revocation. The plan documents this as "attempt
	// revocation after PR creation; fail with warning if revocation
	// fails". We log the warning on stderr; the run.json record (wired
	// by a later step) captures the structured outcome.
	defer func() {
		if revokeErr := opts.Broker.RevokeToken(token); revokeErr != nil {
			fmt.Fprintf(opts.Stderr, "ai-env pr: warning: revoke token: %v\n", revokeErr)
		}
	}()

	if err := opts.Broker.PushBranch(ctx, token); err != nil {
		return fmt.Errorf("ai-env pr: broker push branch: %w", err)
	}

	// Plan 07 step 5: scan PR metadata (title, body, branch, commit
	// messages) before submission. A finding with BlocksExport=true is
	// the broker-side analogue of an ExportGate hard block; we refuse
	// to call CreateDraftPR when one is present.
	scan, err := opts.Broker.ScanMetadata(ctx, opts.PRTitle, opts.PRBody, opts.CommitMessages)
	if err != nil {
		return fmt.Errorf("ai-env pr: broker scan metadata: %w", err)
	}
	if blockers := blockingMetadataFindings(scan); len(blockers) > 0 {
		renderMetadataBlockers(opts.Stderr, blockers)
		return fmt.Errorf("ai-env pr: PR metadata scan found %d blocking finding(s); submission refused", len(blockers))
	}

	pr, err := opts.Broker.CreateDraftPR(ctx, token, opts.PRTitle, opts.PRBody)
	if err != nil {
		return fmt.Errorf("ai-env pr: broker create draft PR: %w", err)
	}

	renderPRResult(opts.Stdout, pr, opts.Draft)
	return nil
}

// blockingMetadataFindings filters a ScanResult to the findings that
// would block submission per the Plan 06 BlocksExport contract. The
// helper is exported as an unexported function (rather than inlined) so
// the test that asserts on the refusal path can drive the same filter
// without re-coding it.
func blockingMetadataFindings(res scanners.ScanResult) []scanners.Finding {
	out := make([]scanners.Finding, 0, len(res.Findings))
	for _, f := range res.Findings {
		if f.BlocksExport {
			out = append(out, f)
		}
	}
	return out
}

// renderMetadataBlockers prints the per-finding blocker list to stderr
// in the same shape renderGateResult uses for gate reasons, so the
// operator sees a uniform "blocked because" format whether the blocker
// came from the workspace gate or from the PR metadata scan.
func renderMetadataBlockers(stderr io.Writer, blockers []scanners.Finding) {
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "ai-env pr blocked (PR metadata scan):")
	for _, f := range blockers {
		fmt.Fprintf(stderr, "  - [%s][%s] %s at %s:%d\n", "metadata", f.Pattern, f.Type, f.File, f.Line)
	}
}

// renderPRResult prints the successful PR creation summary. The shape
// is deliberately compact: the PR URL is the load-bearing field for an
// operator who wants to open the PR in a browser; Number and the draft
// indicator round out the line for a script that parses output.
//
// draftRequested is the operator-supplied --draft flag (defaults true
// in the Cobra layer); we echo it alongside the broker-reported
// pr.Draft so a future non-draft surface can show "requested non-draft
// but broker fixed draft-only" without changing the call site.
func renderPRResult(stdout io.Writer, pr githubbroker.PRResult, draftRequested bool) {
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "ai-env pr created:")
	if pr.Number > 0 {
		fmt.Fprintf(stdout, "  number:  #%d\n", pr.Number)
	}
	if pr.URL != "" {
		fmt.Fprintf(stdout, "  url:     %s\n", pr.URL)
	}
	fmt.Fprintf(stdout, "  draft:   %t (requested %t)\n", pr.Draft, draftRequested)
}

// renderPRPreview prints the per-file preview an operator sees when
// the gate allows a PR. The shape mirrors renderPatchResult so the two
// commands feel uniform; the difference is that no patch file is
// emitted, just the summary.
func renderPRPreview(stdout io.Writer, inputs exportInputs) {
	diff := inputs.Diff
	fmt.Fprintf(stdout, "env:       %s\n", diff.Name)
	fmt.Fprintf(stdout, "strategy:  %s\n", diff.Strategy)
	if inputs.RunID != "" {
		fmt.Fprintf(stdout, "run id:    %s\n", inputs.RunID)
	}
	if len(diff.Files) == 0 {
		fmt.Fprintln(stdout, "files:     (no changes)")
		return
	}
	fmt.Fprintf(stdout, "files:     %d changed\n", len(diff.Files))
	for _, f := range diff.Files {
		marker := ""
		if f.Protected {
			marker = "  [protected]"
		}
		fmt.Fprintf(stdout, "  %s  %s%s\n", changeKindGlyph(f.Change), f.Path, marker)
	}
}

