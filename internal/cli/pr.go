package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/i1rr/ai-env/internal/export"
	"github.com/i1rr/ai-env/internal/githubbroker"
	"github.com/i1rr/ai-env/internal/run"
	"github.com/i1rr/ai-env/internal/scanners"
	"github.com/i1rr/ai-env/internal/workspace"
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

	// Plan 07 step 12: open the per-run policy-decisions writer so
	// every gate verdict and broker stage outcome lands in
	// policy-decisions.jsonl. The writer is run-scoped, so we only
	// open it when a run directory has been located (loadExportInputs
	// populates inputs.RunPath on success). An ad-hoc export off a
	// workspace that has never been run carries no run dir; the
	// decisions are still rendered to the operator via the CLI but
	// have no on-disk home, so the writer stays nil.
	pdw := openPolicyDecisionsWriter(inputs.RunPath, inputs.RunID, opts.Stderr)
	if pdw != nil {
		defer func() {
			if closeErr := pdw.Close(); closeErr != nil {
				fmt.Fprintf(opts.Stderr, "ai-env pr: warning: close policy decisions log: %v\n", closeErr)
			}
		}()
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

	// Plan 07 step 12: record the gate verdict regardless of whether
	// it allowed or blocked. A blocked verdict is the explicit reason
	// the broker never ran; recording it makes the on-disk file the
	// single audit trail for "why did this run not produce a PR".
	emitPolicyDecision(pdw, gateDecisionEvent("pr", opts.EnvName, verdict), opts.Stderr)

	if verdict.Blocked() {
		renderGateResult(opts.Stdout, opts.Stderr, "ai-env pr", verdict)
		return fmt.Errorf("ai-env pr: export blocked by %d reason(s); see stderr for details", len(verdict.BlockingReasons()))
	}

	renderPRPreview(opts.Stdout, inputs)
	renderGateResult(opts.Stdout, opts.Stderr, "ai-env pr", verdict)

	// Plan iter-4 Batch 4.3: build the real broker from the workspace's
	// secrets.local.yaml + origin pin when the caller did not inject one.
	// resolveBroker returns (nil, nil) when no credentials are configured
	// (the documented preview-only fallback) and propagates errors
	// (ErrPinNotFound, ErrOriginDrift, ErrInvalidOrigin) verbatim so the
	// CLI fails closed on a misconfigured workspace rather than silently
	// pushing against an unverified remote.
	setup, err := resolveBroker(opts, aiEnvDir, inputs.Policy)
	if err != nil {
		return fmt.Errorf("ai-env pr: %w", err)
	}
	if setup == nil {
		// Plan 07 step 10: if no broker is wired, retain the preview-only
		// behavior plan 06 step 8 documented. An operator on a workstation
		// without a configured GitHub App / PAT still gets a useful gate
		// verdict; the broker path lights up once credentials are wired.
		fmt.Fprintln(opts.Stdout, "")
		fmt.Fprintln(opts.Stdout, "note:      broker not configured; PR push skipped (gate verdict only)")
		return nil
	}

	// Thread the resolved broker + repo back through PROptions so the
	// existing lifecycle helper stays unchanged. Pinning the values on
	// the local options copy (rather than mutating the caller's struct)
	// preserves the test-injection contract: opts.Broker the caller
	// passed in is the same broker runBrokerLifecycle drives.
	opts.Broker = setup.Broker
	opts.Repo = setup.Repo

	// When the broker was constructed inside RunPR (not test-injected),
	// arrange a Close() at exit so the TokenHolder's slots and any
	// PATSource cached bytes are scrubbed on the way out — Close is
	// safe to call on any *githubbroker.Broker including a fake.
	if concrete, ok := setup.Broker.(*githubbroker.Broker); ok {
		defer concrete.Close()
	}

	return runBrokerLifecycle(opts, inputs.Diff, pdw)
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
func runBrokerLifecycle(opts PROptions, diff workspace.DiffResult, pdw *run.PolicyDecisionsWriter) error {
	branch := workspace.BranchName(opts.EnvName)

	ctx, err := opts.Broker.Prepare(opts.EnvName, branch, opts.Repo)
	if err != nil {
		// Plan 07 step 12: Prepare validates branch prefix and
		// protected paths. Distinguish a policy refusal (which
		// surfaces as one of the broker's sentinel errors) from an
		// infrastructure failure so the on-disk record reflects the
		// right verdict.
		emitPolicyDecision(pdw, brokerActionEvent(
			run.PolicyActionBrokerPrepare,
			classifyBrokerErr(err),
			opts.EnvName, branch, opts.Repo.Owner, opts.Repo.Name,
			err.Error(), nil,
		), opts.Stderr)
		return fmt.Errorf("ai-env pr: broker prepare: %w", err)
	}

	token, err := opts.Broker.AcquireToken(ctx)
	if err != nil {
		emitPolicyDecision(pdw, brokerActionEvent(
			run.PolicyActionBrokerAcquireToken,
			run.PolicyDecisionFail,
			opts.EnvName, branch, opts.Repo.Owner, opts.Repo.Name,
			err.Error(), nil,
		), opts.Stderr)
		return fmt.Errorf("ai-env pr: broker acquire token: %w", err)
	}
	// Always attempt revocation. The plan documents this as "attempt
	// revocation after PR creation; fail with warning if revocation
	// fails". We log the warning on stderr; the run.json record (wired
	// by a later step) captures the structured outcome.
	defer func() {
		if revokeErr := opts.Broker.RevokeToken(token); revokeErr != nil {
			fmt.Fprintf(opts.Stderr, "ai-env pr: warning: revoke token: %v\n", revokeErr)
			emitPolicyDecision(pdw, brokerActionEvent(
				run.PolicyActionBrokerRevokeToken,
				run.PolicyDecisionFail,
				opts.EnvName, branch, opts.Repo.Owner, opts.Repo.Name,
				revokeErr.Error(), nil,
			), opts.Stderr)
			return
		}
		revokeEvt := brokerActionEvent(
			run.PolicyActionBrokerRevokeToken,
			run.PolicyDecisionAllow,
			opts.EnvName, branch, opts.Repo.Owner, opts.Repo.Name,
			"", nil,
		)
		revokeEvt.TokenKind = string(token.Kind)
		emitPolicyDecision(pdw, revokeEvt, opts.Stderr)
	}()

	if err := opts.Broker.PushBranch(ctx, token); err != nil {
		emitPolicyDecision(pdw, brokerActionEvent(
			run.PolicyActionBrokerPushBranch,
			classifyBrokerErr(err),
			opts.EnvName, branch, opts.Repo.Owner, opts.Repo.Name,
			err.Error(), nil,
		), opts.Stderr)
		return fmt.Errorf("ai-env pr: broker push branch: %w", err)
	}

	// Plan 07 step 5: scan PR metadata (title, body, branch, commit
	// messages) before submission. A finding with BlocksExport=true is
	// the broker-side analogue of an ExportGate hard block; we refuse
	// to call CreateDraftPR when one is present.
	scan, err := opts.Broker.ScanMetadata(ctx, opts.PRTitle, opts.PRBody, opts.CommitMessages)
	if err != nil {
		emitPolicyDecision(pdw, brokerActionEvent(
			run.PolicyActionBrokerScanMetadata,
			run.PolicyDecisionFail,
			opts.EnvName, branch, opts.Repo.Owner, opts.Repo.Name,
			err.Error(), nil,
		), opts.Stderr)
		return fmt.Errorf("ai-env pr: broker scan metadata: %w", err)
	}
	if blockers := blockingMetadataFindings(scan); len(blockers) > 0 {
		renderMetadataBlockers(opts.Stderr, blockers)
		emitPolicyDecision(pdw, brokerMetadataScanBlockEvent(
			opts.EnvName, branch, opts.Repo.Owner, opts.Repo.Name,
			blockers, token.Kind,
		), opts.Stderr)
		return fmt.Errorf("ai-env pr: PR metadata scan found %d blocking finding(s); submission refused", len(blockers))
	}

	pr, err := opts.Broker.CreateDraftPR(ctx, token, opts.PRTitle, opts.PRBody)
	if err != nil {
		emitPolicyDecision(pdw, brokerActionEvent(
			run.PolicyActionBrokerCreatePR,
			run.PolicyDecisionFail,
			opts.EnvName, branch, opts.Repo.Owner, opts.Repo.Name,
			err.Error(), nil,
		), opts.Stderr)
		return fmt.Errorf("ai-env pr: broker create draft PR: %w", err)
	}

	emitPolicyDecision(pdw, brokerCreatePREvent(
		opts.EnvName, branch, opts.Repo.Owner, opts.Repo.Name,
		pr, token.Kind,
	), opts.Stderr)

	renderPRResult(opts.Stdout, pr, opts.Draft)
	return nil
}

// classifyBrokerErr maps a broker-returned error to the decision string
// recorded on a policy decision event. A wrap of one of the broker's
// sentinel errors (branch prefix, protected branch, protected path,
// token expired, token revoked) is a policy refusal ("block"); any
// other error is treated as an infrastructure failure ("fail").
//
// This distinction matters to an operator reading
// policy-decisions.jsonl: a "block" means "your inputs violated a
// policy rule; fix the inputs" while a "fail" means "the broker could
// not complete the request; retry or check connectivity".
func classifyBrokerErr(err error) string {
	if err == nil {
		return run.PolicyDecisionAllow
	}
	switch {
	case errors.Is(err, githubbroker.ErrInvalidBranchPrefix),
		errors.Is(err, githubbroker.ErrProtectedBranch),
		errors.Is(err, githubbroker.ErrProtectedPath),
		errors.Is(err, githubbroker.ErrTokenExpired),
		errors.Is(err, githubbroker.ErrTokenRevoked):
		return run.PolicyDecisionBlock
	}
	return run.PolicyDecisionFail
}

// openPolicyDecisionsWriter constructs a run.PolicyDecisionsWriter for
// the given run dir, or returns nil when no run dir is available. A nil
// writer is a no-op at every call site (emitPolicyDecision below
// tolerates it) so the CLI can run uniformly on an ad-hoc workspace
// that has never been through the supervisor.
//
// Errors from the underlying file open are surfaced as a warning on
// stderr rather than aborting the export: the gate verdict is the
// load-bearing output of `ai-env pr`, and losing the on-disk log
// should not block the user from learning whether their PR shipped.
func openPolicyDecisionsWriter(runPath, runID string, stderr io.Writer) *run.PolicyDecisionsWriter {
	if runPath == "" || runID == "" {
		return nil
	}
	w, err := run.OpenPolicyDecisionsWriter(runPath, run.PolicyDecisionsWriterOptions{
		RunID: runID,
	})
	if err != nil {
		fmt.Fprintf(stderr, "ai-env pr: warning: open policy decisions log: %v\n", err)
		return nil
	}
	return w
}

// emitPolicyDecision writes evt to pdw, tolerating a nil writer (no-op)
// and surfacing a write error as a stderr warning. The export path
// must not abort because the audit log dropped an event; the warning
// makes the failure visible without breaking the user's flow.
func emitPolicyDecision(pdw *run.PolicyDecisionsWriter, evt run.PolicyDecisionEvent, stderr io.Writer) {
	if pdw == nil {
		return
	}
	if err := pdw.Write(evt); err != nil {
		fmt.Fprintf(stderr, "ai-env pr: warning: write policy decision: %v\n", err)
	}
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
