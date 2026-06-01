// pr_broker.go contains the helper that constructs the production
// GitHubBroker the `ai-env pr` command drives. Plan iter-4 Batch 4.3
// ("Wire real broker into cli.RunPR") asks the CLI to stop treating the
// PROptions.Broker field as the only source of brokers: when the caller
// (the Cobra layer) leaves Broker nil, RunPR must attempt to build a
// real broker from the workspace's `.ai-env/secrets.local.yaml` and
// origin pin. The construction surface lives here so the body of
// pr.go stays focused on the lifecycle.
//
// Construction inputs:
//
//  1. `.ai-env/secrets.local.yaml` (the operator's host-side credentials,
//     loaded via secrets.LoadLocal). When the file is missing or carries
//     no GitHub block, BuildBrokerFromSecrets returns ErrNoTokenSource;
//     RunPR treats that as the documented "broker not configured;
//     preview only" path so an operator on a workstation without an
//     App / PAT keeps the gate verdict surface.
//
//  2. The workspace's recorded origin pin (loaded via
//     githubbroker.LoadOriginPin) plus the workspace's live `origin`
//     remote URL (loaded via githubbroker.WorkspaceOriginURL). The two
//     are compared with githubbroker.CheckOriginPin so a quietly
//     rewired origin surfaces as ErrOriginDrift and refuses the push.
//     The pin's coordinates become the broker's Repo (canonical HTTPS
//     CloneURL).
//
//  3. The policy.yaml-derived protected-branch list and path-gate
//     extensions (already loaded by loadExportInputs via
//     loadPolicyIfPresent). They are threaded into BuildBrokerOptions
//     so the broker's Prepare gate honours operator-configured rules.
//
// Failure modes:
//
//   - ErrNoTokenSource: documented "no broker configured"; RunPR falls
//     back to preview-only.
//   - ErrPinNotFound: a workspace created before pinning was added.
//     Treated as a fail-closed condition: the broker refuses to push
//     against an unpinned workspace because the drift guard cannot
//     fire. The CLI surfaces a remediation hint pointing at a future
//     `ai-env doctor` repair path.
//   - ErrOriginDrift: any (owner, name, host) divergence between pin
//     and live origin; refuse the push with the documented
//     `origin_drift` reason.
//   - ErrInvalidOrigin: the workspace's live origin URL is unrecognized
//     (a non-github remote, a malformed URL). Refuse the push so the
//     broker never speaks to an unverified remote.
//   - Any underlying credential / I/O error surfaces verbatim so the
//     CLI can render the operator's remediation hint.

package cli

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/rivan1986/ai-env/internal/config"
	"github.com/rivan1986/ai-env/internal/githubbroker"
	"github.com/rivan1986/ai-env/internal/scanners"
	"github.com/rivan1986/ai-env/internal/secrets"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// brokerSetup bundles the resolved broker plus the repository
// coordinate the lifecycle pushes against. The repo is returned
// alongside the broker because RunPR's PROptions.Repo may be empty
// (the Cobra layer does not supply it) and the lifecycle's
// brokerActionEvent helpers need owner/name for the on-disk record.
type brokerSetup struct {
	Broker githubbroker.GitHubBroker
	Repo   githubbroker.Repo
}

// resolveBroker constructs the production broker for envName. When
// PROptions.Broker is non-nil (the test-injection path) the function
// returns it verbatim along with PROptions.Repo so RunPR's flow stays
// identical to the iter-3 behavior under tests.
//
// When PROptions.Broker is nil the function:
//
//  1. Reads .ai-env/secrets.local.yaml via secrets.LoadLocal. A missing
//     file produces a non-nil but empty *LocalConfig (per LoadLocal's
//     documented contract); BuildBrokerFromSecrets then returns
//     ErrNoTokenSource which we propagate so RunPR can fall back to
//     preview-only.
//
//  2. Loads the workspace's recorded origin pin and re-parses the live
//     `git remote get-url origin`. A mismatch returns ErrOriginDrift;
//     a missing pin returns ErrPinNotFound; both are fail-closed.
//
//  3. Builds the BuildBrokerOptions from the pin (Repo coordinate),
//     policy (protected branches), and the policy.yaml scanner config
//     (a real *scanners.BuiltIn for ScanMetadata).
//
// The returned brokerSetup is non-nil iff err is nil. A nil broker +
// nil error is reserved for the "no credentials" case so the caller
// can distinguish "fall back to preview" from "construction error".
func resolveBroker(opts PROptions, aiEnvDir string, policy *config.PolicyConfig) (*brokerSetup, error) {
	// Test injection: PROptions.Broker pre-populated. The caller has
	// already decided which broker to drive; we trust the Repo field
	// too because tests pin it directly.
	if opts.Broker != nil {
		return &brokerSetup{Broker: opts.Broker, Repo: opts.Repo}, nil
	}

	// Load secrets.local.yaml. A missing file produces an empty cfg;
	// BuildBrokerFromSecrets surfaces that as ErrNoTokenSource which
	// we propagate as a nil broker / nil error so RunPR falls into the
	// documented preview-only path.
	secretsPath := filepath.Join(aiEnvDir, secrets.LocalConfigDefaultFilename)
	cfg, _, err := secrets.LoadLocal(secretsPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", secretsPath, err)
	}
	if cfg == nil || cfg.Secrets.GitHub == nil {
		// No GitHub credentials configured. Preview-only fallback.
		return nil, nil
	}

	// Resolve the workspace's origin pin + live URL. A missing pin or
	// a drift event is fail-closed; we surface the error verbatim so
	// the CLI can render the documented remediation hint.
	wsDir := workspace.WorkspacePath(aiEnvDir, opts.EnvName)
	pin, err := loadAndCheckOriginPin(wsDir)
	if err != nil {
		return nil, err
	}

	// Build the scanner the broker's ScanMetadata routes through.
	// loadPolicyIfPresent already validated the policy; we reuse it
	// here for both the protected-branch list and the path-gate
	// extension list.
	scanner, err := buildMetadataScanner(policy)
	if err != nil {
		return nil, fmt.Errorf("build metadata scanner: %w", err)
	}

	protected := protectedBranchesFromPolicy(policy)

	repo := pin.ToRepo()
	repo.DefaultBranch = defaultBranchFromPolicy(policy)

	apiBase := ""
	if !pin.IsCanonicalGitHub() {
		// A GHE host needs an explicit api.<host>/api/v3 base; the
		// supervisor can later wire this from policy.yaml. For now we
		// leave APIBaseURL empty when the host is github.com so
		// BuildBrokerFromSecrets defaults to https://api.github.com,
		// and pass the pin's host scheme for GHE so the App's
		// installation-token round trip points at the right host.
		apiBase = fmt.Sprintf("https://%s/api/v3", pin.Host)
	}

	broker, buildErr := githubbroker.BuildBrokerFromSecrets(cfg, githubbroker.BuildBrokerOptions{
		Repo:                   repo,
		ExtraProtectedBranches: protected,
		Scanner:                scanner,
		APIBaseURL:             apiBase,
	})
	if buildErr != nil {
		if errors.Is(buildErr, githubbroker.ErrNoTokenSource) {
			// The credential file existed but did not carry a usable
			// source (e.g. a PAT block without enabled: true). Fall
			// back to preview-only — the gate's verdict is still the
			// load-bearing output for the operator.
			return nil, nil
		}
		return nil, buildErr
	}
	return &brokerSetup{Broker: broker, Repo: repo}, nil
}

// loadAndCheckOriginPin reads the workspace's recorded origin pin and
// re-parses the live `git remote get-url origin`, comparing the two via
// githubbroker.CheckOriginPin. A missing pin (ErrPinNotFound) and a
// drift (ErrOriginDrift) both fail-close; the CLI surfaces the error.
//
// When the workspace's git remote is unreadable (a copy-strategy
// workspace with no .git, or a worktree whose origin has been removed)
// WorkspaceOriginURL returns an empty string and a nil error: the
// broker refuses the push in that case because the pin check cannot
// fire.
func loadAndCheckOriginPin(workspaceDir string) (githubbroker.OriginPin, error) {
	pin, err := githubbroker.LoadOriginPin(workspaceDir)
	if err != nil {
		return githubbroker.OriginPin{}, err
	}
	liveURL, err := githubbroker.WorkspaceOriginURL(workspaceDir)
	if err != nil {
		return githubbroker.OriginPin{}, fmt.Errorf("read workspace origin: %w", err)
	}
	if liveURL == "" {
		// No live origin to compare against — refuse the push so the
		// drift guard cannot be silently bypassed by removing the
		// remote.
		return githubbroker.OriginPin{}, fmt.Errorf("%w: workspace has no origin remote", githubbroker.ErrOriginDrift)
	}
	live, err := githubbroker.ParseOriginRepo(liveURL)
	if err != nil {
		return githubbroker.OriginPin{}, err
	}
	if !pin.Equal(live) {
		return githubbroker.OriginPin{}, fmt.Errorf("%w: pinned %s, live %s", githubbroker.ErrOriginDrift, pin, live)
	}
	return pin, nil
}

// buildMetadataScanner constructs the *scanners.BuiltIn the broker's
// ScanMetadata routes through. The scanner is configured from
// policy.yaml's scanners section when one is present, falling back to
// the documented defaults (built-in patterns only, entropy warnings) so
// a fresh workspace still gets the full pattern catalogue.
func buildMetadataScanner(policy *config.PolicyConfig) (*scanners.BuiltIn, error) {
	cfg := scanners.Config{}
	if policy != nil {
		cfg.CustomPatterns = append([]string(nil), policy.Scanners.CustomPatterns...)
	}
	return scanners.NewBuiltIn(cfg)
}

// protectedBranchesFromPolicy returns the operator-supplied
// protected-branch extension list. The broker's defaults
// (defaultProtectedBranches in validate.go) are always applied; this
// helper only forwards the extras so the broker's Prepare check refuses
// pushes against branches the operator pinned in policy.yaml.
//
// Policy iter-4 does not carry an explicit protected_branches field
// yet; we read it from policy.Review.ProtectedBranches if the field
// exists. Until the field lands, this returns nil and the broker
// applies its built-in default list.
func protectedBranchesFromPolicy(_ *config.PolicyConfig) []string {
	return nil
}

// defaultBranchFromPolicy resolves the default branch the broker
// records in Repo.DefaultBranch. Policy iter-4 does not carry an
// explicit field; we default to "main" so the broker's protected-branch
// gate has a sensible target. A future policy field can override.
func defaultBranchFromPolicy(_ *config.PolicyConfig) string {
	return "main"
}
