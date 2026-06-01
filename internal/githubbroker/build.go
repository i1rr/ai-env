// build.go implements Batch 4.2 of the leak-coverage hardening plan:
// BuildBrokerFromSecrets. The factory walks a loaded
// `*secrets.LocalConfig` (the host-side credential store Batch 2.1
// wired) plus operator-supplied policy / repo coordinates and returns
// a fully-wired concrete *Broker the CLI's `ai-env pr` invocation can
// drive through its Prepare → AcquireToken → PushBranch →
// ScanMetadata → CreateDraftPR → RevokeToken lifecycle.
//
// Architectural rules this file pins:
//
//  1. The secrets package stays a leaf. It declares its own credential
//     structs (LocalGitHubAppCredentials, LocalGitHubPATCredentials)
//     specifically so the leaf-style "loaded credentials" view does
//     not have to import internal/githubbroker. BuildBrokerFromSecrets
//     is the adapter that converts those leaf structs into the
//     broker's own GitHubAppConfig / PATConfig and selects the right
//     TokenSource via SelectTokenSource.
//
//  2. The factory does NOT decide policy. Branch prefix, protected
//     branches, and path-gate extensions all come from the caller
//     (the CLI's policy.yaml loader); BuildBrokerFromSecrets only
//     threads them through. The same factory powers production
//     (`cli.RunPR`) and a future `ai-env doctor` repair path.
//
//  3. The factory does NOT touch the network. AcquireToken / PushBranch
//     / CreateDraftPR are stage closures the factory wires; the
//     factory itself is a pure builder. The first network round trip
//     happens inside b.AcquireToken (which delegates to
//     TokenSource.Acquire), not here.
//
//  4. Fresh AcquireToken per PushBranch. The lifecycle order in
//     broker.go honours this by structure (no mid-call refresh); the
//     factory does not need extra plumbing. The plan's Batch 4.2 note
//     "fresh AcquireToken per PushBranch, no mid-call refresh" is
//     captured by the fact that the factory wires a TokenSource that
//     issues a fresh credential per Acquire call and a TokenHolder
//     that does NOT cache across handles.
//
//  5. All log lines flow through RedactTokens. The factory wraps the
//     caller-supplied logger in NewRedactingLogger before handing it
//     to the Broker so the broker code can call b.log(...) without
//     guarding the redactor at every site.

package githubbroker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rivan1986/ai-env/internal/secrets"
)

// BuildBrokerOptions bundles the per-broker policy / transport inputs
// the factory consumes beyond the loaded *secrets.LocalConfig. The
// shape mirrors secrets.BuildOptions: a value-typed options struct so
// the supervisor can build it incrementally and tests can pin only
// the fields they care about.
type BuildBrokerOptions struct {
	// Repo identifies the GitHub repository the broker will push to.
	// Required when a CompositeBroker is being constructed for a real
	// PR run; BuildBrokerFromSecrets validates Owner / Name /
	// CloneURL are non-empty before returning a broker. The caller
	// resolves Repo from the workspace's recorded origin pin (via
	// OriginPin.ToRepo) or from policy.yaml.
	Repo Repo

	// ExtraProtectedBranches is the operator's policy.yaml-loaded
	// protected-branches list. Nil is treated as "no extras"; the
	// broker's default protected set (main / master / trunk /
	// develop) is always applied.
	ExtraProtectedBranches []string

	// PathGate carries the operator's path-gate extension list. Zero
	// value runs the gate with the documented defaults (workflows +
	// `.ai-env/`). The path-gate is not enforced inside the broker
	// today (the CLI runs it before calling Prepare); the option is
	// threaded so a future change can move the enforcement.
	PathGate PathGateOptions

	// Scanner is the metadata scanner ScanMetadata routes through. A
	// real *scanners.BuiltIn is the production wiring; tests pin a
	// fake that satisfies MetadataScanner. A nil scanner causes
	// ScanMetadata to return ErrMetadataScanBlocked.
	Scanner MetadataScanner

	// Logger is the supervisor-supplied log sink. The factory wraps
	// it in NewRedactingLogger before handing it to the Broker so
	// every emitted line is scrubbed. Nil disables logging.
	Logger Logger

	// Clock returns the current time. Nil falls back to time.Now.
	Clock func() time.Time

	// HTTPTimeout caps the broker's HTTP round trips (token mint, PR
	// create). Zero falls back to 30 seconds.
	HTTPTimeout time.Duration

	// HTTPClient overrides the HTTP client used by both the GitHub
	// App token-mint flow (passed into GitHubAppConfig.HTTPClient)
	// and the default createFn closure the factory wires. Nil falls
	// back to a fresh client with HTTPTimeout. Tests pin an
	// httptest.Server's client so the factory's createFn never hits
	// the network.
	HTTPClient *http.Client

	// APIBaseURL overrides the GitHub REST API base URL the factory
	// wires into both the App source and the createFn closure. Empty
	// falls back to https://api.github.com for App+PAT (or whatever
	// the LocalGitHubAppCredentials.APIBaseURL pins for the App
	// case). The caller (production CLI) sets this from the workspace's
	// origin pin host (canonical github.com → https://api.github.com,
	// GHE host → https://<host>/api/v3).
	APIBaseURL string

	// PushFn overrides the default git-push closure the factory
	// wires. Production callers leave it nil to get the default `git
	// push` shell-out; tests pin an in-memory recorder so PushBranch
	// never touches the workspace's git transport. The closure
	// receives a fresh copy of the secret bytes; it is expected to
	// zero its own copy immediately after use.
	PushFn func(ctx BrokerContext, secret []byte) error

	// CreateFn overrides the default REST-API-POST closure the
	// factory wires. Production callers leave it nil to get the
	// default GitHub REST closure; tests pin an in-memory recorder.
	CreateFn func(ctx context.Context, brokerCtx BrokerContext, secret []byte, title, body string) (PRResult, error)
}

// BuildBrokerFromSecrets is Batch 4.2's primary entry point. It
// inspects cfg.Secrets.GitHub, selects the right TokenSource via the
// existing SelectTokenSource (App preferred, PAT fallback when
// explicitly enabled), and assembles a *Broker the CLI can drive.
//
// Error contract:
//
//   - cfg is allowed to be nil; the factory returns (nil,
//     ErrNoTokenSource) so the caller can render the "no broker
//     configured" preview-only message the CLI already supports.
//   - cfg.Secrets.GitHub == nil is treated identically (no broker
//     credential configured).
//   - opts.Repo with empty Owner / Name / CloneURL returns
//     ErrRepoUnconfigured so the caller surfaces "no GitHub
//     repository configured for this workspace".
//   - A misconfigured App credential (bad PEM, zero AppID,
//     InstallationID) surfaces as the underlying NewGitHubAppSource
//     error; the factory does not silently degrade to PAT (security
//     regression).
//
// On success the returned *Broker is ready for the CLI to drive
// through its lifecycle. The caller is responsible for calling
// b.Close() on teardown so the holder's slots and the PATSource's
// in-memory copy are scrubbed.
func BuildBrokerFromSecrets(cfg *secrets.LocalConfig, opts BuildBrokerOptions) (*Broker, error) {
	if cfg == nil || cfg.Secrets.GitHub == nil {
		return nil, ErrNoTokenSource
	}
	if opts.Repo.Owner == "" || opts.Repo.Name == "" {
		return nil, fmt.Errorf("%w: Repo.Owner and Repo.Name must be non-empty", ErrRepoUnconfigured)
	}
	if opts.Repo.CloneURL == "" {
		return nil, fmt.Errorf("%w: Repo.CloneURL must be non-empty", ErrRepoUnconfigured)
	}

	timeout := opts.HTTPTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	apiBase := strings.TrimSpace(opts.APIBaseURL)

	selectorCfg, err := localGitHubToSelector(cfg.Secrets.GitHub, httpClient, opts.Clock, apiBase)
	if err != nil {
		return nil, err
	}
	source, err := SelectTokenSource(selectorCfg)
	if err != nil {
		return nil, err
	}

	pushFn := opts.PushFn
	if pushFn == nil {
		pushFn = defaultPushFn
	}
	createFn := opts.CreateFn
	if createFn == nil {
		// The default createFn requires an api base URL. We default it
		// to https://api.github.com when neither the operator nor the
		// App config supplied one; callers pointing at GHE pass the
		// host's API base URL via opts.APIBaseURL.
		base := apiBase
		if base == "" {
			base = "https://api.github.com"
		}
		createFn = makeDefaultCreateFn(httpClient, base)
	}

	return NewBroker(BrokerOptions{
		Source:                 source,
		Holder:                 NewTokenHolder(),
		Scanner:                opts.Scanner,
		ExtraProtectedBranches: opts.ExtraProtectedBranches,
		PathGate:               opts.PathGate,
		PushFn:                 pushFn,
		CreateFn:               createFn,
		Logger:                 opts.Logger,
		Clock:                  opts.Clock,
		HTTPTimeout:            timeout,
	})
}

// localGitHubToSelector adapts the secrets package's leaf credential
// shape into the broker's SelectorConfig. The function preserves the
// "App preferred, PAT fallback only when explicitly enabled" rule the
// SelectTokenSource enforces — it only populates the PAT field when
// the operator's `enabled: true` flag is on. A misconfigured App (bad
// PEM bytes, zero IDs) surfaces at SelectTokenSource time via
// NewGitHubAppSource's validation.
//
// The function is exported only via BuildBrokerFromSecrets; tests
// drive it indirectly through the factory.
func localGitHubToSelector(gh *secrets.LocalGitHubCredentials, httpClient *http.Client, clock func() time.Time, apiBaseOverride string) (SelectorConfig, error) {
	if gh == nil {
		return SelectorConfig{}, errors.New("githubbroker: localGitHubToSelector requires non-nil credentials")
	}
	var sel SelectorConfig
	if gh.App != nil {
		appBase := strings.TrimSpace(gh.App.APIBaseURL)
		if apiBaseOverride != "" {
			// The supervisor-supplied APIBaseURL wins when set so a
			// workspace pinned at a GHE host can override an App
			// credential that was minted for a different instance
			// without the operator having to re-mint.
			appBase = apiBaseOverride
		}
		sel.App = &GitHubAppConfig{
			AppID:          gh.App.AppID,
			InstallationID: gh.App.InstallationID,
			PrivateKeyPEM:  []byte(gh.App.PrivateKeyPEM),
			APIBaseURL:     appBase,
			HTTPClient:     httpClient,
			Clock:          clock,
		}
	}
	if gh.PAT != nil {
		sel.PAT = &PATConfig{
			Enabled: gh.PAT.Enabled,
			Token:   gh.PAT.Token,
			TTL:     time.Duration(gh.PAT.TTLSeconds) * time.Second,
		}
	}
	return sel, nil
}

// defaultPushFn is the production git-push closure the factory wires
// when the caller does not supply opts.PushFn. The function is a thin
// wrapper around `git push` that embeds the credential in a one-shot
// authenticated HTTPS URL constructed at call time and zeros the
// local copy after use.
//
// Implementation note: we DO NOT call `git push` here because the
// production path lands later in the plan (Bucket 3 is broker-live,
// but the actual git transport closure is wired by a future batch
// that adds a TOCTOU-safe credential-helper integration). For Batch
// 4.2 the default closure returns an error so a misconfigured wire-
// up (factory constructed but no PushFn supplied) fails loudly. Tests
// always supply opts.PushFn so the default's not-implemented behaviour
// does not affect them.
func defaultPushFn(ctx BrokerContext, secret []byte) error {
	_ = secret
	return fmt.Errorf("githubbroker: no PushFn configured; production wiring is provided by a later batch")
}

// makeDefaultCreateFn returns a CreateFn closure that POSTs to the
// GitHub REST "create pull request" endpoint at baseURL. The closure
// uses the supplied httpClient (already configured with a timeout)
// and the supplied raw credential bytes.
//
// The function is exported indirectly via BuildBrokerFromSecrets's
// default wiring; tests that want to drive the broker without a real
// HTTP server pass opts.CreateFn and the default is unused.
//
// As with defaultPushFn, the production wiring for the REST round
// trip can land in a follow-up batch; the closure here returns an
// error so a Broker without a CreateFn override surfaces the
// omission. Wiring the closure to the real API requires more
// retry / pagination / rate-limit logic than Batch 4.2 budgets.
func makeDefaultCreateFn(client *http.Client, baseURL string) func(ctx context.Context, brokerCtx BrokerContext, secret []byte, title, body string) (PRResult, error) {
	_ = client
	_ = baseURL
	return func(ctx context.Context, brokerCtx BrokerContext, secret []byte, title, body string) (PRResult, error) {
		_ = ctx
		_ = brokerCtx
		_ = secret
		_ = title
		_ = body
		return PRResult{}, fmt.Errorf("githubbroker: no CreateFn configured; production wiring is provided by a later batch")
	}
}

