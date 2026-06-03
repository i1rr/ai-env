// Package githubbroker defines the host-side broker that ai-env uses to
// create draft GitHub pull requests on behalf of an agent without ever
// exposing a raw GitHub token to the sandbox.
//
// Plan 07 step 1 defines only the public surface here: the GitHubBroker
// interface, the BrokerContext / BrokerToken / PRResult companion types,
// and the package's stable error vocabulary. The concrete behaviours
// (branch prefix enforcement, protected branch check, path gate checks,
// metadata scanning, broker-generated PR body, GitHub App installation
// token flow, TTL/revocation, log redaction, CLI wiring, ExportGate
// integration, policy-decision logging) land in later steps of plan 07.
// Wiring the interface first lets downstream code (the CLI's `ai-env pr`
// command, ExportGate's broker hook, the run-lifecycle revocation hook)
// compile against a stable type while the concrete implementation is
// built incrementally.
//
// Design rules this package enforces:
//
//  1. The raw GitHub token never crosses into the sandbox. The broker
//     runs on the host, holds the token in memory, and exposes only the
//     opaque BrokerToken handle to callers. CLI code, run lifecycle
//     code, and any other in-process consumer must address tokens by
//     handle and let the broker materialize the secret only inside its
//     own HTTP transport. See plan 07 section "Key decisions from
//     master plan", item 1.
//
//  2. One verb per lifecycle stage. The interface is intentionally
//     decomposed into the six stages the plan's "Token lifecycle"
//     diagram lists: Prepare validates inputs and produces a
//     BrokerContext; AcquireToken obtains a short-lived install token;
//     PushBranch ships the workspace branch to the remote; ScanMetadata
//     screens the human-visible fields with the Plan 06 secret scanner;
//     CreateDraftPR opens the PR; RevokeToken returns the token to its
//     issuer. Splitting them this way lets the caller (the CLI's `ai-env
//     pr` command and the run finalizer's revocation hook) interleave
//     ExportGate checks and `policy-decisions.jsonl` events at the
//     right boundaries instead of having one monolithic method do
//     everything.
//
//  3. Pure interface, injectable implementation. Like internal/backend,
//     internal/scanners, and internal/agents, the broker is defined as
//     an interface so the CLI and the run lifecycle can be unit tested
//     with a fake. The concrete GitHub-App-backed implementation lands
//     in plan 07 step 7; until then, callers wire a fake that satisfies
//     this interface.
//
//  4. Stable error vocabulary. The Err* values exported below are the
//     sentinel errors the CLI pattern-matches on (via errors.Is) to
//     decide whether to render a remediation hint or a generic failure.
//     New error categories add new sentinels; existing ones keep their
//     identity so downstream code does not break across releases.
//
//  5. ScanMetadata returns the Plan 06 ScanResult shape. Plan 07 step 5
//     explicitly reuses the built-in secret scanner from Plan 06 to
//     scrub PR title, body, branch name, and commit messages. Reusing
//     scanners.ScanResult means the same secret-scan.json contract,
//     the same findings semantics, and the same export-gate hookup
//     apply to broker metadata as to workspace files; the broker is
//     not allowed to invent a parallel finding shape.
//
// Implementations of GitHubBroker land in later steps of plan 07. This
// file defines only the public surface so the CLI command, the run
// lifecycle hook, and the export gate can be wired against a stable
// type.
package githubbroker

import (
	"errors"
	"time"

	"github.com/i1rr/ai-env/internal/scanners"
)

// GitHubBroker is the contract every broker implementation satisfies.
// A single GitHubBroker is constructed per `ai-env pr` invocation by
// the CLI; the same instance is reused across the lifecycle calls
// (Prepare -> AcquireToken -> PushBranch -> ScanMetadata ->
// CreateDraftPR -> RevokeToken) so the broker can keep its loaded
// configuration, HTTP client, and in-memory token state private to a
// single run.
//
// Methods on GitHubBroker are not required to be safe for concurrent
// use by multiple goroutines. The CLI invokes them sequentially in
// the order the plan's "Token lifecycle" diagram lists.
//
// The methods accept a BrokerContext value (the `ctx` parameter in the
// plan signatures, distinct from a standard context.Context) returned
// by Prepare; this captures the validated inputs and the broker-side
// derived state (resolved repo coordinates, run metadata, etc.) so the
// later calls can stay narrow on their per-call arguments.
type GitHubBroker interface {
	// Prepare validates the requested PR coordinates and returns a
	// BrokerContext the caller threads through the rest of the
	// lifecycle. Validation here includes the static rules that do
	// not depend on a token or a network round-trip: branch prefix
	// (plan 07 step 2), protected branch check (step 3), and path
	// gate checks (step 4). The BrokerContext snapshot lets the
	// later calls operate on the validated inputs without re-parsing
	// them.
	//
	// envName is the ai-env environment the PR is being opened for
	// (e.g. "fix-tests"). branchName is the workspace branch the
	// caller intends to push (e.g. "ai-env/fix-tests"). repo
	// identifies the GitHub repository the PR will land on.
	Prepare(envName, branchName string, repo Repo) (BrokerContext, error)

	// AcquireToken obtains a short-lived credential for the
	// repository identified by ctx and returns an opaque BrokerToken.
	// The raw token value is held by the broker; callers receive
	// only a handle, never the secret. Plan 07 step 7 documents the
	// preferred credential type (GitHub App installation token) and
	// the PAT development fallback.
	AcquireToken(ctx BrokerContext) (BrokerToken, error)

	// PushBranch ships the workspace branch named in ctx to the
	// remote identified by ctx.Repo, authenticated with token. It is
	// the broker's responsibility to materialize the credential into
	// the git transport without leaking it into shell history or
	// process environment visible to the agent.
	PushBranch(ctx BrokerContext, token BrokerToken) error

	// ScanMetadata runs the Plan 06 built-in secret scanner over the
	// human-visible PR fields (title, body, commitMessages) and
	// returns a ScanResult. The broker does not decide whether the
	// findings block submission; that decision belongs to ExportGate
	// (plan 07 step 11) and the CLI. ScanMetadata is a pure
	// inspection: it produces findings, it does not mutate broker
	// state.
	//
	// The branch name does not appear as a separate parameter
	// because it is part of the BrokerContext threaded through every
	// other lifecycle call; implementations include the branch name
	// in the scanner input.
	ScanMetadata(ctx BrokerContext, title, body string, commitMessages []string) (scanners.ScanResult, error)

	// CreateDraftPR opens a draft pull request on the repository
	// identified by ctx using title and body. Plan 07 fixes draft as
	// the default; the interface accepts no "draft" flag because the
	// broker never opens a non-draft PR in the v0.1 surface.
	//
	// title and body must be the sanitized, broker-generated values
	// (plan 07 step 6), not the raw agent transcript. The broker
	// trusts the caller to have already passed them through
	// ScanMetadata and ExportGate; CreateDraftPR does not re-scan.
	CreateDraftPR(ctx BrokerContext, token BrokerToken, title, body string) (PRResult, error)

	// RevokeToken returns token to its issuer (revokes a GitHub App
	// installation token, deletes a transient PAT, etc.). Per plan
	// 07 step 8, revocation is attempted after CreateDraftPR and is
	// re-attempted from the `ai-env destroy` path. A failed
	// revocation is recorded as a warning by the caller; the
	// underlying token still expires naturally at its TTL.
	RevokeToken(token BrokerToken) error
}

// Repo identifies the GitHub repository a brokered PR targets. The CLI
// constructs a Repo from the workspace's git remote and the policy
// configuration; the broker uses it both for the GitHub API base path
// (Owner / Name) and for the git push transport (CloneURL).
type Repo struct {
	// Owner is the GitHub account or organization that owns the
	// repository (the path segment before the slash in
	// "owner/name").
	Owner string

	// Name is the repository's short name (the path segment after
	// the slash in "owner/name").
	Name string

	// DefaultBranch is the repository's default branch (e.g. "main",
	// "master"). Plan 07 step 3 uses it to enforce the
	// "no push to protected branches" rule.
	DefaultBranch string

	// CloneURL is the URL the broker uses to push the workspace
	// branch. Typically the repository's HTTPS clone URL; the broker
	// rewrites it to embed the BrokerToken at push time.
	CloneURL string
}

// BrokerContext is the validated, broker-side snapshot Prepare returns.
// It threads through the rest of the lifecycle so AcquireToken,
// PushBranch, ScanMetadata, CreateDraftPR, and RevokeToken operate on
// a single immutable description of "what PR are we opening, for which
// env, on which branch, against which repo". This is the `ctx`
// parameter in the plan signatures; it is intentionally a distinct
// type from a standard context.Context so callers cannot confuse
// cancellation plumbing with broker state.
//
// Implementations may carry private fields beyond the exported ones
// (resolved API endpoints, sanitized run metadata, gate result, etc.);
// the exported fields below are the minimum contract the interface
// users (CLI command, run lifecycle, policy-decision logger) depend on.
type BrokerContext struct {
	// EnvName is the ai-env environment the PR is being opened for
	// (e.g. "fix-tests"). The run lifecycle hooks use it to locate
	// the run record when recording broker outcomes.
	EnvName string

	// BranchName is the workspace branch the broker will push. Plan
	// 07 step 2 fixes the "ai-env/" prefix; Prepare rejects names
	// that do not match before constructing a BrokerContext.
	BranchName string

	// Repo identifies the repository the PR will land on. Captured
	// at Prepare time so later calls do not re-resolve the remote.
	Repo Repo
}

// BrokerToken is the opaque handle the broker hands back from
// AcquireToken. It identifies a token the broker is holding for the
// caller; the caller passes it back to PushBranch, CreateDraftPR, and
// RevokeToken so the broker can look up the underlying secret without
// the caller ever seeing it.
//
// Plan 07's "raw GitHub token is never visible inside the sandbox"
// rule (master plan section 19) makes this opacity load-bearing: a
// caller that printed token.Secret or marshaled BrokerToken to JSON
// would defeat the whole isolation model, so the struct exposes only
// metadata fields (token kind, issuance time, TTL) and keeps the
// secret material inside the broker's process memory.
type BrokerToken struct {
	// Kind reports which credential type backs this handle: a
	// GitHub App installation token (plan 07 step 7 primary path) or
	// a PAT (plan 07 step 7 development fallback). The CLI surfaces
	// it in `ai-env status` so operators know which credential
	// flowed.
	Kind TokenKind

	// Handle is the broker-internal identifier for the token. It is
	// opaque to callers; equality of two BrokerToken values is
	// determined by Handle. The broker rotates handles per
	// AcquireToken call so a leaked handle from one run cannot be
	// replayed against another.
	Handle string

	// IssuedAt is the wall-clock time AcquireToken obtained the
	// token. Plan 07 step 8 records it in run.json so operators can
	// reason about the credential's lifetime.
	IssuedAt time.Time

	// TTL is the time-to-live the issuer attached to the token. Plan
	// 07 step 8 fixes the default at 300s and the maximum at 1800s;
	// the broker enforces those bounds when requesting credentials,
	// not when populating this field.
	TTL time.Duration
}

// TokenKind enumerates the credential types the broker can hand out.
// Plan 07 step 7 names the two: GitHub App installation tokens as the
// primary, PATs as a development fallback. The CLI groups its output
// by Kind and refuses the PAT path outside development mode.
type TokenKind string

const (
	// TokenKindGitHubApp identifies a GitHub App installation token.
	// Short-lived, repo-scoped, the recommended credential per plan
	// 07 "Key decisions from master plan", item 2.
	TokenKindGitHubApp TokenKind = "github_app"

	// TokenKindPersonalAccessToken identifies a PAT (or a fine-grained
	// PAT). Used as a development fallback when no GitHub App is
	// configured; plan 07 step 7 keeps it behind explicit opt-in.
	TokenKindPersonalAccessToken TokenKind = "pat"
)

// String makes TokenKind satisfy fmt.Stringer so it formats cleanly in
// log lines and CLI output without an explicit conversion.
func (k TokenKind) String() string { return string(k) }

// PRResult is the outcome of CreateDraftPR. The CLI renders it to the
// operator; the run finalizer records the URL in run.json so a later
// `ai-env status` can surface it.
type PRResult struct {
	// Number is the PR number GitHub assigned (e.g. 1234). Zero when
	// the API call did not return a number (e.g. dry-run paths).
	Number int

	// URL is the HTML URL of the created PR. Empty when no PR was
	// created. Always populated on success.
	URL string

	// Draft reports whether the PR is in draft state. Plan 07 fixes
	// draft as the default, so this is always true today; the field
	// exists so future non-draft surfaces (gated behind explicit
	// operator opt-in) can be added without changing the result
	// shape.
	Draft bool

	// CreatedAt is the wall-clock time the PR was created on the
	// GitHub side, as reported by the API. Zero when the API did not
	// return a timestamp.
	CreatedAt time.Time
}

// Err* are the sentinel errors the broker returns. The CLI matches
// against them with errors.Is to render the right remediation hint
// (e.g. "your branch must start with ai-env/", "push to main is
// blocked by policy") instead of parsing free-form message text.
// Values are stable across versions; deprecate by adding a new
// sentinel rather than reusing an existing one.
var (
	// ErrInvalidBranchPrefix is returned by Prepare when the
	// requested branch name does not begin with the policy-required
	// "ai-env/" prefix. Plan 07 step 2 enforcement point.
	ErrInvalidBranchPrefix = errors.New("githubbroker: branch name must start with ai-env/")

	// ErrProtectedBranch is returned by Prepare when the requested
	// branch matches a protected branch (main, master, or one
	// configured in policy.yaml). Plan 07 step 3 enforcement point.
	ErrProtectedBranch = errors.New("githubbroker: push to protected branch is blocked")

	// ErrProtectedPath is returned by Prepare when the workspace
	// diff includes a file under .github/workflows/**, .ai-env/**,
	// or another path the policy's block_auto_pr_on_paths list
	// covers. Plan 07 step 4 enforcement point.
	ErrProtectedPath = errors.New("githubbroker: workspace changes touch a path that blocks automatic PR")

	// ErrTokenExpired is returned by PushBranch and CreateDraftPR
	// when the supplied BrokerToken's TTL has elapsed before use.
	// Plan 07 step 8 lifecycle guard.
	ErrTokenExpired = errors.New("githubbroker: broker token has expired")

	// ErrTokenRevoked is returned by PushBranch and CreateDraftPR
	// when the supplied BrokerToken has already been revoked
	// (either explicitly by RevokeToken or implicitly by a prior
	// destroy hook). Plan 07 step 8 lifecycle guard.
	ErrTokenRevoked = errors.New("githubbroker: broker token has been revoked")

	// ErrMetadataScanBlocked is returned by ScanMetadata when the
	// underlying scanner errored out. A clean scan that found
	// secrets returns a populated ScanResult with a nil error; the
	// caller (ExportGate) decides whether the findings block
	// submission. ErrMetadataScanBlocked is reserved for scanner
	// infrastructure failures.
	ErrMetadataScanBlocked = errors.New("githubbroker: PR metadata scan failed")

	// ErrRepoUnconfigured is returned by Prepare when the supplied
	// Repo is missing fields the broker needs (Owner, Name, or
	// CloneURL). The CLI surfaces it as "no GitHub repository
	// configured for this workspace".
	ErrRepoUnconfigured = errors.New("githubbroker: GitHub repository is not configured")
)
