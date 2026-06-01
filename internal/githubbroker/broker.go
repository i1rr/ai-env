// broker.go implements the concrete GitHubBroker the production CLI
// wires through `cli.RunPR`. The struct (Broker) satisfies the
// interface declared in githubbroker.go by composing the per-stage
// primitives that already live in this package:
//
//   - validate.go            → branch prefix + protected branch +
//                              path-gate checks at Prepare
//   - auth.go (TokenSource)  → Acquire / revoke callback at
//                              AcquireToken
//   - token.go (TokenHolder) → handle bookkeeping at AcquireToken /
//                              PushBranch / CreateDraftPR /
//                              RevokeToken
//   - metadata.go            → built-in scanner walk at ScanMetadata
//   - redact.go              → log scrubbing for every emitted log line
//
// What this file deliberately does NOT do:
//
//   - It does not invent a parallel credential flow. Acquire / Revoke
//     come from the TokenSource (GitHubAppSource or PATSource); the
//     broker only orchestrates them.
//   - It does not embed the raw token in any log line or returned
//     value. Every log line passes through the broker's Logger (a
//     NewRedactingLogger wrap of the supervisor-supplied closure); the
//     materialized bytes only flow into the push transport closure
//     and the PR create closure, both of which receive a fresh copy
//     and are expected to zero it immediately after use.
//   - It does not perform mid-call refresh. The plan's locked decision
//     is "fresh AcquireToken per PushBranch, no mid-call refresh"; the
//     lifecycle order (Prepare → AcquireToken → PushBranch →
//     ScanMetadata → CreateDraftPR → RevokeToken) honours this
//     trivially by structure: AcquireToken happens once per lifecycle,
//     PushBranch and CreateDraftPR re-materialize the same holder slot,
//     and RevokeToken disposes of it.
//
// The struct is constructed via BuildBrokerFromSecrets (build.go) for
// the production path. Tests construct a Broker directly with injected
// pushFn / createFn closures so the HTTP / git transports never hit
// the network.
//
// Concurrency: like the interface, Broker methods are NOT safe for
// concurrent use by multiple goroutines. The CLI invokes them
// sequentially in the order the plan's "Token lifecycle" diagram lists.

package githubbroker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rivan1986/ai-env/internal/scanners"
)

// Broker is the concrete GitHubBroker implementation. Fields are
// populated by BuildBrokerFromSecrets (or by a unit test) and the
// resulting struct is consumed by `cli.RunPR` for the lifetime of a
// single `ai-env pr` invocation.
//
// All exported fields are non-zero on a Broker returned from
// BuildBrokerFromSecrets; tests that construct a Broker directly may
// leave per-stage helpers nil and the default value documented on each
// field applies.
type Broker struct {
	// source is the credential issuer for this run. Selected once via
	// SelectTokenSource (App preferred, PAT fallback when explicitly
	// enabled). Not safe to swap mid-run; reconstruct a fresh Broker
	// instead.
	source TokenSource

	// holder is the in-memory token store. Each AcquireToken issues
	// into it; PushBranch / CreateDraftPR materialize from it;
	// RevokeToken / Close clear it. A fresh holder is provisioned per
	// Broker so two concurrent CLI invocations cannot accidentally
	// share slots.
	holder *TokenHolder

	// scanner is the built-in secret scanner used by ScanMetadata.
	// Required for ScanMetadata to fire; BuildBrokerFromSecrets passes
	// in a real *scanners.BuiltIn. A nil scanner causes ScanMetadata
	// to return ErrMetadataScanBlocked so a misconfigured Broker
	// surfaces the omission instead of silently producing a clean
	// scan result.
	scanner MetadataScanner

	// extraProtected is the operator-supplied list of additional
	// protected branch names (loaded from policy.yaml's protected
	// branches list). Combined with the broker's defaults
	// (defaultProtectedBranches) at Prepare time. Nil is treated as
	// "no extras", which is the most common case.
	extraProtected []string

	// pathGate carries the policy-supplied extra block-globs / replace
	// flag. The zero value runs the gate with the documented defaults
	// (`.github/workflows/**`, `.ai-env/**`).
	pathGate PathGateOptions

	// pushFn ships the workspace branch named in ctx to the remote
	// identified by ctx.Repo, using the supplied raw credential bytes.
	// Required: PushBranch returns an error when pushFn is nil so a
	// misconfigured Broker does not silently succeed.
	//
	// The closure receives a fresh copy of the secret bytes the caller
	// owns; pushFn is expected to zero its own copy immediately after
	// use. The Broker zeros the materialized bytes on its side before
	// PushBranch returns.
	pushFn func(ctx BrokerContext, secret []byte) error

	// createFn opens the draft PR on the remote identified by ctx
	// using the supplied raw credential bytes plus the broker-
	// generated title / body. Required: CreateDraftPR returns an error
	// when createFn is nil. createFn is expected to zero its own copy
	// of the secret immediately after use.
	createFn func(ctx context.Context, brokerCtx BrokerContext, secret []byte, title, body string) (PRResult, error)

	// logger is the broker's NewRedactingLogger-wrapped sink for every
	// emitted log line. A nil logger is tolerated (treated as
	// "discard") so a tests that does not care about logs can construct
	// a Broker without wiring a buffer.
	logger Logger

	// clock returns the current time. Used only for context deadlines
	// and never for token-state-keeping (TokenHolder owns that). Nil
	// falls back to time.Now.
	clock func() time.Time

	// httpTimeout caps how long CreateDraftPR's HTTP call may take.
	// Zero falls back to a 30-second default. The same default applies
	// to AcquireToken indirectly via the TokenSource's own client.
	httpTimeout time.Duration
}

// Verify Broker satisfies GitHubBroker at compile time. A future
// change to the interface lights up here before any caller has to
// re-discover the contract.
var _ GitHubBroker = (*Broker)(nil)

// BrokerOptions bundles every knob the concrete Broker accepts beyond
// the credential source. BuildBrokerFromSecrets populates this from
// secrets.LocalConfig + policy.yaml; unit tests pin the same fields
// directly.
//
// Every field is optional EXCEPT Source, Holder, PushFn, and CreateFn.
// A Broker built without one of those four required pieces will panic
// at construction (NewBroker) so misconfiguration surfaces at wire-up,
// not at the first AcquireToken.
type BrokerOptions struct {
	// Source is the credential issuer. Required. Production callers
	// wire either *GitHubAppSource (the primary) or *PATSource (the
	// development fallback) via SelectTokenSource.
	Source TokenSource

	// Holder is the in-memory token store. Required. Pass a fresh
	// holder per Broker (NewTokenHolder) so two concurrent CLI
	// invocations cannot share slots.
	Holder *TokenHolder

	// Scanner is the metadata scanner ScanMetadata routes through.
	// Optional in the sense that the Broker still constructs without
	// it, but ScanMetadata returns ErrMetadataScanBlocked when it is
	// nil. Production callers wire a real *scanners.BuiltIn.
	Scanner MetadataScanner

	// ExtraProtectedBranches extends the broker's default protected-
	// branch list (main / master / trunk / develop) with the
	// operator's policy.yaml entries. Pass nil for "no extras".
	ExtraProtectedBranches []string

	// PathGate carries the operator's path-gate extension. Zero value
	// runs with the documented defaults (workflows + `.ai-env/`).
	PathGate PathGateOptions

	// PushFn is the git push transport closure. Required. Production
	// callers wire a closure that shells out to `git push` with the
	// supplied secret embedded via a credential helper or a one-shot
	// URL. Tests wire an in-memory recorder so PushBranch never hits
	// the network. The closure receives a fresh copy of the secret;
	// the closure is expected to zero its own copy immediately after
	// use.
	PushFn func(ctx BrokerContext, secret []byte) error

	// CreateFn is the GitHub REST closure that opens the draft PR.
	// Required. Production callers wire a closure that POSTs to the
	// GitHub API's "create pull request" endpoint; tests wire an
	// in-memory recorder. As with PushFn, the closure receives a
	// fresh copy of the secret and is expected to zero its own copy.
	CreateFn func(ctx context.Context, brokerCtx BrokerContext, secret []byte, title, body string) (PRResult, error)

	// Logger is the unwrapped log sink the broker will route every
	// emitted log line through (after wrapping in NewRedactingLogger
	// so the GitHub-token patterns scrub any echoed credential). Nil
	// disables logging.
	Logger Logger

	// Clock returns the current time. Nil falls back to time.Now.
	Clock func() time.Time

	// HTTPTimeout caps CreateDraftPR's HTTP round trip. Zero falls
	// back to 30 seconds.
	HTTPTimeout time.Duration
}

// NewBroker constructs a concrete Broker from opts. The required
// fields (Source, Holder, PushFn, CreateFn) are validated; a missing
// piece returns an error so a misconfigured caller fails loudly.
//
// The logger is wrapped in NewRedactingLogger so every line the broker
// emits passes through the GitHub-token pattern set. Callers MUST NOT
// pass an already-redacting logger or the wrap becomes a double-redact
// (functionally harmless but wasted work); BuildBrokerFromSecrets is
// the canonical wire-up point.
func NewBroker(opts BrokerOptions) (*Broker, error) {
	if opts.Source == nil {
		return nil, errors.New("githubbroker: NewBroker requires Source")
	}
	if opts.Holder == nil {
		return nil, errors.New("githubbroker: NewBroker requires Holder")
	}
	if opts.PushFn == nil {
		return nil, errors.New("githubbroker: NewBroker requires PushFn")
	}
	if opts.CreateFn == nil {
		return nil, errors.New("githubbroker: NewBroker requires CreateFn")
	}
	logger := NewRedactingLogger(opts.Logger)
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	timeout := opts.HTTPTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Broker{
		source:         opts.Source,
		holder:         opts.Holder,
		scanner:        opts.Scanner,
		extraProtected: append([]string(nil), opts.ExtraProtectedBranches...),
		pathGate:       opts.PathGate,
		pushFn:         opts.PushFn,
		createFn:       opts.CreateFn,
		logger:         logger,
		clock:          clock,
		httpTimeout:    timeout,
	}, nil
}

// Prepare runs the static, network-free validation rules (branch
// prefix, protected branch, repo coordinates). The path-gate is NOT
// run here because the workspace diff is owned by `cli.RunPR`; the
// CLI runs the path-gate before calling Prepare. The Broker's
// PathGate option still exists so a future change can add the gate
// here without churning callers.
//
// A nil envName / branchName / Repo with empty Owner/Name is rejected
// so the rest of the lifecycle has a usable context.
func (b *Broker) Prepare(envName, branchName string, repo Repo) (BrokerContext, error) {
	if envName == "" {
		return BrokerContext{}, errors.New("githubbroker: Prepare requires envName")
	}
	if repo.Owner == "" || repo.Name == "" {
		return BrokerContext{}, fmt.Errorf("%w: Owner and Name required", ErrRepoUnconfigured)
	}
	if repo.CloneURL == "" {
		return BrokerContext{}, fmt.Errorf("%w: CloneURL required", ErrRepoUnconfigured)
	}
	if err := ValidateBranchPrefix(branchName); err != nil {
		return BrokerContext{}, err
	}
	if err := ValidateProtectedBranch(branchName, repo, b.extraProtected); err != nil {
		return BrokerContext{}, err
	}
	b.log("broker: prepared env=%s branch=%s repo=%s/%s", envName, branchName, repo.Owner, repo.Name)
	return BrokerContext{
		EnvName:    envName,
		BranchName: branchName,
		Repo:       repo,
	}, nil
}

// AcquireToken obtains a fresh credential from the underlying
// TokenSource and records it in the Broker's TokenHolder. The
// returned BrokerToken carries only the metadata (kind, handle,
// IssuedAt, TTL); the raw secret stays inside the holder.
//
// The context.Background here is the broker's own context. A future
// caller-supplied context.Context would belong on the GitHubBroker
// interface; today the interface signature is context-free so the
// broker uses its own.
func (b *Broker) AcquireToken(_ BrokerContext) (BrokerToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), b.httpTimeout)
	defer cancel()
	secret, ttl, revokeFn, err := b.source.Acquire(ctx)
	if err != nil {
		b.log("broker: acquire token failed: %v", err)
		return BrokerToken{}, err
	}
	tok := b.holder.Issue(b.source.Kind(), secret, ttl, revokeFn)
	zeroBytes(secret)
	b.log("broker: acquired token handle=%s kind=%s ttl=%s", tok.Handle, tok.Kind, tok.TTL)
	return tok, nil
}

// PushBranch materializes the credential bytes from the holder, hands
// them to the pushFn closure, and immediately zeros the local copy.
// The lifecycle's "fresh AcquireToken per PushBranch, no mid-call
// refresh" rule is honoured by structure: PushBranch never touches the
// TokenSource; the holder slot is the only credential surface here.
func (b *Broker) PushBranch(ctx BrokerContext, token BrokerToken) error {
	secret, err := b.holder.Materialize(token)
	if err != nil {
		b.log("broker: push branch %s: materialize failed: %v", ctx.BranchName, err)
		return err
	}
	pushErr := b.pushFn(ctx, secret)
	zeroBytes(secret)
	if pushErr != nil {
		b.log("broker: push branch %s failed", ctx.BranchName)
		return pushErr
	}
	b.log("broker: pushed branch=%s to %s/%s", ctx.BranchName, ctx.Repo.Owner, ctx.Repo.Name)
	return nil
}

// ScanMetadata runs the broker's metadata scanner over the supplied
// PR fields. The Metadata's BranchName is taken from the BrokerContext
// (so the gate scans the exact branch the broker would push) and the
// commit-message slice is forwarded verbatim.
//
// A nil scanner produces ErrMetadataScanBlocked so a misconfigured
// Broker surfaces the omission instead of silently producing a clean
// scan result.
func (b *Broker) ScanMetadata(ctx BrokerContext, title, body string, commitMessages []string) (scanners.ScanResult, error) {
	return ScanMetadata(b.scanner, Metadata{
		Title:          title,
		Body:           body,
		BranchName:     ctx.BranchName,
		CommitMessages: commitMessages,
	})
}

// CreateDraftPR materializes the credential bytes one more time, calls
// the createFn closure with a fresh-context timeout, zeros the local
// copy, and returns the broker-supplied PRResult.
func (b *Broker) CreateDraftPR(brokerCtx BrokerContext, token BrokerToken, title, body string) (PRResult, error) {
	secret, err := b.holder.Materialize(token)
	if err != nil {
		b.log("broker: create PR for %s: materialize failed: %v", brokerCtx.BranchName, err)
		return PRResult{}, err
	}
	httpCtx, cancel := context.WithTimeout(context.Background(), b.httpTimeout)
	defer cancel()
	pr, createErr := b.createFn(httpCtx, brokerCtx, secret, title, body)
	zeroBytes(secret)
	if createErr != nil {
		b.log("broker: create PR for %s failed: %v", brokerCtx.BranchName, createErr)
		return PRResult{}, createErr
	}
	b.log("broker: created PR #%d url=%s draft=%t", pr.Number, pr.URL, pr.Draft)
	return pr, nil
}

// RevokeToken delegates to the TokenHolder's two-phase revoke (issuer
// callback + local scrub). A nil error means both phases succeeded; a
// non-nil error came from the issuer (the local scrub still ran).
func (b *Broker) RevokeToken(token BrokerToken) error {
	err := b.holder.Revoke(token)
	if err != nil {
		b.log("broker: revoke token failed: %v", err)
		return err
	}
	b.log("broker: revoked token handle=%s", token.Handle)
	return nil
}

// Close drops every slot the holder owns, scrubbing in-memory secrets
// for tokens the broker forgot to revoke (e.g. on a mid-lifecycle
// panic). The PATSource holds its own copy of the configured token;
// Close also calls source.Forget when the source supports it so the
// PAT bytes do not survive process teardown.
//
// Close is safe to call repeatedly. The supervisor's teardown step
// invokes it once; an `ai-env destroy` path can invoke it again
// without error.
func (b *Broker) Close() {
	if b == nil {
		return
	}
	if b.holder != nil {
		_ = b.holder.ForgetAll()
	}
	// PATSource carries a private []byte that should be zeroed; the
	// type assertion is safe because PATSource is the only source
	// that holds a cached secret across calls.
	if pat, ok := b.source.(*PATSource); ok {
		pat.Forget()
	}
}

// log formats a line and forwards it to the broker's redacting
// logger. A nil logger (test default) silently drops the line. The
// helper exists so call sites stay terse: `b.log("broker: prepared
// env=%s ...", ...)` instead of guarding the nil logger at every
// call site.
func (b *Broker) log(format string, args ...any) {
	if b.logger == nil {
		return
	}
	b.logger(fmt.Sprintf(format, args...))
}
