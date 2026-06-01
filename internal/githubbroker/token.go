// token.go implements plan 07 step 8: token TTL and revocation. The
// broker keeps the raw GitHub credential (App installation token or
// PAT) in host-side memory and exposes only an opaque BrokerToken
// handle to callers. This file owns the supporting machinery:
//
//   - DefaultTokenTTL / MaxTokenTTL: the policy-fixed lifetime bounds
//     the broker enforces when it asks an issuer for a credential and
//     when it caps a caller-supplied TTL.
//   - TokenHolder: the in-memory store the concrete broker uses to map
//     a BrokerToken.Handle back to the raw secret without ever putting
//     that secret on a BrokerToken value the caller can read.
//   - issuance helpers (newHandle, ClampTTL) that the GitHub App and
//     PAT token sources share so handle generation and TTL clamping
//     live in exactly one place.
//
// The plan calls the rules out in two places:
//
//  1. "Key decisions from master plan", item 10: "Token TTL default:
//     300s. Max: 1800s. Rotate per action, revoke on destroy."
//  2. Step 8: "Record token issue time and TTL in run.json. Attempt
//     revocation after PR creation. Fail with warning if revocation
//     fails. Revoke on `ai-env destroy`."
//
// Design choices this file pins:
//
//  1. The raw secret never appears on BrokerToken. BrokerToken carries
//     Kind / Handle / IssuedAt / TTL only; the secret lives inside the
//     TokenHolder, addressed by Handle. A caller that prints a
//     BrokerToken sees no token material.
//  2. TokenHolder zeroes the secret on Revoke and Forget. Go's garbage
//     collector cannot promise to scrub a string's backing bytes, so
//     the holder stores the secret as a []byte that it overwrites
//     before releasing the slot. This is best-effort (the kernel may
//     still have a copy in the page cache from the issuance round
//     trip) but it removes the in-process copy the next debugger
//     attach would see.
//  3. Expiry is wall-clock relative. IssuedAt + TTL is the cutoff. A
//     small skew is tolerated by callers (a token returned "live" at
//     T-1ms is still treated as live; that is the issuer's contract,
//     not ours).
//  4. Handles are opaque, single-run. newHandle returns a 16-byte
//     hex-encoded random string per issuance. The handle does not
//     embed the run ID or the token kind because the BrokerToken value
//     already carries that metadata; the handle's only job is to be
//     unique within a TokenHolder.
//  5. Revocation is two-phase. The token source's Revoke removes the
//     credential at the issuer; TokenHolder.Forget removes the local
//     copy. The concrete broker invokes both in order; either phase
//     failing is recorded as a warning but does not crash the run
//     (the credential still expires naturally at IssuedAt + TTL).

package githubbroker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// DefaultTokenTTL is the policy-fixed default lifetime the broker asks
// a token issuer for. Plan 07 "Key decisions from master plan" item 10
// pins this at 300 seconds. A token source whose issuer cannot honor
// the request (the GitHub Apps API caps installation tokens at one
// hour regardless of the request) reports back the actual TTL the
// issuer returned; the broker then records that real value in
// BrokerToken.TTL and run.json.
const DefaultTokenTTL = 300 * time.Second

// MaxTokenTTL is the policy ceiling on requested token lifetime. Plan
// 07 fixes it at 1800 seconds (30 minutes). The broker refuses to ask
// an issuer for a credential whose requested TTL exceeds this bound;
// see ClampTTL.
const MaxTokenTTL = 1800 * time.Second

// MinTokenTTL is the floor the broker enforces on requested TTLs. Zero
// or negative is treated as "use DefaultTokenTTL"; anything between
// zero and MinTokenTTL is rounded up so we never hand a caller a token
// that is effectively already expired. The 60s floor matches the
// shortest meaningful lifetime an issuer round trip can produce.
const MinTokenTTL = 60 * time.Second

// ClampTTL applies the policy bounds to a requested token TTL. Zero or
// negative requests get DefaultTokenTTL; requests below MinTokenTTL
// are rounded up; requests above MaxTokenTTL are capped. The function
// is pure (no I/O, no time-of-day reads) so token sources and tests
// can call it without standing up a broker.
//
// The function is exported because both the GitHub App source and the
// PAT source need it, and a future operator-facing CLI flag
// ("--token-ttl 600s") will route through here as well.
func ClampTTL(requested time.Duration) time.Duration {
	if requested <= 0 {
		return DefaultTokenTTL
	}
	if requested < MinTokenTTL {
		return MinTokenTTL
	}
	if requested > MaxTokenTTL {
		return MaxTokenTTL
	}
	return requested
}

// tokenSlot is the per-handle record TokenHolder stores. The secret
// lives in a []byte so Revoke / Forget can overwrite it in place;
// string would leave the backing bytes around for an indeterminate
// time after the assignment.
//
// Concurrency: tokenSlot is only mutated under TokenHolder.mu. A
// caller that obtains a slot reference via TokenHolder.Materialize
// receives a copy of the secret bytes, not a reference into this
// struct, so subsequent Revoke calls do not race with the caller's
// HTTP request.
type tokenSlot struct {
	kind     TokenKind
	secret   []byte
	issuedAt time.Time
	ttl      time.Duration
	revoked  bool
	revokeFn func() error
}

// expiresAt returns the wall-clock cutoff for the slot. Issuers report
// TTL relative to issue time, so the cutoff is the obvious sum. A zero
// TTL is treated as "already expired" so a slot the holder failed to
// populate is never used.
func (s *tokenSlot) expiresAt() time.Time {
	if s.ttl <= 0 {
		return s.issuedAt
	}
	return s.issuedAt.Add(s.ttl)
}

// expired reports whether the slot's TTL has elapsed relative to now.
// now is passed in (rather than calling time.Now inside) so tests can
// pin the comparison without a clock injection on TokenHolder.
func (s *tokenSlot) expired(now time.Time) bool {
	if s.ttl <= 0 {
		return true
	}
	return !now.Before(s.expiresAt())
}

// TokenHolder is the host-side store that maps a BrokerToken.Handle to
// the raw secret the broker is holding for the caller. The concrete
// GitHubBroker constructs one holder per run and threads it through
// AcquireToken / PushBranch / CreateDraftPR / RevokeToken; the CLI and
// the run lifecycle never see the holder directly.
//
// The holder is the single chokepoint that materializes the secret:
// PushBranch and CreateDraftPR call Materialize to embed the credential
// in the outbound HTTP / git transport, RevokeToken calls Forget (after
// invoking the source-specific Revoke) to scrub the in-memory copy.
// Centralizing the access means the rule "no log line, no error
// message, no PR body ever contains the raw secret" reduces to "do not
// pass the bytes returned by Materialize into a logger or a
// user-visible string".
//
// Concurrency: TokenHolder methods are safe for concurrent use. The
// concrete broker is single-goroutine today, but the holder uses a
// mutex so a future async revoke hook (e.g. an `ai-env destroy` that
// races the run finalizer) cannot corrupt the slot map.
type TokenHolder struct {
	mu    sync.Mutex
	slots map[string]*tokenSlot
}

// NewTokenHolder returns an empty holder. The concrete broker
// constructs one per run; tests construct one per test case.
func NewTokenHolder() *TokenHolder {
	return &TokenHolder{slots: map[string]*tokenSlot{}}
}

// Issue records a freshly acquired credential and returns the public
// BrokerToken handle. The raw secret bytes are copied into the holder;
// callers may zero their own copy after Issue returns. revokeFn is the
// issuer-side revocation callback the holder will invoke from Revoke;
// nil means "no issuer revocation available" (PATs typically have no
// programmatic revoke), in which case Revoke still zeroes the local
// copy.
//
// The returned BrokerToken's TTL is ClampTTL(ttl) so a source that
// somehow asked for a longer-than-policy lifetime still surfaces a
// policy-compliant value to run.json. The IssuedAt field reflects the
// holder's wall-clock at Issue time, not the issuer's reported issue
// time, so two slots issued back-to-back are comparable on a single
// process clock.
func (h *TokenHolder) Issue(kind TokenKind, secret []byte, ttl time.Duration, revokeFn func() error) BrokerToken {
	handle := newHandle()
	clamped := ClampTTL(ttl)
	now := time.Now().UTC()

	// Copy the secret so the caller's buffer can be reused / zeroed.
	buf := make([]byte, len(secret))
	copy(buf, secret)

	h.mu.Lock()
	h.slots[handle] = &tokenSlot{
		kind:     kind,
		secret:   buf,
		issuedAt: now,
		ttl:      clamped,
		revokeFn: revokeFn,
	}
	h.mu.Unlock()

	return BrokerToken{
		Kind:     kind,
		Handle:   handle,
		IssuedAt: now,
		TTL:      clamped,
	}
}

// Materialize returns a copy of the raw secret bytes for the slot
// addressed by token.Handle. The caller is expected to use the bytes
// inside a single HTTP request (Authorization header, git push refspec
// URL) and discard them; passing them into a logger, a PR body, or a
// long-lived structure defeats the holder's purpose.
//
// Returns ErrTokenExpired when the slot's TTL has elapsed and
// ErrTokenRevoked when Revoke / Forget already cleared it. The error
// values are the same sentinels GitHubBroker.PushBranch and
// CreateDraftPR are documented to surface, so callers can match with
// errors.Is.
//
// The returned slice is a fresh copy of the slot bytes. A subsequent
// Revoke that zeroes the slot does not affect the returned slice,
// which means a long-running request can complete even if a parallel
// destroy hook invokes Revoke; the caller is responsible for wiping
// its own copy after use.
func (h *TokenHolder) Materialize(token BrokerToken) ([]byte, error) {
	h.mu.Lock()
	slot, ok := h.slots[token.Handle]
	h.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown handle", ErrTokenRevoked)
	}
	if slot.revoked {
		return nil, ErrTokenRevoked
	}
	if slot.expired(time.Now().UTC()) {
		return nil, ErrTokenExpired
	}
	out := make([]byte, len(slot.secret))
	copy(out, slot.secret)
	return out, nil
}

// Revoke invokes the issuer-side revocation callback (if any), zeroes
// the in-memory secret, and marks the slot revoked. Subsequent
// Materialize calls return ErrTokenRevoked.
//
// Revoke is idempotent: calling it on an already-revoked or unknown
// handle is a no-op that returns nil. The plan's "revoke on destroy"
// path can call Revoke multiple times safely (once after CreateDraftPR,
// once again from `ai-env destroy`); the holder collapses repeats.
//
// The error return is the issuer-side error verbatim. The local
// scrub still runs even when the issuer call fails; an upstream that
// refuses revocation does not leave the local copy live. The concrete
// broker logs the error as a warning per plan 07 step 8.
func (h *TokenHolder) Revoke(token BrokerToken) error {
	h.mu.Lock()
	slot, ok := h.slots[token.Handle]
	if !ok {
		h.mu.Unlock()
		return nil
	}
	if slot.revoked {
		h.mu.Unlock()
		return nil
	}
	fn := slot.revokeFn
	// Capture the secret so we can zero it after the unlock; we do not
	// want to hold the mutex across a network round trip.
	h.mu.Unlock()

	var issuerErr error
	if fn != nil {
		issuerErr = fn()
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	// Re-resolve in case Forget raced us; the second lookup is the
	// cheapest way to keep Revoke idempotent without a separate
	// "revoking" intermediate state.
	if slot, ok = h.slots[token.Handle]; !ok || slot.revoked {
		return issuerErr
	}
	zeroBytes(slot.secret)
	slot.secret = nil
	slot.revoked = true
	return issuerErr
}

// Forget drops the slot entirely without invoking the issuer-side
// revocation callback. The secret is zeroed first so a stale reference
// in the slot map cannot leak the bytes. Forget is the cleanup hook
// the broker calls when it knows the credential will not be reused
// (e.g. after Revoke succeeded, or at the end of a run that never
// reached the broker step).
//
// Returns true when a slot was actually dropped, false when the handle
// was unknown. Forget is safe to call repeatedly.
func (h *TokenHolder) Forget(token BrokerToken) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	slot, ok := h.slots[token.Handle]
	if !ok {
		return false
	}
	zeroBytes(slot.secret)
	slot.secret = nil
	slot.revoked = true
	delete(h.slots, token.Handle)
	return true
}

// ForgetAll zeroes and drops every slot the holder owns. The concrete
// broker calls it from a deferred cleanup so a panic between
// AcquireToken and CreateDraftPR still scrubs the in-memory secret.
// Returns the number of slots that were dropped.
func (h *TokenHolder) ForgetAll() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for handle, slot := range h.slots {
		zeroBytes(slot.secret)
		slot.secret = nil
		slot.revoked = true
		delete(h.slots, handle)
		n++
	}
	return n
}

// Inspect returns the lifecycle metadata for the slot addressed by
// token.Handle. The raw secret is never returned; the inspector is for
// run.json recording and "ai-env status" rendering. Returns false for
// an unknown handle so the caller can render "no token" rather than
// panicking.
//
// The reported fields mirror BrokerToken: Kind, IssuedAt, TTL, plus a
// derived ExpiresAt and a Revoked flag. The IssuedAt / TTL pair is the
// same one plan 07 step 8 wants recorded in run.json.
func (h *TokenHolder) Inspect(token BrokerToken) (TokenStatus, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	slot, ok := h.slots[token.Handle]
	if !ok {
		return TokenStatus{}, false
	}
	return TokenStatus{
		Kind:      slot.kind,
		IssuedAt:  slot.issuedAt,
		TTL:       slot.ttl,
		ExpiresAt: slot.expiresAt(),
		Revoked:   slot.revoked,
		Expired:   slot.expired(time.Now().UTC()),
	}, true
}

// TokenStatus is the lifecycle snapshot Inspect returns. It is the
// shape the run lifecycle marshals into run.json's `broker.token`
// block; the field names match the JSON keys plan 07 step 8 names so
// the marshal is a straight tagged-struct write at the lifecycle
// layer.
type TokenStatus struct {
	Kind      TokenKind     `json:"kind"`
	IssuedAt  time.Time     `json:"issued_at"`
	TTL       time.Duration `json:"ttl"`
	ExpiresAt time.Time     `json:"expires_at"`
	Revoked   bool          `json:"revoked"`
	Expired   bool          `json:"expired"`
}

// newHandle returns a random 16-byte hex string the broker uses as the
// public BrokerToken.Handle. crypto/rand is the source so the handle
// cannot be guessed by an attacker who somehow sees one handle and
// wants to address another slot. The 16-byte width gives 2^128 distinct
// handles, comfortably more than the per-process slot count.
//
// On the (effectively impossible) event that crypto/rand fails, the
// fallback returns a timestamp-prefixed handle so the broker still
// makes progress; the issuer's TTL bound is the security backstop
// either way.
func newHandle() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("handle-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

// zeroBytes overwrites b in place with zeros. The compiler is allowed
// to optimize away a "buf = nil" assignment, so the explicit loop is
// the portable best-effort scrub. Callers wipe slot.secret with this
// before releasing the slot.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
