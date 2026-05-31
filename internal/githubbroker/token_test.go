// token_test.go covers the pure logic in token.go: the policy-bound
// TTL clamp, the TokenHolder issuance / materialize / revoke / forget
// lifecycle, and the lifecycle-snapshot Inspect surface that plan 07
// step 8 demands for run.json. These tests are intentionally scoped to
// the host-side primitives; the broker-level integration tests land in
// plan 07 batch 8.

package githubbroker

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

// TestClampTTL_AppliesPolicyBounds pins the policy-fixed bounds:
// requests below MinTokenTTL round up, requests above MaxTokenTTL get
// capped, zero / negative falls back to DefaultTokenTTL.
func TestClampTTL_AppliesPolicyBounds(t *testing.T) {
	cases := []struct {
		name     string
		in       time.Duration
		want     time.Duration
	}{
		{"zero falls back to default", 0, DefaultTokenTTL},
		{"negative falls back to default", -1 * time.Second, DefaultTokenTTL},
		{"below floor rounds up", 1 * time.Second, MinTokenTTL},
		{"at floor passes through", MinTokenTTL, MinTokenTTL},
		{"between floor and ceiling passes through", 5 * time.Minute, 5 * time.Minute},
		{"at ceiling passes through", MaxTokenTTL, MaxTokenTTL},
		{"above ceiling caps to max", 2 * MaxTokenTTL, MaxTokenTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClampTTL(tc.in)
			if got != tc.want {
				t.Fatalf("ClampTTL(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestTokenHolder_IssueMaterializeRoundTrip pins the basic happy path:
// Issue records a slot, the returned BrokerToken does NOT carry the
// secret, and Materialize hands back a copy of the bytes.
func TestTokenHolder_IssueMaterializeRoundTrip(t *testing.T) {
	h := NewTokenHolder()
	secret := []byte("ghs_fake_installation_token_payload")
	tok := h.Issue(TokenKindGitHubApp, secret, 5*time.Minute, nil)

	if tok.Handle == "" {
		t.Fatal("Issue returned an empty handle")
	}
	if tok.Kind != TokenKindGitHubApp {
		t.Fatalf("Issue kind = %v, want %v", tok.Kind, TokenKindGitHubApp)
	}
	if tok.TTL != 5*time.Minute {
		t.Fatalf("Issue TTL = %v, want 5m", tok.TTL)
	}
	if tok.IssuedAt.IsZero() {
		t.Fatal("Issue IssuedAt is zero")
	}

	got, err := h.Materialize(tok)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("Materialize returned %q, want %q", got, secret)
	}

	// Mutating the caller's copy of secret must not affect the holder.
	secret[0] = 0
	got2, err := h.Materialize(tok)
	if err != nil {
		t.Fatalf("second Materialize: %v", err)
	}
	if got2[0] == 0 {
		t.Fatal("holder slot was mutated by caller's secret buffer")
	}
}

// TestTokenHolder_HandlesAreOpaqueAndUnique pins the security
// property that two Issue calls produce distinct opaque handles.
func TestTokenHolder_HandlesAreOpaqueAndUnique(t *testing.T) {
	h := NewTokenHolder()
	a := h.Issue(TokenKindGitHubApp, []byte("a"), 0, nil)
	b := h.Issue(TokenKindGitHubApp, []byte("b"), 0, nil)
	if a.Handle == b.Handle {
		t.Fatalf("Issue produced colliding handles: %q", a.Handle)
	}
	// Default TTL applies when 0 is passed.
	if a.TTL != DefaultTokenTTL || b.TTL != DefaultTokenTTL {
		t.Fatalf("Issue did not apply DefaultTokenTTL: a=%v b=%v", a.TTL, b.TTL)
	}
}

// TestTokenHolder_ClampsTTLOnIssue pins that the operator-visible
// BrokerToken.TTL is always within policy bounds, even if the source
// reports something the policy would not allow.
func TestTokenHolder_ClampsTTLOnIssue(t *testing.T) {
	h := NewTokenHolder()
	// An issuer that returns an absurd 24h TTL must be capped.
	tok := h.Issue(TokenKindGitHubApp, []byte("x"), 24*time.Hour, nil)
	if tok.TTL != MaxTokenTTL {
		t.Fatalf("Issue TTL = %v, want %v (capped)", tok.TTL, MaxTokenTTL)
	}
}

// TestTokenHolder_MaterializeAfterRevokeFails pins the revocation
// contract: once Revoke runs, Materialize must return ErrTokenRevoked.
func TestTokenHolder_MaterializeAfterRevokeFails(t *testing.T) {
	h := NewTokenHolder()
	tok := h.Issue(TokenKindGitHubApp, []byte("ghs_secret"), 5*time.Minute, nil)
	if err := h.Revoke(tok); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err := h.Materialize(tok)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Materialize after Revoke err = %v, want ErrTokenRevoked", err)
	}
}

// TestTokenHolder_RevokeInvokesIssuerCallback pins that Revoke calls
// the source-supplied revokeFn exactly once and surfaces its error to
// the caller.
func TestTokenHolder_RevokeInvokesIssuerCallback(t *testing.T) {
	h := NewTokenHolder()
	calls := 0
	wantErr := errors.New("issuer rejected")
	tok := h.Issue(TokenKindGitHubApp, []byte("x"), 5*time.Minute, func() error {
		calls++
		return wantErr
	})

	if err := h.Revoke(tok); !errors.Is(err, wantErr) {
		t.Fatalf("Revoke err = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Fatalf("revokeFn calls = %d, want 1", calls)
	}

	// A second Revoke is a no-op: the callback must not be invoked
	// again and the call must not error.
	if err := h.Revoke(tok); err != nil {
		t.Fatalf("second Revoke err = %v, want nil", err)
	}
	if calls != 1 {
		t.Fatalf("revokeFn was invoked again on idempotent Revoke (calls=%d)", calls)
	}
}

// TestTokenHolder_RevokeUnknownHandleIsNoop pins idempotency for the
// "destroy hook fires before AcquireToken ever ran" path.
func TestTokenHolder_RevokeUnknownHandleIsNoop(t *testing.T) {
	h := NewTokenHolder()
	tok := BrokerToken{Kind: TokenKindGitHubApp, Handle: "deadbeef"}
	if err := h.Revoke(tok); err != nil {
		t.Fatalf("Revoke unknown handle: %v", err)
	}
}

// TestTokenHolder_ForgetScrubsLocalCopy pins that Forget zeroes the
// slot's secret bytes in place. We test the externally observable
// effect: Materialize after Forget returns ErrTokenRevoked, and a
// subsequent Issue with the same handle space still works.
func TestTokenHolder_ForgetScrubsLocalCopy(t *testing.T) {
	h := NewTokenHolder()
	tok := h.Issue(TokenKindGitHubApp, []byte("x"), 5*time.Minute, nil)
	if !h.Forget(tok) {
		t.Fatal("Forget reported no slot dropped")
	}
	if _, err := h.Materialize(tok); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Materialize after Forget = %v, want ErrTokenRevoked", err)
	}
	if h.Forget(tok) {
		t.Fatal("Forget reported a slot dropped on the second call")
	}
}

// TestTokenHolder_ForgetAllScrubsAllSlots pins the panic-defer path:
// a broker that panics between AcquireToken and CreateDraftPR must be
// able to scrub every outstanding credential with one call.
func TestTokenHolder_ForgetAllScrubsAllSlots(t *testing.T) {
	h := NewTokenHolder()
	a := h.Issue(TokenKindGitHubApp, []byte("a"), 5*time.Minute, nil)
	b := h.Issue(TokenKindPersonalAccessToken, []byte("b"), 5*time.Minute, nil)
	n := h.ForgetAll()
	if n != 2 {
		t.Fatalf("ForgetAll dropped %d slots, want 2", n)
	}
	for _, tok := range []BrokerToken{a, b} {
		if _, err := h.Materialize(tok); !errors.Is(err, ErrTokenRevoked) {
			t.Fatalf("Materialize after ForgetAll = %v, want ErrTokenRevoked", err)
		}
	}
}

// TestTokenHolder_ExpiredSlotReturnsExpired pins the TTL contract:
// once IssuedAt + TTL has elapsed, Materialize returns ErrTokenExpired
// rather than the secret bytes.
func TestTokenHolder_ExpiredSlotReturnsExpired(t *testing.T) {
	h := NewTokenHolder()
	// Use the minimum TTL so the test does not have to wait long.
	tok := h.Issue(TokenKindGitHubApp, []byte("x"), MinTokenTTL, nil)
	// Manually backdate the slot so the test does not actually have to
	// sleep MinTokenTTL.
	h.mu.Lock()
	slot := h.slots[tok.Handle]
	slot.issuedAt = time.Now().UTC().Add(-2 * MinTokenTTL)
	h.mu.Unlock()

	_, err := h.Materialize(tok)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Materialize on expired slot = %v, want ErrTokenExpired", err)
	}
}

// TestTokenHolder_InspectReportsLifecycle pins the run.json snapshot
// contract: Inspect returns Kind, IssuedAt, TTL, ExpiresAt, Revoked,
// Expired without leaking the secret.
func TestTokenHolder_InspectReportsLifecycle(t *testing.T) {
	h := NewTokenHolder()
	tok := h.Issue(TokenKindGitHubApp, []byte("x"), 5*time.Minute, nil)

	st, ok := h.Inspect(tok)
	if !ok {
		t.Fatal("Inspect reported unknown handle for a freshly issued token")
	}
	if st.Kind != TokenKindGitHubApp {
		t.Fatalf("Inspect kind = %v, want %v", st.Kind, TokenKindGitHubApp)
	}
	if st.TTL != 5*time.Minute {
		t.Fatalf("Inspect TTL = %v, want 5m", st.TTL)
	}
	if st.ExpiresAt.Sub(st.IssuedAt) != 5*time.Minute {
		t.Fatalf("Inspect ExpiresAt - IssuedAt = %v, want 5m", st.ExpiresAt.Sub(st.IssuedAt))
	}
	if st.Revoked || st.Expired {
		t.Fatalf("Inspect Revoked=%v Expired=%v, want both false", st.Revoked, st.Expired)
	}

	if err := h.Revoke(tok); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	st, ok = h.Inspect(tok)
	if !ok {
		t.Fatal("Inspect reported unknown handle after Revoke (should still be addressable)")
	}
	if !st.Revoked {
		t.Fatal("Inspect Revoked=false after Revoke")
	}
}

// TestTokenHolder_InspectUnknownHandleReportsFalse pins the safe-fall
// path the CLI uses when rendering "ai-env status" for a run whose
// broker step never reached AcquireToken.
func TestTokenHolder_InspectUnknownHandleReportsFalse(t *testing.T) {
	h := NewTokenHolder()
	tok := BrokerToken{Kind: TokenKindGitHubApp, Handle: "nope"}
	if _, ok := h.Inspect(tok); ok {
		t.Fatal("Inspect reported a slot for an unknown handle")
	}
}

// TestBrokerToken_DoesNotCarrySecret is a structural assertion: the
// public BrokerToken type must not include any field that holds the
// raw secret. The test enumerates the struct's fields via reflect so a
// future refactor that adds a "Secret string" field lights up here and
// forces a deliberate review.
func TestBrokerToken_DoesNotCarrySecret(t *testing.T) {
	wantFields := map[string]bool{
		"Kind":     false,
		"Handle":   false,
		"IssuedAt": false,
		"TTL":      false,
	}
	tt := reflect.TypeOf(BrokerToken{})
	for i := 0; i < tt.NumField(); i++ {
		name := tt.Field(i).Name
		if _, ok := wantFields[name]; !ok {
			t.Fatalf("BrokerToken has unexpected field %q; verify it is not a secret leak", name)
		}
		wantFields[name] = true
	}
	for name, seen := range wantFields {
		if !seen {
			t.Fatalf("BrokerToken is missing expected field %q", name)
		}
	}
}
