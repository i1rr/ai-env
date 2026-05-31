// auth_test.go covers plan 07 step 7's token-source surfaces:
// SelectTokenSource's precedence rule, the GitHub App installation
// flow's JWT shape and revoke contract, and the PAT fallback's
// development-only opt-in semantics. The HTTP round-trip is exercised
// with an httptest.Server so the test stays self-contained; broker-
// level integration tests land in plan 07 batch 8.

package githubbroker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// generateTestRSAKey returns a fresh 2048-bit RSA key and its PKCS#1
// PEM encoding. 2048 bits is the smallest size GitHub Apps accept and
// is comfortably fast enough for a unit test (key gen is the
// dominant cost).
func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return key, pemBytes
}

// pkcs8PEM re-encodes key as a PKCS#8 PEM block so the
// parser can be exercised on both shapes.
func pkcs8PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// TestParseRSAPrivateKey_AcceptsPKCS1AndPKCS8 pins that both PEM
// encodings GitHub Apps export are accepted. A regression that drops
// one would silently lock operators out of half the App download menu.
func TestParseRSAPrivateKey_AcceptsPKCS1AndPKCS8(t *testing.T) {
	key, pkcs1 := generateTestRSAKey(t)
	pkcs8 := pkcs8PEM(t, key)

	for _, tc := range []struct {
		name string
		pem  []byte
	}{
		{"pkcs1", pkcs1},
		{"pkcs8", pkcs8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseRSAPrivateKey(tc.pem)
			if err != nil {
				t.Fatalf("parseRSAPrivateKey: %v", err)
			}
			if parsed.N.Cmp(key.N) != 0 {
				t.Fatal("parsed key modulus does not match original")
			}
		})
	}
}

// TestParseRSAPrivateKey_RejectsGarbage pins the negative path so an
// operator who pastes the wrong file sees a clean error instead of a
// nil-deref panic later.
func TestParseRSAPrivateKey_RejectsGarbage(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"not pem", []byte("hello world")},
		{"wrong block type", []byte("-----BEGIN CERTIFICATE-----\nABC=\n-----END CERTIFICATE-----\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRSAPrivateKey(tc.in); err == nil {
				t.Fatal("parseRSAPrivateKey accepted garbage")
			}
		})
	}
}

// TestNewGitHubAppSource_ValidatesConfig pins the construction-time
// validation. Each case omits one required field and expects an error
// so the broker fails fast on misconfiguration.
func TestNewGitHubAppSource_ValidatesConfig(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)
	cases := []struct {
		name string
		cfg  GitHubAppConfig
	}{
		{"no app id", GitHubAppConfig{InstallationID: 1, PrivateKeyPEM: pemBytes}},
		{"no installation id", GitHubAppConfig{AppID: 1, PrivateKeyPEM: pemBytes}},
		{"no key", GitHubAppConfig{AppID: 1, InstallationID: 1}},
		{"bad key", GitHubAppConfig{AppID: 1, InstallationID: 1, PrivateKeyPEM: []byte("nope")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewGitHubAppSource(tc.cfg); err == nil {
				t.Fatal("NewGitHubAppSource accepted invalid config")
			}
		})
	}
}

// TestGitHubAppSource_Acquire_RoundTrip pins the App flow end-to-end
// against a stub upstream:
//
//   - The POST hits the installation-token endpoint.
//   - The Authorization header carries a Bearer JWT whose signature
//     verifies against the App's public key and whose claims match
//     GitHub's documented shape (iss=AppID, exp > iat).
//   - The returned secret bytes and TTL match what the API returned.
//   - The revoke callback DELETEs the installation token and the
//     callback's local copy of the token is zeroed afterwards.
func TestGitHubAppSource_Acquire_RoundTrip(t *testing.T) {
	key, pemBytes := generateTestRSAKey(t)

	var (
		acquireCalls atomic.Int32
		revokeCalls  atomic.Int32
		gotAuth      atomic.Value // last Authorization header value
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/access_tokens"):
			acquireCalls.Add(1)
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			jwt := strings.TrimPrefix(auth, "Bearer ")
			if err := verifyAppJWT(jwt, key, 1234); err != nil {
				t.Errorf("JWT verification: %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// Return a fixed token and an expiry 10 minutes from now.
			resp := map[string]any{
				"token":      "ghs_FAKE_INSTALLATION_TOKEN",
				"expires_at": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/installation/token"):
			revokeCalls.Add(1)
			gotAuth.Store(r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	src, err := NewGitHubAppSource(GitHubAppConfig{
		AppID:          1234,
		InstallationID: 5678,
		PrivateKeyPEM:  pemBytes,
		APIBaseURL:     srv.URL,
		HTTPClient:     srv.Client(),
		Clock:          func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewGitHubAppSource: %v", err)
	}

	if src.Kind() != TokenKindGitHubApp {
		t.Fatalf("Kind = %v, want %v", src.Kind(), TokenKindGitHubApp)
	}

	secret, ttl, revoke, err := src.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if string(secret) != "ghs_FAKE_INSTALLATION_TOKEN" {
		t.Fatalf("Acquire returned %q, want ghs_FAKE_INSTALLATION_TOKEN", secret)
	}
	if ttl <= 0 || ttl > 11*time.Minute {
		t.Fatalf("Acquire TTL = %v, want roughly 10m", ttl)
	}
	if acquireCalls.Load() != 1 {
		t.Fatalf("acquire calls = %d, want 1", acquireCalls.Load())
	}

	if err := revoke(); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revokeCalls.Load() != 1 {
		t.Fatalf("revoke calls = %d, want 1", revokeCalls.Load())
	}
	gotAuthStr, _ := gotAuth.Load().(string)
	if !strings.Contains(gotAuthStr, "ghs_FAKE_INSTALLATION_TOKEN") {
		t.Fatalf("revoke Authorization header = %q, want it to carry the installation token", gotAuthStr)
	}
}

// TestGitHubAppSource_Acquire_FailsOnNon2xx pins the negative path:
// a non-success HTTP status from GitHub is reported back without
// quoting the body (which could carry sensitive material).
func TestGitHubAppSource_Acquire_FailsOnNon2xx(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a body that contains a token-shaped string; the
		// error must not echo it.
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"sk-ant-leak","token":"sk-ant-leak"}`)
	}))
	defer srv.Close()

	src, err := NewGitHubAppSource(GitHubAppConfig{
		AppID:          1,
		InstallationID: 1,
		PrivateKeyPEM:  pemBytes,
		APIBaseURL:     srv.URL,
		HTTPClient:     srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewGitHubAppSource: %v", err)
	}

	_, _, _, err = src.Acquire(context.Background())
	if err == nil {
		t.Fatal("Acquire succeeded against 403")
	}
	if strings.Contains(err.Error(), "sk-ant-leak") {
		t.Fatalf("error message leaked response body: %q", err.Error())
	}
}

// TestGitHubAppSource_Revoke_401IsNoop pins that an already-expired
// token at GitHub returns nil from revoke so the broker's idempotent
// destroy path stays clean.
func TestGitHubAppSource_Revoke_401IsNoop(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"ghs_x","expires_at":"`+time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339)+`"}`)
		case http.MethodDelete:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	src, err := NewGitHubAppSource(GitHubAppConfig{
		AppID:          1,
		InstallationID: 1,
		PrivateKeyPEM:  pemBytes,
		APIBaseURL:     srv.URL,
		HTTPClient:     srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewGitHubAppSource: %v", err)
	}
	_, _, revoke, err := src.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := revoke(); err != nil {
		t.Fatalf("revoke on 401 = %v, want nil (idempotent)", err)
	}
}

// TestNewPATSource_ValidatesConfig pins the gating: PAT cannot be
// constructed unless explicitly enabled and Token is non-empty.
func TestNewPATSource_ValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  PATConfig
	}{
		{"disabled", PATConfig{Token: "ghp_x"}},
		{"empty token", PATConfig{Enabled: true, Token: ""}},
		{"whitespace token", PATConfig{Enabled: true, Token: "   "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPATSource(tc.cfg); err == nil {
				t.Fatal("NewPATSource accepted invalid config")
			}
		})
	}
}

// TestPATSource_AcquireReturnsCopy pins the per-Acquire copy
// behaviour: mutating the returned slice must not affect a subsequent
// Acquire, and the source's internal buffer survives until Forget.
func TestPATSource_AcquireReturnsCopy(t *testing.T) {
	src, err := NewPATSource(PATConfig{Enabled: true, Token: "ghp_secret"})
	if err != nil {
		t.Fatalf("NewPATSource: %v", err)
	}
	got1, _, revoke, err := src.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if string(got1) != "ghp_secret" {
		t.Fatalf("Acquire returned %q, want ghp_secret", got1)
	}
	if err := revoke(); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Mutate the returned slice; the source's internal buffer must
	// not be affected.
	got1[0] = 'X'

	got2, _, _, err := src.Acquire(context.Background())
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	if string(got2) != "ghp_secret" {
		t.Fatalf("second Acquire returned %q, want ghp_secret", got2)
	}

	src.Forget()
	if _, _, _, err := src.Acquire(context.Background()); err == nil {
		t.Fatal("Acquire after Forget did not error")
	}
}

// TestPATSource_TTLPassesThroughToHolder pins that PAT TTL configured
// on the source is honoured: the holder's ClampTTL then bounds it,
// but the source itself reports the configured value.
func TestPATSource_TTLPassesThroughToHolder(t *testing.T) {
	src, err := NewPATSource(PATConfig{Enabled: true, Token: "ghp_x", TTL: 7 * time.Minute})
	if err != nil {
		t.Fatalf("NewPATSource: %v", err)
	}
	_, ttl, _, err := src.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if ttl != 7*time.Minute {
		t.Fatalf("Acquire ttl = %v, want 7m", ttl)
	}
}

// TestSelectTokenSource_PrefersApp pins the precedence rule: a
// configured App wins even when a PAT is also enabled, matching plan
// 07's "preferred credential type" decision.
func TestSelectTokenSource_PrefersApp(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)
	app := &GitHubAppConfig{
		AppID:          1,
		InstallationID: 1,
		PrivateKeyPEM:  pemBytes,
	}
	pat := &PATConfig{Enabled: true, Token: "ghp_x"}

	src, err := SelectTokenSource(SelectorConfig{App: app, PAT: pat})
	if err != nil {
		t.Fatalf("SelectTokenSource: %v", err)
	}
	if src.Kind() != TokenKindGitHubApp {
		t.Fatalf("selected kind = %v, want %v", src.Kind(), TokenKindGitHubApp)
	}
}

// TestSelectTokenSource_FallsBackToPAT pins that the PAT path is
// chosen when the App is not configured.
func TestSelectTokenSource_FallsBackToPAT(t *testing.T) {
	pat := &PATConfig{Enabled: true, Token: "ghp_x"}
	src, err := SelectTokenSource(SelectorConfig{PAT: pat})
	if err != nil {
		t.Fatalf("SelectTokenSource: %v", err)
	}
	if src.Kind() != TokenKindPersonalAccessToken {
		t.Fatalf("selected kind = %v, want %v", src.Kind(), TokenKindPersonalAccessToken)
	}
}

// TestSelectTokenSource_NoSourceErrors pins the safety rule: an empty
// selector returns ErrNoTokenSource so the CLI can render a clear
// "configure a credential" hint.
func TestSelectTokenSource_NoSourceErrors(t *testing.T) {
	_, err := SelectTokenSource(SelectorConfig{})
	if !errors.Is(err, ErrNoTokenSource) {
		t.Fatalf("SelectTokenSource err = %v, want ErrNoTokenSource", err)
	}
	// A PAT block present but Enabled=false also produces the no-source
	// error: the operator must opt in explicitly.
	_, err = SelectTokenSource(SelectorConfig{PAT: &PATConfig{Enabled: false, Token: "ghp_x"}})
	if !errors.Is(err, ErrNoTokenSource) {
		t.Fatalf("SelectTokenSource (disabled PAT) err = %v, want ErrNoTokenSource", err)
	}
}

// TestSelectTokenSource_MalformedAppErrors pins the security rule:
// a malformed App must not silently fall back to PAT (would degrade
// security expectations). The selector surfaces the App construction
// error verbatim.
func TestSelectTokenSource_MalformedAppErrors(t *testing.T) {
	app := &GitHubAppConfig{AppID: 1, InstallationID: 1, PrivateKeyPEM: []byte("nope")}
	pat := &PATConfig{Enabled: true, Token: "ghp_x"}
	_, err := SelectTokenSource(SelectorConfig{App: app, PAT: pat})
	if err == nil {
		t.Fatal("SelectTokenSource with malformed App did not error")
	}
	if errors.Is(err, ErrNoTokenSource) {
		t.Fatal("SelectTokenSource silently fell back to PAT on malformed App")
	}
}

// verifyAppJWT parses jwt, checks the claims against expectedIss, and
// verifies the RS256 signature with the supplied key's public half.
// Used by the App round-trip test to assert the JWT the source signed
// matches GitHub's expectations.
func verifyAppJWT(jwt string, key *rsa.PrivateKey, expectedIss int64) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return fmt.Errorf("expected 3 JWT segments, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("unmarshal header: %w", err)
	}
	if header.Alg != "RS256" {
		return fmt.Errorf("alg = %q, want RS256", header.Alg)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}
	var claims struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
		Iss int64 `json:"iss"`
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return fmt.Errorf("unmarshal claims: %w", err)
	}
	if claims.Iss != expectedIss {
		return fmt.Errorf("iss = %d, want %d", claims.Iss, expectedIss)
	}
	if claims.Exp <= claims.Iat {
		return fmt.Errorf("exp (%d) must be > iat (%d)", claims.Exp, claims.Iat)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], sig); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}

