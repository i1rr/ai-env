// auth.go implements plan 07 step 7: the GitHub App installation token
// flow (the primary credential path) and the PAT fallback (development
// only). Both paths funnel through a single TokenSource interface so
// the concrete GitHubBroker can stay agnostic about which credential
// type backs a given run; selection happens once at construction time
// via SelectTokenSource, and the rest of the broker only sees Acquire
// / Revoke calls.
//
// The plan calls the rule out in two places:
//
//  1. "Key decisions from master plan", item 2: "Preferred credential
//     type: GitHub App installation token (short-lived, repo-scoped)."
//  2. Step 7: "Implement GitHub App installation token flow (primary).
//     Add PAT fallback for development."
//
// Design rules this file pins:
//
//  1. The raw token never crosses into the sandbox and never appears
//     in a log line or PR body. Acquire returns a []byte the caller
//     immediately hands to TokenHolder.Issue, which copies it into the
//     holder and lets the source's local copy be zeroed. The source
//     itself does not retain the materialized token; the holder is
//     the single chokepoint.
//  2. The GitHub App flow uses only the standard library. The plan
//     does not budget a third-party JWT or GitHub SDK dependency, and
//     RS256 over a JSON payload is a few dozen lines of crypto/rsa +
//     encoding/base64 + crypto/sha256. Keeping the dependency surface
//     narrow matches the rest of the project (no go-github, no jwt-go).
//  3. The PAT path is gated behind explicit opt-in. PATConfig.Enabled
//     must be true and a non-empty Token must be supplied; the
//     selector refuses to silently fall back to PAT if a GitHub App
//     is configured but malformed. This matches plan 07 step 7's
//     "Add PAT fallback for development" intent: the fallback is a
//     developer convenience, not a silent compatibility shim.
//  4. TokenSource is a narrow interface (Acquire / Revoke / Kind).
//     Tests inject a fake to drive the broker's token lifecycle
//     without standing up an HTTP server. The concrete sources
//     accept an HTTP client so a future test that wants to exercise
//     the network path against a httptest.Server can do so.
//  5. Revoke is best-effort. The plan documents revocation as
//     "attempt revocation after PR creation; fail with warning if
//     revocation fails." Both sources return the issuer's error
//     verbatim so the broker can log a warning, and the TokenHolder
//     scrubs the local copy regardless of issuer response.

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
	"strings"
	"time"
)

// TokenSource is the contract every credential issuer implements. The
// concrete GitHubBroker holds one source per run; AcquireToken delegates
// to source.Acquire, RevokeToken delegates to source.Revoke (after
// TokenHolder has the bytes; the holder closes over the source's Revoke
// via a revokeFn callback when it stores the slot).
//
// Implementations must:
//
//   - Return a fresh credential per Acquire call (no caching across
//     calls; the broker's "rotate per action" rule depends on a new
//     token per run).
//   - Bound the returned TTL by their issuer's contract; the holder's
//     ClampTTL is the policy-side ceiling, but the issuer's own bound
//     (e.g. GitHub Apps cap installation tokens at 3600s) takes
//     precedence.
//   - Treat Revoke as idempotent at the protocol level: a second call
//     for an already-revoked credential must not return an error the
//     broker would surface as a hard failure.
type TokenSource interface {
	// Kind reports the token kind this source issues. The concrete
	// broker stamps it onto BrokerToken so the CLI can render it in
	// `ai-env status`.
	Kind() TokenKind

	// Acquire obtains a fresh credential and returns the raw secret
	// bytes, the TTL the issuer reported, and the issuer-side revoke
	// callback the holder should invoke when the broker revokes the
	// token. The caller is expected to immediately hand the bytes to
	// TokenHolder.Issue and discard its own reference; the source does
	// not retain the bytes.
	//
	// The returned revokeFn closure is called by TokenHolder.Revoke
	// without arguments because the source already has the protocol-
	// level identifier (the JWT, the installation ID, the token itself)
	// captured at Acquire time. The closure returns the issuer's error
	// verbatim so the broker can log a warning.
	Acquire(ctx context.Context) (secret []byte, ttl time.Duration, revokeFn func() error, err error)
}

// GitHubAppConfig configures GitHubAppSource. Plan 07 step 7's primary
// path is the GitHub App flow; this struct captures the four
// parameters the App API needs:
//
//   - AppID: the integer App ID GitHub assigns when the App is
//     registered. Used as the JWT "iss" claim.
//   - InstallationID: the integer Installation ID for the target
//     repository. The installation token endpoint is per-installation,
//     not per-repo, but the broker's Repo identifies which installation
//     to use.
//   - PrivateKeyPEM: the PEM-encoded RSA private key the App uses to
//     sign the JWT. The bytes are held in memory for the lifetime of
//     the source; the source zeroes its copy in Revoke when the
//     broker's run finalizer tears it down.
//   - APIBaseURL: the GitHub REST API base URL. Defaults to
//     https://api.github.com when empty so the common case stays
//     terse; GHE callers pin their own URL.
//
// The TTL the App API returns is currently a fixed 3600s; the broker
// applies its own ClampTTL on the way into the holder so the operator-
// visible TTL never exceeds MaxTokenTTL.
type GitHubAppConfig struct {
	AppID          int64
	InstallationID int64
	PrivateKeyPEM  []byte
	APIBaseURL     string

	// HTTPClient is the http.Client used for the installation-token
	// POST and the revoke DELETE. Nil falls back to a client with a
	// 30-second timeout. Tests pin a custom client to point at an
	// httptest.Server.
	HTTPClient *http.Client

	// Clock returns the current time. Nil falls back to time.Now. The
	// JWT issued by Acquire uses this for the iat / exp claims; tests
	// pin a deterministic clock so the JWT bytes are reproducible.
	Clock func() time.Time
}

// GitHubAppSource issues GitHub App installation tokens. Construct one
// via NewGitHubAppSource; the broker calls Acquire once per run and
// the holder invokes the source's Revoke callback (via the closure
// returned from Acquire) when the run finalizer tears down.
//
// The source is goroutine-safe: a future async destroy hook can race
// the run finalizer without corrupting state. The internal private
// key bytes are held in memory for the source's lifetime; ZeroKey
// scrubs them when the broker is sure no further Acquire calls will
// happen.
type GitHubAppSource struct {
	cfg        GitHubAppConfig
	privateKey *rsa.PrivateKey
	httpClient *http.Client
	clock      func() time.Time
}

// NewGitHubAppSource validates cfg and returns a configured source.
// The PEM bytes are parsed once and the *rsa.PrivateKey is cached so
// every Acquire call signs without re-parsing.
//
// Returns an error when AppID or InstallationID is zero (the GitHub
// API would reject the call), when PrivateKeyPEM is empty or not a
// valid RSA PEM, or when APIBaseURL is set but malformed.
func NewGitHubAppSource(cfg GitHubAppConfig) (*GitHubAppSource, error) {
	if cfg.AppID <= 0 {
		return nil, errors.New("githubbroker: GitHubAppConfig.AppID must be > 0")
	}
	if cfg.InstallationID <= 0 {
		return nil, errors.New("githubbroker: GitHubAppConfig.InstallationID must be > 0")
	}
	if len(cfg.PrivateKeyPEM) == 0 {
		return nil, errors.New("githubbroker: GitHubAppConfig.PrivateKeyPEM is empty")
	}
	key, err := parseRSAPrivateKey(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("githubbroker: parse GitHub App private key: %w", err)
	}
	if strings.TrimSpace(cfg.APIBaseURL) == "" {
		cfg.APIBaseURL = "https://api.github.com"
	}
	cfg.APIBaseURL = strings.TrimRight(cfg.APIBaseURL, "/")

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	return &GitHubAppSource{
		cfg:        cfg,
		privateKey: key,
		httpClient: client,
		clock:      clock,
	}, nil
}

// Kind reports TokenKindGitHubApp.
func (s *GitHubAppSource) Kind() TokenKind { return TokenKindGitHubApp }

// Acquire signs a fresh App JWT and exchanges it for an installation
// token. Returns the raw token bytes, the TTL the API reported (or
// DefaultTokenTTL if the API omitted an expiry), and a revoke callback
// that DELETEs the installation token at the API.
//
// The JWT iat claim is now-60s (per GitHub's "allow for clock skew"
// guidance) and the exp claim is now+9min (App JWTs are capped at 10
// minutes; 9 leaves headroom for a slow client clock).
func (s *GitHubAppSource) Acquire(ctx context.Context) ([]byte, time.Duration, func() error, error) {
	jwt, err := s.signAppJWT()
	if err != nil {
		return nil, 0, nil, fmt.Errorf("githubbroker: sign App JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", s.cfg.APIBaseURL, s.cfg.InstallationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("githubbroker: build installation-token request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("githubbroker: installation-token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("githubbroker: read installation-token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Do NOT include the response body in the error: GitHub error
		// payloads typically do not echo the token but a future API
		// change could; keep the failure message status-only.
		return nil, 0, nil, fmt.Errorf("githubbroker: installation-token API returned HTTP %d", resp.StatusCode)
	}

	var parsed struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, 0, nil, fmt.Errorf("githubbroker: parse installation-token response: %w", err)
	}
	if parsed.Token == "" {
		return nil, 0, nil, errors.New("githubbroker: installation-token response missing token field")
	}

	ttl := DefaultTokenTTL
	if !parsed.ExpiresAt.IsZero() {
		ttl = time.Until(parsed.ExpiresAt)
		if ttl <= 0 {
			ttl = DefaultTokenTTL
		}
	}

	// Capture the token for the revoke closure. The holder will get a
	// copy via Issue and we zero the local one in the closure once the
	// revoke round trip completes.
	tokenBytes := []byte(parsed.Token)
	parsed.Token = "" // best-effort scrub of the struct copy

	revoke := func() error {
		err := s.revokeInstallationToken(context.Background(), tokenBytes)
		zeroBytes(tokenBytes)
		return err
	}

	// Return a fresh copy so the caller can use the slice without
	// being affected by the revoke closure's later zeroing.
	out := make([]byte, len(tokenBytes))
	copy(out, tokenBytes)
	return out, ttl, revoke, nil
}

// revokeInstallationToken DELETEs the installation token at the API.
// The endpoint is /installation/token and authenticates with the
// installation token itself (not the App JWT); the token is passed as
// the Authorization header.
func (s *GitHubAppSource) revokeInstallationToken(ctx context.Context, token []byte) error {
	if len(token) == 0 {
		return nil
	}
	url := s.cfg.APIBaseURL + "/installation/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("githubbroker: build revoke request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// Authorization header contains the raw installation token; the
	// http.Client does not log it and the redactor in the broker's
	// log path scrubs any echoed header.
	req.Header.Set("Authorization", "token "+string(token))
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("githubbroker: revoke request: %w", err)
	}
	defer resp.Body.Close()
	// Drain the body so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	// 401 means the token already expired or was already revoked; treat
	// it as a no-op so the broker's idempotent revoke path stays clean.
	if resp.StatusCode == http.StatusUnauthorized {
		return nil
	}
	return fmt.Errorf("githubbroker: revoke API returned HTTP %d", resp.StatusCode)
}

// signAppJWT produces an RS256-signed JSON Web Token for the App. The
// claims match GitHub's documented App JWT shape: iss is the App ID,
// iat is now-60s (skew tolerance), exp is now+9min.
//
// The function is exported only via Acquire; tests exercise it
// indirectly by inspecting the Authorization header on the mocked
// installation-token request.
func (s *GitHubAppSource) signAppJWT() (string, error) {
	now := s.clock().UTC()
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	claims := map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": s.cfg.AppID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	hash := sha256.Sum256([]byte(encoded))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// parseRSAPrivateKey decodes the first PEM block in pemBytes as an RSA
// private key. Both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE
// KEY") encodings are supported because GitHub Apps download as either
// shape depending on which menu the operator used. Returns an error
// when no PEM block is present, when the block is not an RSA key, or
// when the bytes fail to decode.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is %T, want *rsa.PrivateKey", key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// PATConfig configures PATSource. Plan 07 step 7 names the PAT path as
// a development fallback; the Enabled flag makes the opt-in explicit so
// a production deployment with a misconfigured App does not silently
// degrade to a PAT.
type PATConfig struct {
	// Enabled gates the PAT path. SelectTokenSource returns an error
	// if Enabled is false and no GitHub App is configured.
	Enabled bool

	// Token is the raw PAT. Required when Enabled is true; an empty
	// string is rejected at construction time.
	Token string

	// TTL is the artificial lifetime the source attaches to the PAT.
	// Because GitHub does not give a PAT an inherent short lifetime,
	// the broker imposes one via TokenHolder so the run.json record
	// reflects the bounded window the PAT was actually live for. Zero
	// falls back to DefaultTokenTTL.
	TTL time.Duration
}

// PATSource is the development-fallback credential issuer. It returns
// a copy of the configured PAT on every Acquire call (PATs are not
// rotated by the issuer; the rotation is the broker's TokenHolder
// scrubbing the local copy on Revoke).
//
// The source does not attempt to revoke the PAT at GitHub. The legacy
// /authorizations/{id} endpoint is gone and fine-grained PATs are
// owned by the user, not deletable by an API token. Revoke is a no-op
// at the issuer; the TokenHolder.Revoke path still zeroes the local
// copy.
type PATSource struct {
	token []byte
	ttl   time.Duration
}

// NewPATSource validates cfg and returns a configured source. The
// caller-supplied Token is copied into the source so the caller can
// zero its own buffer; the source's copy is zeroed by Forget when the
// broker is sure no further Acquire calls will happen.
func NewPATSource(cfg PATConfig) (*PATSource, error) {
	if !cfg.Enabled {
		return nil, errors.New("githubbroker: PAT source requires PATConfig.Enabled=true")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("githubbroker: PAT source requires PATConfig.Token")
	}
	buf := make([]byte, len(cfg.Token))
	copy(buf, cfg.Token)
	return &PATSource{
		token: buf,
		ttl:   cfg.TTL,
	}, nil
}

// Kind reports TokenKindPersonalAccessToken.
func (s *PATSource) Kind() TokenKind { return TokenKindPersonalAccessToken }

// Acquire returns a fresh copy of the configured PAT. The TTL is
// PATConfig.TTL (clamped by the holder's ClampTTL) so the run.json
// record shows a bounded window even though the underlying credential
// has no inherent expiry.
func (s *PATSource) Acquire(_ context.Context) ([]byte, time.Duration, func() error, error) {
	if len(s.token) == 0 {
		return nil, 0, nil, errors.New("githubbroker: PAT source has been forgotten")
	}
	out := make([]byte, len(s.token))
	copy(out, s.token)
	// Revoke is a no-op at the issuer; the holder scrubs the local
	// copy. We still return a callback so the holder's Revoke path is
	// uniform across source kinds.
	revoke := func() error { return nil }
	return out, s.ttl, revoke, nil
}

// Forget zeroes the source's in-memory copy of the PAT. The concrete
// broker calls it from a deferred cleanup so a panic between
// AcquireToken and the run finalizer still scrubs the credential.
// Safe to call repeatedly.
func (s *PATSource) Forget() {
	zeroBytes(s.token)
	s.token = nil
}

// SelectorConfig bundles the inputs SelectTokenSource needs to decide
// which credential path to use. The CLI populates it from policy.yaml,
// secrets.local.yaml, and the operator's environment; the broker
// receives the resulting source and never sees the raw inputs.
type SelectorConfig struct {
	// App is the GitHub App configuration. When non-nil and well-
	// formed, SelectTokenSource returns a GitHubAppSource regardless
	// of PAT settings; the App path is the plan-mandated primary.
	App *GitHubAppConfig

	// PAT is the PAT fallback configuration. Consulted only when App
	// is nil. When PAT.Enabled is false here too, SelectTokenSource
	// returns an error so the broker never silently runs without a
	// credential.
	PAT *PATConfig
}

// SelectTokenSource returns the credential source the broker should
// use for a run. Selection rules:
//
//  1. If cfg.App is non-nil, attempt NewGitHubAppSource; any error
//     bubbles up so a misconfigured App does not silently fall back to
//     PAT (security regression).
//  2. Else if cfg.PAT is non-nil and Enabled, attempt NewPATSource.
//  3. Else return ErrNoTokenSource: the broker has nothing to
//     authenticate with and the CLI must tell the operator to
//     configure one path or the other.
//
// The function is pure: no I/O, no time-of-day reads, no goroutine
// state. It exists so the CLI / config layer's selection logic lives
// in one place and downstream code does not duplicate the precedence
// rule.
func SelectTokenSource(cfg SelectorConfig) (TokenSource, error) {
	if cfg.App != nil {
		return NewGitHubAppSource(*cfg.App)
	}
	if cfg.PAT != nil && cfg.PAT.Enabled {
		return NewPATSource(*cfg.PAT)
	}
	return nil, ErrNoTokenSource
}

// ErrNoTokenSource is returned by SelectTokenSource when neither a
// GitHub App nor an enabled PAT fallback is configured. The CLI
// surfaces it as "no GitHub credential configured for this workspace"
// with a hint pointing at the App registration docs.
var ErrNoTokenSource = errors.New("githubbroker: no GitHub credential configured (need GitHub App or PAT fallback)")
