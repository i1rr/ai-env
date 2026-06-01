package githubbroker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/scanners"
	"github.com/rivan1986/ai-env/internal/secrets"
)

// generateTestAppPEM produces a fresh, valid PKCS#1 PEM-encoded RSA
// private key for tests that need to satisfy NewGitHubAppSource's PEM
// parser. The key is generated on the fly with crypto/rand so it
// satisfies the n = p*q invariant; the previous static fixture did
// not. The bytes are NOT a live GitHub App key; the test server never
// validates the JWT signature.
//
// 2048 bits keeps the test fast (sub-second on modern hardware) while
// staying well above the size GitHub itself accepts.
func generateTestAppPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// TestBuildBrokerFromSecrets_PATPath confirms the factory selects the
// PAT source when the operator's secrets.local.yaml enables it and
// constructs a usable Broker whose lifecycle the test can drive end-
// to-end.
func TestBuildBrokerFromSecrets_PATPath(t *testing.T) {
	cfg := &secrets.LocalConfig{
		Version: secrets.LocalConfigSchemaVersion,
		Secrets: secrets.LocalSecretsSection{
			GitHub: &secrets.LocalGitHubCredentials{
				PAT: &secrets.LocalGitHubPATCredentials{
					Enabled:    true,
					Token:      "ghp_fakeTOKEN_for_tests_only_xxxxxxxxxxxxxxxx",
					TTLSeconds: 600,
				},
			},
		},
	}

	pushCalls := 0
	createCalls := 0
	pushFn := func(_ BrokerContext, secret []byte) error {
		pushCalls++
		if len(secret) == 0 {
			t.Errorf("PushFn got empty secret")
		}
		return nil
	}
	createFn := func(_ context.Context, _ BrokerContext, secret []byte, title, _ string) (PRResult, error) {
		createCalls++
		if len(secret) == 0 {
			t.Errorf("CreateFn got empty secret")
		}
		return PRResult{Number: 7, URL: "https://github.com/acme/demo/pull/7", Draft: true, CreatedAt: time.Now()}, nil
	}

	sc, err := scanners.NewBuiltIn(scanners.Config{})
	if err != nil {
		t.Fatalf("scanners.NewBuiltIn: %v", err)
	}

	b, err := BuildBrokerFromSecrets(cfg, BuildBrokerOptions{
		Repo: Repo{
			Owner: "acme", Name: "demo", DefaultBranch: "main",
			CloneURL: "https://github.com/acme/demo.git",
		},
		Scanner:  sc,
		PushFn:   pushFn,
		CreateFn: createFn,
	})
	if err != nil {
		t.Fatalf("BuildBrokerFromSecrets: %v", err)
	}
	defer b.Close()

	ctx, err := b.Prepare("fix-tests", "ai-env/fix-tests", Repo{
		Owner: "acme", Name: "demo", DefaultBranch: "main",
		CloneURL: "https://github.com/acme/demo.git",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	tok, err := b.AcquireToken(ctx)
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if tok.Kind != TokenKindPersonalAccessToken {
		t.Errorf("token kind=%s, want %s", tok.Kind, TokenKindPersonalAccessToken)
	}
	if err := b.PushBranch(ctx, tok); err != nil {
		t.Fatalf("PushBranch: %v", err)
	}
	scan, err := b.ScanMetadata(ctx, "fix bug", "no leaks here", []string{"fix bug"})
	if err != nil {
		t.Fatalf("ScanMetadata: %v", err)
	}
	for _, f := range scan.Findings {
		if f.BlocksExport {
			t.Errorf("unexpected blocking finding %+v", f)
		}
	}
	pr, err := b.CreateDraftPR(ctx, tok, "fix bug", "no leaks here")
	if err != nil {
		t.Fatalf("CreateDraftPR: %v", err)
	}
	if pr.Number != 7 || pr.URL != "https://github.com/acme/demo/pull/7" {
		t.Errorf("PRResult=%+v, want {Number:7, URL: ...}", pr)
	}
	if err := b.RevokeToken(tok); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if pushCalls != 1 || createCalls != 1 {
		t.Errorf("pushCalls=%d createCalls=%d, want 1/1", pushCalls, createCalls)
	}
}

// TestBuildBrokerFromSecrets_AppPath confirms the factory selects the
// GitHub App source when an App credential is configured. We stand up
// an httptest.Server that simulates the installation-token endpoint
// so AcquireToken's round trip returns a synthetic token without
// touching the real API.
func TestBuildBrokerFromSecrets_AppPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/app/installations/42/access_tokens"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":"ghs_fake_installation_token_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","expires_at":"%s"}`,
				time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
		case strings.HasSuffix(r.URL.Path, "/installation/token") && r.Method == http.MethodDelete:
			// The revoke round trip uses DELETE /installation/token; a
			// 204 No Content is the documented success shape.
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected path %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := &secrets.LocalConfig{
		Version: secrets.LocalConfigSchemaVersion,
		Secrets: secrets.LocalSecretsSection{
			GitHub: &secrets.LocalGitHubCredentials{
				App: &secrets.LocalGitHubAppCredentials{
					AppID:          1234,
					InstallationID: 42,
					PrivateKeyPEM:  generateTestAppPEM(t),
					APIBaseURL:     srv.URL,
				},
			},
		},
	}

	b, err := BuildBrokerFromSecrets(cfg, BuildBrokerOptions{
		Repo: Repo{
			Owner: "acme", Name: "demo", DefaultBranch: "main",
			CloneURL: "https://github.com/acme/demo.git",
		},
		HTTPClient: srv.Client(),
		PushFn:     func(_ BrokerContext, _ []byte) error { return nil },
		CreateFn: func(_ context.Context, _ BrokerContext, _ []byte, _, _ string) (PRResult, error) {
			return PRResult{Number: 1, URL: "x", Draft: true}, nil
		},
	})
	if err != nil {
		t.Fatalf("BuildBrokerFromSecrets: %v", err)
	}
	defer b.Close()

	ctx, err := b.Prepare("demo", "ai-env/demo", Repo{
		Owner: "acme", Name: "demo", DefaultBranch: "main",
		CloneURL: "https://github.com/acme/demo.git",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	tok, err := b.AcquireToken(ctx)
	if err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	if tok.Kind != TokenKindGitHubApp {
		t.Errorf("token kind=%s, want %s", tok.Kind, TokenKindGitHubApp)
	}
	if err := b.RevokeToken(tok); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
}

// TestBuildBrokerFromSecrets_NoCredsReturnsErrNoTokenSource asserts the
// "no broker configured" path the CLI relies on for the preview-only
// fallback: a nil cfg, or cfg with nil GitHub credentials, surfaces
// ErrNoTokenSource so the caller renders the documented notice.
func TestBuildBrokerFromSecrets_NoCredsReturnsErrNoTokenSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *secrets.LocalConfig
	}{
		{"nil cfg", nil},
		{"nil github", &secrets.LocalConfig{Version: 1, Secrets: secrets.LocalSecretsSection{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildBrokerFromSecrets(tc.cfg, BuildBrokerOptions{
				Repo: Repo{Owner: "a", Name: "b", CloneURL: "https://x"},
			})
			if !errors.Is(err, ErrNoTokenSource) {
				t.Fatalf("err=%v, want ErrNoTokenSource", err)
			}
		})
	}
}

// TestBuildBrokerFromSecrets_MissingRepoReturnsErrRepoUnconfigured
// asserts that an attempt to build a broker without a usable repo
// coordinate surfaces ErrRepoUnconfigured so the CLI can render the
// documented "no GitHub repository configured" remediation hint.
func TestBuildBrokerFromSecrets_MissingRepoReturnsErrRepoUnconfigured(t *testing.T) {
	cfg := &secrets.LocalConfig{
		Version: 1,
		Secrets: secrets.LocalSecretsSection{
			GitHub: &secrets.LocalGitHubCredentials{
				PAT: &secrets.LocalGitHubPATCredentials{Enabled: true, Token: "ghp_xxx"},
			},
		},
	}
	for _, tc := range []struct {
		name string
		repo Repo
	}{
		{"empty owner", Repo{Owner: "", Name: "n", CloneURL: "https://x"}},
		{"empty name", Repo{Owner: "o", Name: "", CloneURL: "https://x"}},
		{"empty cloneurl", Repo{Owner: "o", Name: "n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildBrokerFromSecrets(cfg, BuildBrokerOptions{Repo: tc.repo})
			if !errors.Is(err, ErrRepoUnconfigured) {
				t.Fatalf("err=%v, want errors.Is(ErrRepoUnconfigured)", err)
			}
		})
	}
}

// TestBuildBrokerFromSecrets_PATDisabledReturnsErrNoTokenSource
// asserts that a PAT entry without `enabled: true` is NOT silently
// fallen through to; the broker requires explicit opt-in for the PAT
// path so a production deployment with a malformed App cannot silently
// degrade.
func TestBuildBrokerFromSecrets_PATDisabledReturnsErrNoTokenSource(t *testing.T) {
	cfg := &secrets.LocalConfig{
		Version: 1,
		Secrets: secrets.LocalSecretsSection{
			GitHub: &secrets.LocalGitHubCredentials{
				PAT: &secrets.LocalGitHubPATCredentials{Enabled: false, Token: "ghp_xxx"},
			},
		},
	}
	_, err := BuildBrokerFromSecrets(cfg, BuildBrokerOptions{
		Repo: Repo{Owner: "a", Name: "b", CloneURL: "https://x"},
	})
	if !errors.Is(err, ErrNoTokenSource) {
		t.Fatalf("err=%v, want ErrNoTokenSource", err)
	}
}

// TestBroker_FreshAcquireTokenPerPushBranch confirms the plan's
// "fresh AcquireToken per PushBranch, no mid-call refresh" rule by
// driving two consecutive Acquire → Push cycles and asserting each
// Acquire produces a fresh handle (distinct from the previous one).
//
// The test does NOT call PushBranch after RevokeToken (that would
// return ErrTokenRevoked); the assertion is on handle distinctness.
func TestBroker_FreshAcquireTokenPerPushBranch(t *testing.T) {
	cfg := &secrets.LocalConfig{
		Version: 1,
		Secrets: secrets.LocalSecretsSection{
			GitHub: &secrets.LocalGitHubCredentials{
				PAT: &secrets.LocalGitHubPATCredentials{Enabled: true, Token: "ghp_xxx"},
			},
		},
	}
	var seenSecrets [][]byte
	pushFn := func(_ BrokerContext, secret []byte) error {
		cp := make([]byte, len(secret))
		copy(cp, secret)
		seenSecrets = append(seenSecrets, cp)
		return nil
	}
	b, err := BuildBrokerFromSecrets(cfg, BuildBrokerOptions{
		Repo: Repo{
			Owner: "a", Name: "b", DefaultBranch: "main",
			CloneURL: "https://github.com/a/b.git",
		},
		PushFn: pushFn,
		CreateFn: func(_ context.Context, _ BrokerContext, _ []byte, _, _ string) (PRResult, error) {
			return PRResult{Number: 1}, nil
		},
	})
	if err != nil {
		t.Fatalf("BuildBrokerFromSecrets: %v", err)
	}
	defer b.Close()

	ctx, err := b.Prepare("env", "ai-env/env", Repo{
		Owner: "a", Name: "b", DefaultBranch: "main",
		CloneURL: "https://github.com/a/b.git",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	tok1, _ := b.AcquireToken(ctx)
	_ = b.PushBranch(ctx, tok1)
	_ = b.RevokeToken(tok1)

	tok2, _ := b.AcquireToken(ctx)
	_ = b.PushBranch(ctx, tok2)
	_ = b.RevokeToken(tok2)

	if tok1.Handle == "" || tok2.Handle == "" {
		t.Fatalf("got empty handles: tok1=%+v tok2=%+v", tok1, tok2)
	}
	if tok1.Handle == tok2.Handle {
		t.Errorf("AcquireToken returned same handle twice: %s — should rotate per call", tok1.Handle)
	}
	if len(seenSecrets) != 2 {
		t.Errorf("PushFn called %d times, want 2", len(seenSecrets))
	}
}
