package mcp

import (
	"errors"
	"testing"
)

// ghServer is a small RegistryServer factory the github-scope tests
// reuse. It returns a server with the canonical current_repo_only
// scope so each test only states the operations cap and per-server
// policy when it cares about them.
func ghServer(operations, policy string) RegistryServer {
	if operations == "" {
		operations = GitHubOperationsReadOnly
	}
	if policy == "" {
		policy = ServerPolicyAllow
	}
	return RegistryServer{
		Source: "oci:ghcr.io/example/server-github:1.1.0",
		Scope: map[string]ScopeSection{
			ScopeKindGitHub: {
				Repos:      GitHubReposCurrentRepoOnly,
				Operations: operations,
			},
		},
		Policy: policy,
	}
}

func TestNewGitHubScopeEnforcer_RejectsEmptyRepo(t *testing.T) {
	if _, err := NewGitHubScopeEnforcer(""); err == nil {
		t.Fatal("expected error for empty repo")
	}
}

func TestNewGitHubScopeEnforcer_RejectsMalformedRepo(t *testing.T) {
	cases := []string{
		"no-slash",
		"/leading-slash",
		"trailing-slash/",
		"three/parts/here",
		"only/",
		"/only",
	}
	for _, c := range cases {
		if _, err := NewGitHubScopeEnforcer(c); err == nil {
			t.Errorf("repo %q: expected error, got nil", c)
		}
	}
}

func TestNewGitHubScopeEnforcer_NormalizesCommonForms(t *testing.T) {
	cases := map[string]string{
		"Owner/Repo":                          "owner/repo",
		"github.com/Owner/Repo":               "owner/repo",
		"https://github.com/Owner/Repo":       "owner/repo",
		"https://github.com/Owner/Repo.git":   "owner/repo",
		"git@github.com:Owner/Repo.git":       "owner/repo",
		"  Owner/Repo  ":                      "owner/repo",
	}
	for in, want := range cases {
		e, err := NewGitHubScopeEnforcer(in)
		if err != nil {
			t.Errorf("%q: unexpected err: %v", in, err)
			continue
		}
		if got := e.CurrentRepo(); got != want {
			t.Errorf("%q: CurrentRepo = %q, want %q", in, got, want)
		}
	}
}

func TestGitHubScopeEnforcer_AllowsCurrentRepoRead(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	err := e.EnforceScope(ghServer("", ""), ScopeKindGitHub, ScopeRequest{
		Tool:      "list_issues",
		Repo:      "owner/repo",
		Operation: GitHubOperationRead,
	})
	if err != nil {
		t.Errorf("current repo read rejected: %v", err)
	}
}

func TestGitHubScopeEnforcer_RejectsForeignRepo(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	err := e.EnforceScope(ghServer("", ""), ScopeKindGitHub, ScopeRequest{
		Tool:      "list_issues",
		Repo:      "evil/repo",
		Operation: GitHubOperationRead,
	})
	if !errors.Is(err, ErrGitHubRepoOutsideScope) {
		t.Errorf("err = %v, want wraps ErrGitHubRepoOutsideScope", err)
	}
}

func TestGitHubScopeEnforcer_AcceptsRepoInAnyCommonForm(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	cases := []string{
		"owner/repo",
		"Owner/Repo",
		"github.com/owner/repo",
		"https://github.com/owner/repo",
		"https://github.com/owner/repo.git",
		"git@github.com:owner/repo.git",
	}
	for _, c := range cases {
		err := e.EnforceScope(ghServer("", ""), ScopeKindGitHub, ScopeRequest{
			Tool:      "list_issues",
			Repo:      c,
			Operation: GitHubOperationRead,
		})
		if err != nil {
			t.Errorf("repo %q rejected: %v", c, err)
		}
	}
}

func TestGitHubScopeEnforcer_RejectsEmptyRepo(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	err := e.EnforceScope(ghServer("", ""), ScopeKindGitHub, ScopeRequest{
		Tool:      "list_issues",
		Repo:      "",
		Operation: GitHubOperationRead,
	})
	if !errors.Is(err, ErrGitHubEmptyRepo) {
		t.Errorf("err = %v, want wraps ErrGitHubEmptyRepo", err)
	}
}

func TestGitHubScopeEnforcer_ReadOnlyBlocksWrite(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	err := e.EnforceScope(ghServer(GitHubOperationsReadOnly, ""), ScopeKindGitHub, ScopeRequest{
		Tool:      "create_issue",
		Repo:      "owner/repo",
		Operation: GitHubOperationWrite,
	})
	if !errors.Is(err, ErrGitHubWriteForbidden) {
		t.Errorf("err = %v, want wraps ErrGitHubWriteForbidden", err)
	}
}

func TestGitHubScopeEnforcer_ReadOnlyBlocksEmptyOperation(t *testing.T) {
	// On a read_only scope, an empty Operation must be rejected: the
	// caller did not declare intent, and fail-closed is the default.
	e := mustGHEnforcer(t, "owner/repo")
	err := e.EnforceScope(ghServer(GitHubOperationsReadOnly, ""), ScopeKindGitHub, ScopeRequest{
		Tool: "ambiguous",
		Repo: "owner/repo",
	})
	if !errors.Is(err, ErrGitHubWriteForbidden) {
		t.Errorf("err = %v, want wraps ErrGitHubWriteForbidden", err)
	}
}

func TestGitHubScopeEnforcer_ReadWriteAllowsWrite(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	err := e.EnforceScope(ghServer(GitHubOperationsReadWrite, ""), ScopeKindGitHub, ScopeRequest{
		Tool:      "create_issue",
		Repo:      "owner/repo",
		Operation: GitHubOperationWrite,
	})
	if err != nil {
		t.Errorf("read_write should allow write: %v", err)
	}
}

func TestGitHubScopeEnforcer_RejectsUnknownOperation(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	err := e.EnforceScope(ghServer(GitHubOperationsReadWrite, ""), ScopeKindGitHub, ScopeRequest{
		Tool:      "weird",
		Repo:      "owner/repo",
		Operation: "delete",
	})
	if !errors.Is(err, ErrGitHubOperationUnknown) {
		t.Errorf("err = %v, want wraps ErrGitHubOperationUnknown", err)
	}
}

func TestGitHubScopeEnforcer_RejectsUnknownReposToken(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	server := ghServer(GitHubOperationsReadOnly, "")
	server.Scope[ScopeKindGitHub] = ScopeSection{
		Repos:      "any_repo", // future token, not yet supported
		Operations: GitHubOperationsReadOnly,
	}
	err := e.EnforceScope(server, ScopeKindGitHub, ScopeRequest{
		Tool:      "list_issues",
		Repo:      "owner/repo",
		Operation: GitHubOperationRead,
	})
	if !errors.Is(err, ErrGitHubScopeUnsupported) {
		t.Errorf("err = %v, want wraps ErrGitHubScopeUnsupported", err)
	}
}

func TestGitHubScopeEnforcer_RejectsUnknownOperationsToken(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	server := ghServer(GitHubOperationsReadOnly, "")
	server.Scope[ScopeKindGitHub] = ScopeSection{
		Repos:      GitHubReposCurrentRepoOnly,
		Operations: "admin",
	}
	err := e.EnforceScope(server, ScopeKindGitHub, ScopeRequest{
		Tool:      "list_issues",
		Repo:      "owner/repo",
		Operation: GitHubOperationRead,
	})
	if !errors.Is(err, ErrGitHubScopeUnsupported) {
		t.Errorf("err = %v, want wraps ErrGitHubScopeUnsupported", err)
	}
}

func TestGitHubScopeEnforcer_RejectsWrongKindRegistration(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	err := e.EnforceScope(ghServer("", ""), ScopeKindFilesystem, ScopeRequest{
		Tool:      "list_issues",
		Repo:      "owner/repo",
		Operation: GitHubOperationRead,
	})
	if err == nil {
		t.Fatal("expected error for wrong kind dispatch")
	}
}

func TestGitHubScopeEnforcer_RejectsServerWithoutGitHubSection(t *testing.T) {
	e := mustGHEnforcer(t, "owner/repo")
	server := RegistryServer{
		Source: "oci:ghcr.io/example/server-github:1.1.0",
		Policy: ServerPolicyAllow,
		Scope:  map[string]ScopeSection{},
	}
	err := e.EnforceScope(server, ScopeKindGitHub, ScopeRequest{
		Tool:      "list_issues",
		Repo:      "owner/repo",
		Operation: GitHubOperationRead,
	})
	if err == nil {
		t.Fatal("expected error for missing github section")
	}
}

func TestGitHubScopeEnforcer_GatewayIntegration_PlugsInAsScopeEnforcer(t *testing.T) {
	// End-to-end check that the enforcer satisfies the ScopeEnforcer
	// interface and is rejected/allowed correctly via the gateway's
	// AuthorizeCall pipeline. The github fixture in the gateway test
	// suite uses Policy: warn, so an allowed call surfaces as Warn
	// rather than Allow; that lets us assert both that the scope
	// passed and that the per-server policy still applied.
	e := mustGHEnforcer(t, "rivan1986/ai-env")
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, map[string]ScopeEnforcer{
		ScopeKindGitHub: e,
	})

	// Current repo, read -> warn (per-server policy is warn).
	dec, err := gw.AuthorizeCall(CallRequest{
		Server:    "github",
		Tool:      "list_issues",
		Repo:      "rivan1986/ai-env",
		Operation: GitHubOperationRead,
	})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if dec.Outcome != GatewayOutcomeWarn {
		t.Fatalf("current repo Outcome = %v, want Warn (per-server policy warn)", dec.Outcome)
	}

	// Foreign repo -> block with ErrScopeViolation wrapping
	// ErrGitHubRepoOutsideScope.
	dec, err = gw.AuthorizeCall(CallRequest{
		Server:    "github",
		Tool:      "list_issues",
		Repo:      "evil/repo",
		Operation: GitHubOperationRead,
	})
	if err != nil {
		t.Fatalf("AuthorizeCall (foreign): %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("foreign repo Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrScopeViolation) {
		t.Errorf("Err = %v, want wraps ErrScopeViolation", dec.Err)
	}
	if !errors.Is(dec.Err, ErrGitHubRepoOutsideScope) {
		t.Errorf("Err = %v, want wraps ErrGitHubRepoOutsideScope", dec.Err)
	}
}

func mustGHEnforcer(t *testing.T, repo string) *GitHubScopeEnforcer {
	t.Helper()
	e, err := NewGitHubScopeEnforcer(repo)
	if err != nil {
		t.Fatalf("NewGitHubScopeEnforcer: %v", err)
	}
	return e
}
