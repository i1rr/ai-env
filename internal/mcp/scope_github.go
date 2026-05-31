// Current-repo-only GitHub scope enforcement (plan 09, step 5).
//
// The GitHub MCP server lets an agent file issues, comment on PRs,
// read repository contents, and (with write scope) push branches.
// Without scope enforcement, an agent could file an issue against an
// arbitrary repository the operator's token has access to, leak the
// contents of a private repo by reading it through the MCP server, or
// open a PR against a production repository. The master plan's rule
// (section 22) is "GitHub MCP scoped to current repo only": every
// call must target the repository the supervisor declared as the
// current one. This file implements that rule as a concrete
// ScopeEnforcer that the gateway (step 3) plugs in for the "github"
// scope kind.
//
// Design rules:
//
//  1. The current repo coordinate ("owner/name") is captured at
//     construction time. The registry's "repos: current_repo_only"
//     token is a marker that says "use the current repo the
//     supervisor passed me", not a list of repos. This keeps
//     mcp.yaml repo-independent: the same committed mcp.yaml works
//     for every project the operator runs ai-env in.
//
//  2. The coordinate is normalized once at construction
//     (lower-case, leading "github.com/" stripped, trailing ".git"
//     stripped). GitHub coordinates are case-insensitive at the
//     server (an "Owner/Name" URL resolves to "owner/name"), so a
//     case-sensitive exact match would produce spurious rejections
//     when the agent learned the coordinate from a different
//     source than the supervisor.
//
//  3. The per-call comparison is exact on the normalized form. We
//     deliberately do not accept partial matches ("owner/" alone is
//     rejected because it would allow every repo under owner; an
//     empty coordinate is rejected because no-target is fail-closed
//     per the master plan).
//
//  4. The read_only / read_write distinction in the registry is
//     honored: when the server's scope declares Operations =
//     read_only, a request whose Operation is anything other than
//     "read" is rejected. The token vocabulary ("read" / "write") is
//     the same the gateway test suite uses for ScopeRequest.Operation
//     so the two layers stay aligned. An empty Operation on a
//     read_only scope is treated as "could be a write" and rejected:
//     the caller must declare intent.
//
//  5. The enforcer is registry-agnostic for the bulk of its logic
//     but does verify that the server's declared github scope uses
//     the current_repo_only token and a recognized Operations value.
//     Unknown tokens fail closed (ErrGitHubScopeUnsupported) so a
//     future enum value cannot accidentally widen the surface.
//
// The enforcer is safe for concurrent use: it holds only immutable
// state after construction.
//
// Why not put the repo math in the gateway? Same reasons as the
// filesystem enforcer (scope_filesystem.go): the gateway is dispatch
// logic and the coordinate-normalization rules are GitHub-specific.
// A future refactor that moves "what is the current repo?" into a
// dedicated package only needs to change this file's construction
// site, not the gateway.

package mcp

import (
	"errors"
	"fmt"
	"strings"
)

// ErrGitHubRepoOutsideScope is the sentinel returned when a github
// call targets a repository other than the configured current one.
// The gateway wraps it with ErrScopeViolation. Operator-facing
// messages should prefer this sentinel so the audit log makes it
// clear the agent tried to reach a foreign repo.
var ErrGitHubRepoOutsideScope = errors.New("mcp: github repo outside current-repo scope")

// ErrGitHubEmptyRepo is the sentinel returned when a github call
// arrives without a Repo coordinate. The master plan's deny-by-
// default rule applies: a github call without a target is a
// misconfigured caller, not an implicit allow. A separate sentinel
// from ErrGitHubRepoOutsideScope keeps the audit trail unambiguous
// ("the agent asked for nothing" vs. "the agent asked for the wrong
// repo").
var ErrGitHubEmptyRepo = errors.New("mcp: github call requires a repo")

// ErrGitHubWriteForbidden is the sentinel returned when a github
// call's Operation is "write" (or any non-read token) but the
// server's scope declares Operations = read_only. The master plan
// requires the per-server operations cap to be enforceable; this is
// where the cap takes effect.
var ErrGitHubWriteForbidden = errors.New("mcp: github write operation forbidden by read-only scope")

// ErrGitHubOperationUnknown is the sentinel returned when a github
// call arrives with an Operation token this enforcer does not
// recognize. The supported vocabulary is "read" / "write"; anything
// else fails closed so a typo in the caller (or a future enum value
// added without updating the enforcer) cannot bypass the read-only
// cap.
var ErrGitHubOperationUnknown = errors.New("mcp: github operation unrecognized")

// ErrGitHubScopeUnsupported is the sentinel returned when a
// server's github scope is declared with Repos / Operations tokens
// this enforcer does not know how to evaluate. v0.2 only supports
// the constants in registry.go (GitHubReposCurrentRepoOnly,
// GitHubOperationsReadOnly, GitHubOperationsReadWrite); any other
// token is treated as a configuration error rather than an implicit
// allow, mirroring the gateway's "deny unknown scope" rule.
var ErrGitHubScopeUnsupported = errors.New("mcp: github scope token unsupported")

// Operation tokens the enforcer understands on the per-call
// ScopeRequest.Operation field. Mirrored as constants so the
// gateway-side caller and this file compare against the same
// strings. The values match the tokens the existing gateway test
// suite already uses ("read", "write").
const (
	GitHubOperationRead  = "read"
	GitHubOperationWrite = "write"
)

// GitHubScopeEnforcer enforces the master plan's "GitHub MCP scoped
// to current repo only" rule plus the per-server read_only /
// read_write cap. It is constructed once per run (the supervisor
// calls NewGitHubScopeEnforcer with the active repo coordinate) and
// registered with the gateway under ScopeKindGitHub.
type GitHubScopeEnforcer struct {
	// currentRepo is the normalized "owner/name" coordinate the
	// run is scoped to. Captured at construction so the enforcer
	// never re-derives it per call.
	currentRepo string
}

// NewGitHubScopeEnforcer normalizes currentRepo and returns a
// ready-to-register enforcer. An empty currentRepo is rejected (the
// enforcer's only job is to compare against a known repo; the zero
// value would silently allow nothing or, worse, allow only the empty
// string). A malformed coordinate (missing "/") is rejected so a
// supervisor bug surfaces at construction time, not on the first
// agent call.
func NewGitHubScopeEnforcer(currentRepo string) (*GitHubScopeEnforcer, error) {
	if currentRepo == "" {
		return nil, errors.New("mcp: NewGitHubScopeEnforcer requires a non-empty current repo")
	}
	normalized := normalizeRepoCoordinate(currentRepo)
	if !strings.Contains(normalized, "/") {
		return nil, fmt.Errorf("mcp: NewGitHubScopeEnforcer: current repo %q must be owner/name", currentRepo)
	}
	owner, name, _ := strings.Cut(normalized, "/")
	if owner == "" || name == "" || strings.Contains(name, "/") {
		return nil, fmt.Errorf("mcp: NewGitHubScopeEnforcer: current repo %q must be owner/name", currentRepo)
	}
	return &GitHubScopeEnforcer{currentRepo: normalized}, nil
}

// CurrentRepo returns the normalized current repo coordinate.
// Exposed so the supervisor's audit / report code can surface "the
// enforced repo was X" without re-normalizing.
func (e *GitHubScopeEnforcer) CurrentRepo() string {
	return e.currentRepo
}

// EnforceScope implements ScopeEnforcer. The gateway forwards every
// github-scope call here; the enforcer either returns nil (allowed)
// or a non-nil error the gateway wraps with ErrScopeViolation. The
// kind argument is always ScopeKindGitHub in production but is
// forwarded verbatim so a misregistration surfaces with the actual
// kind in the error message.
func (e *GitHubScopeEnforcer) EnforceScope(server RegistryServer, kind string, req ScopeRequest) error {
	if kind != ScopeKindGitHub {
		return fmt.Errorf("mcp: GitHubScopeEnforcer registered under unexpected kind %q", kind)
	}
	section, ok := server.Scope[ScopeKindGitHub]
	if !ok {
		// The gateway only dispatches to this enforcer for servers
		// that declared the github scope, so a missing section
		// here is a programming error (caller forgot to filter)
		// rather than an operator-facing one. Surface it loudly.
		return fmt.Errorf("mcp: server has no github scope section")
	}
	if section.Repos != GitHubReposCurrentRepoOnly {
		return fmt.Errorf("%w: repos=%q (want %q)",
			ErrGitHubScopeUnsupported, section.Repos, GitHubReposCurrentRepoOnly)
	}
	switch section.Operations {
	case GitHubOperationsReadOnly, GitHubOperationsReadWrite:
		// recognized
	default:
		return fmt.Errorf("%w: operations=%q", ErrGitHubScopeUnsupported, section.Operations)
	}

	if req.Repo == "" {
		return ErrGitHubEmptyRepo
	}
	candidate := normalizeRepoCoordinate(req.Repo)
	if candidate != e.currentRepo {
		return fmt.Errorf("%w: %q resolved to %q (current repo: %q)",
			ErrGitHubRepoOutsideScope, req.Repo, candidate, e.currentRepo)
	}

	// Operations cap. On a read_write scope every recognized
	// operation is fine; we still validate the operation token so a
	// typo surfaces loudly rather than silently being treated as a
	// read.
	if req.Operation != "" {
		switch req.Operation {
		case GitHubOperationRead, GitHubOperationWrite:
			// recognized
		default:
			return fmt.Errorf("%w: %q (want %q or %q)",
				ErrGitHubOperationUnknown, req.Operation,
				GitHubOperationRead, GitHubOperationWrite)
		}
	}
	if section.Operations == GitHubOperationsReadOnly {
		// Empty Operation is treated as "could be a write" and
		// rejected: the caller must declare intent so the cap can be
		// enforced. This is the fail-closed half of the master
		// plan's "operations: read_only" rule.
		if req.Operation == "" || req.Operation != GitHubOperationRead {
			return fmt.Errorf("%w: tool %q operation %q",
				ErrGitHubWriteForbidden, req.Tool, req.Operation)
		}
	}
	return nil
}

// normalizeRepoCoordinate lower-cases the coordinate and strips a
// leading "github.com/" host and a trailing ".git" suffix so the
// enforcer matches the same repo regardless of whether the agent
// supplied "Owner/Repo", "github.com/Owner/Repo", or
// "https://github.com/Owner/Repo.git". The URL-scheme prefix is also
// stripped because some MCP servers pass through the full URL.
func normalizeRepoCoordinate(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "git@")
	// "git@github.com:owner/repo.git" -> after TrimPrefix above:
	// "github.com:owner/repo.git". Swap the host separator so the
	// rest of the normalization treats it like a URL form.
	s = strings.Replace(s, "github.com:", "github.com/", 1)
	s = strings.TrimPrefix(s, "github.com/")
	s = strings.TrimSuffix(s, ".git")
	s = strings.Trim(s, "/")
	return strings.ToLower(s)
}
