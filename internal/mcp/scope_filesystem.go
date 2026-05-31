// Workspace-only filesystem scope enforcement (plan 09, step 4).
//
// The filesystem MCP server lets an agent read and write files. Without
// scope enforcement, an agent could trivially exfiltrate the operator's
// SSH keys, dotfiles, or production credentials by asking the
// filesystem server to read /home/user/.ssh/id_rsa or /etc/passwd. The
// master plan's rule (section 22) is "filesystem MCP scoped to
// workspace only": every path the agent supplies must resolve inside
// .ai-env/workspaces/<env-name>/. This file implements that rule as a
// concrete ScopeEnforcer that the gateway (step 3) plugs in for the
// "filesystem" scope kind.
//
// Design rules:
//
//  1. The workspace root is captured at construction time. The
//     enforcer never reads it from the registry: the registry's
//     "root: workspace_only" token is a marker that says "use the
//     workspace root the supervisor passed me", not a path. This
//     keeps mcp.yaml host-independent (an operator's mcp.yaml
//     committed to git does not encode their home directory) and
//     means the enforcer cannot accidentally widen the surface by
//     swapping in a different root mid-run.
//
//  2. The root is canonicalized once at construction (Abs +
//     EvalSymlinks when the directory exists, Abs + Clean
//     otherwise). Every per-call comparison reuses the canonical
//     form so a workspace that is itself a symlink does not produce
//     spurious rejections.
//
//  3. The per-call path is resolved using filepath.Abs against the
//     workspace root (relative paths are interpreted relative to
//     the workspace, matching how the filesystem MCP server itself
//     resolves them when the agent supplies a relative path). The
//     resolved path is then EvalSymlinks'd when it exists; if it
//     does not exist (e.g. the agent is creating a new file), the
//     enforcer resolves the nearest existing parent and appends the
//     remaining components so a symlinked parent still anchors the
//     check.
//
//  4. The acceptance test is "resolved path is the root or a
//     descendant of it". The descendant check uses
//     filepath.Rel + a "does not start with ..\<sep>" guard rather
//     than HasPrefix, because HasPrefix on path strings has the
//     classic /workspace vs /workspace2 false-positive bug.
//
//  5. Empty paths are blocked. The master plan's deny-by-default
//     rule applies: a filesystem call without a path target is a
//     misconfigured caller, not an implicit allow.
//
//  6. The enforcer is registry-agnostic for the bulk of its logic
//     but does verify that the server's declared filesystem scope
//     uses the workspace_only token. A server registered with a
//     different (future) token would slip past this enforcer
//     silently; surfacing the mismatch as an error keeps the
//     master plan's "deny unknown scope" rule honest even when a
//     future enum value lands.
//
// The enforcer is safe for concurrent use: it holds only immutable
// state after construction.
//
// Why not put the path math in the gateway? Two reasons. First, the
// gateway is registry/dispatch logic; symlink resolution and the
// workspace-root anchor are filesystem concerns that belong in a
// filesystem-specific file. Second, plan 04 already has a workspace
// package that knows about workspace roots; a future refactor that
// moves the canonical "where is the workspace?" answer to that
// package only needs to change this file's construction site, not
// the gateway.

package mcp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrFilesystemPathOutsideWorkspace is the sentinel returned when a
// filesystem call targets a path that resolves outside the configured
// workspace root. The gateway wraps it with ErrScopeViolation so
// callers can match either the generic scope sentinel or this
// specific one ("the agent tried to leave the workspace"). Operator-
// facing messages should prefer this sentinel so the audit log makes
// it clear what kind of escape was attempted.
var ErrFilesystemPathOutsideWorkspace = errors.New("mcp: filesystem path outside workspace")

// ErrFilesystemEmptyPath is the sentinel returned when a filesystem
// call arrives with an empty Path. The master plan's deny-by-default
// rule treats a missing required field as a hard block (not an
// implicit allow), so this is a separate sentinel from the
// out-of-workspace error: an operator reading the audit log can tell
// "the agent asked for nothing" from "the agent asked for /etc".
var ErrFilesystemEmptyPath = errors.New("mcp: filesystem call requires a path")

// ErrFilesystemScopeUnsupported is the sentinel returned when a
// server's filesystem scope is declared with a Root token this
// enforcer does not know how to evaluate. v0.2 only supports
// FilesystemRootWorkspaceOnly; any other token is treated as a
// configuration error rather than an implicit allow, mirroring the
// gateway's "deny unknown scope" rule for missing enforcers.
var ErrFilesystemScopeUnsupported = errors.New("mcp: filesystem scope root unsupported")

// FilesystemScopeEnforcer enforces the master plan's
// "filesystem MCP scoped to workspace only" rule. It is constructed
// once per run (the supervisor calls NewFilesystemScopeEnforcer with
// the active workspace root) and registered with the gateway under
// ScopeKindFilesystem.
type FilesystemScopeEnforcer struct {
	// workspaceRoot is the canonical, symlink-resolved path to the
	// .ai-env/workspaces/<env-name>/ directory. Captured at
	// construction so the enforcer never has to re-read it per call.
	workspaceRoot string
}

// NewFilesystemScopeEnforcer canonicalizes workspaceRoot and returns
// a ready-to-register enforcer. An empty workspaceRoot is rejected
// (the enforcer's only job is to compare against a known root; the
// zero value would silently allow every call). A non-existent
// workspaceRoot is accepted with a Clean+Abs canonicalization: the
// supervisor may construct the enforcer before the workspace is
// materialized in early-init paths, and rejecting here would force
// an unfortunate ordering constraint on the supervisor.
func NewFilesystemScopeEnforcer(workspaceRoot string) (*FilesystemScopeEnforcer, error) {
	if workspaceRoot == "" {
		return nil, errors.New("mcp: NewFilesystemScopeEnforcer requires a non-empty workspace root")
	}
	canonical, err := canonicalizePath(workspaceRoot)
	if err != nil {
		return nil, fmt.Errorf("mcp: canonicalize workspace root %q: %w", workspaceRoot, err)
	}
	return &FilesystemScopeEnforcer{workspaceRoot: canonical}, nil
}

// WorkspaceRoot returns the canonicalized workspace root. Exposed so
// the supervisor's audit / report code can surface "the enforced
// workspace was X" without re-deriving it.
func (e *FilesystemScopeEnforcer) WorkspaceRoot() string {
	return e.workspaceRoot
}

// EnforceScope implements ScopeEnforcer. The gateway forwards every
// filesystem-scope call here; the enforcer either returns nil
// (allowed) or a non-nil error the gateway wraps with
// ErrScopeViolation. The kind argument is always ScopeKindFilesystem
// in production (the gateway dispatches by kind) but is forwarded
// verbatim so a misregistration surfaces with the actual kind in the
// error message.
func (e *FilesystemScopeEnforcer) EnforceScope(server RegistryServer, kind string, req ScopeRequest) error {
	if kind != ScopeKindFilesystem {
		return fmt.Errorf("mcp: FilesystemScopeEnforcer registered under unexpected kind %q", kind)
	}
	section, ok := server.Scope[ScopeKindFilesystem]
	if !ok {
		// The gateway only dispatches to this enforcer for servers
		// that declared the filesystem scope, so a missing section
		// here is a programming error (caller forgot to filter)
		// rather than an operator-facing one. Surface it loudly.
		return fmt.Errorf("mcp: server has no filesystem scope section")
	}
	if section.Root != FilesystemRootWorkspaceOnly {
		return fmt.Errorf("%w: %q (want %q)",
			ErrFilesystemScopeUnsupported, section.Root, FilesystemRootWorkspaceOnly)
	}
	if req.Path == "" {
		return ErrFilesystemEmptyPath
	}
	resolved, err := e.resolveAgainstWorkspace(req.Path)
	if err != nil {
		// Resolution failures (e.g. permission denied stat'ing a
		// parent) are surfaced as out-of-workspace blocks: we
		// cannot prove the path is inside, so the fail-closed rule
		// applies. The wrapped error preserves the underlying
		// reason for the audit log.
		return fmt.Errorf("%w: %q: %v", ErrFilesystemPathOutsideWorkspace, req.Path, err)
	}
	if !isWithin(e.workspaceRoot, resolved) {
		return fmt.Errorf("%w: %q resolved to %q (workspace root: %q)",
			ErrFilesystemPathOutsideWorkspace, req.Path, resolved, e.workspaceRoot)
	}
	return nil
}

// resolveAgainstWorkspace returns the canonical absolute path the
// caller's input refers to. Relative inputs are anchored against the
// workspace root (matching how the filesystem MCP server resolves
// agent-supplied relative paths). Symlinks anywhere along the path
// are resolved so a symlink-into-/etc cannot be smuggled in via a
// relative-looking input. Paths that do not exist (e.g. the agent is
// creating a new file) are resolved by walking upward to the nearest
// existing ancestor and appending the remainder.
func (e *FilesystemScopeEnforcer) resolveAgainstWorkspace(input string) (string, error) {
	candidate := input
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(e.workspaceRoot, candidate)
	}
	candidate = filepath.Clean(candidate)
	return resolveSymlinksBestEffort(candidate)
}

// canonicalizePath returns the absolute, symlink-resolved form of p.
// Used by the constructor (for the workspace root) and indirectly by
// resolveAgainstWorkspace (via resolveSymlinksBestEffort) for per-call
// paths. A non-existent path falls back to Abs+Clean so the function
// can be called on workspaces that have not been materialized yet.
func canonicalizePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Workspace not yet materialized: accept the Abs form.
			// resolveSymlinksBestEffort handles per-call paths
			// that contain symlinked ancestors even when the
			// workspace root itself is not yet on disk.
			return abs, nil
		}
		return "", err
	}
	return resolved, nil
}

// resolveSymlinksBestEffort returns the symlink-resolved form of p
// when possible, otherwise resolves as much of the path as exists
// and appends the unresolvable tail verbatim. This matches the
// semantics of "where would a write to this path actually land?":
// the agent creating /workspace/new.txt should be allowed even
// though new.txt does not exist yet, but if /workspace/ is itself a
// symlink, the check must apply to the resolved target.
func resolveSymlinksBestEffort(p string) (string, error) {
	resolved, err := filepath.EvalSymlinks(p)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// Walk upward until we find an existing ancestor, then
	// EvalSymlinks it and re-attach the tail. We stop at the
	// filesystem root to avoid an infinite loop on a malformed path.
	parent := p
	var tail []string
	for {
		next := filepath.Dir(parent)
		if next == parent {
			// Reached the filesystem root with no existing
			// ancestor; surface the original ENOENT.
			return "", err
		}
		tail = append([]string{filepath.Base(parent)}, tail...)
		parent = next
		resolved, err2 := filepath.EvalSymlinks(parent)
		if err2 == nil {
			return filepath.Join(append([]string{resolved}, tail...)...), nil
		}
		if !errors.Is(err2, os.ErrNotExist) {
			return "", err2
		}
	}
}

// isWithin reports whether candidate is root or a descendant of root.
// Both arguments must already be in canonical (absolute, cleaned,
// symlink-resolved) form. The implementation uses filepath.Rel +
// a "..<sep>" guard instead of strings.HasPrefix to avoid the
// classic /workspace vs /workspace-evil false positive.
func isWithin(root, candidate string) bool {
	if candidate == root {
		return true
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	// "..<sep>" or exactly ".." means the candidate climbed out of
	// the root. On the rare host where filepath.Separator is not '/'
	// (Windows), filepath.Rel still emits the host separator so the
	// prefix check stays correct.
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}
