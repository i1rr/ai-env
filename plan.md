# Plan 09: MCP Gateway

Master plan reference: sections 22, 30 (Milestone 9), 34 (v0.2-v0.3 roadmap)

## Objective

Implement MCP server registry, deny-unknown-server enforcement, schema hash pinning, MCP call logging, and workspace-scoped filesystem MCP. This is a post-MVP phase targeting v0.2 or v0.3.

## Dependencies

Plans 01-08 must be complete. Policy engine from Plan 08 must be extensible to cover MCP decisions.

## Why MCP governance matters

MCP servers can:

1. Exfiltrate files through filesystem tools.
2. Make network calls to arbitrary destinations.
3. Invoke cloud or production tools if configured.
4. Change behavior through tool description updates (MCP poisoning).

`ai-env` cannot govern MCP calls that are not routed through its gateway. This plan adds that routing.

## Key decisions from master plan

- Unknown MCP servers denied by default.
- Server package version or container digest pinned.
- Tool schema hash pinned per server version.
- Changed tool description triggers warning or block.
- Filesystem MCP scoped to workspace only.
- GitHub MCP scoped to current repo only.
- Production cloud MCP forbidden by default.
- All MCP calls logged.

## MCP registry format (`mcp.yaml`)

```yaml
version: 1
default: deny
servers:
  filesystem:
    source: npm:@modelcontextprotocol/server-filesystem@1.2.3
    digest: sha256:abc123...
    schema_hash: sha256:def456...
    scope:
      filesystem:
        root: workspace_only
    policy: allow
  github:
    source: npm:@modelcontextprotocol/server-github@1.1.0
    digest: sha256:ghi789...
    schema_hash: sha256:jkl012...
    scope:
      github:
        repos: current_repo_only
        operations: read_only
    policy: allow
```

## Tasks

1. [x] Implement `MCPRegistry` in `internal/mcp/`:
   - Load and validate `mcp.yaml`.
   - Deny unknown servers by default.
   - Match server by name and validate version or digest.
2. [x] Implement schema hash pinning:
   - Compute hash of server tool schema on first registration.
   - Compare on each launch.
   - Warn or block if schema changed.
3. [x] Implement MCP gateway proxy:
   - Intercept MCP requests from the agent.
   - Validate server registration.
   - Apply scope constraints (filesystem root, GitHub repo, etc.).
   - Log all calls to `mcp-calls.jsonl`.
   - Return policy decision (allow/deny/warn).
4. [x] Implement workspace-only filesystem scope enforcement:
   - Reject any path outside `.ai-env/workspaces/<env-name>/`.
5. [x] Implement current-repo-only GitHub scope enforcement:
   - Reject operations on any repo other than the current one.
6. [x] Implement `ai-env mcp list`, `ai-env mcp add <server>`, `ai-env mcp pin <server>`, `ai-env mcp scan <server>`, `ai-env mcp remove <server>`.
7. [x] Add `mcp-calls.jsonl` to run directory layout.
8. Write `docs/mcp-security.md`: MCP risks, gateway model, server registration.
9. Add acceptance tests:
   - Unknown MCP server is blocked.
   - Changed tool schema triggers warning or block.
   - Filesystem MCP cannot read outside workspace.
   - MCP calls appear in audit logs.

## Acceptance criteria

1. Unknown MCP server is blocked from running.
2. Changed tool schema triggers warning or block before the server is used.
3. Filesystem MCP cannot access paths outside the active workspace.
4. All MCP calls appear in `mcp-calls.jsonl` in the run directory.
5. `ai-env mcp list` shows registered servers with their version and schema hash.
