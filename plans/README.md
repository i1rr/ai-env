# ai-env Implementation Plans

Master plan: `../plan_v3_1.md`

Each plan here is a focused implementation guide for one phase. Plans are sequential: complete each one before starting the next.

| Plan | Phase | Milestone | Delivers |
|------|-------|-----------|----------|
| [01 Foundation](plan_01_foundation.md) | Week 1 | M1 | Go CLI, `ai-env new`, `ai-env list`, config generation, CI |
| [02 Workspace](plan_02_workspace.md) | Week 2 | M2 | Git worktree, copy strategy, diff, patch, protected paths |
| [03 Supervision](plan_03_supervision.md) | Week 3 | M3 | Run lifecycle, state machine, timeouts, signals, log streaming |
| [04 Backend](plan_04_backend.md) | Week 4 | M4 | Docker Sandboxes adapter, Claude and Codex launchers, credential modes |
| [05 Network](plan_05_network.md) | Week 5 | M5 | Network policy, provider proxy, fallback offline backend |
| [06 Scanning](plan_06_scanning.md) | Week 6 | M6 | Secret scanner, export gates, optional external scanners |
| [07 GitHub Broker](plan_07_github_broker.md) | Week 7 | M7 | Brokered draft PR, branch prefix, token TTL, PR metadata scan |
| [08 Hardening](plan_08_hardening.md) | Week 8 | M8 | Policy engine, shell shim, acceptance tests, docs, MVP demo |
| [09 MCP Gateway](plan_09_mcp_gateway.md) | Post-MVP | M9 | MCP registry, schema pinning, workspace-scoped filesystem MCP |

## MVP done when

Plans 01-08 complete and all 19 items in master plan section 37 pass.

## Quick dependency chain

```
01 -> 02 -> 03 -> 04 -> 05 -> 06 -> 07 -> 08
                                          |
                                         MVP
                                          |
                                         09 (post-MVP)
```
