# Plan 06: Scanning and Export Gates

Master plan reference: sections 25, 30 (Milestone 6), 31 (Week 6)

## Objective

Implement the built-in pattern-only secret scanner, entropy warn-only checks, optional gitleaks integration, external scanner discovery, and export gates. After this phase, `ai-env scan` works without any user-installed tools and secret findings block export.

## Dependencies

Plans 01-03 must be complete. Workspace diff and run directory must exist before scanning.

## Key decisions from master plan

**Pattern-only blocking**: the built-in scanner blocks only high-confidence pattern matches in v0.1. Entropy-only findings warn but do not block export by default. This avoids UUIDs, checksums, test fixtures, hashes, and generated IDs triggering false-positive export blocks.

**Useful without external tools**: `ai-env scan` must produce output even if gitleaks, osv-scanner, trivy, semgrep, and audit tools are not installed. Missing optional scanners produce warnings, not crashes.

**Export gate order**: scanner runs before export. Export command must check gate results.

## Built-in scanner pattern classes

1. Provider API keys: OpenAI (`sk-...`), Anthropic (`sk-ant-...`), GitHub (`ghp_...`, `github_pat_...`), npm, PyPI, AWS (`AKIA...`), Google Cloud, Azure, Slack, Stripe.
2. Private key headers: `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, `-----BEGIN OPENSSH PRIVATE KEY-----`.
3. `.env`-style assignments: `*_SECRET=`, `*_TOKEN=`, `*_KEY=`, `PASSWORD=` with non-empty values.
4. User-configurable custom regex patterns from `policy.yaml`.
5. Allowlist: inline comments `# ai-env-scan-ignore` or entries in `policy.yaml`.

## Optional external scanners

Discovered and run when available:

```
gitleaks detect
osv-scanner .
trivy fs .
semgrep --config auto
npm audit --audit-level=high
pip-audit
cargo audit
govulncheck ./...
```

## Scan output format

`secret-scan.json`:

```json
{
  "run_id": "20260528-101300-a1b2c3",
  "scanner": "built-in-patterns",
  "findings": [
    {
      "id": "finding_001",
      "type": "api_key",
      "pattern": "ANTHROPIC_API_KEY",
      "file": "src/config.ts",
      "line": 12,
      "confidence": "high",
      "entropy_only": false,
      "blocks_export": true
    }
  ],
  "entropy_warnings": [],
  "scanned_at": "2026-05-28T10:24:00+10:00"
}
```

## Export gate checks

Hard blockers (cannot be overridden by default):

1. Built-in scanner high-confidence secret finding.
2. `gitleaks` finding (if installed).
3. `.github/workflows/**` changed (for brokered PR; patch export warns but proceeds).
4. `.ai-env/**` changed by agent.
5. Backend run marked `quarantined`.
6. Policy file modified by agent.

Configurable blockers (can be adjusted in `policy.yaml`):

1. High severity dependency vulnerability.
2. Protected path changes.
3. Large diff size.
4. New binary files.
5. New executable files.
6. Lockfile changes.

## Tasks

1. Implement `ScanRunner` interface in `internal/scanners/`:
   ```
   RunBuiltIn(workspacePath, diff) -> ScanResult
   RunExternal(scanner, workspacePath) -> ScanResult
   DiscoverExternal() -> []ExternalScanner
   ```
2. [x] Implement built-in pattern-only secret scanner:
   - Scan all changed files in the diff.
   - Detect patterns from the list above.
   - Mark findings as `high` confidence when pattern matches a known provider format.
3. [x] Implement entropy analysis as warn-only (no export block by default):
   - Flag strings above entropy threshold.
   - Write to `entropy_warnings` in `secret-scan.json`.
4. [x] Implement gitleaks integration: run `gitleaks detect` when binary is found via `exec.LookPath`.
5. [x] Implement external scanner discovery: check PATH for each optional tool, report availability.
6. [x] Implement `ai-env scan <env-name>`:
   - Run built-in scanner.
   - Run available external scanners.
   - Write `secret-scan.json` and `dependency-report.json` to run directory.
   - Print summary.
   - Print warnings for unavailable optional scanners.
7. [x] Implement `ExportGate` in `internal/export/`:
   - Check scan results against hard blockers.
   - Check configurable blockers against `policy.yaml`.
   - Return `GateResult` with allow/block decision and reasons.
8. [x] Wire `ExportGate` into `ai-env patch` and `ai-env pr` (stub for PR, wired in Plan 07).
9. [x] Wire scanner into run lifecycle in Plan 03: run scan automatically after agent stops, before report.
10. [x] Add tests: built-in scanner detects common fake secrets.
11. [x] Add tests: missing optional scanners do not crash.
12. [x] Add tests: secret findings block export.
13. [x] Add tests: entropy-only findings warn but do not block.

## Acceptance criteria

1. `ai-env scan fix-tests` works without any user-installed external tools.
2. Missing optional scanners produce warnings, not crashes.
3. High-confidence secret finding blocks `ai-env patch` export.
4. `.github/workflows/**` change blocks `ai-env pr` (brokered PR only; patch export warns).
5. Entropy-only findings warn but do not block export by default.
6. Scan results are saved to `secret-scan.json` in the run directory.
7. `ai-env scan` shows a summary of findings and available/unavailable scanners.
