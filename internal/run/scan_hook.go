package run

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// defaultScanTimeout is the upper bound the supervisor enforces on a
// ScanHook call. Plan 06 wires the built-in pattern scanner plus every
// available external scanner (gitleaks, osv-scanner, trivy, semgrep,
// audit tools, govulncheck); the slowest of these (a full trivy filesystem
// scan on a large workspace, or a govulncheck run on a multi-module Go
// repo) can take several tens of seconds, and we never want the
// supervisor's StateScanning walk to outlive the wall-clock the operator
// would tolerate. Five minutes leaves headroom for a slow external tool
// while still bounding the worst case so a wedged scanner does not block
// the terminal walk indefinitely.
const defaultScanTimeout = 5 * time.Minute

// ScanHook is the seam the supervisor uses to invoke the post-run
// scanner during StateScanning. It is supplied by the caller (the
// `ai-env run` CLI in production, a test stub in unit tests) so the run
// package does not have to import internal/scanners and so the
// supervisor stays decoupled from policy / workspace loading.
//
// Contract:
//
//   - The hook is invoked exactly once per run, during StateScanning,
//     after the agent stopped (StateStopping has already been recorded)
//     and before StateReporting. Plan 06 step 9: "run scan automatically
//     after agent stops, before report".
//   - The hook is responsible for materializing secret-scan.json and
//     dependency-report.json inside runDir. ExportGate reads
//     run.SecretScanPath(runDir) afterwards, so any other layout would
//     desync the gate from the scan output.
//   - The hook is invoked with a context whose deadline is at most
//     SupervisorOptions.ScanTimeout in the future. Implementations
//     should honor ctx so a wedged external scanner does not block the
//     supervisor's terminal walk.
//   - An error returned from the hook is treated as a scanner-
//     infrastructure failure: the supervisor diverts the happy-path
//     walk into StateFailedScan / StopReasonScanFailure rather than
//     continuing to StateReporting / StateCompleted. Findings themselves
//     are NOT failures: a scanner that wrote secret-scan.json with
//     blocking findings still returns nil; the export gate (consulted
//     later by `ai-env patch` / `ai-env pr`) is the surface that refuses
//     the diff. Plan 06 deliberately separates "scan ran" from "diff is
//     shippable" so a run with findings still ends in StateCompleted on
//     disk and remains inspectable.
//   - The hook is never invoked on non-happy terminals (timeout, idle,
//     cancel, failed_agent, failed_backend, failed_policy). Those paths
//     transition directly to their terminal state, by design: the run
//     never reached StateRunning's completion edge, so there is nothing
//     post-agent to scan.
type ScanHook func(ctx context.Context, runDir string) error

// runScanHook invokes the configured ScanHook with a timeout-bound
// context. It is the implementation of plan 06 step 9's "wire scanner
// into run lifecycle" requirement: the supervisor's driveTerminalSequence
// calls this helper after writing the StateScanning lifecycle event and
// before transitioning to StateReporting.
//
// Behavior matrix:
//
//   - hook nil: no ScanHook configured. The function returns nil so the
//     supervisor's StateScanning transition is a lifecycle stamp only,
//     matching the legacy plan-03 behavior. The plan-03 / plan-04 tests
//     that do not wire a scanner continue to walk the full happy path
//     unchanged.
//   - hook returns nil: the scan succeeded (or produced findings that
//     are advisory at run time). The supervisor proceeds to
//     StateReporting.
//   - hook returns non-nil err: the scan infrastructure failed. The
//     supervisor diverts to StateFailedScan / StopReasonScanFailure.
//   - context deadline elapses while the hook is running: the hook
//     returns ctx.Err() (or a wrapped form), which the supervisor treats
//     as a scan-infrastructure failure.
//
// timeout caps how long the hook is allowed to run. Zero falls back to
// defaultScanTimeout; negative values are rejected up front by the
// SupervisorOptions validator, never reaching this helper.
func runScanHook(runDir string, hook ScanHook, timeout time.Duration) error {
	if runDir == "" {
		return errors.New("run: runScanHook requires runDir")
	}
	if hook == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = defaultScanTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := hook(ctx, runDir); err != nil {
		return fmt.Errorf("run: scan hook: %w", err)
	}
	return nil
}
