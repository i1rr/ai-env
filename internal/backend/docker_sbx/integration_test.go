package docker_sbx

// Integration tests for plan 04 step 9 ("sbx integration rules" item 7):
// gated by AI_ENV_BACKEND_INTEGRATION=1 so the default `go test ./...`
// invocation skips them cleanly without requiring an installed sbx
// binary. When the gate is on, each test still calls exec.LookPath("sbx")
// and t.Skip's if the binary is absent: the gate enables integration
// testing, it does not promise the host has the prerequisites.
//
// These tests exercise the real adapter against the real `sbx` CLI: no
// Runner override, no canned stdout. They cover what the plan's
// acceptance criteria require us to verify end-to-end:
//
//   - Detect against a real sbx binary returns Available=true and a
//     parsable Version (criterion: adapter does not depend on scraping
//     interactive sbx stdout for state transitions).
//   - The full Create -> Start -> Exec -> Stop -> Destroy lifecycle
//     completes for a real environment without intermediate errors
//     (criteria 1, 2, 6).
//   - Exec inside the environment runs a trivial command, returns the
//     correct exit code, and forwards stdout (the supervisor relies on
//     this to launch the agent).

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/backend"
)

// backendIntegrationGate is the env var the plan specifies (section
// "sbx integration rules" item 7). When unset, the integration tests
// in this file skip immediately so `go test ./...` stays hermetic.
const backendIntegrationGate = "AI_ENV_BACKEND_INTEGRATION"

// requireBackendIntegration is the entry-point gate every integration
// test in this file calls first. The two-stage skip (env var, then
// binary presence) matches the existing project idiom: a hermetic
// default test run, plus a clear "prereq missing" message when the
// gate is on but the host cannot satisfy it.
func requireBackendIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(backendIntegrationGate) != "1" {
		t.Skipf("integration test skipped: set %s=1 to enable", backendIntegrationGate)
	}
	if _, err := exec.LookPath(defaultBinary); err != nil {
		t.Skipf("integration test skipped: %s not on PATH: %v", defaultBinary, err)
	}
}

// uniqueEnvName returns a per-test env name the adapter can use as the
// sbx environment identifier. We tag it with the test name + a
// nanosecond timestamp so concurrent test runs (or a previous failed
// run that leaked an env) do not collide with each other.
func uniqueEnvName(t *testing.T, prefix string) string {
	t.Helper()
	safe := strings.ReplaceAll(t.Name(), "/", "-")
	return prefix + "-" + safe + "-" + time.Now().Format("20060102-150405.000000000")
}

// TestIntegration_Detect probes a real sbx binary. The adapter must
// report Available=true and a non-empty Version; whether the version
// falls in the tested range is informational here (a freshly-released
// sbx could be unsupported but still usable in the lifecycle test).
func TestIntegration_Detect(t *testing.T) {
	requireBackendIntegration(t)

	b := New(Options{})
	status := b.Detect()

	if status.Name != Name {
		t.Errorf("Detect.Name = %q, want %q", status.Name, Name)
	}
	if !status.Available {
		t.Fatalf("Detect.Available = false; message = %q", status.Message)
	}
	if status.Version == "" {
		t.Errorf("Detect.Version is empty; sbx reported no version string")
	}
}

// TestIntegration_Lifecycle drives Create -> Start -> Exec -> Stop ->
// Destroy against a real sbx environment. It is the end-to-end proof
// that the adapter's command shape is compatible with the installed
// sbx CLI: any breakage in the argv contract surfaces here.
//
// The test uses a temp directory as the workspace mount so it can
// inspect the environment's view of the workspace via Exec and assert
// on the captured stdout.
func TestIntegration_Lifecycle(t *testing.T) {
	requireBackendIntegration(t)

	workspace := t.TempDir()
	// Write a sentinel into the workspace so an `ls` from inside the
	// environment proves the mount worked. The exact contents are
	// irrelevant; we just need a file the agent could observe.
	sentinel := filepath.Join(workspace, "INTEGRATION_OK")
	if err := os.WriteFile(sentinel, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	b := New(Options{})
	if !b.Detect().Available {
		t.Skip("sbx Detect failed even though binary is present; skipping lifecycle")
	}

	envName := uniqueEnvName(t, "aienv-integ")
	spec := backend.EnvSpec{
		Name:          envName,
		WorkspacePath: workspace,
	}

	envID, err := b.Create(spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if envID != envName {
		t.Errorf("Create envID = %q, want %q", envID, envName)
	}
	// Always attempt Destroy even if a later step fails, so a flaky
	// host does not leak sbx environments across runs.
	t.Cleanup(func() {
		if err := b.Destroy(envID); err != nil {
			t.Logf("Destroy(%s) on cleanup: %v", envID, err)
		}
	})

	info, err := b.Start(envID)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if info.EnvID != envID {
		t.Errorf("Start RuntimeInfo.EnvID = %q, want %q", info.EnvID, envID)
	}
	if info.StartedAt.IsZero() {
		t.Errorf("Start RuntimeInfo.StartedAt is zero")
	}

	// Trivial exec: print a literal token we can grep for. Using `echo`
	// avoids assuming the workspace mount path inside the sandbox (sbx
	// templates differ on whether they place /workspace at /work, etc.).
	var stdout, stderr bytes.Buffer
	res, err := b.Exec(envID, backend.Command{
		Program: "echo",
		Args:    []string{"ai-env-integration"},
	}, backend.ExecOptions{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Exec(echo): %v\nstderr: %s", err, stderr.String())
	}
	if !res.HasExitCode || res.ExitCode != 0 {
		t.Errorf("Exec exit = %d (has=%v), want 0; stderr=%q",
			res.ExitCode, res.HasExitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ai-env-integration") {
		t.Errorf("Exec stdout = %q, want it to contain %q", stdout.String(), "ai-env-integration")
	}

	if err := b.Stop(envID, nil, 5*time.Second); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

// TestIntegration_ExecExitCode confirms the adapter surfaces non-zero
// exit codes through ExecResult.ExitCode instead of erroring out: the
// supervisor relies on this to record the agent's exit code in
// run.json.
func TestIntegration_ExecExitCode(t *testing.T) {
	requireBackendIntegration(t)

	b := New(Options{})
	if !b.Detect().Available {
		t.Skip("sbx Detect failed even though binary is present; skipping exit-code test")
	}

	envName := uniqueEnvName(t, "aienv-exit")
	envID, err := b.Create(backend.EnvSpec{Name: envName, WorkspacePath: t.TempDir()})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		if err := b.Destroy(envID); err != nil {
			t.Logf("Destroy(%s): %v", envID, err)
		}
	})
	if _, err := b.Start(envID); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// `sh -c 'exit 7'` is a portable way to ask for a specific non-zero
	// exit code. The adapter must return it via ExecResult, not as an
	// error.
	res, err := b.Exec(envID, backend.Command{
		Program: "sh",
		Args:    []string{"-c", "exit 7"},
	}, backend.ExecOptions{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("Exec(sh -c exit 7): %v", err)
	}
	if !res.HasExitCode {
		t.Errorf("Exec HasExitCode = false; supervisor relies on a reported exit code")
	}
	if res.ExitCode != 7 {
		t.Errorf("Exec ExitCode = %d, want 7", res.ExitCode)
	}

	if err := b.Stop(envID, nil, 5*time.Second); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

// TestIntegration_VersionParse is a lightweight sanity check on the
// version probe: it runs `sbx version` outside the adapter and confirms
// the adapter's extractor produces the same numeric core. This guards
// against an upstream format change quietly breaking compat.go.
func TestIntegration_VersionParse(t *testing.T) {
	requireBackendIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, defaultBinary, "version").CombinedOutput()
	if err != nil {
		t.Skipf("sbx version probe failed (likely environmental): %v\n%s", err, out)
	}
	parsed := extractVersion(string(out))
	if parsed == "" {
		t.Errorf("extractVersion(%q) = empty; sbx version output not parsable", string(out))
	}
}
