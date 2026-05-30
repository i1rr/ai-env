package claude

// Integration test for plan 04 step 9: real `claude --version` and
// `claude --help` probing through the production Launcher.Probe path.
// Gated by AI_ENV_BACKEND_INTEGRATION=1 to match the docker_sbx
// integration tests; additionally requires `claude` on PATH and skips
// cleanly when it is missing so a host without Claude Code installed
// can still set the gate.

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/agents"
)

// backendIntegrationGate is the env var the plan specifies. The
// constant is duplicated here (rather than imported from docker_sbx)
// to keep packages decoupled: the integration gate is a project-wide
// convention, not a docker_sbx concept.
const backendIntegrationGate = "AI_ENV_BACKEND_INTEGRATION"

// requireRealClaude is the two-stage skip: the env gate guards the
// default `go test ./...` run, and the binary check guards a gated
// run on a host that does not have Claude Code installed.
func requireRealClaude(t *testing.T) {
	t.Helper()
	if os.Getenv(backendIntegrationGate) != "1" {
		t.Skipf("integration test skipped: set %s=1 to enable", backendIntegrationGate)
	}
	if _, err := exec.LookPath("claude"); err != nil {
		t.Skipf("integration test skipped: claude not on PATH: %v", err)
	}
}

// TestIntegration_Probe_Claude runs the real Probe end-to-end against
// the host's installed `claude` binary. The plan's acceptance
// criteria require ai-env to launch Claude Code in a sandbox; the
// first prerequisite for that is a working Probe on the host CLI.
//
// The test asserts on what the contract guarantees: a non-empty
// BinaryPath, a parsable Version, and (when the contract's autonomous
// mode supports it) a non-empty SelectedFlags. It does not require
// VersionSupported=true because a host with a freshly-released claude
// version is still useful to probe; the supervisor's gating policy
// decides whether to refuse the launch.
func TestIntegration_Probe_Claude(t *testing.T) {
	requireRealClaude(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res := New().Probe(ctx, claudeContract(), agents.ProbeDeps{})
	if res.Error != nil {
		t.Fatalf("Probe error: %v", res.Error)
	}
	if res.BinaryPath == "" {
		t.Errorf("Probe BinaryPath empty")
	}
	if res.Version == "" {
		t.Errorf("Probe Version empty")
	}
	if len(res.SelectedFlags) == 0 {
		t.Errorf("Probe SelectedFlags empty: contract autonomous mode should match a candidate against `claude --help`")
	}
	if res.HelpOutput == "" {
		t.Errorf("Probe HelpOutput empty: --help should have produced text")
	}
}
