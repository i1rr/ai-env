package codex

// Integration test for plan 04 step 9: real `codex --version` and
// `codex --help` probing through the production Launcher.Probe path.
// Gated by AI_ENV_BACKEND_INTEGRATION=1 to match the docker_sbx
// integration tests; additionally requires `codex` on PATH and skips
// cleanly when it is missing.

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/agents"
)

// backendIntegrationGate is the env var the plan specifies. The
// constant is duplicated rather than imported from docker_sbx to keep
// packages decoupled.
const backendIntegrationGate = "AI_ENV_BACKEND_INTEGRATION"

// requireRealCodex is the two-stage skip: env gate first, then binary
// presence. Matches the docker_sbx and claude integration helpers.
func requireRealCodex(t *testing.T) {
	t.Helper()
	if os.Getenv(backendIntegrationGate) != "1" {
		t.Skipf("integration test skipped: set %s=1 to enable", backendIntegrationGate)
	}
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skipf("integration test skipped: codex not on PATH: %v", err)
	}
}

// TestIntegration_Probe_Codex runs the real Probe end-to-end against
// the host's installed `codex` binary. The expectations mirror the
// claude integration test: non-empty BinaryPath / Version /
// SelectedFlags / HelpOutput, no Probe error. The contract's
// autonomous mode candidate must be discoverable in the real
// `codex --help` text or the supervisor cannot launch the agent.
func TestIntegration_Probe_Codex(t *testing.T) {
	requireRealCodex(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res := New().Probe(ctx, codexContract(), agents.ProbeDeps{})
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
		t.Errorf("Probe SelectedFlags empty: contract autonomous mode should match a candidate against `codex --help`")
	}
	if res.HelpOutput == "" {
		t.Errorf("Probe HelpOutput empty: --help should have produced text")
	}
}
