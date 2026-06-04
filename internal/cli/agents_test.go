package cli

import (
	"strings"
	"testing"

	"github.com/i1rr/ai-env/internal/config"
)

// TestEvaluateCredentialMode_BrokeredPasses pins the regression: the
// default agents.yaml shipped by `ai-env new` declares
// CredentialMode.Default = "brokered" (see defaultAgentsConfig in
// new.go), and the original switch in evaluateCredentialMode did not
// recognise that mode, so `ai-env agents doctor` flagged a freshly
// scaffolded project as FAIL with "(unknown mode)". The supervisor
// validates the broker contract at run time, so doctor must report
// PASS and defer.
func TestEvaluateCredentialMode_BrokeredPasses(t *testing.T) {
	cred := config.AgentCredentialMode{
		Default:       "brokered",
		FallbackOrder: []string{"raw_env_explicit"},
	}

	pass, reason := evaluateCredentialMode("claude", cred)
	if !pass {
		t.Fatalf("expected PASS for brokered default, got FAIL: %s", reason)
	}
	if !strings.Contains(reason, "brokered") {
		t.Fatalf("reason missing 'brokered' note: %q", reason)
	}
	if strings.Contains(reason, "unknown mode") {
		t.Fatalf("reason should not flag brokered as unknown mode: %q", reason)
	}
}

// TestEvaluateCredentialMode_BackendManagedStillPasses guards the
// pre-existing behaviour while the brokered case is added.
func TestEvaluateCredentialMode_BackendManagedStillPasses(t *testing.T) {
	cred := config.AgentCredentialMode{Default: "backend_managed"}

	pass, reason := evaluateCredentialMode("claude", cred)
	if !pass {
		t.Fatalf("expected PASS for backend_managed default, got FAIL: %s", reason)
	}
	if !strings.Contains(reason, "backend_managed") {
		t.Fatalf("reason missing 'backend_managed' note: %q", reason)
	}
}

// TestEvaluateCredentialMode_UnknownModeFails ensures the catch-all
// branch still surfaces unfamiliar modes so misconfigured contracts
// are not silently green.
func TestEvaluateCredentialMode_UnknownModeFails(t *testing.T) {
	cred := config.AgentCredentialMode{Default: "weird_mode"}

	pass, reason := evaluateCredentialMode("claude", cred)
	if pass {
		t.Fatalf("expected FAIL for unknown mode, got PASS: %s", reason)
	}
	if !strings.Contains(reason, "unknown mode") {
		t.Fatalf("reason should describe unknown mode: %q", reason)
	}
}

// TestEvaluateCredentialMode_DefaultsMatchScaffold asserts the
// scaffold produced by `ai-env new` (defaultAgentsConfig in new.go)
// runs PASS through doctor. This is the end-to-end pin for the
// regression: a fresh project must not fail doctor on a stock
// agents.yaml.
func TestEvaluateCredentialMode_DefaultsMatchScaffold(t *testing.T) {
	cfg := defaultAgentsConfig()
	claude, ok := cfg.Agents["claude"]
	if !ok {
		t.Fatalf("defaultAgentsConfig must declare claude agent")
	}

	pass, reason := evaluateCredentialMode("claude", claude.CredentialMode)
	if !pass {
		t.Fatalf("scaffold's claude credential mode should PASS, got FAIL: %s", reason)
	}
}
