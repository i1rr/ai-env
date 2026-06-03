package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/run"
)

// TestRunReport_NoRunsYet exercises the empty-state path: a freshly
// scaffolded project with no run directories should produce a
// "no runs recorded yet" hint rather than a stack of wrapped errors.
func TestRunReport_NoRunsYet(t *testing.T) {
	cwd := t.TempDir()
	if err := RunNew(NewOptions{EnvName: "fix-tests", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	var out, errOut bytes.Buffer
	err := RunReport(ReportOptions{
		EnvName: "fix-tests",
		Cwd:     cwd,
		Stdout:  &out,
		Stderr:  &errOut,
	})
	if err != nil {
		t.Fatalf("RunReport on fresh project: %v", err)
	}
	if !strings.Contains(out.String(), "(none recorded yet)") {
		t.Errorf("expected empty-state hint, got:\n%s", out.String())
	}
}

// TestRunReport_NetworkSummary verifies the report includes the
// network policy section sourced from network-events.jsonl. We seed
// the run directory with a policy_applied event and a couple of
// per-destination events, then assert on the rendered section.
func TestRunReport_NetworkSummary(t *testing.T) {
	cwd, runID := scaffoldProjectWithRun(t, "demo", run.StateCompleted)
	aiEnvDir := filepath.Join(cwd, ".ai-env")
	runDir := run.RunPath(aiEnvDir, runID)

	// Seed network-events.jsonl with a deterministic event stream.
	wri, err := run.OpenNetworkEventsWriter(runDir, run.NetworkEventsWriterOptions{
		RunID:   runID,
		Backend: "docker-sbx",
		Now:     func() time.Time { return time.Date(2026, 5, 28, 10, 13, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenNetworkEventsWriter: %v", err)
	}
	defer wri.Close()
	events := []run.NetworkEvent{
		{
			Event:        run.NetworkEventPolicyApplied,
			Default:      "deny",
			AllowDomains: []string{"api.openai.com"},
			BlockedCIDRs: []string{"169.254.169.254/32"},
			BlockedHosts: []string{"localhost"},
		},
		{Event: run.NetworkEventOutboundAllowed, Destination: "api.openai.com"},
		{Event: run.NetworkEventOutboundBlocked, Destination: "169.254.169.254"},
	}
	for _, e := range events {
		if err := wri.Write(e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	var out, errOut bytes.Buffer
	if err := RunReport(ReportOptions{
		EnvName: "demo",
		Cwd:     cwd,
		Stdout:  &out,
		Stderr:  &errOut,
	}); err != nil {
		t.Fatalf("RunReport: %v", err)
	}

	body := out.String()
	wantSubstrings := []string{
		"env:       demo",
		"network:",
		"network policy: applied",
		"default:        deny",
		"allow domains:  api.openai.com",
		"events:         3 total (1 allowed, 1 denied)",
		"top allowed:",
		"api.openai.com",
		"top denied:",
		"169.254.169.254",
		"artifacts:",
		"network events",
		"final summary",
	}
	for _, w := range wantSubstrings {
		if !strings.Contains(body, w) {
			t.Errorf("missing %q in report:\n%s", w, body)
		}
	}
}
