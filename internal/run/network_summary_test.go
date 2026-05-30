package run

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSummarizeNetworkEvents_Empty verifies that an empty event slice
// produces a zero-valued summary whose PolicyStatus is the canonical
// "not_attempted" token. This is the path the report renderer follows
// for a run that never reached the applying_policy stage.
func TestSummarizeNetworkEvents_Empty(t *testing.T) {
	s := SummarizeNetworkEvents(nil)
	if s.Total != 0 {
		t.Errorf("Total = %d, want 0", s.Total)
	}
	if s.PolicyStatus != NetworkSummaryPolicyNotAttempted {
		t.Errorf("PolicyStatus = %q, want %q", s.PolicyStatus, NetworkSummaryPolicyNotAttempted)
	}
	if s.AllowedCount != 0 || s.DeniedCount != 0 {
		t.Errorf("counts = (%d,%d), want (0,0)", s.AllowedCount, s.DeniedCount)
	}
	if len(s.TopAllowed) != 0 || len(s.TopDenied) != 0 {
		t.Errorf("top lists should be empty")
	}
}

// TestSummarizeNetworkEvents_PolicyAppliedAndOutbound exercises the
// canonical happy path: a policy_apply_attempt + policy_applied pair
// followed by a mix of outbound_allowed and outbound_blocked events.
// The summary should carry the applied status, the snapshot fields,
// and the correctly-tallied destination top lists.
func TestSummarizeNetworkEvents_PolicyAppliedAndOutbound(t *testing.T) {
	events := []NetworkEvent{
		{
			Event:        NetworkEventPolicyApplyAttempt,
			Default:      "deny",
			AllowDomains: []string{"api.openai.com", "api.anthropic.com"},
			BlockedCIDRs: []string{"10.0.0.0/8"},
			BlockedHosts: []string{"localhost"},
		},
		{
			Event:        NetworkEventPolicyApplied,
			Default:      "deny",
			AllowDomains: []string{"api.openai.com", "api.anthropic.com"},
			BlockedCIDRs: []string{"10.0.0.0/8"},
			BlockedHosts: []string{"localhost"},
		},
		{Event: NetworkEventOutboundAllowed, Destination: "api.openai.com"},
		{Event: NetworkEventOutboundAllowed, Destination: "api.openai.com"},
		{Event: NetworkEventOutboundAllowed, Destination: "api.anthropic.com"},
		{Event: NetworkEventOutboundBlocked, Destination: "169.254.169.254"},
		{Event: NetworkEventOutboundBlocked, Destination: "169.254.169.254"},
		{Event: NetworkEventOutboundBlocked, Destination: "10.0.0.5"},
	}

	s := SummarizeNetworkEvents(events)

	if s.Total != len(events) {
		t.Errorf("Total = %d, want %d", s.Total, len(events))
	}
	if s.PolicyStatus != "applied" {
		t.Errorf("PolicyStatus = %q, want %q", s.PolicyStatus, "applied")
	}
	if s.Default != "deny" {
		t.Errorf("Default = %q, want %q", s.Default, "deny")
	}
	if s.AllowedCount != 3 || s.DeniedCount != 3 {
		t.Errorf("counts = (%d,%d), want (3,3)", s.AllowedCount, s.DeniedCount)
	}
	if len(s.TopAllowed) != 2 {
		t.Fatalf("TopAllowed len = %d, want 2", len(s.TopAllowed))
	}
	if s.TopAllowed[0].Destination != "api.openai.com" || s.TopAllowed[0].Count != 2 {
		t.Errorf("TopAllowed[0] = %+v, want {api.openai.com, 2}", s.TopAllowed[0])
	}
	if s.TopDenied[0].Destination != "169.254.169.254" || s.TopDenied[0].Count != 2 {
		t.Errorf("TopDenied[0] = %+v, want {169.254.169.254, 2}", s.TopDenied[0])
	}
}

// TestSummarizeNetworkEvents_PolicyFailed verifies that a
// policy_apply_failed event lands the failed status and captures the
// error string. A later attempt overwrites the failed status so the
// summary reflects the most recent install attempt.
func TestSummarizeNetworkEvents_PolicyFailed(t *testing.T) {
	events := []NetworkEvent{
		{Event: NetworkEventPolicyApplyAttempt, Default: "deny"},
		{Event: NetworkEventPolicyApplyFailed, Error: "adapter rejected policy"},
	}
	s := SummarizeNetworkEvents(events)
	if s.PolicyStatus != "failed" {
		t.Errorf("PolicyStatus = %q, want %q", s.PolicyStatus, "failed")
	}
	if s.PolicyError != "adapter rejected policy" {
		t.Errorf("PolicyError = %q", s.PolicyError)
	}
}

// TestSummarizeNetworkEvents_TopNCap verifies that the top-N
// destination lists cap at NetworkSummaryTopN regardless of how many
// unique destinations the backend emitted.
func TestSummarizeNetworkEvents_TopNCap(t *testing.T) {
	events := make([]NetworkEvent, 0, NetworkSummaryTopN+5)
	for i := 0; i < NetworkSummaryTopN+5; i++ {
		// Use a digit-padded suffix so the sort order is deterministic.
		events = append(events, NetworkEvent{
			Event:       NetworkEventOutboundAllowed,
			Destination: padDigit(i),
		})
	}
	s := SummarizeNetworkEvents(events)
	if len(s.TopAllowed) != NetworkSummaryTopN {
		t.Errorf("TopAllowed len = %d, want %d", len(s.TopAllowed), NetworkSummaryTopN)
	}
}

func padDigit(i int) string {
	const pad = "00"
	out := pad
	for x := i; x > 0; x /= 10 {
		out = out[:len(out)-1]
	}
	return out + itoaSimple(i)
}

func itoaSimple(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}

// TestRenderNetworkSummaryText_HappyPath confirms the text renderer
// emits the labeled lines for the populated summary and includes the
// top-allowed / top-denied sections.
func TestRenderNetworkSummaryText_HappyPath(t *testing.T) {
	s := NetworkSummary{
		Total:        4,
		PolicyStatus: "applied",
		Default:      "deny",
		AllowDomains: []string{"api.openai.com"},
		BlockedCIDRs: []string{"10.0.0.0/8"},
		BlockedHosts: []string{"localhost"},
		AllowedCount: 2,
		DeniedCount:  2,
		TopAllowed:   []NetworkSummaryDestination{{Destination: "api.openai.com", Count: 2}},
		TopDenied:    []NetworkSummaryDestination{{Destination: "169.254.169.254", Count: 2}},
	}
	var buf bytes.Buffer
	RenderNetworkSummaryText(&buf, s)
	out := buf.String()
	wantSubstrings := []string{
		"network policy: applied",
		"default:        deny",
		"allow domains:  api.openai.com",
		"blocked cidrs:  10.0.0.0/8",
		"blocked hosts:  localhost",
		"events:         4 total (2 allowed, 2 denied)",
		"top allowed:",
		"api.openai.com",
		"top denied:",
		"169.254.169.254",
	}
	for _, w := range wantSubstrings {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in text render:\n%s", w, out)
		}
	}
}

// TestRenderNetworkSummaryMarkdown_HappyPath confirms the markdown
// renderer emits the section header, the bullet list, and the
// destination tables.
func TestRenderNetworkSummaryMarkdown_HappyPath(t *testing.T) {
	s := NetworkSummary{
		Total:        2,
		PolicyStatus: "applied",
		Default:      "deny",
		AllowDomains: []string{"api.openai.com"},
		AllowedCount: 1,
		DeniedCount:  1,
		TopAllowed:   []NetworkSummaryDestination{{Destination: "api.openai.com", Count: 1}},
		TopDenied:    []NetworkSummaryDestination{{Destination: "10.0.0.5", Count: 1}},
	}
	var buf bytes.Buffer
	RenderNetworkSummaryMarkdown(&buf, s)
	out := buf.String()
	wantSubstrings := []string{
		"## Network",
		"- policy: applied",
		"- default: deny",
		"- allow domains: api.openai.com",
		"- events: 2 total (1 allowed, 1 denied)",
		"### Top allowed",
		"| destination | count |",
		"| api.openai.com | 1 |",
		"### Top denied",
		"| 10.0.0.5 | 1 |",
	}
	for _, w := range wantSubstrings {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in markdown render:\n%s", w, out)
		}
	}
}

// TestWriteFinalSummary_RoundTrip exercises the on-disk path: create
// a run directory, write a summary, then read it back as bytes and
// confirm the markdown body contains the run id, the env, and the
// network section.
func TestWriteFinalSummary_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	aiEnvDir := filepath.Join(tmp, ".ai-env")
	runID := "20260530-101300-abc123"
	dir, err := CreateRunDirectory(aiEnvDir, runID, time.Now())
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	in := FinalSummaryInput{
		EnvName: "demo",
		RunID:   runID,
		State:   StateCompleted,
		Network: NetworkSummary{
			Total:        1,
			PolicyStatus: "applied",
			Default:      "deny",
			AllowedCount: 1,
		},
	}
	if err := WriteFinalSummary(dir.Path, in); err != nil {
		t.Fatalf("WriteFinalSummary: %v", err)
	}
	bodyBytes, err := readFile(t, FinalSummaryPath(dir.Path))
	if err != nil {
		t.Fatalf("read final-summary: %v", err)
	}
	body := string(bodyBytes)
	wantSubstrings := []string{
		"# Run " + runID,
		"- env: demo",
		"- state: " + string(StateCompleted),
		"## Network",
		"- policy: applied",
	}
	for _, w := range wantSubstrings {
		if !strings.Contains(body, w) {
			t.Errorf("missing %q in final-summary:\n%s", w, body)
		}
	}
}

// readFile is a tiny helper so each test assertion has one place to
// adjust the read semantics if the run package ever grows a dedicated
// reader.
func readFile(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(path)
}
