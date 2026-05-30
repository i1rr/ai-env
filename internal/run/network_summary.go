package run

import (
	"fmt"
	"io"
	"strings"
)

// RenderNetworkSummaryText writes a deterministic, human-readable text
// summary of s to w. Used by `ai-env report` to surface the network
// section in the run report (plan 05 task 7) and by the final-summary
// writer to capture the same information on disk (plan 05 task 12).
//
// Format (label-aligned colon-separated lines, mirroring the rest of
// the CLI's report sections):
//
//	network policy: applied
//	default:        deny
//	allow domains:  api.openai.com, api.anthropic.com
//	blocked cidrs:  10.0.0.0/8, 169.254.169.254/32
//	blocked hosts:  localhost, host.docker.internal
//	events:         42 total (1 allowed, 41 denied)
//	top allowed:
//	  api.openai.com           20
//	top denied:
//	  169.254.169.254          15
//	  10.0.0.5                 12
//
// When PolicyStatus is "not_attempted" and the event counts are zero,
// the renderer writes a single "network policy: not attempted" line so
// a run that aborted before the policy stage still produces a
// well-formed section instead of an empty hole.
//
// The trailing newline policy mirrors renderStatusReport: each line is
// terminated with "\n", and the caller is responsible for any leading
// section header (e.g. a blank line or a "network:" banner) so the
// renderer composes cleanly into both the report and the markdown
// final-summary.
func RenderNetworkSummaryText(w io.Writer, s NetworkSummary) {
	fmt.Fprintf(w, "network policy: %s\n", networkPolicyStatusLabel(s.PolicyStatus))
	if s.PolicyError != "" {
		fmt.Fprintf(w, "policy error:   %s\n", s.PolicyError)
	}
	if s.Default != "" {
		fmt.Fprintf(w, "default:        %s\n", s.Default)
	}
	if len(s.AllowDomains) > 0 {
		fmt.Fprintf(w, "allow domains:  %s\n", strings.Join(s.AllowDomains, ", "))
	}
	if len(s.BlockedCIDRs) > 0 {
		fmt.Fprintf(w, "blocked cidrs:  %s\n", strings.Join(s.BlockedCIDRs, ", "))
	}
	if len(s.BlockedHosts) > 0 {
		fmt.Fprintf(w, "blocked hosts:  %s\n", strings.Join(s.BlockedHosts, ", "))
	}
	fmt.Fprintf(w, "events:         %d total (%d allowed, %d denied)\n",
		s.Total, s.AllowedCount, s.DeniedCount)
	if len(s.TopAllowed) > 0 {
		fmt.Fprintln(w, "top allowed:")
		for _, d := range s.TopAllowed {
			fmt.Fprintf(w, "  %-40s %d\n", d.Destination, d.Count)
		}
	}
	if len(s.TopDenied) > 0 {
		fmt.Fprintln(w, "top denied:")
		for _, d := range s.TopDenied {
			fmt.Fprintf(w, "  %-40s %d\n", d.Destination, d.Count)
		}
	}
}

// RenderNetworkSummaryMarkdown writes a Markdown-flavored version of
// the network summary to w. Used by the final-summary.md writer so the
// section composes into the broader markdown final summary alongside
// other artifacts.
//
// Format:
//
//	## Network
//
//	- policy: applied
//	- default: deny
//	- allow domains: api.openai.com, api.anthropic.com
//	- blocked cidrs: 10.0.0.0/8, 169.254.169.254/32
//	- blocked hosts: localhost, host.docker.internal
//	- events: 42 total (1 allowed, 41 denied)
//
//	### Top allowed
//
//	| destination | count |
//	| --- | --- |
//	| api.openai.com | 20 |
//
//	### Top denied
//
//	| destination | count |
//	| --- | --- |
//	| 169.254.169.254 | 15 |
//
// The renderer writes a leading "## Network\n\n" header. Callers that
// want to compose this section into a larger document write any
// preamble themselves and then call this function.
func RenderNetworkSummaryMarkdown(w io.Writer, s NetworkSummary) {
	fmt.Fprintln(w, "## Network")
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "- policy: %s\n", networkPolicyStatusLabel(s.PolicyStatus))
	if s.PolicyError != "" {
		fmt.Fprintf(w, "- policy error: %s\n", s.PolicyError)
	}
	if s.Default != "" {
		fmt.Fprintf(w, "- default: %s\n", s.Default)
	}
	if len(s.AllowDomains) > 0 {
		fmt.Fprintf(w, "- allow domains: %s\n", strings.Join(s.AllowDomains, ", "))
	}
	if len(s.BlockedCIDRs) > 0 {
		fmt.Fprintf(w, "- blocked cidrs: %s\n", strings.Join(s.BlockedCIDRs, ", "))
	}
	if len(s.BlockedHosts) > 0 {
		fmt.Fprintf(w, "- blocked hosts: %s\n", strings.Join(s.BlockedHosts, ", "))
	}
	fmt.Fprintf(w, "- events: %d total (%d allowed, %d denied)\n",
		s.Total, s.AllowedCount, s.DeniedCount)
	if len(s.TopAllowed) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "### Top allowed")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "| destination | count |")
		fmt.Fprintln(w, "| --- | --- |")
		for _, d := range s.TopAllowed {
			fmt.Fprintf(w, "| %s | %d |\n", d.Destination, d.Count)
		}
	}
	if len(s.TopDenied) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "### Top denied")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "| destination | count |")
		fmt.Fprintln(w, "| --- | --- |")
		for _, d := range s.TopDenied {
			fmt.Fprintf(w, "| %s | %d |\n", d.Destination, d.Count)
		}
	}
}

// networkPolicyStatusLabel maps the canonical PolicyStatus token onto a
// human-readable phrase. Unknown verbs pass through verbatim so a future
// event type (e.g. a richer policy verdict) renders even before the
// renderer learns its specific label.
func networkPolicyStatusLabel(status string) string {
	switch status {
	case NetworkSummaryPolicyNotAttempted:
		return "not attempted"
	case "attempt":
		return "attempting"
	case "applied":
		return "applied"
	case "failed":
		return "failed"
	default:
		if status == "" {
			return "(unknown)"
		}
		return status
	}
}
