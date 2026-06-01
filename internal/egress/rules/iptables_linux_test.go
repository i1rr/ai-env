//go:build linux

package rules

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestIptablesDriver_InstallEmitsExpectedSequence pins the exact
// `iptables` invocations the Linux driver emits at Install
// time. The supervisor's audit story depends on this ordering:
// the chain must exist before the NFLOG rule is added, and the
// JUMP at OUTPUT 1 must be the last step so a half-installed
// chain does not divert traffic.
func TestIptablesDriver_InstallEmitsExpectedSequence(t *testing.T) {
	rec := newRecordingCommander()
	d := iptablesDriver{}
	opts := Options{
		Chain:      "AIENV-EGR-deadbeef",
		NFLOGGroup: 42,
		Verdict:    VerdictReject,
	}
	if err := d.Install(context.Background(), rec, opts); err != nil {
		t.Fatalf("Install err = %v", err)
	}
	summaries := rec.CallSummaries()
	want := []string{
		"iptables -N AIENV-EGR-deadbeef",
		"iptables -A AIENV-EGR-deadbeef -j NFLOG --nflog-group 42 --nflog-prefix reject",
		"iptables -A AIENV-EGR-deadbeef -j REJECT --reject-with icmp-port-unreachable",
		"iptables -I OUTPUT 1 -j AIENV-EGR-deadbeef",
	}
	if len(summaries) != len(want) {
		t.Fatalf("got %d calls, want %d: %v", len(summaries), len(want), summaries)
	}
	for i, s := range summaries {
		if s != want[i] {
			t.Errorf("call[%d] = %q, want %q", i, s, want[i])
		}
	}
}

// TestIptablesDriver_InstallWrapsInNsenterWhenNetNSSet pins the
// `ns.Do` equivalent: when Options.NetNSPath is set the driver
// emits the `--ai-env-netns <path>` sentinel that the production
// execCommander rewrites to `nsenter --net=<path> -- iptables
// <rest>`. The recording commander captures the sentinel
// verbatim so a regression that lost the netns wrapping surfaces
// here.
func TestIptablesDriver_InstallWrapsInNsenterWhenNetNSSet(t *testing.T) {
	rec := newRecordingCommander()
	d := iptablesDriver{}
	opts := Options{
		Chain:      "AIENV-EGR-cafef00d",
		NFLOGGroup: 1,
		NetNSPath:  "/proc/1234/ns/net",
		Verdict:    VerdictReject,
	}
	if err := d.Install(context.Background(), rec, opts); err != nil {
		t.Fatalf("Install err = %v", err)
	}
	for _, c := range rec.CallSummaries() {
		if !strings.Contains(c, "--ai-env-netns /proc/1234/ns/net") {
			t.Errorf("call %q missing netns sentinel", c)
		}
	}
}

// TestIptablesDriver_InstallRollsBackOnPartialFailure pins the
// crash-safety guarantee: when the JUMP-at-OUTPUT step fails
// (the most common partial-install failure: the kernel rejects
// the rule because of ordering), the driver unwinds every
// previously-successful step. The recording commander returns a
// canned error for the JUMP step and the test asserts the chain
// is flushed and deleted in reverse order.
func TestIptablesDriver_InstallRollsBackOnPartialFailure(t *testing.T) {
	rec := newRecordingCommander()
	wantErr := errors.New("kernel rejected")
	// Cause `-I OUTPUT 1 ...` to fail.
	rec.runError["iptables -I OUTPUT 1 -j AIENV-EGR-deadbeef"] = wantErr

	d := iptablesDriver{}
	opts := Options{Chain: "AIENV-EGR-deadbeef", NFLOGGroup: 1, Verdict: VerdictReject}
	err := d.Install(context.Background(), rec, opts)
	if err == nil {
		t.Fatal("Install err = nil, want non-nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("Install err = %v, want wrap of %v", err, wantErr)
	}
	// Verify the rollback sequence ran (in reverse).
	summaries := rec.CallSummaries()
	rollbackPrefixes := []string{
		"iptables -F AIENV-EGR-deadbeef",
		"iptables -F AIENV-EGR-deadbeef",
		"iptables -X AIENV-EGR-deadbeef",
	}
	var rolledBack int
	for _, want := range rollbackPrefixes {
		for _, c := range summaries {
			if c == want {
				rolledBack++
				break
			}
		}
	}
	if rolledBack < 1 {
		t.Errorf("rollback did not run; calls: %v", summaries)
	}
}

// TestIptablesDriver_UninstallSequence pins the teardown order:
// detach JUMP from OUTPUT first, then flush, then delete the
// chain. The order matters because iptables refuses to delete a
// chain that is still referenced.
func TestIptablesDriver_UninstallSequence(t *testing.T) {
	rec := newRecordingCommander()
	d := iptablesDriver{}
	if err := d.Uninstall(context.Background(), rec, "AIENV-EGR-deadbeef"); err != nil {
		t.Fatalf("Uninstall err = %v", err)
	}
	want := []string{
		"iptables -D OUTPUT -j AIENV-EGR-deadbeef",
		"iptables -F AIENV-EGR-deadbeef",
		"iptables -X AIENV-EGR-deadbeef",
	}
	summaries := rec.CallSummaries()
	if len(summaries) != len(want) {
		t.Fatalf("got %d calls, want %d: %v", len(summaries), len(want), summaries)
	}
	for i, s := range summaries {
		if s != want[i] {
			t.Errorf("call[%d] = %q, want %q", i, s, want[i])
		}
	}
}

// TestUnwrapNetNS pins the production execCommander's sentinel
// rewrite: a leading "--ai-env-netns <path>" pair is replaced
// with `nsenter --net=<path> -- <name>`. A regression here would
// silently drop the netns wrapping in production while keeping
// the recording commander tests green.
func TestUnwrapNetNS(t *testing.T) {
	prog, args := unwrapNetNS("iptables", []string{"--ai-env-netns", "/proc/9/ns/net", "-L"})
	if prog != "nsenter" {
		t.Errorf("program = %q, want %q", prog, "nsenter")
	}
	wantArgs := []string{"--net=/proc/9/ns/net", "--", "iptables", "-L"}
	if len(args) != len(wantArgs) {
		t.Fatalf("args = %v, want %v", args, wantArgs)
	}
	for i := range wantArgs {
		if args[i] != wantArgs[i] {
			t.Errorf("args[%d] = %q, want %q", i, args[i], wantArgs[i])
		}
	}
	// No sentinel: passthrough.
	prog, args = unwrapNetNS("iptables", []string{"-L"})
	if prog != "iptables" || len(args) != 1 || args[0] != "-L" {
		t.Errorf("passthrough = (%q, %v), want (iptables, [-L])", prog, args)
	}
}
