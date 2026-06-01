//go:build darwin

package rules

import (
	"context"
	"strings"
	"testing"
)

// TestPFDriver_InstallEmitsLoadAnchor pins the macOS rule
// installer's invocation: it shells out to `sh -c "printf ... |
// pfctl -a <Chain> -f -"` to load the anchor's rule body.
func TestPFDriver_InstallEmitsLoadAnchor(t *testing.T) {
	rec := newRecordingCommander()
	d := pfDriver{}
	opts := Options{Chain: "AIENV-EGR-deadbeef", Verdict: VerdictReject}
	if err := d.Install(context.Background(), rec, opts); err != nil {
		t.Fatalf("Install err = %v", err)
	}
	var sawShell bool
	for _, c := range rec.CallSummaries() {
		if strings.HasPrefix(c, "sh -c") && strings.Contains(c, "pfctl -a AIENV-EGR-deadbeef -f -") {
			sawShell = true
		}
	}
	if !sawShell {
		t.Errorf("call summaries did not include the pfctl load: %v", rec.CallSummaries())
	}
}

// TestPFDriver_UninstallFlushesAnchor pins the teardown: pfctl
// -a <Chain> -F all flushes the anchor's rules. The anchor
// itself is removed by the operator's pre-existing pf.conf
// include (documented as a setup step) so the driver does not
// emit a delete.
func TestPFDriver_UninstallFlushesAnchor(t *testing.T) {
	rec := newRecordingCommander()
	d := pfDriver{}
	if err := d.Uninstall(context.Background(), rec, "AIENV-EGR-deadbeef"); err != nil {
		t.Fatalf("Uninstall err = %v", err)
	}
	want := "pfctl -a AIENV-EGR-deadbeef -F all"
	if got := rec.CallSummaries(); len(got) != 1 || got[0] != want {
		t.Errorf("got %v, want exactly [%q]", got, want)
	}
}

// TestPFDriver_ExistsScansAnchorList pins the existence check:
// pfDriver issues `pfctl -sA` (list anchors) and looks for the
// chain name. A regression that switched to `-sr` (list rules)
// would silently flip the existence semantics.
func TestPFDriver_ExistsScansAnchorList(t *testing.T) {
	rec := newRecordingCommander()
	rec.runResponse["pfctl -sA"] = []byte("OtherAnchor\nAIENV-EGR-deadbeef\n")
	d := pfDriver{}
	exists, err := d.Exists(context.Background(), rec, "AIENV-EGR-deadbeef")
	if err != nil {
		t.Fatalf("Exists err = %v", err)
	}
	if !exists {
		t.Errorf("Exists = false, want true")
	}
	// Negative case.
	rec2 := newRecordingCommander()
	rec2.runResponse["pfctl -sA"] = []byte("OtherAnchor\n")
	exists, err = d.Exists(context.Background(), rec2, "AIENV-EGR-deadbeef")
	if err != nil {
		t.Fatalf("Exists err = %v", err)
	}
	if exists {
		t.Errorf("Exists = true, want false (chain not in list)")
	}
}
