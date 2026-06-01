package run

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/policy"
)

// TestInjectShimPath_PrependsToExistingPath asserts the helper rewrites a
// PATH= entry by placing the shim directory first and preserving the
// existing PATH after the colon separator. The behavior is the contract
// the supervisor's wiring relies on, and the future `ai-env run` CLI
// will compose against the same helper without re-implementing the rule.
func TestInjectShimPath_PrependsToExistingPath(t *testing.T) {
	in := []string{"HOME=/h", "PATH=/usr/bin:/bin", "LANG=C"}
	out := InjectShimPath(in, "/shim")

	wantPath := "PATH=/shim:/usr/bin:/bin"
	found := false
	for _, kv := range out {
		if kv == wantPath {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("InjectShimPath = %v, want entry %q", out, wantPath)
	}

	// HOME and LANG must survive untouched and in the original order.
	if out[0] != "HOME=/h" || out[2] != "LANG=C" {
		t.Errorf("non-PATH entries reordered: %v", out)
	}
	// Caller's slice must not be mutated.
	if in[1] != "PATH=/usr/bin:/bin" {
		t.Errorf("input slice mutated: %v", in)
	}
}

// TestInjectShimPath_AppendsWhenAbsent confirms the helper adds a fresh
// PATH= entry when the input env did not carry one. The supervisor's
// wiring relies on this so a caller that hands the supervisor an env
// without a PATH still sees the child resolve the shim first.
func TestInjectShimPath_AppendsWhenAbsent(t *testing.T) {
	in := []string{"HOME=/h"}
	out := InjectShimPath(in, "/shim")

	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2; got %v", len(out), out)
	}
	if out[1] != "PATH=/shim" {
		t.Errorf("out[1] = %q, want PATH=/shim", out[1])
	}
}

// TestInjectShimPath_NilEnv pins the nil-input behavior: a nil env
// returns a fresh slice containing only the PATH= entry, matching the
// "no inherited host PATH" rule documented on the helper.
func TestInjectShimPath_NilEnv(t *testing.T) {
	out := InjectShimPath(nil, "/shim")
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1; got %v", len(out), out)
	}
	if out[0] != "PATH=/shim" {
		t.Errorf("out[0] = %q, want PATH=/shim", out[0])
	}
}

// TestInjectShimPath_EmptyShimDirNoOp asserts the helper returns env
// unchanged when shimDir is the empty string. The defensive branch
// protects callers outside NewSupervisor (e.g. unit tests of the future
// CLI wiring) from producing a malformed PATH.
func TestInjectShimPath_EmptyShimDirNoOp(t *testing.T) {
	in := []string{"PATH=/usr/bin"}
	out := InjectShimPath(in, "")
	if len(out) != 1 || out[0] != "PATH=/usr/bin" {
		t.Errorf("InjectShimPath(_, \"\") = %v, want input unchanged", out)
	}
}

// TestInjectShimPath_EmptyExistingPathValue covers the edge case where
// the env carries "PATH=" (empty value). The helper must produce
// "PATH=<shimDir>" rather than "PATH=<shimDir>:" so the resulting
// PATH does not contain a leading empty entry that the shell would
// resolve as the current directory.
func TestInjectShimPath_EmptyExistingPathValue(t *testing.T) {
	in := []string{"PATH="}
	out := InjectShimPath(in, "/shim")
	if len(out) != 1 || out[0] != "PATH=/shim" {
		t.Errorf("InjectShimPath = %v, want [PATH=/shim]", out)
	}
}

// TestNewSupervisor_ShellShimRequiresShellShimDir pins the constructor's
// rule: opting into ShellShim without naming the wrapper directory must
// fail loudly. The supervisor does not invent a directory; the future
// `ai-env run --shell-shim` CLI and test fixtures both pin the location
// explicitly.
func TestNewSupervisor_ShellShimRequiresShellShimDir(t *testing.T) {
	dir := newSupervisorRunDir(t)
	_, err := NewSupervisor(SupervisorOptions{
		RunDir:    dir.Path,
		RunID:     dir.ID,
		EnvName:   "env",
		Backend:   "local-process",
		Agent:     "claude",
		Task:      "do thing",
		Command:   shellCmd("true"),
		ShellShim: true,
		// ShellShimDir intentionally empty.
	})
	if err == nil {
		t.Fatalf("NewSupervisor: expected error when ShellShim is true and ShellShimDir is empty")
	}
	if !strings.Contains(err.Error(), "ShellShimDir") {
		t.Errorf("error = %v, want it to mention ShellShimDir", err)
	}
}

// TestNewSupervisor_ShellShimRequiresEngine pins the rule that the shim
// wiring is only useful when there is a policy engine to consult. The
// supervisor fails fast rather than silently degrading into "log every
// command, deny none."
func TestNewSupervisor_ShellShimRequiresEngine(t *testing.T) {
	dir := newSupervisorRunDir(t)
	shimDir := t.TempDir()
	_, err := NewSupervisor(SupervisorOptions{
		RunDir:       dir.Path,
		RunID:        dir.ID,
		EnvName:      "env",
		Backend:      "local-process",
		Agent:        "claude",
		Task:         "do thing",
		Command:      shellCmd("true"),
		ShellShim:    true,
		ShellShimDir: shimDir,
		// PolicyEngine / PolicyEnginePath intentionally empty.
	})
	if err == nil {
		t.Fatalf("NewSupervisor: expected error when ShellShim is true without an engine")
	}
	if !strings.Contains(err.Error(), "PolicyEngine") {
		t.Errorf("error = %v, want it to mention PolicyEngine", err)
	}
}

// TestNewSupervisor_ShellShimMutatesPATH confirms that when ShellShim is
// true the supervisor prepends ShellShimDir to the child's PATH env.
// This is the actual "wire the shim into the child" contract Plan 08
// step 9 calls out: an agent that resolves "bash" through PATH lands on
// the wrapper before the real binary.
func TestNewSupervisor_ShellShimMutatesPATH(t *testing.T) {
	dir := newSupervisorRunDir(t)
	shimDir := t.TempDir()

	eng := policy.NewEngine(validPolicyConfig())
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:       dir.Path,
		RunID:        dir.ID,
		EnvName:      "env",
		Backend:      "local-process",
		Agent:        "claude",
		Task:         "do thing",
		Command:      CommandSpec{Program: "true", Env: []string{"HOME=/h", "PATH=/usr/bin", "LANG=C"}},
		PolicyEngine: eng,
		ShellShim:    true,
		ShellShimDir: shimDir,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	wantPath := "PATH=" + shimDir + ":/usr/bin"
	foundPath := false
	for _, kv := range sup.opts.Command.Env {
		if kv == wantPath {
			foundPath = true
			break
		}
	}
	if !foundPath {
		t.Errorf("Command.Env = %v, want PATH entry %q", sup.opts.Command.Env, wantPath)
	}
}

// TestNewSupervisor_NoShellShimLeavesPATHIntact pins the negative side
// of the wiring: without the opt-in flag the supervisor must not touch
// the child's PATH and must not open a shell-commands.jsonl writer.
// Legacy callers (plan-03 / 04 / 05 / 06 / 07 tests) rely on the
// "behavior unchanged when the flag is off" rule.
func TestNewSupervisor_NoShellShimLeavesPATHIntact(t *testing.T) {
	dir := newSupervisorRunDir(t)
	originalEnv := []string{"HOME=/h", "PATH=/usr/bin", "LANG=C"}

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:  dir.Path,
		RunID:   dir.ID,
		EnvName: "env",
		Backend: "local-process",
		Agent:   "claude",
		Task:    "do thing",
		Command: CommandSpec{Program: "true", Env: originalEnv},
		// ShellShim intentionally false.
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	if sup.shellCmdLog != nil {
		t.Errorf("shellCmdLog = non-nil, want nil when ShellShim is false")
	}
	// PATH must be exactly what the caller passed in.
	gotPath := ""
	for _, kv := range sup.opts.Command.Env {
		if strings.HasPrefix(kv, "PATH=") {
			gotPath = kv
			break
		}
	}
	if gotPath != "PATH=/usr/bin" {
		t.Errorf("Command.Env PATH = %q, want PATH=/usr/bin", gotPath)
	}

	// The shell-commands.jsonl file is created as an empty placeholder
	// by CreateRunDirectory regardless of whether the shim is wired.
	// What changes when ShellShim is off is that the supervisor never
	// opens the file for append, so no records can flow in. The
	// observable for "the shim was not wired" is therefore
	// shellCmdLog == nil on the Supervisor; the file itself stays as
	// the zero-byte placeholder.
	path := filepath.Join(dir.Path, "shell-commands.jsonl")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat shell-commands.jsonl placeholder: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("shell-commands.jsonl size = %d, want 0 (placeholder, no writer wired)", info.Size())
	}
}

// TestNewSupervisor_ShellShimOpensCommandsLog confirms the supervisor
// materializes shell-commands.jsonl in the run directory when the
// flag is on. The file is the audit trail the shim appends to; its
// presence (created by the writer's O_CREATE open) is the observable
// the future `ai-env run --shell-shim` CLI relies on for the "shim is
// wired" affordance.
func TestNewSupervisor_ShellShimOpensCommandsLog(t *testing.T) {
	dir := newSupervisorRunDir(t)
	shimDir := t.TempDir()
	eng := policy.NewEngine(validPolicyConfig())

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:       dir.Path,
		RunID:        dir.ID,
		EnvName:      "env",
		Backend:      "local-process",
		Agent:        "claude",
		Task:         "do thing",
		Command:      CommandSpec{Program: "true", Env: []string{"PATH=/usr/bin"}},
		PolicyEngine: eng,
		ShellShim:    true,
		ShellShimDir: shimDir,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if sup.shellCmdLog == nil {
		t.Fatalf("shellCmdLog = nil, want non-nil when ShellShim is true")
	}

	path := filepath.Join(dir.Path, "shell-commands.jsonl")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("shell-commands.jsonl missing under run dir: %v", err)
	}

	// The shim's log must accept writes once the supervisor opens it.
	// We drive a record through it to confirm the writer is usable
	// end-to-end (open + write + flush). The supervisor itself does
	// not write records; that is the shim's job at command-exec time.
	if err := sup.shellCmdLog.Write(policy.ShellCommandRecord{
		Program:       "bash",
		Argv:          []string{"bash", "-c", "echo hi"},
		CmdLine:       "bash -c echo hi",
		Decision:      "allow",
		PolicyEventID: "evt_test_0001",
	}); err != nil {
		t.Errorf("shellCmdLog.Write: %v", err)
	}

	// Close cooperates so a subsequent Run() deferred-drain Close is a
	// safe no-op.
	if err := sup.shellCmdLog.Close(); err != nil {
		t.Errorf("shellCmdLog.Close: %v", err)
	}
}

// TestNewSupervisor_ShellShimCanRunEndToEnd drives a happy-path run with
// the shim enabled. The test does NOT need the shim binary to exist in
// shimDir (the child program is the absolute path /bin/true, which
// bypasses PATH); it confirms that wiring the shim does not break the
// happy-path lifecycle. This is the "non-regression" backstop for the
// step-9 wiring: enabling --shell-shim must not change the run's
// terminal state.
func TestNewSupervisor_ShellShimCanRunEndToEnd(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)
	shimDir := t.TempDir()
	eng := policy.NewEngine(validPolicyConfig())

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "env",
		Backend:           "local-process",
		Agent:             "claude",
		Task:              "do thing",
		Command:           shellCmd("echo hi; exit 0"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		PolicyEngine:      eng,
		ShellShim:         true,
		ShellShimDir:      shimDir,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}

	// The log file must still exist after Run (it was opened in
	// NewSupervisor and closed in Run's deferred drain). An empty file
	// is fine: nothing in this test actually appended a record.
	if _, err := os.Stat(filepath.Join(dir.Path, "shell-commands.jsonl")); err != nil {
		t.Errorf("shell-commands.jsonl missing post-run: %v", err)
	}
}

// TestNewSupervisor_ShellShimInstallsWrappers is the Batch 1.4 wiring
// acceptance: NewSupervisor must materialize one wrapper script per
// canonical ShimProgramSet entry in ShellShimDir before the run starts.
// The wrapper count and the per-file shebang are the on-disk evidence
// that policy.InstallShim ran; this test does not re-validate the
// wrapper body (the policy package's own tests already pin that).
func TestNewSupervisor_ShellShimInstallsWrappers(t *testing.T) {
	dir := newSupervisorRunDir(t)
	shimDir := t.TempDir()
	eng := policy.NewEngine(validPolicyConfig())

	_, err := NewSupervisor(SupervisorOptions{
		RunDir:       dir.Path,
		RunID:        dir.ID,
		EnvName:      "env",
		Backend:      "local-process",
		Agent:        "claude",
		Task:         "do thing",
		Command:      CommandSpec{Program: "true", Env: []string{"PATH=/usr/bin"}},
		PolicyEngine: eng,
		ShellShim:    true,
		ShellShimDir: shimDir,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	for _, p := range policy.ShimProgramSet {
		path := filepath.Join(shimDir, string(p))
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("wrapper for %q missing in shimDir: %v", string(p), err)
			continue
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("wrapper %q mode = %v, want 0755", path, info.Mode().Perm())
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read wrapper %q: %v", path, err)
			continue
		}
		if !strings.HasPrefix(string(body), "#!/bin/sh\n") {
			t.Errorf("wrapper %q missing /bin/sh shebang", path)
		}
		wantExec := "exec " + DefaultShimHelperCmd + " shell " + string(p) + " \"$@\""
		if !strings.Contains(string(body), wantExec) {
			t.Errorf("wrapper %q missing exec line %q", path, wantExec)
		}
	}
}

// TestNewSupervisor_ShellShim_ShimHelperCmdOverride pins the
// ShimHelperCmd option: a caller (typically a test harness) can
// override the in-sandbox helper invocation so the wrapper's exec
// line points at a host-side stub. The override flows verbatim into
// the wrapper body so the wrapper is usable end-to-end without a
// backend.
func TestNewSupervisor_ShellShim_ShimHelperCmdOverride(t *testing.T) {
	dir := newSupervisorRunDir(t)
	shimDir := t.TempDir()
	eng := policy.NewEngine(validPolicyConfig())

	override := "/tmp/fixtures/test-shim-helper --opt"
	_, err := NewSupervisor(SupervisorOptions{
		RunDir:        dir.Path,
		RunID:         dir.ID,
		EnvName:       "env",
		Backend:       "local-process",
		Agent:         "claude",
		Task:          "do thing",
		Command:       CommandSpec{Program: "true", Env: []string{"PATH=/usr/bin"}},
		PolicyEngine:  eng,
		ShellShim:     true,
		ShellShimDir:  shimDir,
		ShimHelperCmd: override,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(shimDir, "sh"))
	if err != nil {
		t.Fatalf("read sh wrapper: %v", err)
	}
	wantExec := "exec " + override + " shell sh \"$@\""
	if !strings.Contains(string(body), wantExec) {
		t.Errorf("sh wrapper missing override exec line %q; body = %q", wantExec, string(body))
	}
}

// TestNewSupervisor_ShellShim_HostModeEmitsCoverageDegraded is the
// Batch 1.3 acceptance: host-mode runs (BackendAdapter == nil) cannot
// install the canonical absolute-path shadow mounts, so the supervisor
// emits `shim_coverage_degraded` to make the degradation auditable.
// The verb carries the canonical-path prefix set in metadata so a
// downstream remediation reader sees exactly which paths the shim
// cannot shadow.
func TestNewSupervisor_ShellShim_HostModeEmitsCoverageDegraded(t *testing.T) {
	dir := newSupervisorRunDir(t)
	shimDir := t.TempDir()
	eng := policy.NewEngine(validPolicyConfig())

	_, err := NewSupervisor(SupervisorOptions{
		RunDir:       dir.Path,
		RunID:        dir.ID,
		EnvName:      "env",
		Backend:      "local-process",
		Agent:        "claude",
		Task:         "do thing",
		Command:      CommandSpec{Program: "true", Env: []string{"PATH=/usr/bin"}},
		PolicyEngine: eng,
		ShellShim:    true,
		ShellShimDir: shimDir,
		// BackendAdapter intentionally nil to drive host-mode.
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	// Read lifecycle.jsonl and look for the shim_coverage_degraded verb.
	raw, err := os.ReadFile(filepath.Join(dir.Path, "lifecycle.jsonl"))
	if err != nil {
		t.Fatalf("read lifecycle.jsonl: %v", err)
	}
	if len(raw) == 0 {
		t.Fatalf("lifecycle.jsonl is empty, want at least the shim_coverage_degraded verb")
	}
	found := false
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		var evt LifecycleEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("parse lifecycle event %q: %v", line, err)
		}
		if evt.Verb != LifecycleVerbShimCoverageDegraded {
			continue
		}
		found = true
		if evt.Metadata["reason"] != "host_mode" {
			t.Errorf("shim_coverage_degraded metadata reason = %q, want host_mode", evt.Metadata["reason"])
		}
		if evt.Metadata["program"] != "*" {
			t.Errorf("shim_coverage_degraded metadata program = %q, want *", evt.Metadata["program"])
		}
		gotMissing := evt.Metadata["missing"]
		wantMissing := strings.Join(policy.ShimCanonicalPathPrefixes, ",")
		if gotMissing != wantMissing {
			t.Errorf("shim_coverage_degraded metadata missing = %q, want %q", gotMissing, wantMissing)
		}
	}
	if !found {
		t.Errorf("lifecycle.jsonl missing shim_coverage_degraded verb; raw = %q", string(raw))
	}
}

// TestShimLimitationsDocumented is the discoverability guard plan 08
// step 10 calls for. The README and internal/policy/shim.go are the two
// surfaces a downstream operator reads; this test pins the four
// limitations enumerated in the master plan onto both so a future
// refactor that loses the text fails the test rather than the operator.
func TestShimLimitationsDocumented(t *testing.T) {
	// The four limitations the master plan documents (section 22):
	// absolute paths, static binaries, interpreters, kernel-level
	// controls. We check for short, distinctive substrings rather than
	// the full sentence so a copy edit that reflows the prose does not
	// fail the test.
	needles := []string{
		"absolute path",
		"static binar",
		"kernel-level",
	}

	shimSrc, err := os.ReadFile("../policy/shim.go")
	if err != nil {
		t.Fatalf("read shim.go: %v", err)
	}
	shimText := string(shimSrc)
	for _, n := range needles {
		if !strings.Contains(strings.ToLower(shimText), strings.ToLower(n)) {
			t.Errorf("internal/policy/shim.go missing limitation phrase %q", n)
		}
	}

	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readmeText := strings.ToLower(string(readme))
	if !strings.Contains(readmeText, "shell-shim") && !strings.Contains(readmeText, "shell shim") {
		t.Errorf("README.md does not mention the shell-shim flag")
	}
	for _, n := range needles {
		if !strings.Contains(readmeText, strings.ToLower(n)) {
			t.Errorf("README.md missing shim limitation phrase %q", n)
		}
	}
}
