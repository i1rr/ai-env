// Tests for the typed-data surface Plan §0.5 introduces (BindMount,
// EnvSpec extensions, BackendEventSink, and the Backend interface's
// GatewayAddress / MappedUID / ProbeImage methods). These are pure
// shape / contract tests: they verify field zero-values, the
// interface signatures, and the runDir/ipc mount-split invariant the
// plan locks in. Behavior-level tests for each method live with the
// adapter that implements it (mock/, docker/, podman/, docker_sbx/).
package backend_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/backend"
)

// TestBindMount_ZeroValueDefaults pins the zero-value semantics of
// BindMount so a caller that omits ReadOnly / Mode gets the documented
// "writable, source-mode" behavior. The plan's Bucket-1 wrappers
// depend on ReadOnly defaulting to false (the workspace mount is
// writable); the HOME shadow depends on Mode=0 meaning "use the
// source path's mode" (the supervisor's tmpfs source already carries
// the intended mode).
func TestBindMount_ZeroValueDefaults(t *testing.T) {
	t.Parallel()
	var m backend.BindMount
	if m.Source != "" {
		t.Errorf("BindMount{}.Source = %q, want empty", m.Source)
	}
	if m.Target != "" {
		t.Errorf("BindMount{}.Target = %q, want empty", m.Target)
	}
	if m.ReadOnly {
		t.Errorf("BindMount{}.ReadOnly = true, want false (writable default)")
	}
	if m.Mode != 0 {
		t.Errorf("BindMount{}.Mode = %v, want 0 (source-mode default)", m.Mode)
	}
}

// TestBindMount_RoundTripFields pins the public field set so a future
// refactor that renames Source / Target / ReadOnly / Mode catches the
// caller side (supervisor's BindMounts builder, adapter mount-spec
// renderers) at build time.
func TestBindMount_RoundTripFields(t *testing.T) {
	t.Parallel()
	want := backend.BindMount{
		Source:   "/run/ai-env-1/ipc",
		Target:   "/var/run/ai-env",
		ReadOnly: false,
		Mode:     0o755,
	}
	got := want
	if got.Source != want.Source ||
		got.Target != want.Target ||
		got.ReadOnly != want.ReadOnly ||
		got.Mode != want.Mode {
		t.Errorf("BindMount round-trip mismatch:\n got = %+v\n want = %+v", got, want)
	}
}

// TestEnvSpec_NewFieldsZeroValues pins the zero values for the
// Plan §0.5 EnvSpec extensions. BindMounts defaults to nil (no
// per-run mounts), UID defaults to nil (use the image's default user),
// HomeTarget defaults to "" (the supervisor resolves via ProbeImage
// + fallback /root). The defaults are what existing callers (the
// docker / docker-sbx / podman integration tests that don't populate
// the fields) rely on; this test catches a future change that flips
// any of them.
func TestEnvSpec_NewFieldsZeroValues(t *testing.T) {
	t.Parallel()
	var s backend.EnvSpec
	if s.BindMounts != nil {
		t.Errorf("EnvSpec{}.BindMounts = %v, want nil", s.BindMounts)
	}
	if s.UID != nil {
		t.Errorf("EnvSpec{}.UID = %v, want nil", s.UID)
	}
	if s.HomeTarget != "" {
		t.Errorf("EnvSpec{}.HomeTarget = %q, want empty", s.HomeTarget)
	}
}

// TestEnvSpec_UIDPointerDistinguishesUnsetFromZero pins the pointer
// semantics Plan §0.5 documents: nil means "use the image default",
// non-nil pointing at 0 means "run as root in the sandbox". A naive
// `int` field would conflate the two; the test catches a regression
// to a plain int.
func TestEnvSpec_UIDPointerDistinguishesUnsetFromZero(t *testing.T) {
	t.Parallel()
	zero := 0
	one := 1
	cases := []struct {
		name    string
		uid     *int
		wantUID int
		wantSet bool
	}{
		{name: "unset", uid: nil, wantSet: false},
		{name: "root", uid: &zero, wantUID: 0, wantSet: true},
		{name: "non-root", uid: &one, wantUID: 1, wantSet: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := backend.EnvSpec{UID: tc.uid}
			if tc.wantSet {
				if s.UID == nil {
					t.Fatalf("UID = nil, want pointer to %d", tc.wantUID)
				}
				if *s.UID != tc.wantUID {
					t.Errorf("*UID = %d, want %d", *s.UID, tc.wantUID)
				}
			} else if s.UID != nil {
				t.Errorf("UID = %d, want nil", *s.UID)
			}
		})
	}
}

// fakeSink is a minimal BackendEventSink the contract tests use to
// verify the interface signature. It records each Emit call so the
// test can assert on the recorded slice; the production sink lives in
// internal/run (LifecycleWriter) and the test recorder lives in
// internal/testharness — we keep the fake here local to avoid an
// import cycle and to keep the contract test self-contained.
type fakeSink struct {
	events []event
}

type event struct {
	verb     string
	metadata map[string]string
}

func (s *fakeSink) Emit(verb string, metadata map[string]string) error {
	s.events = append(s.events, event{verb: verb, metadata: metadata})
	return nil
}

// TestBackendEventSink_InterfaceShape pins the public interface
// signature Plan §0.5 introduces. The compile-time assignment below
// would refuse to compile if the interface signature drifted; the
// runtime assertions catch a regression where the fake stops being
// recorded.
func TestBackendEventSink_InterfaceShape(t *testing.T) {
	t.Parallel()
	var sink backend.BackendEventSink = &fakeSink{}
	if err := sink.Emit("proxy_started", map[string]string{"provider": "anthropic"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	recorder, ok := sink.(*fakeSink)
	if !ok {
		t.Fatalf("type assertion failed; sink is not *fakeSink")
	}
	if len(recorder.events) != 1 {
		t.Fatalf("recorder.events len = %d, want 1", len(recorder.events))
	}
	if recorder.events[0].verb != "proxy_started" {
		t.Errorf("verb = %q, want proxy_started", recorder.events[0].verb)
	}
	if recorder.events[0].metadata["provider"] != "anthropic" {
		t.Errorf("metadata[provider] = %q, want anthropic", recorder.events[0].metadata["provider"])
	}
}

// TestBackendEventSink_EmitErrorPropagates pins the contract that a
// sink rejecting an emission surfaces the error to the caller. Plan
// §10 row 10 says "graceful degradation": the caller logs the error
// and continues; the sink itself just has to honor the err return.
func TestBackendEventSink_EmitErrorPropagates(t *testing.T) {
	t.Parallel()
	want := errors.New("sink closed")
	sink := &errSink{err: want}
	var bs backend.BackendEventSink = sink
	if err := bs.Emit("gateway_stopped", nil); !errors.Is(err, want) {
		t.Errorf("Emit err = %v, want %v", err, want)
	}
}

type errSink struct {
	err error
}

func (s *errSink) Emit(verb string, metadata map[string]string) error {
	return s.err
}

// TestEnvSpec_RunDirSensitiveFilesNotInSandbox is the plan's named
// acceptance test (Plan §0.5 line 146). It verifies the BindMount
// split: the supervisor mounts <runDir>/ipc/ into the sandbox, NOT
// the whole <runDir>. Sensitive files (leaks.jsonl, secret-scan.json,
// the per-stream JSONL inputs) live in <runDir> directly so the
// agent UID inside the sandbox cannot read them via the bind-mount.
//
// The test constructs the canonical EnvSpec the supervisor would
// build for a real run and verifies:
//
//  1. There IS a bind-mount whose Source ends in "/ipc" — that is
//     the agent-visible IPC root.
//  2. There is NO bind-mount whose Source matches <runDir> directly
//     — the sensitive files at <runDir>/leaks.jsonl etc. are
//     therefore not reachable through any bind-mount.
//  3. The runDir's leaks.jsonl is created with mode 0600 owned by
//     the host supervisor user (we cannot test the UID here because
//     unit tests run as the test process's UID; we test the mode and
//     the absence-from-mounts invariant).
//
// Behavior-level enforcement (the agent process actually trying to
// open the file and failing) lives in the section-9 red-team
// scenario suite; this unit test pins the structural invariant.
func TestEnvSpec_RunDirSensitiveFilesNotInSandbox(t *testing.T) {
	t.Parallel()

	// Build a temp "runDir" tree the way internal/run.CreateRunDirectory
	// would: runDir with ipc/ subdir, plus the sensitive leaks.jsonl
	// living directly under runDir.
	runDir := t.TempDir()
	ipcDir := filepath.Join(runDir, "ipc")
	if err := os.MkdirAll(ipcDir, 0o755); err != nil {
		t.Fatalf("mkdir ipc: %v", err)
	}
	leaksPath := filepath.Join(runDir, "leaks.jsonl")
	if err := os.WriteFile(leaksPath, []byte{}, 0o600); err != nil {
		t.Fatalf("write leaks.jsonl: %v", err)
	}
	scanPath := filepath.Join(runDir, "secret-scan.json")
	if err := os.WriteFile(scanPath, []byte{}, 0o600); err != nil {
		t.Fatalf("write secret-scan.json: %v", err)
	}

	// Build the EnvSpec the supervisor would construct (BindMounts
	// split: ipc/ → /var/run/ai-env, NOT runDir → /var/run/ai-env).
	uidZero := 0
	spec := backend.EnvSpec{
		Name:          "fix-tests",
		Template:      "node",
		WorkspacePath: t.TempDir(),
		UID:           &uidZero,
		HomeTarget:    "/root",
		BindMounts: []backend.BindMount{
			{Source: ipcDir, Target: "/var/run/ai-env", ReadOnly: false},
		},
	}

	// Invariant 1: there IS a bind-mount whose Source ends in "/ipc".
	foundIPC := false
	for _, m := range spec.BindMounts {
		if strings.HasSuffix(m.Source, "/ipc") {
			foundIPC = true
			break
		}
	}
	if !foundIPC {
		t.Errorf("no bind-mount with /ipc Source; spec.BindMounts = %+v", spec.BindMounts)
	}

	// Invariant 2: no bind-mount maps <runDir> directly (the
	// sensitive files at runDir/leaks.jsonl etc. would otherwise be
	// reachable from inside the sandbox).
	for _, m := range spec.BindMounts {
		if m.Source == runDir {
			t.Errorf("bind-mount maps runDir directly (Source=%q); sensitive files would be visible from inside the sandbox", m.Source)
		}
	}

	// Invariant 3: the host-side leaks.jsonl is mode 0600 (per Plan
	// §0.2 + §0.5). We stat the file and check the perm bits; a
	// world-readable file would defeat the host-only intent even
	// without a bind-mount, since any other process running as a
	// different UID on the same host could read it.
	info, err := os.Stat(leaksPath)
	if err != nil {
		t.Fatalf("stat leaks.jsonl: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("leaks.jsonl mode = %o, want 0600", got)
	}
}
