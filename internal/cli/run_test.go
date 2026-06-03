package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/agents"
	"github.com/i1rr/ai-env/internal/backend"
	"github.com/i1rr/ai-env/internal/backend/mock"
	"github.com/i1rr/ai-env/internal/config"
	"github.com/i1rr/ai-env/internal/run"
)

// withRunSeams temporarily rebinds BackendFactory and
// RunAgentPlanner to test stubs and returns a deferred cleanup that
// restores the production defaults. Tests use this so a parallel
// future test does not see leaked seams.
func withRunSeams(t *testing.T, bf func(name, mode string) (backend.Backend, error), planner func(ctx context.Context, agentName string, contract config.AgentEntry, req agents.Request, env agents.EnvironmentProbe) (agents.LaunchPlan, error)) {
	t.Helper()
	prevBF := BackendFactory
	prevPlanner := RunAgentPlanner
	BackendFactory = bf
	RunAgentPlanner = planner
	t.Cleanup(func() {
		BackendFactory = prevBF
		RunAgentPlanner = prevPlanner
	})
}

// shortTempDir mirrors the control_socket_test helper: it creates a
// temp dir under /tmp rather than t.TempDir() because the default
// macOS test TempDir under /var/folders/... is long enough that the
// per-run control.sock path can exceed the Unix-domain-socket path
// limit (104 chars on Darwin / 108 on Linux). Routing through /tmp
// keeps the socket path well under the platform limit so the
// supervisor's canonical pre-launch step 2 (control socket Start)
// does not fail with a confusing "bind: invalid argument" or
// "no such file or directory" error driven by truncation.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "aienv-run-")
	if err != nil {
		t.Fatalf("MkdirTemp /tmp: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

// noopPlanner is the default test planner: returns a LaunchPlan
// whose Command is an echo invocation so launchChildBackend can
// finish immediately with exit 0 via the mock backend's default
// ExecResult.
func noopPlanner(_ context.Context, _ string, _ config.AgentEntry, req agents.Request, _ agents.EnvironmentProbe) (agents.LaunchPlan, error) {
	return agents.LaunchPlan{
		Command: backend.Command{
			Program: "echo",
			Args:    []string{"ok"},
			Dir:     req.WorkspaceDir,
		},
		CredentialMode: agents.CredentialModeBackendManaged,
		StdinBody:      req.TaskBody,
	}, nil
}

// mockBackendFactory returns a fresh in-memory mock backend
// regardless of the requested name so tests can scaffold an
// ai-env.yaml with sandbox.backend=docker-sbx (the production
// default) without standing up a real container runtime.
func mockBackendFactory(_ string, _ string) (backend.Backend, error) {
	return mock.New(nil), nil
}

func TestRunRun_RequiresTask(t *testing.T) {
	cwd := shortTempDir(t)
	if err := RunNew(NewOptions{EnvName: "demo", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	err := RunRun(RunOptions{
		EnvName: "demo",
		Cwd:     cwd,
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected RunRun without --task to fail")
	}
	if !strings.Contains(err.Error(), "task") {
		t.Errorf("expected error to mention --task, got %v", err)
	}
}

func TestRunRun_UnknownEnv(t *testing.T) {
	cwd := shortTempDir(t)
	if err := RunNew(NewOptions{EnvName: "demo", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	err := RunRun(RunOptions{
		EnvName: "no-such-env",
		Task:    "fix it",
		Cwd:     cwd,
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected RunRun against missing workspace to fail")
	}
	if !strings.Contains(err.Error(), "workspace") {
		t.Errorf("expected workspace error, got %v", err)
	}
}

func TestRunRun_HappyPath_MockBackend(t *testing.T) {
	withRunSeams(t, mockBackendFactory, noopPlanner)

	cwd := shortTempDir(t)
	if err := RunNew(NewOptions{EnvName: "demo", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}

	var out, errOut bytes.Buffer
	err := RunRun(RunOptions{
		EnvName: "demo",
		Agent:   "claude",
		Task:    "make it pass",
		Cwd:     cwd,
		Stdout:  &out,
		Stderr:  &errOut,
	})
	if err != nil {
		t.Fatalf("RunRun happy path: %v\nstderr:\n%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "state:") {
		t.Errorf("expected state line in stdout:\n%s", out.String())
	}
	if !strings.Contains(out.String(), string(run.StateCompleted)) {
		t.Errorf("expected terminal state %s in stdout:\n%s", run.StateCompleted, out.String())
	}

	// Verify the supervisor materialized a run directory with lifecycle.jsonl.
	aiEnvDir := filepath.Join(cwd, ".ai-env")
	latest, err := run.LatestRunForEnv(aiEnvDir, "demo")
	if err != nil {
		t.Fatalf("LatestRunForEnv: %v", err)
	}
	lcPath := run.LifecyclePath(latest.Path)
	if info, err := os.Stat(lcPath); err != nil {
		t.Fatalf("stat lifecycle.jsonl: %v", err)
	} else if info.Size() == 0 {
		t.Errorf("lifecycle.jsonl is empty; supervisor did not record any events")
	}

	rec, err := run.ReadRecord(latest.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.State != run.StateCompleted {
		t.Errorf("run.json state = %s, want %s", rec.State, run.StateCompleted)
	}
	if rec.EnvName != "demo" {
		t.Errorf("run.json env_name = %s, want demo", rec.EnvName)
	}

	taskBody, err := os.ReadFile(run.TaskPath(aiEnvDir, latest.ID))
	if err != nil {
		t.Fatalf("read task.md: %v", err)
	}
	if !strings.Contains(string(taskBody), "make it pass") {
		t.Errorf("task.md content = %q, want it to contain the --task body", string(taskBody))
	}
}

func TestRunRun_FallbackBackend(t *testing.T) {
	// Primary backend returns Available=false; fallback returns the
	// healthy mock. We assert RunRun completes successfully and the
	// notice is printed to stderr.
	primaryCalled := false
	fallbackCalled := false
	factory := func(name, mode string) (backend.Backend, error) {
		switch name {
		case "docker-sbx":
			primaryCalled = true
			bk := mock.New(nil)
			bk.SetStatus(backend.BackendStatus{
				Name:      "docker-sbx",
				Available: false,
				Message:   "test-injected unavailable",
			})
			return bk, nil
		case "mock":
			fallbackCalled = true
			return mock.New(nil), nil
		default:
			return nil, errors.New("unexpected backend name in test: " + name)
		}
	}
	withRunSeams(t, factory, noopPlanner)

	cwd := shortTempDir(t)
	if err := RunNew(NewOptions{EnvName: "demo", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	// Patch the generated ai-env.yaml so fallback_backend points at the
	// in-memory mock; `ai-env new` writes "none" by default which would
	// block the fallback path.
	cfgPath := filepath.Join(cwd, ".ai-env", "ai-env.yaml")
	if err := patchAIEnvFallback(cfgPath, "mock"); err != nil {
		t.Fatalf("patchAIEnvFallback: %v", err)
	}

	var out, errOut bytes.Buffer
	err := RunRun(RunOptions{
		EnvName: "demo",
		Agent:   "claude",
		Task:    "exercise fallback",
		Cwd:     cwd,
		Stdout:  &out,
		Stderr:  &errOut,
	})
	if err != nil {
		t.Fatalf("RunRun fallback path: %v\nstderr:\n%s", err, errOut.String())
	}
	if !primaryCalled {
		t.Errorf("primary backend was not constructed")
	}
	if !fallbackCalled {
		t.Errorf("fallback backend was not constructed")
	}
	if !strings.Contains(errOut.String(), "fallback") {
		t.Errorf("expected fallback notice on stderr, got:\n%s", errOut.String())
	}
}

func TestRunRun_Continue_LinksPreviousRun(t *testing.T) {
	withRunSeams(t, mockBackendFactory, noopPlanner)

	cwd := shortTempDir(t)
	if err := RunNew(NewOptions{EnvName: "demo", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}

	// First run, no --continue. Capture its run id from the run dir
	// once it completes.
	var firstOut, firstErr bytes.Buffer
	if err := RunRun(RunOptions{
		EnvName: "demo",
		Agent:   "claude",
		Task:    "first round",
		Cwd:     cwd,
		Stdout:  &firstOut,
		Stderr:  &firstErr,
	}); err != nil {
		t.Fatalf("first RunRun: %v\nstderr:\n%s", err, firstErr.String())
	}
	aiEnvDir := filepath.Join(cwd, ".ai-env")
	first, err := run.LatestRunForEnv(aiEnvDir, "demo")
	if err != nil {
		t.Fatalf("LatestRunForEnv after first run: %v", err)
	}
	firstID := first.ID

	// Sleep a beat so the run ID's timestamp portion differs even on
	// fast hosts (the hex suffix is also a guard, but we want the
	// LatestRunForEnv lookup to deterministically pick the older one
	// as the predecessor).
	time.Sleep(1100 * time.Millisecond)

	var secondOut, secondErr bytes.Buffer
	if err := RunRun(RunOptions{
		EnvName:  "demo",
		Agent:    "claude",
		Task:     "second round",
		Continue: true,
		Cwd:      cwd,
		Stdout:   &secondOut,
		Stderr:   &secondErr,
	}); err != nil {
		t.Fatalf("second RunRun --continue: %v\nstderr:\n%s", err, secondErr.String())
	}
	second, err := run.LatestRunForEnv(aiEnvDir, "demo")
	if err != nil {
		t.Fatalf("LatestRunForEnv after second run: %v", err)
	}
	if second.ID == firstID {
		t.Fatalf("second LatestRunForEnv returned the first run; ids must differ")
	}
	rec, err := run.ReadRecord(second.Path)
	if err != nil {
		t.Fatalf("ReadRecord second: %v", err)
	}
	if rec.LinkedPreviousRun == nil {
		t.Fatal("second run.json LinkedPreviousRun is nil, expected first run id")
	}
	if *rec.LinkedPreviousRun != firstID {
		t.Errorf("LinkedPreviousRun = %s, want %s", *rec.LinkedPreviousRun, firstID)
	}
}

// patchAIEnvFallback rewrites the sandbox.fallback_backend value in
// the generated ai-env.yaml so the fallback test can point at the
// in-memory mock without editing the production defaults.
func patchAIEnvFallback(path, fallback string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updated := strings.Replace(string(data), "fallback_backend: none", "fallback_backend: "+fallback, 1)
	if updated == string(data) {
		// Some YAML dumpers quote "none"; tolerate both shapes.
		updated = strings.Replace(string(data), "fallback_backend: \"none\"", "fallback_backend: "+fallback, 1)
	}
	return os.WriteFile(path, []byte(updated), 0o644)
}
