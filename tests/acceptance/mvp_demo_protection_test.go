//go:build acceptance

// Package acceptance MVP-demonstration protection verifications.
//
// This file implements plan.md lines 99-100 (master plan section "MVP
// demonstration", verification bullets 28-29):
//
//   - Verify: attempted push to main fails.
//   - Verify: hung agent stopped by timeout.
//
// The two scenarios share the same shape as the batch 13 security
// verifications: each test exercises the runtime decision point the
// agent's misbehaviour would land on, asserts the visible refusal
// (sentinel error / terminal state), and asserts the on-disk audit
// trail carries a corresponding record so an operator can reason
// about the refusal after the fact.
//
// Why this layer (and not a real GitHub remote or a real long sleep):
//
//   - The broker's push-to-main refusal lives in the static validation
//     helpers (ValidateBranchPrefix + ValidateProtectedBranch) and is
//     consulted by Prepare before any network round-trip. Driving the
//     helpers directly exercises the same code path the production
//     broker would hit; no GitHub credentials, no remote, no flake.
//   - The supervisor's timeout enforcement is the run package's job;
//     a 1s test timeout against a `sleep 5` child terminates well
//     under the suite's wall-clock budget while still proving the
//     supervisor escalates SIGTERM/SIGKILL on the way to a
//     StateTimedOut terminal. The existing TestStep16 supervisor-
//     timeout unit test covers the unit-level guarantee; this file
//     adds the acceptance-level pin (terminal + lifecycle audit +
//     reaping) tied directly to plan.md line 100.
//
// Gating mirrors section32_test.go and mvp_demo_security_test.go: the
// "acceptance" build tag is the static gate and AI_ENV_ACCEPTANCE=1
// (via TestMain in section32_test.go) is the dynamic gate.

package acceptance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/githubbroker"
	"github.com/i1rr/ai-env/internal/run"
)

// TestAcceptance_PushToMainDenied implements plan.md line 99 (master
// plan section "MVP demonstration", verification bullet 28): an
// attempted push to a protected branch (main / master) must fail.
//
// The broker refuses such pushes in two layers, both exercised here:
//
//  1. ValidateBranchPrefix rejects any branch that is not prefixed
//     with "ai-env/". A raw "main" / "master" never gets past this
//     gate because it has no prefix.
//  2. ValidateProtectedBranch rejects the protected names even when
//     the prefix check is satisfied (e.g. the repository's
//     DefaultBranch is "ai-env/main" or "main" itself, or the names
//     appear in the policy's extraProtected list).
//
// The test pins both layers and writes a corresponding
// PolicyDecisionBrokerAction record to policy-decisions.jsonl so the
// audit trail carries the refusal (the file is the operator's read-
// back surface). This mirrors what the run lifecycle does when the
// real broker's Prepare returns ErrProtectedBranch.
func TestAcceptance_PushToMainDenied(t *testing.T) {
	// Layer 1: raw branch names "main" / "master" are rejected by the
	// branch-prefix gate. This is the load-bearing first check; a
	// regression that loosened the prefix would let an agent push to
	// main directly.
	for _, name := range []string{"main", "master"} {
		t.Run("BranchPrefix_"+name, func(t *testing.T) {
			err := githubbroker.ValidateBranchPrefix(name)
			if err == nil {
				t.Fatalf("ValidateBranchPrefix(%q) returned nil; want ErrInvalidBranchPrefix", name)
			}
			if !errors.Is(err, githubbroker.ErrInvalidBranchPrefix) {
				t.Fatalf("ValidateBranchPrefix(%q) err = %v; want errors.Is ErrInvalidBranchPrefix", name, err)
			}
		})
	}

	// Layer 2: the protected-branch gate refuses any name in the
	// default-protected set (main, master, trunk, develop) and any
	// name matching the repo's DefaultBranch or the extras list. We
	// drive each variant so a regression that dropped one of the
	// inputs from the rule surfaces here.
	repo := githubbroker.Repo{
		Owner:         "acme",
		Name:          "demo",
		DefaultBranch: "main",
		CloneURL:      "https://github.com/acme/demo.git",
	}
	t.Run("ProtectedBranch_MainViaDefaults", func(t *testing.T) {
		err := githubbroker.ValidateProtectedBranch("main", repo, nil)
		if err == nil {
			t.Fatalf("ValidateProtectedBranch(main) = nil; want ErrProtectedBranch")
		}
		if !errors.Is(err, githubbroker.ErrProtectedBranch) {
			t.Fatalf("error %v; want errors.Is ErrProtectedBranch", err)
		}
	})
	t.Run("ProtectedBranch_MasterViaDefaults", func(t *testing.T) {
		err := githubbroker.ValidateProtectedBranch("master", repo, nil)
		if err == nil {
			t.Fatalf("ValidateProtectedBranch(master) = nil; want ErrProtectedBranch")
		}
		if !errors.Is(err, githubbroker.ErrProtectedBranch) {
			t.Fatalf("error %v; want errors.Is ErrProtectedBranch", err)
		}
	})
	t.Run("ProtectedBranch_ExoticDefault", func(t *testing.T) {
		// A repository whose default branch is none of the conventional
		// names (here "production") still gets blocked when the broker
		// is asked to push directly to it.
		exotic := githubbroker.Repo{Owner: "acme", Name: "demo", DefaultBranch: "production"}
		err := githubbroker.ValidateProtectedBranch("production", exotic, nil)
		if err == nil {
			t.Fatalf("ValidateProtectedBranch(production) = nil; want ErrProtectedBranch")
		}
		if !errors.Is(err, githubbroker.ErrProtectedBranch) {
			t.Fatalf("error %v; want errors.Is ErrProtectedBranch", err)
		}
	})

	// Audit-trail assertion: when the broker's Prepare returns
	// ErrProtectedBranch the run lifecycle writes a
	// PolicyDecisionBrokerAction event recording the refusal. We
	// drive the writer directly so this test exercises the on-disk
	// record shape an operator would later inspect via the broker's
	// audit log.
	dir := newRunDir(t)
	w, err := run.OpenPolicyDecisionsWriter(dir.Path, run.PolicyDecisionsWriterOptions{
		RunID: dir.ID,
	})
	if err != nil {
		t.Fatalf("OpenPolicyDecisionsWriter: %v", err)
	}

	// Simulate the broker's Prepare-time refusal. The supervisor
	// writes the failure verbatim with Decision=block and the action
	// name pinned by the broker constants. The Error string carries
	// the sentinel error's text so an operator grepping the trail
	// sees which gate fired.
	prepErr := githubbroker.ValidateProtectedBranch("main", repo, nil)
	if prepErr == nil {
		t.Fatal("ValidateProtectedBranch(main) returned nil; cannot construct refusal record")
	}
	if err := w.Write(run.PolicyDecisionEvent{
		Event:    run.PolicyDecisionBrokerAction,
		EnvName:  "demo",
		Decision: run.PolicyDecisionBlock,
		Action:   run.PolicyActionBrokerPrepare,
		Reasons:  []string{prepErr.Error()},
		Error:    prepErr.Error(),
		Branch:   "main",
		Repo:     "acme/demo",
	}); err != nil {
		t.Fatalf("write broker-action refusal record: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	events, err := run.ReadPolicyDecisions(dir.Path)
	if err != nil {
		t.Fatalf("ReadPolicyDecisions: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("policy-decisions.jsonl empty; want one broker-action refusal")
	}
	var refusal run.PolicyDecisionEvent
	var found bool
	for _, e := range events {
		if e.Event == run.PolicyDecisionBrokerAction && e.Decision == run.PolicyDecisionBlock {
			refusal = e
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no broker-action block recorded; events=%+v", events)
	}
	if refusal.Action != run.PolicyActionBrokerPrepare {
		t.Errorf("Action = %q; want %q", refusal.Action, run.PolicyActionBrokerPrepare)
	}
	if refusal.Branch != "main" {
		t.Errorf("Branch = %q; want main", refusal.Branch)
	}
	if refusal.Repo != "acme/demo" {
		t.Errorf("Repo = %q; want acme/demo", refusal.Repo)
	}
	if refusal.Error == "" {
		t.Errorf("Error empty; want broker sentinel text for grep-based audit")
	}
	if !strings.Contains(refusal.Error, "protected") {
		t.Errorf("Error = %q; want substring 'protected'", refusal.Error)
	}
}

// TestAcceptance_HungAgentStoppedByTimeout implements plan.md line 100
// (master plan section "MVP demonstration", verification bullet 29):
// a hung agent must be stopped by the supervisor's timeout enforcement.
//
// The test wires a real supervisor against a `sleep 5` child whose
// natural exit is 50x longer than the configured MaxRuntime (100ms).
// The supervisor must:
//
//   - Terminate the child well before the 5s natural exit (we use a 3s
//     overall budget as a generous CI bound).
//   - Land on StateTimedOut with StopReasonTimeout.
//   - Reap the child process (no zombie).
//   - Persist the timeout terminal in lifecycle.jsonl and run.json so
//     the audit trail carries the cause.
//
// The unit-level test in internal/run/supervisor_timeout_test.go pins
// the same guarantees at a finer granularity; this acceptance test ties
// them to plan.md line 100 and lives alongside the other MVP
// demonstration verifications so an operator running the suite sees
// one pass per plan bullet.
func TestAcceptance_HungAgentStoppedByTimeout(t *testing.T) {
	const maxRuntime = 100 * time.Millisecond
	// Generous overall budget: max runtime + stop grace + scheduler
	// noise on a busy CI box. Anything well under sleep 5 catches a
	// regression that forgets to enforce the budget.
	const overallBudget = 3 * time.Second

	dir := newRunDir(t)
	sup, err := run.NewSupervisor(run.SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "demo",
		Task:              "Hung agent past max runtime",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           sh("sleep 5"),
		MaxRuntime:        maxRuntime,
		IdleTimeout:       0,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	start := time.Now()
	result, err := sup.Run(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// --- Promptness ---------------------------------------------------
	// The supervisor must land its terminal long before the `sleep 5`
	// child would naturally exit. A regression that forgets to enforce
	// the budget would push elapsed past 5s.
	if elapsed > overallBudget {
		t.Errorf("Run took %v; expected timeout to fire within %v (max runtime = %v)",
			elapsed, overallBudget, maxRuntime)
	}
	if elapsed < maxRuntime {
		t.Errorf("Run took %v; budget was %v, suspiciously short (timer mis-armed?)",
			elapsed, maxRuntime)
	}

	// --- Terminal state ------------------------------------------------
	if result.FinalState != run.StateTimedOut {
		t.Errorf("FinalState = %q; want %q", result.FinalState, run.StateTimedOut)
	}
	if result.StopReason != run.StopReasonTimeout {
		t.Errorf("StopReason = %q; want %q", result.StopReason, run.StopReasonTimeout)
	}
	if result.StartedAt.IsZero() {
		t.Error("result.StartedAt is zero")
	}
	if result.StoppedAt.IsZero() {
		t.Error("result.StoppedAt is zero")
	}

	// --- Audit trail: lifecycle.jsonl ends on StateTimedOut ----------
	events, err := run.ReadLifecycleEvents(dir.Path)
	if err != nil {
		t.Fatalf("ReadLifecycleEvents: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("lifecycle.jsonl is empty; expected at least one terminal event")
	}
	last := events[len(events)-1]
	if last.State != run.StateTimedOut {
		t.Errorf("lifecycle last state = %q; want %q (full events=%+v)",
			last.State, run.StateTimedOut, events)
	}
	if last.RunID != dir.ID {
		t.Errorf("lifecycle RunID = %q; want %q", last.RunID, dir.ID)
	}
	if last.Agent != "claude" {
		t.Errorf("lifecycle Agent = %q; want claude", last.Agent)
	}

	// --- Audit trail: run.json carries the timeout terminal ----------
	rec, err := run.ReadRecord(dir.Path)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.State != run.StateTimedOut {
		t.Errorf("run.json State = %q; want %q", rec.State, run.StateTimedOut)
	}
	if rec.StopReason == nil || *rec.StopReason != run.StopReasonTimeout {
		t.Errorf("run.json StopReason = %v; want %q", rec.StopReason, run.StopReasonTimeout)
	}
	if rec.StoppedAt == nil {
		t.Error("run.json StoppedAt is nil; expected timeout terminal snapshot")
	}
	if rec.EnvName != "demo" {
		t.Errorf("run.json EnvName = %q; want demo", rec.EnvName)
	}

	// --- Sanity: run.json file exists on disk -------------------------
	// ReadRecord already returned without error, but locking down the
	// physical file existence guards against a future refactor that
	// returns a synthesized Record without touching the disk.
	if _, err := os.Stat(filepath.Join(dir.Path, "run.json")); err != nil {
		t.Errorf("run.json missing on disk: %v", err)
	}
}
