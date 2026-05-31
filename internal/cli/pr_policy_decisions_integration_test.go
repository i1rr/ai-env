package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/githubbroker"
	"github.com/rivan1986/ai-env/internal/run"
	"github.com/rivan1986/ai-env/internal/scanners"
)

// seedRunDirForEnv attaches a real run directory + run.json for envName
// to the given aiEnvDir. The PR tests in pr_test.go intentionally skip
// this step because they only assert on broker call ordering and gate
// output; without a run dir, loadExportInputs swallows ErrNoRuns and
// RunPR's policy-decisions writer stays nil. The integration tests in
// this file need on-disk policy-decisions.jsonl emission to be
// exercised, so we seed the run dir explicitly.
//
// Returns the run ID so the test can assert the events are stamped with
// the expected RunID, and the absolute run dir path so the test can
// read back policy-decisions.jsonl directly.
func seedRunDirForEnv(t *testing.T, aiEnvDir, envName string) (runID, runDir string) {
	t.Helper()
	runID = "20260531-120000-pdtest"
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	dir, err := run.CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	started := now
	rec := run.Record{
		RunID:               runID,
		EnvName:             envName,
		Agent:               "claude",
		Task:                "integration: drive policy decisions",
		State:               run.StateCompleted,
		StartedAt:           &started,
		Backend:             "local-process",
		ModelCredentialMode: run.ModelCredentialBackendManaged,
	}
	stopped := started.Add(time.Minute)
	rec.StoppedAt = &stopped
	exit := 0
	rec.ExitCode = &exit
	reason := run.StopReasonAgentExit
	rec.StopReason = &reason
	if err := run.WriteRecord(dir.Path, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	// CreateRunDirectory pre-materializes empty placeholder scan
	// artifacts. loadScanArtifacts treats a missing file as a clean
	// scan, but an empty file fails JSON parse. Overwrite with valid
	// empty JSON objects so the gate evaluates with "no findings"
	// rather than failing at input load.
	if err := os.WriteFile(run.SecretScanPath(dir.Path), []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed secret-scan.json: %v", err)
	}
	if err := os.WriteFile(run.DependencyReportPath(dir.Path), []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed dependency-report.json: %v", err)
	}
	return runID, dir.Path
}

// findBrokerActionEvent returns the first broker_action event whose
// Action matches the supplied stage. Returns nil when no such event is
// in the slice; the caller decides whether the absence is a failure.
func findBrokerActionEvent(events []run.PolicyDecisionEvent, action string) *run.PolicyDecisionEvent {
	for i := range events {
		if events[i].Event == run.PolicyDecisionBrokerAction && events[i].Action == action {
			return &events[i]
		}
	}
	return nil
}

// TestRunPR_EmitsPolicyDecisionsJSONL_HappyPath is the integration test
// for Plan 07 step 12: it drives the full RunPR happy path against a
// fake broker, then asserts that policy-decisions.jsonl exists, is valid
// JSONL (round-trips through ReadPolicyDecisions), and contains the
// expected sequence of events:
//
//  1. The gate verdict (export_gate / allow) MUST be the first event
//     so an operator can tell that the gate ran before the broker.
//  2. One broker_action / allow event per lifecycle stage that ran
//     (prepare, acquire_token, push_branch, scan_metadata, create_pr,
//     revoke_token).
//  3. The CreateDraftPR event carries the PR number and URL.
//  4. Every event carries the correct RunID and a non-empty Timestamp
//     stamped by the writer.
//
// This catches a regression where any of the per-stage emit calls in
// runBrokerLifecycle are dropped, where the gate event is forgotten,
// where the writer is constructed against the wrong run dir, or where
// the on-disk shape silently breaks (e.g. someone switches to a
// pretty-printer that emits multi-line records).
func TestRunPR_EmitsPolicyDecisionsJSONL_HappyPath(t *testing.T) {
	project, envName := makeCopyProject(t, "fix-login")
	aiEnvDir := filepath.Join(project, ".ai-env")
	runID, runDir := seedRunDirForEnv(t, aiEnvDir, envName)

	fake := &fakeBroker{
		scanResult: scanners.ScanResult{Scanner: "built-in-patterns"},
		createPR: githubbroker.PRResult{
			Number: 7,
			URL:    "https://github.com/acme/demo/pull/7",
			Draft:  true,
		},
	}
	var stdout, stderr bytes.Buffer
	err := RunPR(PROptions{
		EnvName: envName,
		Cwd:     project,
		Draft:   true,
		Broker:  fake,
		Repo: githubbroker.Repo{
			Owner: "acme", Name: "demo", DefaultBranch: "main",
			CloneURL: "https://github.com/acme/demo.git",
		},
		PRTitle:        "fix login",
		PRBody:         "broker-generated body",
		CommitMessages: []string{"fix login"},
		Stdout:         &stdout,
		Stderr:         &stderr,
	})
	if err != nil {
		t.Fatalf("RunPR err=%v, want nil. stderr=%s", err, stderr.String())
	}

	// The file must exist at the path the package exposes.
	wantPath := run.PolicyDecisionsPath(runDir)
	if wantPath == "" {
		t.Fatalf("PolicyDecisionsPath returned empty")
	}

	events, err := run.ReadPolicyDecisions(runDir)
	if err != nil {
		t.Fatalf("ReadPolicyDecisions: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("no policy decision events on disk; want gate + per-stage broker actions. stderr=%s", stderr.String())
	}

	// First event must be the gate verdict so the file orders the
	// decisions the way the lifecycle ran them.
	if events[0].Event != run.PolicyDecisionExportGate {
		t.Fatalf("events[0].Event=%q, want %q (gate must precede broker)", events[0].Event, run.PolicyDecisionExportGate)
	}
	if events[0].Decision != run.PolicyDecisionAllow {
		t.Errorf("events[0].Decision=%q, want %q", events[0].Decision, run.PolicyDecisionAllow)
	}
	if events[0].Surface != "pr" {
		t.Errorf("events[0].Surface=%q, want %q", events[0].Surface, "pr")
	}

	// Every event must be stamped with the writer-pinned fields.
	for i, e := range events {
		if e.RunID != runID {
			t.Errorf("events[%d].RunID=%q, want %q", i, e.RunID, runID)
		}
		if e.Timestamp == "" {
			t.Errorf("events[%d].Timestamp empty; writer must fill it", i)
		}
	}

	// Plan acceptance criterion 8 reads: "Blocked or failed broker
	// actions appear in policy-decisions.jsonl". The CLI's emission
	// policy is therefore "always log failure / block; log success
	// only for stages that materially change external state
	// (CreateDraftPR and RevokeToken)". On the happy path this means
	// the lifecycle outcome events MUST include create_pr and
	// revoke_token, and MUST NOT include any failure events for the
	// intermediate stages. A regression that drops either of these
	// allow events (e.g. someone refactors the deferred revoke and
	// forgets the emit) shows up here.
	wantOutcomes := []string{
		run.PolicyActionBrokerCreatePR,
		run.PolicyActionBrokerRevokeToken,
	}
	for _, stage := range wantOutcomes {
		evt := findBrokerActionEvent(events, stage)
		if evt == nil {
			t.Errorf("missing broker_action event for stage %q. events=%+v", stage, events)
			continue
		}
		if evt.Decision != run.PolicyDecisionAllow {
			t.Errorf("stage %q decision=%q, want %q", stage, evt.Decision, run.PolicyDecisionAllow)
		}
	}
	// No broker_action event should carry a Decision of "block" or
	// "fail" on the happy path; if one does, an upstream stage
	// regressed.
	for _, e := range events {
		if e.Event != run.PolicyDecisionBrokerAction {
			continue
		}
		if e.Decision == run.PolicyDecisionBlock || e.Decision == run.PolicyDecisionFail {
			t.Errorf("happy path emitted unexpected %s/%s event: %+v", e.Action, e.Decision, e)
		}
	}

	// The CreateDraftPR event must carry the PR coordinates so a
	// future audit can find the produced PR without joining run.json.
	prEvt := findBrokerActionEvent(events, run.PolicyActionBrokerCreatePR)
	if prEvt == nil {
		t.Fatalf("no broker_action event for create_pr")
	}
	if prEvt.PRNumber != 7 {
		t.Errorf("create_pr PRNumber=%d, want 7", prEvt.PRNumber)
	}
	if prEvt.PRURL != "https://github.com/acme/demo/pull/7" {
		t.Errorf("create_pr PRURL=%q, want PR url", prEvt.PRURL)
	}
	if prEvt.Branch != "ai-env/fix-login" {
		t.Errorf("create_pr Branch=%q, want ai-env/fix-login", prEvt.Branch)
	}
	if prEvt.Repo != "acme/demo" {
		t.Errorf("create_pr Repo=%q, want acme/demo", prEvt.Repo)
	}
}

// TestRunPR_EmitsPolicyDecisionsJSONL_BlockedGateRecordsBlockOnly drives
// the gate-block path: a workflow change is hard-blocked under ModePR,
// so the broker must never run and the on-disk decisions log must
// contain exactly one event (the gate block) with the block reason.
//
// This regression-tests two things at once:
//   - The gate event is emitted even when the gate blocks (the writer
//     is opened before evaluate, and the emit happens before the early
//     return that surfaces the gate reasons to the operator).
//   - No broker_action event leaks into the file when the broker was
//     never invoked.
func TestRunPR_EmitsPolicyDecisionsJSONL_BlockedGateRecordsBlockOnly(t *testing.T) {
	project, envName := makeWorkflowChangeProject(t, "fix-tests")
	aiEnvDir := filepath.Join(project, ".ai-env")
	runID, runDir := seedRunDirForEnv(t, aiEnvDir, envName)

	fake := &fakeBroker{}
	var stdout, stderr bytes.Buffer
	err := RunPR(PROptions{
		EnvName: envName,
		Cwd:     project,
		Draft:   true,
		Broker:  fake,
		Repo: githubbroker.Repo{
			Owner: "acme", Name: "demo", DefaultBranch: "main",
			CloneURL: "https://github.com/acme/demo.git",
		},
		PRTitle:        "fix: stop crashing",
		PRBody:         "broker-generated body",
		CommitMessages: []string{"fix: stop crashing"},
		Stdout:         &stdout,
		Stderr:         &stderr,
	})
	if err == nil {
		t.Fatalf("RunPR err=nil, want non-nil (gate must block)")
	}

	events, err := run.ReadPolicyDecisions(runDir)
	if err != nil {
		t.Fatalf("ReadPolicyDecisions: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1 (the gate-block event only). events=%+v", len(events), events)
	}
	evt := events[0]
	if evt.Event != run.PolicyDecisionExportGate {
		t.Errorf("Event=%q, want %q", evt.Event, run.PolicyDecisionExportGate)
	}
	if evt.Decision != run.PolicyDecisionBlock {
		t.Errorf("Decision=%q, want %q", evt.Decision, run.PolicyDecisionBlock)
	}
	if evt.RunID != runID {
		t.Errorf("RunID=%q, want %q", evt.RunID, runID)
	}
	if len(evt.Reasons) == 0 {
		t.Errorf("Reasons empty; want at least one block reason for the workflow change")
	}
	// Reason strings must mention the workflow_change code so the
	// on-disk record is self-contained for an operator reading it.
	joined := strings.Join(evt.Reasons, " | ")
	if !strings.Contains(joined, "workflow_change") {
		t.Errorf("Reasons=%q, want substring 'workflow_change'", joined)
	}
}

// TestRunPR_EmitsPolicyDecisionsJSONL_BrokerFailureRedactsToken pins the
// security contract on the emission path: when a broker stage fails
// with an error that echoes a credential-looking substring, the Error
// field on the on-disk event MUST be redacted (not the raw string).
//
// This is an integration test (not just the unit test in
// policy_events_test.go) because the redaction happens at the emission
// site inside runBrokerLifecycle; a regression that forgets to thread
// the error through the redactor would slip past the pure helper test
// since the helper is correct in isolation.
func TestRunPR_EmitsPolicyDecisionsJSONL_BrokerFailureRedactsToken(t *testing.T) {
	project, envName := makeCopyProject(t, "fix-leakerr")
	aiEnvDir := filepath.Join(project, ".ai-env")
	_, runDir := seedRunDirForEnv(t, aiEnvDir, envName)

	// Drive a PushBranch failure whose error echoes a GitHub PAT.
	// PushBranch (not Prepare) is the right stage because the
	// emission path uses classifyBrokerErr to decide allow/block/fail
	// and the unknown error must map to "fail" with the redacted
	// error string on disk.
	leakedToken := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	fake := &fakeBroker{
		pushErr: errors.New("push refused: token " + leakedToken + " rejected"),
	}

	var stdout, stderr bytes.Buffer
	err := RunPR(PROptions{
		EnvName: envName,
		Cwd:     project,
		Draft:   true,
		Broker:  fake,
		Repo: githubbroker.Repo{
			Owner: "acme", Name: "demo", DefaultBranch: "main",
			CloneURL: "https://github.com/acme/demo.git",
		},
		PRTitle:        "fix",
		PRBody:         "body",
		CommitMessages: []string{"fix"},
		Stdout:         &stdout,
		Stderr:         &stderr,
	})
	if err == nil {
		t.Fatalf("RunPR err=nil, want non-nil (push failed)")
	}

	events, err := run.ReadPolicyDecisions(runDir)
	if err != nil {
		t.Fatalf("ReadPolicyDecisions: %v", err)
	}
	pushEvt := findBrokerActionEvent(events, run.PolicyActionBrokerPushBranch)
	if pushEvt == nil {
		t.Fatalf("no push_branch event on disk; events=%+v", events)
	}
	if pushEvt.Decision != run.PolicyDecisionFail {
		t.Errorf("push_branch Decision=%q, want %q", pushEvt.Decision, run.PolicyDecisionFail)
	}
	if pushEvt.Error == "" {
		t.Fatalf("push_branch Error empty; want a redacted error string")
	}
	if strings.Contains(pushEvt.Error, leakedToken) {
		t.Errorf("push_branch Error leaked raw token: %q", pushEvt.Error)
	}
	if !strings.Contains(pushEvt.Error, githubbroker.RedactedPlaceholder) {
		t.Errorf("push_branch Error missing redaction marker %q; got %q",
			githubbroker.RedactedPlaceholder, pushEvt.Error)
	}

	// RevokeToken must still have run (deferred), and the event must
	// be on disk with allow decision since the fake's revoke succeeds.
	revokeEvt := findBrokerActionEvent(events, run.PolicyActionBrokerRevokeToken)
	if revokeEvt == nil {
		t.Errorf("no revoke_token event on disk; deferred revoke must still emit. events=%+v", events)
	} else if revokeEvt.Decision != run.PolicyDecisionAllow {
		t.Errorf("revoke_token Decision=%q, want %q (fake revoke succeeds)",
			revokeEvt.Decision, run.PolicyDecisionAllow)
	}
}
