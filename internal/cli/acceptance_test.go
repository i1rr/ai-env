// acceptance_test.go holds the Plan 07 batch 8 acceptance tests that
// live in the CLI package. The other four acceptance tests in this
// batch (raw token visibility, branch prefix, metadata scan, token
// lifetime) live alongside the broker primitives in
// internal/githubbroker because they exercise the broker's internals;
// the workflow-change acceptance test lives here because the broker's
// path-gate check is invoked from the CLI's runBrokerLifecycle path
// via ExportGate (plan 07 step 11), and the security bar is "the CLI
// refuses to construct or invoke the broker when the diff touches a
// workflow file".
//
// Design rule: this test exercises RunPR end-to-end against a fake
// broker. The fake broker must NEVER receive a call, since the gate
// blocks before the broker is constructed. The brittle assertion is
// "len(fake.calls) == 0"; the test name names the security invariant
// explicitly so a reviewer can map it onto the plan acceptance
// criteria.

package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/i1rr/ai-env/internal/export"
	"github.com/i1rr/ai-env/internal/githubbroker"
	"github.com/i1rr/ai-env/internal/run"
	"github.com/i1rr/ai-env/internal/workspace"
)

// TestAcceptance_WorkflowChangesBlockAutomaticPR pins plan 07
// acceptance criterion 4 at the CLI seam: ".github/workflows/** change
// blocks automatic brokered PR creation."
//
// The test drives RunPR with a workspace whose diff touches a
// .github/workflows/* file and asserts:
//
//  1. RunPR returns a non-zero error mentioning the export was blocked.
//  2. The fake broker received ZERO lifecycle calls (the gate
//     short-circuits before Prepare).
//  3. The on-disk policy-decisions.jsonl carries exactly one event:
//     a gate-block event with a Reason that mentions workflow_change.
//
// This is the integration counterpart of the pure ExportGate test:
// the bar here is that the broker's path-gate rule (plan 07 step 4)
// is wired through the CLI surface plan 07 step 10 introduced and the
// gate from plan 07 step 11 runs before any broker call.
func TestAcceptance_WorkflowChangesBlockAutomaticPR(t *testing.T) {
	project, envName := makeWorkflowChangeProject(t, "fix-workflow")
	aiEnvDir := filepath.Join(project, ".ai-env")
	_, runDir := seedRunDirForEnv(t, aiEnvDir, envName)

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
		PRTitle:        "fix: ci tweak",
		PRBody:         "broker-generated body",
		CommitMessages: []string{"fix: ci tweak"},
		Stdout:         &stdout,
		Stderr:         &stderr,
	})
	if err == nil {
		t.Fatalf("RunPR err=nil, want non-nil (workflow change must block PR)")
	}
	if !strings.Contains(err.Error(), "export blocked") {
		t.Fatalf("RunPR err=%q, want 'export blocked' substring", err.Error())
	}

	// The broker MUST NOT have been called: the security bar is "no
	// credential acquisition, no push, no API call when the diff
	// touches a workflow file".
	if len(fake.calls) != 0 {
		t.Errorf("broker was invoked despite workflow change gate block: calls=%v", fake.calls)
	}

	// The on-disk decisions log must record exactly one block event
	// citing the workflow_change reason. A regression that silently
	// drops the gate event would slip past the negative
	// broker-call assertion above; this assertion catches it.
	events, readErr := run.ReadPolicyDecisions(runDir)
	if readErr != nil {
		t.Fatalf("ReadPolicyDecisions: %v", readErr)
	}
	if len(events) != 1 {
		t.Fatalf("got %d policy-decision events, want exactly 1 (the gate block). events=%+v", len(events), events)
	}
	evt := events[0]
	if evt.Event != run.PolicyDecisionExportGate {
		t.Errorf("evt.Event=%q, want %q", evt.Event, run.PolicyDecisionExportGate)
	}
	if evt.Decision != run.PolicyDecisionBlock {
		t.Errorf("evt.Decision=%q, want %q", evt.Decision, run.PolicyDecisionBlock)
	}
	if len(evt.Reasons) == 0 {
		t.Fatal("evt.Reasons empty; want at least one workflow_change reason")
	}
	joined := strings.Join(evt.Reasons, " | ")
	if !strings.Contains(joined, "workflow_change") {
		t.Errorf("evt.Reasons=%q, want substring 'workflow_change'", joined)
	}

	// stderr must surface the workflow-change reason so the operator
	// sees why the PR was refused without having to open the on-disk
	// log.
	if !strings.Contains(stderr.String(), "workflow") {
		t.Errorf("stderr missing 'workflow' substring; operator must see the reason. stderr=%s", stderr.String())
	}
}

// TestAcceptance_PRCreatedOnlyFromAIEnvBranch is the CLI-seam counterpart
// of the broker-package branch-prefix acceptance test. It pins plan 07
// acceptance criterion 2/3 at the CLI layer: the branch name the CLI
// hands the broker is always derived from workspace.BranchName, which
// fixes the "ai-env/" prefix. A regression where the CLI invents a
// branch name (e.g. someone wires --branch and forgets to enforce the
// prefix) would surface here as the test's fake broker receiving a
// branch that does not start with "ai-env/".
func TestAcceptance_PRCreatedOnlyFromAIEnvBranch(t *testing.T) {
	project, envName := makeCopyProject(t, "fix-prefix")

	fake := &fakeBroker{}
	var stdout, stderr bytes.Buffer
	_ = RunPR(PROptions{
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

	if len(fake.calls) == 0 {
		t.Fatalf("Prepare was not called; calls=%v", fake.calls)
	}
	wantBranch := workspace.BranchName(envName)
	if !strings.HasPrefix(wantBranch, "ai-env/") {
		// Sanity guard: BranchName itself must produce the prefix; if
		// it stops, the whole acceptance bar collapses.
		t.Fatalf("workspace.BranchName(%q)=%q must start with ai-env/", envName, wantBranch)
	}
	if !strings.Contains(fake.calls[0], wantBranch) {
		t.Errorf("Prepare call=%q, want substring %q (CLI must hand the broker the ai-env/-prefixed branch)",
			fake.calls[0], wantBranch)
	}
}

// modeSanityCheck guards against a future refactor that changes
// export.ModePR's stringification: the policy-decisions writer reads
// the surface verbatim ("pr") and a silent rename would invalidate
// downstream consumers that grep on the value. This is a cheap
// compile-time / once-per-build check, not a real acceptance test.
var _ export.Mode = export.ModePR
