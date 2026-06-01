package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/githubbroker"
	"github.com/rivan1986/ai-env/internal/scanners"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// fakeBroker is the test double the pr_test exercises against. It
// records every lifecycle call so the test can assert on the order
// the CLI invoked the broker, and lets each step return a canned
// error so the failure paths (e.g. acquire-token failure must still
// not have made it to push) are observable.
//
// The struct intentionally mirrors the githubbroker.GitHubBroker
// interface one method at a time so a future change to the interface
// shows up here as a compile error.
type fakeBroker struct {
	prepareErr error
	acquireErr error
	pushErr    error
	scanErr    error
	createErr  error
	revokeErr  error
	scanResult scanners.ScanResult
	createPR   githubbroker.PRResult

	calls []string
}

func (f *fakeBroker) Prepare(envName, branchName string, repo githubbroker.Repo) (githubbroker.BrokerContext, error) {
	f.calls = append(f.calls, fmt.Sprintf("Prepare(%s,%s,%s/%s)", envName, branchName, repo.Owner, repo.Name))
	if f.prepareErr != nil {
		return githubbroker.BrokerContext{}, f.prepareErr
	}
	return githubbroker.BrokerContext{
		EnvName:    envName,
		BranchName: branchName,
		Repo:       repo,
	}, nil
}

func (f *fakeBroker) AcquireToken(ctx githubbroker.BrokerContext) (githubbroker.BrokerToken, error) {
	f.calls = append(f.calls, "AcquireToken")
	if f.acquireErr != nil {
		return githubbroker.BrokerToken{}, f.acquireErr
	}
	return githubbroker.BrokerToken{Kind: githubbroker.TokenKindPersonalAccessToken, Handle: "fake-handle"}, nil
}

func (f *fakeBroker) PushBranch(ctx githubbroker.BrokerContext, token githubbroker.BrokerToken) error {
	f.calls = append(f.calls, "PushBranch")
	return f.pushErr
}

func (f *fakeBroker) ScanMetadata(ctx githubbroker.BrokerContext, title, body string, commitMessages []string) (scanners.ScanResult, error) {
	f.calls = append(f.calls, fmt.Sprintf("ScanMetadata(title=%q,body=%q,commits=%d)", title, body, len(commitMessages)))
	if f.scanErr != nil {
		return scanners.ScanResult{}, f.scanErr
	}
	return f.scanResult, nil
}

func (f *fakeBroker) CreateDraftPR(ctx githubbroker.BrokerContext, token githubbroker.BrokerToken, title, body string) (githubbroker.PRResult, error) {
	f.calls = append(f.calls, fmt.Sprintf("CreateDraftPR(title=%q)", title))
	if f.createErr != nil {
		return githubbroker.PRResult{}, f.createErr
	}
	if f.createPR.Draft || f.createPR.Number != 0 || f.createPR.URL != "" {
		return f.createPR, nil
	}
	return githubbroker.PRResult{Number: 42, URL: "https://example/pr/42", Draft: true}, nil
}

func (f *fakeBroker) RevokeToken(token githubbroker.BrokerToken) error {
	f.calls = append(f.calls, "RevokeToken")
	return f.revokeErr
}

// makeCopyProject builds a project with a copy-strategy env where the
// agent has produced a real diff. It returns the project directory and
// the env name; callers pass them to RunPR.
//
// The helper exists so each test below stays focused on the gate /
// broker assertions rather than rebuilding the workspace fixture.
func makeCopyProject(t *testing.T, envName string) (string, string) {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "source")
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	writeFile(t, filepath.Join(src, "README.md"), "hello\n")

	scaffoldAIEnv(t, project, "demo")

	aiEnvDir := filepath.Join(project, ".ai-env")
	now := timeNow(t)
	info := mustCreateCopy(t, aiEnvDir, envName, src, now)

	// Real edit so the diff has content for the preview to render.
	writeFile(t, filepath.Join(info.Path, "README.md"), "hello\nupdated\n")

	return project, envName
}

// makeWorkflowChangeProject builds a project whose agent diff touches
// a workflow file, which the gate must hard-block under ModePR per
// plan 06 step 7. Used by the "gate blocks before broker" test.
func makeWorkflowChangeProject(t *testing.T, envName string) (string, string) {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "source")
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	writeFile(t, filepath.Join(src, "README.md"), "hello\n")
	writeFile(t, filepath.Join(src, ".github/workflows/ci.yml"), "name: ci\n")

	scaffoldAIEnv(t, project, "demo")

	aiEnvDir := filepath.Join(project, ".ai-env")
	now := timeNow(t)
	info := mustCreateCopy(t, aiEnvDir, envName, src, now)

	// Modify the workflow file so the path-gate-equivalent gate rule
	// fires under ModePR.
	writeFile(t, filepath.Join(info.Path, ".github/workflows/ci.yml"), "name: ci\nchanged: true\n")

	return project, envName
}

// TestRunPR_GateBlocks_DoesNotInvokeBroker verifies the plan 07 step 11
// contract: the export gate is consulted first, and a blocked verdict
// must short-circuit the command before any broker call. The broker is
// wired but the test asserts it received zero calls; this is the
// separation-of-concerns guarantee that the broker stays unaware of
// the gate.
func TestRunPR_GateBlocks_DoesNotInvokeBroker(t *testing.T) {
	project, envName := makeWorkflowChangeProject(t, "fix-tests")

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
		t.Fatalf("RunPR err=nil, want non-nil (gate must block workflow change under ModePR)")
	}
	if !strings.Contains(err.Error(), "export blocked") {
		t.Fatalf("RunPR err=%q, want substring %q", err.Error(), "export blocked")
	}
	if len(fake.calls) != 0 {
		t.Fatalf("broker was invoked despite gate block: calls=%v", fake.calls)
	}
	if !strings.Contains(stderr.String(), "workflow change") {
		t.Errorf("stderr should mention workflow change reason, got: %s", stderr.String())
	}
}

// TestRunPR_GateAllows_RunsBrokerLifecycle verifies plan 07 step 10:
// when the gate allows, the CLI threads the lifecycle through the
// broker in the order the plan's "Token lifecycle" diagram pins
// (Prepare -> AcquireToken -> PushBranch -> ScanMetadata ->
// CreateDraftPR -> RevokeToken). The fake broker records every call so
// we can assert on the order; the test also checks that the branch
// passed to Prepare carries the workspace's ai-env/ prefix.
func TestRunPR_GateAllows_RunsBrokerLifecycle(t *testing.T) {
	project, envName := makeCopyProject(t, "fix-login")

	fake := &fakeBroker{
		scanResult: scanners.ScanResult{Scanner: "built-in-patterns"},
		createPR:   githubbroker.PRResult{Number: 7, URL: "https://github.com/acme/demo/pull/7", Draft: true},
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

	want := []string{
		fmt.Sprintf("Prepare(%s,ai-env/%s,acme/demo)", envName, envName),
		"AcquireToken",
		"PushBranch",
		"ScanMetadata(title=\"fix login\",body=\"broker-generated body\",commits=1)",
		"CreateDraftPR(title=\"fix login\")",
		"RevokeToken",
	}
	if len(fake.calls) != len(want) {
		t.Fatalf("broker call count=%d, want %d. calls=%v", len(fake.calls), len(want), fake.calls)
	}
	for i, w := range want {
		if fake.calls[i] != w {
			t.Errorf("call[%d]=%q, want %q", i, fake.calls[i], w)
		}
	}

	out := stdout.String()
	if !strings.Contains(out, "https://github.com/acme/demo/pull/7") {
		t.Errorf("stdout missing PR URL, got:\n%s", out)
	}
	if !strings.Contains(out, "#7") {
		t.Errorf("stdout missing PR number, got:\n%s", out)
	}
}

// TestRunPR_NoBrokerWired_PreviewOnly verifies the plan 06 step 8
// fallback the CLI must preserve: when no broker is configured, an
// allowed gate produces the preview-only output and a "broker not
// configured" notice, with no network call attempted.
func TestRunPR_NoBrokerWired_PreviewOnly(t *testing.T) {
	project, envName := makeCopyProject(t, "fix-noop")

	var stdout, stderr bytes.Buffer
	err := RunPR(PROptions{
		EnvName: envName,
		Cwd:     project,
		Draft:   true,
		Broker:  nil,
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunPR err=%v, want nil. stderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "broker not configured") {
		t.Errorf("stdout missing broker-not-configured notice, got:\n%s", out)
	}
	if !strings.Contains(out, "files:") {
		t.Errorf("stdout missing per-file summary, got:\n%s", out)
	}
}

// TestRunPR_MetadataScanFinding_BlocksSubmission verifies plan 07 step
// 5 + step 10's interaction: a BlocksExport finding from ScanMetadata
// refuses CreateDraftPR but still attempts RevokeToken so the
// short-lived credential is scrubbed regardless of the failure path.
func TestRunPR_MetadataScanFinding_BlocksSubmission(t *testing.T) {
	project, envName := makeCopyProject(t, "fix-leak")

	fake := &fakeBroker{
		scanResult: scanners.ScanResult{
			Scanner: "built-in-patterns",
			Findings: []scanners.Finding{
				{
					ID:           "finding_001",
					File:         "pr_title",
					Line:         1,
					Type:         "api_key",
					Pattern:      "Anthropic sk-ant- prefix",
					Confidence:   scanners.ConfidenceHigh,
					BlocksExport: true,
				},
			},
		},
	}

	var stdout, stderr bytes.Buffer
	err := RunPR(PROptions{
		EnvName:        envName,
		Cwd:            project,
		Draft:          true,
		Broker:         fake,
		Repo:           githubbroker.Repo{Owner: "acme", Name: "demo", DefaultBranch: "main"},
		PRTitle:        "leaks a secret",
		PRBody:         "body",
		CommitMessages: nil,
		Stdout:         &stdout,
		Stderr:         &stderr,
	})
	if err == nil {
		t.Fatalf("RunPR err=nil, want non-nil (metadata scan finding must refuse submission)")
	}
	if !strings.Contains(err.Error(), "metadata scan") {
		t.Errorf("err should mention metadata scan, got: %v", err)
	}

	// CreateDraftPR must not have been called; RevokeToken still must
	// be called (defer) so the credential is scrubbed.
	for _, c := range fake.calls {
		if strings.HasPrefix(c, "CreateDraftPR") {
			t.Errorf("CreateDraftPR was called despite metadata blocker: calls=%v", fake.calls)
		}
	}
	sawRevoke := false
	for _, c := range fake.calls {
		if c == "RevokeToken" {
			sawRevoke = true
		}
	}
	if !sawRevoke {
		t.Errorf("RevokeToken must run even on metadata-block path: calls=%v", fake.calls)
	}

	if !strings.Contains(stderr.String(), "pr_title") {
		t.Errorf("stderr should cite the offending field, got:\n%s", stderr.String())
	}
}

// TestRunPR_AcquireTokenFails_NoPushNoRevoke verifies the lifecycle
// short-circuit when AcquireToken fails: Prepare ran, but no token was
// issued so PushBranch / ScanMetadata / CreateDraftPR / RevokeToken
// must not run (RevokeToken in particular would have nothing to
// revoke and the contract is "no token ever issued").
func TestRunPR_AcquireTokenFails_NoPushNoRevoke(t *testing.T) {
	project, envName := makeCopyProject(t, "fix-noacquire")

	fake := &fakeBroker{acquireErr: errors.New("issuer unavailable")}

	var stdout, stderr bytes.Buffer
	err := RunPR(PROptions{
		EnvName: envName,
		Cwd:     project,
		Draft:   true,
		Broker:  fake,
		Repo:    githubbroker.Repo{Owner: "acme", Name: "demo", DefaultBranch: "main"},
		PRTitle: "anything",
		PRBody:  "anything",
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err == nil {
		t.Fatalf("RunPR err=nil, want non-nil (acquire token failed)")
	}
	if !strings.Contains(err.Error(), "acquire token") {
		t.Errorf("err should mention acquire token, got: %v", err)
	}
	wantCalls := []string{"Prepare(fix-noacquire,ai-env/fix-noacquire,acme/demo)", "AcquireToken"}
	if len(fake.calls) != len(wantCalls) {
		t.Fatalf("calls=%v, want %v", fake.calls, wantCalls)
	}
	for i, w := range wantCalls {
		if fake.calls[i] != w {
			t.Errorf("call[%d]=%q, want %q", i, fake.calls[i], w)
		}
	}
}

// TestRunPR_BranchNamePassesAIEnvPrefix asserts the CLI hands the
// broker a branch name that starts with the workspace-fixed
// "ai-env/" prefix. This is the contract that lets the broker's
// ValidateBranchPrefix (plan 07 step 2) accept the input; the CLI
// must not bypass it by inventing its own branch name.
func TestRunPR_BranchNamePassesAIEnvPrefix(t *testing.T) {
	project, envName := makeCopyProject(t, "deploy-branch")

	fake := &fakeBroker{}
	var stdout, stderr bytes.Buffer
	_ = RunPR(PROptions{
		EnvName: envName,
		Cwd:     project,
		Draft:   true,
		Broker:  fake,
		Repo:    githubbroker.Repo{Owner: "acme", Name: "demo", DefaultBranch: "main"},
		PRTitle: "x",
		PRBody:  "y",
		Stdout:  &stdout,
		Stderr:  &stderr,
	})

	if len(fake.calls) == 0 {
		t.Fatalf("Prepare was not called; calls=%v", fake.calls)
	}
	want := fmt.Sprintf("Prepare(%s,%s,acme/demo)", envName, workspace.BranchName(envName))
	if fake.calls[0] != want {
		t.Errorf("Prepare call=%q, want %q (branch must carry ai-env/ prefix)", fake.calls[0], want)
	}
}

// TestBlockingMetadataFindings_FiltersByBlocksExport pins the helper
// used in the metadata refusal path: only findings with BlocksExport
// true must surface as blockers. The Plan 06 contract is that
// configurable / entropy-only findings are warn-only; the broker
// inherits that policy verbatim by routing through this helper.
func TestBlockingMetadataFindings_FiltersByBlocksExport(t *testing.T) {
	res := scanners.ScanResult{
		Findings: []scanners.Finding{
			{ID: "a", BlocksExport: true, File: "pr_title"},
			{ID: "b", BlocksExport: false, File: "pr_body"},
			{ID: "c", BlocksExport: true, File: "commit_message[0]"},
		},
	}
	got := blockingMetadataFindings(res)
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2 (only BlocksExport=true findings)", len(got))
	}
	if got[0].ID != "a" || got[1].ID != "c" {
		t.Errorf("got=%v, want [a, c]", got)
	}
}
