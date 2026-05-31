//go:build acceptance

// Package acceptance MVP-demonstration export verifications.
//
// This file implements plan.md lines 104-106 (master plan section "MVP
// demonstration", verification bullets 33-35):
//
//   - Verify: workflow file change blocks brokered PR.
//   - Verify: `ai-env patch demo --out demo.patch` exports a valid patch.
//   - Verify: `ai-env new nongit --from ./some-non-git-dir` uses copy
//     mode and exports a diff.
//
// The three scenarios share the same shape as the batch 13 / 14 / 15
// verifications: each test exercises the runtime decision point an
// operator would observe and asserts the user-visible verdict (CLI exit,
// gate Decision, on-disk artifacts) plus the load-bearing supporting
// evidence so the audit trail an operator inspects after the demo
// carries the right shape.
//
// Why this layer (and not a real GitHub remote / real downloaded fixture):
//
//   - The broker's PR-gate refusal lives in two layers, both consulted
//     before any network round-trip: the static githubbroker.ValidatePathGate
//     helper (used by Prepare) and the export.ExportGate ModePR rule that
//     flags any .github/workflows/** change as a hard blocker. Driving
//     both layers directly exercises the same code path the production
//     broker hits without standing up a GitHub credential or a network
//     listener. The CLI's `ai-env pr` command consults the same gate
//     before constructing the broker, so its refusal verdict against a
//     workflow-touching diff is pinned in addition to the helper.
//   - The `ai-env patch` command produces a unified-diff patch from the
//     workspace's diff. We validate the patch by re-running `git apply
//     --check` against the source repository it was produced from, which
//     is the exact contract a reviewer or CI bot would consume.
//   - The non-git copy-mode scenario uses a fixture directory that has
//     NOT been `git init`-ed. The CLI's `ai-env new --from <non-git>`
//     selects copy strategy automatically (DetectWorkspaceStrategy); a
//     follow-up `ai-env diff` / `ai-env patch` against the resulting
//     workspace produces a file-level unified diff (one `diff --git`
//     block per changed file) that is non-empty after a real edit.
//
// Gating mirrors section32_test.go and the other mvp_demo_* files: the
// build tag `acceptance` is the static gate and AI_ENV_ACCEPTANCE=1 (via
// TestMain in section32_test.go) is the dynamic gate. The binary is
// built once by section32_test.go's TestMain and reused via suite.binPath.

package acceptance

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/export"
	"github.com/rivan1986/ai-env/internal/githubbroker"
	"github.com/rivan1986/ai-env/internal/workspace"
)

// TestAcceptance_WorkflowFileBlocksBrokeredPR implements plan.md line
// 104 (master plan section "MVP demonstration", verification bullet
// 33): any change under .github/workflows/** must block a brokered PR.
//
// Two layers enforce this rule, both exercised here:
//
//  1. export.ExportGate.Evaluate under ModePR must return DecisionBlock
//     for a diff that touches .github/workflows/ci.yml, with a
//     workflow-tagged blocking reason. This is the in-process pipeline
//     `ai-env pr` consults before ever constructing a broker; a regression
//     that downgraded workflow changes to warn under ModePR would surface
//     here.
//  2. githubbroker.ValidatePathGate (used by Broker.Prepare) must trip
//     ErrProtectedPath for the same diff. This is the static helper the
//     broker consults at Prepare time, independent of the gate; both
//     layers must fire because they are the two checkpoints the plan
//     calls out.
//
// The test also drives the real `ai-env pr` CLI surface against a
// worktree env whose tip commit changes a workflow file, and asserts
// that the command exits non-zero with the gate's workflow-tagged
// blocker rendered to stderr. We do not stand up a broker (there is no
// GitHub App / PAT wired in CI); the gate refusal is the load-bearing
// invariant the bullet pins, because if the gate refuses, the broker is
// never constructed and so never asked to push the workflow change.
func TestAcceptance_WorkflowFileBlocksBrokeredPR(t *testing.T) {
	// Layer 1: ExportGate (the pipeline `ai-env pr` consults before any
	// broker action). A workflow change under ModePR is a hard blocker.
	t.Run("Layer1_ExportGate_PR_BlocksWorkflowChange", func(t *testing.T) {
		gate := export.NewExportGate(nil)
		verdict := gate.Evaluate(export.Input{
			Mode: export.ModePR,
			Diff: workspace.DiffResult{
				Files: []workspace.FileDiff{
					{Path: ".github/workflows/ci.yml", Change: workspace.ChangeModified},
				},
			},
		})
		if verdict.Decision != export.DecisionBlock {
			t.Fatalf("gate Decision = %q, want %q. Reasons=%+v",
				verdict.Decision, export.DecisionBlock, verdict.Reasons)
		}
		if !verdict.Blocked() {
			t.Errorf("verdict.Blocked() = false; want true")
		}
		blockers := verdict.BlockingReasons()
		if len(blockers) == 0 {
			t.Fatalf("verdict has no blocking reasons; full Reasons=%+v", verdict.Reasons)
		}
		var sawWorkflow bool
		for _, r := range blockers {
			if r.Code != export.ReasonWorkflowChange {
				continue
			}
			sawWorkflow = true
			if !r.Hard {
				t.Errorf("workflow-change reason Hard = false; want true under ModePR")
			}
			if !strings.Contains(strings.ToLower(r.Message), "workflow") {
				t.Errorf("workflow-change reason Message = %q, want substring 'workflow'", r.Message)
			}
			if !strings.Contains(r.Path, ".github/workflows/ci.yml") {
				t.Errorf("workflow-change reason Path = %q, want '.github/workflows/ci.yml'", r.Path)
			}
		}
		if !sawWorkflow {
			t.Errorf("no ReasonWorkflowChange in blocking reasons; got %+v", blockers)
		}

		// Symmetry check: the same diff under ModePatch downgrades the
		// workflow blocker to a warning (the plan keeps patch export
		// permissive for review purposes). A regression that promoted
		// workflow changes to hard under ModePatch would surface here.
		patchVerdict := gate.Evaluate(export.Input{
			Mode: export.ModePatch,
			Diff: workspace.DiffResult{
				Files: []workspace.FileDiff{
					{Path: ".github/workflows/ci.yml", Change: workspace.ChangeModified},
				},
			},
		})
		if patchVerdict.Decision != export.DecisionAllow {
			t.Errorf("patch-mode workflow gate Decision = %q, want %q. Reasons=%+v",
				patchVerdict.Decision, export.DecisionAllow, patchVerdict.Reasons)
		}
	})

	// Layer 2: githubbroker.ValidatePathGate (Prepare-time helper). This
	// is the static rule the broker consults before any token acquisition
	// or push; it is independent of the gate and must agree on the
	// verdict so a regression in either layer surfaces here.
	t.Run("Layer2_BrokerPathGate_RejectsWorkflowChange", func(t *testing.T) {
		diff := workspace.DiffResult{
			Files: []workspace.FileDiff{
				{Path: ".github/workflows/ci.yml", Change: workspace.ChangeModified},
				{Path: "src/main.go", Change: workspace.ChangeModified},
			},
		}
		hits, err := githubbroker.ValidatePathGate(diff, githubbroker.PathGateOptions{})
		if err == nil {
			t.Fatalf("ValidatePathGate returned nil error; want ErrProtectedPath")
		}
		if !errors.Is(err, githubbroker.ErrProtectedPath) {
			t.Fatalf("ValidatePathGate error = %v; want errors.Is ErrProtectedPath", err)
		}
		if len(hits) != 1 {
			t.Fatalf("len(hits) = %d; want 1 (only the workflow path should match)", len(hits))
		}
		if hits[0].Path != ".github/workflows/ci.yml" {
			t.Errorf("hits[0].Path = %q; want '.github/workflows/ci.yml'", hits[0].Path)
		}
		if hits[0].Glob != ".github/workflows/**" {
			t.Errorf("hits[0].Glob = %q; want '.github/workflows/**'", hits[0].Glob)
		}
	})

	// Layer 3: the real `ai-env pr` CLI surface. A worktree env whose
	// agent committed a workflow change must produce a non-zero exit and
	// render the gate's workflow-tagged blocker to stderr. The CLI does
	// not need a broker to be wired: the gate refusal happens BEFORE the
	// broker is constructed, so a "broker not configured" environment
	// still surfaces the right verdict.
	t.Run("Layer3_CLI_PR_RefusesWorkflowChange", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skipf("git not on PATH: %v", err)
		}

		// 1. Scaffold a worktree env from the Node fixture. We seed the
		// workflow file in the source repo so a modification to it lands
		// as a "modified" change in the workspace diff (the gate fires on
		// any change, but modified is the most realistic shape).
		src := copyFixture(t, "node-app")
		if err := os.MkdirAll(filepath.Join(src, ".github", "workflows"), 0o755); err != nil {
			t.Fatalf("mkdir .github/workflows: %v", err)
		}
		if err := os.WriteFile(filepath.Join(src, ".github", "workflows", "ci.yml"),
			[]byte("name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"),
			0o644); err != nil {
			t.Fatalf("seed workflow file: %v", err)
		}
		initGitFixture(t, src)
		if _, _, err := runAIEnvWithOutput(t, src, "new", "demo"); err != nil {
			t.Fatalf("ai-env new demo: %v", err)
		}

		// 2. Mutate the workflow file inside the workspace and commit the
		// change so it appears in the env-vs-source diff.
		wsRoot := filepath.Join(src, ".ai-env", "workspaces", "demo")
		if err := os.WriteFile(filepath.Join(wsRoot, ".github", "workflows", "ci.yml"),
			[]byte("name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo HACKED\n"),
			0o644); err != nil {
			t.Fatalf("mutate workflow file in workspace: %v", err)
		}
		runGit(t, wsRoot, "add", ".github/workflows/ci.yml")
		runGit(t, wsRoot, "commit", "-m", "agent: tamper with workflow")

		// 3. Run `ai-env pr demo` and expect a non-zero exit. The gate
		// refuses ModePR for the workflow change; the broker is never
		// constructed. The CLI's renderer prints the blocked reasons to
		// stderr with the workflow code tag.
		stdout, stderr, err := runAIEnv(t, src, "pr", "demo")
		if err == nil {
			t.Fatalf("ai-env pr demo returned nil error; expected non-zero exit (gate must block workflow change)\nstdout:\n%s\nstderr:\n%s",
				stdout, stderr)
		}
		// The renderer tags blocking reasons with the gate's code; we
		// pin both the human-readable substring ("workflow") and the
		// reason code so a regression in either layer is caught.
		lowerStderr := strings.ToLower(stderr)
		if !strings.Contains(lowerStderr, "workflow") {
			t.Errorf("stderr missing 'workflow' substring; got:\n%s", stderr)
		}
		if !strings.Contains(stderr, string(export.ReasonWorkflowChange)) {
			t.Errorf("stderr missing reason code %q; got:\n%s", export.ReasonWorkflowChange, stderr)
		}
		if !strings.Contains(stderr, "blocked") {
			t.Errorf("stderr missing 'blocked' header; got:\n%s", stderr)
		}
	})
}

// TestAcceptance_PatchDemoExportsValidPatch implements plan.md line 105
// (master plan section "MVP demonstration", verification bullet 34):
// `ai-env patch demo --out demo.patch` exports a valid unified-diff
// patch file.
//
// "Valid" here means the on-disk file is:
//
//  1. Non-empty after a real edit landed in the workspace.
//  2. A parseable unified diff (carries the `diff --git` header that
//     `git apply` keys on).
//  3. Applicable against the source repository the env was created from
//     — verified by running `git apply --check` in a freshly-reset clone
//     of the source repo. This is the contract a reviewer or CI bot
//     would consume; a regression in the diff renderer that produced
//     malformed hunks or wrong paths would fail the --check.
//
// The test uses the worktree strategy (the production default for a Git
// source) so the patch is produced via `git diff` between the env branch
// and the source HEAD, which is the same primitive `ai-env patch`
// consults via workspace.Diff.
func TestAcceptance_PatchDemoExportsValidPatch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not on PATH: %v", err)
	}

	// 1. Scaffold a worktree env from the Node fixture.
	src := copyFixture(t, "node-app")
	initGitFixture(t, src)
	if _, _, err := runAIEnvWithOutput(t, src, "new", "demo"); err != nil {
		t.Fatalf("ai-env new demo: %v", err)
	}

	// 2. Mutate an existing file and add a new file inside the workspace
	// so the diff is non-empty and covers both change kinds. Commit so
	// the change appears in the env-branch-vs-source-HEAD git diff.
	wsRoot := filepath.Join(src, ".ai-env", "workspaces", "demo")
	if err := os.WriteFile(filepath.Join(wsRoot, "index.js"),
		[]byte("// patched by agent\nconsole.log('hello from patch');\n"),
		0o644); err != nil {
		t.Fatalf("mutate index.js: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wsRoot, "FEATURE.md"),
		[]byte("# Feature\n\nAgent added this file.\n"),
		0o644); err != nil {
		t.Fatalf("add FEATURE.md: %v", err)
	}
	runGit(t, wsRoot, "add", "index.js", "FEATURE.md")
	runGit(t, wsRoot, "commit", "-m", "agent: feature + index update")

	// 3. Run `ai-env patch demo --out <abs>` and confirm the command
	// succeeds. The output path is absolute so the resolved location is
	// deterministic regardless of where the CLI's relative-to-cwd
	// behavior lands the file.
	outDir := t.TempDir()
	outFile := filepath.Join(outDir, "demo.patch")
	stdout, stderr, err := runAIEnvWithOutput(t, src, "patch", "demo", "--out", outFile)
	if err != nil {
		t.Fatalf("ai-env patch demo --out %s: %v\nstdout:\n%s\nstderr:\n%s",
			outFile, err, stdout, stderr)
	}

	// 4. The patch file must exist and be non-empty.
	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("stat %s: %v", outFile, err)
	}
	if info.Size() == 0 {
		t.Fatalf("patch file %s is empty; expected a non-zero unified diff", outFile)
	}
	body, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read patch file: %v", err)
	}
	patch := string(body)

	// 5. The body must carry the unified-diff structural markers. We
	// pin two: the `diff --git` header (which `git apply` keys on) and
	// the per-file `---`/`+++` markers. Missing either would indicate a
	// renderer regression that produced free-form text instead of a
	// parseable patch.
	if !strings.Contains(patch, "diff --git") {
		t.Errorf("patch missing 'diff --git' header; not a parseable unified diff:\n%s", patch)
	}
	if !strings.Contains(patch, "--- a/") && !strings.Contains(patch, "--- /dev/null") {
		t.Errorf("patch missing '--- a/' or '--- /dev/null' marker; not a parseable unified diff:\n%s", patch)
	}
	if !strings.Contains(patch, "+++ b/") {
		t.Errorf("patch missing '+++ b/' marker; not a parseable unified diff:\n%s", patch)
	}
	// Substantive body checks: the two changed files must appear with
	// their actual mutations in the patch.
	if !strings.Contains(patch, "index.js") {
		t.Errorf("patch missing index.js path:\n%s", patch)
	}
	if !strings.Contains(patch, "FEATURE.md") {
		t.Errorf("patch missing FEATURE.md path:\n%s", patch)
	}
	if !strings.Contains(patch, "+console.log('hello from patch');") {
		t.Errorf("patch missing index.js added line:\n%s", patch)
	}

	// 6. The load-bearing validation: re-apply the patch against a fresh
	// clone of the source repo via `git apply --check`. This is the
	// contract a reviewer or CI bot consumes; if --check passes the
	// patch is structurally valid and the hunks line up with the source.
	//
	// We clone (not copy) the source so the apply target is a clean
	// working tree at the same HEAD the patch was produced against.
	// A failure here would mean the renderer produced a patch with the
	// wrong line numbers, malformed hunks, or paths that do not match
	// the source layout.
	cloneDir := filepath.Join(t.TempDir(), "clone")
	cloneCmd := exec.Command("git", "clone", "--quiet", "--branch", "main", src, cloneDir)
	if out, cloneErr := cloneCmd.CombinedOutput(); cloneErr != nil {
		t.Fatalf("git clone source for apply --check: %v\n%s", cloneErr, out)
	}
	applyCmd := exec.Command("git", "apply", "--check", outFile)
	applyCmd.Dir = cloneDir
	var applyOut bytes.Buffer
	applyCmd.Stdout = &applyOut
	applyCmd.Stderr = &applyOut
	if applyErr := applyCmd.Run(); applyErr != nil {
		t.Errorf("git apply --check failed against the produced patch: %v\noutput:\n%s\npatch body:\n%s",
			applyErr, applyOut.String(), patch)
	}

	// 7. The stdout summary must mention the env handle and the written
	// path so a human running the demo sees the export succeeded.
	if !strings.Contains(stdout, "demo") {
		t.Errorf("ai-env patch stdout did not mention env name 'demo'; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "wrote:") {
		t.Errorf("ai-env patch stdout missing 'wrote:' confirmation line; got:\n%s", stdout)
	}
}

// TestAcceptance_NewNongitCopyModeExportsDiff implements plan.md line
// 106 (master plan section "MVP demonstration", verification bullet
// 35): `ai-env new <env> --from <non-git-dir>` must select the copy
// strategy automatically, and a follow-up diff/export against the
// resulting workspace must produce a non-empty unified diff after a
// real edit.
//
// The test:
//
//  1. Stages a fixture directory (python-app) that is intentionally NOT
//     a git repository. DetectWorkspaceStrategy returns "copy" for any
//     non-Git source, so `ai-env new --from <dir>` lands on copy mode
//     without the operator passing any extra flag.
//  2. Runs `ai-env new nongit --from <fixture>` against a separate
//     project directory and asserts the .env-meta.json records
//     strategy=copy and a non-empty baseline_path.
//  3. Mutates an existing file and adds a new file inside the
//     materialized workspace.
//  4. Runs `ai-env patch nongit --out <abs>` (the export surface from
//     bullet 34, here exercised against the copy strategy) and asserts
//     the resulting patch is non-empty and carries one file-level
//     `diff --git` block per changed file. The plan calls for "exports
//     a diff" generically; the patch command IS the export surface for
//     copy-strategy envs (its output is a file-level unified diff, per
//     the workspace package's CopyDiff renderer).
//  5. Cross-checks the same behavior via `ai-env diff nongit` so the
//     two export-shaped commands agree on what the diff looks like.
func TestAcceptance_NewNongitCopyModeExportsDiff(t *testing.T) {
	// 1. Stage a fixture WITHOUT `git init`. python-app is a pristine
	// tree; copyFixture preserves the file mode and skips git plumbing,
	// so the source has no .git entry and DetectWorkspaceStrategy
	// returns "copy".
	src := copyFixture(t, "python-app")
	if _, err := os.Stat(filepath.Join(src, ".git")); !os.IsNotExist(err) {
		t.Fatalf("fixture %s unexpectedly carries .git (err=%v); copy mode test cannot run", src, err)
	}

	// 2. Run `ai-env new nongit --from <src>` from a separate project
	// directory. The .ai-env/ tree is created inside the cwd (project),
	// not inside the source.
	project := t.TempDir()
	// CreateCopy leaves the baseline read-only; restore write bits so
	// t.TempDir's recursive cleanup can unlink children on macOS.
	t.Cleanup(func() {
		restoreWriteBitsRecursive(filepath.Join(project, ".ai-env"))
	})
	stdout, stderr, err := runAIEnvWithOutput(t, project, "new", "nongit", "--from", src)
	if err != nil {
		t.Fatalf("ai-env new nongit --from %s: %v\nstdout:\n%s\nstderr:\n%s",
			src, err, stdout, stderr)
	}

	// 3. The .env-meta.json must record strategy=copy and a populated
	// baseline_path. The baseline is the read-only snapshot the diff
	// engine compares against; without it a copy-strategy diff would
	// have nothing to compare to.
	aiEnvDir := filepath.Join(project, ".ai-env")
	meta := readEnvMeta(t, aiEnvDir, "nongit")
	if meta.Strategy != "copy" {
		t.Fatalf("meta.strategy = %q, want %q (non-git --from must select copy strategy)",
			meta.Strategy, "copy")
	}
	if meta.BaselinePath == "" {
		t.Errorf("meta.baseline_path empty; copy-strategy diff needs a baseline to compare against")
	}
	if meta.WorkspacePath == "" {
		t.Errorf("meta.workspace_path empty; cannot locate the materialized workspace")
	}
	// And the printed summary should mention the strategy label so a
	// human running the demo sees copy-mode was selected.
	if !strings.Contains(stdout, "copy") {
		t.Errorf("ai-env new summary did not mention 'copy' strategy; got:\n%s", stdout)
	}

	// 4. Mutate an existing file and add a new one in the workspace so
	// the copy-mode diff has something to render. The fixture seeds at
	// least README.md and pyproject.toml; we modify the README and add a
	// new file under src/ to cover both change kinds.
	wsRoot := filepath.Join(aiEnvDir, "workspaces", "nongit")
	readme := filepath.Join(wsRoot, "README.md")
	if _, statErr := os.Stat(readme); statErr != nil {
		t.Fatalf("expected README.md inside workspace at %s, got: %v", readme, statErr)
	}
	if err := os.WriteFile(readme, []byte("# nongit fixture\n\nagent added a line\n"), 0o644); err != nil {
		t.Fatalf("mutate README.md: %v", err)
	}
	addedDir := filepath.Join(wsRoot, "src")
	if err := os.MkdirAll(addedDir, 0o755); err != nil {
		t.Fatalf("mkdir src/: %v", err)
	}
	if err := os.WriteFile(filepath.Join(addedDir, "feature.py"),
		[]byte("def feature():\n    return \"agent-added\"\n"), 0o644); err != nil {
		t.Fatalf("add src/feature.py: %v", err)
	}

	// 5. Export the diff via `ai-env patch` and assert the patch file
	// is non-empty, structurally a unified diff, and carries one
	// file-level `diff --git` block per changed file.
	outDir := t.TempDir()
	outFile := filepath.Join(outDir, "nongit.patch")
	patchStdout, patchStderr, err := runAIEnvWithOutput(t, project, "patch", "nongit", "--out", outFile)
	if err != nil {
		t.Fatalf("ai-env patch nongit --out %s: %v\nstdout:\n%s\nstderr:\n%s",
			outFile, err, patchStdout, patchStderr)
	}

	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("stat %s: %v", outFile, err)
	}
	if info.Size() == 0 {
		t.Fatalf("copy-mode patch file %s is empty; expected non-empty diff after real edits", outFile)
	}
	body, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read patch file: %v", err)
	}
	patch := string(body)

	// Copy-mode renderer emits one `diff --git a/<rel> b/<rel>` header
	// per changed file (per workspace.CopyDiff). We pin both files.
	for _, want := range []string{
		"diff --git a/README.md b/README.md",
		"diff --git a/src/feature.py b/src/feature.py",
	} {
		if !strings.Contains(patch, want) {
			t.Errorf("copy-mode patch missing file-level header %q:\n%s", want, patch)
		}
	}
	// Added-file marker (the new file should reference /dev/null on the
	// "old" side per the unified-diff convention).
	if !strings.Contains(patch, "--- /dev/null") {
		t.Errorf("patch missing '/dev/null' marker for added file:\n%s", patch)
	}
	// Substantive content checks on the two mutated files.
	if !strings.Contains(patch, "+agent added a line") {
		t.Errorf("patch missing README.md added line:\n%s", patch)
	}
	if !strings.Contains(patch, "+def feature():") {
		t.Errorf("patch missing src/feature.py added body:\n%s", patch)
	}

	// 6. Cross-check via `ai-env diff nongit`: the same workspace must
	// surface the same set of changed files via the diff command. A
	// regression that diverged the two surfaces would surface here.
	diffStdout, diffStderr, err := runAIEnvWithOutput(t, project, "diff", "nongit")
	if err != nil {
		t.Fatalf("ai-env diff nongit: %v\nstderr:\n%s", err, diffStderr)
	}
	if !strings.Contains(diffStdout, "README.md") {
		t.Errorf("ai-env diff stdout missing README.md; got:\n%s", diffStdout)
	}
	if !strings.Contains(diffStdout, "src/feature.py") {
		t.Errorf("ai-env diff stdout missing src/feature.py; got:\n%s", diffStdout)
	}
	if !strings.Contains(diffStdout, "copy") {
		t.Errorf("ai-env diff stdout did not advertise copy strategy; got:\n%s", diffStdout)
	}
}
