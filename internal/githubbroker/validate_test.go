package githubbroker

import (
	"errors"
	"testing"

	"github.com/i1rr/ai-env/internal/workspace"
)

// TestValidateBranchPrefix_AcceptsAIEnvPrefix pins plan 07 step 2:
// a branch name with the BranchPrefix and a non-empty suffix passes.
func TestValidateBranchPrefix_AcceptsAIEnvPrefix(t *testing.T) {
	cases := []string{
		"ai-env/fix-tests",
		"ai-env/feature/something",
		"ai-env/x",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateBranchPrefix(name); err != nil {
				t.Fatalf("ValidateBranchPrefix(%q) = %v, want nil", name, err)
			}
		})
	}
}

// TestValidateBranchPrefix_RejectsNonPrefixed pins plan 07 step 2's
// negative path: any branch name that does not start with "ai-env/"
// must be rejected with ErrInvalidBranchPrefix.
func TestValidateBranchPrefix_RejectsNonPrefixed(t *testing.T) {
	cases := []string{
		"main",
		"master",
		"feature/fix-tests",
		"ai-env-fix-tests", // close but missing the slash
		"AI-ENV/fix-tests", // case-sensitive
		"",
		"ai-env/", // prefix but no suffix
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateBranchPrefix(name)
			if err == nil {
				t.Fatalf("ValidateBranchPrefix(%q) = nil, want error", name)
			}
			if !errors.Is(err, ErrInvalidBranchPrefix) {
				t.Fatalf("ValidateBranchPrefix(%q) error %v, want errors.Is ErrInvalidBranchPrefix", name, err)
			}
		})
	}
}

// TestValidateProtectedBranch_AcceptsNonProtected pins plan 07 step 3
// positive path: branches that are not main, master, or in the extras
// list pass.
func TestValidateProtectedBranch_AcceptsNonProtected(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "widgets", DefaultBranch: "main"}
	cases := []string{
		"ai-env/fix-tests",
		"ai-env/feature",
		"release/v1",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateProtectedBranch(name, repo, nil); err != nil {
				t.Fatalf("ValidateProtectedBranch(%q) = %v, want nil", name, err)
			}
		})
	}
}

// TestValidateProtectedBranch_RejectsDefaultProtected pins plan 07
// step 3: the default-protected list (main, master, etc.) must block.
func TestValidateProtectedBranch_RejectsDefaultProtected(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "widgets"}
	cases := []string{"main", "master", "trunk", "develop"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateProtectedBranch(name, repo, nil)
			if err == nil {
				t.Fatalf("ValidateProtectedBranch(%q) = nil, want error", name)
			}
			if !errors.Is(err, ErrProtectedBranch) {
				t.Fatalf("ValidateProtectedBranch(%q) error %v, want errors.Is ErrProtectedBranch", name, err)
			}
		})
	}
}

// TestValidateProtectedBranch_RejectsRepoDefaultBranch confirms a
// repository whose default branch is something exotic (not in the
// hardcoded defaults) still gets blocked when the broker is asked to
// push directly to that default branch.
func TestValidateProtectedBranch_RejectsRepoDefaultBranch(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "widgets", DefaultBranch: "production"}
	err := ValidateProtectedBranch("production", repo, nil)
	if err == nil {
		t.Fatalf("ValidateProtectedBranch(production) = nil, want error")
	}
	if !errors.Is(err, ErrProtectedBranch) {
		t.Fatalf("error %v, want errors.Is ErrProtectedBranch", err)
	}
}

// TestValidateProtectedBranch_RejectsExtrasList confirms the
// caller-supplied extras list (loaded from policy.yaml) adds protection
// beyond the defaults.
func TestValidateProtectedBranch_RejectsExtrasList(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "widgets", DefaultBranch: "main"}
	extras := []string{"release", "staging"}
	err := ValidateProtectedBranch("staging", repo, extras)
	if err == nil {
		t.Fatalf("ValidateProtectedBranch(staging) = nil, want error")
	}
	if !errors.Is(err, ErrProtectedBranch) {
		t.Fatalf("error %v, want errors.Is ErrProtectedBranch", err)
	}
}

// TestValidateProtectedBranch_RejectsEmpty confirms an empty branch
// name is rejected so a caller that forgets to populate BranchName
// does not silently succeed.
func TestValidateProtectedBranch_RejectsEmpty(t *testing.T) {
	err := ValidateProtectedBranch("", Repo{DefaultBranch: "main"}, nil)
	if err == nil {
		t.Fatalf("ValidateProtectedBranch(\"\") = nil, want error")
	}
	if !errors.Is(err, ErrProtectedBranch) {
		t.Fatalf("error %v, want errors.Is ErrProtectedBranch", err)
	}
}

// TestValidatePathGate_BlocksWorkflowChanges pins plan 07 step 4: a
// diff that touches .github/workflows/** must trip the gate.
func TestValidatePathGate_BlocksWorkflowChanges(t *testing.T) {
	diff := workspace.DiffResult{
		Files: []workspace.FileDiff{
			{Path: ".github/workflows/ci.yml", Change: workspace.ChangeModified},
			{Path: "src/main.go", Change: workspace.ChangeModified},
		},
	}
	hits, err := ValidatePathGate(diff, PathGateOptions{})
	if err == nil {
		t.Fatalf("ValidatePathGate returned nil error, want ErrProtectedPath")
	}
	if !errors.Is(err, ErrProtectedPath) {
		t.Fatalf("error %v, want errors.Is ErrProtectedPath", err)
	}
	if len(hits) != 1 {
		t.Fatalf("len(hits)=%d, want 1; hits=%+v", len(hits), hits)
	}
	if hits[0].Path != ".github/workflows/ci.yml" {
		t.Fatalf("hits[0].Path=%q, want .github/workflows/ci.yml", hits[0].Path)
	}
	if hits[0].Glob != ".github/workflows/**" {
		t.Fatalf("hits[0].Glob=%q, want .github/workflows/**", hits[0].Glob)
	}
}

// TestValidatePathGate_BlocksAIEnvChanges pins plan 07 step 4: a diff
// that touches .ai-env/** must trip the gate.
func TestValidatePathGate_BlocksAIEnvChanges(t *testing.T) {
	diff := workspace.DiffResult{
		Files: []workspace.FileDiff{
			{Path: ".ai-env/policy.yaml", Change: workspace.ChangeModified},
		},
	}
	hits, err := ValidatePathGate(diff, PathGateOptions{})
	if err == nil {
		t.Fatalf("ValidatePathGate returned nil error, want ErrProtectedPath")
	}
	if !errors.Is(err, ErrProtectedPath) {
		t.Fatalf("error %v, want errors.Is ErrProtectedPath", err)
	}
	if len(hits) != 1 {
		t.Fatalf("len(hits)=%d, want 1; hits=%+v", len(hits), hits)
	}
	if hits[0].Glob != ".ai-env/**" {
		t.Fatalf("hits[0].Glob=%q, want .ai-env/**", hits[0].Glob)
	}
}

// TestValidatePathGate_AllowsCleanDiff confirms a diff that touches
// only allowed paths passes the gate.
func TestValidatePathGate_AllowsCleanDiff(t *testing.T) {
	diff := workspace.DiffResult{
		Files: []workspace.FileDiff{
			{Path: "src/main.go", Change: workspace.ChangeModified},
			{Path: "README.md", Change: workspace.ChangeModified},
			{Path: "docs/howto.md", Change: workspace.ChangeAdded},
		},
	}
	hits, err := ValidatePathGate(diff, PathGateOptions{})
	if err != nil {
		t.Fatalf("ValidatePathGate err=%v, want nil", err)
	}
	if len(hits) != 0 {
		t.Fatalf("len(hits)=%d, want 0; hits=%+v", len(hits), hits)
	}
}

// TestValidatePathGate_BlocksDeletedProtectedFile confirms that
// removing a workflow file is still considered a hit. The gate cares
// about touching the path, not about the direction of the change.
func TestValidatePathGate_BlocksDeletedProtectedFile(t *testing.T) {
	diff := workspace.DiffResult{
		Files: []workspace.FileDiff{
			{Path: ".github/workflows/release.yml", Change: workspace.ChangeDeleted},
		},
	}
	hits, err := ValidatePathGate(diff, PathGateOptions{})
	if err == nil {
		t.Fatalf("ValidatePathGate returned nil error, want ErrProtectedPath")
	}
	if !errors.Is(err, ErrProtectedPath) {
		t.Fatalf("error %v, want errors.Is ErrProtectedPath", err)
	}
	if len(hits) != 1 {
		t.Fatalf("len(hits)=%d, want 1; hits=%+v", len(hits), hits)
	}
}

// TestValidatePathGate_ExtraBlockGlobs confirms the caller can add
// patterns (e.g. from policy.yaml) on top of the defaults.
func TestValidatePathGate_ExtraBlockGlobs(t *testing.T) {
	diff := workspace.DiffResult{
		Files: []workspace.FileDiff{
			{Path: "terraform/prod/main.tf", Change: workspace.ChangeModified},
		},
	}
	hits, err := ValidatePathGate(diff, PathGateOptions{
		ExtraBlockGlobs: []string{"terraform/**"},
	})
	if err == nil {
		t.Fatalf("ValidatePathGate returned nil error, want ErrProtectedPath")
	}
	if !errors.Is(err, ErrProtectedPath) {
		t.Fatalf("error %v, want errors.Is ErrProtectedPath", err)
	}
	if len(hits) != 1 || hits[0].Glob != "terraform/**" {
		t.Fatalf("hits=%+v, want one terraform/** hit", hits)
	}
}

// TestValidatePathGate_ReplaceDefaults confirms ReplaceDefaults makes
// the extras the only block list (and tests that workflow changes
// pass when the operator explicitly disables the default rule).
func TestValidatePathGate_ReplaceDefaults(t *testing.T) {
	diff := workspace.DiffResult{
		Files: []workspace.FileDiff{
			{Path: ".github/workflows/ci.yml", Change: workspace.ChangeModified},
		},
	}
	hits, err := ValidatePathGate(diff, PathGateOptions{
		ExtraBlockGlobs: []string{"infra/**"},
		ReplaceDefaults: true,
	})
	if err != nil {
		t.Fatalf("ValidatePathGate err=%v, want nil (defaults replaced)", err)
	}
	if len(hits) != 0 {
		t.Fatalf("len(hits)=%d, want 0; hits=%+v", len(hits), hits)
	}
}

// TestValidatePathGate_BlocksMultipleHits confirms every matching path
// is reported, not just the first one.
func TestValidatePathGate_BlocksMultipleHits(t *testing.T) {
	diff := workspace.DiffResult{
		Files: []workspace.FileDiff{
			{Path: ".github/workflows/ci.yml", Change: workspace.ChangeModified},
			{Path: ".ai-env/policy.yaml", Change: workspace.ChangeModified},
			{Path: "src/main.go", Change: workspace.ChangeModified},
		},
	}
	hits, err := ValidatePathGate(diff, PathGateOptions{})
	if err == nil {
		t.Fatalf("ValidatePathGate returned nil error, want ErrProtectedPath")
	}
	if !errors.Is(err, ErrProtectedPath) {
		t.Fatalf("error %v, want errors.Is ErrProtectedPath", err)
	}
	if len(hits) != 2 {
		t.Fatalf("len(hits)=%d, want 2; hits=%+v", len(hits), hits)
	}
}

// TestValidatePathGate_EmptyDiff confirms the gate passes for an empty
// diff: there is nothing to block on.
func TestValidatePathGate_EmptyDiff(t *testing.T) {
	hits, err := ValidatePathGate(workspace.DiffResult{}, PathGateOptions{})
	if err != nil {
		t.Fatalf("ValidatePathGate err=%v, want nil", err)
	}
	if len(hits) != 0 {
		t.Fatalf("len(hits)=%d, want 0", len(hits))
	}
}
