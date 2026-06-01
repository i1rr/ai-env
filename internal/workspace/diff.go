package workspace

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ReadMetadata loads and decodes a workspace's .env-meta.json file. It is
// the entry point Diff (and later Patch) use to discover which strategy
// backs envName so the right diff engine can be dispatched without the
// caller needing to know.
//
// aiEnvDir is the absolute path to the host's .ai-env/ directory; the
// metadata file is read from .ai-env/workspaces/<env-name>/.env-meta.json.
// A clear error is returned when the workspace does not exist or its
// metadata is unreadable; the message includes envName so the user can
// trace which command they were running.
func ReadMetadata(aiEnvDir, envName string) (WorkspaceInfo, error) {
	if aiEnvDir == "" {
		return WorkspaceInfo{}, errors.New("workspace: ReadMetadata requires aiEnvDir")
	}
	if envName == "" {
		return WorkspaceInfo{}, errors.New("workspace: ReadMetadata requires envName")
	}

	path := MetadataPath(aiEnvDir, envName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return WorkspaceInfo{}, fmt.Errorf("workspace: no metadata for env %q at %s (was it created with `ai-env new`?)", envName, path)
		}
		return WorkspaceInfo{}, fmt.Errorf("workspace: read metadata %s: %w", path, err)
	}

	var meta envMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return WorkspaceInfo{}, fmt.Errorf("workspace: parse metadata %s: %w", path, err)
	}

	// We deliberately do not parse CreatedAt back into time.Time here: the
	// diff path never needs it, and parsing would force the caller to handle
	// a malformed timestamp inside what should be a fast happy path. If a
	// future caller needs the timestamp it can do its own parse.
	info := WorkspaceInfo{
		Name:         meta.Name,
		Strategy:     StrategyType(meta.Strategy),
		Path:         meta.WorkspacePath,
		SourcePath:   meta.SourcePath,
		Branch:       meta.Branch,
		BaselinePath: meta.BaselinePath,
		Template:     meta.Template,
	}
	if info.Name == "" {
		// Tolerate older metadata files that omitted name; fall back to the
		// directory basename so callers always get a usable label.
		info.Name = envName
	}
	if info.Path == "" {
		// Same fallback for workspace path: compute it from aiEnvDir so the
		// diff engine has somewhere concrete to read.
		info.Path = WorkspacePath(aiEnvDir, envName)
	}
	return info, nil
}

// Diff computes the structured diff for envName using the strategy recorded
// in its metadata. It is the single entry point CLI callers should reach
// for; the per-strategy implementations live below.
//
// matcher classifies each changed file as protected or not. Pass nil to opt
// out of protected-path flagging entirely; pass a matcher built from
// policy.yaml + DefaultProtectedPaths to use the configured rules.
//
// On unknown strategy values (e.g. a metadata file from a future version of
// ai-env) Diff returns a clear error rather than guessing.
func Diff(aiEnvDir, envName string, matcher *ProtectedMatcher) (DiffResult, error) {
	info, err := ReadMetadata(aiEnvDir, envName)
	if err != nil {
		return DiffResult{}, err
	}

	switch info.Strategy {
	case StrategyWorktree:
		return diffWorktree(info, matcher)
	case StrategyCopy:
		return diffCopy(info, matcher)
	default:
		return DiffResult{}, fmt.Errorf("workspace: unknown strategy %q for env %q", info.Strategy, envName)
	}
}

// diffWorktree produces a DiffResult by asking git for the diff between the
// env branch's tip and its merge base against the source repo's HEAD. We
// use the merge base (rather than HEAD directly) so a commit landed on the
// source's HEAD after the worktree was created does not show up as an
// "undone" change in the env's diff. The intent is to show only what the
// agent itself changed since the worktree was branched.
//
// The function also generates a per-file breakdown so the CLI can render a
// summary table and flag protected hits without re-parsing the unified
// diff text.
func diffWorktree(info WorkspaceInfo, matcher *ProtectedMatcher) (DiffResult, error) {
	if info.SourcePath == "" {
		return DiffResult{}, fmt.Errorf("workspace: worktree env %q has no recorded source path", info.Name)
	}
	if info.Branch == "" {
		return DiffResult{}, fmt.Errorf("workspace: worktree env %q has no recorded branch", info.Name)
	}

	// The base ref is the source repo's current HEAD; the env branch's
	// changes are everything that differs between that base and the env
	// branch's tip. `git diff <base>...<branch>` asks specifically for that
	// (the symmetric "..." form picks the merge base for us).
	base := "HEAD"
	branch := info.Branch
	spec := base + "..." + branch

	// Unified diff body. We pass --no-color so the output is suitable both
	// for piping into patch(1) and for stable matching in tests.
	unified, err := captureGit(info.SourcePath, "diff", "--no-color", spec)
	if err != nil {
		return DiffResult{}, fmt.Errorf("workspace: git diff %s in %s: %w", spec, info.SourcePath, err)
	}

	// --name-status gives us a deterministic per-file list with change kind
	// (A/M/D/R...). Parsing the unified diff text would be brittle; the
	// porcelain output is the contract git documents for scripts.
	nameStatus, err := captureGit(info.SourcePath, "diff", "--name-status", "--no-color", spec)
	if err != nil {
		return DiffResult{}, fmt.Errorf("workspace: git diff --name-status %s in %s: %w", spec, info.SourcePath, err)
	}

	files := parseNameStatus(nameStatus)

	// Flag protected paths and collect the hit list. We do this in a second
	// pass so the order in DiffResult.Files matches name-status output but
	// DiffResult.ProtectedHits stays a flat, dedup-by-path list the caller
	// can show on its own.
	var hits []string
	for i := range files {
		if matcher != nil && matcher.Match(files[i].Path) {
			files[i].Protected = true
			hits = append(hits, files[i].Path)
		}
	}

	return DiffResult{
		Name:          info.Name,
		Strategy:      StrategyWorktree,
		Files:         files,
		Unified:       unified,
		ProtectedHits: hits,
	}, nil
}

// parseNameStatus turns git's --name-status output into FileDiff entries.
// The format is one line per file: "<status>\t<path>" (or
// "<status>\t<src>\t<dst>" for renames/copies). We only need the change
// kind and the workspace-relative path, so renames are recorded as a
// modified entry on the destination path (the unified diff text already
// carries the rename detail).
func parseNameStatus(output string) []FileDiff {
	var files []FileDiff
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		status := parts[0]
		// Use the last path field so renames/copies are attributed to the
		// destination, which is what shows up in the unified diff.
		path := parts[len(parts)-1]
		files = append(files, FileDiff{
			Path:   path,
			Change: changeKindFromStatus(status),
		})
	}
	return files
}

// changeKindFromStatus maps git's single-letter status codes onto the
// workspace-level ChangeKind enum. Anything we do not explicitly recognize
// (e.g. "U" for unmerged) is reported as modified so the file still shows
// up in the listing rather than being silently dropped.
func changeKindFromStatus(status string) ChangeKind {
	if status == "" {
		return ChangeModified
	}
	switch status[0] {
	case 'A':
		return ChangeAdded
	case 'D':
		return ChangeDeleted
	case 'M', 'R', 'C', 'T':
		return ChangeModified
	default:
		return ChangeModified
	}
}

// diffCopy produces a DiffResult by walking the workspace and the baseline
// in parallel and emitting an entry for every file whose content (or
// presence) differs. The unified-diff body is assembled per-file with the
// "diff -u"-compatible header git apply and patch(1) expect, so callers can
// hand DiffResult.Unified straight to either tool.
func diffCopy(info WorkspaceInfo, matcher *ProtectedMatcher) (DiffResult, error) {
	if info.Path == "" {
		return DiffResult{}, fmt.Errorf("workspace: copy env %q has no recorded workspace path", info.Name)
	}
	if info.BaselinePath == "" {
		return DiffResult{}, fmt.Errorf("workspace: copy env %q has no recorded baseline path", info.Name)
	}

	wsFiles, err := listRegularFiles(info.Path)
	if err != nil {
		return DiffResult{}, fmt.Errorf("workspace: scan workspace %s: %w", info.Path, err)
	}
	blFiles, err := listRegularFiles(info.BaselinePath)
	if err != nil {
		return DiffResult{}, fmt.Errorf("workspace: scan baseline %s: %w", info.BaselinePath, err)
	}

	// Build a sorted, deduplicated union of relative paths so the per-file
	// loop visits each path exactly once in a deterministic order. Sorting
	// is important: tests and human readers both rely on stable output.
	union := make(map[string]struct{}, len(wsFiles)+len(blFiles))
	for p := range wsFiles {
		union[p] = struct{}{}
	}
	for p := range blFiles {
		union[p] = struct{}{}
	}
	rels := make([]string, 0, len(union))
	for p := range union {
		rels = append(rels, p)
	}
	sort.Strings(rels)

	var files []FileDiff
	var unifiedBuf bytes.Buffer
	var hits []string

	for _, rel := range rels {
		// Skip the workspace's own metadata file: it is bookkeeping, not a
		// user change. Without this skip every diff would include a noisy
		// ".env-meta.json" entry on copy-strategy workspaces.
		if rel == metadataFileName {
			continue
		}

		_, inWs := wsFiles[rel]
		_, inBl := blFiles[rel]

		switch {
		case inWs && inBl:
			same, err := filesEqual(filepath.Join(info.BaselinePath, rel), filepath.Join(info.Path, rel))
			if err != nil {
				return DiffResult{}, err
			}
			if same {
				continue
			}
			fd, body, err := buildModifiedDiff(info.BaselinePath, info.Path, rel)
			if err != nil {
				return DiffResult{}, err
			}
			files = append(files, fd)
			unifiedBuf.WriteString(body)
		case inWs && !inBl:
			fd, body, err := buildAddedDiff(info.Path, rel)
			if err != nil {
				return DiffResult{}, err
			}
			files = append(files, fd)
			unifiedBuf.WriteString(body)
		case !inWs && inBl:
			fd, body, err := buildDeletedDiff(info.BaselinePath, rel)
			if err != nil {
				return DiffResult{}, err
			}
			files = append(files, fd)
			unifiedBuf.WriteString(body)
		}
	}

	// Flag protected paths in a single pass so DiffResult.Files and
	// DiffResult.ProtectedHits agree on which entries are protected.
	for i := range files {
		if matcher != nil && matcher.Match(files[i].Path) {
			files[i].Protected = true
			hits = append(hits, files[i].Path)
		}
	}

	return DiffResult{
		Name:          info.Name,
		Strategy:      StrategyCopy,
		Files:         files,
		Unified:       unifiedBuf.String(),
		ProtectedHits: hits,
	}, nil
}

// listRegularFiles returns a set of workspace-relative paths under root for
// every regular file. Directories, symlinks, and special files are omitted:
// the copy-strategy diff only meaningfully compares regular-file contents,
// and a symlink that changed target is rare enough we can punt on it for
// this phase (it will simply not appear in the diff).
func listRegularFiles(root string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		// filepath.Rel uses the host separator; normalize to forward slashes
		// so the matcher (which is POSIX-form) sees consistent input.
		rel = filepath.ToSlash(rel)
		out[rel] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// filesEqual reports whether the two files have identical content. We use
// a SHA-256 of each file rather than byte-by-byte streaming so we do not
// have to special-case "one ended early" or worry about partial reads;
// hashing is O(n) and the two hashes are cheap to compare.
func filesEqual(a, b string) (bool, error) {
	ha, err := sha256File(a)
	if err != nil {
		return false, err
	}
	hb, err := sha256File(b)
	if err != nil {
		return false, err
	}
	return ha == hb, nil
}

// sha256File returns the hex SHA-256 digest of the file at path. It streams
// so a multi-gigabyte file does not have to fit in memory.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// buildModifiedDiff renders a unified-diff entry for a file that exists in
// both baseline and workspace but with different content. The header lines
// use the conventional "a/<rel>" and "b/<rel>" prefixes so the output is
// parseable by patch(1) -p1 and `git apply`.
func buildModifiedDiff(baselineRoot, workspaceRoot, rel string) (FileDiff, string, error) {
	oldBytes, err := os.ReadFile(filepath.Join(baselineRoot, rel))
	if err != nil {
		return FileDiff{}, "", fmt.Errorf("read baseline %s: %w", rel, err)
	}
	newBytes, err := os.ReadFile(filepath.Join(workspaceRoot, rel))
	if err != nil {
		return FileDiff{}, "", fmt.Errorf("read workspace %s: %w", rel, err)
	}

	body := renderUnifiedDiff(rel, string(oldBytes), string(newBytes), "a/"+rel, "b/"+rel)
	return FileDiff{
		Path:    rel,
		Change:  ChangeModified,
		Unified: body,
	}, body, nil
}

// buildAddedDiff renders a unified-diff entry for a file present only in
// the workspace. The "old" side is /dev/null, which is the convention
// patch(1) recognizes for "create this file".
func buildAddedDiff(workspaceRoot, rel string) (FileDiff, string, error) {
	newBytes, err := os.ReadFile(filepath.Join(workspaceRoot, rel))
	if err != nil {
		return FileDiff{}, "", fmt.Errorf("read workspace %s: %w", rel, err)
	}
	body := renderUnifiedDiff(rel, "", string(newBytes), "/dev/null", "b/"+rel)
	return FileDiff{
		Path:    rel,
		Change:  ChangeAdded,
		Unified: body,
	}, body, nil
}

// buildDeletedDiff renders a unified-diff entry for a file present only in
// the baseline. The "new" side is /dev/null, which is the convention
// patch(1) recognizes for "remove this file".
func buildDeletedDiff(baselineRoot, rel string) (FileDiff, string, error) {
	oldBytes, err := os.ReadFile(filepath.Join(baselineRoot, rel))
	if err != nil {
		return FileDiff{}, "", fmt.Errorf("read baseline %s: %w", rel, err)
	}
	body := renderUnifiedDiff(rel, string(oldBytes), "", "a/"+rel, "/dev/null")
	return FileDiff{
		Path:    rel,
		Change:  ChangeDeleted,
		Unified: body,
	}, body, nil
}

// renderUnifiedDiff emits a unified-diff block for a single file. The
// algorithm is a deliberately simple "show the entire old and new file as
// one hunk" rather than a real LCS-based diff: the copy strategy is for
// non-Git sources where we have no commit graph anyway, the patch is
// applied wholesale by patch(1) regardless of hunk shape, and the simpler
// renderer avoids pulling in a diff library for this phase. A real
// myers-style diff can replace this body without changing any callers.
//
// The header lines mirror git's format ("diff --git a/<rel> b/<rel>" plus
// the "---"/"+++" lines) so DiffResult.Unified is interchangeable with the
// worktree strategy's output for downstream tools.
func renderUnifiedDiff(rel, oldText, newText, oldLabel, newLabel string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "diff --git a/%s b/%s\n", rel, rel)
	fmt.Fprintf(&b, "--- %s\n", oldLabel)
	fmt.Fprintf(&b, "+++ %s\n", newLabel)

	oldLines := splitLinesPreserve(oldText)
	newLines := splitLinesPreserve(newText)

	// Hunk header: @@ -<old-start>,<old-len> +<new-start>,<new-len> @@
	// Use 1-based starts (or 0 when the side is empty) and the count of
	// lines on each side. Empty sides record length 0 so patch(1) handles
	// "create" and "delete" cases correctly.
	oldStart := 1
	if len(oldLines) == 0 {
		oldStart = 0
	}
	newStart := 1
	if len(newLines) == 0 {
		newStart = 0
	}
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", oldStart, len(oldLines), newStart, len(newLines))

	for _, line := range oldLines {
		writeDiffLine(&b, "-", line)
	}
	for _, line := range newLines {
		writeDiffLine(&b, "+", line)
	}
	return b.String()
}

// splitLinesPreserve splits text into lines without stripping the trailing
// newline of each line. This matters because patch(1) treats a missing
// final newline as a content difference; preserving it here lets the
// emitter add a "\ No newline at end of file" marker correctly.
func splitLinesPreserve(text string) []string {
	if text == "" {
		return nil
	}
	var lines []string
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			lines = append(lines, text[start:i+1])
			start = i + 1
		}
	}
	if start < len(text) {
		// Last line without a trailing newline. Keep it as-is; the writer
		// will tag it with the "no newline" marker.
		lines = append(lines, text[start:])
	}
	return lines
}

// writeDiffLine writes a single diff body line with the appropriate prefix,
// adding the "\ No newline at end of file" marker when the line does not
// end with a newline so the emitted patch round-trips cleanly through
// patch(1).
func writeDiffLine(b *strings.Builder, prefix, line string) {
	b.WriteString(prefix)
	if strings.HasSuffix(line, "\n") {
		b.WriteString(line)
		return
	}
	b.WriteString(line)
	b.WriteString("\n")
	b.WriteString("\\ No newline at end of file\n")
}
