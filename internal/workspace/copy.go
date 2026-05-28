package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// baselineSubdir is the directory under the host's .ai-env/ where every
// copy-strategy baseline snapshot lives. The baseline is the read-only
// reference the diff engine compares the live workspace against, so it has
// to live somewhere stable and predictable; ".ai-env/baselines/" mirrors the
// ".ai-env/workspaces/" layout used by Create so the two roots stay siblings.
const baselineSubdir = "baselines"

// BaselinePath returns the absolute path of the baseline snapshot directory
// for envName under aiEnvDir. It is the read-only mirror of WorkspacePath
// used by the copy-strategy diff engine.
func BaselinePath(aiEnvDir, envName string) string {
	return filepath.Join(aiEnvDir, baselineSubdir, envName)
}

// CreateCopy materializes a copy-backed workspace for envName.
//
// It performs the three actions plan 02 step 4 requires:
//
//  1. Copy the source directory recursively to
//     aiEnvDir/workspaces/<env-name>/ so the agent has an isolated working
//     tree of its own.
//  2. Store a read-only baseline snapshot at
//     aiEnvDir/baselines/<env-name>/ so the diff engine has a stable
//     reference to compare the workspace against later.
//  3. Write a .env-meta.json file inside the workspace recording the source
//     path, copy time, baseline path, and a hash summary of the copied
//     contents (plus identifying fields shared with the worktree strategy:
//     name, strategy, created_at, template).
//
// Inputs:
//   - aiEnvDir is the absolute path to the host's .ai-env/ directory. The
//     workspace lands under aiEnvDir/workspaces/<env-name>/ and the baseline
//     under aiEnvDir/baselines/<env-name>/. The caller resolves this path;
//     CreateCopy does not assume the process working directory.
//   - envName is the workspace name. It is used as the basename of both the
//     workspace and the baseline directories.
//   - sourcePath is the absolute path to the directory being copied. It must
//     exist and be a directory; CreateCopy does not perform Git detection of
//     its own (the caller's strategy selection already did that).
//   - template is the sandbox template label (e.g. "node") to record in the
//     metadata file. Pass "" when no template applies.
//   - now supplies the timestamp recorded as both created_at and copy_time.
//     Pass time.Now in production; tests pass a fixed time so on-disk
//     metadata is deterministic.
//
// On success CreateCopy returns a fully populated WorkspaceInfo
// (Strategy=StrategyCopy, Branch empty, BaselinePath set). On failure it
// makes a best-effort attempt to roll back partial state: any partially
// copied workspace or baseline directory is removed so a retry starts from
// a clean slate.
func CreateCopy(aiEnvDir, envName, sourcePath, template string, now time.Time) (WorkspaceInfo, error) {
	if aiEnvDir == "" {
		return WorkspaceInfo{}, errors.New("workspace: CreateCopy requires aiEnvDir")
	}
	if envName == "" {
		return WorkspaceInfo{}, errors.New("workspace: CreateCopy requires envName")
	}
	if sourcePath == "" {
		return WorkspaceInfo{}, errors.New("workspace: CreateCopy requires sourcePath")
	}

	// Confirm the source is a directory we can read. Catching this up front
	// gives a clearer error than letting the recursive walk fail on its
	// first stat call.
	srcInfo, err := os.Stat(sourcePath)
	if err != nil {
		return WorkspaceInfo{}, fmt.Errorf("workspace: stat source %s: %w", sourcePath, err)
	}
	if !srcInfo.IsDir() {
		return WorkspaceInfo{}, fmt.Errorf("workspace: source %s is not a directory", sourcePath)
	}

	wsPath := WorkspacePath(aiEnvDir, envName)
	blPath := BaselinePath(aiEnvDir, envName)

	// Refuse to clobber an existing workspace directory. As with
	// CreateWorktree, the caller's policy (e.g. --force) is responsible for
	// cleaning up first; CreateCopy itself stays conservative so a retried
	// run cannot silently merge state from a previous attempt.
	if _, err := os.Stat(wsPath); err == nil {
		return WorkspaceInfo{}, fmt.Errorf("workspace: workspace path %s already exists", wsPath)
	} else if !os.IsNotExist(err) {
		return WorkspaceInfo{}, fmt.Errorf("workspace: stat %s: %w", wsPath, err)
	}
	if _, err := os.Stat(blPath); err == nil {
		return WorkspaceInfo{}, fmt.Errorf("workspace: baseline path %s already exists", blPath)
	} else if !os.IsNotExist(err) {
		return WorkspaceInfo{}, fmt.Errorf("workspace: stat %s: %w", blPath, err)
	}

	// Ensure the parent directories (.ai-env/workspaces/ and
	// .ai-env/baselines/) exist before any copy work runs. copyTree creates
	// the leaf directory itself but does not create intermediate parents.
	if err := os.MkdirAll(filepath.Dir(wsPath), 0o755); err != nil {
		return WorkspaceInfo{}, fmt.Errorf("workspace: create workspace parent %s: %w", filepath.Dir(wsPath), err)
	}
	if err := os.MkdirAll(filepath.Dir(blPath), 0o755); err != nil {
		return WorkspaceInfo{}, fmt.Errorf("workspace: create baseline parent %s: %w", filepath.Dir(blPath), err)
	}

	// Copy the source into the workspace first. The workspace is the
	// agent-writable copy; the baseline is a frozen mirror of the same
	// bytes. We do the workspace copy first so a failure here does not
	// leave a baseline orphaned without a matching workspace.
	if err := copyTree(sourcePath, wsPath, false); err != nil {
		_ = os.RemoveAll(wsPath)
		return WorkspaceInfo{}, fmt.Errorf("workspace: copy source to workspace: %w", err)
	}

	// Copy the same source into the baseline directory with read-only
	// permissions. The baseline is what Diff compares the workspace against;
	// stripping write bits at copy time is a cheap guard against accidental
	// edits by the agent or its tools.
	if err := copyTree(sourcePath, blPath, true); err != nil {
		_ = os.RemoveAll(wsPath)
		_ = removeReadOnlyTree(blPath)
		return WorkspaceInfo{}, fmt.Errorf("workspace: copy source to baseline: %w", err)
	}

	// Compute a single hash summarizing the copied contents. The hash is
	// recorded in metadata so a later integrity check can detect baseline
	// tampering without re-walking the tree from scratch.
	summary, err := hashTree(blPath)
	if err != nil {
		_ = os.RemoveAll(wsPath)
		_ = removeReadOnlyTree(blPath)
		return WorkspaceInfo{}, fmt.Errorf("workspace: hash baseline: %w", err)
	}

	info := WorkspaceInfo{
		Name:         envName,
		Strategy:     StrategyCopy,
		Path:         wsPath,
		SourcePath:   sourcePath,
		BaselinePath: blPath,
		Template:     template,
		CreatedAt:    now,
	}

	// Persist metadata. If this fails we tear the workspace and baseline
	// down so the next attempt is not blocked by leftover state. The user
	// only sees a successful workspace when its metadata exists too, so
	// later commands can rely on the file being present.
	if err := writeCopyMetadata(aiEnvDir, info, now, summary); err != nil {
		_ = os.RemoveAll(wsPath)
		_ = removeReadOnlyTree(blPath)
		return WorkspaceInfo{}, err
	}

	return info, nil
}

// writeCopyMetadata serializes info plus copy-strategy specific fields
// (copy_time, hash_summary) to the workspace's .env-meta.json file. It
// reuses writeMetadata's worktree-strategy fields by going through the same
// envMetadata struct so the two strategies share a single on-disk schema.
func writeCopyMetadata(aiEnvDir string, info WorkspaceInfo, copyTime time.Time, hashSummary string) error {
	// Reuse writeMetadata for the shared fields, then patch in the copy-
	// specific ones. Doing it in two steps keeps the shared serialization
	// (field ordering, indent, trailing newline) in one place.
	if err := writeMetadata(aiEnvDir, info); err != nil {
		return err
	}

	// Re-read what writeMetadata produced, augment it with the copy fields,
	// and write it back. The metadata file is small (a few hundred bytes)
	// so the round trip costs nothing and avoids duplicating envMetadata
	// marshaling logic.
	path := MetadataPath(aiEnvDir, info.Name)
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("workspace: re-read metadata %s: %w", path, err)
	}

	var meta envMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return fmt.Errorf("workspace: parse metadata %s: %w", path, err)
	}
	meta.CopyTime = copyTime.Format(time.RFC3339)
	meta.HashSummary = hashSummary

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("workspace: marshal metadata for %s: %w", info.Name, err)
	}
	// Trailing newline keeps the file POSIX-text-file friendly, matching
	// what writeMetadata wrote the first time around.
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("workspace: write metadata %s: %w", path, err)
	}
	return nil
}

// copyTree recursively copies the directory at src to dst. When readOnly is
// true, regular files land with mode 0o444 and directories with 0o555 so
// the baseline cannot be edited in place; otherwise the source's own
// permission bits are preserved.
//
// Symlinks are reproduced as symlinks (their target is not followed). This
// matches what the user would expect of an isolated copy of their tree:
// links inside the tree continue to resolve relatively, links pointing
// outside still point outside.
func copyTree(src, dst string, readOnly bool) error {
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("lstat %s: %w", src, err)
	}

	switch {
	case srcInfo.Mode()&os.ModeSymlink != 0:
		return copySymlink(src, dst)
	case srcInfo.IsDir():
		dirMode := srcInfo.Mode().Perm()
		finalMode := dirMode
		if readOnly {
			finalMode = 0o555
		}
		// Create the directory with writable bits regardless of the final
		// mode. A read-only directory (0o555) cannot accept new children, so
		// we must populate it first and only then chmod it down to its final
		// read-only mode. We use 0o755 for the staging mode rather than the
		// source's own mode so even a source dir that happens to be read-only
		// can be populated faithfully.
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dst, err)
		}

		entries, err := os.ReadDir(src)
		if err != nil {
			return fmt.Errorf("readdir %s: %w", src, err)
		}
		for _, entry := range entries {
			if err := copyTree(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name()), readOnly); err != nil {
				return err
			}
		}
		// Apply the final directory mode after populating it. MkdirAll
		// respects the process umask, so even the non-readOnly case needs an
		// explicit chmod to land on the source's exact permission bits. The
		// read-only case must wait until children are written because a
		// 0o555 directory cannot accept new entries.
		if err := os.Chmod(dst, finalMode); err != nil {
			return fmt.Errorf("chmod %s: %w", dst, err)
		}
		return nil
	case srcInfo.Mode().IsRegular():
		return copyFile(src, dst, srcInfo, readOnly)
	default:
		// Sockets, devices, named pipes: skip silently. They have no place
		// in a source-tree copy and reproducing them would require elevated
		// privileges we deliberately do not assume.
		return nil
	}
}

// copyFile copies the regular file at src to dst, preserving its content
// and (when readOnly is false) its permission bits. When readOnly is true
// the destination is written with mode 0o444 so the baseline cannot be
// edited in place.
func copyFile(src, dst string, info os.FileInfo, readOnly bool) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	mode := info.Mode().Perm()
	if readOnly {
		mode = 0o444
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	// Re-apply mode explicitly: OpenFile's mode argument is masked by the
	// process umask, so a read-only file would otherwise pick up the user's
	// default write bits even when we asked for 0o444.
	if err := os.Chmod(dst, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", dst, err)
	}
	return nil
}

// copySymlink reproduces the symlink at src as a symlink at dst. The link
// target is copied verbatim; it is not resolved, so links pointing inside
// the tree continue to resolve relatively in the copy and links pointing
// outside still point outside.
func copySymlink(src, dst string) error {
	target, err := os.Readlink(src)
	if err != nil {
		return fmt.Errorf("readlink %s: %w", src, err)
	}
	if err := os.Symlink(target, dst); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", dst, target, err)
	}
	return nil
}

// removeReadOnlyTree deletes a directory tree even when its directories or
// files were created read-only (as the baseline is). os.RemoveAll on its
// own fails on read-only directories on some filesystems because it cannot
// unlink children inside them; this helper walks the tree first and
// restores write bits before delegating to RemoveAll.
func removeReadOnlyTree(root string) error {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Ignore: best-effort cleanup.
			return nil
		}
		_ = os.Chmod(path, 0o755)
		return nil
	})
	return os.RemoveAll(root)
}

// hashTree returns a single SHA-256 digest summarizing the contents of the
// tree rooted at root. The digest is taken over a deterministic listing of
// (relative path, file kind, file content hash) tuples so two trees with
// the same files in any walk order produce the same summary.
//
// The summary is recorded in the workspace's metadata as "sha256:<hex>" so
// later commands can detect baseline tampering without re-walking the tree
// from scratch.
func hashTree(root string) (string, error) {
	type entry struct {
		rel  string
		kind string
		hash string
	}
	var entries []entry

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, lerr := os.Readlink(path)
			if lerr != nil {
				return fmt.Errorf("readlink %s: %w", path, lerr)
			}
			h := sha256.Sum256([]byte(target))
			entries = append(entries, entry{rel: rel, kind: "l", hash: hex.EncodeToString(h[:])})
		case info.IsDir():
			entries = append(entries, entry{rel: rel, kind: "d", hash: ""})
		case info.Mode().IsRegular():
			fh, herr := hashFile(path)
			if herr != nil {
				return herr
			}
			entries = append(entries, entry{rel: rel, kind: "f", hash: fh})
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	// Sort so the summary is stable regardless of the OS-dependent walk
	// order. filepath.Walk already sorts per-directory, but sorting the
	// flattened list explicitly is cheap insurance against any future
	// change.
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	h := sha256.New()
	for _, e := range entries {
		// One line per entry, NUL-separated fields to keep paths with
		// spaces unambiguous. Newline terminates each entry.
		fmt.Fprintf(h, "%s\x00%s\x00%s\n", e.kind, e.rel, e.hash)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// hashFile returns the hex-encoded SHA-256 digest of the file at path. It
// streams the file so large blobs do not have to fit in memory.
func hashFile(path string) (string, error) {
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
