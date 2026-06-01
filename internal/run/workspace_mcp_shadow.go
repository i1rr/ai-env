// Workspace MCP config shadowing (Plan Batch 3.2).
//
// At backend.Create the supervisor renames any workspace-local MCP
// configs out of the way so the agent CLI's auto-merge cannot
// reintroduce a server that bypasses the supervisor's per-run
// `mcp-servers.json`. The two files Plan §3.2 calls out:
//
//   - `<workspace>/.mcp.json` — Claude's native workspace-level MCP
//     config. Whole file is shadowed.
//   - `<workspace>/.claude/settings.json` — Claude's per-project
//     settings. Only the `mcpServers` key is the concern; we shadow
//     the whole file when the key is present so the merge surface
//     stays binary (the file is either shadowed or not, never
//     partially scrubbed). A future iteration may scrub the key in
//     place; the plan tolerates either approach.
//
// On any of those files being present we rename them to
// `<original>.ai-env-shadowed` and record a `mcp_config_neutralized`
// lifecycle verb so a reviewer can correlate the action with the
// run. At backend.Destroy the supervisor calls
// `RestoreWorkspaceMCPConfig` which renames them back.
//
// The shadow target ".ai-env-shadowed" is deliberately a static
// suffix (NOT a per-run-id basename): if the user's previous run
// crashed between Create and Destroy the workspace already carries
// the shadowed file; the next Create sees the original gone (only
// the shadowed file present) and produces no new shadow entry. The
// stale `.ai-env-shadowed` file persists on disk until the user
// manually restores it; this is the documented graceful-degradation
// path for the "crashed mid-run" case.
//
// The functions in this file are NOT safe for concurrent use against
// the same workspace — the supervisor calls them serially at
// backend.Create / backend.Destroy time, never from multiple
// goroutines.

package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// shadowSuffix is the static suffix appended to shadowed file paths.
// Plan §3.2: ".ai-env-shadowed". Centralized here so both the shadow
// and restore paths agree on the rename target.
const shadowSuffix = ".ai-env-shadowed"

// mcpJSONFileName is the basename of Claude's workspace-level MCP
// config. The supervisor shadows the whole file when present.
const mcpJSONFileName = ".mcp.json"

// claudeSettingsDir is the basename of Claude's per-project settings
// directory under the workspace root.
const claudeSettingsDir = ".claude"

// claudeSettingsFileName is the basename of Claude's per-project
// settings file under `.claude/`. The supervisor shadows the whole
// file when its decoded shape carries an `mcpServers` key.
const claudeSettingsFileName = "settings.json"

// ShadowEntryKind is the type token recorded on each shadow entry so
// the `mcp_config_neutralized` lifecycle verb can carry it as
// metadata. The exported strings are the same tokens the verb
// metadata documents.
type ShadowEntryKind string

const (
	// ShadowEntryKindMCPJSON marks the workspace-level `.mcp.json`
	// shadow. Matches the lifecycle verb metadata's "kind" value.
	ShadowEntryKindMCPJSON ShadowEntryKind = "mcp_json"

	// ShadowEntryKindClaudeSettingsMCPServers marks the
	// `.claude/settings.json` shadow (when `mcpServers` key was
	// present). Matches the lifecycle verb metadata's "kind" value.
	ShadowEntryKindClaudeSettingsMCPServers ShadowEntryKind = "claude_settings_mcp_servers"
)

// ShadowEntry records one neutralized workspace-local MCP config.
// The supervisor holds the slice returned by
// `ShadowWorkspaceMCPConfig` for the lifetime of the run; at
// backend.Destroy it passes the same slice back to
// `RestoreWorkspaceMCPConfig` which renames each entry's Shadowed
// path back to Original.
type ShadowEntry struct {
	// Original is the absolute path of the workspace-local config
	// file the supervisor renamed away.
	Original string

	// Shadowed is the absolute path of the renamed file (typically
	// `<Original>.ai-env-shadowed`). The supervisor renames this
	// back to Original at backend.Destroy.
	Shadowed string

	// Kind is the type token recorded on the lifecycle verb so a
	// reviewer can tell at a glance which kind of config was
	// shadowed.
	Kind ShadowEntryKind
}

// ShadowWorkspaceMCPConfig renames any workspace-local MCP configs
// out of the way so the agent CLI's auto-merge cannot reintroduce a
// server bypassing the per-run `mcp-servers.json`. The function is
// idempotent in the sense that a workspace already in the shadowed
// state (the original file gone, the `.ai-env-shadowed` file
// present) produces no new shadow entry — the caller sees an empty
// slice and continues.
//
// On any error the function rolls back any rename already performed
// so the workspace is left in a consistent state — either every
// matching config is shadowed, or none are. The supervisor surfaces
// the error to abort the run before backend.Create proceeds; the
// per-run `mcp-servers.json` would otherwise compete with the
// workspace's leftover config.
//
// workspace is the absolute path of the workspace directory. An
// empty workspace path is a supervisor bug; the function rejects it
// rather than silently producing no shadows.
func ShadowWorkspaceMCPConfig(workspace string) ([]ShadowEntry, error) {
	if workspace == "" {
		return nil, errors.New("run: ShadowWorkspaceMCPConfig requires workspace")
	}

	var entries []ShadowEntry

	// Best-effort rollback: if a later step fails, undo the renames
	// already performed so the workspace is in a consistent state.
	rollback := func(done []ShadowEntry) {
		for i := len(done) - 1; i >= 0; i-- {
			_ = os.Rename(done[i].Shadowed, done[i].Original)
		}
	}

	// 1. Workspace-level .mcp.json. Shadowed whole.
	mcpPath := filepath.Join(workspace, mcpJSONFileName)
	if entry, ok, err := shadowFileIfPresent(mcpPath, ShadowEntryKindMCPJSON); err != nil {
		rollback(entries)
		return nil, err
	} else if ok {
		entries = append(entries, entry)
	}

	// 2. .claude/settings.json with mcpServers key. Shadowed whole
	//    when the key is present; left alone otherwise so an
	//    unrelated settings.json (theme, keybindings) keeps working.
	settingsPath := filepath.Join(workspace, claudeSettingsDir, claudeSettingsFileName)
	if has, err := claudeSettingsHasMCPServers(settingsPath); err != nil {
		rollback(entries)
		return nil, err
	} else if has {
		if entry, ok, err := shadowFileIfPresent(settingsPath, ShadowEntryKindClaudeSettingsMCPServers); err != nil {
			rollback(entries)
			return nil, err
		} else if ok {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// shadowFileIfPresent renames `path` to `path.ai-env-shadowed` if the
// original exists. Returns (entry, true, nil) when a rename happened,
// (zero, false, nil) when the original does not exist (or has already
// been shadowed), and (zero, false, err) on a hard error.
//
// The function deliberately tolerates the "already shadowed" state:
// a crashed previous run that did not restore would have left the
// shadowed file present and the original gone; the next call sees
// `path` does not exist and returns ok=false, leaving the stale
// shadow alone.
func shadowFileIfPresent(path string, kind ShadowEntryKind) (ShadowEntry, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ShadowEntry{}, false, nil
		}
		return ShadowEntry{}, false, fmt.Errorf("run: stat %s: %w", path, err)
	}
	// Refuse to follow a symlink: a workspace whose .mcp.json is a
	// symlink to /etc/passwd would otherwise let an attacker target
	// arbitrary host paths via the rename. We only shadow regular
	// files.
	if !info.Mode().IsRegular() {
		return ShadowEntry{}, false, fmt.Errorf("run: refuse to shadow non-regular file %s (mode=%v)", path, info.Mode())
	}

	shadowed := path + shadowSuffix
	// If the shadowed path already exists we cannot rename onto it.
	// This is the "stale shadow from a crashed previous run" case;
	// surface it as an error so the operator knows the workspace
	// needs manual cleanup rather than silently overwriting the
	// stale shadow.
	if _, err := os.Lstat(shadowed); err == nil {
		return ShadowEntry{}, false, fmt.Errorf("run: shadow target %s already exists (stale from previous run?)", shadowed)
	} else if !os.IsNotExist(err) {
		return ShadowEntry{}, false, fmt.Errorf("run: stat %s: %w", shadowed, err)
	}

	if err := os.Rename(path, shadowed); err != nil {
		return ShadowEntry{}, false, fmt.Errorf("run: rename %s -> %s: %w", path, shadowed, err)
	}

	return ShadowEntry{
		Original: path,
		Shadowed: shadowed,
		Kind:     kind,
	}, true, nil
}

// claudeSettingsHasMCPServers returns true when `path` exists and its
// decoded JSON shape carries an `mcpServers` key at the top level.
// Returns false (with a nil error) when the file is missing or when
// the file exists but does not declare the key — the supervisor
// leaves an unrelated settings.json untouched. A malformed JSON
// surfaces as an error so the operator can fix the file rather than
// silently letting an unparseable settings.json bypass the shadow.
func claudeSettingsHasMCPServers(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("run: read %s: %w", path, err)
	}
	// We decode into a generic map (not a typed struct) so a
	// settings.json carrying extra keys we do not know about still
	// parses; we only need to know whether `mcpServers` is present.
	var top map[string]any
	if err := json.Unmarshal(data, &top); err != nil {
		return false, fmt.Errorf("run: decode %s: %w", path, err)
	}
	_, ok := top["mcpServers"]
	return ok, nil
}

// RestoreWorkspaceMCPConfig renames each entry's Shadowed path back
// to Original. Called by the supervisor at backend.Destroy. Best-
// effort: a missing shadowed file (the user manually restored it
// between Create and Destroy) is tolerated; any other error is
// returned to the caller so the supervisor can surface it as a
// teardown warning. We process entries in reverse order so a
// future caller that wants to shadow nested paths (e.g.
// `.claude/settings.json` AND `.claude/settings.json.<env>` if such
// a thing ever existed) sees the inner entries restored first.
func RestoreWorkspaceMCPConfig(entries []ShadowEntry) error {
	var firstErr error
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if _, err := os.Lstat(e.Shadowed); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("run: stat %s: %w", e.Shadowed, err)
			}
			continue
		}
		if err := os.Rename(e.Shadowed, e.Original); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("run: rename %s -> %s: %w", e.Shadowed, e.Original, err)
			}
		}
	}
	return firstErr
}

// MCPConfigNeutralizedMetadata returns the metadata map for a single
// `mcp_config_neutralized` lifecycle verb emission. Centralized here
// so the supervisor's emit-verb call site does not have to re-derive
// the key names from `lifecycle_verbs.go`'s comment.
func MCPConfigNeutralizedMetadata(entry ShadowEntry) map[string]string {
	return map[string]string{
		"original": entry.Original,
		"shadowed": entry.Shadowed,
		"kind":     string(entry.Kind),
	}
}
