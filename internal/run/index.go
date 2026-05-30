package run

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrNoRuns is returned by LatestRunForEnv (and helpers built on top of
// it) when no run directory for the requested env exists yet. Callers
// that distinguish "this env has never run" from "the lookup itself
// failed" use errors.Is to match on it. The status and logs commands
// surface this as a clean "no runs yet" message rather than a stack of
// wrapped errors.
var ErrNoRuns = errors.New("run: no runs recorded for env")

// RunSummary is the small, read-only view of a run that callers outside
// the run package (CLI status / list / logs) hold onto. Every field is
// cheap to compute: ID is the directory basename, EnvName is read from
// run.json (or inferred from a fallback path on the unwritten edge case),
// Path is the absolute on-disk run directory. The full Record is loaded
// separately via ReadRecord when callers actually need the schema.
//
// RunSummary is intentionally a value type with no pointers and no
// methods. Callers append to slices of it freely; sorting and filtering
// happen at the use site so the index helpers stay tiny.
type RunSummary struct {
	// ID is the run identifier, which is also the directory basename
	// under .ai-env/runs/. Lexically sortable by construction (the run
	// ID format starts with "YYYYMMDD-HHMMSS-"), so callers that want
	// "the latest" sort the slice descending and take element 0.
	ID string

	// EnvName is the env_name field decoded from run.json. Empty when
	// run.json has not been written yet (the post-CreateRunDirectory
	// placeholder state); the index helpers skip such rows when
	// filtering by env so partially-initialized runs do not pollute
	// results.
	EnvName string

	// Path is the absolute path of the run directory itself, suitable
	// for passing into ReadRecord, OpenLifecycleWriter (replay only),
	// or filepath.Join'ing for stdout.log / stderr.log access. Always
	// non-empty.
	Path string
}

// ListRuns enumerates every run directory under aiEnvDir/runs/ and
// returns one RunSummary per entry. The result is sorted by run ID in
// descending order (most recent first) so callers that want "the
// latest" can take element 0 without a second sort.
//
// Behavior notes:
//
//   - When aiEnvDir/runs/ does not exist (a fresh project that has not
//     yet executed a run), ListRuns returns an empty slice and a nil
//     error. The caller distinguishes "no runs yet" from "the listing
//     failed" by inspecting the slice length.
//   - Entries whose run.json is missing or malformed are still included
//     with an empty EnvName. The directory itself is the source of
//     truth for "a run happened here"; the schema decode is best
//     effort. CLI callers filtering by env will skip these rows
//     naturally (an empty EnvName cannot equal a non-empty requested
//     env), but list-all callers see the row so the operator can
//     investigate a half-written run.
//   - Hidden directories (names starting with ".") are skipped. Real
//     run IDs cannot start with a dot (they start with a digit by the
//     timestamp format), so this only filters accidental dotfile
//     droppings (e.g. .DS_Store on macOS).
//   - Regular files at runs/ root are ignored. The supervisor only
//     ever creates directories there.
//
// ListRuns does not validate that each entry name matches the run ID
// format. A future replay tool might create directories that follow a
// different naming scheme (e.g. archived runs renamed by a janitor);
// the index helpers should not gate on the regex so those entries stay
// discoverable.
func ListRuns(aiEnvDir string) ([]RunSummary, error) {
	if aiEnvDir == "" {
		return nil, errors.New("run: ListRuns requires aiEnvDir")
	}

	runsDir := RunsRoot(aiEnvDir)
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("run: read runs dir %s: %w", runsDir, err)
	}

	out := make([]RunSummary, 0, len(entries))
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		if strings.HasPrefix(de.Name(), ".") {
			continue
		}
		runDir := filepath.Join(runsDir, de.Name())
		summary := RunSummary{
			ID:   de.Name(),
			Path: runDir,
		}
		// Read env_name on a best-effort basis. ReadRecord returns
		// ErrRecordNotWritten on the post-CreateRunDirectory empty-file
		// placeholder; we silently fold that into "EnvName stays empty"
		// so the row still appears in the listing for diagnostic
		// purposes. Decode failures land in the same bucket: the
		// directory exists, so the row is real, but env attribution
		// is unknown.
		if rec, err := ReadRecord(runDir); err == nil {
			summary.EnvName = rec.EnvName
		}
		out = append(out, summary)
	}

	// Descending sort: newest run first. Run IDs are
	// "YYYYMMDD-HHMMSS-<hex>" which sorts naturally as a string.
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// LatestRunForEnv returns the most recent run directory associated with
// envName under aiEnvDir/runs/. It is the read-only helper the status,
// logs, and list commands use to locate "the run we care about" without
// each having to re-do the runs scan.
//
// envName matches against RunSummary.EnvName, which is decoded from
// run.json's env_name field. Runs whose run.json has not been written
// yet are skipped (their EnvName is empty), so a partially-initialized
// run does not mask an older completed one.
//
// Returns ErrNoRuns when no matching run exists (the runs/ directory is
// absent, empty, or contains nothing for envName). Callers wrap or
// surface ErrNoRuns directly with errors.Is.
func LatestRunForEnv(aiEnvDir, envName string) (RunSummary, error) {
	if aiEnvDir == "" {
		return RunSummary{}, errors.New("run: LatestRunForEnv requires aiEnvDir")
	}
	if envName == "" {
		return RunSummary{}, errors.New("run: LatestRunForEnv requires envName")
	}

	all, err := ListRuns(aiEnvDir)
	if err != nil {
		return RunSummary{}, err
	}
	// ListRuns already returns the slice in descending run-id order, so
	// the first match is the latest by construction.
	for _, r := range all {
		if r.EnvName == envName {
			return r, nil
		}
	}
	return RunSummary{}, fmt.Errorf("%w %q", ErrNoRuns, envName)
}

// FindRunByID returns the run directory for runID under aiEnvDir/runs/.
// It is the read-only helper the logs command uses when the operator
// passes --run <id> to pick a specific historical run rather than the
// latest one for the env.
//
// Returns ErrNoRuns when the directory does not exist; other I/O
// failures (permission errors, transient ENOENT races) are wrapped
// with their underlying error so the caller can distinguish them.
func FindRunByID(aiEnvDir, runID string) (RunSummary, error) {
	if aiEnvDir == "" {
		return RunSummary{}, errors.New("run: FindRunByID requires aiEnvDir")
	}
	if runID == "" {
		return RunSummary{}, errors.New("run: FindRunByID requires runID")
	}
	if strings.HasPrefix(runID, ".") || strings.ContainsAny(runID, "/\\") {
		// Defensive: reject path-traversal sneak attempts up front so a
		// caller passing "../" cannot escape the runs/ directory via the
		// helper. Real run IDs never contain a path separator.
		return RunSummary{}, fmt.Errorf("run: FindRunByID: invalid runID %q", runID)
	}

	runDir := RunPath(aiEnvDir, runID)
	info, err := os.Stat(runDir)
	if err != nil {
		if os.IsNotExist(err) {
			return RunSummary{}, fmt.Errorf("%w: run id %q", ErrNoRuns, runID)
		}
		return RunSummary{}, fmt.Errorf("run: stat %s: %w", runDir, err)
	}
	if !info.IsDir() {
		return RunSummary{}, fmt.Errorf("run: %s is not a directory", runDir)
	}

	summary := RunSummary{ID: runID, Path: runDir}
	if rec, err := ReadRecord(runDir); err == nil {
		summary.EnvName = rec.EnvName
	}
	return summary, nil
}

// StdoutLogPath returns the absolute path of the stdout.log file inside
// runDir. It is the package-level helper the status / logs commands use
// to reach the captured stdout file without re-deriving the layout.
// Mirrors RunJSONPath / GitDiffPath.
func StdoutLogPath(runDir string) string {
	return filepath.Join(runDir, stdoutFileName)
}

// StderrLogPath returns the absolute path of the stderr.log file inside
// runDir. Symmetric to StdoutLogPath.
func StderrLogPath(runDir string) string {
	return filepath.Join(runDir, stderrFileName)
}

// LifecyclePath returns the absolute path of the lifecycle.jsonl file
// inside runDir. The status command tails this file to surface the
// recent lifecycle events alongside run.json's snapshot.
func LifecyclePath(runDir string) string {
	return filepath.Join(runDir, lifecycleFileName)
}

// ReadLifecycleEvents loads every LifecycleEvent recorded in runDir's
// lifecycle.jsonl, in the order they were appended. Each line is one
// JSON object; blank lines (e.g. a trailing newline at EOF) are
// skipped silently so a well-formed log produces a clean slice.
//
// ReadLifecycleEvents returns an empty slice and nil when the file
// exists but is empty (the post-CreateRunDirectory placeholder state)
// or absent. A malformed line returns the events read so far plus the
// parse error so a caller can still surface the partial trail.
//
// The function reads the whole file into memory. lifecycle.jsonl is
// strictly events (state transitions, infrequent), so the file is small
// in practice and the simpler implementation is preferable to a
// streaming parse.
func ReadLifecycleEvents(runDir string) ([]LifecycleEvent, error) {
	if runDir == "" {
		return nil, errors.New("run: ReadLifecycleEvents requires runDir")
	}
	path := LifecyclePath(runDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("run: read lifecycle %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	return parseLifecycleEvents(data, path)
}

// parseLifecycleEvents decodes data as JSONL lifecycle events. Split
// out so ReadLifecycleEvents can stay tiny and so tests can exercise
// the parser against in-memory byte slices.
func parseLifecycleEvents(data []byte, path string) ([]LifecycleEvent, error) {
	out := make([]LifecycleEvent, 0, 16)
	for i, line := range splitJSONLines(data) {
		if len(line) == 0 {
			continue
		}
		var evt LifecycleEvent
		if err := json.Unmarshal(line, &evt); err != nil {
			return out, fmt.Errorf("run: parse %s line %d: %w", path, i+1, err)
		}
		out = append(out, evt)
	}
	return out, nil
}

// splitJSONLines is the trivial \n-splitter the parser uses. We do not
// use bufio.Scanner because lifecycle.jsonl is small enough to read
// whole and we want the line numbers in error messages to be derived
// from the same iteration index as the parse loop, not from a separate
// counter. Trailing newline at EOF produces a final empty line which
// the parser skips.
func splitJSONLines(data []byte) [][]byte {
	return bytes.Split(data, []byte{'\n'})
}
