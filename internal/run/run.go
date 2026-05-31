// Package run implements the per-run on-disk layout, the run ID format, and
// the scaffolding that later supervisor stages (state machine, lifecycle
// writer, stdout/stderr capture) build on top of.
//
// A "run" is one invocation of an agent against a workspace. Every run owns
// its own directory under .ai-env/runs/<run-id>/. That directory holds the
// task description, the lifecycle log, the captured stdout/stderr, the final
// run.json record, and the various event streams (shell commands, filesystem
// events, network events, policy decisions) that other plan phases will fill
// in. Centralizing the layout here keeps every later piece in agreement
// about where each artifact belongs.
//
// This file is the public surface for batch 0 of plan 03: a run ID generator,
// a RunDirectory creator that materializes the full file/subdir layout, and a
// task.md writer that captures the --task flag content for posterity. Later
// batches add the state machine, the lifecycle and run.json writers, and the
// supervisor main loop.
package run

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// runsSubdir is the directory under the host's .ai-env/ where every run
// directory lives. Centralizing this string keeps the run ID generator, the
// run directory creator, and later commands (status, logs) in agreement
// about the on-disk layout. It mirrors workspace.workspaceSubdir's role for
// the workspaces tree.
const runsSubdir = "runs"

// runIDTimeLayout is the timestamp portion of a run ID, "YYYYMMDD-HHMMSS"
// in the supplied clock's time zone. It is declared as a Go reference time
// (Mon Jan 2 15:04:05 MST 2006) so callers can format with time.Format
// without re-deriving the layout. The master plan picks a sortable,
// punctuation-light format because run IDs serve as directory basenames
// and have to be safe across every filesystem we support.
const runIDTimeLayout = "20060102-150405"

// runIDRandomBytes is the number of random bytes appended to the run ID
// after the timestamp. The plan asks for "6+ random hex chars"; six hex
// chars is three bytes. Three bytes gives ~16M distinct suffixes per
// second, which is well above the collision risk for human-paced runs
// while staying short enough that the run ID is still easy to type and
// recognize in a `ls` listing.
const runIDRandomBytes = 3

// runDirMode is the permission mode used for intermediate parent
// directories (e.g. .ai-env/runs/) and the scan-results subdirectory
// inside a run. 0o755 matches the project's "user writes, group/others
// read" convention for the broader workspace tree.
//
// The run directory itself (.ai-env/runs/<run-id>/) is created with this
// permission and then tightened to runDirModeStrict (0o700) at the end of
// CreateRunDirectory per Plan §0.2: the run directory holds the per-run
// control socket, MCP server tokens, and proxy credentials, so even
// "world readable" by the host user's group is too permissive. The
// stricter mode lands after every per-run file has been materialized
// so a partially populated tree still cleans up correctly if the
// chmod itself fails.
const runDirMode os.FileMode = 0o755

// runDirModeStrict is the permission mode applied to the run directory
// itself at the end of CreateRunDirectory. 0o700 keeps the per-run
// control socket, MCP server-token registry, and provider proxy logs
// inaccessible to any other host user. Plan §0.2 calls this out
// explicitly: "CreateRunDirectory ends with chmod runDir 0700".
const runDirModeStrict os.FileMode = 0o700

// runFileMode is the permission mode used for every file the run
// scaffolding creates (task.md and the empty stream/log placeholders).
// 0o644 matches the project convention; like runDirMode, it leans on the
// host's umask rather than imposing a stricter mode of its own.
const runFileMode os.FileMode = 0o644

// taskFileName is the basename of the file that captures the --task flag's
// content. It lives at the root of the run directory so it is the first
// artifact a reviewer sees when looking at a run on disk.
const taskFileName = "task.md"

// runFileNames lists every regular file the RunDirectory creator
// materializes at the root of a run directory. The slice is the single
// source of truth for the run directory layout's file portion; later
// writers (lifecycle.jsonl, run.json, the stdout/stderr stream writers,
// the event stream writers) append to whichever file matches their
// concern. Order is preserved when iterating so the creator's behavior is
// deterministic.
//
// task.md is created up front but is left empty here; the WriteTask
// helper (or its caller) fills it in. Every other file is created as an
// empty placeholder so callers can rely on the path existing before they
// open it for append, which keeps stream-writer code in later batches
// from having to do its own first-write-creates dance.
var runFileNames = []string{
	taskFileName,
	"run.json",
	"agent-command.txt",
	"transcript.md",
	"stdout.log",
	"stderr.log",
	"lifecycle.jsonl",
	"shell-commands.jsonl",
	"filesystem-events.jsonl",
	"network-events.jsonl",
	"policy-decisions.jsonl",
	"mcp-calls.jsonl",
	"leaks.jsonl",
	"transcript.jsonl",
	"git-diff.patch",
	"secret-scan.json",
	"dependency-report.json",
	"security-report.md",
	"final-summary.md",
}

// runSubdirNames lists every subdirectory the RunDirectory creator
// materializes inside a run directory. Today there is only one
// (scan-results/), but the slice keeps the creator symmetric with
// runFileNames so future plan phases that add subdirs (e.g. an
// attachments/ tree for downloaded artifacts) extend a single list rather
// than threading new MkdirAll calls through the creator.
var runSubdirNames = []string{
	"scan-results",
}

// RunsRoot returns the absolute path of the directory that holds every
// run directory for the host. aiEnvDir is the host's .ai-env/ directory;
// the caller is responsible for resolving it. This helper is the run
// analog of workspace.WorkspacePath: the rest of the codebase asks
// RunsRoot rather than re-deriving the "runs" segment on its own.
func RunsRoot(aiEnvDir string) string {
	return filepath.Join(aiEnvDir, runsSubdir)
}

// RunPath returns the absolute path of the run directory for runID under
// aiEnvDir. Like RunsRoot, it is the single place the "<aiEnvDir>/runs/
// <run-id>" layout is encoded so the creator, the task writer, and later
// readers (status, logs) cannot drift.
func RunPath(aiEnvDir, runID string) string {
	return filepath.Join(RunsRoot(aiEnvDir), runID)
}

// TaskPath returns the absolute path of the task.md file inside the run
// directory for runID under aiEnvDir. WriteTask uses it internally; it is
// also exported so later batches (status, replay, final-summary
// rendering) can reach the file without duplicating the join.
func TaskPath(aiEnvDir, runID string) string {
	return filepath.Join(RunPath(aiEnvDir, runID), taskFileName)
}

// clock is the small abstraction the run ID generator and the directory
// creator share so tests can pin both the timestamp portion of the run
// ID and the directory's recorded creation time without monkey-patching
// time.Now. It is intentionally just "give me a time"; nothing in this
// package needs sleep or after.
type clock interface {
	Now() time.Time
}

// systemClock is the production clock. It delegates straight to time.Now
// so the run ID's timestamp matches the host's wall clock in the local
// time zone (mirroring the master plan's example "20260528-101300-...").
type systemClock struct{}

// Now returns the current local time. Production callers reach this via
// SystemClock; tests use a fixed-time clock to make the run ID stable.
func (systemClock) Now() time.Time { return time.Now() }

// SystemClock is the singleton production clock. Callers that build a
// RunIDGenerator or a RunDirectory by hand pass this; the convenience
// constructors below use it implicitly.
var SystemClock clock = systemClock{}

// randomReader is the source of randomness for the run ID suffix. It is
// a package variable (not a hardcoded crypto/rand.Reader) so tests can
// substitute a deterministic byte source without touching the public
// API. Production callers leave it alone; it points at crypto/rand by
// default, which is sufficient for collision avoidance within the same
// second on a single host.
var randomReader io.Reader = rand.Reader

// RunIDGenerator produces run IDs of the format
// "YYYYMMDD-HHMMSS-<hex>". It is a struct (rather than a free function)
// so the clock and random source can be wired in once and reused, which
// keeps test setup small and matches the dependency-injection style the
// workspace package uses for time.Now.
type RunIDGenerator struct {
	// Clock supplies the timestamp portion of the run ID. Defaults to
	// SystemClock when zero.
	Clock clock

	// Random is the byte source for the hex suffix. Defaults to
	// crypto/rand.Reader when nil. Three bytes are read per call.
	Random io.Reader
}

// NewRunIDGenerator returns a generator wired to the production clock
// and crypto/rand. It is the path most production callers take; tests
// build a RunIDGenerator literal with their own clock and reader.
func NewRunIDGenerator() *RunIDGenerator {
	return &RunIDGenerator{Clock: SystemClock, Random: randomReader}
}

// Generate returns a fresh run ID of the form
// "YYYYMMDD-HHMMSS-<6-hex>". It reads three random bytes from the
// generator's Random source and formats them as six lowercase hex
// characters; that is enough entropy that two runs started in the same
// second on the same host collide with probability ~2^-24, well below
// the threshold the plan tolerates (two same-second runs must be
// distinguishable, see acceptance criterion 2).
//
// Generate returns an error only when the random source fails. The
// timestamp portion never fails: time.Format on any time value cannot
// fail, and a zero-value Clock falls back to SystemClock.
func (g *RunIDGenerator) Generate() (string, error) {
	c := g.Clock
	if c == nil {
		c = SystemClock
	}
	r := g.Random
	if r == nil {
		r = randomReader
	}

	suffix := make([]byte, runIDRandomBytes)
	if _, err := io.ReadFull(r, suffix); err != nil {
		return "", fmt.Errorf("run: read random run ID suffix: %w", err)
	}
	return c.Now().Format(runIDTimeLayout) + "-" + hex.EncodeToString(suffix), nil
}

// GenerateRunID is the convenience wrapper most production call sites
// use: a single call that constructs a generator with the production
// clock and random source, generates one ID, and returns it. Callers
// that need a custom clock or reader (tests, future replay tooling) build
// a RunIDGenerator literal directly.
func GenerateRunID() (string, error) {
	return NewRunIDGenerator().Generate()
}

// RunDirectory is the value type RunDirectory.Create returns. It records
// the run ID, the absolute path of the run directory, and the moment
// Create stamped the directory. Later batches (lifecycle writer, run.json
// writer, status/logs commands) read fields off this struct rather than
// recomputing paths.
type RunDirectory struct {
	// ID is the run ID this directory was created for. It is also the
	// directory's basename under aiEnvDir/runs/.
	ID string

	// Path is the absolute path to the run directory itself
	// (.ai-env/runs/<run-id>/). All files and subdirs listed in
	// runFileNames and runSubdirNames live underneath it.
	Path string

	// CreatedAt is when the directory was materialized, in the clock's
	// time zone. Later batches persist this to run.json as the run's
	// started_at; here it is recorded so a caller that wants to write a
	// lifecycle "created" event can pull it off the struct without
	// asking the clock again.
	CreatedAt time.Time
}

// TaskPath returns the absolute path of this run's task.md file. It is
// the per-instance counterpart to the package-level TaskPath helper; the
// two return the same string. Callers that already hold a RunDirectory
// use this to avoid re-passing the aiEnvDir/runID pair.
func (r RunDirectory) TaskPath() string {
	return filepath.Join(r.Path, taskFileName)
}

// CreateRunDirectory materializes the on-disk run directory for runID
// under aiEnvDir. It performs the actions plan 03 step 2 requires:
//
//  1. Create .ai-env/runs/<run-id>/ with mode 0o755.
//  2. Create every subdirectory listed in runSubdirNames (scan-results/
//     today).
//  3. Create every regular file listed in runFileNames as an empty
//     placeholder with mode 0o644 so later stream writers can open them
//     for append without worrying about first-write creation.
//
// Inputs:
//   - aiEnvDir is the absolute path to the host's .ai-env/ directory.
//     The run directory lands under aiEnvDir/runs/<run-id>/. The caller
//     resolves this path; CreateRunDirectory does not assume the process
//     working directory.
//   - runID is the run identifier. It is used as the directory basename
//     and recorded back in the returned RunDirectory. Callers that have
//     just generated an ID with RunIDGenerator pass it through.
//   - now supplies the timestamp recorded as CreatedAt. Pass time.Now in
//     production; tests pass a fixed time so the returned struct is
//     deterministic. It is taken as a value (not a clock) so the call
//     site stays explicit about which time is persisted, mirroring the
//     workspace.CreateWorktree style.
//
// On success CreateRunDirectory returns a fully populated RunDirectory.
// On failure it makes a best-effort attempt to roll back partial state:
// the partially populated run directory tree is removed so a retry
// starts from a clean slate.
func CreateRunDirectory(aiEnvDir, runID string, now time.Time) (RunDirectory, error) {
	if aiEnvDir == "" {
		return RunDirectory{}, errors.New("run: CreateRunDirectory requires aiEnvDir")
	}
	if runID == "" {
		return RunDirectory{}, errors.New("run: CreateRunDirectory requires runID")
	}

	runDir := RunPath(aiEnvDir, runID)

	// Refuse to clobber an existing run directory. A duplicate ID should
	// be impossible under the generator's collision odds, but if it ever
	// happens we prefer a loud failure to silently merging state from a
	// previous run. This mirrors workspace.CreateWorktree's stance on
	// pre-existing workspace paths.
	if _, err := os.Stat(runDir); err == nil {
		return RunDirectory{}, fmt.Errorf("run: run directory %s already exists", runDir)
	} else if !os.IsNotExist(err) {
		return RunDirectory{}, fmt.Errorf("run: stat %s: %w", runDir, err)
	}

	// MkdirAll creates intermediate parents (.ai-env/runs/) as well as
	// the run directory itself. Using MkdirAll on the leaf rather than a
	// separate parent-then-leaf pair keeps the happy path a single
	// syscall and is the same pattern the workspace package uses.
	if err := os.MkdirAll(runDir, runDirMode); err != nil {
		return RunDirectory{}, fmt.Errorf("run: create run directory %s: %w", runDir, err)
	}

	// From this point on, any failure rolls the whole run directory
	// back. A partially populated run directory would confuse later
	// reads (e.g. a stream writer opening lifecycle.jsonl might find it
	// missing and crash); cleaning up keeps the on-disk state binary
	// (either fully present or fully absent).
	cleanup := func() {
		_ = os.RemoveAll(runDir)
	}

	for _, name := range runSubdirNames {
		sub := filepath.Join(runDir, name)
		if err := os.MkdirAll(sub, runDirMode); err != nil {
			cleanup()
			return RunDirectory{}, fmt.Errorf("run: create subdir %s: %w", sub, err)
		}
	}

	for _, name := range runFileNames {
		path := filepath.Join(runDir, name)
		if err := createEmptyFile(path, runFileMode); err != nil {
			cleanup()
			return RunDirectory{}, fmt.Errorf("run: create %s: %w", path, err)
		}
	}

	// Plan §0.2: tighten the run directory itself to 0o700 after
	// every per-run placeholder lands. The run dir holds the
	// per-run control socket, MCP server-token registry, and
	// provider proxy logs; even "world readable" via the host
	// user's group is too permissive. We do this last so a
	// partially populated tree (which the cleanup() defer above
	// removes on every earlier error path) cannot leak through a
	// failed Chmod: if Chmod itself fails the tree is rolled back
	// too. The umask-resistance argument matches createEmptyFile's
	// trailing Chmod.
	if err := os.Chmod(runDir, runDirModeStrict); err != nil {
		cleanup()
		return RunDirectory{}, fmt.Errorf("run: tighten run dir %s to 0o700: %w", runDir, err)
	}

	return RunDirectory{
		ID:        runID,
		Path:      runDir,
		CreatedAt: now,
	}, nil
}

// createEmptyFile creates path as an empty file with the given mode. It
// uses O_CREATE|O_EXCL so a stale file from a previous botched run is
// reported rather than silently truncated; CreateRunDirectory already
// rejected the case where the run directory existed up front, so the
// only way a file inside it can pre-exist is a bug.
//
// We use OpenFile+Close rather than os.WriteFile([]byte{}) because the
// latter would silently truncate an existing file, defeating the
// O_EXCL guard. The explicit Chmod after close ensures the mode lands
// even when the host umask would otherwise widen or narrow it.
func createEmptyFile(path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
