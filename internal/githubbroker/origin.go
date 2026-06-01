// origin.go implements Batch 4.1 of the leak-coverage hardening plan:
// the GitHub broker's origin parser and pinning machinery. Two concerns
// live here:
//
//  1. ParseOriginRepo turns a raw `git remote get-url origin` value into
//     a (Owner, Name, Host) coordinate. The parser tolerates the three
//     shapes the workspace might emit: HTTPS (`https://github.com/o/n[.git]`),
//     SSH (`git@github.com:o/n[.git]`), and `git://github.com/o/n[.git]`.
//     Anything else (a raw file path, an unrecognised scheme) is rejected
//     with ErrInvalidOrigin so the broker never speaks to an unverified
//     remote.
//
//  2. OriginPin records the (Owner, Name, Host) snapshot the supervisor
//     captured at `ai-env new` into the workspace's `.ai-env/env.yaml`
//     metadata. At PR time the broker re-parses the live origin URL and
//     compares against the pin: any divergence is reported as
//     ErrOriginDrift so an attacker who quietly rewired `origin` after
//     workspace creation cannot redirect the broker's push at a
//     different repository.
//
// The plan calls the rule out in §4 ("GitHub broker rules", locked
// decision row 3) and in Batch 4.1's acceptance:
//
//   - TestBroker_OriginPinMatchesAtPR — happy path: a workspace whose
//     pin matches the live origin proceeds.
//   - TestBroker_OriginDriftBlocks   — drift path: any mismatch in
//     (owner, name, host) blocks with `origin_drift`.
//
// Design rules this file pins:
//
//  1. Pure parser, no I/O. ParseOriginRepo never touches the filesystem
//     or the network; callers that want to read a workspace's live
//     origin pass the URL string in (see ReadOriginRepo / WorkspaceOriginURL
//     below for the filesystem-backed helpers).
//
//  2. Host normalization is conservative. The parser lower-cases the
//     host (DNS names are case-insensitive) but otherwise preserves the
//     bytes verbatim — a custom GHE host like `github.enterprise.local`
//     records as such and pin/check round-trips even when the operator
//     points the workspace at a non-github.com instance.
//
//  3. Pinning lives in a small dedicated YAML file. The plan describes
//     the pin as living in "the workspace's `.ai-env/env.yaml`". The
//     existing per-workspace metadata file (`.env-meta.json`, owned by
//     internal/workspace) intentionally remains the workspace layer's
//     own contract, so the origin pin is written to a sibling file
//     `env.yaml` inside the workspace directory. The two metadata files
//     stay independent: a workspace strategy change does not perturb
//     the pin and a pin re-record does not perturb the worktree
//     metadata.
//
//  4. All error logs flow through RedactTokens. The PR-time check
//     surfaces only the parsed coordinates (already token-free) in its
//     error; the supervisor / CLI is still expected to route any
//     wrapping log line through the broker's RedactTokens helper per
//     plan §4 locked-decision row 3.

package githubbroker

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// OriginPinFilename is the basename of the per-workspace YAML file the
// supervisor writes (at `ai-env new`) and re-reads (at PR time) to
// hold the (Owner, Name, Host) origin snapshot. Exported so callers
// (the CLI's `ai-env new` body, the broker's PR-time check, a future
// `ai-env doctor` repair path) share one constant.
//
// The file lives next to the worktree's `.env-meta.json` so a
// workspace move (worktree → copy via `ai-env new --force`) writes both
// files in one directory and a `rm -rf .ai-env/workspaces/<env>`
// drops both at once.
const OriginPinFilename = "env.yaml"

// OriginPinSchemaVersion is the only schema version this loader
// recognizes. New keys are added by bumping this and teaching the
// loader to accept both shapes; the supervisor refuses to read a
// future-versioned file so an older binary cannot silently mis-interpret
// a newer file.
const OriginPinSchemaVersion = 1

// OriginPin is the (Owner, Name, Host) snapshot the supervisor records
// at `ai-env new` and the broker re-checks at PR time. The struct is
// the in-memory shape; the on-disk YAML representation is the
// originPinFile shape declared in this file (kept private so callers
// cannot construct partially-populated YAML).
//
// All three fields are required for a valid pin. A pin whose Owner,
// Name, or Host is empty is treated as malformed (ErrPinNotFound) so a
// half-written file cannot mask a real drift event.
type OriginPin struct {
	// Owner is the lower-cased GitHub account or organization that owns
	// the repository (the path segment before the slash in
	// "owner/name").
	Owner string

	// Name is the repository's short name (the path segment after the
	// slash in "owner/name"), with the trailing ".git" suffix stripped.
	Name string

	// Host is the lower-cased DNS host the workspace was created
	// against (e.g. "github.com" or a GitHub Enterprise host). It is
	// recorded so a workspace pinned at github.com cannot silently
	// drift to a self-hosted GHE host (or vice versa); the host is
	// part of the identity that BuildBrokerFromSecrets honours when
	// pointing at api.github.com vs. a GHE API base URL.
	Host string
}

// Equal reports whether p and other carry the same (Owner, Name, Host).
// The comparison is exact after normalization (lower-case host /
// owner / name); callers that loaded a pin with LoadOriginPin and an
// origin URL parsed with ParseOriginRepo can compare directly without
// having to re-normalize.
func (p OriginPin) Equal(other OriginPin) bool {
	return p.Owner == other.Owner && p.Name == other.Name && p.Host == other.Host
}

// String renders the pin in a stable "host/owner/name" form for log
// lines. The order is host-first so a log scan can group multiple
// runs by GHE instance without parsing.
func (p OriginPin) String() string {
	return fmt.Sprintf("%s/%s/%s", p.Host, p.Owner, p.Name)
}

// originPinFile is the on-disk YAML representation. Kept private so a
// caller cannot construct a partial YAML and skip the validation in
// LoadOriginPin / RecordOriginPin.
type originPinFile struct {
	Version   int             `yaml:"version"`
	OriginPin originPinFields `yaml:"origin_pin"`
}

type originPinFields struct {
	Owner string `yaml:"owner"`
	Name  string `yaml:"name"`
	Host  string `yaml:"host"`
}

// Sentinel errors the parser and pin machinery return. Callers
// (`ai-env new`, the broker's PR-time check, the CLI's error renderer)
// pattern-match these with errors.Is to decide whether to render
// "drift" vs "no pin recorded" vs "malformed URL" hints.
var (
	// ErrInvalidOrigin is returned by ParseOriginRepo when the supplied
	// URL does not match any of the recognized shapes (HTTPS, SSH,
	// git://) or when the path does not have the "owner/name" shape.
	// The CLI surfaces it as "GitHub origin URL is unrecognized".
	ErrInvalidOrigin = errors.New("githubbroker: origin URL is not a recognized GitHub remote shape")

	// ErrOriginDrift is returned by CheckOriginPin when the live origin
	// no longer matches the pin recorded at `ai-env new`. The CLI
	// surfaces it as "GitHub origin pinned at <pin> drifted to <live>"
	// and refuses to push. The reason token "origin_drift" is reserved
	// in run/lifecycle_verbs.go (LifecycleVerbBrokerUnavailable) so
	// supervisor emission stays consistent.
	ErrOriginDrift = errors.New("githubbroker: GitHub origin drift detected (origin_drift)")

	// ErrPinNotFound is returned by LoadOriginPin when the per-workspace
	// `env.yaml` file does not exist or carries no valid origin_pin
	// block. The CLI treats it as "this workspace was created before
	// pinning was added; refuse PR until re-pinned" — the secure
	// default. A doctor / repair path may invoke RecordOriginPin to
	// fix it.
	ErrPinNotFound = errors.New("githubbroker: no origin pin recorded for this workspace")
)

// canonicalGitHubHost is the lower-cased DNS name for the public
// GitHub instance. The parser normalises any case variant ("GitHub.COM",
// "github.com") to this string so the pin compares stably across
// re-parses.
const canonicalGitHubHost = "github.com"

// ParseOriginRepo turns a raw git remote URL into an OriginPin. The
// three accepted shapes:
//
//   - HTTPS: `https://<host>/<owner>/<name>[.git]`
//   - git://: `git://<host>/<owner>/<name>[.git]`
//   - SSH:   `git@<host>:<owner>/<name>[.git]`
//   - ssh:// `ssh://git@<host>[:<port>]/<owner>/<name>[.git]`
//
// Trailing ".git", trailing slashes, and any userinfo other than "git"
// for SSH are accepted; an https URL with embedded credentials
// (`https://user:pass@host/...`) is also accepted and the credentials
// are dropped on the way through — the pin only carries the host,
// owner, and name. Any other shape is rejected with ErrInvalidOrigin.
//
// The function is pure: no I/O, no time-of-day reads, no goroutine
// state. The returned OriginPin has all fields lower-cased and with
// the ".git" suffix stripped from Name.
func ParseOriginRepo(originURL string) (OriginPin, error) {
	raw := strings.TrimSpace(originURL)
	if raw == "" {
		return OriginPin{}, fmt.Errorf("%w: empty URL", ErrInvalidOrigin)
	}

	host, path, err := splitHostAndPath(raw)
	if err != nil {
		return OriginPin{}, err
	}

	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return OriginPin{}, fmt.Errorf("%w: empty host in %q", ErrInvalidOrigin, originURL)
	}

	// The path must carry exactly two non-empty segments: owner and
	// name. Reject anything else (a single segment like "owner" or a
	// nested path like "owner/group/repo") so the broker cannot be
	// pointed at a path-shaped URL that GitHub's API would reject only
	// at request time.
	path = strings.Trim(path, "/")
	segments := strings.Split(path, "/")
	if len(segments) != 2 {
		return OriginPin{}, fmt.Errorf("%w: expected owner/name path, got %q", ErrInvalidOrigin, path)
	}
	owner := strings.TrimSpace(segments[0])
	name := strings.TrimSuffix(strings.TrimSpace(segments[1]), ".git")
	if owner == "" || name == "" {
		return OriginPin{}, fmt.Errorf("%w: owner or name empty in %q", ErrInvalidOrigin, originURL)
	}
	// Reject path segments that look like a control char or carry a
	// path-separator escape: the broker is going to embed these into a
	// URL and we want any odd shape to surface here rather than at the
	// HTTP layer.
	if strings.ContainsAny(owner, " \t\n\r/\\") || strings.ContainsAny(name, " \t\n\r/\\") {
		return OriginPin{}, fmt.Errorf("%w: owner or name contains whitespace or separators in %q", ErrInvalidOrigin, originURL)
	}

	return OriginPin{
		Owner: strings.ToLower(owner),
		Name:  strings.ToLower(name),
		Host:  host,
	}, nil
}

// splitHostAndPath dispatches on URL shape and returns the host and
// path components. The function recognizes HTTPS, git://, ssh://, and
// the SCP-style "git@host:owner/name" SSH shape. Anything else returns
// ErrInvalidOrigin.
//
// The function is intentionally narrow: it does not validate the path
// shape (the caller does that on the returned `path` string). Keeping
// the dispatch isolated here makes it easy to add a new scheme later
// (e.g. https+git or a sourcehut-shaped URL) without churning the
// owner/name extraction.
func splitHostAndPath(raw string) (string, string, error) {
	switch {
	case strings.HasPrefix(raw, "https://"):
		return splitURL(raw[len("https://"):])
	case strings.HasPrefix(raw, "http://"):
		// `git remote get-url` can return an http URL for a local
		// mirror or a private network. We accept it and let the pin
		// record the host verbatim; the broker's higher-level checks
		// (api_base_url in BuildBrokerFromSecrets) decide whether to
		// actually speak http.
		return splitURL(raw[len("http://"):])
	case strings.HasPrefix(raw, "git://"):
		return splitURL(raw[len("git://"):])
	case strings.HasPrefix(raw, "ssh://"):
		// ssh://[user@]host[:port]/owner/name[.git]
		body := raw[len("ssh://"):]
		if i := strings.Index(body, "@"); i >= 0 {
			// Drop the userinfo; the pin only records the host.
			body = body[i+1:]
		}
		return splitURL(body)
	case strings.HasPrefix(raw, "git@"):
		// SCP-style: git@host:owner/name[.git]
		body := raw[len("git@"):]
		i := strings.Index(body, ":")
		if i < 0 {
			return "", "", fmt.Errorf("%w: expected `:` separator in SSH URL %q", ErrInvalidOrigin, raw)
		}
		host := body[:i]
		path := body[i+1:]
		return host, path, nil
	default:
		return "", "", fmt.Errorf("%w: unrecognized scheme in %q", ErrInvalidOrigin, raw)
	}
}

// splitURL chops `host[:port]/path` into (host, path). The port (if
// present) is dropped from the host because the pin compares on the
// canonical DNS name, not the listening port. Any embedded userinfo
// before the host has already been stripped by the caller.
func splitURL(body string) (string, string, error) {
	// Strip an embedded userinfo segment for the http(s) case where the
	// caller passed splitURL the substring after "https://". A "@" in
	// the body that precedes the first "/" is a userinfo separator
	// (e.g. https://user:pass@host/owner/name → we drop "user:pass@").
	if at := strings.Index(body, "@"); at >= 0 {
		if slash := strings.Index(body, "/"); slash < 0 || at < slash {
			body = body[at+1:]
		}
	}
	slash := strings.Index(body, "/")
	if slash < 0 {
		return "", "", fmt.Errorf("%w: no path component in %q", ErrInvalidOrigin, body)
	}
	hostport := body[:slash]
	path := body[slash:]
	// Drop port (`host:port` → `host`). A pinned port would force
	// drift on a routine port change; the pin already covers the
	// repository identity, not the network reachability path.
	if colon := strings.Index(hostport, ":"); colon >= 0 {
		hostport = hostport[:colon]
	}
	return hostport, path, nil
}

// ToRepo converts the pin to a broker Repo coordinate. The CloneURL is
// reconstructed from (host, owner, name) so a caller (BuildBrokerFromSecrets,
// the CLI's repo-resolution path) gets a usable Repo without re-parsing
// the original URL. The DefaultBranch field is left empty; the caller
// fills it from policy.yaml or repository defaults.
//
// CloneURL is always rendered as an HTTPS URL ("https://<host>/<owner>/<name>.git").
// This matches the broker's "credentials in the URL via token-substitution"
// rule (see auth.go): the broker is going to embed the BrokerToken at
// push time, and an SSH URL would force the broker to also wire an SSH
// agent. HTTPS keeps the surface narrow.
func (p OriginPin) ToRepo() Repo {
	return Repo{
		Owner:    p.Owner,
		Name:     p.Name,
		CloneURL: fmt.Sprintf("https://%s/%s/%s.git", p.Host, p.Owner, p.Name),
	}
}

// IsCanonicalGitHub reports whether the pin's host is the public
// github.com instance. The CLI uses it to decide whether to default
// the broker's APIBaseURL to https://api.github.com (the empty default
// in GitHubAppConfig) or whether the operator must supply a GHE base URL.
func (p OriginPin) IsCanonicalGitHub() bool {
	return p.Host == canonicalGitHubHost
}

// RecordOriginPin writes pin to <workspaceDir>/<OriginPinFilename> in
// the YAML shape LoadOriginPin reads. The file is written atomically
// (write to <name>.tmp + rename) so a crash mid-write cannot leave a
// half-formed pin that masks a real drift event.
//
// File mode is 0644: the pin is not a secret (it carries only host,
// owner, name) and a normal user reading a workspace's status command
// should be able to see it.
//
// workspaceDir must be an absolute path to the workspace directory
// (the same path workspace.WorkspacePath returns). pin must be a
// non-zero OriginPin: every field must be non-empty. RecordOriginPin
// validates the pin and returns an error rather than writing a
// malformed file.
func RecordOriginPin(workspaceDir string, pin OriginPin) error {
	if strings.TrimSpace(workspaceDir) == "" {
		return errors.New("githubbroker: RecordOriginPin requires workspaceDir")
	}
	if pin.Owner == "" || pin.Name == "" || pin.Host == "" {
		return fmt.Errorf("%w: pin owner/name/host must be non-empty (got %+v)", ErrPinNotFound, pin)
	}

	file := originPinFile{
		Version: OriginPinSchemaVersion,
		OriginPin: originPinFields{
			Owner: pin.Owner,
			Name:  pin.Name,
			Host:  pin.Host,
		},
	}
	data, err := yaml.Marshal(file)
	if err != nil {
		return fmt.Errorf("githubbroker: marshal origin pin: %w", err)
	}

	path := filepath.Join(workspaceDir, OriginPinFilename)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("githubbroker: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		// Best-effort cleanup of the temp file so a botched rename does
		// not leave a stale file the next attempt has to discover.
		_ = os.Remove(tmp)
		return fmt.Errorf("githubbroker: rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

// LoadOriginPin reads <workspaceDir>/<OriginPinFilename> and returns
// the parsed pin. Returns ErrPinNotFound when the file does not exist
// or carries no valid origin_pin block; a malformed YAML or unsupported
// schema version returns a hard error so a corrupt file cannot be
// silently treated as "no pin".
//
// The function is read-only: it does not chmod, repair, or migrate the
// file. A doctor / repair path that wants to rewrite a stale pin calls
// RecordOriginPin directly.
func LoadOriginPin(workspaceDir string) (OriginPin, error) {
	if strings.TrimSpace(workspaceDir) == "" {
		return OriginPin{}, errors.New("githubbroker: LoadOriginPin requires workspaceDir")
	}
	path := filepath.Join(workspaceDir, OriginPinFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return OriginPin{}, fmt.Errorf("%w: %s does not exist", ErrPinNotFound, path)
		}
		return OriginPin{}, fmt.Errorf("githubbroker: read %s: %w", path, err)
	}

	var file originPinFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return OriginPin{}, fmt.Errorf("githubbroker: parse %s: %w", path, err)
	}
	if file.Version != OriginPinSchemaVersion {
		return OriginPin{}, fmt.Errorf("githubbroker: %s carries unsupported schema version %d (expected %d)", path, file.Version, OriginPinSchemaVersion)
	}
	pin := OriginPin{
		Owner: strings.ToLower(strings.TrimSpace(file.OriginPin.Owner)),
		Name:  strings.ToLower(strings.TrimSpace(file.OriginPin.Name)),
		Host:  strings.ToLower(strings.TrimSpace(file.OriginPin.Host)),
	}
	if pin.Owner == "" || pin.Name == "" || pin.Host == "" {
		return OriginPin{}, fmt.Errorf("%w: %s carries an incomplete origin_pin (got %+v)", ErrPinNotFound, path, pin)
	}
	return pin, nil
}

// CheckOriginPin re-parses the live origin URL and compares it against
// the pin previously recorded for workspaceDir. The function is the
// load-bearing call site for the plan's "origin_drift" guard: any
// mismatch in (owner, name, host) returns ErrOriginDrift wrapped with
// a short pin-vs-live summary.
//
// Returns:
//   - (pin, nil) on a match. The returned pin is the recorded one
//     (the live one was equal by definition) so callers that need
//     to thread the canonical coordinates downstream can use the
//     return value without re-loading.
//   - (zero, ErrPinNotFound) when the workspace has no recorded pin.
//   - (zero, ErrInvalidOrigin) when liveOriginURL fails to parse.
//   - (zero, ErrOriginDrift) on (owner|name|host) mismatch.
//
// Callers that have already loaded the pin (e.g. the supervisor's
// LifecycleVerbBrokerStarted hook) can skip the LoadOriginPin call by
// invoking compareOriginPin directly; this entry point exists for the
// CLI's single-call PR-time use.
func CheckOriginPin(workspaceDir, liveOriginURL string) (OriginPin, error) {
	pin, err := LoadOriginPin(workspaceDir)
	if err != nil {
		return OriginPin{}, err
	}
	live, err := ParseOriginRepo(liveOriginURL)
	if err != nil {
		return OriginPin{}, err
	}
	if !pin.Equal(live) {
		return OriginPin{}, fmt.Errorf("%w: pinned %s, live %s", ErrOriginDrift, pin, live)
	}
	return pin, nil
}

// WorkspaceOriginURL reads the `origin` remote URL from the git
// repository rooted at workspaceDir. The function shells out to `git
// remote get-url origin` so it picks up whatever URL the workspace's
// own git config carries (including a recently-rewritten one — which
// is exactly the drift CheckOriginPin is meant to catch).
//
// Returns an empty string and a nil error when the workspace is not a
// git repository (the `git` invocation reports "fatal: not a git
// repository"); callers that need to differentiate "no remote
// configured" from "not a git repo" inspect the returned URL: empty +
// nil error means "no origin available; skip the pin check for this
// workspace". A genuine I/O failure (git not in PATH, command killed)
// returns the underlying error.
//
// The function does NOT read .ai-env/workspaces/<env>/.env-meta.json
// for the workspace's SourcePath: the pin's whole purpose is to catch
// drift relative to the workspace's own remote (the path the broker
// will push to). Reading the source repo's origin would defeat the
// guard if an attacker rewired the workspace's origin to point at a
// different repo than the source.
func WorkspaceOriginURL(workspaceDir string) (string, error) {
	if strings.TrimSpace(workspaceDir) == "" {
		return "", errors.New("githubbroker: WorkspaceOriginURL requires workspaceDir")
	}
	cmd := exec.Command("git", "remote", "get-url", "origin")
	cmd.Dir = workspaceDir
	out, err := cmd.Output()
	if err != nil {
		// "not a git repo" and "no such remote" both surface as a
		// non-zero exit; treat them uniformly as "no origin available".
		// A genuine ENOENT for git itself is the only failure we
		// re-raise; we detect it by checking exec.Error.
		var execErr *exec.Error
		if errors.As(err, &execErr) {
			return "", fmt.Errorf("githubbroker: run git: %w", err)
		}
		return "", nil
	}
	return strings.TrimSpace(string(out)), nil
}
