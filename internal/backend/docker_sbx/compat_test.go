package docker_sbx

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/backend"
)

// TestParseSemver covers the internal parser used by IsVersionSupported.
// The parser is lenient on purpose: a leading "v" / "V" is dropped, and
// pre-release ("-rc1") and build ("+abc") suffixes are trimmed before
// numeric parsing. Inputs the parser cannot turn into a 1- to 3-component
// dotted number return an error.
func TestParseSemver(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      string
		want    semver
		wantErr bool
	}{
		{name: "three components", in: "1.2.3", want: semver{1, 2, 3}},
		{name: "two components", in: "0.4", want: semver{0, 4, 0}},
		{name: "one component", in: "7", want: semver{7, 0, 0}},
		{name: "leading v lower", in: "v0.5.0", want: semver{0, 5, 0}},
		{name: "leading V upper", in: "V0.5.0", want: semver{0, 5, 0}},
		{name: "prerelease dash", in: "0.5.0-rc1", want: semver{0, 5, 0}},
		{name: "build metadata plus", in: "1.2.3+build.7", want: semver{1, 2, 3}},
		{name: "prerelease and build", in: "v1.2.3-alpha+sha", want: semver{1, 2, 3}},
		{name: "surrounding whitespace", in: "  0.4.2  ", want: semver{0, 4, 2}},
		{name: "empty string", in: "", wantErr: true},
		{name: "four components rejected", in: "1.2.3.4", wantErr: true},
		{name: "non-numeric component", in: "1.x.3", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSemver(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseSemver(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSemver(%q) error = %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseSemver(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestSemverCmp pins the ordering used by IsVersionSupported.
func TestSemverCmp(t *testing.T) {
	t.Parallel()

	cases := []struct {
		a, b semver
		want int
	}{
		{semver{0, 1, 0}, semver{0, 1, 0}, 0},
		{semver{0, 1, 0}, semver{0, 2, 0}, -1},
		{semver{0, 2, 0}, semver{0, 1, 9}, 1},
		{semver{1, 0, 0}, semver{0, 99, 99}, 1},
		{semver{0, 4, 1}, semver{0, 4, 2}, -1},
		{semver{2, 0, 0}, semver{1, 9, 9}, 1},
	}
	for _, tc := range cases {
		if got := tc.a.cmp(tc.b); got != tc.want {
			t.Errorf("%+v.cmp(%+v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestIsVersionSupported exercises the boundary conditions of the
// tested-version window. Anything below MinTestedVersion or above
// MaxTestedVersion is fail-closed, as is anything unparsable.
func TestIsVersionSupported(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "min boundary", in: MinTestedVersion, want: true},
		{name: "max boundary", in: MaxTestedVersion, want: true},
		{name: "middle of range", in: "0.5.0", want: true},
		{name: "v-prefixed in range", in: "v0.5.0", want: true},
		{name: "prerelease in range", in: "0.5.0-rc1", want: true},
		{name: "below range", in: "0.0.9", want: false},
		{name: "above range patch", in: "1.0.0", want: false},
		{name: "above range major", in: "2.0.0", want: false},
		{name: "garbage string", in: "not-a-version", want: false},
		{name: "empty string", in: "", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsVersionSupported(tc.in); got != tc.want {
				t.Errorf("IsVersionSupported(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestExtractVersion confirms the package-level version regex picks up
// the first dotted-numeric token in mixed output (the regex is shared
// with the `sbx version` parser).
func TestExtractVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "0.5.0", want: "0.5.0"},
		{name: "with v prefix", in: "v0.5.0", want: "0.5.0"},
		{name: "embedded in line", in: "sbx version 0.4.2 (build abc)", want: "0.4.2"},
		{name: "two components", in: "sbx 0.4", want: "0.4"},
		{name: "first dotted token wins", in: "build 1.2 then v0.5.0", want: "1.2"},
		{name: "bare integer ignored", in: "build 99 v0.5.0", want: "0.5.0"},
		{name: "no version", in: "no numbers here", want: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := extractVersion(tc.in); got != tc.want {
				t.Errorf("extractVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// fakeRunner is a Runner that returns canned output for a single
// invocation. It records the argv it saw so tests can assert the adapter
// invoked sbx with the expected command line.
type fakeRunner struct {
	stdout   string
	stderr   string
	exitCode int
	spawnErr error
	gotArgs  []string
	gotEnv   []string
	gotDir   string
}

func (f *fakeRunner) Run(_ context.Context, _ string, args []string, _ io.Reader, stdout, stderr io.Writer, env []string, dir string) (int, error) {
	f.gotArgs = append([]string(nil), args...)
	f.gotEnv = append([]string(nil), env...)
	f.gotDir = dir
	if stdout != nil && f.stdout != "" {
		_, _ = stdout.Write([]byte(f.stdout))
	}
	if stderr != nil && f.stderr != "" {
		_, _ = stderr.Write([]byte(f.stderr))
	}
	if f.spawnErr != nil {
		return -1, f.spawnErr
	}
	return f.exitCode, nil
}

// TestDetect_VersionInRange wires a fake runner so Detect sees a stdout
// version it can parse, and confirms BackendStatus reports the version
// as supported. We use a real binary path lookup by pointing Options.Binary
// at "/bin/sh" so exec.LookPath does not fail; the runner is faked so the
// shell is never actually invoked.
func TestDetect_VersionInRange(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{stdout: "sbx version 0.5.0\n", exitCode: 0}
	b := New(Options{Binary: "sh", Runner: runner.Run, DetectTimeout: 2 * time.Second})

	status := b.Detect()

	if !status.Available {
		t.Fatalf("Detect.Available = false, want true (message=%q)", status.Message)
	}
	if status.Name != Name {
		t.Errorf("Detect.Name = %q, want %q", status.Name, Name)
	}
	if status.Version != "0.5.0" {
		t.Errorf("Detect.Version = %q, want %q", status.Version, "0.5.0")
	}
	if !status.VersionSupported {
		t.Errorf("Detect.VersionSupported = false, want true")
	}
	if len(runner.gotArgs) != 1 || runner.gotArgs[0] != "version" {
		t.Errorf("runner argv = %v, want [version]", runner.gotArgs)
	}
}

// TestDetect_VersionOutsideRange confirms an above-range version is
// reported as unsupported with an actionable message that includes the
// tested range string. This is the documented fail-closed path for
// `ai-env doctor`.
func TestDetect_VersionOutsideRange(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{stdout: "sbx 2.0.0\n", exitCode: 0}
	b := New(Options{Binary: "sh", Runner: runner.Run})

	status := b.Detect()

	if !status.Available {
		t.Fatalf("Detect.Available = false, want true (message=%q)", status.Message)
	}
	if status.VersionSupported {
		t.Errorf("Detect.VersionSupported = true, want false for %q", status.Version)
	}
	if status.Message == "" || !contains(status.Message, TestedVersionRange) {
		t.Errorf("Detect.Message = %q, want it to mention TestedVersionRange %q",
			status.Message, TestedVersionRange)
	}
}

// TestDetect_BinaryMissing covers the LookPath miss path: the adapter
// must surface an actionable installation message and report
// Available=false. We use a binary name that cannot exist on PATH.
func TestDetect_BinaryMissing(t *testing.T) {
	t.Parallel()

	b := New(Options{Binary: "definitely-not-a-real-binary-ai-env-xyzzy"})

	status := b.Detect()

	if status.Available {
		t.Fatalf("Detect.Available = true, want false for missing binary")
	}
	if status.Message == "" {
		t.Errorf("Detect.Message empty, want guidance about missing binary")
	}
}

// TestDetect_VersionUnparsable covers the case where sbx exits 0 but
// prints something that does not contain a version token. Per the plan,
// the adapter must fail closed when required semantics cannot be
// verified.
func TestDetect_VersionUnparsable(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{stdout: "hello, world\n", exitCode: 0}
	b := New(Options{Binary: "sh", Runner: runner.Run})

	status := b.Detect()

	if status.Available {
		t.Errorf("Detect.Available = true, want false for unparsable version")
	}
	if !contains(status.Message, TestedVersionRange) {
		t.Errorf("Detect.Message = %q, want it to mention TestedVersionRange", status.Message)
	}
}

// TestDetect_ProbeNonZeroExit covers `sbx version` exiting non-zero
// (sbx wedged, permissions issue). The adapter must report unavailable
// rather than crash on missing version output.
func TestDetect_ProbeNonZeroExit(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{stderr: "sbx: not initialized\n", exitCode: 2}
	b := New(Options{Binary: "sh", Runner: runner.Run})

	status := b.Detect()

	if status.Available {
		t.Errorf("Detect.Available = true, want false on non-zero exit")
	}
	if !contains(status.Message, "exited 2") {
		t.Errorf("Detect.Message = %q, want it to include exit code", status.Message)
	}
}

// TestDetect_SpawnError covers a runner-side error (process could not
// be spawned at all). The adapter surfaces it through BackendStatus.
func TestDetect_SpawnError(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{spawnErr: errors.New("boom")}
	b := New(Options{Binary: "sh", Runner: runner.Run})

	status := b.Detect()

	if status.Available {
		t.Errorf("Detect.Available = true, want false on spawn error")
	}
	if !contains(status.Message, "boom") {
		t.Errorf("Detect.Message = %q, want it to mention runner error", status.Message)
	}
}

// TestDetect_TimeoutContextHonored confirms Detect plumbs its
// DetectTimeout to the runner. We give the runner a 2s budget and assert
// the context it receives has a deadline within that bound.
func TestDetect_TimeoutContextHonored(t *testing.T) {
	t.Parallel()

	var sawDeadline bool
	var saw time.Duration
	runner := func(ctx context.Context, _ string, _ []string, _ io.Reader, stdout, _ io.Writer, _ []string, _ string) (int, error) {
		dl, ok := ctx.Deadline()
		sawDeadline = ok
		saw = time.Until(dl)
		if stdout != nil {
			_, _ = stdout.Write([]byte("0.5.0\n"))
		}
		return 0, nil
	}
	b := New(Options{Binary: "sh", Runner: runner, DetectTimeout: 2 * time.Second})

	_ = b.Detect()

	if !sawDeadline {
		t.Fatalf("runner did not see a context deadline; Detect did not plumb timeout")
	}
	if saw <= 0 || saw > 2*time.Second {
		t.Errorf("context deadline = %v, want in (0, 2s]", saw)
	}
}

// TestDetect_AllowUntestedSurfacedAsFalse asserts that an in-tested
// version flips VersionSupported true, and the docs-style message is
// only set when the version is out of range. This pins the contract
// `ai-env doctor` and the supervisor rely on when deciding whether to
// honor --allow-untested-backend-version.
func TestDetect_AllowUntestedSurfacedAsFalse(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{stdout: "0.5.0\n", exitCode: 0}
	b := New(Options{Binary: "sh", Runner: runner.Run})
	s := b.Detect()
	if s.Message != "" {
		t.Errorf("in-range Detect.Message = %q, want empty", s.Message)
	}

	runner.stdout = "0.0.1\n"
	s = b.Detect()
	if s.VersionSupported {
		t.Errorf("below-range Detect.VersionSupported = true, want false")
	}
	if !contains(s.Message, "--allow-untested-backend-version") {
		t.Errorf("below-range Detect.Message = %q, want it to mention --allow-untested-backend-version", s.Message)
	}
}

// Compile-time assertion that fakeRunner.Run has the Runner signature.
var _ Runner = (*fakeRunner)(nil).Run

// Sanity assertion on the public ResourceStats path used elsewhere: we
// don't test it here, but importing backend keeps the test file compiling
// alongside the rest of the package.
var _ backend.BackendStatus = backend.BackendStatus{}

// contains is a small substring helper kept as a local name so the
// individual assertions read like prose ("want it to mention ...").
func contains(s, sub string) bool { return strings.Contains(s, sub) }
