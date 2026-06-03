// Package docker_sbx implements the backend.Backend interface against
// the Docker Sandboxes `sbx` CLI.
//
// The adapter parses minimally: it relies on exit codes, explicit
// version probes, and known workspace paths rather than scraping
// interactive sbx stdout. If sbx output formatting changes but exit
// codes and known paths still work, ai-env keeps working. If required
// semantics cannot be verified, the adapter fails closed.
//
// Implementation rules tracked from plan 04:
//
//  1. Detect with exec.LookPath("sbx").
//  2. Run `sbx version`, parse only the version string.
//  3. Compare against the tested range in compat.go. Fail closed on
//     unknown version.
//  4. Wrap sbx as a subprocess: capture stdout, stderr, exit code,
//     timing.
//  5. Treat sbx stdout/stderr as logs, not a machine API.
//  6. Store the exact sbx command in agent-command.txt (supervisor's
//     responsibility; this package only exposes the command).
//  7. Integration tests are gated by AI_ENV_BACKEND_INTEGRATION=1.
package docker_sbx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/i1rr/ai-env/internal/backend"
)

// Name is the backend identifier surfaced through BackendStatus and the
// CLI's `doctor` output. Kept as a constant so tests can compare
// against it without importing internal/backend names twice.
const Name = "docker-sbx"

// defaultBinary is the binary name the adapter looks for on $PATH. It
// is configurable via Option.Binary so a test fixture can point at a
// shim, but in production we always resolve "sbx".
const defaultBinary = "sbx"

// defaultDetectTimeout caps the `sbx version` probe. Detect is on the
// hot path of `ai-env doctor` and similar interactive commands; if the
// binary is wedged we want to surface the failure quickly rather than
// hang the CLI.
const defaultDetectTimeout = 5 * time.Second

// defaultStopTimeout is the fallback grace period the adapter uses
// when Stop is called with a zero timeout. The supervisor normally
// supplies its own grace period; this constant is only the floor.
const defaultStopTimeout = 5 * time.Second

// Options configures the adapter. Zero value is usable: New applies
// the defaults documented on each field. Production callers typically
// pass Options{} and let the defaults take over; tests inject Runner
// to avoid shelling out.
type Options struct {
	// Binary is the sbx executable to invoke. Empty means "sbx".
	Binary string

	// Runner is the function the adapter uses to actually execute sbx.
	// Nil means "use the real os/exec runner". Tests override it to
	// return canned stdout/stderr/exit-code triples without spawning
	// processes.
	Runner Runner

	// DetectTimeout caps the version-probe call. Zero falls back to
	// defaultDetectTimeout.
	DetectTimeout time.Duration

	// Now is the clock used for RuntimeInfo.StartedAt and stat
	// timestamps. Nil falls back to time.Now.
	Now func() time.Time
}

// Runner is the seam tests use to intercept sbx invocations. It
// receives the binary name, the argv after it, and the streaming
// wiring; it returns the exit code and any spawn-side error. A nil
// error with a non-zero exit code is a clean failure from sbx; a
// non-nil error is a spawn/IO failure of the runner itself.
type Runner func(ctx context.Context, binary string, args []string, stdin io.Reader, stdout, stderr io.Writer, env []string, dir string) (exitCode int, err error)

// Backend is the docker-sbx implementation of backend.Backend. The
// zero value is not usable; callers must construct one via New so the
// runner and clock have sensible defaults.
type Backend struct {
	binary        string
	runner        Runner
	detectTimeout time.Duration
	now           func() time.Time

	mu   sync.Mutex
	envs map[string]*envState
}

// envState tracks an environment the adapter created. It mirrors the
// shape of the mock's record so the supervisor's bookkeeping is
// uniform across backends.
type envState struct {
	spec    backend.EnvSpec
	info    backend.RuntimeInfo
	running bool
}

// New constructs a docker-sbx Backend with sensible defaults. Pass an
// Options to override the binary, runner, or clock for testing.
func New(opts Options) *Backend {
	binary := opts.Binary
	if binary == "" {
		binary = defaultBinary
	}
	runner := opts.Runner
	if runner == nil {
		runner = realRunner
	}
	detectTimeout := opts.DetectTimeout
	if detectTimeout <= 0 {
		detectTimeout = defaultDetectTimeout
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Backend{
		binary:        binary,
		runner:        runner,
		detectTimeout: detectTimeout,
		now:           now,
		envs:          map[string]*envState{},
	}
}

// realRunner is the production Runner. It shells out via os/exec and
// honors the context for cancellation. It returns the OS exit code if
// the child reported one, or -1 with a non-nil error when the child
// could not be spawned at all.
func realRunner(ctx context.Context, binary string, args []string, stdin io.Reader, stdout, stderr io.Writer, env []string, dir string) (int, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	if stdout != nil {
		cmd.Stdout = stdout
	}
	if stderr != nil {
		cmd.Stderr = stderr
	}
	if env != nil {
		cmd.Env = env
	}
	if dir != "" {
		cmd.Dir = dir
	}
	err := cmd.Run()
	if err == nil {
		return cmd.ProcessState.ExitCode(), nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// sbx ran to completion but returned non-zero. Surface the
		// exit code without an error: clean failure from sbx is not
		// the same as a spawn failure here.
		return exitErr.ExitCode(), nil
	}
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode(), err
	}
	return -1, err
}

// versionLine matches the first semver-ish token in the output of
// `sbx version`. We only ever extract this single token; everything
// else on the line is treated as opaque log content. Keeping the
// regex this loose is deliberate: the plan's parsing principle says
// "parse minimally", so we only require that *some* dotted-numeric
// version is present.
var versionLine = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?)`)

// Detect implements backend.Backend. It checks for the sbx binary on
// $PATH, probes its version, and compares the version against the
// tested range in compat.go. Detect never returns an error: an
// unavailable backend reports its absence through BackendStatus.
func (b *Backend) Detect() backend.BackendStatus {
	status := backend.BackendStatus{Name: Name}

	if _, err := exec.LookPath(b.binary); err != nil {
		status.Available = false
		status.Message = fmt.Sprintf("sbx not found on PATH (looked for %q): install Docker Sandboxes or configure the binary location", b.binary)
		return status
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.detectTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, []string{"version"}, nil, &stdout, &stderr, nil, "")
	if err != nil {
		status.Available = false
		status.Message = fmt.Sprintf("sbx version probe failed: %v", err)
		return status
	}
	if exitCode != 0 {
		status.Available = false
		status.Message = fmt.Sprintf("sbx version exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
		return status
	}

	version := extractVersion(stdout.String())
	if version == "" {
		// Treat an unparsable version as unavailable: the rest of the
		// adapter assumes a known version, and the plan's compatibility
		// rule is to fail closed when required semantics cannot be
		// verified.
		status.Available = false
		status.Message = fmt.Sprintf("sbx version output did not contain a recognizable version string (tested range %s)", TestedVersionRange)
		return status
	}

	status.Available = true
	status.Version = version
	status.VersionSupported = IsVersionSupported(version)
	if !status.VersionSupported {
		status.Message = fmt.Sprintf("sbx version %s is outside the tested range %s; pass --allow-untested-backend-version to proceed", version, TestedVersionRange)
	}
	return status
}

// extractVersion pulls the first semver-ish token from sbx's version
// output and returns it without a leading "v". An empty string means
// no version token was found.
func extractVersion(raw string) string {
	m := versionLine.FindStringSubmatch(raw)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// Create implements backend.Backend. It shells out to `sbx create`
// with the supplied EnvSpec and returns the envID the rest of the
// methods address the environment by.
//
// The envID is the spec.Name: sbx names environments by string, and
// the supervisor already enforces name uniqueness through the
// workspace registry. Carrying the same identifier through avoids a
// second layer of mapping the operator would have to learn.
func (b *Backend) Create(spec backend.EnvSpec) (string, error) {
	if spec.Name == "" {
		return "", fmt.Errorf("docker-sbx: Create requires a non-empty EnvSpec.Name")
	}
	if spec.WorkspacePath == "" {
		return "", fmt.Errorf("docker-sbx: Create requires a non-empty EnvSpec.WorkspacePath")
	}

	args := []string{"create", "--name", spec.Name}
	if spec.Template != "" {
		args = append(args, "--template", spec.Template)
	}
	args = append(args, "--workspace", spec.WorkspacePath)
	// Plan §0.5: forward EnvSpec.BindMounts as `--bind <src>:<tgt>[:ro]`
	// entries. sbx accepts the same colon-separated form docker does;
	// adapters that gain richer mount semantics override this method.
	for _, m := range spec.BindMounts {
		entry := fmt.Sprintf("%s:%s", m.Source, m.Target)
		if m.ReadOnly {
			entry += ":ro"
		}
		args = append(args, "--bind", entry)
	}
	if spec.UID != nil {
		args = append(args, "--user", fmt.Sprintf("%d", *spec.UID))
	}
	for k, v := range spec.Labels {
		args = append(args, "--label", fmt.Sprintf("%s=%s", k, v))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, args, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return "", fmt.Errorf("docker-sbx: sbx create spawn failed: %w", err)
	}
	if exitCode != 0 {
		return "", fmt.Errorf("docker-sbx: sbx create exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.envs[spec.Name] = &envState{spec: spec}
	return spec.Name, nil
}

// Start implements backend.Backend. It invokes `sbx start <envID>`
// and returns RuntimeInfo describing the running environment. Calling
// Start on an already-running env is a no-op that returns the cached
// RuntimeInfo.
func (b *Backend) Start(envID string) (backend.RuntimeInfo, error) {
	b.mu.Lock()
	env, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return backend.RuntimeInfo{}, fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}
	if env.running {
		return env.info, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, []string{"start", envID}, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return backend.RuntimeInfo{}, fmt.Errorf("docker-sbx: sbx start spawn failed: %w", err)
	}
	if exitCode != 0 {
		return backend.RuntimeInfo{}, fmt.Errorf("docker-sbx: sbx start exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	env.running = true
	env.info = backend.RuntimeInfo{
		EnvID:          envID,
		ContainerID:    "", // sbx does not expose a stable container ID without scraping stdout
		WorkspaceMount: env.spec.WorkspacePath,
		StartedAt:      b.now(),
	}
	return env.info, nil
}

// Exec implements backend.Backend. It runs cmd inside the
// environment via `sbx exec <envID> -- <program> <args...>`. The
// stream wiring on opts is forwarded directly to the child; nil
// streams are discarded.
func (b *Backend) Exec(envID string, cmd backend.Command, opts backend.ExecOptions) (backend.ExecResult, error) {
	b.mu.Lock()
	env, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return backend.ExecResult{}, fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}
	if cmd.Program == "" {
		return backend.ExecResult{}, fmt.Errorf("docker-sbx: Exec requires a non-empty Command.Program")
	}

	args := []string{"exec", envID}
	if cmd.Dir != "" {
		args = append(args, "--cwd", cmd.Dir)
	}
	for _, e := range cmd.Env {
		args = append(args, "--env", e)
	}
	args = append(args, "--", cmd.Program)
	args = append(args, cmd.Args...)

	ctx := context.Background()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	stdin := ioReader(opts.Stdin)
	stdout := ioWriter(opts.Stdout)
	stderr := ioWriter(opts.Stderr)

	start := b.now()
	exitCode, err := b.runner(ctx, b.binary, args, stdin, stdout, stderr, nil, env.spec.WorkspacePath)
	dur := b.now().Sub(start)
	if err != nil {
		return backend.ExecResult{Duration: dur}, fmt.Errorf("docker-sbx: sbx exec spawn failed: %w", err)
	}
	return backend.ExecResult{
		ExitCode:    exitCode,
		HasExitCode: true,
		Duration:    dur,
	}, nil
}

// Stop implements backend.Backend. It invokes `sbx stop` with the
// requested signal and grace period. A nil signal means "let sbx pick
// its default" (SIGTERM on POSIX).
func (b *Backend) Stop(envID string, signal os.Signal, timeout time.Duration) error {
	b.mu.Lock()
	env, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}

	if timeout <= 0 {
		timeout = defaultStopTimeout
	}
	args := []string{"stop", envID, "--timeout", fmt.Sprintf("%d", int(timeout.Seconds()))}
	if signal != nil {
		args = append(args, "--signal", signal.String())
	}

	// Allow a small buffer over the grace period so the runner has
	// time to wait sbx out before cancelling the context. Adding this
	// is cheap and avoids fighting our own grace timer.
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, args, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return fmt.Errorf("docker-sbx: sbx stop spawn failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("docker-sbx: sbx stop exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	env.running = false
	return nil
}

// CopyIn implements backend.Backend via `sbx cp <src> <envID>:<dest>`.
func (b *Backend) CopyIn(envID, src, dest string) error {
	b.mu.Lock()
	_, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}
	if src == "" || dest == "" {
		return fmt.Errorf("docker-sbx: CopyIn requires non-empty src and dest")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	args := []string{"cp", src, fmt.Sprintf("%s:%s", envID, dest)}
	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, args, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return fmt.Errorf("docker-sbx: sbx cp (in) spawn failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("docker-sbx: sbx cp (in) exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// CopyOut implements backend.Backend via `sbx cp <envID>:<src> <dest>`.
func (b *Backend) CopyOut(envID, src, dest string) error {
	b.mu.Lock()
	_, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}
	if src == "" || dest == "" {
		return fmt.Errorf("docker-sbx: CopyOut requires non-empty src and dest")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	args := []string{"cp", fmt.Sprintf("%s:%s", envID, src), dest}
	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, args, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return fmt.Errorf("docker-sbx: sbx cp (out) spawn failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("docker-sbx: sbx cp (out) exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ApplyNetworkPolicy implements backend.Backend. The default sbx CLI
// in the tested range does not expose a single network-policy
// subcommand; this method translates the policy into the sbx network
// flags we know about and invokes `sbx network apply`. Backends that
// gain a richer policy API later can refine this method without
// touching the supervisor.
func (b *Backend) ApplyNetworkPolicy(envID string, policy backend.NetworkPolicy) error {
	b.mu.Lock()
	_, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}

	args := []string{"network", "apply", envID}
	if policy.Default != "" {
		args = append(args, "--default", policy.Default)
	}
	for _, d := range policy.AllowDomains {
		args = append(args, "--allow-domain", d)
	}
	if policy.BlockPrivateRanges {
		args = append(args, "--block-private-ranges")
	}
	if policy.BlockMetadataServices {
		args = append(args, "--block-metadata-services")
	}
	if policy.BlockLocalhost {
		args = append(args, "--block-localhost")
	}
	if policy.BlockHostDockerInternal {
		args = append(args, "--block-host-docker-internal")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, args, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return fmt.Errorf("docker-sbx: sbx network apply spawn failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("docker-sbx: sbx network apply exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Stats implements backend.Backend. The tested sbx range does not
// expose a stable stats endpoint; per the plan we return a zero
// ResourceStats with Available=false rather than an error. Once a
// stats endpoint lands upstream this method is the only place that
// has to change.
func (b *Backend) Stats(envID string) (backend.ResourceStats, error) {
	b.mu.Lock()
	_, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return backend.ResourceStats{}, fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}
	return backend.ResourceStats{
		Available:   false,
		CollectedAt: b.now(),
	}, nil
}

// Destroy implements backend.Backend via `sbx destroy <envID>`. After
// a successful Destroy the envID is invalid and further calls
// referencing it return an "unknown envID" error.
func (b *Backend) Destroy(envID string) error {
	b.mu.Lock()
	_, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, []string{"destroy", envID}, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return fmt.Errorf("docker-sbx: sbx destroy spawn failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("docker-sbx: sbx destroy exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.envs, envID)
	return nil
}

// GatewayAddress implements backend.Backend. The tested sbx range does
// not expose a stable gateway-IP endpoint; Plan §0.5 documents the
// contract: backends that cannot report a gateway return ("", nil) so
// the supervisor's ProviderProxy picker falls through to UnixSocket.
// An unknown envID still returns an error so the supervisor's "env
// not created" path is exercised.
func (b *Backend) GatewayAddress(envID string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.envs[envID]; !ok {
		return "", fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}
	return "", nil
}

// MappedUID implements backend.Backend. The docker-sbx adapter does
// not have a documented userns-remap signal in the tested range; the
// adapter returns EnvSpec.UID verbatim (or 0 when nil). Operators
// running sbx on a host with dockerd userns-remap enabled must
// configure the host's remap policy out of band; the capability
// detector's `RequiresMappedUID` bit will surface the mismatch.
func (b *Backend) MappedUID(envID string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	env, ok := b.envs[envID]
	if !ok {
		return 0, fmt.Errorf("docker-sbx: unknown envID %q", envID)
	}
	if env.spec.UID != nil {
		return *env.spec.UID, nil
	}
	return 0, nil
}

// ProbeImage implements backend.Backend. The sbx CLI's template layer
// is opaque: there is no documented way to read the underlying
// image's `/etc/passwd` without first running the template (which
// the supervisor will not do at Create time). Plan §0.5: the
// adapter returns ("", nil) and the supervisor falls back to the
// policy default `/root`. Operators with non-root templates set
// EnvSpec.HomeTarget explicitly in policy.yaml.
func (b *Backend) ProbeImage(template string, uid *int) (string, error) {
	return "", nil
}

// ioReader narrows an ExecOptions.Stdin (declared as a tiny inline
// interface so the public backend package stays import-light) into a
// plain io.Reader the runner accepts. Returns nil when the caller
// supplied no reader.
func ioReader(r interface{ Read(p []byte) (int, error) }) io.Reader {
	if r == nil {
		return nil
	}
	return readerAdapter{r}
}

// ioWriter is the writer analogue of ioReader.
func ioWriter(w interface{ Write(p []byte) (int, error) }) io.Writer {
	if w == nil {
		return nil
	}
	return writerAdapter{w}
}

// readerAdapter satisfies io.Reader by delegating to the inline-
// interface value the backend package exposes on ExecOptions.
type readerAdapter struct {
	r interface{ Read(p []byte) (int, error) }
}

func (a readerAdapter) Read(p []byte) (int, error) { return a.r.Read(p) }

// writerAdapter satisfies io.Writer by delegating to the inline-
// interface value the backend package exposes on ExecOptions.
type writerAdapter struct {
	w interface{ Write(p []byte) (int, error) }
}

func (a writerAdapter) Write(p []byte) (int, error) { return a.w.Write(p) }

// compile-time check that Backend satisfies backend.Backend.
var _ backend.Backend = (*Backend)(nil)
