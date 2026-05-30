// Package docker implements the rootless Docker fallback backend.
//
// This backend is the reduced-isolation fallback the master plan calls
// out when the primary docker-sbx adapter is unavailable. It speaks to
// the host's `docker` CLI (rootless or rooted: the adapter does not
// distinguish, but the master plan recommends rootless) and brings up
// a container per environment with `--network none` by default. The
// fallback is suitable for development and testing but explicitly NOT
// for high-risk autonomous execution: invoking it for autonomous mode
// requires the operator to opt in via --accept-reduced-isolation, and
// the adapter prints the reduced-isolation warning on every Detect that
// observes acceptance.
//
// Design rules tracked from plan 05 step 10:
//
//  1. Detect with exec.LookPath("docker"). An unavailable binary
//     reports Available=false through BackendStatus.
//  2. Default to `--network none` for every container the adapter
//     starts. ApplyNetworkPolicy rejects any policy that requires
//     allowlist enforcement, because the rootless docker fallback
//     cannot honor a domain allowlist without a DNS / firewall stack
//     the plan refuses to wire up in v0.1.
//  3. Autonomous mode requires Options.AcceptReducedIsolation=true.
//     Detect returns Available=false with a clear message otherwise,
//     mirroring the supervisor's fail-closed contract for the primary
//     adapter.
//  4. Outbound network in fallback mode requires both
//     Options.AcceptReducedIsolation=true AND Options.UnsafeHostNetwork
//     =true. Without UnsafeHostNetwork, the container is brought up
//     with `--network none` regardless of what the operator wrote in
//     policy.yaml; ApplyNetworkPolicy is a structural validator only
//     and never widens the network beyond what Start configured.
//  5. The adapter prints the reduced-isolation warning (the literal
//     text the plan fixes in "Reduced-isolation fallback warning") to
//     Options.WarningWriter the first time Detect observes a state
//     that triggers it. The supervisor wires WarningWriter to stderr
//     in production; tests inject a buffer to assert on the warning
//     text.
package docker

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

	"github.com/rivan1986/ai-env/internal/backend"
	"github.com/rivan1986/ai-env/internal/network"
)

// Name is the backend identifier surfaced through BackendStatus and the
// CLI's `doctor` output. Kept as a constant so audit logs and tests can
// compare against it without retyping the literal.
const Name = "docker"

// defaultBinary is the binary name the adapter resolves on $PATH. It is
// configurable via Options.Binary so a test fixture can point at a shim;
// in production we always resolve "docker".
const defaultBinary = "docker"

// defaultDetectTimeout caps the `docker version` probe. Detect is on
// the hot path of `ai-env doctor` and similar interactive commands; if
// the binary is wedged we want to surface the failure quickly rather
// than hang the CLI.
const defaultDetectTimeout = 5 * time.Second

// defaultStopTimeout is the fallback grace period the adapter uses when
// Stop is called with a zero timeout. The supervisor normally supplies
// its own grace period; this constant is only the floor.
const defaultStopTimeout = 5 * time.Second

// ReducedIsolationWarning is the verbatim warning text the master plan
// requires the fallback adapters to print when they are selected. The
// literal is exported so the podman fallback (and any future fallback
// with the same posture) can reuse it without diverging on wording.
const ReducedIsolationWarning = `WARNING: This backend provides reduced isolation. It is suitable for development
and testing, but not for high-risk autonomous execution with untrusted dependencies
or secrets.`

// defaultImage is the container image the adapter starts when EnvSpec
// .Template is empty. We pick a tiny base image so the fallback can run
// on hosts that have not pre-pulled anything heavier; the supervisor
// overrides this for real runs via the template lookup.
const defaultImage = "alpine:3.19"

// Options configures the docker fallback adapter. The zero value is
// usable but reports Available=false through Detect because the
// fallback requires explicit AcceptReducedIsolation=true for autonomous
// runs and an explicit Mode so it knows whether to enforce the
// autonomous gate.
type Options struct {
	// Binary is the docker executable to invoke. Empty means "docker".
	Binary string

	// Runner is the function the adapter uses to actually execute the
	// docker CLI. Nil means "use the real os/exec runner". Tests
	// override it to return canned stdout/stderr/exit-code triples
	// without spawning processes.
	Runner Runner

	// DetectTimeout caps the version-probe call. Zero falls back to
	// defaultDetectTimeout.
	DetectTimeout time.Duration

	// Now is the clock used for RuntimeInfo.StartedAt and stat
	// timestamps. Nil falls back to time.Now.
	Now func() time.Time

	// Mode is the run mode the supervisor selected ("autonomous",
	// "interactive", "dry-run", "continue"). The adapter uses it to
	// decide whether AcceptReducedIsolation is required: autonomous
	// runs without acceptance are rejected at Detect time; interactive
	// runs are allowed (with the warning printed) so an operator can
	// debug inside the fallback without explicit acknowledgement.
	Mode string

	// AcceptReducedIsolation is the operator-supplied acknowledgement
	// (typically wired from the --accept-reduced-isolation CLI flag /
	// config field). It must be true for autonomous mode; without it
	// Detect reports the backend as unavailable and explains why.
	AcceptReducedIsolation bool

	// UnsafeHostNetwork is the operator-supplied acknowledgement that
	// the container may have host network access (typically wired from
	// the --unsafe-host-network CLI flag). Without it, the container
	// is started with --network none regardless of what the network
	// policy requests; ApplyNetworkPolicy still validates the policy
	// structurally but never widens the container's network.
	UnsafeHostNetwork bool

	// WarningWriter receives the reduced-isolation warning text when
	// Detect observes a state that triggers it. Nil routes the warning
	// to os.Stderr in production; tests inject a buffer to assert.
	WarningWriter io.Writer
}

// Runner is the seam tests use to intercept docker invocations. It
// receives the binary name, the argv after it, and the streaming wiring;
// it returns the exit code and any spawn-side error. A nil error with a
// non-zero exit code is a clean failure from docker; a non-nil error is
// a spawn/IO failure of the runner itself.
type Runner func(ctx context.Context, binary string, args []string, stdin io.Reader, stdout, stderr io.Writer, env []string, dir string) (exitCode int, err error)

// Backend is the docker fallback implementation of backend.Backend.
// The zero value is not usable; callers must construct one via New so
// the runner, clock, and warning writer have sensible defaults.
type Backend struct {
	binary        string
	runner        Runner
	detectTimeout time.Duration
	now           func() time.Time
	mode          string
	accepted      bool
	hostNetwork   bool
	warnings      io.Writer

	mu           sync.Mutex
	envs         map[string]*envState
	warned       bool
	nextEnvIndex int
}

// envState tracks an environment the adapter created. Carries the
// container name (used as envID) so the adapter can address the
// container in every subsequent docker invocation.
type envState struct {
	spec          backend.EnvSpec
	containerName string
	info          backend.RuntimeInfo
	running       bool
	networkMode   string // "none" or "host"; the value passed to docker run --network
}

// New constructs a docker fallback Backend with sensible defaults. Pass
// an Options to override the binary, runner, clock, mode, or
// reduced-isolation acceptance flags.
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
	warnings := opts.WarningWriter
	if warnings == nil {
		warnings = os.Stderr
	}
	return &Backend{
		binary:        binary,
		runner:        runner,
		detectTimeout: detectTimeout,
		now:           now,
		mode:          opts.Mode,
		accepted:      opts.AcceptReducedIsolation,
		hostNetwork:   opts.UnsafeHostNetwork,
		warnings:      warnings,
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
		return exitErr.ExitCode(), nil
	}
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode(), err
	}
	return -1, err
}

// versionLine matches the first semver-ish token in the output of
// `docker version` / `podman version`. We only ever extract this single
// token; everything else on the line is treated as opaque log content.
var versionLine = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?)`)

// Detect implements backend.Backend. It checks for the docker binary on
// $PATH, probes its version, enforces the reduced-isolation gate for
// autonomous mode, and prints the reduced-isolation warning the first
// time it observes acceptance.
//
// Detect never returns an error: every unavailable path reports its
// reason through BackendStatus.Message. The supervisor consults Message
// when surfacing the doctor diagnostic.
func (b *Backend) Detect() backend.BackendStatus {
	status := backend.BackendStatus{Name: Name}

	if _, err := exec.LookPath(b.binary); err != nil {
		status.Available = false
		status.Message = fmt.Sprintf("docker not found on PATH (looked for %q): install Docker (rootless recommended) or configure the binary location", b.binary)
		return status
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.detectTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, []string{"version", "--format", "{{.Client.Version}}"}, nil, &stdout, &stderr, nil, "")
	if err != nil {
		status.Available = false
		status.Message = fmt.Sprintf("docker version probe failed: %v", err)
		return status
	}
	if exitCode != 0 {
		status.Available = false
		status.Message = fmt.Sprintf("docker version exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
		return status
	}

	version := extractVersion(stdout.String())
	if version == "" {
		status.Available = false
		status.Message = "docker version output did not contain a recognizable version string"
		return status
	}

	// Autonomous mode requires --accept-reduced-isolation. We refuse to
	// advertise the backend as available until the operator has
	// acknowledged the reduced-isolation posture; an unacknowledged
	// autonomous run that picks this backend would silently degrade
	// the security posture, which the plan forbids.
	if b.mode == "autonomous" && !b.accepted {
		status.Available = false
		status.Version = version
		status.VersionSupported = true
		status.Message = "docker fallback backend requires --accept-reduced-isolation for autonomous mode (reduced isolation: see WARNING below)\n" + ReducedIsolationWarning
		return status
	}

	status.Available = true
	status.Version = version
	// The fallback has no upstream version range to track; every
	// docker release the binary can run is accepted. Operators who
	// want a stricter pin gate the fallback through doctor instead.
	status.VersionSupported = true
	if b.accepted {
		status.Message = "docker fallback backend (reduced isolation; --accept-reduced-isolation acknowledged)"
		b.printWarningOnce()
	} else {
		status.Message = "docker fallback backend (reduced isolation; interactive mode)"
		b.printWarningOnce()
	}
	return status
}

// extractVersion pulls the first semver-ish token from docker's version
// output and returns it without a leading "v". An empty string means no
// version token was found.
func extractVersion(raw string) string {
	m := versionLine.FindStringSubmatch(raw)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// printWarningOnce writes the reduced-isolation warning to the
// configured writer the first time it is called. Subsequent calls are
// no-ops so a noisy `doctor` invocation does not repeat the warning.
func (b *Backend) printWarningOnce() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.warned {
		return
	}
	b.warned = true
	if b.warnings == nil {
		return
	}
	fmt.Fprintln(b.warnings, ReducedIsolationWarning)
}

// Create implements backend.Backend. The rootless docker fallback does
// not have a "create without start" abstraction the way sbx does:
// `docker create` would leave a stopped container behind that Start
// then has to `docker start`, but Start's job in this adapter is to
// run the container with the network settings the supervisor wants.
// We defer the actual container creation to Start; Create records the
// spec and returns the envID (which doubles as the container name).
func (b *Backend) Create(spec backend.EnvSpec) (string, error) {
	if spec.Name == "" {
		return "", fmt.Errorf("docker: Create requires a non-empty EnvSpec.Name")
	}
	if spec.WorkspacePath == "" {
		return "", fmt.Errorf("docker: Create requires a non-empty EnvSpec.WorkspacePath")
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextEnvIndex++
	containerName := fmt.Sprintf("ai-env-%s-%d", sanitizeName(spec.Name), b.nextEnvIndex)
	b.envs[spec.Name] = &envState{
		spec:          spec,
		containerName: containerName,
	}
	return spec.Name, nil
}

// sanitizeName strips characters docker rejects from container names.
// docker container names match [a-zA-Z0-9][a-zA-Z0-9_.-]*; the adapter
// replaces every other rune with '-' so an env name like "fix tests"
// becomes "fix-tests". Empty input becomes "env" so the name slot is
// always populated.
func sanitizeName(s string) string {
	if s == "" {
		return "env"
	}
	var out strings.Builder
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
			out.WriteRune(r)
		case (r == '_' || r == '.' || r == '-') && i > 0:
			out.WriteRune(r)
		default:
			if i == 0 {
				out.WriteByte('e')
			} else {
				out.WriteByte('-')
			}
		}
	}
	s2 := out.String()
	if s2 == "" {
		return "env"
	}
	return s2
}

// Start implements backend.Backend. It runs the container in
// detached mode with the network mode the adapter's configuration
// dictates: `--network none` by default, `--network host` only when
// the operator has explicitly opted in via UnsafeHostNetwork=true AND
// AcceptReducedIsolation=true. Calling Start on an already-running env
// is a no-op that returns the cached RuntimeInfo.
func (b *Backend) Start(envID string) (backend.RuntimeInfo, error) {
	b.mu.Lock()
	env, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return backend.RuntimeInfo{}, fmt.Errorf("docker: unknown envID %q", envID)
	}
	if env.running {
		return env.info, nil
	}

	networkMode := "none"
	if b.hostNetwork && b.accepted {
		networkMode = "host"
	}

	image := env.spec.Template
	if image == "" {
		image = defaultImage
	}

	args := []string{
		"run", "-d",
		"--name", env.containerName,
		"--network", networkMode,
		"-v", fmt.Sprintf("%s:%s", env.spec.WorkspacePath, "/workspace"),
		"-w", "/workspace",
	}
	for k, v := range env.spec.Labels {
		args = append(args, "--label", fmt.Sprintf("%s=%s", k, v))
	}
	// Tail /dev/null keeps the container alive so subsequent Exec calls
	// can attach to it. The fallback does not run a long-lived
	// entrypoint; the agent process is launched via `docker exec`.
	args = append(args, image, "tail", "-f", "/dev/null")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, args, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return backend.RuntimeInfo{}, fmt.Errorf("docker: docker run spawn failed: %w", err)
	}
	if exitCode != 0 {
		return backend.RuntimeInfo{}, fmt.Errorf("docker: docker run exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	env.running = true
	env.networkMode = networkMode
	env.info = backend.RuntimeInfo{
		EnvID:          envID,
		ContainerID:    strings.TrimSpace(stdout.String()),
		WorkspaceMount: "/workspace",
		StartedAt:      b.now(),
	}
	return env.info, nil
}

// Exec implements backend.Backend. It runs cmd inside the container
// via `docker exec`. The stream wiring on opts is forwarded directly
// to the child; nil streams are discarded.
func (b *Backend) Exec(envID string, cmd backend.Command, opts backend.ExecOptions) (backend.ExecResult, error) {
	b.mu.Lock()
	env, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return backend.ExecResult{}, fmt.Errorf("docker: unknown envID %q", envID)
	}
	if cmd.Program == "" {
		return backend.ExecResult{}, fmt.Errorf("docker: Exec requires a non-empty Command.Program")
	}
	if !env.running {
		return backend.ExecResult{}, fmt.Errorf("docker: env %q is not running; call Start first", envID)
	}

	args := []string{"exec"}
	if cmd.Dir != "" {
		args = append(args, "--workdir", cmd.Dir)
	}
	for _, e := range cmd.Env {
		args = append(args, "--env", e)
	}
	args = append(args, env.containerName, cmd.Program)
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
	exitCode, err := b.runner(ctx, b.binary, args, stdin, stdout, stderr, nil, "")
	dur := b.now().Sub(start)
	if err != nil {
		return backend.ExecResult{Duration: dur}, fmt.Errorf("docker: docker exec spawn failed: %w", err)
	}
	return backend.ExecResult{
		ExitCode:    exitCode,
		HasExitCode: true,
		Duration:    dur,
	}, nil
}

// Stop implements backend.Backend. It invokes `docker stop` with the
// requested grace period and signal. A nil signal means "use docker's
// default" (SIGTERM).
func (b *Backend) Stop(envID string, signal os.Signal, timeout time.Duration) error {
	b.mu.Lock()
	env, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker: unknown envID %q", envID)
	}

	if timeout <= 0 {
		timeout = defaultStopTimeout
	}
	args := []string{"stop", "-t", fmt.Sprintf("%d", int(timeout.Seconds()))}
	if signal != nil {
		args = append(args, "--signal", signal.String())
	}
	args = append(args, env.containerName)

	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, args, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return fmt.Errorf("docker: docker stop spawn failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("docker: docker stop exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	env.running = false
	return nil
}

// CopyIn implements backend.Backend via `docker cp <src>
// <container>:<dest>`.
func (b *Backend) CopyIn(envID, src, dest string) error {
	b.mu.Lock()
	env, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker: unknown envID %q", envID)
	}
	if src == "" || dest == "" {
		return fmt.Errorf("docker: CopyIn requires non-empty src and dest")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	args := []string{"cp", src, fmt.Sprintf("%s:%s", env.containerName, dest)}
	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, args, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return fmt.Errorf("docker: docker cp (in) spawn failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("docker: docker cp (in) exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// CopyOut implements backend.Backend via `docker cp <container>:<src>
// <dest>`.
func (b *Backend) CopyOut(envID, src, dest string) error {
	b.mu.Lock()
	env, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker: unknown envID %q", envID)
	}
	if src == "" || dest == "" {
		return fmt.Errorf("docker: CopyOut requires non-empty src and dest")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	args := []string{"cp", fmt.Sprintf("%s:%s", env.containerName, src), dest}
	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, args, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return fmt.Errorf("docker: docker cp (out) spawn failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("docker: docker cp (out) exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ApplyNetworkPolicy implements backend.Backend. The rootless docker
// fallback has no per-container firewall or DNS interception capability
// in v0.1: the container is locked to whatever network mode Start
// configured (`none` by default, `host` with UnsafeHostNetwork). This
// method therefore validates the requested policy structurally and
// rejects policies the fallback cannot honor, returning a descriptive
// error rather than silently degrading.
//
// The supervisor calls ApplyNetworkPolicy after Start. We use the
// recorded networkMode to decide:
//
//   - networkMode == "none": every policy is honored trivially (no
//     outbound traffic is possible). We accept any AllowDomains list:
//     it is moot, but the operator's intent is recorded in run.json.
//   - networkMode == "host": the container has host network access.
//     We refuse policies with Default="deny" AND a non-empty
//     AllowDomains list, because the fallback cannot enforce the
//     allowlist. Default="allow" is honored (the operator already
//     accepted the reduced isolation), and the always-block flags are
//     reported back unchanged but not enforced; the run.json record
//     reflects this through the "reduced isolation" message.
func (b *Backend) ApplyNetworkPolicy(envID string, policy backend.NetworkPolicy) error {
	b.mu.Lock()
	env, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker: unknown envID %q", envID)
	}

	switch env.networkMode {
	case "none":
		// Network is already closed: every policy is honored. No
		// further work to do.
		return nil
	case "host":
		// Host network mode: cannot enforce a per-destination
		// allowlist. Reject deny+allowlist policies so the supervisor
		// fails closed (the run aborts with failed_policy per plan
		// step 4 rather than silently running without enforcement).
		if policy.Default == "deny" && len(policy.AllowDomains) > 0 {
			return fmt.Errorf("docker: cannot enforce allowlist on rootless fallback with --unsafe-host-network; remove allow_domains or run on the docker-sbx backend")
		}
		return nil
	default:
		return fmt.Errorf("docker: env %q has unknown networkMode %q (Start must run first)", envID, env.networkMode)
	}
}

// Stats implements backend.Backend. `docker stats --no-stream` exists,
// but parsing its output is brittle and the rootless fallback's place
// in the architecture is "good enough to debug, not good enough to
// audit". We return Available=false here so callers know the snapshot
// is informational only, matching the docker-sbx adapter's stance for
// the same reason.
func (b *Backend) Stats(envID string) (backend.ResourceStats, error) {
	b.mu.Lock()
	_, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return backend.ResourceStats{}, fmt.Errorf("docker: unknown envID %q", envID)
	}
	return backend.ResourceStats{
		Available:   false,
		CollectedAt: b.now(),
	}, nil
}

// Destroy implements backend.Backend via `docker rm -f <container>`.
// After a successful Destroy the envID is invalid; further calls
// referencing it return an "unknown envID" error.
func (b *Backend) Destroy(envID string) error {
	b.mu.Lock()
	env, ok := b.envs[envID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("docker: unknown envID %q", envID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCode, err := b.runner(ctx, b.binary, []string{"rm", "-f", env.containerName}, nil, &stdout, &stderr, nil, "")
	if err != nil {
		return fmt.Errorf("docker: docker rm spawn failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("docker: docker rm exited %d: %s", exitCode, strings.TrimSpace(stderr.String()))
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.envs, envID)
	return nil
}

// NetworkPolicyAdapter is the network.NetworkPolicyAdapter the
// supervisor uses to install policy on a docker fallback environment.
// It delegates to the Backend's ApplyNetworkPolicy with the canonical
// policy projection, so the supervisor only ever speaks one policy
// shape and audit code can compare what the adapter saw against what
// was recorded in run.json.
type NetworkPolicyAdapter struct {
	backend *Backend
}

// NewNetworkPolicyAdapter constructs an adapter that installs policies
// on environments owned by the supplied Backend. Passing a nil Backend
// is a programming error; Apply panics on a nil backend.
func NewNetworkPolicyAdapter(b *Backend) *NetworkPolicyAdapter {
	return &NetworkPolicyAdapter{backend: b}
}

// Name returns the adapter identifier surfaced through audit logs and
// run reports. It mirrors docker.Name so operators can correlate the
// network entry in run.json with the backend entry: both read "docker".
func (a *NetworkPolicyAdapter) Name() string {
	return Name
}

// Apply installs policy on envID. It validates the policy's structural
// invariants (delegating to NetworkPolicy.Validate in lenient
// "interactive" mode, since the supervisor already enforced the
// autonomous-mode rule before reaching the adapter) and then calls the
// Backend's ApplyNetworkPolicy with the projected backend.NetworkPolicy.
// Errors propagate verbatim so the supervisor's failed_policy state
// captures the adapter's diagnostic.
func (a *NetworkPolicyAdapter) Apply(envID string, policy network.NetworkPolicy) error {
	if a.backend == nil {
		return fmt.Errorf("docker: NetworkPolicyAdapter has nil Backend (programmer error)")
	}
	if envID == "" {
		return fmt.Errorf("docker: ApplyNetworkPolicy requires a non-empty envID")
	}
	if err := policy.Validate("interactive"); err != nil {
		return fmt.Errorf("docker: invalid network policy: %w", err)
	}
	return a.backend.ApplyNetworkPolicy(envID, policy.ToBackendPolicy())
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

// compile-time checks that the docker fallback satisfies both the
// generic Backend contract and the network adapter contract.
var (
	_ backend.Backend             = (*Backend)(nil)
	_ network.NetworkPolicyAdapter = (*NetworkPolicyAdapter)(nil)
)
