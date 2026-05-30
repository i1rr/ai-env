// Package backend defines the abstraction ai-env uses to launch and
// supervise agent processes inside an isolated environment.
//
// The Backend interface is implemented by concrete adapters
// (internal/backend/docker_sbx for the Docker Sandboxes adapter,
// internal/backend/mock for an in-memory no-op used by unit tests). The
// supervisor in internal/run drives a Backend through the lifecycle:
// Detect, Create, Start, Exec, Stop, Destroy, with CopyIn/CopyOut,
// ApplyNetworkPolicy, and Stats interleaved as needed.
//
// The shape of this interface is fixed by plan 04. Adapters parse only
// minimal output (exit codes, well-known paths, explicit version probes)
// and never scrape interactive stdout for state transitions.
package backend

import (
	"os"
	"time"
)

// Backend is the contract every environment adapter satisfies. The
// supervisor talks to exactly one Backend per run; the same Backend
// instance may be reused across runs that share an env.
type Backend interface {
	// Detect reports whether this backend is available on the host and,
	// if so, what version and feature set it offers. Detect never fails:
	// an unavailable backend reports its absence through BackendStatus.
	Detect() BackendStatus

	// Create materializes a new isolated environment from spec and
	// returns an opaque envID the rest of the methods address it by. The
	// environment is not running yet; Start brings it up.
	Create(spec EnvSpec) (envID string, err error)

	// Start brings the environment identified by envID online and
	// returns runtime information about it (e.g. container ID, mount
	// points). Calling Start on an already-running env is a no-op that
	// returns the current RuntimeInfo.
	Start(envID string) (RuntimeInfo, error)

	// Exec runs cmd inside the environment and returns the result once
	// the command exits. The supervisor uses Exec to launch the agent
	// process; opts controls stream wiring, working directory, and
	// environment variables.
	Exec(envID string, cmd Command, opts ExecOptions) (ExecResult, error)

	// Stop asks the environment to shut down. signal is the OS signal
	// to deliver first; timeout is how long to wait for a graceful exit
	// before escalating to a hard kill. A nil signal means the backend
	// picks the platform default (SIGTERM on POSIX).
	Stop(envID string, signal os.Signal, timeout time.Duration) error

	// CopyIn copies a host path src into the environment at dest. The
	// adapter is responsible for resolving dest relative to the
	// environment's filesystem root.
	CopyIn(envID, src, dest string) error

	// CopyOut copies a path src out of the environment to the host at
	// dest. Symmetric to CopyIn.
	CopyOut(envID, src, dest string) error

	// ApplyNetworkPolicy installs the supplied network policy on the
	// environment. Implementations enforce policy through whatever
	// mechanism the backend exposes (firewall rules, namespace
	// configuration, proxy interception); the supervisor only supplies
	// the policy and trusts the adapter to apply it.
	ApplyNetworkPolicy(envID string, policy NetworkPolicy) error

	// Stats returns a point-in-time resource snapshot for the
	// environment. Backends that have no stats endpoint return a zero
	// ResourceStats with Available=false rather than an error.
	Stats(envID string) (ResourceStats, error)

	// Destroy tears the environment down and reclaims its resources.
	// After Destroy returns successfully the envID is invalid; further
	// calls referring to it return an error.
	Destroy(envID string) error
}

// BackendStatus is the result of Backend.Detect. It tells the caller
// whether the backend is usable and surfaces the diagnostic information
// the CLI's "doctor" commands print.
type BackendStatus struct {
	// Name is the backend identifier (e.g. "docker-sbx", "mock"). Always
	// populated, even when the backend is unavailable.
	Name string

	// Available reports whether the backend can be used on this host.
	// False means Detect found no binary, no daemon, or an unsupported
	// version; the supervisor must not attempt to Create.
	Available bool

	// Version is the backend's reported version string. Empty when the
	// backend is unavailable or when no version can be probed.
	Version string

	// VersionSupported reports whether Version falls within the tested
	// range. False on an unknown version means the caller must fail
	// closed unless the operator opted in with
	// --allow-untested-backend-version.
	VersionSupported bool

	// Message is a short human-readable diagnostic the CLI surfaces
	// verbatim. Empty when the backend is healthy and supported.
	Message string
}

// EnvSpec is the input to Backend.Create. It describes the workspace
// the environment will host, the template it should be built from, and
// the policy the supervisor wants applied at startup.
type EnvSpec struct {
	// Name is the env name (e.g. "fix-tests"). Adapters use it to derive
	// container names, mount paths, and on-disk labels.
	Name string

	// Template is the sandbox template the environment is built from
	// (e.g. "node", "go", "python"). Adapters look up the template in
	// their own registry.
	Template string

	// WorkspacePath is the absolute host path of the workspace that
	// should be mounted into the environment.
	WorkspacePath string

	// NetworkPolicy is the policy to install at Start. Adapters may
	// apply it during Create if their stack requires baking the policy
	// into the environment definition.
	NetworkPolicy NetworkPolicy

	// Labels are caller-supplied key/value tags the adapter records on
	// the environment so external tooling can locate it.
	Labels map[string]string
}

// RuntimeInfo describes a running environment. The supervisor records
// it in run.json and surfaces it through `ai-env status`.
type RuntimeInfo struct {
	// EnvID is the opaque identifier the backend uses to address this
	// environment.
	EnvID string

	// ContainerID is the backend-native identifier (e.g. Docker
	// container ID) when one exists. Empty for backends that do not
	// expose a container abstraction.
	ContainerID string

	// WorkspaceMount is the absolute path inside the environment where
	// the workspace is mounted. The supervisor passes this to the agent
	// as its working directory.
	WorkspaceMount string

	// StartedAt is the wall-clock time the environment came up.
	StartedAt time.Time
}

// Command is the description of a process to execute inside the
// environment via Backend.Exec.
type Command struct {
	// Program is the executable name or absolute path inside the
	// environment.
	Program string

	// Args is the rest of argv (without the program). May be nil.
	Args []string

	// Dir is the working directory inside the environment. Empty means
	// "use the workspace mount" (the adapter's default).
	Dir string

	// Env is the environment variables to inject. Nil means "inherit the
	// environment's default env"; an empty slice means "run with no
	// environment".
	Env []string
}

// ExecOptions are the run-time knobs Backend.Exec consults. They are
// kept separate from Command so the same Command can be replayed with
// different stream wiring or timeouts.
type ExecOptions struct {
	// Stdin is the reader piped into the child's stdin. Nil means
	// /dev/null (no input).
	Stdin interface{ Read(p []byte) (int, error) }

	// Stdout is the writer that receives the child's stdout. Nil
	// discards the stream.
	Stdout interface{ Write(p []byte) (int, error) }

	// Stderr is the writer that receives the child's stderr. Nil
	// discards the stream.
	Stderr interface{ Write(p []byte) (int, error) }

	// Timeout caps how long the Exec is allowed to run. Zero means no
	// timeout (the supervisor enforces its own max-runtime budget out of
	// band).
	Timeout time.Duration
}

// ExecResult is the outcome of a Backend.Exec call.
type ExecResult struct {
	// ExitCode is the child's exit code. Zero on success, non-zero on
	// failure. Negative when the process was killed by a signal and no
	// exit code is meaningful.
	ExitCode int

	// HasExitCode reports whether ExitCode reflects a real reported
	// value. False when the process was force-killed before reporting,
	// or when the launch itself failed.
	HasExitCode bool

	// Duration is the wall-clock time the command took.
	Duration time.Duration
}

// NetworkPolicy is the runtime view of the policy the supervisor wants
// installed on the environment. It mirrors the policy.yaml shape but is
// reduced to the fields the backend adapter actually enforces; the YAML
// loader translates from config.NetworkPolicy into this shape.
type NetworkPolicy struct {
	// Default is the default outbound policy ("deny" or "allow").
	Default string

	// AllowDomains is the explicit allowlist of fully-qualified domain
	// names the agent may reach. Ignored when Default is "allow".
	AllowDomains []string

	// BlockPrivateRanges blocks RFC1918 ranges from the agent's view of
	// the network.
	BlockPrivateRanges bool

	// BlockMetadataServices blocks cloud-provider metadata services
	// (169.254.169.254 and friends).
	BlockMetadataServices bool

	// BlockLocalhost blocks the loopback interface (some agents try to
	// reach a co-tenant by accident).
	BlockLocalhost bool

	// BlockHostDockerInternal blocks host.docker.internal so an agent
	// inside a container cannot reach the host's daemon.
	BlockHostDockerInternal bool
}

// ResourceStats is the point-in-time resource snapshot Backend.Stats
// returns. Fields that the backend cannot report are left at their zero
// value; Available reports whether any field is meaningful.
type ResourceStats struct {
	// Available reports whether the backend produced real numbers. False
	// means every other field is zero because the backend has no stats
	// endpoint; the supervisor treats the snapshot as informational only.
	Available bool

	// CPUPercent is the cumulative CPU usage in percent (100.0 means one
	// fully loaded core). Zero when unavailable.
	CPUPercent float64

	// MemoryBytes is the resident memory the environment is using right
	// now, in bytes. Zero when unavailable.
	MemoryBytes uint64

	// MemoryLimitBytes is the memory cap configured for the environment.
	// Zero when uncapped or unavailable.
	MemoryLimitBytes uint64

	// CollectedAt is the wall-clock time the snapshot was taken.
	CollectedAt time.Time
}
