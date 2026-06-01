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

	// GatewayAddress returns the IPv4 address of the host-side bridge
	// gateway that is reachable from inside the sandbox identified by
	// envID, when one exists. The supervisor uses the address at the
	// canonical pre-launch step 6 (Plan §5.5) to pick the ProviderProxy
	// reachability mode (the BridgeGateway alternative when SetnsTCP
	// is unavailable). Backends that have no bridge gateway concept —
	// the rootless `--network none` fallbacks, or the docker-sbx
	// adapter whose network plumbing is opaque — return an empty
	// string with a nil error so the picker falls through to the
	// next mode (UnixSocket). A non-nil error is reserved for the
	// "the backend cannot be queried right now" case (e.g. the envID
	// is unknown or Start has not been called yet); the supervisor
	// surfaces it verbatim.
	GatewayAddress(envID string) (ip string, err error)

	// MappedUID returns the host-side UID the sandbox's EnvSpec.UID
	// maps to. Plan §0.5 introduces the method because Linux dockerd
	// configured with `userns-remap` rewrites every in-sandbox UID to
	// a host-side offset; supervisor-side chown operations (the
	// control socket, the per-server MCP token files, the originals
	// map) must address the host-mapped UID, not the in-sandbox UID.
	//
	// Backends that do not implement userns-remap return the same UID
	// the caller passed via EnvSpec.UID (or 0 when EnvSpec.UID was
	// nil); the host- and sandbox-side UIDs are identical in that
	// case. A non-nil error means the backend cannot resolve the
	// mapping for envID (e.g. the env is not running, or the daemon
	// is in a state we cannot inspect); the supervisor surfaces the
	// error and refuses to proceed when the capability detector
	// reported `RequiresMappedUID()=true`.
	MappedUID(envID string) (hostUID int, err error)

	// ProbeImage resolves the absolute home-directory path the image
	// would assign to uid by reading the image's `/etc/passwd`. The
	// supervisor calls ProbeImage before Create to populate
	// EnvSpec.HomeTarget; the HOME shadow bind-mount at Create
	// targets the returned path so the agent CLI's startup files
	// land in a supervisor-owned tmpfs rather than the workspace.
	//
	// template is the EnvSpec.Template that will be used at Create;
	// uid is the EnvSpec.UID the supervisor intends to run the agent
	// as (nil means "the image's default user"). Adapters that can
	// inspect the image (docker, podman) parse the matching passwd
	// entry; adapters that cannot (docker-sbx with opaque templates)
	// return ("", nil) and the supervisor falls back to the policy
	// default `/root` per Plan §0.5. A non-nil error is reserved for
	// "the backend tried to probe and the probe failed in an
	// unexpected way"; the supervisor surfaces the error verbatim
	// rather than silently defaulting.
	ProbeImage(template string, uid *int) (homeTarget string, err error)
}

// BackendEventSink is the contract the supervisor passes to backend
// adapters so they can emit lifecycle verbs into the run's
// `lifecycle.jsonl`. Plan §0.5 introduces it so non-supervisor code
// paths (e.g. an adapter that observes a policy degradation while
// applying iptables rules) can record audit-relevant events through
// the same writer the supervisor owns, without coupling the adapter
// to the run package's concrete LifecycleWriter type.
//
// Emit MUST be safe to call from multiple goroutines: the supervisor
// may share a single sink with several adapters / observers, and the
// recording implementation in the testharness already serializes
// access with a mutex.
//
// The verb string is a `LifecycleVerb` value from
// `internal/run/lifecycle_verbs.go` (kept as a plain string here so
// the backend package does not pull in the run package and create an
// import cycle). The metadata map carries the per-verb key/value
// table documented on each LifecycleVerb constant; the sink shallow-
// copies the map at emit time so the caller can reuse the map after
// the call returns.
//
// A non-nil error means the sink rejected the emission (typically
// because the writer is shut down or a fault was injected for
// testing). Plan §10 row 10 specifies "graceful degradation": the
// caller logs the error and continues, the run is not aborted.
type BackendEventSink interface {
	Emit(verb string, metadata map[string]string) error
}

// BindMount describes one host→sandbox bind-mount the backend should
// install at Create. The supervisor builds the per-run BindMounts
// slice from the canonical pre-launch layout (Plan §5.5 step 3):
//
//   - <runDir>/ipc/ → /var/run/ai-env/ (agent-readable IPC root)
//   - <shimDir>/ → /var/run/ai-env/shim (shim wrappers, RO)
//   - <ai-env binary> → /usr/local/bin/ai-env (RO)
//   - empty tmpdir → EnvSpec.HomeTarget (HOME shadow)
//   - per-program shadow over /usr/bin/<prog>, /bin/<prog>,
//     /usr/local/bin/<prog> for every entry in the canonical shim
//     program set (Plan Bucket 1).
//
// The mount split is deliberate: sensitive files (`leaks.jsonl`,
// `secret-scan.json`) stay in <runDir> directly, host-only; only
// <runDir>/ipc/ is bind-mounted into the sandbox, so the agent UID
// cannot read leaks.jsonl even when it has full access to its own
// IPC tree.
//
// Backends translate the slice into their native mount flags
// (`docker run -v <source>:<target>:ro,mode=<mode>`,
// `podman run --mount type=bind,source=<source>,target=<target>,readonly`,
// etc.). A bind-mount whose Target does not exist in the image is
// tolerated per Plan Bucket 1: the docker/podman CLIs auto-create
// the path; failures for a single entry are non-fatal and the
// supervisor logs `shim_coverage_degraded` to record the degradation.
type BindMount struct {
	// Source is the absolute host-side path the backend bind-mounts
	// FROM. The supervisor resolves the path before adding it to
	// EnvSpec.BindMounts; adapters do not consult the workspace
	// path or the runDir layout, they just consume the slice.
	Source string

	// Target is the absolute sandbox-side path the bind-mount lands
	// at. Sandbox-relative paths are rejected by the supervisor's
	// EnvSpec builder; the field is always an absolute path the
	// adapter can pass through to its native mount flag.
	Target string

	// ReadOnly requests a read-only mount. The supervisor sets this
	// for every Bucket-1 shim shadow and for the `ai-env` binary
	// mount; only the HOME shadow and the <runDir>/ipc mount are
	// read-write. Adapters that cannot satisfy the request (e.g.
	// docker on Windows with broken `:ro` semantics) fail closed.
	ReadOnly bool

	// Mode is the file mode the backend applies to the bind-mount's
	// in-sandbox view, when the underlying mount syscall supports
	// it. Zero means "use the source path's mode" (the default
	// docker / podman behavior). The supervisor uses non-zero modes
	// only for the per-server MCP token file (0600) and the
	// originals map (0755) at <runDir>/ipc/orig/<prog>.
	Mode os.FileMode
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

	// BindMounts is the list of host→sandbox bind-mounts the backend
	// should install at Create. Plan §0.5 / §5.5 step 3: the supervisor
	// pre-computes the slice (the runDir/ipc split, the shim wrapper
	// shadows, the ai-env binary mount, the HOME tmpfs shadow) and the
	// adapter installs them verbatim. Nil means "no per-run binds";
	// every production run carries a populated slice.
	BindMounts []BindMount

	// UID is the in-sandbox UID the agent process should run as. nil
	// means "use the image's default user" (typically root on the
	// fallback adapters, the template's USER on docker-sbx). The
	// supervisor reads the value before Create — chown'ing the
	// control socket at runDir/ipc/control.sock to the in-sandbox
	// UID (via Backend.MappedUID on userns-remap hosts) requires
	// knowing the in-sandbox value up front.
	//
	// Stored as a pointer so the zero value ("not set, use image
	// default") is distinguishable from the literal UID 0 ("run as
	// root in the sandbox"). Adapters that need an int dereference
	// the pointer and treat nil as "image default".
	UID *int

	// HomeTarget is the absolute sandbox-side path the HOME shadow
	// bind-mount lands at. Plan §0.5: resolved by the supervisor
	// before Create by reading the image's `/etc/passwd` entry for
	// the resolved UID (via Backend.ProbeImage), falling back to
	// "/root" when the lookup fails or UID is nil/zero. Adapters
	// consume the value verbatim and build the HOME shadow
	// bind-mount entry against it.
	HomeTarget string
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
