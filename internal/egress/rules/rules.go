// Package rules owns the iptables (Linux) / pf (macOS) firewall
// rule lifecycle the supervisor installs at Plan §5.5 step 7 and
// tears down at teardown step 3 (see also Plan Batch 5.4).
//
// The package is the structural counterpart of `egress/nflog`
// (Linux) and `egress/pflog` (macOS): the observer attaches to a
// kernel log surface, while this package installs the rules that
// feed that surface. The two halves agree only on the per-run
// chain name (`AIENV-EGR-<8hex>`) and, on Linux, the NFLOG group
// id; everything else is private to each side.
//
// Crash-safety + idempotence (plan locks):
//
//   - Rule installation must be idempotent. The supervisor may
//     re-enter `Install` after a partial-crash teardown left
//     orphaned rules; the package detects existing rules for the
//     same chain name and refuses to overwrite them, surfacing
//     `ErrChainAlreadyExists` instead. The supervisor's crash-
//     recovery handler is responsible for calling `Uninstall`
//     first to drop the stale chain.
//
//   - Rollback on partial failure. If `Install` succeeds halfway
//     through (e.g. the chain was created but the JUMP rule
//     could not be attached), the package unwinds the partial
//     state via `Uninstall` before returning the error so the
//     host is left with no orphaned rules.
//
//   - Lifecycle verbs. The supervisor wires
//     `Lifecycle.OnInstalled` / `Lifecycle.OnUninstalled` to its
//     `LifecycleVerbObserverStarted` / `LifecycleVerbObserverStopped`
//     writers so the on-disk audit trail records the chain name
//     and the install / uninstall mode tokens.
//
// Build-tag layout:
//
//   - `rules.go` (this file): cross-platform `Lifecycle`,
//     `Options`, `Mode`, `New`. Compiles on every OS.
//   - `iptables_linux.go`: the iptables Commander (build tag
//     `linux`).
//   - `pf_darwin.go`: the pf Commander (build tag `darwin`).
//   - `rules_other.go`: stub Commander for non-Linux / non-Darwin
//     hosts; `New` falls back to it when the host OS is not
//     supported and `Install` returns `ErrUnsupportedOS`.
//
// Dependencies: standard library only. The Commander interface is
// the seam tests use to inject a fake; production code uses
// `os/exec` to shell out to `iptables` / `pfctl` (the canonical
// admin tools that ship with every Linux / macOS host).
package rules

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Mode is the token recorded in the supervisor's
// `observer_started` Metadata.mode for the rule lifecycle. The
// values are intentionally distinct from the observer Mode tokens
// (`nflog` / `pflog`) so a future audit pipeline can correlate the
// two halves without ambiguity.
type Mode string

const (
	// ModeIptables is the Linux rule lifecycle: iptables in the
	// sandbox netns. The supervisor sets `chain` Metadata to the
	// per-run `AIENV-EGR-<8hex>` name.
	ModeIptables Mode = "iptables"

	// ModePF is the macOS rule lifecycle: pf anchor in the host
	// pf ruleset. Same chain Metadata.
	ModePF Mode = "pf"

	// ModeUnsupported is the fallback on non-Linux/non-Darwin
	// hosts. `Install` returns `ErrUnsupportedOS` so the
	// supervisor's strict-mode abort or auto-mode skip path
	// engages without an OS-specific branch.
	ModeUnsupported Mode = "unsupported_os"
)

// MaxChainLength caps the length of a chain name. iptables
// imposes a 28-character limit (IPT_CHAIN_MAXNAMELEN); pf has no
// hard cap but anchors longer than 64 characters are unusual and
// would be hard to debug. We pick 28 so the Linux path is the
// constraint and the same value is enforced on macOS.
const MaxChainLength = 28

// ChainNameRegexp is the format Plan §5.5 step 7 locks for the
// chain. Eight lower-case hex chars after a fixed prefix; no
// other characters tolerated. The supervisor derives the suffix
// from the run id so concurrent runs do not collide.
var ChainNameRegexp = regexp.MustCompile(`^AIENV-EGR-[0-9a-f]{8}$`)

// Options bundles every per-run input the lifecycle needs. The
// supervisor populates this struct once at §5.5 step 7; the
// lifecycle copies the fields so a caller mutating the source
// after `New` returns cannot affect an in-flight install.
type Options struct {
	// Chain is the per-run chain / pf anchor name. Format:
	// `AIENV-EGR-<8hex>`. Required; `New` rejects an empty or
	// malformed value.
	Chain string

	// NFLOGGroup is the Linux NFLOG `--nflog-group` the observer
	// (Plan Batch 5.2) binds. The rule installer wires
	// `-j NFLOG --nflog-group <n>` into the chain so the
	// observer sees the matching packets. Ignored on macOS (pf
	// uses the `log` action without a numeric group). 0 means
	// "use the default group 0" which is valid; the field has
	// no nil sentinel because uint16 cannot.
	NFLOGGroup uint16

	// NetNSPath is the sandbox network namespace path. The Linux
	// rule installer enters this netns via `setns(2)` before
	// shelling out to `iptables` so the rules land in the
	// sandbox's table, not the supervisor's. Empty means "use
	// the current netns"; the supervisor passes the sandbox
	// path. Ignored on macOS.
	NetNSPath string

	// Commander is the seam tests use to substitute a fake for
	// the real `iptables` / `pfctl` shell-out. nil means "use
	// the platform default" wired by `platformCommander`. The
	// supervisor never sets this; tests inject a recording
	// commander to assert the exact command sequence.
	Commander Commander

	// Verdict is the action the per-run chain applies to
	// matching packets after the NFLOG / pf-log mirror. Plan
	// locks Verdict to `Reject` so a leaked packet is dropped
	// rather than allowed; the field is exported so a future
	// `--observer-mode shadow` (audit-only) can pass `Pass`.
	Verdict Verdict

	// OnInstalled is an optional callback the lifecycle invokes
	// after Install succeeds. The supervisor wires this to its
	// `LifecycleVerbObserverStarted` writer so the on-disk
	// audit trail records the chain name + mode at the same
	// moment the kernel surface accepts the rules.
	OnInstalled func(chain string, mode Mode)

	// OnUninstalled is the symmetric callback for Uninstall.
	// The supervisor wires this to `LifecycleVerbObserverStopped`.
	OnUninstalled func(chain string, mode Mode, reason string)
}

// Verdict names the action the per-run chain applies after the
// log mirror. The supervisor's plan locks `Reject` (a leaked
// packet is dropped); `Pass` is reserved for a future
// observer-only audit mode.
type Verdict string

const (
	// VerdictReject drops the packet. The Linux rule installer
	// uses `-j REJECT --reject-with icmp-port-unreachable` so
	// the application sees an immediate error rather than a
	// silent black-hole; macOS uses `block return`.
	VerdictReject Verdict = "reject"

	// VerdictPass allows the packet after logging. Reserved.
	VerdictPass Verdict = "pass"
)

// Commander is the per-platform command-execution seam. The real
// implementation shells out to `iptables` / `pfctl`; tests inject
// a recording Commander to assert the exact sequence.
//
// The interface is intentionally narrow: one method that returns
// (stdout, error). The Lifecycle does not need stderr separately
// because a non-nil error already carries the command's stderr in
// its wrapped form.
type Commander interface {
	// Run executes the named command with the supplied args and
	// returns its stdout. A non-zero exit must be returned as a
	// non-nil error containing the program's stderr (the
	// `os/exec.ExitError` shape works directly). The context is
	// honoured for cancellation.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// CommanderFunc is the function-typed Commander used by tests
// for one-off mocks without a full struct.
type CommanderFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// Run implements Commander.
func (f CommanderFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

// ErrChainAlreadyExists is returned from `Install` when a chain
// or pf anchor with the same name already exists on the host. The
// supervisor's crash-recovery handler is responsible for calling
// `Uninstall` first to drop the stale chain. Refusing to
// overwrite is a defense-in-depth measure: a stale chain with
// unknown rules could let traffic escape unmonitored.
var ErrChainAlreadyExists = errors.New("egress/rules: chain already exists")

// ErrChainNotFound is returned from `Uninstall` when the chain
// does not exist on the host. Treated as a clean exit by the
// supervisor (the desired post-state is "no chain"); the error
// is surfaced so a caller can distinguish "we removed it" from
// "it was never there".
var ErrChainNotFound = errors.New("egress/rules: chain not found")

// ErrUnsupportedOS is returned from `Install` on a host where the
// rule lifecycle cannot run (anything not Linux / not macOS).
var ErrUnsupportedOS = errors.New("egress/rules: unsupported_os")

// Lifecycle owns the per-run install / uninstall flow. The
// supervisor builds one Lifecycle per run, calls `Install` at
// §5.5 step 7, then `Uninstall` at teardown step 3. The struct
// is safe for concurrent Install / Uninstall calls (the mutex
// serializes them) but the canonical use is single-threaded.
type Lifecycle struct {
	opts Options
	mu   sync.Mutex

	// installed is true between a successful Install and a
	// completed Uninstall. A second Install fails with
	// `ErrChainAlreadyExists` even on the same Lifecycle so a
	// buggy supervisor cannot double-install.
	installed bool

	// driver is the per-platform rule driver. The Linux build
	// tag wires it to the iptables driver; the macOS build tag
	// wires the pf driver; the non-Linux/non-Darwin stub wires
	// the unsupported-os driver.
	driver ruleDriver
}

// ruleDriver is the per-platform install / uninstall contract.
// One driver per OS; the cross-platform Lifecycle wraps the
// chosen driver. The interface is package-private because
// callers only ever hold a Lifecycle.
type ruleDriver interface {
	// Mode reports the lifecycle verb Metadata token.
	Mode() Mode

	// Exists checks whether a chain / pf anchor with the given
	// name already exists. Used by Install to refuse to
	// overwrite and by Uninstall to surface ErrChainNotFound.
	Exists(ctx context.Context, cmd Commander, chain string) (bool, error)

	// Install creates the chain and inserts the rules. The
	// driver is responsible for unwinding partial state on
	// error; the cross-platform Lifecycle does not see the
	// half-built chain.
	Install(ctx context.Context, cmd Commander, opts Options) error

	// Uninstall removes the chain and its rules. Idempotent:
	// removing a non-existent chain returns ErrChainNotFound.
	Uninstall(ctx context.Context, cmd Commander, chain string) error
}

// New constructs a Lifecycle from the supplied options. It
// validates the chain name and binds the platform driver.
func New(opts Options) (*Lifecycle, error) {
	if !ChainNameRegexp.MatchString(opts.Chain) {
		return nil, fmt.Errorf("egress/rules: invalid chain name %q (want %s)", opts.Chain, ChainNameRegexp.String())
	}
	if len(opts.Chain) > MaxChainLength {
		return nil, fmt.Errorf("egress/rules: chain %q exceeds MaxChainLength %d", opts.Chain, MaxChainLength)
	}
	if opts.Verdict == "" {
		opts.Verdict = VerdictReject
	}
	if opts.Verdict != VerdictReject && opts.Verdict != VerdictPass {
		return nil, fmt.Errorf("egress/rules: unknown verdict %q", opts.Verdict)
	}
	driver := platformDriver()
	return &Lifecycle{opts: opts, driver: driver}, nil
}

// Mode reports the per-platform mode token the lifecycle records
// on its lifecycle-verb callbacks. The supervisor stamps this
// onto `observer_started` Metadata.
func (l *Lifecycle) Mode() Mode {
	if l.driver == nil {
		return ModeUnsupported
	}
	return l.driver.Mode()
}

// Chain returns the per-run chain name.
func (l *Lifecycle) Chain() string { return l.opts.Chain }

// Install creates the chain / pf anchor, inserts the per-rule
// log + verdict, and emits the OnInstalled callback. The flow
// is:
//
//  1. Validate the platform driver.
//  2. Check the chain does not already exist (refuse overwrite).
//  3. Delegate to the driver's Install for the actual work.
//  4. Record the installed state, fire OnInstalled.
//
// On any step's failure the lifecycle attempts a best-effort
// rollback via the driver's Uninstall and returns the original
// error. The supervisor's crash-recovery handler relies on the
// rollback so a partial install does not leak rules.
func (l *Lifecycle) Install(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.installed {
		return ErrChainAlreadyExists
	}
	if l.driver == nil {
		return ErrUnsupportedOS
	}
	cmd := l.commander()

	exists, err := l.driver.Exists(ctx, cmd, l.opts.Chain)
	if err != nil {
		return fmt.Errorf("check chain exists: %w", err)
	}
	if exists {
		return ErrChainAlreadyExists
	}

	if err := l.driver.Install(ctx, cmd, l.opts); err != nil {
		// Best-effort rollback. If Uninstall also fails we
		// surface the original Install error (the supervisor
		// cares more about why Install failed than why the
		// rollback could not finish; the rollback failure is
		// surfaced via OnUninstalled with reason="rollback_failed"
		// in a future enhancement).
		_ = l.driver.Uninstall(ctx, cmd, l.opts.Chain)
		return fmt.Errorf("install rules: %w", err)
	}
	l.installed = true
	if l.opts.OnInstalled != nil {
		l.opts.OnInstalled(l.opts.Chain, l.driver.Mode())
	}
	return nil
}

// Uninstall removes the chain / pf anchor and emits
// OnUninstalled with the supplied reason. Idempotent: a second
// Uninstall after the chain was already removed returns
// ErrChainNotFound without firing the callback (the supervisor
// has already recorded `observer_stopped`).
//
// reason is the short token recorded in OnUninstalled (e.g.
// "teardown" / "error" / "rollback"). Empty defaults to
// "teardown" so the common path stays terse.
func (l *Lifecycle) Uninstall(ctx context.Context, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.driver == nil {
		return ErrUnsupportedOS
	}
	cmd := l.commander()
	if !l.installed {
		// Caller may invoke Uninstall on a Lifecycle that was
		// never installed (e.g. a strict-mode abort before
		// step 7). We probe Exists so a real stale chain from
		// a prior crashed run is still removed.
		exists, err := l.driver.Exists(ctx, cmd, l.opts.Chain)
		if err != nil {
			return fmt.Errorf("check chain exists: %w", err)
		}
		if !exists {
			return ErrChainNotFound
		}
	}
	if err := l.driver.Uninstall(ctx, cmd, l.opts.Chain); err != nil {
		return fmt.Errorf("uninstall rules: %w", err)
	}
	l.installed = false
	if reason == "" {
		reason = "teardown"
	}
	if l.opts.OnUninstalled != nil {
		l.opts.OnUninstalled(l.opts.Chain, l.driver.Mode(), reason)
	}
	return nil
}

// Installed reports whether the lifecycle currently holds an
// installed chain. Used by tests to assert the state after Stop /
// rollback.
func (l *Lifecycle) Installed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.installed
}

// commander returns the active Commander for the lifecycle: the
// caller-supplied one when set, the platform default otherwise.
func (l *Lifecycle) commander() Commander {
	if l.opts.Commander != nil {
		return l.opts.Commander
	}
	return platformCommander()
}

// describeChain returns a short human-readable string the
// callbacks pass back to the supervisor for diagnostic logging.
// Defined here rather than in the driver files because every
// driver wants the same shape.
func describeChain(chain string, m Mode) string {
	return strings.TrimSpace(fmt.Sprintf("%s(%s)", m, chain))
}

// unusedDescribeChain keeps describeChain referenced even when no
// driver currently uses it (the stub driver path). A future
// driver enhancement plugs the helper in without rewiring the
// import graph.
var _ = describeChain
