// Package egress owns the foundational scaffolding for ai-env's
// per-run EgressObserver. The observer is the host-side packet-log
// reader the supervisor attaches at Plan §5.5 step 5 (post
// `backend.Start`, once the sandbox netns exists) and detaches at
// teardown step 4. Two concrete observers will land in subsequent
// batches:
//
//   - Batch 5.2 (Linux NFLOG) — `florianl/go-nflog/v2` reader attached
//     inside the sandbox netns via `containernetworking/plugins/pkg/ns`.
//   - Batch 5.3 (macOS pflog) — `tcpdump`-on-`pflog0` adapter.
//
// This package (Batch 5.0 + Batch 5.1) introduces two contract-only
// surfaces both of those concrete observers — and the supervisor that
// composes them — depend on:
//
//   - `EgressObserverMode` (Batch 5.0): a typed string that names the
//     operator's chosen behaviour when the host cannot start an
//     observer. The plan locks three values (Auto / Strict / Disabled);
//     the picker `ResolveStartDecision` codifies the per-mode rule the
//     plan's acceptance criterion #8 (`--observer-mode strict aborts
//     without CAP_NET_ADMIN; auto (default) succeeds`) encodes.
//
//   - `EgressObserver` (Batch 5.1): the per-platform interface every
//     observer adapter implements. The supervisor depends only on this
//     interface so the Linux and macOS paths can land independently
//     (Batch 5.2 / 5.3) and a future third platform (e.g. eBPF on a
//     newer kernel) drops in without touching the supervisor.
//
// Design rules this package enforces (mirrored from the parent
// capability package's design rules for consistency):
//
//   - No I/O at construction. `EgressObserverMode` is pure data; the
//     picker is a pure function. The interface defines `Start`/`Stop`
//     as the only side-effecting verbs; constructing an observer
//     adapter (in 5.2 / 5.3) must not open sockets or shell out.
//
//   - Tokens are plan-pinned. Every short-token string this package
//     emits (mode values, `StartDecision` outcomes, unavailable
//     reasons) is exported as a constant and pinned in a test so a
//     downstream reader (lifecycle.jsonl walker, `ai-env doctor`
//     remediation table) can grep against the canonical name.
//
//   - The interface is intentionally small. `Start`, `Stop`, `Mode`,
//     and `Chain` are the only methods the supervisor calls. Per-
//     packet event delivery is the responsibility of the concrete
//     observer's constructor wiring (it takes a writer / sink at
//     construction); the interface itself stays minimal so a test
//     fake is a 30-line struct.
//
// The package has no external dependencies beyond the standard library
// and `internal/capability`; it builds on every platform.
package egress

import (
	"context"
	"fmt"

	"github.com/i1rr/ai-env/internal/capability"
)

// EgressObserverMode is the operator-configured policy that decides
// what the supervisor does when the host cannot start an observer.
// Plan §5.0 ("EgressObserverMode") introduces the typed string; the
// plan's acceptance criterion #8 pins the per-mode semantics.
//
// The mode is set via `--observer-mode` on `ai-env run` (and the
// matching field on the workspace `policy.yaml`'s `network` block when
// per-workspace defaults land). The supervisor parses the operator's
// string into this type via `ParseEgressObserverMode`; an unknown
// value is a hard error so a typo in policy.yaml fails fast rather
// than silently degrading to a permissive default.
//
// The three legal values, and the per-mode behaviour the picker
// (`ResolveStartDecision`, below) returns:
//
//   - `EgressObserverModeAuto` (default; matches the plan's "default
//     Auto" locked decision in Bucket 5 row): try to start the
//     observer; if `capability.ObserverModeAvailable()` is false, emit
//     `observer_unavailable` and continue the run. This is the
//     dev-machine default so a host without CAP_NET_ADMIN can still
//     run `ai-env`.
//
//   - `EgressObserverModeStrict` (production posture; matches
//     acceptance criterion #8): require the observer. If
//     `capability.ObserverModeAvailable()` is false, the supervisor
//     aborts before `backend.Start` (Plan §5.5 step 5 fails) and the
//     run record is finalized with the unavailable reason. Operators
//     who care about network-level evidence set strict in production.
//
//   - `EgressObserverModeDisabled`: skip the observer entirely. The
//     supervisor does not call `Start`, does not emit
//     `observer_unavailable` (because the operator's policy is "don't
//     try"), and the lifecycle verb the run records instead is
//     `observer_stopped` with reason="disabled" at teardown. This
//     mode exists so a fleet operator who knows the host cannot
//     attach an observer (e.g. macOS Apple Silicon without `/dev/pf`
//     access) can suppress the per-run `observer_unavailable` noise.
//
// The underlying string is the on-disk / on-wire token: lower-case,
// single word, matches the value the operator types on the command
// line. Adding a new mode (e.g. `"shadow"`) is one constant + one
// switch arm in `ResolveStartDecision` + one entry in the parser.
type EgressObserverMode string

const (
	// EgressObserverModeAuto is the default: best-effort observer
	// start, graceful degradation when the host capability probe
	// reports unavailable. The supervisor emits the
	// `observer_unavailable` lifecycle verb (Plan Batch 0.1) and
	// continues the run.
	EgressObserverModeAuto EgressObserverMode = "auto"

	// EgressObserverModeStrict is the production posture: refuse to
	// start the run when the host capability probe reports
	// unavailable. The supervisor records the unavailable reason and
	// aborts before step 5; no `backend.Exec` is invoked.
	EgressObserverModeStrict EgressObserverMode = "strict"

	// EgressObserverModeDisabled suppresses the observer entirely:
	// no attach attempt, no `observer_unavailable` verb (the
	// operator's policy is "don't try"). The supervisor records
	// `observer_stopped` reason="disabled" at teardown so the audit
	// trail still notes the chosen posture.
	EgressObserverModeDisabled EgressObserverMode = "disabled"
)

// DefaultEgressObserverMode is the value the supervisor uses when the
// operator does not specify `--observer-mode` and the workspace
// policy does not pin a value. Plan Bucket 5 row: "EgressObserverMode
// default Auto."
const DefaultEgressObserverMode = EgressObserverModeAuto

// ParseEgressObserverMode converts an operator-supplied string to the
// typed mode. Empty input maps to the default (matches the supervisor
// not passing the flag); unknown input is a hard error so a typo in
// policy.yaml fails fast.
//
// The parser is case-insensitive on the input token (operators
// frequently capitalise mode names in config files) but the canonical
// stored value is always lower-case so on-disk JSON / lifecycle
// records use one spelling regardless of the operator's casing.
func ParseEgressObserverMode(s string) (EgressObserverMode, error) {
	switch s {
	case "":
		return DefaultEgressObserverMode, nil
	case string(EgressObserverModeAuto), "Auto", "AUTO":
		return EgressObserverModeAuto, nil
	case string(EgressObserverModeStrict), "Strict", "STRICT":
		return EgressObserverModeStrict, nil
	case string(EgressObserverModeDisabled), "Disabled", "DISABLED":
		return EgressObserverModeDisabled, nil
	default:
		return "", fmt.Errorf("egress: unknown observer mode %q (want one of %q, %q, %q)",
			s,
			string(EgressObserverModeAuto),
			string(EgressObserverModeStrict),
			string(EgressObserverModeDisabled),
		)
	}
}

// Valid reports whether the mode is one of the plan-pinned constants.
// The zero-value `""` is not valid (a zero-value mode indicates a
// supervisor code path that forgot to apply the default — that's a
// regression we want surfaced at the call site rather than silently
// papered over).
func (m EgressObserverMode) Valid() bool {
	switch m {
	case EgressObserverModeAuto, EgressObserverModeStrict, EgressObserverModeDisabled:
		return true
	default:
		return false
	}
}

// String returns the canonical on-wire token. It mirrors the
// underlying type so callers can `fmt.Sprintf("%s", mode)` without an
// explicit cast.
func (m EgressObserverMode) String() string {
	return string(m)
}

// StartDecision is the outcome the per-mode picker returns when the
// supervisor asks "given this host capability snapshot and this
// configured mode, what do I do at Plan §5.5 step 5?". The
// supervisor's step-5 code branches on this enum exactly once; the
// picker (`ResolveStartDecision`) owns the per-mode rule so the
// supervisor stays a single switch.
//
// The four outcomes mirror the operator-visible behaviours the plan
// locks in Bucket 5 + acceptance criterion #8:
//
//   - `StartDecisionAttach` — start the observer (Linux NFLOG attach
//     or macOS pflog attach, picked by `ChooseObserver` in a future
//     batch). The supervisor expects `Start` to succeed; failure is a
//     run abort under strict, a `observer_unavailable` emission under
//     auto.
//
//   - `StartDecisionSkipUnavailable` — do not attach; emit
//     `observer_unavailable` with the capability-supplied reason; the
//     run continues. Only `EgressObserverModeAuto` ever resolves to
//     this outcome.
//
//   - `StartDecisionSkipDisabled` — do not attach; do NOT emit
//     `observer_unavailable` (the operator chose to suppress the
//     observer). The supervisor records `observer_stopped`
//     reason="disabled" at teardown so the policy choice is in the
//     audit trail. Only `EgressObserverModeDisabled` resolves here.
//
//   - `StartDecisionAbort` — abort the run before step 5. The reason
//     surfaces in the run's final summary; no `backend.Exec` is
//     called. Only `EgressObserverModeStrict` resolves to this
//     outcome (and only when the capability probe reports
//     unavailable).
type StartDecision string

const (
	// StartDecisionAttach instructs the supervisor to call
	// `EgressObserver.Start`. The chosen platform observer is picked
	// elsewhere (Batch 5.2 / 5.3); this decision is purely "yes,
	// attempt the attach".
	StartDecisionAttach StartDecision = "attach"

	// StartDecisionSkipUnavailable instructs the supervisor to skip
	// the attach and emit the `observer_unavailable` lifecycle verb
	// (Plan Batch 0.1) with `Reason` populated from
	// `capability.ObserverUnavailableReason()`.
	StartDecisionSkipUnavailable StartDecision = "skip_unavailable"

	// StartDecisionSkipDisabled instructs the supervisor to skip the
	// attach and NOT emit `observer_unavailable` (the operator's
	// policy is "disabled"). The run continues silently with respect
	// to the observer.
	StartDecisionSkipDisabled StartDecision = "skip_disabled"

	// StartDecisionAbort instructs the supervisor to abort the run
	// at step 5 with the unavailable reason as the abort cause. The
	// supervisor must NOT call `backend.Exec`.
	StartDecisionAbort StartDecision = "abort"
)

// String mirrors the underlying token for `fmt.Sprintf` ergonomics.
func (d StartDecision) String() string { return string(d) }

// ResolveStartDecision is the pure picker the supervisor calls at
// Plan §5.5 step 5 to translate (configured mode, host capability
// snapshot) into a `StartDecision`. The function is intentionally
// pure (no I/O, no logging) so a test can pin every per-mode +
// per-capability cell without a host environment.
//
// The semantics encode the plan's locked rules:
//
//	mode=disabled                      -> skip_disabled
//	mode=auto    + available=true      -> attach
//	mode=auto    + available=false     -> skip_unavailable
//	mode=strict  + available=true      -> attach
//	mode=strict  + available=false     -> abort
//
// An unknown / zero-value mode is treated as auto, but the function
// also surfaces a non-nil error so the supervisor can log a
// regression-grade message at the call site. The decision is
// returned regardless of the error so the caller stays on a single
// happy path; the error is the audit hook.
func ResolveStartDecision(mode EgressObserverMode, cap capability.Capability) (StartDecision, error) {
	if !mode.Valid() {
		// Unknown mode: behave like auto so the run still has a
		// chance to produce evidence, but surface the regression to
		// the supervisor so it can log a `helper_rpc_aborted`-style
		// audit entry. The supervisor's step-5 handler treats the
		// returned decision as authoritative and the error as a
		// diagnostic.
		mode = DefaultEgressObserverMode
		if cap.ObserverModeAvailable() {
			return StartDecisionAttach, fmt.Errorf("egress: unknown observer mode treated as %q", DefaultEgressObserverMode)
		}
		return StartDecisionSkipUnavailable, fmt.Errorf("egress: unknown observer mode treated as %q", DefaultEgressObserverMode)
	}
	if mode == EgressObserverModeDisabled {
		return StartDecisionSkipDisabled, nil
	}
	if cap.ObserverModeAvailable() {
		return StartDecisionAttach, nil
	}
	if mode == EgressObserverModeStrict {
		return StartDecisionAbort, nil
	}
	// mode == EgressObserverModeAuto here: degrade gracefully.
	return StartDecisionSkipUnavailable, nil
}

// EgressObserver is the per-platform interface the supervisor depends
// on to attach / detach a packet-log reader to the sandbox's netns.
// Plan Batch 5.1 introduces the interface; concrete adapters land in
// Batch 5.2 (Linux NFLOG) and Batch 5.3 (macOS pflog).
//
// Construction is the responsibility of the platform-specific
// constructor (e.g. `egress/nflog.New(...)`). The constructor takes
// every per-run input the observer needs (the network-events.jsonl
// writer / sink, the per-run chain name, the netns path, etc.) so
// the interface itself stays narrow. Callers obtain a constructed
// observer from `ChooseObserver` (added in a future batch) and pass
// it to the supervisor.
//
// Lifecycle: `Start(ctx)` blocks only long enough to bind the kernel
// surface (NFLOG socket / pflog `tcpdump` child) and start the
// background reader goroutine; it returns once the observer is ready
// to receive packets. `Stop()` is idempotent and returns only after
// the background goroutine has drained pending events; double-close
// is a no-op so the supervisor's teardown can call it in any order
// relative to context cancellation.
//
// The interface is intentionally small. The supervisor:
//
//  1. Asks `Mode()` for the lifecycle verb metadata ("nflog" /
//     "pflog") so the `observer_started` event records which adapter
//     attached.
//  2. Asks `Chain()` for the iptables / pf chain name the observer
//     will pull packets from; the rule-installation step (Batch 5.4)
//     uses this same name so the two halves agree.
//  3. Calls `Start(ctx)` once at Plan §5.5 step 5.
//  4. Calls `Stop()` once at Plan §5.5 teardown step 4.
//
// No method returns per-packet data on the interface itself; per-
// packet events flow through the network-events writer the
// constructor wired in. This keeps the interface stable across
// adapters that internally model packets differently.
type EgressObserver interface {
	// Mode returns the short token for the lifecycle event metadata.
	// Plan Batch 0.1 `observer_started` Metadata key `mode`: one of
	// "nflog" / "pflog". The constant lives on the adapter so a
	// test fake can return any short string and assert the
	// supervisor wrote that token verbatim.
	Mode() string

	// Chain returns the per-run iptables / pf chain name the
	// observer pulls packets from. Plan §5.5 step 7 installs the
	// rules into the same chain; the observer and the rule-
	// installer must agree on the name. Format: `AIENV-EGR-<8hex>`,
	// 8 hex chars derived from the run ID so concurrent runs do
	// not collide.
	Chain() string

	// Start binds the kernel surface and begins forwarding packets
	// to the constructor-supplied sink. Returns once the observer
	// is ready; the background reader goroutine continues until
	// Stop is called. The context is the supervisor's run context;
	// cancellation triggers an internal shutdown equivalent to
	// Stop but without waiting for the caller to call Stop
	// explicitly.
	//
	// Start MUST be called inside the sandbox netns (Linux
	// adapters use `ns.WithNetNSPath` for this). On macOS the
	// observer attaches host-side (pflog is a host interface) so
	// the netns wrapping is a no-op.
	//
	// Start returns nil only on a successful attach; any error is
	// final (the supervisor degrades per the configured
	// `EgressObserverMode`).
	Start(ctx context.Context) error

	// Stop tears down the kernel surface and waits for the
	// background reader goroutine to drain any in-flight events.
	// Idempotent: a second call is a no-op. The supervisor calls
	// Stop at Plan §5.5 teardown step 4, before stopping the
	// ProviderProxy (step 5) so any final egress decisions are
	// captured.
	Stop() error
}
