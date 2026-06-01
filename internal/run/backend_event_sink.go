// BackendEventSink adapter over LifecycleWriter.
//
// Plan §0.5 introduces `backend.BackendEventSink` so non-supervisor
// code paths (e.g. a backend adapter that observes a policy
// degradation while applying iptables rules) can record audit-relevant
// events through the same writer the supervisor owns. Plan §10 row 10
// (`network_policy_degraded`) names the canonical use case: the
// adapter emits via `BackendEventSink` rather than coupling itself to
// the run package's concrete LifecycleWriter type.
//
// This file is the production adapter the supervisor hands to its
// adapters. It is a one-method type that converts a string verb +
// metadata into a `LifecycleWriter.WriteVerb` call. Keeping the
// adapter in the run package (rather than in backend/) avoids forcing
// the backend package to depend on lifecycle.go; the supervisor wires
// the adapter at construction time and the backend package only sees
// the interface.
//
// The adapter is goroutine-safe: WriteVerb on the underlying
// LifecycleWriter already serializes writes under a mutex (see
// lifecycle.go writeEvent). Multiple adapters / observers can share a
// single sink instance.

package run

import (
	"errors"

	"github.com/rivan1986/ai-env/internal/backend"
)

// Compile-time check that LifecycleWriterBackendEventSink satisfies
// the backend.BackendEventSink interface. If the interface signature
// drifts in a future plan batch this line refuses to compile.
var _ backend.BackendEventSink = (*LifecycleWriterBackendEventSink)(nil)

// LifecycleWriterBackendEventSink is a thin adapter that exposes a
// `backend.BackendEventSink` over a `*LifecycleWriter`. The supervisor
// constructs one at startup and hands it to any code path (typically a
// backend adapter or a policy installer) that needs to emit lifecycle
// verbs without learning about the LifecycleWriter type directly.
//
// A nil writer is tolerated: Emit becomes a no-op so a caller that
// wires the sink unconditionally does not have to nil-check the
// supervisor's writer. Production supervisors always have a non-nil
// writer; the nil tolerance is a test convenience.
type LifecycleWriterBackendEventSink struct {
	writer *LifecycleWriter
}

// NewLifecycleWriterBackendEventSink constructs an adapter over the
// supplied lifecycle writer. A nil writer is legal — see the type
// comment for the no-op semantics.
func NewLifecycleWriterBackendEventSink(w *LifecycleWriter) *LifecycleWriterBackendEventSink {
	return &LifecycleWriterBackendEventSink{writer: w}
}

// Emit implements backend.BackendEventSink by forwarding the verb +
// metadata to the underlying LifecycleWriter.WriteVerb. The verb is a
// plain string here per the BackendEventSink contract (the backend
// package cannot import the run package's LifecycleVerb type without
// an import cycle); the adapter wraps the string in a LifecycleVerb
// value before calling through.
//
// An empty verb is rejected with an error so a caller that forgets to
// supply one sees the failure immediately, matching the LifecycleWriter
// rule. A nil writer is silently no-op (see the type comment).
func (s *LifecycleWriterBackendEventSink) Emit(verb string, metadata map[string]string) error {
	if s == nil || s.writer == nil {
		return nil
	}
	if verb == "" {
		return errors.New("run: BackendEventSink Emit requires non-empty verb")
	}
	return s.writer.WriteVerb(LifecycleVerb(verb), metadata)
}

// BackendEventSink returns the BackendEventSink adapter over the
// supervisor's lifecycle writer. Adapters that need to emit lifecycle
// verbs (e.g. a NetworkPolicyAdapter that observes a partial-policy
// install) consume this rather than reaching into the supervisor's
// internals.
//
// Plan §10 row 10 names this as the canonical surface a network policy
// adapter uses to emit `network_policy_degraded` when it cannot enforce
// the configured policy in full but proceeds anyway. The supervisor
// itself emits the same verb directly via its lcWri for the two paths
// it owns (observer auto-mode failure, rules.ErrUnsupportedOS skip);
// the BackendEventSink is the seam for any future emitter that lives
// outside the supervisor goroutine.
func (s *Supervisor) BackendEventSink() backend.BackendEventSink {
	return NewLifecycleWriterBackendEventSink(s.lcWri)
}
