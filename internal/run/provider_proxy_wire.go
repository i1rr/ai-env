// provider_proxy_wire.go implements Plan Batch 2.3 — Supervisor starts
// ProviderProxy(es). The supervisor takes a slice of
// *secrets.ProviderProxy via SupervisorOptions.ProviderProxies, starts
// each one as part of the canonical pre-launch sequence (Plan §5.5
// step 8), emits a `proxy_started` lifecycle verb per proxy with the
// metadata table documented in lifecycle_verbs.go, and tears them
// down in reverse order during finalize (teardown step 5) with a
// matching `proxy_stopped` verb.
//
// Failure semantics:
//
//   - A bind failure on any proxy is fail-closed per the plan's
//     Bucket 2 locked decision ("Hard fail-closed on unreachable").
//     The supervisor stops every already-started proxy, transitions
//     to StateFailedPolicy (the state machine's StateApplyingPolicy
//     window allows that terminal; the proxy bind is wired as a
//     policy-install component because the per-proxy carve-outs are
//     installed alongside the egress rules at the same step), and
//     surfaces the error via StopReasonPolicyFailure. Plan rationale:
//     a missing proxy means the agent cannot reach the model
//     provider; silently continuing would force the agent into the
//     network-policy egress denylist path, which is exactly the
//     silent-degrade the plan forbids.
//
//   - A stop failure during teardown is logged via the lifecycle
//     writer with reason="error" and otherwise ignored. The run's
//     terminal state has already been decided; an out-of-band proxy
//     stop failure cannot un-fail it.
//
// The verb's "reachability" metadata field carries the bind mode
// stringified — "setns_tcp" / "bridge_gateway" / "unix_socket" /
// "loopback" — so a reviewer can correlate the run's proxy reach
// surface to the capability picker's decision.
package run

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rivan1986/ai-env/internal/secrets"
)

// startProviderProxies starts each proxy in opts.ProviderProxies in
// order, emits a `proxy_started` lifecycle verb per successful start,
// and returns the slice of started proxies so the caller can stop them
// in reverse order during finalize.
//
// On the first bind failure, the helper stops every already-started
// proxy (emitting `proxy_stopped` with reason="error" for each) and
// returns the wrapped error so the caller can transition to
// StateFailedBackend. This is the plan's "fail-closed on unreachable"
// rule: a missing proxy is treated as a backend-level failure, not a
// soft degrade.
//
// Emits one `proxy_started` verb per successful start with the
// metadata table documented on LifecycleVerbProxyStarted:
//
//   - "provider"      — the proxy's Provider() value
//   - "listen_addr"   — the proxy's ListenAddr() (host:port for TCP,
//     socket path for UnixSocket)
//   - "upstream_host" — the proxy's UpstreamHost() (the canonical
//     provider host the upstream-Host allowlist
//     pins)
//   - "reachability"  — the proxy's BindMode() stringified
//
// Returns the started proxies slice so the caller can pass it to
// stopProviderProxies on the terminal path.
func (s *Supervisor) startProviderProxies() ([]*secrets.ProviderProxy, error) {
	if len(s.opts.ProviderProxies) == 0 {
		return nil, nil
	}
	started := make([]*secrets.ProviderProxy, 0, len(s.opts.ProviderProxies))
	for i, proxy := range s.opts.ProviderProxies {
		if proxy == nil {
			// Roll back any started proxies before surfacing the
			// configuration error; a nil entry is a programming
			// mistake but the supervisor must not leak listeners.
			s.stopStartedProxies(started)
			return nil, fmt.Errorf("run: ProviderProxies[%d] is nil", i)
		}
		if err := proxy.Start(); err != nil {
			// Bind failure on this proxy: stop every already-started
			// proxy and surface the error so the caller fails the
			// run closed.
			s.stopStartedProxies(started)
			return nil, fmt.Errorf("run: start provider proxy %q: %w", proxy.Provider(), err)
		}
		started = append(started, proxy)
		if err := s.emitProxyStarted(proxy); err != nil {
			// Lifecycle write failure during start is fatal: the
			// run's audit trail must record every proxy_started
			// verb. Stop everything and fail closed.
			s.stopStartedProxies(started)
			return nil, fmt.Errorf("run: emit proxy_started for %q: %w", proxy.Provider(), err)
		}
	}
	return started, nil
}

// stopProviderProxies stops each proxy in reverse order, emitting a
// `proxy_stopped` lifecycle verb per stop. Errors from Stop are
// captured in the verb's "reason" field as "error"; a successful stop
// records reason="teardown". The helper does NOT short-circuit on a
// single failure: every proxy must be asked to stop on the terminal
// path so a stuck downstream proxy does not block its peers.
//
// The reason argument lets the caller distinguish the canonical
// teardown path (reason="teardown") from the fail-closed error path
// (reason="error" / "shutdown") — the plan's per-verb metadata table
// pins those tokens.
func (s *Supervisor) stopProviderProxies(proxies []*secrets.ProviderProxy, baseReason string) {
	if len(proxies) == 0 {
		return
	}
	if baseReason == "" {
		baseReason = "teardown"
	}
	// Reverse iteration so the most-recently-started proxy is stopped
	// first; mirrors the canonical teardown order in Plan §5.5.
	for i := len(proxies) - 1; i >= 0; i-- {
		proxy := proxies[i]
		if proxy == nil {
			continue
		}
		reason := baseReason
		if err := proxy.Stop(); err != nil {
			reason = "error"
		}
		_ = s.emitProxyStopped(proxy, reason)
	}
}

// stopStartedProxies is the rollback helper invoked on a fail-closed
// bind. It stops every already-started proxy and emits
// `proxy_stopped` with reason="error" so a reviewer can correlate the
// per-proxy unwind to the bind failure that triggered it. Errors are
// swallowed: the supervisor has already decided to fail the run.
func (s *Supervisor) stopStartedProxies(started []*secrets.ProviderProxy) {
	s.stopProviderProxies(started, "error")
}

// emitProxyStarted writes the proxy_started lifecycle verb. Returns
// the lifecycle writer's error verbatim so startProviderProxies can
// fail-closed on a writer outage; the audit record must be durable
// before the supervisor proceeds to the next step.
func (s *Supervisor) emitProxyStarted(proxy *secrets.ProviderProxy) error {
	if s.lcWri == nil {
		return errors.New("run: emit proxy_started requires a lifecycle writer")
	}
	mode := strings.TrimSpace(string(proxy.BindMode()))
	if mode == "" {
		mode = "loopback"
	}
	return s.lcWri.WriteVerb(LifecycleVerbProxyStarted, map[string]string{
		"provider":      proxy.Provider(),
		"listen_addr":   proxy.ListenAddr(),
		"upstream_host": proxy.UpstreamHost(),
		"reachability":  mode,
	})
}

// emitProxyStopped writes the proxy_stopped lifecycle verb. Errors
// from the writer are returned but the caller (stopProviderProxies)
// swallows them: the run has already decided its terminal and a
// downstream audit failure cannot un-decide it.
func (s *Supervisor) emitProxyStopped(proxy *secrets.ProviderProxy, reason string) error {
	if s.lcWri == nil {
		return errors.New("run: emit proxy_stopped requires a lifecycle writer")
	}
	if reason == "" {
		reason = "teardown"
	}
	return s.lcWri.WriteVerb(LifecycleVerbProxyStopped, map[string]string{
		"provider": proxy.Provider(),
		"reason":   reason,
	})
}
