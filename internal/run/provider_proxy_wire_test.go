package run

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/secrets"
)

// readLifecycleVerbs parses lifecycle.jsonl and returns the lifecycle
// events whose Verb field matches one of the supplied targets. Used by
// the proxy-wire tests so we can assert on the Metadata table the
// plan's Batch 0.1 pins for proxy_started / proxy_stopped.
func readLifecycleVerbs(t *testing.T, runDir string, targets ...LifecycleVerb) []LifecycleEvent {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(runDir, "lifecycle.jsonl"))
	if err != nil {
		t.Fatalf("read lifecycle.jsonl: %v", err)
	}
	want := make(map[LifecycleVerb]struct{}, len(targets))
	for _, v := range targets {
		want[v] = struct{}{}
	}
	var out []LifecycleEvent
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var evt LifecycleEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("parse lifecycle line %q: %v", line, err)
		}
		if _, ok := want[evt.Verb]; ok {
			out = append(out, evt)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan lifecycle: %v", err)
	}
	return out
}

// newTestProviderProxy builds a ProviderProxy bound to loopback for
// the supervisor wire tests. The test does not exercise upstream
// traffic — only the Start / Stop lifecycle and the verb metadata —
// so a default loopback bind is enough.
func newTestProviderProxy(t *testing.T, provider, token string) *secrets.ProviderProxy {
	t.Helper()
	p, err := secrets.NewProviderProxy(secrets.Options{
		Provider:        provider,
		Token:           token,
		ShutdownTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewProviderProxy: %v", err)
	}
	return p
}

// TestSupervisor_ProviderProxies_StartedAndStoppedInOrder verifies the
// supervisor starts each configured ProviderProxy as part of the
// canonical pre-launch sequence, emits one proxy_started lifecycle
// verb per proxy with the documented metadata keys, and stops them in
// reverse order during finalize with matching proxy_stopped verbs.
func TestSupervisor_ProviderProxies_StartedAndStoppedInOrder(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)

	antProxy := newTestProviderProxy(t, secrets.ProviderAnthropic, "sk-ant-supervisor-aaaaaaaaaaaaaaaaa")
	oaProxy := newTestProviderProxy(t, secrets.ProviderOpenAI, "sk-openai-supervisor-bbbbbbbbbbbbbbb")

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "proxy-wire",
		Task:              "ProviderProxy wire test",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		ProviderProxies:   []*secrets.ProviderProxy{antProxy, oaProxy},
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateCompleted {
		t.Fatalf("FinalState = %q, want %q", result.FinalState, StateCompleted)
	}

	// proxy_started verbs: one per proxy, in the order the supervisor
	// was given them.
	started := readLifecycleVerbs(t, dir.Path, LifecycleVerbProxyStarted)
	if len(started) != 2 {
		t.Fatalf("proxy_started verbs = %d, want 2", len(started))
	}
	if started[0].Metadata["provider"] != secrets.ProviderAnthropic {
		t.Errorf("started[0] provider = %q, want %q", started[0].Metadata["provider"], secrets.ProviderAnthropic)
	}
	if started[1].Metadata["provider"] != secrets.ProviderOpenAI {
		t.Errorf("started[1] provider = %q, want %q", started[1].Metadata["provider"], secrets.ProviderOpenAI)
	}
	// Required metadata keys per LifecycleVerbProxyStarted's table.
	for i, evt := range started {
		for _, key := range []string{"provider", "listen_addr", "upstream_host", "reachability"} {
			if evt.Metadata[key] == "" {
				t.Errorf("started[%d] missing metadata key %q (got %#v)", i, key, evt.Metadata)
			}
		}
		// The default BindMode is loopback (test proxies didn't set
		// one); the reachability metadata must reflect that.
		if evt.Metadata["reachability"] != "loopback" {
			t.Errorf("started[%d] reachability = %q, want loopback", i, evt.Metadata["reachability"])
		}
	}
	// Upstream hosts must match the canonical per-provider pins.
	if started[0].Metadata["upstream_host"] != "api.anthropic.com" {
		t.Errorf("anthropic upstream_host = %q, want api.anthropic.com", started[0].Metadata["upstream_host"])
	}
	if started[1].Metadata["upstream_host"] != "api.openai.com" {
		t.Errorf("openai upstream_host = %q, want api.openai.com", started[1].Metadata["upstream_host"])
	}

	// proxy_stopped verbs: one per proxy, in REVERSE order (openai
	// stops before anthropic) per the canonical teardown sequence.
	stopped := readLifecycleVerbs(t, dir.Path, LifecycleVerbProxyStopped)
	if len(stopped) != 2 {
		t.Fatalf("proxy_stopped verbs = %d, want 2", len(stopped))
	}
	if stopped[0].Metadata["provider"] != secrets.ProviderOpenAI {
		t.Errorf("stopped[0] provider = %q, want %q (reverse order)", stopped[0].Metadata["provider"], secrets.ProviderOpenAI)
	}
	if stopped[1].Metadata["provider"] != secrets.ProviderAnthropic {
		t.Errorf("stopped[1] provider = %q, want %q", stopped[1].Metadata["provider"], secrets.ProviderAnthropic)
	}
	// Clean terminal: reason = "teardown".
	for i, evt := range stopped {
		if evt.Metadata["reason"] != "teardown" {
			t.Errorf("stopped[%d] reason = %q, want teardown", i, evt.Metadata["reason"])
		}
	}
}

// stubFailingProxy is a tiny test seam that satisfies the same
// Start/Stop surface as *secrets.ProviderProxy but always returns an
// error from Start. It exists because the real ProviderProxy validates
// at construction; we want a clean way to inject a guaranteed bind
// failure without spinning up a port that is genuinely occupied.
// Since SupervisorOptions.ProviderProxies is typed as
// []*secrets.ProviderProxy, we cannot inject the stub via the public
// surface — instead we deliberately collide a pinned ListenAddr.

// TestSupervisor_ProviderProxies_BindFailureFailsClosed verifies the
// plan's "Hard fail-closed on unreachable" rule: a ProviderProxy that
// cannot bind aborts the run with StateFailedBackend and stops every
// already-started proxy. We trigger the failure by binding two proxies
// on the same pinned port; the second Start collides with EADDRINUSE.
func TestSupervisor_ProviderProxies_BindFailureFailsClosed(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)

	// Bind a sacrificial listener on a known loopback port so the
	// supervisor's second proxy collides with it on Start. We use a
	// pre-bound real listener (kept alive by t.Cleanup) so the
	// collision is deterministic across CI hosts.
	occupier, err := newPinnedLoopbackProxy(t, secrets.ProviderOpenAI, "sk-openai-occupied-aaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("setup occupier: %v", err)
	}
	pinnedAddr := occupier.URL()
	// Strip "http://" prefix to get host:port.
	pinnedAddr = strings.TrimPrefix(pinnedAddr, "http://")

	// First proxy: anthropic, ephemeral port — will start fine.
	antProxy := newTestProviderProxy(t, secrets.ProviderAnthropic, "sk-ant-failclosed-aaaaaaaaaaaaaaaa")

	// Second proxy: openai, pinned to the occupied port — will fail
	// at Start with "address in use".
	collidingProxy, err := secrets.NewProviderProxy(secrets.Options{
		Provider:        secrets.ProviderOpenAI,
		Token:           "sk-openai-collide-bbbbbbbbbbbbbbbbbbbb",
		ListenAddr:      pinnedAddr,
		ShutdownTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewProviderProxy colliding: %v", err)
	}

	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "proxy-failclosed",
		Task:              "ProviderProxy fail-closed test",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("echo should-not-run; exit 0"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
		ProviderProxies:   []*secrets.ProviderProxy{antProxy, collidingProxy},
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	result, err := sup.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FinalState != StateFailedPolicy {
		t.Errorf("FinalState = %q, want %q", result.FinalState, StateFailedPolicy)
	}
	if result.StopReason != StopReasonPolicyFailure {
		t.Errorf("StopReason = %q, want %q", result.StopReason, StopReasonPolicyFailure)
	}

	// The child must NOT have run. Stdout would contain
	// "should-not-run" if launchChild fired.
	stdout, err := os.ReadFile(filepath.Join(dir.Path, "stdout.log"))
	if err == nil && strings.Contains(string(stdout), "should-not-run") {
		t.Errorf("child ran despite fail-closed proxy bind; stdout=%q", string(stdout))
	}

	// proxy_started must record the anthropic proxy (which bound
	// successfully); the colliding openai proxy never reached the
	// verb.
	started := readLifecycleVerbs(t, dir.Path, LifecycleVerbProxyStarted)
	if len(started) != 1 {
		t.Fatalf("proxy_started verbs = %d, want 1 (only anthropic should be recorded)", len(started))
	}
	if started[0].Metadata["provider"] != secrets.ProviderAnthropic {
		t.Errorf("started[0] provider = %q, want %q", started[0].Metadata["provider"], secrets.ProviderAnthropic)
	}

	// proxy_stopped must record the rollback of the anthropic proxy
	// with reason="error" so a reviewer sees the unwind that follows
	// the fail-closed bind error.
	stopped := readLifecycleVerbs(t, dir.Path, LifecycleVerbProxyStopped)
	if len(stopped) == 0 {
		t.Fatalf("proxy_stopped verbs = 0, want >= 1 (rollback of started proxies)")
	}
	// Find the anthropic stop event; it must carry reason="error".
	var antStop *LifecycleEvent
	for i, evt := range stopped {
		if evt.Metadata["provider"] == secrets.ProviderAnthropic {
			antStop = &stopped[i]
			break
		}
	}
	if antStop == nil {
		t.Fatalf("no anthropic proxy_stopped event found in %+v", stopped)
	}
	if antStop.Metadata["reason"] != "error" {
		t.Errorf("anthropic stop reason = %q, want error", antStop.Metadata["reason"])
	}
}

// TestSupervisor_NoProviderProxies_NoVerbs verifies the legacy path:
// a supervisor with no ProviderProxies configured does NOT emit any
// proxy_started / proxy_stopped verbs (backward compatibility with
// pre-Batch-2.3 tests).
func TestSupervisor_NoProviderProxies_NoVerbs(t *testing.T) {
	skipIfNoSh(t)
	dir := newSupervisorRunDir(t)
	sup, err := NewSupervisor(SupervisorOptions{
		RunDir:            dir.Path,
		RunID:             dir.ID,
		EnvName:           "no-proxies",
		Task:              "no proxies configured",
		Backend:           "local-process",
		Agent:             "claude",
		Command:           shellCmd("exit 0"),
		MaxRuntime:        5 * time.Second,
		IdleTimeout:       5 * time.Second,
		StatsPollInterval: 20 * time.Millisecond,
		StopGracePeriod:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if _, err := sup.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := readLifecycleVerbs(t, dir.Path, LifecycleVerbProxyStarted, LifecycleVerbProxyStopped); len(got) != 0 {
		t.Errorf("expected 0 proxy verbs, got %d: %+v", len(got), got)
	}
}

// newPinnedLoopbackProxy stands up a real ProviderProxy bound to an
// OS-picked loopback port and starts it. Used by the fail-closed test
// to occupy a port we then ask another proxy to bind. The proxy is
// stopped via t.Cleanup so the port is released at test end.
func newPinnedLoopbackProxy(t *testing.T, provider, token string) (*secrets.ProviderProxy, error) {
	t.Helper()
	p, err := secrets.NewProviderProxy(secrets.Options{
		Provider:        provider,
		Token:           token,
		ShutdownTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		return nil, err
	}
	if err := p.Start(); err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = p.Stop() })
	return p, nil
}
