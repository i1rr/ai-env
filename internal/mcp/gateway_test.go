package mcp

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

// recordingLogger is the test double for CallLogger. It captures
// every CallRecord the gateway emits so tests can assert on the
// audit trail in addition to the in-memory decision. The mutex keeps
// concurrent-Log tests deterministic.
type recordingLogger struct {
	mu      sync.Mutex
	records []CallRecord
	err     error // optional: returned from Log to test logger-error propagation
}

// Log implements CallLogger. The supplied record is copied via the
// caller's struct semantics (CallRecord has no pointer fields aside
// from the ScopeKinds slice, which the gateway constructs fresh
// per-call); we still append the value as-is so a test can inspect
// the exact bytes the production writer would receive.
func (l *recordingLogger) Log(r CallRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, r)
	return l.err
}

// last returns the most recently logged record. Helper so each test
// asserts on the single record it produces without manually indexing.
func (l *recordingLogger) last(t *testing.T) CallRecord {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.records) == 0 {
		t.Fatal("recordingLogger: no records captured")
	}
	return l.records[len(l.records)-1]
}

// stubEnforcer is the test double for ScopeEnforcer. It returns the
// configured error verbatim so a single test can exercise allow,
// deny, and missing-field paths by swapping the err field.
type stubEnforcer struct {
	err  error
	seen []ScopeRequest // captured for assertion
	mu   sync.Mutex
}

// EnforceScope implements ScopeEnforcer. The captured request is
// stored so the test can assert that the gateway forwarded the
// expected Tool / Path / Repo / Operation tuple.
func (s *stubEnforcer) EnforceScope(_ RegistryServer, _ string, req ScopeRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, req)
	return s.err
}

// fixedClock returns a function that yields a deterministic, slowly
// advancing time so CallRecord.Timestamp values are predictable. The
// gateway formats the time as RFC3339 with a numeric offset; we pin
// the location to UTC so the encoded string is stable across hosts.
func fixedClock() func() time.Time {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	var step time.Duration
	var mu sync.Mutex
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t := base.Add(step)
		step += time.Second
		return t
	}
}

// newTestGateway builds a Gateway from the canonical valid fixture
// plus optional logger / enforcers / clock so each test only states
// the dependencies it cares about. The fixture has filesystem
// (Policy: allow) and github (Policy: warn) servers, which gives
// every per-server-Policy branch a target without bespoke fixtures.
func newTestGateway(t *testing.T, logger CallLogger, enforcers map[string]ScopeEnforcer) *Gateway {
	t.Helper()
	reg := mustLoadRegistry(t, validRegistryYAML)
	gw, err := NewGateway(reg, &GatewayOptions{
		Logger:    logger,
		Enforcers: enforcers,
		Now:       fixedClock(),
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return gw
}

func TestNewGateway_RejectsNilRegistry(t *testing.T) {
	if _, err := NewGateway(nil, nil); err == nil {
		t.Fatal("expected error when Registry is nil")
	}
}

func TestNewGateway_DefaultsLoggerToNoop(t *testing.T) {
	reg := mustLoadRegistry(t, validRegistryYAML)
	gw, err := NewGateway(reg, nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	// Use the no-op path: a Launch against a registered server
	// without any pin candidates must succeed and must not panic on
	// the missing logger.
	dec, err := gw.AuthorizeLaunch(LaunchRequest{Server: "filesystem"})
	if err != nil {
		t.Fatalf("AuthorizeLaunch with default logger: %v", err)
	}
	if dec.Outcome != GatewayOutcomeAllow {
		t.Fatalf("Outcome = %v, want Allow", dec.Outcome)
	}
}

func TestGateway_Registry_ExposedForCLI(t *testing.T) {
	gw := newTestGateway(t, nil, nil)
	if gw.Registry() == nil {
		t.Fatal("Registry() returned nil")
	}
	if got, want := gw.Registry().DefaultPolicy(), DefaultPolicyDeny; got != want {
		t.Errorf("Registry().DefaultPolicy() = %q, want %q", got, want)
	}
}

func TestAuthorizeLaunch_UnknownServerIsBlocked(t *testing.T) {
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeLaunch(LaunchRequest{Server: "does-not-exist"})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrUnknownServer) {
		t.Fatalf("Err = %v, want wraps ErrUnknownServer", dec.Err)
	}

	rec := logger.last(t)
	if rec.Stage != CallStageLaunch {
		t.Errorf("Stage = %q, want %q", rec.Stage, CallStageLaunch)
	}
	if rec.Decision != GatewayOutcomeBlock.String() {
		t.Errorf("Decision = %q, want %q", rec.Decision, GatewayOutcomeBlock)
	}
	if rec.Server != "does-not-exist" {
		t.Errorf("Server = %q, want passthrough of caller name", rec.Server)
	}
}

func TestAuthorizeLaunch_ParkedServerIsBlocked(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Policy = ServerPolicyDeny
	cfg.Servers["filesystem"] = fs
	if err := ValidateRegistry(cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	logger := &recordingLogger{}
	gw, err := NewGateway(NewRegistry(cfg), &GatewayOptions{Logger: logger, Now: fixedClock()})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	dec, err := gw.AuthorizeLaunch(LaunchRequest{Server: "filesystem"})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrServerParked) {
		t.Fatalf("Err = %v, want wraps ErrServerParked", dec.Err)
	}
}

func TestAuthorizeLaunch_SourceMismatchBlocks(t *testing.T) {
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeLaunch(LaunchRequest{
		Server: "filesystem",
		Source: "npm:@modelcontextprotocol/server-filesystem@9.9.9",
	})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrVersionMismatch) {
		t.Fatalf("Err = %v, want wraps ErrVersionMismatch", dec.Err)
	}
	rec := logger.last(t)
	if rec.Source != "npm:@modelcontextprotocol/server-filesystem@9.9.9" {
		t.Errorf("Source = %q, want passthrough", rec.Source)
	}
}

func TestAuthorizeLaunch_DigestMismatchBlocks(t *testing.T) {
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeLaunch(LaunchRequest{
		Server: "filesystem",
		Source: "npm:@modelcontextprotocol/server-filesystem@1.2.3",
		Digest: "sha256:nope",
	})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrDigestMismatch) {
		t.Fatalf("Err = %v, want wraps ErrDigestMismatch", dec.Err)
	}
}

func TestAuthorizeLaunch_EmptyDigestSkipsDigestCheck(t *testing.T) {
	// The gateway treats an empty caller-supplied Digest as
	// "operator did not run a digest check"; combined with the
	// registry's non-empty pinned digest, this should still allow
	// (we are not asserting "must supply digest", we are asserting
	// "missing candidate = skip the comparison").
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeLaunch(LaunchRequest{
		Server: "filesystem",
		Source: "npm:@modelcontextprotocol/server-filesystem@1.2.3",
	})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != GatewayOutcomeAllow {
		t.Fatalf("Outcome = %v, want Allow (Err=%v)", dec.Outcome, dec.Err)
	}
}

func TestAuthorizeLaunch_SchemaMatchAllows(t *testing.T) {
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeLaunch(LaunchRequest{
		Server:         "filesystem",
		LiveSchemaHash: "sha256:def456", // matches fixture's pinned hash
	})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != GatewayOutcomeAllow {
		t.Fatalf("Outcome = %v, want Allow (Err=%v)", dec.Outcome, dec.Err)
	}
	rec := logger.last(t)
	if rec.ExpectedHash != "sha256:def456" {
		t.Errorf("ExpectedHash = %q", rec.ExpectedHash)
	}
	if rec.ActualHash != "sha256:def456" {
		t.Errorf("ActualHash = %q", rec.ActualHash)
	}
}

func TestAuthorizeLaunch_SchemaMismatchAllowPolicyBlocks(t *testing.T) {
	// fixture: filesystem has Policy: allow, so a schema mismatch must
	// block (master plan rule "warn or block"; the allow-policy track
	// is fail-closed).
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeLaunch(LaunchRequest{
		Server:         "filesystem",
		LiveSchemaHash: "sha256:changed",
	})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrSchemaMismatch) {
		t.Fatalf("Err = %v, want wraps ErrSchemaMismatch", dec.Err)
	}
}

func TestAuthorizeLaunch_SchemaMismatchWarnPolicyWarns(t *testing.T) {
	// fixture: github has Policy: warn, so a schema mismatch must
	// produce a warning, not a block.
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeLaunch(LaunchRequest{
		Server:         "github",
		LiveSchemaHash: "sha256:changed",
	})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != GatewayOutcomeWarn {
		t.Fatalf("Outcome = %v, want Warn", dec.Outcome)
	}
	if dec.Err != nil {
		t.Errorf("Warn outcome must not carry Err, got %v", dec.Err)
	}
}

func TestAuthorizeLaunch_SchemaRecordOnFirstLaunchAllows(t *testing.T) {
	// A freshly registered server (empty SchemaHash) plus a live hash
	// produces SchemaOutcomeRecord, which the gateway maps to Allow
	// with a "please pin" reason.
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.SchemaHash = ""
	cfg.Servers["filesystem"] = fs
	if err := ValidateRegistry(cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	logger := &recordingLogger{}
	gw, err := NewGateway(NewRegistry(cfg), &GatewayOptions{Logger: logger, Now: fixedClock()})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	dec, err := gw.AuthorizeLaunch(LaunchRequest{
		Server:         "filesystem",
		LiveSchemaHash: "sha256:firstlaunch",
	})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != GatewayOutcomeAllow {
		t.Fatalf("Outcome = %v, want Allow (Err=%v)", dec.Outcome, dec.Err)
	}
	rec := logger.last(t)
	if rec.ActualHash != "sha256:firstlaunch" {
		t.Errorf("ActualHash = %q", rec.ActualHash)
	}
	if rec.ExpectedHash != "" {
		t.Errorf("ExpectedHash should be empty for first-launch record, got %q", rec.ExpectedHash)
	}
}

func TestAuthorizeLaunch_WarnPolicyServerWarnsWithoutSchemaCheck(t *testing.T) {
	// A registered server with Policy: warn must surface a warning at
	// launch even when no schema hash was supplied; the operator
	// explicitly asked for visibility on every launch.
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeLaunch(LaunchRequest{Server: "github"})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != GatewayOutcomeWarn {
		t.Fatalf("Outcome = %v, want Warn", dec.Outcome)
	}
}

func TestAuthorizeLaunch_LoggerErrorIsReturned(t *testing.T) {
	logger := &recordingLogger{err: errors.New("disk full")}
	gw := newTestGateway(t, logger, nil)
	dec, err := gw.AuthorizeLaunch(LaunchRequest{Server: "filesystem"})
	if err == nil {
		t.Fatal("expected logger error to surface")
	}
	// Decision must still reflect the underlying verdict so the
	// supervisor can fail closed without re-evaluating.
	if dec.Outcome != GatewayOutcomeAllow {
		t.Errorf("Outcome = %v, want Allow even when logger errored", dec.Outcome)
	}
}

func TestAuthorizeCall_UnknownServerIsBlocked(t *testing.T) {
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeCall(CallRequest{Server: "nope", Tool: "x"})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrUnknownServer) {
		t.Fatalf("Err = %v, want wraps ErrUnknownServer", dec.Err)
	}
	rec := logger.last(t)
	if rec.Stage != CallStageCall {
		t.Errorf("Stage = %q, want %q", rec.Stage, CallStageCall)
	}
}

func TestAuthorizeCall_ParkedServerIsBlocked(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Policy = ServerPolicyDeny
	cfg.Servers["filesystem"] = fs
	if err := ValidateRegistry(cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	logger := &recordingLogger{}
	gw, err := NewGateway(NewRegistry(cfg), &GatewayOptions{Logger: logger, Now: fixedClock()})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	dec, err := gw.AuthorizeCall(CallRequest{Server: "filesystem", Tool: "read_file"})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrServerParked) {
		t.Fatalf("Err = %v, want wraps ErrServerParked", dec.Err)
	}
}

func TestAuthorizeCall_MissingToolIsBlocked(t *testing.T) {
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeCall(CallRequest{Server: "filesystem"})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if dec.Err == nil {
		t.Errorf("Block must carry Err explaining missing Tool")
	}
}

func TestAuthorizeCall_MissingScopeEnforcerBlocks(t *testing.T) {
	// fixture: filesystem server declares a filesystem scope but the
	// gateway is built with no enforcers, so the gateway must block
	// with ErrMissingScopeEnforcer (master plan "deny unknown
	// scope").
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	dec, err := gw.AuthorizeCall(CallRequest{
		Server: "filesystem",
		Tool:   "read_file",
		Path:   "/anything",
	})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrMissingScopeEnforcer) {
		t.Fatalf("Err = %v, want wraps ErrMissingScopeEnforcer", dec.Err)
	}
}

func TestAuthorizeCall_ScopeEnforcerAllowsThenAllows(t *testing.T) {
	logger := &recordingLogger{}
	fs := &stubEnforcer{}
	gw := newTestGateway(t, logger, map[string]ScopeEnforcer{
		ScopeKindFilesystem: fs,
	})

	dec, err := gw.AuthorizeCall(CallRequest{
		Server: "filesystem",
		Tool:   "read_file",
		Path:   "/workspace/foo",
	})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if dec.Outcome != GatewayOutcomeAllow {
		t.Fatalf("Outcome = %v, want Allow", dec.Outcome)
	}
	if len(fs.seen) != 1 {
		t.Fatalf("enforcer saw %d requests, want 1", len(fs.seen))
	}
	if got, want := fs.seen[0].Path, "/workspace/foo"; got != want {
		t.Errorf("forwarded Path = %q, want %q", got, want)
	}
	if got, want := fs.seen[0].Tool, "read_file"; got != want {
		t.Errorf("forwarded Tool = %q, want %q", got, want)
	}
	rec := logger.last(t)
	if got, want := rec.ScopeKinds, []string{ScopeKindFilesystem}; !reflect.DeepEqual(got, want) {
		t.Errorf("ScopeKinds = %v, want %v", got, want)
	}
}

func TestAuthorizeCall_ScopeEnforcerRejectsBlocks(t *testing.T) {
	logger := &recordingLogger{}
	fs := &stubEnforcer{err: fmt.Errorf("path outside workspace")}
	gw := newTestGateway(t, logger, map[string]ScopeEnforcer{
		ScopeKindFilesystem: fs,
	})

	dec, err := gw.AuthorizeCall(CallRequest{
		Server: "filesystem",
		Tool:   "read_file",
		Path:   "/etc/passwd",
	})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrScopeViolation) {
		t.Fatalf("Err = %v, want wraps ErrScopeViolation", dec.Err)
	}
}

func TestAuthorizeCall_WarnPolicyWarnsAfterScopeAllow(t *testing.T) {
	// fixture: github has Policy: warn. A passing scope check must
	// then surface a warning, not an allow, so the operator sees
	// every github call in the audit log.
	logger := &recordingLogger{}
	gh := &stubEnforcer{}
	gw := newTestGateway(t, logger, map[string]ScopeEnforcer{
		ScopeKindGitHub: gh,
	})

	dec, err := gw.AuthorizeCall(CallRequest{
		Server:    "github",
		Tool:      "list_issues",
		Repo:      "i1rr/ai-env",
		Operation: "read",
	})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if dec.Outcome != GatewayOutcomeWarn {
		t.Fatalf("Outcome = %v, want Warn", dec.Outcome)
	}
	if len(gh.seen) != 1 || gh.seen[0].Repo != "i1rr/ai-env" {
		t.Errorf("enforcer didn't see expected Repo, got %+v", gh.seen)
	}
}

func TestAuthorizeCall_DeterministicScopeOrder(t *testing.T) {
	// A server with both filesystem and github scopes must evaluate
	// in sorted order so the audit log's ScopeKinds list is stable
	// and so the first-failure reason is deterministic. We override
	// the fixture to declare both scopes on one server.
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Scope = map[string]ScopeSection{
		ScopeKindFilesystem: {Root: FilesystemRootWorkspaceOnly},
		ScopeKindGitHub:     {Repos: GitHubReposCurrentRepoOnly, Operations: GitHubOperationsReadOnly},
	}
	cfg.Servers["filesystem"] = fs
	if err := ValidateRegistry(cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	logger := &recordingLogger{}
	fsE := &stubEnforcer{}
	ghE := &stubEnforcer{}
	gw, err := NewGateway(NewRegistry(cfg), &GatewayOptions{
		Logger: logger,
		Enforcers: map[string]ScopeEnforcer{
			ScopeKindFilesystem: fsE,
			ScopeKindGitHub:     ghE,
		},
		Now: fixedClock(),
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	dec, err := gw.AuthorizeCall(CallRequest{
		Server:    "filesystem",
		Tool:      "do_thing",
		Path:      "/ws",
		Repo:      "owner/repo",
		Operation: "read",
	})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if dec.Outcome != GatewayOutcomeAllow {
		t.Fatalf("Outcome = %v, want Allow", dec.Outcome)
	}
	rec := logger.last(t)
	want := []string{ScopeKindFilesystem, ScopeKindGitHub}
	if !reflect.DeepEqual(rec.ScopeKinds, want) {
		t.Errorf("ScopeKinds = %v, want %v (sorted)", rec.ScopeKinds, want)
	}
}

func TestAuthorizeCall_LoggerErrorIsReturned(t *testing.T) {
	logger := &recordingLogger{err: errors.New("disk full")}
	fs := &stubEnforcer{}
	gw := newTestGateway(t, logger, map[string]ScopeEnforcer{
		ScopeKindFilesystem: fs,
	})

	dec, err := gw.AuthorizeCall(CallRequest{
		Server: "filesystem",
		Tool:   "read_file",
		Path:   "/ws/foo",
	})
	if err == nil {
		t.Fatal("expected logger error to surface")
	}
	if dec.Outcome != GatewayOutcomeAllow {
		t.Errorf("Outcome = %v, want Allow even when logger errored", dec.Outcome)
	}
}

func TestGatewayOutcome_StringTokens(t *testing.T) {
	// Pin the on-disk vocabulary so an audit-log consumer can grep on
	// stable strings across releases.
	cases := []struct {
		o    GatewayOutcome
		want string
	}{
		{GatewayOutcomeAllow, "allow"},
		{GatewayOutcomeWarn, "warn"},
		{GatewayOutcomeBlock, "block"},
	}
	for _, c := range cases {
		if got := c.o.String(); got != c.want {
			t.Errorf("%d.String() = %q, want %q", int(c.o), got, c.want)
		}
	}
}

func TestCallStage_AuditTokens(t *testing.T) {
	// CallStage is what an auditor greps for in mcp-calls.jsonl;
	// pin the spelling so step 7's writer cannot drift.
	if string(CallStageLaunch) != "launch" {
		t.Errorf("CallStageLaunch = %q, want %q", string(CallStageLaunch), "launch")
	}
	if string(CallStageCall) != "call" {
		t.Errorf("CallStageCall = %q, want %q", string(CallStageCall), "call")
	}
}

func TestAuthorizeLaunch_EveryDecisionEmitsExactlyOneRecord(t *testing.T) {
	// The audit-log contract is "every decision -> exactly one
	// record". This test makes that promise an invariant by issuing
	// one of each outcome and asserting the logger saw exactly one
	// record per call.
	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, nil)

	calls := []LaunchRequest{
		{Server: "missing"},                   // Block / unknown
		{Server: "filesystem"},                // Allow
		{Server: "github"},                    // Warn (per-server policy warn)
		{Server: "filesystem", Source: "bad"}, // Block / version mismatch
	}
	for i, c := range calls {
		if _, err := gw.AuthorizeLaunch(c); err != nil {
			t.Fatalf("AuthorizeLaunch[%d]: %v", i, err)
		}
	}
	if got, want := len(logger.records), len(calls); got != want {
		t.Fatalf("records = %d, want %d (one per call)", got, want)
	}
}

func TestAuthorizeCall_EveryDecisionEmitsExactlyOneRecord(t *testing.T) {
	logger := &recordingLogger{}
	fs := &stubEnforcer{}
	gw := newTestGateway(t, logger, map[string]ScopeEnforcer{
		ScopeKindFilesystem: fs,
		ScopeKindGitHub:     &stubEnforcer{},
	})

	calls := []CallRequest{
		{Server: "missing", Tool: "x"},
		{Server: "filesystem", Tool: "read_file", Path: "/ws/a"},
		{Server: "github", Tool: "list_issues", Repo: "o/r", Operation: "read"},
		{Server: "filesystem"}, // missing tool -> Block
	}
	for i, c := range calls {
		if _, err := gw.AuthorizeCall(c); err != nil {
			t.Fatalf("AuthorizeCall[%d]: %v", i, err)
		}
	}
	if got, want := len(logger.records), len(calls); got != want {
		t.Fatalf("records = %d, want %d (one per call)", got, want)
	}
}
