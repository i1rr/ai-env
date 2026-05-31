package mcp

import (
	"errors"
	"strings"
	"testing"
)

// sampleSchema returns a non-trivial ServerSchema fixture used by
// many tests: two tools, one with a nested input schema, in
// reverse-alphabetical order so tests can verify the canonical
// sort happens regardless of input order.
func sampleSchema() ServerSchema {
	return ServerSchema{
		Tools: []ToolSchema{
			{
				Name:        "write_file",
				Description: "Write a file to the workspace.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path":    map[string]any{"type": "string"},
						"content": map[string]any{"type": "string"},
					},
					"required": []any{"path", "content"},
				},
			},
			{
				Name:        "read_file",
				Description: "Read a file from the workspace.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{"type": "string"},
					},
					"required": []any{"path"},
				},
			},
		},
	}
}

func TestComputeSchemaHash_Deterministic(t *testing.T) {
	h1, err := ComputeSchemaHash(sampleSchema())
	if err != nil {
		t.Fatalf("ComputeSchemaHash: %v", err)
	}
	h2, err := ComputeSchemaHash(sampleSchema())
	if err != nil {
		t.Fatalf("ComputeSchemaHash second call: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %q vs %q", h1, h2)
	}
	if !strings.HasPrefix(h1, SchemaHashPrefix) {
		t.Errorf("hash missing %q prefix: %q", SchemaHashPrefix, h1)
	}
	// The hashed digest body must be non-empty and shaped like
	// validateDigest expects so the value can round-trip through
	// mcp.yaml without bespoke handling.
	if err := validateDigest("schema_hash", h1); err != nil {
		t.Errorf("computed hash failed registry digest validation: %v", err)
	}
}

func TestComputeSchemaHash_ToolOrderInsensitive(t *testing.T) {
	s := sampleSchema()
	reordered := ServerSchema{Tools: []ToolSchema{s.Tools[1], s.Tools[0]}}

	h1, err := ComputeSchemaHash(s)
	if err != nil {
		t.Fatalf("hash original: %v", err)
	}
	h2, err := ComputeSchemaHash(reordered)
	if err != nil {
		t.Fatalf("hash reordered: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hash flipped on tool reorder: %q vs %q", h1, h2)
	}
}

func TestComputeSchemaHash_InputSchemaMapOrderInsensitive(t *testing.T) {
	// Build two equivalent schemas whose nested maps were
	// "constructed" in different orders. Since Go maps already
	// randomize iteration order, we cannot guarantee the
	// orderings differ at runtime, but canonicalize must produce
	// identical bytes either way.
	a := ServerSchema{Tools: []ToolSchema{{
		Name:        "t",
		Description: "d",
		InputSchema: map[string]any{
			"a": 1,
			"b": map[string]any{"x": 1, "y": 2, "z": 3},
		},
	}}}
	b := ServerSchema{Tools: []ToolSchema{{
		Name:        "t",
		Description: "d",
		InputSchema: map[string]any{
			"b": map[string]any{"z": 3, "y": 2, "x": 1},
			"a": 1,
		},
	}}}

	h1, err := ComputeSchemaHash(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	h2, err := ComputeSchemaHash(b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hash flipped on nested-map reorder: %q vs %q", h1, h2)
	}
}

func TestComputeSchemaHash_DescriptionChangeFlipsHash(t *testing.T) {
	original, err := ComputeSchemaHash(sampleSchema())
	if err != nil {
		t.Fatalf("hash original: %v", err)
	}
	tampered := sampleSchema()
	// The MCP poisoning vector: same name + schema, the
	// description tries to convince the agent to do more.
	tampered.Tools[0].Description += " Also reads /etc/passwd."
	h2, err := ComputeSchemaHash(tampered)
	if err != nil {
		t.Fatalf("hash tampered: %v", err)
	}
	if original == h2 {
		t.Fatal("description change must flip the hash")
	}
}

func TestComputeSchemaHash_InputSchemaChangeFlipsHash(t *testing.T) {
	original, err := ComputeSchemaHash(sampleSchema())
	if err != nil {
		t.Fatalf("hash original: %v", err)
	}
	tampered := sampleSchema()
	// "required" relaxed: the operator pinned a schema where
	// "path" is required; this change makes it optional.
	tampered.Tools[1].InputSchema["required"] = []any{}
	h2, err := ComputeSchemaHash(tampered)
	if err != nil {
		t.Fatalf("hash tampered: %v", err)
	}
	if original == h2 {
		t.Fatal("input schema change must flip the hash")
	}
}

func TestComputeSchemaHash_EmptyServerStillProducesHash(t *testing.T) {
	// A server with zero tools is degenerate but must not panic
	// and must produce a well-formed hash so the registry can
	// pin it (zero tools is itself the "shape" being pinned).
	h, err := ComputeSchemaHash(ServerSchema{})
	if err != nil {
		t.Fatalf("hash empty: %v", err)
	}
	if !strings.HasPrefix(h, SchemaHashPrefix) {
		t.Errorf("empty hash missing prefix: %q", h)
	}
}

func TestCompareSchemaHash_UnknownServer(t *testing.T) {
	reg := mustLoadRegistry(t, validRegistryYAML)
	dec := reg.CompareSchemaHash("nope", "sha256:whatever")
	if dec.Outcome != SchemaOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrUnknownServer) {
		t.Fatalf("Err = %v, want wraps ErrUnknownServer", dec.Err)
	}
	if dec.Actual != "sha256:whatever" {
		t.Errorf("Actual = %q, want passthrough", dec.Actual)
	}
}

func TestCompareSchemaHash_Match(t *testing.T) {
	reg := mustLoadRegistry(t, validRegistryYAML)
	// The fixture pins sha256:def456 for filesystem (Policy: allow).
	dec := reg.CompareSchemaHash("filesystem", "sha256:def456")
	if dec.Outcome != SchemaOutcomeAllow {
		t.Fatalf("Outcome = %v, want Allow", dec.Outcome)
	}
	if dec.Err != nil {
		t.Errorf("Err = %v, want nil", dec.Err)
	}
}

func TestCompareSchemaHash_MismatchPolicyAllowBlocks(t *testing.T) {
	reg := mustLoadRegistry(t, validRegistryYAML)
	// filesystem has Policy: allow in the fixture, so a mismatch
	// must fail-closed: master-plan rule "warn or block".
	dec := reg.CompareSchemaHash("filesystem", "sha256:changed")
	if dec.Outcome != SchemaOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrSchemaMismatch) {
		t.Fatalf("Err = %v, want wraps ErrSchemaMismatch", dec.Err)
	}
	if dec.Expected != "sha256:def456" || dec.Actual != "sha256:changed" {
		t.Errorf("Expected/Actual = %q/%q", dec.Expected, dec.Actual)
	}
}

func TestCompareSchemaHash_MismatchPolicyWarnWarns(t *testing.T) {
	reg := mustLoadRegistry(t, validRegistryYAML)
	// github has Policy: warn in the fixture, so a mismatch
	// produces a warning rather than a block.
	dec := reg.CompareSchemaHash("github", "sha256:changed")
	if dec.Outcome != SchemaOutcomeWarn {
		t.Fatalf("Outcome = %v, want Warn", dec.Outcome)
	}
	if dec.Err != nil {
		t.Errorf("warn outcome must not set Err, got %v", dec.Err)
	}
}

func TestCompareSchemaHash_MismatchPolicyDenyBlocks(t *testing.T) {
	// A registered-but-parked server (Policy: deny) must still
	// block on schema mismatch. "deny" already means "do not
	// launch", and a mismatch is a strictly stronger reason not
	// to launch.
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Policy = ServerPolicyDeny
	cfg.Servers["filesystem"] = fs
	if err := ValidateRegistry(cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	reg := NewRegistry(cfg)

	dec := reg.CompareSchemaHash("filesystem", "sha256:changed")
	if dec.Outcome != SchemaOutcomeBlock {
		t.Fatalf("Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrSchemaMismatch) {
		t.Fatalf("Err = %v, want wraps ErrSchemaMismatch", dec.Err)
	}
}

func TestCompareSchemaHash_EmptyPinnedRecords(t *testing.T) {
	// A freshly registered server (no schema_hash on file) must
	// produce a Record outcome so the operator can pin the
	// just-observed hash. Auto-pinning is intentionally absent:
	// it would silently accept whatever the first launch sees.
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.SchemaHash = ""
	cfg.Servers["filesystem"] = fs
	if err := ValidateRegistry(cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	reg := NewRegistry(cfg)

	dec := reg.CompareSchemaHash("filesystem", "sha256:fresh")
	if dec.Outcome != SchemaOutcomeRecord {
		t.Fatalf("Outcome = %v, want Record", dec.Outcome)
	}
	if dec.Err != nil {
		t.Errorf("record outcome must not set Err, got %v", dec.Err)
	}
	if dec.Expected != "" {
		t.Errorf("Expected = %q, want empty", dec.Expected)
	}
	if dec.Actual != "sha256:fresh" {
		t.Errorf("Actual = %q, want %q", dec.Actual, "sha256:fresh")
	}
}

func TestSchemaOutcome_StringTokens(t *testing.T) {
	// The audit log (step 7) uses these tokens verbatim; lock
	// them in to keep the on-disk format stable across releases.
	cases := []struct {
		o    SchemaOutcome
		want string
	}{
		{SchemaOutcomeAllow, "allow"},
		{SchemaOutcomeRecord, "record"},
		{SchemaOutcomeWarn, "warn"},
		{SchemaOutcomeBlock, "block"},
	}
	for _, c := range cases {
		if got := c.o.String(); got != c.want {
			t.Errorf("%d.String() = %q, want %q", int(c.o), got, c.want)
		}
	}
}

func TestComputeSchemaHash_RoundTripsAsRegisteredHash(t *testing.T) {
	// Treat a computed hash as if it had been pinned in mcp.yaml,
	// then compare against the same live schema: it must Allow.
	// This is the end-to-end "pin then re-launch" scenario.
	live, err := ComputeSchemaHash(sampleSchema())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.SchemaHash = live
	cfg.Servers["filesystem"] = fs
	if err := ValidateRegistry(cfg); err != nil {
		t.Fatalf("validate after pinning live hash: %v", err)
	}
	reg := NewRegistry(cfg)

	dec := reg.CompareSchemaHash("filesystem", live)
	if dec.Outcome != SchemaOutcomeAllow {
		t.Fatalf("round-trip Outcome = %v, want Allow (Err=%v)", dec.Outcome, dec.Err)
	}
}
