// Schema-hash pinning for MCP servers (plan 09, step 2).
//
// MCP servers advertise their capabilities through a tool list: each
// tool has a name, a human-readable description, and a JSON schema
// describing its input parameters. The agent reads this list and
// decides which tools to call and how. That makes the tool list a
// soft attack surface: an upstream server release can quietly change
// a tool's description ("now also reads /etc/passwd") or relax its
// schema ("path is now optional and defaults to /") and the agent
// will pick the change up on the next launch without any operator
// involvement. This is the "MCP poisoning" risk called out in
// section 22 of the master plan.
//
// The defense, per the master plan, is to pin the hash of the tool
// schema at registration time and compare on every launch. A
// mismatch is either warned about (operator-friendly drift report)
// or blocked outright (fail-closed default), per the server's
// Policy field.
//
// This file is the policy- and I/O-free core of that mechanism:
//
//  1. ToolSchema is the in-memory shape of a single tool exported by
//     a server. ServerSchema bundles all tools advertised by one
//     server. These types are intentionally a small subset of the
//     real MCP tool-definition object: only the fields that affect
//     the agent's decision-making (name, description, input
//     schema) are hashed. Server-side metadata that does not change
//     agent behavior (e.g. transport hints) is deliberately excluded
//     so that a benign server-version bump that only touches such
//     metadata does not produce a false-positive mismatch.
//
//  2. ComputeSchemaHash turns a ServerSchema into a deterministic
//     "sha256:<hex>" string that is byte-identical to what
//     RegistryServer.SchemaHash records in mcp.yaml. The output
//     shape matches validateDigest in registry.go so the audit log
//     and the operator-authored YAML file speak the same language.
//
//  3. CompareSchemaHash applies the per-server Policy field to a
//     freshly computed hash:
//
//        - registered hash empty: this is the first launch, so the
//          gateway records the just-computed hash for the operator
//          to pin (SchemaDecisionRecord).
//        - hashes match: proceed silently (SchemaDecisionAllow).
//        - hashes differ + Policy is "warn": emit a warning in the
//          audit log but still launch (SchemaDecisionWarn). This is
//          the master plan's "warn" track for operators who want
//          drift visibility without operational pain.
//        - hashes differ + Policy is "allow" or "deny": block
//          (SchemaDecisionBlock). "allow" servers fail-closed on
//          drift because the master plan says "warn OR block";
//          "deny" servers are already parked and stay blocked.
//
// The gateway proxy (plan 09 step 3) is the consumer of this
// surface: at server-launch time it computes the schema, calls
// CompareSchemaHash, writes the decision to mcp-calls.jsonl
// (step 7), and either launches, warns, or blocks accordingly.
// Keeping the I/O out of this file means the test suite can
// exercise every code path with pure structs and no temp dirs.
//
// Canonicalization rules (the contract every other layer relies on):
//
//   - Tools are sorted by Name before hashing. The server may emit
//     them in any order; the hash must not flip on a reordering.
//   - InputSchema is a free-form map. We canonicalize it via the
//     standard library's json.Marshal with a recursive map-sort
//     pass so two semantically equal schemas produce the same
//     bytes regardless of upstream map iteration order.
//   - The hash input is "<name>\x00<description>\x00<canonical-json>\n"
//     per tool, concatenated in sorted order. NUL separators keep
//     fields with embedded newlines unambiguous; the trailing
//     newline lets `tail` and `grep` on a dumped buffer show one
//     tool per line during debugging.
//   - The supported version of the canonical form is encoded as a
//     leading "v1\n" line. Bumping this constant is how we'd land
//     a future canonicalization change without silently
//     invalidating every pinned hash.

package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// schemaCanonicalVersion is the leading marker baked into every
// computed schema hash. Bumping it forces every operator to re-pin
// (because old hashes will mismatch), which is exactly what we
// want if the canonicalization rules ever change.
const schemaCanonicalVersion = "v1"

// SchemaHashPrefix is the literal "sha256:" prefix shared with
// RegistryServer.SchemaHash and the digest validator. Exported so
// the gateway proxy and CLI can build / strip the prefix without
// retyping the constant.
const SchemaHashPrefix = "sha256:"

// ToolSchema is the hashable subset of one MCP tool definition.
// MCP servers may advertise additional fields (annotations,
// transport hints, vendor extensions); we deliberately do not
// include those in the hash so the pin tracks only the fields the
// agent acts on. The plan calls out "tool description" changes
// specifically as the MCP-poisoning vector, which is why
// Description is on this struct.
type ToolSchema struct {
	// Name is the tool identifier the agent uses to invoke the
	// tool. MCP requires it to be a non-empty string, but we do
	// not enforce that here: ComputeSchemaHash will still produce
	// a deterministic hash for a degenerate input so test fixtures
	// remain straightforward.
	Name string

	// Description is the natural-language description the agent
	// reads. This is the primary MCP-poisoning surface: an
	// upstream change here can convince the agent to use a tool
	// in ways the operator never reviewed, so the hash treats
	// description changes as schema changes.
	Description string

	// InputSchema is the JSON Schema for the tool's input
	// parameters, decoded as a generic map[string]any. Two
	// semantically equal schemas (same keys, same values, only
	// the encoding map iteration order differs) hash to the same
	// value because ComputeSchemaHash sorts keys recursively
	// before serialization.
	InputSchema map[string]any
}

// ServerSchema is the full set of tools advertised by one MCP
// server at a point in time. Order does not matter: ComputeSchemaHash
// sorts by tool name.
type ServerSchema struct {
	Tools []ToolSchema
}

// ErrSchemaMismatch is the sentinel returned inside a
// SchemaDecision when a server's freshly computed hash differs
// from the one pinned in mcp.yaml. Exported so the gateway proxy
// and CLI can match it with errors.Is.
var ErrSchemaMismatch = errors.New("mcp: tool schema hash mismatch")

// SchemaOutcome is the gateway-facing verdict from CompareSchemaHash.
// Three states correspond directly to the master-plan rule "warn or
// block if schema changed" plus a "first launch, please pin"
// onboarding state.
type SchemaOutcome int

const (
	// SchemaOutcomeAllow is the happy path: the hashes match and
	// the gateway should proceed with launching the server.
	SchemaOutcomeAllow SchemaOutcome = iota

	// SchemaOutcomeRecord means the registry has no pinned hash
	// yet (a freshly registered server). The gateway should
	// record the just-computed hash and surface it for the
	// operator to pin into mcp.yaml. The launch itself is
	// allowed in this state: blocking here would prevent any
	// server from ever being onboarded.
	SchemaOutcomeRecord

	// SchemaOutcomeWarn means the hashes differ and the server's
	// Policy is "warn". The gateway should emit a warning to the
	// audit log and continue with the launch.
	SchemaOutcomeWarn

	// SchemaOutcomeBlock means the hashes differ and the server's
	// Policy is "allow" or "deny". The gateway must refuse to
	// launch the server. The accompanying SchemaDecision.Err
	// wraps ErrSchemaMismatch so callers can match with errors.Is.
	SchemaOutcomeBlock
)

// String returns the lowercase token used in mcp-calls.jsonl so
// the audit log is grep-friendly and stable across releases.
func (o SchemaOutcome) String() string {
	switch o {
	case SchemaOutcomeAllow:
		return "allow"
	case SchemaOutcomeRecord:
		return "record"
	case SchemaOutcomeWarn:
		return "warn"
	case SchemaOutcomeBlock:
		return "block"
	default:
		return fmt.Sprintf("unknown(%d)", int(o))
	}
}

// SchemaDecision is the structured result of CompareSchemaHash. The
// gateway proxy (step 3) writes a SchemaDecision-shaped record to
// mcp-calls.jsonl (step 7) on every server launch; centralizing
// the shape here keeps step 3 and step 7 in lock-step.
type SchemaDecision struct {
	// Server is the registered server name the decision applies
	// to. Echoed back so callers can pass the decision around
	// without re-threading the name.
	Server string

	// Outcome is the operator-visible verdict.
	Outcome SchemaOutcome

	// Expected is the hash pinned in mcp.yaml at compare time.
	// Empty when Outcome is SchemaOutcomeRecord (first launch).
	Expected string

	// Actual is the hash freshly computed from the live server's
	// advertised tool list. Always populated.
	Actual string

	// Err is set for SchemaOutcomeBlock (wraps ErrSchemaMismatch
	// so errors.Is works) and nil for all other outcomes. Storing
	// the error here, rather than returning it as a second value,
	// lets callers serialize SchemaDecision verbatim into the
	// audit log without losing the diagnostic.
	Err error
}

// ComputeSchemaHash returns the canonical "sha256:<hex>" digest of
// the given ServerSchema. The output is byte-identical for two
// schemas that differ only in tool ordering or JSON map iteration
// order, so a benign upstream re-serialization will not flip the
// pinned hash. The shape matches RegistryServer.SchemaHash (and
// passes validateDigest) so the same string round-trips through
// mcp.yaml without translation.
//
// Hash input layout (deterministic):
//
//	v1\n
//	<tool0.Name>\x00<tool0.Description>\x00<canonical-json>\n
//	<tool1.Name>\x00<tool1.Description>\x00<canonical-json>\n
//	...
//
// Tools are sorted by Name; canonical-json is produced by
// canonicalJSON below.
func ComputeSchemaHash(s ServerSchema) (string, error) {
	tools := append([]ToolSchema(nil), s.Tools...)
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	h := sha256.New()
	if _, err := fmt.Fprintln(h, schemaCanonicalVersion); err != nil {
		return "", fmt.Errorf("mcp: hash schema header: %w", err)
	}
	for _, t := range tools {
		canon, err := canonicalJSON(t.InputSchema)
		if err != nil {
			return "", fmt.Errorf("mcp: canonicalize tool %q input schema: %w", t.Name, err)
		}
		if _, err := fmt.Fprintf(h, "%s\x00%s\x00%s\n", t.Name, t.Description, canon); err != nil {
			return "", fmt.Errorf("mcp: hash tool %q: %w", t.Name, err)
		}
	}
	return SchemaHashPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// canonicalJSON returns a stable JSON serialization of v: maps have
// their keys sorted recursively, slices preserve their order (they
// are positional in JSON Schema). nil produces the literal "null"
// so an absent InputSchema and an explicitly-nil InputSchema hash
// the same way.
//
// We canonicalize before hashing rather than relying on
// json.Marshal's map ordering (which is already sorted for
// map[string]string but produces undefined order for
// map[string]any nested inside slices) because the operator-facing
// contract is "same logical schema = same hash". A loose
// implementation would produce mysterious mismatches when a server
// upgrade only changes a serialization library.
func canonicalJSON(v any) (string, error) {
	normalized := canonicalize(v)
	b, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// canonicalize walks v and returns a value whose maps are
// serialized in key-sorted order by the standard library's
// json.Marshal. The standard library already sorts top-level
// map[string]T keys; the recursion ensures nested maps inside
// slices are also sorted.
func canonicalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		// Build a fresh map; json.Marshal already sorts string
		// keys, so we only need to canonicalize the values.
		out := make(map[string]any, len(x))
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out[k] = canonicalize(x[k])
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = canonicalize(e)
		}
		return out
	default:
		return v
	}
}

// CompareSchemaHash applies the per-server Policy to a freshly
// computed live hash and returns the gateway-facing SchemaDecision.
// The caller is expected to have already validated the server name
// against the registry (Registry.Lookup); a server name unknown to
// the registry returns ErrUnknownServer (wrapped) so the caller
// does not have to duplicate the lookup.
//
// Decision matrix:
//
//	pinned == ""              -> SchemaOutcomeRecord (no err)
//	pinned == live            -> SchemaOutcomeAllow  (no err)
//	pinned != live, warn      -> SchemaOutcomeWarn   (no err)
//	pinned != live, allow/deny-> SchemaOutcomeBlock  (ErrSchemaMismatch)
//
// The two "fail-closed" cases share ErrSchemaMismatch so callers
// can match with errors.Is without caring whether the underlying
// Policy was "allow" or "deny": both mean "do not launch this
// server".
func (r *Registry) CompareSchemaHash(name, liveHash string) SchemaDecision {
	server, err := r.Lookup(name)
	if err != nil {
		return SchemaDecision{
			Server:  name,
			Outcome: SchemaOutcomeBlock,
			Actual:  liveHash,
			Err:     err,
		}
	}

	dec := SchemaDecision{
		Server:   name,
		Expected: server.SchemaHash,
		Actual:   liveHash,
	}

	switch {
	case server.SchemaHash == "":
		// First launch after registration: record the live hash
		// and let the operator pin it. We never auto-pin from
		// inside the gateway because doing so would silently
		// accept whatever the server happens to advertise on the
		// first run (which may itself be malicious).
		dec.Outcome = SchemaOutcomeRecord
		return dec
	case server.SchemaHash == liveHash:
		dec.Outcome = SchemaOutcomeAllow
		return dec
	case server.Policy == ServerPolicyWarn:
		dec.Outcome = SchemaOutcomeWarn
		return dec
	default:
		dec.Outcome = SchemaOutcomeBlock
		dec.Err = fmt.Errorf("%w: server %q expected %q, got %q",
			ErrSchemaMismatch, name, server.SchemaHash, liveHash)
		return dec
	}
}
