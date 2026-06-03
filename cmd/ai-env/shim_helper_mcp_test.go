package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/i1rr/ai-env/internal/scanners"
)

// TestMCPScrubber_ScrubChunkRedactsWholeKey verifies that a
// well-known provider key is replaced by the sentinel.
func TestMCPScrubber_ScrubChunkRedactsWholeKey(t *testing.T) {
	s := newMCPScrubber(scanners.BuiltInSecretPatterns())
	// Make sure the chunk is long enough that the overlap window
	// does not hide the key in the carry buffer (we want the test
	// to assert the emitted bytes; padding the tail moves the key
	// out of the carry window).
	in := []byte("noise prefix sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM trailing-noise-x-y-z-padding-to-clear-overlap-window-" + strings.Repeat("a", 300))
	first := s.ScrubChunk(in)
	tail := s.Flush()
	got := append(first, tail...)
	if bytes.Contains(got, []byte("sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM")) {
		t.Errorf("scrubbed output still contains the raw key: %s", string(got))
	}
	if !bytes.Contains(got, []byte("[REDACTED")) {
		t.Errorf("scrubbed output missing sentinel: %s", string(got))
	}
}

// TestMCPScrubber_RollingBufferCatchesBoundarySplit verifies that a
// secret split across two ScrubChunk calls is still caught.
func TestMCPScrubber_RollingBufferCatchesBoundarySplit(t *testing.T) {
	s := newMCPScrubber(scanners.BuiltInSecretPatterns())
	full := "noise-prefix sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM trailing-padding-" + strings.Repeat("z", 400)
	// Split the input in the middle of the secret so the boundary
	// straddles chunk seams.
	cut := strings.Index(full, "sk-ant-") + 10 // mid-secret
	first := []byte(full[:cut])
	second := []byte(full[cut:])

	out := s.ScrubChunk(first)
	out = append(out, s.ScrubChunk(second)...)
	out = append(out, s.Flush()...)
	if bytes.Contains(out, []byte("sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM")) {
		t.Errorf("boundary-split secret survived: %s", string(out))
	}
	if !bytes.Contains(out, []byte("[REDACTED")) {
		t.Errorf("scrubbed output missing sentinel: %s", string(out))
	}
}

// TestMCPScrubber_FlushEmitsTail verifies that Flush returns the
// held-back overlap bytes at EOF.
func TestMCPScrubber_FlushEmitsTail(t *testing.T) {
	s := newMCPScrubber(scanners.BuiltInSecretPatterns())
	// A small benign chunk shorter than the overlap; all bytes
	// should be held back and emitted by Flush.
	in := []byte("hello world")
	first := s.ScrubChunk(in)
	if len(first) != 0 {
		t.Errorf("short chunk should be entirely held back, got %d bytes out", len(first))
	}
	tail := s.Flush()
	if string(tail) != string(in) {
		t.Errorf("Flush returned %q, want %q", tail, in)
	}
}

// TestMCPScrubber_ScrubJSONFramePreservesStructure verifies the
// JSON-aware walker scrubs string values while leaving structure
// intact.
func TestMCPScrubber_ScrubJSONFramePreservesStructure(t *testing.T) {
	s := newMCPScrubber(scanners.BuiltInSecretPatterns())
	frame := []byte(`{"jsonrpc":"2.0","id":1,"result":{"token":"sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM","name":"safe"}}`)
	out, err := s.ScrubJSONFrame(frame)
	if err != nil {
		t.Fatalf("ScrubJSONFrame err = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("scrubbed frame is not valid JSON: %v; payload=%s", err, string(out))
	}
	result, ok := decoded["result"].(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %v", decoded)
	}
	tok, _ := result["token"].(string)
	if strings.Contains(tok, "sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM") {
		t.Errorf("token field still carries the secret: %q", tok)
	}
	if !strings.Contains(tok, "[REDACTED") {
		t.Errorf("token field missing sentinel: %q", tok)
	}
	if name, _ := result["name"].(string); name != "safe" {
		t.Errorf("safe value mutated: %q", name)
	}
}

// TestMCPScrubber_ScrubJSONFrameRejectsInvalidJSON verifies the
// walker surfaces an error on malformed input.
func TestMCPScrubber_ScrubJSONFrameRejectsInvalidJSON(t *testing.T) {
	s := newMCPScrubber(scanners.BuiltInSecretPatterns())
	if _, err := s.ScrubJSONFrame([]byte("{not json")); err == nil {
		t.Errorf("expected error for malformed JSON, got nil")
	}
}

// TestRunMCPPipeline_ScrubsStreamingInput verifies the pipeline
// loops chunks from src, applies the scrubber, and writes to dst.
func TestRunMCPPipeline_ScrubsStreamingInput(t *testing.T) {
	src := bytes.NewReader([]byte("plain text sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM end" + strings.Repeat("x", 400)))
	var dst bytes.Buffer
	s := newMCPScrubber(scanners.BuiltInSecretPatterns())
	if err := runMCPPipeline(src, &dst, s); err != nil {
		t.Fatalf("runMCPPipeline err = %v", err)
	}
	if strings.Contains(dst.String(), "sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM") {
		t.Errorf("pipeline output still carries secret: %s", dst.String())
	}
	if !strings.Contains(dst.String(), "[REDACTED") {
		t.Errorf("pipeline output missing sentinel: %s", dst.String())
	}
}

// TestRunMCPPipeline_HandlesShortStream verifies the pipeline
// flushes when EOF arrives without any chunks.
func TestRunMCPPipeline_HandlesShortStream(t *testing.T) {
	src := bytes.NewReader([]byte("tiny"))
	var dst bytes.Buffer
	s := newMCPScrubber(scanners.BuiltInSecretPatterns())
	if err := runMCPPipeline(src, &dst, s); err != nil {
		t.Fatalf("runMCPPipeline err = %v", err)
	}
	if dst.String() != "tiny" {
		t.Errorf("pipeline emitted %q, want %q", dst.String(), "tiny")
	}
}

// TestRunShimHelperMCP_RejectsEmptyServer verifies the empty-name
// guard.
func TestRunShimHelperMCP_RejectsEmptyServer(t *testing.T) {
	t.Setenv(shimHelperEnvDepth, "0")
	t.Setenv(shimHelperEnvServerToken, "some-token")
	if err := runShimHelperMCP("", strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Errorf("expected error for empty server name")
	}
}

// TestRunShimHelperMCP_RejectsMissingServerToken verifies the
// AI_ENV_MCP_SERVER_TOKEN guard.
func TestRunShimHelperMCP_RejectsMissingServerToken(t *testing.T) {
	t.Setenv(shimHelperEnvDepth, "0")
	t.Setenv(shimHelperEnvServerToken, "")
	if err := runShimHelperMCP("github", strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Errorf("expected error when AI_ENV_MCP_SERVER_TOKEN is unset")
	}
}

// TestMCPShim_ResponseSecretWalkedNotByteReplaced is the Plan Batch
// 3.4 acceptance test for the response-direction JSON-aware walker.
// A JSON-RPC frame whose RESULT carries a nested string with a
// secret must be re-marshalled as VALID JSON-RPC with the matched
// value (and only the matched value) replaced by the sentinel —
// never a byte-window substitution that could corrupt the surrounding
// braces / quotes / commas and break framing.
//
// The test asserts THREE invariants:
//
//  1. The scrubbed output decodes as valid JSON (no broken framing).
//  2. The original structural keys + non-secret values are
//     preserved verbatim (the walker only touches string VALUES
//     that match a pattern).
//  3. The matched value is replaced by the sentinel; the raw secret
//     is absent from the output.
func TestMCPShim_ResponseSecretWalkedNotByteReplaced(t *testing.T) {
	s := newMCPScrubber(scanners.BuiltInSecretPatterns())

	// Nested JSON-RPC response frame: the secret lives 3 levels deep,
	// inside an array of objects, so a byte-window replacer would
	// have a hard time avoiding the surrounding braces / commas. The
	// JSON walker traverses the structure and only touches the
	// matched string value.
	secret := "sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM"
	frame := []byte(`{"jsonrpc":"2.0","id":42,"result":{"tools":[{"name":"safe-tool","metadata":{"token":"` + secret + `","other":"untouched"}}],"summary":"two tools"}}`)

	out, err := s.ScrubJSONFrame(frame)
	if err != nil {
		t.Fatalf("ScrubJSONFrame err = %v", err)
	}

	// Invariant 1: output decodes as valid JSON.
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("scrubbed frame is not valid JSON (framing broken): %v; payload=%s", err, string(out))
	}

	// Invariant 2: structural keys preserved.
	if decoded["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc key mutated: %v", decoded["jsonrpc"])
	}
	if v, ok := decoded["id"].(float64); !ok || v != 42 {
		t.Errorf("id key mutated: %v", decoded["id"])
	}
	result, ok := decoded["result"].(map[string]any)
	if !ok {
		t.Fatalf("result key not an object: %v", decoded["result"])
	}
	if result["summary"] != "two tools" {
		t.Errorf("summary value mutated: %v", result["summary"])
	}
	tools, ok := result["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools array shape mutated: %v", result["tools"])
	}
	tool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("tools[0] not an object: %v", tools[0])
	}
	if tool["name"] != "safe-tool" {
		t.Errorf("tools[0].name mutated: %v", tool["name"])
	}
	meta, ok := tool["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata not an object: %v", tool["metadata"])
	}
	if meta["other"] != "untouched" {
		t.Errorf("non-secret value mutated: %v", meta["other"])
	}

	// Invariant 3: matched value is replaced by the sentinel; the
	// raw secret is absent.
	tok, _ := meta["token"].(string)
	if strings.Contains(tok, secret) {
		t.Errorf("token field still carries the raw secret: %q", tok)
	}
	if !strings.Contains(tok, "[REDACTED") {
		t.Errorf("token field missing sentinel after walk: %q", tok)
	}
	// And the raw secret must not appear ANYWHERE in the output
	// (defense-in-depth against a future refactor that lets the
	// walker accidentally re-emit the value).
	if bytes.Contains(out, []byte(secret)) {
		t.Errorf("scrubbed output still carries raw secret bytes: %s", string(out))
	}
}

// TestMCPShim_SecretSplitAcrossChunks is the Plan Batch 3.4
// acceptance test for the rolling-buffer streaming scanner. A
// secret whose bytes straddle two ScrubChunk calls (the boundary
// case the 256-byte overlap window is designed to catch) must still
// be redacted. The plan's "Rolling-buffer scanner with 256-byte
// overlap" locked decision is the contract; this test pins the
// behavior so a future refactor cannot regress to per-chunk-only
// scanning.
func TestMCPShim_SecretSplitAcrossChunks(t *testing.T) {
	s := newMCPScrubber(scanners.BuiltInSecretPatterns())

	// Build a payload whose canonical Anthropic key is split exactly
	// in the middle: the first ScrubChunk sees bytes up to "sk-ant-"
	// + 4 chars; the second ScrubChunk sees the trailing bytes. With
	// a chunk-only scanner the secret survives both passes; with the
	// rolling-buffer overlap the boundary is re-scanned and the
	// match fires.
	//
	// The trailing space between the noise prefix and the "sk-ant-"
	// is required so the pattern's leading \b word boundary matches
	// (a contiguous \w-class run between the noise and the secret
	// would defeat \b and break the test regardless of buffer
	// behavior).
	secret := "sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM"
	prefix := "noise-prefix-leading-bytes-" + strings.Repeat("a", 60) + " "
	suffix := " trailing-noise-bytes-" + strings.Repeat("z", 400)
	full := prefix + secret + suffix

	// Cut the secret exactly in the middle so the boundary straddles
	// the match. The chunk boundary is at `prefix + "sk-ant-AABB"`;
	// the remaining "CCDDEEFFGGHHIIJJKKLLMM" is in the second chunk.
	cutOffset := len(prefix) + len("sk-ant-") + 4
	first := []byte(full[:cutOffset])
	second := []byte(full[cutOffset:])

	// Sanity: each half ALONE does not match the pattern (the
	// rolling buffer is the only way to catch this; if a half
	// matched on its own the test would not be exercising the
	// boundary case).
	halfDetector := newMCPScrubber(scanners.BuiltInSecretPatterns())
	firstOut := halfDetector.ScrubChunk(first)
	firstTail := halfDetector.Flush()
	combined := string(append(firstOut, firstTail...))
	// The first half alone should not produce a redaction (the
	// sk-ant- prefix without enough trailing chars is below the
	// pattern's minimum length).
	if strings.Contains(combined, "[REDACTED") {
		t.Logf("first half alone matched (acceptable, but means the test does not exercise the boundary case)")
	}

	// Drive the real scrubber across BOTH chunks.
	out := s.ScrubChunk(first)
	out = append(out, s.ScrubChunk(second)...)
	out = append(out, s.Flush()...)

	if bytes.Contains(out, []byte(secret)) {
		t.Errorf("boundary-split secret survived the rolling buffer: %s", string(out))
	}
	if !bytes.Contains(out, []byte("[REDACTED")) {
		t.Errorf("rolling-buffer scrubber missing sentinel after boundary scan: %s", string(out))
	}
}
