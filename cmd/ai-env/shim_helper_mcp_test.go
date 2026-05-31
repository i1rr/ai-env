package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/scanners"
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
