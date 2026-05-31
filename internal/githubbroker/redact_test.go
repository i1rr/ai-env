// redact_test.go covers the pure logic in redact.go: the RedactTokens
// pattern set, the Logger decorator's no-op / wrap behaviour, and the
// RedactingWriter line-buffered forwarding contract. These tests are
// intentionally scoped to the host-side primitives; integration with
// the rest of the broker (the AcquireToken / PushBranch happy path
// emitting a redacted log line) lands in plan 07 batch 8.

package githubbroker

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// Fake-shape tokens reused across cases. These are NOT live secrets;
// they exist only to match the prefix-anchored regex set so the
// redactor's behaviour can be asserted without scattering string
// literals through the test file.
const (
	fakeGhpToken    = "ghp_AAAAAAAAAAAAAAAAAAAA12345678901234"
	fakeGhsToken    = "ghs_BBBBBBBBBBBBBBBBBBBB12345678901234"
	fakeGhoToken    = "gho_CCCCCCCCCCCCCCCCCCCC12345678901234"
	fakeGhuToken    = "ghu_DDDDDDDDDDDDDDDDDDDD12345678901234"
	fakeGhrToken    = "ghr_EEEEEEEEEEEEEEEEEEEE12345678901234"
	fakeFineGrained = "github_pat_FFFFFFFFFFFFFFFFFFFF1234567890"
	// The v1.<hex> shape is the legacy GitHub App installation token
	// the redactor accepts. 40 hex chars is the regex minimum.
	fakeV1Token = "v1.0123456789abcdef0123456789abcdef01234567"
)

// TestRedactTokens_GitHubPrefixedShapes pins the broker's primary
// concern: every GitHub-issued credential shape the broker handles is
// rewritten to the redacted placeholder.
func TestRedactTokens_GitHubPrefixedShapes(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"classic PAT", fakeGhpToken},
		{"fine-grained PAT", fakeFineGrained},
		{"OAuth token", fakeGhoToken},
		{"user-to-server token", fakeGhuToken},
		{"server / App installation token", fakeGhsToken},
		{"refresh token", fakeGhrToken},
		{"legacy v1.<hex> installation token", fakeV1Token},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := "broker: acquired token=" + tc.token + " for installation 42"
			got := RedactTokens(line)
			if strings.Contains(got, tc.token) {
				t.Fatalf("RedactTokens did not remove %s\ninput: %s\noutput: %s", tc.token, line, got)
			}
			if !strings.Contains(got, RedactedPlaceholder) {
				t.Fatalf("RedactTokens did not insert %s marker\noutput: %s", RedactedPlaceholder, got)
			}
			// Surrounding text must survive so grep on the log line
			// still works after redaction.
			if !strings.Contains(got, "broker: acquired token=") {
				t.Fatalf("RedactTokens mangled surrounding text: %s", got)
			}
			if !strings.Contains(got, "for installation 42") {
				t.Fatalf("RedactTokens mangled trailing text: %s", got)
			}
		})
	}
}

// TestRedactTokens_AuthorizationHeaderShapes pins the generic Bearer /
// token header sweep: a header line a third-party library echoed into
// the log must lose its value before the line is written.
func TestRedactTokens_AuthorizationHeaderShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"Bearer header", "Authorization: Bearer " + fakeGhsToken},
		{"token header lowercase", "authorization: token " + fakeGhpToken},
		{"token header mixed case", "AUTHORIZATION: Token " + fakeGhpToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactTokens(tc.in)
			if strings.Contains(got, fakeGhsToken) || strings.Contains(got, fakeGhpToken) {
				t.Fatalf("RedactTokens leaked token\ninput: %s\noutput: %s", tc.in, got)
			}
			if !strings.Contains(got, RedactedPlaceholder) {
				t.Fatalf("RedactTokens did not insert placeholder\noutput: %s", got)
			}
		})
	}
}

// TestRedactTokens_MultipleTokensSingleLine covers the case where a
// single log line carries two distinct token shapes (e.g. a debug
// trace that dumps both an old and a new credential). Both must be
// redacted in one pass.
func TestRedactTokens_MultipleTokensSingleLine(t *testing.T) {
	line := "rotated " + fakeGhsToken + " -> " + fakeGhpToken
	got := RedactTokens(line)
	if strings.Contains(got, fakeGhsToken) {
		t.Fatalf("first token leaked: %s", got)
	}
	if strings.Contains(got, fakeGhpToken) {
		t.Fatalf("second token leaked: %s", got)
	}
	// Two redactions should produce two placeholder markers.
	if n := strings.Count(got, RedactedPlaceholder); n != 2 {
		t.Fatalf("want 2 placeholders, got %d (output=%s)", n, got)
	}
}

// TestRedactTokens_PreservesNonSecretText pins the "no false positives
// on innocuous strings" contract: a string with no token shapes must
// be returned byte-identical so call sites that pipe normal log lines
// through the redactor pay no cost.
func TestRedactTokens_PreservesNonSecretText(t *testing.T) {
	cases := []string{
		"",
		"plain log line with no secrets",
		"branch=ai-env/fix-tests repo=owner/name run_id=20260531-101300-a1b2c3",
		// "v1.deadbeef" is not 40 hex chars so it must NOT be redacted
		// (avoids matching innocuous version strings).
		"using API version v1.deadbeef as documented",
		// A short ghp_ prefix that does not meet the 30-char minimum
		// must NOT match either; the broker's contract is to leak
		// nothing while accepting innocuous prefixes.
		"variable name: ghp_short",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got := RedactTokens(in)
			if got != in {
				t.Fatalf("RedactTokens mutated benign input\nin:  %q\nout: %q", in, got)
			}
		})
	}
}

// TestRedactTokens_FoldsInProxyPatterns proves that calling
// RedactTokens also covers the Plan 05 secrets.RedactSecrets set, so a
// caller has exactly one entry point to remember.
func TestRedactTokens_FoldsInProxyPatterns(t *testing.T) {
	// sk-ant- is the Anthropic prefix the proxy redactor handles.
	line := "proxied upstream: sk-ant-AAAAAAAAAAAAAAAAAAAA1234567890 OK"
	got := RedactTokens(line)
	if strings.Contains(got, "sk-ant-AAAAAAAAAAAAAAAAAAAA1234567890") {
		t.Fatalf("proxy-pattern token leaked: %s", got)
	}
	// The proxy uses "REDACTED" (no brackets); accept either marker so
	// this test is not coupled to the proxy's exact placeholder text.
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("expected a redaction marker, got: %s", got)
	}
}

// TestNewRedactingLogger_WrapsAndRedacts covers the Logger decorator:
// the wrapper forwards lines after redaction, and a nil inner produces
// a no-op so call sites can always wrap.
func TestNewRedactingLogger_WrapsAndRedacts(t *testing.T) {
	t.Run("nil inner is a safe no-op", func(t *testing.T) {
		log := NewRedactingLogger(nil)
		if log == nil {
			t.Fatal("NewRedactingLogger(nil) returned nil; want a no-op closure")
		}
		// Calling the no-op must not panic.
		log("anything " + fakeGhsToken)
	})

	t.Run("wraps and redacts", func(t *testing.T) {
		var captured []string
		var mu sync.Mutex
		inner := Logger(func(line string) {
			mu.Lock()
			defer mu.Unlock()
			captured = append(captured, line)
		})
		log := NewRedactingLogger(inner)

		log("issued token " + fakeGhsToken)
		log("benign line")

		mu.Lock()
		defer mu.Unlock()
		if len(captured) != 2 {
			t.Fatalf("captured %d lines, want 2: %v", len(captured), captured)
		}
		if strings.Contains(captured[0], fakeGhsToken) {
			t.Fatalf("first captured line leaks token: %s", captured[0])
		}
		if !strings.Contains(captured[0], RedactedPlaceholder) {
			t.Fatalf("first captured line missing placeholder: %s", captured[0])
		}
		if captured[1] != "benign line" {
			t.Fatalf("benign line was mutated: %q", captured[1])
		}
	})
}

// TestRedactingWriter_LineBufferedRedaction covers the io.Writer
// wrapper: bytes are buffered until a newline arrives, then the
// completed line is redacted and forwarded. A token split across two
// Write calls is still redacted because the partial line stays in the
// buffer.
func TestRedactingWriter_LineBufferedRedaction(t *testing.T) {
	var sink bytes.Buffer
	w := NewRedactingWriter(&sink)

	// Token split across two Writes; second write completes the line.
	first := "broker: acquired " + fakeGhsToken[:10]
	second := fakeGhsToken[10:] + " for installation 42\n"
	if _, err := w.Write([]byte(first)); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	// Sink must still be empty: no newline has arrived yet so the
	// partial line stays in the buffer.
	if sink.Len() != 0 {
		t.Fatalf("sink populated before newline: %q", sink.String())
	}
	if _, err := w.Write([]byte(second)); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	got := sink.String()
	if strings.Contains(got, fakeGhsToken) {
		t.Fatalf("RedactingWriter leaked split token: %s", got)
	}
	if !strings.Contains(got, RedactedPlaceholder) {
		t.Fatalf("RedactingWriter did not insert placeholder: %s", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("RedactingWriter dropped trailing newline: %q", got)
	}
}

// TestRedactingWriter_FlushEmitsPartialLine pins the Flush contract:
// a partial line in the buffer must be redacted and emitted when
// Flush is called (the broker calls Flush from its teardown so an
// abrupt exit still surfaces the redacted prefix).
func TestRedactingWriter_FlushEmitsPartialLine(t *testing.T) {
	var sink bytes.Buffer
	w := NewRedactingWriter(&sink)

	partial := "broker: about to acquire " + fakeGhpToken
	if _, err := w.Write([]byte(partial)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if sink.Len() != 0 {
		t.Fatalf("sink populated before flush: %q", sink.String())
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	got := sink.String()
	if strings.Contains(got, fakeGhpToken) {
		t.Fatalf("Flush leaked token: %s", got)
	}
	if !strings.Contains(got, RedactedPlaceholder) {
		t.Fatalf("Flush did not insert placeholder: %s", got)
	}

	// A second Flush with nothing buffered must be a no-op.
	beforeLen := sink.Len()
	if err := w.Flush(); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
	if sink.Len() != beforeLen {
		t.Fatalf("second Flush wrote bytes: before=%d after=%d", beforeLen, sink.Len())
	}
}

// TestRedactingWriter_NilDstIsSafe covers the defensive default: a
// nil destination is treated as io.Discard so the writer is always
// safe to use without callers having to guard.
func TestRedactingWriter_NilDstIsSafe(t *testing.T) {
	w := NewRedactingWriter(nil)
	n, err := w.Write([]byte("anything " + fakeGhsToken + "\n"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n == 0 {
		t.Fatal("Write returned 0; want full byte count")
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

// TestRedactingWriter_MultipleLinesInOneWrite covers the case where a
// single Write carries several newline-terminated lines: each line
// must be redacted independently and forwarded in order.
func TestRedactingWriter_MultipleLinesInOneWrite(t *testing.T) {
	var sink bytes.Buffer
	w := NewRedactingWriter(&sink)

	payload := "first " + fakeGhsToken + "\nsecond " + fakeGhpToken + "\nthird benign\n"
	if _, err := w.Write([]byte(payload)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := sink.String()
	if strings.Contains(got, fakeGhsToken) || strings.Contains(got, fakeGhpToken) {
		t.Fatalf("leaked token in batched write: %s", got)
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d (%q)", len(lines), got)
	}
	if !strings.HasPrefix(lines[0], "first ") {
		t.Fatalf("first line wrong prefix: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "second ") {
		t.Fatalf("second line wrong prefix: %q", lines[1])
	}
	if lines[2] != "third benign" {
		t.Fatalf("third line mutated: %q", lines[2])
	}
}
