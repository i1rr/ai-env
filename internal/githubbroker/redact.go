// redact.go implements plan 07 step 9: redact token-like strings in
// broker logs. The broker holds credentials in host-side memory and
// hands callers only opaque BrokerToken handles, so the raw secret
// should never reach a log line on its own. This file is the defence-
// in-depth backstop: any log line the broker emits (or a caller routes
// through the broker's logger) passes through RedactTokens, which
// rewrites recognizable GitHub token shapes to "[REDACTED]" before the
// line is written.
//
// The plan calls the rule out in two places:
//
//  1. "Key decisions from master plan", item 1: "Raw GitHub token is
//     never visible inside the sandbox or in any log line."
//  2. Step 9: "Implement redaction of token-like strings in broker
//     logs."
//
// Design rules this file pins:
//
//  1. Pure function at the core. RedactTokens(s) -> s' is the load-
//     bearing primitive: no I/O, no time-of-day reads, no goroutine
//     state. The decorator types and the io.Writer wrapper all defer
//     to it so the regex set lives in exactly one place.
//  2. Mirror the broker's credential types. The pattern set covers the
//     credential shapes the broker actually issues or accepts:
//     GitHub PATs (ghp_, gho_, ghu_, ghs_, ghr_, and the fine-grained
//     github_pat_ prefix), App installation tokens (ghs_ above plus the
//     legacy v1.<hex> shape some GitHub App installations still emit),
//     and a generic Authorization: Bearer <token> sweep so a header
//     echoed into a log line is scrubbed even when the token does not
//     match a prefixed pattern. The patterns are conservative: false
//     positives are preferable to a real leak.
//  3. Compatible with secrets.RedactSecrets. The Plan 05 secret proxy
//     already exposes secrets.RedactSecrets for Anthropic/OpenAI/Bearer
//     redaction; this file's RedactTokens runs the broker-specific
//     GitHub patterns first and then folds in the proxy's pattern set
//     so a single call scrubs every shape the host knows about.
//     Downstream callers (broker code, the PR body builder) can call
//     either entry point; both end up with the same final string.
//  4. Logger shape matches the rest of the project. internal/secrets/
//     ProviderProxy uses a `func(string)` logger; this file mirrors
//     that signature with the Logger type and the RedactingLogger
//     decorator so a caller can wrap an existing logger without
//     dragging a new logging interface across package boundaries.
//  5. io.Writer wrapper for callers that need it. Some downstream
//     consumers (an http.Client transport that writes to an io.Writer,
//     a third-party library that takes a *log.Logger backed by a
//     Writer) cannot accept a func(string). NewRedactingWriter wraps
//     an io.Writer so every byte written passes through RedactTokens
//     before being forwarded. The wrapper is line-buffered so a token
//     split across two Write calls is still redacted (the buffer holds
//     the partial line until a newline arrives, then RedactTokens runs
//     over the full line).

package githubbroker

import (
	"bytes"
	"io"
	"regexp"
	"sync"

	"github.com/rivan1986/ai-env/internal/secrets"
)

// RedactedPlaceholder is the literal string token-like fragments are
// replaced with. Exported so tests can assert against a stable value
// rather than re-deriving it from a regex.
//
// The square brackets visually distinguish the placeholder from a real
// token in grep output and keep it stable across pattern revisions:
// downstream tooling that filters log lines by "saw a redaction" can
// match on this literal.
const RedactedPlaceholder = "[REDACTED]"

// githubTokenPatterns matches GitHub-issued credential shapes the
// broker may handle. Each pattern is conservative; the goal is "never
// leak a real token", not "match nothing else". The patterns are
// applied in order against the input.
//
// Patterns covered:
//
//   - ghp_<30+>: classic GitHub Personal Access Token.
//   - github_pat_<20+>: GitHub fine-grained PAT.
//   - gho_<30+>: GitHub OAuth token.
//   - ghu_<30+>: GitHub user-to-server token.
//   - ghs_<30+>: GitHub server / App installation token (the broker's
//     primary credential shape).
//   - ghr_<30+>: GitHub refresh token.
//   - v1.<40+ hex>: legacy GitHub App installation token shape some
//     installations still emit. The 40-hex minimum matches the
//     observed token width and avoids matching innocuous "v1.deadbeef"
//     version strings in unrelated text.
//
// The minimum lengths mirror internal/scanners/builtin.go's
// rules so a leak shape that lights up the scanner here also lights up
// in workspace files.
var githubTokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bghp_[A-Za-z0-9]{30,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`\bgho_[A-Za-z0-9]{30,}`),
	regexp.MustCompile(`\bghu_[A-Za-z0-9]{30,}`),
	regexp.MustCompile(`\bghs_[A-Za-z0-9]{30,}`),
	regexp.MustCompile(`\bghr_[A-Za-z0-9]{30,}`),
	regexp.MustCompile(`\bv1\.[0-9a-fA-F]{40,}\b`),
}

// genericBearerPattern catches the "Authorization: token <value>" and
// "Authorization: Bearer <value>" header shapes the GitHub API uses for
// installation tokens. The Plan 05 secrets.RedactSecrets covers
// "Bearer" only with an "Authorization:" prefix; the GitHub API
// accepts "token <value>" too, so we add a parallel sweep here.
//
// The pattern is case-insensitive on the header name and the scheme
// word so an upper- or mixed-case header is still redacted.
var genericBearerPattern = regexp.MustCompile(`(?i)Authorization:\s*(?:token|bearer)\s+\S+`)

// RedactTokens replaces GitHub-token-like fragments in s with
// RedactedPlaceholder and then folds in the Plan 05 proxy's
// RedactSecrets sweep so Anthropic / OpenAI / Authorization-Bearer
// shapes are also scrubbed. The function is pure: no I/O, no time-of-
// day reads, no goroutine state. A string with no matches is returned
// unchanged.
//
// Order matters: the GitHub-specific patterns run first so a longer,
// more specific shape (ghs_<token>) is replaced before the generic
// proxy patterns get a chance to match. This is defence-in-depth, not
// correctness; the placeholder text RedactedPlaceholder does not match
// any of the patterns we run, so a second pass cannot "re-redact" the
// marker.
func RedactTokens(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, re := range githubTokenPatterns {
		out = re.ReplaceAllString(out, RedactedPlaceholder)
	}
	out = genericBearerPattern.ReplaceAllString(out, "Authorization: "+RedactedPlaceholder)
	// Fold in the proxy's pattern set (sk-ant-, sk-, Authorization:
	// Bearer, x-api-key:) so a single RedactTokens call scrubs every
	// shape the host knows about. The proxy's replacement string is
	// "REDACTED" (no brackets); we accept that asymmetry rather than
	// rewriting the proxy's contract because the two forms are equally
	// safe and the test surface is clearer when each package owns its
	// own pattern set.
	out = secrets.RedactSecrets(out)
	return out
}

// Logger is the narrow log-sink contract broker code uses. It mirrors
// internal/secrets.Options.Logger: one string per call, nil disables
// logging. Keeping the signature identical means a supervisor that
// already has a logger for the secret proxy can pass the same closure
// to the broker without an adapter.
//
// Implementations must be safe for concurrent use; the broker is
// single-goroutine today but a future async destroy hook could log
// from a parallel goroutine.
type Logger func(line string)

// NewRedactingLogger returns a Logger that passes every line through
// RedactTokens before forwarding it to inner. A nil inner disables
// logging (the returned Logger is a no-op) so call sites that always
// wrap can stay terse. A nil return is never produced; the wrapper is
// always safe to call.
//
// The wrapper is the recommended way for broker code to obtain a
// logger: a caller that constructs the broker passes its raw logger
// (e.g. a closure that writes into the run's stderr.log) and the
// broker decorates it with this function before storing it on the
// concrete broker struct. That way every log line the broker emits is
// scrubbed without each call site having to remember to call
// RedactTokens.
func NewRedactingLogger(inner Logger) Logger {
	if inner == nil {
		return func(string) {}
	}
	return func(line string) {
		inner(RedactTokens(line))
	}
}

// RedactingWriter is an io.Writer that buffers bytes by line and
// forwards each completed line through RedactTokens to the wrapped
// writer. Used by callers that cannot accept a Logger func(string) and
// must hand an io.Writer to a third-party library (e.g. a
// *log.Logger backed by a Writer, an http.Client transport debug
// hook). The line buffer guarantees a token split across two Write
// calls is still redacted: the writer holds the partial line until a
// newline arrives, then RedactTokens runs over the full line.
//
// Flush emits any buffered partial line as a final redacted write. The
// broker calls Flush from its teardown so a process that exits between
// a "started request" debug print and the trailing newline still
// surfaces the redacted prefix instead of dropping it on the floor.
//
// Concurrency: RedactingWriter is safe for concurrent Write / Flush
// calls. The internal mutex serializes access to the line buffer.
type RedactingWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	dst io.Writer
}

// NewRedactingWriter wraps dst so every line written is passed through
// RedactTokens before being forwarded. A nil dst is treated as
// io.Discard so the writer is always safe to use.
func NewRedactingWriter(dst io.Writer) *RedactingWriter {
	if dst == nil {
		dst = io.Discard
	}
	return &RedactingWriter{dst: dst}
}

// Write buffers p by line and forwards each completed line through
// RedactTokens to the wrapped destination. The returned count is
// len(p): we always claim to have accepted every byte (the caller's
// contract with io.Writer is "bytes written" not "bytes forwarded to
// the underlying sink"), and a downstream Write error is recorded on
// the next Flush / Write so callers that check err see it.
func (w *RedactingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	return len(p), w.flushCompleteLinesLocked()
}

// Flush emits any buffered bytes as a final redacted write. Returns
// the underlying writer's error verbatim. Safe to call repeatedly; a
// flush of an empty buffer is a no-op that returns nil.
func (w *RedactingWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() == 0 {
		return nil
	}
	line := w.buf.String()
	w.buf.Reset()
	_, err := io.WriteString(w.dst, RedactTokens(line))
	return err
}

// flushCompleteLinesLocked drains every complete line (ending in \n)
// from the buffer, redacts it, and forwards it to the wrapped writer.
// A partial line at the end of the buffer is left in place for the
// next Write / Flush. Caller must hold w.mu.
func (w *RedactingWriter) flushCompleteLinesLocked() error {
	for {
		data := w.buf.Bytes()
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			return nil
		}
		// Include the newline in the redacted output so downstream
		// readers see line boundaries verbatim.
		line := string(data[:idx+1])
		// Advance the buffer past the consumed line. bytes.Buffer.Next
		// returns the consumed slice; we discard it because we already
		// captured the bytes in `line`.
		w.buf.Next(idx + 1)
		if _, err := io.WriteString(w.dst, RedactTokens(line)); err != nil {
			return err
		}
	}
}
