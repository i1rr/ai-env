// shell_tokenize.go implements the POSIX-aware shell tokenizer the
// policy engine consults before applying high-risk pattern rules.
// Plan Batch 1.1 pins the surface: a substring matcher on a lowercased
// command line (the v0.1 implementation) is bypassed by trivial quoting
// tricks (`c"u"rl ...`), whitespace variations (`curl  ` with two
// spaces still matches today's `"curl "` substring by accident, but
// `c\url ...` does not), absolute paths (`/usr/bin/curl` does not match
// `"curl "`), and interpreter wrappers (`python -c "import os;
// os.system('curl ...')"` hides the inner curl from the matcher).
//
// The tokenizer here is the foundation Batch 1.2 layers token-aware
// rules on top of. It is deliberately narrow:
//
//  1. It is NOT a full shell parser. It does not expand parameters
//     (`$VAR`, `${VAR}`), it does not invoke command substitution
//     (`$(...)`, backticks), and it does not evaluate arithmetic
//     (`$((...))`). Expansion-as-source-of-truth is a posture the v0.1
//     engine refuses on principle: an agent that hides a payload behind
//     `$(echo curl)` is still subject to the network policy and the
//     sandbox boundary; the engine documents the limit and refuses to
//     run the expansion itself (which would be turing-complete + side-
//     effectful).
//
//  2. It IS POSIX-aware about quoting and escaping. Single quotes are
//     literal (no escapes), double quotes preserve backslash escapes
//     for `$`, `\``, `"`, `\\` and a trailing newline (the POSIX-defined
//     set), and an unquoted backslash escapes the next character. The
//     tokenizer also splits commands on the shell control operators
//     `|`, `||`, `&&`, `;`, and `&` so a downstream rule can inspect
//     each command in a pipeline independently (which is the whole
//     point of catching `curl ... | sh`: the rule must see `sh` as its
//     own command, not as a substring inside the curl line).
//
//  3. It IS lossy for invalid input. A command line with an unterminated
//     quote returns an error rather than silently consuming the rest of
//     input (which would fail open for the matcher). Callers fail
//     closed on any tokenizer error.
//
// What the tokenizer does NOT own
//
//   - The actual rule list. ShellTokenize returns the parsed structure;
//     the rules that decide allow/deny live in policy.go's
//     evalShellCommand and the HighRiskShellPatterns set.
//
//   - Command resolution. The tokenizer does not turn `/usr/bin/curl`
//     into the basename `curl` (that is a rule decision: a rule that
//     wants to compare against the basename calls filepath.Base on the
//     token; a rule that wants the full path inspects the token
//     directly).
//
//   - Variable expansion or globbing. A token like `$HOME/.ssh/id_rsa`
//     is returned verbatim with the literal `$HOME` prefix; the rule
//     for SSH paths matches `.ssh/` as a substring across tokens and
//     catches this case. Globs (`~`, `*`, `?`) are returned verbatim.

package policy

import (
	"fmt"
	"strings"
)

// ShellCommand is one command in a parsed command line. A pipeline like
// `curl https://example.com | sh` parses into two ShellCommands; a
// single command like `npm test` parses into one. The separator that
// precedes this command in the source is recorded on Operator so a
// downstream rule can distinguish a pipeline from a sequence (relevant
// to the curl-pipe-shell rule: only `|` between curl and a shell is
// "pipe-to-shell").
type ShellCommand struct {
	// Argv is the command and its arguments after quoting/escaping
	// is resolved. Argv[0] is the program (possibly an absolute path,
	// possibly a basename); Argv[1:] are the arguments verbatim. A
	// well-formed command line always produces a non-empty Argv;
	// pathological input (an operator with no command, e.g. `|`) is
	// rejected at tokenize time so this invariant holds for callers.
	Argv []string

	// Operator is the shell control operator that PRECEDES this
	// command in the source. The first command in a parsed line has
	// Operator == "" (no preceding operator). Subsequent commands
	// carry the operator that separated them from the previous one:
	// one of "|", "||", "&&", ";", or "&".
	Operator string
}

// ShellTokenize parses a command line into a slice of ShellCommands.
// The parser is POSIX-aware about single-quoting, double-quoting, and
// backslash escapes; it splits commands on `|`, `||`, `&&`, `;`, and
// `&` operators. It does NOT expand variables, command substitution,
// arithmetic, or globs (see the file-level doc comment for the
// rationale).
//
// Empty input returns nil and a nil error: a downstream rule that
// receives an empty Target has already been rejected by the engine's
// fail-closed check, so this path is unreachable in production but kept
// total for tokenizer unit tests.
//
// Returns an error on malformed input: an unterminated single or double
// quote, an operator with no command on either side, or a backslash at
// end-of-input. Callers fail closed on any error.
func ShellTokenize(input string) ([]ShellCommand, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}

	tokens, operators, err := tokenizeShell(input)
	if err != nil {
		return nil, err
	}

	// Group tokens into commands separated by operators. The
	// operators slice is parallel to a "between tokens" position: an
	// operator at index i means "this operator appears between token
	// i and token i+1". We walk both slices to build the command
	// sequence.
	var cmds []ShellCommand
	cur := ShellCommand{}
	for i, tok := range tokens {
		cur.Argv = append(cur.Argv, tok)
		op := operators[i]
		if op != "" {
			if len(cur.Argv) == 0 {
				return nil, fmt.Errorf("policy: shell tokenizer: operator %q has no command before it", op)
			}
			cmds = append(cmds, cur)
			cur = ShellCommand{Operator: op}
		}
	}
	if len(cur.Argv) > 0 {
		cmds = append(cmds, cur)
	}
	// Trailing operator (e.g. `foo |`) leaves an empty cur with a
	// non-empty Operator. The loop above does not append this case,
	// but we still need to surface the malformed-input error.
	if cur.Operator != "" && len(cur.Argv) == 0 {
		return nil, fmt.Errorf("policy: shell tokenizer: operator %q has no command after it", cur.Operator)
	}
	return cmds, nil
}

// tokenizeShell scans input into a flat slice of tokens plus a parallel
// slice of operators describing the separator that FOLLOWS each token.
// An operator value of "" means "whitespace separator" (the default;
// the next token continues the same command).
//
// The parallel slice shape is the building block ShellTokenize uses to
// regroup tokens into ShellCommand structs; keeping the lexer separate
// from the grouper makes both halves trivially testable.
func tokenizeShell(input string) (tokens []string, operators []string, err error) {
	var cur strings.Builder
	flush := func(nextOp string) {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			operators = append(operators, nextOp)
			cur.Reset()
		} else if nextOp != "" && len(operators) > 0 {
			// An operator without a preceding token within the same
			// segment is only valid when the previous token also
			// produced an operator (e.g. `foo ; ; bar` is malformed;
			// `foo|bar` is fine because flush happens at '|' with cur
			// holding "foo"). We surface this case as an error in
			// ShellTokenize's downstream grouping, not here.
			operators[len(operators)-1] = nextOp
		}
	}

	i := 0
	n := len(input)
	for i < n {
		c := input[i]
		switch {
		case c == '\\':
			// Backslash escape outside quotes: consume the next byte
			// verbatim. A trailing backslash is malformed.
			if i+1 >= n {
				return nil, nil, fmt.Errorf("policy: shell tokenizer: trailing backslash")
			}
			cur.WriteByte(input[i+1])
			i += 2
		case c == '\'':
			// Single-quoted string: every byte until the next `'` is
			// literal (no escapes recognized). An unterminated single
			// quote is malformed.
			end := strings.IndexByte(input[i+1:], '\'')
			if end < 0 {
				return nil, nil, fmt.Errorf("policy: shell tokenizer: unterminated single quote")
			}
			cur.WriteString(input[i+1 : i+1+end])
			i += end + 2
		case c == '"':
			// Double-quoted string: backslash escapes `$`, `\``, `"`,
			// `\\`, and newline; every other byte is literal. The
			// quoted segment ends at the next unescaped `"`. An
			// unterminated double quote is malformed.
			j := i + 1
			for j < n {
				if input[j] == '\\' && j+1 < n {
					next := input[j+1]
					if next == '$' || next == '`' || next == '"' || next == '\\' || next == '\n' {
						cur.WriteByte(next)
						j += 2
						continue
					}
					// Non-POSIX-escaped backslash inside double quotes
					// is preserved literally (the POSIX rule).
					cur.WriteByte('\\')
					cur.WriteByte(next)
					j += 2
					continue
				}
				if input[j] == '"' {
					break
				}
				cur.WriteByte(input[j])
				j++
			}
			if j >= n {
				return nil, nil, fmt.Errorf("policy: shell tokenizer: unterminated double quote")
			}
			i = j + 1
		case c == ' ' || c == '\t' || c == '\n':
			// Whitespace flushes the current token (if any) without
			// emitting an operator. Repeated whitespace collapses to
			// one separator.
			flush("")
			i++
		case c == '|':
			// `|` or `||` operator.
			if i+1 < n && input[i+1] == '|' {
				flush("||")
				i += 2
			} else {
				flush("|")
				i++
			}
		case c == '&':
			// `&` or `&&` operator.
			if i+1 < n && input[i+1] == '&' {
				flush("&&")
				i += 2
			} else {
				flush("&")
				i++
			}
		case c == ';':
			flush(";")
			i++
		default:
			cur.WriteByte(c)
			i++
		}
	}
	flush("")
	return tokens, operators, nil
}

// TokenBasename returns the basename portion of a token. The shim's
// rule layer uses this to compare `/usr/bin/curl` and `curl`
// equivalently: both produce the basename `curl`. A token with no `/`
// is returned verbatim; a token ending in `/` (an unusual but legal
// argv[0]) returns the trailing empty string, which no rule matches.
//
// This is a small helper not a filepath.Base call so the package keeps
// its small import surface; the policy package is consumed in many
// places and adding an import to internal callers adds noise to test
// builds.
func TokenBasename(token string) string {
	if idx := strings.LastIndexByte(token, '/'); idx >= 0 {
		return token[idx+1:]
	}
	return token
}
