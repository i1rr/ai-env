package cli

// policy.go implements plan 08 steps 3-6: the operator-facing
// `ai-env policy` family of subcommands. Each function below is a thin,
// Cobra-independent entry point with the same Options struct + RunXxx
// shape the rest of internal/cli uses (RunNew, RunList, RunStatus, etc.)
// so the Cobra wiring in cmd/ai-env can be a straight pass-through.
//
// The commands operate on the project-scoped `.ai-env/policy.yaml`
// document (mirroring how `ai-env scan` and `ai-env pr` read it via
// loadPolicyIfPresent). v0.1 keeps one policy file per project: the
// `<env-name>` positional argument is used to (a) scope the per-run
// audit reads (explain) and (b) validate the env name is well-formed
// for the check/allow/deny surfaces even though they mutate the
// project-wide file. The argument is preserved on the wire so a future
// version that adds per-env overrides can change the implementation
// without breaking the CLI contract.
//
// Design rules:
//
//  1. Locate the project's `.ai-env/` directory via findAIEnvDir so the
//     commands work from any subdirectory of the project (matching
//     `ai-env list` / `diff` / `patch`).
//  2. `policy init` is the only command that creates `policy.yaml`; the
//     others fail loudly when the file is missing rather than silently
//     using documented defaults so an operator who deleted the file
//     does not get a confusing "looks fine" check output.
//  3. Mutations (allow/deny) round-trip through ValidatePolicy before
//     writing so a typo in an existing field cannot turn a successful
//     allow-domain into an unreadable policy.
//  4. The on-disk YAML is rewritten with yaml.Marshal so the mutation
//     surface is byte-stable: the file is structurally identical to
//     what `ai-env new` would write (no merge conflicts when the
//     operator commits policy.yaml to git).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/rivan1986/ai-env/internal/config"
	"github.com/rivan1986/ai-env/internal/run"
)

// policyFileName is the basename of the project's policy document.
// Pinned here so every entry point in this file agrees on the name even
// if a future refactor moves the constant.
const policyFileName = "policy.yaml"

// PolicyInitOptions captures inputs for `ai-env policy init`.
type PolicyInitOptions struct {
	// Cwd is the working directory the command was invoked from. Used
	// to locate the project's .ai-env/ directory. Tests pass a temp
	// dir; the CLI wiring passes os.Getwd().
	Cwd string

	// Force allows overwriting an existing policy.yaml. Without it the
	// command refuses to clobber a customized file so a typo in the
	// subcommand cannot wipe an operator's tuned policy.
	Force bool

	// Stdout is the writer for the human-readable summary.
	Stdout io.Writer

	// Stderr is the writer for warnings. Today the command emits no
	// warnings; the field exists so a future "policy file present but
	// invalid" warning fits without changing the signature.
	Stderr io.Writer
}

// RunPolicyInit scaffolds a default .ai-env/policy.yaml for the current
// project. It mirrors the `ai-env new` flow's policy write step: the
// file is generated from defaultPolicyConfig, validated, and written at
// mode 0644.
//
// The command requires that the project already has an .ai-env/
// directory (i.e. `ai-env new` was run first). Creating .ai-env/ from
// scratch is `ai-env new`'s job; `ai-env policy init` only fills in the
// policy document, which is useful when an operator deleted it or never
// committed it.
//
// Behavior:
//
//   - Missing .ai-env/: hard error directing the operator to `ai-env new`.
//   - policy.yaml exists, no --force: refuse with an explicit error so
//     a tuned policy is never silently overwritten.
//   - policy.yaml exists, --force: rewrite with the default scaffold.
//   - policy.yaml missing: write the default and print a summary.
func RunPolicyInit(opts PolicyInitOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env policy init: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env policy init: %w", err)
	}

	policyPath := filepath.Join(aiEnvDir, policyFileName)
	if _, statErr := os.Stat(policyPath); statErr == nil {
		if !opts.Force {
			return fmt.Errorf("ai-env policy init: refusing to overwrite existing %s; rerun with --force to replace", policyPath)
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("ai-env policy init: stat %s: %w", policyPath, statErr)
	}

	cfg := defaultPolicyConfig()
	if err := config.ValidatePolicy(cfg); err != nil {
		return fmt.Errorf("ai-env policy init: generated policy.yaml is invalid: %w", err)
	}
	if err := writeYAMLFile(policyPath, cfg, 0o644); err != nil {
		return fmt.Errorf("ai-env policy init: %w", err)
	}

	fmt.Fprintf(opts.Stdout, "Wrote default policy to %s\n", policyPath)
	fmt.Fprintln(opts.Stdout, "")
	fmt.Fprintln(opts.Stdout, "Next: review the file, then run `ai-env policy check <env-name>`.")
	return nil
}

// PolicyCheckOptions captures inputs for `ai-env policy check <env-name>`.
type PolicyCheckOptions struct {
	// EnvName is the positional <env-name> argument. v0.1 stores one
	// policy.yaml per project, so EnvName is currently used only for
	// audit-trail context and for the env-name grammar check; the
	// summary it prints is the project-wide policy. Required.
	EnvName string

	// Cwd is the working directory the command was invoked from. Used
	// to locate the project's .ai-env/ directory.
	Cwd string

	// Stdout is the writer for the human-readable summary.
	Stdout io.Writer

	// Stderr is the writer for warnings (e.g. a stale field default).
	Stderr io.Writer
}

// RunPolicyCheck prints a summary of the project's policy.yaml together
// with any structural warnings (missing file, validation failures,
// surprising defaults). The output is intentionally simple
// (label-aligned colon-separated lines) so it is greppable and stable
// for tests.
//
// Behavior:
//
//   - Missing policy.yaml: hard error pointing at `ai-env policy init`.
//   - Malformed policy.yaml: surface the underlying validation error so
//     the operator sees the exact field that failed.
//   - Valid policy.yaml: print the summary, plus any soft warnings
//     about open-by-default fields (e.g. network.default == "allow")
//     so an operator immediately sees a permissive configuration.
func RunPolicyCheck(opts PolicyCheckOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env policy check: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env policy check: %w", err)
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env policy check: %w", err)
	}

	policyPath := filepath.Join(aiEnvDir, policyFileName)
	if _, statErr := os.Stat(policyPath); statErr != nil {
		if os.IsNotExist(statErr) {
			return fmt.Errorf("ai-env policy check: no %s; run `ai-env policy init` to scaffold one", policyPath)
		}
		return fmt.Errorf("ai-env policy check: stat %s: %w", policyPath, statErr)
	}

	cfg, err := config.LoadPolicy(policyPath)
	if err != nil {
		return fmt.Errorf("ai-env policy check: %w", err)
	}

	warnings := policyWarnings(cfg)
	for _, w := range warnings {
		fmt.Fprintln(opts.Stderr, "warning:", w)
	}

	renderPolicySummary(opts.Stdout, opts.EnvName, policyPath, cfg)
	return nil
}

// policyWarnings flags configuration values that are valid but
// permissive enough that an operator probably wants to know they are
// set that way. The list is intentionally short: the gate, network, and
// shell rules already enforce the deny-by-default contract, so a
// permissive policy.yaml is the only place where a careless operator
// can soften the defaults without realizing.
func policyWarnings(cfg *config.PolicyConfig) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	if strings.EqualFold(cfg.Network.Default, "allow") {
		out = append(out, "network.default is \"allow\"; sandbox egress is unrestricted by default")
	}
	if strings.EqualFold(cfg.Network.Enforcement, "none") {
		out = append(out, "network.enforcement is \"none\"; the backend will not enforce network policy")
	}
	if strings.EqualFold(cfg.Commands.Default, "allow") {
		out = append(out, "commands.default is \"allow\"; shell commands are unrestricted by default")
	}
	if cfg.Secrets.RawEnvInjection {
		out = append(out, "secrets.raw_env_injection is true; raw credentials may be exposed to the agent")
	}
	if !cfg.Review.FailOnSecretLeak {
		out = append(out, "review.fail_on_secret_leak is false; high-confidence secret findings will not block export")
	}
	return out
}

// renderPolicySummary writes a deterministic, column-aligned summary of
// cfg to w. The output mirrors `ai-env status` / `ai-env report` style:
// label-aligned colon-separated lines so the file is greppable and the
// test assertions remain stable.
func renderPolicySummary(w io.Writer, envName, policyPath string, cfg *config.PolicyConfig) {
	fmt.Fprintf(w, "env:             %s\n", envName)
	fmt.Fprintf(w, "policy file:     %s\n", policyPath)
	fmt.Fprintf(w, "version:         %d\n", cfg.Version)
	fmt.Fprintf(w, "mode:            %s\n", cfg.Mode)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "network:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  default\t%s\n", cfg.Network.Default)
	fmt.Fprintf(tw, "  enforcement\t%s\n", cfg.Network.Enforcement)
	fmt.Fprintf(tw, "  tls_mitm\t%t\n", cfg.Network.TLSMITM)
	fmt.Fprintf(tw, "  block_private_ranges\t%t\n", cfg.Network.BlockPrivateRanges)
	fmt.Fprintf(tw, "  block_metadata_services\t%t\n", cfg.Network.BlockMetadataServices)
	fmt.Fprintf(tw, "  block_localhost\t%t\n", cfg.Network.BlockLocalhost)
	fmt.Fprintf(tw, "  allow_domains\t%s\n", formatStringSlice(cfg.Network.AllowDomains))
	_ = tw.Flush()

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "filesystem:")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  workspace_write\t%t\n", cfg.Filesystem.WorkspaceWrite)
	fmt.Fprintf(tw, "  host_home_read\t%t\n", cfg.Filesystem.HostHomeRead)
	fmt.Fprintf(tw, "  host_home_write\t%t\n", cfg.Filesystem.HostHomeWrite)
	fmt.Fprintf(tw, "  protected_paths\t%s\n", formatStringSlice(cfg.Filesystem.ProtectedPaths))
	_ = tw.Flush()

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "commands:")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  default\t%s\n", cfg.Commands.Default)
	fmt.Fprintf(tw, "  deny_patterns\t%s\n", formatStringSlice(cfg.Commands.DenyPatterns))
	_ = tw.Flush()

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "review:")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  require_diff_review\t%t\n", cfg.Review.RequireDiffReview)
	fmt.Fprintf(tw, "  require_scan_before_export\t%t\n", cfg.Review.RequireScanBeforeExport)
	fmt.Fprintf(tw, "  fail_on_secret_leak\t%t\n", cfg.Review.FailOnSecretLeak)
	fmt.Fprintf(tw, "  fail_on_high_vulnerability\t%t\n", cfg.Review.FailOnHighVulnerability)
	fmt.Fprintf(tw, "  scan_pr_metadata\t%t\n", cfg.Review.ScanPRTitleBodyAndCommits)
	fmt.Fprintf(tw, "  block_auto_pr_on_workflow_changes\t%t\n", cfg.Review.BlockAutoPRonWorkflowChanges)
	_ = tw.Flush()
}

// formatStringSlice renders a string slice as "[a, b, c]" (or "[]" for
// empty / nil) so the policy summary stays on one line per field.
func formatStringSlice(s []string) string {
	if len(s) == 0 {
		return "[]"
	}
	return "[" + strings.Join(s, ", ") + "]"
}

// PolicyExplainOptions captures inputs for
// `ai-env policy explain <env-name> --event <event-id>`.
type PolicyExplainOptions struct {
	// EnvName is the positional <env-name> argument identifying which
	// env's run trail to search. Required.
	EnvName string

	// EventID is the engine's "evt_<ts>_<hex>" identifier or any
	// gate/broker-action record's stable spelling the operator wants
	// to look up. Required.
	EventID string

	// RunID, when non-empty, pins the search to a specific historical
	// run instead of the env's latest. Defaults to the env's latest
	// run.
	RunID string

	// Cwd is the working directory the command was invoked from. Used
	// to locate the project's .ai-env/ directory.
	Cwd string

	// Stdout is the writer for the human-readable explanation.
	Stdout io.Writer

	// Stderr is the writer for warnings (malformed trail line, etc.).
	Stderr io.Writer
}

// RunPolicyExplain looks up one policy-decision record from the env's
// run trail and renders a human-readable explanation. The lookup
// matches on PolicyEventID first (the engine's evt_<ts>_<hex> id) and
// falls back to a substring match against the Action / EventType /
// Event fields so an operator who recorded the action verb instead of
// the engine id still gets the right line.
//
// Behavior:
//
//   - Missing run trail: hard error directing the operator to check the
//     env name and that a run exists.
//   - No matching record: hard error so the operator sees the lookup
//     failure explicitly.
//   - One matching record: render its fields + the JSON envelope so a
//     downstream consumer can copy it.
//   - More than one matching record: render the first hit and warn on
//     stderr so the operator knows the id was not unique (in practice
//     the engine's evt_ ids are unique, so this only fires when the
//     operator passed an Action verb).
func RunPolicyExplain(opts PolicyExplainOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env policy explain: resolve working directory: %w", err)
		}
		opts.Cwd = cwd
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env policy explain: %w", err)
	}
	if strings.TrimSpace(opts.EventID) == "" {
		return errors.New("ai-env policy explain: --event is required")
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env policy explain: %w", err)
	}

	var summary run.RunSummary
	if opts.RunID != "" {
		summary, err = run.FindRunByID(aiEnvDir, opts.RunID)
	} else {
		summary, err = run.LatestRunForEnv(aiEnvDir, opts.EnvName)
	}
	if err != nil {
		if errors.Is(err, run.ErrNoRuns) {
			return fmt.Errorf("ai-env policy explain: no recorded runs for env %q", opts.EnvName)
		}
		return fmt.Errorf("ai-env policy explain: %w", err)
	}

	events, readErr := run.ReadPolicyDecisions(summary.Path)
	if readErr != nil {
		// Surface the partial-read error to stderr; we may still have
		// loaded the matching record before the failure so we let the
		// lookup proceed.
		fmt.Fprintf(opts.Stderr, "warning: %v\n", readErr)
	}
	if len(events) == 0 {
		return fmt.Errorf("ai-env policy explain: no policy decisions recorded for run %s", summary.ID)
	}

	matches := findPolicyDecision(events, opts.EventID)
	if len(matches) == 0 {
		return fmt.Errorf("ai-env policy explain: no policy decision matching %q in run %s", opts.EventID, summary.ID)
	}
	if len(matches) > 1 {
		fmt.Fprintf(opts.Stderr, "warning: %d records matched %q; showing the first\n", len(matches), opts.EventID)
	}

	renderPolicyDecisionExplain(opts.Stdout, opts.EnvName, summary.ID, summary.Path, matches[0])
	return nil
}

// findPolicyDecision returns every event whose identifier matches
// query. The match order is:
//
//  1. Exact PolicyEventID (the engine's evt_<ts>_<hex>).
//  2. Exact Event (e.g. "broker_action") plus exact Action (e.g.
//     "broker_push_branch") when query has the "event:action" shape.
//  3. Exact Action.
//  4. Exact Event.
//
// The function returns every event that satisfies the first match
// criterion that produces any hits; this keeps the result narrow when
// the engine id is unique and lets a "broker_push_branch" query find
// every recorded push without falling back to the noisier global
// substring match.
func findPolicyDecision(events []run.PolicyDecisionEvent, query string) []run.PolicyDecisionEvent {
	q := strings.TrimSpace(query)
	if q == "" {
		return nil
	}
	// 1. Exact PolicyEventID hits.
	var hits []run.PolicyDecisionEvent
	for _, e := range events {
		if e.PolicyEventID == q {
			hits = append(hits, e)
		}
	}
	if len(hits) > 0 {
		return hits
	}
	// 2. "event:action" shape (e.g. "broker_action:broker_push_branch").
	if before, after, ok := strings.Cut(q, ":"); ok && before != "" && after != "" {
		for _, e := range events {
			if e.Event == before && e.Action == after {
				hits = append(hits, e)
			}
		}
		if len(hits) > 0 {
			return hits
		}
	}
	// 3. Exact Action.
	for _, e := range events {
		if e.Action == q {
			hits = append(hits, e)
		}
	}
	if len(hits) > 0 {
		return hits
	}
	// 4. Exact Event.
	for _, e := range events {
		if e.Event == q {
			hits = append(hits, e)
		}
	}
	return hits
}

// renderPolicyDecisionExplain writes a deterministic explanation of
// evt to w. The fields are surfaced in the same order PolicyDecisionEvent
// declares them so an operator who has read the JSONL file directly
// sees a familiar layout.
func renderPolicyDecisionExplain(w io.Writer, envName, runID, runPath string, evt run.PolicyDecisionEvent) {
	fmt.Fprintf(w, "env:           %s\n", envName)
	fmt.Fprintf(w, "run id:        %s\n", runID)
	fmt.Fprintf(w, "run dir:       %s\n", runPath)
	if evt.PolicyEventID != "" {
		fmt.Fprintf(w, "event id:      %s\n", evt.PolicyEventID)
	}
	fmt.Fprintf(w, "event:         %s\n", evt.Event)
	if evt.EventType != "" {
		fmt.Fprintf(w, "event type:    %s\n", evt.EventType)
	}
	if evt.Action != "" {
		fmt.Fprintf(w, "action:        %s\n", evt.Action)
	}
	if evt.Target != "" {
		fmt.Fprintf(w, "target:        %s\n", evt.Target)
	}
	if evt.Surface != "" {
		fmt.Fprintf(w, "surface:       %s\n", evt.Surface)
	}
	fmt.Fprintf(w, "decision:      %s\n", evt.Decision)
	if evt.Reason != "" {
		fmt.Fprintf(w, "reason:        %s\n", evt.Reason)
	}
	if len(evt.Reasons) > 0 {
		fmt.Fprintln(w, "reasons:")
		for _, r := range evt.Reasons {
			fmt.Fprintf(w, "  - %s\n", r)
		}
	}
	if evt.Error != "" {
		fmt.Fprintf(w, "error:         %s\n", evt.Error)
	}
	if evt.Branch != "" {
		fmt.Fprintf(w, "branch:        %s\n", evt.Branch)
	}
	if evt.Repo != "" {
		fmt.Fprintf(w, "repo:          %s\n", evt.Repo)
	}
	if evt.TokenKind != "" {
		fmt.Fprintf(w, "token kind:    %s\n", evt.TokenKind)
	}
	if evt.PRNumber != 0 {
		fmt.Fprintf(w, "pr number:     %d\n", evt.PRNumber)
	}
	if evt.PRURL != "" {
		fmt.Fprintf(w, "pr url:        %s\n", evt.PRURL)
	}
	if len(evt.Metadata) > 0 {
		fmt.Fprintln(w, "metadata:")
		keys := make([]string, 0, len(evt.Metadata))
		for k := range evt.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %s: %s\n", k, evt.Metadata[k])
		}
	}
	fmt.Fprintf(w, "timestamp:     %s\n", evt.Timestamp)

	// Re-render the raw JSON envelope so a downstream consumer can pipe
	// the output into jq without re-reading the .jsonl file. Marshal
	// errors are surfaced inline (rather than returned) because the
	// human-readable section above is already complete.
	if line, err := json.Marshal(evt); err == nil {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "raw:")
		fmt.Fprintf(w, "  %s\n", string(line))
	}
}

// PolicyMutateKind names the policy.yaml field a mutate-class command
// targets. Pinned as a typed string so the CLI wiring and the command
// body share the canonical spelling.
type PolicyMutateKind string

const (
	// PolicyMutateDomain targets policy.yaml's network.allow_domains.
	PolicyMutateDomain PolicyMutateKind = "domain"

	// PolicyMutateTool targets policy.yaml's commands.deny_patterns
	// (for the deny path) or removes from it (for the allow path).
	// The v0.1 contract treats "tool" as a synonym for a command
	// substring: an allowed tool is one absent from
	// commands.deny_patterns; a denied tool is added to it.
	PolicyMutateTool PolicyMutateKind = "tool"
)

// PolicyMutateAction names the verb of a mutate-class command. Pinned
// as a typed string so the CLI wiring and the command body share the
// canonical spelling.
type PolicyMutateAction string

const (
	// PolicyMutateAllow grants the value (adds to network.allow_domains
	// or removes from commands.deny_patterns).
	PolicyMutateAllow PolicyMutateAction = "allow"

	// PolicyMutateDeny refuses the value (removes from
	// network.allow_domains or adds to commands.deny_patterns).
	PolicyMutateDeny PolicyMutateAction = "deny"
)

// PolicyMutateOptions captures inputs for the `ai-env policy
// allow|deny domain|tool <env-name> <value>` family.
type PolicyMutateOptions struct {
	// Action is the verb (PolicyMutateAllow / PolicyMutateDeny).
	// Required.
	Action PolicyMutateAction

	// Kind is the targeted field (PolicyMutateDomain /
	// PolicyMutateTool). Required.
	Kind PolicyMutateKind

	// EnvName is the positional <env-name> argument. Used for env-name
	// grammar validation and audit context; v0.1's policy.yaml is
	// project-wide so the mutation applies project-wide.
	EnvName string

	// Value is the domain (e.g. "github.com") or the tool / command
	// substring (e.g. "rm -rf"). Required, must be non-empty after
	// trimming whitespace.
	Value string

	// Cwd is the working directory the command was invoked from. Used
	// to locate the project's .ai-env/ directory.
	Cwd string

	// Stdout is the writer for the human-readable confirmation.
	Stdout io.Writer

	// Stderr is the writer for warnings (no-op mutations, etc.).
	Stderr io.Writer
}

// RunPolicyMutate is the entry point for the allow/deny + domain/tool
// commands. It reads .ai-env/policy.yaml, applies the requested
// mutation in memory, validates the result, and rewrites the file. A
// missing policy.yaml is a hard error (the operator should run
// `ai-env policy init` first).
//
// Semantics:
//
//   - allow domain <name>: append <name> to network.allow_domains if
//     absent. A no-op produces a friendly notice on stderr and exits
//     0 so a scripted caller treats already-allowed as success.
//   - deny domain <name>: remove <name> from network.allow_domains if
//     present. Domains are not added to a deny list because v0.1's
//     network policy treats the absence of a domain in allow_domains
//     as a deny under network.default == "deny".
//   - allow tool <pattern>: remove <pattern> from
//     commands.deny_patterns if present. v0.1 has no per-tool allow
//     list; allowing a tool means clearing its deny-pattern entry.
//   - deny tool <pattern>: append <pattern> to commands.deny_patterns
//     if absent.
//
// The function rewrites policy.yaml byte-for-byte from the parsed
// document so an existing file's structure is preserved up to the
// canonical yaml.Marshal output (mirroring `ai-env policy init`).
func RunPolicyMutate(opts PolicyMutateOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("ai-env policy %s %s: resolve working directory: %w", opts.Action, opts.Kind, err)
		}
		opts.Cwd = cwd
	}
	if err := ValidateEnvName(opts.EnvName); err != nil {
		return fmt.Errorf("ai-env policy %s %s: %w", opts.Action, opts.Kind, err)
	}
	value := strings.TrimSpace(opts.Value)
	if value == "" {
		return fmt.Errorf("ai-env policy %s %s: value must be non-empty", opts.Action, opts.Kind)
	}
	if opts.Action != PolicyMutateAllow && opts.Action != PolicyMutateDeny {
		return fmt.Errorf("ai-env policy: unknown action %q (expected allow or deny)", opts.Action)
	}
	if opts.Kind != PolicyMutateDomain && opts.Kind != PolicyMutateTool {
		return fmt.Errorf("ai-env policy: unknown kind %q (expected domain or tool)", opts.Kind)
	}

	aiEnvDir, err := findAIEnvDir(opts.Cwd)
	if err != nil {
		return fmt.Errorf("ai-env policy %s %s: %w", opts.Action, opts.Kind, err)
	}

	policyPath := filepath.Join(aiEnvDir, policyFileName)
	if _, statErr := os.Stat(policyPath); statErr != nil {
		if os.IsNotExist(statErr) {
			return fmt.Errorf("ai-env policy %s %s: no %s; run `ai-env policy init` to scaffold one", opts.Action, opts.Kind, policyPath)
		}
		return fmt.Errorf("ai-env policy %s %s: stat %s: %w", opts.Action, opts.Kind, policyPath, statErr)
	}

	cfg, err := config.LoadPolicy(policyPath)
	if err != nil {
		return fmt.Errorf("ai-env policy %s %s: %w", opts.Action, opts.Kind, err)
	}

	changed, summary := applyPolicyMutation(cfg, opts.Action, opts.Kind, value)
	if !changed {
		fmt.Fprintf(opts.Stderr, "note: %s\n", summary)
		return nil
	}

	if err := config.ValidatePolicy(cfg); err != nil {
		return fmt.Errorf("ai-env policy %s %s: post-mutation policy.yaml is invalid: %w", opts.Action, opts.Kind, err)
	}
	if err := writeYAMLFile(policyPath, cfg, 0o644); err != nil {
		return fmt.Errorf("ai-env policy %s %s: %w", opts.Action, opts.Kind, err)
	}

	fmt.Fprintf(opts.Stdout, "%s\n", summary)
	fmt.Fprintf(opts.Stdout, "Updated %s\n", policyPath)
	return nil
}

// applyPolicyMutation mutates cfg in place per the action+kind+value
// triple and returns (changed, summary). When the mutation is a no-op
// (e.g. allow-domain for a domain already on the list) changed=false
// and summary describes the no-op so the caller can surface it.
//
// The function is split out so the disk-side helpers in
// RunPolicyMutate stay readable and the mutation logic can be tested
// in isolation against a *config.PolicyConfig literal.
func applyPolicyMutation(cfg *config.PolicyConfig, action PolicyMutateAction, kind PolicyMutateKind, value string) (bool, string) {
	switch {
	case kind == PolicyMutateDomain && action == PolicyMutateAllow:
		if stringSliceContains(cfg.Network.AllowDomains, value) {
			return false, fmt.Sprintf("domain %q already in network.allow_domains; no change", value)
		}
		cfg.Network.AllowDomains = append(cfg.Network.AllowDomains, value)
		sort.Strings(cfg.Network.AllowDomains)
		return true, fmt.Sprintf("added %q to network.allow_domains", value)

	case kind == PolicyMutateDomain && action == PolicyMutateDeny:
		filtered, removed := removeStringSliceEntry(cfg.Network.AllowDomains, value)
		if !removed {
			return false, fmt.Sprintf("domain %q is not in network.allow_domains; nothing to remove (network.default=%q still applies)", value, cfg.Network.Default)
		}
		cfg.Network.AllowDomains = filtered
		return true, fmt.Sprintf("removed %q from network.allow_domains", value)

	case kind == PolicyMutateTool && action == PolicyMutateAllow:
		filtered, removed := removeStringSliceEntry(cfg.Commands.DenyPatterns, value)
		if !removed {
			return false, fmt.Sprintf("tool pattern %q is not in commands.deny_patterns; nothing to remove", value)
		}
		cfg.Commands.DenyPatterns = filtered
		return true, fmt.Sprintf("removed %q from commands.deny_patterns", value)

	case kind == PolicyMutateTool && action == PolicyMutateDeny:
		if stringSliceContains(cfg.Commands.DenyPatterns, value) {
			return false, fmt.Sprintf("tool pattern %q already in commands.deny_patterns; no change", value)
		}
		cfg.Commands.DenyPatterns = append(cfg.Commands.DenyPatterns, value)
		sort.Strings(cfg.Commands.DenyPatterns)
		return true, fmt.Sprintf("added %q to commands.deny_patterns", value)
	}
	// The validator above guarantees we never reach this default.
	return false, fmt.Sprintf("unsupported mutation %s %s", action, kind)
}

// stringSliceContains reports whether s contains v. Pulled into a
// helper so the mutate logic stays readable.
func stringSliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// removeStringSliceEntry returns a new slice with every occurrence of
// v removed plus a boolean indicating whether any removal happened.
// Used by the deny-domain / allow-tool paths so the helper handles the
// "value not present" case uniformly.
func removeStringSliceEntry(s []string, v string) ([]string, bool) {
	out := make([]string, 0, len(s))
	removed := false
	for _, x := range s {
		if x == v {
			removed = true
			continue
		}
		out = append(out, x)
	}
	if !removed {
		return s, false
	}
	return out, true
}
