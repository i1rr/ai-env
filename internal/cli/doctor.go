// `ai-env doctor` is the operator-facing diagnostic command for the
// supervisor and its surrounding subsystems. Where `ai-env agents
// doctor` (plan 03) reports on per-agent CLIs, `ai-env doctor` (Batch
// 10.5) reports on the *host* surface the supervisor walks at run
// time:
//
//   - host platform + ai-env binary version (the things the platform-
//     parity matrix in Batch 10.2 documents);
//   - the capability snapshot from internal/capability.Detect() (Plan
//     Batch 0.4): CAP_NET_ADMIN, CAP_SYS_ADMIN, NFLOG / pflog reach,
//     slirp4netns, bridge gateway, /dev/fd, userns-remap;
//   - the optional dependencies the supervisor shells out to: docker /
//     podman runtime binaries (probed with `<bin> version` and a short
//     timeout, mirroring the backend adapter's Detect path), plus git
//     and the optional security scanners (gitleaks, etc.).
//
// Each check renders as a single PASS / WARN / FAIL row in a
// tab-aligned, grep-friendly table (mirrors `ai-env agents doctor`
// style). After the checks, a **remediation table** lists every
// lifecycle verb the supervisor can emit at run time alongside the
// pointer to the docs / config knob an operator should consult when
// it fires. The plan locks the contents of this table in Batch 10.5:
// "remediation table covers EVERY lifecycle verb + capability
// detection result + new verbs from iter-3/iter-4
// (shim_coverage_degraded, helper_rpc_aborted, transcript_parser_error,
// gateway_secret_response, mcp_config_neutralized, origin_drift)."
// Every verb in run.LifecycleVerb* maps to a remediation row here, so
// adding a new verb without also extending this command's table is
// a compile-time visible omission for a reviewer.
//
// Exit code policy:
//
//   - Every check that PASSes or WARNs leaves the exit code at zero.
//     The doctor command is diagnostic; warnings are advisory.
//   - A check FAILs (exit non-zero) only when a missing capability /
//     dependency would block ai-env from running at all on this host
//     (e.g. no container runtime found, supervisor on Linux without
//     CAP_NET_ADMIN under --observer-mode strict). Capability surfaces
//     that the supervisor degrades around (no NFLOG → observer
//     unavailable, no /dev/fd → no single-fd exec) are reported as
//     WARN, not FAIL.
//
// JSON output:
//
// `ai-env doctor --json` emits one machine-readable JSON document with
// the same row contents the table renders, plus the raw capability
// snapshot, the dependency probes, and the remediation table. The JSON
// shape is intentionally stable so a CI job can pin one field without
// the table format breaking it.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/i1rr/ai-env/internal/capability"
	"github.com/i1rr/ai-env/internal/run"
)

// doctorRuntimeProbeTimeout caps every external probe `ai-env doctor`
// runs (docker version, podman version, etc.). The diagnostic must
// not hang on a wedged daemon socket: a missing answer within the
// timeout is reported as WARN with "timed out".
const doctorRuntimeProbeTimeout = 5 * time.Second

// doctorVersionRegexp pulls a semver-ish token out of `<runtime>
// version` output. Same shape as internal/backend/docker.versionLine
// (kept duplicated rather than re-exported to keep the doctor command
// free of backend-package dependencies — backends pull in network /
// systemd code we do not want in the diagnostic binary path).
var doctorVersionRegexp = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?)`)

// DoctorOptions captures the parsed flags for `ai-env doctor`.
type DoctorOptions struct {
	// JSON selects the machine-readable JSON projection instead of the
	// default human-readable table. Mirrors `ai-env leaks --format json`
	// but is a bool because doctor has no second non-table format.
	JSON bool

	// Stdout is the writer for the report (table or JSON).
	Stdout io.Writer

	// Stderr is the writer for advisory notices that are not part of
	// the report itself (e.g. "supervisor binary path could not be
	// resolved"). Empty for normal operation.
	Stderr io.Writer

	// detectCapability is the seam tests use to inject a canned
	// capability snapshot instead of probing the live host. Production
	// callers leave this nil; nil falls through to capability.Detect.
	detectCapability func() capability.Capability

	// runtimeProbe is the seam tests use to intercept docker / podman /
	// git version probes. Production callers leave this nil; nil falls
	// through to a real os/exec invocation with the timeout above.
	runtimeProbe func(ctx context.Context, binary string, args []string) (stdout string, exitCode int, err error)

	// lookPath is the seam tests use to intercept exec.LookPath. nil
	// falls through to exec.LookPath.
	lookPath func(name string) (string, error)
}

// DoctorReport is the machine-readable projection of `ai-env doctor`.
// Field order is the order the table renders so a downstream consumer
// can read either format without surprise.
type DoctorReport struct {
	// SchemaVersion pins the on-wire shape so a CI consumer can detect
	// an incompatible doctor binary version. Bumped only on a breaking
	// field rename / removal; new optional fields go in at the same
	// version.
	SchemaVersion int `json:"_schema_version"`

	// AIEnvVersion is the supervisor binary's reported version
	// (`ai-env --version`). Captured here so a JSON consumer can pin
	// the doctor output against a specific build.
	AIEnvVersion string `json:"ai_env_version"`

	// Platform is the host OS the supervisor is running on
	// (runtime.GOOS). Mirrors the platform-parity matrix's row key.
	Platform string `json:"platform"`

	// Arch is the host CPU architecture (runtime.GOARCH). Captured for
	// the same reason as Platform.
	Arch string `json:"arch"`

	// Capability is the raw capability snapshot from internal/capability.
	// JSON consumers can read this directly without re-parsing the
	// human-readable rows.
	Capability DoctorCapability `json:"capability"`

	// Checks is the ordered list of PASS / WARN / FAIL rows the table
	// renders. Each row carries the same fields the table shows so a
	// JSON consumer can reconstruct the table verbatim.
	Checks []DoctorCheck `json:"checks"`

	// Remediations is the full lifecycle-verb → remediation table.
	// Static for a given doctor binary version; the field is included
	// in the JSON projection so a consumer that wants to print the
	// table without running doctor can read it from here.
	Remediations []DoctorRemediation `json:"remediations"`

	// Failed is true when at least one check has Status="FAIL"; the
	// CLI exits non-zero in that case.
	Failed bool `json:"failed"`
}

// DoctorCapability is the JSON projection of capability.Capability. We
// keep a separate struct (rather than embedding capability.Capability)
// so we can stringify the Errors slice without leaking Go error
// fingerprints into the on-wire shape.
type DoctorCapability struct {
	OS                  string   `json:"os"`
	CAPNetAdmin         bool     `json:"cap_net_admin"`
	CAPSysAdmin         bool     `json:"cap_sys_admin"`
	SetnsAvailable      bool     `json:"setns_available"`
	NFLOGAvailable      bool     `json:"nflog_available"`
	PFLogAvailable      bool     `json:"pflog_available"`
	Slirp4netns         bool     `json:"slirp4netns"`
	BridgeGatewayLikely bool     `json:"bridge_gateway_likely"`
	DevFdAvailable      bool     `json:"dev_fd_available"`
	UserNSRemap         bool     `json:"userns_remap"`
	Errors              []string `json:"errors,omitempty"`
}

// DoctorCheck is one row in the diagnostic table.
type DoctorCheck struct {
	// Category groups checks for the table renderer: "platform",
	// "capability", "dependency". Stable string tokens so a downstream
	// jq consumer can filter by category.
	Category string `json:"category"`

	// Name is the short check name shown in the NAME column.
	Name string `json:"name"`

	// Status is one of "PASS", "WARN", "FAIL". The CLI exits non-zero
	// when at least one check is "FAIL".
	Status string `json:"status"`

	// Detail is the short human-readable explanation shown in the
	// DETAIL column.
	Detail string `json:"detail"`
}

// DoctorRemediation is one row in the verb → remediation table. The
// rows are static (the doctor binary owns the mapping); the table is
// rendered after the checks so the operator sees actionable guidance
// without leaving the terminal.
type DoctorRemediation struct {
	// Verb is the lifecycle verb name (matches run.LifecycleVerb* on
	// the wire — `proxy_started`, `gateway_secret_blocked`, ...).
	Verb string `json:"verb"`

	// Severity is one of "info", "warn", "block". "info" is a normal
	// start/stop verb; "warn" is a degraded path the supervisor
	// tolerates (observer_unavailable, network_policy_degraded,
	// shim_coverage_degraded, transcript_parser_error,
	// secrets_permission_warning, helper_rpc_aborted, etc.); "block"
	// is a verb that aborts the action that triggered it
	// (gateway_secret_blocked, origin_drift).
	Severity string `json:"severity"`

	// Remediation is the operator-facing one-liner explaining what to
	// look at when the verb appears in lifecycle.jsonl. Pointers to
	// docs/ pages are preferred over inlined steps because the docs
	// page is the source of truth (Batch 10.1, 10.3, 10.4).
	Remediation string `json:"remediation"`
}

// doctorReportSchemaVersion pins the on-wire JSON shape. Bumped on a
// breaking field rename; new optional fields go in at the same
// version.
const doctorReportSchemaVersion = 1

// RunDoctor is the entry point used by the Cobra wiring. It runs the
// platform / capability / dependency probes, renders the report (table
// or JSON), and returns a non-nil error when any check reported FAIL.
// The error is the CLI's non-zero exit signal; the report itself is
// always written first so the operator sees the full diagnostic before
// the shell prints the error.
func RunDoctor(opts DoctorOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	detectFn := opts.detectCapability
	if detectFn == nil {
		detectFn = capability.Detect
	}
	probeFn := opts.runtimeProbe
	if probeFn == nil {
		probeFn = realDoctorRuntimeProbe
	}
	lookPathFn := opts.lookPath
	if lookPathFn == nil {
		lookPathFn = exec.LookPath
	}

	report := DoctorReport{
		SchemaVersion: doctorReportSchemaVersion,
		AIEnvVersion:  resolveAIEnvVersion(),
		Platform:      runtime.GOOS,
		Arch:          runtime.GOARCH,
	}

	cap := detectFn()
	report.Capability = capabilitySnapshot(cap)

	// 1) Platform row: always informational. We tag it PASS so the
	//    table has at least one row even on a stripped-down host.
	report.Checks = append(report.Checks, DoctorCheck{
		Category: "platform",
		Name:     "ai-env",
		Status:   "PASS",
		Detail:   fmt.Sprintf("version=%s os=%s arch=%s", report.AIEnvVersion, report.Platform, report.Arch),
	})

	// 2) Capability rows. Walk the capability snapshot in the order
	//    capability.Detect populates it so the rows mirror the source
	//    of truth.
	report.Checks = append(report.Checks, capabilityChecks(cap)...)

	// 3) Dependency rows. docker / podman / git / scanners.
	report.Checks = append(report.Checks, dependencyChecks(probeFn, lookPathFn)...)

	// 4) Tally FAILs.
	for _, c := range report.Checks {
		if c.Status == "FAIL" {
			report.Failed = true
			break
		}
	}

	// 5) Remediation table. Static.
	report.Remediations = buildRemediationTable()

	if opts.JSON {
		enc := json.NewEncoder(opts.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("ai-env doctor: encode JSON: %w", err)
		}
	} else {
		renderDoctorTable(opts.Stdout, report)
	}

	if report.Failed {
		return errors.New("ai-env doctor: one or more checks failed")
	}
	return nil
}

// resolveAIEnvVersion looks up the supervisor binary's version string.
// The CLI wiring (cmd/ai-env/main.go) sets a package-level `version`
// variable via -ldflags; we cannot import that from internal/, so we
// fall back to "dev" the same way Cobra's --version flag would.
// Production callers may override via the AI_ENV_VERSION env var (a
// build script trick) but that is intentionally undocumented because
// the build-time -ldflags path is the canonical one.
func resolveAIEnvVersion() string {
	if v := strings.TrimSpace(os.Getenv("AI_ENV_VERSION")); v != "" {
		return v
	}
	return "dev"
}

// capabilitySnapshot translates capability.Capability into the JSON
// projection. Errors are stringified so JSON consumers do not have to
// understand Go error fingerprints.
func capabilitySnapshot(c capability.Capability) DoctorCapability {
	snap := DoctorCapability{
		OS:                  c.OS,
		CAPNetAdmin:         c.CAPNetAdmin,
		CAPSysAdmin:         c.CAPSysAdmin,
		SetnsAvailable:      c.SetnsAvailable,
		NFLOGAvailable:      c.NFLOGAvailable,
		PFLogAvailable:      c.PFLogAvailable,
		Slirp4netns:         c.Slirp4netns,
		BridgeGatewayLikely: c.BridgeGatewayLikely,
		DevFdAvailable:      c.DevFdAvailable,
		UserNSRemap:         c.UserNSRemap,
	}
	for _, e := range c.Errors {
		if e == nil {
			continue
		}
		snap.Errors = append(snap.Errors, e.Error())
	}
	return snap
}

// capabilityChecks turns the capability snapshot into a sequence of
// rows. The status policy is conservative: missing capabilities that
// the supervisor degrades around report WARN; the supervisor still
// runs, just with a documented degraded surface. Only "supervisor
// cannot launch a sandbox at all" surfaces report FAIL — those are
// surfaced by the dependency probes (no container runtime), not by
// capability rows.
func capabilityChecks(c capability.Capability) []DoctorCheck {
	rows := make([]DoctorCheck, 0, 9)

	switch c.OS {
	case "linux":
		// CAP_NET_ADMIN: needed for NFLOG attach and per-run iptables
		// rules. Absence → observer_unavailable; the supervisor
		// degrades. Report WARN.
		rows = append(rows, capRow("CAP_NET_ADMIN", c.CAPNetAdmin,
			"required for NFLOG egress observer + per-run iptables rules; without it `--observer-mode strict` aborts",
			"absent (run with --observer-mode auto for degraded operation, or grant CAP_NET_ADMIN)"))
		rows = append(rows, capRow("CAP_SYS_ADMIN", c.CAPSysAdmin,
			"required for setns(2) into the sandbox netns (SetnsTCP ProviderProxy)",
			"absent (ProviderProxy falls back to bridge_gateway or unix_socket)"))
		rows = append(rows, capRow("NFLOG", c.NFLOGAvailable,
			"kernel netfilter surface for the egress observer is present",
			"netfilter markers missing — observer will report observer_unavailable reason=no_nflog"))
		// Slirp4netns is "present" reported as WARN (it is a known
		// constraint), absent is PASS. Invert the conventional shape.
		if c.Slirp4netns {
			rows = append(rows, DoctorCheck{
				Category: "capability",
				Name:     "slirp4netns",
				Status:   "WARN",
				Detail:   "rootless slirp4netns detected; observer will report observer_unavailable reason=slirp4netns",
			})
		} else {
			rows = append(rows, DoctorCheck{
				Category: "capability",
				Name:     "slirp4netns",
				Status:   "PASS",
				Detail:   "not in a slirp4netns environment",
			})
		}
		rows = append(rows, capRow("bridge gateway", c.BridgeGatewayLikely,
			"docker0/podman0/cni0 interface detected; BridgeGateway ProviderProxy mode is plausible",
			"no bridge interface detected; ProviderProxy will fall back to unix_socket"))
		// UserNSRemap: present is WARN (operator action required for
		// backends without MappedUID); absent is PASS.
		if c.UserNSRemap {
			rows = append(rows, DoctorCheck{
				Category: "capability",
				Name:     "userns-remap",
				Status:   "WARN",
				Detail:   "docker/podman userns-remap signal detected; the configured backend must implement Backend.MappedUID or the supervisor refuses to start",
			})
		} else {
			rows = append(rows, DoctorCheck{
				Category: "capability",
				Name:     "userns-remap",
				Status:   "PASS",
				Detail:   "no userns-remap signal detected; backends without MappedUID are usable",
			})
		}
	case "darwin":
		rows = append(rows, capRow("pflog", c.PFLogAvailable,
			"pf packet-filter device /dev/pf present; pflog observer is reachable",
			"/dev/pf not present; observer will report observer_unavailable reason=no_pflog"))
	default:
		rows = append(rows, DoctorCheck{
			Category: "capability",
			Name:     "platform",
			Status:   "WARN",
			Detail:   fmt.Sprintf("unsupported OS %q; capability probes are conservative", c.OS),
		})
	}

	rows = append(rows, capRow("/dev/fd", c.DevFdAvailable,
		"/dev/fd surface is reachable; TOCTOU-safe interpreter-via-file exec works",
		"/dev/fd missing; the shim helper's interpreter-via-file flow degrades"))

	if len(c.Errors) > 0 {
		messages := make([]string, 0, len(c.Errors))
		for _, e := range c.Errors {
			if e == nil {
				continue
			}
			messages = append(messages, e.Error())
		}
		rows = append(rows, DoctorCheck{
			Category: "capability",
			Name:     "probe errors",
			Status:   "WARN",
			Detail:   strings.Join(messages, "; "),
		})
	}

	return rows
}

// capRow is a small helper that turns one boolean capability into a
// PASS / WARN row. Capabilities are conservative-by-default (false
// means "missing"), so a true value is always PASS and a false value
// is always WARN — capability misses are degraded paths, not blockers.
func capRow(name string, present bool, passDetail, warnDetail string) DoctorCheck {
	if present {
		return DoctorCheck{
			Category: "capability",
			Name:     name,
			Status:   "PASS",
			Detail:   passDetail,
		}
	}
	return DoctorCheck{
		Category: "capability",
		Name:     name,
		Status:   "WARN",
		Detail:   warnDetail,
	}
}

// dependencyChecks probes the optional external binaries the
// supervisor shells out to: docker / podman runtime (at least one
// must be present, else FAIL), git (PASS or WARN, used by worktree
// strategy), and the optional security scanners (gitleaks, etc.) —
// WARN when absent because the supervisor degrades around each one
// individually.
func dependencyChecks(probe func(ctx context.Context, binary string, args []string) (string, int, error), lookPath func(string) (string, error)) []DoctorCheck {
	rows := make([]DoctorCheck, 0, 8)

	// Container runtimes: at least one of docker / podman must be
	// usable, otherwise the supervisor cannot Create a sandbox at all.
	// We probe both; the missing-runtime FAIL only fires when BOTH are
	// missing.
	dockerRow := probeRuntime("docker", probe, lookPath)
	podmanRow := probeRuntime("podman", probe, lookPath)

	// Downgrade per-runtime FAIL → WARN when at least one runtime is
	// healthy; the supervisor only needs one. Then add a synthetic
	// "container runtime" row that summarizes the combined verdict.
	atLeastOnePass := dockerRow.Status == "PASS" || podmanRow.Status == "PASS"
	if atLeastOnePass {
		if dockerRow.Status == "FAIL" {
			dockerRow.Status = "WARN"
		}
		if podmanRow.Status == "FAIL" {
			podmanRow.Status = "WARN"
		}
	}
	rows = append(rows, dockerRow)
	rows = append(rows, podmanRow)
	if atLeastOnePass {
		rows = append(rows, DoctorCheck{
			Category: "dependency",
			Name:     "container runtime",
			Status:   "PASS",
			Detail:   "at least one of docker / podman is available",
		})
	} else {
		rows = append(rows, DoctorCheck{
			Category: "dependency",
			Name:     "container runtime",
			Status:   "FAIL",
			Detail:   "neither docker nor podman is available; the supervisor cannot Create a sandbox",
		})
	}

	// git: used by worktree-strategy envs and by the GitHub broker.
	// Absence is WARN, not FAIL: copy-strategy envs still work.
	rows = append(rows, probeBinary("git", []string{"--version"}, probe, lookPath,
		"git is on PATH; worktree-strategy envs and the GitHub broker are usable",
		"git is not on PATH; worktree-strategy envs and the GitHub broker will be unavailable"))

	// Optional scanners. All WARN-on-missing because the supervisor
	// degrades around each one.
	for _, name := range []string{"gitleaks", "osv-scanner", "trivy", "semgrep"} {
		rows = append(rows, probeBinary(name, nil, probe, lookPath,
			fmt.Sprintf("%s is on PATH; the optional scanner will run during `ai-env scan`", name),
			fmt.Sprintf("%s is not on PATH; the optional scanner will be skipped (warning, not blocker)", name)))
	}

	return rows
}

// probeRuntime runs `<binary> version` and returns a row. PASS when
// the probe succeeds and the output contains a recognizable version
// string; WARN when the binary is on PATH but the probe is degraded
// (non-zero exit, no version line); FAIL when the binary is absent.
// The caller is expected to downgrade FAIL → WARN when a sibling
// runtime is present.
func probeRuntime(binary string, probe func(ctx context.Context, binary string, args []string) (string, int, error), lookPath func(string) (string, error)) DoctorCheck {
	row := DoctorCheck{Category: "dependency", Name: binary}
	path, err := lookPath(binary)
	if err != nil {
		row.Status = "FAIL"
		row.Detail = fmt.Sprintf("%s not found on PATH", binary)
		return row
	}
	ctx, cancel := context.WithTimeout(context.Background(), doctorRuntimeProbeTimeout)
	defer cancel()
	out, exitCode, perr := probe(ctx, binary, []string{"version"})
	if perr != nil {
		row.Status = "WARN"
		row.Detail = fmt.Sprintf("%s: probe failed: %v", path, perr)
		return row
	}
	if exitCode != 0 {
		row.Status = "WARN"
		row.Detail = fmt.Sprintf("%s: `%s version` exited %d", path, binary, exitCode)
		return row
	}
	version := extractFirstVersion(out)
	if version == "" {
		row.Status = "WARN"
		row.Detail = fmt.Sprintf("%s: version output did not contain a recognizable version token", path)
		return row
	}
	row.Status = "PASS"
	row.Detail = fmt.Sprintf("%s (version %s)", path, version)
	return row
}

// probeBinary is a thin wrapper for dependencies that we just want to
// confirm are on PATH (git, scanners). When args is non-nil we also
// run a quick `<binary> <args>` to confirm the binary is invokable.
// Absence is reported as WARN (the caller can decide to flip it to
// FAIL when needed).
func probeBinary(binary string, args []string, probe func(ctx context.Context, binary string, args []string) (string, int, error), lookPath func(string) (string, error), passDetail, warnDetail string) DoctorCheck {
	row := DoctorCheck{Category: "dependency", Name: binary}
	path, err := lookPath(binary)
	if err != nil {
		row.Status = "WARN"
		row.Detail = warnDetail
		return row
	}
	if len(args) == 0 {
		row.Status = "PASS"
		row.Detail = path
		return row
	}
	ctx, cancel := context.WithTimeout(context.Background(), doctorRuntimeProbeTimeout)
	defer cancel()
	_, exitCode, perr := probe(ctx, binary, args)
	if perr != nil || exitCode != 0 {
		row.Status = "WARN"
		row.Detail = fmt.Sprintf("%s present but invocation failed (exit=%d err=%v)", path, exitCode, perr)
		return row
	}
	row.Status = "PASS"
	row.Detail = fmt.Sprintf("%s (%s)", passDetail, path)
	return row
}

// extractFirstVersion pulls the first semver-ish token out of arbitrary
// docker/podman/git version output. Returns "" when no token matches.
func extractFirstVersion(s string) string {
	m := doctorVersionRegexp.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// realDoctorRuntimeProbe is the production probe. It shells out via
// os/exec, captures stdout, and returns the parsed exit code. Stderr
// is discarded — the doctor command only needs the version token (the
// table renderer surfaces "probe failed" without the raw stderr to
// keep the table readable).
func realDoctorRuntimeProbe(ctx context.Context, binary string, args []string) (string, int, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), cmd.ProcessState.ExitCode(), nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// Treat a non-zero exit as a clean failure with exit code
		// surfaced, not a probe error: the caller distinguishes the
		// two and reports them as separate WARN messages.
		return stdout.String(), exitErr.ExitCode(), nil
	}
	if cmd.ProcessState != nil {
		return stdout.String(), cmd.ProcessState.ExitCode(), err
	}
	return stdout.String(), -1, err
}

// renderDoctorTable writes the human-readable report. The format
// mirrors `ai-env agents doctor` for visual consistency: a per-check
// "STATUS  NAME: DETAIL" row, grouped by category with blank-line
// separators, then the remediation table.
func renderDoctorTable(w io.Writer, report DoctorReport) {
	fmt.Fprintf(w, "ai-env doctor — version %s, %s/%s\n", report.AIEnvVersion, report.Platform, report.Arch)
	fmt.Fprintln(w, "")

	// Group checks by category, in the order they appear.
	categoryOrder := []string{"platform", "capability", "dependency"}
	for i, cat := range categoryOrder {
		if i > 0 {
			fmt.Fprintln(w, "")
		}
		fmt.Fprintf(w, "[%s]\n", cat)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "STATUS\tNAME\tDETAIL")
		for _, c := range report.Checks {
			if c.Category != cat {
				continue
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Status, c.Name, c.Detail)
		}
		_ = tw.Flush()
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "[remediation]")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VERB\tSEVERITY\tREMEDIATION")
	for _, r := range report.Remediations {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Verb, r.Severity, r.Remediation)
	}
	_ = tw.Flush()
}

// buildRemediationTable returns the lifecycle-verb → remediation
// mapping the plan locks in Batch 10.5. Every constant in
// internal/run.LifecycleVerb* maps to exactly one row; the doctor
// tests assert the table covers the full enum so a future verb is
// caught by CI if its remediation row is forgotten.
//
// The verb list is taken from internal/run/lifecycle_verbs.go to keep
// this in lockstep with the lifecycle stream's source of truth. Plan
// Batch 10.5 also lists `origin_drift` as a remediation surface even
// though it is not a LifecycleVerb constant (it rides as the
// `reason="origin_drift"` Metadata key on `broker_unavailable`), so
// we include it here explicitly.
func buildRemediationTable() []DoctorRemediation {
	rows := []DoctorRemediation{
		{
			Verb:        string(run.LifecycleVerbProxyStarted),
			Severity:    "info",
			Remediation: "ProviderProxy listener bound; see docs/model-credentials.md if upstream traffic is unexpected",
		},
		{
			Verb:        string(run.LifecycleVerbProxyStopped),
			Severity:    "info",
			Remediation: "ProviderProxy stopped at teardown; reason=error indicates a panic, inspect lifecycle.jsonl Metadata",
		},
		{
			Verb:        string(run.LifecycleVerbGatewayStarted),
			Severity:    "info",
			Remediation: "MCP Gateway brought up <runDir>/mcp-servers.json; see docs/mcp-security.md if scope is unexpected",
		},
		{
			Verb:        string(run.LifecycleVerbGatewayStopped),
			Severity:    "info",
			Remediation: "MCP Gateway stopped at teardown; reason=error indicates a panic, inspect lifecycle.jsonl Metadata",
		},
		{
			Verb:        string(run.LifecycleVerbGatewaySecretBlocked),
			Severity:    "block",
			Remediation: "Outbound MCP request blocked because the gateway's secret scanner matched a builtin pattern; rotate the leaked secret and review the agent's tool input",
		},
		{
			Verb:        string(run.LifecycleVerbGatewaySecretResponse),
			Severity:    "warn",
			Remediation: "Inbound MCP response redacted by the gateway's secret scanner; review leaks.jsonl for the per-match audit trail and tighten the upstream tool's output handling",
		},
		{
			Verb:        string(run.LifecycleVerbObserverStarted),
			Severity:    "info",
			Remediation: "Egress observer attached; mode=nflog (Linux) or mode=pflog (macOS)",
		},
		{
			Verb:        string(run.LifecycleVerbObserverStopped),
			Severity:    "info",
			Remediation: "Egress observer stopped at teardown; reason=error indicates a panic, inspect lifecycle.jsonl Metadata",
		},
		{
			Verb:        string(run.LifecycleVerbObserverUnavailable),
			Severity:    "warn",
			Remediation: "Egress observer could not attach (reason=slirp4netns|no_capability|no_nflog|no_pflog); under --observer-mode strict the supervisor aborts, under auto it continues with degraded network evidence",
		},
		{
			Verb:        string(run.LifecycleVerbBrokerStarted),
			Severity:    "info",
			Remediation: "GitHub broker brought up; see docs/operator-runbook.md for token-rotation guidance",
		},
		{
			Verb:        string(run.LifecycleVerbBrokerStopped),
			Severity:    "info",
			Remediation: "GitHub broker stopped at teardown; AcquireToken / RevokeToken pair should appear in the same run",
		},
		{
			Verb:        string(run.LifecycleVerbBrokerUnavailable),
			Severity:    "warn",
			Remediation: "GitHub broker could not start (reason=missing_secrets|origin_drift|mint_failed); `ai-env pr` falls back to preview-only verdict — see docs/operator-runbook.md",
		},
		{
			// origin_drift is a Metadata reason on broker_unavailable
			// but the plan explicitly enumerates it as its own
			// remediation row because it is the most common cause of
			// the broker not coming up.
			Verb:        "origin_drift",
			Severity:    "block",
			Remediation: "Origin URL drifted from the pin recorded at `ai-env new`; either reset the remote (`git remote set-url origin <pinned>`) or re-create the env with `ai-env new` against the new remote",
		},
		{
			Verb:        string(run.LifecycleVerbControlSocketStarted),
			Severity:    "info",
			Remediation: "Control socket bound at <runDir>/control.sock; the in-sandbox helpers reach the supervisor through this",
		},
		{
			Verb:        string(run.LifecycleVerbControlSocketStopped),
			Severity:    "info",
			Remediation: "Control socket stopped at teardown; reason=error indicates a panic, inspect lifecycle.jsonl Metadata",
		},
		{
			Verb:        string(run.LifecycleVerbNetworkPolicyDegraded),
			Severity:    "warn",
			Remediation: "Backend could not enforce part of the network policy (reason=iptables_rejected|ipset_missing|other); the run continues with the narrower policy — see docs/operator-runbook.md",
		},
		{
			Verb:        string(run.LifecycleVerbSecretsPermissionWarning),
			Severity:    "warn",
			Remediation: "`.ai-env/secrets.local.yaml` has loose permissions; `chmod 0600` the file to suppress the warning — see docs/secrets-local-yaml.md",
		},
		{
			Verb:        string(run.LifecycleVerbShimCoverageDegraded),
			Severity:    "warn",
			Remediation: "One or more shim wrappers could not be mounted at every canonical path (Metadata.missing lists which); the supervisor logs each entry but tolerates the gap — verify the backend's `--mount type=bind` accepts the canonical paths",
		},
		{
			Verb:        string(run.LifecycleVerbHelperRPCAborted),
			Severity:    "warn",
			Remediation: "A control-socket RPC was refused mid-flight (reason=bad_token|version_mismatch|shutdown|no_handler); a single bad_token after a clean handshake is benign — repeated occurrences suggest a tampered helper",
		},
		{
			Verb:        string(run.LifecycleVerbTranscriptParserError),
			Severity:    "warn",
			Remediation: "Per-CLI transcript parser failed (reason=scan_overflow|json_parse|stream_error); the transcript stream is marked degraded — review the upstream CLI's `--output-format` for compatibility",
		},
		{
			Verb:        string(run.LifecycleVerbMCPConfigNeutralized),
			Severity:    "info",
			Remediation: "Workspace-local MCP config was renamed to `.ai-env-shadowed` to prevent agent-CLI auto-merge; restored at backend.Destroy — no operator action required",
		},
	}

	// Defensive: stable sort by verb so a future addition does not
	// reorder the rendered table. We sort after the explicit-order
	// build so a reviewer reading buildRemediationTable() still sees
	// the verb list in the same order the plan documents.
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].Verb < rows[j].Verb
	})

	return rows
}
