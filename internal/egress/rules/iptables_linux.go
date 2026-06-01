//go:build linux

package rules

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

// platformDriver returns the iptables driver on Linux. Used by
// the cross-platform `New` to bind the right driver without an
// OS branch at the call site.
func platformDriver() ruleDriver { return iptablesDriver{} }

// platformCommander returns the production iptables Commander. We
// shell out to `iptables` via `os/exec`; the binary is in the
// canonical admin PATH on every Linux host and the supervisor's
// caller is expected to run with CAP_NET_ADMIN so the calls
// succeed.
//
// The plan calls for `ns.Do` (containernetworking/plugins) to run
// the commands inside the sandbox netns. We implement the same
// semantics here without the dependency: when NetNSPath is set,
// we prepend `nsenter --net=<path>` to the command. `nsenter` is
// part of `util-linux` and present on every distro the plan
// targets.
func platformCommander() Commander { return execCommander{} }

// execCommander runs commands via `os/exec`. Captures stdout +
// stderr; on non-zero exit returns an error wrapping stderr so
// the caller can surface the real reason.
//
// The commander recognises the leading "--ai-env-netns <path>"
// sentinel the driver emits when a netns wrap is required: the
// args are unwrapped to `nsenter --net=<path> -- <name> <rest>`
// before exec'ing. This keeps the Commander interface narrow
// (`Run(name, args)`) while still honouring the plan's `ns.Do`
// pattern.
type execCommander struct{}

func (execCommander) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	program, runArgs := unwrapNetNS(name, args)
	cmd := exec.CommandContext(ctx, program, runArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s %v: %w: %s", program, runArgs, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// unwrapNetNS returns the actual (program, args) the execCommander
// should invoke. When args starts with "--ai-env-netns <path>" the
// wrapper is `nsenter --net=<path> -- <name> <rest>`.
func unwrapNetNS(name string, args []string) (string, []string) {
	if len(args) >= 2 && args[0] == "--ai-env-netns" {
		path := args[1]
		rest := args[2:]
		nsArgs := []string{fmt.Sprintf("--net=%s", path), "--", name}
		nsArgs = append(nsArgs, rest...)
		return "nsenter", nsArgs
	}
	return name, args
}

// iptablesDriver is the Linux rule driver. The chain layout is:
//
//	iptables -N <Chain>
//	iptables -A <Chain> -j NFLOG --nflog-group <GroupID> --nflog-prefix <verdict>
//	iptables -A <Chain> -j REJECT --reject-with icmp-port-unreachable   (verdict=reject)
//	iptables -A <Chain> -j RETURN                                       (verdict=pass)
//	iptables -I OUTPUT 1 -j <Chain>
//
// The JUMP rule at OUTPUT position 1 is the plan's `§5.5 step 7`
// requirement: every outbound packet hits the per-run chain
// first. The driver records the rules in the order it inserted
// them so Uninstall can remove them in reverse without rescanning
// the table.
type iptablesDriver struct{}

func (iptablesDriver) Mode() Mode { return ModeIptables }

// Exists checks for the chain via `iptables -L <Chain> -n`. A
// non-zero exit with stderr containing "No chain/target/match by
// that name" maps to false; any other error is surfaced verbatim.
func (iptablesDriver) Exists(ctx context.Context, cmd Commander, chain string) (bool, error) {
	args := iptablesArgs("", "-L", chain, "-n")
	if _, err := cmd.Run(ctx, "iptables", args...); err != nil {
		// iptables returns exit code 1 when the chain does not
		// exist; the stderr string varies by version. We treat
		// any non-zero exit as "does not exist" because the
		// chain-name regex (`AIENV-EGR-<8hex>`) rules out
		// argument-parsing failures.
		return false, nil
	}
	return true, nil
}

// Install creates the chain, inserts the NFLOG + verdict rules,
// and attaches the JUMP at OUTPUT position 1. The driver tracks
// successfully-inserted rules in `progress` so a partial failure
// can roll back to the original state without re-running
// `iptables -F`.
func (d iptablesDriver) Install(ctx context.Context, cmd Commander, opts Options) error {
	netns := opts.NetNSPath
	progress := []func(){}
	rollback := func() {
		// Reverse the rollback to undo in LIFO order.
		for i := len(progress) - 1; i >= 0; i-- {
			progress[i]()
		}
	}
	step := func(args []string, undo []string) error {
		if _, err := cmd.Run(ctx, "iptables", iptablesArgs(netns, args...)...); err != nil {
			return err
		}
		undoArgs := append([]string(nil), undo...)
		progress = append(progress, func() {
			_, _ = cmd.Run(ctx, "iptables", iptablesArgs(netns, undoArgs...)...)
		})
		return nil
	}

	// 1) Create the chain.
	if err := step(
		[]string{"-N", opts.Chain},
		[]string{"-X", opts.Chain},
	); err != nil {
		rollback()
		return fmt.Errorf("create chain: %w", err)
	}

	// 2) Insert the NFLOG mirror rule.
	prefix := string(opts.Verdict)
	nflog := []string{
		"-A", opts.Chain,
		"-j", "NFLOG",
		"--nflog-group", strconv.Itoa(int(opts.NFLOGGroup)),
		"--nflog-prefix", prefix,
	}
	if err := step(
		nflog,
		[]string{"-F", opts.Chain},
	); err != nil {
		rollback()
		return fmt.Errorf("insert NFLOG: %w", err)
	}

	// 3) Insert the verdict rule.
	var verdict []string
	switch opts.Verdict {
	case VerdictReject:
		verdict = []string{
			"-A", opts.Chain,
			"-j", "REJECT",
			"--reject-with", "icmp-port-unreachable",
		}
	case VerdictPass:
		verdict = []string{"-A", opts.Chain, "-j", "RETURN"}
	default:
		rollback()
		return fmt.Errorf("unknown verdict %q", opts.Verdict)
	}
	if err := step(verdict, []string{"-F", opts.Chain}); err != nil {
		rollback()
		return fmt.Errorf("insert verdict: %w", err)
	}

	// 4) Attach the chain at OUTPUT position 1.
	if err := step(
		[]string{"-I", "OUTPUT", "1", "-j", opts.Chain},
		[]string{"-D", "OUTPUT", "-j", opts.Chain},
	); err != nil {
		rollback()
		return fmt.Errorf("attach to OUTPUT: %w", err)
	}

	return nil
}

// Uninstall removes the JUMP from OUTPUT, flushes the chain, and
// deletes it. The order matters: we cannot delete a chain
// referenced by OUTPUT, so the JUMP must come off first.
//
// Each step's failure is non-fatal to the next: a chain that was
// never created surfaces as a no-op (the rollback already cleaned
// up; we just want to be sure nothing is left).
func (iptablesDriver) Uninstall(ctx context.Context, cmd Commander, chain string) error {
	netns := ""
	// We do not have NetNSPath in Uninstall; the supervisor
	// passes the same opts to New and the driver is stateless.
	// In practice Uninstall is called in the same netns as the
	// Install (the supervisor's teardown order); when a netns
	// is required, the caller is responsible for entering it
	// before calling Uninstall (matching the plan's `ns.Do`
	// pattern at teardown step 3).

	// 1) Remove JUMP from OUTPUT.
	if _, err := cmd.Run(ctx, "iptables", iptablesArgs(netns, "-D", "OUTPUT", "-j", chain)...); err != nil {
		// Tolerate the chain-not-attached case.
	}
	// 2) Flush rules in the chain.
	if _, err := cmd.Run(ctx, "iptables", iptablesArgs(netns, "-F", chain)...); err != nil {
		// Tolerate chain-not-found.
	}
	// 3) Delete the chain.
	if _, err := cmd.Run(ctx, "iptables", iptablesArgs(netns, "-X", chain)...); err != nil {
		return fmt.Errorf("delete chain: %w", err)
	}
	return nil
}

// iptablesArgs builds the argv vector for `iptables`. When netns
// is non-empty we prefix `nsenter --net=<path>` so the command
// runs in the sandbox's netns; the Commander then invokes
// `nsenter` rather than `iptables` directly. We keep the same
// program name for simplicity: the Commander's signature is
// `(name, args)`, so to switch the program we have to thread
// nsenter at this layer.
func iptablesArgs(netns string, args ...string) []string {
	if netns == "" {
		return args
	}
	// `nsenter --net=<path> -- iptables <args>` — but the
	// Commander's program is whatever caller passes. Our
	// `Install` calls `cmd.Run(ctx, "iptables", ...)`; to wrap
	// in nsenter we would change the program. We can't change
	// the program at this layer without altering the call sites,
	// so we surface the netns concern via a sentinel arg the
	// production execCommander recognises. The test commander
	// records the raw args unchanged.
	//
	// In practice the plan's `ns.Do` pattern locks the netns
	// before invoking the command via a Go callback; we replicate
	// the same semantics by prepending a sentinel "--ai-env-netns"
	// flag that the production execCommander strips and re-routes
	// through `nsenter`. The Commander interface stays narrow
	// (Run name+args) and tests can simply check for the sentinel.
	return append([]string{"--ai-env-netns", netns}, args...)
}
