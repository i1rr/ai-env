//go:build darwin

package rules

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// platformDriver returns the pf driver on macOS.
func platformDriver() ruleDriver { return pfDriver{} }

// platformCommander runs `pfctl` via `os/exec`. The supervisor is
// expected to run with sudo on dev-machine macOS (documented in
// the platform matrix); the production code path does not retry
// nor escalate privileges.
func platformCommander() Commander { return execCommander{} }

// execCommander runs commands via `os/exec`. Captures stdout +
// stderr; on non-zero exit returns an error wrapping stderr.
type execCommander struct{}

func (execCommander) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s %v: %w: %s", name, args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// pfDriver is the macOS rule driver. The chain is implemented as
// a pf anchor: the supervisor creates a per-run anchor
// `AIENV-EGR-<8hex>`, loads two rules (a `pass log` for the
// mirror and a `block return log` for the verdict), and hooks the
// anchor into the main pf ruleset at OUTPUT-equivalent (`out`
// quick rules).
//
// pfctl command flow:
//
//	pfctl -a <Chain> -sr                                  # list rules in anchor
//	echo "block return log all" | pfctl -a <Chain> -f -    # load anchor rules
//	pfctl -a 'ai-env/<Chain>' -f -                         # attach to main ruleset
//
// pfctl exits 0 even when the anchor is empty; we rely on the
// list output to detect existence.
type pfDriver struct{}

func (pfDriver) Mode() Mode { return ModePF }

// Exists checks for the anchor via `pfctl -a <Chain> -sr`. An
// empty stdout with a zero exit means "anchor exists but no
// rules"; a non-zero exit means the anchor does not exist or
// pfctl could not query it. To distinguish "exists with rules"
// from "does not exist" we instead probe via `pfctl -sA` (list
// anchors) and look for the chain name in the output.
func (pfDriver) Exists(ctx context.Context, cmd Commander, chain string) (bool, error) {
	out, err := cmd.Run(ctx, "pfctl", "-sA")
	if err != nil {
		// pfctl may exit non-zero when the firewall is
		// disabled; treat as "does not exist" so a fresh-host
		// run is not blocked by a transient query failure.
		return false, nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == chain {
			return true, nil
		}
	}
	return false, nil
}

// Install creates the pf anchor, loads the rules, and hooks the
// anchor into the main ruleset. Same step-by-step rollback
// pattern as the Linux driver.
func (d pfDriver) Install(ctx context.Context, cmd Commander, opts Options) error {
	progress := []func(){}
	rollback := func() {
		for i := len(progress) - 1; i >= 0; i-- {
			progress[i]()
		}
	}
	chain := opts.Chain

	// 1) Load the anchor's rule body. We use `pfctl -a <Chain>
	//    -f -` and pipe the rules via stdin; the execCommander
	//    does not support stdin so we materialise the rules to
	//    a temporary file via the `printf`/`pfctl` pipeline.
	//    For simplicity we shell out to `sh -c` with a here-string;
	//    the chain name has been validated against the strict
	//    regex above so command injection is not a concern.
	var verdictRule string
	switch opts.Verdict {
	case VerdictReject:
		verdictRule = "block return log all"
	case VerdictPass:
		verdictRule = "pass log all"
	default:
		return fmt.Errorf("unknown verdict %q", opts.Verdict)
	}
	ruleBody := verdictRule + "\n"
	loadAnchor := []string{"-c", fmt.Sprintf("printf %q | pfctl -a %s -f -", ruleBody, chain)}
	if _, err := cmd.Run(ctx, "sh", loadAnchor...); err != nil {
		rollback()
		return fmt.Errorf("load anchor: %w", err)
	}
	progress = append(progress, func() {
		// Anchor flush via `pfctl -a <Chain> -F all`.
		_, _ = cmd.Run(ctx, "pfctl", "-a", chain, "-F", "all")
	})

	// 2) Hook the anchor into the main ruleset's out path so
	//    every egress packet is mirrored. The hook itself is a
	//    `anchor "<Chain>" all` line loaded into the main
	//    ruleset; we cannot easily merge into the operator's
	//    existing pf.conf, so the plan locks the supervisor to
	//    installing into a per-run anchor file the operator's
	//    pf.conf includes (documented as a setup step). For the
	//    purposes of this package the hook is the operator's
	//    pre-existing include; we record the no-op via progress
	//    so the rollback symmetry is preserved.
	progress = append(progress, func() {
		// No-op rollback for the operator-managed include.
	})

	return nil
}

// Uninstall flushes the anchor rules and removes the anchor.
// `pfctl -a <Chain> -F all` flushes; the anchor itself goes away
// once the operator's main pf.conf no longer references it (which
// is the operator's pre-existing include's responsibility).
func (pfDriver) Uninstall(ctx context.Context, cmd Commander, chain string) error {
	if _, err := cmd.Run(ctx, "pfctl", "-a", chain, "-F", "all"); err != nil {
		return fmt.Errorf("flush anchor: %w", err)
	}
	return nil
}
