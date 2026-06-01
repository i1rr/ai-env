//go:build !linux && !darwin

package rules

import "context"

// platformDriver returns the stub driver on hosts that are
// neither Linux nor macOS. The stub itself lives in
// `unsupported.go` so the test suite (which assigns
// `unsupportedDriver{}` directly to a Lifecycle) can compile on
// every OS.
func platformDriver() ruleDriver { return unsupportedDriver{} }

// platformCommander returns a stub Commander that errors on
// every call. Never invoked in practice (the driver short-
// circuits first), but defined so the package compiles cleanly
// without a nil panic if a future enhancement somehow reaches
// the Commander before the driver.
func platformCommander() Commander {
	return CommanderFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, ErrUnsupportedOS
	})
}
