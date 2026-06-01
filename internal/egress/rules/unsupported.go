package rules

import "context"

// unsupportedDriver is the stub `ruleDriver` for hosts where the
// production driver cannot run (non-Linux, non-Darwin). It also
// serves as the test seam tests use to assert the
// `ErrUnsupportedOS` propagation without an OS-conditional
// compile.
//
// The driver is intentionally exported only inside the package:
// callers obtain it via `platformDriver()` (build-tagged) or
// substitute it directly via the `Lifecycle.driver` field in
// tests; there is no external constructor.
type unsupportedDriver struct{}

func (unsupportedDriver) Mode() Mode { return ModeUnsupported }

func (unsupportedDriver) Exists(ctx context.Context, cmd Commander, chain string) (bool, error) {
	return false, ErrUnsupportedOS
}

func (unsupportedDriver) Install(ctx context.Context, cmd Commander, opts Options) error {
	return ErrUnsupportedOS
}

func (unsupportedDriver) Uninstall(ctx context.Context, cmd Commander, chain string) error {
	return ErrUnsupportedOS
}
