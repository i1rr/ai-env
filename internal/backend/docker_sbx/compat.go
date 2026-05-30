package docker_sbx

import (
	"fmt"
	"strconv"
	"strings"
)

// MinTestedVersion is the lowest sbx version this adapter has been
// exercised against. Bump alongside TestedVersionRange when a new sbx
// release is qualified.
const MinTestedVersion = "0.1.0"

// MaxTestedVersion is the highest sbx version this adapter has been
// exercised against. Versions above this are considered untested and
// fail closed unless --allow-untested-backend-version is passed.
const MaxTestedVersion = "0.9.99"

// TestedVersionRange is the human-readable inclusive range printed in
// doctor output and error messages when an untested version is
// detected. Keeping the range as a literal string (rather than computing
// it) lets us print exactly what we mean even if MinTestedVersion or
// MaxTestedVersion is later replaced with a constraint expression.
const TestedVersionRange = MinTestedVersion + " - " + MaxTestedVersion

// semver is the minimal three-component representation the adapter
// needs to compare versions. Pre-release and build-metadata suffixes
// are ignored: sbx version strings observed in the wild ("0.4.2",
// "v0.5.0-rc1") only need ordering by the numeric core.
type semver struct {
	major int
	minor int
	patch int
}

// parseSemver extracts a semver from a free-form version string. It
// tolerates a leading "v", trailing pre-release / build suffixes after
// "-" or "+", and surrounding whitespace. The plan's parsing principle
// is to parse minimally: anything more would couple us to upstream
// formatting decisions we have no control over.
func parseSemver(s string) (semver, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return semver{}, fmt.Errorf("unrecognized version %q", s)
	}
	out := semver{}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return semver{}, fmt.Errorf("unrecognized version component %q: %w", p, err)
		}
		switch i {
		case 0:
			out.major = n
		case 1:
			out.minor = n
		case 2:
			out.patch = n
		}
	}
	return out, nil
}

// cmp returns -1, 0, or 1 the same way strings.Compare does.
func (a semver) cmp(b semver) int {
	if a.major != b.major {
		if a.major < b.major {
			return -1
		}
		return 1
	}
	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1
		}
		return 1
	}
	if a.patch != b.patch {
		if a.patch < b.patch {
			return -1
		}
		return 1
	}
	return 0
}

// IsVersionSupported reports whether the supplied sbx version string
// falls within the tested range. A version that cannot be parsed is
// treated as unsupported: the caller must fail closed and surface the
// raw string to the operator.
func IsVersionSupported(version string) bool {
	v, err := parseSemver(version)
	if err != nil {
		return false
	}
	lo, err := parseSemver(MinTestedVersion)
	if err != nil {
		return false
	}
	hi, err := parseSemver(MaxTestedVersion)
	if err != nil {
		return false
	}
	if v.cmp(lo) < 0 {
		return false
	}
	if v.cmp(hi) > 0 {
		return false
	}
	return true
}
