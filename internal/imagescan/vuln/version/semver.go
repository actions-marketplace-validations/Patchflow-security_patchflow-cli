package version

import (
	"strconv"
	"strings"
)

// semverComparator handles npm, cargo, and any other ecosystem that uses
// a subset of semantic versioning (MAJOR.MINOR.PATCH[-pre][+build]).
// Build metadata is ignored for comparison per the SemVer spec.
// Pre-release identifiers lower the version: "1.0.0-alpha" < "1.0.0".
type semverComparator struct{ eco string }

// NewSemver returns a semver-based comparator for the given ecosystem name.
// Used as the fallback in the registry for unknown ecosystems.
func NewSemver(ecosystem string) Comparator { return &semverComparator{eco: ecosystem} }

func (c *semverComparator) Ecosystem() string { return c.eco }

func (c *semverComparator) Compare(a, b string) int {
	return semverCmp(stripV(a), stripV(b))
}

func (c *semverComparator) IsFixedBy(installed, fixed string) bool {
	return semverCmp(stripV(installed), stripV(fixed)) < 0
}

func (c *semverComparator) InRange(version, affectedRange string) bool {
	return evalRange(c, version, affectedRange)
}

// stripV removes a leading "v" or "V" prefix.
func stripV(v string) string {
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		return v[1:]
	}
	return v
}

type semVer struct {
	major, minor, patch int
	pre                 []string // pre-release identifiers, empty means release
}

func parseSemver(v string) semVer {
	var res semVer
	// Drop build metadata.
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	// Split pre-release.
	if i := strings.IndexByte(v, '-'); i >= 0 {
		res.pre = strings.Split(v[i+1:], ".")
		v = v[:i]
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) > 0 {
		res.major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) > 1 {
		res.minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) > 2 {
		res.patch, _ = strconv.Atoi(parts[2])
	}
	return res
}

func semverCmp(a, b string) int {
	va, vb := parseSemver(a), parseSemver(b)
	if c := cmpInt(va.major, vb.major); c != 0 {
		return c
	}
	if c := cmpInt(va.minor, vb.minor); c != 0 {
		return c
	}
	if c := cmpInt(va.patch, vb.patch); c != 0 {
		return c
	}
	// Pre-release comparison: no pre-release > pre-release.
	switch {
	case len(va.pre) == 0 && len(vb.pre) > 0:
		return 1
	case len(va.pre) > 0 && len(vb.pre) == 0:
		return -1
	}
	limit := len(va.pre)
	if len(vb.pre) > limit {
		limit = len(vb.pre)
	}
	for i := 0; i < limit; i++ {
		var pa, pb string
		if i < len(va.pre) {
			pa = va.pre[i]
		}
		if i < len(vb.pre) {
			pb = vb.pre[i]
		}
		na, aerr := strconv.Atoi(pa)
		nb, berr := strconv.Atoi(pb)
		if aerr == nil && berr == nil {
			if c := cmpInt(na, nb); c != 0 {
				return c
			}
		} else if aerr == nil {
			return -1 // numeric < alpha per SemVer §11.4
		} else if berr == nil {
			return 1
		} else {
			if c := strings.Compare(pa, pb); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(va.pre), len(vb.pre))
}
