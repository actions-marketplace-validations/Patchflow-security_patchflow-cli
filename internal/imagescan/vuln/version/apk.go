package version

import (
	"strconv"
	"strings"
	"unicode"
)

// apkComparator implements Alpine's APK version ordering.
//
// APK version format: [epoch:]version[-release][_pre/alpha/beta/rc/p<N>]
// Examples: "3.1.4-r1", "1.2.0_pre1", "2:1.0-r0"
//
// Ordering rules (apk_version_compare in apk-tools source):
//  1. Epoch (numeric prefix before ':') is compared first.
//  2. Remaining numeric/alpha segments are compared left-to-right.
//  3. A numeric segment is greater than an alpha segment.
//  4. Suffix ordering: (none) > _rc > _beta > _alpha > _pre > _p<N>
//     where _p<N> means "patch N of a release" and is GREATER than the release.
type apkComparator struct{}

// NewAPK returns the Alpine APK version comparator.
func NewAPK() Comparator { return &apkComparator{} }

func (*apkComparator) Ecosystem() string { return "alpine" }

func (c *apkComparator) Compare(a, b string) int {
	return apkCompare(a, b)
}

func (c *apkComparator) IsFixedBy(installed, fixed string) bool {
	return apkCompare(installed, fixed) < 0
}

// InRange checks OSV-style range expressions for Alpine:
//   - "< X"  — affected while installed < X
//   - ">= X" — affected while installed >= X
//   - ">= X, < Y" — affected in [X, Y)
//   - exact equality "<version>" (no operator) — match only that version
func (c *apkComparator) InRange(version, affectedRange string) bool {
	return evalRange(c, version, affectedRange)
}

// --- APK version parser ---------------------------------------------------

type apkVer struct {
	epoch    int
	parts    []apkPart
	preSuffix int  // suffix_pre order: _p > (none) > _rc > _beta > _alpha > _pre
	preN     int
}

type apkPart struct {
	isNum bool
	num   int
	str   string
}

// suffixOrder maps known suffix strings to a comparable integer.
// Higher = newer. "p" patches come AFTER the release, all pre-release comes before.
var suffixOrder = map[string]int{
	"p":     6,
	"":      5, // release
	"rc":    4,
	"beta":  3,
	"alpha": 2,
	"pre":   1,
}

func parseAPK(v string) apkVer {
	var res apkVer

	// Strip epoch.
	if idx := strings.IndexByte(v, ':'); idx >= 0 {
		res.epoch, _ = strconv.Atoi(v[:idx])
		v = v[idx+1:]
	}

	// Split suffix: everything after the last '_' that is a known suffix.
	suffixStr := ""
	suffixN := 0
	if idx := strings.LastIndexByte(v, '_'); idx >= 0 {
		s := v[idx+1:]
		// s may be "pre1", "rc2", "p3", "alpha", "beta", etc.
		sfx := strings.TrimRightFunc(s, unicode.IsDigit)
		n := 0
		if sfx != s {
			n, _ = strconv.Atoi(s[len(sfx):])
		}
		if _, known := suffixOrder[sfx]; known {
			suffixStr = sfx
			suffixN = n
			v = v[:idx]
		}
	}
	res.preSuffix = suffixOrder[suffixStr]
	res.preN = suffixN

	// Split the remainder on dots and dashes; classify each segment.
	// The "-r<N>" release suffix is treated as another numeric part.
	v = strings.ReplaceAll(v, "-", ".")
	for _, seg := range strings.Split(v, ".") {
		if seg == "" {
			continue
		}
		if n, err := strconv.Atoi(seg); err == nil {
			res.parts = append(res.parts, apkPart{isNum: true, num: n})
		} else {
			res.parts = append(res.parts, apkPart{isNum: false, str: seg})
		}
	}
	return res
}

func apkCompare(a, b string) int {
	va, vb := parseAPK(a), parseAPK(b)

	if c := cmpInt(va.epoch, vb.epoch); c != 0 {
		return c
	}

	lena, lenb := len(va.parts), len(vb.parts)
	limit := lena
	if lenb > limit {
		limit = lenb
	}
	for i := 0; i < limit; i++ {
		var pa, pb apkPart
		if i < lena {
			pa = va.parts[i]
		}
		if i < lenb {
			pb = vb.parts[i]
		}
		switch {
		case pa.isNum && pb.isNum:
			if c := cmpInt(pa.num, pb.num); c != 0 {
				return c
			}
		case pa.isNum && !pb.isNum:
			return 1 // numeric > alpha
		case !pa.isNum && pb.isNum:
			return -1
		default:
			if c := strings.Compare(pa.str, pb.str); c != 0 {
				return c
			}
		}
	}

	// Suffix ordering.
	if c := cmpInt(va.preSuffix, vb.preSuffix); c != 0 {
		return c
	}
	return cmpInt(va.preN, vb.preN)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
