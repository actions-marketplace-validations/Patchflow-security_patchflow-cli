package version

import (
	"strconv"
	"strings"
	"unicode"
)

// dpkgComparator implements Debian's dpkg version ordering as defined in
// the Debian Policy Manual §5.6.12.
//
// Format: [epoch:]upstream_version[-debian_revision]
//
// The comparison algorithm:
//  1. Epoch (integer before ':'); higher epoch always wins.
//  2. Upstream version: alternating non-digit and digit chunks compared
//     lexicographically (with special ASCII ordering) and numerically.
//  3. Debian revision (after last '-'): same chunking as upstream.
//
// Special ASCII ordering for non-digit chunks: '~' < '' (empty) < letters
// < everything else. This allows "1.0~rc1" to sort BEFORE "1.0".
type dpkgComparator struct{}

// NewDpkg returns the Debian/Ubuntu dpkg version comparator.
func NewDpkg() Comparator { return &dpkgComparator{} }

func (*dpkgComparator) Ecosystem() string { return "deb" }

func (c *dpkgComparator) Compare(a, b string) int {
	return dpkgCompare(a, b)
}

func (c *dpkgComparator) IsFixedBy(installed, fixed string) bool {
	return dpkgCompare(installed, fixed) < 0
}

func (c *dpkgComparator) InRange(version, affectedRange string) bool {
	return evalRange(c, version, affectedRange)
}

// --- dpkg version parser --------------------------------------------------

type dpkgVer struct {
	epoch    int
	upstream string
	revision string
}

func parseDpkg(v string) dpkgVer {
	var res dpkgVer
	// Strip epoch.
	if idx := strings.IndexByte(v, ':'); idx >= 0 {
		res.epoch, _ = strconv.Atoi(v[:idx])
		v = v[idx+1:]
	}
	// Split revision at last '-'.
	if idx := strings.LastIndexByte(v, '-'); idx >= 0 {
		res.upstream = v[:idx]
		res.revision = v[idx+1:]
	} else {
		res.upstream = v
	}
	return res
}

func dpkgCompare(a, b string) int {
	va, vb := parseDpkg(a), parseDpkg(b)
	if c := cmpInt(va.epoch, vb.epoch); c != 0 {
		return c
	}
	if c := dpkgCmpString(va.upstream, vb.upstream); c != 0 {
		return c
	}
	return dpkgCmpString(va.revision, vb.revision)
}

// dpkgCmpString implements the alternating non-digit/digit chunk comparison
// from the Debian Policy Manual.
func dpkgCmpString(a, b string) int {
	for a != "" || b != "" {
		// Compare non-digit prefix.
		na := dpkgNonDigit(a)
		nb := dpkgNonDigit(b)
		if c := dpkgCmpNonDigit(na, nb); c != 0 {
			return c
		}
		a = a[len(na):]
		b = b[len(nb):]

		// Compare digit prefix numerically.
		da := dpkgDigit(a)
		db := dpkgDigit(b)
		na2, _ := strconv.Atoi(da)
		nb2, _ := strconv.Atoi(db)
		if c := cmpInt(na2, nb2); c != 0 {
			return c
		}
		a = a[len(da):]
		b = b[len(db):]
	}
	return 0
}

// dpkgNonDigit returns the leading non-digit chunk of s.
func dpkgNonDigit(s string) string {
	i := 0
	for i < len(s) && !unicode.IsDigit(rune(s[i])) {
		i++
	}
	return s[:i]
}

// dpkgDigit returns the leading digit chunk of s.
func dpkgDigit(s string) string {
	i := 0
	for i < len(s) && unicode.IsDigit(rune(s[i])) {
		i++
	}
	return s[:i]
}

// dpkgOrder returns the sort order for a single character in a non-digit
// chunk. This is the Debian-defined order:
//
//	'~' sorts first (before anything, even an empty string).
//	Letters sort next.
//	Everything else (digits never appear here) sorts after letters.
func dpkgOrder(ch byte) int {
	switch {
	case ch == '~':
		return -1
	case ch >= 'A' && ch <= 'Z':
		return int(ch)
	case ch >= 'a' && ch <= 'z':
		return int(ch)
	default:
		return int(ch) + 256
	}
}

// dpkgCmpNonDigit compares two non-digit strings character by character
// using the Debian ordering. Missing characters are treated as 0 (empty),
// which sorts between '~' and all other characters.
func dpkgCmpNonDigit(a, b string) int {
	lena, lenb := len(a), len(b)
	limit := lena
	if lenb > limit {
		limit = lenb
	}
	for i := 0; i < limit; i++ {
		oa, ob := 0, 0
		if i < lena {
			oa = dpkgOrder(a[i])
		}
		if i < lenb {
			ob = dpkgOrder(b[i])
		}
		if c := cmpInt(oa, ob); c != 0 {
			return c
		}
	}
	return 0
}
