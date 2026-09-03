package version

import (
	"strconv"
	"strings"
)

// mavenComparator implements Maven's version ordering as defined in
// https://maven.apache.org/pom.html#version-order-specification
//
// The rules are significantly more complex than SemVer:
//  - Versions are split into dot- and hyphen-separated tokens.
//  - Tokens are compared as integers where possible, strings otherwise.
//  - Known qualifier order (ascending): alpha < beta < milestone < rc/cr <
//    snapshot < (no qualifier/ga/final) < sp.
//  - Unknown string qualifiers sort lexicographically after sp.
//  - The algorithm pads shorter versions with zeros/empty strings.
//
// For PatchFlow's purposes (matching installed vs fixed version) the
// standard numeric + qualifier ordering is sufficient.
type mavenComparator struct{}

// NewMaven returns the Maven version comparator.
func NewMaven() Comparator { return &mavenComparator{} }

func (*mavenComparator) Ecosystem() string { return "maven" }

func (c *mavenComparator) Compare(a, b string) int {
	return mavenCmp(a, b)
}

func (c *mavenComparator) IsFixedBy(installed, fixed string) bool {
	return mavenCmp(installed, fixed) < 0
}

func (c *mavenComparator) InRange(version, affectedRange string) bool {
	return evalRange(c, version, affectedRange)
}

// --- Maven version item ---------------------------------------------------

// mvnItemKind distinguishes integers, qualifiers, and separators.
type mvnItem struct {
	isInt bool
	n     int64
	s     string
}

// qualifierOrder maps known Maven qualifiers to their sort weight.
// Higher weight = more recent. Release (empty / "ga" / "final") = 9.
var qualifierOrder = map[string]int{
	"alpha":     1, "a": 1,
	"beta":      2, "b": 2,
	"milestone": 3, "m": 3,
	"rc":        4, "cr": 4,
	"snapshot":  5,
	"":          9, "ga": 9, "final": 9,
	"sp":        10,
}

func mvnQualifierOrd(s string) int {
	s = strings.ToLower(s)
	if n, ok := qualifierOrder[s]; ok {
		return n
	}
	return 11 // unknown qualifiers sort after sp, then lexicographic
}

// tokenizeMaven splits a Maven version string into a flat list of tokens.
// Both '.' and '-' are treated as separators; a transition between a digit
// run and a letter run is also an implicit separator.
func tokenizeMaven(v string) []mvnItem {
	v = strings.ToLower(v)
	var items []mvnItem
	i := 0
	for i < len(v) {
		if v[i] == '.' || v[i] == '-' {
			i++
			continue
		}
		j := i + 1
		if v[i] >= '0' && v[i] <= '9' {
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			n, _ := strconv.ParseInt(v[i:j], 10, 64)
			items = append(items, mvnItem{isInt: true, n: n})
		} else {
			for j < len(v) && v[j] != '.' && v[j] != '-' &&
				!(v[j] >= '0' && v[j] <= '9') {
				j++
			}
			items = append(items, mvnItem{isInt: false, s: v[i:j]})
		}
		i = j
	}
	return items
}

func mavenCmp(a, b string) int {
	ta, tb := tokenizeMaven(a), tokenizeMaven(b)
	la, lb := len(ta), len(tb)
	limit := la
	if lb > limit {
		limit = lb
	}
	for i := 0; i < limit; i++ {
		aPresent := i < la
		bPresent := i < lb

		if aPresent && bPresent {
			ia, ib := ta[i], tb[i]
			if ia.isInt && ib.isInt {
				if c := cmpInt64(ia.n, ib.n); c != 0 {
					return c
				}
			} else if !ia.isInt && !ib.isInt {
				oa, ob := mvnQualifierOrd(ia.s), mvnQualifierOrd(ib.s)
				if oa != ob {
					return cmpInt(oa, ob)
				}
				if c := strings.Compare(ia.s, ib.s); c != 0 {
					return c
				}
			} else if ia.isInt {
				return 1 // int > qualifier
			} else {
				return -1 // qualifier < int
			}
		} else if aPresent {
			// b is absent; treat as 0 (int) or "" (release qualifier = order 9).
			item := ta[i]
			if item.isInt {
				if item.n != 0 {
					return 1
				}
			} else {
				ord := mvnQualifierOrd(item.s)
				if ord != 9 { // 9 = release/""/ga/final
					return cmpInt(ord, 9)
				}
			}
		} else {
			// a is absent; same logic mirrored.
			item := tb[i]
			if item.isInt {
				if item.n != 0 {
					return -1
				}
			} else {
				ord := mvnQualifierOrd(item.s)
				if ord != 9 {
					return cmpInt(9, ord)
				}
			}
		}
	}
	return 0
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
