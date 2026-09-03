package version

import (
	"regexp"
	"strconv"
	"strings"
)

// pep440Comparator implements PEP 440 version ordering for Python packages.
//
// Canonical form: N[.N]*[{a|b|rc}N][.postN][.devN]
// Ordering: devN < alphaN < betaN < rcN < release < postN
// Epoch (E!) prefix: higher epoch always wins.
//
// We handle normalisation per PEP 440 §5 (hyphen/underscore → dot, etc.)
// but do not implement the full dependency specifier DSL — range evaluation
// uses evalRange() with operator tokens just like every other ecosystem.
type pep440Comparator struct{}

// NewPEP440 returns the PEP 440 comparator for Python/PyPI.
func NewPEP440() Comparator { return &pep440Comparator{} }

func (*pep440Comparator) Ecosystem() string { return "pypi" }

func (c *pep440Comparator) Compare(a, b string) int {
	return pep440Cmp(a, b)
}

func (c *pep440Comparator) IsFixedBy(installed, fixed string) bool {
	return pep440Cmp(installed, fixed) < 0
}

func (c *pep440Comparator) InRange(version, affectedRange string) bool {
	return evalRange(c, version, affectedRange)
}

type pep440Ver struct {
	epoch   int
	release []int   // N[.N]*
	pre     string  // "a", "b", "rc", or ""
	preN    int
	post    int
	dev     int
	hasDev  bool
	hasPost bool
}

// pep440Re matches the canonical PEP 440 version format after normalisation.
// Groups: 1=epoch, 2=release, 3=pre-type (a/b/rc/c), 4=pre-N, 5=post-N, 6=dev-N
// "c" is treated as "rc" per PEP 440 compatibility alias.
var pep440Re = regexp.MustCompile(
	`^(?:(\d+)!)?` + // epoch (optional)
		`(\d+(?:\.\d+)*)` + // release N[.N]*
		`(?:(a|b|rc|c)(\d*))?` + // pre-release (optional, no dot required)
		`(?:\.post(\d+))?` + // post-release (optional)
		`(?:\.dev(\d+))?$`, // dev release (optional)
)

// pep440Normalize applies PEP 440 §5 normalisation before regex parsing.
func pep440Normalize(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "-", ".")
	v = strings.ReplaceAll(v, "_", ".")
	// Long-form synonyms → canonical single-letter forms.
	v = strings.ReplaceAll(v, "alpha", "a")
	v = strings.ReplaceAll(v, "beta", "b")
	v = strings.ReplaceAll(v, "preview", "rc")
	// ".a1" / ".b1" / ".rc1" — strip the dot so the regex matches.
	for _, pre := range []string{"rc", "b", "a"} {
		v = strings.ReplaceAll(v, "."+pre, pre)
	}
	return v
}

func parsePEP440(v string) pep440Ver {
	norm := pep440Normalize(v)
	var res pep440Ver

	m := pep440Re.FindStringSubmatch(norm)
	if m == nil {
		// Fallback: treat as a plain dotted integer release.
		for _, s := range strings.Split(norm, ".") {
			n, _ := strconv.Atoi(s)
			res.release = append(res.release, n)
		}
		return res
	}

	// m[1] epoch
	if m[1] != "" {
		res.epoch, _ = strconv.Atoi(m[1])
	}
	// m[2] release
	for _, s := range strings.Split(m[2], ".") {
		n, _ := strconv.Atoi(s)
		res.release = append(res.release, n)
	}
	// m[3] pre type, m[4] pre N ("c" is a PEP 440 alias for "rc")
	if m[3] != "" {
		pre := m[3]
		if pre == "c" {
			pre = "rc"
		}
		res.pre = pre
		if m[4] != "" {
			res.preN, _ = strconv.Atoi(m[4])
		}
	}
	// m[5] post N
	if m[5] != "" {
		res.hasPost = true
		res.post, _ = strconv.Atoi(m[5])
	}
	// m[6] dev N
	if m[6] != "" {
		res.hasDev = true
		res.dev, _ = strconv.Atoi(m[6])
	}
	return res
}

func pep440Cmp(a, b string) int {
	va, vb := parsePEP440(a), parsePEP440(b)

	if c := cmpInt(va.epoch, vb.epoch); c != 0 {
		return c
	}

	// Release: pad shorter to same length with zeros.
	la, lb := len(va.release), len(vb.release)
	limit := la
	if lb > limit {
		limit = lb
	}
	for i := 0; i < limit; i++ {
		na, nb := 0, 0
		if i < la {
			na = va.release[i]
		}
		if i < lb {
			nb = vb.release[i]
		}
		if c := cmpInt(na, nb); c != 0 {
			return c
		}
	}

	// Pre-release: dev < a < b < rc < release.
	preOrder := func(p pep440Ver) int {
		if p.hasDev {
			return -10 + p.dev // dev always before everything
		}
		switch p.pre {
		case "a":
			return 100 + p.preN
		case "b":
			return 200 + p.preN
		case "rc":
			return 300 + p.preN
		}
		return 1000 // release
	}
	oa, ob := preOrder(va), preOrder(vb)
	if c := cmpInt(oa, ob); c != 0 {
		return c
	}

	// Post.
	aPost := 0
	if va.hasPost {
		aPost = va.post + 1
	}
	bPost := 0
	if vb.hasPost {
		bPost = vb.post + 1
	}
	return cmpInt(aPost, bPost)
}
