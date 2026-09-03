package version

import "strings"

// evalRange evaluates a range expression against an installed version using
// the given comparator. It is the single implementation shared by all
// comparators' InRange methods.
//
// Supported range expression formats (used by OSV, Alpine SecDB, Debian
// Security Tracker, Ubuntu OVAL, and PatchFlow-native advisories):
//
//   Operator expressions (comma-separated, all must hold):
//     "< 1.2.3"     installed < 1.2.3
//     "<= 1.2.3"    installed <= 1.2.3
//     "> 1.2.3"     installed > 1.2.3
//     ">= 1.2.3"    installed >= 1.2.3
//     "= 1.2.3"     installed == 1.2.3
//     "!= 1.2.3"    installed != 1.2.3
//
//   Convenience shorthands:
//     "[1.0.0, 2.0.0)"   half-open interval [introduced, fixed)
//     "(,2.0.0)"         affected up to (not including) 2.0.0
//
//   Empty string → always in range (matches any version; used when the
//   advisory specifies "all versions" without a bound).
func evalRange(c Comparator, version, affectedRange string) bool {
	if affectedRange == "" {
		return true
	}

	// Maven-style interval notation: "[1.0,2.0)" or "(,2.0)".
	if strings.HasPrefix(affectedRange, "[") || strings.HasPrefix(affectedRange, "(") {
		return evalMavenRange(c, version, affectedRange)
	}

	// Comma-separated operator expressions.
	for _, clause := range strings.Split(affectedRange, ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		if !evalClause(c, version, clause) {
			return false
		}
	}
	return true
}

// evalClause evaluates a single "OP version" clause.
func evalClause(c Comparator, installed, clause string) bool {
	clause = strings.TrimSpace(clause)
	// Extract operator prefix.
	op, ver := splitOp(clause)
	if ver == "" {
		return false
	}
	cmp := c.Compare(installed, ver)
	switch op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "=", "==":
		return cmp == 0
	case "!=":
		return cmp != 0
	default:
		// No operator — treat as exact equality.
		return c.Compare(installed, clause) == 0
	}
}

// splitOp splits an operator+version string into (op, version).
func splitOp(s string) (op, ver string) {
	for _, o := range []string{"<=", ">=", "!=", "<", ">", "=", "=="} {
		if strings.HasPrefix(s, o) {
			return o, strings.TrimSpace(s[len(o):])
		}
	}
	return "", s
}

// evalMavenRange handles interval notation "[lo,hi)" / "(lo,hi]" etc.
// Also accepted by OSV for some ecosystems.
//
//   '[' = inclusive lower bound
//   '(' = exclusive lower bound / no lower bound
//   ']' = inclusive upper bound
//   ')' = exclusive upper bound / no upper bound
func evalMavenRange(c Comparator, version, r string) bool {
	if len(r) < 2 {
		return false
	}
	loBound := r[0]   // '[' or '('
	hiBound := r[len(r)-1] // ']' or ')'
	inner := r[1 : len(r)-1]

	// Split into lo, hi.
	var lo, hi string
	if idx := strings.IndexByte(inner, ','); idx >= 0 {
		lo = strings.TrimSpace(inner[:idx])
		hi = strings.TrimSpace(inner[idx+1:])
	} else {
		// Single-bound: "[1.0]" means exactly 1.0.
		lo = strings.TrimSpace(inner)
		hi = lo
		loBound = '['
		hiBound = ']'
	}

	// Lower bound.
	if lo != "" {
		clo := c.Compare(version, lo)
		switch loBound {
		case '[':
			if clo < 0 {
				return false
			}
		case '(':
			if clo <= 0 {
				return false
			}
		}
	}

	// Upper bound.
	if hi != "" {
		chi := c.Compare(version, hi)
		switch hiBound {
		case ']':
			if chi > 0 {
				return false
			}
		case ')':
			if chi >= 0 {
				return false
			}
		}
	}
	return true
}
