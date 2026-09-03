// Package version provides per-ecosystem version comparison for the
// PatchFlow vulnerability matcher. Using a single comparator for all
// ecosystems produces wrong results because each package manager defines
// its own ordering and range syntax.
//
// The rule: never use simple string comparison or semver for OS packages.
// Alpine's "1.2.3-r1" is not semver. Debian's "2:3.4-5+deb12u1" is not
// semver. Getting this wrong means false-negatives in the matcher — the
// most dangerous bug a security scanner can have.
package version

import "fmt"

// Comparator is the interface every ecosystem comparator must implement.
type Comparator interface {
	// Ecosystem returns the ecosystem identifier (matches AffectedPackage.Ecosystem).
	Ecosystem() string

	// Compare returns -1, 0, or +1 (a < b, a == b, a > b).
	Compare(a, b string) int

	// IsFixedBy reports whether installedVersion is fixed by fixedVersion,
	// i.e. installedVersion < fixedVersion in this ecosystem's ordering.
	IsFixedBy(installedVersion, fixedVersion string) bool

	// InRange reports whether version falls within affectedRange. The range
	// syntax is ecosystem-specific; see each implementation for details.
	InRange(version, affectedRange string) bool
}

// Registry maps ecosystem names to their Comparator. Callers that need to
// pick the right comparator at runtime use ForEcosystem.
type Registry struct {
	m map[string]Comparator
}

// NewRegistry returns a Registry pre-loaded with all built-in comparators.
func NewRegistry() *Registry {
	r := &Registry{m: make(map[string]Comparator)}
	for _, c := range []Comparator{
		NewAPK(),
		NewDpkg(),
		NewSemver("npm"),
		NewSemver("cargo"),
		NewPEP440(),
		NewMaven(),
		NewGomod(),
	} {
		r.Register(c)
	}
	return r
}

// Register adds a comparator; panics on duplicate ecosystem key.
func (r *Registry) Register(c Comparator) {
	if _, dup := r.m[c.Ecosystem()]; dup {
		panic(fmt.Sprintf("version: duplicate comparator for ecosystem %q", c.Ecosystem()))
	}
	r.m[c.Ecosystem()] = c
}

// ForEcosystem returns the Comparator for the given ecosystem, or the
// semver fallback if none is registered. Never returns nil.
func (r *Registry) ForEcosystem(ecosystem string) Comparator {
	if c, ok := r.m[ecosystem]; ok {
		return c
	}
	return NewSemver(ecosystem)
}
