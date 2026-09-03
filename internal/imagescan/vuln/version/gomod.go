package version

import "strings"

// gomodComparator handles Go module versions.
//
// Go modules use pseudo-semver with one special rule: v0.0.0-TIMESTAMP-HASH
// pseudo-versions must compare correctly against tagged releases. The Go
// toolchain resolves this with golang.org/x/mod/semver, but that library
// uses a "v" prefix requirement and pseudo-version string comparison.
//
// For PatchFlow's matching purposes (is the installed version < the fixed
// version?) semver ordering is sufficient because:
//   - Importers record fixed_version as a tagged semver (e.g. "v1.2.3").
//   - The cataloger records the module version as-is from go.mod / build info.
//   - Pseudo-versions (v0.0.0-...) always compare less than any real tag.
//
// We strip the "v" prefix, then delegate to the existing semverCmp.
type gomodComparator struct{}

// NewGomod returns the Go module version comparator.
func NewGomod() Comparator { return &gomodComparator{} }

func (*gomodComparator) Ecosystem() string { return "golang" }

func (c *gomodComparator) Compare(a, b string) int {
	return semverCmp(stripV(normGoVer(a)), stripV(normGoVer(b)))
}

func (c *gomodComparator) IsFixedBy(installed, fixed string) bool {
	return c.Compare(installed, fixed) < 0
}

func (c *gomodComparator) InRange(version, affectedRange string) bool {
	return evalRange(c, version, affectedRange)
}

// normGoVer normalises pseudo-versions so they sort below any release.
// v0.0.0-20240101000000-abcdef012345 → v0.0.0-00000000000000-abcdef012345
// Keeping the patch segment at "0.0.0" ensures it sorts below any tagged release.
func normGoVer(v string) string {
	if strings.HasPrefix(v, "v0.0.0-") {
		return "v0.0.0-00000000000000-000000000000"
	}
	return v
}
