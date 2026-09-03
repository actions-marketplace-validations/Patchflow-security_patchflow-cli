package version_test

import (
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/version"
)

// --- APK ------------------------------------------------------------------

func TestAPKCompare(t *testing.T) {
	c := version.NewAPK()
	cases := []struct {
		a, b string
		want int
	}{
		{"3.18.0-r0", "3.18.0-r1", -1}, // revision bump
		{"3.18.0-r1", "3.18.0-r0", 1},
		{"3.18.0-r0", "3.18.0-r0", 0},  // equal
		{"3.18.0", "3.18.1", -1},        // patch bump
		{"3.19.0-r0", "3.18.9-r9", 1},  // minor bump
		{"1.2.3_pre1", "1.2.3", -1},     // pre-release < release
		{"1.2.3_rc1", "1.2.3", -1},
		{"1.2.3_p1", "1.2.3", 1},        // patch > release
		{"1.2.3_alpha1", "1.2.3_beta1", -1},
		{"2:1.0-r0", "1:99.0-r0", 1},   // epoch wins
		{"5.3.2-r1", "5.3.2-r0", 1},
	}
	for _, tc := range cases {
		got := sign(c.Compare(tc.a, tc.b))
		if got != tc.want {
			t.Errorf("APK.Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestAPKIsFixedBy(t *testing.T) {
	c := version.NewAPK()
	if !c.IsFixedBy("3.20.3-r0", "3.20.4-r0") {
		t.Error("3.20.3-r0 should be fixed by 3.20.4-r0")
	}
	if c.IsFixedBy("3.20.4-r0", "3.20.4-r0") {
		t.Error("same version should not be fixed")
	}
	if c.IsFixedBy("3.20.5-r0", "3.20.4-r0") {
		t.Error("newer version should not be fixed by older fixed version")
	}
}

func TestAPKInRange(t *testing.T) {
	c := version.NewAPK()
	cases := []struct {
		ver, rng string
		want     bool
	}{
		{"3.20.3-r0", "< 3.20.4-r0", true},
		{"3.20.4-r0", "< 3.20.4-r0", false},
		{"3.20.5-r0", ">= 3.20.3-r0, < 3.20.6-r0", true},
		{"3.20.2-r0", ">= 3.20.3-r0, < 3.20.6-r0", false},
		{"1.0.0-r0", "", true}, // empty range = always affected
	}
	for _, tc := range cases {
		got := c.InRange(tc.ver, tc.rng)
		if got != tc.want {
			t.Errorf("APK.InRange(%q, %q) = %v, want %v", tc.ver, tc.rng, got, tc.want)
		}
	}
}

// --- dpkg -----------------------------------------------------------------

func TestDpkgCompare(t *testing.T) {
	c := version.NewDpkg()
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0-1", "1.0-2", -1},             // revision bump
		{"1.0-2", "1.0-1", 1},
		{"1.0-1", "1.0-1", 0},
		{"1.2.3", "1.2.4", -1},             // no revision
		{"2:1.0-1", "1:99.0-1", 1},         // epoch wins
		{"1.0~rc1", "1.0", -1},             // tilde < empty
		{"1.0", "1.0~rc1", 1},
		{"1.0+deb12u1", "1.0", 1},          // backport > upstream
		{"1.0-1+deb12u2", "1.0-1+deb12u1", 1},
		{"3.1.4-1+deb12u4", "3.1.4-1", 1}, // Debian backport patch
	}
	for _, tc := range cases {
		got := sign(c.Compare(tc.a, tc.b))
		if got != tc.want {
			t.Errorf("dpkg.Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDpkgIsFixedBy(t *testing.T) {
	c := version.NewDpkg()
	if !c.IsFixedBy("3.1.4-1", "3.1.4-1+deb12u4") {
		t.Error("3.1.4-1 should be fixed by the backport version")
	}
}

// --- semver (npm / cargo) -------------------------------------------------

func TestSemverCompare(t *testing.T) {
	c := version.NewSemver("npm")
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.4", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0-alpha", "1.0.0", -1},      // pre-release < release
		{"1.0.0-alpha.1", "1.0.0-alpha.2", -1},
		{"1.0.0-alpha.1", "1.0.0-1", 1},   // alpha > numeric per SemVer §11.4
		{"v1.2.3", "1.2.3", 0},            // v prefix stripped
	}
	for _, tc := range cases {
		got := sign(c.Compare(tc.a, tc.b))
		if got != tc.want {
			t.Errorf("semver.Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// --- PEP 440 --------------------------------------------------------------

func TestPEP440Compare(t *testing.T) {
	c := version.NewPEP440()
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.1", -1},
		{"1.0.0a1", "1.0.0", -1},    // alpha < release
		{"1.0.0b1", "1.0.0rc1", -1}, // beta < rc
		{"1.0.0rc1", "1.0.0", -1},   // rc < release
		{"1.0.0.post1", "1.0.0", 1}, // post > release
		{"1.0.0.dev1", "1.0.0a1", -1}, // dev < alpha
		{"1!0.0.0", "999.0.0", 1},   // epoch wins
	}
	for _, tc := range cases {
		got := sign(c.Compare(tc.a, tc.b))
		if got != tc.want {
			t.Errorf("pep440.Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// --- Maven ----------------------------------------------------------------

func TestMavenCompare(t *testing.T) {
	c := version.NewMaven()
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.1", -1},
		{"2.0-SNAPSHOT", "2.0", -1},      // snapshot < release
		{"1.0-alpha1", "1.0-beta1", -1},
		{"1.0-rc1", "1.0", -1},
		{"1.0-sp1", "1.0", 1},            // sp > release
		{"1.0.0.0", "1.0", 0},            // trailing zeros equal
	}
	for _, tc := range cases {
		got := sign(c.Compare(tc.a, tc.b))
		if got != tc.want {
			t.Errorf("maven.Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// --- Registry -------------------------------------------------------------

func TestRegistry(t *testing.T) {
	r := version.NewRegistry()
	ecosystems := []string{"alpine", "deb", "npm", "cargo", "pypi", "maven", "golang"}
	for _, eco := range ecosystems {
		c := r.ForEcosystem(eco)
		if c == nil {
			t.Errorf("no comparator for ecosystem %q", eco)
		}
		if c.Ecosystem() != eco {
			t.Errorf("comparator ecosystem = %q, want %q", c.Ecosystem(), eco)
		}
	}
	// Unknown falls back to semver.
	c := r.ForEcosystem("unknown-eco")
	if c == nil {
		t.Error("ForEcosystem should never return nil")
	}
}

// --- Range evaluation -----------------------------------------------------

func TestRangeOperators(t *testing.T) {
	c := version.NewSemver("test")
	cases := []struct {
		ver, rng string
		want     bool
	}{
		{"1.0.0", "< 2.0.0", true},
		{"2.0.0", "< 2.0.0", false},
		{"2.0.0", "<= 2.0.0", true},
		{"1.5.0", ">= 1.0.0, < 2.0.0", true},
		{"0.9.0", ">= 1.0.0, < 2.0.0", false},
		{"2.0.0", ">= 1.0.0, < 2.0.0", false},
		{"1.0.0", "!= 2.0.0", true},
		{"2.0.0", "!= 2.0.0", false},
		{"1.0.0", "", true},            // empty = always in range
		{"1.5.0", "[1.0.0,2.0.0)", true},
		{"2.0.0", "[1.0.0,2.0.0)", false},
		{"1.0.0", "[1.0.0,2.0.0)", true},
		{"0.9.0", "(1.0.0,2.0.0)", false},
	}
	for _, tc := range cases {
		got := c.InRange(tc.ver, tc.rng)
		if got != tc.want {
			t.Errorf("InRange(%q, %q) = %v, want %v", tc.ver, tc.rng, got, tc.want)
		}
	}
}

// --- helpers --------------------------------------------------------------

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
