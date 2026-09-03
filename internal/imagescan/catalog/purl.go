// Package catalog provides a PURL (Package URL) construction helper that
// handles the per-ecosystem normalisation rules from the Package URL spec
// (https://github.com/package-url/purl-spec).
//
// PURLs are the canonical cross-ecosystem package identifier used by the
// matcher and SBOM exporters. Each cataloger calls PURL() with its ecosystem
// slug, the package name (and group for Maven), and the version.
package catalog

import (
	"fmt"
	"net/url"
	"strings"
)

// PURL builds a canonical Package URL string for the given ecosystem.
//
// Ecosystem-specific rules applied:
//   - npm: scoped names like "@scope/name" are preserved as-is; the name is
//     NOT lowercased (npm names are case-sensitive in the registry but
//     conventionally lowercase).
//   - pypi: the name is normalised per PEP 503 — lowercase, and runs of
//     [-_.] are collapsed to a single "-".
//   - maven: the groupID is required and placed before the artifactID,
//     separated by "/".
//   - golang: the module path may contain "/" and is preserved as-is.
//   - cargo: names are lowercased.
//   - alpine/deb/rpm: OS package names are used verbatim.
//
// The version is URL-encoded so characters like "+" in Maven versions
// (e.g. "1.2.0+deb12u1") are preserved correctly.
func PURL(ecosystem, name, version string) string {
	return PURLWithGroup(ecosystem, "", name, version)
}

// PURLWithGroup builds a PURL for ecosystems that require a group/namespace
// (currently only Maven). For all other ecosystems, pass group="" and the
// plain PURL() helper is used.
func PURLWithGroup(ecosystem, group, name, version string) string {
	ecosystem = strings.ToLower(ecosystem)
	name = normaliseName(ecosystem, name)

	var path string
	switch ecosystem {
	case "maven":
		// pkg:maven/{group}/{artifact}@{version}
		path = strings.TrimPrefix(group, "/") + "/" + name
	case "npm":
		// npm scoped names already contain the "/" — keep as-is.
		path = name
	case "golang":
		// Go module paths contain "/" — keep as-is.
		path = name
	default:
		path = name
	}

	purl := "pkg:" + ecosystem + "/" + path
	if version != "" {
		purl += "@" + urlEncode(version)
	}
	return purl
}

// normaliseName applies the per-ecosystem name normalisation rules.
func normaliseName(ecosystem, name string) string {
	switch ecosystem {
	case "pypi":
		return normalisePyPI(name)
	case "cargo":
		return strings.ToLower(name)
	case "npm":
		// npm names are conventionally lowercase but the registry treats them
		// as case-sensitive. We preserve the original case to avoid mismatches
		// with advisory feeds that may use either form.
		return name
	default:
		return name
	}
}

// normalisePyPI implements PEP 503 name normalisation: lowercase and collapse
// runs of [-_.] into a single "-".
func normalisePyPI(name string) string {
	s := strings.ToLower(name)
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch r {
		case '-', '_', '.':
			if !prevDash {
				b.WriteRune('-')
				prevDash = true
			}
		default:
			b.WriteRune(r)
			prevDash = false
		}
	}
	return b.String()
}

// urlEncode wraps url.PathEscape but falls back to the raw string if encoding
// fails (it never should for valid versions, but we never want a PURL build
// to panic).
func urlEncode(s string) string {
	enc := url.PathEscape(s)
	if enc == "" && s != "" {
		return s
	}
	return enc
}

// MavenPURL is a convenience wrapper for Maven PURLs, which require a group
// and artifact. Equivalent to PURLWithGroup("maven", group, artifact, version).
func MavenPURL(group, artifact, version string) string {
	return PURLWithGroup("maven", group, artifact, version)
}

// formatPURLf is a debug-only helper kept for future use; not exported.
func formatPURLf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

var _ = formatPURLf // suppress unused warning
