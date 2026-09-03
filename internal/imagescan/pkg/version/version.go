// Package version exposes build-time metadata injected via -ldflags.
//
// Version, Commit, and Date are overridable at build time so that released
// binaries and container images can self-report their provenance. This
// mirrors the convention used across the PatchFlow CLI family.
package version

import "fmt"

var (
	// Version is the semantic version of the binary. Defaults to "dev"
	// for local builds; overridden by goreleaser/Makefile ldflags.
	Version = "0.1.0"

	// Commit is the short git SHA the binary was built from.
	Commit = "dev"

	// Date is the UTC build timestamp in RFC3339 form.
	Date = "unknown"
)

// BuildInfo returns a single-line, human-readable build banner.
func BuildInfo() string {
	return fmt.Sprintf("patchflow-image-scanner version %s (commit: %s, built: %s)", Version, Commit, Date)
}

// Short returns just the version string (e.g. "0.1.0") for embedding in
// scan/SBOM metadata without the full build banner.
func Short() string {
	return Version
}
