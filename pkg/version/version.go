package version

import (
	"fmt"
	"runtime"
)

// Build metadata injected via ldflags during release builds.
var (
	Version = "0.1.6"
	Commit  = "dev"
	Date    = "unknown"
)

// Static metadata — these are constants, not build-injected.
const (
	// RulesetVersion identifies the embedded rule collection.
	// Increment when rules are added, removed, or semantically changed.
	RulesetVersion = "framework-rules-v1"

	// SchemaVersion is the config schema version for .patchflow/rules.yaml.
	SchemaVersion = "1.0"

	// SARIFVersion is the SARIF output schema version.
	SARIFVersion = "2.1.0"

	// OSVDBVersion is the OSV database snapshot date (updated by `cache update`).
	// This is a placeholder — the actual version is determined at runtime
	// from the local DB metadata.
	OSVDBVersion = "runtime"
)

// BuildInfo returns a human-readable version string.
func BuildInfo() string {
	return fmt.Sprintf("patchflow version %s (commit: %s, built: %s)", Version, Commit, Date)
}

// Short returns just the version string (e.g. "0.1.1") for embedding in scan
// metadata without the full build info banner.
func Short() string {
	return Version
}

// GoVersion returns the Go runtime version used to build the binary.
func GoVersion() string {
	return runtime.Version()
}

// FullInfo returns all version metadata as a map for JSON output.
func FullInfo() map[string]string {
	return map[string]string{
		"version":          Version,
		"commit":           Commit,
		"built_at":         Date,
		"go_version":       GoVersion(),
		"ruleset_version":  RulesetVersion,
		"schema_version":   SchemaVersion,
		"sarif_version":    SARIFVersion,
		"osv_db_version":   OSVDBVersion,
	}
}
