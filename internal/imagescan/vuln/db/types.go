// Package db provides the normalized, embedded SQLite vulnerability database
// for the PatchFlow Image Scanner. It owns the schema, the migration runner,
// and the read/write helpers used by importers and the matching engine.
//
// The database is a local file written once by pf-db-builder and opened
// read-only by the scanner CLI. The schema is relational (advisory × package
// × distro) because distro-aware vulnerability matching requires JOINs and
// range queries that a flat key-value store cannot express cleanly.
//
// All SQL is executed through database/sql; no ORM. Every query is
// parameterised — no string concatenation of user-supplied values.
package db

import "time"

// Source is one advisory feed. Each importer registers itself here so the
// CLI can show sync timestamps and provenance per record.
type Source struct {
	ID           int64
	Name         string    // "osv", "alpine-secdb", "debian-security", "ubuntu-oval", "nvd"
	URL          string
	License      string
	LastSyncedAt time.Time
	RecordCount  int64
	Checksum     string // hex SHA-256 of the last downloaded feed blob
}

// Vulnerability is one advisory record from a single source. Multiple sources
// may describe the same CVE; the matcher deduplicates by highest confidence.
type Vulnerability struct {
	ID          int64
	SourceID    int64
	VulnID      string    // "CVE-2024-xxxx", "GHSA-xxxx", "ALPINE-2024-xxxx"
	Aliases     []string  // Other IDs for the same advisory (stored as JSON)
	Summary     string
	Description string
	Severity    string    // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	CVSSScore   float64
	CVSSVector  string
	PublishedAt time.Time
	ModifiedAt  time.Time
}

// AffectedPackage is one (package, range, distro) tuple within a Vulnerability.
// A single advisory may have many affected-package rows — one per ecosystem,
// distro release, or architecture variant.
type AffectedPackage struct {
	ID               int64
	VulnerabilityID  int64
	Ecosystem        string // "alpine", "deb", "npm", "pypi", "maven", "golang", "cargo"
	PackageName      string
	PackageType      string // "os", "npm", "pypi", ...
	DistroName       string // "alpine", "debian", "ubuntu", "" for lang pkgs
	DistroVersion    string // "3.20", "12", "22.04", ""
	IntroducedVersion string
	FixedVersion     string
	AffectedRange    string // raw range expression (ecosystem-specific syntax)
	SourcePackage    string // Debian source package name
	Architecture     string // "x86_64", "amd64", "" (arch-independent)
	Status           string // "affected", "fixed", "not-affected", "unknown"
	Confidence       int    // 0-100, see matcher confidence tiers
}

// Stats is returned by each importer summarising what was written.
type Stats struct {
	Source        string
	Inserted      int64
	Updated       int64
	Skipped       int64
	Errors        int64
	Duration      time.Duration
}
