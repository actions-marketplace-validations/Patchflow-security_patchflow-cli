package db

// schema contains the complete DDL for the vulnerability database.
// Each statement is idempotent (IF NOT EXISTS) so the migration runner
// can re-run on an existing DB without errors.
//
// Schema version is bumped in migrateSchema() below whenever a breaking
// change is made. Forward-only migrations are appended as extra steps.
const schemaVersion = 2

const createTablesSQL = `
-- Schema metadata: single-row key-value store for schema version and
-- build-time information.
CREATE TABLE IF NOT EXISTS vuln_db_meta (
    key   TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (key)
);

-- One row per advisory feed (source of truth for provenance).
CREATE TABLE IF NOT EXISTS vulnerability_sources (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE,
    url           TEXT    NOT NULL DEFAULT '',
    license       TEXT    NOT NULL DEFAULT '',
    last_synced_at DATETIME,
    record_count  INTEGER NOT NULL DEFAULT 0,
    checksum      TEXT    NOT NULL DEFAULT ''
);

-- One row per advisory. Multiple sources may describe the same CVE; the
-- matcher deduplicates by highest confidence at query time.
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id    INTEGER NOT NULL REFERENCES vulnerability_sources(id) ON DELETE CASCADE,
    vuln_id      TEXT    NOT NULL,
    aliases      TEXT    NOT NULL DEFAULT '[]',  -- JSON array of alias IDs
    summary      TEXT    NOT NULL DEFAULT '',
    description  TEXT    NOT NULL DEFAULT '',
    severity     TEXT    NOT NULL DEFAULT 'UNKNOWN',
    cvss_score   REAL    NOT NULL DEFAULT 0,
    cvss_vector  TEXT    NOT NULL DEFAULT '',
    published_at DATETIME,
    modified_at  DATETIME,
    UNIQUE (source_id, vuln_id)
);

CREATE INDEX IF NOT EXISTS idx_vulns_vuln_id ON vulnerabilities (vuln_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities (severity);

-- One row per (package, version-range, distro) tuple within an advisory.
-- This is the hot table — matcher queries hit it on every scan.
CREATE TABLE IF NOT EXISTS affected_packages (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id    INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    ecosystem           TEXT    NOT NULL DEFAULT '',
    package_name        TEXT    NOT NULL,
    package_type        TEXT    NOT NULL DEFAULT '',
    distro_name         TEXT    NOT NULL DEFAULT '',
    distro_version      TEXT    NOT NULL DEFAULT '',
    introduced_version  TEXT    NOT NULL DEFAULT '',
    fixed_version       TEXT    NOT NULL DEFAULT '',
    affected_range      TEXT    NOT NULL DEFAULT '',
    source_package      TEXT    NOT NULL DEFAULT '',
    architecture        TEXT    NOT NULL DEFAULT '',
    status              TEXT    NOT NULL DEFAULT 'affected',
    confidence          INTEGER NOT NULL DEFAULT 95
);

-- Primary hot path: look up by (ecosystem, name, distro_name, distro_version).
CREATE INDEX IF NOT EXISTS idx_ap_lookup
    ON affected_packages (ecosystem, package_name, distro_name, distro_version);

-- Secondary: source-package lookup for Debian/Ubuntu vendor matching.
CREATE INDEX IF NOT EXISTS idx_ap_source_pkg
    ON affected_packages (source_package, distro_name, distro_version)
    WHERE source_package != '';

-- Tertiary: all rows for a vulnerability (used by explain command).
CREATE INDEX IF NOT EXISTS idx_ap_vuln_id
    ON affected_packages (vulnerability_id);
`
