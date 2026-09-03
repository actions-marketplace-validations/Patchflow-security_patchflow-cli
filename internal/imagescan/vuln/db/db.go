package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	_ "modernc.org/sqlite" // registers "sqlite" driver
)

const driverName = "sqlite"

// pragmasDSN appends performance and safety pragmas to the DSN.
// WAL mode gives readers non-blocking access while the writer commits;
// FOREIGN_KEYS enforces referential integrity at the SQL layer.
func pragmasDSN(path string) string {
	return path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(10000)"
}

// DB wraps a *sql.DB with schema migration and domain-level helpers.
// Open opens read-write; OpenReadOnly opens read-only for the scanner CLI.
type DB struct {
	sql *sql.DB
	ro  bool
}

// Open opens (or creates) the SQLite DB at path in read-write mode, runs
// migrations, and returns the handle. Callers must call Close.
func Open(path string) (*DB, error) {
	conn, err := sql.Open(driverName, pragmasDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open vuln db %s: %w", path, err)
	}
	// Single writer; multiple readers via WAL.
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(0)

	d := &DB{sql: conn}
	if err := d.migrate(context.Background()); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("migrate vuln db: %w", err)
	}
	return d, nil
}

// OpenReadOnly opens an existing SQLite DB at path in read-only mode.
// It does not run migrations; the DB must already be at the current schema
// version. Returns ErrDBNotFound if path does not exist.
func OpenReadOnly(path string) (*DB, error) {
	// file: URI with immutable flag prevents accidental writes.
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)", path)
	conn, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open vuln db (ro) %s: %w", path, err)
	}
	conn.SetMaxOpenConns(4)
	conn.SetMaxIdleConns(4)
	if err := conn.PingContext(context.Background()); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %s", ErrDBNotFound, path)
	}
	return &DB{sql: conn, ro: true}, nil
}

// Close closes the underlying connection.
func (d *DB) Close() error { return d.sql.Close() }

// --- Migration -----------------------------------------------------------

// migrate applies the DDL schema and updates the schema_version meta key.
// It is idempotent: safe to run on an already-migrated DB.
func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.sql.ExecContext(ctx, createTablesSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return d.setMeta(ctx, "schema_version", strconv.Itoa(schemaVersion))
}

// --- Meta helpers ---------------------------------------------------------

func (d *DB) setMeta(ctx context.Context, key, value string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT INTO vuln_db_meta(key,value) VALUES(?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return err
}

func (d *DB) getMeta(ctx context.Context, key string) (string, error) {
	var v string
	err := d.sql.QueryRowContext(ctx,
		`SELECT value FROM vuln_db_meta WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SchemaVersion returns the schema_version stored in the DB, or 0.
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	s, err := d.getMeta(ctx, "schema_version")
	if err != nil || s == "" {
		return 0, err
	}
	v, _ := strconv.Atoi(s)
	return v, nil
}

// --- Source management ---------------------------------------------------

// UpsertSource inserts or updates a source row and returns its ID.
// We always SELECT after the upsert because SQLite's ON CONFLICT DO UPDATE
// may increment the internal AUTOINCREMENT counter before resolving the
// conflict, making LastInsertId() return a phantom new rowid rather than
// the existing row's ID. The SELECT is the only reliable way to get it.
func (d *DB) UpsertSource(ctx context.Context, s Source) (int64, error) {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO vulnerability_sources(name, url, license, last_synced_at, record_count, checksum)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
			url            = excluded.url,
			license        = excluded.license,
			last_synced_at = excluded.last_synced_at,
			record_count   = excluded.record_count,
			checksum       = excluded.checksum`,
		s.Name, s.URL, s.License,
		s.LastSyncedAt.UTC().Format(time.RFC3339),
		s.RecordCount, s.Checksum,
	)
	if err != nil {
		return 0, fmt.Errorf("upsert source %s: %w", s.Name, err)
	}
	// Always SELECT to get the authoritative ID — never trust LastInsertId
	// after ON CONFLICT DO UPDATE (SQLite may return a phantom new rowid).
	var id int64
	err = d.sql.QueryRowContext(ctx,
		`SELECT id FROM vulnerability_sources WHERE name=?`, s.Name).Scan(&id)
	return id, err
}

// ListSources returns all sources ordered by name.
func (d *DB) ListSources(ctx context.Context) ([]Source, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT id, name, url, license, last_synced_at, record_count, checksum
		FROM vulnerability_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var s Source
		var ts sql.NullString
		if err := rows.Scan(&s.ID, &s.Name, &s.URL, &s.License, &ts,
			&s.RecordCount, &s.Checksum); err != nil {
			return nil, err
		}
		if ts.Valid && ts.String != "" {
			s.LastSyncedAt, _ = time.Parse(time.RFC3339, ts.String)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// --- Vulnerability writes -------------------------------------------------

// InsertVulnerability inserts a vulnerability row and returns its ID.
// Duplicate (source_id, vuln_id) pairs are ignored. We always SELECT the
// authoritative ID afterwards — see UpsertSource for the reason.
func (d *DB) InsertVulnerability(ctx context.Context, v Vulnerability) (int64, error) {
	aliases, _ := json.Marshal(v.Aliases)
	_, err := d.sql.ExecContext(ctx, `
		INSERT OR IGNORE INTO vulnerabilities
			(source_id, vuln_id, aliases, summary, description, severity,
			 cvss_score, cvss_vector, published_at, modified_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		v.SourceID, v.VulnID, string(aliases),
		v.Summary, v.Description, v.Severity,
		v.CVSSScore, v.CVSSVector,
		nullTime(v.PublishedAt), nullTime(v.ModifiedAt),
	)
	if err != nil {
		return 0, fmt.Errorf("insert vuln %s: %w", v.VulnID, err)
	}
	var id int64
	err = d.sql.QueryRowContext(ctx,
		`SELECT id FROM vulnerabilities WHERE source_id=? AND vuln_id=?`,
		v.SourceID, v.VulnID).Scan(&id)
	return id, err
}

// InsertAffectedPackage inserts one affected-package row. Callers hold a
// transaction; duplicate rows within the same source batch are acceptable
// and skipped via INSERT OR IGNORE.
func (d *DB) InsertAffectedPackage(ctx context.Context, ap AffectedPackage) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT OR IGNORE INTO affected_packages
			(vulnerability_id, ecosystem, package_name, package_type,
			 distro_name, distro_version, introduced_version, fixed_version,
			 affected_range, source_package, architecture, status, confidence)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ap.VulnerabilityID, ap.Ecosystem, ap.PackageName, ap.PackageType,
		ap.DistroName, ap.DistroVersion,
		ap.IntroducedVersion, ap.FixedVersion, ap.AffectedRange,
		ap.SourcePackage, ap.Architecture, ap.Status, ap.Confidence,
	)
	return err
}

// Tx runs fn inside a serializable write transaction. If fn returns an error
// the transaction is rolled back; otherwise committed.
func (d *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ExecTx is a convenience wrapper for single-statement transactions.
func (d *DB) ExecTx(ctx context.Context, query string, args ...interface{}) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query, args...)
		return err
	})
}

// --- Vulnerability reads (used by matcher) --------------------------------

// AffectedRow is the minimal shape the matcher needs from one query hit.
type AffectedRow struct {
	VulnID          string
	Aliases         []string
	Summary         string
	Severity        string
	CVSSScore       float64
	FixedVersion    string
	AffectedRange   string
	IntroducedVersion string
	SourcePackage   string
	Confidence      int
	Status          string
	SourceName      string // from vulnerability_sources
}

// QueryByPackage returns all affected rows for a given ecosystem+name,
// optionally filtered by distro name+version. This is the primary lookup
// path for the vendor-exact and OSV-exact match tiers.
func (d *DB) QueryByPackage(ctx context.Context, ecosystem, name, distroName, distroVersion string) ([]AffectedRow, error) {
	// Vendor-exact: distro_name+version must match OR be empty (lang pkgs).
	rows, err := d.sql.QueryContext(ctx, `
		SELECT
			v.vuln_id, v.aliases, v.summary, v.severity, v.cvss_score,
			ap.fixed_version, ap.affected_range, ap.introduced_version,
			ap.source_package, ap.confidence, ap.status,
			s.name
		FROM affected_packages ap
		JOIN vulnerabilities v ON v.id = ap.vulnerability_id
		JOIN vulnerability_sources s ON s.id = v.source_id
		WHERE ap.ecosystem     = ?
		  AND ap.package_name  = ?
		  AND (ap.distro_name  = '' OR ap.distro_name  = ?)
		  AND (ap.distro_version = '' OR ap.distro_version = ?)
		ORDER BY ap.confidence DESC, v.cvss_score DESC`,
		ecosystem, name, distroName, distroVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("query by package: %w", err)
	}
	defer rows.Close()
	return scanAffectedRows(rows)
}

// QueryBySourcePackage looks up by the Debian/Ubuntu source package name.
// This is the source-package match tier (confidence 85).
func (d *DB) QueryBySourcePackage(ctx context.Context, srcPkg, distroName, distroVersion string) ([]AffectedRow, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT
			v.vuln_id, v.aliases, v.summary, v.severity, v.cvss_score,
			ap.fixed_version, ap.affected_range, ap.introduced_version,
			ap.source_package, ap.confidence, ap.status,
			s.name
		FROM affected_packages ap
		JOIN vulnerabilities v ON v.id = ap.vulnerability_id
		JOIN vulnerability_sources s ON s.id = v.source_id
		WHERE ap.source_package  = ?
		  AND (ap.distro_name    = '' OR ap.distro_name    = ?)
		  AND (ap.distro_version = '' OR ap.distro_version = ?)
		ORDER BY ap.confidence DESC, v.cvss_score DESC`,
		srcPkg, distroName, distroVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("query by source pkg: %w", err)
	}
	defer rows.Close()
	return scanAffectedRows(rows)
}

// QueryByVulnID returns all affected-package rows for a given vuln ID.
// Used by the explain subcommand.
func (d *DB) QueryByVulnID(ctx context.Context, vulnID string) ([]AffectedRow, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT
			v.vuln_id, v.aliases, v.summary, v.severity, v.cvss_score,
			ap.fixed_version, ap.affected_range, ap.introduced_version,
			ap.source_package, ap.confidence, ap.status,
			s.name
		FROM affected_packages ap
		JOIN vulnerabilities v ON v.id = ap.vulnerability_id
		JOIN vulnerability_sources s ON s.id = v.source_id
		WHERE v.vuln_id = ?
		   OR v.aliases LIKE ?
		ORDER BY ap.confidence DESC`,
		vulnID, "%"+vulnID+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAffectedRows(rows)
}

// VulnDBVersion returns a human-readable version string (last sync timestamp
// + total record count) for embedding in scan results.
func (d *DB) VulnDBVersion(ctx context.Context) (string, error) {
	var count int64
	var latest sql.NullString
	err := d.sql.QueryRowContext(ctx, `
		SELECT COUNT(*), MAX(last_synced_at)
		FROM vulnerability_sources`).Scan(&count, &latest)
	if err != nil {
		return "unknown", nil
	}
	ts := "never"
	if latest.Valid && latest.String != "" {
		ts = latest.String
	}
	return fmt.Sprintf("records=%d synced=%s", count, ts), nil
}

// --- internal helpers -----------------------------------------------------

func scanAffectedRows(rows *sql.Rows) ([]AffectedRow, error) {
	var out []AffectedRow
	for rows.Next() {
		var r AffectedRow
		var aliasesJSON string
		if err := rows.Scan(
			&r.VulnID, &aliasesJSON, &r.Summary, &r.Severity, &r.CVSSScore,
			&r.FixedVersion, &r.AffectedRange, &r.IntroducedVersion,
			&r.SourcePackage, &r.Confidence, &r.Status,
			&r.SourceName,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(aliasesJSON), &r.Aliases)
		out = append(out, r)
	}
	return out, rows.Err()
}

// nullTime returns the RFC3339 string for t, or an empty string for zero time
// (stored as SQL NULL via empty string trigger in the schema).
func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}
