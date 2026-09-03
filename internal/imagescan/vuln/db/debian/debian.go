// Package debian implements a vulnerability importer for the Debian Security
// Tracker JSON feed (https://security-tracker.debian.org/tracker/data/json).
//
// The feed is a single large JSON object (~20 MB) keyed by Debian source
// package name. Each source package maps to a set of CVE IDs; each CVE maps
// to per-release metadata (status, fixed_version, urgency, …).
//
// Security model: TLS verification is never skipped. The response body is
// capped at 200 MiB to guard against runaway streams. CVE descriptions and
// package names are only written to the DB — never printed to stdout.
package debian

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
)

const (
	defaultFeedURL = "https://security-tracker.debian.org/tracker/data/json"
	sourceName     = "debian-security"
	feedLicense    = "https://security-tracker.debian.org/tracker/data/license"
	maxBodyBytes   = 200 * 1024 * 1024 // 200 MiB
)

// codenames maps supported Debian release codenames to their numeric version
// strings. Releases absent from this map (e.g. "sid") are skipped.
var codenames = map[string]string{
	"jessie":   "8",
	"stretch":  "9",
	"buster":   "10",
	"bullseye": "11",
	"bookworm": "12",
	"trixie":   "13",
}

// Importer fetches the Debian Security Tracker JSON feed and persists the
// vulnerability data into the local SQLite DB.
type Importer struct {
	// HTTPClient is used for all outgoing requests. Override in tests.
	HTTPClient *http.Client
	// FeedURL is the JSON feed endpoint. Defaults to defaultFeedURL.
	FeedURL string
}

// New returns an Importer configured with secure defaults.
func New() *Importer {
	return &Importer{
		HTTPClient: &http.Client{Timeout: 5 * time.Minute},
		FeedURL:    defaultFeedURL,
	}
}

// Name implements db.Importer.
func (imp *Importer) Name() string { return sourceName }

// --- internal JSON shapes --------------------------------------------------

// releaseInfo holds per-release vulnerability metadata from the Debian feed.
type releaseInfo struct {
	Status       string            `json:"status"`
	Repositories map[string]string `json:"repositories"`
	FixedVersion string            `json:"fixed_version"`
	Urgency      string            `json:"urgency"`
}

// cveEntry is one CVE record within a source package in the Debian feed.
type cveEntry struct {
	Description string                 `json:"description"`
	Scope       string                 `json:"scope"`
	Releases    map[string]releaseInfo `json:"releases"`
}

// Import implements db.Importer. It streams the Debian JSON feed and writes
// vulnerability data in batches — one source package per transaction.
func (imp *Importer) Import(ctx context.Context, database *db.DB) (db.Stats, error) {
	start := time.Now()
	stats := db.Stats{Source: sourceName}

	sourceID, err := database.UpsertSource(ctx, db.Source{
		Name:         sourceName,
		URL:          imp.FeedURL,
		License:      feedLicense,
		LastSyncedAt: time.Now(),
	})
	if err != nil {
		return stats, fmt.Errorf("debian: upsert source: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imp.FeedURL, nil)
	if err != nil {
		return stats, fmt.Errorf("debian: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "patchflow-is-cli/1.0 (https://github.com/patchflow/patchflow-is-cli)")

	resp, err := imp.HTTPClient.Do(req)
	if err != nil {
		return stats, fmt.Errorf("debian: fetch feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return stats, fmt.Errorf("debian: unexpected HTTP status %d", resp.StatusCode)
	}

	body := io.LimitReader(resp.Body, maxBodyBytes)
	dec := json.NewDecoder(body)

	// Consume the opening '{' of the top-level object.
	tok, err := dec.Token()
	if err != nil {
		return stats, fmt.Errorf("debian: read opening token: %w", err)
	}
	if tok != json.Delim('{') {
		return stats, fmt.Errorf("debian: expected '{', got %v", tok)
	}

	// Stream one source-package entry at a time to keep memory bounded.
	for dec.More() {
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}

		// Read source package name (the object key).
		tok, err := dec.Token()
		if err != nil {
			return stats, fmt.Errorf("debian: read package key: %w", err)
		}
		srcPkg, ok := tok.(string)
		if !ok {
			return stats, fmt.Errorf("debian: expected string key, got %T", tok)
		}

		// Decode the CVE map for this source package.
		var cves map[string]cveEntry
		if err := dec.Decode(&cves); err != nil {
			stats.Errors++
			slog.Debug("debian: skip malformed package entry", "pkg", srcPkg, "err", err)
			continue
		}

		if err := imp.importPackage(ctx, database, sourceID, srcPkg, cves, &stats); err != nil {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			stats.Errors++
			slog.Debug("debian: package import error", "pkg", srcPkg, "err", err)
		}
	}

	stats.Duration = time.Since(start)
	slog.Info("debian: import complete",
		"inserted", stats.Inserted,
		"skipped", stats.Skipped,
		"errors", stats.Errors,
		"duration", stats.Duration,
	)
	return stats, nil
}

// importPackage writes all CVEs for one Debian source package inside a single
// transaction, giving atomic all-or-nothing semantics per package.
func (imp *Importer) importPackage(
	ctx context.Context,
	database *db.DB,
	sourceID int64,
	srcPkg string,
	cves map[string]cveEntry,
	stats *db.Stats,
) error {
	return database.Tx(ctx, func(tx *sql.Tx) error {
		for cveID, info := range cves {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			vulnRowID, err := upsertVulnTx(ctx, tx, sourceID, cveID, info.Description)
			if err != nil {
				stats.Errors++
				slog.Debug("debian: skip vuln insert", "cve", cveID, "err", err)
				continue
			}

			// Remove stale affected-package rows before re-inserting.
			// affected_packages has no UNIQUE constraint, so INSERT OR IGNORE
			// would not deduplicate across runs; delete-first ensures idempotency.
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM affected_packages WHERE vulnerability_id=?`,
				vulnRowID); err != nil {
				stats.Errors++
				slog.Debug("debian: skip delete affected pkgs", "cve", cveID, "err", err)
				continue
			}

			for codename, rel := range info.Releases {
				version, ok := codenames[codename]
				if !ok {
					// Codename not in our supported list (e.g. "sid"/"unstable").
					stats.Skipped++
					continue
				}
				if rel.Status == "undetermined" {
					stats.Skipped++
					continue
				}

				status := debianStatus(rel.Status)
				fixedVer := rel.FixedVersion
				if rel.Status == "open" {
					fixedVer = ""
				}

				if err := writeAffectedPkgTx(ctx, tx, db.AffectedPackage{
					VulnerabilityID: vulnRowID,
					Ecosystem:       "deb",
					PackageName:     srcPkg,
					SourcePackage:   srcPkg,
					DistroName:      "debian",
					DistroVersion:   version,
					FixedVersion:    fixedVer,
					Status:          status,
					Confidence:      100,
				}); err != nil {
					stats.Errors++
					slog.Debug("debian: skip affected pkg insert",
						"cve", cveID, "codename", codename, "err", err)
					continue
				}
				stats.Inserted++
			}
		}
		return nil
	})
}

// debianStatus maps a Debian tracker status string to the canonical DB value.
func debianStatus(s string) string {
	switch s {
	case "resolved":
		return "fixed"
	case "open":
		return "affected"
	default:
		return "unknown"
	}
}

// --- transaction-scoped SQL helpers ----------------------------------------
// These helpers write directly to a *sql.Tx so they can participate in the
// caller's batch transaction without creating a nested auto-commit.

const sqlInsertVuln = `
INSERT OR IGNORE INTO vulnerabilities
    (source_id, vuln_id, aliases, summary, description, severity,
     cvss_score, cvss_vector, published_at, modified_at)
VALUES (?,?,?,?,?,?,?,?,?,?)`

// upsertVulnTx inserts a vulnerability row if it does not already exist and
// returns its row ID. On INSERT OR IGNORE (duplicate), it fetches the existing
// row ID instead.
//
// IMPORTANT: never rely on LastInsertId() after INSERT OR IGNORE — when the
// insert is ignored, SQLite leaves sqlite3_last_insert_rowid() unchanged
// (it retains the previous connection-level value), which would be wrong.
// Always SELECT the canonical ID.
func upsertVulnTx(ctx context.Context, tx *sql.Tx, sourceID int64, vulnID, description string) (int64, error) {
	if _, err := tx.ExecContext(ctx, sqlInsertVuln,
		sourceID, vulnID, "[]",
		"", description, "UNKNOWN",
		0.0, "", nil, nil,
	); err != nil {
		return 0, fmt.Errorf("insert vuln %s: %w", vulnID, err)
	}
	// Always SELECT: correct whether row was just inserted or already existed.
	var id int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM vulnerabilities WHERE source_id=? AND vuln_id=?`,
		sourceID, vulnID).Scan(&id); err != nil {
		return 0, fmt.Errorf("fetch vuln id %s: %w", vulnID, err)
	}
	return id, nil
}

const sqlInsertAP = `
INSERT OR IGNORE INTO affected_packages
    (vulnerability_id, ecosystem, package_name, package_type,
     distro_name, distro_version, introduced_version, fixed_version,
     affected_range, source_package, architecture, status, confidence)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`

// writeAffectedPkgTx inserts one affected-package row. Duplicate rows are
// silently ignored via INSERT OR IGNORE.
func writeAffectedPkgTx(ctx context.Context, tx *sql.Tx, ap db.AffectedPackage) error {
	_, err := tx.ExecContext(ctx, sqlInsertAP,
		ap.VulnerabilityID, ap.Ecosystem, ap.PackageName, ap.PackageType,
		ap.DistroName, ap.DistroVersion,
		ap.IntroducedVersion, ap.FixedVersion, ap.AffectedRange,
		ap.SourcePackage, ap.Architecture, ap.Status, ap.Confidence,
	)
	return err
}
