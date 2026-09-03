// Package ubuntu implements a vulnerability importer for Ubuntu OVAL feeds.
//
// Ubuntu publishes one bzip2-compressed OVAL XML file per LTS release at:
//
//	https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.<codename>.cve.oval.xml.bz2
//
// Each OVAL definition represents one CVE. The criteria section lists binary
// packages and their minimum fixed versions.
//
// Security model: TLS verification is never skipped. Response bodies are
// capped at 200 MiB. CVE data is written to the DB only — never printed.
package ubuntu

import (
	"compress/bzip2"
	"context"
	"database/sql"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
)

const (
	sourceName   = "ubuntu-oval"
	maxBodyBytes = 200 * 1024 * 1024 // 200 MiB
)

// defaultReleases lists the LTS releases imported by default.
var defaultReleases = []Release{
	{
		Codename: "focal",
		Version:  "20.04",
		URL:      "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.focal.cve.oval.xml.bz2",
	},
	{
		Codename: "jammy",
		Version:  "22.04",
		URL:      "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.jammy.cve.oval.xml.bz2",
	},
	{
		Codename: "noble",
		Version:  "24.04",
		URL:      "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.noble.cve.oval.xml.bz2",
	},
}

// Release describes one Ubuntu LTS release and its OVAL feed URL.
type Release struct {
	Codename string // "focal", "jammy", "noble"
	Version  string // "20.04", "22.04", "24.04"
	URL      string
}

// Importer fetches Ubuntu OVAL feeds and persists vulnerability data into the
// local SQLite DB.
type Importer struct {
	// HTTPClient is used for all outgoing requests. Override in tests.
	HTTPClient *http.Client
	// Releases is the list of Ubuntu LTS releases to import.
	Releases []Release
}

// New returns an Importer configured with secure defaults and all three
// supported LTS releases (focal, jammy, noble).
func New() *Importer {
	return &Importer{
		HTTPClient: &http.Client{Timeout: 10 * time.Minute},
		Releases:   defaultReleases,
	}
}

// Name implements db.Importer.
func (imp *Importer) Name() string { return sourceName }

// --- OVAL XML types --------------------------------------------------------
// Go's encoding/xml matches struct tags by local name only when no namespace
// is specified, so these types work for OVAL files with or without a default
// namespace declaration.

type ovalDefinitions struct {
	XMLName     xml.Name     `xml:"oval_definitions"`
	Definitions []definition `xml:"definitions>definition"`
}

type definition struct {
	ID       string   `xml:"id,attr"`
	Class    string   `xml:"class,attr"`
	Metadata metadata `xml:"metadata"`
	Criteria criteria `xml:"criteria"`
}

type metadata struct {
	Title    string   `xml:"title"`
	Advisory advisory `xml:"advisory"`
}

type advisory struct {
	Severity string    `xml:"severity"`
	CVEs     []ovalCVE `xml:"cve"`
}

type ovalCVE struct {
	Href       string `xml:"href,attr"`
	Priority   string `xml:"priority,attr"`
	CVSSScore  string `xml:"cvss_score,attr"`
	CVSSVector string `xml:"cvss_vector,attr"`
	// Value holds the CVE-ID text content of the <cve> element.
	Value string `xml:",chardata"`
}

type criteria struct {
	Operator  string      `xml:"operator,attr"`
	Criteria  []criteria  `xml:"criteria"`
	Criterion []criterion `xml:"criterion"`
}

type criterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

// --- parsing helpers -------------------------------------------------------

var (
	// cveIDRe extracts a CVE identifier from an OVAL definition title.
	cveIDRe = regexp.MustCompile(`CVE-\d{4}-\d+`)

	// installedRe matches: "libcurl4 - 7.68.0-1ubuntu2.22 is installed"
	installedRe = regexp.MustCompile(`^(\S+) - (\S+) is installed`)

	// fixRe matches: "...can be fixed by installing libcurl4=7.68.0-1ubuntu2.22"
	fixRe = regexp.MustCompile(`installing (\S+)=(\S+)`)
)

// parseComment extracts the binary package name and fixed version from an OVAL
// criterion comment. Returns empty strings when the comment does not match
// either known format.
func parseComment(comment string) (name, version string) {
	if m := installedRe.FindStringSubmatch(comment); m != nil {
		return m[1], m[2]
	}
	if m := fixRe.FindStringSubmatch(comment); m != nil {
		return m[1], m[2]
	}
	return "", ""
}

// flattenCriteria recursively collects all leaf criterion elements from a
// nested OVAL criteria tree.
func flattenCriteria(c criteria) []criterion {
	out := make([]criterion, 0, len(c.Criterion))
	out = append(out, c.Criterion...)
	for _, sub := range c.Criteria {
		out = append(out, flattenCriteria(sub)...)
	}
	return out
}

// Import implements db.Importer. It fetches and parses one OVAL feed per
// configured release, writing one transaction per OVAL definition.
func (imp *Importer) Import(ctx context.Context, database *db.DB) (db.Stats, error) {
	start := time.Now()
	stats := db.Stats{Source: sourceName}

	sourceID, err := database.UpsertSource(ctx, db.Source{
		Name:         sourceName,
		URL:          "https://people.canonical.com/~ubuntu-security/oval/",
		License:      "https://ubuntu.com/security",
		LastSyncedAt: time.Now(),
	})
	if err != nil {
		return stats, fmt.Errorf("ubuntu: upsert source: %w", err)
	}

	for _, rel := range imp.Releases {
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}
		slog.Debug("ubuntu: importing release", "codename", rel.Codename, "version", rel.Version)
		if err := imp.importRelease(ctx, database, sourceID, rel, &stats); err != nil {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			stats.Errors++
			slog.Warn("ubuntu: release import error", "codename", rel.Codename, "err", err)
		}
	}

	stats.Duration = time.Since(start)
	slog.Info("ubuntu: import complete",
		"inserted", stats.Inserted,
		"skipped", stats.Skipped,
		"errors", stats.Errors,
		"duration", stats.Duration,
	)
	return stats, nil
}

// importRelease downloads, decompresses, and parses one Ubuntu OVAL bz2 file.
func (imp *Importer) importRelease(
	ctx context.Context,
	database *db.DB,
	sourceID int64,
	rel Release,
	stats *db.Stats,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.URL, nil)
	if err != nil {
		return fmt.Errorf("build request for %s: %w", rel.Codename, err)
	}
	req.Header.Set("User-Agent", "patchflow-is-cli/1.0 (https://github.com/patchflow/patchflow-is-cli)")

	resp, err := imp.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", rel.Codename, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d for %s", resp.StatusCode, rel.Codename)
	}

	limited := io.LimitReader(resp.Body, maxBodyBytes)
	bz2r := bzip2.NewReader(limited)

	var oval ovalDefinitions
	if err := xml.NewDecoder(bz2r).Decode(&oval); err != nil {
		return fmt.Errorf("decode OVAL XML for %s: %w", rel.Codename, err)
	}

	slog.Debug("ubuntu: loaded definitions",
		"codename", rel.Codename,
		"count", len(oval.Definitions),
	)

	for i := range oval.Definitions {
		def := &oval.Definitions[i]
		if def.Class != "vulnerability" {
			stats.Skipped++
			continue
		}
		cveID := cveIDRe.FindString(def.Metadata.Title)
		if cveID == "" {
			stats.Skipped++
			slog.Debug("ubuntu: no CVE ID in title", "id", def.ID)
			continue
		}
		if err := imp.importDefinition(ctx, database, sourceID, rel, cveID, def, stats); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			stats.Errors++
			slog.Debug("ubuntu: skip definition", "cve", cveID, "err", err)
		}
	}
	return nil
}

// pkgEntry holds a binary package name and its minimum fixed version.
type pkgEntry struct {
	name    string
	version string
}

// importDefinition writes one OVAL definition (one CVE) into the DB inside a
// single transaction.
func (imp *Importer) importDefinition(
	ctx context.Context,
	database *db.DB,
	sourceID int64,
	rel Release,
	cveID string,
	def *definition,
	stats *db.Stats,
) error {
	severity := strings.ToUpper(strings.TrimSpace(def.Metadata.Advisory.Severity))
	if severity == "" {
		severity = "UNKNOWN"
	}

	var cvssScore float64
	var cvssVector string
	if len(def.Metadata.Advisory.CVEs) > 0 {
		c := def.Metadata.Advisory.CVEs[0]
		cvssScore, _ = strconv.ParseFloat(strings.TrimSpace(c.CVSSScore), 64)
		cvssVector = strings.TrimSpace(c.CVSSVector)
	}

	// Collect unique (package, version) pairs from flattened criteria.
	all := flattenCriteria(def.Criteria)
	seen := make(map[string]bool, len(all))
	var packages []pkgEntry
	for _, crit := range all {
		name, version := parseComment(crit.Comment)
		if name == "" {
			continue
		}
		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		packages = append(packages, pkgEntry{name: name, version: version})
	}

	if len(packages) == 0 {
		stats.Skipped++
		return nil
	}

	return database.Tx(ctx, func(tx *sql.Tx) error {
		vulnID, err := upsertVulnTx(ctx, tx, sourceID, cveID, severity, cvssScore, cvssVector)
		if err != nil {
			return err
		}
		// Delete stale affected-package rows before re-inserting.
		// affected_packages has no UNIQUE constraint, so INSERT OR IGNORE would
		// not deduplicate across runs; delete-first ensures idempotency.
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM affected_packages WHERE vulnerability_id=?`, vulnID); err != nil {
			return fmt.Errorf("clean affected pkgs %s: %w", cveID, err)
		}
		for _, pkg := range packages {
			if err := writeAffectedPkgTx(ctx, tx, db.AffectedPackage{
				VulnerabilityID: vulnID,
				Ecosystem:       "deb",
				PackageName:     pkg.name,
				DistroName:      "ubuntu",
				DistroVersion:   rel.Version,
				FixedVersion:    pkg.version,
				Status:          "fixed",
				Confidence:      100,
			}); err != nil {
				return fmt.Errorf("insert affected pkg %s/%s: %w", cveID, pkg.name, err)
			}
			stats.Inserted++
		}
		return nil
	})
}

// --- transaction-scoped SQL helpers ----------------------------------------

const sqlInsertVuln = `
INSERT OR IGNORE INTO vulnerabilities
    (source_id, vuln_id, aliases, summary, description, severity,
     cvss_score, cvss_vector, published_at, modified_at)
VALUES (?,?,?,?,?,?,?,?,?,?)`

// upsertVulnTx inserts a vulnerability row if it does not already exist and
// returns its row ID.
//
// IMPORTANT: never rely on LastInsertId() after INSERT OR IGNORE — when the
// insert is ignored SQLite leaves sqlite3_last_insert_rowid() at its previous
// connection-level value. Always SELECT the canonical ID instead.
func upsertVulnTx(
	ctx context.Context,
	tx *sql.Tx,
	sourceID int64,
	vulnID, severity string,
	cvssScore float64,
	cvssVector string,
) (int64, error) {
	if _, err := tx.ExecContext(ctx, sqlInsertVuln,
		sourceID, vulnID, "[]",
		"", "", severity,
		cvssScore, cvssVector,
		nil, nil,
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

func writeAffectedPkgTx(ctx context.Context, tx *sql.Tx, ap db.AffectedPackage) error {
	_, err := tx.ExecContext(ctx, sqlInsertAP,
		ap.VulnerabilityID, ap.Ecosystem, ap.PackageName, ap.PackageType,
		ap.DistroName, ap.DistroVersion,
		ap.IntroducedVersion, ap.FixedVersion, ap.AffectedRange,
		ap.SourcePackage, ap.Architecture, ap.Status, ap.Confidence,
	)
	return err
}
