// Package osv implements an advisory importer for the OSV (Open Source
// Vulnerability) database.  It downloads per-ecosystem batch ZIP archives from
// the OSV Google Cloud Storage bucket, parses every JSON advisory inside them,
// and writes normalised records into the PatchFlow vulnerability database.
//
// Security properties:
//   - TLS verification is always ON (net/http default — never disabled).
//   - All HTTP requests honour context cancellation.
//   - Response bodies are bounded to 100 MB via io.LimitReader.
//   - No user-supplied values are concatenated into SQL; all DB writes go
//     through the parameterised helpers in the db package.
//   - AffectedPackage rows are inserted with an atomic check-then-insert
//     transaction so re-running the importer on the same feed never creates
//     duplicate rows.
package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	defaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"
	userAgent      = "patchflow-image-scanner/1.0 vuln-db-importer"
	maxBodyBytes   = 100 * 1024 * 1024 // 100 MB safety cap on any single download
	httpTimeout    = 30 * time.Second
	osvConfidence  = 95 // OSV-exact tier
)

// ─── Package-level configuration vars ────────────────────────────────────────

// defaultEcosystems are the OSV ecosystem slugs fetched when none are specified.
// Each slug corresponds to one ZIP at {baseURL}/{slug}/all.zip.
var defaultEcosystems = []string{
	"Alpine",
	"Debian",
	"npm",
	"PyPI",
	"Maven",
	"Go",
	"crates.io",
}

// ecosystemMeta maps an OSV ecosystem name to the DB's internal identifiers.
type ecosystemMeta struct {
	dbEcosystem string // db.AffectedPackage.Ecosystem
	distroName  string // db.AffectedPackage.DistroName; empty for language packages
}

// ecosystemMetas contains the full mapping for all supported OSV ecosystems.
var ecosystemMetas = map[string]ecosystemMeta{
	"Alpine":    {dbEcosystem: "alpine", distroName: "alpine"},
	"Debian":    {dbEcosystem: "deb", distroName: "debian"},
	"npm":       {dbEcosystem: "npm"},
	"PyPI":      {dbEcosystem: "pypi"},
	"Maven":     {dbEcosystem: "maven"},
	"Go":        {dbEcosystem: "golang"},
	"crates.io": {dbEcosystem: "cargo"},
}

// ─── OSV JSON schema ─────────────────────────────────────────────────────────

type osvRecord struct {
	ID        string        `json:"id"`
	Aliases   []string      `json:"aliases"`
	Summary   string        `json:"summary"`
	Details   string        `json:"details"`
	Modified  time.Time     `json:"modified"`
	Published time.Time     `json:"published"`
	Severity  []osvSev      `json:"severity"`
	Affected  []osvAffected `json:"affected"`
}

type osvSev struct {
	Type  string `json:"type"`  // "CVSS_V3", "CVSS_V4", "CVSS_V2"
	Score string `json:"score"` // the full CVSS vector string
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvRange struct {
	Type   string     `json:"type"`   // "ECOSYSTEM", "SEMVER", "GIT"
	Events []osvEvent `json:"events"` // ordered: introduced, fixed, …
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// ─── Importer ────────────────────────────────────────────────────────────────

// Importer downloads OSV batch ZIPs and writes advisories into the PatchFlow DB.
//
// HTTPClient, Ecosystems, and BaseURL are all injectable for testing.
// When HTTPClient is nil New() supplies a hardened default; callers should
// never replace it with one that skips TLS verification.
type Importer struct {
	HTTPClient *http.Client
	Ecosystems []string
	BaseURL    string // overrides defaultBaseURL (set in tests)
}

// New returns a production-ready Importer with secure defaults.
func New() *Importer {
	return &Importer{
		HTTPClient: &http.Client{
			Timeout: httpTimeout,
			// Transport is nil → http.DefaultTransport, which enforces TLS.
		},
		Ecosystems: defaultEcosystems,
		BaseURL:    defaultBaseURL,
	}
}

// Name implements db.Importer and must match the Source.Name registered in
// the vulnerability_sources table.
func (imp *Importer) Name() string { return "osv" }

// Import fetches each ecosystem's batch ZIP and writes the parsed advisories
// into database.  It is safe to call multiple times on the same DB — duplicate
// records are detected and skipped via atomic check-then-insert transactions.
func (imp *Importer) Import(ctx context.Context, database *db.DB) (db.Stats, error) {
	start := time.Now()
	stats := db.Stats{Source: imp.Name()}

	sourceID, err := database.UpsertSource(ctx, db.Source{
		Name:         "osv",
		URL:          imp.effectiveBaseURL(),
		License:      "CC-BY-4.0",
		LastSyncedAt: time.Now().UTC(),
	})
	if err != nil {
		return stats, fmt.Errorf("osv: upsert source: %w", err)
	}

	for _, ecosystem := range imp.Ecosystems {
		if ctx.Err() != nil {
			break
		}
		meta, ok := ecosystemMetas[ecosystem]
		if !ok {
			slog.Warn("osv: unknown ecosystem, skipping", "ecosystem", ecosystem)
			stats.Skipped++
			continue
		}
		slog.Info("osv: importing ecosystem", "ecosystem", ecosystem)
		ins, skip, errs := imp.importEcosystem(ctx, database, sourceID, ecosystem, meta)
		stats.Inserted += ins
		stats.Skipped += skip
		stats.Errors += errs
	}

	stats.Duration = time.Since(start)
	return stats, nil
}

// importEcosystem downloads and processes one ecosystem ZIP file.
func (imp *Importer) importEcosystem(
	ctx context.Context,
	database *db.DB,
	sourceID int64,
	ecosystem string,
	meta ecosystemMeta,
) (inserted, skipped, errors int64) {

	url := fmt.Sprintf("%s/%s/all.zip", imp.effectiveBaseURL(), ecosystem)
	raw, err := imp.fetchBytes(ctx, url)
	if err != nil {
		slog.Error("osv: fetch failed", "ecosystem", ecosystem, "url", url, "err", err)
		errors++
		return
	}

	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		slog.Error("osv: ZIP open failed", "ecosystem", ecosystem, "err", err)
		errors++
		return
	}

	for _, zf := range zr.File {
		if ctx.Err() != nil {
			return
		}
		if !strings.HasSuffix(zf.Name, ".json") {
			continue
		}
		ok, skip, errs := imp.processEntry(ctx, database, sourceID, zf, meta)
		if ok {
			inserted++
		}
		skipped += skip
		errors += errs
	}
	return
}

// processEntry reads one JSON file from the ZIP and writes it to the DB.
// Malformed JSON is logged and skipped; other records continue processing.
func (imp *Importer) processEntry(
	ctx context.Context,
	database *db.DB,
	sourceID int64,
	zf *zip.File,
	meta ecosystemMeta,
) (inserted bool, skipped, errors int64) {

	rc, err := zf.Open()
	if err != nil {
		slog.Warn("osv: open ZIP entry failed", "file", zf.Name, "err", err)
		errors++
		return
	}
	raw, err := io.ReadAll(io.LimitReader(rc, maxBodyBytes))
	rc.Close()
	if err != nil {
		slog.Warn("osv: read ZIP entry failed", "file", zf.Name, "err", err)
		errors++
		return
	}

	var rec osvRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		slog.Warn("osv: malformed JSON, skipping", "file", zf.Name, "err", err)
		errors++
		return
	}

	if rec.ID == "" {
		skipped++
		return
	}
	// Skip records with no affected packages — nothing useful to store.
	if len(rec.Affected) == 0 {
		slog.Debug("osv: skip — no affected entries", "id", rec.ID)
		skipped++
		return
	}

	vector, score, severity := parseSeverity(rec.Severity)

	vulnID, err := database.InsertVulnerability(ctx, db.Vulnerability{
		SourceID:    sourceID,
		VulnID:      rec.ID,
		Aliases:     rec.Aliases,
		Summary:     rec.Summary,
		Description: rec.Details,
		Severity:    severity,
		CVSSScore:   score,
		CVSSVector:  vector,
		PublishedAt: rec.Published,
		ModifiedAt:  rec.Modified,
	})
	if err != nil {
		slog.Warn("osv: insert vulnerability failed", "id", rec.ID, "err", err)
		errors++
		return
	}

	pkgInserted := imp.insertAffected(ctx, database, vulnID, rec.Affected, meta)
	if pkgInserted {
		inserted = true
	} else {
		skipped++
	}
	return
}

// insertAffected writes AffectedPackage rows for every (package, range) pair
// in the affected list.  Uses insertAffectedPackageSafe to prevent duplicates.
// Returns true if at least one row was newly inserted.
func (imp *Importer) insertAffected(
	ctx context.Context,
	database *db.DB,
	vulnID int64,
	affected []osvAffected,
	defaultMeta ecosystemMeta,
) bool {
	anyInserted := false

	for _, aff := range affected {
		pkgEco := defaultMeta.dbEcosystem
		pkgDistro := defaultMeta.distroName

		// Per-package ecosystem override (e.g., the record lists "npm" explicitly).
		if m, ok := ecosystemMetas[aff.Package.Ecosystem]; ok {
			pkgEco = m.dbEcosystem
			pkgDistro = m.distroName
		}

		// pkgRowInserted: a new row was written on this run (for stats).
		// pkgRowHandled:  a row exists (inserted or pre-existing); suppresses fallback.
		pkgRowInserted := false
		pkgRowHandled := false

		for _, rng := range aff.Ranges {
			// Only ECOSYSTEM and SEMVER ranges carry version semantics we can store.
			if rng.Type != "ECOSYSTEM" && rng.Type != "SEMVER" {
				continue
			}
			for _, pair := range buildVersionPairs(rng.Events) {
				ap := db.AffectedPackage{
					VulnerabilityID:   vulnID,
					Ecosystem:         pkgEco,
					PackageName:       aff.Package.Name,
					DistroName:        pkgDistro,
					IntroducedVersion: pair.introduced,
					FixedVersion:      pair.fixed,
					AffectedRange:     pair.affectedRange,
					Status:            "affected",
					Confidence:        osvConfidence,
				}
				ok, err := insertAffectedPackageSafe(ctx, database, ap)
				if err != nil {
					slog.Warn("osv: insert affected package failed",
						"vuln_id", vulnID, "pkg", aff.Package.Name, "err", err)
					continue
				}
				// Either newly inserted or already present — a row exists for this
				// package, so the fallback must not fire.
				pkgRowHandled = true
				if ok {
					pkgRowInserted = true
				}
			}
		}

		// Fallback: no ECOSYSTEM/SEMVER ranges (e.g., GIT-only) — record the
		// package as generically affected so we don't silently drop it.
		// Also skipped when a row already exists from a prior run (pkgRowHandled).
		if !pkgRowHandled {
			ap := db.AffectedPackage{
				VulnerabilityID: vulnID,
				Ecosystem:       pkgEco,
				PackageName:     aff.Package.Name,
				DistroName:      pkgDistro,
				Status:          "affected",
				Confidence:      osvConfidence,
			}
			ok, err := insertAffectedPackageSafe(ctx, database, ap)
			if err != nil {
				slog.Warn("osv: insert fallback affected package failed",
					"vuln_id", vulnID, "pkg", aff.Package.Name, "err", err)
			} else if ok {
				pkgRowInserted = true
			}
		}

		if pkgRowInserted {
			anyInserted = true
		}
	}
	return anyInserted
}

// ─── Version range parsing ────────────────────────────────────────────────────

// versionPair holds one (introduced, fixed) combination from an OSV range.
type versionPair struct {
	introduced    string
	fixed         string
	affectedRange string // set when last_affected is used
}

// buildVersionPairs converts the OSV event list into (introduced, fixed) pairs.
// The OSV specification states events alternate introduced → fixed → introduced
// → fixed …; an open range at the end has no matching fixed event.
func buildVersionPairs(events []osvEvent) []versionPair {
	var pairs []versionPair
	var current versionPair
	inOpen := false

	for _, e := range events {
		switch {
		case e.Introduced != "":
			if inOpen {
				// Unclosed range — emit it before opening a new one.
				pairs = append(pairs, current)
			}
			current = versionPair{introduced: e.Introduced}
			inOpen = true

		case e.Fixed != "":
			current.fixed = e.Fixed
			pairs = append(pairs, current)
			current = versionPair{}
			inOpen = false

		case e.LastAffected != "":
			current.affectedRange = "<= " + e.LastAffected
			pairs = append(pairs, current)
			current = versionPair{}
			inOpen = false
		}
	}

	if inOpen {
		pairs = append(pairs, current) // open-ended (no fix available yet)
	}
	if len(pairs) == 0 {
		pairs = append(pairs, versionPair{}) // placeholder for ranges with no events
	}
	return pairs
}

// ─── CVSS parsing ─────────────────────────────────────────────────────────────

// parseSeverity extracts the first recognised CVSS entry from the severity list.
// The OSV "score" field IS the CVSS vector string; a numeric score would require
// a full CVSS calculation library, so CVSSScore is always returned as 0.0 and
// the severity label is derived heuristically from the vector components.
func parseSeverity(sevs []osvSev) (vector string, score float64, severity string) {
	for _, s := range sevs {
		switch s.Type {
		case "CVSS_V4", "CVSS_V3", "CVSS_V2":
			vector = s.Score
			severity = severityFromVector(vector)
			return vector, 0.0, severity
		}
	}
	return "", 0.0, "UNKNOWN"
}

// severityFromVector derives a severity label from a CVSS vector string using
// simple metric pattern matching.  The full numeric scoring algorithm is
// deliberately omitted; heuristics cover the common cases accurately enough
// for display purposes.
func severityFromVector(v string) string {
	if v == "" {
		return "UNKNOWN"
	}
	cH := strings.Contains(v, "/C:H")
	iH := strings.Contains(v, "/I:H")
	aH := strings.Contains(v, "/A:H")

	switch {
	case cH && iH && aH:
		return "CRITICAL"
	case cH || iH || aH:
		return "HIGH"
	case strings.Contains(v, "/C:L") || strings.Contains(v, "/I:L") || strings.Contains(v, "/A:L"):
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// ─── Idempotent affected-package insert ──────────────────────────────────────

// insertAffectedPackageSafe atomically checks whether an identical
// AffectedPackage row already exists and inserts it only when absent.
//
// The affected_packages schema has no UNIQUE constraint (it is append-only by
// design), so idempotency must be enforced at the application layer.  A write
// transaction is used so the check and the insert are atomic even if the
// importer is ever parallelised in future.
//
// Returns (true, nil) when a new row is inserted, (false, nil) when the row
// already exists, and (false, err) on failure.
func insertAffectedPackageSafe(ctx context.Context, database *db.DB, ap db.AffectedPackage) (bool, error) {
	var inserted bool
	err := database.Tx(ctx, func(tx *sql.Tx) error {
		var count int64
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(1) FROM affected_packages
			WHERE vulnerability_id   = ?
			  AND ecosystem          = ?
			  AND package_name       = ?
			  AND distro_name        = ?
			  AND distro_version     = ?
			  AND introduced_version = ?
			  AND fixed_version      = ?
			  AND status             = ?`,
			ap.VulnerabilityID, ap.Ecosystem, ap.PackageName,
			ap.DistroName, ap.DistroVersion,
			ap.IntroducedVersion, ap.FixedVersion,
			ap.Status,
		).Scan(&count); err != nil {
			return fmt.Errorf("check duplicate affected_package: %w", err)
		}
		if count > 0 {
			inserted = false
			return nil // row already exists — idempotent skip
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO affected_packages
				(vulnerability_id, ecosystem, package_name, package_type,
				 distro_name, distro_version, introduced_version, fixed_version,
				 affected_range, source_package, architecture, status, confidence)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			ap.VulnerabilityID, ap.Ecosystem, ap.PackageName, ap.PackageType,
			ap.DistroName, ap.DistroVersion,
			ap.IntroducedVersion, ap.FixedVersion,
			ap.AffectedRange, ap.SourcePackage, ap.Architecture,
			ap.Status, ap.Confidence,
		); err != nil {
			return fmt.Errorf("insert affected_package: %w", err)
		}
		inserted = true
		return nil
	})
	return inserted, err
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

// effectiveBaseURL returns the configured base URL, falling back to the
// production GCS bucket URL.
func (imp *Importer) effectiveBaseURL() string {
	if imp.BaseURL != "" {
		return imp.BaseURL
	}
	return defaultBaseURL
}

// fetchBytes performs an HTTP GET with context, User-Agent, and a 100 MB body
// cap.  TLS certificate verification is always enforced by the default transport.
func (imp *Importer) fetchBytes(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := imp.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read body from %s: %w", url, err)
	}
	return body, nil
}
