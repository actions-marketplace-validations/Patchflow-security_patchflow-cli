// Package alpine implements an advisory importer for the Alpine Linux Security
// Database (https://secdb.alpinelinux.org).
//
// Alpine's secdb is the vendor-authoritative source for Alpine package
// vulnerabilities, so all records are stored with Confidence=100
// (vendor-exact tier in the PatchFlow matcher).
//
// The importer fetches one JSON feed per (release × repo) combination
// sequentially, honouring a configurable inter-request delay to avoid
// hammering the upstream server.
//
// Security properties:
//   - TLS verification always ON (net/http default).
//   - All HTTP requests respect context cancellation.
//   - Response bodies bounded to 100 MB via io.LimitReader.
//   - No hardcoded credentials; no user-supplied values concatenated into SQL.
//   - AffectedPackage rows are written via atomic check-then-insert transactions,
//     making repeated runs fully idempotent with no duplicate rows.
package alpine

import (
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
	defaultBaseURL    = "https://secdb.alpinelinux.org"
	userAgent         = "patchflow-image-scanner/1.0 vuln-db-importer"
	maxBodyBytes      = 100 * 1024 * 1024 // 100 MB
	httpTimeout       = 30 * time.Second
	defaultRateSleep  = 100 * time.Millisecond // polite delay between requests
	vendorConfidence  = 100                    // vendor-exact tier
)

// ─── Package-level configuration vars ────────────────────────────────────────

// defaultReleases are the Alpine branch slugs fetched when none are specified.
var defaultReleases = []string{"v3.17", "v3.18", "v3.19", "v3.20", "v3.21", "edge"}

// defaultRepos are the Alpine repository names fetched when none are specified.
var defaultRepos = []string{"main", "community"}

// ─── Alpine SecDB JSON schema ─────────────────────────────────────────────────

// secDBFeed is the top-level structure of each release/repo JSON file.
type secDBFeed struct {
	URLPrefix     string     `json:"urlprefix"`
	APKUrl        string     `json:"apkurl"`
	Archs         []string   `json:"archs"`
	RepoName      string     `json:"reponame"`
	DistroVersion string     `json:"distroversion"`
	Packages      []secEntry `json:"packages"`
}

// secEntry is one element in the packages array.
type secEntry struct {
	Pkg secPackage `json:"pkg"`
}

// secPackage represents a single APK package and its security fix map.
type secPackage struct {
	Name     string              `json:"name"`
	SecFixes map[string][]string `json:"secfixes"` // fixedVersion → []cve_id
}

// ─── Importer ────────────────────────────────────────────────────────────────

// Importer fetches Alpine SecDB feeds and writes advisories into the
// PatchFlow DB.  All exported fields are injectable for testing.
//
// Zero-value fields default to production values via New(); callers should
// not set HTTPClient.Transport to one that skips TLS verification.
type Importer struct {
	HTTPClient *http.Client
	Releases   []string
	Repos      []string
	BaseURL    string        // overrides defaultBaseURL; set in tests
	RateSleep  time.Duration // overrides defaultRateSleep; set to 0 in tests
}

// New returns a production-ready Importer with secure defaults.
func New() *Importer {
	return &Importer{
		HTTPClient: &http.Client{
			Timeout: httpTimeout,
			// Transport is nil → http.DefaultTransport with TLS verification ON.
		},
		Releases:  defaultReleases,
		Repos:     defaultRepos,
		BaseURL:   defaultBaseURL,
		RateSleep: defaultRateSleep,
	}
}

// Name implements db.Importer and must match the Source.Name registered in
// the vulnerability_sources table.
func (imp *Importer) Name() string { return "alpine-secdb" }

// Import fetches all (release × repo) JSON feeds and writes the parsed
// advisories into database.  Requests are serialised; a configurable sleep
// between each request keeps the importer a good citizen to the upstream
// server.  It is safe to call multiple times: duplicate records are detected
// and skipped via atomic check-then-insert transactions.
func (imp *Importer) Import(ctx context.Context, database *db.DB) (db.Stats, error) {
	start := time.Now()
	stats := db.Stats{Source: imp.Name()}

	sourceID, err := database.UpsertSource(ctx, db.Source{
		Name:         "alpine-secdb",
		URL:          imp.effectiveBaseURL(),
		License:      "MIT",
		LastSyncedAt: time.Now().UTC(),
	})
	if err != nil {
		return stats, fmt.Errorf("alpine-secdb: upsert source: %w", err)
	}

	for _, release := range imp.Releases {
		for _, repo := range imp.Repos {
			if ctx.Err() != nil {
				stats.Duration = time.Since(start)
				return stats, ctx.Err()
			}

			url := fmt.Sprintf("%s/%s/%s.json", imp.effectiveBaseURL(), release, repo)
			slog.Info("alpine-secdb: fetching feed", "release", release, "repo", repo)

			raw, fetchErr := imp.fetchBytes(ctx, url)
			if fetchErr != nil {
				slog.Warn("alpine-secdb: fetch failed", "url", url, "err", fetchErr)
				stats.Errors++
				imp.sleep(ctx)
				continue
			}

			var feed secDBFeed
			if parseErr := json.Unmarshal(raw, &feed); parseErr != nil {
				slog.Warn("alpine-secdb: JSON parse failed", "url", url, "err", parseErr)
				stats.Errors++
				imp.sleep(ctx)
				continue
			}

			ins, skip, errs := imp.processFeed(ctx, database, sourceID, release, &feed)
			stats.Inserted += ins
			stats.Skipped += skip
			stats.Errors += errs

			imp.sleep(ctx)
		}
	}

	stats.Duration = time.Since(start)
	return stats, nil
}

// processFeed iterates all (package × fixedVersion × CVE) tuples from one
// feed file and writes them to the DB.
func (imp *Importer) processFeed(
	ctx context.Context,
	database *db.DB,
	sourceID int64,
	release string,
	feed *secDBFeed,
) (inserted, skipped, errors int64) {

	// Alpine release tags use "v3.20" format; distro_version stores "3.20".
	distroVersion := strings.TrimPrefix(release, "v")

	for _, entry := range feed.Packages {
		pkg := entry.Pkg
		if pkg.Name == "" {
			skipped++
			continue
		}

		for fixedVersion, cveList := range pkg.SecFixes {
			for _, rawID := range cveList {
				cveID := sanitiseID(rawID)
				if cveID == "" {
					skipped++
					continue
				}

				status, fv := versionKeyToStatus(fixedVersion)

				summary := fmt.Sprintf("Alpine Linux %s: %s fixed in %s %s",
					distroVersion, cveID, pkg.Name, fixedVersion)

				vulnID, err := database.InsertVulnerability(ctx, db.Vulnerability{
					SourceID: sourceID,
					VulnID:   cveID,
					Summary:  summary,
					Severity: "UNKNOWN",
				})
				if err != nil {
					slog.Warn("alpine-secdb: insert vulnerability failed",
						"cve", cveID, "pkg", pkg.Name, "err", err)
					errors++
					continue
				}

				ap := db.AffectedPackage{
					VulnerabilityID: vulnID,
					Ecosystem:       "alpine",
					PackageName:     pkg.Name,
					PackageType:     "os",
					DistroName:      "alpine",
					DistroVersion:   distroVersion,
					FixedVersion:    fv,
					Status:          status,
					Confidence:      vendorConfidence,
				}

				ok, insertErr := insertAffectedPackageSafe(ctx, database, ap)
				if insertErr != nil {
					slog.Warn("alpine-secdb: insert affected package failed",
						"cve", cveID, "pkg", pkg.Name, "err", insertErr)
					errors++
					continue
				}
				if ok {
					inserted++
				} else {
					skipped++ // already present from a previous run
				}
			}
		}
	}
	return
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// sanitiseID strips trailing qualifiers from raw CVE strings.
// Some Alpine SecDB entries include annotations such as:
//
//	"CVE-2023-42363 (+ 2 more)"
//
// We take only the first whitespace-delimited token.
func sanitiseID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return strings.Fields(raw)[0]
}

// versionKeyToStatus maps a SecDB fixedVersion key to a DB status and the
// canonical fixed_version value.
//
// The special key "0" means the package was never affected in this branch
// (status="not-affected"); all other keys are regular fixed versions
// (status="fixed").
func versionKeyToStatus(key string) (status, fixedVersion string) {
	if key == "0" {
		return "not-affected", ""
	}
	return "fixed", key
}

// insertAffectedPackageSafe atomically checks whether an identical
// AffectedPackage row already exists and inserts it only when absent.
//
// The affected_packages table has no UNIQUE constraint, so idempotency must
// be enforced at the application layer.  A write transaction guarantees the
// check and the insert are atomic, preventing duplicates across concurrent or
// repeated import runs.
//
// Returns (true, nil) on a new insertion, (false, nil) when the row already
// exists, and (false, err) on any failure.
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
			return nil // row already present — idempotent skip
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

// effectiveBaseURL returns the configured base URL or the production default.
func (imp *Importer) effectiveBaseURL() string {
	if imp.BaseURL != "" {
		return imp.BaseURL
	}
	return defaultBaseURL
}

// sleep waits for the configured rate-limit duration, returning early if the
// context is cancelled.  When RateSleep is zero it is a no-op.
func (imp *Importer) sleep(ctx context.Context) {
	d := imp.RateSleep
	if d <= 0 {
		return
	}
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

// fetchBytes performs an authenticated HTTP GET with a context, User-Agent
// header, and a 100 MB body cap.  TLS certificate verification is always
// enforced (net/http default — the Transport is never overridden here).
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
