// Package nvd implements a vulnerability importer for the NVD (National
// Vulnerability Database) REST API v2.0.
//
// API endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
//
// Authentication is optional: set the NVD_API_KEY environment variable to
// increase the rate limit from 5 to 50 requests per 30 s.
//
// Security model: TLS verification is never skipped. The API key is read from
// the environment and sent as a query parameter — it is never logged. Response
// bodies are capped at 200 MiB. All requests respect context cancellation.
package nvd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
)

const (
	defaultBaseURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultPageSize = 2000
	sourceName      = "nvd"
	maxBodyBytes    = 200 * 1024 * 1024 // 200 MiB

	// NVD confidence is lower than vendor feeds because CPE matching is
	// product-level, not distro-release-level.
	sourceConfidence = 70
)

// Importer fetches the NVD CVE catalogue via its paginated REST API and
// persists each CVE into the local SQLite DB.
type Importer struct {
	// HTTPClient is used for all outgoing requests. Override in tests.
	HTTPClient *http.Client
	// APIKey is the NVD API key. Set from NVD_API_KEY env var by New().
	// Providing a key raises the rate limit from 5 to 50 requests/30 s.
	APIKey string
	// BaseURL is the NVD API v2.0 endpoint. Defaults to defaultBaseURL.
	BaseURL string
	// PageSize is the number of CVEs to request per page. Defaults to 2000.
	PageSize int
	// LastModStart, when non-zero, enables incremental sync by adding
	// lastModStartDate / lastModEndDate query parameters.
	LastModStart time.Time
	// DelayNoKey is the minimum sleep between pages when no API key is set.
	// Defaults to 700 ms. Override in tests.
	DelayNoKey time.Duration
	// DelayWithKey is the minimum sleep between pages when an API key is set.
	// Defaults to 150 ms. Override in tests.
	DelayWithKey time.Duration
}

// New returns an Importer configured with secure defaults.
// The NVD_API_KEY environment variable is read at construction time.
func New() *Importer {
	return &Importer{
		HTTPClient:   &http.Client{Timeout: 60 * time.Second},
		APIKey:       os.Getenv("NVD_API_KEY"),
		BaseURL:      defaultBaseURL,
		PageSize:     defaultPageSize,
		DelayNoKey:   700 * time.Millisecond,
		DelayWithKey: 150 * time.Millisecond,
	}
}

// Name implements db.Importer.
func (imp *Importer) Name() string { return sourceName }

// effectiveDelay returns the applicable inter-page delay for the current API
// key configuration.
func (imp *Importer) effectiveDelay() time.Duration {
	if imp.APIKey != "" {
		return imp.DelayWithKey
	}
	return imp.DelayNoKey
}

// --- NVD API v2.0 JSON shapes -----------------------------------------------

type nvdResponse struct {
	ResultsPerPage  int       `json:"resultsPerPage"`
	StartIndex      int       `json:"startIndex"`
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []nvdItem `json:"vulnerabilities"`
}

type nvdItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string        `json:"id"`
	Published      string        `json:"published"`
	LastModified   string        `json:"lastModified"`
	VulnStatus     string        `json:"vulnStatus"`
	Descriptions   []nvdDesc     `json:"descriptions"`
	Metrics        nvdMetrics    `json:"metrics"`
	Configurations []nvdConfig   `json:"configurations"`
}

type nvdDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdMetricV3  `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdMetricV3  `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdMetricV2  `json:"cvssMetricV2"`
}

type nvdMetricV3 struct {
	CVSSData nvdCVSSDataV3 `json:"cvssData"`
}

type nvdCVSSDataV3 struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdMetricV2 struct {
	CVSSData nvdCVSSDataV2 `json:"cvssData"`
}

type nvdCVSSDataV2 struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	Operator string       `json:"operator"`
	Negate   bool         `json:"negate"`
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
	Children []nvdNode    `json:"children"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// Import implements db.Importer. It paginates through the NVD CVE API,
// applying rate limiting between requests, and writes one transaction per
// page of results.
func (imp *Importer) Import(ctx context.Context, database *db.DB) (db.Stats, error) {
	start := time.Now()
	stats := db.Stats{Source: sourceName}

	sourceID, err := database.UpsertSource(ctx, db.Source{
		Name:         sourceName,
		URL:          imp.BaseURL,
		License:      "https://nvd.nist.gov/general/privacy-policy",
		LastSyncedAt: time.Now(),
	})
	if err != nil {
		return stats, fmt.Errorf("nvd: upsert source: %w", err)
	}

	delay := imp.effectiveDelay()
	startIndex := 0
	firstPage := true

	for {
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}

		// Rate-limit: sleep between every page except the very first.
		if !firstPage {
			select {
			case <-ctx.Done():
				return stats, ctx.Err()
			case <-time.After(delay):
			}
		}
		firstPage = false

		page, err := imp.fetchPage(ctx, startIndex)
		if err != nil {
			return stats, fmt.Errorf("nvd: fetch page at index %d: %w", startIndex, err)
		}

		slog.Debug("nvd: fetched page",
			"startIndex", page.StartIndex,
			"count", len(page.Vulnerabilities),
			"total", page.TotalResults,
		)

		if err := imp.processPage(ctx, database, sourceID, page, &stats); err != nil {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			// Page-level errors are fatal; we can't safely re-paginate.
			return stats, fmt.Errorf("nvd: process page at %d: %w", startIndex, err)
		}

		// Advance to the next page.
		nextIndex := startIndex + len(page.Vulnerabilities)
		if len(page.Vulnerabilities) == 0 || nextIndex >= page.TotalResults {
			break
		}
		startIndex = nextIndex
	}

	stats.Duration = time.Since(start)
	slog.Info("nvd: import complete",
		"inserted", stats.Inserted,
		"skipped", stats.Skipped,
		"errors", stats.Errors,
		"duration", stats.Duration,
	)
	return stats, nil
}

// fetchPage downloads one page of CVEs from the NVD API.
func (imp *Importer) fetchPage(ctx context.Context, startIndex int) (*nvdResponse, error) {
	u, err := url.Parse(imp.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}

	q := u.Query()
	q.Set("resultsPerPage", fmt.Sprintf("%d", imp.PageSize))
	q.Set("startIndex", fmt.Sprintf("%d", startIndex))
	if imp.APIKey != "" {
		q.Set("apiKey", imp.APIKey)
	}
	if !imp.LastModStart.IsZero() {
		end := imp.LastModStart.Add(120 * 24 * time.Hour) // NVD max window: 120 days
		const layout = "2006-01-02T15:04:05.000"
		q.Set("lastModStartDate", imp.LastModStart.UTC().Format(layout))
		q.Set("lastModEndDate", end.UTC().Format(layout))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "patchflow-is-cli/1.0 (https://github.com/patchflow/patchflow-is-cli)")

	resp, err := imp.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	body := io.LimitReader(resp.Body, maxBodyBytes)
	var result nvdResponse
	if err := json.NewDecoder(body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

// processPage writes all CVEs from one API page inside a single transaction.
func (imp *Importer) processPage(
	ctx context.Context,
	database *db.DB,
	sourceID int64,
	page *nvdResponse,
	stats *db.Stats,
) error {
	return database.Tx(ctx, func(tx *sql.Tx) error {
		for _, item := range page.Vulnerabilities {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := imp.processCVE(ctx, tx, sourceID, &item.CVE, stats); err != nil {
				stats.Errors++
				slog.Debug("nvd: skip CVE", "id", item.CVE.ID, "err", err)
			}
		}
		return nil
	})
}

// processCVE writes one CVE (vulnerability row + affected package rows) to the
// open transaction tx.
func (imp *Importer) processCVE(
	ctx context.Context,
	tx *sql.Tx,
	sourceID int64,
	cve *nvdCVE,
	stats *db.Stats,
) error {
	if cve.ID == "" {
		stats.Skipped++
		return nil
	}

	// Extract the best available English description.
	description := findEnDesc(cve.Descriptions)

	// Determine CVSS score, vector, and severity (prefer v3.1 → v3.0 → v2).
	score, vector, severity := extractCVSS(&cve.Metrics)

	// Parse timestamps; missing timestamps become zero time (stored as NULL).
	publishedAt := parseNVDTime(cve.Published)
	modifiedAt := parseNVDTime(cve.LastModified)

	vulnID, err := upsertVulnTx(ctx, tx, sourceID, cve.ID,
		description, severity, score, vector,
		publishedAt, modifiedAt,
	)
	if err != nil {
		return err
	}

	// Delete stale affected-package rows before re-inserting.
	// affected_packages has no UNIQUE constraint, so INSERT OR IGNORE would
	// not deduplicate across runs; delete-first ensures idempotency.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM affected_packages WHERE vulnerability_id=?`, vulnID); err != nil {
		return fmt.Errorf("clean affected pkgs %s: %w", cve.ID, err)
	}

	// Collect CPE matches from all configuration nodes (flattened).
	matches := flattenNodes(cve.Configurations)

	inserted := 0
	for _, m := range matches {
		if !m.Vulnerable {
			continue
		}
		part, _, product, ok := parseCPE(m.Criteria)
		if !ok {
			stats.Skipped++
			continue
		}
		// Skip hardware CPEs — they don't map to software packages.
		if part == "h" {
			stats.Skipped++
			continue
		}
		if product == "" || product == "*" || product == "-" {
			stats.Skipped++
			continue
		}

		if err := writeAffectedPkgTx(ctx, tx, db.AffectedPackage{
			VulnerabilityID:   vulnID,
			Ecosystem:         "", // NVD is CPE-based, not ecosystem-specific
			PackageName:       product,
			IntroducedVersion: m.VersionStartIncluding,
			FixedVersion:      m.VersionEndExcluding,
			Status:            "affected",
			Confidence:        sourceConfidence,
		}); err != nil {
			return fmt.Errorf("insert affected pkg %s/%s: %w", cve.ID, product, err)
		}
		inserted++
		stats.Inserted++
	}

	if inserted == 0 && len(matches) == 0 {
		// CVE with no CPE data; vulnerability row was still written.
		slog.Debug("nvd: CVE has no CPE configurations", "id", cve.ID)
	}
	return nil
}

// --- parsing helpers -------------------------------------------------------

// findEnDesc returns the first English description value.
func findEnDesc(descs []nvdDesc) string {
	for _, d := range descs {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

// extractCVSS picks the best available CVSS version (v3.1 → v3.0 → v2).
func extractCVSS(m *nvdMetrics) (score float64, vector, severity string) {
	if len(m.CVSSMetricV31) > 0 {
		d := m.CVSSMetricV31[0].CVSSData
		return d.BaseScore, d.VectorString, normalizeSeverity(d.BaseSeverity)
	}
	if len(m.CVSSMetricV30) > 0 {
		d := m.CVSSMetricV30[0].CVSSData
		return d.BaseScore, d.VectorString, normalizeSeverity(d.BaseSeverity)
	}
	if len(m.CVSSMetricV2) > 0 {
		d := m.CVSSMetricV2[0].CVSSData
		return d.BaseScore, d.VectorString, cvssV2Severity(d.BaseScore)
	}
	return 0, "", "UNKNOWN"
}

// normalizeSeverity maps NVD severity strings to canonical uppercase values.
func normalizeSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return strings.ToUpper(s)
	default:
		return "UNKNOWN"
	}
}

// cvssV2Severity maps a CVSS v2 base score to a severity string.
func cvssV2Severity(score float64) string {
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// parseNVDTime parses the NVD timestamp format "2006-01-02T15:04:05.000".
// Returns the zero time on any error.
func parseNVDTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// NVD may use ".000" suffix or no sub-second.
	for _, layout := range []string{
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// parseCPE parses a CPE 2.3 formatted string and returns the component,
// vendor, and product fields.
//
// Format: cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{…}
func parseCPE(criteria string) (part, vendor, product string, ok bool) {
	fields := strings.SplitN(criteria, ":", 6)
	if len(fields) < 5 || fields[0] != "cpe" || fields[1] != "2.3" {
		return "", "", "", false
	}
	return fields[2], fields[3], fields[4], true
}

// flattenNodes recursively collects all CPE matches from a nested node tree.
func flattenNodes(configs []nvdConfig) []nvdCPEMatch {
	var out []nvdCPEMatch
	for _, cfg := range configs {
		out = append(out, flattenNodeList(cfg.Nodes)...)
	}
	return out
}

func flattenNodeList(nodes []nvdNode) []nvdCPEMatch {
	var out []nvdCPEMatch
	for _, n := range nodes {
		out = append(out, n.CPEMatch...)
		out = append(out, flattenNodeList(n.Children)...)
	}
	return out
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
	vulnID, description, severity string,
	cvssScore float64,
	cvssVector string,
	publishedAt, modifiedAt time.Time,
) (int64, error) {
	var pub, mod interface{}
	if !publishedAt.IsZero() {
		pub = publishedAt.UTC().Format(time.RFC3339)
	}
	if !modifiedAt.IsZero() {
		mod = modifiedAt.UTC().Format(time.RFC3339)
	}

	if _, err := tx.ExecContext(ctx, sqlInsertVuln,
		sourceID, vulnID, "[]",
		"", description, severity,
		cvssScore, cvssVector,
		pub, mod,
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
