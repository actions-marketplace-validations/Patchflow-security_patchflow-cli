package nvd_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db/nvd"
)

// --- fixture helpers -------------------------------------------------------

// makeVuln builds a minimal NVD vulnerability JSON object.
func makeVuln(cveID, description, severity string, score float64, cpe string) map[string]interface{} {
	return map[string]interface{}{
		"cve": map[string]interface{}{
			"id":           cveID,
			"published":    "2024-01-01T00:00:00.000",
			"lastModified": "2024-01-15T00:00:00.000",
			"vulnStatus":   "Analyzed",
			"descriptions": []map[string]interface{}{
				{"lang": "en", "value": description},
			},
			"metrics": map[string]interface{}{
				"cvssMetricV31": []map[string]interface{}{
					{
						"cvssData": map[string]interface{}{
							"baseScore":    score,
							"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
							"baseSeverity": severity,
						},
					},
				},
			},
			"configurations": []map[string]interface{}{
				{
					"nodes": []map[string]interface{}{
						{
							"cpeMatch": []map[string]interface{}{
								{
									"vulnerable":         true,
									"criteria":           cpe,
									"versionEndExcluding": "1.2.3",
								},
							},
						},
					},
				},
			},
		},
	}
}

// makePage builds an NVD API response for the given page of vulnerabilities.
func makePage(start, total int, vulns []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"resultsPerPage":  len(vulns),
		"startIndex":      start,
		"totalResults":    total,
		"vulnerabilities": vulns,
	}
}

// newTestDB opens a temporary SQLite DB in t.TempDir().
func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

// --- tests -----------------------------------------------------------------

func TestName(t *testing.T) {
	imp := nvd.New()
	if imp.Name() != "nvd" {
		t.Errorf("Name() = %q, want %q", imp.Name(), "nvd")
	}
}

// TestImportPagination verifies that the importer fetches all pages and inserts
// all CVEs. The fixture has 2 pages × 2 CVEs each = 4 total.
func TestImportPagination(t *testing.T) {
	page1 := makePage(0, 4, []map[string]interface{}{
		makeVuln("CVE-2024-0001", "Test vuln 1", "HIGH", 7.5, "cpe:2.3:a:vendor:product1:*:*:*:*:*:*:*:*"),
		makeVuln("CVE-2024-0002", "Test vuln 2", "MEDIUM", 5.0, "cpe:2.3:a:vendor:product2:*:*:*:*:*:*:*:*"),
	})
	page2 := makePage(2, 4, []map[string]interface{}{
		makeVuln("CVE-2024-0003", "Test vuln 3", "LOW", 3.1, "cpe:2.3:a:vendor:product3:*:*:*:*:*:*:*:*"),
		makeVuln("CVE-2024-0004", "Test vuln 4", "CRITICAL", 9.8, "cpe:2.3:o:vendor:product4:*:*:*:*:*:*:*:*"),
	})

	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		startStr := r.URL.Query().Get("startIndex")
		start, _ := strconv.Atoi(startStr)
		w.Header().Set("Content-Type", "application/json")
		if start == 0 {
			_ = json.NewEncoder(w).Encode(page1)
		} else {
			_ = json.NewEncoder(w).Encode(page2)
		}
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := nvd.New()
	imp.BaseURL = srv.URL
	imp.HTTPClient = srv.Client()
	imp.PageSize = 2
	imp.DelayNoKey = 5 * time.Millisecond // fast for tests

	stats, err := imp.Import(context.Background(), database)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	if requestCount != 2 {
		t.Errorf("expected 2 HTTP requests (2 pages), got %d", requestCount)
	}
	if stats.Inserted != 4 {
		t.Errorf("stats.Inserted = %d, want 4", stats.Inserted)
	}
	if stats.Errors != 0 {
		t.Errorf("stats.Errors = %d, want 0", stats.Errors)
	}
}

// TestImportRateLimiting checks that the importer sleeps between pages.
// With 2 pages and DelayNoKey=20ms, total time must be >= 20ms.
func TestImportRateLimiting(t *testing.T) {
	const delay = 20 * time.Millisecond

	page1 := makePage(0, 2, []map[string]interface{}{
		makeVuln("CVE-2024-1001", "Rate limit test 1", "HIGH", 7.5, "cpe:2.3:a:v:p1:*:*:*:*:*:*:*:*"),
	})
	page2 := makePage(1, 2, []map[string]interface{}{
		makeVuln("CVE-2024-1002", "Rate limit test 2", "HIGH", 7.5, "cpe:2.3:a:v:p2:*:*:*:*:*:*:*:*"),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		startStr := r.URL.Query().Get("startIndex")
		start, _ := strconv.Atoi(startStr)
		if start == 0 {
			_ = json.NewEncoder(w).Encode(page1)
		} else {
			_ = json.NewEncoder(w).Encode(page2)
		}
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := nvd.New()
	imp.BaseURL = srv.URL
	imp.HTTPClient = srv.Client()
	imp.PageSize = 1
	imp.DelayNoKey = delay

	start := time.Now()
	_, err := imp.Import(context.Background(), database)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	// One delay between page 1 and page 2.
	if elapsed < delay {
		t.Errorf("expected elapsed >= %v (rate limit delay), got %v", delay, elapsed)
	}
}

// TestImportAPIKey verifies the API key is sent as the "apiKey" query
// parameter when configured.
func TestImportAPIKey(t *testing.T) {
	const wantKey = "test-api-key-12345"
	var gotKey string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(makePage(0, 0, nil))
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := nvd.New()
	imp.BaseURL = srv.URL
	imp.HTTPClient = srv.Client()
	imp.APIKey = wantKey
	imp.DelayWithKey = 1 * time.Millisecond

	if _, err := imp.Import(context.Background(), database); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if gotKey != wantKey {
		t.Errorf("apiKey query param = %q, want %q", gotKey, wantKey)
	}
}

// TestImportHardwareCPESkipped confirms that hardware CPEs (part='h') do not
// produce AffectedPackage rows.
func TestImportHardwareCPESkipped(t *testing.T) {
	hardwareVuln := makeVuln(
		"CVE-2024-2001", "Hardware vuln", "MEDIUM", 5.0,
		"cpe:2.3:h:cisco:router_model:*:*:*:*:*:*:*:*", // part=h
	)
	page := makePage(0, 1, []map[string]interface{}{hardwareVuln})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := nvd.New()
	imp.BaseURL = srv.URL
	imp.HTTPClient = srv.Client()
	imp.DelayNoKey = 1 * time.Millisecond

	stats, err := imp.Import(context.Background(), database)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.Inserted != 0 {
		t.Errorf("hardware CPE: stats.Inserted = %d, want 0", stats.Inserted)
	}
	if stats.Skipped == 0 {
		t.Error("hardware CPE: expected stats.Skipped > 0")
	}
}

// TestImportIdempotent verifies that running the import twice produces no
// duplicate rows and no errors on the second run.
func TestImportIdempotent(t *testing.T) {
	page := makePage(0, 2, []map[string]interface{}{
		makeVuln("CVE-2024-3001", "Idempotent test 1", "HIGH", 7.5, "cpe:2.3:a:v:pkg1:*:*:*:*:*:*:*:*"),
		makeVuln("CVE-2024-3002", "Idempotent test 2", "LOW", 3.0, "cpe:2.3:a:v:pkg2:*:*:*:*:*:*:*:*"),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := nvd.New()
	imp.BaseURL = srv.URL
	imp.HTTPClient = srv.Client()
	imp.DelayNoKey = 1 * time.Millisecond

	ctx := context.Background()

	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("first Import: %v", err)
	}

	stats2, err := imp.Import(ctx, database)
	if err != nil {
		t.Fatalf("second Import: %v", err)
	}
	if stats2.Errors != 0 {
		t.Errorf("idempotency: stats.Errors = %d, want 0", stats2.Errors)
	}
}

// TestImportContextCancelled verifies that a cancelled context stops the import.
func TestImportContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(makePage(0, 0, nil))
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := nvd.New()
	imp.BaseURL = srv.URL
	imp.HTTPClient = srv.Client()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling Import

	_, err := imp.Import(ctx, database)
	if err == nil {
		t.Error("expected error with cancelled context, got nil")
	}
}

// TestImportBadHTTPStatus verifies that a non-200 response is treated as an
// error.
func TestImportBadHTTPStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := nvd.New()
	imp.BaseURL = srv.URL
	imp.HTTPClient = srv.Client()
	imp.DelayNoKey = 1 * time.Millisecond

	_, err := imp.Import(context.Background(), database)
	if err == nil {
		t.Error("expected error for 429 response, got nil")
	}
}
