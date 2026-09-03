// Package osv_test exercises the OSV advisory importer against an in-process
// HTTP test server that serves synthetic ZIP archives.  No network traffic
// leaves the test process.
package osv_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db/osv"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

// buildZip creates an in-memory ZIP archive from a slice of JSON-serialisable
// values. Each value is written as a separate .json entry.
func buildZip(t *testing.T, records []any) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i, r := range records {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("buildZip: marshal record %d: %v", i, err)
		}
		entry, err := w.Create(fmt.Sprintf("record-%04d.json", i))
		if err != nil {
			t.Fatalf("buildZip: create ZIP entry %d: %v", i, err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatalf("buildZip: write ZIP entry %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("buildZip: close ZIP writer: %v", err)
	}
	return buf.Bytes()
}

// openTestDB opens a fresh, schema-migrated SQLite DB in a temp directory and
// registers a cleanup handler to close it when the test finishes.
func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "vuln.db"))
	if err != nil {
		t.Fatalf("openTestDB: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// osvFixture returns a minimal OSV JSON object that has one ECOSYSTEM range
// for an npm package.  The CVSS vector produces a CRITICAL severity label.
func osvFixture(id, pkgName string) map[string]any {
	return map[string]any{
		"id":        id,
		"aliases":   []string{"CVE-2024-99999"},
		"summary":   "Test advisory " + id,
		"details":   "Detailed description for " + id,
		"modified":  "2024-06-01T00:00:00Z",
		"published": "2024-05-01T00:00:00Z",
		"severity": []map[string]any{
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		"affected": []map[string]any{
			{
				"package": map[string]string{"name": pkgName, "ecosystem": "npm"},
				"ranges": []map[string]any{
					{
						"type": "ECOSYSTEM",
						"events": []map[string]any{
							{"introduced": "0"},
							{"fixed": "1.2.3"},
						},
					},
				},
			},
		},
	}
}

// osvNoAffected returns a minimal OSV JSON object with an empty affected list.
// The importer must skip it gracefully without returning an error.
func osvNoAffected(id string) map[string]any {
	return map[string]any{
		"id":        id,
		"summary":   "Advisory with no affected packages",
		"modified":  "2024-06-01T00:00:00Z",
		"published": "2024-05-01T00:00:00Z",
		"affected":  []any{},
	}
}

// newTestImporter builds an Importer pointing at the given test server.
// The Importer's HTTPClient is set to the server's own client so redirects
// and TLS are handled correctly even for TLS test servers.
func newTestImporter(ts *httptest.Server, ecosystems []string) *osv.Importer {
	return &osv.Importer{
		HTTPClient: ts.Client(),
		Ecosystems: ecosystems,
		BaseURL:    ts.URL,
	}
}

// serveEcosystemZip returns an HTTP handler that serves zipData only for
// requests whose path matches "/{ecosystem}/all.zip".
func serveEcosystemZip(ecosystem string, zipData []byte) http.HandlerFunc {
	wantPath := fmt.Sprintf("/%s/all.zip", ecosystem)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// TestOSVImport_BasicImport verifies that the importer:
//  1. Inserts all valid advisories (Inserted >= 2).
//  2. Gracefully skips advisories that have no affected entries (Skipped >= 1).
//  3. Makes both valid records queryable in the DB.
//  4. Does NOT persist the no-affected advisory in the DB.
func TestOSVImport_BasicImport(t *testing.T) {
	records := []any{
		osvFixture("GHSA-0001-0001-0001", "lodash"),
		osvFixture("GHSA-0002-0002-0002", "express"),
		osvNoAffected("GHSA-0003-0003-0003"),
	}
	zipData := buildZip(t, records)

	ts := httptest.NewServer(serveEcosystemZip("npm", zipData))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"npm"})

	stats, err := imp.Import(ctx, database)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.Inserted < 2 {
		t.Errorf("Inserted: got %d, want >= 2", stats.Inserted)
	}
	if stats.Skipped < 1 {
		t.Errorf("Skipped: got %d, want >= 1 (no-affected advisory)", stats.Skipped)
	}

	// Both valid advisories must be retrievable.
	for _, id := range []string{"GHSA-0001-0001-0001", "GHSA-0002-0002-0002"} {
		rows, err := database.QueryByVulnID(ctx, id)
		if err != nil {
			t.Fatalf("QueryByVulnID(%s): %v", id, err)
		}
		if len(rows) == 0 {
			t.Errorf("%s not found in DB after import", id)
		}
	}

	// The no-affected advisory must NOT be in the DB.
	rows, err := database.QueryByVulnID(ctx, "GHSA-0003-0003-0003")
	if err != nil {
		t.Fatalf("QueryByVulnID(GHSA-0003-0003-0003): %v", err)
	}
	if len(rows) > 0 {
		t.Error("GHSA-0003-0003-0003 should be absent (no affected entries) but was found in DB")
	}
}

// TestOSVImport_Idempotent verifies that running the importer twice on the
// same data produces exactly one affected-package row, not two.
func TestOSVImport_Idempotent(t *testing.T) {
	records := []any{
		osvFixture("GHSA-1111-1111-1111", "semver"),
	}
	zipData := buildZip(t, records)

	ts := httptest.NewServer(serveEcosystemZip("npm", zipData))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"npm"})

	// First run.
	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("first Import: %v", err)
	}

	// Second run — identical feed, same DB.
	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("second Import: %v", err)
	}

	// Exactly one affected-package row must exist (no duplicates).
	rows, err := database.QueryByVulnID(ctx, "GHSA-1111-1111-1111")
	if err != nil {
		t.Fatalf("QueryByVulnID: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("GHSA-1111-1111-1111 not found after idempotent import")
	}
	if len(rows) > 1 {
		t.Errorf("idempotency violated: want 1 affected row, got %d", len(rows))
	}
}

// TestOSVImport_NoAffectedIsSkipped is a focused test confirming that an
// advisory whose affected list is empty never touches the DB.
func TestOSVImport_NoAffectedIsSkipped(t *testing.T) {
	records := []any{
		osvNoAffected("GHSA-9999-9999-9999"),
	}
	zipData := buildZip(t, records)

	ts := httptest.NewServer(serveEcosystemZip("npm", zipData))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"npm"})

	stats, err := imp.Import(ctx, database)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.Inserted != 0 {
		t.Errorf("Inserted: got %d, want 0 for no-affected advisory", stats.Inserted)
	}
	if stats.Skipped < 1 {
		t.Errorf("Skipped: got %d, want >= 1", stats.Skipped)
	}

	rows, err := database.QueryByVulnID(ctx, "GHSA-9999-9999-9999")
	if err != nil {
		t.Fatalf("QueryByVulnID: %v", err)
	}
	if len(rows) > 0 {
		t.Error("no-affected advisory must not appear in DB but was found")
	}
}

// TestOSVImport_UserAgent verifies that every outbound request carries the
// required User-Agent header.
func TestOSVImport_UserAgent(t *testing.T) {
	var capturedUA string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUA = r.Header.Get("User-Agent")
		data := buildZip(t, []any{})
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"npm"})

	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("Import: %v", err)
	}

	const wantUA = "patchflow-image-scanner/1.0 vuln-db-importer"
	if capturedUA != wantUA {
		t.Errorf("User-Agent: got %q, want %q", capturedUA, wantUA)
	}
}

// TestOSVImport_SeverityMapping verifies that the CVSS vector in the fixture
// is correctly mapped to the CRITICAL severity label.
func TestOSVImport_SeverityMapping(t *testing.T) {
	records := []any{
		osvFixture("GHSA-2222-2222-2222", "axios"),
	}
	zipData := buildZip(t, records)

	ts := httptest.NewServer(serveEcosystemZip("npm", zipData))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"npm"})

	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("Import: %v", err)
	}

	rows, err := database.QueryByVulnID(ctx, "GHSA-2222-2222-2222")
	if err != nil {
		t.Fatalf("QueryByVulnID: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("GHSA-2222-2222-2222 not found")
	}
	// The fixture uses /C:H/I:H/A:H → CRITICAL.
	if rows[0].Severity != "CRITICAL" {
		t.Errorf("Severity: got %q, want CRITICAL", rows[0].Severity)
	}
}

// TestOSVImport_VersionRangeStored confirms that introduced and fixed version
// fields are correctly persisted for an ECOSYSTEM range.
func TestOSVImport_VersionRangeStored(t *testing.T) {
	record := map[string]any{
		"id":        "GHSA-3333-3333-3333",
		"summary":   "Range test",
		"modified":  "2024-06-01T00:00:00Z",
		"published": "2024-05-01T00:00:00Z",
		"affected": []map[string]any{
			{
				"package": map[string]string{"name": "some-lib", "ecosystem": "npm"},
				"ranges": []map[string]any{
					{
						"type": "ECOSYSTEM",
						"events": []map[string]any{
							{"introduced": "1.0.0"},
							{"fixed": "2.3.4"},
						},
					},
				},
			},
		},
	}
	zipData := buildZip(t, []any{record})

	ts := httptest.NewServer(serveEcosystemZip("npm", zipData))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"npm"})

	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("Import: %v", err)
	}

	rows, err := database.QueryByPackage(ctx, "npm", "some-lib", "", "")
	if err != nil {
		t.Fatalf("QueryByPackage: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("some-lib not found in DB")
	}

	r := rows[0]
	if r.IntroducedVersion != "1.0.0" {
		t.Errorf("IntroducedVersion: got %q, want 1.0.0", r.IntroducedVersion)
	}
	if r.FixedVersion != "2.3.4" {
		t.Errorf("FixedVersion: got %q, want 2.3.4", r.FixedVersion)
	}
}

// TestOSVImport_HTTP404Skipped verifies that the importer handles a 404
// response from the server (e.g., an ecosystem that doesn't exist yet) without
// aborting the entire import run.
func TestOSVImport_HTTP404Skipped(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"npm"})

	stats, err := imp.Import(ctx, database)
	// The importer must not return a top-level error on HTTP 404.
	if err != nil {
		t.Fatalf("Import returned error on 404: %v", err)
	}
	if stats.Errors < 1 {
		t.Errorf("Errors: got %d, want >= 1 for HTTP 404", stats.Errors)
	}
}
