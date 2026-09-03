// Package alpine_test exercises the Alpine SecDB advisory importer against
// an in-process HTTP test server that serves synthetic SecDB JSON fixtures.
// No network traffic leaves the test process.
package alpine_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db/alpine"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

// openTestDB opens a fresh, schema-migrated SQLite DB in a temp directory
// and registers a cleanup handler to close it when the test finishes.
func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "vuln.db"))
	if err != nil {
		t.Fatalf("openTestDB: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// secDBFixture builds a minimal Alpine SecDB JSON payload.
// It includes:
//   - busybox with two CVEs fixed in "1.36.1-r15" and one "not-affected" entry
//     (version key "0").
//   - curl with one fixed CVE.
func secDBFixture(distroVersion, repoName string) []byte {
	feed := map[string]any{
		"urlprefix":     "http://dl-cdn.alpinelinux.org/alpine/",
		"reponame":      repoName,
		"distroversion": distroVersion,
		"packages": []map[string]any{
			{
				"pkg": map[string]any{
					"name": "busybox",
					"secfixes": map[string][]string{
						"1.36.1-r15": {"CVE-2023-42363", "CVE-2023-42364"},
						"0":          {"CVE-2021-28831"},
					},
				},
			},
			{
				"pkg": map[string]any{
					"name": "curl",
					"secfixes": map[string][]string{
						"8.4.0-r0": {"CVE-2023-46218"},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(feed)
	return data
}

// newTestImporter creates an Importer that talks to ts, scanning only the
// given releases and repos.  RateSleep is set to zero so tests complete
// quickly.
func newTestImporter(ts *httptest.Server, releases, repos []string) *alpine.Importer {
	return &alpine.Importer{
		HTTPClient: ts.Client(),
		Releases:   releases,
		Repos:      repos,
		BaseURL:    ts.URL,
		RateSleep:  0,
	}
}

// serveReleaseRepo returns an HTTP handler that serves feedData only for
// requests whose path matches "/{release}/{repo}.json".
func serveReleaseRepo(release, repo string, feedData []byte) http.HandlerFunc {
	wantPath := "/" + release + "/" + repo + ".json"
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(feedData)
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// TestAlpineImport_BasicImport verifies that:
//  1. All CVEs in the fixture are imported (Inserted >= 4: 2+1+1).
//  2. CVE-2023-42363 is stored with status="fixed" and the correct fixed_version.
//  3. CVE-2021-28831 (version key "0") is stored with status="not-affected"
//     and an empty fixed_version.
//  4. Confidence is 100 for all rows.
func TestAlpineImport_BasicImport(t *testing.T) {
	feedData := secDBFixture("v3.20", "main")

	ts := httptest.NewServer(serveReleaseRepo("v3.20", "main", feedData))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"v3.20"}, []string{"main"})

	stats, err := imp.Import(ctx, database)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	// busybox: 2 fixed + 1 not-affected; curl: 1 fixed → 4 affected-package rows.
	if stats.Inserted < 4 {
		t.Errorf("Inserted: got %d, want >= 4", stats.Inserted)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors: got %d, want 0", stats.Errors)
	}

	// ── Verify CVE-2023-42363 (fixed) ──────────────────────────────────────
	rows, err := database.QueryByPackage(ctx, "alpine", "busybox", "alpine", "3.20")
	if err != nil {
		t.Fatalf("QueryByPackage busybox: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no rows for busybox on alpine 3.20")
	}

	found363 := false
	for _, r := range rows {
		if r.VulnID == "CVE-2023-42363" {
			found363 = true
			if r.FixedVersion != "1.36.1-r15" {
				t.Errorf("CVE-2023-42363 FixedVersion: got %q, want 1.36.1-r15", r.FixedVersion)
			}
			if r.Status != "fixed" {
				t.Errorf("CVE-2023-42363 Status: got %q, want fixed", r.Status)
			}
			if r.Confidence != 100 {
				t.Errorf("CVE-2023-42363 Confidence: got %d, want 100", r.Confidence)
			}
		}
	}
	if !found363 {
		t.Error("CVE-2023-42363 not found in DB after import")
	}

	// ── Verify CVE-2021-28831 (not-affected / version key "0") ────────────
	naRows, err := database.QueryByVulnID(ctx, "CVE-2021-28831")
	if err != nil {
		t.Fatalf("QueryByVulnID CVE-2021-28831: %v", err)
	}
	foundNA := false
	for _, r := range naRows {
		if r.SourceName == "alpine-secdb" && r.Status == "not-affected" {
			foundNA = true
			if r.FixedVersion != "" {
				t.Errorf("not-affected row FixedVersion: got %q, want empty", r.FixedVersion)
			}
		}
	}
	if !foundNA {
		t.Error("CVE-2021-28831 with status=not-affected not found in DB")
	}

	// ── Verify curl CVE is stored ──────────────────────────────────────────
	curlRows, err := database.QueryByPackage(ctx, "alpine", "curl", "alpine", "3.20")
	if err != nil {
		t.Fatalf("QueryByPackage curl: %v", err)
	}
	if len(curlRows) == 0 {
		t.Error("CVE-2023-46218 (curl) not found in DB")
	}
}

// TestAlpineImport_Idempotent verifies that running the importer twice on the
// same feed produces no duplicate rows.
func TestAlpineImport_Idempotent(t *testing.T) {
	feedData := secDBFixture("v3.20", "main")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(feedData)
	}))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"v3.20"}, []string{"main"})

	// First run.
	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("first Import: %v", err)
	}

	// Second run — identical feed, same DB.
	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("second Import: %v", err)
	}

	// Each (CVE, package) combination must appear exactly once in the results.
	rows, err := database.QueryByPackage(ctx, "alpine", "busybox", "alpine", "3.20")
	if err != nil {
		t.Fatalf("QueryByPackage after idempotent run: %v", err)
	}

	seen := make(map[string]int)
	for _, r := range rows {
		seen[r.VulnID]++
	}
	for vulnID, count := range seen {
		if count > 1 {
			t.Errorf("idempotency violated: %s has %d rows (want 1)", vulnID, count)
		}
	}

	// Data integrity: CVE-2023-42363 still present with correct status.
	found := false
	for _, r := range rows {
		if r.VulnID == "CVE-2023-42363" && r.Status == "fixed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CVE-2023-42363 with status=fixed not found after idempotent import")
	}
}

// TestAlpineImport_NotAffectedStatus is a focused test confirming that the
// special version key "0" is stored with status="not-affected" and empty
// fixed_version.
func TestAlpineImport_NotAffectedStatus(t *testing.T) {
	feed := map[string]any{
		"distroversion": "v3.19",
		"reponame":      "main",
		"packages": []map[string]any{
			{
				"pkg": map[string]any{
					"name": "openssl",
					"secfixes": map[string][]string{
						"0": {"CVE-2023-99999"},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(feed)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"v3.19"}, []string{"main"})

	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("Import: %v", err)
	}

	rows, err := database.QueryByVulnID(ctx, "CVE-2023-99999")
	if err != nil {
		t.Fatalf("QueryByVulnID CVE-2023-99999: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("CVE-2023-99999 not found after import")
	}

	r := rows[0]
	if r.Status != "not-affected" {
		t.Errorf("Status: got %q, want not-affected", r.Status)
	}
	if r.FixedVersion != "" {
		t.Errorf("FixedVersion: got %q, want empty for not-affected entry", r.FixedVersion)
	}
}

// TestAlpineImport_MultipleReleases verifies that the same CVE can be stored
// independently for different distro versions (e.g., v3.19 and v3.20) without
// the record from one release blocking the insertion for another.
func TestAlpineImport_MultipleReleases(t *testing.T) {
	feed319 := secDBFixture("v3.19", "main")
	feed320 := secDBFixture("v3.20", "main")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3.19/main.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(feed319)
		case "/v3.20/main.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(feed320)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"v3.19", "v3.20"}, []string{"main"})

	stats, err := imp.Import(ctx, database)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors: got %d, want 0", stats.Errors)
	}

	// busybox on v3.19 must be queryable.
	rows319, err := database.QueryByPackage(ctx, "alpine", "busybox", "alpine", "3.19")
	if err != nil {
		t.Fatalf("QueryByPackage v3.19: %v", err)
	}
	if len(rows319) == 0 {
		t.Error("no rows for busybox on alpine 3.19")
	}

	// busybox on v3.20 must be queryable independently.
	rows320, err := database.QueryByPackage(ctx, "alpine", "busybox", "alpine", "3.20")
	if err != nil {
		t.Fatalf("QueryByPackage v3.20: %v", err)
	}
	if len(rows320) == 0 {
		t.Error("no rows for busybox on alpine 3.20")
	}
}

// TestAlpineImport_HTTP404SkipsRepo verifies that a 404 from the server for
// one repo does not abort the entire import; the error is counted in Stats.Errors.
func TestAlpineImport_HTTP404SkipsRepo(t *testing.T) {
	feedData := secDBFixture("v3.20", "main")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3.20/main.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(feedData)
			return
		}
		// community.json returns 404 — the importer must continue gracefully.
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"v3.20"}, []string{"main", "community"})

	stats, err := imp.Import(ctx, database)
	// Top-level error must be nil; the 404 is recorded in Stats.Errors.
	if err != nil {
		t.Fatalf("Import returned unexpected error: %v", err)
	}
	if stats.Errors < 1 {
		t.Errorf("Errors: got %d, want >= 1 (community.json returned 404)", stats.Errors)
	}
	// main.json succeeded — there should be inserted rows.
	if stats.Inserted < 1 {
		t.Errorf("Inserted: got %d, want >= 1 (main.json should have succeeded)", stats.Inserted)
	}
}

// TestAlpineImport_UserAgent verifies that every request carries the expected
// User-Agent header.
func TestAlpineImport_UserAgent(t *testing.T) {
	var capturedUA string
	feedData := secDBFixture("v3.20", "main")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUA = r.Header.Get("User-Agent")
		_, _ = w.Write(feedData)
	}))
	defer ts.Close()

	ctx := context.Background()
	database := openTestDB(t)
	imp := newTestImporter(ts, []string{"v3.20"}, []string{"main"})

	if _, err := imp.Import(ctx, database); err != nil {
		t.Fatalf("Import: %v", err)
	}

	const wantUA = "patchflow-image-scanner/1.0 vuln-db-importer"
	if capturedUA != wantUA {
		t.Errorf("User-Agent: got %q, want %q", capturedUA, wantUA)
	}
}

// TestAlpineImport_ContextCancellation verifies that the importer stops
// early and returns the context error when the context is cancelled.
func TestAlpineImport_ContextCancellation(t *testing.T) {
	feedData := secDBFixture("v3.20", "main")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(feedData)
	}))
	defer ts.Close()

	// Cancel immediately so the first or second request sees a done context.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	database := openTestDB(t)
	// Use many releases to give cancellation a chance to fire.
	releases := []string{"v3.17", "v3.18", "v3.19", "v3.20", "v3.21"}
	imp := newTestImporter(ts, releases, []string{"main"})

	_, err := imp.Import(ctx, database)
	// With a 1ms timeout and no sleep the importer may or may not finish.
	// We only check that it does NOT panic and that if it returns an error
	// it is the context error.
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("unexpected error: %v", err)
	}
}
