package ubuntu_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db/ubuntu"
)

// fixtureOVAL is a minimal OVAL XML document that exercises the importer.
// It contains two definitions:
//   - CVE-2024-1001 (vulnerability) → libcurl4 fixed at 7.68.0-1ubuntu2.22
//   - CVE-2024-1002 (vulnerability) → two packages: openssl + libssl1.1
//   - An "inventory" class definition that should be skipped
const fixtureOVAL = `<?xml version="1.0" encoding="utf-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
    <definition id="oval:com.ubuntu.focal:def:100" class="vulnerability">
      <metadata>
        <title>CVE-2024-1001 on Ubuntu 20.04 LTS (focal) - high</title>
        <advisory>
          <severity>High</severity>
          <cve href="https://ubuntu.com/security/CVE-2024-1001"
               priority="high"
               public="20240101"
               cvss_score="7.5"
               cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N">CVE-2024-1001</cve>
        </advisory>
      </metadata>
      <criteria>
        <criterion test_ref="oval:com.ubuntu.focal:tst:1001"
                   comment="libcurl4 - 7.68.0-1ubuntu2.22 is installed"/>
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.focal:def:101" class="vulnerability">
      <metadata>
        <title>CVE-2024-1002 on Ubuntu 20.04 LTS (focal) - medium</title>
        <advisory>
          <severity>Medium</severity>
          <cve href="https://ubuntu.com/security/CVE-2024-1002"
               priority="medium"
               public="20240201"
               cvss_score="5.9"
               cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N">CVE-2024-1002</cve>
        </advisory>
      </metadata>
      <criteria operator="OR">
        <criterion test_ref="oval:com.ubuntu.focal:tst:1002a"
                   comment="openssl - 1.1.1f-1ubuntu2.23 is installed"/>
        <criterion test_ref="oval:com.ubuntu.focal:tst:1002b"
                   comment="libssl1.1 - 1.1.1f-1ubuntu2.23 is installed"/>
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.focal:def:102" class="inventory">
      <metadata>
        <title>Ubuntu 20.04 LTS (focal) is installed</title>
        <advisory>
          <severity>None</severity>
        </advisory>
      </metadata>
      <criteria>
        <criterion test_ref="oval:com.ubuntu.focal:tst:os"
                   comment="Ubuntu focal is installed"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`

// compressBzip2 compresses data using the system bzip2 binary.
// The test is skipped if bzip2 is not found in PATH.
func compressBzip2(t *testing.T, data []byte) []byte {
	t.Helper()
	path, err := exec.LookPath("bzip2")
	if err != nil {
		t.Skip("bzip2 binary not found in PATH — install bzip2 to run this test")
	}
	cmd := exec.Command(path, "-c")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("bzip2 compression failed: %v", err)
	}
	return out
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

func TestName(t *testing.T) {
	imp := ubuntu.New()
	if imp.Name() != "ubuntu-oval" {
		t.Errorf("Name() = %q, want %q", imp.Name(), "ubuntu-oval")
	}
}

func TestImport(t *testing.T) {
	compressed := compressBzip2(t, []byte(fixtureOVAL))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-bzip2")
		_, _ = w.Write(compressed)
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := ubuntu.New()
	imp.HTTPClient = srv.Client()
	// Override releases to a single focal entry pointing at the test server.
	imp.Releases = []ubuntu.Release{
		{Codename: "focal", Version: "20.04", URL: srv.URL + "/focal.bz2"},
	}

	ctx := context.Background()
	stats, err := imp.Import(ctx, database)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	if stats.Source != "ubuntu-oval" {
		t.Errorf("stats.Source = %q, want %q", stats.Source, "ubuntu-oval")
	}
	if stats.Errors != 0 {
		t.Errorf("stats.Errors = %d, want 0", stats.Errors)
	}

	// Expected inserted:
	//   CVE-2024-1001 → 1 package (libcurl4) → 1 row
	//   CVE-2024-1002 → 2 packages (openssl, libssl1.1) → 2 rows
	//   inventory definition → skipped
	// Total: 3 rows
	if stats.Inserted != 3 {
		t.Errorf("stats.Inserted = %d, want 3", stats.Inserted)
	}

	// The inventory class definition should be counted as skipped.
	if stats.Skipped == 0 {
		t.Error("expected at least 1 skipped (inventory class), got 0")
	}
}

func TestImportPackageExtraction(t *testing.T) {
	// Verify the "can be fixed by installing pkg=version" comment format.
	const fixFormatXML = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition id="oval:test:def:1" class="vulnerability">
      <metadata>
        <title>CVE-2024-9999 on Ubuntu 22.04 LTS (jammy) - low</title>
        <advisory>
          <severity>Low</severity>
          <cve cvss_score="3.1" cvss_vector="CVSS:3.1/AV:N">CVE-2024-9999</cve>
        </advisory>
      </metadata>
      <criteria>
        <criterion test_ref="tst:1"
                   comment="nginx in Ubuntu jammy can be fixed by installing nginx=1.18.0-6ubuntu14.5"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`

	compressed := compressBzip2(t, []byte(fixFormatXML))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-bzip2")
		_, _ = w.Write(compressed)
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := ubuntu.New()
	imp.HTTPClient = srv.Client()
	imp.Releases = []ubuntu.Release{
		{Codename: "jammy", Version: "22.04", URL: srv.URL + "/jammy.bz2"},
	}

	stats, err := imp.Import(context.Background(), database)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if stats.Errors != 0 {
		t.Errorf("stats.Errors = %d, want 0", stats.Errors)
	}
	if stats.Inserted != 1 {
		t.Errorf("stats.Inserted = %d, want 1", stats.Inserted)
	}

	// Query to verify the package name and version were parsed correctly.
	rows, err := database.QueryByPackage(context.Background(), "deb", "nginx", "ubuntu", "22.04")
	if err != nil {
		t.Fatalf("QueryByPackage: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected at least one affected row for nginx, got none")
	}
	if rows[0].VulnID != "CVE-2024-9999" {
		t.Errorf("VulnID = %q, want %q", rows[0].VulnID, "CVE-2024-9999")
	}
	if rows[0].FixedVersion != "1.18.0-6ubuntu14.5" {
		t.Errorf("FixedVersion = %q, want %q", rows[0].FixedVersion, "1.18.0-6ubuntu14.5")
	}
}

func TestImportIdempotent(t *testing.T) {
	compressed := compressBzip2(t, []byte(fixtureOVAL))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-bzip2")
		_, _ = w.Write(compressed)
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := ubuntu.New()
	imp.HTTPClient = srv.Client()
	imp.Releases = []ubuntu.Release{
		{Codename: "focal", Version: "20.04", URL: srv.URL + "/focal.bz2"},
	}

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

func TestImportBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	database := newTestDB(t)
	imp := ubuntu.New()
	imp.HTTPClient = srv.Client()
	imp.Releases = []ubuntu.Release{
		{Codename: "focal", Version: "20.04", URL: srv.URL + "/focal.bz2"},
	}

	stats, err := imp.Import(context.Background(), database)
	// Release errors are accumulated in stats.Errors, not returned as fatal.
	if err != nil {
		t.Fatalf("Import returned fatal error: %v", err)
	}
	if stats.Errors == 0 {
		t.Error("expected stats.Errors > 0 for 404 response, got 0")
	}
}
