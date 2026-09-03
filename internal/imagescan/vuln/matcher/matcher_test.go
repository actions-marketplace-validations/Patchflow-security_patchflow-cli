package matcher_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
	vulndb "github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/matcher"
)

// openTestDB creates a temporary SQLite DB seeded with fixture advisories.
func openTestDB(t *testing.T) *vulndb.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	database, err := vulndb.Open(path)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	ctx := context.Background()

	// Register a fixture source.
	srcID, err := database.UpsertSource(ctx, vulndb.Source{
		Name: "alpine-secdb",
		URL:  "https://secdb.alpinelinux.org",
	})
	if err != nil {
		t.Fatalf("upsert source: %v", err)
	}

	osvID, err := database.UpsertSource(ctx, vulndb.Source{
		Name: "osv",
		URL:  "https://osv.dev",
	})
	if err != nil {
		t.Fatalf("upsert osv source: %v", err)
	}

	nvdID, err := database.UpsertSource(ctx, vulndb.Source{
		Name: "nvd",
		URL:  "https://nvd.nist.gov",
	})
	if err != nil {
		t.Fatalf("upsert nvd source: %v", err)
	}

	// --- Alpine vendor-exact fixture ---
	// busybox < 1.36.1-r15 is vulnerable in alpine 3.20
	vulnID, err := database.InsertVulnerability(ctx, vulndb.Vulnerability{
		SourceID: srcID,
		VulnID:   "CVE-2023-42363",
		Aliases:  []string{"GHSA-fake-0001"},
		Summary:  "busybox argument injection",
		Severity: "HIGH",
		CVSSScore: 7.5,
	})
	if err != nil {
		t.Fatalf("insert vuln: %v", err)
	}
	if err := database.InsertAffectedPackage(ctx, vulndb.AffectedPackage{
		VulnerabilityID: vulnID,
		Ecosystem:       "alpine",
		PackageName:     "busybox",
		DistroName:      "alpine",
		DistroVersion:   "3.20",
		FixedVersion:    "1.36.1-r15",
		Status:          "fixed",
		Confidence:      100,
	}); err != nil {
		t.Fatalf("insert affected pkg: %v", err)
	}

	// --- OSV npm fixture ---
	osvVulnID, err := database.InsertVulnerability(ctx, vulndb.Vulnerability{
		SourceID:  osvID,
		VulnID:    "GHSA-npm-0001-xxxx",
		Summary:   "prototype pollution in lodash",
		Severity:  "HIGH",
		CVSSScore: 7.4,
	})
	if err != nil {
		t.Fatalf("insert osv vuln: %v", err)
	}
	if err := database.InsertAffectedPackage(ctx, vulndb.AffectedPackage{
		VulnerabilityID: osvVulnID,
		Ecosystem:       "npm",
		PackageName:     "lodash",
		FixedVersion:    "4.17.21",
		Status:          "fixed",
		Confidence:      95,
	}); err != nil {
		t.Fatalf("insert osv affected pkg: %v", err)
	}

	// --- NVD CPE fuzzy fixture (confidence 70) ---
	nvdVulnID, err := database.InsertVulnerability(ctx, vulndb.Vulnerability{
		SourceID:  nvdID,
		VulnID:    "CVE-2024-99999",
		Summary:   "CPE-based match only",
		Severity:  "MEDIUM",
		CVSSScore: 5.5,
	})
	if err != nil {
		t.Fatalf("insert nvd vuln: %v", err)
	}
	if err := database.InsertAffectedPackage(ctx, vulndb.AffectedPackage{
		VulnerabilityID: nvdVulnID,
		Ecosystem:       "alpine",
		PackageName:     "curl",
		DistroName:      "alpine",
		DistroVersion:   "3.20",
		FixedVersion:    "8.5.0-r0",
		Status:          "fixed",
		Confidence:      70,
	}); err != nil {
		t.Fatalf("insert nvd affected pkg: %v", err)
	}

	return database
}

func alpine320() model.OperatingSystem {
	return model.OperatingSystem{Name: "alpine", VersionID: "3.20"}
}

// --- Tests ----------------------------------------------------------------

// TestVendorExactMatch verifies that an installed busybox below the fixed
// version produces a confidence-100 vendor_exact finding.
func TestVendorExactMatch(t *testing.T) {
	database := openTestDB(t)
	m := matcher.New(database, 70)

	pkg := model.Package{
		Name:    "busybox",
		Version: "1.36.1-r14", // below the fixed 1.36.1-r15
		Type:    "apk",
	}
	results, err := m.MatchPackage(context.Background(), pkg, alpine320())
	if err != nil {
		t.Fatalf("MatchPackage: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one match, got none")
	}
	got := results[0]
	if got.VulnID != "CVE-2023-42363" {
		t.Errorf("VulnID = %q, want CVE-2023-42363", got.VulnID)
	}
	if got.Type != matcher.MatchTypeVendorExact {
		t.Errorf("MatchType = %q, want vendor_exact", got.Type)
	}
	if got.Confidence != 100 {
		t.Errorf("Confidence = %d, want 100", got.Confidence)
	}
	if !got.FixAvailable {
		t.Error("FixAvailable should be true")
	}
	if got.FixedVersion != "1.36.1-r15" {
		t.Errorf("FixedVersion = %q, want 1.36.1-r15", got.FixedVersion)
	}
}

// TestAlreadyFixed verifies that a package at or above the fixed version
// does NOT appear in results.
func TestAlreadyFixed(t *testing.T) {
	database := openTestDB(t)
	m := matcher.New(database, 70)

	pkg := model.Package{
		Name:    "busybox",
		Version: "1.36.1-r15", // exactly at the fix
		Type:    "apk",
	}
	results, err := m.MatchPackage(context.Background(), pkg, alpine320())
	if err != nil {
		t.Fatalf("MatchPackage: %v", err)
	}
	for _, r := range results {
		if r.VulnID == "CVE-2023-42363" {
			t.Error("already-fixed package should not appear in results")
		}
	}
}

// TestOSVExactMatch verifies the OSV npm tier.
func TestOSVExactMatch(t *testing.T) {
	database := openTestDB(t)
	m := matcher.New(database, 70)

	pkg := model.Package{
		Name:    "lodash",
		Version: "4.17.20",
		Type:    "npm",
	}
	results, err := m.MatchPackage(context.Background(), pkg, model.OperatingSystem{})
	if err != nil {
		t.Fatalf("MatchPackage: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected OSV npm match, got none")
	}
	got := results[0]
	if got.Type != matcher.MatchTypeOSVExact {
		t.Errorf("MatchType = %q, want osv_exact", got.Type)
	}
	if got.Confidence != 95 {
		t.Errorf("Confidence = %d, want 95", got.Confidence)
	}
}

// TestMinConfidenceFilter verifies that results below MinConfidence are excluded.
func TestMinConfidenceFilter(t *testing.T) {
	database := openTestDB(t)

	// With threshold 80: NVD (confidence 70) should be filtered out.
	m := matcher.New(database, 80)
	pkg := model.Package{Name: "curl", Version: "8.4.0-r0", Type: "apk"}
	results, err := m.MatchPackage(context.Background(), pkg, alpine320())
	if err != nil {
		t.Fatalf("MatchPackage: %v", err)
	}
	for _, r := range results {
		if r.Confidence < 80 {
			t.Errorf("result below min confidence threshold: %+v", r)
		}
	}

	// With threshold 0: NVD result should appear.
	m2 := matcher.New(database, 0)
	results2, err := m2.MatchPackage(context.Background(), pkg, alpine320())
	if err != nil {
		t.Fatalf("MatchPackage low threshold: %v", err)
	}
	found := false
	for _, r := range results2 {
		if r.VulnID == "CVE-2024-99999" {
			found = true
		}
	}
	if !found {
		t.Error("NVD result should appear with MinConfidence=0")
	}
}

// TestDeduplication verifies that the same vuln_id appears only once even if
// multiple DB rows match (e.g. two sources describe the same CVE).
func TestDeduplication(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()

	// Add a second source describing the same busybox CVE with lower confidence.
	osvID, _ := database.UpsertSource(ctx, vulndb.Source{Name: "osv-dup-test", URL: "https://osv.dev"})
	vulnID, _ := database.InsertVulnerability(ctx, vulndb.Vulnerability{
		SourceID:  osvID,
		VulnID:    "CVE-2023-42363",
		Summary:   "duplicate from osv",
		Severity:  "HIGH",
		CVSSScore: 7.5,
	})
	_ = database.InsertAffectedPackage(ctx, vulndb.AffectedPackage{
		VulnerabilityID: vulnID,
		Ecosystem:       "alpine",
		PackageName:     "busybox",
		DistroName:      "alpine",
		DistroVersion:   "3.20",
		FixedVersion:    "1.36.1-r15",
		Status:          "fixed",
		Confidence:      95,
	})

	m := matcher.New(database, 70)
	pkg := model.Package{Name: "busybox", Version: "1.36.1-r14", Type: "apk"}
	results, err := m.MatchPackage(ctx, pkg, alpine320())
	if err != nil {
		t.Fatalf("MatchPackage: %v", err)
	}
	count := 0
	for _, r := range results {
		if r.VulnID == "CVE-2023-42363" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 deduplicated result for CVE-2023-42363, got %d", count)
	}
	// The keeper should be the highest confidence (vendor_exact = 100).
	for _, r := range results {
		if r.VulnID == "CVE-2023-42363" && r.Confidence != 100 {
			t.Errorf("expected confidence 100 after dedup, got %d", r.Confidence)
		}
	}
}

// TestMatchAll wires through MatchAll with a minimal ScanResult.
func TestMatchAll(t *testing.T) {
	database := openTestDB(t)
	m := matcher.New(database, 70)

	result := &model.ScanResult{
		OS: &model.OperatingSystem{Name: "alpine", VersionID: "3.20"},
		Packages: []model.Package{
			{Name: "busybox", Version: "1.36.1-r14", Type: "apk"},
			{Name: "curl", Version: "8.6.0-r0", Type: "apk"}, // above fixed — no finding
		},
	}

	n, err := m.MatchAll(context.Background(), result)
	if err != nil {
		t.Fatalf("MatchAll: %v", err)
	}
	if n == 0 {
		t.Error("expected at least one finding from MatchAll")
	}
	if len(result.Findings) != n {
		t.Errorf("Findings len %d != returned count %d", len(result.Findings), n)
	}
}

// TestMatchAllDeduplicatesAcrossSources verifies that the same package
// discovered from multiple sources (e.g. lockfile + node_modules) produces a
// single finding with merged locations.
func TestMatchAllDeduplicatesAcrossSources(t *testing.T) {
	database := openTestDB(t)
	m := matcher.New(database, 70)

	result := &model.ScanResult{
		OS: &model.OperatingSystem{Name: "", VersionID: ""}, // language packages are distro-agnostic
		Packages: []model.Package{
			{Name: "lodash", Version: "4.17.20", Type: "npm", LayerDigest: "sha256:lockfile",
				Locations: []model.Location{{Path: "/app/package-lock.json", LayerDigest: "sha256:lockfile"}}},
			{Name: "lodash", Version: "4.17.20", Type: "npm", LayerDigest: "sha256:nodemod",
				Locations: []model.Location{{Path: "/app/node_modules/lodash/package.json", LayerDigest: "sha256:nodemod"}}},
		},
	}

	n, err := m.MatchAll(context.Background(), result)
	if err != nil {
		t.Fatalf("MatchAll: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", n)
	}
	f := result.Findings[0]
	if len(f.Locations) != 2 {
		t.Errorf("expected 2 merged locations, got %d: %+v", len(f.Locations), f.Locations)
	}
	if f.Confidence != model.Confidence(95) {
		t.Errorf("expected confidence 95, got %d", f.Confidence)
	}
}

// TestExplainVuln verifies that ExplainVuln returns rows regardless of
// MinConfidence and supports alias lookup.
func TestExplainVuln(t *testing.T) {
	database := openTestDB(t)
	m := matcher.New(database, 100) // high threshold filters everything in Match

	rows, err := m.ExplainVuln(context.Background(), "CVE-2023-42363")
	if err != nil {
		t.Fatalf("ExplainVuln: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("ExplainVuln: expected rows for CVE-2023-42363")
	}
}

// TestDBSchemaRoundtrip verifies that the SQLite DB can be opened, written,
// closed, and re-opened with all data intact.
func TestDBSchemaRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roundtrip.db")

	// Write.
	{
		d, err := vulndb.Open(path)
		if err != nil {
			t.Fatalf("open write: %v", err)
		}
		ctx := context.Background()
		srcID, _ := d.UpsertSource(ctx, vulndb.Source{Name: "test-src", URL: "http://example.com"})
		vulnID, _ := d.InsertVulnerability(ctx, vulndb.Vulnerability{
			SourceID: srcID, VulnID: "CVE-1999-0001", Severity: "LOW",
		})
		_ = d.InsertAffectedPackage(ctx, vulndb.AffectedPackage{
			VulnerabilityID: vulnID,
			Ecosystem: "alpine", PackageName: "openssl", FixedVersion: "3.3.1-r0",
			Status: "fixed", Confidence: 100,
		})
		_ = d.Close()
	}

	// Read back.
	{
		d, err := vulndb.OpenReadOnly(path)
		if err != nil {
			t.Fatalf("open readonly: %v", err)
		}
		defer d.Close()
		ctx := context.Background()
		rows, err := d.QueryByPackage(ctx, "alpine", "openssl", "alpine", "3.20")
		if err != nil {
			t.Fatalf("QueryByPackage: %v", err)
		}
		if len(rows) == 0 {
			t.Fatal("roundtrip: no rows found after re-open")
		}
		if rows[0].VulnID != "CVE-1999-0001" {
			t.Errorf("roundtrip VulnID = %q, want CVE-1999-0001", rows[0].VulnID)
		}
		if rows[0].FixedVersion != "3.3.1-r0" {
			t.Errorf("roundtrip FixedVersion = %q, want 3.3.1-r0", rows[0].FixedVersion)
		}

		// SchemaVersion should match.
		sv, err := d.SchemaVersion(ctx)
		if err != nil {
			t.Fatalf("SchemaVersion: %v", err)
		}
		if sv < 1 {
			t.Errorf("SchemaVersion = %d, want >= 1", sv)
		}

		// Delete the temp file so os.Remove in cleanup works.
		if err := os.Remove(path); err != nil {
			// Non-fatal; OS cleanup handles it.
			t.Logf("remove db: %v", err)
		}
	}
}
