// Package matcher implements the PatchFlow vendor-first vulnerability matcher.
//
// The matcher's job is to answer: "given a cataloged package and an installed
// version, which advisory records apply, how confident are we, and why?"
// It is deliberately explainable — every MatchResult carries the full
// evidence chain so the explain command (and CI output) can show the user
// exactly why a finding was raised, not just a CVE number.
//
// Match tiers (ordered by precision, highest confidence first):
//
//	100  vendor-exact   — vendor advisory (Alpine SecDB, Debian, Ubuntu) exact
//	                      package name + distro version match
//	 95  osv-exact      — OSV ecosystem-exact match (package + ecosystem + range)
//	 85  source-pkg     — Debian/Ubuntu source-package match (binary differs from src)
//	 70  cpe-fuzzy      — NVD CPE match (no distro confirmation)
//	 50  name-fuzzy     — package name match across ecosystems (audit-only)
//
// Only tiers >= 70 produce Findings by default. The explain command shows
// all tiers including lower-confidence ones.
package matcher

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/version"
)

// MatchType identifies which evidence tier produced a match.
type MatchType string

const (
	MatchTypeVendorExact  MatchType = "vendor_exact"   // confidence 100
	MatchTypeOSVExact     MatchType = "osv_exact"       // confidence 95
	MatchTypeSourcePkg    MatchType = "source_package"  // confidence 85
	MatchTypeCPEFuzzy     MatchType = "cpe_fuzzy"       // confidence 70
	MatchTypeNameFuzzy    MatchType = "name_fuzzy"       // confidence 50
)

// Evidence is one piece of reasoning that contributed to a match.
type Evidence struct {
	Source     string // "alpine-secdb", "osv", "debian-security", "ubuntu-oval", "nvd"
	VulnID     string // canonical ID from that source
	MatchField string // "package_name", "source_package", "cpe_product"
	MatchValue string // the value that matched
}

// MatchResult is a single vulnerability match for one package.
// Callers project this into model.Finding for output.
type MatchResult struct {
	// Identity
	VulnID      string
	Aliases     []string
	Summary     string
	Severity    string
	CVSSScore   float64

	// Match metadata
	Type        MatchType
	Confidence  int
	Evidence    []Evidence

	// Fix information
	FixAvailable    bool
	FixedVersion    string
	AffectedRange   string

	// Package context (copied from the matched Package)
	PackageName      string
	PackageType      string
	InstalledVersion string
	LayerDigest      string
	LayerCreatedBy   string

	// Recommendation populated by the caller (layerblame — Phase 4).
	Recommendation string
}

// Matcher performs vulnerability matching against the embedded SQLite DB.
type Matcher struct {
	db       *db.DB
	versions *version.Registry
	// MinConfidence is the threshold below which matches are not returned by
	// Match(). Use ExplainPackage() to get all tiers including lower ones.
	MinConfidence int
}

// New returns a Matcher backed by the given DB. minConfidence should be 70
// for CI/scanning use-cases (omit CPE-fuzzy and name-fuzzy audit findings).
func New(database *db.DB, minConfidence int) *Matcher {
	return &Matcher{
		db:            database,
		versions:      version.NewRegistry(),
		MinConfidence: minConfidence,
	}
}

// MatchPackage runs all tiers against a single Package and returns deduplicated
// MatchResults ordered by confidence descending.
func (m *Matcher) MatchPackage(ctx context.Context, pkg model.Package, os model.OperatingSystem) ([]MatchResult, error) {
	eco, distroName, distroVersion := resolveEcosystem(pkg, os)

	var all []MatchResult

	// Tier 1 + 2: vendor-exact and OSV-exact via package name lookup.
	rows, err := m.db.QueryByPackage(ctx, eco, pkg.Name, distroName, distroVersion)
	if err != nil {
		return nil, fmt.Errorf("query by package %s: %w", pkg.Name, err)
	}
	for _, row := range rows {
		mt, conf := classifyMatch(row.SourceName, distroName)
		if !m.versionAffected(eco, pkg.Version, row) {
			continue
		}
		all = append(all, buildResult(pkg, row, mt, conf, "package_name", pkg.Name))
	}

	// Tier 3: source-package lookup (Debian/Ubuntu binary vs source name).
	if pkg.SourcePackage != "" && pkg.SourcePackage != pkg.Name {
		srcRows, err := m.db.QueryBySourcePackage(ctx, pkg.SourcePackage, distroName, distroVersion)
		if err != nil {
			return nil, fmt.Errorf("query by source pkg %s: %w", pkg.SourcePackage, err)
		}
		for _, row := range srcRows {
			if !m.versionAffected(eco, pkg.Version, row) {
				continue
			}
			all = append(all, buildResult(pkg, row, MatchTypeSourcePkg, 85, "source_package", pkg.SourcePackage))
		}
	}

	// Within a single package, the same CVE may be reported by multiple sources.
	// Keep the most authoritative one.
	deduped := deduplicate(all)
	return m.filter(deduped), nil
}

// MatchAll runs MatchPackage for every package in a ScanResult and appends
// deduplicated Findings back to it. Returns the number of findings added.
//
// Deduplication merges findings for the same (vulnerability, package, ecosystem)
// pair that were discovered via different sources (e.g. package-lock.json and
// node_modules). The highest-confidence match is kept and Locations from all
// sources are merged.
func (m *Matcher) MatchAll(ctx context.Context, result *model.ScanResult) (int, error) {
	if result.OS == nil {
		return 0, nil
	}
	os := *result.OS
	raw := make([]model.Finding, 0, len(result.Findings)+len(result.Packages))
	for _, pkg := range result.Packages {
		matches, err := m.MatchPackage(ctx, pkg, os)
		if err != nil {
			return 0, err
		}
		for _, mr := range matches {
			raw = append(raw, toFinding(mr))
		}
	}
	deduped := dedupFindings(raw)
	result.Findings = append(result.Findings, deduped...)
	return len(deduped), nil
}

// dedupFindings merges findings for the same (vuln_id, package_name, ecosystem)
// tuple, keeping the highest-confidence match and merging Locations from all
// sources. This prevents duplicate CVE reports when a package is discovered
// from both a lockfile and the installed tree.
func dedupFindings(findings []model.Finding) []model.Finding {
	type key struct {
		vulnID, pkgName, ecosystem string
	}
	best := make(map[key]model.Finding, len(findings))
	for _, f := range findings {
		k := key{f.VulnerabilityID, f.PackageName, f.PackageType}
		existing, ok := best[k]
		if !ok {
			best[k] = f
			continue
		}
		// Keep the highest-confidence finding; merge Locations either way.
		keep, drop := existing, f
		if f.Confidence > existing.Confidence {
			keep, drop = f, existing
		}
		keep.Locations = mergeLocations(keep.Locations, drop.Locations)
		best[k] = keep
	}
	out := make([]model.Finding, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	return out
}

// mergeLocations returns a slice containing all unique locations from a and b,
// preserving order from a.
func mergeLocations(a, b []model.Location) []model.Location {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]model.Location, 0, len(a)+len(b))
	for _, l := range a {
		k := l.Path + "\x00" + l.LayerDigest
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, l)
	}
	for _, l := range b {
		k := l.Path + "\x00" + l.LayerDigest
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, l)
	}
	return out
}

// ExplainVuln returns all affected-package rows for a vuln ID, regardless of
// confidence threshold, for use by the explain subcommand.
func (m *Matcher) ExplainVuln(ctx context.Context, vulnID string) ([]db.AffectedRow, error) {
	return m.db.QueryByVulnID(ctx, vulnID)
}

// ExplainPackage returns ALL match tiers (including below MinConfidence) for
// a single package, for use by the explain subcommand.
func (m *Matcher) ExplainPackage(ctx context.Context, pkg model.Package, os model.OperatingSystem) ([]MatchResult, error) {
	orig := m.MinConfidence
	m.MinConfidence = 0
	defer func() { m.MinConfidence = orig }()
	return m.MatchPackage(ctx, pkg, os)
}

// --- internal helpers -----------------------------------------------------

// resolveEcosystem maps a Package to the ecosystem + distro name/version
// used in DB queries. OS packages use distro-specific ecosystems.
func resolveEcosystem(pkg model.Package, os model.OperatingSystem) (eco, distroName, distroVersion string) {
	ver := os.VersionID
	switch pkg.Type {
	case "apk":
		return "alpine", "alpine", ver
	case "deb":
		distro := strings.ToLower(os.Name)
		if distro == "" {
			distro = "debian"
		}
		return "deb", distro, ver
	case "rpm":
		return "rpm", strings.ToLower(os.Name), ver
	case "npm":
		return "npm", "", ""
	case "pypi":
		return "pypi", "", ""
	case "maven":
		return "maven", "", ""
	case "golang":
		return "golang", "", ""
	case "cargo":
		return "cargo", "", ""
	default:
		// Derive from OS name for unknown OS package types.
		switch strings.ToLower(os.Name) {
		case "alpine":
			return "alpine", "alpine", ver
		case "debian":
			return "deb", "debian", ver
		case "ubuntu":
			return "deb", "ubuntu", ver
		}
		return "unknown", "", ""
	}
}

// classifyMatch determines the match type and confidence from the source name
// and whether a distro match occurred. Vendor-exact sources score 100.
func classifyMatch(sourceName, distroName string) (MatchType, int) {
	switch sourceName {
	case "alpine-secdb", "debian-security", "ubuntu-oval":
		if distroName != "" {
			return MatchTypeVendorExact, 100
		}
		return MatchTypeOSVExact, 95
	case "nvd":
		return MatchTypeCPEFuzzy, 70
	default: // "osv" and any future sources
		if distroName != "" {
			return MatchTypeOSVExact, 95
		}
		return MatchTypeOSVExact, 95
	}
}

// versionAffected reports whether the installed version is within the
// advisory's affected range.
func (m *Matcher) versionAffected(eco, installedVersion string, row db.AffectedRow) bool {
	if row.Status == "not-affected" {
		return false
	}
	cmp := m.versions.ForEcosystem(eco)

	// If we have a fixed version: affected iff installed < fixed.
	if row.FixedVersion != "" && row.FixedVersion != "0" {
		return cmp.IsFixedBy(installedVersion, row.FixedVersion)
	}

	// If we have an explicit range expression: use it.
	if row.AffectedRange != "" {
		return cmp.InRange(installedVersion, row.AffectedRange)
	}

	// If introduced_version is set: affected iff installed >= introduced.
	if row.IntroducedVersion != "" && row.IntroducedVersion != "0" {
		return cmp.Compare(installedVersion, row.IntroducedVersion) >= 0
	}

	// No version bounds at all — advisory says "all versions" or data is
	// incomplete. Include as a match but with reduced confidence (caller
	// may downgrade).
	return true
}

// buildResult constructs a MatchResult from a DB row and package.
func buildResult(pkg model.Package, row db.AffectedRow, mt MatchType, conf int, field, value string) MatchResult {
	return MatchResult{
		VulnID:           row.VulnID,
		Aliases:          row.Aliases,
		Summary:          row.Summary,
		Severity:         normSeverity(row.Severity),
		CVSSScore:        row.CVSSScore,
		Type:             mt,
		Confidence:       conf,
		Evidence:         []Evidence{{Source: row.SourceName, VulnID: row.VulnID, MatchField: field, MatchValue: value}},
		FixAvailable:     row.FixedVersion != "" && row.FixedVersion != "0",
		FixedVersion:     row.FixedVersion,
		AffectedRange:    row.AffectedRange,
		PackageName:      pkg.Name,
		PackageType:      pkg.Type,
		InstalledVersion: pkg.Version,
		LayerDigest:      pkg.LayerDigest,
		LayerCreatedBy:   pkg.LayerCreatedBy,
	}
}

// deduplicate removes duplicate (vuln_id, package_name) pairs, keeping the
// highest-confidence result. Multiple sources may describe the same advisory;
// we surface the one with the most authoritative evidence.
func deduplicate(results []MatchResult) []MatchResult {
	type key struct{ vulnID, pkgName string }
	best := make(map[key]MatchResult, len(results))
	for _, r := range results {
		k := key{r.VulnID, r.PackageName}
		if existing, ok := best[k]; !ok || r.Confidence > existing.Confidence {
			best[k] = r
		}
	}
	out := make([]MatchResult, 0, len(best))
	for _, r := range best {
		out = append(out, r)
	}
	return out
}

// filter removes results below MinConfidence.
func (m *Matcher) filter(results []MatchResult) []MatchResult {
	if m.MinConfidence == 0 {
		return results
	}
	out := results[:0]
	for _, r := range results {
		if r.Confidence >= m.MinConfidence {
			out = append(out, r)
		}
	}
	return out
}

// toFinding projects a MatchResult into a model.Finding.
func toFinding(mr MatchResult) model.Finding {
	evidence := make([]model.Evidence, len(mr.Evidence))
	for i, e := range mr.Evidence {
		evidence[i] = model.Evidence{
			Source:     e.Source,
			MatchField: e.MatchField,
			MatchValue: e.MatchValue,
			Reason: fmt.Sprintf("%s advisory confirms %s=%s",
				e.Source, e.MatchField, e.MatchValue),
		}
	}
	return model.Finding{
		ID:              fmt.Sprintf("%s/%s", mr.VulnID, mr.PackageName),
		Type:            model.FindingTypeVulnerability,
		Title:           mr.VulnID,
		Description:     mr.Summary,
		Severity:        model.Severity(mr.Severity),
		CVSSScore:       mr.CVSSScore,
		Confidence:      model.Confidence(mr.Confidence),
		VulnerabilityID: mr.VulnID,
		Aliases:         mr.Aliases,
		MatchType:       string(mr.Type),
		Evidence:        evidence,
		FixedVersion:    mr.FixedVersion,
		PackageName:     mr.PackageName,
		PackageVersion:  mr.InstalledVersion,
		PackageType:     mr.PackageType,
		LayerDigest:     mr.LayerDigest,
		LayerCreatedBy:  mr.LayerCreatedBy,
		Locations:       []model.Location{{Path: "", LayerDigest: mr.LayerDigest}},
		Recommendation:  mr.Recommendation,
		AdvisoryURL:     "",
		DetectedAt:      time.Now().UTC(),
	}
}

// normSeverity normalises severity strings to CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN.
func normSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL", "CRIT":
		return "CRITICAL"
	case "HIGH", "IMPORTANT":
		return "HIGH"
	case "MEDIUM", "MODERATE", "MED":
		return "MEDIUM"
	case "LOW", "MINOR", "UNIMPORTANT":
		return "LOW"
	case "NEGLIGIBLE":
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
