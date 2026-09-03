// Package sca implements Software Composition Analysis: it parses dependency manifests,
// queries the OSV.dev vulnerability database, and produces normalized findings.
package sca

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/manifest"
	"github.com/Patchflow-security/patchflow-cli/internal/mavenres"
	osvclient "github.com/Patchflow-security/patchflow-cli/internal/osv"
)

// Analyzer runs SCA analysis on a repository.
type Analyzer struct {
	OSV        *osvclient.Client
	MaxDepth   int
	ChangedOnly bool
	ChangedFiles []string
	// ResolveMavenTransitives enables transitive dependency resolution for
	// Maven projects by fetching POM files from Maven Central. This closes
	// the gap with Trivy's Java DB, which resolves full Maven dependency trees.
	ResolveMavenTransitives bool
}

// NewAnalyzer creates an SCA analyzer with default settings.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		OSV:      osvclient.NewClient(),
		MaxDepth: 3,
	}
}

// Result is the output of an SCA analysis run.
type Result struct {
	Dependencies   []analysis.Dependency `json:"dependencies"`
	Manifests      []manifest.ManifestInfo `json:"manifests"`
	Findings       []analysis.Finding  `json:"findings"`
	VulnerableDeps int                 `json:"vulnerable_deps"`
	TotalDeps      int                 `json:"total_deps"`
	QueryErrors    int                 `json:"query_errors"`
}

// Analyze runs the full SCA pipeline: parse manifests → query OSV → produce findings.
func (a *Analyzer) Analyze(ctx context.Context, root string) (*Result, error) {
	started := time.Now()
	_ = started

	// 1. Detect and parse manifests
	deps, manifests, err := manifest.ParseAll(root, a.MaxDepth)
	if err != nil {
		return nil, fmt.Errorf("sca: failed to parse manifests: %w", err)
	}

	// Filter to changed manifests if requested
	if a.ChangedOnly && len(a.ChangedFiles) > 0 {
		deps = filterToChanged(deps, a.ChangedFiles)
		manifests = filterManifestsToChanged(manifests, a.ChangedFiles)
	}

	// 1b. Resolve Maven transitive dependencies by fetching POM files from
	//     Maven Central. This adds transitive deps that aren't declared
	//     directly in pom.xml but are pulled in at build time. Without this,
	//     PatchFlow misses vulnerabilities in transitive Java deps (e.g.,
	//     jackson-databind pulled in via another library).
	if a.ResolveMavenTransitives {
		hasMaven := false
		for _, d := range deps {
			if d.Ecosystem == analysis.EcosystemMaven {
				hasMaven = true
				break
			}
		}
		if hasMaven {
			resolver := mavenres.NewResolver()
			resolver.SetCache(mavenres.NewCache(root))
			resolver.SetRoot(root)
			resolved, err := resolver.Resolve(ctx, deps)
			if err == nil && len(resolved) > len(deps) {
				deps = resolved
			}
			// Non-fatal: if resolution fails, continue with direct deps only
		}
	}

	result := &Result{
		Dependencies: deps,
		Manifests:    manifests,
		TotalDeps:    len(deps),
	}

	if len(deps) == 0 {
		return result, nil
	}

	// 2. Query OSV.dev for vulnerabilities (batch)
	vulnResults, err := a.OSV.QueryBatch(ctx, deps)
	if err != nil {
		result.QueryErrors = len(deps)
		return result, fmt.Errorf("sca: osv query failed: %w", err)
	}

	// 2b. Enrich with full vulnerability details (aliases/CVE IDs).
	// The batch endpoint returns empty aliases arrays, so we fetch each
	// vulnerability individually to get CVE IDs.
	if err := a.OSV.EnrichAliases(ctx, vulnResults); err != nil {
		// Non-fatal: we still have the vulnerabilities, just without CVE IDs.
		result.QueryErrors++
	}

	// 3. Normalize vulnerabilities into findings
	vulnerableSet := make(map[string]bool)
	for i, vulns := range vulnResults {
		if i >= len(deps) {
			break
		}
		dep := deps[i]

		for _, vuln := range vulns {
			finding := vulnToFinding(vuln, dep)
			result.Findings = append(result.Findings, finding)
			vulnerableSet[dep.Name] = true
		}
	}

	result.VulnerableDeps = len(vulnerableSet)

	return result, nil
}

// vulnToFinding converts an OSV vulnerability + dependency into a normalized Finding.
func vulnToFinding(vuln osvclient.Vulnerability, dep analysis.Dependency) analysis.Finding {
	severity := osvclient.ExtractSeverity(vuln)
	cveID := osvclient.ExtractCVEID(vuln)
	cweID := osvclient.ExtractCWEID(vuln)
	fixedVer := osvclient.ExtractFixedVersion(vuln, dep.Name, dep.Version)
	advisoryURL := osvclient.ExtractAdvisoryURL(vuln)

	title := fmt.Sprintf("%s@%s: %s", dep.Name, dep.Version, vuln.ID)
	if vuln.Summary != "" {
		title = fmt.Sprintf("%s@%s: %s", dep.Name, dep.Version, truncate(vuln.Summary, 80))
	}

	// Build a recommendation
	recommendation := ""
	if fixedVer != "" {
		recommendation = fmt.Sprintf("Upgrade %s to %s or later", dep.Name, fixedVer)
	} else if advisoryURL != "" {
		recommendation = fmt.Sprintf("Review advisory for %s — no fixed version available yet (%s)", dep.Name, advisoryURL)
	} else {
		recommendation = fmt.Sprintf("Review advisory for %s — no fixed version available", dep.Name)
	}

	// Build evidence
	evidence := ""
	if vuln.Summary != "" {
		evidence = vuln.Summary
	}
	if len(vuln.Aliases) > 0 {
		evidence = evidence + " (Aliases: " + strings.Join(vuln.Aliases, ", ") + ")"
	}

	return analysis.Finding{
		ID:             fmt.Sprintf("sca-%s-%s-%s", dep.Ecosystem, dep.Name, vuln.ID),
		Type:           analysis.TypeSCA,
		Analyzer:       "osv",
		Severity:       severity,
		Confidence:     analysis.ConfidenceHigh,
		Title:          title,
		Description:    vuln.Details,
		FilePath:       dep.ManifestPath,
		PackageName:    dep.Name,
		PackageVersion: dep.Version,
		FixedVersion:   fixedVer,
		CVEID:          cveID,
		CWEID:          cweID,
		AdvisoryURL:    advisoryURL,
		Evidence:       evidence,
		Recommendation: recommendation,
		RuleID:         scaRuleID(vuln, cveID),
		DetectedAt:     time.Now(),
	}
}

func filterToChanged(deps []analysis.Dependency, changedFiles []string) []analysis.Dependency {
	changedSet := make(map[string]bool, len(changedFiles))
	for _, f := range changedFiles {
		changedSet[f] = true
	}

	var filtered []analysis.Dependency
	for _, dep := range deps {
		if changedSet[dep.ManifestPath] {
			filtered = append(filtered, dep)
		}
	}
	return filtered
}

func filterManifestsToChanged(manifests []manifest.ManifestInfo, changedFiles []string) []manifest.ManifestInfo {
	changedSet := make(map[string]bool, len(changedFiles))
	for _, f := range changedFiles {
		changedSet[f] = true
	}

	var filtered []manifest.ManifestInfo
	for _, m := range manifests {
		if changedSet[m.Path] {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

// scaRuleID generates a deterministic rule ID for an SCA finding. This
// enables suppression, mode overrides, and cross-scan tracking. The ID
// prefers CVE IDs, falls back to GHSA IDs, then OSV IDs.
//
// Format: OSV-CVE-2024-12345, OSV-GHSA-xxxx, or OSV-VULN-xxxx.
func scaRuleID(vuln osvclient.Vulnerability, cveID string) string {
	if cveID != "" {
		return "OSV-" + cveID
	}
	// Check aliases for a GHSA or CVE
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return "OSV-" + alias
		}
	}
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "GHSA-") {
			return "OSV-" + alias
		}
	}
	// Fall back to the OSV vulnerability ID
	return "OSV-" + vuln.ID
}
