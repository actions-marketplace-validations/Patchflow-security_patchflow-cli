// Package sbom generates Software Bill of Materials (SBOM) documents in
// CycloneDX and SPDX formats from PatchFlow's dependency analysis results.
//
// SBOMs are machine-readable inventories of software components and their
// supply chain relationships. They are required for:
//   - US Executive Order 14028 compliance
//   - EU Cyber Resilience Act compliance
//   - Enterprise vendor security assessments
//   - Supply chain transparency
package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// GenerateConfig controls SBOM generation parameters.
type GenerateConfig struct {
	// Format is the SBOM format: "cyclonedx-json", "cyclonedx-xml",
	// "spdx-json", "spdx-tagvalue"
	Format string

	// ToolVersion is the PatchFlow CLI version string.
	ToolVersion string

	// IncludeVEX controls whether VEX (Vulnerability Exploitability eXchange)
	// statements are embedded in the SBOM. When true, SCA findings are
	// converted to VEX statements with reachability-based exploitability
	// assessments.
	IncludeVEX bool
}

// cyclonedxBOM is the CycloneDX JSON structure (v1.5).
type cyclonedxBOM struct {
	BomFormat       string              `json:"bomFormat"`
	SpecVersion     string              `json:"specVersion"`
	SerialNumber    string              `json:"serialNumber"`
	Version         int                 `json:"version"`
	Metadata        cycloneDXMetadata   `json:"metadata"`
	Components      []cycloneDXComponent `json:"components"`
	Vulnerabilities []cycloneDXVuln     `json:"vulnerabilities,omitempty"`
}

type cycloneDXMetadata struct {
	Timestamp string              `json:"timestamp"`
	Tools     []cycloneDXTool     `json:"tools"`
	Component *cycloneDXComponent `json:"component,omitempty"`
}

type cycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cycloneDXComponent struct {
	Type       string            `json:"type"`
	BomRef     string            `json:"bom-ref"`
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Purl       string            `json:"purl,omitempty"`
	Ecosystem  string            `json:"ecosystem,omitempty"`
	Licenses   []cycloneDXLicense `json:"licenses,omitempty"`
	Properties []cycloneDXProperty `json:"properties,omitempty"`
}

type cycloneDXLicense struct {
	License struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"license"`
}

type cycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cycloneDXVuln struct {
	ID          string                `json:"id"`
	Source      cycloneDXSource       `json:"source"`
	Ratings     []cycloneDXRating     `json:"ratings,omitempty"`
	Affects     []cycloneDXAffect     `json:"affects"`
	Analysis    *cycloneDXVexAnalysis `json:"analysis,omitempty"`
	Description string                `json:"description,omitempty"`
}

// cycloneDXVexAnalysis is the VEX analysis statement embedded in CycloneDX.
type cycloneDXVexAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type cycloneDXSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cycloneDXRating struct {
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity"`
	Method   string  `json:"method,omitempty"`
}

type cycloneDXAffect struct {
	Ref string `json:"ref"`
}

// GenerateCycloneDXJSON generates a CycloneDX v1.5 SBOM in JSON format.
func GenerateCycloneDXJSON(result *analysis.AnalysisResult, cfg GenerateConfig) ([]byte, error) {
	bom := buildCycloneDXBOM(result, cfg)
	return json.MarshalIndent(bom, "", "  ")
}

// buildCycloneDXBOM constructs the CycloneDX BOM structure from analysis results.
func buildCycloneDXBOM(result *analysis.AnalysisResult, cfg GenerateConfig) *cyclonedxBOM {
	bom := &cyclonedxBOM{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + result.ScanID,
		Version:      1,
		Metadata: cycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cycloneDXTool{
				{
					Vendor:  "PatchFlow",
					Name:    "patchflow-cli",
					Version: cfg.ToolVersion,
				},
			},
		},
	}

	// Root component (the project itself)
	rootName := projectNameFromResult(result)
	rootLicense := rootLicenseFromResult(result)
	bom.Metadata.Component = &cycloneDXComponent{
		Type:   "application",
		BomRef: "pkg:patchflow/" + rootName,
		Name:   rootName,
		Properties: []cycloneDXProperty{
			{Name: "patchflow:scan_id", Value: result.ScanID},
			{Name: "patchflow:branch", Value: result.Branch},
			{Name: "patchflow:commit", Value: result.CommitSHA},
		},
	}
	if rootLicense != "" {
		lc := cycloneDXLicense{}
		if isSPDXLicenseID(rootLicense) {
			lc.License.ID = rootLicense
		} else {
			lc.License.Name = rootLicense
		}
		bom.Metadata.Component.Licenses = []cycloneDXLicense{lc}
	}

	// Components from dependencies
	bom.Components = []cycloneDXComponent{}
	seen := make(map[string]bool)
	for _, dep := range result.Dependencies {
		ref := componentRef(dep)
		if seen[ref] {
			continue
		}
		seen[ref] = true

		comp := cycloneDXComponent{
			Type:      componentType(dep),
			BomRef:    ref,
			Name:      dep.Name,
			Version:   dep.Version,
			Purl:      purlFor(dep),
			Ecosystem: string(dep.Ecosystem),
		}

		if dep.License != "" {
			lc := cycloneDXLicense{}
			if isSPDXLicenseID(dep.License) {
				lc.License.ID = dep.License
			} else {
				lc.License.Name = dep.License
			}
			comp.Licenses = []cycloneDXLicense{lc}
		}

		comp.Properties = append(comp.Properties,
			cycloneDXProperty{Name: "patchflow:ecosystem", Value: string(dep.Ecosystem)},
		)
		if dep.IsDirect {
			comp.Properties = append(comp.Properties,
				cycloneDXProperty{Name: "patchflow:direct", Value: "true"},
			)
		}
		if dep.IsDev {
			comp.Properties = append(comp.Properties,
				cycloneDXProperty{Name: "patchflow:dev_dependency", Value: "true"},
			)
		}
		if dep.ManifestPath != "" {
			comp.Properties = append(comp.Properties,
				cycloneDXProperty{Name: "patchflow:manifest", Value: dep.ManifestPath},
			)
		}

		bom.Components = append(bom.Components, comp)
	}

	// Vulnerabilities from SCA findings — always included so the SBOM is
	// useful for vulnerability management. When IncludeVEX is true, the
	// VEX analysis (reachability-based exploitability) is also embedded.
	bom.Vulnerabilities = []cycloneDXVuln{}
	for _, f := range result.Findings {
		if f.Type != analysis.TypeSCA {
			continue
		}
		vuln := cycloneDXVuln{
			ID: vulnID(f),
			Source: cycloneDXSource{
				Name: "OSV.dev",
				URL:  f.AdvisoryURL,
			},
			Description: f.Description,
			Affects: []cycloneDXAffect{
				{Ref: componentRefByNameVer(f.PackageName, f.PackageVersion)},
			},
		}

		// VEX analysis is only included when --include-vex is set.
		if cfg.IncludeVEX {
			vuln.Analysis = reachabilityToCycloneDXAnalysis(f)
		}

		rating := cycloneDXRating{
			Severity: string(f.Severity),
			Method:   "other",
		}
		vuln.Ratings = append(vuln.Ratings, rating)

		// Add response if there's a fixed version
		if f.FixedVersion != "" && vuln.Analysis != nil {
			vuln.Analysis.Response = []string{
				fmt.Sprintf("Upgrade to %s or later", f.FixedVersion),
			}
		}

		bom.Vulnerabilities = append(bom.Vulnerabilities, vuln)
	}

	return bom
}

// componentType returns the CycloneDX component type for a dependency.
func componentType(dep analysis.Dependency) string {
	if dep.IsRoot {
		return "application"
	}
	return "library"
}

// componentRef generates a bom-ref for a dependency.
func componentRef(dep analysis.Dependency) string {
	return componentRefByNameVer(dep.Name, dep.Version)
}

// componentRefByNameVer generates a bom-ref from name and version.
func componentRefByNameVer(name, version string) string {
	if version == "" {
		return "pkg:" + name
	}
	return "pkg:" + name + "@" + version
}

// purlFor generates a Package URL (purl) for a dependency.
// See: https://github.com/package-url/purl-spec
func purlFor(dep analysis.Dependency) string {
	ecosystem := purlType(dep.Ecosystem)
	if ecosystem == "" {
		return ""
	}
	if dep.Version == "" {
		return fmt.Sprintf("pkg:%s/%s", ecosystem, dep.Name)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", ecosystem, dep.Name, dep.Version)
}

// purlType maps PatchFlow ecosystems to purl type strings.
func purlType(eco analysis.Ecosystem) string {
	switch eco {
	case analysis.EcosystemGo:
		return "golang"
	case analysis.EcosystemNPM:
		return "npm"
	case analysis.EcosystemPyPI:
		return "pypi"
	case analysis.EcosystemCargo:
		return "cargo"
	case analysis.EcosystemRubyGems:
		return "gem"
	case analysis.EcosystemPackagist:
		return "composer"
	case analysis.EcosystemMaven:
		return "maven"
	default:
		return ""
	}
}

// vulnID returns the best vulnerability identifier (CVE ID or OSV ID).
func vulnID(f analysis.Finding) string {
	if f.CVEID != "" {
		return f.CVEID
	}
	// Extract OSV ID from the finding ID (format: sca-<eco>-<pkg>-<osvid>)
	parts := strings.Split(f.ID, "-")
	if len(parts) >= 4 {
		return strings.Join(parts[3:], "-")
	}
	return f.ID
}

// projectNameFromResult extracts a project name from the analysis result.
// It first checks for a root dependency (IsRoot=true), then falls back to
// the directory name from ProjectRoot.
func projectNameFromResult(result *analysis.AnalysisResult) string {
	// Check for root dependency with a name
	for _, dep := range result.Dependencies {
		if dep.IsRoot && dep.Name != "" {
			return dep.Name
		}
	}
	if result.ProjectRoot == "" {
		return "unknown"
	}
	// Use the last path component
	parts := strings.Split(strings.TrimSuffix(result.ProjectRoot, "/"), "/")
	return parts[len(parts)-1]
}

// rootLicenseFromResult extracts the license from the root dependency.
func rootLicenseFromResult(result *analysis.AnalysisResult) string {
	for _, dep := range result.Dependencies {
		if dep.IsRoot && dep.License != "" {
			return dep.License
		}
	}
	return ""
}

// reachabilityToCycloneDXAnalysis converts a finding's reachability status
// to a CycloneDX VEX analysis statement.
func reachabilityToCycloneDXAnalysis(f analysis.Finding) *cycloneDXVexAnalysis {
	stmt := &cycloneDXVexAnalysis{}

	switch f.Reachability {
	case analysis.ReachabilityHigh:
		stmt.State = VEXStateExploitable
		stmt.Detail = "Vulnerable package is directly imported in source code."
		if len(f.ReachabilityEvidence) > 0 {
			stmt.Detail += " Evidence: " + strings.Join(f.ReachabilityEvidence, "; ")
		}

	case analysis.ReachabilityMedium:
		stmt.State = VEXStateInTriage
		stmt.Detail = "Package is a direct dependency but no direct imports found."
		if len(f.ReachabilityEvidence) > 0 {
			stmt.Detail += " Evidence: " + strings.Join(f.ReachabilityEvidence, "; ")
		}

	case analysis.ReachabilityLow:
		stmt.State = VEXStateInTriage
		stmt.Justification = VEXJustVulnerableCodeNotInExecutePath
		stmt.Detail = "Package is a transitive dependency with no direct imports."

	case analysis.ReachabilityNone:
		stmt.State = VEXStateNotAffected
		stmt.Justification = VEXJustComponentNotPresent
		stmt.Detail = "Package not found in the dependency graph."

	default:
		stmt.State = VEXStateInTriage
		stmt.Detail = "Reachability analysis incomplete."
	}

	return stmt
}

// isSPDXLicenseID checks if a string looks like a valid SPDX license identifier.
// SPDX IDs are typically uppercase alphanumeric with dashes (e.g., "MIT", "Apache-2.0").
func isSPDXLicenseID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
