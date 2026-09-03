// Package container provides embedded container image scanning using the
// PatchFlow native image scanner. No external tools (Trivy, etc.) are required.
//
// The scanner pulls images via Docker Registry API v2 (or local Docker/Podman
// daemon, tarballs, OCI layouts), reconstructs the layered filesystem,
// catalogs OS and language packages, and optionally matches vulnerabilities
// against a local SQLite vulnerability database.
package container

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/config"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/scan"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/db"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/vuln/matcher"
)

// ImageScanner scans container images using the embedded PatchFlow scanner.
type ImageScanner struct {
	Timeout     time.Duration
	Platform    string
	Input       string // local tarball or OCI layout path
	WithVulns   bool   // enable vulnerability matching
	scanner     *scan.Scanner
}

// NewImageScanner creates an embedded container image scanner.
func NewImageScanner() *ImageScanner {
	return &ImageScanner{
		Timeout:   10 * time.Minute,
		WithVulns: true,
		scanner:   scan.New(),
	}
}

// IsAvailable returns true — the embedded scanner is always available.
func (s *ImageScanner) IsAvailable() bool {
	return true
}

// ScanResult holds the output of a container image scan.
type ScanResult struct {
	Findings []analysis.Finding
	Packages int
	Target   string
	Image    model.ImageIdentity
	OS       *model.OperatingSystem
	Raw      *model.ScanResult
}

// ScanImage scans a container image for vulnerabilities, secrets,
// hardening issues, and misconfigurations. The image can be a local image
// (e.g., "myapp:latest"), a remote registry image (e.g., "nginx:1.21"),
// or a local tarball/OCI layout (when Input is set).
func (s *ImageScanner) ScanImage(ctx context.Context, image string) (*ScanResult, error) {
	if err := validateImageRef(image); err != nil {
		return nil, err
	}

	// Optionally attach vulnerability matcher
	if s.WithVulns {
		if m, err := buildMatcher(); err == nil {
			s.scanner.Matcher = m
		}
	}

	req := scan.Request{
		Ref:      image,
		Input:    s.Input,
		Platform: s.Platform,
	}

	output, err := s.scanner.Scan(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("image scan failed: %w", err)
	}
	defer output.Close()

	result := output.Result
	findings := convertFindings(result.Findings)

	return &ScanResult{
		Findings: findings,
		Packages: len(result.Packages),
		Target:   image,
		Image:    result.Image,
		OS:       result.OS,
		Raw:      result,
	}, nil
}

// buildMatcher creates a vulnerability matcher from the local SQLite DB.
func buildMatcher() (scan.VulnMatcher, error) {
	dbPath := config.VulnDBPath()
	database, err := db.OpenReadOnly(dbPath)
	if err != nil {
		return nil, err
	}
	return matcher.New(database, 70), nil
}

// convertFindings converts image scanner findings to patchflow-cli analysis.Finding.
func convertFindings(imgFindings []model.Finding) []analysis.Finding {
	var findings []analysis.Finding
	for _, f := range imgFindings {
		finding := analysis.Finding{
			ID:             f.ID,
			Type:           convertFindingType(f.Type),
			Analyzer:       "patchflow-image",
			Severity:       convertSeverity(f.Severity),
			Confidence:     convertConfidence(f.Confidence),
			Title:          f.Title,
			Description:    f.Description,
			PackageName:    f.PackageName,
			PackageVersion: f.PackageVersion,
			FixedVersion:   f.FixedVersion,
			CVEID:          f.VulnerabilityID,
			Recommendation: f.Recommendation,
			AdvisoryURL:    f.AdvisoryURL,
			DetectedAt:     f.DetectedAt,
		}
		if f.LayerDigest != "" {
			finding.FilePath = f.LayerDigest
		}
		findings = append(findings, finding)
	}
	return findings
}

func convertFindingType(t model.FindingType) analysis.FindingType {
	switch t {
	case model.FindingTypeVulnerability:
		return analysis.TypeSCA
	case model.FindingTypeSecret:
		return analysis.TypeSecret
	case model.FindingTypeHardening, model.FindingTypeMisconfig:
		return analysis.TypeIaC
	default:
		return analysis.TypeSAST
	}
}

func convertSeverity(s model.Severity) analysis.Severity {
	switch s {
	case model.SeverityCritical:
		return analysis.SeverityCritical
	case model.SeverityHigh:
		return analysis.SeverityHigh
	case model.SeverityMedium:
		return analysis.SeverityMedium
	case model.SeverityLow:
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

func convertConfidence(c model.Confidence) analysis.Confidence {
	if c >= 80 {
		return analysis.ConfidenceHigh
	}
	if c >= 50 {
		return analysis.ConfidenceMedium
	}
	return analysis.ConfidenceLow
}

func validateImageRef(image string) error {
	if strings.TrimSpace(image) == "" {
		return fmt.Errorf("container image reference cannot be empty")
	}
	if strings.HasPrefix(image, "-") {
		return fmt.Errorf("container image reference cannot start with '-'")
	}
	if strings.ContainsAny(image, "\x00\r\n") {
		return fmt.Errorf("container image reference contains invalid control characters")
	}
	return nil
}
