package layerblame

import (
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

func TestAnalyzeAddsRecommendations(t *testing.T) {
	result := &model.ScanResult{
		Layers: []model.LayerProvenance{
			{LayerDigest: "sha256:base", CreatedBy: "ADD file:abc /"},
			{LayerDigest: "sha256:app", CreatedBy: "RUN /app/build.sh"},
		},
		Findings: []model.Finding{
			{
				ID:          "CVE-2023-0001/busybox",
				Type:        model.FindingTypeVulnerability,
				VulnerabilityID: "CVE-2023-0001",
				PackageName: "busybox",
				PackageVersion: "1.36.0",
				PackageType: "apk",
				LayerDigest: "sha256:base",
				FixedVersion: "1.36.1",
			},
			{
				ID:          "CVE-2023-0002/lodash",
				Type:        model.FindingTypeVulnerability,
				VulnerabilityID: "CVE-2023-0002",
				PackageName: "lodash",
				PackageVersion: "4.17.20",
				PackageType: "npm",
				LayerDigest: "sha256:app",
				FixedVersion: "4.17.21",
			},
		},
	}

	Analyze(result)

	base := result.Findings[0]
	if base.Recommendation == "" {
		t.Errorf("base finding should have a recommendation")
	}
	if base.LayerCreatedBy != "ADD file:abc /" {
		t.Errorf("LayerCreatedBy = %q, want ADD file:abc /", base.LayerCreatedBy)
	}
	if !strings.Contains(base.Recommendation, "base image") {
		t.Errorf("base finding should recommend base image upgrade; got %q", base.Recommendation)
	}

	app := result.Findings[1]
	if app.Recommendation == "" {
		t.Errorf("app finding should have a recommendation")
	}
	if app.LayerCreatedBy != "RUN /app/build.sh" {
		t.Errorf("LayerCreatedBy = %q, want RUN /app/build.sh", app.LayerCreatedBy)
	}
	if !strings.Contains(app.Recommendation, "lockfile") {
		t.Errorf("npm finding should recommend lockfile update; got %q", app.Recommendation)
	}
}

func TestAnalyzeSkipsNonVulnerabilityFindings(t *testing.T) {
	result := &model.ScanResult{
		Layers: []model.LayerProvenance{
			{LayerDigest: "sha256:base", CreatedBy: "ADD file:abc /"},
		},
		Findings: []model.Finding{
			{
				ID:          "PF-IMG-001",
				Type:        model.FindingTypeHardening,
				LayerDigest: "sha256:base",
				PackageName: "root",
				PackageType: "image",
			},
		},
	}

	Analyze(result)

	if result.Findings[0].Recommendation != "" {
		t.Errorf("hardening finding should not get a vulnerability recommendation")
	}
}

func TestIsBaseImageLayer(t *testing.T) {
	cases := []struct {
		idx       int
		createdBy string
		want      bool
	}{
		{0, "ADD file:abc /", true},
		{1, "RUN /app/build.sh", false},
		{1, "RUN apt-get update && apt-get install -y curl", true},
		{2, "RUN apk add --no-cache python3", true},
		{3, "RUN npm ci", false},
		{1, "", true},
	}

	for _, c := range cases {
		layers := []model.LayerProvenance{
			{LayerDigest: "sha256:base", CreatedBy: "ADD file:abc /"},
			{LayerDigest: "sha256:second", CreatedBy: c.createdBy},
			{LayerDigest: "sha256:third", CreatedBy: "RUN npm ci"},
		}
		got := isBaseImageLayer(c.idx, layers, c.createdBy)
		if got != c.want {
			t.Errorf("isBaseImageLayer(%d, %q) = %v, want %v", c.idx, c.createdBy, got, c.want)
		}
	}
}
