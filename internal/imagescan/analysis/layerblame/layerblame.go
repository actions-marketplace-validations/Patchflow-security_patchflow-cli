// Package layerblame computes fix-path recommendations for vulnerability
// findings based on which image layer introduced the affected package. The
// goal is to answer "what should I change to make this finding go away?"
// without re-running the scanner.
package layerblame

import (
	"fmt"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// Blame holds the layer-blame decision for one finding.
type Blame struct {
	// LayerIndex is the 0-based position of the introducing layer in the image
	// layer stack. -1 means unknown.
	LayerIndex int

	// LayerCreatedBy is the image config history command for that layer.
	LayerCreatedBy string

	// IsBaseImage is true when the introducing layer is part of the base
	// image rather than an application layer built on top.
	IsBaseImage bool

	// Recommendation is a human-readable, actionable fix path.
	Recommendation string
}

// Analyze updates all vulnerability findings in result with layer-blame
// recommendations. It uses the package's Type, the introducing layer's
// CreatedBy command, and the layer's position in the image stack.
func Analyze(result *model.ScanResult) {
	if result == nil || len(result.Layers) == 0 {
		return
	}

	layerIdx := make(map[string]int, len(result.Layers))
	for i, l := range result.Layers {
		layerIdx[l.LayerDigest] = i
	}

	for i := range result.Findings {
		if result.Findings[i].Type != model.FindingTypeVulnerability {
			continue
		}
		blame := blameForFinding(result.Findings[i], result.Layers, layerIdx)
		result.Findings[i].LayerCreatedBy = blame.LayerCreatedBy
		result.Findings[i].Recommendation = blame.Recommendation
	}
}

func blameForFinding(f model.Finding, layers []model.LayerProvenance, layerIdx map[string]int) Blame {
	idx, ok := layerIdx[f.LayerDigest]
	if !ok || idx < 0 || idx >= len(layers) {
		return Blame{
			LayerIndex:     -1,
			Recommendation: recommendGeneric(f),
		}
	}

	layer := layers[idx]
	isBase := isBaseImageLayer(idx, layers, layer.CreatedBy)

	return Blame{
		LayerIndex:     idx,
		LayerCreatedBy: layer.CreatedBy,
		IsBaseImage:    isBase,
		Recommendation: recommend(f, layer.CreatedBy, isBase),
	}
}

// isBaseImageLayer heuristically decides whether a layer belongs to the base
// image. The first layer is always base. Subsequent layers are base only if
// their command is base-like (package manager setup, ADD tarballs, rootfs
// imports) and every preceding non-first layer is also base-like. Once an
// app-like layer appears, everything above it is considered an app layer.
func isBaseImageLayer(idx int, layers []model.LayerProvenance, createdBy string) bool {
	if idx < 0 || idx >= len(layers) {
		return false
	}
	if idx == 0 {
		return true
	}
	if !isBaseLikeCommand(strings.ToLower(createdBy)) {
		return false
	}
	for i := 1; i < idx; i++ {
		if !isBaseLikeCommand(strings.ToLower(layers[i].CreatedBy)) {
			return false
		}
	}
	return true
}

func isBaseLikeCommand(cmd string) bool {
	return strings.Contains(cmd, "apt-get update") ||
		strings.Contains(cmd, "apt-get install") ||
		strings.Contains(cmd, "apk add") ||
		strings.Contains(cmd, "yum install") ||
		strings.Contains(cmd, "dnf install") ||
		strings.Contains(cmd, "zypper install") ||
		strings.Contains(cmd, "pacman -") ||
		strings.Contains(cmd, "#(nop) add") ||
		strings.Contains(cmd, "add file:") ||
		strings.Contains(cmd, "from scratch") ||
		strings.Contains(cmd, "image rootfs") ||
		cmd == ""
}

func recommend(f model.Finding, createdBy string, isBase bool) string {
	if f.PackageType == "" {
		return recommendGeneric(f)
	}

	pt := strings.ToLower(f.PackageType)
	switch {
	case isBase:
		return fmt.Sprintf("Upgrade the base image to a version that includes a patched %s (%s). Rebuild the application layer.",
			f.PackageName, f.PackageVersion)
	case pt == "apk" || pt == "deb" || pt == "rpm":
		return fmt.Sprintf("Rebuild the image and upgrade the OS package: %s (currently %s). Add the package manager update step to the Dockerfile before this vulnerability is introduced.",
			f.PackageName, f.PackageVersion)
	case pt == "npm" || pt == "pypi" || pt == "maven" || pt == "golang" || pt == "cargo":
		return fmt.Sprintf("Update the %s dependency to a version that fixes %s (currently %s), regenerate the lockfile, and rebuild the image.",
			f.PackageName, f.VulnerabilityID, f.PackageVersion)
	default:
		return fmt.Sprintf("Update or remove the affected component (%s %s) and rebuild the image.",
			f.PackageName, f.PackageVersion)
	}
}

func recommendGeneric(f model.Finding) string {
	if f.FixedVersion != "" {
		return fmt.Sprintf("Upgrade to %s or later and rebuild the image.", f.FixedVersion)
	}
	return fmt.Sprintf("Review the affected component (%s %s) and rebuild the image.", f.PackageName, f.PackageVersion)
}
