// Package cyclonedx exports a PatchFlow-native SBOM (model.SBOM) to the
// CycloneDX 1.6 JSON format using the official CycloneDX/cyclonedx-go
// library.
//
// The image itself is represented as the metadata.Component (type
// "container"); each discovered package becomes a top-level Component with
// a Package URL, layer attribution carried as a Property, and the OS
// distro recorded as a Property on the container component.
package cyclonedx

import (
	"fmt"
	"io"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/pkg/version"
)

// WriteJSON writes the SBOM as pretty-printed CycloneDX 1.6 JSON to w.
func WriteJSON(w io.Writer, sbom *model.SBOM) error {
	bom := buildBOM(sbom)
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)
	return enc.Encode(bom)
}

// buildBOM projects a model.SBOM onto a CycloneDX BOM.
func buildBOM(sbom *model.SBOM) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SerialNumber = serial(sbom)

	// Metadata: timestamp + the image as the container component.
	bom.Metadata = &cdx.Metadata{
		Timestamp: sbom.GeneratedAt.UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    "patchflow-image-scanner",
				Version: version.Short(),
			}},
		},
		Component: containerComponent(sbom),
	}

	components := make([]cdx.Component, 0, len(sbom.Packages))
	for _, p := range sbom.Packages {
		components = append(components, packageComponent(p))
	}
	bom.Components = &components
	return bom
}

// containerComponent describes the scanned image as a CycloneDX container
// component, with the digest as bom-ref and OS info as properties.
func containerComponent(sbom *model.SBOM) *cdx.Component {
	c := &cdx.Component{
		BOMRef:  "image:" + sbom.Image.Digest,
		Type:    cdx.ComponentTypeContainer,
		Name:    imageComponentName(sbom.Image),
		Version: sbom.Image.Digest,
		PackageURL: imagePURL(sbom.Image),
	}
	props := []cdx.Property{
		{Name: "patchflow:image:registry", Value: sbom.Image.Registry},
		{Name: "patchflow:image:repository", Value: sbom.Image.Repository},
		{Name: "patchflow:image:digest", Value: sbom.Image.Digest},
		{Name: "patchflow:image:platform", Value: sbom.Image.Platform},
		{Name: "patchflow:image:original_ref", Value: sbom.Image.OriginalRef},
	}
	if sbom.OS != nil {
		props = append(props,
			cdx.Property{Name: "patchflow:os:name", Value: sbom.OS.Name},
			cdx.Property{Name: "patchflow:os:version_id", Value: sbom.OS.VersionID},
			cdx.Property{Name: "patchflow:os:codename", Value: sbom.OS.Codename},
		)
	}
	c.Properties = &props
	return c
}

// packageComponent projects a discovered package to a CycloneDX component.
// Layer attribution is preserved as a property so downstream consumers can
// answer "which layer introduced this package".
func packageComponent(p model.Package) cdx.Component {
	c := cdx.Component{
		BOMRef:     p.PURL,
		Type:       componentType(p),
		Name:       p.Name,
		Version:    p.Version,
		PackageURL: p.PURL,
		Group:      componentGroup(p),
	}
	if len(p.CPEs) > 0 {
		c.CPE = p.CPEs[0]
	}
	props := []cdx.Property{
		{Name: "patchflow:package:type", Value: p.Type},
		{Name: "patchflow:package:ecosystem", Value: p.Ecosystem},
		{Name: "patchflow:package:layer_digest", Value: p.LayerDigest},
	}
	if p.Architecture != "" {
		props = append(props, cdx.Property{Name: "patchflow:package:arch", Value: p.Architecture})
	}
	if p.SourcePackage != "" {
		props = append(props, cdx.Property{Name: "patchflow:package:source", Value: p.SourcePackage})
	}
	if p.SourceVersion != "" {
		props = append(props, cdx.Property{Name: "patchflow:package:source_version", Value: p.SourceVersion})
	}
	if p.DistroName != "" {
		props = append(props, cdx.Property{Name: "patchflow:package:distro_name", Value: p.DistroName})
	}
	if p.DistroVersion != "" {
		props = append(props, cdx.Property{Name: "patchflow:package:distro_version", Value: p.DistroVersion})
	}
	c.Properties = &props
	return c
}

// componentType maps a PatchFlow package type to a CycloneDX component type.
// OS packages map to "library"; language packages also map to "library" —
// CycloneDX does not distinguish OS vs language at the type level.
func componentType(p model.Package) cdx.ComponentType {
	return cdx.ComponentTypeLibrary
}

// componentGroup returns the CycloneDX "group" field for a package: the
// distro name for OS packages, empty otherwise.
func componentGroup(p model.Package) string {
	if p.Type == "os" && p.DistroName != "" {
		return p.DistroName
	}
	return ""
}

// imageComponentName returns a human-friendly name for the image component.
func imageComponentName(id model.ImageIdentity) string {
	if id.Repository != "" {
		return id.Repository
	}
	return id.OriginalRef
}

// imagePURL builds a best-effort Package URL for the image itself.
func imagePURL(id model.ImageIdentity) string {
	if id.Repository == "" {
		return ""
	}
	purl := fmt.Sprintf("pkg:oci/%s", id.Repository)
	if id.Tag != "" {
		purl += "@" + id.Tag
	}
	if id.Digest != "" {
		purl += "?digest=" + id.Digest
	}
	return purl
}

// serial returns a urn:uuid-style serial number derived from the image
// digest so the same image+scan-time yields a stable-ish identifier.
func serial(sbom *model.SBOM) string {
	// CycloneDX expects a URN; we use a deterministic pseudo-urn based on
	// the digest. A real UUID v5 would be ideal; this is sufficient for v1.
	return "urn:patchflow:image:" + shortDigest(sbom.Image.Digest)
}

// shortDigest trims a "sha256:..." digest to its first 16 hex chars.
func shortDigest(d string) string {
	const prefix = "sha256:"
	if len(d) > len(prefix)+16 {
		return d[len(prefix) : len(prefix)+16]
	}
	return d
}
