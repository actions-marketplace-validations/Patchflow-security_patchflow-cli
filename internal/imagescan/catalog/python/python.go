// Package python catalogs Python packages installed in a container image.
// It discovers packages from two sources:
//
//  1. Installed distributions — *.dist-info/METADATA and *.egg-info/PKG-INFO
//     files under the common site-packages/dist-packages roots. These are
//     RFC 822-style text files with "Name:" and "Version:" headers.
//  2. requirements.txt — used only as a fallback when no installed
//     distributions are found. Only exactly pinned lines (name==version or
//     name===version) are emitted; ranges, comments, and includes are skipped.
package python

import (
	"context"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// sitePackagesPrefixes are the directory prefixes that hold installed Python
// distributions. The python3.* version segment is a wildcard handled by
// walking the prefix and filtering on site-packages/dist-packages paths.
var sitePackagesPrefixes = []string{
	"/usr/lib/python3",
	"/usr/local/lib/python3",
}

// Cataloger implements catalog.Cataloger for Python (PyPI) packages.
type Cataloger struct{}

// New returns a Python cataloger.
func New() *Cataloger { return &Cataloger{} }

func (*Cataloger) Name() string { return "python" }

func (*Cataloger) Match(fs model.FileSystemView) bool {
	if hasDistInfo(fs) {
		return true
	}
	return hasRequirementsTxt(fs)
}

func (c *Cataloger) Catalog(_ context.Context, fs model.FileSystemView) ([]model.Package, error) {
	var pkgs []model.Package

	// Installed distributions: dist-info METADATA + egg-info PKG-INFO.
	for _, prefix := range sitePackagesPrefixes {
		entries, err := catalog.WalkDir(fs, prefix)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !isSitePackagesPath(e.Path) {
				continue
			}
			switch {
			case strings.HasSuffix(e.Path, ".dist-info/METADATA"):
				if p, ok := parseMetadataFile(fs, e, "dist-info"); ok {
					pkgs = append(pkgs, p)
				}
			case strings.HasSuffix(e.Path, ".egg-info/PKG-INFO"):
				if p, ok := parseMetadataFile(fs, e, "egg-info"); ok {
					pkgs = append(pkgs, p)
				}
			}
		}
	}

	// requirements.txt is a fallback only when no installed packages exist.
	if len(pkgs) > 0 {
		return pkgs, nil
	}
	for _, e := range findRequirementsTxt(fs) {
		lines, _, err := catalog.ReadLines(fs, e.Path)
		if err != nil {
			continue
		}
		pkgs = append(pkgs, parseRequirements(lines, e)...)
	}
	return pkgs, nil
}

// hasDistInfo reports whether any METADATA/PKG-INFO file exists under the
// site-packages roots.
func hasDistInfo(fs model.FileSystemView) bool {
	for _, prefix := range sitePackagesPrefixes {
		entries, err := catalog.WalkDir(fs, prefix)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if isSitePackagesPath(e.Path) && isMetadataFile(e.Path) {
				return true
			}
		}
	}
	return false
}

// hasRequirementsTxt reports whether any requirements.txt exists in the view.
func hasRequirementsTxt(fs model.FileSystemView) bool {
	var found bool
	_ = fs.Walk("/", func(e *model.FileEntry) error {
		if e.IsDeleted {
			return nil
		}
		if base(e.Path) == "requirements.txt" {
			found = true
		}
		return nil
	})
	return found
}

// findRequirementsTxt returns all requirements.txt entries in the view.
func findRequirementsTxt(fs model.FileSystemView) []*model.FileEntry {
	var out []*model.FileEntry
	_ = fs.Walk("/", func(e *model.FileEntry) error {
		if e.IsDeleted {
			return nil
		}
		if base(e.Path) == "requirements.txt" {
			out = append(out, e)
		}
		return nil
	})
	return out
}

// parseMetadataFile reads and parses a METADATA/PKG-INFO file into a package.
func parseMetadataFile(fs model.FileSystemView, e *model.FileEntry, source string) (model.Package, bool) {
	lines, _, err := catalog.ReadLines(fs, e.Path)
	if err != nil {
		return model.Package{}, false
	}
	name, version := parseRFC822(lines)
	if name == "" || version == "" {
		return model.Package{}, false
	}
	return model.Package{
		Name:        name,
		Version:     version,
		Type:        "python",
		Ecosystem:   "pypi",
		PURL:        catalog.PURL("pypi", name, version),
		LayerDigest: e.LayerDigest,
		Locations:   []model.Location{{Path: e.Path, LayerDigest: e.LayerDigest}},
		Metadata:    map[string]string{"source": source},
	}, true
}

// parseRFC822 extracts the Name and Version headers from RFC 822-style lines.
// Headers end at the first blank line (the message body follows).
func parseRFC822(lines []string) (name, version string) {
	for _, line := range lines {
		if line == "" {
			break
		}
		switch {
		case strings.HasPrefix(line, "Name:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "Version:"):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	return name, version
}

// parseRequirements parses pinned lines from a requirements.txt file.
func parseRequirements(lines []string, e *model.FileEntry) []model.Package {
	var pkgs []model.Package
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-r") {
			continue
		}
		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		var name, version string
		switch {
		case strings.Contains(line, "==="):
			parts := strings.SplitN(line, "===", 2)
			name, version = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		case strings.Contains(line, "=="):
			parts := strings.SplitN(line, "==", 2)
			name, version = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		default:
			// Unpinned (>=, ~=, <, >, !=) or bare names: skip.
			continue
		}
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, model.Package{
			Name:        name,
			Version:     version,
			Type:        "python",
			Ecosystem:   "pypi",
			PURL:        catalog.PURL("pypi", name, version),
			LayerDigest: e.LayerDigest,
			Locations:   []model.Location{{Path: e.Path, LayerDigest: e.LayerDigest}},
			Metadata:    map[string]string{"source": "requirements.txt"},
		})
	}
	return pkgs
}

func isMetadataFile(path string) bool {
	return strings.HasSuffix(path, ".dist-info/METADATA") ||
		strings.HasSuffix(path, ".egg-info/PKG-INFO")
}

func isSitePackagesPath(path string) bool {
	return strings.Contains(path, "/site-packages/") ||
		strings.Contains(path, "/dist-packages/")
}

func base(path string) string {
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

// Ensure the cataloger satisfies the interface.
var _ catalog.Cataloger = (*Cataloger)(nil)
