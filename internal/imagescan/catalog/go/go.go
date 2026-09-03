// Package gocatalog catalogs Go modules by parsing go.mod files and reading
// build info embedded in compiled Go binaries.
//
// Two discovery sources:
//
//  1. **go.mod** — the `require` blocks list direct and indirect module
//     dependencies with their versions. Replace/exclude directives are
//     skipped; indirect dependencies are still emitted (they are installed).
//
//  2. **Go binaries** — compiled Go binaries embed module dependency info
//     accessible via debug/buildinfo. We walk common binary locations and
//     attempt to read build info from each candidate file.
package gocatalog

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"fmt"
	"io"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// goModCandidates are the common locations for a go.mod file in a container.
var goModCandidates = []string{
	"/app/go.mod",
	"/go.mod",
	"/src/go.mod",
	"/workspace/go.mod",
}

// binDirs are the common locations for compiled binaries in a container.
var binDirs = []string{
	"/app/",
	"/usr/local/bin/",
	"/",
	"/bin/",
	"/usr/bin/",
}

// Cataloger implements catalog.Cataloger for Go modules.
type Cataloger struct{}

// New returns a Go cataloger.
func New() *Cataloger { return &Cataloger{} }

func (*Cataloger) Name() string { return "go" }

func (c *Cataloger) Match(fs model.FileSystemView) bool {
	for _, p := range goModCandidates {
		if _, ok := fs.Get(p); ok {
			return true
		}
	}
	// Check for any Go binary in common bin directories.
	for _, dir := range binDirs {
		var found bool
		_ = fs.Walk(dir, func(e *model.FileEntry) error {
			if e.IsDeleted || e.IsDir || e.IsSymlink {
				return nil
			}
			if isGoBinary(fs, e) {
				found = true
				return model.ErrWalkStop
			}
			return nil
		})
		if found {
			return true
		}
	}
	return false
}

func (c *Cataloger) Catalog(_ context.Context, fs model.FileSystemView) ([]model.Package, error) {
	var pkgs []model.Package
	seen := make(map[string]bool)

	// Source 1: go.mod files.
	for _, p := range goModCandidates {
		e, ok := fs.Get(p)
		if !ok {
			continue
		}
		modPkgs, err := catalogGoMod(fs, p, e.LayerDigest)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		for _, pkg := range modPkgs {
			key := pkg.Name + "@" + pkg.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			pkgs = append(pkgs, pkg)
		}
	}

	// Source 2: Go binaries with embedded build info.
	binPkgs, err := catalogBinaries(fs)
	if err != nil {
		return nil, err
	}
	for _, pkg := range binPkgs {
		key := pkg.Name + "@" + pkg.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}

// catalogGoMod parses a single go.mod file and returns its required modules.
func catalogGoMod(fs model.FileSystemView, path, layerDigest string) ([]model.Package, error) {
	lines, _, err := catalog.ReadLines(fs, path)
	if err != nil {
		return nil, err
	}
	mods := parseGoMod(lines)
	var pkgs []model.Package
	for _, m := range mods {
		pkgs = append(pkgs, model.Package{
			Type:       "go",
			Ecosystem:  "golang",
			Name:       m.path,
			Version:    m.version,
			PURL:       catalog.PURL("golang", m.path, m.version),
			LayerDigest: layerDigest,
			Locations:  []model.Location{{Path: path, LayerDigest: layerDigest}},
			Metadata:   map[string]string{"source": "go.mod"},
		})
	}
	return pkgs, nil
}

// moduleRef is a parsed require entry from go.mod.
type moduleRef struct {
	path    string
	version string
}

// parseGoMod extracts module path/version pairs from require directives.
// Replace and exclude directives are skipped. Indirect dependencies are
// retained (they are installed).
func parseGoMod(lines []string) []moduleRef {
	var mods []moduleRef
	inBlock := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if inBlock {
			if line == ")" {
				inBlock = false
				continue
			}
			if m := parseRequireLine(line); m != nil {
				mods = append(mods, *m)
			}
			continue
		}
		if strings.HasPrefix(line, "require ") {
			rest := strings.TrimPrefix(line, "require ")
			rest = strings.TrimSpace(rest)
			if rest == "(" {
				inBlock = true
				continue
			}
			if m := parseRequireLine(rest); m != nil {
				mods = append(mods, *m)
			}
			continue
		}
		// Skip replace, exclude, retract, toolchain, go, module directives.
	}
	return mods
}

// parseRequireLine parses a single "module-path version [// indirect]" line.
func parseRequireLine(line string) *moduleRef {
	// Strip trailing comments.
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	return &moduleRef{path: fields[0], version: fields[1]}
}

// catalogBinaries walks common binary locations and extracts Go build info
// dependencies from each Go binary found.
func catalogBinaries(fs model.FileSystemView) ([]model.Package, error) {
	var pkgs []model.Package
	for _, dir := range binDirs {
		_ = fs.Walk(dir, func(e *model.FileEntry) error {
			if e.IsDeleted || e.IsDir || e.IsSymlink {
				return nil
			}
			bi, ok := readBuildInfo(fs, e)
			if !ok || bi == nil {
				return nil
			}
			for _, dep := range bi.Deps {
				if dep.Path == "" || dep.Version == "" {
					continue
				}
				pkgs = append(pkgs, model.Package{
					Type:       "go",
					Ecosystem:  "golang",
					Name:       dep.Path,
					Version:    dep.Version,
					PURL:       catalog.PURL("golang", dep.Path, dep.Version),
					LayerDigest: e.LayerDigest,
					Locations:  []model.Location{{Path: e.Path, LayerDigest: e.LayerDigest}},
					Metadata:   map[string]string{"source": "binary-buildinfo"},
				})
			}
			return nil
		})
	}
	return pkgs, nil
}

// readBuildInfo reads a file from the view and attempts to parse Go build info
// from its bytes. Returns (info, true) if the file is a Go binary with build
// info, (nil, false) otherwise.
func readBuildInfo(fs model.FileSystemView, e *model.FileEntry) (*buildinfo.BuildInfo, bool) {
	rc, err := fs.Open(e.Path)
	if err != nil {
		return nil, false
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, false
	}
	bi, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil || bi == nil {
		return nil, false
	}
	return bi, true
}

// isGoBinary reports whether the file at entry contains Go build info.
func isGoBinary(fs model.FileSystemView, e *model.FileEntry) bool {
	bi, ok := readBuildInfo(fs, e)
	if !ok || bi == nil {
		return false
	}
	return bi.GoVersion != ""
}

// Ensure the cataloger satisfies the interface.
var _ catalog.Cataloger = (*Cataloger)(nil)
