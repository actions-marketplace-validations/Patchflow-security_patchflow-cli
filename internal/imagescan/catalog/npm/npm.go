// Package npm catalogs JavaScript packages by parsing npm lockfiles
// (package-lock.json) and installed node_modules trees.
//
// Two lockfile shapes are supported:
//
//   - lockfileVersion 2/3: a flat "packages" map keyed by install path
//     (e.g. "node_modules/express", "node_modules/@scope/name"). The root
//     project entry (key "") is skipped. Each value carries version,
//     resolved, integrity, dev, optional, and link flags.
//   - lockfileVersion 1: a recursive "dependencies" tree where each node
//     has version, dev, optional, and a nested "dependencies" map.
//
// Installed packages are also discovered by walking node_modules directories
// and reading each package's package.json (name + version). Both sources are
// emitted when present; deduplication is the matcher's responsibility.
package npm

import (
	"context"
	"fmt"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// Cataloger implements catalog.Cataloger for npm packages.
type Cataloger struct{}

// New returns an npm cataloger.
func New() *Cataloger { return &Cataloger{} }

func (*Cataloger) Name() string { return "npm" }

// Match reports whether npm packages may be present: a package-lock.json
// anywhere in the view, or any node_modules/ directory.
func (*Cataloger) Match(fs model.FileSystemView) bool {
	if locks, err := catalog.FindFiles(fs, "package-lock.json"); err == nil && len(locks) > 0 {
		return true
	}
	hit := false
	_ = fs.Walk("/", func(e *model.FileEntry) error {
		if e.IsDeleted {
			return nil
		}
		if strings.Contains(e.Path, "/node_modules/") || strings.HasSuffix(e.Path, "/node_modules") || e.Path == "node_modules" {
			hit = true
		}
		return nil
	})
	return hit
}

// lockEntry is one value in the lockfileVersion 2/3 "packages" map.
type lockEntry struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
	Optional  bool   `json:"optional"`
	Link      bool   `json:"link"`
}

// lockDep is one node in the lockfileVersion 1 "dependencies" tree.
type lockDep struct {
	Version      string             `json:"version"`
	Dev          bool               `json:"dev"`
	Optional     bool               `json:"optional"`
	Dependencies map[string]lockDep `json:"dependencies"`
}

type lockfile struct {
	LockfileVersion int                  `json:"lockfileVersion"`
	Packages        map[string]lockEntry `json:"packages"`
	Dependencies    map[string]lockDep   `json:"dependencies"`
}

func (c *Cataloger) Catalog(_ context.Context, fs model.FileSystemView) ([]model.Package, error) {
	var pkgs []model.Package

	// Source 1: package-lock.json files.
	locks, err := catalog.FindFiles(fs, "package-lock.json")
	if err != nil {
		return nil, fmt.Errorf("find lockfiles: %w", err)
	}
	for _, e := range locks {
		got, err := c.parseLockfile(fs, e.Path, e.LayerDigest)
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, got...)
	}

	// Source 2: node_modules/*/package.json (and nested node_modules).
	nm, err := c.parseNodeModules(fs)
	if err != nil {
		return nil, err
	}
	pkgs = append(pkgs, nm...)

	return pkgs, nil
}

// parseLockfile parses a single package-lock.json and emits packages.
func (c *Cataloger) parseLockfile(fs model.FileSystemView, path, layer string) ([]model.Package, error) {
	var lf lockfile
	e, err := catalog.ReadJSON(fs, path, &lf)
	if err != nil {
		// Malformed lockfile: skip rather than abort the whole catalog.
		return nil, nil
	}
	if e != nil && layer == "" {
		layer = e.LayerDigest
	}

	var pkgs []model.Package
	switch {
	case lf.LockfileVersion >= 2 && len(lf.Packages) > 0:
		// v2/v3: flat packages map keyed by install path.
		for key, ent := range lf.Packages {
			if key == "" { // root project entry
				continue
			}
			if ent.Link || ent.Version == "" {
				continue
			}
			name := nameFromKey(key)
			if name == "" {
				continue
			}
			pkgs = append(pkgs, makePkg(name, ent.Version, path, layer, "lockfile", ent.Dev))
		}
	default:
		// v1 (or v2/v3 with no packages map): recursive dependencies tree.
		walkDeps(lf.Dependencies, path, layer, &pkgs)
	}
	return pkgs, nil
}

// walkDeps recursively walks a lockfileVersion 1 dependencies tree.
func walkDeps(deps map[string]lockDep, path, layer string, out *[]model.Package) {
	for name, d := range deps {
		if d.Version == "" {
			continue
		}
		*out = append(*out, makePkg(name, d.Version, path, layer, "lockfile", d.Dev))
		if len(d.Dependencies) > 0 {
			walkDeps(d.Dependencies, path, layer, out)
		}
	}
}

// parseNodeModules walks node_modules trees and reads each package.json.
func (c *Cataloger) parseNodeModules(fs model.FileSystemView) ([]model.Package, error) {
	all, err := catalog.FindFiles(fs, "/package.json")
	if err != nil {
		return nil, fmt.Errorf("find package.json: %w", err)
	}
	var pkgs []model.Package
	for _, e := range all {
		if !isNodeModulesPkg(e.Path) {
			continue
		}
		var pj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if _, err := catalog.ReadJSON(fs, e.Path, &pj); err != nil {
			// Malformed package.json: skip this entry, keep going.
			continue
		}
		if pj.Name == "" || pj.Version == "" {
			continue
		}
		pkgs = append(pkgs, makePkg(pj.Name, pj.Version, e.Path, e.LayerDigest, "node_modules", false))
	}
	return pkgs, nil
}

// isNodeModulesPkg reports whether path is a package.json directly inside a
// node_modules package directory (top-level or nested under another
// package's node_modules).
func isNodeModulesPkg(path string) bool {
	if !strings.HasSuffix(path, "/package.json") {
		return false
	}
	if !strings.Contains(path, "/node_modules/") {
		return false
	}
	// The segment immediately before "/package.json" must be a package name,
	// not "node_modules".
	dir := strings.TrimSuffix(path, "/package.json")
	idx := strings.LastIndex(dir, "/")
	if idx < 0 {
		return false
	}
	return dir[idx+1:] != "node_modules"
}

// nameFromKey derives the npm package name from a lockfile packages key.
// "node_modules/express" -> "express"; "node_modules/@scope/name" ->
// "@scope/name"; "node_modules/a/node_modules/b" -> "b".
func nameFromKey(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		return ""
	}
	return key[idx+len("node_modules/"):]
}

// makePkg builds a model.Package with the common npm attribution.
func makePkg(name, version, path, layer, source string, dev bool) model.Package {
	m := map[string]string{"source": source}
	if dev {
		m["dev"] = "true"
	}
	return model.Package{
		Name:        name,
		Version:     version,
		Type:        "npm",
		Ecosystem:   "npm",
		PURL:        catalog.PURL("npm", name, version),
		LayerDigest: layer,
		Locations:   []model.Location{{Path: path, LayerDigest: layer}},
		Metadata:    m,
	}
}

// Ensure the cataloger satisfies the interface.
var _ catalog.Cataloger = (*Cataloger)(nil)
