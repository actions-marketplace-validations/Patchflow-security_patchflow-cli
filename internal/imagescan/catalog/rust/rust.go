// Package rust catalogs Rust (Cargo) packages by parsing Cargo.lock. Each
// [[package]] entry records the crate name, version, source (registry URL) and
// checksum. Local path crates (no source field) are skipped — they are not
// publishable and have no advisory surface.
//
// Cargo.lock is a simple TOML subset: a top-level `version = N` line followed
// by repeated [[package]] tables with `key = "value"` lines. We parse it with
// a line-based scanner rather than pulling in a TOML dependency.
package rust

import (
	"context"
	"fmt"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// commonPaths are the well-known locations for Cargo.lock in a container.
var commonPaths = []string{"/app/Cargo.lock", "/Cargo.lock", "/src/Cargo.lock"}

// Cataloger implements catalog.Cataloger for Rust Cargo packages.
type Cataloger struct{}

// New returns a Rust cataloger.
func New() *Cataloger { return &Cataloger{} }

func (*Cataloger) Name() string { return "rust" }

func (*Cataloger) Match(fs model.FileSystemView) bool {
	for _, p := range commonPaths {
		if _, ok := fs.Get(p); ok {
			return true
		}
	}
	// Shallow walk for any Cargo.lock elsewhere in the view.
	var found bool
	_ = fs.Walk("/", func(e *model.FileEntry) error {
		if e.IsDeleted {
			return nil
		}
		if strings.HasSuffix(e.Path, "/Cargo.lock") {
			found = true
			return model.ErrWalkStop
		}
		return nil
	})
	return found
}

func (c *Cataloger) Catalog(_ context.Context, fs model.FileSystemView) ([]model.Package, error) {
	path, ok := findCargoLock(fs)
	if !ok {
		return nil, nil
	}
	lines, entry, err := catalog.ReadLines(fs, path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	pkgs := parseCargoLock(lines)
	for i := range pkgs {
		pkgs[i].Type = "rust"
		pkgs[i].Ecosystem = "cargo"
		pkgs[i].LayerDigest = entry.LayerDigest
		pkgs[i].Locations = []model.Location{{Path: path, LayerDigest: entry.LayerDigest}}
		pkgs[i].PURL = catalog.PURL("cargo", pkgs[i].Name, pkgs[i].Version)
	}
	return pkgs, nil
}

// findCargoLock returns the first Cargo.lock path present in the view, checking
// common locations then falling back to a shallow walk.
func findCargoLock(fs model.FileSystemView) (string, bool) {
	for _, p := range commonPaths {
		if _, ok := fs.Get(p); ok {
			return p, true
		}
	}
	var hit string
	_ = fs.Walk("/", func(e *model.FileEntry) error {
		if e.IsDeleted {
			return nil
		}
		if strings.HasSuffix(e.Path, "/Cargo.lock") {
			hit = e.Path
			return model.ErrWalkStop
		}
		return nil
	})
	if hit != "" {
		return hit, true
	}
	return "", false
}

// parseCargoLock parses the line-based Cargo.lock TOML subset into packages.
// Only [[package]] tables with a `source` field are emitted (local path crates
// are skipped). Malformed entries are skipped rather than aborting the parse.
func parseCargoLock(lines []string) []model.Package {
	var pkgs []model.Package
	var cur *model.Package
	inPackage := false

	flush := func() {
		if cur != nil && cur.Name != "" && cur.Version != "" {
			// Skip local path crates (no source field).
			if src, ok := cur.Metadata["source"]; ok && src != "" {
				pkgs = append(pkgs, *cur)
			}
		}
		cur = nil
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case line == "[[package]]":
			flush()
			cur = &model.Package{Metadata: make(map[string]string)}
			inPackage = true
		case strings.HasPrefix(line, "["):
			// Entering a different table; close the current package.
			flush()
			inPackage = false
			continue
		}

		if !inPackage || cur == nil {
			continue
		}

		key, val, ok := splitKV(line)
		if !ok {
			continue
		}
		switch key {
		case "name":
			cur.Name = val
		case "version":
			cur.Version = val
		case "source":
			cur.Metadata["source"] = val
		}
	}
	flush()
	return pkgs
}

// splitKV splits a `key = "value"` (or `key = value`) TOML line into its
// trimmed key and value. Quoted values are unquoted; bare values are returned
// as-is. Returns ok=false for lines without an `=`.
func splitKV(line string) (key, val string, ok bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	val = strings.TrimSpace(line[idx+1:])
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return key, val, true
}

// Ensure the cataloger satisfies the interface.
var _ catalog.Cataloger = (*Cataloger)(nil)
