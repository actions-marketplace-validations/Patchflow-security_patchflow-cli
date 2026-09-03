// Package apk catalogs Alpine Linux packages by parsing the APK installed
// database at /lib/apk/db/installed. Each package stanza records the
// package name, version, architecture, origin (source package), and
// installed files.
//
// The APK database format is a flat text file with stanzas separated by
// blank lines. Key fields:
//
//	P: package name
//	V: version
//	A: architecture
//	o: origin (source package name)
//	F: directory path (file list follows)
//	R: file path relative to the preceding F
package apk

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// dbPath is the canonical location of the APK installed database.
const dbPath = "/lib/apk/db/installed"

// Cataloger implements catalog.Cataloger for Alpine APK packages.
type Cataloger struct{}

// New returns an APK cataloger.
func New() *Cataloger { return &Cataloger{} }

func (*Cataloger) Name() string { return "apk" }

func (*Cataloger) Match(fs model.FileSystemView) bool {
	_, ok := fs.Get(dbPath)
	return ok
}

func (c *Cataloger) Catalog(_ context.Context, fs model.FileSystemView) ([]model.Package, error) {
	e, ok := fs.Get(dbPath)
	if !ok {
		return nil, nil
	}
	rc, err := fs.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dbPath, err)
	}
	defer rc.Close()

	pkgs, err := parseDB(rc)
	if err != nil {
		return nil, err
	}
	// Attach layer attribution from the db file's provenance.
	for i := range pkgs {
		pkgs[i].Type = "os"
		pkgs[i].Ecosystem = "alpine"
		pkgs[i].LayerDigest = e.LayerDigest
		pkgs[i].Locations = []model.Location{{Path: dbPath, LayerDigest: e.LayerDigest}}
		pkgs[i].PURL = buildPURL(pkgs[i])
	}
	return pkgs, nil
}

// parseDB parses the APK installed database into packages.
func parseDB(r io.Reader) ([]model.Package, error) {
	var pkgs []model.Package
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var cur *model.Package
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if cur != nil && cur.Name != "" {
				pkgs = append(pkgs, *cur)
			}
			cur = nil
			continue
		}
		// Lines are "X:value" where X is a single-letter field.
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		field := line[0]
		val := line[2:]

		if cur == nil {
			cur = &model.Package{}
		}
		switch field {
		case 'P':
			cur.Name = val
		case 'V':
			cur.Version = val
		case 'A':
			cur.Architecture = val
		case 'o':
			cur.SourcePackage = val
		case 'T':
			cur.Metadata = setMeta(cur.Metadata, "description", val)
		case 'm':
			cur.Metadata = setMeta(cur.Metadata, "maintainer", val)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan apk db: %w", err)
	}
	if cur != nil && cur.Name != "" {
		pkgs = append(pkgs, *cur)
	}
	return pkgs, nil
}

// buildPURL constructs a Package URL for an Alpine package.
// Format: pkg:alpine/<name>@<version>?arch=<arch>
func buildPURL(p model.Package) string {
	purl := fmt.Sprintf("pkg:alpine/%s@%s", p.Name, p.Version)
	if p.Architecture != "" {
		purl += "?arch=" + p.Architecture
	}
	return purl
}

func setMeta(m map[string]string, k, v string) map[string]string {
	if m == nil {
		m = make(map[string]string)
	}
	m[k] = v
	return m
}

// Ensure the cataloger satisfies the interface.
var _ catalog.Cataloger = (*Cataloger)(nil)

// _ keeps strings referenced for future CPE/qualifier logic.
var _ = strings.TrimSpace
