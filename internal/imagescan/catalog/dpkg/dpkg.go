// Package dpkg catalogs Debian/Ubuntu packages by parsing the dpkg status
// database at /var/lib/dpkg/status. Each paragraph is an RFC-823-style
// stanza with fields like Package, Version, Architecture, Source, and
// Status.
//
// Only installed packages (Status: "install ok installed") are emitted.
// The Source field, when present, carries the upstream source package name
// and optional version — essential for Debian/Ubuntu vendor-first matching.
package dpkg

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// dbPath is the canonical location of the dpkg status database.
const dbPath = "/var/lib/dpkg/status"

// Cataloger implements catalog.Cataloger for Debian/Ubuntu dpkg packages.
type Cataloger struct{}

// New returns a dpkg cataloger.
func New() *Cataloger { return &Cataloger{} }

func (*Cataloger) Name() string { return "dpkg" }

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

	pkgs, err := parseStatus(rc)
	if err != nil {
		return nil, err
	}
	for i := range pkgs {
		pkgs[i].Type = "os"
		pkgs[i].Ecosystem = "deb"
		pkgs[i].LayerDigest = e.LayerDigest
		pkgs[i].Locations = []model.Location{{Path: dbPath, LayerDigest: e.LayerDigest}}
		pkgs[i].PURL = buildPURL(pkgs[i])
	}
	return pkgs, nil
}

// parseStatus parses the dpkg status file into packages, keeping only
// installed ones.
func parseStatus(r io.Reader) ([]model.Package, error) {
	var pkgs []model.Package
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)

	type stanza = map[string]string
	cur := make(stanza)

	flush := func() {
		if cur["Package"] == "" {
			cur = make(stanza)
			return
		}
		// Only keep installed packages.
		if !strings.Contains(cur["Status"], "install ok installed") {
			cur = make(stanza)
			return
		}
		p := model.Package{
			Name:         cur["Package"],
			Version:      cur["Version"],
			Architecture: cur["Architecture"],
		}
		// Source may carry a version in parentheses: "foo (1.2-3)".
		if src := cur["Source"]; src != "" {
			p.SourcePackage, p.SourceVersion = splitSource(src)
		}
		if cur["Description"] != "" {
			p.Metadata = map[string]string{"description": firstLine(cur["Description"])}
		}
		pkgs = append(pkgs, p)
		cur = make(stanza)
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		// Continuation lines start with whitespace and belong to the
		// previous field (common for Description).
		if line[0] == ' ' || line[0] == '\t' {
			if len(cur) > 0 {
				// Append to the most recently inserted key. We track it
				// via a sentinel; simpler: append to "Description" if set.
				if _, ok := cur["Description"]; ok {
					cur["Description"] += "\n" + strings.TrimSpace(line)
				}
			}
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := line[:idx]
		val := strings.TrimSpace(line[idx+1:])
		cur[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan dpkg status: %w", err)
	}
	// Flush the last stanza (status files may not end with a blank line).
	if len(cur) > 0 {
		flush()
	}
	return pkgs, nil
}

// splitSource splits a Source field like "foo (1.2-3)" into name and version.
func splitSource(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, '('); idx >= 0 {
		name = strings.TrimSpace(s[:idx])
		version = strings.Trim(s[idx:], "()")
		version = strings.TrimSpace(version)
		return name, version
	}
	return s, ""
}

// firstLine returns the first line of a (possibly multi-line) description.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// buildPURL constructs a Package URL for a Debian package.
// Format: pkg:deb/<distro>/<name>@<version>?arch=<arch>
// The distro is filled later by the matcher using OS context; here we use
// "debian" as a placeholder ecosystem qualifier.
func buildPURL(p model.Package) string {
	purl := fmt.Sprintf("pkg:deb/%s@%s", p.Name, p.Version)
	if p.Architecture != "" {
		purl += "?arch=" + p.Architecture
	}
	if p.SourcePackage != "" {
		purl += "&source=" + p.SourcePackage
	}
	return purl
}

// Ensure the cataloger satisfies the interface.
var _ catalog.Cataloger = (*Cataloger)(nil)
