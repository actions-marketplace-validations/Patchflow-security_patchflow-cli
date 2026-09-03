// Package java catalogs Java/JVM packages by inspecting JAR, WAR, and EAR
// archives in the reconstructed filesystem view. These archives are ZIP files;
// Maven-built artifacts embed pom.properties under
// META-INF/maven/{groupId}/{artifactId}/pom.properties, which is the most
// reliable source of Maven coordinates. When pom.properties is absent the
// cataloger falls back to the Implementation-Title / Implementation-Version
// headers of META-INF/MANIFEST.MF.
//
// Fat jars (spring-boot, shade, etc.) bundle nested JARs under BOOT-INF/lib or
// similar paths. Nested JARs are inspected recursively up to depth 3.
package java

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// maxNestDepth caps recursive descent into nested JARs to bound work on
// pathological archives.
const maxNestDepth = 3

// Cataloger implements catalog.Cataloger for Java/JVM archives.
type Cataloger struct{}

// New returns a Java cataloger.
func New() *Cataloger { return &Cataloger{} }

func (*Cataloger) Name() string { return "java" }

func (*Cataloger) Match(fs model.FileSystemView) bool {
	files, err := catalog.FindFiles(fs, ".jar", ".war", ".ear")
	if err != nil {
		return false
	}
	return len(files) > 0
}

func (c *Cataloger) Catalog(_ context.Context, fs model.FileSystemView) ([]model.Package, error) {
	files, err := catalog.FindFiles(fs, ".jar", ".war", ".ear")
	if err != nil {
		return nil, fmt.Errorf("java: find archives: %w", err)
	}
	var pkgs []model.Package
	for _, e := range files {
		rc, err := fs.Open(e.Path)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		found := scanZip(data, e.Path, e.LayerDigest, 1)
		for i := range found {
			found[i].Type = "java"
			found[i].Ecosystem = "maven"
			found[i].LayerDigest = e.LayerDigest
		}
		pkgs = append(pkgs, found...)
	}
	return pkgs, nil
}

// scanZip parses a ZIP byte blob (a JAR/WAR/EAR or a nested JAR) and returns
// discovered packages. depth is the current nesting level (1 = top-level
// archive). The outerPath/layer pair attribute every discovered package to the
// top-level archive on disk.
func scanZip(data []byte, outerPath, layer string, depth int) []model.Package {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		// Malformed ZIP — skip with a warning via package-level log sink is
		// overkill; we simply drop the archive.
		return nil
	}
	var pkgs []model.Package
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "pom.properties") &&
			strings.HasPrefix(f.Name, "META-INF/maven/") {
			p := parsePomProperties(f, outerPath, layer)
			if p != nil {
				pkgs = append(pkgs, *p)
			}
			continue
		}
		// Recurse into nested JARs (fat jars).
		if depth < maxNestDepth && strings.HasSuffix(f.Name, ".jar") {
			inner, err := readZipEntry(f)
			if err != nil {
				continue
			}
			pkgs = append(pkgs, scanZip(inner, outerPath, layer, depth+1)...)
		}
	}
	// Manifest fallback only when no pom.properties packages were found at
	// this level.
	if len(pkgs) == 0 {
		if mf := findEntry(zr, "META-INF/MANIFEST.MF"); mf != nil {
			if p := parseManifest(mf, outerPath, layer); p != nil {
				pkgs = append(pkgs, *p)
			}
		}
	}
	return pkgs
}

// parsePomProperties reads a Maven pom.properties entry and builds a Package.
func parsePomProperties(f *zip.File, outerPath, layer string) *model.Package {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	props := readProperties(rc)
	groupID := props["groupId"]
	artifactID := props["artifactId"]
	version := props["version"]
	if artifactID == "" || version == "" {
		return nil
	}
	return &model.Package{
		Name:          artifactID,
		Version:       version,
		SourcePackage: groupID,
		PURL:          catalog.MavenPURL(groupID, artifactID, version),
		Locations:     []model.Location{{Path: outerPath, LayerDigest: layer}},
		Metadata:      map[string]string{"source": "pom.properties"},
	}
}

// parseManifest reads a MANIFEST.MF entry and builds a Package from the
// Implementation-Title / Implementation-Version headers. groupId is unknown in
// this case.
func parseManifest(f *zip.File, outerPath, layer string) *model.Package {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	hdrs := readManifestHeaders(rc)
	name := hdrs["Implementation-Title"]
	version := hdrs["Implementation-Version"]
	if name == "" || version == "" {
		return nil
	}
	return &model.Package{
		Name:      name,
		Version:   version,
		PURL:      catalog.MavenPURL("", name, version),
		Locations: []model.Location{{Path: outerPath, LayerDigest: layer}},
		Metadata:  map[string]string{"source": "manifest"},
	}
}

// readProperties parses a Java .properties stream into a map. Lines are
// "key=value"; blank lines and lines starting with '#' are comments.
func readProperties(r io.Reader) map[string]string {
	m := make(map[string]string)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		m[key] = val
	}
	return m
}

// readManifestHeaders parses the manifest main section headers. Manifest
// continuation lines (values folded onto the next line beginning with a single
// space) are joined. Header names are case-insensitive; keys are returned with
// their original casing as written.
func readManifestHeaders(r io.Reader) map[string]string {
	m := make(map[string]string)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var lastKey string
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of main section
		}
		// Continuation line: starts with a single space.
		if strings.HasPrefix(line, " ") {
			if lastKey != "" {
				m[lastKey] += strings.TrimSpace(line)
			}
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		m[key] = val
		lastKey = key
	}
	return m
}

// findEntry returns the zip.File for the given name, or nil if absent.
func findEntry(zr *zip.Reader, name string) *zip.File {
	for _, f := range zr.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// readZipEntry opens a zip.File and reads its full content.
func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// Ensure the cataloger satisfies the interface.
var _ catalog.Cataloger = (*Cataloger)(nil)
