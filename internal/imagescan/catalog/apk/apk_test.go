package apk

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// fakeFS is a minimal FileSystemView for parser tests.
type fakeFS struct {
	entries map[string]*model.FileEntry
	content map[string]string
}

func (f *fakeFS) Get(path string) (*model.FileEntry, bool) {
	e, ok := f.entries[path]
	return e, ok
}
func (f *fakeFS) Open(path string) (model.ContentReader, error) {
	c, ok := f.content[path]
	if !ok {
		return nil, errNotFound{}
	}
	return io.NopCloser(strings.NewReader(c)), nil
}
func (f *fakeFS) Walk(prefix string, fn func(*model.FileEntry) error) error {
	return nil
}
func (f *fakeFS) Entries() int { return len(f.entries) }

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

func TestParseDB(t *testing.T) {
	input := `P:openssl
V:3.1.4-r1
A:x86_64
o:openssl
T:TLS library
F:usr/lib
R:libssl.so.3

P:busybox
V:1.36.1-r29
A:x86_64
o:busybox
T:Swiss army knife

`
	pkgs, err := parseDB(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseDB: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "openssl" || pkgs[0].Version != "3.1.4-r1" {
		t.Errorf("pkg0 = %+v", pkgs[0])
	}
	if pkgs[0].Architecture != "x86_64" {
		t.Errorf("arch = %q", pkgs[0].Architecture)
	}
	if pkgs[0].SourcePackage != "openssl" {
		t.Errorf("source = %q", pkgs[0].SourcePackage)
	}
	if pkgs[1].Name != "busybox" || pkgs[1].Version != "1.36.1-r29" {
		t.Errorf("pkg1 = %+v", pkgs[1])
	}
}

func TestCatalogAttachesLayerAndPURL(t *testing.T) {
	const db = `P:zlib
V:1.3.1-r0
A:x86_64
o:zlib
`
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			dbPath: {Path: dbPath, LayerDigest: "sha256:layerAAA"},
		},
		content: map[string]string{dbPath: db},
	}
	c := New()
	if !c.Match(fs) {
		t.Fatal("expected Match=true")
	}
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	p := pkgs[0]
	if p.LayerDigest != "sha256:layerAAA" {
		t.Errorf("LayerDigest = %q", p.LayerDigest)
	}
	if p.Type != "os" || p.Ecosystem != "alpine" {
		t.Errorf("Type/Ecosystem = %q/%q", p.Type, p.Ecosystem)
	}
	if p.PURL != "pkg:alpine/zlib@1.3.1-r0?arch=x86_64" {
		t.Errorf("PURL = %q", p.PURL)
	}
	if len(p.Locations) != 1 || p.Locations[0].Path != dbPath {
		t.Errorf("Locations = %+v", p.Locations)
	}
}
