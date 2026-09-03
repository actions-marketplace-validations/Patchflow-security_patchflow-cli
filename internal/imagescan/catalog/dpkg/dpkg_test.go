package dpkg

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

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
func (f *fakeFS) Walk(prefix string, fn func(*model.FileEntry) error) error { return nil }
func (f *fakeFS) Entries() int                                                { return len(f.entries) }

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

func TestParseStatus(t *testing.T) {
	input := `Package: openssl
Status: install ok installed
Priority: optional
Section: utils
Architecture: amd64
Source: openssl (3.0.11-1)
Version: 3.0.11-1

Package: old-removed
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1

Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.36-9+deb12u4

`
	pkgs, err := parseStatus(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	// Only installed packages should be returned; old-removed is not.
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 installed packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "openssl" || pkgs[0].Version != "3.0.11-1" {
		t.Errorf("pkg0 = %+v", pkgs[0])
	}
	if pkgs[0].Architecture != "amd64" {
		t.Errorf("arch = %q", pkgs[0].Architecture)
	}
	if pkgs[0].SourcePackage != "openssl" || pkgs[0].SourceVersion != "3.0.11-1" {
		t.Errorf("source = %q/%q", pkgs[0].SourcePackage, pkgs[0].SourceVersion)
	}
	if pkgs[1].Name != "libc6" {
		t.Errorf("pkg1 = %+v", pkgs[1])
	}
}

func TestCatalogAttachesLayerAndPURL(t *testing.T) {
	const db = `Package: zlib1g
Status: install ok installed
Architecture: amd64
Version: 1:1.2.13-5
`
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			dbPath: {Path: dbPath, LayerDigest: "sha256:layerBBB"},
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
	if p.LayerDigest != "sha256:layerBBB" {
		t.Errorf("LayerDigest = %q", p.LayerDigest)
	}
	if p.Type != "os" || p.Ecosystem != "deb" {
		t.Errorf("Type/Ecosystem = %q/%q", p.Type, p.Ecosystem)
	}
	wantPURL := "pkg:deb/zlib1g@1:1.2.13-5?arch=amd64"
	if p.PURL != wantPURL {
		t.Errorf("PURL = %q, want %q", p.PURL, wantPURL)
	}
}

func TestSplitSource(t *testing.T) {
	cases := []struct {
		in, name, ver string
	}{
		{"foo (1.2-3)", "foo", "1.2-3"},
		{"foo", "foo", ""},
		{"  bar  ( 4.5 )  ", "bar", "4.5"},
	}
	for _, c := range cases {
		name, ver := splitSource(c.in)
		if name != c.name || ver != c.ver {
			t.Errorf("splitSource(%q) = (%q,%q), want (%q,%q)", c.in, name, ver, c.name, c.ver)
		}
	}
}
