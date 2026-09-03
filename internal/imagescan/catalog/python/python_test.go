package python

import (
	"context"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// fakeFS is a minimal FileSystemView for cataloger tests. Unlike the apk
// fakeFS, Walk iterates over the in-memory entries so WalkDir/FindFiles work.
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
	// Match the real View.Walk semantics: empty or "/" prefix means all
	// entries; otherwise include the prefix itself and all children.
	var paths []string
	for path, e := range f.entries {
		if e.IsDeleted {
			continue
		}
		if prefix == "" || prefix == "/" || path == prefix || strings.HasPrefix(path, prefix+"/") {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := fn(f.entries[path]); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeFS) Entries() int { return len(f.entries) }

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

func TestParseDistInfo(t *testing.T) {
	const (
		flaskMeta = "/usr/lib/python3.11/site-packages/Flask-2.3.0.dist-info/METADATA"
		reqMeta   = "/usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA"
	)
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			flaskMeta: {Path: flaskMeta, LayerDigest: "sha256:layerA"},
			reqMeta:   {Path: reqMeta, LayerDigest: "sha256:layerB"},
		},
		content: map[string]string{
			flaskMeta: "Metadata-Version: 2.1\nName: Flask\nVersion: 2.3.0\nSummary: A framework.\n",
			reqMeta:   "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
		},
	}
	c := New()
	if !c.Match(fs) {
		t.Fatal("expected Match=true")
	}
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	// WalkDir sorts by path: Flask-... before requests-...
	if pkgs[0].Name != "Flask" || pkgs[0].Version != "2.3.0" {
		t.Errorf("pkg0 = %+v", pkgs[0])
	}
	if pkgs[1].Name != "requests" || pkgs[1].Version != "2.31.0" {
		t.Errorf("pkg1 = %+v", pkgs[1])
	}
	// PEP 503 normalisation: Flask -> flask
	if pkgs[0].PURL != "pkg:pypi/flask@2.3.0" {
		t.Errorf("PURL0 = %q", pkgs[0].PURL)
	}
	if pkgs[1].PURL != "pkg:pypi/requests@2.31.0" {
		t.Errorf("PURL1 = %q", pkgs[1].PURL)
	}
	// Layer attribution.
	if pkgs[0].LayerDigest != "sha256:layerA" {
		t.Errorf("LayerDigest0 = %q", pkgs[0].LayerDigest)
	}
	if pkgs[1].LayerDigest != "sha256:layerB" {
		t.Errorf("LayerDigest1 = %q", pkgs[1].LayerDigest)
	}
	if pkgs[0].Metadata["source"] != "dist-info" {
		t.Errorf("source0 = %q", pkgs[0].Metadata["source"])
	}
}

func TestParseEggInfo(t *testing.T) {
	const pkgInfo = "/usr/local/lib/python3.12/site-packages/Django-4.2.egg-info/PKG-INFO"
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			pkgInfo: {Path: pkgInfo, LayerDigest: "sha256:eggLayer"},
		},
		content: map[string]string{
			pkgInfo: "Metadata-Version: 1.0\nName: Django\nVersion: 4.2\n",
		},
	}
	c := New()
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	p := pkgs[0]
	if p.Name != "Django" || p.Version != "4.2" {
		t.Errorf("pkg = %+v", p)
	}
	if p.PURL != "pkg:pypi/django@4.2" {
		t.Errorf("PURL = %q", p.PURL)
	}
	if p.Metadata["source"] != "egg-info" {
		t.Errorf("source = %q", p.Metadata["source"])
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	const req = "/app/requirements.txt"
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			req: {Path: req, LayerDigest: "sha256:reqLayer"},
		},
		content: map[string]string{
			req: "flask==2.3.0\n" +
				"requests>=2.31\n" +
				"# a comment\n" +
				"\n" +
				"numpy~=1.26.0\n" +
				"-r other.txt\n" +
				"click===8.1.0\n" +
				"urllib3<2.0\n",
		},
	}
	c := New()
	if !c.Match(fs) {
		t.Fatal("expected Match=true")
	}
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 pinned packages, got %d (%+v)", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "flask" || pkgs[0].Version != "2.3.0" {
		t.Errorf("pkg0 = %+v", pkgs[0])
	}
	if pkgs[1].Name != "click" || pkgs[1].Version != "8.1.0" {
		t.Errorf("pkg1 = %+v", pkgs[1])
	}
	if pkgs[0].Metadata["source"] != "requirements.txt" {
		t.Errorf("source = %q", pkgs[0].Metadata["source"])
	}
	if pkgs[0].LayerDigest != "sha256:reqLayer" {
		t.Errorf("LayerDigest = %q", pkgs[0].LayerDigest)
	}
}

func TestMatch_DistInfo(t *testing.T) {
	const meta = "/usr/lib/python3.11/site-packages/Flask-2.3.0.dist-info/METADATA"
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			meta: {Path: meta, LayerDigest: "sha256:layerA"},
		},
		content: map[string]string{meta: "Name: Flask\nVersion: 2.3.0\n"},
	}
	if !New().Match(fs) {
		t.Fatal("expected Match=true for dist-info")
	}
}

func TestMatch_RequirementsOnly(t *testing.T) {
	const req = "/app/requirements.txt"
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			req: {Path: req, LayerDigest: "sha256:layerA"},
		},
		content: map[string]string{req: "flask==2.3.0\n"},
	}
	if !New().Match(fs) {
		t.Fatal("expected Match=true for requirements.txt only")
	}
}

func TestCatalog_DistInfoPreferredOverRequirements(t *testing.T) {
	const (
		meta = "/usr/lib/python3.11/site-packages/Flask-2.3.0.dist-info/METADATA"
		req  = "/app/requirements.txt"
	)
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			meta: {Path: meta, LayerDigest: "sha256:layerA"},
			req:  {Path: req, LayerDigest: "sha256:layerB"},
		},
		content: map[string]string{
			meta: "Name: Flask\nVersion: 2.3.0\n",
			req:  "requests==2.31.0\n",
		},
	}
	c := New()
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected only dist-info package, got %d (%+v)", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "Flask" {
		t.Errorf("expected Flask, got %q", pkgs[0].Name)
	}
	if pkgs[0].Metadata["source"] != "dist-info" {
		t.Errorf("source = %q", pkgs[0].Metadata["source"])
	}
}

func TestParseMalformedMetadata(t *testing.T) {
	const meta = "/usr/lib/python3.11/site-packages/Broken-1.0.dist-info/METADATA"
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			meta: {Path: meta, LayerDigest: "sha256:layerA"},
		},
		content: map[string]string{
			meta: "This is not a valid metadata file.\nNo headers here.\n",
		},
	}
	c := New()
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages for malformed metadata, got %d (%+v)", len(pkgs), pkgs)
	}
}
