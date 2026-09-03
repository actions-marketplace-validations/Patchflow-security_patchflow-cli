package npm

import (
	"context"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// fakeFS is a minimal FileSystemView for npm cataloger tests.
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
	var es []*model.FileEntry
	for _, e := range f.entries {
		if e.IsDeleted {
			continue
		}
		if prefix == "" || prefix == "/" || e.Path == prefix || strings.HasPrefix(e.Path, prefix+"/") {
			es = append(es, e)
		}
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
	for _, e := range es {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeFS) Entries() int { return len(f.entries) }

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

const lockV3 = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.2", "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz", "integrity": "sha512-abc" },
    "node_modules/@babel/core": { "version": "7.22.0", "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.22.0.tgz", "integrity": "sha512-def" },
    "node_modules/lodash": { "version": "4.17.21", "dev": true, "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "integrity": "sha512-ghi" }
  }
}`

func TestParseLockfileV3(t *testing.T) {
	const p = "/app/package-lock.json"
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			p: {Path: p, LayerDigest: "sha256:layerL3"},
		},
		content: map[string]string{p: lockV3},
	}
	c := New()
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d: %+v", len(pkgs), pkgs)
	}
	want := map[string]string{
		"express":     "4.18.2",
		"@babel/core": "7.22.0",
		"lodash":      "4.17.21",
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
		if p.Type != "npm" || p.Ecosystem != "npm" {
			t.Errorf("%s: Type/Ecosystem = %q/%q", p.Name, p.Type, p.Ecosystem)
		}
		if p.LayerDigest != "sha256:layerL3" {
			t.Errorf("%s: LayerDigest = %q", p.Name, p.LayerDigest)
		}
		if len(p.Locations) != 1 || p.Locations[0].Path != "/app/package-lock.json" {
			t.Errorf("%s: Locations = %+v", p.Name, p.Locations)
		}
		if p.Metadata["source"] != "lockfile" {
			t.Errorf("%s: source = %q", p.Name, p.Metadata["source"])
		}
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("version for %s = %q, want %q", name, got[name], ver)
		}
	}
	// PURL spot-checks.
	for _, p := range pkgs {
		var exp string
		switch p.Name {
		case "express":
			exp = "pkg:npm/express@4.18.2"
		case "@babel/core":
			exp = "pkg:npm/@babel/core@7.22.0"
		case "lodash":
			exp = "pkg:npm/lodash@4.17.21"
		}
		if p.PURL != exp {
			t.Errorf("%s: PURL = %q, want %q", p.Name, p.PURL, exp)
		}
	}
	// dev flag on lodash.
	for _, p := range pkgs {
		if p.Name == "lodash" && p.Metadata["dev"] != "true" {
			t.Errorf("lodash: dev = %q, want true", p.Metadata["dev"])
		}
		if p.Name == "express" && p.Metadata["dev"] == "true" {
			t.Errorf("express: should not be dev")
		}
	}
}

const lockV1 = `{
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.17.1",
      "dependencies": {
        "accepts": { "version": "1.3.7" },
        "body-parser": { "version": "1.19.0", "dependencies": {
          "bytes": { "version": "3.1.0", "dev": true }
        }}
      }
    },
    "lodash": { "version": "4.17.21", "dev": true }
  }
}`

func TestParseLockfileV1(t *testing.T) {
	const p = "/app/package-lock.json"
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			p: {Path: p, LayerDigest: "sha256:layerV1"},
		},
		content: map[string]string{p: lockV1},
	}
	c := New()
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	want := map[string]string{
		"express":     "4.17.1",
		"accepts":     "1.3.7",
		"body-parser": "1.19.0",
		"bytes":       "3.1.0",
		"lodash":      "4.17.21",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("expected %d packages, got %d: %+v", len(want), len(pkgs), pkgs)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
		if p.Metadata["source"] != "lockfile" {
			t.Errorf("%s: source = %q", p.Name, p.Metadata["source"])
		}
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("version for %s = %q, want %q", name, got[name], ver)
		}
	}
	// nested dev flag.
	for _, p := range pkgs {
		if p.Name == "bytes" && p.Metadata["dev"] != "true" {
			t.Errorf("bytes: dev = %q, want true", p.Metadata["dev"])
		}
	}
}

func TestParseNodeModules(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/app/node_modules/express/package.json": {Path: "/app/node_modules/express/package.json", LayerDigest: "sha256:layerNM"},
			"/app/node_modules/lodash/package.json":  {Path: "/app/node_modules/lodash/package.json", LayerDigest: "sha256:layerNM"},
		},
		content: map[string]string{
			"/app/node_modules/express/package.json": `{"name":"express","version":"4.18.2"}`,
			"/app/node_modules/lodash/package.json":  `{"name":"lodash","version":"4.17.21"}`,
		},
	}
	c := New()
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(pkgs), pkgs)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
		if p.Metadata["source"] != "node_modules" {
			t.Errorf("%s: source = %q", p.Name, p.Metadata["source"])
		}
		if p.LayerDigest != "sha256:layerNM" {
			t.Errorf("%s: LayerDigest = %q", p.Name, p.LayerDigest)
		}
	}
	if got["express"] != "4.18.2" {
		t.Errorf("express version = %q", got["express"])
	}
	if got["lodash"] != "4.17.21" {
		t.Errorf("lodash version = %q", got["lodash"])
	}
	for _, p := range pkgs {
		if p.Name == "express" && p.PURL != "pkg:npm/express@4.18.2" {
			t.Errorf("express PURL = %q", p.PURL)
		}
	}
}

func TestMatch(t *testing.T) {
	const p = "/app/package-lock.json"
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			p: {Path: p, LayerDigest: "sha256:layer"},
		},
		content: map[string]string{p: lockV3},
	}
	if !New().Match(fs) {
		t.Fatal("expected Match=true with package-lock.json")
	}
}

func TestMatch_NoNpm(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/etc/hosts": {Path: "/etc/hosts", LayerDigest: "sha256:x"},
		},
		content: map[string]string{"/etc/hosts": "127.0.0.1 localhost"},
	}
	if New().Match(fs) {
		t.Fatal("expected Match=false with no npm markers")
	}
}

func TestMatch_NodeModulesOnly(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/app/node_modules/express/package.json": {Path: "/app/node_modules/express/package.json", LayerDigest: "sha256:layer"},
		},
		content: map[string]string{
			"/app/node_modules/express/package.json": `{"name":"express","version":"4.18.2"}`,
		},
	}
	if !New().Match(fs) {
		t.Fatal("expected Match=true with node_modules only")
	}
}

func TestCatalog_DedupSources(t *testing.T) {
	const lock = "/app/package-lock.json"
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			lock: {Path: lock, LayerDigest: "sha256:layerLock"},
			"/app/node_modules/express/package.json": {Path: "/app/node_modules/express/package.json", LayerDigest: "sha256:layerNM"},
		},
		content: map[string]string{
			lock: `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/express":{"version":"4.18.2"}}}`,
			"/app/node_modules/express/package.json": `{"name":"express","version":"4.18.2"}`,
		},
	}
	c := New()
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	// Both sources emit express -> 2 entries (dedup is the matcher's job).
	var count int
	for _, p := range pkgs {
		if p.Name == "express" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 express entries (lockfile + node_modules), got %d", count)
	}
	// Verify source metadata distinguishes them.
	sources := map[string]bool{}
	for _, p := range pkgs {
		if p.Name == "express" {
			sources[p.Metadata["source"]] = true
		}
	}
	if !sources["lockfile"] || !sources["node_modules"] {
		t.Errorf("expected both sources, got %v", sources)
	}
}

func TestCatalog_MalformedPackageJSON(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/app/node_modules/bad/package.json":   {Path: "/app/node_modules/bad/package.json", LayerDigest: "sha256:layer"},
			"/app/node_modules/good/package.json":  {Path: "/app/node_modules/good/package.json", LayerDigest: "sha256:layer"},
		},
		content: map[string]string{
			"/app/node_modules/bad/package.json":  `{not valid json`,
			"/app/node_modules/good/package.json": `{"name":"good","version":"1.2.3"}`,
		},
	}
	c := New()
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package (bad skipped), got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "good" || pkgs[0].Version != "1.2.3" {
		t.Errorf("got %+v", pkgs[0])
	}
}
