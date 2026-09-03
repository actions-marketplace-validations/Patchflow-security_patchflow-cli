package gocatalog

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// fakeFS is a minimal FileSystemView for parser tests.
type fakeFS struct {
	entries map[string]*model.FileEntry
	content map[string][]byte
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
	return io.NopCloser(bytes.NewReader(c)), nil
}
func (f *fakeFS) Walk(prefix string, fn func(*model.FileEntry) error) error {
	var paths []string
	for p := range f.entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		e := f.entries[p]
		if e.IsDeleted {
			continue
		}
		if p == prefix || hasPrefix(p, prefix) {
			if err := fn(e); err != nil {
				return err
			}
		}
	}
	return nil
}
func (f *fakeFS) Entries() int { return len(f.entries) }

func hasPrefix(p, prefix string) bool {
	if prefix == "/" {
		return true
	}
	return len(p) > len(prefix) && p[:len(prefix)] == prefix && (prefix[len(prefix)-1] == '/' || p[len(prefix)] == '/')
}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

// --- go.mod parsing tests --------------------------------------------------

func TestParseGoMod_BlockRequire(t *testing.T) {
	const mod = `module github.com/myapp

go 1.21

require (
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/gin-gonic/gin v1.9.1
)
`
	mods := parseGoMod(splitLines(mod))
	if len(mods) != 3 {
		t.Fatalf("expected 3 modules, got %d", len(mods))
	}
	want := []moduleRef{
		{"github.com/spf13/cobra", "v1.7.0"},
		{"github.com/spf13/pflag", "v1.0.5"},
		{"github.com/gin-gonic/gin", "v1.9.1"},
	}
	for i, w := range want {
		if mods[i].path != w.path || mods[i].version != w.version {
			t.Errorf("mod[%d] = %+v, want %+v", i, mods[i], w)
		}
	}
}

func TestParseGoMod_SingleLineRequire(t *testing.T) {
	const mod = `module github.com/myapp

go 1.21

require github.com/spf13/cobra v1.7.0
require github.com/spf13/pflag v1.0.5
`
	mods := parseGoMod(splitLines(mod))
	if len(mods) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(mods))
	}
	if mods[0].path != "github.com/spf13/cobra" || mods[0].version != "v1.7.0" {
		t.Errorf("mod0 = %+v", mods[0])
	}
	if mods[1].path != "github.com/spf13/pflag" || mods[1].version != "v1.0.5" {
		t.Errorf("mod1 = %+v", mods[1])
	}
}

func TestParseGoMod_SkipsReplaceAndExclude(t *testing.T) {
	const mod = `module github.com/myapp

go 1.21

require github.com/spf13/cobra v1.7.0

replace github.com/spf13/cobra => github.com/myfork/cobra v1.8.0

exclude github.com/old/dep v0.1.0

require github.com/spf13/pflag v1.0.5
`
	mods := parseGoMod(splitLines(mod))
	if len(mods) != 2 {
		t.Fatalf("expected 2 modules (replace/exclude skipped), got %d", len(mods))
	}
	for _, m := range mods {
		if strings.Contains(m.path, "myfork") {
			t.Errorf("replace target should not be emitted: %+v", m)
		}
		if strings.Contains(m.path, "old/dep") {
			t.Errorf("exclude target should not be emitted: %+v", m)
		}
	}
}

func TestParseGoMod_IndirectRetained(t *testing.T) {
	const mod = `module github.com/myapp

go 1.21

require (
	github.com/spf13/cobra v1.7.0
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
)
`
	mods := parseGoMod(splitLines(mod))
	if len(mods) != 2 {
		t.Fatalf("expected 2 modules (indirect retained), got %d", len(mods))
	}
	if mods[1].path != "github.com/inconshreveable/mousetrap" || mods[1].version != "v1.1.0" {
		t.Errorf("indirect mod = %+v", mods[1])
	}
}

func TestMatch_GoMod(t *testing.T) {
	const mod = `module github.com/myapp
go 1.21
require github.com/spf13/cobra v1.7.0
`
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/app/go.mod": {Path: "/app/go.mod", LayerDigest: "sha256:layerG"},
		},
		content: map[string][]byte{"/app/go.mod": []byte(mod)},
	}
	c := New()
	if !c.Match(fs) {
		t.Fatal("expected Match=true for go.mod")
	}
}

func TestCatalog_GoMod_AttachesLayerAndPURL(t *testing.T) {
	const mod = `module github.com/myapp
go 1.21
require github.com/spf13/cobra v1.7.0
`
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/app/go.mod": {Path: "/app/go.mod", LayerDigest: "sha256:layerG"},
		},
		content: map[string][]byte{"/app/go.mod": []byte(mod)},
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
	if p.Type != "go" || p.Ecosystem != "golang" {
		t.Errorf("Type/Ecosystem = %q/%q", p.Type, p.Ecosystem)
	}
	if p.Name != "github.com/spf13/cobra" || p.Version != "v1.7.0" {
		t.Errorf("Name/Version = %q/%q", p.Name, p.Version)
	}
	if p.PURL != "pkg:golang/github.com/spf13/cobra@v1.7.0" {
		t.Errorf("PURL = %q", p.PURL)
	}
	if p.LayerDigest != "sha256:layerG" {
		t.Errorf("LayerDigest = %q", p.LayerDigest)
	}
	if len(p.Locations) != 1 || p.Locations[0].Path != "/app/go.mod" {
		t.Errorf("Locations = %+v", p.Locations)
	}
	if p.Metadata["source"] != "go.mod" {
		t.Errorf("Metadata source = %q", p.Metadata["source"])
	}
}

// --- binary build info tests -----------------------------------------------

// buildTestBinary compiles a small Go module with a known dependency into a
// binary and returns its bytes. Returns "" and skips if the toolchain is
// unavailable or network access for the dependency is missing.
func buildTestBinary(t *testing.T, modPath, depPath, depVersion, mainGo string) []byte {
	t.Helper()
	tmp := t.TempDir()

	goMod := "module " + modPath + "\n\ngo 1.21\n\nrequire " + depPath + " " + depVersion + "\n"
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Skipf("setup go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "main.go"), []byte(mainGo), 0o644); err != nil {
		t.Skipf("setup main.go: %v", err)
	}

	// Download deps; skip if no network.
	dl := exec.Command("go", "mod", "download")
	dl.Dir = tmp
	if out, err := dl.CombinedOutput(); err != nil {
		t.Skipf("go mod download (no network?): %v\n%s", err, out)
	}
	// Ensure go.sum is populated so the build succeeds.
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = tmp
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Skipf("go mod tidy: %v\n%s", err, out)
	}

	outBin := filepath.Join(tmp, "app")
	build := exec.Command("go", "build", "-o", outBin, ".")
	build.Dir = tmp
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("go build: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outBin)
	if err != nil {
		t.Skipf("read binary: %v", err)
	}
	return data
}

func TestParseBinaryBuildInfo(t *testing.T) {
	// Use a tiny, stable stdlib-only module to avoid network dependency.
	// We build a binary that imports only stdlib packages; buildinfo still
	// records the main module and (if any) deps. To guarantee a dep appears,
	// we attempt to use a common external dep and skip if offline.
	depPath := "github.com/inconshreveable/mousetrap"
	depVersion := "v1.1.0"
	mainGo := `package main

import (
	"fmt"
	"github.com/inconshreveable/mousetrap"
)

func main() {
	fmt.Println(mousetrap.StartedByExplorer())
}
`
	bin := buildTestBinary(t, "github.com/myapp/testbin", depPath, depVersion, mainGo)
	if bin == nil {
		return // skipped
	}

	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/app/testbin": {Path: "/app/testbin", LayerDigest: "sha256:layerB"},
		},
		content: map[string][]byte{"/app/testbin": bin},
	}
	c := New()
	if !c.Match(fs) {
		t.Fatal("expected Match=true for Go binary")
	}
	pkgs, err := c.Catalog(context.Background(), fs)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	var dep *model.Package
	for i := range pkgs {
		if pkgs[i].Name == depPath {
			dep = &pkgs[i]
			break
		}
	}
	if dep == nil {
		t.Fatalf("expected dependency %s in catalog output; got %d packages", depPath, len(pkgs))
	}
	if dep.Version != depVersion {
		t.Errorf("dep version = %q, want %q", dep.Version, depVersion)
	}
	if dep.Type != "go" || dep.Ecosystem != "golang" {
		t.Errorf("Type/Ecosystem = %q/%q", dep.Type, dep.Ecosystem)
	}
	if dep.PURL != "pkg:golang/"+depPath+"@"+depVersion {
		t.Errorf("PURL = %q", dep.PURL)
	}
	if dep.LayerDigest != "sha256:layerB" {
		t.Errorf("LayerDigest = %q", dep.LayerDigest)
	}
	if dep.Metadata["source"] != "binary-buildinfo" {
		t.Errorf("Metadata source = %q", dep.Metadata["source"])
	}
}

func TestCatalog_BothSources(t *testing.T) {
	depPath := "github.com/inconshreveable/mousetrap"
	depVersion := "v1.1.0"
	mainGo := `package main

import (
	"fmt"
	"github.com/inconshreveable/mousetrap"
)

func main() {
	fmt.Println(mousetrap.StartedByExplorer())
}
`
	bin := buildTestBinary(t, "github.com/myapp/testbin", depPath, depVersion, mainGo)
	if bin == nil {
		return // skipped
	}

	const mod = `module github.com/myapp
go 1.21
require github.com/spf13/cobra v1.7.0
`
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/app/go.mod":   {Path: "/app/go.mod", LayerDigest: "sha256:layerG"},
			"/app/testbin":  {Path: "/app/testbin", LayerDigest: "sha256:layerB"},
		},
		content: map[string][]byte{
			"/app/go.mod":  []byte(mod),
			"/app/testbin": bin,
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
	names := make(map[string]bool)
	for _, p := range pkgs {
		names[p.Name] = true
	}
	if !names["github.com/spf13/cobra"] {
		t.Errorf("expected cobra from go.mod in output; got %v", names)
	}
	if !names[depPath] {
		t.Errorf("expected %s from binary in output; got %v", depPath, names)
	}
}

// splitLines splits s into lines without trailing newlines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
