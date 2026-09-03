package catalog

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// fakeFS is a minimal FileSystemView for helper tests.
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
	var paths []string
	for p := range f.entries {
		if strings.HasPrefix(p, prefix) || p == prefix {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		if err := fn(f.entries[p]); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeFS) Entries() int { return len(f.entries) }

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

// --- ReadJSON ---

func TestReadJSON(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/app/lock.json": {Path: "/app/lock.json", LayerDigest: "sha256:AAA"},
		},
		content: map[string]string{
			"/app/lock.json": `{"name":"express","version":"4.18.0"}`,
		},
	}
	var v struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	e, err := ReadJSON(fs, "/app/lock.json", &v)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if v.Name != "express" || v.Version != "4.18.0" {
		t.Errorf("parsed = %+v", v)
	}
	if e == nil || e.LayerDigest != "sha256:AAA" {
		t.Errorf("entry = %+v", e)
	}
}

func TestReadJSON_Malformed(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{"/bad.json": {Path: "/bad.json"}},
		content: map[string]string{"/bad.json": `{not json`},
	}
	var v map[string]any
	_, err := ReadJSON(fs, "/bad.json", &v)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if _, ok := err.(*json.SyntaxError); !ok {
		// The error is wrapped; check it mentions decode.
		if !strings.Contains(err.Error(), "decode") {
			t.Errorf("expected decode error, got: %v", err)
		}
	}
}

func TestReadJSON_NotFound(t *testing.T) {
	fs := &fakeFS{}
	var v map[string]any
	_, err := ReadJSON(fs, "/missing.json", &v)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// --- ReadBytes ---

func TestReadBytes(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{"/Cargo.lock": {Path: "/Cargo.lock", LayerDigest: "sha256:BBB"}},
		content: map[string]string{"/Cargo.lock": "name = \"app\"\nversion = \"1.0\""},
	}
	data, e, err := ReadBytes(fs, "/Cargo.lock")
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}
	if string(data) != "name = \"app\"\nversion = \"1.0\"" {
		t.Errorf("data = %q", data)
	}
	if e == nil || e.LayerDigest != "sha256:BBB" {
		t.Errorf("entry = %+v", e)
	}
}

// --- ReadLines ---

func TestReadLines(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{"/req.txt": {Path: "/req.txt", LayerDigest: "sha256:CCC"}},
		content: map[string]string{"/req.txt": "flask==2.3.0\nrequests>=2.31\n\n# comment"},
	}
	lines, e, err := ReadLines(fs, "/req.txt")
	if err != nil {
		t.Fatalf("ReadLines: %v", err)
	}
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d", len(lines))
	}
	if lines[0] != "flask==2.3.0" || lines[1] != "requests>=2.31" {
		t.Errorf("lines = %+v", lines)
	}
	if lines[2] != "" {
		t.Errorf("expected blank line at index 2, got %q", lines[2])
	}
	if e == nil || e.LayerDigest != "sha256:CCC" {
		t.Errorf("entry = %+v", e)
	}
}

// --- WalkDir ---

func TestWalkDir(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/usr/lib/python3.12/site-packages":               {Path: "/usr/lib/python3.12/site-packages", IsDir: true},
			"/usr/lib/python3.12/site-packages/flask":          {Path: "/usr/lib/python3.12/site-packages/flask", IsDir: true},
			"/usr/lib/python3.12/site-packages/flask/__init__.py": {Path: "/usr/lib/python3.12/site-packages/flask/__init__.py"},
			"/usr/lib/python3.12/site-packages/requests":       {Path: "/usr/lib/python3.12/site-packages/requests", IsDir: true},
			"/usr/lib/python3.12/site-packages/requests/__init__.py": {Path: "/usr/lib/python3.12/site-packages/requests/__init__.py"},
			"/etc/passwd": {Path: "/etc/passwd"},
		},
	}
	entries, err := WalkDir(fs, "/usr/lib/python3.12/site-packages")
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	// Verify lexical sort.
	if entries[0].Path != "/usr/lib/python3.12/site-packages/flask" {
		t.Errorf("first entry = %q", entries[0].Path)
	}
}

func TestWalkDir_SkipsDeleted(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/app/node_modules/express":          {Path: "/app/node_modules/express", IsDir: true},
			"/app/node_modules/express/package.json": {Path: "/app/node_modules/express/package.json", IsDeleted: true},
			"/app/node_modules/lodash":           {Path: "/app/node_modules/lodash", IsDir: true},
		},
	}
	entries, err := WalkDir(fs, "/app/node_modules")
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	for _, e := range entries {
		if e.IsDeleted {
			t.Errorf("deleted entry should be skipped: %s", e.Path)
		}
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 live entries, got %d", len(entries))
	}
}

// --- FindFiles ---

func TestFindFiles(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/app/lib/foo.jar":      {Path: "/app/lib/foo.jar"},
			"/app/lib/bar.war":      {Path: "/app/lib/bar.war"},
			"/app/lib/baz.txt":      {Path: "/app/lib/baz.txt"},
			"/opt/app/inner.jar":    {Path: "/opt/app/inner.jar"},
			"/opt/app/deleted.jar":  {Path: "/opt/app/deleted.jar", IsDeleted: true},
		},
	}
	entries, err := FindFiles(fs, ".jar", ".war")
	if err != nil {
		t.Fatalf("FindFiles: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 live .jar/.war, got %d", len(entries))
	}
	if entries[0].Path != "/app/lib/bar.war" {
		t.Errorf("first = %q (expected lexical sort)", entries[0].Path)
	}
}

// --- PURL ---

func TestPURL_Npm(t *testing.T) {
	got := PURL("npm", "express", "4.18.0")
	want := "pkg:npm/express@4.18.0"
	if got != want {
		t.Errorf("PURL(npm, express, 4.18.0) = %q, want %q", got, want)
	}
}

func TestPURL_NpmScoped(t *testing.T) {
	got := PURL("npm", "@babel/core", "7.22.0")
	want := "pkg:npm/@babel/core@7.22.0"
	if got != want {
		t.Errorf("PURL(npm, @babel/core, 7.22.0) = %q, want %q", got, want)
	}
}

func TestPURL_PyPI(t *testing.T) {
	// PEP 503 normalisation: lowercase, runs of [-_.] → "-"
	cases := []struct {
		name, version, want string
	}{
		{"Flask", "2.3.0", "pkg:pypi/flask@2.3.0"},
		{"Pillow", "10.0.0", "pkg:pypi/pillow@10.0.0"},
		{"Jinja2", "3.1.2", "pkg:pypi/jinja2@3.1.2"},
		{"python_dateutil", "2.8.2", "pkg:pypi/python-dateutil@2.8.2"},
		{"Zope.Interface", "5.4.0", "pkg:pypi/zope-interface@5.4.0"},
	}
	for _, c := range cases {
		got := PURL("pypi", c.name, c.version)
		if got != c.want {
			t.Errorf("PURL(pypi, %q, %q) = %q, want %q", c.name, c.version, got, c.want)
		}
	}
}

func TestPURL_Maven(t *testing.T) {
	got := MavenPURL("org.springframework", "spring-core", "6.0.10")
	want := "pkg:maven/org.springframework/spring-core@6.0.10"
	if got != want {
		t.Errorf("MavenPURL = %q, want %q", got, want)
	}
}

func TestPURL_MavenVersionWithPlus(t *testing.T) {
	got := MavenPURL("commons-io", "commons-io", "2.11.0+deb12u1")
	// "+" should be percent-encoded in the version portion.
	if !strings.Contains(got, "2.11.0") {
		t.Errorf("MavenPURL with + version = %q", got)
	}
}

func TestPURL_Golang(t *testing.T) {
	got := PURL("golang", "github.com/spf13/cobra", "1.7.0")
	want := "pkg:golang/github.com/spf13/cobra@1.7.0"
	if got != want {
		t.Errorf("PURL(golang) = %q, want %q", got, want)
	}
}

func TestPURL_Cargo(t *testing.T) {
	got := PURL("cargo", "Serde", "1.0.171")
	want := "pkg:cargo/serde@1.0.171" // lowercased
	if got != want {
		t.Errorf("PURL(cargo, Serde) = %q, want %q", got, want)
	}
}

func TestPURL_NoVersion(t *testing.T) {
	got := PURL("npm", "lodash", "")
	want := "pkg:npm/lodash"
	if got != want {
		t.Errorf("PURL(npm, lodash, \"\") = %q, want %q", got, want)
	}
}
