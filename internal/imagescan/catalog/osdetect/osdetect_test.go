package osdetect

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

func TestParseOSReleaseDebian(t *testing.T) {
	input := `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
`
	os, err := parseOSRelease(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseOSRelease: %v", err)
	}
	if os == nil {
		t.Fatal("expected non-nil OS")
	}
	if os.Name != "debian" || os.VersionID != "12" || os.Codename != "bookworm" {
		t.Errorf("OS = %+v", os)
	}
	if os.Pretty != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("Pretty = %q", os.Pretty)
	}
}

func TestParseOSReleaseAlpine(t *testing.T) {
	input := `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20
PRETTY_NAME="Alpine Linux v3.20"
ID_LIKE=alpine
`
	os, err := parseOSRelease(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseOSRelease: %v", err)
	}
	if os.Name != "alpine" || os.VersionID != "3.20" {
		t.Errorf("OS = %+v", os)
	}
	if len(os.IDLike) != 1 || os.IDLike[0] != "alpine" {
		t.Errorf("IDLike = %+v", os.IDLike)
	}
}

func TestDetectMissingReturnsNil(t *testing.T) {
	fs := &fakeFS{entries: map[string]*model.FileEntry{}, content: map[string]string{}}
	os, err := Detect(context.Background(), fs)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if os != nil {
		t.Errorf("expected nil OS for distroless, got %+v", os)
	}
}

func TestDetectFallbackToUsrLib(t *testing.T) {
	fs := &fakeFS{
		entries: map[string]*model.FileEntry{
			"/usr/lib/os-release": {Path: "/usr/lib/os-release"},
		},
		content: map[string]string{
			"/usr/lib/os-release": "ID=ubuntu\nVERSION_ID=24.04\n",
		},
	}
	os, err := Detect(context.Background(), fs)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if os == nil || os.Name != "ubuntu" || os.VersionID != "24.04" {
		t.Errorf("OS = %+v", os)
	}
}
