package extractor

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

// TestWhiteoutAndOpaque verifies that whiteout and opaque-whiteout entries
// delete the right paths when layers are applied in order. It feeds raw tar
// streams to applyTarStream, bypassing the v1.Layer interface.
func TestWhiteoutAndOpaque(t *testing.T) {
	dir := t.TempDir()
	v := &View{
		entries: make(map[string]*model.FileEntry),
		snapDir: dir,
	}

	// Layer 1: add /etc/foo, /etc/bar/baz, /etc/keep
	if err := v.applyTarStream(makeTarReader(t, []tarEntry{
		{path: "/etc", isDir: true},
		{path: "/etc/foo", content: []byte("foo")},
		{path: "/etc/bar", isDir: true},
		{path: "/etc/bar/baz", content: []byte("baz")},
		{path: "/etc/keep", content: []byte("keep")},
	}), "sha256:layer1"); err != nil {
		t.Fatalf("apply layer1: %v", err)
	}

	// Layer 2: whiteout /etc/foo, opaque whiteout /etc/bar, add /etc/bar/new
	if err := v.applyTarStream(makeTarReader(t, []tarEntry{
		{path: "/etc/.wh.foo"},          // deletes /etc/foo
		{path: "/etc/bar/.wh..wh..opq"}, // deletes all children of /etc/bar
		{path: "/etc/bar", isDir: true},
		{path: "/etc/bar/new", content: []byte("new")},
	}), "sha256:layer2"); err != nil {
		t.Fatalf("apply layer2: %v", err)
	}

	// /etc/foo should be gone.
	if _, ok := v.Get("/etc/foo"); ok {
		t.Error("/etc/foo should have been whiteout-deleted")
	}
	// /etc/bar/baz should be gone (opaque whiteout).
	if _, ok := v.Get("/etc/bar/baz"); ok {
		t.Error("/etc/bar/baz should have been opaque-whiteout-deleted")
	}
	// /etc/bar/new should exist and be attributed to layer2.
	e, ok := v.Get("/etc/bar/new")
	if !ok {
		t.Fatal("/etc/bar/new should exist")
	}
	if e.LayerDigest != "sha256:layer2" {
		t.Errorf("/etc/bar/new LayerDigest = %q, want layer2", e.LayerDigest)
	}
	// /etc/keep should still exist, attributed to layer1.
	e, ok = v.Get("/etc/keep")
	if !ok {
		t.Fatal("/etc/keep should still exist")
	}
	if e.LayerDigest != "sha256:layer1" {
		t.Errorf("/etc/keep LayerDigest = %q, want layer1", e.LayerDigest)
	}
}

// TestNormalizeUsesOCISeparators verifies that image paths remain portable
// when the scanner itself is running on Windows.
func TestNormalizeUsesOCISeparators(t *testing.T) {
	for input, want := range map[string]string{
		`etc\\foo`:        "/etc/foo",
		`/etc/bar/../foo`: "/etc/foo",
	} {
		if got := normalize(input); got != want {
			t.Errorf("normalize(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestSymlinkCycle verifies that Open detects a symlink cycle instead of
// recursing until a stack overflow.
func TestSymlinkCycle(t *testing.T) {
	dir := t.TempDir()
	v := &View{
		entries: map[string]*model.FileEntry{
			"/a": {Path: "/a", IsSymlink: true, LinkTarget: "/b"},
			"/b": {Path: "/b", IsSymlink: true, LinkTarget: "/c"},
			"/c": {Path: "/c", IsSymlink: true, LinkTarget: "/a"},
		},
		snapDir: dir,
	}
	if _, err := v.Open("/a"); err == nil {
		t.Fatal("expected symlink cycle error")
	}
}

// TestSymlinkTooManyHops verifies that Open aborts after too many hops.
func TestSymlinkTooManyHops(t *testing.T) {
	dir := t.TempDir()
	entries := make(map[string]*model.FileEntry)
	for i := 0; i < 50; i++ {
		next := fmt.Sprintf("/%03d", i+1)
		entries[fmt.Sprintf("/%03d", i)] = &model.FileEntry{
			Path:        fmt.Sprintf("/%03d", i),
			IsSymlink:   true,
			LinkTarget:  next,
			LayerDigest: "sha256:layer",
		}
	}
	entries["/050"] = &model.FileEntry{Path: "/050", LayerDigest: "sha256:layer"}
	v := &View{entries: entries, snapDir: dir}
	if _, err := v.Open("/000"); err == nil {
		t.Fatal("expected too many hops error")
	}
}

// TestBuildFromRandomImage runs the full Build pipeline against a synthetic
// random image to ensure layer extraction and provenance pairing works.
func TestBuildFromRandomImage(t *testing.T) {
	img, err := random.Image(1024, 3)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	e := &Extractor{SnapshotDir: t.TempDir()}
	res, err := e.Build(context.Background(), img)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer res.FS.Close()

	layers, err := img.Layers()
	if err != nil {
		t.Fatalf("img.Layers: %v", err)
	}
	if len(res.Layers) != len(layers) {
		t.Errorf("provenance count = %d, want %d", len(res.Layers), len(layers))
	}
	if res.FS.Entries() == 0 {
		t.Error("expected non-zero filesystem entries")
	}
}

// --- helpers ---------------------------------------------------------------

type tarEntry struct {
	path       string
	isDir      bool
	isSymlink  bool
	linkTarget string
	content    []byte
}

// makeTarReader returns a reader over a tar stream built from entries.
func makeTarReader(t *testing.T, entries []tarEntry) io.Reader {
	return bytes.NewReader(makeTarBytes(t, entries))
}

// makeTarBytes serializes entries to a tar stream.
func makeTarBytes(t *testing.T, entries []tarEntry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.path,
			Mode:     0644,
			Typeflag: tar.TypeReg,
			Size:     int64(len(e.content)),
		}
		if e.isDir {
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
		} else if e.isSymlink {
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.linkTarget
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader %s: %v", e.path, err)
		}
		if !e.isDir && !e.isSymlink && len(e.content) > 0 {
			if _, err := tw.Write(e.content); err != nil {
				t.Fatalf("Write %s: %v", e.path, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}
