// Package extractor reconstructs a layer-aware virtual filesystem from a
// resolved OCI image. It applies layers in manifest order, handles OCI
// whiteout and opaque-whiteout entries, and records which layer introduced
// each surviving path.
//
// The output is a model.FileSystemView that catalogers consume to discover
// packages, plus the per-layer provenance (config history) used for layer
// attribution and fix-path recommendations.
//
// Whiteout semantics (OCI image spec):
//   - A file named ".wh.<name>" in a layer deletes "<name>" from the
//     accumulated filesystem.
//   - A file named ".wh..wh..opq" in a directory deletes all existing
//     children of that directory (opaque whiteout), then the layer's own
//     entries under that directory are added.
package extractor

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Extractor builds a FileSystemView from a v1.Image.
type Extractor struct {
	// SnapshotDir is where extracted file contents are materialized so
	// that Open() can stream them. If empty, a temp dir is created and
	// removed when the view is closed.
	SnapshotDir string
}

// New returns an Extractor with a default temp snapshot directory.
func New() *Extractor { return &Extractor{} }

// Result bundles the filesystem view and the layer provenance list.
type Result struct {
	FS     *View
	Layers []model.LayerProvenance
}

// Build applies all layers of img in manifest order and returns the merged
// filesystem view plus the layer provenance derived from the config history.
func (e *Extractor) Build(ctx context.Context, img v1.Image) (*Result, error) {
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("enumerate layers: %w", err)
	}

	// The config history and the layer list are parallel, except that
	// history may contain empty-layer entries (no blob). We pair them by
	// walking both in order and skipping empty-layer history entries.
	history := cfg.History
	prov := make([]model.LayerProvenance, 0, len(layers))
	hIdx := 0
	for _, l := range layers {
		d, err := l.Digest()
		if err != nil {
			return nil, fmt.Errorf("layer digest: %w", err)
		}
		p := model.LayerProvenance{LayerDigest: d.String()}
		// Advance history to the next non-empty entry that corresponds
		// to this layer.
		for hIdx < len(history) {
			h := history[hIdx]
			hIdx++
			p.CreatedBy = h.CreatedBy
			p.Comment = h.Comment
			p.Author = h.Author
			p.EmptyLayer = h.EmptyLayer
			if !h.EmptyLayer {
				if !h.Created.IsZero() {
					p.Created = h.Created.UTC()
				}
				break
			}
		}
		prov = append(prov, p)
	}

	snapDir := e.SnapshotDir
	cleanup := false
	if snapDir == "" {
		snapDir, err = os.MkdirTemp("", "pf-is-fs-*")
		if err != nil {
			return nil, fmt.Errorf("create snapshot dir: %w", err)
		}
		cleanup = true
	}

	view := &View{
		entries:   make(map[string]*model.FileEntry),
		snapDir:   snapDir,
		cleanup:   cleanup,
		createdAt: time.Now().UTC(),
	}

	for i, l := range layers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		d, err := l.Digest()
		if err != nil {
			return nil, fmt.Errorf("layer %d digest: %w", i, err)
		}
		if err := view.applyLayer(l, d.String()); err != nil {
			return nil, fmt.Errorf("apply layer %d (%s): %w", i, d.String()[:min(12, len(d.String()))], err)
		}
	}

	return &Result{FS: view, Layers: prov}, nil
}

// View is the in-memory, layer-aware filesystem view. File contents are
// materialized under snapDir keyed by a content digest so Open() can stream
// them without holding everything in RAM.
type View struct {
	entries   map[string]*model.FileEntry
	snapDir   string
	cleanup   bool
	createdAt time.Time
}

// ensure View implements model.FileSystemView.
var _ model.FileSystemView = (*View)(nil)

// Get returns the entry for path, or nil if absent or whiteout-deleted.
func (v *View) Get(path string) (*model.FileEntry, bool) {
	e, ok := v.entries[normalize(path)]
	if !ok || e.IsDeleted {
		return nil, false
	}
	return e, true
}

// Open opens the file content for reading. Symlinks are resolved against
// the view (so /etc/os-release -> ../usr/lib/os-release works). Returns an
// error for directories or deleted entries.
func (v *View) Open(path string) (model.ContentReader, error) {
	return v.openWithSeen(path, make(map[string]int), 0)
}

// openWithSeen resolves symlinks iteratively. seen tracks how many times each
// path has been visited; maxDepth limits the total hops to prevent runaway
// chains or cycles.
func (v *View) openWithSeen(path string, seen map[string]int, depth int) (model.ContentReader, error) {
	const maxDepth = 40
	if depth > maxDepth {
		return nil, fmt.Errorf("open %q: too many symlink hops", path)
	}
	norm := normalize(path)
	if seen[norm]++; seen[norm] > 1 {
		return nil, fmt.Errorf("open %q: symlink cycle detected", path)
	}

	e, ok := v.Get(norm)
	if !ok {
		return nil, fmt.Errorf("open %q: not found", path)
	}
	if e.IsDir {
		return nil, fmt.Errorf("open %q: is a directory", path)
	}
	if e.IsSymlink {
		target := resolveSymlink(norm, e.LinkTarget)
		return v.openWithSeen(target, seen, depth+1)
	}
	if e.Digest == "" {
		return nil, fmt.Errorf("open %q: no content digest", path)
	}
	return os.Open(v.blobPath(e.Digest))
}

// Walk iterates over all live (non-deleted) entries under prefix in lexical
// order. The callback may return model.ErrWalkStop to halt early.
func (v *View) Walk(prefix string, fn func(*model.FileEntry) error) error {
	prefix = normalize(prefix)
	paths := make([]string, 0, len(v.entries))
	for p, e := range v.entries {
		if e.IsDeleted {
			continue
		}
		if prefix == "" || prefix == "/" || strings.HasPrefix(p, prefix) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		if err := fn(v.entries[p]); err != nil {
			if err == model.ErrWalkStop {
				return nil
			}
			return err
		}
	}
	return nil
}

// Entries returns the count of live entries.
func (v *View) Entries() int {
	n := 0
	for _, e := range v.entries {
		if !e.IsDeleted {
			n++
		}
	}
	return n
}

// Close removes the snapshot directory if the extractor created it.
func (v *View) Close() error {
	if v.cleanup && v.snapDir != "" {
		return os.RemoveAll(v.snapDir)
	}
	return nil
}

// blobPath returns the on-disk path for a content digest.
func (v *View) blobPath(digest string) string {
	// Strip "sha256:" prefix for filesystem safety.
	name := strings.ReplaceAll(digest, ":", "_")
	return filepath.Join(v.snapDir, name)
}

// applyLayer reads one layer's tar stream and merges it into the view,
// honoring whiteout and opaque-whiteout entries.
func (v *View) applyLayer(l v1.Layer, layerDigest string) error {
	rc, err := l.Uncompressed()
	if err != nil {
		return fmt.Errorf("open uncompressed: %w", err)
	}
	defer rc.Close()
	return v.applyTarStream(rc, layerDigest)
}

// applyTarStream merges a raw tar stream into the view. Split out from
// applyLayer so it can be tested with synthetic tar bytes without a
// v1.Layer implementation.
func (v *View) applyTarStream(r io.Reader, layerDigest string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		if err := v.applyEntry(hdr, tr, layerDigest); err != nil {
			return err
		}
	}
	return nil
}

// applyEntry processes one tar header, handling whiteouts and materializing
// file content to the snapshot dir.
func (v *View) applyEntry(hdr *tar.Header, r io.Reader, layerDigest string) error {
	name := normalize(hdr.Name)
	if name == "" {
		return nil
	}

	base := path.Base(name)
	dir := path.Dir(name)

	// Opaque whiteout: ".wh..wh..opq" deletes all existing children of dir.
	if base == ".wh..wh..opq" {
		v.deleteChildren(dir)
		return nil
	}

	// Regular whiteout: ".wh.<x>" deletes "<x>" in the same directory.
	if strings.HasPrefix(base, ".wh.") {
		target := normalize(path.Join(dir, strings.TrimPrefix(base, ".wh.")))
		v.deletePath(target)
		return nil
	}

	entry := &model.FileEntry{
		Path:        name,
		Mode:        uint32(hdr.Mode),
		Size:        hdr.Size,
		LayerDigest: layerDigest,
		ModTime:     hdr.ModTime,
		IsDir:       hdr.Typeflag == tar.TypeDir,
		IsSymlink:   hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink,
		LinkTarget:  hdr.Linkname,
	}

	// Materialize regular-file content to the snapshot dir and record a
	// content digest so Open() can stream it later.
	if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
		digest, err := v.writeBlob(r)
		if err != nil {
			return fmt.Errorf("write blob %q: %w", name, err)
		}
		entry.Digest = digest
		entry.Size = hdr.Size
	}

	v.entries[name] = entry
	return nil
}

// writeBlob copies the reader to a snapshot file named by its sha256 digest.
func (v *View) writeBlob(r io.Reader) (string, error) {
	tmp, err := os.CreateTemp(v.snapDir, "blob-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	h := newSHA256()
	w := io.MultiWriter(tmp, h)
	if _, err := io.Copy(w, r); err != nil {
		return "", err
	}
	// Windows does not allow renaming an open file. Close it before checking
	// for deduplication or moving it into its content-addressed location.
	if err := tmp.Close(); err != nil {
		return "", err
	}
	digest := "sha256:" + h.hex()

	final := v.blobPath(digest)
	// If the blob already exists (content-addressed dedup), drop the temp.
	if _, err := os.Stat(final); err == nil {
		return digest, nil
	}
	if err := os.Rename(tmpName, final); err != nil {
		return "", err
	}
	return digest, nil
}

// deletePath marks a path (and everything under it) as deleted.
func (v *View) deletePath(path string) {
	path = normalize(path)
	if e, ok := v.entries[path]; ok {
		e.IsDeleted = true
	}
	prefix := path + "/"
	for p, e := range v.entries {
		if strings.HasPrefix(p, prefix) {
			e.IsDeleted = true
		}
	}
}

// deleteChildren marks all children of dir as deleted, but keeps dir itself.
func (v *View) deleteChildren(dir string) {
	dir = normalize(dir)
	var prefix string
	if dir == "" || dir == "/" {
		prefix = ""
	} else {
		prefix = dir + "/"
	}
	for p, e := range v.entries {
		if p == dir {
			continue
		}
		if prefix == "" || strings.HasPrefix(p, prefix) {
			e.IsDeleted = true
		}
	}
}

// normalize cleans a path and ensures a leading slash.
func normalize(p string) string {
	// OCI image paths always use slash separators, regardless of the host
	// running the scanner. Using filepath here would turn "/etc/foo" into
	// "\\etc\\foo" on Windows and break whiteout prefix matching.
	p = path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	if p == "." {
		return "/"
	}
	return p
}

// resolveSymlink resolves a symlink target relative to its containing
// directory. Absolute targets are cleaned as-is; relative targets are joined
// against the symlink's directory.
func resolveSymlink(linkPath, target string) string {
	if path.IsAbs(strings.ReplaceAll(target, "\\", "/")) {
		return normalize(target)
	}
	dir := path.Dir(normalize(linkPath))
	return normalize(path.Join(dir, target))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
