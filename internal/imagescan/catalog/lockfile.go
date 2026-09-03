// Package catalog provides shared helpers for catalogers that need to read
// lockfiles or walk installed-package directories from a FileSystemView.
//
// These helpers centralise the boilerplate of opening a file from the view,
// reading its content, capturing the FileEntry for layer attribution, and
// walking directory subtrees — so each language cataloger can focus on
// parsing logic rather than I/O plumbing.
package catalog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// ReadJSON opens path in fs, reads its full content, and unmarshals it into
// target. Returns the FileEntry (for layer attribution) alongside the parse
// error. The caller receives a typed *json.SyntaxError when the content is
// malformed; other I/O errors are wrapped.
func ReadJSON(fs model.FileSystemView, path string, target any) (*model.FileEntry, error) {
	e, ok := fs.Get(path)
	if !ok {
		return nil, fmt.Errorf("read json: %s: not found", path)
	}
	rc, err := fs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer rc.Close()

	dec := json.NewDecoder(rc)
	if err := dec.Decode(target); err != nil {
		return e, fmt.Errorf("decode %s: %w", path, err)
	}
	return e, nil
}

// ReadBytes opens path in fs and reads its full content as bytes. Returns the
// content, the FileEntry, and any I/O error. Suitable for lockfiles that need
// raw parsing (TOML, custom formats).
func ReadBytes(fs model.FileSystemView, path string) ([]byte, *model.FileEntry, error) {
	e, ok := fs.Get(path)
	if !ok {
		return nil, nil, fmt.Errorf("read bytes: %s: not found", path)
	}
	rc, err := fs.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, e, fmt.Errorf("read %s: %w", path, err)
	}
	return data, e, nil
}

// ReadLines opens path in fs and returns its content as a slice of lines
// (without trailing newlines). Returns the FileEntry for layer attribution.
// Blank lines are preserved in the output so callers can detect stanza
// boundaries.
func ReadLines(fs model.FileSystemView, path string) ([]string, *model.FileEntry, error) {
	e, ok := fs.Get(path)
	if !ok {
		return nil, nil, fmt.Errorf("read lines: %s: not found", path)
	}
	rc, err := fs.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer rc.Close()

	var lines []string
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, e, fmt.Errorf("scan %s: %w", path, err)
	}
	return lines, e, nil
}

// WalkDir walks all live (non-deleted) entries whose path begins with prefix.
// Entries are returned in lexical path order. The prefix path itself is
// excluded (only children are returned). This matches the real filesystem
// view's Walk semantics: a prefix of "/" returns all entries.
func WalkDir(fs model.FileSystemView, prefix string) ([]*model.FileEntry, error) {
	var out []*model.FileEntry
	err := fs.Walk("/", func(e *model.FileEntry) error {
		if e.IsDeleted || e.Path == prefix {
			return nil
		}
		if strings.HasPrefix(e.Path, prefix) {
			out = append(out, e)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", prefix, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// FindFiles walks the entire filesystem view and returns all live entries
// whose path has one of the given suffixes (e.g. ".jar", ".war"). Results are
// sorted by path for deterministic output.
func FindFiles(fs model.FileSystemView, suffixes ...string) ([]*model.FileEntry, error) {
	var out []*model.FileEntry
	err := fs.Walk("/", func(e *model.FileEntry) error {
		if e.IsDeleted {
			return nil
		}
		for _, sfx := range suffixes {
			if strings.HasSuffix(e.Path, sfx) {
				out = append(out, e)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find files: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
