package resolver

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// resolveInput resolves a local --input source: either a tarball (docker
// save / OCI archive) or an OCI image layout directory. The form is detected
// from the filesystem: a directory is treated as an OCI layout; a file (or
// anything ending in .tar) is treated as a tarball.
func resolveInput(input string, opts Options) (*ResolvedImage, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("stat input %q: %w", input, err)
	}

	if info.IsDir() {
		return resolveLayout(input, opts)
	}
	return resolveTarball(input, opts)
}

// resolveLayout opens an OCI image layout directory. If the layout contains
// a single image, it is returned directly; for multi-image layouts the first
// image manifest is selected (digest-based selection is a later phase).
func resolveLayout(path string, opts Options) (*ResolvedImage, error) {
	p, err := layout.FromPath(path)
	if err != nil {
		return nil, fmt.Errorf("open OCI layout %q: %w", path, err)
	}

	idx, err := p.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("read index of %q: %w", path, err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read index manifest of %q: %w", path, err)
	}
	if len(manifest.Manifests) == 0 {
		return nil, fmt.Errorf("OCI layout %q has no manifests", path)
	}

	// Pick the first image manifest descriptor. A manifest list entry with
	// a platform filter is handled in a later phase.
	desc := manifest.Manifests[0]
	img, err := p.Image(desc.Digest)
	if err != nil {
		return nil, fmt.Errorf("load image %s from layout %q: %w", desc.Digest, path, err)
	}
	return buildResolvedFromV1(path, img, opts)
}

// resolveTarball opens a docker-save or OCI archive tarball.
// go-containerregistry's tarball.ImageFromPath handles both layouts when the
// archive contains a single image.
func resolveTarball(path string, opts Options) (*ResolvedImage, error) {
	img, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open tarball %q: %w", path, err)
	}
	return buildResolvedFromV1(path, img, opts)
}

// buildResolvedFromV1 assembles a ResolvedImage for local sources that have
// no registry/tag identity; the original ref is the local path and the
// digest is derived from the image content.
func buildResolvedFromV1(source string, img v1.Image, opts Options) (*ResolvedImage, error) {
	d, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("compute digest for %s: %w", source, err)
	}
	identity := ImageIdentity{
		OriginalRef: source,
		Digest:      d.String(),
		Platform:    opts.Platform,
	}
	if mt, err := img.MediaType(); err == nil {
		identity.MediaType = string(mt)
	}
	// Best-effort repository inference for tarballs named like
	// "api-1.2.3.tar" — purely cosmetic, never authoritative.
	if base := filepath.Base(source); strings.HasSuffix(base, ".tar") {
		identity.Repository = strings.TrimSuffix(base, ".tar")
	}
	return &ResolvedImage{Identity: identity, Image: img}, nil
}
