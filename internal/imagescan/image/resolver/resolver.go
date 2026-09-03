// Package resolver turns an image reference string into a concrete,
// digest-identified image handle. It is the entry point of the scan
// pipeline: every downstream stage operates on the ResolvedImage returned
// here.
//
// Supported reference forms (v1):
//
//	ghcr.io/org/api:1.2.3        remote registry (tag)
//	ghcr.io/org/api@sha256:...   remote registry (digest)
//	--input image.tar            docker save / OCI archive (tarball)
//	--input ./oci-image/         OCI image layout directory
//	docker-daemon:api:latest     local Docker daemon
//	podman:api:latest            local Podman (via Docker-compatible API)
//
// The Digest in the returned ImageIdentity is always the content-addressed
// manifest digest; Tag is advisory only and MUST NOT be used as a security
// identity.
package resolver

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// ResolvedImage is the output of Resolve: a v1.Image handle plus the
// normalized identity. Callers must not mutate the handle.
type ResolvedImage struct {
	Identity ImageIdentity
	Image    v1.Image
}

// ImageIdentity is re-exported from the model package so callers of the
// resolver do not need a second import for the same concept.
type ImageIdentity = model.ImageIdentity

// Options configures resolver behavior: registry auth, platform selection,
// and local archive/layout paths.
type Options struct {
	// Platform selects a single platform for multi-arch manifests, e.g.
	// "linux/amd64". Empty means the manifest's default.
	Platform string

	// Input is a local source path used when the ref is empty: a tarball
	// file or an OCI image layout directory.
	Input string

	// DockerHost overrides the Docker/Podman API socket endpoint for
	// docker-daemon: and podman: refs. If empty, DOCKER_HOST is honored.
	DockerHost string

	// RemoteOptions are passed through to go-containerregistry's remote
	// package for registry pulls (auth, transport, etc.).
	RemoteOptions []remote.Option
}

// Resolver resolves a single reference. Implementations must be safe for
// concurrent use.
type Resolver interface {
	Resolve(ctx context.Context, ref string, opts Options) (*ResolvedImage, error)
}

// New returns the default dispatching resolver.
func New() Resolver { return &dispatcher{} }

// dispatcher inspects the ref/opts and delegates to the right backend.
type dispatcher struct{}

func (d *dispatcher) Resolve(ctx context.Context, ref string, opts Options) (*ResolvedImage, error) {
	switch {
	case strings.HasPrefix(ref, "docker-daemon:"):
		return resolveDaemon(strings.TrimPrefix(ref, "docker-daemon:"), opts, false)
	case strings.HasPrefix(ref, "podman:"):
		return resolveDaemon(strings.TrimPrefix(ref, "podman:"), opts, true)
	case opts.Input != "":
		return resolveInput(opts.Input, opts)
	default:
		return resolveRemote(ref, opts)
	}
}

// resolveRemote handles registry refs by tag or digest.
func resolveRemote(ref string, opts Options) (*ResolvedImage, error) {
	if ref == "" {
		return nil, fmt.Errorf("image reference is required (or pass --input for a local archive/layout)")
	}

	ropts := append([]remote.Option{}, opts.RemoteOptions...)
	if opts.Platform != "" {
		plat, perr := parsePlatform(opts.Platform)
		if perr != nil {
			return nil, fmt.Errorf("platform %q: %w", opts.Platform, perr)
		}
		ropts = append(ropts, remote.WithPlatform(plat))
	}

	// name.NewDigest parses refs containing @sha256:...; otherwise treat
	// as a tag reference. Both implement name.Reference for remote.Image.
	// WeakValidation allows shorthand refs like "alpine:3.20" to resolve
	// against the default registry (Docker Hub) — the expected CLI UX.
	if strings.Contains(ref, "@") {
		d, err := name.NewDigest(ref, name.WeakValidation)
		if err != nil {
			return nil, fmt.Errorf("parse digest ref %q: %w", ref, err)
		}
		img, err := remote.Image(d, ropts...)
		if err != nil {
			return nil, fmt.Errorf("pull %s: %w", ref, err)
		}
		return buildIdentity(ref, d.Context(), d.DigestStr(), img, opts)
	}

	t, err := name.NewTag(ref, name.WeakValidation)
	if err != nil {
		return nil, fmt.Errorf("parse tag ref %q: %w", ref, err)
	}
	img, err := remote.Image(t, ropts...)
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", ref, err)
	}

	// Always derive the canonical digest from the fetched image so the
	// identity is content-addressed even when the caller passed a tag.
	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("compute digest for %s: %w", ref, err)
	}
	return buildIdentity(ref, t.Context(), digest.String(), img, opts)
}

// buildIdentity assembles a ResolvedImage from a fetched v1.Image and the
// parsed repository/digest components.
func buildIdentity(originalRef string, repo name.Repository, digest string, img v1.Image, opts Options) (*ResolvedImage, error) {
	identity := ImageIdentity{
		OriginalRef: originalRef,
		Registry:    repo.RegistryStr(),
		Repository:  repo.RepositoryStr(),
		Digest:      digest,
		Platform:    opts.Platform,
	}
	// Tag is advisory: extract it from the original ref if present.
	if strings.Contains(originalRef, "@") {
		// digest ref — no tag
	} else if t, err := name.NewTag(originalRef, name.WeakValidation); err == nil {
		identity.Tag = t.TagStr()
	}
	if mt, err := img.MediaType(); err == nil {
		identity.MediaType = string(mt)
	}
	return &ResolvedImage{Identity: identity, Image: img}, nil
}
