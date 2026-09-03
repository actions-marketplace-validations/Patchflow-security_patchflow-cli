package resolver

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
)

// resolveDaemon resolves an image from a local Docker or Podman daemon via
// the Docker-compatible API. It creates a Docker client pointed at the
// correct socket without mutating the global DOCKER_HOST environment variable.
func resolveDaemon(ref string, opts Options, podman bool) (*ResolvedImage, error) {
	if ref == "" {
		return nil, fmt.Errorf("daemon image reference is required (e.g. docker-daemon:api:latest)")
	}

	tag, err := name.NewTag(ref, name.StrictValidation)
	if err != nil {
		return nil, fmt.Errorf("parse daemon ref %q: %w", ref, err)
	}

	host := daemonHost(opts, podman)
	cli, err := client.NewClientWithOpts(
		client.WithHost(host),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("create docker client for %s: %w", host, err)
	}
	defer cli.Close()

	ctx := context.Background()
	cli.NegotiateAPIVersion(ctx)

	img, err := daemon.Image(tag, daemon.WithClient(cli))
	if err != nil {
		which := "docker"
		if podman {
			which = "podman"
		}
		return nil, fmt.Errorf("read %s image %q: %w (is the daemon running?)", which, ref, err)
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("compute digest for %s: %w", ref, err)
	}
	return buildIdentity(ref, tag.Context(), digest.String(), img, opts)
}

// daemonHost returns the Docker API socket host to use. The caller's explicit
// DockerHost takes precedence, then an existing DOCKER_HOST env var, then the
// default Podman socket for podman requests, and finally the Docker default.
func daemonHost(opts Options, podman bool) string {
	if opts.DockerHost != "" {
		return opts.DockerHost
	}
	if env := os.Getenv("DOCKER_HOST"); env != "" {
		return env
	}
	if podman {
		return defaultPodmanSocket()
	}
	return client.DefaultDockerHost
}

// defaultPodmanSocket returns the most likely rootless Podman socket for the
// current user. Falls back to the system socket.
func defaultPodmanSocket() string {
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); runtime != "" {
		return "unix://" + runtime + "/podman/podman.sock"
	}
	return "unix:///run/podman/podman.sock"
}

// parsePlatform splits "linux/amd64" into a v1.Platform. It tolerates an
// optional variant suffix ("linux/arm/v7").
func parsePlatform(s string) (v1.Platform, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return v1.Platform{}, fmt.Errorf("empty platform")
	}
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return v1.Platform{}, fmt.Errorf("expected os/arch[,variant], got %q", s)
	}
	p := v1.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) >= 3 {
		p.Variant = parts[2]
	}
	return p, nil
}
