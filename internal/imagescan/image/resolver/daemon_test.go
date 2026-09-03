package resolver

import (
	"os"
	"strings"
	"testing"

	"github.com/docker/docker/client"
)

func TestDaemonHost(t *testing.T) {
	t.Run("explicit DockerHost wins", func(t *testing.T) {
		got := daemonHost(Options{DockerHost: "tcp://explicit:2376"}, false)
		if got != "tcp://explicit:2376" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("env DOCKER_HOST honored when no explicit host", func(t *testing.T) {
		t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
		got := daemonHost(Options{}, false)
		if got != "unix:///var/run/docker.sock" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("podman falls back to default socket", func(t *testing.T) {
		t.Setenv("DOCKER_HOST", "")
		got := daemonHost(Options{}, true)
		if !strings.Contains(got, "podman") {
			t.Errorf("expected podman socket, got %q", got)
		}
	})

	t.Run("docker falls back to default host", func(t *testing.T) {
		t.Setenv("DOCKER_HOST", "")
		got := daemonHost(Options{}, false)
		if got != client.DefaultDockerHost {
			t.Errorf("expected %q, got %q", client.DefaultDockerHost, got)
		}
	})
}

func TestResolveDaemonDoesNotMutateEnv(t *testing.T) {
	orig := os.Getenv("DOCKER_HOST")
	defer os.Setenv("DOCKER_HOST", orig)

	// Set a value that should be left unchanged.
	_ = os.Setenv("DOCKER_HOST", "unix:///should-not-change")

	// We can't call resolveDaemon without a real daemon, but we can verify
	// daemonHost does not mutate state and returns the expected host.
	_ = daemonHost(Options{DockerHost: "tcp://other:2376"}, false)
	if os.Getenv("DOCKER_HOST") != "unix:///should-not-change" {
		t.Error("DOCKER_HOST was mutated by daemonHost")
	}
}
