// Package config provides helpers for locating PatchFlow scanner runtime
// artefacts (vuln DB, caches) under the OS-standard user config directory.
package config

import (
	"os"
	"path/filepath"
)

const appName = "patchflow-image-scanner"

// Dir returns the base config directory for the scanner.
// Precedence: $PATCHFLOW_CONFIG_DIR > $XDG_CONFIG_HOME/patchflow-image-scanner
// > $HOME/.config/patchflow-image-scanner.
func Dir() string {
	if d := os.Getenv("PATCHFLOW_CONFIG_DIR"); d != "" {
		return d
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, appName)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", appName)
}

// VulnDBPath returns the default path to the SQLite vulnerability database.
// Override with $PATCHFLOW_VULNDB_PATH.
func VulnDBPath() string {
	if p := os.Getenv("PATCHFLOW_VULNDB_PATH"); p != "" {
		return p
	}
	return filepath.Join(Dir(), "vulndb", "sqlite.db")
}

// CacheDir returns the directory used for layer/SBOM caches.
func CacheDir() string {
	if d := os.Getenv("PATCHFLOW_CACHE_DIR"); d != "" {
		return d
	}
	return filepath.Join(Dir(), "cache")
}

// EnsureDir creates path and all parents if they do not exist. Returns nil
// if the directory already exists.
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0o700)
}
