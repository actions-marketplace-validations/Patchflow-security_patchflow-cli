// Package osdetect parses /etc/os-release (and /usr/lib/os-release as a
// fallback) to identify the base operating system of an image. The result
// drives distro-aware vulnerability matching: the same package/version can
// be vulnerable in one distro and patched in another.
package osdetect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// Detect reads os-release from the filesystem view and returns the
// normalized OS identity. Returns nil if no os-release is present (the
// image may be distroless or scratch-based).
func Detect(_ context.Context, fs model.FileSystemView) (*model.OperatingSystem, error) {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if e, ok := fs.Get(path); ok && !e.IsDir {
			rc, err := fs.Open(path)
			if err != nil {
				return nil, fmt.Errorf("open %s: %w", path, err)
			}
			defer rc.Close()
			return parseOSRelease(rc)
		}
	}
	return nil, nil
}

// parseOSRelease parses the freedesktop.org os-release key=value format.
func parseOSRelease(r io.Reader) (*model.OperatingSystem, error) {
	os := &model.OperatingSystem{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := splitKV(line)
		if !ok {
			continue
		}
		switch key {
		case "ID":
			os.Name = val
		case "VERSION_ID":
			os.VersionID = val
		case "VERSION_CODENAME":
			os.Codename = val
		case "PRETTY_NAME":
			os.Pretty = val
		case "ID_LIKE":
			os.IDLike = strings.Fields(val)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan os-release: %w", err)
	}
	if os.Name == "" {
		return nil, nil
	}
	return os, nil
}

// splitKV splits a "KEY=value" line, stripping surrounding quotes from value.
func splitKV(line string) (key, val string, ok bool) {
	idx := strings.IndexByte(line, '=')
	if idx < 0 {
		return "", "", false
	}
	key = line[:idx]
	val = line[idx+1:]
	val = strings.Trim(val, `"'`)
	return key, val, true
}
