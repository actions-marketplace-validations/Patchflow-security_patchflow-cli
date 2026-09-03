package scan

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/Patchflow-security/patchflow-cli/internal/git"
)

var manifestTypes = map[string]string{
	"requirements.txt":  "python",
	"pyproject.toml":    "python",
	"package.json":      "node",
	"package-lock.json": "node-lock",
	"pnpm-lock.yaml":    "node-lock",
	"yarn.lock":         "node-lock",
	"go.mod":            "go",
	"Cargo.toml":        "rust",
	"composer.json":     "php",
	"Gemfile.lock":      "ruby",
	"pom.xml":           "java",
	"build.gradle":      "java",
}

var skipDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
}

// Result holds the output of a scan operation.
type Result struct {
	Root         string     `json:"root"`
	Manifests    []Manifest `json:"manifests"`
	ChangedFiles []string   `json:"changed_files,omitempty"`
}

// Manifest represents a detected dependency manifest file.
type Manifest struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// DetectManifests walks the filesystem starting at root and detects known
// manifest files up to one subdirectory deep (maxDepth=1).
func DetectManifests(root string) ([]Manifest, error) {
	var manifests []Manifest

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	// Check root level (depth 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if t, ok := manifestTypes[name]; ok {
			manifests = append(manifests, Manifest{
				Path: name,
				Type: t,
			})
		}
	}

	// Check one level deep (depth 1)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if skipDirs[entry.Name()] {
			continue
		}
		subPath := filepath.Join(root, entry.Name())
		subEntries, err := os.ReadDir(subPath)
		if err != nil {
			continue
		}
		for _, subEntry := range subEntries {
			if subEntry.IsDir() {
				continue
			}
			name := subEntry.Name()
			if t, ok := manifestTypes[name]; ok {
				manifests = append(manifests, Manifest{
					Path: filepath.ToSlash(filepath.Join(entry.Name(), name)),
					Type: t,
				})
			}
		}
	}

	// Sort for stable output
	sort.Slice(manifests, func(i, j int) bool {
		return manifests[i].Path < manifests[j].Path
	})

	return manifests, nil
}

// ScanLocal detects the git repository and scans for manifests.
func ScanLocal() (*Result, error) {
	repo, err := git.Detect()
	if err != nil {
		return nil, err
	}

	manifests, err := DetectManifests(repo.Root)
	if err != nil {
		return nil, err
	}

	return &Result{
		Root:         repo.Root,
		Manifests:    manifests,
		ChangedFiles: repo.ChangedFiles,
	}, nil
}

// ScanChanged detects the git repository, determines changed files, and returns
// manifests that exist in the repo root or are among the changed files.
func ScanChanged() (*Result, error) {
	repo, err := git.Detect()
	if err != nil {
		return nil, err
	}

	if err := repo.DetectChangedFiles(); err != nil {
		return nil, err
	}

	allManifests, err := DetectManifests(repo.Root)
	if err != nil {
		return nil, err
	}

	changedSet := make(map[string]bool, len(repo.ChangedFiles))
	for _, f := range repo.ChangedFiles {
		changedSet[f] = true
	}

	var filtered []Manifest
	for _, m := range allManifests {
		if filepath.Dir(m.Path) == "." || changedSet[m.Path] {
			filtered = append(filtered, m)
		}
	}

	return &Result{
		Root:         repo.Root,
		Manifests:    filtered,
		ChangedFiles: repo.ChangedFiles,
	}, nil
}
