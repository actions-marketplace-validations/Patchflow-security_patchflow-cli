// Package manifest parses dependency manifest files and extracts package
// names and versions across multiple ecosystems (Go, npm, PyPI, Cargo, RubyGems, etc.).
package manifest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// ManifestInfo represents a detected manifest file and its ecosystem.
type ManifestInfo struct {
	Path      string             `json:"path"`
	Ecosystem analysis.Ecosystem `json:"ecosystem"`
}

// MaxManifestSize is the maximum file size for manifest parsing (50 MB).
// Files larger than this are skipped to prevent denial-of-service via
// maliciously large manifest files.
const MaxManifestSize = 50 * 1024 * 1024

// readFileWithLimit reads a file but rejects files larger than MaxManifestSize.
// This prevents denial-of-service attacks via maliciously large manifest files.
func readFileWithLimit(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxManifestSize {
		return nil, fmt.Errorf("file %s is too large (%d bytes, max %d bytes)", path, info.Size(), MaxManifestSize)
	}
	return os.ReadFile(path)
}

// KnownManifests maps manifest filenames to their ecosystem.
var KnownManifests = map[string]analysis.Ecosystem{
	"go.mod":              analysis.EcosystemGo,
	"go.work":             analysis.EcosystemGo,
	"package.json":        analysis.EcosystemNPM,
	"package-lock.json":   analysis.EcosystemNPM,
	"yarn.lock":           analysis.EcosystemNPM,
	"pnpm-lock.yaml":      analysis.EcosystemNPM,
	"pnpm-workspace.yaml": analysis.EcosystemNPM,
	"requirements.txt":    analysis.EcosystemPyPI,
	"pyproject.toml":      analysis.EcosystemPyPI,
	"setup.py":            analysis.EcosystemPyPI,
	"setup.cfg":           analysis.EcosystemPyPI,
	"Pipfile.lock":        analysis.EcosystemPyPI,
	"poetry.lock":         analysis.EcosystemPyPI,
	"uv.lock":             analysis.EcosystemPyPI,
	"Cargo.toml":          analysis.EcosystemCargo,
	"Gemfile":             analysis.EcosystemRubyGems,
	"Gemfile.lock":        analysis.EcosystemRubyGems,
	"composer.json":       analysis.EcosystemPackagist,
	"pom.xml":             analysis.EcosystemMaven,
	"build.gradle":        analysis.EcosystemMaven,
	"build.gradle.kts":    analysis.EcosystemMaven,
	"settings.gradle":     analysis.EcosystemMaven,
	"settings.gradle.kts": analysis.EcosystemMaven,
	"Chart.yaml":          analysis.EcosystemHelm,
}

// SkipDirs are directories that should never be traversed.
var SkipDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
}

// Detect walks the filesystem from root and finds manifest files up to maxDepth
// subdirectories deep. Returns sorted results.
func Detect(root string, maxDepth int) ([]ManifestInfo, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}

	var manifests []ManifestInfo

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}

		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			return nil
		}

		depth := strings.Count(rel, string(filepath.Separator))
		if d.IsDir() {
			if depth > maxDepth {
				return filepath.SkipDir
			}
			if SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()
		if eco, ok := KnownManifests[name]; ok {
			manifests = append(manifests, ManifestInfo{
				Path:      rel,
				Ecosystem: eco,
			})
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk %s: %w", root, err)
	}

	sort.Slice(manifests, func(i, j int) bool {
		return manifests[i].Path < manifests[j].Path
	})

	return manifests, nil
}

// Parse reads a manifest file and extracts dependencies.
// It dispatches to the appropriate parser based on the filename.
// Files larger than MaxManifestSize are rejected to prevent DoS.
func Parse(path string) ([]analysis.Dependency, error) {
	name := filepath.Base(path)

	// Check file size before parsing to prevent DoS
	if info, err := os.Stat(path); err == nil && info.Size() > MaxManifestSize {
		return nil, fmt.Errorf("manifest %s is too large (%d bytes, max %d bytes)", path, info.Size(), MaxManifestSize)
	}

	switch name {
	case "go.mod":
		return ParseGoMod(path)
	case "go.work":
		return ParseGoWork(path)
	case "package.json":
		return ParsePackageJSON(path)
	case "package-lock.json":
		return ParsePackageLock(path)
	case "yarn.lock":
		return ParseYarnLock(path)
	case "pnpm-lock.yaml":
		return ParsePnpmLock(path)
	case "pnpm-workspace.yaml":
		return ParsePnpmWorkspace(path)
	case "requirements.txt":
		return ParseRequirementsTxt(path)
	case "pyproject.toml":
		return ParsePyProjectToml(path)
	case "setup.py":
		return ParseSetupPy(path)
	case "setup.cfg":
		return ParseSetupCfg(path)
	case "Pipfile.lock":
		return ParsePipfileLock(path)
	case "poetry.lock":
		return ParsePoetryLock(path)
	case "uv.lock":
		return ParseUvLock(path)
	case "Cargo.toml":
		return ParseCargoToml(path)
	case "Gemfile":
		return ParseGemfile(path)
	case "Gemfile.lock":
		return ParseGemfileLock(path)
	case "composer.json":
		return ParseComposerJSON(path)
	case "pom.xml":
		return ParsePomXMLWithParent(path)
	case "build.gradle", "build.gradle.kts":
		return ParseBuildGradle(path)
	case "settings.gradle", "settings.gradle.kts":
		return ParseSettingsGradle(path)
	case "Chart.yaml":
		return ParseHelmChart(path)
	default:
		return nil, nil
	}
}

// ParseAll parses all detected manifests in a repository root.
// When workspace configuration files are present (go.work, pnpm-workspace.yaml,
// or yarn workspaces in a root package.json), individual member manifests
// referenced by the workspace are skipped to avoid duplicate dependencies
// (the workspace parser already aggregates them).
func ParseAll(root string, maxDepth int) ([]analysis.Dependency, []ManifestInfo, error) {
	manifests, err := Detect(root, maxDepth)
	if err != nil {
		return nil, nil, err
	}

	// Build a set of go.mod paths covered by go.work files.
	coveredGoMods := make(map[string]bool)
	for _, m := range manifests {
		if filepath.Base(m.Path) != "go.work" {
			continue
		}
		workPath := filepath.Join(root, m.Path)
		mods, err := parseGoWorkModules(workPath)
		if err != nil {
			continue
		}
		workDir := filepath.Dir(workPath)
		for _, modPath := range mods {
			absMod := modPath
			if !filepath.IsAbs(absMod) {
				absMod = filepath.Join(workDir, modPath)
			}
			goModPath := filepath.Join(absMod, "go.mod")
			relMod, err := filepath.Rel(root, goModPath)
			if err == nil {
				coveredGoMods[relMod] = true
			}
		}
	}

	// Build a set of package.json paths covered by npm workspaces
	// (pnpm-workspace.yaml or yarn workspaces in root package.json).
	// Also track yarn workspace roots so we can resolve their workspace deps.
	coveredPkgJSONs := make(map[string]bool)
	type yarnWorkspaceRoot struct {
		path     string // relative to root
		patterns []string
	}
	var yarnRoots []yarnWorkspaceRoot

	for _, m := range manifests {
		switch filepath.Base(m.Path) {
		case "pnpm-workspace.yaml":
			workPath := filepath.Join(root, m.Path)
			data, err := os.ReadFile(workPath)
			if err != nil {
				continue
			}
			var ws pnpmWorkspace
			if err := yaml.Unmarshal(data, &ws); err != nil {
				continue
			}
			workDir := filepath.Dir(workPath)
			markCoveredPkgJSONs(root, workDir, ws.Packages, coveredPkgJSONs)

		case "package.json":
			// Check if this is a root package.json with yarn workspaces.
			// Only root-level package.json (at depth 0) can be a yarn workspace root.
			depth := strings.Count(m.Path, string(filepath.Separator))
			if depth > 0 {
				continue
			}
			data, err := os.ReadFile(filepath.Join(root, m.Path))
			if err != nil {
				continue
			}
			var pkg packageJSON
			if err := json.Unmarshal(data, &pkg); err != nil {
				continue
			}
			patterns := extractWorkspacePatterns(pkg.Workspaces)
			if len(patterns) == 0 {
				continue
			}
			workDir := filepath.Dir(filepath.Join(root, m.Path))
			markCoveredPkgJSONs(root, workDir, patterns, coveredPkgJSONs)
			yarnRoots = append(yarnRoots, yarnWorkspaceRoot{path: m.Path, patterns: patterns})
		}
	}

	// Build a set of build.gradle/build.gradle.kts paths covered by
	// settings.gradle files (Gradle multi-project).
	coveredGradleBuilds := make(map[string]bool)
	for _, m := range manifests {
		base := filepath.Base(m.Path)
		if base != "settings.gradle" && base != "settings.gradle.kts" {
			continue
		}
		workPath := filepath.Join(root, m.Path)
		data, err := os.ReadFile(workPath)
		if err != nil {
			continue
		}
		workDir := filepath.Dir(workPath)
		matches := gradleIncludeRe.FindAllStringSubmatch(string(data), -1)
		for _, match := range matches {
			name := match[1]
			if name == "" {
				name = match[2]
			}
			if name == "" {
				continue
			}
			spPath := strings.ReplaceAll(name, ":", string(filepath.Separator))
			spDir := filepath.Join(workDir, spPath)
			for _, buildFile := range []string{"build.gradle", "build.gradle.kts"} {
				buildPath := filepath.Join(spDir, buildFile)
				rel, err := filepath.Rel(root, buildPath)
				if err == nil {
					coveredGradleBuilds[rel] = true
				}
			}
		}
	}

	var allDeps []analysis.Dependency
	for _, m := range manifests {
		base := filepath.Base(m.Path)

		// Skip go.mod files already covered by a go.work workspace.
		if base == "go.mod" && coveredGoMods[m.Path] {
			continue
		}

		// Skip package.json files already covered by an npm workspace.
		if base == "package.json" && coveredPkgJSONs[m.Path] {
			continue
		}

		// Skip build.gradle files already covered by a settings.gradle.
		if (base == "build.gradle" || base == "build.gradle.kts") && coveredGradleBuilds[m.Path] {
			continue
		}

		fullPath := filepath.Join(root, m.Path)
		deps, err := Parse(fullPath)
		if err != nil {
			continue // skip unparseable manifests
		}
		for i := range deps {
			deps[i].ManifestPath = m.Path
		}
		allDeps = append(allDeps, deps...)

		// If this is a yarn workspace root, also resolve workspace package deps.
		if base == "package.json" {
			for _, yr := range yarnRoots {
				if yr.path == m.Path {
					workDir := filepath.Dir(fullPath)
					wsDeps, _ := resolveNpmWorkspacePackages(workDir, yr.patterns)
					allDeps = append(allDeps, wsDeps...)
					break
				}
			}
		}
	}

	// Deduplicate Maven dependencies across multi-module projects.
	// In Maven multi-module builds, the same dependency can appear in both
	// the parent POM and child module POMs (via inheritance). We keep the
	// first occurrence (which is from the parent or earlier module).
	allDeps = dedupMavenDeps(allDeps)

	// Deduplicate npm dependencies when both package.json and
	// package-lock.json are present. The lockfile contains the full
	// transitive tree with license info, so it takes precedence. Any
	// package.json deps not in the lockfile (e.g. unresolved or git deps)
	// are kept as supplementary entries.
	allDeps = dedupNpmDeps(allDeps)

	// Deduplicate Ruby dependencies when both Gemfile and Gemfile.lock are
	// present. The lockfile has resolved versions, while Gemfile entries are
	// often unpinned placeholders like "gem \"fastlane\"".
	allDeps = dedupRubyDeps(allDeps)

	return allDeps, manifests, nil
}

// dedupMavenDeps removes duplicate Maven dependencies (same name@version),
// keeping the first occurrence. This prevents double-counting in multi-module
// Maven projects where parent POM dependencies are inherited by children.
func dedupMavenDeps(deps []analysis.Dependency) []analysis.Dependency {
	seen := make(map[string]bool)
	var result []analysis.Dependency
	for _, dep := range deps {
		if dep.Ecosystem != analysis.EcosystemMaven {
			result = append(result, dep)
			continue
		}
		key := dep.Name + "@" + dep.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, dep)
	}
	return result
}

func dedupRubyDeps(deps []analysis.Dependency) []analysis.Dependency {
	gemfileDirect := make(map[string]bool)
	lockIndex := make(map[string]int)

	for i, dep := range deps {
		if dep.Ecosystem != analysis.EcosystemRubyGems {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(dep.ManifestPath))
		key := dir + ":" + dep.Name
		switch filepath.Base(dep.ManifestPath) {
		case "Gemfile":
			if dep.IsDirect {
				gemfileDirect[key] = true
			}
		case "Gemfile.lock":
			lockIndex[key] = i
		}
	}

	for key, idx := range lockIndex {
		if gemfileDirect[key] {
			deps[idx].IsDirect = true
		}
	}

	var result []analysis.Dependency
	for _, dep := range deps {
		if dep.Ecosystem == analysis.EcosystemRubyGems && filepath.Base(dep.ManifestPath) == "Gemfile" {
			dir := filepath.ToSlash(filepath.Dir(dep.ManifestPath))
			key := dir + ":" + dep.Name
			if _, ok := lockIndex[key]; ok {
				continue
			}
		}
		result = append(result, dep)
	}
	return result
}

// dedupNpmDeps removes duplicate npm dependencies when both package.json and
// a lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml) are present.
// The lockfile entries (which have transitive deps + license info) take
// precedence over package.json entries. Any package.json deps not in the
// lockfile (e.g. unresolved or git deps) are kept as supplementary entries.
//
// This ensures that when a lockfile is present, we use the full transitive
// tree from the lockfile rather than just the direct deps from package.json.
func dedupNpmDeps(deps []analysis.Dependency) []analysis.Dependency {
	// First pass: collect all lockfile deps into a set.
	lockKeys := make(map[string]bool)
	hasLockfile := false
	for _, dep := range deps {
		if dep.Ecosystem == analysis.EcosystemNPM && isNpmLockfile(dep.ManifestPath) {
			hasLockfile = true
			lockKeys[dep.Name+"@"+dep.Version] = true
		}
	}

	// If no lockfile deps, nothing to dedup.
	if !hasLockfile {
		return deps
	}

	// Second pass: keep all lockfile deps, and keep package.json deps
	// only if they're not already covered by the lockfile.
	var result []analysis.Dependency
	for _, dep := range deps {
		if dep.Ecosystem != analysis.EcosystemNPM {
			result = append(result, dep)
			continue
		}
		isFromLock := isNpmLockfile(dep.ManifestPath)
		if isFromLock {
			result = append(result, dep)
			continue
		}
		// From package.json — keep only if not in lockfile
		key := dep.Name + "@" + dep.Version
		if !lockKeys[key] {
			result = append(result, dep)
		}
	}
	return result
}

// markCoveredPkgJSONs resolves workspace glob patterns and marks all matching
// package.json files as covered in the provided set.
func markCoveredPkgJSONs(root, workDir string, patterns []string, covered map[string]bool) {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		matches, err := filepath.Glob(filepath.Join(workDir, pattern))
		if err != nil {
			continue
		}
		for _, match := range matches {
			pkgJSONPath := filepath.Join(match, "package.json")
			if _, err := os.Stat(pkgJSONPath); err != nil {
				continue
			}
			rel, err := filepath.Rel(root, pkgJSONPath)
			if err == nil {
				covered[rel] = true
			}
		}
	}
}

// --- Go: go.mod ---

var goModRequireRe = regexp.MustCompile(`^\s*(\S+)\s+(\S+)(?:\s+//\s*(indirect))?`)

// ParseGoMod parses a go.mod file and extracts direct (non-indirect) requires.
func ParseGoMod(path string) ([]analysis.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []analysis.Dependency
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	inRequireBlock := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Check for block require first: "require ("
		if trimmed == "require (" {
			inRequireBlock = true
			continue
		}
		// Single-line require: require foo v1.2.3
		if strings.HasPrefix(trimmed, "require ") && !strings.HasSuffix(trimmed, "(") {
			rest := strings.TrimPrefix(trimmed, "require ")
			if dep := parseGoModRequireLine(rest); dep != nil {
				deps = append(deps, *dep)
			}
			continue
		}
		if trimmed == ")" && inRequireBlock {
			inRequireBlock = false
			continue
		}
		if inRequireBlock {
			if dep := parseGoModRequireLine(trimmed); dep != nil {
				deps = append(deps, *dep)
			}
		}
	}

	return deps, scanner.Err()
}

func parseGoModRequireLine(line string) *analysis.Dependency {
	m := goModRequireRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	pkg := m[1]
	ver := m[2]
	indirect := strings.Contains(line, "// indirect")
	// Skip the Go toolchain and module self-reference
	if pkg == "" || strings.HasPrefix(pkg, "go ") || ver == "" {
		return nil
	}
	return &analysis.Dependency{
		Name:      pkg,
		Version:   ver,
		Ecosystem: analysis.EcosystemGo,
		IsDirect:  !indirect,
	}
}

// --- Go: go.work ---

// goWorkUseRe matches "use" directives in go.work files.
// go.work syntax: use ( ... ) block or single-line "use ./module1".
var goWorkUseRe = regexp.MustCompile(`^\s*(\.\./?\S*|\./?\S*|\S+)`)

// ParseGoWork parses a go.work file. Unlike go.mod, go.work does not list
// dependencies directly; it lists local modules via "use" directives.
// ParseGoWork resolves each referenced module's go.mod and aggregates all
// dependencies, deduplicating by name@version.
func ParseGoWork(path string) ([]analysis.Dependency, error) {
	modules, err := parseGoWorkModules(path)
	if err != nil {
		return nil, err
	}

	// Resolve each module's go.mod and parse its dependencies.
	// go.work is at the workspace root; module paths are relative to it.
	workDir := filepath.Dir(path)
	var allDeps []analysis.Dependency
	seen := make(map[string]bool) // dedupe by name@version

	for _, modPath := range modules {
		absModPath := modPath
		if !filepath.IsAbs(absModPath) {
			absModPath = filepath.Join(workDir, modPath)
		}
		goModPath := filepath.Join(absModPath, "go.mod")
		if _, err := os.Stat(goModPath); err != nil {
			continue // module without go.mod, skip
		}

		modDeps, err := ParseGoMod(goModPath)
		if err != nil {
			continue
		}

		// Compute the manifest path relative to the workspace root
		// so findings point to the correct module.
		relModPath, err := filepath.Rel(workDir, goModPath)
		if err != nil {
			relModPath = goModPath
		}

		for _, dep := range modDeps {
			key := dep.Name + "@" + dep.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			dep.ManifestPath = relModPath
			allDeps = append(allDeps, dep)
		}
	}

	return allDeps, nil
}

// parseGoWorkModules reads a go.work file and returns the list of module
// paths from its "use" directives.
func parseGoWorkModules(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var modules []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	inUseBlock := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Block use: "use ("
		if trimmed == "use (" {
			inUseBlock = true
			continue
		}
		// Single-line use: use ./services/api
		if strings.HasPrefix(trimmed, "use ") && !strings.HasSuffix(trimmed, "(") {
			rest := strings.TrimPrefix(trimmed, "use ")
			rest = strings.TrimSpace(rest)
			if rest != "" {
				modules = append(modules, rest)
			}
			continue
		}
		if trimmed == ")" && inUseBlock {
			inUseBlock = false
			continue
		}
		if inUseBlock {
			m := goWorkUseRe.FindString(trimmed)
			if m != "" {
				modules = append(modules, strings.TrimSpace(m))
			}
		}
	}
	return modules, scanner.Err()
}

// --- npm: package.json ---

type packageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	License         string            `json:"license"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Workspaces      json.RawMessage   `json:"workspaces"` // can be []string or {"packages": []string}
}

// extractWorkspacePatterns extracts glob patterns from the "workspaces" field
// of a package.json. The field can be either an array of strings or an object
// with a "packages" key containing an array of strings (yarn workspace format).
func extractWorkspacePatterns(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	// Try array format: ["packages/*", "apps/*"]
	var patterns []string
	if err := json.Unmarshal(raw, &patterns); err == nil {
		return patterns
	}
	// Try object format: {"packages": ["packages/*"], "nohoist": [...]}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Packages
	}
	return nil
}

// ParsePackageJSON parses a package.json file.
func ParsePackageJSON(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("invalid package.json: %w", err)
	}

	var deps []analysis.Dependency

	// Include the package itself so OSV can detect vulnerabilities in the
	// root package (e.g. CVE-2024-29041 affects express itself, not its deps).
	if pkg.Name != "" && pkg.Version != "" {
		deps = append(deps, analysis.Dependency{
			Name:      pkg.Name,
			Version:   cleanNPMVersion(pkg.Version),
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true,
			IsRoot:    true,
			License:   pkg.License,
		})
	}

	for name, version := range pkg.Dependencies {
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true,
			IsDev:     false,
		})
	}
	for name, version := range pkg.DevDependencies {
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true,
			IsDev:     true,
		})
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// cleanNPMVersion strips semver range operators ( ^, ~, >=, etc.) to get a base version.
func cleanNPMVersion(v string) string {
	v = strings.TrimSpace(v)
	// Handle git/file/local specs — keep as-is for display but they won't query OSV
	if strings.HasPrefix(v, "git+") || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "link:") {
		return v
	}
	// Strip leading range operators
	v = strings.TrimLeft(v, "^~>=< ")
	// Handle wildcard
	if v == "*" || v == "" || v == "latest" {
		return ""
	}
	// Handle "x.y.z || a.b.c" — take the first
	if idx := strings.Index(v, " || "); idx > 0 {
		v = v[:idx]
	}
	return strings.TrimLeft(v, "v")
}

// --- npm: package-lock.json ---

// packageLock represents the structure of a package-lock.json file (v2/v3).
// The "packages" key maps package paths to their metadata, including
// transitive dependencies. The "dependencies" key (v1) is a flat list.
type packageLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version      string            `json:"version"`
		License      string            `json:"license"`
		Resolved     string            `json:"resolved"`
		Dev          bool              `json:"dev"`
		Optional     bool              `json:"optional"`
		Dependencies map[string]string `json:"dependencies"`
	} `json:"packages"`
	// v1 format: flat dependency map
	Dependencies map[string]struct {
		Version  string            `json:"version"`
		Resolved string            `json:"resolved"`
		Dev      bool              `json:"dev"`
		License  string            `json:"license"`
		Requires map[string]string `json:"requires"`
	} `json:"dependencies"`
}

// ParsePackageLock parses a package-lock.json file and extracts ALL
// dependencies (direct + transitive) with their resolved versions and
// license info. This is the key data source for npm transitive dependency
// scanning — it contains the full dependency tree that package.json
// (which only lists direct deps) does not.
//
// Supports both lockfile v1 (flat "dependencies" map) and v2/v3
// (nested "packages" map with "node_modules/" paths).
func ParsePackageLock(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid package-lock.json: %w", err)
	}

	var deps []analysis.Dependency
	seen := make(map[string]bool) // dedup by name@version

	// v2/v3 format: "packages" map with "node_modules/" paths
	if len(lock.Packages) > 0 {
		for pkgPath, info := range lock.Packages {
			// Skip the root package (empty path)
			if pkgPath == "" {
				continue
			}
			// Skip linked packages (no version)
			if info.Version == "" {
				continue
			}
			// Extract package name from the path.
			// Paths are like "node_modules/foo" or "node_modules/bar/node_modules/baz"
			// For scoped packages: "node_modules/@scope/pkg"
			name := extractPkgNameFromLockPath(pkgPath)
			if name == "" {
				continue
			}

			key := name + "@" + info.Version
			if seen[key] {
				continue
			}
			seen[key] = true

			// Determine if this is a direct or transitive dependency.
			// In lockfile v2, direct deps are at "node_modules/{name}" (one level).
			// Transitive deps are at "node_modules/{parent}/node_modules/{name}".
			isDirect := isDirectLockDep(pkgPath)

			deps = append(deps, analysis.Dependency{
				Name:      name,
				Version:   info.Version,
				Ecosystem: analysis.EcosystemNPM,
				IsDirect:  isDirect,
				IsDev:     info.Dev,
				License:   info.License,
			})
		}
	}

	// v1 format: flat "dependencies" map (fallback if no "packages" key)
	if len(lock.Packages) == 0 && len(lock.Dependencies) > 0 {
		for name, info := range lock.Dependencies {
			if info.Version == "" {
				continue
			}
			key := name + "@" + info.Version
			if seen[key] {
				continue
			}
			seen[key] = true

			deps = append(deps, analysis.Dependency{
				Name:      name,
				Version:   info.Version,
				Ecosystem: analysis.EcosystemNPM,
				IsDirect:  true, // v1 format doesn't distinguish direct/transitive
				IsDev:     info.Dev,
				License:   info.License,
			})
		}
	}

	return deps, nil
}

// extractPkgNameFromLockPath extracts the package name from a lockfile v2
// package path. Paths look like:
//
//	"node_modules/foo"           -> "foo"
//	"node_modules/@scope/bar"    -> "@scope/bar"
//	"node_modules/a/node_modules/b" -> "b" (nested transitive dep)
//	"apps/web/node_modules/foo"  -> "foo"
func extractPkgNameFromLockPath(path string) string {
	// Find the last "node_modules/" segment
	idx := strings.LastIndex(path, "node_modules/")
	if idx < 0 {
		return ""
	}
	rest := path[idx+len("node_modules/"):]

	// Handle scoped packages (@scope/pkg)
	if strings.HasPrefix(rest, "@") {
		// The name is "@scope/pkg" — take up to the next "/" after the scope
		slashIdx := strings.Index(rest, "/")
		if slashIdx < 0 {
			return rest
		}
		secondSlash := strings.Index(rest[slashIdx+1:], "/")
		if secondSlash < 0 {
			return rest
		}
		return rest[:slashIdx+1+secondSlash]
	}

	// Non-scoped: name is everything up to the next "/"
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return rest
	}
	return rest[:slashIdx]
}

// isDirectLockDep returns true if the package path indicates a direct
// dependency (only one "node_modules/" level, no nesting).
func isDirectLockDep(path string) bool {
	count := strings.Count(path, "node_modules/")
	return count == 1
}

// isNpmLockfile returns true if the manifest path is an npm lockfile
// (package-lock.json, yarn.lock, or pnpm-lock.yaml).
func isNpmLockfile(manifestPath string) bool {
	return strings.HasSuffix(manifestPath, "package-lock.json") ||
		strings.HasSuffix(manifestPath, "yarn.lock") ||
		strings.HasSuffix(manifestPath, "pnpm-lock.yaml")
}

// --- npm: yarn.lock ---

// ParseYarnLock parses a yarn.lock file (v1 format) and extracts ALL
// dependencies (direct + transitive) with their resolved versions.
// yarn.lock v1 is a text-based format with entries like:
//
//	abbrev@1, abbrev@1.0.x:
//	  version "1.0.9"
//	  resolved "https://registry.yarnpkg.com/abbrev/-/abbrev-1.0.9.tgz#..."
//
// Each key can have multiple package specifiers separated by ", ".
// We extract the package name from the first specifier and the version
// from the "version" field.
func ParseYarnLock(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	var deps []analysis.Dependency
	seen := make(map[string]bool)

	lines := strings.Split(string(data), "\n")
	i := 0
	for i < len(lines) {
		line := lines[i]

		// Skip comments, blank lines, and metadata
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			i++
			continue
		}

		// A key line ends with ":" and contains package specifiers
		if !strings.HasSuffix(strings.TrimSpace(line), ":") {
			i++
			continue
		}

		// Extract package name from the key line
		keyLine := strings.TrimSuffix(strings.TrimSpace(line), ":")
		name := extractYarnPkgName(keyLine)
		if name == "" {
			i++
			continue
		}

		// Look for the version field in subsequent indented lines
		version := ""
		resolved := ""
		for j := i + 1; j < len(lines); j++ {
			subLine := strings.TrimSpace(lines[j])
			if subLine == "" {
				break
			}
			if !strings.HasPrefix(lines[j], " ") && !strings.HasPrefix(lines[j], "\t") {
				break
			}
			if strings.HasPrefix(subLine, "version ") {
				version = strings.Trim(strings.TrimPrefix(subLine, "version "), `"`)
			}
			if strings.HasPrefix(subLine, "resolved ") {
				resolved = strings.Trim(strings.TrimPrefix(subLine, "resolved "), `"`)
			}
		}

		if version == "" {
			i++
			continue
		}

		key := name + "@" + version
		if seen[key] {
			i++
			continue
		}
		seen[key] = true

		// Check if this is a direct dependency (no nesting in yarn.lock v1)
		// In yarn.lock v1, all entries are at the top level — we can't
		// distinguish direct from transitive. We mark all as direct.
		// The dedup logic will handle overlap with package.json.
		_ = resolved // resolved URL (not used for OSV queries)
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true, // yarn.lock v1 doesn't distinguish direct/transitive
		})

		i++
	}

	return deps, nil
}

// extractYarnPkgName extracts the package name from a yarn.lock key line.
// Key lines can be: "abbrev@1, abbrev@1.0.x" or "@scope/pkg@^1.0.0"
// We take the first specifier and extract the name part.
func extractYarnPkgName(keyLine string) string {
	// Take the first specifier (before ", ")
	if idx := strings.Index(keyLine, ", "); idx >= 0 {
		keyLine = keyLine[:idx]
	}

	// Handle scoped packages: @scope/pkg@version
	if strings.HasPrefix(keyLine, "@") {
		// Find the second @ (after the scope/pkg name)
		secondAt := strings.Index(keyLine[1:], "@")
		if secondAt >= 0 {
			return keyLine[:secondAt+1]
		}
		return keyLine
	}

	// Non-scoped: name@version
	if idx := strings.Index(keyLine, "@"); idx >= 0 {
		return keyLine[:idx]
	}

	return keyLine
}

// --- npm: pnpm-lock.yaml ---

// pnpmLock represents the structure of a pnpm-lock.yaml file (v6+).
// The "packages" key maps import paths to package metadata.
type pnpmLock struct {
	LockfileVersion int `yaml:"lockfileVersion"`
	Packages        map[string]struct {
		Version      string            `yaml:"version"`
		Resolved     string            `yaml:"resolved"`
		Dev          bool              `yaml:"dev"`
		Optional     bool              `yaml:"optional"`
		Dependencies map[string]string `yaml:"dependencies"`
	} `yaml:"packages"`
	// v5 and earlier use "dependencies" instead of "packages"
	Dependencies map[string]struct {
		Version      string            `yaml:"version"`
		Resolved     string            `yaml:"resolved"`
		Dev          bool              `yaml:"dev"`
		Dependencies map[string]string `yaml:"dependencies"`
	} `yaml:"dependencies"`
}

// ParsePnpmLock parses a pnpm-lock.yaml file and extracts ALL dependencies
// (direct + transitive) with their resolved versions.
// pnpm-lock.yaml uses a nested structure where the "packages" key maps
// import paths (like "/abbrev/1.1.1") to package metadata.
func ParsePnpmLock(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	var lock pnpmLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid pnpm-lock.yaml: %w", err)
	}

	var deps []analysis.Dependency
	seen := make(map[string]bool)

	// v6+ format: "packages" map with import paths
	for pkgPath, info := range lock.Packages {
		if info.Version == "" {
			continue
		}

		// Extract package name from the import path.
		// Paths are like "/abbrev/1.1.1" or "/@scope/pkg/1.2.3"
		name := extractPnpmPkgName(pkgPath)
		if name == "" {
			continue
		}

		key := name + "@" + info.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		// In pnpm-lock.yaml, direct deps are at the top level of
		// the "dependencies" or "devDependencies" in package.json.
		// The lockfile itself doesn't clearly mark direct vs transitive,
		// so we mark all as direct (dedup with package.json handles overlap).
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   info.Version,
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true,
			IsDev:     info.Dev,
		})
	}

	// v5 and earlier: "dependencies" map (flat)
	for name, info := range lock.Dependencies {
		if info.Version == "" {
			continue
		}
		key := name + "@" + info.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   info.Version,
			Ecosystem: analysis.EcosystemNPM,
			IsDirect:  true,
			IsDev:     info.Dev,
		})
	}

	return deps, nil
}

// extractPnpmPkgName extracts the package name from a pnpm-lock.yaml import path.
// Paths are like "/abbrev/1.1.1" or "/@scope/pkg/1.2.3" or
// "/@scope/pkg/1.2.3/peer_id@2.0.0"
func extractPnpmPkgName(path string) string {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// Handle scoped packages: @scope/pkg/version
	if strings.HasPrefix(path, "@") {
		// Find the second slash (after @scope/pkg)
		slashIdx := strings.Index(path, "/")
		if slashIdx < 0 {
			return path
		}
		secondSlash := strings.Index(path[slashIdx+1:], "/")
		if secondSlash < 0 {
			return path
		}
		return path[:slashIdx+1+secondSlash]
	}

	// Non-scoped: name/version
	slashIdx := strings.Index(path, "/")
	if slashIdx < 0 {
		return path
	}
	return path[:slashIdx]
}

// --- npm: pnpm-workspace.yaml ---

// pnpmWorkspace represents the structure of pnpm-workspace.yaml.
type pnpmWorkspace struct {
	Packages []string `yaml:"packages"`
}

// ParsePnpmWorkspace parses a pnpm-workspace.yaml file. Like go.work, it
// lists workspace member packages via glob patterns. ParsePnpmWorkspace
// resolves each matching package's package.json and aggregates dependencies,
// deduplicating by name@version.
func ParsePnpmWorkspace(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	var ws pnpmWorkspace
	if err := yaml.Unmarshal(data, &ws); err != nil {
		return nil, fmt.Errorf("invalid pnpm-workspace.yaml: %w", err)
	}

	workDir := filepath.Dir(path)
	return resolveNpmWorkspacePackages(workDir, ws.Packages)
}

// resolveNpmWorkspacePackages resolves workspace glob patterns (e.g.
// "packages/*", "apps/*") relative to workDir, parses each matching
// package.json, and returns deduplicated dependencies.
func resolveNpmWorkspacePackages(workDir string, patterns []string) ([]analysis.Dependency, error) {
	var allDeps []analysis.Dependency
	seen := make(map[string]bool) // dedupe by name@version

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		matches, err := filepath.Glob(filepath.Join(workDir, pattern))
		if err != nil {
			continue
		}

		for _, match := range matches {
			pkgJSONPath := filepath.Join(match, "package.json")
			if _, err := os.Stat(pkgJSONPath); err != nil {
				continue
			}

			pkgDeps, err := ParsePackageJSON(pkgJSONPath)
			if err != nil {
				continue
			}

			relPath, err := filepath.Rel(workDir, pkgJSONPath)
			if err != nil {
				relPath = pkgJSONPath
			}

			for _, dep := range pkgDeps {
				// Skip root package self-references in workspace aggregation
				if dep.IsRoot {
					continue
				}
				key := dep.Name + "@" + dep.Version
				if seen[key] {
					continue
				}
				seen[key] = true
				dep.ManifestPath = relPath
				allDeps = append(allDeps, dep)
			}
		}
	}

	return allDeps, nil
}

// --- Python: requirements.txt ---

var requirementsRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_.-]+\])?)\s*([=<>!~]=|=|<|>|~=)?\s*([0-9A-Za-z.*+!-]*)`)

// ParseRequirementsTxt parses a requirements.txt file.
func ParseRequirementsTxt(path string) ([]analysis.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []analysis.Dependency
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Strip environment markers
		if idx := strings.Index(line, ";"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		m := requirementsRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.ToLower(m[1])
		// Strip extras: package[extra] -> package
		if idx := strings.Index(name, "["); idx > 0 {
			name = name[:idx]
		}
		version := m[3]
		if version == "" || version == "*" {
			version = ""
		}

		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
		})
	}

	return deps, scanner.Err()
}

// --- Python: pyproject.toml ---

var tomlDependencyRe = regexp.MustCompile(`^"?([A-Za-z0-9_.-]+)"?\s*=\s*"?(.+?)"?\s*$`)
var tomlArrayDepRe = regexp.MustCompile(`^"?([A-Za-z0-9_.-]+)"?\s*=\s*\[`)
var tomlKeyValueRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*=\s*"?(.+?)"?\s*$`)

// ParsePyProjectToml parses a pyproject.toml file for [project.dependencies] and
// [tool.poetry.dependencies] sections. Also extracts the root package from
// [project] name/version or [tool.poetry] name/version.
func ParsePyProjectToml(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	var deps []analysis.Dependency
	lines := strings.Split(string(data), "\n")

	section := ""
	inArray := false
	rootName := ""
	rootVersion := ""
	rootLicense := ""

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			inArray = false
			continue
		}

		// Extract root package name/version from [project] or [tool.poetry]
		if section == "[project]" || section == "[tool.poetry]" {
			if strings.HasPrefix(line, "name") {
				m := tomlKeyValueRe.FindStringSubmatch(line)
				if m != nil {
					rootName = strings.Trim(m[2], `"'`)
				}
			}
			if strings.HasPrefix(line, "version") {
				m := tomlKeyValueRe.FindStringSubmatch(line)
				if m != nil {
					rootVersion = strings.Trim(m[2], `"'`)
				}
			}
			if strings.HasPrefix(line, "license") {
				m := tomlKeyValueRe.FindStringSubmatch(line)
				if m != nil {
					licVal := strings.Trim(m[2], `"'`)
					// Handle inline table: license = {file = "LICENSE.rst"}
					// or license = {text = "MIT"}
					if strings.HasPrefix(licVal, "{") {
						// Extract text = "..." if present
						textRe := regexp.MustCompile(`text\s*=\s*"([^"]+)"`)
						if tm := textRe.FindStringSubmatch(licVal); tm != nil {
							rootLicense = tm[1]
						} else {
							// It's a file reference — we can't read it here
							rootLicense = ""
						}
					} else {
						rootLicense = licVal
					}
				}
			}
		}

		isDepSection := strings.Contains(section, "dependencies") ||
			section == "[project.dependencies]" ||
			section == "[tool.poetry.dependencies]" ||
			strings.HasPrefix(section, "[project.optional-dependencies")

		if !isDepSection {
			continue
		}

		// Skip python version constraint
		if strings.HasPrefix(line, "python") {
			continue
		}

		// Array-style: package = ["foo>=1.0", "bar>=2.0"]
		// Can be multi-line (starts with [ on its own line) or single-line
		// (e.g., test = ["pytest"] in [project.optional-dependencies])
		if tomlArrayDepRe.MatchString(line) {
			// Check if it's a single-line array: key = ["val1", "val2"]
			if strings.HasSuffix(line, "]") {
				// Single-line array — parse the contents directly
				// Extract the array content between [ and ]
				bracketStart := strings.Index(line, "[")
				bracketEnd := strings.LastIndex(line, "]")
				if bracketStart >= 0 && bracketEnd > bracketStart {
					arrayContent := line[bracketStart+1 : bracketEnd]
					// Parse each quoted element
					depMatches := setupPySingleDepRe.FindAllStringSubmatch(arrayContent, -1)
					for _, dm := range depMatches {
						spec := dm[1]
						dep := parsePythonVersionSpec(spec)
						if dep == nil {
							name := strings.ToLower(strings.TrimSpace(spec))
							if name != "" && name != "python" {
								deps = append(deps, analysis.Dependency{
									Name:      name,
									Version:   "",
									Ecosystem: analysis.EcosystemPyPI,
									IsDirect:  true,
								})
							}
						} else {
							deps = append(deps, *dep)
						}
					}
				}
				continue
			}
			// Multi-line array
			if strings.HasSuffix(line, "[") {
				inArray = true
				continue
			}
		}
		if inArray {
			if strings.HasPrefix(line, "]") {
				inArray = false
				continue
			}
			// Parse array element: "foo>=1.0"
			elem := strings.Trim(line, `",`)
			elem = strings.TrimSpace(elem)
			if dep := parsePythonVersionSpec(elem); dep != nil {
				deps = append(deps, *dep)
			}
			continue
		}

		// Key-value: package = ">=1.0.0" or package = "1.2.3"
		m := tomlDependencyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.ToLower(m[1])
		val := m[2]

		// Skip non-dependency keys
		if name == "python" || name == "build-backend" || name == "requires" {
			continue
		}

		// In [project.optional-dependencies], the key is an extras group name
		// (e.g., "test", "dev", "docs"), NOT a package name. Skip the key
		// and only parse the array values (handled above for single-line arrays).
		if strings.HasPrefix(section, "[project.optional-dependencies") {
			// The key is an extras group — skip it as a dependency name.
			// The actual packages are in the array value, handled above.
			continue
		}

		dep := parsePythonVersionSpec(name + val)
		if dep == nil {
			dep = &analysis.Dependency{
				Name:      name,
				Version:   cleanPythonVersion(val),
				Ecosystem: analysis.EcosystemPyPI,
				IsDirect:  true,
			}
		}
		deps = append(deps, *dep)
	}

	// Add root package if we found name and version
	if rootName != "" && rootVersion != "" {
		deps = append(deps, analysis.Dependency{
			Name:      strings.ToLower(rootName),
			Version:   cleanPythonVersion(rootVersion),
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
			IsRoot:    true,
			License:   rootLicense,
		})
	}

	return deps, nil
}

// --- Python: setup.py ---

// setupPyInstallRequiresRe matches install_requires = ["pkg>=1.0", ...]
var setupPyInstallRequiresRe = regexp.MustCompile(`(?:install_requires|requires)\s*=\s*\[(.*?)\]`)
var setupPySingleDepRe = regexp.MustCompile(`["']([^"']+)["']`)
var setupPyNameRe = regexp.MustCompile(`setup\s*\([^)]*name\s*=\s*['"]([^'"]+)['"]`)
var setupPyVersionRe = regexp.MustCompile(`setup\s*\([^)]*version\s*=\s*['"]([^'"]+)['"]`)
var initVersionRe = regexp.MustCompile(`__version__\s*=\s*['"]([^'"]+)['"]`)

// ParseSetupPy parses a setup.py file for install_requires and the root package.
// Since setup.py is Python code, we use regex to extract the install_requires list.
// The root package name is extracted from setup(name=...). The version is extracted
// from setup(version=...) or, if it's a variable, from __init__.py in the same dir.
func ParseSetupPy(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	src := string(data)
	var deps []analysis.Dependency

	// Extract root package name and version
	if m := setupPyNameRe.FindStringSubmatch(src); m != nil {
		pkgName := strings.ToLower(strings.TrimSpace(m[1]))
		pkgVersion := ""

		// Try to get version from setup(version='...')
		if vm := setupPyVersionRe.FindStringSubmatch(src); vm != nil {
			pkgVersion = vm[1]
		}

		// If version is not a literal, try __init__.py
		if pkgVersion == "" {
			dir := filepath.Dir(path)
			pkgVersion = findVersionInInitFiles(dir, pkgName)
		}

		if pkgVersion != "" {
			deps = append(deps, analysis.Dependency{
				Name:      pkgName,
				Version:   pkgVersion,
				Ecosystem: analysis.EcosystemPyPI,
				IsDirect:  true,
				IsRoot:    true,
			})
		}
	}

	// Extract install_requires = [...] blocks
	matches := setupPyInstallRequiresRe.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		listContent := m[1]
		// Parse each "pkg>=1.0" entry
		depMatches := setupPySingleDepRe.FindAllStringSubmatch(listContent, -1)
		for _, dm := range depMatches {
			spec := dm[1]
			dep := parsePythonVersionSpec(spec)
			if dep == nil {
				// No version constraint — just the package name
				name := strings.TrimSpace(spec)
				name = strings.ToLower(name)
				if name != "" && name != "python" {
					deps = append(deps, analysis.Dependency{
						Name:      name,
						Version:   "",
						Ecosystem: analysis.EcosystemPyPI,
						IsDirect:  true,
					})
				}
			} else {
				deps = append(deps, *dep)
			}
		}
	}

	return deps, nil
}

// findVersionInInitFiles searches for __version__ = 'x.y.z' in __init__.py
// files near the setup.py. It checks src/<pkg>/__init__.py and <pkg>/__init__.py.
func findVersionInInitFiles(dir, pkgName string) string {
	candidates := []string{
		filepath.Join(dir, "src", pkgName, "__init__.py"),
		filepath.Join(dir, pkgName, "__init__.py"),
		filepath.Join(dir, "src", "__init__.py"),
	}
	for _, c := range candidates {
		data, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		if m := initVersionRe.FindStringSubmatch(string(data)); m != nil {
			return m[1]
		}
	}
	return ""
}

// --- Python: setup.cfg ---

var setupCfgInstallRequiresRe = regexp.MustCompile(`(?m)^install_requires\s*=\s*(.*)$`)
var setupCfgOptionsRe = regexp.MustCompile(`(?m)^\[options\]`)

// ParseSetupCfg parses a setup.cfg file for install_requires.
func ParseSetupCfg(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	src := string(data)
	var deps []analysis.Dependency

	// Find [options] section
	optionsIdx := setupCfgOptionsRe.FindStringIndex(src)
	if optionsIdx == nil {
		return deps, nil
	}

	// Get the section content (from [options] to the next [section] or EOF)
	sectionStart := optionsIdx[1]
	nextSection := strings.Index(src[sectionStart:], "\n[")
	var section string
	if nextSection > 0 {
		section = src[sectionStart : sectionStart+nextSection]
	} else {
		section = src[sectionStart:]
	}

	// Parse install_requires (can span multiple lines with continuation)
	lines := strings.Split(section, "\n")
	var installRequires string
	inInstallRequires := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "install_requires") {
			// Could be inline or start of multi-line
			idx := strings.Index(trimmed, "=")
			if idx > 0 {
				val := strings.TrimSpace(trimmed[idx+1:])
				if val != "" {
					installRequires = val
				}
				inInstallRequires = val == "" || strings.HasSuffix(val, "\\")
			}
			continue
		}
		if inInstallRequires {
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			installRequires += " " + trimmed
			if !strings.HasSuffix(trimmed, "\\") {
				inInstallRequires = false
			}
		}
	}

	if installRequires != "" {
		// Parse space or newline separated requirements
		for _, spec := range strings.Fields(installRequires) {
			spec = strings.Trim(spec, ",\\")
			dep := parsePythonVersionSpec(spec)
			if dep == nil {
				name := strings.ToLower(strings.TrimSpace(spec))
				if name != "" && name != "python" {
					deps = append(deps, analysis.Dependency{
						Name:      name,
						Version:   "",
						Ecosystem: analysis.EcosystemPyPI,
						IsDirect:  true,
					})
				}
			} else {
				deps = append(deps, *dep)
			}
		}
	}

	return deps, nil
}

// --- Python: Pipfile.lock ---

// pipfileLockJSON represents the relevant parts of a Pipfile.lock.
type pipfileLockJSON struct {
	Default map[string]struct {
		Version string `json:"version"`
	} `json:"default"`
	Develop map[string]struct {
		Version string `json:"version"`
	} `json:"develop"`
}

// ParsePipfileLock parses a Pipfile.lock file (JSON format).
func ParsePipfileLock(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	var lock pipfileLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid Pipfile.lock: %w", err)
	}

	var deps []analysis.Dependency
	for name, info := range lock.Default {
		deps = append(deps, analysis.Dependency{
			Name:      strings.ToLower(name),
			Version:   cleanPythonVersion(info.Version),
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
			IsDev:     false,
		})
	}
	for name, info := range lock.Develop {
		deps = append(deps, analysis.Dependency{
			Name:      strings.ToLower(name),
			Version:   cleanPythonVersion(info.Version),
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
			IsDev:     true,
		})
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// --- Python: poetry.lock ---

// poetryLockJSON represents the relevant parts of a poetry.lock file.
type poetryLockJSON struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
}

// ParsePoetryLock parses a poetry.lock file (TOML/JSON format).
// poetry.lock v1 is TOML, but we try JSON first (poetry.lock v2).
func ParsePoetryLock(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	// Try JSON first (some tools output JSON locks)
	var lock poetryLockJSON
	if err := json.Unmarshal(data, &lock); err == nil && len(lock.Packages) > 0 {
		var deps []analysis.Dependency
		for _, pkg := range lock.Packages {
			deps = append(deps, analysis.Dependency{
				Name:      strings.ToLower(pkg.Name),
				Version:   cleanPythonVersion(pkg.Version),
				Ecosystem: analysis.EcosystemPyPI,
				IsDirect:  true,
			})
		}
		sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
		return deps, nil
	}

	// Fall back to TOML regex parsing for [[package]] sections
	src := string(data)
	var deps []analysis.Dependency
	inPackage := false
	var name, version string

	pkgNameRe := regexp.MustCompile(`^name\s*=\s*"(.+)"`)
	pkgVerRe := regexp.MustCompile(`^version\s*=\s*"(.+)"`)

	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[[package]]" {
			if name != "" && version != "" {
				deps = append(deps, analysis.Dependency{
					Name:      strings.ToLower(name),
					Version:   cleanPythonVersion(version),
					Ecosystem: analysis.EcosystemPyPI,
					IsDirect:  true,
				})
			}
			name = ""
			version = ""
			inPackage = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") && trimmed != "[[package]]" {
			inPackage = false
			continue
		}
		if !inPackage {
			continue
		}
		if m := pkgNameRe.FindStringSubmatch(trimmed); m != nil {
			name = m[1]
		}
		if m := pkgVerRe.FindStringSubmatch(trimmed); m != nil {
			version = m[1]
		}
	}
	// Don't forget the last package
	if name != "" && version != "" {
		deps = append(deps, analysis.Dependency{
			Name:      strings.ToLower(name),
			Version:   cleanPythonVersion(version),
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
		})
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// --- Python: uv.lock ---

// ParseUvLock parses a uv.lock file (TOML format used by the uv package manager).
// uv.lock uses [[package]] sections with name and version fields, similar to
// poetry.lock but with a slightly different structure. Some packages may have
// source = { virtual = "..." } for local workspace packages — these are skipped
// as they are internal workspace members, not PyPI dependencies.
func ParseUvLock(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}
	src := string(data)

	var deps []analysis.Dependency
	inPackage := false
	var name, version string
	hasVirtualSource := false

	pkgNameRe := regexp.MustCompile(`^name\s*=\s*"(.+)"`)
	pkgVerRe := regexp.MustCompile(`^version\s*=\s*"(.+)"`)

	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)

		if trimmed == "[[package]]" {
			// Flush previous package
			if name != "" && version != "" && !hasVirtualSource {
				deps = append(deps, analysis.Dependency{
					Name:      strings.ToLower(name),
					Version:   cleanPythonVersion(version),
					Ecosystem: analysis.EcosystemPyPI,
					IsDirect:  true,
				})
			}
			name = ""
			version = ""
			hasVirtualSource = false
			inPackage = true
			continue
		}

		// Check for section change
		if strings.HasPrefix(trimmed, "[") && trimmed != "[[package]]" {
			// Flush previous package on section change
			if inPackage && name != "" && version != "" && !hasVirtualSource {
				deps = append(deps, analysis.Dependency{
					Name:      strings.ToLower(name),
					Version:   cleanPythonVersion(version),
					Ecosystem: analysis.EcosystemPyPI,
					IsDirect:  true,
				})
			}
			inPackage = false
			name = ""
			version = ""
			hasVirtualSource = false
			continue
		}

		if !inPackage {
			continue
		}

		if m := pkgNameRe.FindStringSubmatch(trimmed); m != nil {
			name = m[1]
		}
		if m := pkgVerRe.FindStringSubmatch(trimmed); m != nil {
			version = m[1]
		}
		// Detect virtual/workspace packages: source = { virtual = "..." }
		if strings.Contains(trimmed, "virtual") && strings.Contains(trimmed, "source") {
			hasVirtualSource = true
		}
	}

	// Don't forget the last package
	if inPackage && name != "" && version != "" && !hasVirtualSource {
		deps = append(deps, analysis.Dependency{
			Name:      strings.ToLower(name),
			Version:   cleanPythonVersion(version),
			Ecosystem: analysis.EcosystemPyPI,
			IsDirect:  true,
		})
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// parsePythonVersionSpec parses a spec like "foo>=1.0.0" or "foo==1.2.3" into a Dependency.
func parsePythonVersionSpec(spec string) *analysis.Dependency {
	spec = strings.TrimSpace(spec)
	re := regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*[=<>!~]+\s*([0-9A-Za-z.*+!-]+)`)
	m := re.FindStringSubmatch(spec)
	if m == nil {
		return nil
	}
	return &analysis.Dependency{
		Name:      strings.ToLower(m[1]),
		Version:   m[2],
		Ecosystem: analysis.EcosystemPyPI,
		IsDirect:  true,
	}
}

func cleanPythonVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "=<>!~ ")
	v = strings.TrimPrefix(v, "v")
	if v == "*" || v == "" {
		return ""
	}
	return v
}

// --- Rust: Cargo.toml ---

var cargoDepRe = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*"(.+?)"`)

// ParseCargoToml parses a Cargo.toml file for [dependencies] and [dev-dependencies].
// Also extracts the root package from [package] name/version.
func ParseCargoToml(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	var deps []analysis.Dependency
	lines := strings.Split(string(data), "\n")
	section := ""
	rootName := ""
	rootVersion := ""
	rootLicense := ""

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}

		// Extract root package from [package] section
		if section == "[package]" {
			if strings.HasPrefix(line, "name") {
				m := tomlKeyValueRe.FindStringSubmatch(line)
				if m != nil {
					rootName = strings.Trim(m[2], `"'`)
				}
			}
			if strings.HasPrefix(line, "version") {
				m := tomlKeyValueRe.FindStringSubmatch(line)
				if m != nil {
					rootVersion = strings.Trim(m[2], `"'`)
				}
			}
			if strings.HasPrefix(line, "license") {
				m := tomlKeyValueRe.FindStringSubmatch(line)
				if m != nil {
					rootLicense = strings.Trim(m[2], `"'`)
				}
			}
		}

		isDep := section == "[dependencies]" || section == "[dev-dependencies]"
		if !isDep {
			continue
		}

		m := cargoDepRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ver := m[2]
		// Skip git/path/version specs that aren't semver
		if strings.HasPrefix(ver, "git") || strings.HasPrefix(ver, "path") {
			continue
		}
		deps = append(deps, analysis.Dependency{
			Name:      m[1],
			Version:   strings.TrimPrefix(ver, "v"),
			Ecosystem: analysis.EcosystemCargo,
			IsDirect:  true,
			IsDev:     section == "[dev-dependencies]",
		})
	}

	// Add root package
	if rootName != "" && rootVersion != "" {
		deps = append(deps, analysis.Dependency{
			Name:      rootName,
			Version:   rootVersion,
			Ecosystem: analysis.EcosystemCargo,
			IsDirect:  true,
			IsRoot:    true,
			License:   rootLicense,
		})
	}

	return deps, nil
}

// --- Ruby: Gemfile ---

var gemfileRe = regexp.MustCompile(`^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?`)

// ParseGemfile parses a Ruby Gemfile.
func ParseGemfile(path string) ([]analysis.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []analysis.Dependency
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "gem ") {
			continue
		}
		// gem "foo", "~> 1.0"
		// gem 'foo', '~> 1.0'
		// Use regex to properly extract name and version from quoted strings
		m := gemfileRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		version := ""
		if len(m) > 2 && m[2] != "" {
			version = strings.Trim(m[2], `~>=< `)
		}
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: analysis.EcosystemRubyGems,
			IsDirect:  true,
		})
	}

	return deps, scanner.Err()
}

// ParseGemfileLock parses a Gemfile.lock for GEM specs.
func ParseGemfileLock(path string) ([]analysis.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []analysis.Dependency
	scanner := bufio.NewScanner(f)
	inSpecs := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "specs:") {
			inSpecs = true
			continue
		}
		if inSpecs && !strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "\t") {
			inSpecs = false
			continue
		}
		if !inSpecs {
			continue
		}

		// "    foo (1.2.3)"
		re := regexp.MustCompile(`^\s+([A-Za-z0-9_.-]+)\s+\(([^)]+)\)`)
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		deps = append(deps, analysis.Dependency{
			Name:      m[1],
			Version:   m[2],
			Ecosystem: analysis.EcosystemRubyGems,
			IsDirect:  false,
		})
	}

	return deps, scanner.Err()
}

// --- PHP: composer.json ---

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// ParseComposerJSON parses a composer.json file.
func ParseComposerJSON(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	var c composerJSON
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("invalid composer.json: %w", err)
	}

	var deps []analysis.Dependency
	for name, version := range c.Require {
		if name == "php" || strings.HasPrefix(name, "ext-") {
			continue
		}
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   strings.TrimLeft(version, "^~>=< "),
			Ecosystem: analysis.EcosystemPackagist,
			IsDirect:  true,
		})
	}
	for name, version := range c.RequireDev {
		if name == "php" || strings.HasPrefix(name, "ext-") {
			continue
		}
		deps = append(deps, analysis.Dependency{
			Name:      name,
			Version:   strings.TrimLeft(version, "^~>=< "),
			Ecosystem: analysis.EcosystemPackagist,
			IsDirect:  true,
			IsDev:     true,
		})
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// --- Java: pom.xml ---

var pomDependencyRe = regexp.MustCompile(`<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?`)
var pomPropertyRe = regexp.MustCompile(`<([a-zA-Z0-9_.-]+)>([^<]+)</([a-zA-Z0-9_.-]+)>`)
var pomProjectVersionRe = regexp.MustCompile(`<project[^>]*>[\s\S]*?<version>([^<]+)</version>`)
var pomPropertyRefRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// pomContext holds parsed properties and dependencyManagement from a pom.xml
// for resolving property references and inherited versions.
type pomContext struct {
	properties      map[string]string
	managedVersions map[string]string // groupId:artifactId -> version
	projectVersion  string
}

// parsePomProperties extracts <properties> from a pom.xml.
// Finds the project-level <properties> block (indented with 2 spaces, not
// inside a <developer> or <contributor> subsection).
func parsePomProperties(src string) map[string]string {
	props := make(map[string]string)
	// Find all <properties> blocks and pick the one with the most entries
	// (the project-level properties block typically has 20+ entries, while
	// developer/contributor properties have 1-2).
	var bestBlock string
	var bestCount int
	remaining := src
	for {
		idx := strings.Index(remaining, "<properties>")
		if idx < 0 {
			break
		}
		end := strings.Index(remaining[idx:], "</properties>")
		if end < 0 {
			break
		}
		block := remaining[idx : idx+end]
		matches := pomPropertyRe.FindAllStringSubmatch(block, -1)
		count := 0
		for _, m := range matches {
			if m[1] == m[3] {
				count++
			}
		}
		if count > bestCount {
			bestCount = count
			bestBlock = block
		}
		remaining = remaining[idx+end:]
	}
	if bestBlock == "" {
		return props
	}
	matches := pomPropertyRe.FindAllStringSubmatch(bestBlock, -1)
	for _, m := range matches {
		if m[1] == m[3] {
			props[m[1]] = m[2]
		}
	}
	return props
}

// parsePomProjectVersion extracts the project's own version.
func parsePomProjectVersion(src string) string {
	m := pomProjectVersionRe.FindStringSubmatch(src)
	if m != nil {
		return m[1]
	}
	return ""
}

// pomLicenseRe matches <licenses><license><name>...</name></license></licenses>
var pomLicenseRe = regexp.MustCompile(`<licenses>\s*<license>\s*<name>([^<]+)</name>`)

// parsePomLicense extracts the first license name from a pom.xml.
func parsePomLicense(src string) string {
	m := pomLicenseRe.FindStringSubmatch(src)
	if m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// parsePomDependencyManagement extracts managed versions from
// <dependencyManagement><dependencies> sections.
func parsePomDependencyManagement(src string) map[string]string {
	managed := make(map[string]string)
	idx := strings.Index(src, "<dependencyManagement>")
	if idx < 0 {
		return managed
	}
	end := strings.Index(src[idx:], "</dependencyManagement>")
	if end < 0 {
		return managed
	}
	block := src[idx : idx+end]
	matches := pomDependencyRe.FindAllStringSubmatch(block, -1)
	for _, m := range matches {
		groupID := m[1]
		artifactID := m[2]
		version := m[3]
		if version != "" {
			managed[groupID+":"+artifactID] = version
		}
	}
	return managed
}

// resolveProperty resolves a ${propertyName} reference against the pom context.
// Supports ${project.version}, ${project.parent.version}, and custom properties.
// Handles nested references and unknown refs (returns as-is).
func (ctx *pomContext) resolveProperty(value string) string {
	if !strings.Contains(value, "${") {
		return value
	}
	result := pomPropertyRefRe.ReplaceAllStringFunc(value, func(ref string) string {
		name := ref[2 : len(ref)-1]
		switch name {
		case "project.version":
			return ctx.projectVersion
		case "project.parent.version":
			return ctx.projectVersion
		}
		if val, ok := ctx.properties[name]; ok {
			return ctx.resolveProperty(val)
		}
		return ref
	})
	return result
}

// ParsePomXML parses a Maven pom.xml file for dependencies with property interpolation.
// It extracts <properties>, <dependencyManagement>, and the project version,
// then resolves ${...} references in dependency versions.
func ParsePomXML(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}
	src := string(data)

	ctx := &pomContext{
		properties:      parsePomProperties(src),
		managedVersions: parsePomDependencyManagement(src),
		projectVersion:  parsePomProjectVersion(src),
	}

	var deps []analysis.Dependency
	seen := make(map[string]bool)
	matches := pomDependencyRe.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		groupID := m[1]
		artifactID := m[2]
		version := m[3]

		// If no version in the dependency, try dependencyManagement
		if version == "" {
			if v, ok := ctx.managedVersions[groupID+":"+artifactID]; ok {
				version = v
			}
		}

		// Resolve property references
		version = ctx.resolveProperty(version)

		// Skip if version is still empty or contains unresolved ${...}
		if version == "" {
			version = "unknown"
		}
		if strings.Contains(version, "${") {
			version = "unknown"
		}

		key := groupID + ":" + artifactID + ":" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, analysis.Dependency{
			Name:      groupID + ":" + artifactID,
			Version:   version,
			Ecosystem: analysis.EcosystemMaven,
			IsDirect:  true,
		})
	}

	return deps, nil
}

// --- Java: Maven multi-module ---

var pomModulesRe = regexp.MustCompile(`<modules>([\s\S]*?)</modules>`)
var pomModuleRe = regexp.MustCompile(`<module>([^<]+)</module>`)
var pomParentRe = regexp.MustCompile(`<parent>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>\s*(?:<relativePath>([^<]+)</relativePath>)?\s*</parent>`)

// parsePomModules extracts <module> entries from a parent POM's <modules> section.
// Returns relative directory paths to each sub-module.
func parsePomModules(src string) []string {
	m := pomModulesRe.FindStringSubmatch(src)
	if m == nil {
		return nil
	}
	moduleMatches := pomModuleRe.FindAllStringSubmatch(m[1], -1)
	var modules []string
	for _, mm := range moduleMatches {
		modules = append(modules, strings.TrimSpace(mm[1]))
	}
	return modules
}

// parsePomParent extracts parent POM coordinates and relativePath from a pom.xml.
// Returns (groupId, artifactId, version, relativePath, ok).
func parsePomParent(src string) (string, string, string, string, bool) {
	m := pomParentRe.FindStringSubmatch(src)
	if m == nil {
		return "", "", "", "", false
	}
	relativePath := m[4]
	if relativePath == "" {
		relativePath = "../pom.xml" // Maven default
	}
	return m[1], m[2], m[3], relativePath, true
}

// validatePomRelativePath validates that a parent POM relativePath is safe.
// It rejects absolute paths, paths with .. components that escape the project
// root, and paths that don't end with pom.xml. This prevents path traversal
// attacks via malicious <relativePath> values in pom.xml files.
func validatePomRelativePath(pomDir, relPath string) (string, bool) {
	// Reject empty paths
	relPath = strings.TrimSpace(relPath)
	if relPath == "" {
		return "", false
	}

	// Reject absolute paths in both slash conventions, independent of the
	// host OS. A POM authored on Unix must remain unsafe when scanned on
	// Windows, and vice versa.
	portablePath := strings.ReplaceAll(relPath, "\\", "/")
	isWindowsVolumePath := len(portablePath) >= 3 &&
		((portablePath[0] >= 'A' && portablePath[0] <= 'Z') ||
			(portablePath[0] >= 'a' && portablePath[0] <= 'z')) &&
		portablePath[1] == ':' && portablePath[2] == '/'
	if filepath.IsAbs(relPath) || pathpkg.IsAbs(portablePath) ||
		isWindowsVolumePath || strings.HasPrefix(portablePath, "//") {
		return "", false
	}

	// Clean the path and resolve relative to the POM directory
	cleanRel := filepath.Clean(relPath)
	resolved := filepath.Join(pomDir, cleanRel)
	resolved = filepath.Clean(resolved)

	// Ensure the resolved path stays within the project root (pomDir's parent)
	// Parent POMs should be at most one level up (../pom.xml)
	projectRoot := filepath.Clean(filepath.Dir(pomDir))
	if !strings.HasPrefix(resolved+string(filepath.Separator), projectRoot+string(filepath.Separator)) && resolved != projectRoot {
		return "", false
	}

	// Must end with pom.xml
	if !strings.HasSuffix(resolved, "pom.xml") {
		return "", false
	}

	return resolved, true
}

// loadParentPomContext loads properties and dependencyManagement from a parent
// POM (following relativePath from the child pom.xml directory). This enables
// property interpolation and managed version resolution in child modules.
func loadParentPomContext(pomPath string) *pomContext {
	data, err := readFileWithLimit(pomPath)
	if err != nil {
		return nil
	}
	src := string(data)

	parentGAV, parentArtifact, parentVersion, relPath, hasParent := parsePomParent(src)
	_ = parentGAV
	_ = parentArtifact
	_ = parentVersion

	ctx := &pomContext{
		properties:      parsePomProperties(src),
		managedVersions: parsePomDependencyManagement(src),
		projectVersion:  parsePomProjectVersion(src),
	}

	// Recursively load grandparent POM if this POM also has a parent.
	if hasParent {
		pomDir := filepath.Dir(pomPath)
		parentPath, ok := validatePomRelativePath(pomDir, relPath)
		if !ok {
			return ctx
		}
		if _, err := os.Stat(parentPath); err == nil {
			parentCtx := loadParentPomContext(parentPath)
			if parentCtx != nil {
				// Merge: parent properties are inherited unless overridden
				for k, v := range parentCtx.properties {
					if _, exists := ctx.properties[k]; !exists {
						ctx.properties[k] = v
					}
				}
				// Merge: parent managed versions are inherited unless overridden
				for k, v := range parentCtx.managedVersions {
					if _, exists := ctx.managedVersions[k]; !exists {
						ctx.managedVersions[k] = v
					}
				}
			}
		}
	}

	return ctx
}

// ParsePomXMLWithParent parses a Maven pom.xml with parent POM inheritance.
// It loads the parent POM (if any) and merges its properties and
// dependencyManagement into the child's context for proper version resolution.
func ParsePomXMLWithParent(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}
	src := string(data)

	// Start with parent context (if any), then overlay this POM's context.
	ctx := &pomContext{
		properties:      make(map[string]string),
		managedVersions: make(map[string]string),
	}

	// Load parent POM context for inheritance
	_, _, _, relPath, hasParent := parsePomParent(src)
	if hasParent {
		pomDir := filepath.Dir(path)
		parentPath, ok := validatePomRelativePath(pomDir, relPath)
		if ok {
			if _, err := os.Stat(parentPath); err == nil {
				parentCtx := loadParentPomContext(parentPath)
				if parentCtx != nil {
					for k, v := range parentCtx.properties {
						ctx.properties[k] = v
					}
					for k, v := range parentCtx.managedVersions {
						ctx.managedVersions[k] = v
					}
					ctx.projectVersion = parentCtx.projectVersion
				}
			}
		}
	}

	// Overlay this POM's own properties and managed versions (override parent)
	for k, v := range parsePomProperties(src) {
		ctx.properties[k] = v
	}
	for k, v := range parsePomDependencyManagement(src) {
		ctx.managedVersions[k] = v
	}
	// Override project version with this POM's own version if present
	if v := parsePomProjectVersion(src); v != "" {
		ctx.projectVersion = v
	}

	var deps []analysis.Dependency
	seen := make(map[string]bool)
	matches := pomDependencyRe.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		groupID := m[1]
		artifactID := m[2]
		version := m[3]

		// If no version in the dependency, try dependencyManagement
		if version == "" {
			if v, ok := ctx.managedVersions[groupID+":"+artifactID]; ok {
				version = v
			}
		}

		// Resolve property references
		version = ctx.resolveProperty(version)

		// Skip if version is still empty or contains unresolved ${...}
		if version == "" {
			version = "unknown"
		}
		if strings.Contains(version, "${") {
			version = "unknown"
		}

		key := groupID + ":" + artifactID + ":" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, analysis.Dependency{
			Name:      groupID + ":" + artifactID,
			Version:   version,
			Ecosystem: analysis.EcosystemMaven,
			IsDirect:  true,
		})
	}

	return deps, nil
}

// --- Java: build.gradle (basic) ---

var gradleDepRe = regexp.MustCompile(`(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly)\s+['"]([^:]+):([^:]+):([^'"]+)['"]`)
var gradleDepPlatformRe = regexp.MustCompile(`(?:implementation|api|compileOnly|runtimeOnly)\s+platform\(['"]([^:]+):([^:]+):([^'"]+)['"]\)`)
var gradleProjectDepRe = regexp.MustCompile(`(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+project\(['"]:([^'"]+)['"]\)`)

// ParseBuildGradle parses a Gradle build file for dependencies.
// It handles both string notation ('group:artifact:version') and
// platform() notation, and skips project() references (internal modules).
func ParseBuildGradle(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}
	src := string(data)

	var deps []analysis.Dependency
	seen := make(map[string]bool)

	// Standard dependency declarations
	matches := gradleDepRe.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		key := m[1] + ":" + m[2] + ":" + m[3]
		if seen[key] {
			continue
		}
		seen[key] = true
		deps = append(deps, analysis.Dependency{
			Name:      m[1] + ":" + m[2],
			Version:   m[3],
			Ecosystem: analysis.EcosystemMaven,
			IsDirect:  true,
		})
	}

	// Platform/BOM dependencies: implementation platform('group:artifact:version')
	platformMatches := gradleDepPlatformRe.FindAllStringSubmatch(src, -1)
	for _, m := range platformMatches {
		key := m[1] + ":" + m[2] + ":" + m[3]
		if seen[key] {
			continue
		}
		seen[key] = true
		deps = append(deps, analysis.Dependency{
			Name:      m[1] + ":" + m[2],
			Version:   m[3],
			Ecosystem: analysis.EcosystemMaven,
			IsDirect:  true,
		})
	}

	return deps, nil
}

// --- Java: settings.gradle (multi-project) ---

var gradleIncludeRe = regexp.MustCompile(`include\s*\(\s*['"]([^'"]+)['"]\s*\)|include\s+['"]([^'"]+)['"]`)

// ParseSettingsGradle parses a settings.gradle/settings.gradle.kts file.
// It extracts `include` directives to discover subprojects, then resolves
// each subproject's build.gradle/build.gradle.kts and aggregates dependencies,
// deduplicating by name@version.
func ParseSettingsGradle(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}
	src := string(data)

	// Extract included subprojects
	var subprojects []string
	matches := gradleIncludeRe.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if name != "" {
			subprojects = append(subprojects, name)
		}
	}

	if len(subprojects) == 0 {
		return nil, nil
	}

	// Resolve each subproject's build.gradle
	workDir := filepath.Dir(path)
	var allDeps []analysis.Dependency
	seen := make(map[string]bool)

	for _, sp := range subprojects {
		// Gradle subproject paths use ':' as separator; convert to filepath
		spPath := strings.ReplaceAll(sp, ":", string(filepath.Separator))
		spDir := filepath.Join(workDir, spPath)

		// Try build.gradle and build.gradle.kts
		for _, buildFile := range []string{"build.gradle", "build.gradle.kts"} {
			buildPath := filepath.Join(spDir, buildFile)
			if _, err := os.Stat(buildPath); err != nil {
				continue
			}
			spDeps, err := ParseBuildGradle(buildPath)
			if err != nil {
				continue
			}
			relPath, err := filepath.Rel(workDir, buildPath)
			if err != nil {
				relPath = buildPath
			}
			for _, dep := range spDeps {
				key := dep.Name + "@" + dep.Version
				if seen[key] {
					continue
				}
				seen[key] = true
				dep.ManifestPath = relPath
				allDeps = append(allDeps, dep)
			}
			break // only one build file per subproject
		}
	}

	return allDeps, nil
}

// --- Helm: Chart.yaml ---

type helmChartYAML struct {
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
	AppVersion   string            `yaml:"appVersion"`
	Annotations  map[string]string `yaml:"annotations"`
	Dependencies []struct {
		Name       string `yaml:"name"`
		Version    string `yaml:"version"`
		Repository string `yaml:"repository"`
		Alias      string `yaml:"alias"`
	} `yaml:"dependencies"`
}

// ParseHelmChart parses Helm Chart.yaml files. Helm is not queried through OSV
// here, but representing charts as dependencies makes license coverage visible
// in reports and SBOM-style outputs.
func ParseHelmChart(path string) ([]analysis.Dependency, error) {
	data, err := readFileWithLimit(path)
	if err != nil {
		return nil, err
	}

	var chart helmChartYAML
	if err := yaml.Unmarshal(data, &chart); err != nil {
		return nil, err
	}

	rel := filepath.Base(path)
	license := helmChartLicense(chart.Annotations)
	deps := make([]analysis.Dependency, 0, 1+len(chart.Dependencies))
	if chart.Name != "" {
		version := chart.Version
		if version == "" {
			version = chart.AppVersion
		}
		deps = append(deps, analysis.Dependency{
			Name:         chart.Name,
			Version:      version,
			Ecosystem:    analysis.EcosystemHelm,
			ManifestPath: rel,
			IsDirect:     true,
			IsRoot:       true,
			License:      license,
		})
	}

	for _, dep := range chart.Dependencies {
		if dep.Name == "" {
			continue
		}
		deps = append(deps, analysis.Dependency{
			Name:         dep.Name,
			Version:      dep.Version,
			Ecosystem:    analysis.EcosystemHelm,
			ManifestPath: rel,
			IsDirect:     true,
			Repository:   dep.Repository,
		})
	}

	return deps, nil
}

func helmChartLicense(annotations map[string]string) string {
	if len(annotations) == 0 {
		return ""
	}
	for _, key := range []string{
		"artifacthub.io/license",
		"artifacthub.io/licenses",
		"license",
		"licenses",
	} {
		if value := strings.TrimSpace(annotations[key]); value != "" {
			return value
		}
	}
	return ""
}
