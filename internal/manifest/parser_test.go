package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("failed to create parent dir for %s: %v", name, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
	return path
}

func TestParseGoMod(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/test

go 1.21

require (
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.0.0 // indirect
)

require github.com/stretchr/testify v1.8.0
`
	path := writeTestFile(t, dir, "go.mod", content)

	deps, err := ParseGoMod(path)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}

	// Check cobra is direct
	foundCobra := false
	foundViper := false
	foundTestify := false
	for _, dep := range deps {
		switch dep.Name {
		case "github.com/spf13/cobra":
			foundCobra = true
			if !dep.IsDirect {
				t.Error("cobra should be direct")
			}
			if dep.Version != "v1.0.0" {
				t.Errorf("cobra version: got %s, want v1.0.0", dep.Version)
			}
		case "github.com/spf13/viper":
			foundViper = true
			if dep.IsDirect {
				t.Error("viper should be indirect")
			}
		case "github.com/stretchr/testify":
			foundTestify = true
			if !dep.IsDirect {
				t.Error("testify should be direct (single-line require)")
			}
		}
	}
	if !foundCobra || !foundViper || !foundTestify {
		t.Errorf("missing deps: cobra=%v viper=%v testify=%v", foundCobra, foundViper, foundTestify)
	}

	// Verify ecosystem
	for _, dep := range deps {
		if dep.Ecosystem != analysis.EcosystemGo {
			t.Errorf("expected Go ecosystem, got %s", dep.Ecosystem)
		}
	}
}

func TestParseGoWork(t *testing.T) {
	dir := t.TempDir()

	// Create two modules referenced by go.work
	apiDir := filepath.Join(dir, "services", "api")
	workerDir := filepath.Join(dir, "services", "worker")
	os.MkdirAll(apiDir, 0755)
	os.MkdirAll(workerDir, 0755)

	writeTestFile(t, apiDir, "go.mod", `module example.com/api

go 1.21

require (
	github.com/spf13/cobra v1.0.0
)
`)
	writeTestFile(t, workerDir, "go.mod", `module example.com/worker

go 1.21

require github.com/gin-gonic/gin v1.9.0
`)

	// go.work with block-style use directive
	workContent := `go 1.21

use (
	./services/api
	./services/worker
)
`
	workPath := writeTestFile(t, dir, "go.work", workContent)

	deps, err := ParseGoWork(workPath)
	if err != nil {
		t.Fatalf("ParseGoWork failed: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 deps (cobra + gin), got %d: %+v", len(deps), deps)
	}

	foundCobra := false
	foundGin := false
	for _, dep := range deps {
		switch dep.Name {
		case "github.com/spf13/cobra":
			foundCobra = true
			if dep.Version != "v1.0.0" {
				t.Errorf("cobra version: got %s, want v1.0.0", dep.Version)
			}
			if dep.ManifestPath != filepath.Join("services", "api", "go.mod") {
				t.Errorf("cobra manifest path: got %s, want services/api/go.mod", dep.ManifestPath)
			}
		case "github.com/gin-gonic/gin":
			foundGin = true
			if dep.Version != "v1.9.0" {
				t.Errorf("gin version: got %s, want v1.9.0", dep.Version)
			}
		}
	}
	if !foundCobra || !foundGin {
		t.Errorf("missing deps: cobra=%v gin=%v", foundCobra, foundGin)
	}
}

func TestParseGoWorkSingleLine(t *testing.T) {
	dir := t.TempDir()

	modDir := filepath.Join(dir, "myapp")
	os.MkdirAll(modDir, 0755)

	writeTestFile(t, modDir, "go.mod", `module example.com/myapp

go 1.21

require github.com/spf13/cobra v1.0.0
`)

	// go.work with single-line use directives
	workContent := `go 1.21

use ./myapp
`
	workPath := writeTestFile(t, dir, "go.work", workContent)

	deps, err := ParseGoWork(workPath)
	if err != nil {
		t.Fatalf("ParseGoWork failed: %v", err)
	}

	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d: %+v", len(deps), deps)
	}
	if deps[0].Name != "github.com/spf13/cobra" {
		t.Errorf("expected cobra, got %s", deps[0].Name)
	}
}

func TestParseGoWorkDedup(t *testing.T) {
	dir := t.TempDir()

	// Two modules sharing a common dependency version
	mod1Dir := filepath.Join(dir, "mod1")
	mod2Dir := filepath.Join(dir, "mod2")
	os.MkdirAll(mod1Dir, 0755)
	os.MkdirAll(mod2Dir, 0755)

	writeTestFile(t, mod1Dir, "go.mod", `module example.com/mod1

go 1.21

require github.com/spf13/cobra v1.0.0
`)
	writeTestFile(t, mod2Dir, "go.mod", `module example.com/mod2

go 1.21

require github.com/spf13/cobra v1.0.0
`)

	workContent := `go 1.21

use (
	./mod1
	./mod2
)
`
	workPath := writeTestFile(t, dir, "go.work", workContent)

	deps, err := ParseGoWork(workPath)
	if err != nil {
		t.Fatalf("ParseGoWork failed: %v", err)
	}

	// cobra should appear only once (deduplicated)
	cobraCount := 0
	for _, dep := range deps {
		if dep.Name == "github.com/spf13/cobra" {
			cobraCount++
		}
	}
	if cobraCount != 1 {
		t.Errorf("expected cobra to be deduplicated to 1, got %d", cobraCount)
	}
}

func TestParseAllGoWorkDedup(t *testing.T) {
	dir := t.TempDir()

	apiDir := filepath.Join(dir, "services", "api")
	os.MkdirAll(apiDir, 0755)

	writeTestFile(t, apiDir, "go.mod", `module example.com/api

go 1.21

require github.com/spf13/cobra v1.0.0
`)

	writeTestFile(t, dir, "go.work", `go 1.21

use ./services/api
`)

	deps, manifests, err := ParseAll(dir, 3)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	// go.work should aggregate deps from services/api/go.mod,
	// and the individual go.mod should be skipped to avoid duplicates.
	cobraCount := 0
	for _, dep := range deps {
		if dep.Name == "github.com/spf13/cobra" {
			cobraCount++
		}
	}
	if cobraCount != 1 {
		t.Errorf("expected cobra to appear once (go.work dedup), got %d", cobraCount)
	}

	// Both manifests should still be detected
	foundGoWork := false
	foundGoMod := false
	for _, m := range manifests {
		switch filepath.Base(m.Path) {
		case "go.work":
			foundGoWork = true
		case "go.mod":
			foundGoMod = true
		}
	}
	if !foundGoWork {
		t.Error("go.work manifest not detected")
	}
	if !foundGoMod {
		t.Error("go.mod manifest not detected")
	}
}

func TestParsePnpmWorkspace(t *testing.T) {
	dir := t.TempDir()

	// Create two workspace packages
	pkg1Dir := filepath.Join(dir, "packages", "ui-lib")
	pkg2Dir := filepath.Join(dir, "packages", "utils")
	os.MkdirAll(pkg1Dir, 0755)
	os.MkdirAll(pkg2Dir, 0755)

	writeTestFile(t, pkg1Dir, "package.json", `{
		"name": "@myorg/ui-lib",
		"version": "1.0.0",
		"dependencies": {
			"react": "^18.2.0"
		}
	}`)
	writeTestFile(t, pkg2Dir, "package.json", `{
		"name": "@myorg/utils",
		"version": "1.0.0",
		"dependencies": {
			"lodash": "^4.17.21"
		}
	}`)

	workContent := `packages:
  - "packages/*"
`
	workPath := writeTestFile(t, dir, "pnpm-workspace.yaml", workContent)

	deps, err := ParsePnpmWorkspace(workPath)
	if err != nil {
		t.Fatalf("ParsePnpmWorkspace failed: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 deps (react + lodash), got %d: %+v", len(deps), deps)
	}

	foundReact := false
	foundLodash := false
	for _, dep := range deps {
		switch dep.Name {
		case "react":
			foundReact = true
			if dep.Version != "18.2.0" {
				t.Errorf("react version: got %s, want 18.2.0", dep.Version)
			}
		case "lodash":
			foundLodash = true
		}
	}
	if !foundReact || !foundLodash {
		t.Errorf("missing deps: react=%v lodash=%v", foundReact, foundLodash)
	}
}

func TestParsePnpmWorkspaceDedup(t *testing.T) {
	dir := t.TempDir()

	pkg1Dir := filepath.Join(dir, "packages", "a")
	pkg2Dir := filepath.Join(dir, "packages", "b")
	os.MkdirAll(pkg1Dir, 0755)
	os.MkdirAll(pkg2Dir, 0755)

	writeTestFile(t, pkg1Dir, "package.json", `{
		"name": "@myorg/a",
		"version": "1.0.0",
		"dependencies": { "express": "^4.18.0" }
	}`)
	writeTestFile(t, pkg2Dir, "package.json", `{
		"name": "@myorg/b",
		"version": "1.0.0",
		"dependencies": { "express": "^4.18.0" }
	}`)

	workPath := writeTestFile(t, dir, "pnpm-workspace.yaml", `packages:
  - "packages/*"
`)

	deps, err := ParsePnpmWorkspace(workPath)
	if err != nil {
		t.Fatalf("ParsePnpmWorkspace failed: %v", err)
	}

	expressCount := 0
	for _, dep := range deps {
		if dep.Name == "express" {
			expressCount++
		}
	}
	if expressCount != 1 {
		t.Errorf("expected express deduplicated to 1, got %d", expressCount)
	}
}

func TestParseAllPnpmWorkspaceDedup(t *testing.T) {
	dir := t.TempDir()

	pkgDir := filepath.Join(dir, "packages", "myapp")
	os.MkdirAll(pkgDir, 0755)

	writeTestFile(t, pkgDir, "package.json", `{
		"name": "@myorg/myapp",
		"version": "1.0.0",
		"dependencies": { "express": "^4.18.0" }
	}`)

	writeTestFile(t, dir, "pnpm-workspace.yaml", `packages:
  - "packages/*"
`)

	deps, manifests, err := ParseAll(dir, 3)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	// express should appear only once (workspace dedup)
	expressCount := 0
	for _, dep := range deps {
		if dep.Name == "express" {
			expressCount++
		}
	}
	if expressCount != 1 {
		t.Errorf("expected express once (pnpm workspace dedup), got %d", expressCount)
	}

	// All manifests should still be detected
	foundWorkspace := false
	foundPkgJSON := false
	for _, m := range manifests {
		switch filepath.Base(m.Path) {
		case "pnpm-workspace.yaml":
			foundWorkspace = true
		case "package.json":
			foundPkgJSON = true
		}
	}
	if !foundWorkspace {
		t.Error("pnpm-workspace.yaml not detected")
	}
	if !foundPkgJSON {
		t.Error("package.json not detected")
	}
}

func TestParseAllYarnWorkspaceDedup(t *testing.T) {
	dir := t.TempDir()

	pkgDir := filepath.Join(dir, "packages", "myapp")
	os.MkdirAll(pkgDir, 0755)

	writeTestFile(t, pkgDir, "package.json", `{
		"name": "@myorg/myapp",
		"version": "1.0.0",
		"dependencies": { "express": "^4.18.0" }
	}`)

	// Root package.json with yarn workspaces
	writeTestFile(t, dir, "package.json", `{
		"name": "monorepo-root",
		"version": "1.0.0",
		"private": true,
		"workspaces": ["packages/*"]
	}`)

	deps, _, err := ParseAll(dir, 3)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	// express should appear only once (from workspace package, root has no deps)
	expressCount := 0
	for _, dep := range deps {
		if dep.Name == "express" {
			expressCount++
		}
	}
	if expressCount != 1 {
		t.Errorf("expected express once (yarn workspace dedup), got %d", expressCount)
	}
}

func TestParsePackageJSON(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "name": "test-pkg",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "~4.17.21"
  },
  "devDependencies": {
    "jest": ">=29.0.0"
  }
}`
	path := writeTestFile(t, dir, "package.json", content)

	deps, err := ParsePackageJSON(path)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if len(deps) != 4 {
		t.Fatalf("expected 4 deps (root + 3 deps), got %d", len(deps))
	}

	// Check express
	foundExpress := false
	foundJest := false
	foundRoot := false
	for _, dep := range deps {
		if dep.Name == "test-pkg" && dep.Version == "1.0.0" && dep.IsRoot {
			foundRoot = true
		}
		if dep.Name == "express" {
			foundExpress = true
			if dep.Version != "4.18.0" {
				t.Errorf("express version: got %s, want 4.18.0", dep.Version)
			}
			if dep.IsDev {
				t.Error("express should not be dev")
			}
		}
		if dep.Name == "jest" {
			foundJest = true
			if !dep.IsDev {
				t.Error("jest should be dev")
			}
		}
	}
	if !foundExpress || !foundJest || !foundRoot {
		t.Errorf("missing deps: express=%v jest=%v root=%v", foundExpress, foundJest, foundRoot)
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	content := `# requirements
flask==2.3.0
django>=4.0,<5.0
requests[security]==2.28.0
# comment
numpy
`
	path := writeTestFile(t, dir, "requirements.txt", content)

	deps, err := ParseRequirementsTxt(path)
	if err != nil {
		t.Fatalf("ParseRequirementsTxt failed: %v", err)
	}

	if len(deps) != 4 {
		t.Fatalf("expected 4 deps, got %d: %+v", len(deps), deps)
	}

	// Check flask
	foundFlask := false
	foundDjango := false
	foundRequests := false
	for _, dep := range deps {
		switch dep.Name {
		case "flask":
			foundFlask = true
			if dep.Version != "2.3.0" {
				t.Errorf("flask version: got %s, want 2.3.0", dep.Version)
			}
		case "django":
			foundDjango = true
			if dep.Version != "4.0" {
				t.Errorf("django version: got %s, want 4.0", dep.Version)
			}
		case "requests":
			foundRequests = true
		}
	}
	if !foundFlask || !foundDjango || !foundRequests {
		t.Errorf("missing deps: flask=%v django=%v requests=%v", foundFlask, foundDjango, foundRequests)
	}
}

func TestParseCargoToml(t *testing.T) {
	dir := t.TempDir()
	content := `[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }

[dev-dependencies]
criterion = "0.5"
`
	path := writeTestFile(t, dir, "Cargo.toml", content)

	deps, err := ParseCargoToml(path)
	if err != nil {
		t.Fatalf("ParseCargoToml failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 deps (root + serde + criterion), got %d: %+v", len(deps), deps)
	}

	foundSerde := false
	foundCriterion := false
	foundRoot := false
	for _, dep := range deps {
		if dep.Name == "test" && dep.Version == "0.1.0" && dep.IsRoot {
			foundRoot = true
		}
		if dep.Name == "serde" {
			foundSerde = true
			if dep.Version != "1.0" {
				t.Errorf("serde version: got %s, want 1.0", dep.Version)
			}
			if dep.IsDev {
				t.Error("serde should not be dev")
			}
		}
		if dep.Name == "criterion" {
			foundCriterion = true
			if !dep.IsDev {
				t.Error("criterion should be dev")
			}
		}
	}
	if !foundSerde || !foundCriterion || !foundRoot {
		t.Errorf("missing deps: serde=%v criterion=%v root=%v", foundSerde, foundCriterion, foundRoot)
	}
}

// --- License extraction tests ---

func TestParsePackageJSONLicense(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "name": "my-app",
  "version": "2.0.0",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.0"
  }
}`
	path := writeTestFile(t, dir, "package.json", content)

	deps, err := ParsePackageJSON(path)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	// Find root dep and check license
	for _, dep := range deps {
		if dep.IsRoot {
			if dep.License != "MIT" {
				t.Errorf("root license: got %q, want %q", dep.License, "MIT")
			}
			return
		}
	}
	t.Error("root dependency not found")
}

func TestParsePackageJSONLicenseApache(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "name": "enterprise-app",
  "version": "1.0.0",
  "license": "Apache-2.0",
  "dependencies": {}
}`
	path := writeTestFile(t, dir, "package.json", content)

	deps, err := ParsePackageJSON(path)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	for _, dep := range deps {
		if dep.IsRoot {
			if dep.License != "Apache-2.0" {
				t.Errorf("root license: got %q, want %q", dep.License, "Apache-2.0")
			}
			return
		}
	}
}

func TestParseCargoTomlLicense(t *testing.T) {
	dir := t.TempDir()
	content := `[package]
name = "my-crate"
version = "0.2.0"
license = "MIT"

[dependencies]
serde = "1.0"
`
	path := writeTestFile(t, dir, "Cargo.toml", content)

	deps, err := ParseCargoToml(path)
	if err != nil {
		t.Fatalf("ParseCargoToml failed: %v", err)
	}

	for _, dep := range deps {
		if dep.IsRoot {
			if dep.License != "MIT" {
				t.Errorf("root license: got %q, want %q", dep.License, "MIT")
			}
			return
		}
	}
	t.Error("root dependency not found")
}

func TestParseCargoTomlLicenseGPL(t *testing.T) {
	dir := t.TempDir()
	content := `[package]
name = "gpl-project"
version = "1.0.0"
license = "GPL-3.0"

[dependencies]
`
	path := writeTestFile(t, dir, "Cargo.toml", content)

	deps, err := ParseCargoToml(path)
	if err != nil {
		t.Fatalf("ParseCargoToml failed: %v", err)
	}

	for _, dep := range deps {
		if dep.IsRoot {
			if dep.License != "GPL-3.0" {
				t.Errorf("root license: got %q, want %q", dep.License, "GPL-3.0")
			}
			return
		}
	}
}

func TestParsePyprojectLicense(t *testing.T) {
	dir := t.TempDir()
	content := `[project]
name = "my-package"
version = "1.5.0"
license = "BSD-3-Clause"
dependencies = ["flask>=2.0"]
`
	path := writeTestFile(t, dir, "pyproject.toml", content)

	deps, err := ParsePyProjectToml(path)
	if err != nil {
		t.Fatalf("ParsePyProjectToml failed: %v", err)
	}

	for _, dep := range deps {
		if dep.IsRoot {
			if dep.License != "BSD-3-Clause" {
				t.Errorf("root license: got %q, want %q", dep.License, "BSD-3-Clause")
			}
			return
		}
	}
	t.Error("root dependency not found")
}

func TestParsePyprojectPoetryLicense(t *testing.T) {
	dir := t.TempDir()
	content := `[tool.poetry]
name = "poetry-app"
version = "0.1.0"
license = "Apache-2.0"

[tool.poetry.dependencies]
python = "^3.10"
flask = "^2.0"
`
	path := writeTestFile(t, dir, "pyproject.toml", content)

	deps, err := ParsePyProjectToml(path)
	if err != nil {
		t.Fatalf("ParsePyprojectToml failed: %v", err)
	}

	for _, dep := range deps {
		if dep.IsRoot {
			if dep.License != "Apache-2.0" {
				t.Errorf("root license: got %q, want %q", dep.License, "Apache-2.0")
			}
			return
		}
	}
}

func TestParsePomXMLLicense(t *testing.T) {
	dir := t.TempDir()
	content := `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <licenses>
    <license>
      <name>Apache License, Version 2.0</name>
      <url>https://www.apache.org/licenses/LICENSE-2.0</url>
    </license>
  </licenses>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.0</version>
    </dependency>
  </dependencies>
</project>`
	path := writeTestFile(t, dir, "pom.xml", content)

	_, err := ParsePomXML(path)
	if err != nil {
		t.Fatalf("ParsePomXML failed: %v", err)
	}

	// The license should be extracted from the POM
	// Note: ParsePomXML may not set IsRoot for Maven, but we can check
	// the license is parsed via the parsePomLicense helper
	license := parsePomLicense(content)
	if license != "Apache License, Version 2.0" {
		t.Errorf("POM license: got %q, want %q", license, "Apache License, Version 2.0")
	}
}

func TestParsePomXMLNoLicense(t *testing.T) {
	dir := t.TempDir()
	content := `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>no-license-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
    </dependency>
  </dependencies>
</project>`
	path := writeTestFile(t, dir, "pom.xml", content)

	_, err := ParsePomXML(path)
	if err != nil {
		t.Fatalf("ParsePomXML failed: %v", err)
	}

	license := parsePomLicense(content)
	if license != "" {
		t.Errorf("POM license should be empty, got %q", license)
	}
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module test\n\ngo 1.21\n")
	writeTestFile(t, dir, "package.json", `{"name":"test"}`)

	// Create a subdirectory with a manifest
	subDir := filepath.Join(dir, "subdir")
	os.MkdirAll(subDir, 0755)
	writeTestFile(t, subDir, "requirements.txt", "flask==2.0.0")

	manifests, err := Detect(dir, 3)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(manifests) != 3 {
		t.Fatalf("expected 3 manifests, got %d: %+v", len(manifests), manifests)
	}
}

func TestDetectSkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module test\n\ngo 1.21\n")

	// Create node_modules with a package.json that should be skipped
	nmDir := filepath.Join(dir, "node_modules", "somepkg")
	os.MkdirAll(nmDir, 0755)
	writeTestFile(t, nmDir, "package.json", `{"name":"somepkg"}`)

	manifests, err := Detect(dir, 3)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest (node_modules skipped), got %d: %+v", len(manifests), manifests)
	}
}

func TestParseAll(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", `module test

go 1.21

require (
	github.com/spf13/cobra v1.0.0
)
`)
	writeTestFile(t, dir, "package.json", `{
  "name": "test",
  "dependencies": { "express": "^4.18.0" }
}`)

	deps, manifests, err := ParseAll(dir, 3)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	if len(manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(manifests))
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	// Check manifest paths are set
	for _, dep := range deps {
		if dep.ManifestPath == "" {
			t.Error("manifest path should be set")
		}
	}
}

func TestParsePomXMLMultiModule(t *testing.T) {
	dir := t.TempDir()

	// Parent POM with modules and dependencyManagement
	parentPom := `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>

  <modules>
    <module>api</module>
    <module>web</module>
  </modules>

  <properties>
    <junit.version>5.9.0</junit.version>
  </properties>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter</artifactId>
        <version>${junit.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`
	writeTestFile(t, dir, "pom.xml", parentPom)

	// Child module 'api' - inherits parent properties and depMgmt
	apiDir := filepath.Join(dir, "api")
	os.MkdirAll(apiDir, 0755)
	apiPom := `<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
    <relativePath>../pom.xml</relativePath>
  </parent>
  <artifactId>api</artifactId>

  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.0</version>
    </dependency>
  </dependencies>
</project>`
	writeTestFile(t, apiDir, "pom.xml", apiPom)

	// Child module 'web' - also inherits parent
	webDir := filepath.Join(dir, "web")
	os.MkdirAll(webDir, 0755)
	webPom := `<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
    <relativePath>../pom.xml</relativePath>
  </parent>
  <artifactId>web</artifactId>

  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>1.7.30</version>
    </dependency>
  </dependencies>
</project>`
	writeTestFile(t, webDir, "pom.xml", webPom)

	// Parse the child POM - should inherit junit version from parent's depMgmt
	apiPomPath := filepath.Join(apiDir, "pom.xml")
	deps, err := ParsePomXMLWithParent(apiPomPath)
	if err != nil {
		t.Fatalf("ParsePomXMLWithParent failed: %v", err)
	}

	foundJunit := false
	foundSpring := false
	for _, dep := range deps {
		switch dep.Name {
		case "org.junit.jupiter:junit-jupiter":
			foundJunit = true
			// Version should be resolved from parent's dependencyManagement
			if dep.Version != "5.9.0" {
				t.Errorf("junit version: got %s, want 5.9.0 (from parent depMgmt)", dep.Version)
			}
		case "org.springframework:spring-core":
			foundSpring = true
			if dep.Version != "5.3.0" {
				t.Errorf("spring-core version: got %s, want 5.3.0", dep.Version)
			}
		}
	}
	if !foundJunit {
		t.Error("junit-jupiter not found in api module deps")
	}
	if !foundSpring {
		t.Error("spring-core not found in api module deps")
	}
}

func TestParseAllMavenMultiModuleDedup(t *testing.T) {
	dir := t.TempDir()

	// Parent POM with modules and a shared dependency
	parentPom := `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>

  <modules>
    <module>mod-a</module>
    <module>mod-b</module>
  </modules>

  <dependencies>
    <dependency>
      <groupId>commons-io</groupId>
      <artifactId>commons-io</artifactId>
      <version>2.11.0</version>
    </dependency>
  </dependencies>
</project>`
	writeTestFile(t, dir, "pom.xml", parentPom)

	// Both child modules depend on the same library
	modADir := filepath.Join(dir, "mod-a")
	modBDir := filepath.Join(dir, "mod-b")
	os.MkdirAll(modADir, 0755)
	os.MkdirAll(modBDir, 0755)

	writeTestFile(t, modADir, "pom.xml", `<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>mod-a</artifactId>
  <dependencies>
    <dependency>
      <groupId>commons-io</groupId>
      <artifactId>commons-io</artifactId>
      <version>2.11.0</version>
    </dependency>
  </dependencies>
</project>`)

	writeTestFile(t, modBDir, "pom.xml", `<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>mod-b</artifactId>
  <dependencies>
    <dependency>
      <groupId>commons-io</groupId>
      <artifactId>commons-io</artifactId>
      <version>2.11.0</version>
    </dependency>
  </dependencies>
</project>`)

	deps, _, err := ParseAll(dir, 3)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	// commons-io should appear only once (deduplicated across parent + 2 children)
	commonsCount := 0
	for _, dep := range deps {
		if dep.Name == "commons-io:commons-io" {
			commonsCount++
		}
	}
	if commonsCount != 1 {
		t.Errorf("expected commons-io deduplicated to 1, got %d (total deps: %d)", commonsCount, len(deps))
	}
}

func TestParseSettingsGradle(t *testing.T) {
	dir := t.TempDir()

	// Create subprojects
	coreDir := filepath.Join(dir, "core")
	webDir := filepath.Join(dir, "web")
	os.MkdirAll(coreDir, 0755)
	os.MkdirAll(webDir, 0755)

	writeTestFile(t, coreDir, "build.gradle", `
apply plugin: 'java'
dependencies {
    implementation 'org.springframework:spring-core:5.3.0'
    testImplementation 'junit:junit:4.13.2'
}
`)
	writeTestFile(t, webDir, "build.gradle", `
apply plugin: 'java'
dependencies {
    implementation 'org.springframework:spring-web:5.3.0'
}
`)

	settingsContent := `
rootProject.name = 'myapp'
include 'core'
include 'web'
`
	settingsPath := writeTestFile(t, dir, "settings.gradle", settingsContent)

	deps, err := ParseSettingsGradle(settingsPath)
	if err != nil {
		t.Fatalf("ParseSettingsGradle failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(deps), deps)
	}

	foundSpringCore := false
	foundSpringWeb := false
	foundJunit := false
	for _, dep := range deps {
		switch dep.Name {
		case "org.springframework:spring-core":
			foundSpringCore = true
		case "org.springframework:spring-web":
			foundSpringWeb = true
		case "junit:junit":
			foundJunit = true
		}
	}
	if !foundSpringCore || !foundSpringWeb || !foundJunit {
		t.Errorf("missing deps: spring-core=%v spring-web=%v junit=%v", foundSpringCore, foundSpringWeb, foundJunit)
	}
}

func TestParseSettingsGradleDedup(t *testing.T) {
	dir := t.TempDir()

	modADir := filepath.Join(dir, "mod-a")
	modBDir := filepath.Join(dir, "mod-b")
	os.MkdirAll(modADir, 0755)
	os.MkdirAll(modBDir, 0755)

	writeTestFile(t, modADir, "build.gradle", `
dependencies {
    implementation 'commons-io:commons-io:2.11.0'
}
`)
	writeTestFile(t, modBDir, "build.gradle", `
dependencies {
    implementation 'commons-io:commons-io:2.11.0'
}
`)

	settingsPath := writeTestFile(t, dir, "settings.gradle", `
include 'mod-a'
include 'mod-b'
`)

	deps, err := ParseSettingsGradle(settingsPath)
	if err != nil {
		t.Fatalf("ParseSettingsGradle failed: %v", err)
	}

	commonsCount := 0
	for _, dep := range deps {
		if dep.Name == "commons-io:commons-io" {
			commonsCount++
		}
	}
	if commonsCount != 1 {
		t.Errorf("expected commons-io deduplicated to 1, got %d", commonsCount)
	}
}

func TestParseAllGradleMultiProjectDedup(t *testing.T) {
	dir := t.TempDir()

	coreDir := filepath.Join(dir, "core")
	os.MkdirAll(coreDir, 0755)

	writeTestFile(t, coreDir, "build.gradle", `
dependencies {
    implementation 'org.springframework:spring-core:5.3.0'
}
`)

	writeTestFile(t, dir, "settings.gradle", `
include 'core'
`)

	deps, _, err := ParseAll(dir, 3)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	// spring-core should appear only once (settings.gradle aggregates, core/build.gradle skipped)
	springCount := 0
	for _, dep := range deps {
		if dep.Name == "org.springframework:spring-core" {
			springCount++
		}
	}
	if springCount != 1 {
		t.Errorf("expected spring-core once (gradle multi-project dedup), got %d", springCount)
	}
}

func TestParseBuildGradlePlatform(t *testing.T) {
	dir := t.TempDir()
	content := `
dependencies {
    implementation platform('org.springframework.boot:spring-boot-dependencies:2.7.0')
    implementation 'org.springframework:spring-core'
}
`
	path := writeTestFile(t, dir, "build.gradle", content)

	deps, err := ParseBuildGradle(path)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	foundBOM := false
	for _, dep := range deps {
		if dep.Name == "org.springframework.boot:spring-boot-dependencies" {
			foundBOM = true
			if dep.Version != "2.7.0" {
				t.Errorf("BOM version: got %s, want 2.7.0", dep.Version)
			}
		}
	}
	if !foundBOM {
		t.Error("platform() BOM dependency not found")
	}
}

func TestParseUvLock(t *testing.T) {
	dir := t.TempDir()
	content := `version = 1
revision-id = "abc123"

[[package]]
name = "flask"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "django"
version = "4.2.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "my-workspace-pkg"
version = "0.1.0"
source = { virtual = "my-workspace" }

[[package]]
name = "requests"
version = "2.31.0"
`
	path := writeTestFile(t, dir, "uv.lock", content)

	deps, err := ParseUvLock(path)
	if err != nil {
		t.Fatalf("ParseUvLock failed: %v", err)
	}

	// Should have 3 deps (flask, django, requests) — virtual workspace pkg skipped
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps (virtual pkg skipped), got %d: %+v", len(deps), deps)
	}

	foundFlask := false
	foundDjango := false
	foundRequests := false
	foundWorkspace := false
	for _, dep := range deps {
		switch dep.Name {
		case "flask":
			foundFlask = true
			if dep.Version != "3.0.0" {
				t.Errorf("flask version: got %s, want 3.0.0", dep.Version)
			}
		case "django":
			foundDjango = true
		case "requests":
			foundRequests = true
		case "my-workspace-pkg":
			foundWorkspace = true
		}
	}
	if !foundFlask || !foundDjango || !foundRequests {
		t.Errorf("missing deps: flask=%v django=%v requests=%v", foundFlask, foundDjango, foundRequests)
	}
	if foundWorkspace {
		t.Error("virtual workspace package should be skipped")
	}
}

func TestValidatePomRelativePath_Valid(t *testing.T) {
	dir := t.TempDir()
	childDir := filepath.Join(dir, "child")
	os.MkdirAll(childDir, 0755)

	tests := []struct {
		name    string
		pomDir  string
		relPath string
		valid   bool
	}{
		{"standard parent", childDir, "../pom.xml", true},
		{"same dir", childDir, "pom.xml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := validatePomRelativePath(tt.pomDir, tt.relPath)
			if ok != tt.valid {
				t.Errorf("validatePomRelativePath(%s, %s) = %v, want %v",
					tt.pomDir, tt.relPath, ok, tt.valid)
			}
		})
	}
}

func TestValidatePomRelativePath_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	childDir := filepath.Join(dir, "child")
	os.MkdirAll(childDir, 0755)

	tests := []struct {
		name    string
		pomDir  string
		relPath string
	}{
		{"absolute path", childDir, "/etc/passwd/pom.xml"},
		{"windows absolute path", childDir, `C:\secrets\pom.xml`},
		{"windows UNC path", childDir, `\\server\share\pom.xml`},
		{"escape root", childDir, "../../../etc/passwd/pom.xml"},
		{"deep traversal", childDir, "../../../../../../tmp/pom.xml"},
		{"not pom.xml", childDir, "../secret.txt"},
		{"empty path", childDir, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := validatePomRelativePath(tt.pomDir, tt.relPath)
			if ok {
				t.Errorf("validatePomRelativePath(%s, %s) should reject, but accepted",
					tt.pomDir, tt.relPath)
			}
		})
	}
}

func TestParsePomXMLWithParent_PathTraversal_Blocked(t *testing.T) {
	dir := t.TempDir()
	childDir := filepath.Join(dir, "child")
	os.MkdirAll(childDir, 0755)

	// Create a secret file outside the project that the traversal would try to read
	secretDir := filepath.Join(dir, "..", "secret-pom-dir")
	os.MkdirAll(secretDir, 0755)
	secretPom := `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>evil</groupId>
  <artifactId>secret</artifactId>
  <version>9.9.9</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.evil</groupId>
        <artifactId>malware</artifactId>
        <version>1.0.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`
	writeTestFile(t, secretDir, "pom.xml", secretPom)

	// Malicious child POM with path traversal in relativePath
	maliciousPom := `<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>evil</groupId>
    <artifactId>secret</artifactId>
    <version>9.9.9</version>
    <relativePath>../../secret-pom-dir/pom.xml</relativePath>
  </parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.evil</groupId>
      <artifactId>malware</artifactId>
    </dependency>
  </dependencies>
</project>`
	writeTestFile(t, childDir, "pom.xml", maliciousPom)

	deps, err := ParsePomXMLWithParent(filepath.Join(childDir, "pom.xml"))
	if err != nil {
		t.Fatalf("ParsePomXMLWithParent failed: %v", err)
	}

	// The malicious dependency should NOT have version 1.0.0 from the traversed parent
	for _, dep := range deps {
		if dep.Name == "org.evil:malware" && dep.Version == "1.0.0" {
			t.Error("path traversal succeeded — malicious parent POM was loaded")
		}
	}
}

func TestParse_FileSizeLimit(t *testing.T) {
	// Create a file larger than MaxManifestSize
	dir := t.TempDir()
	largePath := filepath.Join(dir, "package.json")

	// Create a file just over the limit
	largeContent := strings.Repeat(" ", MaxManifestSize+1)
	if err := os.WriteFile(largePath, []byte(largeContent), 0644); err != nil {
		t.Fatalf("failed to write large file: %v", err)
	}

	_, err := Parse(largePath)
	if err == nil {
		t.Error("expected error for oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected 'too large' error, got: %v", err)
	}
}

func TestReadFileWithLimit_ValidSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := "small file content"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	data, err := readFileWithLimit(path)
	if err != nil {
		t.Fatalf("readFileWithLimit failed: %v", err)
	}
	if string(data) != content {
		t.Errorf("expected '%s', got '%s'", content, string(data))
	}
}

func TestReadFileWithLimit_TooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.txt")
	largeContent := strings.Repeat("x", MaxManifestSize+1)
	if err := os.WriteFile(path, []byte(largeContent), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := readFileWithLimit(path)
	if err == nil {
		t.Error("expected error for oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected 'too large' error, got: %v", err)
	}
}

func TestParseHelmChart(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "Chart.yaml", `apiVersion: v2
name: platform
version: 1.2.3
appVersion: "4.5.6"
annotations:
  artifacthub.io/license: Apache-2.0
dependencies:
  - name: postgresql
    version: 15.5.2
    repository: https://charts.bitnami.com/bitnami
  - name: redis
    alias: cache
    version: 19.1.0
    repository: https://charts.bitnami.com/bitnami
`)

	deps, err := ParseHelmChart(filepath.Join(dir, "Chart.yaml"))
	if err != nil {
		t.Fatalf("ParseHelmChart failed: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 Helm dependencies, got %d", len(deps))
	}
	if deps[0].Name != "platform" || deps[0].Version != "1.2.3" || deps[0].Ecosystem != analysis.EcosystemHelm || deps[0].License != "Apache-2.0" || !deps[0].IsRoot {
		t.Fatalf("unexpected root chart dependency: %+v", deps[0])
	}
	if deps[1].Name != "postgresql" || deps[1].Version != "15.5.2" || deps[1].Ecosystem != analysis.EcosystemHelm || deps[1].Repository != "https://charts.bitnami.com/bitnami" {
		t.Fatalf("unexpected chart dependency: %+v", deps[1])
	}
	if deps[2].Name != "redis" || deps[2].Version != "19.1.0" {
		t.Fatalf("unexpected aliased chart dependency: %+v", deps[2])
	}
}

func TestParseAllPrefersGemfileLockOverUnversionedGemfile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "ios/Gemfile", `source "https://rubygems.org"
gem "fastlane"
`)
	writeTestFile(t, dir, "ios/Gemfile.lock", `GEM
  remote: https://rubygems.org/
  specs:
    colored (1.2)
    fastlane (2.232.2)
      colored (~> 1.2)

DEPENDENCIES
  fastlane
`)

	deps, _, err := ParseAll(dir, 5)
	if err != nil {
		t.Fatalf("ParseAll failed: %v", err)
	}

	var fastlane []analysis.Dependency
	for _, dep := range deps {
		if dep.Ecosystem == analysis.EcosystemRubyGems && dep.Name == "fastlane" {
			fastlane = append(fastlane, dep)
		}
	}
	if len(fastlane) != 1 {
		t.Fatalf("expected one fastlane dependency, got %+v", fastlane)
	}
	if fastlane[0].Version != "2.232.2" {
		t.Fatalf("expected lockfile version 2.232.2, got %q", fastlane[0].Version)
	}
	if !fastlane[0].IsDirect {
		t.Fatalf("expected lockfile fastlane to be marked direct")
	}
	if filepath.Base(fastlane[0].ManifestPath) != "Gemfile.lock" {
		t.Fatalf("expected fastlane to come from Gemfile.lock, got %s", fastlane[0].ManifestPath)
	}
}
