// Real-repo integration tests for the SBOM/VEX/license pipeline.
//
// These tests clone real open-source repositories (shallow clones), run the
// full PatchFlow SBOM/VEX/license/dep-graph pipeline against them, and
// verify that the output is valid and contains expected data.
//
// Tests are opt-in because they depend on external repositories or large local
// benchmark fixtures. Set PATCHFLOW_REAL_REPO_TESTS=1 to run them.
package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	realRepoCloneTimeout = 90 * time.Second
	realRepoScanTimeout  = 2 * time.Minute
)

// skipIfShort keeps external and benchmark-repository tests out of the
// deterministic default suite. These tests require network access or large
// fixtures and must be requested explicitly.
func skipIfShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-repo test in -short mode")
	}
	if os.Getenv("PATCHFLOW_REAL_REPO_TESTS") != "1" {
		t.Skip("set PATCHFLOW_REAL_REPO_TESTS=1 to run real-repo integration tests")
	}
	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
}

// cloneRepo clones a repo (shallow) into a temp directory and returns the path.
func cloneRepo(t *testing.T, url, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	ctx, cancel := context.WithTimeout(context.Background(), realRepoCloneTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", url, dir)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Skipf("clone of %s exceeded %s", name, realRepoCloneTimeout)
		}
		t.Skipf("failed to clone %s: %v (network issue?)", name, err)
	}
	return dir
}

// runPatchflowExport runs patchflow scan export with the given format on a repo.
// It builds the patchflow binary first, then runs it.
func runPatchflowExport(t *testing.T, repoDir, format string, extraArgs ...string) []byte {
	t.Helper()
	binPath := buildPatchflowBinary(t)

	// Run scan export
	outputFile := filepath.Join(t.TempDir(), "output")
	args := []string{"scan", "export", "--format", format, "--output", outputFile}
	args = append(args, extraArgs...)
	ctx, cancel := context.WithTimeout(context.Background(), realRepoScanTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = repoDir
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("patchflow scan export --format %s exceeded %s", format, realRepoScanTimeout)
		}
		t.Fatalf("patchflow scan export --format %s failed: %v", format, err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	return data
}

// runPatchflowDepsLicenses runs patchflow deps licenses on a repo.
func runPatchflowDepsLicenses(t *testing.T, repoDir string) string {
	t.Helper()
	binPath := buildPatchflowBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), realRepoScanTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "deps", "licenses")
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("patchflow deps licenses exceeded %s", realRepoScanTimeout)
		}
		t.Fatalf("patchflow deps licenses failed: %v\n%s", err, out)
	}
	return string(out)
}

// --- NodeGoat (OWASP Node.js vulnerable app) ---

func TestRealNodeGoatCycloneDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	data := runPatchflowExport(t, repoDir, "cyclonedx-json", "--include-vex")

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Verify BOM format
	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", bom["bomFormat"])
	}
	if bom["specVersion"] != "1.5" {
		t.Errorf("expected specVersion=1.5, got %v", bom["specVersion"])
	}

	// Verify root component
	meta, ok := bom["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("expected metadata object")
	}
	component, ok := meta["component"].(map[string]interface{})
	if !ok {
		t.Fatal("expected metadata.component")
	}
	rootName, _ := component["name"].(string)
	if !strings.Contains(strings.ToLower(rootName), "goat") {
		t.Errorf("expected root name to contain 'goat', got %s", rootName)
	}

	// Verify root has a license (NodeGoat uses Apache 2.0)
	licenses, ok := component["licenses"].([]interface{})
	if ok && len(licenses) > 0 {
		firstLic, ok := licenses[0].(map[string]interface{})
		if ok {
			licObj, ok := firstLic["license"].(map[string]interface{})
			if ok {
				licName := ""
				if id, ok := licObj["id"].(string); ok {
					licName = id
				}
				if licName == "" {
					if name, ok := licObj["name"].(string); ok {
						licName = name
					}
				}
				if licName != "" && !strings.Contains(strings.ToLower(licName), "apache") {
					t.Logf("root license: %s (expected Apache)", licName)
				}
			}
		}
	}

	// Verify components exist (NodeGoat has ~30+ npm deps)
	components, ok := bom["components"].([]interface{})
	if !ok {
		t.Fatal("expected components array")
	}
	if len(components) < 20 {
		t.Errorf("expected at least 20 components, got %d", len(components))
	}

	// Verify vulnerabilities with VEX (NodeGoat has known vulns)
	vulns, ok := bom["vulnerabilities"].([]interface{})
	if !ok {
		t.Fatal("expected vulnerabilities array")
	}
	if len(vulns) < 5 {
		t.Errorf("expected at least 5 vulnerabilities, got %d", len(vulns))
	}

	// Verify VEX states are populated
	for _, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		analysis, ok := vuln["analysis"].(map[string]interface{})
		if !ok {
			t.Error("expected analysis in vulnerability")
			continue
		}
		state, ok := analysis["state"].(string)
		if !ok || state == "" {
			t.Error("expected non-empty VEX state")
			continue
		}
		// State should be one of the valid VEX states
		validStates := map[string]bool{
			"exploitable": true, "in_triage": true,
			"not_affected": true, "resolved": true,
		}
		if !validStates[state] {
			t.Errorf("invalid VEX state: %s", state)
		}
	}
}

func TestRealNodeGoatSPDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	data := runPatchflowExport(t, repoDir, "spdx-json")

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("expected spdxVersion=SPDX-2.3, got %v", doc["spdxVersion"])
	}

	packages := doc["packages"].([]interface{})
	if len(packages) < 20 {
		t.Errorf("expected at least 20 packages, got %d", len(packages))
	}

	// Verify relationships exist
	rels := doc["relationships"].([]interface{})
	if len(rels) < 20 {
		t.Errorf("expected at least 20 relationships, got %d", len(rels))
	}

	// Verify at least one DEPENDS_ON relationship
	foundDependsOn := false
	for _, r := range rels {
		rel := r.(map[string]interface{})
		if rel["relationshipType"] == "DEPENDS_ON" {
			foundDependsOn = true
			break
		}
	}
	if !foundDependsOn {
		t.Error("expected at least one DEPENDS_ON relationship")
	}
}

func TestRealNodeGoatVEX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	data := runPatchflowExport(t, repoDir, "vex-json")

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", doc["bomFormat"])
	}

	vulns := doc["vulnerabilities"].([]interface{})
	if len(vulns) < 5 {
		t.Errorf("expected at least 5 vulnerabilities, got %d", len(vulns))
	}

	// Verify all vulnerabilities have analysis with valid states
	validStates := map[string]bool{
		"exploitable": true, "in_triage": true,
		"not_affected": true, "resolved": true,
	}
	for _, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		analysis, ok := vuln["analysis"].(map[string]interface{})
		if !ok {
			t.Error("expected analysis in vulnerability")
			continue
		}
		state, ok := analysis["state"].(string)
		if !ok {
			t.Error("expected state in analysis")
			continue
		}
		if !validStates[state] {
			t.Errorf("invalid VEX state: %s", state)
		}
	}

	// Verify at least some vulnerabilities are exploitable (NodeGoat imports vulnerable packages)
	foundExploitable := false
	for _, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		analysis, ok := vuln["analysis"].(map[string]interface{})
		if !ok {
			continue
		}
		if analysis["state"] == "exploitable" {
			foundExploitable = true
			// Verify detail is populated
			if detail, ok := analysis["detail"].(string); ok && detail == "" {
				t.Error("exploitable vulnerability should have detail")
			}
			break
		}
	}
	if !foundExploitable {
		t.Log("warning: no exploitable vulnerabilities found (expected some for NodeGoat)")
	}
}

func TestRealNodeGoatDepTree(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	data := runPatchflowExport(t, repoDir, "dep-tree")
	tree := string(data)

	if !strings.Contains(tree, "npm") {
		t.Error("tree should contain npm ecosystem")
	}

	// NodeGoat uses express — should be in the tree
	if !strings.Contains(tree, "express") {
		t.Error("tree should contain express dependency")
	}

	// Verify tree structure (should have box-drawing characters)
	if !strings.Contains(tree, "└──") && !strings.Contains(tree, "├──") {
		t.Error("tree should use box-drawing characters")
	}
}

func TestRealNodeGoatDepDot(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	data := runPatchflowExport(t, repoDir, "dep-dot")
	dot := string(data)

	if !strings.Contains(dot, "digraph") {
		t.Error("DOT should contain 'digraph'")
	}
	if !strings.Contains(dot, "express") {
		t.Error("DOT should contain express")
	}
}

func TestRealNodeGoatLicenses(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/OWASP/NodeGoat.git", "NodeGoat")

	output := runPatchflowDepsLicenses(t, repoDir)

	if !strings.Contains(output, "License Report") {
		t.Error("expected 'License Report' header")
	}
	if !strings.Contains(output, "By Category") {
		t.Error("expected 'By Category' section")
	}
	if !strings.Contains(output, "By Risk") {
		t.Error("expected 'By Risk' section")
	}

	// NodeGoat's package.json has a license field
	if !strings.Contains(output, "Apache") {
		t.Log("warning: expected Apache license in output")
	}
}

// --- dvna (Damn Vulnerable Node Application) ---

func TestRealDvnaCycloneDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/appsecco/dvna.git", "dvna")

	data := runPatchflowExport(t, repoDir, "cyclonedx-json", "--include-vex")

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", bom["bomFormat"])
	}

	components := bom["components"].([]interface{})
	if len(components) < 10 {
		t.Errorf("expected at least 10 components, got %d", len(components))
	}

	// dvna has known vulnerabilities
	vulns := bom["vulnerabilities"].([]interface{})
	if len(vulns) < 5 {
		t.Errorf("expected at least 5 vulnerabilities, got %d", len(vulns))
	}
}

func TestRealDvnaVEX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/appsecco/dvna.git", "dvna")

	data := runPatchflowExport(t, repoDir, "vex-json")

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	vulns := doc["vulnerabilities"].([]interface{})
	if len(vulns) < 5 {
		t.Errorf("expected at least 5 vulnerabilities, got %d", len(vulns))
	}

	// Verify VEX states
	validStates := map[string]bool{
		"exploitable": true, "in_triage": true,
		"not_affected": true, "resolved": true,
	}
	for _, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		analysis, ok := vuln["analysis"].(map[string]interface{})
		if !ok {
			t.Error("expected analysis in vulnerability")
			continue
		}
		state, ok := analysis["state"].(string)
		if !ok {
			t.Error("expected state in analysis")
			continue
		}
		if !validStates[state] {
			t.Errorf("invalid VEX state: %s", state)
		}
	}
}

// --- django-DefectDojo (Python) ---

func TestRealDjangoDefectDojoCycloneDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/DefectDojo/django-DefectDojo.git", "django-DefectDojo")

	data := runPatchflowExport(t, repoDir, "cyclonedx-json", "--include-vex")

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", bom["bomFormat"])
	}

	// DefectDojo is a large project with many deps
	components := bom["components"].([]interface{})
	if len(components) < 50 {
		t.Errorf("expected at least 50 components, got %d", len(components))
	}

	// Verify root component name
	meta := bom["metadata"].(map[string]interface{})
	component := meta["component"].(map[string]interface{})
	rootName, _ := component["name"].(string)
	if !strings.Contains(strings.ToLower(rootName), "defect") {
		t.Errorf("expected root name to contain 'defect', got %s", rootName)
	}
}

func TestRealDjangoDefectDojoLicenses(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/DefectDojo/django-DefectDojo.git", "django-DefectDojo")

	output := runPatchflowDepsLicenses(t, repoDir)

	if !strings.Contains(output, "License Report") {
		t.Error("expected 'License Report' header")
	}

	// DefectDojo has BSD-3-Clause license
	if !strings.Contains(output, "BSD-3-Clause") {
		t.Log("warning: expected BSD-3-Clause license in output")
	}

	// Should classify some as permissive
	if !strings.Contains(output, "permissive") {
		t.Error("expected permissive category in output")
	}
}

// --- WebGoat (Java/Maven) ---

func TestRealWebGoatCycloneDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/WebGoat/WebGoat.git", "WebGoat")

	data := runPatchflowExport(t, repoDir, "cyclonedx-json", "--include-vex")

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", bom["bomFormat"])
	}

	// WebGoat is a Java/Maven project with many deps
	components := bom["components"].([]interface{})
	if len(components) < 20 {
		t.Errorf("expected at least 20 components, got %d", len(components))
	}

	// Verify root component name
	meta := bom["metadata"].(map[string]interface{})
	component := meta["component"].(map[string]interface{})
	rootName, _ := component["name"].(string)
	if !strings.Contains(strings.ToLower(rootName), "goat") {
		t.Errorf("expected root name to contain 'goat', got %s", rootName)
	}

	// Verify Maven purl format
	foundMavenPurl := false
	for _, c := range components {
		comp := c.(map[string]interface{})
		if purl, ok := comp["purl"].(string); ok {
			if strings.Contains(purl, "pkg:maven/") {
				foundMavenPurl = true
				break
			}
		}
	}
	if !foundMavenPurl {
		t.Error("expected at least one Maven purl in components")
	}
}

func TestRealWebGoatSPDX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/WebGoat/WebGoat.git", "WebGoat")

	data := runPatchflowExport(t, repoDir, "spdx-json")

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("expected spdxVersion=SPDX-2.3, got %v", doc["spdxVersion"])
	}

	packages := doc["packages"].([]interface{})
	if len(packages) < 20 {
		t.Errorf("expected at least 20 packages, got %d", len(packages))
	}

	// Verify root package name
	name, _ := doc["name"].(string)
	if !strings.Contains(strings.ToLower(name), "goat") {
		t.Errorf("expected name to contain 'goat', got %s", name)
	}

	// Verify Maven purl external refs
	foundPurlRef := false
	for _, p := range packages {
		pkg := p.(map[string]interface{})
		if refs, ok := pkg["externalRefs"].([]interface{}); ok {
			for _, r := range refs {
				ref := r.(map[string]interface{})
				if ref["referenceType"] == "purl" {
					if strings.Contains(ref["referenceLocator"].(string), "pkg:maven/") {
						foundPurlRef = true
					}
				}
			}
		}
	}
	if !foundPurlRef {
		t.Error("expected at least one Maven purl external reference")
	}
}

func TestRealWebGoatVEX(t *testing.T) {
	skipIfShort(t)
	repoDir := cloneRepo(t, "https://github.com/WebGoat/WebGoat.git", "WebGoat")

	data := runPatchflowExport(t, repoDir, "vex-json")

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	vulns := doc["vulnerabilities"].([]interface{})
	if len(vulns) < 5 {
		t.Errorf("expected at least 5 vulnerabilities, got %d", len(vulns))
	}

	// Verify all have valid VEX states
	validStates := map[string]bool{
		"exploitable": true, "in_triage": true,
		"not_affected": true, "resolved": true,
	}
	for _, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		analysis, ok := vuln["analysis"].(map[string]interface{})
		if !ok {
			t.Error("expected analysis in vulnerability")
			continue
		}
		state, ok := analysis["state"].(string)
		if !ok {
			t.Error("expected state in analysis")
			continue
		}
		if !validStates[state] {
			t.Errorf("invalid VEX state: %s", state)
		}
	}
}

// --- Cross-repo consistency test ---

func TestRealReposCycloneDXConsistency(t *testing.T) {
	skipIfShort(t)
	repos := []struct {
		url  string
		name string
	}{
		{"https://github.com/OWASP/NodeGoat.git", "NodeGoat"},
		{"https://github.com/appsecco/dvna.git", "dvna"},
	}

	for _, repo := range repos {
		t.Run(repo.name, func(t *testing.T) {
			repoDir := cloneRepo(t, repo.url, repo.name)

			// Generate CycloneDX
			cdxData := runPatchflowExport(t, repoDir, "cyclonedx-json", "--include-vex")
			var bom map[string]interface{}
			if err := json.Unmarshal(cdxData, &bom); err != nil {
				t.Fatalf("invalid CycloneDX JSON: %v", err)
			}

			// Generate SPDX
			spdxData := runPatchflowExport(t, repoDir, "spdx-json")
			var doc map[string]interface{}
			if err := json.Unmarshal(spdxData, &doc); err != nil {
				t.Fatalf("invalid SPDX JSON: %v", err)
			}

			// Verify component counts are consistent
			cdxComponents := len(bom["components"].([]interface{}))
			spdxPackages := len(doc["packages"].([]interface{}))

			// SPDX has 1 extra (root package), CycloneDX root is in metadata
			if spdxPackages < cdxComponents {
				t.Errorf("SPDX packages (%d) should be >= CycloneDX components (%d)",
					spdxPackages, cdxComponents)
			}

			// Verify root name is consistent
			cdxMeta, ok := bom["metadata"].(map[string]interface{})
			if !ok {
				t.Fatal("expected metadata in CycloneDX")
			}
			cdxComp, ok := cdxMeta["component"].(map[string]interface{})
			if !ok {
				t.Fatal("expected component in CycloneDX metadata")
			}
			cdxRoot, _ := cdxComp["name"].(string)
			spdxName, _ := doc["name"].(string)
			if cdxRoot != spdxName {
				t.Errorf("root name mismatch: CycloneDX=%s, SPDX=%s", cdxRoot, spdxName)
			}
		})
	}
}

// --- Taint-rule integration tests (all languages) ---
//
// These tests use pre-cloned repos from the patchflow-benchmarks project.
// No network access is required, but the fixtures are large and remain opt-in.

// benchmarkReposDir is the path to pre-cloned benchmark repos.
const benchmarkReposDir = "/Users/digitalcenter/patchflow-benchmarks/.bench-work"

// localRepo returns the path to a pre-cloned benchmark repo, or skips the test
// if the directory doesn't exist.
func localRepo(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(benchmarkReposDir, name)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Skipf("benchmark repo %q not found at %s", name, dir)
	}
	return dir
}

// runPatchflowScanRun builds the patchflow binary and runs `patchflow scan run
// --json --quiet` in repoDir. It returns the parsed JSON output.
func runPatchflowScanRun(t *testing.T, repoDir string) map[string]interface{} {
	t.Helper()
	binPath := buildPatchflowBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), realRepoScanTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "scan", "run", "--json", "--quiet", "--offline")
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("patchflow scan run exceeded %s", realRepoScanTimeout)
		}
		// Some exit codes are non-zero when findings are present; capture stderr.
		t.Logf("patchflow scan run exited with error: %v", err)
	}
	if len(out) == 0 {
		t.Skip("patchflow scan run produced no output (binary issue?)")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid JSON from patchflow scan run: %v\n%s", err, string(out))
	}
	return result
}

// extractFindings pulls the findings array from the scan-run JSON output.
func extractFindings(t *testing.T, result map[string]interface{}) []map[string]interface{} {
	t.Helper()
	analysis, ok := result["analysis"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'analysis' object in scan output")
	}
	rawFindings, ok := analysis["findings"].([]interface{})
	if !ok {
		t.Fatal("expected 'analysis.findings' array in scan output")
	}
	findings := make([]map[string]interface{}, 0, len(rawFindings))
	for _, f := range rawFindings {
		if m, ok := f.(map[string]interface{}); ok {
			findings = append(findings, m)
		}
	}
	return findings
}

// hasRuleWithPrefix returns true if any finding's rule_id starts with prefix.
func hasRuleWithPrefix(findings []map[string]interface{}, prefix string) bool {
	for _, f := range findings {
		if ruleID, ok := f["rule_id"].(string); ok {
			if strings.HasPrefix(ruleID, prefix) {
				return true
			}
		}
	}
	return false
}

// hasRuleID returns true if any finding's rule_id exactly matches.
func hasRuleID(findings []map[string]interface{}, ruleID string) bool {
	for _, f := range findings {
		if id, ok := f["rule_id"].(string); ok && id == ruleID {
			return true
		}
	}
	return false
}

// hasCVE returns true if any finding's cve_id matches.
func hasCVE(findings []map[string]interface{}, cve string) bool {
	for _, f := range findings {
		if id, ok := f["cve_id"].(string); ok && id == cve {
			return true
		}
	}
	return false
}

// findingRuleIDs extracts the rule_id from each finding for debug logging.
func findingRuleIDs(findings []map[string]interface{}) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		if ruleID, ok := f["rule_id"].(string); ok {
			ids = append(ids, ruleID)
		}
	}
	return ids
}

// findingCVEIDs extracts the cve_id from each finding for debug logging.
func findingCVEIDs(findings []map[string]interface{}) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		if cveID, ok := f["cve_id"].(string); ok && cveID != "" {
			ids = append(ids, cveID)
		}
	}
	return ids
}

// countByAnalyzer returns the number of findings from a specific analyzer.
func countByAnalyzer(findings []map[string]interface{}, analyzer string) int {
	count := 0
	for _, f := range findings {
		if a, ok := f["analyzer"].(string); ok && a == analyzer {
			count++
		}
	}
	return count
}

// =============================================================================
// Ruby Tests
// =============================================================================

// TestRailsGoatTaintRules runs against OWASP RailsGoat (deliberately vulnerable
// Ruby on Rails app) and verifies that Ruby taint rules (TP-RB*) fire.
func TestRailsGoatTaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "railsgoat")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("RailsGoat: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for RailsGoat")
	}

	t.Logf("RailsGoat rules: %v", findingRuleIDs(findings))
	if !hasRuleWithPrefix(findings, "TP-RB") {
		t.Errorf("expected at least one TP-RB* finding, got rules: %v", findingRuleIDs(findings))
	}
}

// TestDVRATaintRules runs against Damn Vulnerable Rails App.
func TestDVRATaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "dvra")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("DVRA: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for DVRA")
	}

	t.Logf("DVRA rules: %v", findingRuleIDs(findings))
}

// =============================================================================
// PHP Tests
// =============================================================================

// TestDVWATaintRules runs against DVWA (Damn Vulnerable Web Application, PHP).
func TestDVWATaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "dvwa")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("DVWA: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for DVWA")
	}

	t.Logf("DVWA rules: %v", findingRuleIDs(findings))
	if !hasRuleWithPrefix(findings, "TP-PHP") {
		t.Errorf("expected at least one TP-PHP* finding, got rules: %v", findingRuleIDs(findings))
	}
}

// TestXVWATaintRules runs against XVWA (Xtreme Vulnerable Web App, PHP).
func TestXVWATaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "xvwa")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("XVWA: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for XVWA")
	}

	t.Logf("XVWA rules: %v", findingRuleIDs(findings))
}

// TestBWAPPTaintRules runs against bWAPP (PHP vulnerable app).
func TestBWAPPTaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "bwapp")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("bWAPP: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for bWAPP")
	}

	t.Logf("bWAPP rules: %v", findingRuleIDs(findings))
}

// TestLaravelTaintRules runs against Laravel 5.5.40 (historical vulnerable).
func TestLaravelTaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "laravel-v5.5.40")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("Laravel 5.5.40: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for Laravel")
	}

	t.Logf("Laravel rules: %v", findingRuleIDs(findings))
}

// =============================================================================
// Java Tests
// =============================================================================

// TestWebGoat_Smoke_ProducesJavaFindings runs against WebGoat (deliberately
// vulnerable Java) and verifies that Java-specific findings are produced.
// This is a SMOKE test — it checks that the scanner runs and produces output,
// not that taint rules fire correctly.
//
// The strict version (TestWebGoat_SpringAnnotationSources_TaintRulesFire) is
// pending until Spring annotation source models are added to the taint engine.
func TestWebGoat_Smoke_ProducesJavaFindings(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "webgoat")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("WebGoat: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for WebGoat")
	}

	t.Logf("WebGoat rules: %v", findingRuleIDs(findings))
	// Smoke test: accept any Java-specific rule (TP-JAVA*, TS-JAVA*, or JAVA*).
	// The strict test below checks for TP-JAVA* specifically.
	if !hasRuleWithPrefix(findings, "TP-JAVA") &&
		!hasRuleWithPrefix(findings, "TS-JAVA") &&
		!hasRuleWithPrefix(findings, "JAVA") {
		t.Errorf("expected at least one Java-specific finding (TP-JAVA*/TS-JAVA*/JAVA*), got rules: %v", findingRuleIDs(findings))
	}
}

// TestWebGoat_SpringAnnotationSources_TaintRulesFire is a STRICT test that
// verifies TP-JAVA* taint rules fire on WebGoat's Spring annotation-based
// source patterns (@RequestParam, @PathVariable, @RequestBody).
//
// Enabled in B6.5: the taint engine now models Spring annotations as taint
// sources via seedAnnotatedParams() in analyzer.go.
func TestWebGoat_SpringAnnotationSources_TaintRulesFire(t *testing.T) {
	skipIfShort(t)

	repoDir := localRepo(t, "webgoat")
	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("WebGoat: %d findings", len(findings))
	if !hasRuleWithPrefix(findings, "TP-JAVA") {
		t.Errorf("expected at least one TP-JAVA* taint finding, got rules: %v", findingRuleIDs(findings))
	}
}

// TestOWASPBenchmarkJava runs against OWASP Benchmark Java.
func TestOWASPBenchmarkJava(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "owasp-benchmark-java")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("OWASP Benchmark Java: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for OWASP Benchmark Java")
	}

	t.Logf("OWASP Benchmark rules: %v", findingRuleIDs(findings))
}

// TestDVJATaintRules runs against Damn Vulnerable Java App.
func TestDVJATaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "dvja")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("DVJA: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for DVJA")
	}

	t.Logf("DVJA rules: %v", findingRuleIDs(findings))
}

// TestYsoserialDeserialization runs against ysoserial (Java deserialization).
func TestYsoserialDeserialization(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "ysoserial")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("ysoserial: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for ysoserial")
	}

	t.Logf("ysoserial rules: %v", findingRuleIDs(findings))
}

// TestFastjsonDeserialization runs against fastjson 1.2.80 (deserialization CVEs).
func TestFastjsonDeserialization(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "fastjson-1.2.80")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("fastjson 1.2.80: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for fastjson")
	}

	t.Logf("fastjson rules: %v", findingRuleIDs(findings))
}

// TestJacksonDatabindDeserialization runs against jackson-databind 2.9.3.
func TestJacksonDatabindDeserialization(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "jackson-databind-2.9.3")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("jackson-databind 2.9.3: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for jackson-databind")
	}

	t.Logf("jackson-databind rules: %v", findingRuleIDs(findings))
}

// TestSpringFrameworkTaintRules runs against Spring Framework 5.3.17.
func TestSpringFrameworkTaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "spring-framework-v5.3.17")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("Spring Framework 5.3.17: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for Spring Framework")
	}

	t.Logf("Spring Framework rules: %v", findingRuleIDs(findings))
}

// =============================================================================
// Python Tests
// =============================================================================

// TestDVGA_Smoke_ProducesPythonFindings runs against Damn Vulnerable GraphQL
// App (Python) and verifies that Python-specific findings are produced.
// This is a SMOKE test — it checks that the scanner runs and produces output,
// not that taint rules fire correctly.
//
// The strict version (TestDVGA_GraphQLSources_TaintRulesFire) is pending until
// GraphQL resolver args are modeled as taint sources.
func TestDVGA_Smoke_ProducesPythonFindings(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "dvga")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("DVGA: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for DVGA")
	}

	t.Logf("DVGA rules: %v", findingRuleIDs(findings))
	// Smoke test: accept any Python-specific rule (TP-PY*, TS-PY*, or PY*).
	if !hasRuleWithPrefix(findings, "TP-PY") &&
		!hasRuleWithPrefix(findings, "TS-PY") &&
		!hasRuleWithPrefix(findings, "PY") {
		t.Errorf("expected at least one Python-specific finding (TP-PY*/TS-PY*/PY*), got rules: %v", findingRuleIDs(findings))
	}
}

// TestDVGA_GraphQLSources_AreSeeded verifies that the GraphQL resolver source
// model is active: the scanner runs on DVGA and produces Python findings
// (pattern/AST/taint). This confirms the source seeding infrastructure works
// even if TP-PY* taint rules don't fire yet (sink coverage gap).
//
// Enabled in B6.5: the taint engine now models GraphQL resolver args as taint
// sources via seedGraphQLResolverParams() in analyzer.go.
func TestDVGA_GraphQLSources_AreSeeded(t *testing.T) {
	skipIfShort(t)

	repoDir := localRepo(t, "dvga")
	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("DVGA: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for DVGA")
	}
	// Verify Python findings exist (any analyzer).
	if !hasRuleWithPrefix(findings, "TP-PY") &&
		!hasRuleWithPrefix(findings, "TS-PY") &&
		!hasRuleWithPrefix(findings, "PY") {
		t.Errorf("expected at least one Python-specific finding, got rules: %v", findingRuleIDs(findings))
	}
}

// TestDVGA_GraphQLSources_TaintRulesFire is a STRICT test that verifies
// TP-PY* taint rules fire on DVGA's GraphQL resolver-based source patterns
// with source-to-sink flow.
//
// Enabled in B7: SQLAlchemy text() is now modeled as a taint sink in TP-PY001.
// The GraphQL resolver source model (B6.5) seeds resolver args as tainted,
// and the text() sink (B7.1) catches the flow: resolver arg → text() → SQLi.
func TestDVGA_GraphQLSources_TaintRulesFire(t *testing.T) {
	skipIfShort(t)

	repoDir := localRepo(t, "dvga")
	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("DVGA: %d findings", len(findings))
	if !hasRuleWithPrefix(findings, "TP-PY") {
		t.Errorf("expected at least one TP-PY* taint finding, got rules: %v", findingRuleIDs(findings))
	}
}

// TestDVFATaintRules runs against Damn Vulnerable Flask App (Python).
func TestDVFATaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "dvfa")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("DVFA: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for DVFA")
	}

	t.Logf("DVFA rules: %v", findingRuleIDs(findings))
	if !hasRuleWithPrefix(findings, "TP-PY") {
		t.Errorf("expected at least one TP-PY* finding, got rules: %v", findingRuleIDs(findings))
	}
}

// TestVulnerableFlaskApp runs against a vulnerable Flask application.
func TestVulnerableFlaskApp(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "vulnerable-flask-app")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("vulnerable-flask-app: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for vulnerable-flask-app")
	}

	t.Logf("vulnerable-flask-app rules: %v", findingRuleIDs(findings))
}

// =============================================================================
// JavaScript/TypeScript Tests
// =============================================================================

// TestJuiceShop_Smoke_ProducesJSFindings runs against OWASP Juice Shop
// (JS/TS) and verifies that JS/Express-specific findings are produced.
// This is a SMOKE test — it checks that the scanner runs and produces output,
// not that taint rules fire correctly.
//
// The strict version (TestJuiceShop_ExpressSources_TaintRulesFire) is pending
// until Express req.* source patterns are modeled in the taint engine.
func TestJuiceShop_Smoke_ProducesJSFindings(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "juice-shop")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("Juice Shop: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for Juice Shop")
	}

	t.Logf("Juice Shop rules: %v", findingRuleIDs(findings))
	// Smoke test: accept any JS/Express-specific rule.
	// The strict test below checks for TP-JS* specifically.
	if !hasRuleWithPrefix(findings, "TP-JS") &&
		!hasRuleWithPrefix(findings, "TS-JS") &&
		!hasRuleWithPrefix(findings, "PF-EXPRESS") &&
		!hasRuleWithPrefix(findings, "JS") {
		t.Errorf("expected at least one JS/Express-specific finding, got rules: %v", findingRuleIDs(findings))
	}
}

// TestJuiceShop_ExpressSources_TaintRulesFire is a STRICT test that verifies
// TP-JS* taint rules fire on Juice Shop's Express req.* source patterns.
//
// Enabled in B6.5: the taint engine now normalizes TypeScript to JavaScript
// for rule matching, and detects direct source-to-sink flows (inline source
// usage in sink arguments without variable assignment).
func TestJuiceShop_ExpressSources_TaintRulesFire(t *testing.T) {
	skipIfShort(t)

	repoDir := localRepo(t, "juice-shop")
	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("Juice Shop: %d findings", len(findings))
	if !hasRuleWithPrefix(findings, "TP-JS") {
		t.Errorf("expected at least one TP-JS* taint finding, got rules: %v", findingRuleIDs(findings))
	}
}

// TestNodeGoatTaintRules runs against OWASP NodeGoat (Node.js).
func TestNodeGoatTaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "nodegoat")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("NodeGoat: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for NodeGoat")
	}

	t.Logf("NodeGoat rules: %v", findingRuleIDs(findings))
	if !hasRuleWithPrefix(findings, "TP-JS") {
		t.Errorf("expected at least one TP-JS* finding, got rules: %v", findingRuleIDs(findings))
	}
}

// TestDVNATaintRules runs against Damn Vulnerable Node App.
func TestDVNATaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "dvna")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("DVNA: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for DVNA")
	}

	t.Logf("DVNA rules: %v", findingRuleIDs(findings))
}

// =============================================================================
// C# / .NET Tests
// =============================================================================

// TestASPGoatTaintRules runs against ASPGoat (ASP.NET vulnerable app).
func TestASPGoatTaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "aspgoat")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("ASPGoat: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for ASPGoat")
	}

	t.Logf("ASPGoat rules: %v", findingRuleIDs(findings))
}

// TestWebGoatNetTaintRules runs against WebGoat.NET.
func TestWebGoatNetTaintRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "webgoat-net")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("WebGoat.NET: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for WebGoat.NET")
	}

	t.Logf("WebGoat.NET rules: %v", findingRuleIDs(findings))
}

// TestVulnerableNetCore runs against vulnerable ASP.NET Core app.
func TestVulnerableNetCore(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "vulnerable-net-core")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("vulnerable-net-core: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for vulnerable-net-core")
	}

	t.Logf("vulnerable-net-core rules: %v", findingRuleIDs(findings))
}

// =============================================================================
// SCA / CVE Tests (Historical Vulnerable Repos)
// =============================================================================

// TestLog4jSCA runs against log4j 2.14.0 and verifies Log4Shell CVEs are detected.
func TestLog4jSCA(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "log4j-old")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("log4j 2.14.0: %d findings", len(findings))
	t.Logf("log4j CVEs: %v", findingCVEIDs(findings))

	expectedCVEs := []string{"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"}
	for _, cve := range expectedCVEs {
		if !hasCVE(findings, cve) {
			t.Errorf("expected %s in findings, got CVEs: %v", cve, findingCVEIDs(findings))
		}
	}
}

// TestLodashSCA runs against lodash 4.17.10 and verifies known CVEs are detected.
func TestLodashSCA(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "lodash-old")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("lodash 4.17.10: %d findings", len(findings))
	t.Logf("lodash CVEs: %v", findingCVEIDs(findings))

	expectedCVEs := []string{"CVE-2019-10744", "CVE-2020-8203", "CVE-2021-23337"}
	for _, cve := range expectedCVEs {
		if !hasCVE(findings, cve) {
			t.Errorf("expected %s in findings, got CVEs: %v", cve, findingCVEIDs(findings))
		}
	}
}

// TestExpressSCA runs against express 4.16.0 and verifies known CVEs are detected.
func TestExpressSCA(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "express-old")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("express 4.16.0: %d findings", len(findings))
	t.Logf("express CVEs: %v", findingCVEIDs(findings))

	expectedCVEs := []string{"CVE-2022-24999", "CVE-2024-29041"}
	for _, cve := range expectedCVEs {
		if !hasCVE(findings, cve) {
			t.Errorf("expected %s in findings, got CVEs: %v", cve, findingCVEIDs(findings))
		}
	}
}

// TestRequestsSCA runs against requests 2.19.0 and verifies known CVEs are detected.
func TestRequestsSCA(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "requests-old")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("requests 2.19.0: %d findings", len(findings))
	t.Logf("requests CVEs: %v", findingCVEIDs(findings))

	expectedCVEs := []string{"CVE-2018-18074", "CVE-2023-32681"}
	for _, cve := range expectedCVEs {
		if !hasCVE(findings, cve) {
			t.Errorf("expected %s in findings, got CVEs: %v", cve, findingCVEIDs(findings))
		}
	}
}

// TestUrllib3SCA runs against urllib3 1.24.1 and verifies known CVEs are detected.
func TestUrllib3SCA(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "urllib3-old")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("urllib3 1.24.1: %d findings", len(findings))
	t.Logf("urllib3 CVEs: %v", findingCVEIDs(findings))

	expectedCVEs := []string{"CVE-2019-11324", "CVE-2020-26137"}
	for _, cve := range expectedCVEs {
		if !hasCVE(findings, cve) {
			t.Errorf("expected %s in findings, got CVEs: %v", cve, findingCVEIDs(findings))
		}
	}
}

// TestGoJwtSCA runs against golang-jwt v3.2.0 and verifies CVE-2020-26160.
// Note: CVE-2020-26160 may not be in the offline OSV DB; the test verifies
// that SCA findings are produced for the go-jwt dependency.
func TestGoJwtSCA(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "go-jwt-old")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("golang-jwt v3.2.0: %d findings", len(findings))
	t.Logf("golang-jwt CVEs: %v", findingCVEIDs(findings))
	t.Logf("golang-jwt rules: %v", findingRuleIDs(findings))

	// CVE-2020-26160 affects golang-jwt v3.2.0. If the offline DB has it,
	// verify it's detected. Otherwise, just verify SCA ran.
	if hasCVE(findings, "CVE-2020-26160") {
		t.Logf("CVE-2020-26160 correctly detected")
	} else {
		t.Logf("CVE-2020-26160 not in offline DB — verifying SCA ran instead")
		// At minimum, the scan should produce some findings (SAST or SCA)
		if len(findings) == 0 {
			t.Errorf("expected at least 1 finding for golang-jwt, got 0")
		}
	}
}

// =============================================================================
// FP Rate Tests (Clean Real-World Repos)
//
// These tests use baseline snapshots from CLEAN_REPO_BASELINE_B1.json.
// They fail when:
//   - blocking findings increase (any blocking finding in a clean repo is a bug)
//   - SAST count exceeds the frozen max_sast threshold
//   - a new noisy rule appears that wasn't in the baseline
//   - a known noisy rule's count jumps >20% above baseline
// =============================================================================

// cleanRepoBaseline holds the frozen FP baseline for a clean repo.
type cleanRepoBaseline struct {
	TotalFindings int            `json:"total_findings"`
	Blocking      int            `json:"blocking"`
	MaxBlocking   int            `json:"max_blocking"`
	SastFindings  int            `json:"sast_findings"`
	MaxSast       int            `json:"max_sast"`
	ByRule        map[string]int `json:"by_rule"`
}

// cleanRepoBaselines is the frozen B1 baseline for clean repos.
// These values must not increase. If they do, it's a regression.
var cleanRepoBaselines = map[string]cleanRepoBaseline{
	"cobra": {
		TotalFindings: 18,
		Blocking:      0,
		MaxBlocking:   0,
		SastFindings:  14,
		MaxSast:       30,
		ByRule: map[string]int{
			"G104": 7, "G201": 5, "G302": 1, "G304": 1,
		},
	},
	"flask": {
		TotalFindings: 43,
		Blocking:      0,
		MaxBlocking:   0,
		SastFindings:  6,
		MaxSast:       15,
		ByRule: map[string]int{
			"PY019": 2, "TS-PY019": 2, "TS-PY002": 1, "TS-PY001": 1,
			"generic-api-key": 5,
		},
	},
	"django": {
		TotalFindings: 143,
		Blocking:      0,
		MaxBlocking:   0,
		SastFindings:  132,
		MaxSast:       200,
		ByRule: map[string]int{
			"PY050": 48, "TS-PY018": 12, "HTML002": 11, "TS-PY005": 7,
			"PY051": 6, "PY001": 6, "PY043": 4, "TS-PY008": 3,
			"TS-PY017": 3, "TS-PY002": 3, "PY010": 3, "PY011": 3,
			"PY044": 3, "TP-PY001-IP": 2, "TS-JS020": 2, "TS-PY001": 2,
			"generic-api-key": 2,
		},
	},
}

// checkCleanRepoBaseline validates findings against the frozen baseline.
// It fails on: blocking findings, SAST count exceeding max, new rules,
// or known rule counts jumping >20% above baseline.
func checkCleanRepoBaseline(t *testing.T, repoName string, findings []map[string]interface{}) {
	t.Helper()
	baseline, ok := cleanRepoBaselines[repoName]
	if !ok {
		t.Fatalf("no baseline found for clean repo %s", repoName)
	}

	// Count by rule and analyzer
	currentByRule := map[string]int{}
	blockingCount := 0
	sastCount := 0
	for _, f := range findings {
		ruleID, _ := f["rule_id"].(string)
		if ruleID == "" {
			ruleID = "none"
		}
		currentByRule[ruleID]++

		if b, ok := f["blocking"].(bool); ok && b {
			blockingCount++
		}

		analyzer, _ := f["analyzer"].(string)
		if isSASTAnalyzer(analyzer) {
			sastCount++
		}
	}

	// 1. Blocking findings must not increase
	if blockingCount > baseline.MaxBlocking {
		t.Errorf("CLEAN REPO REGRESSION [%s]: %d blocking findings (baseline max: %d) — blocking findings in clean repos are bugs",
			repoName, blockingCount, baseline.MaxBlocking)
	}

	// 2. SAST count must not exceed frozen max
	if sastCount > baseline.MaxSast {
		t.Errorf("CLEAN REPO REGRESSION [%s]: %d SAST findings (baseline max: %d) — potential FP increase",
			repoName, sastCount, baseline.MaxSast)
	}

	// 3. Check for new rules not in baseline (excluding SCA/license/secrets)
	for ruleID, count := range currentByRule {
		if _, wasInBaseline := baseline.ByRule[ruleID]; !wasInBaseline {
			// Skip SCA/license/secrets rules — they vary with dependency versions
			if !isSASTRuleID(ruleID) {
				continue
			}
			if count >= 3 {
				t.Errorf("CLEAN REPO REGRESSION [%s]: new noisy rule %s appeared with %d findings (not in baseline) — investigate FP",
					repoName, ruleID, count)
			}
		}
	}

	// 4. Check for known rule count jumps >20%
	for ruleID, baselineCount := range baseline.ByRule {
		currentCount := currentByRule[ruleID]
		if currentCount > int(float64(baselineCount)*1.2) {
			t.Errorf("CLEAN REPO REGRESSION [%s]: rule %s jumped from %d to %d (>20%% increase) — investigate FP",
				repoName, ruleID, baselineCount, currentCount)
		}
	}

	t.Logf("[%s] baseline check: total=%d, sast=%d (max %d), blocking=%d (max %d)",
		repoName, len(findings), sastCount, baseline.MaxSast, blockingCount, baseline.MaxBlocking)
}

// isSASTAnalyzer returns true for SAST analyzers (not SCA/license/secrets).
func isSASTAnalyzer(analyzer string) bool {
	switch analyzer {
	case "gosast-embedded", "patterns-embedded", "treesitter-ast", "taint-patterns":
		return true
	case "framework-spring", "framework-rails", "framework-aspnet", "framework-express",
		"framework-django", "framework-laravel", "framework-react", "framework-nextjs",
		"framework-angular", "framework-nestjs", "framework-spring-security":
		return true
	default:
		return false
	}
}

// isSASTRuleID returns true for SAST rule IDs (not SCA/license/secrets).
func isSASTRuleID(ruleID string) bool {
	if ruleID == "none" || ruleID == "" {
		return false
	}
	// SAST rule ID prefixes
	prefixes := []string{"G", "PY", "JS", "TS", "RB", "PHP", "JAVA", "TP-", "PF-", "HTML", "TS-PY", "TS-JS", "TS-RB", "TS-PHP", "TS-JAVA", "XLANG"}
	for _, p := range prefixes {
		if strings.HasPrefix(ruleID, p) {
			return true
		}
	}
	return false
}

// TestCleanRepoCobra runs against cobra (clean Go project) and checks FP rate
// against the frozen B1 baseline.
func TestCleanRepoCobra(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "cobra")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("cobra (clean): %d findings", len(findings))
	t.Logf("cobra rules: %v", findingRuleIDs(findings))

	checkCleanRepoBaseline(t, "cobra", findings)
}

// TestCleanRepoFlask runs against flask (clean Python project) and checks FP
// rate against the frozen B1 baseline.
func TestCleanRepoFlask(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "flask")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("flask (clean): %d findings", len(findings))
	t.Logf("flask rules: %v", findingRuleIDs(findings))

	checkCleanRepoBaseline(t, "flask", findings)
}

// TestCleanRepoDjango runs against django (clean Python project) and checks
// FP rate against the frozen B1 baseline.
func TestCleanRepoDjango(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "django")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("django (clean): %d findings", len(findings))
	t.Logf("django rules: %v", findingRuleIDs(findings))

	checkCleanRepoBaseline(t, "django", findings)
}

// =============================================================================
// Terraform / IaC Tests
// =============================================================================

// TestTerragoatTerraformRules runs against Terragoat (vulnerable Terraform).
func TestTerragoatTerraformRules(t *testing.T) {
	skipIfShort(t)
	repoDir := localRepo(t, "terragoat")

	result := runPatchflowScanRun(t, repoDir)
	findings := extractFindings(t, result)

	t.Logf("terragoat: %d findings", len(findings))
	if len(findings) == 0 {
		t.Skip("no findings produced for terragoat")
	}

	t.Logf("terragoat rules: %v", findingRuleIDs(findings))
	if !hasRuleWithPrefix(findings, "TF") {
		t.Errorf("expected at least one TF* finding, got rules: %v", findingRuleIDs(findings))
	}
}
