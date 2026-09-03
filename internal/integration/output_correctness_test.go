// Package integration contains end-to-end integration tests that verify
// output correctness — not just "doesn't crash" but "produces the right
// output." These tests guard against silent-wrong-output bugs that are
// the most dangerous class of defect in a security tool.
//
// These tests were added after a post-mortem on v0.1.5 where:
//   - CycloneDX SBOMs exported 0 vulnerabilities despite 42 being known
//   - --since silently dropped all SCA findings
//   - standard profile crashed on real Go projects
//
// Each test here corresponds to a specific silent-wrong-output bug class.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	"github.com/Patchflow-security/patchflow-cli/internal/sbom"
)

// =============================================================================
// CycloneDX SBOM: vulnerabilities array must be populated when SCA findings exist
//
// Bug: v0.1.5 exported "vulnerabilities": [] even when scan run found 42 CVEs.
// Root cause: vulnerabilities were gated behind IncludeVEX=true.
// Fix: always populate vulnerabilities from SCA findings; VEX analysis
// (reachability) is the optional part, not the vulnerabilities themselves.
// =============================================================================

func TestCycloneDXVulnerabilitiesPopulatedFromSCAFindings(t *testing.T) {
	// Build a result with known SCA findings
	result := &analysis.AnalysisResult{
		ScanID:      "test-cdx-vuln-001",
		ProjectRoot: "/tmp/test",
		Findings: []analysis.Finding{
			{
				ID:             "sca-npm-express-CVE-2024-29040",
				Type:           analysis.TypeSCA,
				Analyzer:       "osv",
				Severity:       analysis.SeverityCritical,
				Title:          "express@4.0.0 has CVE-2024-29040",
				PackageName:    "express",
				PackageVersion: "4.0.0",
				CVEID:          "CVE-2024-29040",
				AdvisoryURL:    "https://osv.dev/vulnerability/GHSA-xxxx",
				Description:    "Critical vulnerability in express",
				FixedVersion:   "4.19.2",
				RuleID:         "OSV-CVE-2024-29040",
			},
			{
				ID:             "sca-npm-lodash-CVE-2021-23337",
				Type:           analysis.TypeSCA,
				Analyzer:       "osv",
				Severity:       analysis.SeverityHigh,
				Title:          "lodash@4.17.4 has CVE-2021-23337",
				PackageName:    "lodash",
				PackageVersion: "4.17.4",
				CVEID:          "CVE-2021-23337",
				Description:    "Command injection in lodash",
				FixedVersion:   "4.17.21",
				RuleID:         "OSV-CVE-2021-23337",
			},
			// Non-SCA finding should NOT appear in vulnerabilities
			{
				ID:       "sast-eval-001",
				Type:     analysis.TypeSAST,
				Analyzer: "patterns-embedded",
				Severity: analysis.SeverityHigh,
				Title:    "eval() with user input",
				RuleID:   "TP-JS001",
			},
		},
		Dependencies: []analysis.Dependency{
			{Name: "express", Version: "4.0.0", Ecosystem: analysis.EcosystemNPM},
			{Name: "lodash", Version: "4.17.4", Ecosystem: analysis.EcosystemNPM},
		},
	}

	// Generate WITHOUT IncludeVEX — vulnerabilities must still be present
	cfg := sbom.GenerateConfig{
		Format:      "cyclonedx-json",
		ToolVersion: "test-1.0.0",
		IncludeVEX:  false, // This is the key: VEX off, vulns still required
	}

	data, err := sbom.GenerateCycloneDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateCycloneDXJSON failed: %v", err)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	vulns, ok := bom["vulnerabilities"].([]interface{})
	if !ok {
		t.Fatal("expected vulnerabilities array in CycloneDX output, got non-array or missing")
	}

	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulnerabilities (SCA findings only), got %d. "+
			"This is a regression: vulnerabilities must always be populated "+
			"from SCA findings regardless of IncludeVEX.", len(vulns))
	}

	// Verify each vulnerability has required fields
	for i, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			t.Fatalf("vulnerability[%d] is not an object", i)
		}
		if vuln["id"] == nil || vuln["id"] == "" {
			t.Errorf("vulnerability[%d] has empty id", i)
		}
		affects, ok := vuln["affects"].([]interface{})
		if !ok || len(affects) == 0 {
			t.Errorf("vulnerability[%d] has no affects (no affected component)", i)
		}
		ratings, ok := vuln["ratings"].([]interface{})
		if !ok || len(ratings) == 0 {
			t.Errorf("vulnerability[%d] has no ratings (no severity)", i)
		}
	}

	t.Logf("CycloneDX vulnerabilities correctly populated: %d vulns without VEX", len(vulns))
}

// TestCycloneDXVulnerabilitiesEmptyWhenNoSCAFindings verifies the inverse:
// when there are no SCA findings, vulnerabilities should be an empty array
// (not nil or missing), so consumers can safely parse it.
func TestCycloneDXVulnerabilitiesEmptyWhenNoSCAFindings(t *testing.T) {
	result := &analysis.AnalysisResult{
		ScanID:      "test-cdx-clean-001",
		ProjectRoot: "/tmp/test",
		Findings: []analysis.Finding{
			{
				ID:       "sast-eval-001",
				Type:     analysis.TypeSAST,
				Analyzer: "patterns-embedded",
				Severity: analysis.SeverityHigh,
				Title:    "eval() with user input",
				RuleID:   "TP-JS001",
			},
		},
	}

	cfg := sbom.GenerateConfig{
		Format:      "cyclonedx-json",
		ToolVersion: "test-1.0.0",
		IncludeVEX:  false,
	}

	data, err := sbom.GenerateCycloneDXJSON(result, cfg)
	if err != nil {
		t.Fatalf("GenerateCycloneDXJSON failed: %v", err)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// When there are no SCA findings, vulnerabilities may be omitted (omitempty)
	// or an empty array. Both are acceptable — the key is that it's not a
	// non-empty array with wrong data.
	vulnsRaw, hasVulns := bom["vulnerabilities"]
	if hasVulns {
		vulns, ok := vulnsRaw.([]interface{})
		if !ok {
			t.Fatal("vulnerabilities field present but not an array")
		}
		if len(vulns) != 0 {
			t.Errorf("expected 0 vulnerabilities, got %d", len(vulns))
		}
	}
	// If vulnerabilities is omitted (omitempty), that's fine — it means
	// "no vulnerabilities" which is correct.
}

// =============================================================================
// --since must NOT drop SCA findings
//
// Bug: v0.1.5 --since HEAD~1 silently filtered SCA findings to only
// dependencies whose manifest file changed. This meant a PR that didn't
// touch go.mod/package.json would show 0 vulnerabilities even if the
// project had 42 known CVEs.
// Root cause: scaAnalyzer.ChangedOnly = true was set when --since was used.
// Fix: SCA always scans all dependencies regardless of --changed-only/--since.
// =============================================================================

func TestSinceDoesNotDropSCAFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary-based test in -short mode")
	}

	// Build a Go repo with a known vulnerable dependency
	g := newGoldenRepo(t)
	g.write("go.mod", `module testrepo

go 1.21

require github.com/fatih/color v1.7.0
`)
	g.write("main.go", `package main

import "fmt"

func main() {
    fmt.Println("hello")
}
`)
	g.write("README.md", "# Test Repo\n")
	g.commit("initial commit with vulnerable dep")

	// Create a second commit that changes only the README (not go.mod)
	g.write("README.md", "# Test Repo\n\nUpdated description.\n")
	g.commit("update readme only")

	// Build the binary
	binPath := buildPatchflowBinary(t)

	// Run full scan (no --since)
	fullOut := runPatchflowJSON(t, binPath, g.root, "scan", "run", "--json", "--quiet", "--offline")
	fullFindings := extractFindingsFromJSON(t, fullOut)
	fullSCA := countFindingsByType(fullFindings, "sca")

	// Run scan with --since HEAD~1 (only README changed, not go.mod)
	sinceOut := runPatchflowJSON(t, binPath, g.root, "scan", "run", "--since", "HEAD~1", "--json", "--quiet", "--offline")
	sinceFindings := extractFindingsFromJSON(t, sinceOut)
	sinceSCA := countFindingsByType(sinceFindings, "sca")

	if fullSCA == 0 {
		t.Skip("no SCA findings in full scan (OSV DB may not be available); cannot verify parity")
	}

	if sinceSCA != fullSCA {
		t.Errorf("SCA findings dropped by --since: full=%d, since=%d. "+
			"This is a regression: --since must not filter SCA findings. "+
			"Vulnerabilities in existing deps are still relevant even if the "+
			"manifest file wasn't changed in this PR.",
			fullSCA, sinceSCA)
	}

	t.Logf("SCA parity verified: full=%d, since=%d", fullSCA, sinceSCA)
}

// =============================================================================
// Standard profile must not crash on real Go projects
//
// Bug: v0.1.5 standard profile panicked on Go projects with type errors
// in dependency packages. The taint-ssa analyzer's prog.Build() spawned
// internal goroutines that panicked without recovery.
// Fix: Build SSA packages individually with per-package recover();
// skip packages with type errors in collectAllPackages.
// =============================================================================

func TestStandardProfileNoCrashOnGoProject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary-based test in -short mode")
	}

	// Build a Go repo with a type assertion in a switch (the pattern that
	// triggered the original panic in Sandbox-Orch's service.go:265).
	g := newGoldenRepo(t)
	g.write("go.mod", `module testrepo

go 1.21
`)
	g.write("main.go", `package main

import "fmt"

type Service interface {
	Name() string
}

type fooService struct{}

func (fooService) Name() string { return "foo" }

type barService struct{}

func (barService) Name() string { return "bar" }

func getService(name string) Service {
	switch name {
	case "foo":
		return fooService{}
	case "bar":
		return barService{}
	default:
		return nil
	}
}

func main() {
	s := getService("foo")
	if s != nil {
		fmt.Println(s.Name())
	}
}
`)
	g.commit("initial go repo with switch+type pattern")

	binPath := buildPatchflowBinary(t)

	// Run standard profile — must exit 0 (no panic, no crash)
	cmd := exec.Command(binPath, "scan", "run", "--profile", "standard", "--offline")
	cmd.Dir = g.root
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run patchflow: %v\n%s", err, out)
		}
	}

	// A panic produces exit code 2. Findings with --fail-on produce exit
	// code 1. We accept exit code 0 (no findings) or 1 (findings found,
	// which is expected for a vulnerable repo). Exit code 2 = panic = bug.
	if exitCode == 2 {
		t.Fatalf("patchflow scan run --profile standard crashed with exit code 2 "+
			"(panic). Output:\n%s\nThis is a regression: the taint-ssa analyzer "+
			"must not crash the scan on Go projects with type errors.", out)
	}

	// Verify no panic message in output
	if strings.Contains(string(out), "panic:") {
		t.Fatalf("panic message found in output even though exit code was %d:\n%s",
			exitCode, out)
	}

	t.Logf("Standard profile completed successfully on Go project (exit code %d)", exitCode)
}

// =============================================================================
// SCA findings must have deterministic rule IDs
//
// Bug: v0.1.5 SCA findings showed rule_id "unknown" or empty, making
// suppression and mode overrides impossible.
// Fix: Generate OSV-CVE-*, OSV-GHSA-*, or OSV-VULN-* IDs.
// =============================================================================

func TestSCAFindingsHaveDeterministicRuleIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary-based test in -short mode")
	}

	g := newGoldenRepo(t)
	g.write("go.mod", `module testrepo

go 1.21

require github.com/fatih/color v1.7.0
`)
	g.write("main.go", `package main

import "fmt"

func main() {
    fmt.Println("hello")
}
`)
	g.commit("initial commit with vulnerable dep")

	binPath := buildPatchflowBinary(t)
	out := runPatchflowJSON(t, binPath, g.root, "scan", "run", "--json", "--quiet", "--offline")
	findings := extractFindingsFromJSON(t, out)

	scaCount := 0
	missingRuleID := 0
	for _, f := range findings {
		if f["type"] != "sca" {
			continue
		}
		scaCount++
		ruleID, _ := f["rule_id"].(string)
		if ruleID == "" || ruleID == "unknown" {
			missingRuleID++
			t.Errorf("SCA finding has missing/unknown rule_id: %+v", f)
		}
		// Verify it follows the OSV-* pattern
		if ruleID != "" && !strings.HasPrefix(ruleID, "OSV-") {
			t.Errorf("SCA finding rule_id %q doesn't follow OSV-* pattern", ruleID)
		}
	}

	if scaCount == 0 {
		t.Skip("no SCA findings (OSV DB may not be available)")
	}

	if missingRuleID > 0 {
		t.Errorf("%d/%d SCA findings have missing or 'unknown' rule_ids. "+
			"Deterministic rule IDs are required for suppression and mode overrides.",
			missingRuleID, scaCount)
	}

	t.Logf("All %d SCA findings have deterministic rule IDs", scaCount)
}

// =============================================================================
// JSON mode must not leak SAST diagnostic logs to stderr
//
// Bug: v0.1.5 SAST timing logs (e.g., "[sast] secrets-embedded total: 143ms")
// were written to stderr even in --json mode, breaking parseable output.
// Fix: Scanner diagnostics are no longer emitted on machine-readable paths;
// quiet and verbose JSON modes both keep stderr empty.
// =============================================================================

func TestJSONModeNoStderrLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary-based test in -short mode")
	}

	cleanRepo := newGoldenRepo(t)
	cleanRepo.write("README.md", "# clean fixture\n")
	cleanRepo.commit("initial clean repo")

	findingRepo := newGoldenRepo(t)
	findingRepo.write("app.js", `function run(input) {
    return eval(input);
}
module.exports = { run };
`)
	findingRepo.write("package.json", `{"name":"test","version":"1.0.0"}`)
	findingRepo.commit("initial vulnerable node repo")

	errorDir := t.TempDir()

	binPath := buildPatchflowBinary(t)

	testCases := []struct {
		name     string
		dir      string
		args     []string
		wantExit int
		wantKey  string
	}{
		{
			name:     "clean quiet",
			dir:      cleanRepo.root,
			args:     []string{"scan", "run", "--json", "--quiet", "--offline", "--no-licenses", "--no-reachability", "--fail-on", "low"},
			wantExit: 0,
			wantKey:  "analysis",
		},
		{
			name:     "findings quiet",
			dir:      findingRepo.root,
			args:     []string{"scan", "run", "--json", "--quiet", "--offline", "--no-licenses", "--no-reachability", "--fail-on", "low"},
			wantExit: 1,
			wantKey:  "analysis",
		},
		{
			name:     "findings verbose",
			dir:      findingRepo.root,
			args:     []string{"scan", "run", "--json", "--verbose", "--offline", "--no-licenses", "--no-reachability", "--fail-on", "low"},
			wantExit: 1,
			wantKey:  "analysis",
		},
		{
			name:     "runtime error quiet",
			dir:      errorDir,
			args:     []string{"scan", "run", "--json", "--quiet", "--offline", "--changed-only"},
			wantExit: 3,
			wantKey:  "error",
		},
		{
			name:     "runtime error verbose",
			dir:      errorDir,
			args:     []string{"scan", "run", "--json", "--verbose", "--offline", "--changed-only"},
			wantExit: 3,
			wantKey:  "error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, binPath, tc.args...)
			cmd.Dir = tc.dir
			var stdout, stderr strings.Builder
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			runErr := cmd.Run()
			if ctx.Err() == context.DeadlineExceeded {
				t.Fatal("JSON scan exceeded the 60-second per-test budget")
			}
			gotExit := 0
			if runErr != nil {
				var exitErr *exec.ExitError
				if !errors.As(runErr, &exitErr) {
					t.Fatalf("running PatchFlow: %v", runErr)
				}
				gotExit = exitErr.ExitCode()
			}
			if gotExit != tc.wantExit {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", gotExit, tc.wantExit, stdout.String(), stderr.String())
			}

			if got := strings.TrimSpace(stderr.String()); got != "" {
				t.Fatalf("JSON mode must keep stderr empty; got:\n%s", got)
			}

			decoder := json.NewDecoder(strings.NewReader(stdout.String()))
			var document map[string]interface{}
			if err := decoder.Decode(&document); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			var extra interface{}
			if err := decoder.Decode(&extra); err != io.EOF {
				t.Fatalf("stdout must contain exactly one JSON document; second decode returned %v", err)
			}
			if _, ok := document[tc.wantKey]; !ok {
				t.Fatalf("JSON document missing %q: %s", tc.wantKey, stdout.String())
			}
		})
	}
}

// =============================================================================
// SARIF output must be valid for GitHub Code Scanning
//
// GitHub Code Scanning requires:
// - $schema set to the SARIF 2.1.0 schema
// - runs[0].tool.driver.name set
// - runs[0].results[] have ruleId, message.text, locations[0].physicalLocation
// - runs[0].tool.driver.rules[] have id, name, shortDescription.text
// =============================================================================

func TestSARIFValidForGitHubCodeScanning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary-based test in -short mode")
	}

	g := newGoldenRepo(t)
	g.write("app.js", `function run(input) {
    return eval(input);
}
module.exports = { run };
`)
	g.write("package.json", `{"name":"test","version":"1.0.0"}`)
	g.commit("initial node repo with eval")

	binPath := buildPatchflowBinary(t)

	// Generate SARIF output
	outputFile := filepath.Join(g.root, "results.sarif")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "scan", "run", "--format", "sarif", "--output", outputFile, "--offline")
	cmd.Dir = g.root
	_ = cmd.Run() // non-zero exit is expected with findings
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatal("SARIF scan exceeded the 60-second per-test budget")
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("SARIF file not generated: %v", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	// Check $schema
	schema, ok := sarif["$schema"].(string)
	if !ok || schema == "" {
		t.Error("missing $schema field — GitHub Code Scanning requires this")
	}

	// Check runs
	runs, ok := sarif["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("missing or empty runs array — GitHub Code Scanning requires at least one run")
	}

	run, ok := runs[0].(map[string]interface{})
	if !ok {
		t.Fatal("runs[0] is not an object")
	}

	// Check tool.driver.name
	tool, _ := run["tool"].(map[string]interface{})
	driver, _ := tool["driver"].(map[string]interface{})
	driverName, _ := driver["name"].(string)
	if driverName == "" {
		t.Error("missing tool.driver.name — GitHub Code Scanning requires this")
	}

	// SARIF 2.1.0 requires executionSuccessful on every invocation.
	invocations, _ := run["invocations"].([]interface{})
	if len(invocations) == 0 {
		t.Error("missing invocations — scan provenance and execution status are required")
	} else {
		invocation, _ := invocations[0].(map[string]interface{})
		if _, ok := invocation["executionSuccessful"].(bool); !ok {
			t.Error("missing boolean invocations[0].executionSuccessful — invalid SARIF 2.1.0")
		}
	}

	// Check rules have required fields
	rules, _ := driver["rules"].([]interface{})
	for i, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			t.Errorf("rule[%d] is not an object", i)
			continue
		}
		id, _ := rule["id"].(string)
		if id == "" {
			t.Errorf("rule[%d] missing id", i)
		}
		name, _ := rule["name"].(string)
		if name == "" {
			t.Errorf("rule[%d] missing name", i)
		}
		shortDesc, _ := rule["shortDescription"].(map[string]interface{})
		if shortDesc == nil {
			t.Errorf("rule[%d] missing shortDescription", i)
		} else if text, _ := shortDesc["text"].(string); text == "" {
			t.Errorf("rule[%d] missing shortDescription.text", i)
		}
	}

	// Check results have required fields
	results, _ := run["results"].([]interface{})
	issueCount := 0
	for i, r := range results {
		result, ok := r.(map[string]interface{})
		if !ok {
			t.Errorf("result[%d] is not an object", i)
			continue
		}
		ruleID, _ := result["ruleId"].(string)
		if ruleID == "" {
			t.Errorf("result[%d] missing ruleId", i)
			issueCount++
		}
		msg, _ := result["message"].(map[string]interface{})
		if msg == nil {
			t.Errorf("result[%d] missing message", i)
			issueCount++
		} else if text, _ := msg["text"].(string); text == "" {
			t.Errorf("result[%d] missing message.text", i)
			issueCount++
		}
		locs, _ := result["locations"].([]interface{})
		if len(locs) == 0 {
			t.Errorf("result[%d] missing locations", i)
			issueCount++
		}
	}

	if issueCount > 0 {
		t.Errorf("%d SARIF result field issues — GitHub Code Scanning may reject this file", issueCount)
	} else {
		t.Logf("SARIF valid for GitHub Code Scanning: %d rules, %d results", len(rules), len(results))
	}
}

// =============================================================================
// Helpers
// =============================================================================

// buildPatchflowBinary builds the patchflow CLI binary into a temp dir.
func buildPatchflowBinary(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "patchflow")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	// Use the project root relative to this test file
	build.Dir = projectRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build patchflow: %v\n%s", err, out)
	}
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatal("building patchflow exceeded the 60-second per-test budget")
	}
	return binPath
}

// projectRoot returns the patchflow-cli project root directory.
func projectRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the test file to find go.mod
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find project root (go.mod)")
	return ""
}

// runPatchflowJSON runs patchflow with given args and returns parsed JSON output.
func runPatchflowJSON(t *testing.T, binPath, repoDir string, args ...string) map[string]interface{} {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		// Non-zero exit is expected when findings are present with --fail-on
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Stdout is captured in out even on non-zero exit (cmd.Output
			// returns it before the error)
			if len(out) == 0 {
				t.Fatalf("patchflow exited with code %d and no stdout: %v",
					exitErr.ExitCode(), err)
			}
		} else {
			t.Fatalf("failed to run patchflow: %v", err)
		}
	}
	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v\nraw: %s", err, string(out))
	}
	return result
}

// extractFindingsFromJSON pulls the findings array from the scan run JSON.
func extractFindingsFromJSON(t *testing.T, result map[string]interface{}) []map[string]interface{} {
	t.Helper()
	analysisRaw, ok := result["analysis"]
	if !ok {
		// Some outputs put findings at top level
		findingsRaw, ok := result["findings"]
		if !ok {
			t.Fatalf("no 'analysis' or 'findings' key in JSON output. Keys: %v", mapKeys(result))
		}
		findings, ok := findingsRaw.([]interface{})
		if !ok {
			t.Fatal("findings is not an array")
		}
		return toFindingMaps(findings)
	}
	analysis, ok := analysisRaw.(map[string]interface{})
	if !ok {
		t.Fatal("analysis is not an object")
	}
	findingsRaw, ok := analysis["findings"]
	if !ok {
		t.Fatalf("no findings key in analysis. Keys: %v", mapKeys(analysis))
	}
	findings, ok := findingsRaw.([]interface{})
	if !ok {
		t.Fatal("findings is not an array")
	}
	return toFindingMaps(findings)
}

func toFindingMaps(findings []interface{}) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		if m, ok := f.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// countFindingsByType counts findings of a specific type (e.g., "sca").
func countFindingsByType(findings []map[string]interface{}, findingType string) int {
	count := 0
	for _, f := range findings {
		if t, ok := f["type"].(string); ok && t == findingType {
			count++
		}
	}
	return count
}

// runScanWithRunner runs the in-process SAST runner (for quick tests that
// don't need the full CLI binary).
func runScanWithRunner(t *testing.T, root string) []analysis.Finding {
	t.Helper()
	runner := sast.NewRunner()
	runner.RespectGitignore = true
	runner.Timeout = 60 * time.Second
	runner.Tools = nil
	result, err := runner.Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("SAST Analyze failed: %v", err)
	}
	analysis.PopulateFingerprints(result.Findings)
	return result.Findings
}
