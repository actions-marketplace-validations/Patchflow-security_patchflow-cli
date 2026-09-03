package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/risk"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed testdata/sarif-schema-2.1.0.json
var sarifSchemaJSON []byte

func TestTerminalSummary(t *testing.T) {
	result := &analysis.AnalysisResult{
		ProjectRoot:  "/test/repo",
		Branch:       "main",
		CommitSHA:    "abc123def456",
		BaseBranch:   "develop",
		FilesChanged: 5,
		AddedLines:   100,
		DeletedLines: 20,
		Dependencies: []analysis.Dependency{{Name: "test-pkg", Version: "1.0.0"}},
		Manifests:    []string{"go.mod"},
		Analyzers:    []string{"osv"},
	}

	riskScore := &risk.ScoreOutput{
		Score:              45,
		Level:              "medium",
		FindingsBySeverity: map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 0},
		TopFindings: []analysis.Finding{
			{Title: "Test finding", Severity: analysis.SeverityHigh, PackageName: "test-pkg"},
		},
	}

	gen := NewGenerator(result, riskScore)
	summary := gen.TerminalSummary()

	if !strings.Contains(summary, "PatchFlow Analysis Report") {
		t.Error("summary should contain title")
	}
	if !strings.Contains(summary, "/test/repo") {
		t.Error("summary should contain repo root")
	}
	if !strings.Contains(summary, "45/100") {
		t.Error("summary should contain risk score")
	}
	if !strings.Contains(summary, "MEDIUM") {
		t.Error("summary should contain risk level")
	}
}

func TestMarkdown(t *testing.T) {
	result := &analysis.AnalysisResult{
		ProjectRoot: "/test/repo",
		Branch:      "main",
		CommitSHA:   "abc123",
		Findings: []analysis.Finding{
			{
				Title:          "Test vulnerability",
				Type:           analysis.TypeSCA,
				Severity:       analysis.SeverityHigh,
				PackageName:    "vuln-pkg",
				PackageVersion: "1.0.0",
				FixedVersion:   "2.0.0",
				CVEID:          "CVE-2024-1234",
			},
		},
		Dependencies: []analysis.Dependency{{Name: "test-pkg", Version: "1.0.0"}},
	}

	riskScore := &risk.ScoreOutput{
		Score:              60,
		Level:              "high",
		FindingsBySeverity: map[string]int{"high": 1},
	}

	gen := NewGenerator(result, riskScore)
	md := gen.Markdown()

	if !strings.Contains(md, "# PatchFlow Analysis Report") {
		t.Error("markdown should contain title")
	}
	if !strings.Contains(md, "Test vulnerability") {
		t.Error("markdown should contain finding title")
	}
	if !strings.Contains(md, "CVE-2024-1234") {
		t.Error("markdown should contain CVE ID")
	}
	if !strings.Contains(md, "vuln-pkg") {
		t.Error("markdown should contain package name")
	}
	if !strings.Contains(md, "2.0.0") {
		t.Error("markdown should contain fixed version")
	}
}

func TestJSON(t *testing.T) {
	result := &analysis.AnalysisResult{
		ProjectRoot: "/test/repo",
		Findings: []analysis.Finding{
			{Title: "Test", Severity: analysis.SeverityMedium},
		},
	}

	riskScore := &risk.ScoreOutput{Score: 30, Level: "low"}

	gen := NewGenerator(result, riskScore)
	data, err := gen.JSON()
	if err != nil {
		t.Fatalf("JSON failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if parsed["generated"] == nil {
		t.Error("JSON should contain generated field")
	}
	if parsed["analysis"] == nil {
		t.Error("JSON should contain analysis field")
	}
	if parsed["result"] != nil {
		t.Error("JSON should not use legacy result field")
	}
}

func TestRecommendationsDoNotClaimSafeWhenHighFindingsExist(t *testing.T) {
	result := &analysis.AnalysisResult{
		Findings: []analysis.Finding{
			{Title: "High finding", Severity: analysis.SeverityHigh},
		},
	}
	riskScore := &risk.ScoreOutput{Score: 80, Level: "critical"}

	gen := NewGenerator(result, riskScore)
	recs := gen.GenerateRecommendationsPublic()

	joined := strings.Join(recs, "\n")
	if strings.Contains(joined, "No critical issues detected") {
		t.Fatalf("recommendations should not claim safe on blocking risk: %v", recs)
	}
	if !strings.Contains(joined, "high-severity") {
		t.Fatalf("expected high severity recommendation, got %v", recs)
	}
}

func TestSARIF(t *testing.T) {
	result := &analysis.AnalysisResult{
		Findings: []analysis.Finding{
			{
				Title:     "SQL injection",
				Severity:  analysis.SeverityHigh,
				FilePath:  "src/main.go",
				LineStart: 42,
				RuleID:    "GO-SQL-INJECTION",
			},
		},
	}

	gen := NewGenerator(result, nil)
	report := gen.SARIF("1.0.0")

	if report.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}
	if report.Runs[0].Tool.Driver.Name != "PatchFlow CLI" {
		t.Error("wrong tool name")
	}
	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Runs[0].Results))
	}

	r := report.Runs[0].Results[0]
	if r.RuleID != "GO-SQL-INJECTION" {
		t.Errorf("wrong rule ID: %s", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("high severity should map to error level, got %s", r.Level)
	}
	if len(r.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r.Locations))
	}
	if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "src/main.go" {
		t.Error("wrong file path in SARIF")
	}
}

func TestGroupSCAFindings(t *testing.T) {
	findings := []analysis.Finding{
		{
			ID:                     "sca-npm-next-GHSA-1",
			Type:                   analysis.TypeSCA,
			Severity:               analysis.SeverityMedium,
			Title:                  "next@16.0.10: GHSA-1",
			PackageName:            "next",
			PackageVersion:         "16.0.10",
			FilePath:               "package.json",
			Reachability:           analysis.ReachabilityHigh,
			ReachabilityConfidence: analysis.ConfidenceHigh,
		},
		{
			ID:                     "sca-npm-next-GHSA-2",
			Type:                   analysis.TypeSCA,
			Severity:               analysis.SeverityMedium,
			Title:                  "next@16.0.10: GHSA-2",
			PackageName:            "next",
			PackageVersion:         "16.0.10",
			FilePath:               "package.json",
			Reachability:           analysis.ReachabilityHigh,
			ReachabilityConfidence: analysis.ConfidenceHigh,
		},
		{
			ID:                     "sca-npm-vite-GHSA-3",
			Type:                   analysis.TypeSCA,
			Severity:               analysis.SeverityMedium,
			Title:                  "vite@8.0.12: GHSA-3",
			PackageName:            "vite",
			PackageVersion:         "8.0.12",
			FilePath:               "package.json",
			Reachability:           analysis.ReachabilityHigh,
			ReachabilityConfidence: analysis.ConfidenceHigh,
		},
		{
			ID:        "sast-1",
			Type:      analysis.TypeSAST,
			Severity:  analysis.SeverityHigh,
			Title:     "SQL injection",
			FilePath:  "src/main.go",
			LineStart: 42,
		},
	}

	grouped, groups := GroupSCAFindings(findings)
	if len(groups) != 2 {
		t.Fatalf("expected 2 package groups, got %d", len(groups))
	}
	if len(grouped) != 3 { // 2 SCA groups + 1 SAST
		t.Fatalf("expected 3 grouped findings, got %d", len(grouped))
	}

	// Verify next group collapsed two advisories into one finding.
	var nextGroup *analysis.Finding
	for i := range grouped {
		if grouped[i].PackageName == "next" {
			nextGroup = &grouped[i]
			break
		}
	}
	if nextGroup == nil {
		t.Fatal("expected a grouped next finding")
	}
	if !strings.Contains(nextGroup.Title, "2 advisories") {
		t.Errorf("expected grouped title to mention 2 advisories, got %q", nextGroup.Title)
	}
	if nextGroup.ReachabilityConfidence != analysis.ConfidenceHigh {
		t.Errorf("expected reachability confidence to be preserved, got %q", nextGroup.ReachabilityConfidence)
	}
	if !strings.Contains(nextGroup.Description, "GHSA-1") || !strings.Contains(nextGroup.Description, "GHSA-2") {
		t.Errorf("expected grouped description to list both advisories, got %q", nextGroup.Description)
	}

	// Verify package summary table contains the packages.
	table := packageSummaryTable(groups)
	if !strings.Contains(table, "next") {
		t.Error("package summary table should contain next")
	}
	if !strings.Contains(table, "vite") {
		t.Error("package summary table should contain vite")
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		sev   analysis.Severity
		level string
	}{
		{analysis.SeverityCritical, "error"},
		{analysis.SeverityHigh, "error"},
		{analysis.SeverityMedium, "warning"},
		{analysis.SeverityLow, "note"},
		{analysis.SeverityInfo, "note"},
	}
	for _, tt := range tests {
		if got := severityToSARIFLevel(tt.sev); got != tt.level {
			t.Errorf("severityToSARIFLevel(%s) = %s, want %s", tt.sev, got, tt.level)
		}
	}
}

func TestJSONIncludesScanMetadataAndFingerprints(t *testing.T) {
	findings := []analysis.Finding{
		{
			Type:      analysis.TypeSAST,
			Analyzer:  "gosast-embedded",
			RuleID:    "G104",
			FilePath:  "app/handler.go",
			LineStart: 10,
			Evidence:  "http.Get(url)",
			Title:     "Errors unhandled",
			Severity:  analysis.SeverityMedium,
		},
	}
	analysis.PopulateFingerprints(findings)

	result := &analysis.AnalysisResult{
		ScanID:      "test-scan-123",
		ProjectRoot: "/test/repo",
		Branch:      "main",
		CommitSHA:   "abc123",
		Findings:    findings,
		Profile:     "standard",
		Mode:        "changed",
		Baseline:    "v1.0",
		NewOnly:     true,
		SinceRef:    "main",
		Version:     "0.1.0",
		Duration:    1500 * time.Millisecond,
		ExitCode:    0,
	}
	riskScore := &risk.ScoreOutput{Score: 30, Level: "low"}

	gen := NewGenerator(result, riskScore)
	data, err := gen.JSON()
	if err != nil {
		t.Fatalf("JSON failed: %v", err)
	}
	s := string(data)

	// Scan metadata (MarshalIndent adds a space after the colon)
	for _, want := range []string{`"scan_id": "test-scan-123"`, `"profile": "standard"`, `"mode": "changed"`, `"baseline": "v1.0"`, `"new_only": true`, `"since_ref": "main"`, `"version": "0.1.0"`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON report missing scan metadata %s", want)
		}
	}
	// Fingerprints on findings
	if !strings.Contains(s, `"semantic_fingerprint"`) {
		t.Error("JSON report should include semantic_fingerprint on findings")
	}
	if !strings.Contains(s, `"location_fingerprint"`) {
		t.Error("JSON report should include location_fingerprint on findings")
	}
}

func TestSARIFIncludesFingerprintsAndScanMeta(t *testing.T) {
	findings := []analysis.Finding{
		{
			Type:      analysis.TypeSAST,
			Analyzer:  "gosast-embedded",
			RuleID:    "G104",
			FilePath:  "app/handler.go",
			LineStart: 10,
			Evidence:  "http.Get(url)",
			Title:     "Errors unhandled",
			Severity:  analysis.SeverityMedium,
		},
	}
	analysis.PopulateFingerprints(findings)

	result := &analysis.AnalysisResult{
		ScanID:      "sarif-scan-1",
		ProjectRoot: "/test/repo",
		Profile:     "deep",
		Mode:        "since",
		SinceRef:    "main",
		Version:     "0.1.0",
		Findings:    findings,
	}
	riskScore := &risk.ScoreOutput{Score: 40, Level: "medium"}

	gen := NewGenerator(result, riskScore)
	sarif := gen.SARIF("0.1.0")
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	r := run.Results[0]
	if r.Properties == nil {
		t.Fatal("SARIF result should have properties")
	}
	if r.Properties.SemanticFingerprint == "" {
		t.Error("SARIF result properties should include semantic_fingerprint")
	}
	if r.Properties.LocationFingerprint == "" {
		t.Error("SARIF result properties should include location_fingerprint")
	}
	// Invocation with scan metadata
	if len(run.Invocations) != 1 {
		t.Fatalf("expected 1 invocation, got %d", len(run.Invocations))
	}
	inv := run.Invocations[0]
	if !inv.ExecutionSuccessful {
		t.Fatal("completed SARIF invocation should set executionSuccessful=true")
	}
	if inv.Properties == nil {
		t.Fatal("SARIF invocation should have properties")
	}
	if inv.Properties.ScanID != "sarif-scan-1" {
		t.Errorf("expected scan_id sarif-scan-1, got %s", inv.Properties.ScanID)
	}
	if inv.Properties.Mode != "since" {
		t.Errorf("expected mode since, got %s", inv.Properties.Mode)
	}
	if inv.Properties.SinceRef != "main" {
		t.Errorf("expected since_ref main, got %s", inv.Properties.SinceRef)
	}
}

func TestSARIFInvocationReportsExecutionFailure(t *testing.T) {
	result := &analysis.AnalysisResult{ExitCode: 3}
	run := NewGenerator(result, nil).SARIF("test").Runs[0]
	if len(run.Invocations) != 1 {
		t.Fatalf("expected 1 invocation, got %d", len(run.Invocations))
	}
	if run.Invocations[0].ExecutionSuccessful {
		t.Fatal("internal-error exit code should set executionSuccessful=false")
	}
}

func TestSARIFScenarioMatrixValidatesAgainstOfficialSchema(t *testing.T) {
	schemaDocument, err := jsonschema.UnmarshalJSON(bytes.NewReader(sarifSchemaJSON))
	if err != nil {
		t.Fatalf("parse embedded OASIS SARIF schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft4)
	const schemaLocation = "https://patchflow.dev/test/sarif-schema-2.1.0.json"
	if err := compiler.AddResource(schemaLocation, schemaDocument); err != nil {
		t.Fatalf("add OASIS SARIF schema: %v", err)
	}
	schema, err := compiler.Compile(schemaLocation)
	if err != nil {
		t.Fatalf("compile OASIS SARIF schema: %v", err)
	}

	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	makeFinding := func(i int) analysis.Finding {
		return analysis.Finding{
			Type:      analysis.TypeSAST,
			Analyzer:  "contract-test",
			RuleID:    "PF-CONTRACT",
			Title:     "Contract finding",
			Severity:  analysis.SeverityHigh,
			FilePath:  "src/app.go",
			LineStart: i + 1,
		}
	}
	findingHeavy := make([]analysis.Finding, 100)
	for i := range findingHeavy {
		findingHeavy[i] = makeFinding(i)
	}

	for _, tc := range []struct {
		name                string
		result              *analysis.AnalysisResult
		executionSuccessful bool
		wantResults         int
	}{
		{
			name:                "empty",
			result:              &analysis.AnalysisResult{StartedAt: now, CompletedAt: now, ExitCode: 0},
			executionSuccessful: true,
		},
		{
			name:                "clean",
			result:              &analysis.AnalysisResult{ScanID: "clean", Version: "test", StartedAt: now, CompletedAt: now.Add(time.Second), Findings: []analysis.Finding{}, ExitCode: 0},
			executionSuccessful: true,
		},
		{
			name:                "finding-heavy",
			result:              &analysis.AnalysisResult{ScanID: "findings", Version: "test", StartedAt: now, CompletedAt: now.Add(time.Second), Findings: findingHeavy, ExitCode: 1},
			executionSuccessful: true,
			wantResults:         len(findingHeavy),
		},
		{
			name:                "failed",
			result:              &analysis.AnalysisResult{ScanID: "failed", Version: "test", StartedAt: now, CompletedAt: now.Add(time.Second), ExitCode: 3},
			executionSuccessful: false,
		},
		{
			name:                "partial",
			result:              &analysis.AnalysisResult{ScanID: "partial", Version: "test", StartedAt: now, CompletedAt: now.Add(time.Second), Findings: []analysis.Finding{makeFinding(0)}, ExitCode: 2},
			executionSuccessful: false,
			wantResults:         1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := NewGenerator(tc.result, nil).SARIF("test")
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatalf("marshal SARIF: %v", err)
			}
			var document any
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatalf("decode SARIF for schema validator: %v", err)
			}
			if err := schema.Validate(document); err != nil {
				t.Fatalf("SARIF does not conform to the official OASIS 2.1.0 schema: %v", err)
			}
			run := report.Runs[0]
			if len(run.Results) != tc.wantResults {
				t.Fatalf("results = %d, want %d", len(run.Results), tc.wantResults)
			}
			if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful != tc.executionSuccessful {
				t.Fatalf("executionSuccessful = %v, want %v", run.Invocations, tc.executionSuccessful)
			}
		})
	}
}

func TestMarkdownIncludesScanMetadata(t *testing.T) {
	result := &analysis.AnalysisResult{
		ScanID:      "md-scan-1",
		ProjectRoot: "/test/repo",
		Branch:      "main",
		CommitSHA:   "abc123",
		Profile:     "standard",
		Mode:        "changed",
		Baseline:    "v1.0",
		NewOnly:     true,
		SinceRef:    "main",
		Version:     "0.1.0",
		Duration:    1500 * time.Millisecond,
	}
	riskScore := &risk.ScoreOutput{Score: 30, Level: "low"}

	gen := NewGenerator(result, riskScore)
	md := gen.Markdown()

	for _, want := range []string{"md-scan-1", "standard", "changed", "v1.0", "main", "0.1.0"} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown report missing scan metadata: %s", want)
		}
	}
}
