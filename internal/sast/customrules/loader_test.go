package customrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

func TestLoadFromBytes_ValidRules(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-001
    title: No console.log in production
    description: console.log should not be used in production code
    languages: [javascript, typescript]
    pattern: 'console\.log\s*\('
    severity: low
    confidence: high

  - id: CUSTOM-002
    title: Raw SQL with string interpolation
    description: SQL injection risk via string formatting
    languages: [python]
    pattern: 'cursor\.execute\(.*%.*'
    severity: high
    confidence: medium
`)

	rules, err := LoadFromBytes(yamlData)
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].ID != "CUSTOM-001" {
		t.Errorf("rule[0] ID = %q, want CUSTOM-001", rules[0].ID)
	}
	if rules[0].Title != "No console.log in production" {
		t.Errorf("rule[0] Title = %q", rules[0].Title)
	}
	if len(rules[0].Languages) != 2 {
		t.Errorf("rule[0] Languages len = %d, want 2", len(rules[0].Languages))
	}
	if rules[0].Pattern == nil {
		t.Errorf("rule[0] Pattern should be compiled")
	}

	if rules[1].ID != "CUSTOM-002" {
		t.Errorf("rule[1] ID = %q, want CUSTOM-002", rules[1].ID)
	}
}

func TestLoadFromBytes_MissingID(t *testing.T) {
	yamlData := []byte(`
rules:
  - title: Missing ID
    pattern: 'something'
    languages: [python]
`)
	_, err := LoadFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestLoadFromBytes_MissingPattern(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-003
    title: No pattern
    languages: [python]
`)
	_, err := LoadFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for missing pattern")
	}
}

func TestLoadFromBytes_InvalidRegex(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-004
    title: Bad regex
    pattern: '[invalid('
    languages: [python]
`)
	_, err := LoadFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestLoadFromBytes_UnsupportedLanguage(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-005
    title: Bad language
    pattern: 'something'
    languages: [cobol]
`)
	_, err := LoadFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for unsupported language")
	}
}

func TestLoadFromBytes_NoLanguages(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-006
    title: No languages
    pattern: 'something'
`)
	_, err := LoadFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for missing languages")
	}
}

func TestLoadFromBytes_DefaultSeverity(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-007
    title: Default severity
    pattern: 'something'
    languages: [python]
`)
	rules, err := LoadFromBytes(yamlData)
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}
	// Default severity should be medium
	if rules[0].Severity != "medium" {
		t.Errorf("default severity = %q, want medium", rules[0].Severity)
	}
}

func TestLoadFromDir_FileExists(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, ".patchflow")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rulesPath := filepath.Join(rulesDir, "rules.yaml")
	yamlData := []byte(`
rules:
  - id: CUSTOM-001
    title: Test rule
    pattern: 'test'
    languages: [python]
`)
	if err := os.WriteFile(rulesPath, yamlData, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rules, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDir failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestLoadFromDir_FileNotExists(t *testing.T) {
	dir := t.TempDir()
	rules, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDir should not error when file doesn't exist: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	yamlData := []byte(`
rules:
  - id: CUSTOM-001
    title: File test
    pattern: 'test'
    languages: [ruby]
`)
	if err := os.WriteFile(path, yamlData, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rules, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Languages[0] != "ruby" {
		t.Errorf("language = %q, want ruby", rules[0].Languages[0])
	}
}

func TestParseLanguage_AllLanguages(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"python", "python"},
		{"py", "python"},
		{"javascript", "javascript"},
		{"js", "javascript"},
		{"typescript", "typescript"},
		{"ts", "typescript"},
		{"ruby", "ruby"},
		{"rb", "ruby"},
		{"php", "php"},
		// Languages added to match docs/reference/yaml-policy.md (12 total).
		{"java", "java"},
		{"csharp", "csharp"},
		{"c_sharp", "csharp"},
		{"c#", "csharp"},
		{"go", "go"},
		{"golang", "go"},
		{"rust", "rust"},
		{"rs", "rust"},
		{"yaml", "yaml"},
		{"yml", "yaml"},
		{"dockerfile", "dockerfile"},
		{"docker", "dockerfile"},
		{"terraform", "terraform"},
		{"tf", "terraform"},
		{"hcl", "terraform"},
	}
	for _, tt := range tests {
		got, err := parseLanguage(tt.input)
		if err != nil {
			t.Errorf("parseLanguage(%q) error: %v", tt.input, err)
		}
		if string(got) != tt.want {
			t.Errorf("parseLanguage(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestLoadPolicyFromBytes_FrameworkSelectionAndOverrides(t *testing.T) {
	yamlData := []byte(`
frameworks:
  auto_detect: false
  enabled: [express, react]
  disabled: [spring]

framework_overrides:
  express:
    custom_sources:
      - func: req.headers
    custom_sinks:
      - func: res.redirect
        arg_index: 0
    custom_sanitizers:
      - func: isSafeRedirect
      - regex: 'allowlistedHost\('
    severity_overrides:
      PF-EXPRESS-REDIRECT-001: high
`)

	policy, err := LoadPolicyFromBytes(yamlData)
	if err != nil {
		t.Fatalf("LoadPolicyFromBytes failed: %v", err)
	}
	if policy.FrameworkSelection.AutoDetect {
		t.Fatal("expected auto_detect=false")
	}
	if !policy.FrameworkSelection.AutoDetectSet {
		t.Fatal("expected AutoDetectSet=true")
	}
	if len(policy.FrameworkSelection.Enabled) != 2 {
		t.Fatalf("expected 2 enabled frameworks, got %d", len(policy.FrameworkSelection.Enabled))
	}
	override, ok := policy.FrameworkOverrides["express"]
	if !ok {
		t.Fatal("expected express override")
	}
	if len(override.Sources) != 1 || override.Sources[0].FuncName != "req.headers" {
		t.Fatalf("unexpected sources: %+v", override.Sources)
	}
	if len(override.Sinks) != 1 || override.Sinks[0].FuncName != "res.redirect" {
		t.Fatalf("unexpected sinks: %+v", override.Sinks)
	}
	if len(override.Sanitizers) != 2 {
		t.Fatalf("expected 2 sanitizers, got %d", len(override.Sanitizers))
	}
	if got := override.SeverityOverrides["PF-EXPRESS-REDIRECT-001"]; got != analysis.SeverityHigh {
		t.Fatalf("severity override = %q, want high", got)
	}
}

func TestLoadPolicyFromBytes_InvalidFrameworkOverrideSeverity(t *testing.T) {
	yamlData := []byte(`
framework_overrides:
  express:
    severity_overrides:
      PF-EXPRESS-REDIRECT-001: urgent
`)

	_, err := LoadPolicyFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for invalid framework severity override")
	}
}

func TestLoadPolicyFromBytes_TaintRules(t *testing.T) {
	yamlData := []byte(`
taint_rules:
  - id: CUSTOM-TAINT-001
    title: Django raw SQL with user input
    description: Raw SQL query with user-controlled input
    language: python
    severity: high
    confidence: medium
    cwe: CWE-89
    taint:
      sources:
        - func: request.GET
          subscript: true
        - func: request.POST
          subscript: true
      sinks:
        - func: RawSQL
          arg: 0
      sanitizers:
        - func: quote
`)

	policy, err := LoadPolicyFromBytes(yamlData)
	if err != nil {
		t.Fatalf("LoadPolicyFromBytes failed: %v", err)
	}
	if len(policy.TaintRules) != 1 {
		t.Fatalf("expected 1 taint rule, got %d", len(policy.TaintRules))
	}
	tr := policy.TaintRules[0]
	if tr.ID != "CUSTOM-TAINT-001" {
		t.Errorf("ID = %q, want CUSTOM-TAINT-001", tr.ID)
	}
	if tr.Language != "python" {
		t.Errorf("Language = %q, want python", tr.Language)
	}
	if tr.CWEID != "CWE-89" {
		t.Errorf("CWEID = %q, want CWE-89", tr.CWEID)
	}
	if len(tr.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(tr.Sources))
	}
	if tr.Sources[0].FuncName != "request.GET" {
		t.Errorf("source[0] FuncName = %q", tr.Sources[0].FuncName)
	}
	if !tr.Sources[0].IsSubscript {
		t.Error("source[0] should be subscript")
	}
	if len(tr.Sinks) != 1 {
		t.Fatalf("expected 1 sink, got %d", len(tr.Sinks))
	}
	if tr.Sinks[0].FuncName != "RawSQL" {
		t.Errorf("sink[0] FuncName = %q", tr.Sinks[0].FuncName)
	}
	if tr.Sinks[0].ArgIndex != 0 {
		t.Errorf("sink[0] ArgIndex = %d, want 0", tr.Sinks[0].ArgIndex)
	}
	if len(tr.Sanitizers) != 1 {
		t.Fatalf("expected 1 sanitizer, got %d", len(tr.Sanitizers))
	}
	if tr.Severity != analysis.SeverityHigh {
		t.Errorf("Severity = %q, want high", tr.Severity)
	}
}

func TestLoadPolicyFromBytes_TaintRuleMissingSources(t *testing.T) {
	yamlData := []byte(`
taint_rules:
  - id: CUSTOM-TAINT-002
    title: Missing sources
    language: python
    taint:
      sinks:
        - func: execute
`)
	_, err := LoadPolicyFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for taint rule with no sources")
	}
}

func TestLoadPolicyFromBytes_TaintRuleMissingSinks(t *testing.T) {
	yamlData := []byte(`
taint_rules:
  - id: CUSTOM-TAINT-003
    title: Missing sinks
    language: python
    taint:
      sources:
        - func: request.GET
`)
	_, err := LoadPolicyFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for taint rule with no sinks")
	}
}

func TestLoadPolicyFromBytes_TaintRuleUnsupportedLanguage(t *testing.T) {
	yamlData := []byte(`
taint_rules:
  - id: CUSTOM-TAINT-004
    title: Bad language
    language: cobol
    taint:
      sources:
        - func: INPUT
      sinks:
        - func: EXECUTE
`)
	_, err := LoadPolicyFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for unsupported taint language")
	}
}

func TestLoadPolicyFromBytes_TaintRuleInvalidFuncName(t *testing.T) {
	yamlData := []byte(`
taint_rules:
  - id: CUSTOM-TAINT-005
    title: Regex in func name
    language: python
    taint:
      sources:
        - func: "request.*"
      sinks:
        - func: execute
`)
	_, err := LoadPolicyFromBytes(yamlData)
	if err == nil {
		t.Fatal("expected error for regex chars in source func name")
	}
}

func TestLoadPolicyFromBytes_MixedRules(t *testing.T) {
	yamlData := []byte(`
rules:
  - id: CUSTOM-REGEX-001
    title: No eval
    pattern: 'eval\s*\('
    languages: [python]
    severity: high
    confidence: medium

taint_rules:
  - id: CUSTOM-TAINT-001
    title: SQL injection
    language: javascript
    severity: high
    confidence: high
    cwe: CWE-89
    taint:
      sources:
        - func: req.query
      sinks:
        - func: db.query
          arg: 0
`)

	policy, err := LoadPolicyFromBytes(yamlData)
	if err != nil {
		t.Fatalf("LoadPolicyFromBytes failed: %v", err)
	}
	if len(policy.PatternRules) != 1 {
		t.Fatalf("expected 1 pattern rule, got %d", len(policy.PatternRules))
	}
	if len(policy.TaintRules) != 1 {
		t.Fatalf("expected 1 taint rule, got %d", len(policy.TaintRules))
	}
	// Verify backward compat: regex rules still work
	if policy.PatternRules[0].ID != "CUSTOM-REGEX-001" {
		t.Errorf("pattern rule ID = %q", policy.PatternRules[0].ID)
	}
}
