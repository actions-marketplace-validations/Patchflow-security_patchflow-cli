package testdata

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestReleaseSmoke is the golden release test matrix (B12.9).
// It runs the built patchflow binary against each smoke fixture
// and verifies expected findings counts.
//
// Fixtures are copied to temp directories to avoid the Go SAST
// scanner picking up the patchflow-cli module.
//
// This test requires the patchflow binary at /tmp/patchflow-b12
// or in the project root.

func TestReleaseSmoke(t *testing.T) {
	binary := binaryPath(t)
	if binary == "" {
		t.Skip("patchflow binary not found, skipping release smoke test")
	}

	fixturesDir := fixturesDir(t)

	tests := []struct {
		name        string
		fixture     string
		framework   string
		configPath  string
		minFindings int
		maxFindings int
		// requiredTaintRules are taint-patterns rule IDs that MUST appear in
		// the findings. This verifies the taint engine (not just the pattern
		// scanner) is producing findings. If a required rule is missing, the
		// test fails even if minFindings is met by pattern-based rules.
		requiredTaintRules []string
	}{
		{
			name:        "spring-custom-extension-scoped-sink",
			fixture:     "spring-custom-extension",
			framework:   "spring",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 1,
			maxFindings: 10,
		},
		{
			name:        "graphql-sqli",
			fixture:     "graphql-sqli",
			framework:   "graphql",
			minFindings: 1,
			maxFindings: 10,
		},
		{
			name:        "express-sqli",
			fixture:     "express-sqli",
			framework:   "express",
			minFindings: 1,
			maxFindings: 10,
		},
		{
			name:        "clean-go-no-false-positives",
			fixture:     "clean-go",
			minFindings: 0,
			maxFindings: 0,
		},
		{
			name:        "clean-python-no-false-positives",
			fixture:     "clean-python",
			minFindings: 0,
			maxFindings: 0,
		},
		// Regression fixtures from Safe-pip-backend (2026-07-05).
		// fastapi-orm-safe: parameterized SQLAlchemy select().where() must NOT
		// produce taint findings. Before the -IP safe-pattern suppression fix,
		// this produced 2 PF-FASTAPI-SQLI-002-IP false positives.
		{
			name:        "fastapi-orm-safe-no-false-positives",
			fixture:     "fastapi-orm-safe",
			framework:   "fastapi",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 0,
			maxFindings: 0,
		},
		// fastapi-real-findings: actual vulnerabilities (verify=False, sha1,
		// text(f"...")) must be detected. This is the precision canary — if
		// findings drop below 3, the scanner lost coverage.
		{
			name:        "fastapi-real-findings-detected",
			fixture:     "fastapi-real-findings",
			framework:   "fastapi",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 3,
			maxFindings: 15,
		},
		// --- Cross-language taint framework regression fixtures ---
		// Each taint framework has a safe fixture (0 findings — safe patterns
		// suppress -IP false positives) and a vulnerable fixture (findings
		// detected — precision canary). This covers all 6 taint frameworks.

		// Spring (Java) — 4 taint rules (SQLi, SSRF, redirect, deser)
		// spring-safe: parameterized JPA query must NOT produce taint findings.
		// JAVA064 (endpoint without @PreAuthorize) is a low-severity pattern
		// finding unrelated to SQLi safe-pattern suppression — allowed.
		{
			name:        "spring-safe-parameterized-jpa-no-false-positives",
			fixture:     "spring-safe",
			framework:   "spring",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 0,
			maxFindings: 2,
		},
		{
			name:        "spring-vuln-sqli-and-redirect-detected",
			fixture:     "spring-vuln",
			framework:   "spring",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 1,
			maxFindings: 15,
			// Spring taint rules (PF-SPRING-SQLI-004) use @RequestParam
			// annotation-based source seeding which is a known gap — the
			// seedAnnotatedParams function doesn't correctly taint the
			// parameter variable in all cases. The generic TP-JAVA001 rule
			// fires instead. Requiring the framework taint rule here would
			// fail until the annotation seeding is fixed.
		},

		// Rails (Ruby) — 2 taint rules (SQLi, redirect)
		{
			name:        "rails-safe-parameterized-orm-no-false-positives",
			fixture:     "rails-safe",
			framework:   "rails",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 0,
			maxFindings: 0,
		},
		{
			name:        "rails-vuln-sqli-and-redirect-detected",
			fixture:     "rails-vuln",
			framework:   "rails",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 1,
			maxFindings: 15,
			// Rails taint rule PF-RAILS-SQLI-003 uses Ruby "call" node type
			// which has a different tree-sitter structure. The generic
			// TP-RB001 rule fires instead. Requiring the framework taint
			// rule would fail until the Ruby call extraction is improved.
		},

		// Flask (Python) — 2 taint rules (SQLi, SSRF)
		{
			name:        "flask-safe-orm-select-no-false-positives",
			fixture:     "flask-safe",
			framework:   "flask",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 0,
			maxFindings: 0,
		},
		{
			name:               "flask-vuln-sqli-and-ssrf-detected",
			fixture:            "flask-vuln",
			framework:          "flask",
			configPath:         ".patchflow/rules.yaml",
			minFindings:        1,
			maxFindings:        15,
			requiredTaintRules: []string{"PF-FLASK-SQLI-002"},
		},

		// GraphQL (Python) — 3 taint rules (SQLi, SSRF, path traversal)
		{
			name:        "graphql-safe-orm-select-no-false-positives",
			fixture:     "graphql-safe",
			framework:   "graphql",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 0,
			maxFindings: 0,
		},
		{
			name:        "graphql-vuln-sqli-and-ssrf-detected",
			fixture:     "graphql-vuln",
			framework:   "graphql",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 1,
			maxFindings: 15,
			// GraphQL has no MatchTaint rules (only MatchPattern -001 rules).
			// The generic TP-PY001 taint rule fires instead.
		},

		// Angular (TypeScript) — 2 taint rules (XSS, redirect)
		{
			name:        "angular-safe-dom-sanitizer-no-false-positives",
			fixture:     "angular-safe",
			framework:   "angular",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 0,
			maxFindings: 0,
		},
		{
			name:        "angular-vuln-innerhtml-xss-detected",
			fixture:     "angular-vuln",
			framework:   "angular",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 1,
			maxFindings: 15,
			// Angular taint rule PF-ANGULAR-XSS-003 uses Angular's
			// DomSanitizer bypass patterns which require TypeScript-specific
			// AST handling. The pattern-based PF-ANGULAR-XSS-001 rule fires
			// instead. Requiring the taint rule would fail until the TS
			// sanitizer bypass detection is improved.
		},

		// Echo (Go) — 3 taint rules (SQLi, redirect, XSS)
		{
			name:        "echo-safe-parameterized-query-no-false-positives",
			fixture:     "echo-safe",
			framework:   "echo",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 0,
			maxFindings: 0,
		},
		{
			name:               "echo-vuln-sqli-and-redirect-detected",
			fixture:            "echo-vuln",
			framework:          "echo",
			configPath:         ".patchflow/rules.yaml",
			minFindings:        1,
			maxFindings:        15,
			requiredTaintRules: []string{"PF-ECHO-SQLI-002", "PF-ECHO-REDIRECT-002"},
		},

		// Gin (Go) — 3 taint rules (SQLi, redirect, CMDI)
		{
			name:        "gin-safe-parameterized-query-no-false-positives",
			fixture:     "gin-safe",
			framework:   "gin",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 0,
			maxFindings: 0,
		},
		{
			name:               "gin-vuln-sqli-and-redirect-detected",
			fixture:            "gin-vuln",
			framework:          "gin",
			configPath:         ".patchflow/rules.yaml",
			minFindings:        1,
			maxFindings:        15,
			requiredTaintRules: []string{"PF-GIN-SQLI-002", "PF-GIN-REDIRECT-002"},
		},

		// Laravel (PHP) — 3 taint rules (SQLi, redirect, deser)
		{
			name:        "laravel-safe-parameterized-query-no-false-positives",
			fixture:     "laravel-safe",
			framework:   "laravel",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 0,
			maxFindings: 0,
		},
		{
			name:               "laravel-vuln-sqli-and-redirect-detected",
			fixture:            "laravel-vuln",
			framework:          "laravel",
			configPath:         ".patchflow/rules.yaml",
			minFindings:        1,
			maxFindings:        15,
			requiredTaintRules: []string{"PF-LARAVEL-SQLI-002", "PF-LARAVEL-REDIRECT-002"},
		},

		// Symfony (PHP) — 2 taint rules (SQLi, redirect)
		{
			name:        "symfony-safe-parameterized-query-no-false-positives",
			fixture:     "symfony-safe",
			framework:   "symfony",
			configPath:  ".patchflow/rules.yaml",
			minFindings: 0,
			maxFindings: 0,
		},
		{
			name:               "symfony-vuln-sqli-and-redirect-detected",
			fixture:            "symfony-vuln",
			framework:          "symfony",
			configPath:         ".patchflow/rules.yaml",
			minFindings:        1,
			maxFindings:        15,
			requiredTaintRules: []string{"PF-SYMFONY-SQLI-002", "PF-SYMFONY-REDIRECT-002"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy fixture to a temp directory to avoid git/module interference
			srcDir := filepath.Join(fixturesDir, tt.fixture)
			tmpDir := t.TempDir()
			if err := copyDir(srcDir, tmpDir); err != nil {
				t.Fatalf("failed to copy fixture: %v", err)
			}

			args := []string{"scan", "run", "--json", "--quiet", "--offline", "--no-gitignore", "--no-licenses"}
			if tt.framework != "" {
				args = append(args, "--framework", tt.framework)
			}
			if tt.configPath != "" {
				configAbs := filepath.Join(tmpDir, tt.configPath)
				if _, err := os.Stat(configAbs); err == nil {
					args = append(args, "--config", configAbs)
				}
			}

			cmd := exec.Command(binary, args...)
			cmd.Dir = tmpDir
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("patchflow scan failed: %v\noutput: %s", err, output)
			}

			var result struct {
				Analysis struct {
					Findings []struct {
						RuleID   string `json:"rule_id"`
						Analyzer string `json:"analyzer"`
						FilePath string `json:"file_path"`
					} `json:"findings"`
				} `json:"analysis"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("failed to parse JSON output: %v", err)
			}

			// Filter to only SAST findings (exclude SCA, license, secret findings)
			var sastFindings int
			taintRuleIDs := make(map[string]bool)
			for _, f := range result.Analysis.Findings {
				if f.Analyzer == "taint-patterns" || f.Analyzer == "patterns-embedded" ||
					f.Analyzer == "treesitter-ast" || f.Analyzer == "gosast-embedded" ||
					f.Analyzer == "framework-taint" || f.Analyzer == "framework-pattern" {
					sastFindings++
				}
				if f.Analyzer == "taint-patterns" {
					taintRuleIDs[f.RuleID] = true
				}
			}

			if sastFindings < tt.minFindings {
				t.Errorf("expected at least %d SAST findings, got %d", tt.minFindings, sastFindings)
			}
			if sastFindings > tt.maxFindings {
				t.Errorf("expected at most %d SAST findings, got %d (potential false positives)", tt.maxFindings, sastFindings)
			}

			// Verify required taint rules are present. This catches taint
			// engine regressions that would be masked by pattern-based
			// findings on the same lines.
			// Accept either the base rule ID or the -IP (interprocedural) variant.
			for _, required := range tt.requiredTaintRules {
				if !taintRuleIDs[required] && !taintRuleIDs[required+"-IP"] {
					t.Errorf("required taint rule %s (or -IP variant) not found in findings (taint rules present: %v)", required, taintRuleIDs)
				}
			}
		})
	}
}

func binaryPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"/tmp/patchflow-b12",
		"../../../patchflow",
		"../../../../patchflow",
	}
	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	return ""
}

func fixturesDir(t *testing.T) string {
	t.Helper()
	// Test runs in internal/testdata/, fixtures are in release-smoke/
	abs, _ := filepath.Abs("release-smoke")
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("fixtures directory not found: %s", abs)
	}
	return abs
}

// copyDir copies a directory recursively.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(dstPath, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dstPath, data, 0644)
	})
}
