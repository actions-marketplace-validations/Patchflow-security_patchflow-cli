package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/exitcode"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestDetermineScanExit(t *testing.T) {
	findings := []analysis.Finding{
		{Severity: analysis.SeverityHigh, Blocking: false},
		{Severity: analysis.SeverityLow, Blocking: true},
	}

	for _, tc := range []struct {
		name   string
		input  []analysis.Finding
		failOn string
		code   int
	}{
		{name: "clean", code: exitcode.Success},
		{name: "explicit threshold", input: findings, failOn: "high", code: exitcode.FindingsFound},
		{name: "threshold above findings", input: findings[1:], failOn: "high", code: exitcode.Success},
		{name: "rule mode blocking", input: findings, code: exitcode.FindingsFound},
		{name: "informational findings", input: findings[:1], code: exitcode.Success},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, message := determineScanExit(tc.input, tc.failOn)
			if got != tc.code {
				t.Fatalf("determineScanExit() code = %d, want %d", got, tc.code)
			}
			if (got == exitcode.Success) != (message == "") {
				t.Fatalf("determineScanExit() message = %q for code %d", message, got)
			}
		})
	}
}

// chdirTemp changes the working directory to dir and registers cleanup to
// restore the original directory. The scan run command uses git.DetectOrLocal
// which operates on the current working directory, so tests must chdir into
// the temp project directory.
func chdirTemp(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

// writeVulnPython writes a simple vulnerable Python file to dir.
func writeVulnPython(t *testing.T, dir string) string {
	t.Helper()
	src := "import os\nuser_input = input()\neval(user_input)\n"
	p := filepath.Join(dir, "vuln.py")
	if err := os.WriteFile(p, []byte(src), 0644); err != nil {
		t.Fatalf("write vuln.py: %v", err)
	}
	return p
}

// resetAllFlags walks the root command tree and resets every flag (persistent
// and local) to its default value. This prevents flag state from leaking
// between tests that share the global rootCmd.
func resetAllFlags() {
	resetFlags(rootCmd)
	for _, c := range rootCmd.Commands() {
		resetFlags(c)
		for _, sub := range c.Commands() {
			resetFlags(sub)
		}
	}
}

func resetFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
	})
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
	})
}

// captureStdout replaces os.Stdout with a pipe, runs fn, and returns whatever
// was written to stdout during fn's execution. The original os.Stdout is
// restored afterwards. This is necessary because the output formatter writes
// directly to os.Stdout (not via cmd.SetOut).
func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	runErr := fn()
	_ = w.Close()
	os.Stdout = orig
	out := <-done

	if runErr != nil {
		t.Logf("command returned error: %v", runErr)
	}
	return out
}

// runRootCommand resets flags, sets args on the global rootCmd, captures
// stdout (via pipe since the formatter writes directly to os.Stdout), and
// returns the captured output.
func runRootCommand(t *testing.T, args []string) string {
	t.Helper()
	resetAllFlags()
	rootCmd.SetArgs(args)
	return captureStdout(t, func() error {
		return rootCmd.Execute()
	})
}

// TestScanRun_HelpOutput verifies the scan run command prints help text
// containing "scan" and "Usage" when invoked with --help.
func TestScanRun_HelpOutput(t *testing.T) {
	out := runRootCommand(t, []string{"scan", "run", "--help"})

	if !strings.Contains(out, "scan") {
		t.Errorf("expected help output to contain 'scan', got:\n%s", out)
	}
	if !strings.Contains(out, "Usage") {
		t.Errorf("expected help output to contain 'Usage', got:\n%s", out)
	}
}

// TestScanRun_JSONOutput runs the scan command with --json on a temp dir
// containing a vulnerable Python file and verifies the stdout is valid JSON
// with an "analysis" object containing a "findings" array.
func TestScanRun_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	writeVulnPython(t, tmpDir)
	chdirTemp(t, tmpDir)

	out := runRootCommand(t, []string{"scan", "run", "--json", "--quiet", "--no-reachability", "--offline"})

	// Parse the JSON output. The scan may emit log warnings to stderr; stdout
	// should contain the JSON payload.
	var result map[string]json.RawMessage
	if perr := json.Unmarshal([]byte(out), &result); perr != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput:\n%s", perr, out)
	}

	analysisRaw, ok := result["analysis"]
	if !ok {
		t.Fatalf("expected top-level 'analysis' key, got keys: %v\noutput:\n%s", mapKeys(result), out)
	}

	var analysis map[string]json.RawMessage
	if err := json.Unmarshal(analysisRaw, &analysis); err != nil {
		t.Fatalf("analysis is not valid JSON: %v", err)
	}

	findingsRaw, ok := analysis["findings"]
	if !ok {
		t.Fatalf("expected 'analysis.findings' key, got keys: %v", mapKeys(analysis))
	}

	var findings []json.RawMessage
	if err := json.Unmarshal(findingsRaw, &findings); err != nil {
		t.Fatalf("findings is not a JSON array: %v", err)
	}
	// We don't assert findings > 0 because the embedded scanner may or may not
	// flag eval() depending on rule configuration; we only verify structure.
	t.Logf("scan produced %d findings", len(findings))
}

// TestScanRun_QuietFlag verifies that --quiet suppresses the banner and
// summary output (no human-readable banner/summary lines).
func TestScanRun_QuietFlag(t *testing.T) {
	tmpDir := t.TempDir()
	writeVulnPython(t, tmpDir)
	chdirTemp(t, tmpDir)

	out := runRootCommand(t, []string{"scan", "run", "--quiet", "--no-reachability", "--offline"})

	// In quiet mode, the CLI should not print the ASCII banner or the
	// multi-line terminal summary. We check for absence of common banner
	// markers and the summary header.
	bannerMarkers := []string{"╔", "╗", "╚", "╝", "║", "PatchFlow CLI", "Scan Summary"}
	for _, marker := range bannerMarkers {
		if strings.Contains(out, marker) {
			t.Errorf("expected --quiet to suppress banner/summary marker %q, but found it in output:\n%s", marker, out)
		}
	}
}

// TestVersionCommand verifies the version command output contains "patchflow".
func TestVersionCommand(t *testing.T) {
	out := runRootCommand(t, []string{"version"})

	if !strings.Contains(strings.ToLower(out), "patchflow") {
		t.Errorf("expected version output to contain 'patchflow', got:\n%s", out)
	}
}

// mapKeys returns the keys of a map for debugging output.
func mapKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestScanRun_WithCustomRulesConfig verifies that `scan run --config` works
// end-to-end with a .patchflow/rules.yaml containing custom pattern rules
// (under the `rules:` key as a list), framework extensions, and framework
// selection. This is the exact scenario that was broken by the unified-config
// schema conflict (B11.5.4): rulesconfig.Config read `rules:` as a map while
// customrules.RuleFile read it as a list, causing a "cannot unmarshal !!seq
// into map[string]Mode" crash. This test prevents that class of regression.
func TestScanRun_WithCustomRulesConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// A vulnerable Python file that should trigger both an embedded rule
	// (eval) and our custom rule (hardcoded secret).
	pythonSrc := `import os
SECRET_KEY = "supersecretkey123456789"
user_input = input()
eval(user_input)
`
	if err := os.WriteFile(filepath.Join(tmpDir, "app.py"), []byte(pythonSrc), 0644); err != nil {
		t.Fatalf("write app.py: %v", err)
	}

	// .patchflow/rules.yaml with custom rules (list under `rules:`) + framework
	// extensions. This is the documented unified-config format.
	rulesYAML := `schema_version: "1.0"
frameworks:
  auto_detect: true
  enabled: []
  disabled: []

framework_extensions:
  fastapi:
    custom_sanitizers:
      - function: "sanitize_input"
    safe_patterns:
      - pattern: "select\\("
        reason: "ORM parameterization"

rules:
  - id: TEST-001
    title: Hardcoded SECRET_KEY in source
    pattern: "SECRET_KEY\\s*=\\s*['\"][^'\"]{16,}['\"]"
    severity: critical
    languages: [python]
    confidence: high
    cwe: "CWE-798"
    fix_hint: "Load secrets from env vars"
`
	patchflowDir := filepath.Join(tmpDir, ".patchflow")
	if err := os.MkdirAll(patchflowDir, 0755); err != nil {
		t.Fatalf("mkdir .patchflow: %v", err)
	}
	rulesPath := filepath.Join(patchflowDir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0644); err != nil {
		t.Fatalf("write rules.yaml: %v", err)
	}

	chdirTemp(t, tmpDir)

	// Run scan with --config pointing at our rules file. The key assertion is
	// that this does NOT crash with a YAML unmarshal error.
	out := runRootCommand(t, []string{
		"scan", "run",
		"--config", rulesPath,
		"--json", "--quiet",
		"--no-reachability", "--offline", "--no-licenses",
	})

	// Parse JSON output
	var result map[string]json.RawMessage
	if perr := json.Unmarshal([]byte(out), &result); perr != nil {
		t.Fatalf("stdout is not valid JSON (config crash?): %v\noutput:\n%s", perr, out)
	}

	analysisRaw, ok := result["analysis"]
	if !ok {
		t.Fatalf("expected 'analysis' key, got keys: %v\noutput:\n%s", mapKeys(result), out)
	}

	var analysis struct {
		Findings []struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(analysisRaw, &analysis); err != nil {
		t.Fatalf("failed to parse analysis: %v", err)
	}

	// Assert our custom rule (TEST-001) fired.
	foundCustom := false
	for _, f := range analysis.Findings {
		if f.RuleID == "TEST-001" {
			foundCustom = true
			if f.Severity != "critical" {
				t.Errorf("custom rule TEST-001: expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !foundCustom {
		t.Errorf("expected custom rule TEST-001 to fire, but it did not. Findings: %+v", analysis.Findings)
	}

	t.Logf("scan with --config produced %d findings (custom rule TEST-001 fired: %v)", len(analysis.Findings), foundCustom)
}

// TestScanRun_WithModeOverrideConfig verifies that `scan run --config` also
// works when `rules:` is a map of rule-id -> mode (the mode-override schema).
// This confirms both schemas (list and map) work with the unified --config flag.
func TestScanRun_WithModeOverrideConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// A vulnerable Python file.
	pythonSrc := "import os\nuser_input = input()\neval(user_input)\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "vuln.py"), []byte(pythonSrc), 0644); err != nil {
		t.Fatalf("write vuln.py: %v", err)
	}

	// rules.yaml with `rules:` as a MAP (mode overrides). This is the
	// mode-override schema. The scan should not crash and modes should apply.
	rulesYAML := `schema_version: "1.0"
frameworks:
  auto_detect: true

rules:
  TEST-OFF: off
  TEST-INFORM: inform
`
	patchflowDir := filepath.Join(tmpDir, ".patchflow")
	if err := os.MkdirAll(patchflowDir, 0755); err != nil {
		t.Fatalf("mkdir .patchflow: %v", err)
	}
	rulesPath := filepath.Join(patchflowDir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0644); err != nil {
		t.Fatalf("write rules.yaml: %v", err)
	}

	chdirTemp(t, tmpDir)

	out := runRootCommand(t, []string{
		"scan", "run",
		"--config", rulesPath,
		"--json", "--quiet",
		"--no-reachability", "--offline", "--no-licenses",
	})

	// The key assertion: valid JSON output (no crash).
	var result map[string]json.RawMessage
	if perr := json.Unmarshal([]byte(out), &result); perr != nil {
		t.Fatalf("stdout is not valid JSON (mode-map config crash?): %v\noutput:\n%s", perr, out)
	}
	if _, ok := result["analysis"]; !ok {
		t.Fatalf("expected 'analysis' key, got keys: %v", mapKeys(result))
	}
	t.Logf("scan with mode-override config produced valid JSON")
}
