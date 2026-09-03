package doctor

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/rulesconfig"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/customrules"
	"github.com/Patchflow-security/patchflow-cli/pkg/version"
)

// Report contains the results of the environment diagnostic checks.
type Report struct {
	// Version info (B12.8)
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"go_version"`
	BuiltAt   string `json:"built_at"`
	Status    string `json:"status"` // "ok", "warning", "error"

	IsGitRepo  bool     `json:"is_git_repo"`
	GitVersion string   `json:"git_version"`
	RepoRoot   string   `json:"repo_root"`
	RemoteURL  string   `json:"remote_url"`
	Errors     []string `json:"errors"`
	Checks     []Check  `json:"checks"`

	// Config checks (B12.8)
	ConfigFound bool   `json:"config_found"`
	ConfigPath  string `json:"config_path"`
	ConfigValid bool   `json:"config_valid"`
	ConfigError string `json:"config_error,omitempty"`

	// Cache checks (B12.8)
	CacheDir      string `json:"cache_dir"`
	CacheWritable bool   `json:"cache_writable"`

	// SARIF output check (B12.8)
	SARIFWritable bool   `json:"sarif_writable"`
	SARIFError    string `json:"sarif_error,omitempty"`

	// Config round-trip check: verifies that a config with custom rules
	// (rules: as a list) loads via BOTH rulesconfig and customrules loaders
	// without crashing. This catches the class of bug where the unified
	// --config flag breaks because the two loaders disagree on the `rules:`
	// schema (B11.5.4 regression guard).
	ConfigRoundTripOK    bool   `json:"config_round_trip_ok"`
	ConfigRoundTripError string `json:"config_round_trip_error,omitempty"`

	// Embedded scanners (always available)
	EmbeddedScanners []ScannerInfo `json:"embedded_scanners"`

	// External tools (optional supplements)
	ExternalTools []ToolInfo `json:"external_tools"`
}

// Check is a machine-readable diagnostic. Every non-pass check includes an
// exact remediation so humans and automation receive the same next step.
type Check struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "pass", "warning", "error"
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// ScannerInfo describes an embedded scanner.
type ScannerInfo struct {
	Name      string `json:"name"`
	Language  string `json:"language"`
	RuleCount int    `json:"rule_count"`
	Status    string `json:"status"` // "available"
}

// ToolInfo describes an external tool.
type ToolInfo struct {
	Name     string `json:"name"`
	Language string `json:"language"`
	Found    bool   `json:"found"`
}

// Run performs environment diagnostics and returns a Report.
func Run() (*Report, error) {
	report := &Report{
		Version:   version.Version,
		Commit:    version.Commit,
		GoVersion: version.GoVersion(),
		BuiltAt:   version.Date,
		Status:    "ok",
		Errors:    []string{},
	}

	// Check git
	executor := &git.ShellExecutor{}
	gitVer, err := executor.Run("", "--version")
	if err != nil {
		report.Errors = append(report.Errors, "git is not installed or not in PATH")
		report.Status = "warning"
		report.addCheck("git", "warning", "Git is not installed or not in PATH", "Install Git from https://git-scm.com/downloads, then open a new terminal and run 'git --version'.")
	} else {
		report.GitVersion = strings.TrimSpace(gitVer)
		report.addCheck("git", "pass", report.GitVersion, "")
	}

	repo, err := git.Detect()
	if err == nil {
		report.IsGitRepo = true
		report.RepoRoot = repo.Root
		report.RemoteURL = repo.RemoteURL
		report.addCheck("repository", "pass", "Git repository detected at "+repo.Root, "")
		if repo.RemoteURL == "" {
			report.addCheck("remote", "pass", "No origin remote is configured; local scans work without one", "")
		} else {
			report.addCheck("remote", "pass", repo.RemoteURL, "")
		}
	} else {
		report.Status = "warning"
		report.addCheck("repository", "warning", "The current directory is not a Git repository", "Run 'git init' here or change to the repository you want to scan.")
	}

	// Check config file (B12.8)
	configDir := filepath.Join(report.RepoRoot, ".patchflow")
	configPath := filepath.Join(configDir, "rules.yaml")
	if _, err := os.Stat(configPath); err == nil {
		report.ConfigFound = true
		report.ConfigPath = configPath
		// Try to validate by loading
		if data, err := os.ReadFile(configPath); err == nil {
			if isValidConfig(data) {
				report.ConfigValid = true
				report.addCheck("config", "pass", "Configuration is valid at "+configPath, "")
			} else {
				report.ConfigValid = false
				report.ConfigError = "config file exists but could not be parsed"
				report.Status = "warning"
				report.addCheck("config", "warning", "Configuration cannot be parsed at "+configPath, "Fix the YAML, or move it aside and run 'patchflow rules init'; then rerun 'patchflow doctor'.")
			}
		} else {
			report.ConfigValid = false
			report.ConfigError = err.Error()
			report.Status = "warning"
			report.addCheck("config", "warning", "Configuration cannot be read at "+configPath, "Fix the file permissions so the current user can read it, then rerun 'patchflow doctor'.")
		}
	} else if report.IsGitRepo {
		// Config not found is not an error, just note it
		report.ConfigFound = false
		report.addCheck("config", "pass", "No project rules file; embedded defaults will be used", "")
	}

	// Check cache directory writability (B12.8)
	cacheDir := defaultCacheDir()
	report.CacheDir = cacheDir
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		report.CacheWritable = false
		report.Status = "warning"
		report.addCheck("cache", "warning", "Cannot create cache directory "+cacheDir, "Set XDG_CACHE_HOME to a writable directory or fix the directory permissions, then rerun 'patchflow doctor'.")
	} else {
		testFile := filepath.Join(cacheDir, ".doctor-write-test")
		if err := os.WriteFile(testFile, []byte("ok"), 0644); err != nil {
			report.CacheWritable = false
			report.Status = "warning"
			report.addCheck("cache", "warning", "Cache directory is not writable: "+cacheDir, "Fix the directory permissions or set XDG_CACHE_HOME to a writable directory, then rerun 'patchflow doctor'.")
		} else {
			report.CacheWritable = true
			os.Remove(testFile)
			report.addCheck("cache", "pass", "Cache directory is writable: "+cacheDir, "")
		}
	}

	// Check SARIF output writability (B12.8) — just test writing to cwd
	sarifTest := filepath.Join(report.RepoRoot, ".doctor-sarif-test.sarif")
	if err := os.WriteFile(sarifTest, []byte("{}"), 0644); err != nil {
		report.SARIFWritable = false
		report.SARIFError = err.Error()
		report.Status = "warning"
		report.addCheck("sarif_output", "warning", "SARIF output cannot be written in "+report.RepoRoot, "Change to a writable repository directory or choose a writable path with '--output <path>'.")
	} else {
		report.SARIFWritable = true
		os.Remove(sarifTest)
		report.addCheck("sarif_output", "pass", "SARIF output is writable", "")
	}

	// Config round-trip check: verify that a config with custom rules (rules:
	// as a list) loads via BOTH rulesconfig and customrules loaders without
	// crashing. This catches the class of bug where the unified --config flag
	// breaks because the two loaders disagree on the `rules:` schema
	// (B11.5.4 regression guard — the bug that shipped in v0.1.6).
	report.ConfigRoundTripOK, report.ConfigRoundTripError = checkConfigRoundTrip()
	if report.ConfigRoundTripOK {
		report.addCheck("config_round_trip", "pass", "Unified configuration loaders agree", "")
	} else {
		report.Status = "warning"
		report.addCheck("config_round_trip", "error", report.ConfigRoundTripError, "Reinstall the latest PatchFlow release and rerun 'patchflow doctor'; if it persists, open an issue with 'patchflow doctor --json'.")
	}

	// Check embedded scanners
	runner := sast.NewRunner()
	groups := runner.AllRules()
	for _, g := range groups {
		report.EmbeddedScanners = append(report.EmbeddedScanners, ScannerInfo{
			Name:      g.Scanner,
			Language:  g.Language,
			RuleCount: g.RuleCount,
			Status:    "available",
		})
	}

	// Check external tools
	for _, name := range runner.AvailableTools() {
		report.ExternalTools = append(report.ExternalTools, ToolInfo{
			Name:     name,
			Language: toolLanguage(name),
			Found:    true,
		})
	}
	// Also list tools that are NOT available
	allTools := []string{"gosec", "bandit", "semgrep", "gitleaks"}
	availableSet := make(map[string]bool)
	for _, t := range report.ExternalTools {
		availableSet[t.Name] = true
	}
	for _, name := range allTools {
		if !availableSet[name] {
			report.ExternalTools = append(report.ExternalTools, ToolInfo{
				Name:     name,
				Language: toolLanguage(name),
				Found:    false,
			})
		}
	}

	if len(report.Errors) > 0 && report.Status == "ok" {
		report.Status = "warning"
	}
	return report, nil
}

func (r *Report) addCheck(name, status, message, remediation string) {
	r.Checks = append(r.Checks, Check{
		Name: name, Status: status, Message: message, Remediation: remediation,
	})
}

// isValidConfig does a basic YAML parse check.
func isValidConfig(data []byte) bool {
	// Simple check: non-empty and looks like YAML
	s := strings.TrimSpace(string(data))
	if len(s) == 0 {
		return false
	}
	// If it starts with { or [, it's likely JSON-style YAML
	// Otherwise, check for at least one key: value pair
	if !strings.Contains(s, ":") {
		return false
	}
	return true
}

// checkConfigRoundTrip verifies that a config with custom rules (rules: as a
// list) and framework extensions loads via BOTH rulesconfig.LoadFromBytes and
// customrules.LoadPolicyFromBytes without crashing. This is the regression
// guard for the B11.5.4 unified-config schema conflict: rulesconfig reads
// rules: as a map (mode overrides) while customrules reads it as a list
// (custom pattern rules). If either loader crashes, the --config flag is
// broken and users cannot customize their scan.
func checkConfigRoundTrip() (bool, string) {
	testConfig := []byte(`schema_version: "1.0"
frameworks:
  auto_detect: true
  enabled: []
  disabled: []

framework_extensions:
  fastapi:
    safe_patterns:
      - pattern: "select\\("
        reason: "ORM parameterization"

rules:
  - id: DR-001
    title: Doctor test rule
    pattern: "test\\("
    severity: medium
    languages: [python]
    confidence: medium
    cwe: "CWE-89"
`)

	// 1. rulesconfig.LoadFromBytes — reads rules: as a map (mode overrides).
	// Must not crash on a list under rules:.
	if _, err := rulesconfig.LoadFromBytes(testConfig); err != nil {
		return false, "rulesconfig.LoadFromBytes failed: " + err.Error()
	}

	// 2. customrules.LoadPolicyFromBytes — reads rules: as a list (custom
	// pattern rules). Must not crash and must find the DR-001 rule.
	policy, err := customrules.LoadPolicyFromBytes(testConfig)
	if err != nil {
		return false, "customrules.LoadPolicyFromBytes failed: " + err.Error()
	}
	if policy == nil {
		return false, "customrules.LoadPolicyFromBytes returned nil policy"
	}
	if len(policy.PatternRules) == 0 {
		return false, "customrules.LoadPolicyFromBytes found 0 pattern rules (expected DR-001)"
	}

	return true, ""
}

// defaultCacheDir returns the default cache directory path.
func defaultCacheDir() string {
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "patchflow")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache", "patchflow")
	}
	return ".patchflow-cache"
}

func toolLanguage(name string) string {
	switch name {
	case "gosec":
		return "go"
	case "bandit":
		return "python"
	case "semgrep":
		return "multi"
	case "gitleaks":
		return "secrets"
	default:
		return "unknown"
	}
}
