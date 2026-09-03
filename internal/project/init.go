// Package project handles the initialization of a PatchFlow project directory
// (.patchflow/) with configuration, baselines, and reports subdirectories.
// Cache data is stored in a global XDG-compliant location (~/.cache/patchflow/)
// and is NOT created under .patchflow/ — this keeps project directories clean.
package project

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ProjectConfig is the .patchflow/config.yml structure.
type ProjectConfig struct {
	ProjectID      string `yaml:"project_id,omitempty"`
	OrganizationID string `yaml:"organization_id,omitempty"`
	BackendURL     string `yaml:"backend_url,omitempty"`
	Mode           string `yaml:"mode"`

	Analysis   AnalysisConfig   `yaml:"analysis"`
	Privacy    PrivacyConfig    `yaml:"privacy"`
	Ignore     IgnoreConfig     `yaml:"ignore"`
	Frameworks FrameworksConfig `yaml:"frameworks"`
}

// AnalysisConfig controls which analyzers run and their behavior.
type AnalysisConfig struct {
	DefaultProfile      string `yaml:"default_profile"`
	ChangedFilesOnly    bool   `yaml:"changed_files_only"`
	IncludeReachability bool   `yaml:"include_reachability"`
	IncludeSAST         bool   `yaml:"include_sast"`
	IncludeSecrets      bool   `yaml:"include_secrets"`
	IncludeFixProposals bool   `yaml:"include_fix_proposals"`
}

// PrivacyConfig controls data handling.
type PrivacyConfig struct {
	RedactSecrets        bool `yaml:"redact_secrets"`
	SendCodeToRemoteAI   bool `yaml:"send_code_to_remote_ai"`
	RetainLocalCacheDays int  `yaml:"retain_local_cache_days"`
}

// IgnoreConfig specifies paths to exclude from analysis.
type IgnoreConfig struct {
	Paths []string `yaml:"paths"`
}

// FrameworksConfig controls framework pack auto-detection and explicit pack
// selection at the project level.
type FrameworksConfig struct {
	AutoDetect bool     `yaml:"auto_detect"`
	Enabled    []string `yaml:"enabled,omitempty"`
	Disabled   []string `yaml:"disabled,omitempty"`
}

// DefaultConfig returns the default project configuration.
func DefaultConfig() ProjectConfig {
	return ProjectConfig{
		Mode: "local",
		Analysis: AnalysisConfig{
			DefaultProfile:      "standard",
			ChangedFilesOnly:    true,
			IncludeReachability: true,
			IncludeSAST:         true,
			IncludeSecrets:      true,
			IncludeFixProposals: false,
		},
		Privacy: PrivacyConfig{
			RedactSecrets:        true,
			SendCodeToRemoteAI:   false,
			RetainLocalCacheDays: 7,
		},
		Ignore: IgnoreConfig{
			Paths: []string{
				"node_modules/**",
				"dist/**",
				"build/**",
				"coverage/**",
				"vendor/**",
				"*.lock",
				".git/**",
			},
		},
		Frameworks: FrameworksConfig{
			AutoDetect: true,
		},
	}
}

// InitResult contains the result of an initialization.
type InitResult struct {
	ConfigPath     string   `json:"config_path"`
	RulesPath      string   `json:"rules_path,omitempty"`
	Dir            string   `json:"dir"`
	Created        bool     `json:"created"`
	DetectedFrameworks []string `json:"detected_frameworks,omitempty"`
}

// Init creates the .patchflow/ directory structure in the given root.
// If the directory already exists, it returns the existing path without overwriting.
func Init(root string) (*InitResult, error) {
	pfDir := filepath.Join(root, ".patchflow")
	configPath := filepath.Join(pfDir, "config.yml")

	// Check if already initialized
	if _, err := os.Stat(pfDir); err == nil {
		return &InitResult{
			ConfigPath: configPath,
			Dir:        pfDir,
			Created:    false,
		}, nil
	}

	// Create directory structure.
	// Note: cache/ is NOT created here — it lives in a global XDG-compliant
	// location (~/.cache/patchflow/<project-hash>/) to avoid polluting the
	// project directory. Only project-specific artifacts (baselines, reports)
	// remain under .patchflow/.
	subdirs := []string{"baselines", "reports"}
	if err := os.MkdirAll(pfDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create .patchflow directory: %w", err)
	}
	for _, sub := range subdirs {
		path := filepath.Join(pfDir, sub)
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", sub, err)
		}
	}

	// Write config.yml
	cfg := DefaultConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to write config.yml: %w", err)
	}

	// Write state.json
	state := map[string]interface{}{
		"initialized_at": time.Now().UTC().Format(time.RFC3339),
		"last_scan":      "",
		"baseline":       "",
	}
	stateData, _ := yaml.Marshal(state)
	statePath := filepath.Join(pfDir, "state.json")
	_ = os.WriteFile(statePath, stateData, 0600)

	// Write .gitignore (keep reports and baselines tracked, nothing to ignore
	// since cache is no longer stored under .patchflow/)
	gitignoreContent := "# PatchFlow project directory\n# Reports and baselines are project artifacts.\n# Cache is stored globally at ~/.cache/patchflow/ (XDG-compliant).\n"
	gitignorePath := filepath.Join(pfDir, ".gitignore")
	_ = os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644)

	// Detect frameworks and generate rules.yaml with a working starter config.
	// This is the key first-run experience improvement: init now produces a
	// .patchflow/rules.yaml that immediately customizes the scan for the
	// detected framework, rather than leaving the user to author YAML from
	// scratch.
	detected := detectFrameworksForInit(root)
	rulesPath := filepath.Join(pfDir, "rules.yaml")
	rulesContent := generateRulesYAML(detected)
	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write rules.yaml: %w", err)
	}

	return &InitResult{
		ConfigPath:         configPath,
		RulesPath:          rulesPath,
		Dir:                pfDir,
		Created:            true,
		DetectedFrameworks: detected,
	}, nil
}

// detectFrameworksForInit runs framework detection on the repo root and returns
// the names of detected frameworks (sorted, deduplicated). If detection fails
// or finds nothing, returns nil — the rules.yaml will use auto_detect only.
func detectFrameworksForInit(root string) []string {
	// We import the detector lazily via a function variable to avoid an import
	// cycle: internal/project cannot import internal/sast/frameworks (which
	// transitively imports internal/sast). The cmd layer wires the real
	// detector; if it's not wired, we fall back to auto_detect-only.
	if frameworkDetector != nil {
		result := frameworkDetector(root)
		if result == nil {
			return nil
		}
		seen := make(map[string]bool)
		var names []string
		for _, d := range result.Frameworks {
			name := string(d.Name)
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
		sort.Strings(names)
		return names
	}
	return nil
}

// FrameworkDetectionResult is a local mirror of frameworks.Result to avoid
// importing the frameworks package (which would create a cycle through sast).
// The cmd layer converts frameworks.Result → this type via SetFrameworkDetector.
type FrameworkDetectionResult struct {
	Frameworks []FrameworkDetection `json:"frameworks"`
}

// FrameworkDetection mirrors frameworks.Detection for the bridge.
type FrameworkDetection struct {
	Name       string  `json:"name"`
	Language   string  `json:"language"`
	Confidence float64 `json:"confidence"`
}

// frameworkDetector is set by cmd/init.go via SetFrameworkDetector to avoid
// an import cycle (internal/project → internal/sast/frameworks → internal/sast).
var frameworkDetector func(root string) *FrameworkDetectionResult

// SetFrameworkDetector wires the real framework detector. Called from cmd init.
func SetFrameworkDetector(fn func(root string) *FrameworkDetectionResult) {
	frameworkDetector = fn
}

// generateRulesYAML produces a starter .patchflow/rules.yaml for the detected
// frameworks. If no frameworks are detected, it generates an auto_detect-only
// config with commented examples.
func generateRulesYAML(detected []string) string {
	var sb strings.Builder

	sb.WriteString(`# PatchFlow project configuration.
# This file EXTENDS the official embedded rules — it does not replace them.
# See: patchflow rules list-frameworks  and  patchflow rules list --framework <name>
# Docs: https://patchflow.ai/docs  (custom-rules, custom-framework-extensions)
schema_version: "1.0"

# ---------------------------------------------------------------------------
# Framework pack selection
# ---------------------------------------------------------------------------
frameworks:
  auto_detect: true
`)
	if len(detected) > 0 {
		sb.WriteString("  enabled:\n")
		for _, fw := range detected {
			sb.WriteString("    - " + fw + "\n")
		}
	} else {
		sb.WriteString("  enabled: []\n")
	}
	sb.WriteString("  disabled: []\n\n")

	// Framework extensions skeleton for the first detected framework.
	if len(detected) > 0 {
		primary := detected[0]
		sb.WriteString("# ---------------------------------------------------------------------------\n")
		sb.WriteString("# Framework extensions for " + primary + "\n")
		sb.WriteString("# ---------------------------------------------------------------------------\n")
		sb.WriteString("# Register your INTERNAL helpers so the taint engine understands them.\n")
		sb.WriteString("# Sinks are scoped by CWE/category to avoid cross-rule noise.\n")
		sb.WriteString("# Run `patchflow explain --rule PF-" + strings.ToUpper(primary) + "-*` to see pack rules.\n")
		sb.WriteString("framework_extensions:\n")
		sb.WriteString("  " + primary + ":\n")
		sb.WriteString("    # custom_sanitizers:\n")
		sb.WriteString("    #   - function: \"sanitize_input\"\n")
		sb.WriteString("    #   - regex: \"ParameterizedQuery\\\\(\"\n")
		sb.WriteString("    # safe_patterns:\n")
		sb.WriteString("    #   - pattern: \"Depends\\\\(get_current_user\\\\)\"\n")
		sb.WriteString("    #     reason: \"Endpoint enforces JWT auth\"\n")
		sb.WriteString("    # custom_sinks:\n")
		sb.WriteString("    #   - function: \"db.execute\"\n")
		sb.WriteString("    #     cwe: \"CWE-89\"\n")
		sb.WriteString("    #     category: \"sql_injection\"\n")
		sb.WriteString("    # custom_sources:\n")
		sb.WriteString("    #   - function: \"webhook_payload\"\n")
		sb.WriteString("    #     categories: [sql_injection, ssrf]\n\n")
	}

	// Custom rules examples (commented out).
	sb.WriteString("# ---------------------------------------------------------------------------\n")
	sb.WriteString("# Custom regex rules (project-specific policy)\n")
	sb.WriteString("# ---------------------------------------------------------------------------\n")
	sb.WriteString("# IDs must match ^[A-Z][A-Z0-9]+(-[A-Z0-9]+)+$ (e.g. MYAPP-001, TEAM-SEC-002)\n")
	sb.WriteString("# Supported languages: python, javascript, typescript, ruby, php, java,\n")
	sb.WriteString("#   csharp, go, rust, yaml, dockerfile, terraform\n")
	sb.WriteString("rules:\n")
	sb.WriteString("  # - id: MYAPP-001\n")
	sb.WriteString("  #   title: Hardcoded API key\n")
	sb.WriteString("  #   pattern: \"API_KEY\\\\s*=\\\\s*['\\\"][A-Za-z0-9]{32}['\\\"]\"\n")
	sb.WriteString("  #   severity: critical\n")
	sb.WriteString("  #   languages: [python]\n")
	sb.WriteString("  #   confidence: high\n")
	sb.WriteString("  #   cwe: \"CWE-798\"\n")
	sb.WriteString("  #   fix_hint: \"Load API keys from environment variables\"\n")
	sb.WriteString("\n")

	return sb.String()
}

// LoadConfig reads the .patchflow/config.yml file.
func LoadConfig(root string) (*ProjectConfig, error) {
	configPath := filepath.Join(root, ".patchflow", "config.yml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config.yml: %w", err)
	}
	return &cfg, nil
}

// IsInitialized checks whether .patchflow/ exists in the given root.
func IsInitialized(root string) bool {
	pfDir := filepath.Join(root, ".patchflow")
	_, err := os.Stat(pfDir)
	return err == nil
}
