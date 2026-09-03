package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitCreatesDirectory(t *testing.T) {
	dir := t.TempDir()

	result, err := Init(dir)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if !result.Created {
		t.Error("expected Created=true for new init")
	}

	// Check directory exists
	if _, err := os.Stat(result.Dir); err != nil {
		t.Errorf("directory not created: %v", err)
	}

	// Check config.yml exists
	if _, err := os.Stat(result.ConfigPath); err != nil {
		t.Errorf("config.yml not created: %v", err)
	}

	// Check subdirectories (cache/ is NOT created — it lives in global XDG location)
	for _, sub := range []string{"baselines", "reports"} {
		path := filepath.Join(result.Dir, sub)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("subdirectory %s not created: %v", sub, err)
		}
	}

	// Verify cache/ is NOT created in the project directory
	cachePath := filepath.Join(result.Dir, "cache")
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Errorf("cache/ should NOT be created under .patchflow/ (global XDG location used instead)")
	}

	// Check .gitignore
	gitignorePath := filepath.Join(result.Dir, ".gitignore")
	if _, err := os.Stat(gitignorePath); err != nil {
		t.Errorf(".gitignore not created: %v", err)
	}
}

func TestInitIdempotent(t *testing.T) {
	dir := t.TempDir()

	// First init
	_, err := Init(dir)
	if err != nil {
		t.Fatalf("first Init failed: %v", err)
	}

	// Second init should not overwrite
	result, err := Init(dir)
	if err != nil {
		t.Fatalf("second Init failed: %v", err)
	}

	if result.Created {
		t.Error("expected Created=false for existing .patchflow/")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()

	_, err := Init(dir)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Mode != "local" {
		t.Errorf("expected mode=local, got %s", cfg.Mode)
	}
	if !cfg.Analysis.IncludeReachability {
		t.Error("expected IncludeReachability=true by default")
	}
	if !cfg.Privacy.RedactSecrets {
		t.Error("expected RedactSecrets=true by default")
	}
	if !cfg.Frameworks.AutoDetect {
		t.Error("expected Frameworks.AutoDetect=true by default")
	}
}

func TestIsInitialized(t *testing.T) {
	dir := t.TempDir()

	if IsInitialized(dir) {
		t.Error("should not be initialized before Init")
	}

	_, _ = Init(dir)

	if !IsInitialized(dir) {
		t.Error("should be initialized after Init")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Mode != "local" {
		t.Errorf("expected local mode, got %s", cfg.Mode)
	}
	if cfg.Analysis.DefaultProfile != "standard" {
		t.Errorf("expected standard profile, got %s", cfg.Analysis.DefaultProfile)
	}
	if len(cfg.Ignore.Paths) == 0 {
		t.Error("expected default ignore paths")
	}
	if !cfg.Frameworks.AutoDetect {
		t.Error("expected framework auto-detect enabled by default")
	}
}

// TestInitCreatesRulesYAML verifies that Init generates a .patchflow/rules.yaml
// with the expected structure (schema_version, frameworks, rules sections).
// This is the first-run experience improvement: init should produce a working
// config, not just empty directories.
func TestInitCreatesRulesYAML(t *testing.T) {
	dir := t.TempDir()

	result, err := Init(dir)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// rules.yaml must exist
	if result.RulesPath == "" {
		t.Fatal("expected RulesPath to be set")
	}
	if _, err := os.Stat(result.RulesPath); err != nil {
		t.Errorf("rules.yaml not created at %s: %v", result.RulesPath, err)
	}

	data, err := os.ReadFile(result.RulesPath)
	if err != nil {
		t.Fatalf("failed to read rules.yaml: %v", err)
	}
	content := string(data)

	// Must contain the key structural sections
	mustContain := []string{
		"schema_version:",
		"frameworks:",
		"auto_detect: true",
		"rules:",
	}
	for _, s := range mustContain {
		if !contains(content, s) {
			t.Errorf("rules.yaml missing expected section %q\ncontent:\n%s", s, content)
		}
	}
}

// TestInitRulesYAMLWithDetectedFramework verifies that when a framework is
// detected, the generated rules.yaml includes it in the enabled list and
// generates a framework_extensions skeleton for it.
func TestInitRulesYAMLWithDetectedFramework(t *testing.T) {
	dir := t.TempDir()

	// Wire a mock detector that always detects "fastapi"
	SetFrameworkDetector(func(root string) *FrameworkDetectionResult {
		return &FrameworkDetectionResult{
			Frameworks: []FrameworkDetection{
				{Name: "fastapi", Language: "python", Confidence: 0.9},
			},
		}
	})
	t.Cleanup(func() { SetFrameworkDetector(nil) })

	result, err := Init(dir)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if len(result.DetectedFrameworks) != 1 || result.DetectedFrameworks[0] != "fastapi" {
		t.Errorf("expected detected frameworks [fastapi], got %v", result.DetectedFrameworks)
	}

	data, err := os.ReadFile(result.RulesPath)
	if err != nil {
		t.Fatalf("failed to read rules.yaml: %v", err)
	}
	content := string(data)

	// Must include fastapi in enabled list
	if !contains(content, "- fastapi") {
		t.Errorf("rules.yaml should include fastapi in enabled list\ncontent:\n%s", content)
	}
	// Must include framework_extensions skeleton for fastapi
	if !contains(content, "framework_extensions:") {
		t.Errorf("rules.yaml should include framework_extensions skeleton\ncontent:\n%s", content)
	}
	if !contains(content, "fastapi:") {
		t.Errorf("rules.yaml should include fastapi extension skeleton\ncontent:\n%s", content)
	}
}

// contains is a simple substring check (avoids importing strings for one use).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
