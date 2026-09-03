package cmd

import (
	"fmt"
	"os"
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/customrules"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/packs"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var rulesValidateCmd = &cobra.Command{
	Use:   "validate [path]",
	Short: "Validate a custom rules YAML file",
	Long: `Validate the structure and contents of a custom rules YAML file.

If a path argument is provided, that file is validated. Otherwise the command
looks for .patchflow/rules.yaml in the project root.

Validation checks:
  1. File exists and is valid YAML
  2. Each rule has required fields: id, title, pattern, severity
  3. Severity is one of: low, medium, high, critical
  4. Pattern is a valid regex (compiles without error)
  5. Languages field is present and non-empty
  6. Rule IDs are unique
  7. Rule IDs match pattern ^[A-Z][A-Z0-9]{2,}-[A-Z0-9]+$

Exit code is 0 if valid, 1 if invalid.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRulesValidate,
}

func init() {
	rulesCmd.AddCommand(rulesValidateCmd)
}

// ruleValidationError is a single validation error for JSON output.
type ruleValidationError struct {
	RuleID string `json:"rule_id,omitempty"`
	Error  string `json:"error"`
}

// rulesValidateResult is the JSON-serializable result of 'rules validate'.
type rulesValidateResult struct {
	Valid               bool                  `json:"valid"`
	Path                string                `json:"path"`
	Rules               int                   `json:"rules"`
	FrameworkOverrides  int                   `json:"framework_overrides,omitempty"`
	FrameworkExtensions int                   `json:"framework_extensions,omitempty"`
	Errors              []ruleValidationError `json:"errors,omitempty"`
	Warnings            []string              `json:"warnings,omitempty"`
}

// idPattern enforces the rule ID naming convention: uppercase alphanumeric
// segments separated by hyphens, e.g. CUSTOM-001, MYAPP-XSS-001, PF-FASTAPI-SQLI-001.
// Multi-hyphen IDs are allowed. The first segment starts with a letter and is
// at least 2 characters; subsequent segments are 1+ uppercase alphanumeric.
// This matches the examples in the docs (docs/reference/yaml-policy.md) and
// the official framework rule IDs (PF-FASTAPI-SQLI-001, etc.).
var idPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]+(-[A-Z0-9]+)+$`)

// validSeverities is the set of accepted severity values.
var validSeverities = map[string]bool{
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

func runRulesValidate(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())

	var path string
	if len(args) == 1 {
		path = args[0]
	} else {
		root, err := getProjectRoot()
		if err != nil {
			return formatter.PrintError(err)
		}
		path = root + "/.patchflow/rules.yaml"
	}

	result := rulesValidateResult{Path: path}

	// 1. File exists and is valid YAML.
	data, err := os.ReadFile(path)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ruleValidationError{
			Error: fmt.Sprintf("failed to read file: %v", err),
		})
		return printValidateResult(formatter, result)
	}

	var ruleFile customrules.RuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ruleValidationError{
			Error: fmt.Sprintf("invalid YAML: %v", err),
		})
		return printValidateResult(formatter, result)
	}
	if policy, err := customrules.LoadPolicyFromBytes(data); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ruleValidationError{
			Error: err.Error(),
		})
		return printValidateResult(formatter, result)
	} else {
		result.FrameworkOverrides = len(policy.FrameworkOverrides)
		// Count extensions (overrides that have safe_patterns or came from extensions)
		// We check the raw YAML for framework_extensions section
		var rawCheck struct {
			FrameworkExtensions map[string]yaml.Node `yaml:"framework_extensions"`
		}
		_ = yaml.Unmarshal(data, &rawCheck)
		result.FrameworkExtensions = len(rawCheck.FrameworkExtensions)
	}

	// Check schema_version (B12.6)
	var schemaCheck struct {
		SchemaVersion string `yaml:"schema_version"`
	}
	_ = yaml.Unmarshal(data, &schemaCheck)
	if schemaCheck.SchemaVersion == "" {
		result.Warnings = append(result.Warnings,
			"schema_version missing, assuming 1.0 (add 'schema_version: \"1.0\"' to suppress this warning)")
	}

	result.Rules = len(ruleFile.Rules)
	hasFrameworkConfig := ruleFile.Frameworks.AutoDetect != nil ||
		len(ruleFile.Frameworks.Enabled) > 0 ||
		len(ruleFile.Frameworks.Disabled) > 0
	hasFrameworkOverrides := len(ruleFile.FrameworkOverrides) > 0
	hasFrameworkExtensions := len(ruleFile.FrameworkExtensions) > 0

	if len(ruleFile.Rules) == 0 && !hasFrameworkConfig && !hasFrameworkOverrides && !hasFrameworkExtensions {
		result.Valid = false
		result.Errors = append(result.Errors, ruleValidationError{
			Error: "no rules, framework config, or framework overrides defined",
		})
		return printValidateResult(formatter, result)
	}

	// Validate framework_extensions (B11.5.5 — strong validation)
	knownFrameworks := getKnownFrameworkNames()
	for fwName, ext := range ruleFile.FrameworkExtensions {
		if !knownFrameworks[fwName] {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("framework_extensions.%s: unknown framework (will be ignored at scan time)", fwName))
		}

		// Track entries for duplicate detection
		seenSources := map[string]bool{}
		seenSinks := map[string]bool{}
		seenSanitizers := map[string]bool{}

		for i, src := range ext.CustomSources {
			funcName := src.FuncName()
			if funcName == "" && src.Annotation == "" {
				result.Errors = append(result.Errors, ruleValidationError{
					Error: fmt.Sprintf("framework_extensions.%s.custom_sources[%d]: must set func or annotation", fwName, i),
				})
				continue
			}
			// Check for duplicates
			key := funcName + src.Annotation
			if seenSources[key] {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("framework_extensions.%s.custom_sources[%d]: duplicate source %q", fwName, i, key))
			}
			seenSources[key] = true
		}

		for i, sink := range ext.CustomSinks {
			funcName := sink.FuncName()
			if funcName == "" {
				result.Errors = append(result.Errors, ruleValidationError{
					Error: fmt.Sprintf("framework_extensions.%s.custom_sinks[%d]: must set func or function", fwName, i),
				})
				continue
			}
			// Warn if sink has no CWE/category — it will attach to ALL rules
			if sink.CWE == "" && sink.Category == "" {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("framework_extensions.%s.custom_sinks[%d] %s: no cwe or category — will attach to ALL taint rules (potential noise)", fwName, i, funcName))
			}
			// Validate CWE format if provided
			if sink.CWE != "" && !regexp.MustCompile(`^CWE-\d+$`).MatchString(sink.CWE) {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("framework_extensions.%s.custom_sinks[%d] %s: cwe %q does not match CWE-NNN format", fwName, i, funcName, sink.CWE))
			}
			// Check for duplicates
			if seenSinks[funcName] {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("framework_extensions.%s.custom_sinks[%d]: duplicate sink %q", fwName, i, funcName))
			}
			seenSinks[funcName] = true
		}

		for i, san := range ext.CustomSanitizers {
			funcName := san.FuncName()
			if funcName == "" && san.Regex == "" {
				result.Errors = append(result.Errors, ruleValidationError{
					Error: fmt.Sprintf("framework_extensions.%s.custom_sanitizers[%d]: must set func or regex", fwName, i),
				})
				continue
			}
			if san.Regex != "" {
				if _, err := regexp.Compile(san.Regex); err != nil {
					result.Errors = append(result.Errors, ruleValidationError{
						Error: fmt.Sprintf("framework_extensions.%s.custom_sanitizers[%d]: invalid regex: %v", fwName, i, err),
					})
				}
			}
			// Check for duplicates
			key := funcName + san.Regex
			if seenSanitizers[key] {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("framework_extensions.%s.custom_sanitizers[%d]: duplicate sanitizer", fwName, i))
			}
			seenSanitizers[key] = true
		}

		for i, sp := range ext.SafePatterns {
			if sp.Pattern == "" {
				result.Errors = append(result.Errors, ruleValidationError{
					Error: fmt.Sprintf("framework_extensions.%s.safe_patterns[%d]: must set pattern", fwName, i),
				})
				continue
			}
			if _, err := regexp.Compile(sp.Pattern); err != nil {
				result.Errors = append(result.Errors, ruleValidationError{
					Error: fmt.Sprintf("framework_extensions.%s.safe_patterns[%d]: invalid regex: %v", fwName, i, err),
				})
			}
		}
	}

	// Track seen IDs for uniqueness check.
	seen := map[string]bool{}

	for i, r := range ruleFile.Rules {
		// Use index as a fallback label when ID is missing.
		label := r.ID
		if label == "" {
			label = fmt.Sprintf("rule[%d]", i)
		}

		// 2. Required fields: id, title, pattern, severity.
		if r.ID == "" {
			result.Errors = append(result.Errors, ruleValidationError{
				Error: fmt.Sprintf("rule at index %d: missing required field 'id'", i),
			})
		}
		if r.Title == "" {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: label,
				Error:  "missing required field 'title'",
			})
		}
		if r.Pattern == "" {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: label,
				Error:  "missing required field 'pattern'",
			})
		}
		if r.Severity == "" {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: label,
				Error:  "missing required field 'severity'",
			})
		}

		// 3. Severity is one of: low, medium, high, critical.
		if r.Severity != "" && !validSeverities[r.Severity] {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: label,
				Error:  fmt.Sprintf("invalid severity %q (must be one of: low, medium, high, critical)", r.Severity),
			})
		}

		// 4. Pattern is a valid regex.
		if r.Pattern != "" {
			if _, err := regexp.Compile(r.Pattern); err != nil {
				result.Errors = append(result.Errors, ruleValidationError{
					RuleID: label,
					Error:  fmt.Sprintf("invalid regex pattern: %v", err),
				})
			}
		}

		// 5. Languages field is present and non-empty.
		if len(r.Languages) == 0 {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: label,
				Error:  "missing or empty required field 'languages'",
			})
		}

		// 6. Rule IDs are unique.
		if r.ID != "" {
			if seen[r.ID] {
				result.Errors = append(result.Errors, ruleValidationError{
					RuleID: r.ID,
					Error:  "duplicate rule ID",
				})
			}
			seen[r.ID] = true
		}

		// 7. Rule IDs match the naming convention.
		if r.ID != "" && !idPattern.MatchString(r.ID) {
			result.Errors = append(result.Errors, ruleValidationError{
				RuleID: r.ID,
				Error:  "rule ID must match pattern ^[A-Z][A-Z0-9]+(-[A-Z0-9]+)+$ (uppercase alphanumeric segments separated by hyphens, e.g. CUSTOM-001, MYAPP-XSS-001, PF-FASTAPI-SQLI-001)",
			})
		}
	}

	result.Valid = len(result.Errors) == 0
	return printValidateResult(formatter, result)
}

func printValidateResult(formatter output.Formatter, result rulesValidateResult) error {
	if output.IsJSON(formatter) {
		return formatter.Print(result)
	}

	if result.Valid {
		_ = formatter.PrintSuccess(fmt.Sprintf("%d rules, %d framework overrides, and %d framework extensions validated successfully", result.Rules, result.FrameworkOverrides, result.FrameworkExtensions))
		_ = formatter.Print("  File: " + result.Path)
		for _, w := range result.Warnings {
			_ = formatter.Print("  \u26a0 " + w)
		}
		return nil
	}

	_ = formatter.Print("Validation failed for " + result.Path)
	_ = formatter.Print("")
	for _, e := range result.Errors {
		if e.RuleID != "" {
			_ = formatter.Print(fmt.Sprintf("  \u2717 [%s] %s", e.RuleID, e.Error))
		} else {
			_ = formatter.Print("  \u2717 " + e.Error)
		}
	}
	for _, w := range result.Warnings {
		_ = formatter.Print("  \u26a0 " + w)
	}
	_ = formatter.Print("")
	_ = formatter.Print(fmt.Sprintf("%d error(s), %d warning(s).", len(result.Errors), len(result.Warnings)))
	// Signal failure to cobra so the process exits with code 1.
	return fmt.Errorf("rules validation failed: %d error(s)", len(result.Errors))
}

// getKnownFrameworkNames returns a set of known framework pack names.
func getKnownFrameworkNames() map[string]bool {
	fwReg := packs.BuildDefaultRegistry()
	known := make(map[string]bool)
	for _, p := range fwReg.All() {
		known[p.Name()] = true
	}
	return known
}
