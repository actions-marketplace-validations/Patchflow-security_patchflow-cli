// Package rulesconfig provides ESLint-style rule mode configuration for
// PatchFlow. Users can create a `.patchflow/rules.yaml` (or pass
// `--rules-config <path>`) to control whether each rule blocks CI, reports
// only, or is suppressed entirely.
//
// The three modes are:
//
//   - block: finding is reported and contributes to a non-zero exit code
//   - inform: finding is reported but does not affect the exit code
//   - off: finding is suppressed entirely (not reported)
//
// When a rule is not listed in the config, its mode is derived from the
// governance registry's maturity-based defaults:
//
//   - stable + high/critical severity → block
//   - stable + medium/low severity → inform
//   - beta → inform
//   - experimental → inform (never block unless user explicitly sets block)
//
// Example .patchflow/rules.yaml:
//
//   # Rule mode overrides (ESLint-style)
//   rules:
//     PF-SPRING-SSRF-001: block
//     PF-EXPRESS-AUTH-001: inform
//     G601: off
//
//   # Custom pattern rules (existing format, unchanged)
//   custom_rules:
//     - id: CUSTOM-001
//       title: No console.log in production
//       pattern: 'console\.log\s*\('
//       languages: [javascript, typescript]
//       severity: low
//
//   # Custom taint rules (existing format, unchanged)
//   custom_taint_rules:
//     - id: CUSTOM-TAINT-001
//       ...
//
//   # Framework pack controls (existing format, unchanged)
//   frameworks:
//     auto_detect: true
//     enabled: [rails, spring]
//     disabled: [angular]
package rulesconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode is the enforcement mode for a rule.
type Mode string

const (
	// ModeBlock reports the finding and contributes to a non-zero exit code.
	ModeBlock Mode = "block"

	// ModeInform reports the finding but does not affect the exit code.
	ModeInform Mode = "inform"

	// ModeOff suppresses the finding entirely.
	ModeOff Mode = "off"

	// ModeDefault means no explicit mode is set; the mode is derived from
	// the governance registry's maturity-based defaults.
	ModeDefault Mode = ""
)

// IsValid returns true if the mode is a recognized value.
func (m Mode) IsValid() bool {
	switch m {
	case ModeBlock, ModeInform, ModeOff, ModeDefault:
		return true
	}
	return false
}

// ModeSource indicates where a rule's mode was determined.
type ModeSource string

const (
	// ModeSourceProjectConfig means the mode was set in .patchflow/rules.yaml.
	ModeSourceProjectConfig ModeSource = "project_config"

	// ModeSourceCLI means the mode was set via a CLI flag.
	ModeSourceCLI ModeSource = "cli"

	// ModeSourceDefault means the mode was derived from maturity-based defaults.
	ModeSourceDefault ModeSource = "default"
)

// RuleModeEntry is the resolved mode for a single rule, including provenance.
type RuleModeEntry struct {
	RuleID   string     `json:"rule_id"`
	Mode     Mode       `json:"mode"`
	Blocking bool       `json:"blocking"`
	Source   ModeSource `json:"mode_source"`
	Maturity string     `json:"maturity,omitempty"`
}

// Config is the parsed rule-mode configuration from .patchflow/rules.yaml.
// It is intentionally separate from the customrules.Policy to keep mode
// governance decoupled from custom rule definitions.
type Config struct {
	// SchemaVersion is the config schema version (B12.6). If empty, the
	// loader assumes "1.0" and emits a warning via validate.
	SchemaVersion string `yaml:"schema_version"`

	// RuleModes maps rule IDs to their explicit mode (block/inform/off).
	// Rules not in this map use maturity-based defaults.
	//
	// NOTE: The unified --config flag (B11.5.4) routes the same YAML file to
	// both this loader and the customrules loader. The customrules loader
	// historically reads `rules:` as a list of custom pattern rules, while
	// this struct reads `rules:` as a map of rule modes. To keep both uses
	// working with a single file, LoadFromBytes tolerates `rules:` being
	// either a mapping (mode overrides) or a sequence (legacy custom rules).
	// When it is a sequence, RuleModes is left empty and the customrules
	// loader owns those entries.
	RuleModes map[string]Mode `yaml:"rules"`

	// CustomRules is the legacy custom pattern rules section (unchanged).
	// This is kept here so a single YAML file can contain both mode overrides
	// and custom rules without breaking backward compatibility.
	CustomRules      []rawRule      `yaml:"custom_rules"`
	CustomTaintRules []rawTaintRule `yaml:"custom_taint_rules"`

	// Frameworks controls framework-pack activation (unchanged).
	Frameworks rawFrameworkSelection `yaml:"frameworks"`

	// FrameworkOverrides extends official framework packs (unchanged).
	FrameworkOverrides map[string]rawFrameworkOverride `yaml:"framework_overrides"`

	// FrameworkExtensions is the B11 extension point. It allows teams to
	// add organization-specific sources, sinks, sanitizers, and safe patterns
	// to official framework packs. Unlike framework_overrides, extensions
	// support CWE metadata on custom sinks and safe_patterns for suppression.
	// Both sections are merged into the same pack override pipeline.
	FrameworkExtensions map[string]rawFrameworkExtension `yaml:"framework_extensions"`
}

// rawRule is an alias for the customrules YAML rule, kept as raw yaml.Node
// to avoid importing customrules here (which would create a dependency).
type rawRule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Languages   []string `yaml:"languages"`
	Pattern     string   `yaml:"pattern"`
	Severity    string   `yaml:"severity"`
	Confidence  string   `yaml:"confidence"`
}

type rawTaintRule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Language    string   `yaml:"language"`
	Severity    string   `yaml:"severity"`
	Confidence  string   `yaml:"confidence"`
	CWE         string   `yaml:"cwe"`
}

type rawFrameworkSelection struct {
	AutoDetect *bool    `yaml:"auto_detect"`
	Enabled    []string `yaml:"enabled"`
	Disabled   []string `yaml:"disabled"`
}

type rawFrameworkOverride struct {
	CustomSources     []rawFrameworkSource    `yaml:"custom_sources"`
	CustomSinks       []rawFrameworkSink      `yaml:"custom_sinks"`
	CustomSanitizers  []rawFrameworkSanitizer `yaml:"custom_sanitizers"`
	SeverityOverrides map[string]string       `yaml:"severity_overrides"`
}

type rawFrameworkSource struct {
	Func        string `yaml:"func"`
	IsSubscript bool   `yaml:"is_subscript"`
	Annotation  string `yaml:"annotation"`
}

type rawFrameworkSink struct {
	Func     string `yaml:"func"`
	ArgIndex int    `yaml:"arg_index"`
}

type rawFrameworkSanitizer struct {
	Func  string `yaml:"func"`
	Regex string `yaml:"regex"`
}

// rawFrameworkExtension is the B11 extension schema. It extends the
// framework_overrides schema with safe_patterns and CWE metadata on sinks.
type rawFrameworkExtension struct {
	CustomSources    []rawFrameworkSource    `yaml:"custom_sources"`
	CustomSinks      []rawExtensionSink      `yaml:"custom_sinks"`
	CustomSanitizers []rawFrameworkSanitizer `yaml:"custom_sanitizers"`
	SafePatterns     []rawSafePattern        `yaml:"safe_patterns"`
}

// rawExtensionSink extends rawFrameworkSink with CWE/category/severity so
// custom sinks can declare what vulnerability category they represent.
type rawExtensionSink struct {
	Func     string `yaml:"func"`
	ArgIndex int    `yaml:"arg_index"`
	CWE      string `yaml:"cwe"`
	Category string `yaml:"category"`
	Severity string `yaml:"severity"`
}

// rawSafePattern declares a pattern that suppresses a finding when found
// on the same line (e.g., an internal auth helper that validates ownership).
type rawSafePattern struct {
	Pattern string `yaml:"pattern"`
	Reason  string `yaml:"reason"`
}

// LoadFromFile loads a rules config from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules config: %w", err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses a rules config from YAML bytes.
//
// The `rules:` key is ambiguous in the unified config (B11.5.4): it may be a
// mapping of rule-id -> mode (the mode-override schema) or a sequence of
// custom pattern rules (the legacy customrules schema, still accepted for
// backward compatibility). We decode `rules:` into a yaml.Node first and
// branch on its kind so a single file works with both loaders.
func LoadFromBytes(data []byte) (*Config, error) {
	// First pass: pull out just the `rules:` node so we can decide how to
	// decode it. Everything else is decoded normally into cfg below.
	var probe struct {
		Rules yaml.Node `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("failed to parse rules config YAML: %w", err)
	}

	var cfg Config
	switch probe.Rules.Kind {
	case yaml.SequenceNode:
		// `rules:` is a list of custom pattern rules (legacy/customrules
		// schema). The customrules loader owns these; RuleModes stays empty.
		// We must decode the rest of the document without the `rules:` field
		// to avoid a "!!seq into map" unmarshal error.
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			// Fall back to decoding without the conflicting field by zeroing
			// it via a node-based decode (see decodeIgnoringRules).
			cfg = Config{}
			if err2 := decodeIgnoringRules(data, &cfg); err2 != nil {
				return nil, fmt.Errorf("failed to parse rules config YAML: %w", err)
			}
		}
		cfg.RuleModes = make(map[string]Mode)
	case yaml.MappingNode:
		// `rules:` is a map of rule-id -> mode. Decode normally.
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse rules config YAML: %w", err)
		}
	default:
		// No `rules:` key (or scalar/alias). Decode the rest normally.
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse rules config YAML: %w", err)
		}
		cfg.RuleModes = make(map[string]Mode)
	}

	// Validate mode values
	for id, mode := range cfg.RuleModes {
		if !mode.IsValid() {
			return nil, fmt.Errorf("rule %s: invalid mode %q (expected block, inform, or off)", id, mode)
		}
	}
	if cfg.RuleModes == nil {
		cfg.RuleModes = make(map[string]Mode)
	}
	if cfg.FrameworkOverrides == nil {
		cfg.FrameworkOverrides = make(map[string]rawFrameworkOverride)
	}
	if cfg.FrameworkExtensions == nil {
		cfg.FrameworkExtensions = make(map[string]rawFrameworkExtension)
	}
	return &cfg, nil
}

// decodeIgnoringRules unmarshals the YAML document into cfg while treating the
// `rules:` key as absent. This is used when `rules:` is a sequence (custom
// rules list) so the map-typed RuleModes field does not raise a type error.
func decodeIgnoringRules(data []byte, cfg *Config) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return yaml.Unmarshal(data, cfg)
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return yaml.Unmarshal(data, cfg)
	}
	// Rebuild the mapping without the `rules` key.
	filtered := &yaml.Node{Kind: yaml.MappingNode, Tag: top.Tag}
	for i := 0; i+1 < len(top.Content); i += 2 {
		k := top.Content[i]
		if k.Kind == yaml.ScalarNode && strings.EqualFold(k.Value, "rules") {
			continue // skip
		}
		filtered.Content = append(filtered.Content, k, top.Content[i+1])
	}
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{filtered}}
	return doc.Decode(cfg)
}

// LoadFromDir loads `.patchflow/rules.yaml` from the given directory.
// Returns an empty config if the file does not exist (not an error).
func LoadFromDir(dir string) (*Config, error) {
	path := filepath.Join(dir, ".patchflow", "rules.yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &Config{
			RuleModes:          make(map[string]Mode),
			FrameworkOverrides: make(map[string]rawFrameworkOverride),
			FrameworkExtensions: make(map[string]rawFrameworkExtension),
		}, nil
	}
	return LoadFromFile(path)
}

// GetMode returns the explicit mode for a rule, or ModeDefault if not set.
func (c *Config) GetMode(ruleID string) Mode {
	if c == nil || c.RuleModes == nil {
		return ModeDefault
	}
	return c.RuleModes[ruleID]
}

// SetMode sets the mode for a rule. Used by CLI flags to override config.
func (c *Config) SetMode(ruleID string, mode Mode) {
	if c.RuleModes == nil {
		c.RuleModes = make(map[string]Mode)
	}
	c.RuleModes[ruleID] = mode
}

// HasCustomRules returns true if the config contains legacy custom_rules.
func (c *Config) HasCustomRules() bool {
	return len(c.CustomRules) > 0 || len(c.CustomTaintRules) > 0
}

// HasFrameworkConfig returns true if the config contains framework controls.
func (c *Config) HasFrameworkConfig() bool {
	return c.Frameworks.AutoDetect != nil ||
		len(c.Frameworks.Enabled) > 0 ||
		len(c.Frameworks.Disabled) > 0 ||
		len(c.FrameworkOverrides) > 0 ||
		len(c.FrameworkExtensions) > 0
}

// HasFrameworkExtensions returns true if the config contains framework_extensions.
func (c *Config) HasFrameworkExtensions() bool {
	return len(c.FrameworkExtensions) > 0
}

// GetSchemaVersion returns the config schema version, defaulting to "1.0" if unset.
func (c *Config) GetSchemaVersion() string {
	if c.SchemaVersion == "" {
		return "1.0"
	}
	return c.SchemaVersion
}

// AllConfiguredRuleIDs returns the rule IDs that have an explicit mode set,
// sorted alphabetically.
func (c *Config) AllConfiguredRuleIDs() []string {
	if c == nil || c.RuleModes == nil {
		return nil
	}
	ids := make([]string, 0, len(c.RuleModes))
	for id := range c.RuleModes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// UnknownRules returns rule IDs in the config that are not in the known set.
// This is used to warn users about typos in their config without failing.
func (c *Config) UnknownRules(knownRuleIDs map[string]bool) []string {
	var unknown []string
	for id := range c.RuleModes {
		if !knownRuleIDs[id] {
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// ModeString normalizes a mode string for display.
func ModeString(m Mode) string {
	switch m {
	case ModeBlock:
		return "block"
	case ModeInform:
		return "inform"
	case ModeOff:
		return "off"
	default:
		return "default"
	}
}

// ParseMode parses a mode string, returning an error if invalid.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "block":
		return ModeBlock, nil
	case "inform", "warn", "warning":
		return ModeInform, nil
	case "off", "disable", "disabled":
		return ModeOff, nil
	case "", "default":
		return ModeDefault, nil
	default:
		return ModeDefault, fmt.Errorf("invalid mode %q (expected block, inform, or off)", s)
	}
}
