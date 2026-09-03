// Package sast runs static analysis security tools on the repository.
// It uses embedded scanners (Go SAST, secret scanner, multi-language pattern
// scanner) that require no external installation, and supplements them with
// external tools (gosec, bandit, semgrep, gitleaks) when available.
//
// The embedded scanners run first and always provide baseline coverage.
// External tools run second and add deeper analysis when installed.
package sast

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/cwe"
	"github.com/Patchflow-security/patchflow-cli/internal/frameworks"
	"github.com/Patchflow-security/patchflow-cli/internal/ignore"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/customrules"
	fwpatterns "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks/packs"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/gosast"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/incremental"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/patterns"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/secrets"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/suppression"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/taint"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/taintpatterns"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/treesitter"
)

// Tool represents an external SAST tool that can be invoked via subprocess.
type Tool struct {
	Name        string
	Binary      string
	Language    string // primary language (go, python, multi, secrets)
	IsAvailable func() bool
	Run         func(ctx context.Context, root string) ([]analysis.Finding, error)
}

// Runner manages embedded scanners and external SAST tools.
type Runner struct {
	// Embedded scanners (always available, no installation required)
	gosastAnalyzer       *gosast.Analyzer
	secretScanner        *secrets.Scanner
	patternScanner       *patterns.Scanner
	taintAnalyzer        *taint.Analyzer
	treesitterAnalyzer   *treesitter.Analyzer
	taintPatternAnalyzer *taintpatterns.Analyzer

	// Suppression manager for //patchflow:ignore directives
	suppressionMgr *suppression.Manager

	// External tools (optional, supplement embedded scanners)
	Tools        []Tool
	ChangedOnly  bool
	ChangedFiles []string
	Timeout      time.Duration

	// Flags to control which scanners run
	NoEmbeddedGo            bool
	NoEmbeddedSecrets       bool
	NoEmbeddedPatterns      bool
	NoEmbeddedTaint         bool
	NoEmbeddedTreeSitter    bool
	NoEmbeddedTaintPatterns bool

	// ShowSuppressed controls whether suppressed findings are included in output
	ShowSuppressed bool

	// IncludeTests controls whether findings from test files are included.
	IncludeTests bool

	// CustomRulesPath is the path to a custom rules YAML file.
	// If empty, the runner looks for .patchflow/rules.yaml in the project root.
	CustomRulesPath string

	// IncrementalScan enables incremental scanning: only files that changed
	// since the last scan (tracked via .patchflow/cache/sast_state.json) are
	// re-scanned by the file-based scanners (patterns, secrets, tree-sitter).
	// Go SAST and taint analysis always run fully (they use go/packages).
	IncrementalScan bool

	// GitChangedFiles is the list of files changed according to git diff.
	// When set, the incremental scanner uses this as a pre-filter instead of
	// walking the entire tree. This gives the fastest incremental scans.
	GitChangedFiles []string

	// RespectGitignore controls whether .gitignore patterns are loaded and
	// used to skip files during scanning. When true, a .gitignore matcher is
	// initialized on first use and shared across all embedded scanners.
	RespectGitignore bool

	// TaintDepth controls the maximum inter-procedural call-hop depth for
	// the taint pattern analyzer. 0 disables inter-procedural analysis.
	// Default is 3. Set via the --taint-depth CLI flag.
	TaintDepth int

	// Quiet suppresses diagnostic log output (SAST timing logs, etc.) to
	// keep stdout/stderr clean in JSON mode or CI scripting.
	Quiet bool

	// FrameworkConfig controls which framework rule packs are activated.
	// It is the highest-precedence layer and is typically set from CLI flags.
	FrameworkConfig fwpatterns.SelectionConfig
	// FrameworkProjectConfig is the lower-precedence project-level framework
	// selection loaded from .patchflow/config.yml.
	FrameworkProjectConfig fwpatterns.SelectionConfig

	// fwSafePatterns maps framework rule IDs to their safe patterns (B11.5.3).
	// Used for taint-mode safe pattern suppression after scanning.
	fwSafePatterns map[string][]fwpatterns.SafePattern

	// fwSafePatternsByCWE maps "CWE-89:ruby" → safe patterns. Allows generic
	// taint rules (TP-RB001, TP-PY001) to be suppressed by framework safe
	// patterns when the framework is active.
	fwSafePatternsByCWE map[string][]fwpatterns.SafePattern

	// FrameworksDetected holds the frameworks detected during the last
	// Analyze run. Populated by Analyze; read by callers for reporting
	// and explain output.
	FrameworksDetected []frameworks.Detection

	// frameworkRegistry holds all official embedded framework packs. It is
	// lazily initialized on first use.
	frameworkRegistry *fwpatterns.Registry
}

// defaultFrameworkRegistrySingleton is the package-level shared framework
// registry. Building the registry involves constructing 18 framework packs
// with precompiled regex patterns, so we build it once and share it across
// all Runner instances. This avoids rebuilding the registry on every scan
// when a new Runner is created.
var (
	defaultFrameworkRegistryOnce sync.Once
	defaultFrameworkRegistryInst *fwpatterns.Registry
)

func defaultFrameworkRegistry() *fwpatterns.Registry {
	defaultFrameworkRegistryOnce.Do(func() {
		defaultFrameworkRegistryInst = packs.BuildDefaultRegistry()
	})
	return defaultFrameworkRegistryInst
}

// SetTaintDepth configures the inter-procedural taint analysis depth on the
// taint pattern analyzer. 0 disables inter-procedural analysis.
func (r *Runner) SetTaintDepth(depth int) {
	r.TaintDepth = depth
	r.taintPatternAnalyzer.SetTaintDepth(depth)
}

// NewRunner creates a SAST runner with embedded scanners and external tools.
func NewRunner() *Runner {
	r := &Runner{
		Timeout:              120 * time.Second,
		gosastAnalyzer:       gosast.NewAnalyzer(),
		secretScanner:        secrets.NewScanner(),
		patternScanner:       patterns.NewScanner(),
		taintAnalyzer:        taint.NewAnalyzer(),
		treesitterAnalyzer:   treesitter.NewAnalyzer(),
		taintPatternAnalyzer: taintpatterns.NewAnalyzer(),
		suppressionMgr:       suppression.NewManager(),
		TaintDepth:           taintpatterns.DefaultTaintDepth,
	}
	r.taintPatternAnalyzer.SetTaintDepth(r.TaintDepth)

	r.Tools = []Tool{
		{
			Name:        "gosec",
			Binary:      "gosec",
			Language:    "go",
			IsAvailable: func() bool { return commandExists("gosec") },
			Run:         runGosec,
		},
		{
			Name:        "bandit",
			Binary:      "bandit",
			Language:    "python",
			IsAvailable: func() bool { return commandExists("bandit") },
			Run:         runBandit,
		},
		{
			Name:        "semgrep",
			Binary:      "semgrep",
			Language:    "multi",
			IsAvailable: func() bool { return commandExists("semgrep") },
			Run:         runSemgrep,
		},
		{
			Name:        "gitleaks",
			Binary:      "gitleaks",
			Language:    "secrets",
			IsAvailable: func() bool { return commandExists("gitleaks") },
			Run:         runGitleaks,
		},
		{
			Name:        "checkov",
			Binary:      "checkov",
			Language:    "iac",
			IsAvailable: func() bool { return commandExists("checkov") },
			Run:         runCheckov,
		},
	}

	return r
}

// loadRulePolicy loads the user YAML policy, adds generic regex rules to the
// pattern scanner, and returns any framework selection/override metadata.
func (r *Runner) loadRulePolicy(root string) (*customrules.Policy, error) {
	var (
		policy *customrules.Policy
		err    error
	)

	if r.CustomRulesPath != "" {
		policy, err = customrules.LoadPolicyFromFile(r.CustomRulesPath)
	} else {
		policy, err = customrules.LoadPolicyFromDir(root)
	}
	if err != nil {
		return nil, err
	}
	if len(policy.PatternRules) > 0 {
		r.patternScanner.AddRules(policy.PatternRules)
	}
	// Convert custom taint rules to taintpatterns.Rule and register them.
	if len(policy.TaintRules) > 0 {
		customTaintRules := make([]taintpatterns.Rule, 0, len(policy.TaintRules))
		for _, tr := range policy.TaintRules {
			sources := make([]taintpatterns.SourcePattern, len(tr.Sources))
			for i, s := range tr.Sources {
				sources[i] = taintpatterns.SourcePattern{FuncName: s.FuncName, IsSubscript: s.IsSubscript}
			}
			sinks := make([]taintpatterns.SinkPattern, len(tr.Sinks))
			for i, s := range tr.Sinks {
				sinks[i] = taintpatterns.SinkPattern{FuncName: s.FuncName, ArgIndex: s.ArgIndex}
			}
			sanitizers := make([]taintpatterns.SanitizerPattern, len(tr.Sanitizers))
			for i, s := range tr.Sanitizers {
				sanitizers[i] = taintpatterns.SanitizerPattern{FuncName: s.FuncName}
			}
			customTaintRules = append(customTaintRules, taintpatterns.Rule{
				ID:          tr.ID,
				Title:       tr.Title,
				Description: tr.Description,
				Severity:    tr.Severity,
				Confidence:  tr.Confidence,
				Language:    tr.Language,
				CWEID:       tr.CWEID,
				Sources:     sources,
				Sinks:       sinks,
				Sanitizers:  sanitizers,
			})
		}
		r.taintPatternAnalyzer.AddRules(customTaintRules)
	}
	return policy, nil
}

// RuleGroup represents a group of rules from a specific scanner.
type RuleGroup struct {
	Scanner   string // "gosast-embedded", "secrets-embedded", "patterns-embedded"
	Language  string // "go", "multi", "secrets"
	RuleCount int
	Rules     []RuleEntry
}

// RuleEntry represents a single rule for display purposes.
type RuleEntry struct {
	ID       string
	Title    string
	Severity string
}

// AllRules returns all registered rules from all embedded scanners.
// Custom rules loaded from YAML are included if LoadCustomRules was called.
func (r *Runner) AllRules() []RuleGroup {
	var groups []RuleGroup

	// Go SAST rules
	if !r.NoEmbeddedGo {
		gosastRules := r.gosastAnalyzer.Rules()
		entries := make([]RuleEntry, 0, len(gosastRules))
		for _, ri := range gosastRules {
			entries = append(entries, RuleEntry{
				ID:       ri.ID,
				Title:    ri.What,
				Severity: string(ri.Severity),
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "gosast-embedded",
			Language:  "go",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	// Secret scanner rules
	if !r.NoEmbeddedSecrets {
		secretRules := r.secretScanner.Rules()
		entries := make([]RuleEntry, 0, len(secretRules))
		for _, si := range secretRules {
			entries = append(entries, RuleEntry{
				ID:       "SECRET-" + si.RuleID,
				Title:    si.Name,
				Severity: string(si.Severity),
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "secrets-embedded",
			Language:  "secrets",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	// Pattern scanner rules (includes custom rules if loaded)
	if !r.NoEmbeddedPatterns {
		patternRules := r.patternScanner.Rules()
		entries := make([]RuleEntry, 0, len(patternRules))
		for _, pr := range patternRules {
			entries = append(entries, RuleEntry{
				ID:       pr.ID,
				Title:    pr.Title,
				Severity: string(pr.Severity),
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "patterns-embedded",
			Language:  "multi",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	// Taint analysis rules (SSA-based, Go only)
	if !r.NoEmbeddedTaint && !r.NoEmbeddedGo {
		taintRules := r.taintAnalyzer.Rules()
		entries := make([]RuleEntry, 0, len(taintRules))
		for _, tr := range taintRules {
			entries = append(entries, RuleEntry{
				ID:       tr.ID,
				Title:    tr.Title,
				Severity: tr.Severity,
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "taint-ssa",
			Language:  "go",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	// Tree-sitter AST rules (non-Go languages)
	if !r.NoEmbeddedTreeSitter {
		tsRules := r.treesitterAnalyzer.Rules()
		entries := make([]RuleEntry, 0, len(tsRules))
		for _, tr := range tsRules {
			entries = append(entries, RuleEntry{
				ID:       tr.ID,
				Title:    tr.Title,
				Severity: tr.Severity,
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "treesitter-ast",
			Language:  "multi",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	// Taint pattern rules (Python and JS/TS source-sink analysis)
	if !r.NoEmbeddedTaintPatterns {
		tpRules := r.taintPatternAnalyzer.Rules()
		entries := make([]RuleEntry, 0, len(tpRules))
		for _, tr := range tpRules {
			entries = append(entries, RuleEntry{
				ID:       tr.ID,
				Title:    tr.Title,
				Severity: string(tr.Severity),
			})
		}
		groups = append(groups, RuleGroup{
			Scanner:   "taint-patterns",
			Language:  "multi",
			RuleCount: len(entries),
			Rules:     entries,
		})
	}

	return groups
}

// LoadCustomRules loads custom rules from the specified path or from
// .patchflow/rules.yaml in the given root directory. This is public so
// commands like `rules list` can load custom rules without running a full scan.
func (r *Runner) LoadCustomRules(root string) error {
	_, err := r.loadRulePolicy(root)
	if err != nil {
		return fmt.Errorf("loading custom rules from %s: %w", root, err)
	}
	return nil
}

// AvailableTools returns the names of external tools that are installed and ready to run.
func (r *Runner) AvailableTools() []string {
	var available []string
	for _, t := range r.Tools {
		if t.IsAvailable() {
			available = append(available, t.Name)
		}
	}
	return available
}

// EmbeddedTools returns the names of embedded scanners that are always available.
func (r *Runner) EmbeddedTools() []string {
	return []string{"gosast-embedded", "secrets-embedded", "patterns-embedded", "taint-ssa", "treesitter-ast", "taint-patterns"}
}

// Result is the output of a SAST analysis run.
type Result struct {
	Findings        []analysis.Finding      `json:"findings"`
	ToolsRun        []string                `json:"tools_run"`
	ToolsSkipped    []string                `json:"tools_skipped"`
	Errors          []string                `json:"errors,omitempty"`
	SuppressedCount int                     `json:"suppressed_count,omitempty"`
	Frameworks      []frameworks.Detection  `json:"frameworks,omitempty"`
	EngineTimings   []analysis.EngineTiming `json:"engine_timings,omitempty"`
}

// Analyze runs all embedded scanners first, then external tools as supplements.
func (r *Runner) Analyze(ctx context.Context, root string) (*Result, error) {
	result := &Result{}
	var timings []analysis.EngineTiming
	phaseStart := time.Now()

	// --- Phase 0: Load custom rules from YAML ---
	policy, err := r.loadRulePolicy(root)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("custom-rules: %v", err))
	}

	// --- Phase 0b: Load .gitignore matcher if enabled ---
	var ignoreMatcher *ignore.Matcher
	if r.RespectGitignore {
		ignoreCache := ignore.NewCache(root)
		if matcher := ignoreCache.Get(); !matcher.IsEmpty() {
			ignoreMatcher = matcher
			r.secretScanner.SetIgnoreMatcher(matcher)
			r.patternScanner.SetIgnoreMatcher(matcher)
			r.treesitterAnalyzer.SetIgnoreMatcher(matcher)
		}
	}

	// --- Phase 0c: Framework detection + pack selection ---
	// Detect frameworks in the project, select the official embedded packs to
	// activate, build a line matcher for pattern/template rules, and register
	// framework taint rules into the taint engine. No detection => no
	// framework rules run, which keeps noise out of non-framework projects.
	var frameworkMatcher *fwpatterns.Matcher
	if r.frameworkRegistry == nil {
		r.frameworkRegistry = defaultFrameworkRegistry()
	}
	loader := fwpatterns.NewLoader(r.frameworkRegistry)
	cfg := r.FrameworkProjectConfig
	if policy != nil {
		cfg = fwpatterns.MergeSelectionConfig(cfg, policy.FrameworkSelection)
	}
	cfg = fwpatterns.MergeSelectionConfig(cfg, r.FrameworkConfig)
	if !cfg.AutoDetectSet && len(cfg.Enabled) == 0 {
		// Default: auto-detect on when nothing explicit was configured.
		cfg.AutoDetect = true
		cfg.AutoDetectSet = true
	}
	selection := loader.SelectForRoot(root, cfg, frameworks.NewDetector())
	r.FrameworksDetected = selection.Detections
	result.Frameworks = selection.Detections
	if len(selection.Packs) > 0 {
		var fwRules []fwpatterns.FrameworkRule
		// Collect safe patterns per rule ID for taint suppression (B11.5.3).
		// Pattern/template rules already use safe patterns in the matcher;
		// this map enables taint-rule safe pattern suppression.
		fwSafePatterns := map[string][]fwpatterns.SafePattern{}
		// fwSafePatternsByCWE maps "CWE-89:ruby" → safe patterns. This allows
		// generic taint rules (TP-RB001, TP-PY001) to be suppressed by framework
		// safe patterns when the framework is active. Without this, a Rails
		// .where( safe pattern registered for PF-RAILS-SQLI-003 would not
		// suppress the generic TP-RB001 finding on the same code.
		fwSafePatternsByCWE := map[string][]fwpatterns.SafePattern{}
		for _, p := range selection.Packs {
			if policy != nil {
				if override, ok := policy.FrameworkOverrides[p.Name()]; ok {
					p = fwpatterns.ApplyPackOverride(p, override)
				}
			}
			for _, r := range p.Rules() {
				if len(r.SafePatterns) > 0 {
					fwSafePatterns[r.ID] = r.SafePatterns
					// Also index by CWE+language for generic taint rule suppression
					if r.CWE != "" && r.Language != "" {
						key := r.CWE + ":" + r.Language
						fwSafePatternsByCWE[key] = append(fwSafePatternsByCWE[key], r.SafePatterns...)
					}
				}
			}
			fwRules = append(fwRules, p.Rules()...)
		}
		frameworkMatcher = fwpatterns.NewMatcher(fwRules)
		// Register framework taint rules into the taint engine so its
		// source->sink tracking covers framework-specific flows.
		r.taintPatternAnalyzer.AddRules(fwpatterns.ToTaintRules(fwRules))
		// Store safe patterns for taint suppression (used in Phase 2e.5).
		r.fwSafePatterns = fwSafePatterns
		r.fwSafePatternsByCWE = fwSafePatternsByCWE
	}
	timings = append(timings, analysis.EngineTiming{Engine: "framework_detection", Duration: time.Since(phaseStart)})
	phaseStart = time.Now()

	// --- Phase 1: Embedded scanners ---
	//
	// Go SAST and taint analysis use go/packages (not file-by-file), so they
	// run as separate goroutines. Pattern, secrets, and tree-sitter scanners
	// use the single-pass parallel file collector for ~4x speedup.
	//
	// Two parallel groups:
	//   Group A: Go SAST + Taint (goroutines, use go/packages)
	//   Group B: Single-pass file dispatch (patterns + secrets + tree-sitter)

	type scannerResult struct {
		name     string
		findings []analysis.Finding
		err      error
	}

	var wg sync.WaitGroup
	// Buffer must be large enough for all possible results:
	// Go SAST (1) + Taint SSA (1) + up to 4 parallel scanners + errors
	resultCh := make(chan scannerResult, 16)

	// Build the git changed file set early — used for Go SAST skip logic
	// and for the file-based scanner pre-filter.
	gitChangedSet := map[string]bool{}
	for _, f := range r.GitChangedFiles {
		gitChangedSet[filepath.Join(root, f)] = true
	}

	// 1a. Embedded Go SAST (gosec rules ported to library)
	// In changed-only mode, skip Go SAST if no .go files changed — it
	// always loads the full module graph via go/packages, so running it
	// when only non-Go files changed is pure waste.
	goFilesChanged := false
	for p := range gitChangedSet {
		if strings.HasSuffix(p, ".go") {
			goFilesChanged = true
			break
		}
	}
	skipGoSAST := r.NoEmbeddedGo || (r.ChangedOnly && len(gitChangedSet) > 0 && !goFilesChanged)

	if !skipGoSAST {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toolCtx, cancel := context.WithTimeout(ctx, r.Timeout)
			findings, err := r.gosastAnalyzer.Analyze(toolCtx, root)
			cancel()
			resultCh <- scannerResult{name: "gosast-embedded", findings: findings, err: err}
		}()
	}

	// 1b. Embedded SSA-based taint analysis (Go only)
	if !r.NoEmbeddedTaint && !skipGoSAST {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// The taint-ssa analyzer has its own internal recovery, but
					// add a second safety net so a panic never kills the scan.
					resultCh <- scannerResult{name: "taint-ssa", findings: nil, err: fmt.Errorf("taint-ssa panic: %v", r)}
				}
			}()
			toolCtx, cancel := context.WithTimeout(ctx, r.Timeout)
			findings, err := r.taintAnalyzer.Analyze(toolCtx, root)
			cancel()
			resultCh <- scannerResult{name: "taint-ssa", findings: findings, err: err}
		}()
	}

	// 1c. Single-pass parallel scanning for patterns + secrets + tree-sitter + taint-patterns
	// This walks the file tree once and dispatches files to all scanners
	// in parallel using a worker pool, eliminating redundant tree walks.
	// When incremental scanning is enabled, only changed files are processed.
	scanPatterns := !r.NoEmbeddedPatterns
	scanSecrets := !r.NoEmbeddedSecrets
	scanTreeSitter := !r.NoEmbeddedTreeSitter
	scanTaintPatterns := !r.NoEmbeddedTaintPatterns

	// Load incremental state if enabled
	var incState *incremental.State
	if r.IncrementalScan {
		incState = incremental.LoadState(root)
	}

	// Build the set of files to scan. Three modes:
	// 1. GitChangedFiles pre-filter (fastest): only scan files from git diff.
	// 2. Incremental hash-based: walk tree, hash-check each file.
	// 3. Full scan: walk tree, scan everything.
	// (gitChangedSet was built above before the Go SAST section.)

	if scanPatterns || scanSecrets || scanTreeSitter || frameworkMatcher != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanCtx, cancel := context.WithTimeout(ctx, r.Timeout)
			defer cancel()

			results, errors := runParallelScanners(
				scanCtx, root, ignoreMatcher,
				r.patternScanner, r.secretScanner, r.treesitterAnalyzer, r.taintPatternAnalyzer,
				frameworkMatcher,
				scanPatterns, scanSecrets, scanTreeSitter, scanTaintPatterns,
				r.IncludeTests, r.Timeout, incState, gitChangedSet,
			)

			for _, e := range errors {
				resultCh <- scannerResult{name: "parallel-scanner", err: fmt.Errorf("%s", e)}
			}
			for scannerName, findings := range results {
				resultCh <- scannerResult{name: scannerName, findings: findings}
			}
		}()
	}

	// Save incremental state after scanning completes
	if r.IncrementalScan && incState != nil {
		defer func() {
			_ = incState.SaveState(root)
		}()
	}

	// Close the result channel in a separate goroutine after all scanners
	// finish. This allows us to drain the channel concurrently with the
	// scanners running, avoiding a deadlock when the channel buffer fills up.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for sr := range resultCh {
		if sr.err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sr.name, sr.err))
		} else {
			if r.ChangedOnly && len(r.ChangedFiles) > 0 {
				sr.findings = filterFindingsToChanged(sr.findings, r.ChangedFiles)
			}
			if !r.IncludeTests {
				sr.findings = filterFindingsToNonTests(sr.findings)
			}
			result.Findings = append(result.Findings, sr.findings...)
			result.ToolsRun = append(result.ToolsRun, sr.name)
		}
	}

	// --- Phase 2: External tools (supplement embedded scanners) ---
	// Run all available external tools in parallel for faster scans.

	type externalResult struct {
		name     string
		findings []analysis.Finding
		err      error
	}

	// First, determine which tools are available
	var availableTools []Tool
	for _, tool := range r.Tools {
		if !tool.IsAvailable() {
			result.ToolsSkipped = append(result.ToolsSkipped, tool.Name)
			continue
		}
		availableTools = append(availableTools, tool)
	}

	// Run all available tools concurrently
	if len(availableTools) > 0 {
		resultCh := make(chan externalResult, len(availableTools))
		var wg sync.WaitGroup

		for _, tool := range availableTools {
			wg.Add(1)
			go func(t Tool) {
				defer wg.Done()
				toolCtx, cancel := context.WithTimeout(ctx, r.Timeout)
				findings, err := t.Run(toolCtx, root)
				cancel()
				resultCh <- externalResult{name: t.Name, findings: findings, err: err}
			}(tool)
		}

		// Close channel after all goroutines finish
		go func() {
			wg.Wait()
			close(resultCh)
		}()

		// Collect results in order (channel preserves goroutine completion order,
		// but we sort findings by tool name for deterministic output)
		var collectedResults []externalResult
		for sr := range resultCh {
			collectedResults = append(collectedResults, sr)
		}

		// Sort by tool name for deterministic output
		sort.Slice(collectedResults, func(i, j int) bool {
			return collectedResults[i].name < collectedResults[j].name
		})

		for _, sr := range collectedResults {
			if sr.err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sr.name, sr.err))
				result.ToolsSkipped = append(result.ToolsSkipped, sr.name)
				continue
			}

			findings := sr.findings

			// Filter to changed files if requested
			if r.ChangedOnly && len(r.ChangedFiles) > 0 {
				findings = filterFindingsToChanged(findings, r.ChangedFiles)
			}
			if !r.IncludeTests {
				findings = filterFindingsToNonTests(findings)
			}

			// Drop external gosec findings for rule IDs that the embedded
			// gosast scanner already implements.
			if sr.name == "gosec" {
				findings = filterGosecOverlaps(findings)
			}

			result.Findings = append(result.Findings, findings...)
			result.ToolsRun = append(result.ToolsRun, sr.name)
		}
	}

	// --- Phase 2b: Apply severity overrides for external tool findings ---
	// External tools (gosec, bandit) may report high severity for rules we
	// intentionally demoted in our embedded scanners. Apply our severity
	// policy to their findings to keep noise consistent.
	timings = append(timings, analysis.EngineTiming{Engine: "scanners", Duration: time.Since(phaseStart)})
	phaseStart = time.Now()
	result.Findings = applySeverityFindings(result.Findings)

	// --- Phase 2c: Deduplicate cross-scanner findings ---
	result.Findings = dedupFindings(result.Findings)

	// --- Phase 2d: Semantic deduplication ---
	// Collapse findings with the same rule + file + evidence across different
	// lines. This prevents the same vulnerability (e.g., the same Process.Start
	// call copied 869 times in a generated file) from producing 869 separate
	// findings. The first occurrence is kept; duplicates are dropped.
	result.Findings = semanticDedupFindings(result.Findings)

	// --- Phase 2e: Base/interprocedural deduplication ---
	// Merge base taint findings with their interprocedural (-IP) counterparts
	// on the same file+line. The interprocedural variant is preferred because
	// it demonstrates a longer taint flow. Example: TP-JS001 and TP-JS001-IP
	// on the same line → keep TP-JS001-IP, drop TP-JS001.
	result.Findings = dedupBaseVsInterprocedural(result.Findings)

	// --- Phase 2e.5: Taint safe-pattern suppression (B11.5.3) ---
	// Suppress taint findings whose containing function also contains a
	// safe pattern (e.g., TenantAuth.requireOwner). This applies to
	// framework taint rules that carry SafePatterns from extensions.
	if len(r.fwSafePatterns) > 0 || len(r.fwSafePatternsByCWE) > 0 {
		result.Findings = suppressTaintWithSafePatternsAndCWE(result.Findings, r.fwSafePatterns, r.fwSafePatternsByCWE, root)
	}

	// --- Phase 2f: Issue grouping ---
	// Group related findings in the same function (e.g., EditPaste.mutate
	// with filter_by(id=id) on lines 141 and 148). Each finding gets an
	// IssueGroupID; the primary finding carries OccurrenceCount and
	// RelatedLocations. Findings are NOT dropped — they remain as evidence.
	result.Findings = groupIssues(result.Findings, root)

	// --- Phase 3: Apply suppression directives (//patchflow:ignore) ---
	if !r.ShowSuppressed {
		var filtered []analysis.Finding
		suppressedCount := 0
		for _, f := range result.Findings {
			if r.suppressionMgr.IsSuppressed(f.FilePath, f.LineStart, f.RuleID) {
				suppressedCount++
				continue
			}
			filtered = append(filtered, f)
		}
		if suppressedCount > 0 {
			result.SuppressedCount = suppressedCount
		}
		result.Findings = filtered
	}
	// --- Phase 4: Enrich findings with OWASP category ---
	for i := range result.Findings {
		if result.Findings[i].CWEID != "" && result.Findings[i].OWASPCategory == "" {
			result.Findings[i].OWASPCategory = cwe.OWASPCategoryLabel(result.Findings[i].CWEID)
		}
	}
	timings = append(timings, analysis.EngineTiming{Engine: "dedup_grouping", Duration: time.Since(phaseStart)})

	result.EngineTimings = timings
	return result, nil
}

// dedupFindings removes duplicate findings at the same file+line+rule, keeping
// the one with higher confidence. This prevents both the regex pattern scanner
// and the tree-sitter AST scanner from reporting the same issue twice.
// AST-confirmed findings (treesitter-ast) are preferred over regex-based
// findings (patterns-embedded) when confidence is equal.
//
// The dedup key includes the RuleID so that two different vulnerability types
// on the same line are both kept (e.g., a SQL injection and a hardcoded
// password on the same line should not be deduplicated).
//
// Uses a hash map for O(n) dedup with a slice for order preservation.
func dedupFindings(findings []analysis.Finding) []analysis.Finding {
	type key struct {
		file   string
		line   int
		ruleID string
	}
	best := make(map[key]analysis.Finding)
	var order []key // slice preserves insertion order in O(1) per append
	prio := map[string]int{
		"treesitter-ast":    3, // AST-confirmed findings have highest priority
		"taint-ssa":         3, // SSA-based taint analysis is also high-confidence
		"taint-patterns":    3, // Source-sink taint analysis is high-confidence
		"gosast-embedded":   2, // embedded rules take precedence over external
		"secrets-embedded":  2,
		"patterns-embedded": 2, // embedded patterns are tuned for low noise
		"gosec":             1, // external gosec is noisy, prefer embedded
		"bandit":            1,
		"semgrep":           1,
		"gitleaks":          1,
	}

	// proximityWindow is the max line difference for merging two findings
	// with the same rule ID on the same file. This handles cases where the
	// tree-sitter scanner reports the start of a multi-line call (e.g.,
	// subprocess.run on line 88) while the regex scanner reports the
	// shell=True keyword on a later line (e.g., line 91).
	const proximityWindow = 5

	for _, f := range findings {
		// Normalize path for dedup key — different scanners may report
		// absolute vs relative paths for the same file. Use the last two
		// path components as a balance between uniqueness and robustness.
		normalizedPath := f.FilePath
		parts := strings.Split(filepath.ToSlash(normalizedPath), "/")
		if len(parts) >= 2 {
			normalizedPath = parts[len(parts)-2] + "/" + parts[len(parts)-1]
		} else if len(parts) == 1 {
			normalizedPath = parts[0]
		}
		// Include RuleID in the key so different vulnerability types on the
		// same line are both kept. Also normalize equivalent rule IDs across
		// scanners (e.g., a tree-sitter rule and pattern rule detecting the
		// same issue may have different IDs — match on title as a fallback).
		ruleKey := normalizeRuleID(f.RuleID)
		if ruleKey == "" {
			ruleKey = f.Title
		}

		// Check for an existing finding on the same file+ruleID within the
		// proximity window. This merges findings that report the same issue
		// on slightly different lines (e.g., call start vs keyword line).
		var existingKey *key
		for lineOffset := 0; lineOffset <= proximityWindow; lineOffset++ {
			for _, dir := range []int{1, -1} {
				probeLine := f.LineStart + dir*lineOffset
				probeKey := key{file: normalizedPath, line: probeLine, ruleID: ruleKey}
				if _, ok := best[probeKey]; ok {
					existingKey = &probeKey
					break
				}
			}
			if existingKey != nil {
				break
			}
		}

		if existingKey == nil {
			k := key{file: normalizedPath, line: f.LineStart, ruleID: ruleKey}
			best[k] = f
			order = append(order, k)
			continue
		}

		existing := best[*existingKey]
		// Prefer higher confidence (ConfidenceHigh > ConfidenceMedium > ConfidenceLow)
		if confidenceRank(f.Confidence) > confidenceRank(existing.Confidence) {
			best[*existingKey] = f
			continue
		}
		// If same confidence, prefer higher-priority analyzer
		if f.Confidence == existing.Confidence {
			if prio[f.Analyzer] > prio[existing.Analyzer] {
				best[*existingKey] = f
			}
		}
	}

	// Preserve insertion order — O(n) via slice iteration
	result := make([]analysis.Finding, 0, len(order))
	for _, k := range order {
		result = append(result, best[k])
	}
	return result
}

// semanticDedupFindings collapses findings that share the same rule ID, file
// path, and evidence string across different line numbers. This prevents the
// same vulnerability pattern (e.g., Process.Start("cmd.exe", ...) copied
// hundreds of times in a generated file) from producing hundreds of separate
// findings. The first occurrence is kept; subsequent duplicates are dropped.
//
// The evidence comparison is normalized (whitespace-trimmed) to handle
// minor formatting differences. Findings with empty evidence are not
// collapsed (they may represent distinct issues that happen to share a rule).
//
// This runs after dedupFindings (which handles same-line duplicates) and
// before suppression filtering.
func semanticDedupFindings(findings []analysis.Finding) []analysis.Finding {
	type semKey struct {
		ruleID   string
		file     string
		evidence string
	}
	seen := make(map[semKey]bool)
	result := make([]analysis.Finding, 0, len(findings))

	for _, f := range findings {
		evidence := strings.TrimSpace(f.Evidence)
		if evidence == "" {
			// No evidence to compare — keep the finding as-is.
			result = append(result, f)
			continue
		}

		// Normalize the file path to last two components for robustness
		// (same logic as dedupFindings).
		normalizedPath := f.FilePath
		parts := strings.Split(filepath.ToSlash(normalizedPath), "/")
		if len(parts) >= 2 {
			normalizedPath = parts[len(parts)-2] + "/" + parts[len(parts)-1]
		} else if len(parts) == 1 {
			normalizedPath = parts[0]
		}

		ruleKey := normalizeRuleID(f.RuleID)
		if ruleKey == "" {
			ruleKey = f.Title
		}

		k := semKey{ruleID: ruleKey, file: normalizedPath, evidence: evidence}
		if seen[k] {
			continue // duplicate — same rule + file + evidence on a different line
		}
		seen[k] = true
		result = append(result, f)
	}
	return result
}

// normalizeRuleID maps equivalent rule IDs from different scanners to a
// canonical form so that dedupFindings merges them. For example, the regex
// scanner's "PY005" and the tree-sitter scanner's "TS-PY005" both detect
// pickle.loads() — they should be deduplicated, not reported twice.
func normalizeRuleID(ruleID string) string {
	// Strip "TS-" prefix from tree-sitter rule IDs to match their regex
	// equivalents (TS-PY005 → PY005, TS-JS009 → JS009, etc.)
	if strings.HasPrefix(ruleID, "TS-") {
		return ruleID[3:]
	}
	return ruleID
}

// dedupBaseVsInterprocedural merges base taint findings with their
// interprocedural (-IP) counterparts. When both TP-JS001 (base) and
// TP-JS001-IP (interprocedural) fire on the same file+line, the base finding
// is dropped and the IP finding is kept. This reduces duplicate findings
// without losing the more detailed interprocedural taint path.
//
// The function also handles TP-PY*, TP-RUBY*, TP-JAVA* base/IP pairs.
func dedupBaseVsInterprocedural(findings []analysis.Finding) []analysis.Finding {
	type ipKey struct {
		baseRuleID string
		file       string
		line       int
	}

	// First pass: collect IP finding locations
	ipLocations := make(map[ipKey]bool)
	for _, f := range findings {
		if isInterproceduralRule(f.RuleID) {
			baseID := stripIPSuffixFromRule(f.RuleID)
			normalizedPath := normalizePathForDedup(f.FilePath)
			k := ipKey{baseRuleID: baseID, file: normalizedPath, line: f.LineStart}
			ipLocations[k] = true
		}
	}

	// Second pass: drop base findings that have an IP counterpart
	result := make([]analysis.Finding, 0, len(findings))
	dropped := 0
	for _, f := range findings {
		if !isInterproceduralRule(f.RuleID) {
			// This is a base rule — check if an IP variant exists
			baseID := f.RuleID
			normalizedPath := normalizePathForDedup(f.FilePath)
			k := ipKey{baseRuleID: baseID, file: normalizedPath, line: f.LineStart}
			if ipLocations[k] {
				dropped++
				continue // Drop base finding — IP variant exists
			}
		}
		result = append(result, f)
	}
	return result
}

// isInterproceduralRule returns true if the rule ID ends with "-IP",
// indicating an interprocedural taint variant.
func isInterproceduralRule(ruleID string) bool {
	return strings.HasSuffix(ruleID, "-IP")
}

// stripIPSuffixFromRule removes the "-IP" suffix from a rule ID.
func stripIPSuffixFromRule(ruleID string) string {
	if strings.HasSuffix(ruleID, "-IP") {
		return ruleID[:len(ruleID)-3]
	}
	return ruleID
}

// normalizePathForDedup returns the last two path components for robust
// cross-scanner path matching.
func normalizePathForDedup(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return p
}

// groupIssues assigns IssueGroupIDs to findings that represent the same
// vulnerability scenario across multiple locations in the same function.
// Findings are NOT dropped — they remain as separate findings with their own
// locations. The primary finding (first occurrence) carries OccurrenceCount
// and RelatedLocations for display purposes.
//
// Grouping strategy (in priority order):
//  1. Function name from title/description ("in <func_name>") — highest priority.
//  2. Function boundary detection from source code — reads the file and finds
//     function/method/class definitions. Each finding is assigned to its
//     enclosing function. This is the primary grouping mechanism.
//  3. Line proximity (within 10 lines) — fallback when source code is
//     unavailable or no function boundary is found. Uses a tight window to
//     avoid grouping across function boundaries.
//
// Findings in different functions are NEVER grouped together, even if they're
// close in line number. This prevents EditPaste.mutate (line 141) from being
// grouped with DeletePaste.mutate (line 167) just because they're nearby.
func groupIssues(findings []analysis.Finding, root string) []analysis.Finding {
	type groupKey struct {
		ruleID   string
		file     string
		funcName string // function name or "proximity" fallback
	}

	// Cache function boundaries per file to avoid re-reading
	boundaryCache := make(map[string][]functionBoundary)

	getBoundaries := func(filePath string) []functionBoundary {
		normalized := analysis.NormalizePath(filePath)
		if bs, ok := boundaryCache[normalized]; ok {
			return bs
		}
		resolved := resolveFilePath(filePath, root)
		bs := detectFunctionBoundaries(resolved)
		boundaryCache[normalized] = bs
		return bs
	}

	// First pass: determine the function name for each finding
	type candidate struct {
		key  groupKey
		idx  int
		line int
	}
	var candidates []candidate

	for i, f := range findings {
		funcName := ""

		// Strategy 1: Extract from title/description
		funcName = analysis.ExtractFunctionName(f.Title, f.Description)

		// Strategy 2: Detect from source code boundaries
		if funcName == "" && f.FilePath != "" && f.LineStart > 0 {
			boundaries := getBoundaries(f.FilePath)
			if len(boundaries) > 0 {
				if b := findFunctionForLine(boundaries, f.LineStart); b != nil {
					funcName = fmt.Sprintf("%s@%d", b.name, b.line)
				}
			}
		}

		// Strategy 3: If no function found, use proximity fallback marker
		// (empty string triggers proximity-based grouping below)
		k := groupKey{
			ruleID:   stripIPSuffixFromRule(f.RuleID),
			file:     analysis.NormalizePath(f.FilePath),
			funcName: funcName,
		}
		candidates = append(candidates, candidate{key: k, idx: i, line: f.LineStart})
	}

	// Build groups: for each candidate, either join an existing group with
	// the same key (if funcName is non-empty) or join a group with the same
	// ruleID+file within the proximity window (if funcName is empty).
	// Proximity window is tight (10 lines) to avoid crossing function boundaries.
	const proximityWindow = 10

	groupAssignment := make([]int, len(candidates)) // index → group number
	groupCount := 0

	for i, c := range candidates {
		assigned := -1
		if c.key.funcName != "" {
			// Function-name-based grouping: find an existing group with same key
			for j := 0; j < i; j++ {
				if candidates[j].key == c.key {
					assigned = groupAssignment[j]
					break
				}
			}
		} else {
			// Proximity-based grouping: find an existing group with same ruleID+file
			// where any member is within the tight proximity window
			for j := 0; j < i; j++ {
				if candidates[j].key.ruleID == c.key.ruleID &&
					candidates[j].key.file == c.key.file &&
					abs(c.line-candidates[j].line) <= proximityWindow {
					assigned = groupAssignment[j]
					break
				}
			}
		}

		if assigned == -1 {
			assigned = groupCount
			groupCount++
		}
		groupAssignment[i] = assigned
	}

	// Collect indices by group
	groupIndices := make(map[int][]int)
	for i, ga := range groupAssignment {
		groupIndices[ga] = append(groupIndices[ga], candidates[i].idx)
	}

	// Assign issue group IDs and populate occurrence counts
	for _, indices := range groupIndices {
		if len(indices) == 0 {
			continue
		}

		// Primary finding is the one with the lowest line number
		primaryIdx := indices[0]
		for _, idx := range indices {
			if findings[idx].LineStart < findings[primaryIdx].LineStart {
				primaryIdx = idx
			}
		}
		primary := findings[primaryIdx]
		groupID := analysis.ComputeIssueGroupID(primary)
		// Disambiguate by appending the primary line number so different
		// functions in the same file get different group IDs.
		if primary.LineStart > 0 {
			groupID = groupID + "-L" + fmt.Sprintf("%d", primary.LineStart)
		}
		// Build related locations (non-primary)
		var relatedLocs []string
		for _, idx := range indices {
			if idx == primaryIdx {
				continue
			}
			loc := fmt.Sprintf("%s:%d", findings[idx].FilePath, findings[idx].LineStart)
			relatedLocs = append(relatedLocs, loc)
		}

		// Set group metadata on all findings in the group
		for _, idx := range indices {
			findings[idx].IssueGroupID = groupID
			findings[idx].OccurrenceCount = len(indices)
		}

		// Set related locations only on the primary finding
		findings[primaryIdx].RelatedLocations = relatedLocs
	}

	return findings
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// embeddedGosastRules is the set of rule IDs implemented by the embedded
// gosast scanner. External gosec findings for these rules are dropped
// because the embedded scanner has better precision (value-based checks,
// mock-file detection, severity tuning) and already covers them.
var embeddedGosastRules = map[string]bool{
	"G101": true, // hardcoded credentials (value-based suppression)
	"G102": true, // bind to all interfaces
	"G103": true, // unsafe calls
	"G106": true, // SSH insecure host key
	"G107": true, // SSRF
	"G108": true, // pprof exposure
	"G114": true, // HTTP server without timeouts
	"G115": true, // integer overflow
	"G116": true, // implicit aliasing
	"G201": true, // SQL format string
	"G202": true, // SQL concatenation
	"G203": true, // unescaped HTML template
	"G204": true, // subprocess with variable
	"G301": true, // bad file permissions
	"G302": true, // bad file permissions (chmod)
	"G303": true, // predictable tempfile
	"G304": true, // file path as taint input
	"G305": true, // zip path traversal
	"G306": true, // weak file permissions on write
	"G401": true, // weak crypto
	"G402": true, // TLS InsecureSkipVerify
	"G404": true, // weak random (severity-tuned)
	"G405": true, // weak crypto (blocklist)
	"G501": true, // blocklisted import
	// Taint analysis rules — covered by the embedded SSA taint analyzer
	// with smarter source filtering (os.Getenv removal, HTTP import check).
	"G701": true, // SQL injection
	"G702": true, // command injection
	"G703": true, // path traversal
	"G704": true, // SSRF
	"G705": true, // open redirect
	"G706": true, // log injection
	"G708": true, // SSTI
}

// filterGosecOverlaps drops external gosec findings for rule IDs that the
// embedded gosast scanner already handles. This prevents FPs that the
// embedded scanner suppressed from reappearing via the external tool.
func filterGosecOverlaps(findings []analysis.Finding) []analysis.Finding {
	var filtered []analysis.Finding
	for _, f := range findings {
		if embeddedGosastRules[f.RuleID] {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// severityOverrides maps rule IDs to the severity that PatchFlow assigns
// intentionally (lower than the external tool's default). This keeps noise
// consistent between embedded and external scanners.
var severityOverrides = map[string]analysis.Severity{
	"G104": analysis.SeverityInfo, // unchecked errors: audit-only
	"G115": analysis.SeverityLow,  // integer overflow: most conversions are safe
}

// applySeverityOverrides adjusts the severity of external tool findings to
// match PatchFlow's intentional severity policy for noisy rules.
func applySeverityFindings(findings []analysis.Finding) []analysis.Finding {
	for i := range findings {
		override, ok := severityOverrides[findings[i].RuleID]
		if !ok {
			continue
		}
		// Only downgrade, never upgrade.
		if severityRank(findings[i].Severity) > severityRank(override) {
			findings[i].Severity = override
		}
	}
	return findings
}

func severityRank(s analysis.Severity) int {
	switch s {
	case analysis.SeverityCritical:
		return 4
	case analysis.SeverityHigh:
		return 3
	case analysis.SeverityMedium:
		return 2
	case analysis.SeverityLow:
		return 1
	default:
		return 0
	}
}

// confidenceRank converts a Confidence string to a numeric rank for comparison.
func confidenceRank(c analysis.Confidence) int {
	switch c {
	case analysis.ConfidenceHigh:
		return 3
	case analysis.ConfidenceMedium:
		return 2
	case analysis.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func filterFindingsToChanged(findings []analysis.Finding, changedFiles []string) []analysis.Finding {
	changedSet := make(map[string]bool, len(changedFiles))
	for _, f := range changedFiles {
		changedSet[f] = true
	}

	var filtered []analysis.Finding
	for _, f := range findings {
		// Normalize paths for comparison
		normalized := filepath.ToSlash(f.FilePath)
		normalized = strings.TrimPrefix(normalized, "./")
		if changedSet[normalized] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func filterFindingsToNonTests(findings []analysis.Finding) []analysis.Finding {
	var filtered []analysis.Finding
	for _, f := range findings {
		if isTestPath(f.FilePath) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

func isTestPath(path string) bool {
	normalized := filepath.ToSlash(strings.TrimPrefix(path, "./"))
	lower := strings.ToLower(normalized)
	base := filepath.Base(lower)

	if strings.Contains(lower, "/test/") ||
		strings.Contains(lower, "/tests/") ||
		strings.Contains(lower, "/__tests__/") ||
		strings.Contains(lower, "/spec/") ||
		strings.Contains(lower, "/specs/") {
		return true
	}

	// Build scripts: setup.py commonly uses exec()/os.system() for build steps
	// and is not application code. conftest.py is pytest configuration.
	if base == "setup.py" || base == "conftest.py" || base == "setup.cfg" {
		return true
	}

	return strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, "_test.py") ||
		(strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py")) ||
		strings.HasSuffix(base, ".test.js") ||
		strings.HasSuffix(base, ".spec.js") ||
		strings.HasSuffix(base, ".test.jsx") ||
		strings.HasSuffix(base, ".spec.jsx") ||
		strings.HasSuffix(base, ".test.ts") ||
		strings.HasSuffix(base, ".spec.ts") ||
		strings.HasSuffix(base, ".test.tsx") ||
		strings.HasSuffix(base, ".spec.tsx")
}

// commandExists checks if a binary is available on the PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// parseIntSafe converts a string to an int, returning 0 on failure.
// gosec outputs line numbers as strings in its JSON format.
func parseIntSafe(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// --- gosec ---

type gosecReport struct {
	Issues []gosecIssue         `json:"Issues"`
	Rules  map[string]gosecRule `json:"Rules"`
}

type gosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	Details    string `json:"details"`
	File       string `json:"file"`
	Line       string `json:"line"`
	Col        string `json:"column"`
	What       string `json:"what"`
	Code       string `json:"code"`
}

type gosecRule struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

func runGosec(ctx context.Context, root string) ([]analysis.Finding, error) {
	cmd := exec.CommandContext(ctx, "gosec", "-fmt=json", "-quiet", "./...")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		// gosec returns non-zero exit code when issues are found
		if len(output) > 0 {
			// parse the output anyway
		} else {
			return nil, fmt.Errorf("gosec execution failed: %w", err)
		}
	}

	var report gosecReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse gosec output: %w", err)
	}

	var findings []analysis.Finding
	for _, issue := range report.Issues {
		rule, hasRule := report.Rules[issue.RuleID]
		title := issue.What
		desc := issue.Details
		if hasRule {
			if title == "" {
				title = rule.Title
			}
			if desc == "" {
				desc = rule.Description
			}
		}
		// Fall back to details or rule_id if title is still empty
		if title == "" {
			title = desc
		}
		if title == "" {
			title = issue.RuleID
		}

		lineNum := parseIntSafe(issue.Line)

		findings = append(findings, analysis.Finding{
			ID:          fmt.Sprintf("sast-gosec-%s-%s-%d", issue.RuleID, filepath.Base(issue.File), lineNum),
			Type:        analysis.TypeSAST,
			Analyzer:    "gosec",
			Severity:    normalizeGosecSeverity(issue.Severity),
			Confidence:  normalizeGosecConfidence(issue.Confidence),
			Title:       title,
			Description: desc,
			FilePath:    issue.File,
			LineStart:   lineNum,
			RuleID:      issue.RuleID,
			Evidence:    issue.Code,
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

func normalizeGosecSeverity(s string) analysis.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.SeverityHigh
	case "MEDIUM":
		return analysis.SeverityMedium
	case "LOW":
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

func normalizeGosecConfidence(s string) analysis.Confidence {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.ConfidenceHigh
	case "MEDIUM":
		return analysis.ConfidenceMedium
	case "LOW":
		return analysis.ConfidenceLow
	default:
		return analysis.ConfidenceLow
	}
}

// --- bandit ---

type banditReport struct {
	Results []banditResult `json:"results"`
	Errors  []interface{}  `json:"errors"`
}

type banditResult struct {
	TestID          string `json:"test_id"`
	TestName        string `json:"test_name"`
	IssueSeverity   string `json:"issue_severity"`
	IssueConfidence string `json:"issue_confidence"`
	IssueText       string `json:"issue_text"`
	Filename        string `json:"filename"`
	LineNumber      int    `json:"line_number"`
	ColNumber       int    `json:"col_number"`
	MoreInfo        string `json:"more_info"`
	Code            string `json:"issue_cwe"`
}

func runBandit(ctx context.Context, root string) ([]analysis.Finding, error) {
	// Find Python files to scan
	cmd := exec.CommandContext(ctx, "bandit", "-r", ".", "-f", "json", "-q")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			// bandit returns non-zero when issues found
		} else {
			return nil, fmt.Errorf("bandit execution failed: %w", err)
		}
	}

	var report banditReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse bandit output: %w", err)
	}

	var findings []analysis.Finding
	for _, r := range report.Results {
		findings = append(findings, analysis.Finding{
			ID:          fmt.Sprintf("sast-bandit-%s-%s-%d", r.TestID, filepath.Base(r.Filename), r.LineNumber),
			Type:        analysis.TypeSAST,
			Analyzer:    "bandit",
			Severity:    normalizeBanditSeverity(r.IssueSeverity),
			Confidence:  normalizeBanditConfidence(r.IssueConfidence),
			Title:       r.TestName,
			Description: r.IssueText,
			FilePath:    r.Filename,
			LineStart:   r.LineNumber,
			RuleID:      r.TestID,
			AdvisoryURL: r.MoreInfo,
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

func normalizeBanditSeverity(s string) analysis.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.SeverityHigh
	case "MEDIUM":
		return analysis.SeverityMedium
	case "LOW":
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

func normalizeBanditConfidence(s string) analysis.Confidence {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.ConfidenceHigh
	case "MEDIUM":
		return analysis.ConfidenceMedium
	case "LOW":
		return analysis.ConfidenceLow
	default:
		return analysis.ConfidenceLow
	}
}

// --- semgrep ---

type semgrepReport struct {
	Results []semgrepResult `json:"results"`
	Errors  []interface{}   `json:"errors"`
}

type semgrepResult struct {
	CheckID string          `json:"check_id"`
	Path    string          `json:"path"`
	Start   semgrepPosition `json:"start"`
	End     semgrepPosition `json:"end"`
	Extra   semgrepExtra    `json:"extra"`
}

type semgrepPosition struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

type semgrepExtra struct {
	Message  string                 `json:"message"`
	Severity string                 `json:"severity"`
	Lines    string                 `json:"lines"`
	Metadata map[string]interface{} `json:"metadata"`
}

func runSemgrep(ctx context.Context, root string) ([]analysis.Finding, error) {
	cmd := exec.CommandContext(ctx, "semgrep", "--json", "--quiet", root)
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			// semgrep returns non-zero when findings exist
		} else {
			return nil, fmt.Errorf("semgrep execution failed: %w", err)
		}
	}

	var report semgrepReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	var findings []analysis.Finding
	for _, r := range report.Results {
		severity := analysis.SeverityInfo
		if s, ok := r.Extra.Metadata["severity"]; ok {
			if sv, ok := s.(string); ok {
				severity = normalizeSemgrepSeverity(sv)
			}
		}
		if severity == analysis.SeverityInfo && r.Extra.Severity != "" {
			severity = normalizeSemgrepSeverity(r.Extra.Severity)
		}

		cwe := ""
		if c, ok := r.Extra.Metadata["cwe"]; ok {
			if cv, ok := c.(string); ok {
				cwe = cv
			}
		}

		advisory := ""
		if ref, ok := r.Extra.Metadata["references"]; ok {
			if refs, ok := ref.([]interface{}); ok && len(refs) > 0 {
				if refStr, ok := refs[0].(string); ok {
					advisory = refStr
				}
			}
		}

		findings = append(findings, analysis.Finding{
			ID:          fmt.Sprintf("sast-semgrep-%s-%s-%d", r.CheckID, filepath.Base(r.Path), r.Start.Line),
			Type:        analysis.TypeSAST,
			Analyzer:    "semgrep",
			Severity:    severity,
			Confidence:  analysis.ConfidenceMedium,
			Title:       r.CheckID,
			Description: r.Extra.Message,
			FilePath:    r.Path,
			LineStart:   r.Start.Line,
			LineEnd:     r.End.Line,
			RuleID:      r.CheckID,
			CWEID:       cwe,
			AdvisoryURL: advisory,
			Evidence:    r.Extra.Lines,
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

func normalizeSemgrepSeverity(s string) analysis.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR", "HIGH", "CRITICAL":
		if strings.ToUpper(s) == "CRITICAL" {
			return analysis.SeverityCritical
		}
		return analysis.SeverityHigh
	case "WARNING", "MEDIUM":
		return analysis.SeverityMedium
	case "INFO", "LOW":
		return analysis.SeverityLow
	default:
		return analysis.SeverityInfo
	}
}

// --- gitleaks ---

type gitleaksReport []gitleaksFinding

type gitleaksFinding struct {
	Description string `json:"Description"`
	RuleID      string `json:"RuleID"`
	RuleName    string `json:"RuleName"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`
	Match       string `json:"Match"`
}

func runGitleaks(ctx context.Context, root string) ([]analysis.Finding, error) {
	// Worktree mode avoids repeatedly reporting historical fixture secrets during normal scans.
	cmd := exec.CommandContext(ctx, "gitleaks", "detect", "--source", root, "--no-git", "--report-format", "json", "--report-path", "-", "--no-banner")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			// gitleaks returns non-zero when secrets are found
		} else {
			return nil, fmt.Errorf("gitleaks execution failed: %w", err)
		}
	}

	var report gitleaksReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}

	var findings []analysis.Finding
	for _, f := range report {
		// Mask the secret value — never expose it in findings
		maskedSecret := maskSecret(f.Secret)
		title := f.RuleName
		if title == "" {
			title = f.Description
		}
		if title == "" {
			title = f.RuleID
		}

		findings = append(findings, analysis.Finding{
			ID:             fmt.Sprintf("secret-gitleaks-%s-%s-%d", f.RuleID, filepath.Base(f.File), f.StartLine),
			Type:           analysis.TypeSecret,
			Analyzer:       "gitleaks",
			Severity:       analysis.SeverityHigh, // secrets are always high severity
			Confidence:     analysis.ConfidenceHigh,
			Title:          fmt.Sprintf("Secret detected: %s", title),
			Description:    fmt.Sprintf("Potential secret matching rule %s detected. Value masked: %s", f.RuleID, maskedSecret),
			FilePath:       f.File,
			LineStart:      f.StartLine,
			LineEnd:        f.EndLine,
			RuleID:         f.RuleID,
			Evidence:       maskSecret(f.Match),
			Recommendation: "Remove the secret from the code, rotate it immediately, and use environment variables or a secrets manager.",
			DetectedAt:     time.Now(),
		})
	}

	return findings, nil
}

// maskSecret masks a secret value, showing only the first and last 2 characters.
func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// --- checkov (IaC scanner) ---

// checkovReport represents the JSON output from checkov.
type checkovReport struct {
	Results struct {
		FailedChecks []checkovResult `json:"failed_checks"`
	} `json:"results"`
}

type checkovResult struct {
	CheckID       string   `json:"check_id"`
	CheckName     string   `json:"check_name"`
	CheckType     string   `json:"check_type"`
	FilePath      string   `json:"file_path"`
	FileLineRange []int    `json:"file_line_range"`
	Severity      string   `json:"severity"`
	Guideline     string   `json:"guideline"`
	Evaluated     []string `json:"evaluations"`
	BcID          string   `json:"bc_check_id"`
}

// runCheckov runs the Checkov IaC scanner on the repository root.
// Checkov scans Terraform, Kubernetes, Dockerfile, CloudFormation, ARM,
// and other IaC formats for misconfigurations and policy violations.
func runCheckov(ctx context.Context, root string) ([]analysis.Finding, error) {
	// Run checkov with JSON output, scanning all IaC file types.
	// --quiet suppresses the CLI banner. --compact skips passing checks.
	cmd := exec.CommandContext(ctx, "checkov", "--directory", root, "--output", "json", "--quiet", "--compact")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			// checkov returns non-zero when failed checks are found
		} else {
			return nil, fmt.Errorf("checkov execution failed: %w", err)
		}
	}

	// Checkov outputs a JSON array (one element per framework scanned).
	// We need to handle both array and single-object formats.
	var reports []checkovReport
	if err := json.Unmarshal(output, &reports); err != nil {
		// Try single object
		var single checkovReport
		if err2 := json.Unmarshal(output, &single); err2 != nil {
			return nil, fmt.Errorf("failed to parse checkov output: %w", err)
		}
		reports = []checkovReport{single}
	}

	var findings []analysis.Finding
	for _, report := range reports {
		for _, r := range report.Results.FailedChecks {
			lineStart := 0
			lineEnd := 0
			if len(r.FileLineRange) >= 2 {
				lineStart = r.FileLineRange[0]
				lineEnd = r.FileLineRange[1]
			}

			// Generate a stable ID from check_id + file + line
			id := fmt.Sprintf("iac-checkov-%s-%s-%d", r.CheckID, filepath.Base(r.FilePath), lineStart)

			findings = append(findings, analysis.Finding{
				ID:             id,
				Type:           analysis.TypeIaC,
				Analyzer:       "checkov",
				Severity:       normalizeCheckovSeverity(r.Severity),
				Confidence:     analysis.ConfidenceHigh,
				Title:          r.CheckName,
				Description:    fmt.Sprintf("Checkov check %s failed: %s", r.CheckID, r.CheckName),
				FilePath:       r.FilePath,
				LineStart:      lineStart,
				LineEnd:        lineEnd,
				RuleID:         r.CheckID,
				AdvisoryURL:    r.Guideline,
				Recommendation: fmt.Sprintf("See checkov documentation for %s: %s", r.CheckID, r.Guideline),
				DetectedAt:     time.Now(),
			})
		}
	}

	return findings, nil
}

// normalizeCheckovSeverity converts Checkov severity strings to analysis.Severity.
// Checkov uses: HIGH, MEDIUM, LOW. If severity is empty, default to MEDIUM.
func normalizeCheckovSeverity(s string) analysis.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return analysis.SeverityHigh
	case "MEDIUM":
		return analysis.SeverityMedium
	case "LOW":
		return analysis.SeverityLow
	case "CRITICAL":
		return analysis.SeverityCritical
	default:
		return analysis.SeverityMedium // checkov default is medium when not specified
	}
}

// PlatformBinaryName returns the platform-specific binary name for a tool.
func PlatformBinaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
