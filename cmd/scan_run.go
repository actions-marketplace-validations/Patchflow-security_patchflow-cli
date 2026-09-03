package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/api"
	"github.com/Patchflow-security/patchflow-cli/internal/baseline"
	"github.com/Patchflow-security/patchflow-cli/internal/cacheutil"
	"github.com/Patchflow-security/patchflow-cli/internal/cwe"
	"github.com/Patchflow-security/patchflow-cli/internal/exitcode"
	"github.com/Patchflow-security/patchflow-cli/internal/fix"
	"github.com/Patchflow-security/patchflow-cli/internal/fixsnippet"
	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/monorepo"
	osvclient "github.com/Patchflow-security/patchflow-cli/internal/osv"
	"github.com/Patchflow-security/patchflow-cli/internal/osvdb"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/pathutil"
	"github.com/Patchflow-security/patchflow-cli/internal/project"
	"github.com/Patchflow-security/patchflow-cli/internal/reachability"
	"github.com/Patchflow-security/patchflow-cli/internal/registry"
	"github.com/Patchflow-security/patchflow-cli/internal/report"
	"github.com/Patchflow-security/patchflow-cli/internal/risk"
	"github.com/Patchflow-security/patchflow-cli/internal/rules"
	"github.com/Patchflow-security/patchflow-cli/internal/rulesconfig"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	fwpatterns "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
	"github.com/Patchflow-security/patchflow-cli/internal/sca"
	"github.com/spf13/cobra"
)

var (
	scanProfile           string
	scanNoSAST            bool
	scanNoSecrets         bool
	scanNoReach           bool
	scanOutput            string
	scanFormat            string
	scanChangedOnly       bool
	scanShowSuppressed    bool
	scanRulesPath         string
	scanIncludeTests      bool
	scanNoGitignore       bool
	scanIncremental       bool
	scanNewOnly           bool
	scanFailOn            string
	scanSince             string
	scanBaselineName      string
	scanGovernanceProfile string
	scanSuggestFixes      bool
	scanStaged            bool
	scanPaths             []string
	scanNoLicenses        bool
	scanOffline           bool
	scanLicensePolicy     string
	scanTaintDepth        int
	scanFramework         []string
	scanDisableFramework  []string
	scanRulesConfigPath   string
	scanConfigPath        string
	scanSubmit            bool
	scanProjectID         int
)

var scanRealCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a full security analysis (SCA + SAST + reachability + risk)",
	Long: `Run a comprehensive local security analysis on the current repository.
This performs Software Composition Analysis (SCA) via OSV.dev, Static Analysis
Security Testing (SAST) via embedded scanners (Go SAST, secret scanner, multi-language
pattern scanner) plus external tools when available (gosec, bandit, semgrep, gitleaks),
reachability analysis, and computes a risk score.

No backend connection required — all analysis runs locally.
Embedded scanners require zero installation; external tools supplement when installed.`,
	RunE: runScanReal,
}

func init() {
	scanRealCmd.Flags().StringVar(&scanProfile, "profile", "standard", "Scan profile: quick, standard, deep")
	scanRealCmd.Flags().BoolVar(&scanNoSAST, "no-sast", false, "Skip SAST analysis")
	scanRealCmd.Flags().BoolVar(&scanNoSecrets, "no-secrets", false, "Skip secret detection")
	scanRealCmd.Flags().BoolVar(&scanNoReach, "no-reachability", false, "Skip reachability analysis")
	scanRealCmd.Flags().StringVar(&scanFormat, "format", "", "Output format for report file: markdown, json, sarif")
	scanRealCmd.Flags().StringVar(&scanOutput, "output", "", "Write report to file (stdout if omitted)")
	scanRealCmd.Flags().BoolVar(&scanChangedOnly, "changed-only", false, "Only analyze changed files")
	scanRealCmd.Flags().BoolVar(&scanShowSuppressed, "show-suppressed", false, "Show findings suppressed by //patchflow:ignore comments")
	scanRealCmd.Flags().StringVar(&scanConfigPath, "config", "", "Path to .patchflow/rules.yaml (unified config: custom rules, framework extensions, rule modes)")
	scanRealCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules YAML file (legacy alias for --config; default: .patchflow/rules.yaml)")
	scanRealCmd.Flags().BoolVar(&scanIncludeTests, "include-tests", false, "Include test files in SAST analysis")
	scanRealCmd.Flags().BoolVar(&scanNoGitignore, "no-gitignore", false, "Do not respect .gitignore patterns (scan all files)")
	scanRealCmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Only re-scan files changed since last scan (uses global cache sast_state.json)")
	scanRealCmd.Flags().IntVar(&scanTaintDepth, "taint-depth", 3, "Maximum inter-procedural call-hop depth for taint analysis (0 disables)")
	scanRealCmd.Flags().BoolVar(&scanNewOnly, "new-only", false, "Only report findings not in the baseline (requires --baseline)")
	scanRealCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "Fail (exit code 1) if findings at or above this severity: low, medium, high, critical")
	scanRealCmd.Flags().StringVar(&scanSince, "since", "", "Scan files changed since the given branch/commit (e.g., --since main)")
	scanRealCmd.Flags().StringVar(&scanBaselineName, "baseline", "", "Baseline name to compare against (used with --new-only)")
	scanRealCmd.Flags().StringVar(&scanGovernanceProfile, "governance-profile", "", "Rule governance profile: dev, pr, ci, audit (filters findings by rule maturity)")
	scanRealCmd.Flags().BoolVar(&scanSuggestFixes, "suggest-fixes", false, "Generate safe fix proposals for detected vulnerabilities")
	scanRealCmd.Flags().BoolVar(&scanStaged, "staged", false, "Only scan staged files (git staged changes)")
	scanRealCmd.Flags().StringSliceVar(&scanPaths, "path", nil, "Specific paths to scan (can be repeated)")
	scanRealCmd.Flags().BoolVar(&scanNoLicenses, "no-licenses", false, "Skip license scanning")
	scanRealCmd.Flags().BoolVar(&scanOffline, "offline", false, "Offline mode: only use local OSV DB and cache, no API calls (requires `patchflow cache update` first)")
	scanRealCmd.Flags().StringVar(&scanLicensePolicy, "license-policy", "", "License policy: fail on restricted licenses (e.g., 'gpl,agpl,proprietary,unknown')")
	scanRealCmd.Flags().StringSliceVar(&scanFramework, "framework", nil, "Enable specific framework rule packs (can be repeated, or 'auto' for detection-based activation)")
	scanRealCmd.Flags().StringSliceVar(&scanDisableFramework, "disable-framework", nil, "Disable specific framework rule packs (can be repeated; takes precedence over --framework)")
	scanRealCmd.Flags().StringVar(&scanRulesConfigPath, "rules-config", "", "Path to rules config YAML for block/inform/off mode overrides (legacy alias for --config; default: .patchflow/rules.yaml)")
	scanRealCmd.Flags().BoolVar(&scanSubmit, "submit", false, "Submit scan results to the PatchFlow backend (requires authentication)")
	scanRealCmd.Flags().IntVar(&scanProjectID, "project-id", 0, "Project ID for backend submission (required with --submit)")

	scanCmd.AddCommand(scanRealCmd)
}

func runScanReal(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	// Unify config flags: --config sets both --rules and --rules-config.
	// --rules and --rules-config are legacy aliases that still work
	// independently for backward compatibility.
	if scanConfigPath != "" {
		if scanRulesPath == "" {
			scanRulesPath = scanConfigPath
		}
		if scanRulesConfigPath == "" {
			scanRulesConfigPath = scanConfigPath
		}
	}

	// Determine scan mode for metadata. --since takes precedence over
	// --changed-only, which takes precedence over a full scan.
	scanMode := "full"
	if scanChangedOnly {
		scanMode = "changed"
	}
	if scanSince != "" {
		scanMode = "since"
		scanChangedOnly = true // --since implies changed-only
	}
	if scanStaged {
		scanMode = "staged"
		scanChangedOnly = true // --staged implies changed-only
	}

	// Detect project context. Full scans support non-git directories; diff-only
	// scans still require git metadata.
	repo, isGitRepo, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(err)
	}
	if isGitRepo {
		if scanStaged {
			// --staged: use git diff --name-only --cached
			if stagedErr := repo.DetectStagedFiles(); stagedErr != nil {
				return formatter.PrintError(fmt.Errorf("--staged: %w", stagedErr))
			}
			_ = repo.DetectDiffStats()
		} else if scanSince != "" {
			// --since <ref>: use git diff --name-only <ref>...HEAD and filter.
			sinceFiles, sinceErr := repo.ChangedFilesSince(scanSince)
			if sinceErr != nil {
				return formatter.PrintError(fmt.Errorf("--since %q: %w", scanSince, sinceErr))
			}
			repo.ChangedFiles = sinceFiles
			// Diff stats are still computed against the base branch for risk scoring.
			_ = repo.DetectDiffStats()
		} else {
			_ = repo.DetectChangedFiles()
			_ = repo.DetectDiffStats()
		}
	} else if scanChangedOnly || scanSince != "" || scanStaged {
		return formatter.PrintError(fmt.Errorf("--changed-only/--since/--staged requires a git repository"))
	} else if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
		_ = formatter.Print("Non-git directory detected; running full-project scan.")
	}

	// --path: filter to specific paths if provided
	if len(scanPaths) > 0 {
		repo.ChangedFiles = filterToPaths(repo.ChangedFiles, scanPaths)
	}

	// Debug/verbose: show the changed-file inventory so CI logs are auditable.
	verbose, _ := cmd.Flags().GetBool("verbose")
	if verbose && !output.IsJSON(formatter) && len(repo.ChangedFiles) > 0 {
		_ = formatter.Print(fmt.Sprintf("Changed files (%d) since %s:", len(repo.ChangedFiles), scanSince))
		for _, f := range repo.ChangedFiles {
			_ = formatter.Print("  " + f)
		}
	}

	started := time.Now()
	var engineTimings []analysis.EngineTiming

	// Detect monorepo structure early for informational output
	monorepoInfo := monorepo.Detect(repo.Root)
	if monorepoInfo.IsMonorepo() && (!output.IsJSON(formatter) && !QuietFromContext(ctx)) {
		_ = formatter.Print(fmt.Sprintf("Monorepo detected: %s (%d workspace members)", monorepoInfo.Tool, len(monorepoInfo.MemberDirs)))
	}

	// 1. SCA Analysis
	if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
		_ = formatter.Print("Running SCA analysis (OSV.dev)...")
	}
	scaStart := time.Now()
	scaAnalyzer := sca.NewAnalyzer()
	// SCA always scans all dependencies regardless of --changed-only/--since.
	// Vulnerabilities in existing dependencies are still relevant even if the
	// manifest file wasn't changed in this PR. Filtering to changed files
	// would silently drop critical vulnerability findings.
	switch scanProfile {
	case "quick":
		scaAnalyzer.MaxDepth = 1
	case "deep":
		scaAnalyzer.MaxDepth = 5
		scaAnalyzer.ResolveMavenTransitives = true
	default:
		scaAnalyzer.MaxDepth = 3
		scaAnalyzer.ResolveMavenTransitives = true
	}

	// Wire up OSV response cache so repeated scans skip API calls for
	// unchanged dependencies. Cache lives in a global XDG-compliant location
	// (~/.cache/patchflow/<project-hash>/osv/).
	// Migrate any legacy .patchflow/cache/ to the new global location.
	cacheutil.MigrateLegacyCache(repo.Root)
	osvCache := osvclient.NewCache(repo.Root)
	scaAnalyzer.OSV.SetCache(osvCache)

	// Wire up local OSV DB for offline/fast lookups. The DB is downloaded
	// via `patchflow cache update` and stored at ~/.patchflow/osv-db/.
	// When present, scans use it instead of the OSV.dev API, eliminating
	// network latency and enabling air-gapped scanning.
	osvLocalDB := osvdb.DefaultLocalDB()
	if osvLocalDB.IsAvailable() {
		scaAnalyzer.OSV.SetLocalDB(osvLocalDB)
		if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
			_ = formatter.Print("  Using local OSV database (offline mode).")
		}
	}

	// In --offline mode, skip all API calls. This enables air-gapped
	// scanning in regulated environments. Requires `patchflow cache update`
	// to have been run beforehand.
	if scanOffline {
		scaAnalyzer.OSV.SetOffline(true)
		if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
			_ = formatter.Print("  Offline mode enabled — no API calls will be made.")
		}
	}

	scaResult, err := scaAnalyzer.Analyze(ctx, repo.Root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("SCA analysis failed: %w", err))
	}
	engineTimings = append(engineTimings, analysis.EngineTiming{
		Engine: "osv-sca", Duration: time.Since(scaStart), Findings: len(scaResult.Findings),
	})

	// Initialize finding collection with SCA results.
	var allFindings []analysis.Finding
	allFindings = append(allFindings, scaResult.Findings...)
	analyzersRun := []string{"osv"}

	// 1b. License Analysis — fetch license info from package registries
	//     (npm, PyPI, Maven, RubyGems, Packagist) for dependencies that
	//     don't have license info in their lockfile/manifest. Generates
	//     findings for high-risk licenses (copyleft, proprietary, unknown).
	var licenseResult *registry.LicenseResult
	if !scanNoLicenses && len(scaResult.Dependencies) > 0 {
		if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
			_ = formatter.Print("Running license analysis (registry lookup)...")
		}
		licenseStart := time.Now()
		licenseAnalyzer := registry.NewLicenseAnalyzer()
		// Wire up registry cache so repeated scans skip API calls.
		regCache := registry.NewCache(repo.Root)
		licenseAnalyzer.SetCache(regCache)

		// Apply license policy if specified
		if scanLicensePolicy != "" {
			policies := strings.Split(scanLicensePolicy, ",")
			licenseAnalyzer.SetPolicy(policies)
			if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
				_ = formatter.Print(fmt.Sprintf("  License policy: %s (violations will be CRITICAL)", scanLicensePolicy))
			}
		}

		licenseResult, err = licenseAnalyzer.Analyze(ctx, scaResult.Dependencies)
		if err != nil {
			// Non-fatal — continue without license data
			if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
				_ = formatter.Print("  (license analysis skipped: " + err.Error() + ")")
			}
		} else {
			// Enrich dependencies with license info for SBOM/report
			if licenseResult.Enriched > 0 {
				licenseMap := make(map[string]string, len(scaResult.Dependencies))
				for _, info := range licenseResult.Infos {
					if info.RawLicense != "" {
						licenseMap[fmt.Sprintf("%s@%s", info.Dependency.Name, info.Dependency.Version)] = info.RawLicense
					}
				}
				for i := range scaResult.Dependencies {
					if scaResult.Dependencies[i].License == "" {
						key := fmt.Sprintf("%s@%s", scaResult.Dependencies[i].Name, scaResult.Dependencies[i].Version)
						if lic, ok := licenseMap[key]; ok {
							scaResult.Dependencies[i].License = lic
						}
					}
				}
			}
			allFindings = append(allFindings, licenseResult.Findings...)
			engineTimings = append(engineTimings, analysis.EngineTiming{
				Engine: "registry-license", Duration: time.Since(licenseStart), Findings: len(licenseResult.Findings),
			})
			analyzersRun = append(analyzersRun, "registry-license")
			if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
				_ = formatter.Print(fmt.Sprintf("  Licenses: %d enriched, %d high-risk findings", licenseResult.Enriched, len(licenseResult.Findings)))
			}
		}
	}

	// 2. SAST Analysis
	var sastResult *sast.Result

	if !scanNoSAST || !scanNoSecrets {
		if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
			_ = formatter.Print("Running SAST analysis (local tools)...")
		}
		sastStart := time.Now()
		sastRunner := sast.NewRunner()
		sastRunner.Quiet = output.IsJSON(formatter) || QuietFromContext(ctx)
		if scanChangedOnly {
			sastRunner.ChangedOnly = true
			sastRunner.ChangedFiles = repo.ChangedFiles
		}
		sastRunner.IncludeTests = scanIncludeTests

		// Wire embedded scanner flags based on --no-sast / --no-secrets
		if scanNoSAST {
			sastRunner.NoEmbeddedGo = true
			sastRunner.NoEmbeddedPatterns = true
		}
		if scanNoSecrets {
			sastRunner.NoEmbeddedSecrets = true
		}
		sastRunner.ShowSuppressed = scanShowSuppressed
		if scanRulesPath != "" {
			if err := pathutil.ValidateRulesPath(repo.Root, scanRulesPath); err != nil {
				return formatter.PrintError(fmt.Errorf("invalid rules path: %w", err))
			}
			sastRunner.CustomRulesPath = scanRulesPath
		}
		sastRunner.RespectGitignore = !scanNoGitignore
		sastRunner.IncrementalScan = scanIncremental
		sastRunner.SetTaintDepth(scanTaintDepth)

		// Framework rule pack selection merges three layers:
		// project config -> YAML policy -> CLI flags. The runner handles the
		// YAML policy overlay; CLI remains the highest-precedence input.
		projectFWCfg := fwpatterns.SelectionConfig{}
		if project.IsInitialized(repo.Root) {
			if projectCfg, err := project.LoadConfig(repo.Root); err == nil {
				projectFWCfg = fwpatterns.MergeSelectionConfig(projectFWCfg, fwpatterns.SelectionConfig{
					AutoDetect:    projectCfg.Frameworks.AutoDetect,
					AutoDetectSet: true,
					Enabled:       projectCfg.Frameworks.Enabled,
					Disabled:      projectCfg.Frameworks.Disabled,
				})
			}
		}
		sastRunner.FrameworkProjectConfig = projectFWCfg

		// Framework rule pack selection. --framework auto enables
		// detection-based activation. Explicit names force-enable those packs.
		// --disable-framework always wins.
		fwCfg := fwpatterns.SelectionConfig{}
		if cmd.Flags().Changed("framework") {
			cliCfg := fwpatterns.SelectionConfig{}
			explicit := false
			for _, f := range scanFramework {
				if f == "auto" {
					cliCfg.AutoDetect = true
					cliCfg.AutoDetectSet = true
				} else {
					explicit = true
					cliCfg.Enabled = append(cliCfg.Enabled, f)
				}
			}
			_ = explicit
			fwCfg = fwpatterns.MergeSelectionConfig(fwCfg, cliCfg)
		}
		if cmd.Flags().Changed("disable-framework") {
			fwCfg = fwpatterns.MergeSelectionConfig(fwCfg, fwpatterns.SelectionConfig{
				Disabled: scanDisableFramework,
			})
		}
		sastRunner.FrameworkConfig = fwCfg

		// When --changed-only or --since is set, auto-enable incremental
		// scanning so file-based scanners (patterns, secrets, tree-sitter)
		// only process the changed files. This gives 5-50x speedup on
		// large repos with small diffs.
		if scanChangedOnly && !scanIncremental {
			sastRunner.IncrementalScan = true
		}

		// Pass git changed files as pre-filter for the fastest incremental path.
		if scanChangedOnly && len(repo.ChangedFiles) > 0 {
			sastRunner.GitChangedFiles = repo.ChangedFiles
		}

		// In changed-only mode, skip external tools that can't filter to
		// changed files (gosec, bandit, semgrep scan the whole project).
		// gitleaks can be skipped too since embedded secrets scanner
		// already covers changed files. This avoids redundant full-project
		// scans that defeat the purpose of --changed-only.
		if scanChangedOnly {
			sastRunner.Tools = nil
		}

		// Profile-aware SAST: adjust scanner selection and timeouts per profile.
		// quick: skip taint and tree-sitter for fast CI feedback (~2x faster)
		// standard: all scanners with default 120s timeout
		// deep: all scanners with 10-minute timeout for thorough analysis
		switch scanProfile {
		case "quick":
			sastRunner.NoEmbeddedTaint = true
			sastRunner.NoEmbeddedTreeSitter = true
			sastRunner.NoEmbeddedTaintPatterns = true
			sastRunner.Timeout = 60 * time.Second
			// Quick profile: skip slow external tools (semgrep, bandit)
			var quickTools []sast.Tool
			for _, t := range sastRunner.Tools {
				if t.Name == "gosec" || t.Name == "gitleaks" {
					quickTools = append(quickTools, t)
				}
			}
			sastRunner.Tools = quickTools
		case "deep":
			sastRunner.Timeout = 10 * time.Minute
		default: // standard
			sastRunner.Timeout = 120 * time.Second
		}

		// Filter external tools based on flags
		if scanNoSAST && !scanNoSecrets {
			// Only keep gitleaks (external secret scanner)
			var filtered []sast.Tool
			for _, t := range sastRunner.Tools {
				if t.Name == "gitleaks" {
					filtered = append(filtered, t)
				}
			}
			sastRunner.Tools = filtered
		} else if !scanNoSAST && scanNoSecrets {
			// Remove gitleaks
			var filtered []sast.Tool
			for _, t := range sastRunner.Tools {
				if t.Name != "gitleaks" {
					filtered = append(filtered, t)
				}
			}
			sastRunner.Tools = filtered
		} else if scanNoSAST && scanNoSecrets {
			sastRunner.Tools = nil
		}

		sastResult, err = sastRunner.Analyze(ctx, repo.Root)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("SAST analysis failed: %w", err))
		}
		engineTimings = append(engineTimings, analysis.EngineTiming{
			Engine: "sast", Duration: time.Since(sastStart), Findings: len(sastResult.Findings),
		})
		// Merge SAST runner's internal phase timings (framework_detection, dedup_grouping, etc.)
		engineTimings = append(engineTimings, sastResult.EngineTimings...)
		allFindings = append(allFindings, sastResult.Findings...)
		analyzersRun = append(analyzersRun, sastResult.ToolsRun...)

		// Report detected frameworks and active packs (non-JSON only).
		if !output.IsJSON(formatter) && !QuietFromContext(ctx) && len(sastResult.Frameworks) > 0 {
			names := make([]string, 0, len(sastResult.Frameworks))
			for _, d := range sastResult.Frameworks {
				names = append(names, fmt.Sprintf("%s (%.0f%%)", d.Name, d.Confidence*100))
			}
			_ = formatter.Print(fmt.Sprintf("  Frameworks detected: %s", strings.Join(names, ", ")))
		}
	}

	// 3. Reachability Analysis
	if !scanNoReach && len(scaResult.Findings) > 0 {
		if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
			_ = formatter.Print("Running reachability analysis...")
		}
		reachStart := time.Now()
		reachAnalyzer := reachability.NewAnalyzer()
		reachResult, err := reachAnalyzer.Analyze(ctx, repo.Root, allFindings, scaResult.Dependencies)
		if err != nil {
			// Non-fatal — continue without reachability data
			if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
				_ = formatter.Print("  (reachability analysis skipped: " + err.Error() + ")")
			}
		} else {
			allFindings = reachResult.Findings
			engineTimings = append(engineTimings, analysis.EngineTiming{
				Engine: "reachability", Duration: time.Since(reachStart), Findings: len(allFindings),
			})
		}
	}

	// 3b. Governance profile filtering: if --governance-profile is set,
	//     filter out findings from rules that are not active in the selected
	//     governance profile. This prevents noisy experimental/beta rules
	//     from appearing in dev/pr/ci scans while still running them in audit.
	//
	//     The governance profile is independent of the scan profile (quick/
	//     standard/deep), which controls scanner selection and timeouts.
	//     If not explicitly set, it defaults based on the scan profile:
	//       quick    → dev
	//       standard → ci
	//       deep     → audit
	governanceProfile := rules.Profile(scanGovernanceProfile)
	if governanceProfile == "" {
		switch scanProfile {
		case "quick":
			governanceProfile = rules.ProfileDev
		case "deep":
			governanceProfile = rules.ProfileAudit
		default:
			governanceProfile = rules.ProfileCI
		}
	}
	if governanceProfile != rules.ProfileAudit {
		registry := buildGovernanceRegistry()
		filtered := make([]analysis.Finding, 0, len(allFindings))
		dropped := 0
		droppedByRule := make(map[string]int)
		for _, f := range allFindings {
			// SCA, secret, IaC, and license findings from external sources
			// (OSV, gitleaks, checkov, registry-license) don't have rule_ids
			// in the governance registry — they should never be filtered by
			// governance profile. Only SAST findings with a rule_id are
			// subject to governance filtering.
			if f.RuleID == "" || f.Type == analysis.TypeSCA || f.Type == analysis.TypeSecret || f.Type == analysis.TypeIaC || f.Type == analysis.TypeLicense {
				filtered = append(filtered, f)
				continue
			}
			if registry.IsRuleActiveInProfile(f.RuleID, governanceProfile) {
				filtered = append(filtered, f)
			} else {
				dropped++
				droppedByRule[f.RuleID]++
			}
		}
		if dropped > 0 && (!output.IsJSON(formatter) && !QuietFromContext(ctx)) {
			_ = formatter.Print("  Governance profile " + string(governanceProfile) + ": excluded " + strconv.Itoa(dropped) + " findings from inactive rules.")
			verbose, _ := cmd.Flags().GetBool("verbose")
			if verbose {
				for ruleID, count := range droppedByRule {
					_ = formatter.Print("    dropped " + strconv.Itoa(count) + "x " + ruleID + " (not active in " + string(governanceProfile) + " profile)")
				}
			}
		}
		allFindings = filtered
	}

	// 3c. Rule mode enforcement: load .patchflow/rules.yaml (or --rules-config)
	//     and apply block/inform/off modes. Findings with mode=off are suppressed.
	//     Findings with mode=block are marked as blocking (contribute to exit code).
	//     Findings with mode=inform are kept but do not block. Rules not listed in
	//     the config default to maturity-based behavior (stable+high → block, etc.).
	var modeResolver *rulesconfig.Resolver
	{
		var rulesCfg *rulesconfig.Config
		if scanRulesConfigPath != "" {
			rulesCfg, err = rulesconfig.LoadFromFile(scanRulesConfigPath)
			if err != nil {
				return formatter.PrintError(fmt.Errorf("failed to load rules config: %w", err))
			}
		} else {
			rulesCfg, err = rulesconfig.LoadFromDir(repo.Root)
			if err != nil {
				return formatter.PrintError(fmt.Errorf("failed to load rules config: %w", err))
			}
		}

		// Warn about unknown rule IDs in the config (typos, renamed rules, etc.)
		if rulesCfg != nil && len(rulesCfg.RuleModes) > 0 {
			reg := buildGovernanceRegistry()
			knownIDs := make(map[string]bool, reg.Count())
			for _, meta := range reg.All() {
				knownIDs[meta.ID] = true
			}
			unknown := rulesCfg.UnknownRules(knownIDs)
			if len(unknown) > 0 && !output.IsJSON(formatter) && !QuietFromContext(ctx) {
				_ = formatter.Print("  Warning: unknown rule IDs in rules.yaml (will be ignored): " + strings.Join(unknown, ", "))
			}
		}

		modeResolver = rulesconfig.NewResolver(rulesCfg, buildGovernanceRegistry())

		// Apply mode filtering: drop "off" findings, enrich with mode/blocking fields
		kept := make([]analysis.Finding, 0, len(allFindings))
		suppressedCount := 0
		for _, f := range allFindings {
			if f.RuleID == "" {
				// Findings without a rule ID (SCA, external tools) are not subject to mode enforcement
				kept = append(kept, f)
				continue
			}
			entry := modeResolver.Resolve(f.RuleID)
			if entry.Mode == rulesconfig.ModeOff {
				suppressedCount++
				continue
			}
			f.Mode = string(entry.Mode)
			f.Blocking = entry.Blocking
			f.ModeSource = string(entry.Source)
			f.Maturity = entry.Maturity
			kept = append(kept, f)
		}
		if suppressedCount > 0 && !output.IsJSON(formatter) && !QuietFromContext(ctx) {
			_ = formatter.Print("  Rule modes: suppressed " + strconv.Itoa(suppressedCount) + " findings (mode=off).")
		}
		allFindings = kept
	}

	// 4. Populate stable fingerprints on all findings before risk scoring,
	//    baseline comparison, and report generation. This is the single
	//    post-processing step that makes findings line-number independent.
	analysis.PopulateFingerprints(allFindings)

	// 5. --new-only: filter findings against the baseline BEFORE report
	//    generation so that reports, risk score, and exit code all reflect
	//    only the new findings. This is the production guarantee: running
	//    --new-only right after `baseline create` returns no findings and
	//    exit code 0.
	baselineDiff := (*baseline.Diff)(nil)
	if scanNewOnly && scanBaselineName != "" {
		mgr := baseline.NewManager(repo.Root)
		diff, err := mgr.Compare(scanBaselineName, allFindings)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("baseline comparison failed: %w", err))
		}
		baselineDiff = diff
		allFindings = diff.New
	}

	// 6. Risk Scoring (computed on the final, possibly filtered finding set)
	riskEngine := risk.NewEngine()
	riskScore := riskEngine.Compute(risk.ScoreInput{
		Findings:               allFindings,
		FilesChanged:           len(repo.ChangedFiles),
		AddedLines:             repo.AddedLines,
		DeletedLines:           repo.DeletedLines,
		DependencyFilesChanged: hasDependencyFiles(repo.ChangedFiles),
		CIWorkflowChanged:      hasCIWorkflow(repo.ChangedFiles),
		AuthFilesChanged:       hasAuthFiles(repo.ChangedFiles),
	})

	completed := time.Now()

	// Build analysis result with full scan metadata.
	manifestPaths := make([]string, 0, len(scaResult.Manifests))
	for _, m := range scaResult.Manifests {
		manifestPaths = append(manifestPaths, m.Path)
	}
	var licenseSummary *analysis.LicenseSummary
	if licenseResult != nil {
		licenseSummary = licenseResult.AnalysisSummary()
	}

	result := &analysis.AnalysisResult{
		ScanID:          generateScanID(),
		ProjectRoot:     repo.Root,
		Branch:          repo.CurrentBranch,
		CommitSHA:       repo.CommitSHA,
		BaseBranch:      repo.BaseBranch,
		StartedAt:       started,
		CompletedAt:     completed,
		Duration:        completed.Sub(started),
		Findings:        allFindings,
		Dependencies:    scaResult.Dependencies,
		LicenseSummary:  licenseSummary,
		RiskScore:       riskScore.Score,
		RiskLevel:       riskScore.Level,
		FilesChanged:    len(repo.ChangedFiles),
		AddedLines:      repo.AddedLines,
		DeletedLines:    repo.DeletedLines,
		Manifests:       manifestPaths,
		Analyzers:       analyzersRun,
		EngineTimings:   engineTimings,
		MonorepoTool:    string(monorepoInfo.Tool),
		MonorepoMembers: monorepoInfo.MemberDirs,
		// Scan metadata
		Profile:           scanProfile,
		Mode:              scanMode,
		Baseline:          scanBaselineName,
		NewOnly:           scanNewOnly,
		SinceRef:          scanSince,
		GovernanceProfile: governanceProfile.String(),
		Version:           versionString(),
		ChangedFiles:      repo.ChangedFiles,
	}
	computedExitCode, computedExitMessage := determineScanExit(allFindings, scanFailOn)
	result.ExitCode = computedExitCode

	// 7. Output
	gen := report.NewGenerator(result, &riskScore)

	// Write report file if requested
	if scanFormat != "" || scanOutput != "" {
		fmtStr := scanFormat
		if fmtStr == "" {
			fmtStr = "json"
		}
		if scanOutput != "" {
			// Validate output path to prevent path traversal
			if err := pathutil.ValidateOutputPath(repo.Root, scanOutput); err != nil {
				return formatter.PrintError(fmt.Errorf("invalid output path: %w", err))
			}
			if err := gen.WriteFile(fmtStr, scanOutput); err != nil {
				return formatter.PrintError(fmt.Errorf("failed to write report: %w", err))
			}
			if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
				_ = formatter.PrintSuccess("Report written to " + scanOutput)
			}
		}
	}

	// Auto-save a markdown report to .patchflow/reports/ for full scans, even in
	// non-git directories, so users always have a persistent artifact to share.
	if !output.IsJSON(formatter) && !QuietFromContext(ctx) {
		if writtenPath, err := gen.WriteToReportsDir(repo.Root, "markdown"); err == nil {
			_ = formatter.Print("  Report saved: " + writtenPath)
		}
	}

	// Save the raw AnalysisResult as JSON so `patchflow report` can reuse
	// it without re-running the entire scan pipeline.
	saveLastScanResult(repo.Root, result, &riskScore)

	if output.IsJSON(formatter) {
		// Enrich findings with OWASP category, fix suggestion, and detection method.
		enrichedFindings := enrichFindingsForJSON(allFindings)
		result.Findings = enrichedFindings

		// Submit to backend if --submit is set (before printing so the scan_id
		// from the backend can be included in the output).
		submissionError := ""
		if scanSubmit {
			if err := submitScanToBackend(cmd, ctx, result); err != nil {
				submissionError = fmt.Sprintf("backend submission failed: %v", err)
				// Don't fail the scan — local results are still valid.
			}
		}

		// For JSON mode, output the full result with scan metadata.
		if err := formatter.Print(struct {
			*analysis.AnalysisResult `json:"analysis"`
			Risk                     *risk.ScoreOutput `json:"risk"`
			SubmissionError          string            `json:"submission_error,omitempty"`
		}{
			AnalysisResult:  result,
			Risk:            &riskScore,
			SubmissionError: submissionError,
		}); err != nil {
			return err
		}
		if computedExitCode != exitcode.Success {
			return output.MarkErrorReported(&ExitError{Code: computedExitCode, Msg: computedExitMessage})
		}
		return nil
	}

	// Submit to backend if --submit is set (non-JSON mode).
	if scanSubmit {
		if err := submitScanToBackend(cmd, ctx, result); err != nil {
			if !QuietFromContext(ctx) {
				_ = formatter.PrintError(fmt.Errorf("backend submission failed: %w", err))
			}
		}
	}

	// Terminal summary
	_ = formatter.Print(gen.TerminalSummary())

	// Fix suggestions
	if scanSuggestFixes {
		fixEngine := fix.NewEngine()
		proposals := fixEngine.Suggest(allFindings)
		if len(proposals) > 0 {
			_ = formatter.Print("")
			_ = formatter.Print(fmt.Sprintf("Fix Proposals (%d):", len(proposals)))
			autoCount := 0
			for i, p := range proposals {
				autoTag := ""
				if p.AutoApplicable {
					autoTag = " [auto]"
					autoCount++
				}
				_ = formatter.Print(fmt.Sprintf("  %d. [%s%s] %s", i+1,
					strings.ToUpper(string(p.Confidence)), autoTag, p.Title))
				if p.FilePath != "" {
					_ = formatter.Print(fmt.Sprintf("     File: %s:%d", p.FilePath, p.LineStart))
				}
				if p.PackageName != "" {
					pkgLine := fmt.Sprintf("     Package: %s@%s", p.PackageName, p.PackageVersion)
					if p.FixedVersion != "" {
						pkgLine += fmt.Sprintf(" → %s", p.FixedVersion)
					}
					_ = formatter.Print(pkgLine)
				}
			}
			_ = formatter.Print("")
			_ = formatter.Print(fmt.Sprintf("  %d auto-applicable, %d need review", autoCount, len(proposals)-autoCount))
			_ = formatter.Print("  Run 'patchflow fix apply --all' to apply auto-applicable fixes")
		} else {
			_ = formatter.Print("")
			_ = formatter.Print("Fix Proposals: none available for current findings")
		}
	}

	// --new-only: print baseline comparison summary after the report.
	if baselineDiff != nil {
		_ = formatter.Print(fmt.Sprintf("\nBaseline: %s — New: %d, Resolved: %d, Unchanged: %d",
			scanBaselineName, baselineDiff.NewCount, baselineDiff.ResolvedCount, baselineDiff.UnchangedCount))
		if baselineDiff.NewCount > 0 {
			_ = formatter.Print("\nNew findings:")
			for _, f := range baselineDiff.New {
				_ = formatter.Print(fmt.Sprintf("  [%s] %s:%d — %s", f.RuleID, f.FilePath, f.LineStart, f.Title))
			}
		} else {
			_ = formatter.Print("No new findings relative to baseline.")
		}
	}

	// 8. Return the exit decision computed before report serialization so JSON,
	//    SARIF, saved results, and the process all agree on the same status.
	if computedExitCode != exitcode.Success {
		return &ExitError{Code: computedExitCode, Msg: computedExitMessage}
	}
	return nil
}

// determineScanExit computes the release-facing scan status before any report
// is serialized. --fail-on takes precedence over rule-mode blocking.
func determineScanExit(findings []analysis.Finding, failOn string) (int, string) {
	if failOn != "" {
		threshold := parseSeverityThreshold(failOn)
		blockingCount := 0
		for _, finding := range findings {
			if severityRank(finding.Severity) >= threshold {
				blockingCount++
			}
		}
		if blockingCount > 0 {
			return exitcode.FindingsFound, fmt.Sprintf("%d finding(s) at or above %s severity", blockingCount, failOn)
		}
		return exitcode.Success, ""
	}

	blockingCount := 0
	for _, finding := range findings {
		if finding.Blocking {
			blockingCount++
		}
	}
	if blockingCount > 0 {
		return exitcode.FindingsFound, fmt.Sprintf("%d blocking finding(s) (mode=block)", blockingCount)
	}
	return exitcode.Success, ""
}

func hasDependencyFiles(files []string) bool {
	for _, f := range files {
		name := f
		if idx := len(f); idx > 0 {
			// Get basename
			for i := len(f) - 1; i >= 0; i-- {
				if f[i] == '/' {
					name = f[i+1:]
					break
				}
			}
		}
		switch name {
		case "go.mod", "package.json", "requirements.txt", "pyproject.toml",
			"Cargo.toml", "Gemfile", "Gemfile.lock", "composer.json",
			"pom.xml", "build.gradle", "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
			return true
		}
	}
	return false
}

func hasCIWorkflow(files []string) bool {
	for _, f := range files {
		if contains(f, ".github/workflows/") || contains(f, ".gitlab-ci.yml") ||
			contains(f, "Jenkinsfile") || contains(f, ".circleci/") {
			return true
		}
	}
	return false
}

func hasAuthFiles(files []string) bool {
	for _, f := range files {
		lower := toLower(f)
		for _, p := range []string{"auth", "login", "session", "jwt", "oauth", "password", "credential"} {
			if contains(lower, p) {
				return true
			}
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// getRepoRoot returns the root of the current git repository.
func getRepoRoot() (string, error) {
	repo, err := git.Detect()
	if err != nil {
		return "", err
	}
	return repo.Root, nil
}

// parseSeverityThreshold converts a severity string to a numeric rank.
// low=1, medium=2, high=3, critical=4. Higher = more severe.
func parseSeverityThreshold(s string) int {
	switch toLower(s) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

// severityRank converts an analysis.Severity to a numeric rank.
func severityRank(s analysis.Severity) int {
	switch s {
	case analysis.SeverityLow:
		return 1
	case analysis.SeverityMedium:
		return 2
	case analysis.SeverityHigh:
		return 3
	case analysis.SeverityCritical:
		return 4
	case analysis.SeverityInfo:
		return 0
	}
	return 0
}

// Ensure context is used
var _ = context.Background

// generateScanID returns a short, unique, sortable scan identifier of the form
// YYYYMMDDHHMMSS-<6 random hex>. It is stable enough for CI log correlation
// and report deduplication without pulling in a UUID dependency.
func generateScanID() string {
	now := time.Now().UTC()
	b := make([]byte, 3)
	for i := range b {
		b[i] = byte('0' + (now.UnixNano() >> uint(i*8) & 0x3F))
	}
	return now.Format("20060102150405") + "-" + string(b)
}

// versionString returns the CLI version for scan metadata. It reads the
// pkg/version package's Version variable via a helper to avoid an import cycle
// in test builds.
func versionString() string {
	return versionBuildInfo()
}

// enrichFindingsForJSON adds OWASP category, fix suggestion, detection method,
// and sanitizer status to each finding for JSON output. The Finding struct now
// has dedicated fields for these, so they appear as first-class JSON keys.
func enrichFindingsForJSON(findings []analysis.Finding) []analysis.Finding {
	enriched := make([]analysis.Finding, len(findings))
	for i, f := range findings {
		// Populate the dedicated OWASPCategory field from CWE mapping.
		if f.CWEID != "" && f.OWASPCategory == "" {
			f.OWASPCategory = cwe.OWASPCategoryLabel(f.CWEID)
		}
		// Add fix suggestion from the snippet database into Recommendation.
		if f.RuleID != "" {
			if snippet := fixsnippet.ForRule(f.RuleID); snippet != nil {
				fixLine := fmt.Sprintf(" Fix: %s", snippet.Title)
				if f.Recommendation == "" {
					f.Recommendation = snippet.Title
				} else if !strings.Contains(f.Recommendation, snippet.Title) {
					f.Recommendation = f.Recommendation + fixLine
				}
			}
		}
		enriched[i] = f
	}
	return enriched
}

// filterToPaths filters a list of files to only those matching the given paths.
func filterToPaths(files []string, paths []string) []string {
	if len(paths) == 0 {
		return files
	}
	var result []string
	for _, f := range files {
		for _, p := range paths {
			if strings.HasPrefix(f, p) || f == p {
				result = append(result, f)
				break
			}
		}
	}
	return result
}

// submitScanToBackend posts the AnalysisResult JSON to the backend's
// POST /api/v1/cli/scan-results endpoint. Requires authentication
// (patchflow login) and --project-id.
func submitScanToBackend(cmd *cobra.Command, ctx context.Context, result *analysis.AnalysisResult) error {
	if scanProjectID == 0 {
		return fmt.Errorf("--project-id is required when using --submit")
	}

	token, err := requireAuthToken(cmd)
	if err != nil {
		return err
	}

	cfg := ConfigFromContext(ctx)
	if cfg == nil || cfg.APIURL == "" {
		return fmt.Errorf("no API URL configured. Set --api-url or run 'patchflow config set apiurl <url>'")
	}

	// Marshal the result to JSON (the backend expects the AnalysisResult schema).
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	client := api.NewClient(cfg.APIURL, token)
	resp, err := client.PostScanResults(ctx, payload, scanProjectID, result.ScanID)
	if err != nil {
		return fmt.Errorf("backend rejected scan results: %w", err)
	}

	// Update the result's ScanID to the backend-assigned scan_id so the
	// JSON output reflects the persisted scan.
	result.ScanID = fmt.Sprintf("backend-scan-%d", resp.ScanID)

	return nil
}

// lastScanFile is the filename for the cached scan result used by `patchflow report`.
const lastScanFile = "last-scan.json"

// saveLastScanResult writes the AnalysisResult as JSON to .patchflow/reports/
// so `patchflow report` can reuse it without re-running the scan.
func saveLastScanResult(root string, result *analysis.AnalysisResult, riskScore *risk.ScoreOutput) {
	reportsDir := filepath.Join(root, ".patchflow", "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return
	}
	path := filepath.Join(reportsDir, lastScanFile)
	data, err := json.MarshalIndent(struct {
		*analysis.AnalysisResult `json:"analysis"`
		Risk                     *risk.ScoreOutput `json:"risk"`
	}{
		AnalysisResult: result,
		Risk:           riskScore,
	}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o644)
}

// loadLastScanResult reads the cached scan result from .patchflow/reports/last-scan.json.
// Returns nil if the file doesn't exist or is invalid.
func loadLastScanResult(root string) (*analysis.AnalysisResult, *risk.ScoreOutput) {
	path := filepath.Join(root, ".patchflow", "reports", lastScanFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var cached struct {
		Analysis *analysis.AnalysisResult `json:"analysis"`
		Risk     *risk.ScoreOutput        `json:"risk"`
	}
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, nil
	}
	return cached.Analysis, cached.Risk
}
