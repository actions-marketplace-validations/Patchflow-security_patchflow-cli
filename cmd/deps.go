package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/manifest"
	"github.com/Patchflow-security/patchflow-cli/internal/mavenres"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	osvclient "github.com/Patchflow-security/patchflow-cli/internal/osv"
	"github.com/Patchflow-security/patchflow-cli/internal/registry"
	"github.com/Patchflow-security/patchflow-cli/internal/sbom"
	"github.com/spf13/cobra"
)

var depsCmd = &cobra.Command{
	Use:   "deps",
	Short: "Analyze dependencies",
	Long:  `Analyze project dependencies: list, diff against a base branch, find vulnerable packages, or check licenses.`,
}

var depsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all dependencies",
	RunE:  runDepsList,
}

var depsVulnerableCmd = &cobra.Command{
	Use:   "vulnerable",
	Short: "List vulnerable dependencies",
	RunE:  runDepsVulnerable,
}

var depsDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show dependency changes against base branch",
	RunE:  runDepsDiff,
}

var depsTreeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Show dependency tree by ecosystem",
	RunE:  runDepsTree,
}

var depsLicensesCmd = &cobra.Command{
	Use:   "licenses",
	Short: "Check dependency licenses and classify by risk",
	Long: `Extract and classify license information from project dependencies.
Licenses are categorized as permissive, weak copyleft, copyleft, proprietary, or unknown,
with risk levels (low, medium, high, critical) for policy enforcement.`,
	RunE: runDepsLicenses,
}

func init() {
	depsCmd.AddCommand(depsListCmd)
	depsCmd.AddCommand(depsVulnerableCmd)
	depsCmd.AddCommand(depsDiffCmd)
	depsCmd.AddCommand(depsTreeCmd)
	depsCmd.AddCommand(depsLicensesCmd)
	rootCmd.AddCommand(depsCmd)
}

func runDepsList(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	root, err := getRepoRoot()
	if err != nil {
		return formatter.PrintError(err)
	}

	deps, _, err := manifest.ParseAll(root, 3)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to parse manifests: %w", err))
	}

	// Resolve Maven transitive dependencies to match `scan run` behavior.
	// Without this, `deps list` shows fewer deps than `scan run` because
	// Maven's pom.xml only lists direct deps; transitives are resolved at
	// build time.
	deps = resolveMavenTransitivesIfNeeded(ctx, root, deps)

	if output.IsJSON(formatter) {
		return formatter.Print(deps)
	}

	if len(deps) == 0 {
		_ = formatter.Print("No dependencies found.")
		return nil
	}

	_ = formatter.Print(fmt.Sprintf("Total dependencies: %d", len(deps)))
	_ = formatter.Print("")

	headers := []string{"NAME", "VERSION", "ECOSYSTEM", "DIRECT", "MANIFEST"}
	rows := make([][]string, 0, len(deps))
	for _, dep := range deps {
		direct := "yes"
		if !dep.IsDirect {
			direct = "no"
		}
		rows = append(rows, []string{
			truncateStr(dep.Name, 40),
			dep.Version,
			string(dep.Ecosystem),
			direct,
			dep.ManifestPath,
		})
	}
	return formatter.PrintTable(headers, rows)
}

func runDepsVulnerable(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	root, err := getRepoRoot()
	if err != nil {
		return formatter.PrintError(err)
	}

	deps, _, err := manifest.ParseAll(root, 3)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to parse manifests: %w", err))
	}

	// Resolve Maven transitives to match `scan run` behavior.
	deps = resolveMavenTransitivesIfNeeded(ctx, root, deps)

	if len(deps) == 0 {
		_ = formatter.Print("No dependencies found.")
		return nil
	}

	if !output.IsJSON(formatter) {
		_ = formatter.Print(fmt.Sprintf("Querying OSV.dev for %d dependencies...", len(deps)))
	}

	osv := osvclient.NewClient()
	vulnResults, err := osv.QueryBatch(ctx, deps)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("OSV query failed: %w", err))
	}

	type vulnDep struct {
		Dependency analysis.Dependency   `json:"dependency"`
		Vulns      []osvclient.Vulnerability `json:"vulns"`
	}

	var vulnerableDeps []vulnDep
	for i, vulns := range vulnResults {
		if i >= len(deps) {
			break
		}
		if len(vulns) > 0 {
			vulnerableDeps = append(vulnerableDeps, vulnDep{
				Dependency: deps[i],
				Vulns:      vulns,
			})
		}
	}

	if output.IsJSON(formatter) {
		return formatter.Print(vulnerableDeps)
	}

	if len(vulnerableDeps) == 0 {
		_ = formatter.PrintSuccess("No vulnerable dependencies found.")
		return nil
	}

	_ = formatter.Print(fmt.Sprintf("Vulnerable dependencies: %d", len(vulnerableDeps)))
	_ = formatter.Print("")

	for _, vd := range vulnerableDeps {
		dep := vd.Dependency
		_ = formatter.Print(fmt.Sprintf("%s@%s (%s) — %d vulnerability(ies)",
			dep.Name, dep.Version, dep.Ecosystem, len(vd.Vulns)))
		for _, v := range vd.Vulns {
			severity := osvclient.ExtractSeverity(v)
			cve := osvclient.ExtractCVEID(v)
			fixed := osvclient.ExtractFixedVersion(v, dep.Name, dep.Version)
			line := fmt.Sprintf("  [%s] %s", strings.ToUpper(string(severity)), v.ID)
			if cve != "" {
				line += " (" + cve + ")"
			}
			if fixed != "" {
				line += " — fixed in " + fixed
			}
			_ = formatter.Print(line)
		}
		_ = formatter.Print("")
	}

	return nil
}

func runDepsDiff(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())

	repo, err := git.Detect()
	if err != nil {
		return formatter.PrintError(err)
	}

	// Current dependencies
	currentDeps, _, err := manifest.ParseAll(repo.Root, 3)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to parse manifests: %w", err))
	}

	// Get changed manifest files
	_ = repo.DetectChangedFiles()
	changedManifests := make(map[string]bool)
	for _, f := range repo.ChangedFiles {
		if _, ok := manifest.KnownManifests[filepath.Base(f)]; ok {
			changedManifests[f] = true
		}
	}

	if output.IsJSON(formatter) {
		return formatter.Print(struct {
			ChangedManifests []string                `json:"changed_manifests"`
			Dependencies     []analysis.Dependency    `json:"dependencies"`
			TotalCount       int                     `json:"total_count"`
		}{
			ChangedManifests: keysFromMap(changedManifests),
			Dependencies:     currentDeps,
			TotalCount:       len(currentDeps),
		})
	}

	if len(changedManifests) == 0 {
		_ = formatter.Print("No dependency manifest files changed.")
		return nil
	}

	_ = formatter.Print("Changed dependency manifests:")
	for f := range changedManifests {
		_ = formatter.Print("  " + f)
	}
	_ = formatter.Print("")

	// Show dependencies from changed manifests
	var changedDeps []analysis.Dependency
	for _, dep := range currentDeps {
		if changedManifests[dep.ManifestPath] {
			changedDeps = append(changedDeps, dep)
		}
	}

	if len(changedDeps) > 0 {
		_ = formatter.Print(fmt.Sprintf("Dependencies in changed manifests: %d", len(changedDeps)))
		headers := []string{"NAME", "VERSION", "ECOSYSTEM", "MANIFEST"}
		rows := make([][]string, 0, len(changedDeps))
		for _, dep := range changedDeps {
			rows = append(rows, []string{
				truncateStr(dep.Name, 40),
				dep.Version,
				string(dep.Ecosystem),
				dep.ManifestPath,
			})
		}
		_ = formatter.PrintTable(headers, rows)
	}

	return nil
}

func runDepsTree(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())

	root, err := getRepoRoot()
	if err != nil {
		return formatter.PrintError(err)
	}

	deps, manifests, err := manifest.ParseAll(root, 3)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to parse manifests: %w", err))
	}

	// Group by ecosystem
	byEcosystem := make(map[analysis.Ecosystem][]analysis.Dependency)
	for _, dep := range deps {
		byEcosystem[dep.Ecosystem] = append(byEcosystem[dep.Ecosystem], dep)
	}

	if output.IsJSON(formatter) {
		return formatter.Print(struct {
			Manifests  []manifest.ManifestInfo       `json:"manifests"`
			ByEcosystem map[string][]analysis.Dependency `json:"by_ecosystem"`
			TotalCount  int                          `json:"total_count"`
		}{
			Manifests:   manifests,
			ByEcosystem: ecosystemMapToStringMap(byEcosystem),
			TotalCount:  len(deps),
		})
	}

	if len(deps) == 0 {
		_ = formatter.Print("No dependencies found.")
		return nil
	}

	_ = formatter.Print(fmt.Sprintf("Dependency Tree (%d total)", len(deps)))
	_ = formatter.Print("")

	// Sort ecosystems for stable output
	ecosystems := make([]string, 0, len(byEcosystem))
	for eco := range byEcosystem {
		ecosystems = append(ecosystems, string(eco))
	}
	sort.Strings(ecosystems)

	for _, ecoStr := range ecosystems {
		ecoDeps := byEcosystem[analysis.Ecosystem(ecoStr)]
		_ = formatter.Print(fmt.Sprintf("├─ %s (%d)", ecoStr, len(ecoDeps)))

		// Group by manifest within ecosystem
		byManifest := make(map[string][]analysis.Dependency)
		for _, dep := range ecoDeps {
			byManifest[dep.ManifestPath] = append(byManifest[dep.ManifestPath], dep)
		}

		manifestPaths := make([]string, 0, len(byManifest))
		for mp := range byManifest {
			manifestPaths = append(manifestPaths, mp)
		}
		sort.Strings(manifestPaths)

		for _, mp := range manifestPaths {
			_ = formatter.Print(fmt.Sprintf("│  ├─ %s (%d)", mp, len(byManifest[mp])))
			for _, dep := range byManifest[mp] {
				direct := ""
				if dep.IsDirect {
					direct = " *"
				}
				_ = formatter.Print(fmt.Sprintf("│  │  ├─ %s@%s%s", dep.Name, dep.Version, direct))
			}
		}
	}

	return nil
}

func keysFromMap(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func ecosystemMapToStringMap(m map[analysis.Ecosystem][]analysis.Dependency) map[string][]analysis.Dependency {
	result := make(map[string][]analysis.Dependency, len(m))
	for k, v := range m {
		result[string(k)] = v
	}
	return result
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

func runDepsLicenses(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	root, err := getRepoRoot()
	if err != nil {
		return formatter.PrintError(err)
	}

	// Parse manifests to get dependencies with license info
	deps, _, err := manifest.ParseAll(root, 3)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("failed to parse manifests: %w", err))
	}

	if len(deps) == 0 {
		return formatter.Print("No dependencies found.")
	}

	// Resolve Maven transitives to match `scan run` behavior.
	deps = resolveMavenTransitivesIfNeeded(ctx, root, deps)

	// Use the same enrichment pipeline as `scan run`: fetch missing license
	// info from package registries (npm, PyPI, Maven, RubyGems, Go/GitHub)
	// with disk caching so repeated scans skip network calls.
	if !output.IsJSON(formatter) {
		_ = formatter.Print(fmt.Sprintf("Fetching license info for %d dependencies...", len(deps)))
	}
	licenseAnalyzer := registry.NewLicenseAnalyzer()
	licenseAnalyzer.SetCache(registry.NewCache(root))

	licenseResult, err := licenseAnalyzer.Analyze(ctx, deps)
	if err != nil {
		// Fall back to manifest-only extraction if registry lookup fails
		licenseInfos := sbom.ExtractLicenses(deps)
		summary := sbom.SummarizeLicenses(licenseInfos)
		return outputDepsLicenses(formatter, licenseInfos, summary)
	}

	licenseInfos := licenseResult.Infos
	summary := licenseResult.Summary

	if !output.IsJSON(formatter) {
		_ = formatter.Print(fmt.Sprintf("  Enriched: %d | With license: %d | No license: %d",
			licenseResult.Enriched, summary.WithLicense, summary.NoLicense))
	}

	return outputDepsLicenses(formatter, licenseInfos, summary)
}

// outputDepsLicenses renders the license report in JSON or text format.
func outputDepsLicenses(formatter output.Formatter, licenseInfos []sbom.LicenseInfo, summary sbom.LicenseSummary) error {
	if output.IsJSON(formatter) {
		type licenseReport struct {
			Summary struct {
				Total       int            `json:"total"`
				WithLicense int            `json:"with_license"`
				NoLicense   int            `json:"no_license"`
				ByCategory  map[string]int `json:"by_category"`
				ByRisk      map[string]int `json:"by_risk"`
			} `json:"summary"`
			Licenses []struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
				License   string `json:"license"`
				Category  string `json:"category"`
				Risk      string `json:"risk"`
			} `json:"licenses"`
		}
		var report licenseReport
		report.Summary.Total = summary.Total
		report.Summary.WithLicense = summary.WithLicense
		report.Summary.NoLicense = summary.NoLicense
		report.Summary.ByCategory = make(map[string]int)
		for k, v := range summary.ByCategory {
			report.Summary.ByCategory[string(k)] = v
		}
		report.Summary.ByRisk = make(map[string]int)
		for k, v := range summary.ByRisk {
			report.Summary.ByRisk[string(k)] = v
		}
		for _, info := range licenseInfos {
			report.Licenses = append(report.Licenses, struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
				License   string `json:"license"`
				Category  string `json:"category"`
				Risk      string `json:"risk"`
			}{
				Name:      info.Dependency.Name,
				Version:   info.Dependency.Version,
				Ecosystem: string(info.Dependency.Ecosystem),
				License:   info.RawLicense,
				Category:  string(info.Category),
				Risk:      string(info.Risk),
			})
		}
		return formatter.Print(report)
	}

	// Text output
	formatter.Print(fmt.Sprintf("License Report: %d dependencies\n", summary.Total))
	formatter.Print(fmt.Sprintf("  With license: %d | No license: %d\n\n", summary.WithLicense, summary.NoLicense))

	// Summary by category
	formatter.Print("By Category:")
	categories := []string{"permissive", "weak_copyleft", "copyleft", "proprietary", "unknown"}
	for _, cat := range categories {
		if count := summary.ByCategory[sbom.LicenseCategory(cat)]; count > 0 {
			formatter.Print(fmt.Sprintf("  %-15s %d", cat, count))
		}
	}

	// Summary by risk
	formatter.Print("\nBy Risk:")
	risks := []string{"low", "medium", "high", "critical"}
	for _, risk := range risks {
		if count := summary.ByRisk[sbom.LicenseRisk(risk)]; count > 0 {
			formatter.Print(fmt.Sprintf("  %-15s %d", risk, count))
		}
	}

	// High/critical risk details
	if len(summary.HighRisk) > 0 {
		formatter.Print("\n\nHigh/Critical Risk Licenses:")
		for _, info := range summary.HighRisk {
			license := info.RawLicense
			if license == "" {
				license = "(no license)"
			}
			formatter.Print(fmt.Sprintf("  [%s] %s@%s — %s (%s)",
				info.Risk, info.Dependency.Name, info.Dependency.Version, license, info.Category))
		}
	}

	// All licenses detail
	formatter.Print("\n\nAll Dependencies:")
	for _, info := range licenseInfos {
		license := info.RawLicense
		if license == "" {
			license = "(no license)"
		}
		formatter.Print(fmt.Sprintf("  %-40s %-15s %-20s [%s]", truncateStr(info.Dependency.Name, 40), info.Risk, license, info.Category))
	}

	return nil
}

// resolveMavenTransitivesIfNeeded resolves Maven transitive dependencies
// when the project contains Maven deps, matching `scan run` behavior.
// This ensures `deps list`, `deps vulnerable`, and `deps licenses` report
// the same dependency counts as `scan run`.
func resolveMavenTransitivesIfNeeded(ctx context.Context, root string, deps []analysis.Dependency) []analysis.Dependency {
	hasMaven := false
	for _, d := range deps {
		if d.Ecosystem == analysis.EcosystemMaven {
			hasMaven = true
			break
		}
	}
	if !hasMaven {
		return deps
	}
	resolver := mavenres.NewResolver()
	resolver.SetCache(mavenres.NewCache(root))
	resolver.SetRoot(root)
	resolved, err := resolver.Resolve(ctx, deps)
	if err == nil && len(resolved) > len(deps) {
		return resolved
	}
	return deps
}

// Ensure context is used
var _ = context.Background
