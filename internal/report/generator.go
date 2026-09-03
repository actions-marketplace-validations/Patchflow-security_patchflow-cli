// Package report generates analysis reports in multiple formats:
// terminal summary, Markdown, JSON, and SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/cwe"
	"github.com/Patchflow-security/patchflow-cli/internal/fixsnippet"
	"github.com/Patchflow-security/patchflow-cli/internal/risk"
)

// Generator produces reports from analysis results.
type Generator struct {
	Result *analysis.AnalysisResult
	Risk   *risk.ScoreOutput
}

// NewGenerator creates a report generator.
func NewGenerator(result *analysis.AnalysisResult, riskScore *risk.ScoreOutput) *Generator {
	return &Generator{Result: result, Risk: riskScore}
}

// --- Terminal summary ---

// TerminalSummary returns a human-readable summary string for terminal output.
func (g *Generator) TerminalSummary() string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("PatchFlow Analysis Report\n")
	sb.WriteString("=========================\n")
	sb.WriteString("\n")

	// Repository info
	if g.Result != nil {
		sb.WriteString(fmt.Sprintf("Repository:  %s\n", g.Result.ProjectRoot))
		sb.WriteString(fmt.Sprintf("Branch:      %s\n", g.Result.Branch))
		sb.WriteString(fmt.Sprintf("Commit:      %s\n", shortenSHA(g.Result.CommitSHA)))
		sb.WriteString(fmt.Sprintf("Base:        %s\n", g.Result.BaseBranch))
		// Scan metadata line
		var metaParts []string
		if g.Result.ScanID != "" {
			metaParts = append(metaParts, "scan="+g.Result.ScanID)
		}
		if g.Result.Version != "" {
			metaParts = append(metaParts, "v"+g.Result.Version)
		}
		if g.Result.Profile != "" {
			metaParts = append(metaParts, "profile="+g.Result.Profile)
		}
		if g.Result.Mode != "" {
			metaParts = append(metaParts, "mode="+g.Result.Mode)
		}
		if g.Result.Baseline != "" {
			metaParts = append(metaParts, "baseline="+g.Result.Baseline)
		}
		if g.Result.NewOnly {
			metaParts = append(metaParts, "new-only")
		}
		if g.Result.SinceRef != "" {
			metaParts = append(metaParts, "since="+g.Result.SinceRef)
		}
		if len(metaParts) > 0 {
			sb.WriteString(fmt.Sprintf("Scan:        %s\n", strings.Join(metaParts, "  ")))
		}
		sb.WriteString("\n")

		sb.WriteString(fmt.Sprintf("Files changed: %d  (+%d / -%d)\n",
			g.Result.FilesChanged, g.Result.AddedLines, g.Result.DeletedLines))
		sb.WriteString(fmt.Sprintf("Dependencies:  %d\n", len(g.Result.Dependencies)))
		sb.WriteString(fmt.Sprintf("Manifests:     %d\n", len(g.Result.Manifests)))
		sb.WriteString(fmt.Sprintf("Analyzers:     %s\n", strings.Join(g.Result.Analyzers, ", ")))
		sb.WriteString("\n")

		// Per-engine timing
		if len(g.Result.EngineTimings) > 0 {
			sb.WriteString("Engine timings:\n")
			for _, et := range g.Result.EngineTimings {
				sb.WriteString(fmt.Sprintf("  %-15s  %s  (%d findings)\n", et.Engine, et.Duration.Round(time.Millisecond), et.Findings))
			}
			totalDur := g.Result.Duration
			if totalDur == 0 {
				totalDur = g.Result.CompletedAt.Sub(g.Result.StartedAt)
			}
			sb.WriteString(fmt.Sprintf("  %-15s  %s\n", "total", totalDur.Round(time.Millisecond)))
			sb.WriteString("\n")
		}
	}

	// Risk score
	if g.Risk != nil {
		sb.WriteString(fmt.Sprintf("Risk Score: %d/100 (%s)\n", g.Risk.Score, strings.ToUpper(g.Risk.Level)))
		sb.WriteString("\n")

		// Severity breakdown
		if len(g.Risk.FindingsBySeverity) > 0 {
			sb.WriteString("Findings by severity:\n")
			severities := []string{"critical", "high", "medium", "low", "info"}
			for _, sev := range severities {
				if count, ok := g.Risk.FindingsBySeverity[sev]; ok && count > 0 {
					sb.WriteString(fmt.Sprintf("  %-10s  %d\n", sev, count))
				}
			}
			sb.WriteString("\n")
		}

		// Vulnerability class summary (CWE → OWASP grouping)
		if g.Result != nil && len(g.Result.Findings) > 0 {
			if summary := VulnerabilityClassSummary(g.Result.Findings); summary != "" {
				sb.WriteString("Vulnerability classes:\n")
				sb.WriteString(summary)
				sb.WriteString("\n")
			}
		}
	}

	// Top findings
	topFindings := g.Risk.TopFindings
	if g.Result != nil && len(g.Result.Findings) > 0 {
		grouped, _ := GroupSCAFindings(g.Result.Findings)
		sortedTop := SortFindings(grouped)
		if len(sortedTop) > 10 {
			sortedTop = sortedTop[:10]
		}
		topFindings = sortedTop
	}
	if len(topFindings) > 0 {
		sb.WriteString("Top findings:\n")
		for i, f := range topFindings {
			// Confidence indicator: [TAINT], [AST], [REGEX], [SCA], [SECRET]
			indicator := confidenceIndicator(f)
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s %s\n", i+1, strings.ToUpper(string(f.Severity)), indicator, f.Title))
			if f.PackageName != "" {
				sb.WriteString(fmt.Sprintf("     Package: %s@%s\n", f.PackageName, f.PackageVersion))
			}
			if f.FilePath != "" {
				sb.WriteString(fmt.Sprintf("     File:    %s:%d\n", f.FilePath, f.LineStart))
			}
			if f.CWEID != "" {
				if owaspLabel := cwe.OWASPCategoryLabel(f.CWEID); owaspLabel != "" {
					sb.WriteString(fmt.Sprintf("     Class:   %s (%s)\n", f.CWEID, owaspLabel))
				} else {
					sb.WriteString(fmt.Sprintf("     CWE:     %s\n", f.CWEID))
				}
			}
			if f.Recommendation != "" {
				sb.WriteString(fmt.Sprintf("     Fix:     %s\n", f.Recommendation))
			}
			if f.Reachability != "" {
				sb.WriteString(fmt.Sprintf("     Reach:   %s\n", f.Reachability))
			}
			sb.WriteString("\n")
		}
	}

	// Recommendations
	if g.Risk != nil {
		sb.WriteString("Recommendations:\n")
		recs := g.generateRecommendations()
		for i, rec := range recs {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, rec))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func (g *Generator) generateRecommendations() []string {
	var recs []string

	if g.Risk == nil {
		return recs
	}

	var findings []analysis.Finding
	if g.Result != nil {
		findings = g.Result.Findings
	}
	if len(findings) == 0 {
		findings = g.Risk.TopFindings
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	criticalReachable := 0
	highReachable := 0
	secretsFound := 0
	for _, f := range findings {
		switch f.Severity {
		case analysis.SeverityCritical:
			criticalCount++
		case analysis.SeverityHigh:
			highCount++
		case analysis.SeverityMedium:
			mediumCount++
		}
		if isSecretFinding(f) {
			secretsFound++
		}
		if f.Severity == analysis.SeverityCritical && f.Reachability == analysis.ReachabilityHigh {
			criticalReachable++
		}
		if f.Severity == analysis.SeverityHigh && f.Reachability == analysis.ReachabilityHigh {
			highReachable++
		}
	}

	if secretsFound > 0 {
		recs = append(recs, fmt.Sprintf("Rotate and remove %d detected secret(s) immediately", secretsFound))
	}
	if criticalCount > criticalReachable {
		recs = append(recs, fmt.Sprintf("Fix or triage %d critical finding(s) before opening a PR", criticalCount-criticalReachable))
	}
	if criticalReachable > 0 {
		recs = append(recs, fmt.Sprintf("Fix %d critical reachable vulnerability(s) before opening a PR", criticalReachable))
	}
	if highCount > highReachable {
		recs = append(recs, fmt.Sprintf("Address or triage %d high-severity finding(s)", highCount-highReachable))
	}
	if highReachable > 0 {
		recs = append(recs, fmt.Sprintf("Address %d high-severity reachable vulnerability(s)", highReachable))
	}

	// Reachability-aware SCA counts
	reachableVulns := 0
	unreachableVulns := 0
	upgradeableReachable := 0
	for _, f := range findings {
		if f.Type == analysis.TypeSCA {
			if f.Reachability == analysis.ReachabilityHigh || f.Reachability == analysis.ReachabilityMedium {
				reachableVulns++
				if f.FixedVersion != "" {
					upgradeableReachable++
				}
			} else if f.Reachability == analysis.ReachabilityNone || f.Reachability == analysis.ReachabilityLow {
				unreachableVulns++
			}
		}
	}

	if upgradeableReachable > 0 {
		recs = append(recs, fmt.Sprintf("Upgrade %d reachable vulnerable package(s) with fixed versions", upgradeableReachable))
	}
	if reachableVulns > upgradeableReachable {
		recs = append(recs, fmt.Sprintf("Review %d reachable dependency advisories with no fixed version yet", reachableVulns-upgradeableReachable))
	}
	if unreachableVulns > 0 {
		recs = append(recs, fmt.Sprintf("Track %d unreachable dependency advisories (no immediate action required)", unreachableVulns))
	}

	if g.Risk.Score >= 80 && len(recs) == 0 {
		recs = append(recs, "Risk score is blocking; review the highest weighted findings before opening a PR")
	}
	if len(recs) == 0 && criticalCount == 0 && highCount == 0 && secretsFound == 0 {
		recs = append(recs, "No critical issues detected — proceed with normal review")
	}
	if len(recs) == 0 && mediumCount > 0 {
		recs = append(recs, fmt.Sprintf("Review %d medium-severity finding(s) during normal review", mediumCount))
	}

	return recs
}

func isSecretFinding(f analysis.Finding) bool {
	return f.Type == analysis.TypeSecret ||
		strings.Contains(strings.ToLower(f.Analyzer), "secret") ||
		strings.HasPrefix(strings.ToUpper(f.RuleID), "SECRET-")
}

// PackageGroup aggregates SCA findings for the same package version into a
// single, more readable report entry. The raw findings are still emitted in
// JSON/SARIF; grouping is applied only to terminal and markdown output.
type PackageGroup struct {
	PackageName            string
	PackageVersion         string
	FilePath               string
	Severity               analysis.Severity
	Reachability           analysis.ReachabilityStatus
	ReachabilityConfidence analysis.Confidence
	Advisories             []AdvisoryEntry
	ReachabilityEvidence   []string
}

// AdvisoryEntry captures the details of a single advisory within a package group.
type AdvisoryEntry struct {
	ID           string
	Title        string
	Severity     analysis.Severity
	FixedVersion string
	AdvisoryURL  string
	CVEID        string
	Aliases      []string
}

// GroupSCAFindings folds SCA findings by (package, version). Non-SCA findings
// and SCA findings with no package name are returned unchanged.
func GroupSCAFindings(findings []analysis.Finding) ([]analysis.Finding, []PackageGroup) {
	var nonGrouped []analysis.Finding
	groups := make(map[string]*PackageGroup)

	for _, f := range findings {
		if f.Type != analysis.TypeSCA || f.PackageName == "" {
			nonGrouped = append(nonGrouped, f)
			continue
		}

		key := f.PackageName + "@" + f.PackageVersion
		g, ok := groups[key]
		if !ok {
			g = &PackageGroup{
				PackageName:            f.PackageName,
				PackageVersion:         f.PackageVersion,
				FilePath:               f.FilePath,
				Reachability:           f.Reachability,
				ReachabilityConfidence: f.ReachabilityConfidence,
				ReachabilityEvidence:   f.ReachabilityEvidence,
			}
			groups[key] = g
		}

		adv := AdvisoryEntry{
			ID:           f.ID,
			Title:        f.Title,
			Severity:     f.Severity,
			FixedVersion: f.FixedVersion,
			AdvisoryURL:  f.AdvisoryURL,
			CVEID:        f.CVEID,
			Aliases:      aliasesFromEvidence(f.Evidence),
		}
		g.Advisories = append(g.Advisories, adv)
		if analysis.SeverityOrder(g.Severity) < analysis.SeverityOrder(f.Severity) {
			g.Severity = f.Severity
		}
	}

	// Convert map to slice and sort by severity, then by package name.
	var result []PackageGroup
	for _, g := range groups {
		result = append(result, *g)
	}
	sort.Slice(result, func(i, j int) bool {
		si := analysis.SeverityOrder(result[i].Severity)
		sj := analysis.SeverityOrder(result[j].Severity)
		if si != sj {
			return si > sj
		}
		ri := analysis.ReachabilityWeight(result[i].Reachability)
		rj := analysis.ReachabilityWeight(result[j].Reachability)
		if ri != rj {
			return ri > rj
		}
		return result[i].PackageName < result[j].PackageName
	})

	// Build representative findings for the grouped packages.
	var groupedFindings []analysis.Finding
	for _, g := range result {
		groupedFindings = append(groupedFindings, g.toFinding())
	}

	return append(groupedFindings, nonGrouped...), result
}

// toFinding converts a PackageGroup into a single analysis.Finding that
// represents all advisories in the group.
func (g PackageGroup) toFinding() analysis.Finding {
	advisoryLines := make([]string, 0, len(g.Advisories))
	for _, a := range g.Advisories {
		line := fmt.Sprintf("- %s", a.ID)
		if a.Title != "" && a.Title != a.ID {
			line = fmt.Sprintf("- %s — %s", a.ID, a.Title)
		}
		if a.Severity != "" {
			line += fmt.Sprintf(" (%s)", a.Severity)
		}
		if a.CVEID != "" {
			line += fmt.Sprintf(" [%s]", a.CVEID)
		}
		if a.AdvisoryURL != "" {
			line += fmt.Sprintf(" — <%s>", a.AdvisoryURL)
		}
		advisoryLines = append(advisoryLines, line)
	}

	fixedVersion := commonFixedVersion(g.Advisories)
	recommendation := buildGroupedRecommendation(g.PackageName, g.PackageVersion, len(g.Advisories), fixedVersion, g.Reachability)

	// For a single advisory, preserve the original title and details so the
	// report remains specific and existing tests/content keep working.
	if len(g.Advisories) == 1 {
		a := g.Advisories[0]
		return analysis.Finding{
			ID:                     a.ID,
			Type:                   analysis.TypeSCA,
			Analyzer:               "osv",
			Severity:               g.Severity,
			Confidence:             analysis.ConfidenceHigh,
			Title:                  a.Title,
			Description:            a.Title,
			FilePath:               g.FilePath,
			PackageName:            g.PackageName,
			PackageVersion:         g.PackageVersion,
			FixedVersion:           a.FixedVersion,
			CVEID:                  a.CVEID,
			AdvisoryURL:            a.AdvisoryURL,
			Reachability:           g.Reachability,
			ReachabilityConfidence: g.ReachabilityConfidence,
			ReachabilityEvidence:   g.ReachabilityEvidence,
			Recommendation:         recommendation,
			DetectedAt:             time.Now(),
		}
	}

	description := fmt.Sprintf("%d advisories affect %s@%s:\n\n%s", len(g.Advisories), g.PackageName, g.PackageVersion, strings.Join(advisoryLines, "\n"))

	return analysis.Finding{
		ID:                     fmt.Sprintf("sca-group-%s-%s", g.PackageName, g.PackageVersion),
		Type:                   analysis.TypeSCA,
		Analyzer:               "osv",
		Severity:               g.Severity,
		Confidence:             analysis.ConfidenceHigh,
		Title:                  fmt.Sprintf("%s@%s — %d advisories", g.PackageName, g.PackageVersion, len(g.Advisories)),
		Description:            description,
		FilePath:               g.FilePath,
		PackageName:            g.PackageName,
		PackageVersion:         g.PackageVersion,
		FixedVersion:           fixedVersion,
		Reachability:           g.Reachability,
		ReachabilityConfidence: g.ReachabilityConfidence,
		ReachabilityEvidence:   g.ReachabilityEvidence,
		Recommendation:         recommendation,
		DetectedAt:             time.Now(),
	}
}

// commonFixedVersion returns the fixed version if all advisories agree on one.
func commonFixedVersion(advisories []AdvisoryEntry) string {
	if len(advisories) == 0 {
		return ""
	}
	version := advisories[0].FixedVersion
	for _, a := range advisories[1:] {
		if a.FixedVersion != version {
			return ""
		}
	}
	return version
}

// buildGroupedRecommendation creates an actionable recommendation for a group.
func buildGroupedRecommendation(name, version string, count int, fixedVersion string, reachability analysis.ReachabilityStatus) string {
	if reachability == analysis.ReachabilityNone {
		if count == 1 {
			return fmt.Sprintf("%s@%s is not imported. Track the advisory but no immediate action is required.", name, version)
		}
		return fmt.Sprintf("%s@%s is not imported. Track %d advisories but no immediate action is required.", name, version, count)
	}

	if fixedVersion != "" {
		if count == 1 {
			return fmt.Sprintf("Upgrade %s to %s", name, fixedVersion)
		}
		return fmt.Sprintf("Upgrade %s to %s to address %d advisories", name, fixedVersion, count)
	}

	if count == 1 {
		return fmt.Sprintf("Review the advisory for %s@%s — no fixed version is available yet", name, version)
	}
	return fmt.Sprintf("Review %d advisories for %s@%s — no fixed version is available yet", count, name, version)
}

// aliasesFromEvidence extracts alias strings from the Evidence field when it
// contains an "Aliases: ..." suffix produced by the SCA analyzer.
func aliasesFromEvidence(evidence string) []string {
	idx := strings.Index(evidence, "Aliases: ")
	if idx == -1 {
		return nil
	}
	aliases := strings.TrimPrefix(evidence[idx:], "Aliases: ")
	aliases = strings.TrimSuffix(aliases, ")")
	return strings.Split(aliases, ", ")
}

// packageSummaryTable renders a markdown table summarizing vulnerable packages.
func packageSummaryTable(groups []PackageGroup) string {
	if len(groups) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("| Package | Version | Advisories | Reachability | Max Severity | Action |\n")
	sb.WriteString("|---------|---------|------------|--------------|--------------|--------|\n")
	for _, g := range groups {
		action := "Review"
		if g.Reachability == analysis.ReachabilityNone {
			action = "Track"
		} else if commonFixedVersion(g.Advisories) != "" {
			action = "Upgrade"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s | %s |\n",
			g.PackageName, g.PackageVersion, len(g.Advisories), g.Reachability, g.Severity, action))
	}
	sb.WriteString("\n")
	return sb.String()
}

// --- Markdown ---

// Markdown returns a full Markdown report.
func (g *Generator) Markdown() string {
	var sb strings.Builder

	sb.WriteString("# PatchFlow Analysis Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	// Summary
	sb.WriteString("## Summary\n\n")
	if g.Result != nil {
		sb.WriteString(fmt.Sprintf("| Field | Value |\n|-------|-------|\n"))
		sb.WriteString(fmt.Sprintf("| Repository | %s |\n", g.Result.ProjectRoot))
		sb.WriteString(fmt.Sprintf("| Branch | %s |\n", g.Result.Branch))
		sb.WriteString(fmt.Sprintf("| Commit | %s |\n", g.Result.CommitSHA))
		sb.WriteString(fmt.Sprintf("| Base | %s |\n", g.Result.BaseBranch))
		sb.WriteString(fmt.Sprintf("| Files changed | %d |\n", g.Result.FilesChanged))
		sb.WriteString(fmt.Sprintf("| Added lines | %d |\n", g.Result.AddedLines))
		sb.WriteString(fmt.Sprintf("| Deleted lines | %d |\n", g.Result.DeletedLines))
		sb.WriteString(fmt.Sprintf("| Dependencies | %d |\n", len(g.Result.Dependencies)))
		sb.WriteString(fmt.Sprintf("| Analyzers | %s |\n", strings.Join(g.Result.Analyzers, ", ")))
		// Scan metadata
		if g.Result.ScanID != "" {
			sb.WriteString(fmt.Sprintf("| Scan ID | %s |\n", g.Result.ScanID))
		}
		if g.Result.Version != "" {
			sb.WriteString(fmt.Sprintf("| CLI version | %s |\n", g.Result.Version))
		}
		if g.Result.Profile != "" {
			sb.WriteString(fmt.Sprintf("| Profile | %s |\n", g.Result.Profile))
		}
		if g.Result.Mode != "" {
			sb.WriteString(fmt.Sprintf("| Mode | %s |\n", g.Result.Mode))
		}
		if g.Result.Baseline != "" {
			sb.WriteString(fmt.Sprintf("| Baseline | %s |\n", g.Result.Baseline))
		}
		if g.Result.NewOnly {
			sb.WriteString("| New only | true |\n")
		}
		if g.Result.SinceRef != "" {
			sb.WriteString(fmt.Sprintf("| Since ref | %s |\n", g.Result.SinceRef))
		}
		if g.Result.Duration > 0 {
			sb.WriteString(fmt.Sprintf("| Duration | %s |\n", g.Result.Duration.Round(time.Millisecond)))
		}
		if g.Result.ExitCode != 0 {
			sb.WriteString(fmt.Sprintf("| Exit code | %d |\n", g.Result.ExitCode))
		}
		sb.WriteString("\n")
	}

	// Risk score
	if g.Risk != nil {
		sb.WriteString("## Risk Score\n\n")
		sb.WriteString(fmt.Sprintf("**Score: %d/100 (%s)**\n\n", g.Risk.Score, strings.ToUpper(g.Risk.Level)))
		sb.WriteString("| Component | Points |\n|-----------|--------|\n")
		sb.WriteString(fmt.Sprintf("| Vulnerabilities (SCA) | %d |\n", g.Risk.VulnerabilityPoints))
		sb.WriteString(fmt.Sprintf("| SAST findings | %d |\n", g.Risk.SASTPoints))
		sb.WriteString(fmt.Sprintf("| Secrets | %d |\n", g.Risk.SecretPoints))
		sb.WriteString(fmt.Sprintf("| Change size | %d |\n", g.Risk.ChangePoints))
		sb.WriteString(fmt.Sprintf("| Sensitivity | %d |\n", g.Risk.SensitivityPoints))
		sb.WriteString(fmt.Sprintf("| Reachability bonus | %d |\n", g.Risk.ReachabilityBonus))
		sb.WriteString("\n")

		// Severity breakdown
		if len(g.Risk.FindingsBySeverity) > 0 {
			sb.WriteString("### Findings by Severity\n\n")
			sb.WriteString("| Severity | Count |\n|----------|-------|\n")
			severities := []string{"critical", "high", "medium", "low", "info"}
			for _, sev := range severities {
				if count, ok := g.Risk.FindingsBySeverity[sev]; ok && count > 0 {
					sb.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
				}
			}
			sb.WriteString("\n")
		}

		// Vulnerability class summary (CWE → OWASP grouping)
		if g.Result != nil && len(g.Result.Findings) > 0 {
			if summary := VulnerabilityClassSummary(g.Result.Findings); summary != "" {
				sb.WriteString("### Vulnerability Classes\n\n")
				sb.WriteString("| OWASP | Category | Findings | Breakdown |\n|-------|----------|----------|-----------|\n")
				// Re-parse the summary for markdown table format
				for _, line := range strings.Split(strings.TrimSuffix(summary, "\n"), "\n") {
					// Parse "  A03: Injection — 12 finding(s) (3 high, 6 medium, 3 low)"
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					// Extract OWASP ID, name, count, breakdown
					parts := strings.SplitN(line, " — ", 2)
					if len(parts) != 2 {
						continue
					}
					owaspPart := strings.SplitN(parts[0], ": ", 2)
					if len(owaspPart) != 2 {
						continue
					}
					owaspID := owaspPart[0]
					owaspName := owaspPart[1]
					rest := parts[1]
					// Split "12 finding(s) (3 high, 6 medium, 3 low)"
					countAndBreak := strings.SplitN(rest, " (", 2)
					countStr := strings.TrimSuffix(countAndBreak[0], " finding(s)")
					breakdown := ""
					if len(countAndBreak) == 2 {
						breakdown = strings.TrimSuffix(countAndBreak[1], ")")
					}
					sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", owaspID, owaspName, countStr, breakdown))
				}
				sb.WriteString("\n")
			}
		}
	}

	if g.Result != nil && g.Result.LicenseSummary != nil {
		ls := g.Result.LicenseSummary
		sb.WriteString("## License Summary\n\n")
		sb.WriteString("| Field | Value |\n|-------|-------|\n")
		sb.WriteString(fmt.Sprintf("| Dependencies checked | %d |\n", ls.Total))
		sb.WriteString(fmt.Sprintf("| With license | %d |\n", ls.WithLicense))
		sb.WriteString(fmt.Sprintf("| Missing license | %d |\n", ls.NoLicense))
		if len(ls.ByRisk) > 0 {
			sb.WriteString("\n### Licenses by Risk\n\n")
			sb.WriteString("| Risk | Count |\n|------|-------|\n")
			for _, risk := range []string{"critical", "high", "medium", "low"} {
				if count := ls.ByRisk[risk]; count > 0 {
					sb.WriteString(fmt.Sprintf("| %s | %d |\n", risk, count))
				}
			}
			sb.WriteString("\n")
		}
		if len(ls.ByCategory) > 0 {
			sb.WriteString("### Licenses by Category\n\n")
			sb.WriteString("| Category | Count |\n|----------|-------|\n")
			for _, category := range []string{"proprietary", "unknown", "copyleft", "weak_copyleft", "permissive"} {
				if count := ls.ByCategory[category]; count > 0 {
					sb.WriteString(fmt.Sprintf("| %s | %d |\n", category, count))
				}
			}
			sb.WriteString("\n")
		}
	}

	// Package summary table (grouped SCA view)
	var groupedFindings []analysis.Finding
	var packageGroups []PackageGroup
	if g.Result != nil {
		groupedFindings, packageGroups = GroupSCAFindings(g.Result.Findings)
	}
	if len(packageGroups) > 0 {
		sb.WriteString("## Vulnerable Packages Summary\n\n")
		sb.WriteString(packageSummaryTable(packageGroups))
	}

	// Findings
	if g.Result != nil && len(g.Result.Findings) > 0 {
		sb.WriteString("## Findings\n\n")
		sortedFindings := SortFindings(groupedFindings)
		for i, f := range sortedFindings {
			sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
			sb.WriteString(fmt.Sprintf("- **Type:** %s\n", f.Type))
			sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
			sb.WriteString(fmt.Sprintf("- **Confidence:** %s\n", f.Confidence))
			sb.WriteString(fmt.Sprintf("- **Analyzer:** %s\n", f.Analyzer))
			if f.PackageName != "" {
				sb.WriteString(fmt.Sprintf("- **Package:** %s@%s\n", f.PackageName, f.PackageVersion))
			}
			if f.FixedVersion != "" {
				sb.WriteString(fmt.Sprintf("- **Fixed in:** %s\n", f.FixedVersion))
			}
			if f.CVEID != "" {
				sb.WriteString(fmt.Sprintf("- **CVE:** %s\n", f.CVEID))
			}
			if f.FilePath != "" {
				sb.WriteString(fmt.Sprintf("- **File:** %s:%d\n", f.FilePath, f.LineStart))
			}
			if f.RuleID != "" {
				sb.WriteString(fmt.Sprintf("- **Rule:** %s\n", f.RuleID))
			}
			if f.AdvisoryURL != "" {
				sb.WriteString(fmt.Sprintf("- **Advisory:** %s\n", f.AdvisoryURL))
			}
			if f.Reachability != "" {
				sb.WriteString(fmt.Sprintf("- **Reachability:** %s (confidence: %s)\n", f.Reachability, f.ReachabilityConfidence))
			}
			if len(f.ReachabilityEvidence) > 0 {
				sb.WriteString("- **Evidence:**\n")
				for _, e := range f.ReachabilityEvidence {
					sb.WriteString(fmt.Sprintf("  - %s\n", e))
				}
			}
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf("\n%s\n", truncateForMarkdown(f.Description, 500)))
			}
			// OWASP category mapping
			if f.CWEID != "" {
				if owaspLabel := cwe.OWASPCategoryLabel(f.CWEID); owaspLabel != "" {
					sb.WriteString(fmt.Sprintf("\n**OWASP:** %s\n", owaspLabel))
				}
			}
			// Fix snippet for known rules
			if f.RuleID != "" {
				if snippet := fixsnippet.ForRule(f.RuleID); snippet != nil {
					sb.WriteString("\n" + snippet.FormatMarkdown() + "\n")
				}
			}
			if f.Recommendation != "" {
				sb.WriteString(fmt.Sprintf("\n**Recommendation:** %s\n", f.Recommendation))
			}
			sb.WriteString("\n")
		}
	}

	// Engine timings
	if g.Result != nil && len(g.Result.EngineTimings) > 0 {
		sb.WriteString("## Engine Timings\n\n")
		sb.WriteString("| Engine | Duration | Findings |\n|--------|----------|----------|\n")
		for _, et := range g.Result.EngineTimings {
			sb.WriteString(fmt.Sprintf("| %s | %s | %d |\n", et.Engine, et.Duration.Round(time.Millisecond), et.Findings))
		}
		if g.Result.Duration > 0 {
			sb.WriteString(fmt.Sprintf("| **total** | %s | — |\n", g.Result.Duration.Round(time.Millisecond)))
		}
		sb.WriteString("\n")
	}

	// Dependencies
	if g.Result != nil && len(g.Result.Dependencies) > 0 {
		sb.WriteString("## Dependencies\n\n")
		sb.WriteString("| Package | Version | Ecosystem | Direct | Manifest |\n")
		sb.WriteString("|---------|---------|-----------|--------|----------|\n")
		for _, dep := range g.Result.Dependencies {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %v | %s |\n",
				dep.Name, dep.Version, dep.Ecosystem, dep.IsDirect, dep.ManifestPath))
		}
		sb.WriteString("\n")
	}

	// Recommendations
	if g.Risk != nil {
		recs := g.generateRecommendations()
		if len(recs) > 0 {
			sb.WriteString("## Recommendations\n\n")
			for i, rec := range recs {
				sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// --- JSON ---

// JSON returns a full JSON report.
func (g *Generator) JSON() ([]byte, error) {
	// scanMetadata is a compact, top-level summary of how the scan was run.
	// The full details remain in the analysis block; this block is for
	// quick CI consumption and log correlation.
	type scanMetadata struct {
		ScanID    string        `json:"scan_id,omitempty"`
		Version   string        `json:"version,omitempty"`
		Profile   string        `json:"profile,omitempty"`
		Mode      string        `json:"mode,omitempty"`
		Baseline  string        `json:"baseline,omitempty"`
		NewOnly   bool          `json:"new_only,omitempty"`
		SinceRef  string        `json:"since_ref,omitempty"`
		Duration  time.Duration `json:"duration,omitempty"`
		ExitCode  int           `json:"exit_code,omitempty"`
		StartedAt time.Time     `json:"started_at,omitempty"`
	}

	var meta scanMetadata
	if g.Result != nil {
		meta = scanMetadata{
			ScanID:    g.Result.ScanID,
			Version:   g.Result.Version,
			Profile:   g.Result.Profile,
			Mode:      g.Result.Mode,
			Baseline:  g.Result.Baseline,
			NewOnly:   g.Result.NewOnly,
			SinceRef:  g.Result.SinceRef,
			Duration:  g.Result.Duration,
			ExitCode:  g.Result.ExitCode,
			StartedAt: g.Result.StartedAt,
		}
	}

	report := struct {
		Generated       time.Time                `json:"generated"`
		Scan            scanMetadata             `json:"scan"`
		Analysis        *analysis.AnalysisResult `json:"analysis"`
		Risk            *risk.ScoreOutput        `json:"risk"`
		Recommendations []string                 `json:"recommendations"`
	}{
		Generated:       time.Now().UTC(),
		Scan:            meta,
		Analysis:        g.Result,
		Risk:            g.Risk,
		Recommendations: g.generateRecommendations(),
	}

	return json.MarshalIndent(report, "", "  ")
}

// --- SARIF 2.1.0 ---

// SARIFReport is a SARIF 2.1.0 report.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun is a single run in a SARIF report.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFInvocation describes a single invocation of the tool, carrying scan
// metadata as properties for CI traceability.
type SARIFInvocation struct {
	ExecutionSuccessful bool           `json:"executionSuccessful"`
	StartTimeUTC        string         `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string         `json:"endTimeUtc,omitempty"`
	Properties          *SARIFScanMeta `json:"properties,omitempty"`
}

// SARIFScanMeta is the scan metadata embedded in a SARIF invocation.
type SARIFScanMeta struct {
	ScanID   string `json:"scan_id,omitempty"`
	Version  string `json:"version,omitempty"`
	Profile  string `json:"profile,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Baseline string `json:"baseline,omitempty"`
	NewOnly  bool   `json:"new_only,omitempty"`
	SinceRef string `json:"since_ref,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
}

// SARIFTool describes the tool that produced the report.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver is the tool driver component.
type SARIFDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a single rule that can produce findings. Following the
// SARIF 2.1.0 spec, shortDescription and fullDescription are message objects
// with a "text" sub-field, and properties carries rule metadata such as tags.
type SARIFRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name,omitempty"`
	ShortDescription *SARIFMessage   `json:"shortDescription,omitempty"`
	FullDescription  *SARIFMessage   `json:"fullDescription,omitempty"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       *SARIFRuleProps `json:"properties,omitempty"`
}

// SARIFRuleProps carries rule-level properties (e.g. tags) as defined by the
// SARIF 2.1.0 spec. Tags are a string bag used by downstream viewers to group
// and filter rules.
type SARIFRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

// SARIFResult is a single finding in SARIF format.
type SARIFResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    SARIFMessage     `json:"message"`
	Locations  []SARIFLocation  `json:"locations,omitempty"`
	Properties *SARIFProperties `json:"properties,omitempty"`
}

// SARIFProperties carries finding fingerprints and scan metadata as SARIF
// result properties. This lets downstream tools (GitHub Code Scanning, Azure
// DevOps) deduplicate findings across runs using stable fingerprints.
type SARIFProperties struct {
	SemanticFingerprint string `json:"semantic_fingerprint,omitempty"`
	LocationFingerprint string `json:"location_fingerprint,omitempty"`
	DedupFingerprint    string `json:"dedup_fingerprint,omitempty"`
	IssueGroupID        string `json:"issue_group_id,omitempty"`
	OccurrenceCount     int    `json:"occurrence_count,omitempty"`
	Analyzer            string `json:"analyzer,omitempty"`
	Severity            string `json:"severity,omitempty"`
	Confidence          string `json:"confidence,omitempty"`
	CWEID               string `json:"cwe_id,omitempty"`
	PackageName         string `json:"package_name,omitempty"`
	PackageVersion      string `json:"package_version,omitempty"`
	FixedVersion        string `json:"fixed_version,omitempty"`
	Reachability        string `json:"reachability,omitempty"`
	Mode                string `json:"mode,omitempty"`
	Blocking            bool   `json:"blocking,omitempty"`
	ModeSource          string `json:"mode_source,omitempty"`
	Maturity            string `json:"maturity,omitempty"`
}

// SARIFMessage is a SARIF message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation is a SARIF location.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation is a SARIF physical location.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation is a SARIF artifact location.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion is a SARIF region (line range).
type SARIFRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

// SARIF returns a SARIF 2.1.0 report.
func (g *Generator) SARIF(toolVersion string) *SARIFReport {
	// SARIF requires runs[].results to be an array. Keep it non-nil so clean,
	// empty, and failed scans serialize as [] rather than JSON null.
	results := make([]SARIFResult, 0)

	if g.Result != nil {
		for _, f := range g.Result.Findings {
			result := SARIFResult{
				RuleID: f.RuleID,
				Level:  severityToSARIFLevel(f.Severity),
				Message: SARIFMessage{
					Text: f.Title,
				},
			}

			if f.FilePath != "" {
				loc := SARIFLocation{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: f.FilePath,
						},
					},
				}
				if f.LineStart > 0 {
					loc.PhysicalLocation.Region = &SARIFRegion{
						StartLine: f.LineStart,
						EndLine:   f.LineEnd,
					}
				}
				result.Locations = []SARIFLocation{loc}
			}

			if result.RuleID == "" {
				result.RuleID = string(f.Type) + "-" + f.Analyzer
			}

			// Attach stable fingerprints and finding metadata as properties
			// so downstream tools can deduplicate across runs.
			result.Properties = &SARIFProperties{
				SemanticFingerprint: f.SemanticFingerprint,
				LocationFingerprint: f.LocationFingerprint,
				DedupFingerprint:    f.DedupFingerprint,
				IssueGroupID:        f.IssueGroupID,
				OccurrenceCount:     f.OccurrenceCount,
				Analyzer:            f.Analyzer,
				Severity:            string(f.Severity),
				Confidence:          string(f.Confidence),
				CWEID:               f.CWEID,
				PackageName:         f.PackageName,
				PackageVersion:      f.PackageVersion,
				FixedVersion:        f.FixedVersion,
				Reachability:        string(f.Reachability),
				Mode:                f.Mode,
				Blocking:            f.Blocking,
				ModeSource:          f.ModeSource,
				Maturity:            f.Maturity,
			}

			results = append(results, result)
		}
	}

	// Build invocation with scan metadata for CI traceability.
	var invocations []SARIFInvocation
	if g.Result != nil {
		invocations = []SARIFInvocation{{
			// SARIF treats a completed scan with findings (exit 1) as a
			// successful tool execution. Exit codes 2+ represent execution
			// failures such as invalid configuration, internal errors, or timeouts.
			ExecutionSuccessful: g.Result.ExitCode == 0 || g.Result.ExitCode == 1,
			StartTimeUTC:        g.Result.StartedAt.UTC().Format(time.RFC3339),
			EndTimeUTC:          g.Result.CompletedAt.UTC().Format(time.RFC3339),
			Properties: &SARIFScanMeta{
				ScanID:   g.Result.ScanID,
				Version:  g.Result.Version,
				Profile:  g.Result.Profile,
				Mode:     g.Result.Mode,
				Baseline: g.Result.Baseline,
				NewOnly:  g.Result.NewOnly,
				SinceRef: g.Result.SinceRef,
				ExitCode: g.Result.ExitCode,
			},
		}}
	}

	return &SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    "PatchFlow CLI",
						Version: toolVersion,
						Rules:   g.buildSARIFRules(),
					},
				},
				Results:     results,
				Invocations: invocations,
			},
		},
	}
}

// buildSARIFRules produces a deduplicated, sorted list of SARIF rule
// descriptors from the generator's findings. Every unique rule ID that
// produced at least one finding gets an entry. Tags are derived from the
// finding type, CWE, and the OWASP Top 10 mapping.
func (g *Generator) buildSARIFRules() []SARIFRule {
	if g.Result == nil || len(g.Result.Findings) == 0 {
		return nil
	}

	// Collect the first finding seen for each rule ID so we can derive
	// metadata (title, description, CWE, type) consistently.
	byID := make(map[string]analysis.Finding)
	var order []string
	for _, f := range g.Result.Findings {
		rid := f.RuleID
		if rid == "" {
			rid = string(f.Type) + "-" + f.Analyzer
		}
		if _, ok := byID[rid]; !ok {
			byID[rid] = f
			order = append(order, rid)
		}
	}
	sort.Strings(order)

	rules := make([]SARIFRule, 0, len(order))
	for _, rid := range order {
		f := byID[rid]
		short := f.Description
		if short == "" {
			short = f.Title
		}
		rule := SARIFRule{
			ID:               rid,
			Name:             f.Title,
			ShortDescription: &SARIFMessage{Text: short},
			HelpURI:          "https://patchflow.dev/docs/rules/" + rid,
			Properties: &SARIFRuleProps{
				Tags: deriveSARIFRuleTags(f),
			},
		}
		if f.Description != "" && f.Description != f.Title {
			rule.FullDescription = &SARIFMessage{Text: f.Description}
		}
		rules = append(rules, rule)
	}
	return rules
}

// deriveSARIFRuleTags builds the tag bag for a rule from the finding that
// first triggered it. Tags always include "security" and the finding type.
// When a CWE is present, "cwe" and the CWE identifier are added, plus an
// OWASP Top 10 category derived from the CWE via cweToOWASP.
func deriveSARIFRuleTags(f analysis.Finding) []string {
	tags := []string{"security"}
	tags = append(tags, string(f.Type))
	if f.CWEID != "" {
		tags = append(tags, "cwe", f.CWEID)
		if owasp := cweToOWASP(f.CWEID); owasp != "" {
			tags = append(tags, "owasp", owasp)
		}
	}
	return tags
}

// cweToOWASP maps a CWE identifier to its OWASP Top 10 (2021) category.
// Returns "" when no mapping is known.
func cweToOWASP(cweID string) string {
	switch cweID {
	case "CWE-89", "CWE-77", "CWE-78", "CWE-90", "CWE-94":
		return "A03"
	case "CWE-79":
		return "A07"
	case "CWE-22", "CWE-601":
		return "A01"
	case "CWE-502":
		return "A08"
	case "CWE-918":
		return "A10"
	default:
		return ""
	}
}

// --- File output ---

// WriteFile writes a report to a file in the specified format.
func (g *Generator) WriteFile(format, outputPath string) error {
	switch format {
	case "markdown", "md":
		content := g.Markdown()
		if err := os.WriteFile(outputPath, []byte(content), 0600); err != nil {
			return fmt.Errorf("writing markdown report to %s: %w", outputPath, err)
		}
		return nil
	case "json":
		data, err := g.JSON()
		if err != nil {
			return fmt.Errorf("generating JSON report: %w", err)
		}
		if err := os.WriteFile(outputPath, data, 0600); err != nil {
			return fmt.Errorf("writing JSON report to %s: %w", outputPath, err)
		}
		return nil
	case "sarif":
		report := g.SARIF("0.1.0")
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling SARIF report: %w", err)
		}
		if err := os.WriteFile(outputPath, data, 0600); err != nil {
			return fmt.Errorf("writing SARIF report to %s: %w", outputPath, err)
		}
		return nil
	case "gitlab", "codequality":
		data, err := g.GitLabCodeQuality()
		if err != nil {
			return fmt.Errorf("generating GitLab Code Quality report: %w", err)
		}
		if err := os.WriteFile(outputPath, data, 0600); err != nil {
			return fmt.Errorf("writing GitLab report to %s: %w", outputPath, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported format: %s (supported: markdown, json, sarif, gitlab)", format)
	}
}

// GenerateRecommendationsPublic exposes the recommendations for command use.
func (g *Generator) GenerateRecommendationsPublic() []string {
	return g.generateRecommendations()
}

// --- Helpers ---

func severityToSARIFLevel(s analysis.Severity) string {
	switch s {
	case analysis.SeverityCritical, analysis.SeverityHigh:
		return "error"
	case analysis.SeverityMedium:
		return "warning"
	case analysis.SeverityLow, analysis.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// SortFindings sorts findings by severity and reachability, highest first.
// SortFindings sorts findings by severity (desc) → confidence (desc) → file path.
func SortFindings(findings []analysis.Finding) []analysis.Finding {
	sorted := make([]analysis.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		// 1. Severity (critical first)
		si := analysis.SeverityOrder(sorted[i].Severity)
		sj := analysis.SeverityOrder(sorted[j].Severity)
		if si != sj {
			return si > sj
		}
		// 2. Confidence (high first)
		ci := confidenceOrder(sorted[i].Confidence)
		cj := confidenceOrder(sorted[j].Confidence)
		if ci != cj {
			return ci > cj
		}
		// 3. Reachability
		ri := analysis.ReachabilityWeight(sorted[i].Reachability)
		rj := analysis.ReachabilityWeight(sorted[j].Reachability)
		if ri != rj {
			return ri > rj
		}
		// 4. File path (alphabetical)
		return sorted[i].FilePath < sorted[j].FilePath
	})
	return sorted
}

// confidenceOrder returns a comparable rank for confidence sorting.
func confidenceOrder(c analysis.Confidence) int {
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

// VulnClassGroup represents a group of findings mapped to the same OWASP category.
type VulnClassGroup struct {
	OWASPID    string
	OWASPName  string
	Count      int
	BySeverity map[string]int
}

// VulnerabilityClassSummary groups findings by CWE → OWASP category and returns
// a formatted summary like:
//
//	A03: Injection — 12 findings (3 high, 6 medium, 3 low)
//	A02: Cryptographic Failures — 4 findings (1 high, 3 medium)
func VulnerabilityClassSummary(findings []analysis.Finding) string {
	groups := map[string]*VulnClassGroup{}

	for _, f := range findings {
		cweID := f.CWEID
		if cweID == "" {
			continue
		}
		cat := cwe.OWASPForCWE(cweID)
		if cat.ID == "" {
			continue
		}
		g, ok := groups[cat.ID]
		if !ok {
			g = &VulnClassGroup{
				OWASPID:    cat.ID,
				OWASPName:  cat.Name,
				BySeverity: map[string]int{},
			}
			groups[cat.ID] = g
		}
		g.Count++
		g.BySeverity[string(f.Severity)]++
	}

	if len(groups) == 0 {
		return ""
	}

	// Sort by count (desc), then by OWASP ID
	var sorted []*VulnClassGroup
	for _, g := range groups {
		sorted = append(sorted, g)
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Count != sorted[j].Count {
			return sorted[i].Count > sorted[j].Count
		}
		return sorted[i].OWASPID < sorted[j].OWASPID
	})

	var sb strings.Builder
	for _, g := range sorted {
		var sevParts []string
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if c := g.BySeverity[sev]; c > 0 {
				sevParts = append(sevParts, fmt.Sprintf("%d %s", c, sev))
			}
		}
		sevStr := strings.Join(sevParts, ", ")
		sb.WriteString(fmt.Sprintf("  %s: %s — %d finding(s) (%s)\n", g.OWASPID, g.OWASPName, g.Count, sevStr))
	}
	return sb.String()
}

// confidenceIndicator returns a bracketed tag indicating the detection method:
// [TAINT] for taint analysis (highest confidence), [AST] for tree-sitter AST
// confirmation, [REGEX] for regex-based pattern matching, [SCA] for dependency
// scanning, [SECRET] for secret detection.
func confidenceIndicator(f analysis.Finding) string {
	switch {
	case f.Analyzer == "taint-patterns" || f.Analyzer == "taint-ssa":
		return "[TAINT]"
	case f.Analyzer == "treesitter-ast" || f.Analyzer == "gosast-embedded":
		return "[AST]"
	case f.Analyzer == "patterns-embedded":
		return "[REGEX]"
	case f.Type == analysis.TypeSCA:
		return "[SCA]"
	case f.Type == analysis.TypeSecret:
		return "[SECRET]"
	case f.Analyzer == "semgrep" || f.Analyzer == "gosec" || f.Analyzer == "bandit":
		return "[LINTER]"
	case f.Analyzer == "checkov":
		return "[IAC]"
	default:
		return ""
	}
}

func shortenSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func truncateForMarkdown(s string, maxLen int) string {
	// Strip HTML tags that might be in OSV details
	s = stripHTML(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func stripHTML(s string) string {
	var result strings.Builder
	inTag := false
	for _, c := range s {
		if c == '<' {
			inTag = true
			continue
		}
		if c == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// WriteToReportsDir writes a report to the .patchflow/reports/ directory.
func (g *Generator) WriteToReportsDir(root, format string) (string, error) {
	reportsDir := filepath.Join(root, ".patchflow", "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	ext := "json"
	switch format {
	case "markdown", "md":
		ext = "md"
	case "sarif":
		ext = "sarif"
	}

	filename := fmt.Sprintf("patchflow-report-%s.%s", timestamp, ext)
	outputPath := filepath.Join(reportsDir, filename)

	if err := g.WriteFile(format, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}
