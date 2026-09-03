package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/api"
	"github.com/Patchflow-security/patchflow-cli/internal/fix"
	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/pathutil"
	"github.com/Patchflow-security/patchflow-cli/internal/pr"
	"github.com/Patchflow-security/patchflow-cli/internal/reachability"
	"github.com/Patchflow-security/patchflow-cli/internal/report"
	"github.com/Patchflow-security/patchflow-cli/internal/reviewers"
	"github.com/Patchflow-security/patchflow-cli/internal/risk"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	"github.com/Patchflow-security/patchflow-cli/internal/sca"
	"github.com/spf13/cobra"
)

var (
	prReviewBase      string
	prReviewHead      string
	prReviewFormat    string
	prReviewOutput    string
	prReviewNoSAST    bool
	prReviewNoSecrets bool
	prReviewNoReach   bool
	prReviewSuggestReviewers bool
	prReviewAnnotations      bool
	prReviewSuggestFixes     bool
	prReviewSubmit           bool
	prReviewProjectID        int
	prReviewRepository       string
	prReviewPRNumber         int
	prReviewPRTitle          string
	prReviewPRAuthor         string
	prReviewPRURL            string
)

var prReviewCmd = &cobra.Command{
	Use:   "pr-review",
	Short: "Simulate a PR risk review before opening a pull request",
	Long: `Analyze your current branch changes and compute a risk score, vulnerability
findings, reachability data, and recommendations — all locally, before you open a PR.

This is the PatchFlow "is this change safe?" command. It runs SCA (OSV.dev),
SAST (local tools), reachability analysis, and risk scoring, then produces a
terminal summary or a report file (markdown/json/sarif).

Use --suggest-reviewers to get CODEOWNERS and git blame based reviewer suggestions.
Use --annotations to generate inline code annotations for the PR diff.
Use --suggest-fixes to generate safe fix proposals for detected vulnerabilities.`,
	RunE: runPRReview,
}

func init() {
	prReviewCmd.Flags().StringVar(&prReviewBase, "base", "", "Base branch (auto-detected if omitted)")
	prReviewCmd.Flags().StringVar(&prReviewHead, "head", "", "Head branch (current branch if omitted)")
	prReviewCmd.Flags().StringVar(&prReviewFormat, "format", "", "Report format: markdown, json, sarif, pr-summary, annotations")
	prReviewCmd.Flags().StringVar(&prReviewOutput, "output", "", "Write report to file (stdout if omitted)")
	prReviewCmd.Flags().BoolVar(&prReviewNoSAST, "no-sast", false, "Skip SAST analysis")
	prReviewCmd.Flags().BoolVar(&prReviewNoSecrets, "no-secrets", false, "Skip secret detection")
	prReviewCmd.Flags().BoolVar(&prReviewNoReach, "no-reachability", false, "Skip reachability analysis")
	prReviewCmd.Flags().BoolVar(&prReviewSuggestReviewers, "suggest-reviewers", false, "Suggest reviewers based on CODEOWNERS and git blame")
	prReviewCmd.Flags().BoolVar(&prReviewAnnotations, "annotations", false, "Generate inline code annotations for the PR diff")
	prReviewCmd.Flags().BoolVar(&prReviewSuggestFixes, "suggest-fixes", false, "Generate safe fix proposals for detected vulnerabilities")
	prReviewCmd.Flags().BoolVar(&prReviewSubmit, "submit", false, "Submit PR review results to the PatchFlow backend (requires authentication)")
	prReviewCmd.Flags().IntVar(&prReviewProjectID, "project-id", 0, "Project ID for backend submission (required with --submit)")
	prReviewCmd.Flags().StringVar(&prReviewRepository, "repository", "", "Repository full name (owner/repo) for backend submission")
	prReviewCmd.Flags().IntVar(&prReviewPRNumber, "pr-number", 0, "PR number for backend submission")
	prReviewCmd.Flags().StringVar(&prReviewPRTitle, "pr-title", "", "PR title for backend submission")
	prReviewCmd.Flags().StringVar(&prReviewPRAuthor, "pr-author", "", "PR author for backend submission")
	prReviewCmd.Flags().StringVar(&prReviewPRURL, "pr-url", "", "PR URL for backend submission")

	rootCmd.AddCommand(prReviewCmd)
}

func runPRReview(cmd *cobra.Command, _ []string) error {
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	// Detect git repository and collect context
	repo, err := git.Detect()
	if err != nil {
		return formatter.PrintError(err)
	}
	if err := repo.DetectChangedFiles(); err != nil {
		return formatter.PrintError(fmt.Errorf("failed to detect changed files: %w", err))
	}
	if err := repo.DetectDiffStats(); err != nil {
		return formatter.PrintError(fmt.Errorf("failed to detect diff stats: %w", err))
	}

	if !output.IsJSON(formatter) {
		_ = formatter.Print("PatchFlow PR Risk Review")
		_ = formatter.Print("")
		_ = formatter.Print(fmt.Sprintf("  Branch: %s → %s", repo.BaseBranch, repo.CurrentBranch))
		_ = formatter.Print(fmt.Sprintf("  Commit: %s", shortenSHA(repo.CommitSHA)))
		_ = formatter.Print(fmt.Sprintf("  Files:  %d changed (+%d / -%d)", len(repo.ChangedFiles), repo.AddedLines, repo.DeletedLines))
		_ = formatter.Print("")
	}

	started := time.Now()

	// 1. SCA — full dependency baseline. PR review keeps SAST scoped to changed
	// files, but dependency risk should not disappear when manifests are not in
	// the diff.
	if !output.IsJSON(formatter) {
		_ = formatter.Print("Analyzing dependencies (SCA via OSV.dev)...")
	}
	scaAnalyzer := sca.NewAnalyzer()
	scaAnalyzer.MaxDepth = 3

	scaResult, err := scaAnalyzer.Analyze(ctx, repo.Root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("SCA analysis failed: %w", err))
	}

	var allFindings []analysis.Finding
	allFindings = append(allFindings, scaResult.Findings...)
	analyzersRun := []string{"osv"}

	// 2. SAST — only on changed files
	if !prReviewNoSAST || !prReviewNoSecrets {
		if !output.IsJSON(formatter) {
			_ = formatter.Print("Running SAST (local tools)...")
		}
		sastRunner := sast.NewRunner()
		sastRunner.ChangedOnly = true
		sastRunner.ChangedFiles = repo.ChangedFiles
		sastRunner.IncludeTests = false

		if prReviewNoSAST {
			sastRunner.NoEmbeddedGo = true
			sastRunner.NoEmbeddedPatterns = true
		}
		if prReviewNoSecrets {
			sastRunner.NoEmbeddedSecrets = true
		}

		if prReviewNoSAST && !prReviewNoSecrets {
			var filtered []sast.Tool
			for _, t := range sastRunner.Tools {
				if t.Name == "gitleaks" {
					filtered = append(filtered, t)
				}
			}
			sastRunner.Tools = filtered
		} else if !prReviewNoSAST && prReviewNoSecrets {
			var filtered []sast.Tool
			for _, t := range sastRunner.Tools {
				if t.Name != "gitleaks" {
					filtered = append(filtered, t)
				}
			}
			sastRunner.Tools = filtered
		} else if prReviewNoSAST && prReviewNoSecrets {
			sastRunner.Tools = nil
		}

		sastResult, err := sastRunner.Analyze(ctx, repo.Root)
		if err != nil {
			if !output.IsJSON(formatter) {
				_ = formatter.Print("  (SAST skipped: " + err.Error() + ")")
			}
		} else {
			allFindings = append(allFindings, sastResult.Findings...)
			analyzersRun = append(analyzersRun, sastResult.ToolsRun...)
		}
	}

	// 3. Reachability
	if !prReviewNoReach && len(scaResult.Findings) > 0 {
		if !output.IsJSON(formatter) {
			_ = formatter.Print("Analyzing reachability...")
		}
		reachAnalyzer := reachability.NewAnalyzer()
		reachResult, err := reachAnalyzer.Analyze(ctx, repo.Root, allFindings, scaResult.Dependencies)
		if err == nil {
			allFindings = reachResult.Findings
		}
	}

	// 4. Risk scoring
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

	// Build result
	manifestPaths := make([]string, 0, len(scaResult.Manifests))
	for _, m := range scaResult.Manifests {
		manifestPaths = append(manifestPaths, m.Path)
	}

	result := &analysis.AnalysisResult{
		ProjectRoot:  repo.Root,
		Branch:       repo.CurrentBranch,
		CommitSHA:    repo.CommitSHA,
		BaseBranch:   repo.BaseBranch,
		StartedAt:    started,
		CompletedAt:  completed,
		Findings:     allFindings,
		Dependencies: scaResult.Dependencies,
		RiskScore:    riskScore.Score,
		RiskLevel:    riskScore.Level,
		FilesChanged: len(repo.ChangedFiles),
		AddedLines:   repo.AddedLines,
		DeletedLines: repo.DeletedLines,
		Manifests:    manifestPaths,
		Analyzers:    analyzersRun,
	}

	// 5. Output
	gen := report.NewGenerator(result, &riskScore)

	// Handle PR-specific formats
	if prReviewFormat == "pr-summary" || prReviewFormat == "annotations" {
		// Get diff for finding placement
		diffOutput, err := pr.GetDiff(repo.Root, repo.BaseBranch)
		if err == nil {
			diffs := pr.ParseDiff(diffOutput)
			placements := pr.PlaceFindings(allFindings, diffs)

			if prReviewFormat == "pr-summary" {
				summary := pr.GeneratePRSummary(result, &riskScore, placements)
				if prReviewOutput != "" {
					if err := pathutil.ValidateOutputPath(repo.Root, prReviewOutput); err != nil {
						return formatter.PrintError(fmt.Errorf("invalid output path: %w", err))
					}
					md := pr.RenderMarkdown(summary)
					if err := os.WriteFile(prReviewOutput, []byte(md), 0600); err != nil {
						return formatter.PrintError(fmt.Errorf("failed to write PR summary: %w", err))
					}
					if !output.IsJSON(formatter) {
						_ = formatter.PrintSuccess("PR summary written to " + prReviewOutput)
					}
				} else {
					_ = formatter.Print(pr.RenderMarkdown(summary))
				}
				return nil
			}

			if prReviewFormat == "annotations" {
				annotations := pr.GenerateAnnotations(placements)
				if prReviewOutput != "" {
					if err := pathutil.ValidateOutputPath(repo.Root, prReviewOutput); err != nil {
						return formatter.PrintError(fmt.Errorf("invalid output path: %w", err))
					}
					data, err := json.MarshalIndent(annotations, "", "  ")
					if err != nil {
						return formatter.PrintError(err)
					}
					if err := os.WriteFile(prReviewOutput, data, 0600); err != nil {
						return formatter.PrintError(fmt.Errorf("failed to write annotations: %w", err))
					}
					if !output.IsJSON(formatter) {
						_ = formatter.PrintSuccess(fmt.Sprintf("%d annotations written to %s", len(annotations), prReviewOutput))
					}
				} else {
					return formatter.Print(annotations)
				}
				return nil
			}
		}
	}

	// Write report file if requested
	if prReviewFormat != "" || prReviewOutput != "" {
		fmtStr := prReviewFormat
		if fmtStr == "" {
			fmtStr = "markdown"
		}
		if prReviewOutput != "" {
			if err := pathutil.ValidateOutputPath(repo.Root, prReviewOutput); err != nil {
				return formatter.PrintError(fmt.Errorf("invalid output path: %w", err))
			}
			if err := gen.WriteFile(fmtStr, prReviewOutput); err != nil {
				return formatter.PrintError(fmt.Errorf("failed to write report: %w", err))
			}
			if !output.IsJSON(formatter) {
				_ = formatter.PrintSuccess("Report written to " + prReviewOutput)
			}
		}
	}

	// Also write to .patchflow/reports/ if initialized
	if _, err := getRepoRoot(); err == nil {
		if repoRoot, _ := getRepoRoot(); repoRoot != "" {
			if writtenPath, err := gen.WriteToReportsDir(repoRoot, "markdown"); err == nil {
				if !output.IsJSON(formatter) {
					_ = formatter.Print("  Report saved: " + writtenPath)
				}
			}
		}
	}

	if output.IsJSON(formatter) {
		// Submit to backend if --submit is set.
		if prReviewSubmit {
			if err := submitPRReviewToBackend(cmd, ctx, result); err != nil {
				if !output.IsJSON(formatter) {
					_ = formatter.PrintError(fmt.Errorf("backend submission failed: %w", err))
				}
			}
		}

		return formatter.Print(struct {
			*analysis.AnalysisResult `json:"analysis"`
			Risk                     *risk.ScoreOutput `json:"risk"`
		}{
			AnalysisResult: result,
			Risk:           &riskScore,
		})
	}

	// Submit to backend if --submit is set (non-JSON mode).
	if prReviewSubmit {
		if err := submitPRReviewToBackend(cmd, ctx, result); err != nil {
			_ = formatter.PrintError(fmt.Errorf("backend submission failed: %w", err))
		}
	}

	// Terminal output
	_ = formatter.Print("")
	riskLabel := strings.ToUpper(riskScore.Level)
	_ = formatter.Print(fmt.Sprintf("Risk Score: %d/100 — %s", riskScore.Score, riskLabel))
	_ = formatter.Print("")

	// Severity breakdown
	if len(riskScore.FindingsBySeverity) > 0 {
		_ = formatter.Print("Findings by severity:")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count, ok := riskScore.FindingsBySeverity[sev]; ok && count > 0 {
				_ = formatter.Print(fmt.Sprintf("  %-10s  %d", sev, count))
			}
		}
		_ = formatter.Print("")
	}

	// Top findings (group SCA advisories by package for cleaner terminal output)
	topFindings := riskScore.TopFindings
	if result != nil && len(result.Findings) > 0 {
		grouped, _ := report.GroupSCAFindings(result.Findings)
		sortedTop := report.SortFindings(grouped)
		if len(sortedTop) > 10 {
			sortedTop = sortedTop[:10]
		}
		topFindings = sortedTop
	}
	if len(topFindings) > 0 {
		_ = formatter.Print("Top findings:")
		for i, f := range topFindings {
			_ = formatter.Print(fmt.Sprintf("  %d. [%s] %s", i+1, strings.ToUpper(string(f.Severity)), f.Title))
			if f.PackageName != "" {
				_ = formatter.Print(fmt.Sprintf("     Package: %s@%s", f.PackageName, f.PackageVersion))
			}
			if f.FilePath != "" {
				_ = formatter.Print(fmt.Sprintf("     File:    %s:%d", f.FilePath, f.LineStart))
			}
			if f.Recommendation != "" {
				_ = formatter.Print(fmt.Sprintf("     Fix:     %s", f.Recommendation))
			}
			if f.Reachability != "" {
				_ = formatter.Print(fmt.Sprintf("     Reach:   %s", f.Reachability))
			}
		}
		_ = formatter.Print("")
	}

	// Recommendations
	recs := gen.GenerateRecommendationsPublic()
	if len(recs) > 0 {
		_ = formatter.Print("Recommended before PR:")
		for i, rec := range recs {
			_ = formatter.Print(fmt.Sprintf("  %d. %s", i+1, rec))
		}
		_ = formatter.Print("")
	}

	// Status
	status := "Ready for review"
	if riskScore.Score >= 80 {
		status = "BLOCKING — fix critical issues before opening a PR"
	} else if riskScore.Score >= 60 {
		status = "Warning — address high-severity findings before opening a PR"
	} else if riskScore.Score >= 40 {
		status = "Caution — review findings before opening a PR"
	}
	_ = formatter.Print("Status: " + status)

	// Inline annotations
	if prReviewAnnotations {
		diffOutput, err := pr.GetDiff(repo.Root, repo.BaseBranch)
		if err == nil {
			diffs := pr.ParseDiff(diffOutput)
			placements := pr.PlaceFindings(allFindings, diffs)
			annotations := pr.GenerateAnnotations(placements)
			_ = formatter.Print("")
			if len(annotations) > 0 {
				_ = formatter.Print(fmt.Sprintf("Inline Annotations (%d):", len(annotations)))
				for _, ann := range annotations {
					_ = formatter.Print(fmt.Sprintf("  [%s] %s:%d — %s",
						strings.ToUpper(ann.Severity), ann.Path, ann.Line, ann.Title))
				}
			} else {
				_ = formatter.Print("Inline Annotations: none (no findings in changed code)")
			}
		}
	}

	// Reviewer suggestions
	if prReviewSuggestReviewers {
		suggestResult, err := reviewers.Suggest(reviewers.SuggestOptions{
			RepoRoot:      repo.Root,
			ChangedFiles:  repo.ChangedFiles,
			MaxReviewers:  5,
			UseBlame:      true,
			UseCodeowners: true,
		})
		if err == nil {
			_ = formatter.Print("")
			if len(suggestResult.Reviewers) > 0 {
				_ = formatter.Print("Suggested Reviewers:")
				for i, rev := range suggestResult.Reviewers {
					ownerTag := ""
					if rev.IsOwner {
						ownerTag = " (CODEOWNER)"
					}
					_ = formatter.Print(fmt.Sprintf("  %d. @%s%s — %d pts", i+1, rev.Username, ownerTag, rev.Score))
					for _, reason := range rev.Reasons {
						_ = formatter.Print(fmt.Sprintf("       %s", reason))
					}
				}
				if !suggestResult.CodeownersFound {
					_ = formatter.Print("  (no CODEOWNERS file found — using git blame only)")
				}
			} else {
				_ = formatter.Print("Suggested Reviewers: none found")
			}
		}
	}

	// Fix suggestions
	if prReviewSuggestFixes {
		fixEngine := fix.NewEngine()
		proposals := fixEngine.Suggest(allFindings)
		_ = formatter.Print("")
		if len(proposals) > 0 {
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
			_ = formatter.Print("Fix Proposals: none available for current findings")
		}
	}

	return nil
}

// submitPRReviewToBackend posts the pr-review result JSON to the backend's
// POST /api/v1/cli/pr-review-results endpoint. Requires authentication
// (patchflow login), --project-id, --repository, and --pr-number.
func submitPRReviewToBackend(cmd *cobra.Command, ctx context.Context, result *analysis.AnalysisResult) error {
	if prReviewProjectID == 0 {
		return fmt.Errorf("--project-id is required when using --submit")
	}
	if prReviewRepository == "" {
		return fmt.Errorf("--repository is required when using --submit")
	}
	if prReviewPRNumber == 0 {
		return fmt.Errorf("--pr-number is required when using --submit")
	}

	token, err := requireAuthToken(cmd)
	if err != nil {
		return err
	}

	cfg := ConfigFromContext(ctx)
	if cfg == nil || cfg.APIURL == "" {
		return fmt.Errorf("no API URL configured. Set --api-url or run 'patchflow config set apiurl <url>'")
	}

	// Build the pr-review result payload (findings + annotations + summary).
	// The backend expects a CLIPRReviewResult-compatible JSON object.
	payload := struct {
		Base              string                   `json:"base"`
		Head              string                   `json:"head"`
		Findings          []analysis.Finding       `json:"findings"`
		Annotations       []map[string]interface{} `json:"annotations"`
		PRSummary         string                   `json:"pr_summary,omitempty"`
		SuggestedReviewers []string                `json:"suggested_reviewers,omitempty"`
		RiskScore         int                      `json:"risk_score"`
		RiskLevel         string                   `json:"risk_level"`
		FilesChanged      int                      `json:"files_changed"`
		Version           string                   `json:"version,omitempty"`
	}{
		Base:         result.BaseBranch,
		Head:         result.CommitSHA,
		Findings:     result.Findings,
		RiskScore:    result.RiskScore,
		RiskLevel:    result.RiskLevel,
		FilesChanged: result.FilesChanged,
		Version:      versionString(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal pr-review result: %w", err)
	}

	client := api.NewClient(cfg.APIURL, token)
	resp, err := client.PostPRReviewResults(ctx, body, api.PRReviewSubmitOpts{
		ProjectID:  prReviewProjectID,
		Repository: prReviewRepository,
		PRNumber:   prReviewPRNumber,
		PRTitle:    prReviewPRTitle,
		PRAuthor:   prReviewPRAuthor,
		PRURL:      prReviewPRURL,
	})
	if err != nil {
		return fmt.Errorf("backend rejected pr-review results: %w", err)
	}

	_ = resp // PRReviewID available if needed for logging
	return nil
}
