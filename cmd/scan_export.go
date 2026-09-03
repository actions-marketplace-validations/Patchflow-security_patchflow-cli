package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/git"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/reachability"
	"github.com/Patchflow-security/patchflow-cli/internal/report"
	"github.com/Patchflow-security/patchflow-cli/internal/risk"
	"github.com/Patchflow-security/patchflow-cli/internal/sast"
	"github.com/Patchflow-security/patchflow-cli/internal/sbom"
	"github.com/Patchflow-security/patchflow-cli/internal/sca"
	"github.com/Patchflow-security/patchflow-cli/internal/scan"
	"github.com/spf13/cobra"
)

var scanExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export scan results with real vulnerability findings",
	Long: `Run a full security analysis and export results in SARIF or JSON format.
This performs SCA (OSV.dev), SAST (local tools), reachability analysis, and risk scoring,
then exports the findings in the specified format.`,
	RunE: runScanExport,
}

func init() {
	scanExportCmd.Flags().String("format", "json", "Export format (json, sarif, cyclonedx-json, spdx-json, vex-json, dep-tree, dep-dot)")
	scanExportCmd.Flags().String("output", "", "Output file path (stdout if omitted)")
	scanExportCmd.Flags().Bool("upload-github", false, "Upload SARIF to GitHub Code Scanning (requires --format sarif and GITHUB_TOKEN)")
	scanExportCmd.Flags().Bool("no-gitignore", false, "Do not respect .gitignore patterns (scan all files)")
	scanExportCmd.Flags().Bool("include-vex", false, "Include VEX statements in CycloneDX SBOM (vulnerability exploitability)")
}

func runScanExport(cmd *cobra.Command, _ []string) error {
	format, _ := cmd.Flags().GetString("format")
	outputPath, _ := cmd.Flags().GetString("output")
	uploadGitHub, _ := cmd.Flags().GetBool("upload-github")
	noGitignore, _ := cmd.Flags().GetBool("no-gitignore")
	includeVEX, _ := cmd.Flags().GetBool("include-vex")
	formatter := FormatterFromContext(cmd.Context())
	ctx := cmd.Context()

	// Validate format. "sbom" is accepted as an alias for "cyclonedx-json".
	if format == "sbom" {
		format = "cyclonedx-json"
	}
	// Normalize common aliases.
	switch format {
	case "cyclonedx", "cdx":
		format = "cyclonedx-json"
	case "spdx":
		format = "spdx-json"
	}
	switch format {
	case "json", "sarif", "cyclonedx-json", "spdx-json", "vex-json", "dep-tree", "dep-dot":
	default:
		return fmt.Errorf("unsupported format: %q (supported: json, sarif, cyclonedx-json (or sbom), spdx-json, vex-json, dep-tree, dep-dot)", format)
	}

	// --upload-github requires SARIF format.
	if uploadGitHub && format != "sarif" {
		return fmt.Errorf("--upload-github requires --format sarif")
	}

	// Detect project context. Export can run on unpacked source trees that are
	// not git repositories; diff stats are included only when available.
	repo, isGitRepo, err := git.DetectOrLocal()
	if err != nil {
		return formatter.PrintError(err)
	}
	if isGitRepo {
		_ = repo.DetectChangedFiles()
		_ = repo.DetectDiffStats()
	}

	started := time.Now()

	// Run SCA
	scaAnalyzer := sca.NewAnalyzer()
	scaAnalyzer.MaxDepth = 3
	scaResult, err := scaAnalyzer.Analyze(ctx, repo.Root)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("SCA analysis failed: %w", err))
	}

	var allFindings []analysis.Finding
	allFindings = append(allFindings, scaResult.Findings...)
	analyzersRun := []string{"osv"}

	// Run SAST
	sastRunner := sast.NewRunner()
	sastRunner.Quiet = output.IsJSON(formatter) || QuietFromContext(ctx)
	sastRunner.RespectGitignore = !noGitignore
	sastResult, err := sastRunner.Analyze(ctx, repo.Root)
	if err == nil {
		allFindings = append(allFindings, sastResult.Findings...)
		analyzersRun = append(analyzersRun, sastResult.ToolsRun...)
	}

	// Run reachability
	if len(scaResult.Findings) > 0 {
		reachAnalyzer := reachability.NewAnalyzer()
		reachResult, err := reachAnalyzer.Analyze(ctx, repo.Root, allFindings, scaResult.Dependencies)
		if err == nil {
			allFindings = reachResult.Findings
		}
	}

	// Risk scoring
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

	gen := report.NewGenerator(result, &riskScore)

	var data []byte
	switch format {
	case "sarif":
		sarifReport := gen.SARIF("0.1.2")
		data, err = json.MarshalIndent(sarifReport, "", "  ")
		if err != nil {
			return formatter.PrintError(err)
		}
	case "json":
		data, err = gen.JSON()
		if err != nil {
			return formatter.PrintError(err)
		}
	case "cyclonedx-json":
		sbomCfg := sbom.GenerateConfig{
			Format:       "cyclonedx-json",
			ToolVersion:  versionString(),
			IncludeVEX:   includeVEX,
		}
		data, err = sbom.GenerateCycloneDXJSON(result, sbomCfg)
		if err != nil {
			return formatter.PrintError(err)
		}
	case "spdx-json":
		sbomCfg := sbom.GenerateConfig{
			Format:      "spdx-json",
			ToolVersion: versionString(),
		}
		data, err = sbom.GenerateSPDXJSON(result, sbomCfg)
		if err != nil {
			return formatter.PrintError(err)
		}
	case "vex-json":
		sbomCfg := sbom.GenerateConfig{
			Format:      "vex-json",
			ToolVersion: versionString(),
			IncludeVEX:  true,
		}
		data, err = sbom.GenerateVEXJSON(result, sbomCfg)
		if err != nil {
			return formatter.PrintError(err)
		}
	case "dep-tree":
		graph := sbom.BuildDepGraph(result)
		data = []byte(graph.RenderTree())
	case "dep-dot":
		graph := sbom.BuildDepGraph(result)
		data = []byte(graph.RenderDOT())
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, data, 0600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		if !uploadGitHub {
			return formatter.PrintSuccess("Report written to " + outputPath)
		}
	}

	// Upload SARIF to GitHub Code Scanning when requested.
	if uploadGitHub {
		uploadCfg, err := scan.ResolveGitHubUploadConfig(repo)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("GitHub upload config: %w", err))
		}
		uploadResult, err := scan.UploadSARIF(uploadCfg, data)
		if err != nil {
			return formatter.PrintError(fmt.Errorf("failed to upload SARIF to GitHub: %w", err))
		}
		msg := fmt.Sprintf("SARIF uploaded to GitHub Code Scanning (id: %s)", uploadResult.ID)
		if uploadResult.URL != "" {
			msg += " - status: " + uploadResult.URL
		}
		if outputPath != "" {
			msg = "Report written to " + outputPath + "\n" + msg
		}
		return formatter.PrintSuccess(msg)
	}

	_, err = fmt.Fprintln(os.Stdout, string(data))
	return err
}
