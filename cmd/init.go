package cmd

import (
	"github.com/Patchflow-security/patchflow-cli/internal/frameworks"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/project"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize PatchFlow in the current repository",
	Long: `Create a .patchflow/ directory with configuration, rules.yaml, cache, baselines,
and reports subdirectories. Detects your framework and generates a starter
rules.yaml with the detected pack enabled and extension/custom-rule skeletons.
This sets up the project for local analysis with PatchFlow CLI.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())

		root, err := getRepoRoot()
		if err != nil {
			return formatter.PrintError(err)
		}

		result, err := project.Init(root)
		if err != nil {
			return formatter.PrintError(err)
		}

		if result.Created {
			if _, ok := formatter.(*output.JSONFormatter); ok {
				return formatter.Print(result)
			}
			_ = formatter.PrintSuccess("PatchFlow initialized.")
			_ = formatter.Print("  Config:  " + result.ConfigPath)
			if result.RulesPath != "" {
				_ = formatter.Print("  Rules:   " + result.RulesPath)
			}
			_ = formatter.Print("  Dir:     " + result.Dir)
			if len(result.DetectedFrameworks) > 0 {
				_ = formatter.Print("  Frameworks detected: " + joinStrings(result.DetectedFrameworks, ", "))
			}
			_ = formatter.Print("")
			_ = formatter.Print("Next steps:")
			_ = formatter.Print("  patchflow scan run        # scan the repository")
			_ = formatter.Print("  patchflow rules list      # list active rules")
			_ = formatter.Print("  patchflow pr-review       # review changes before opening a PR")
			return nil
		}

		if _, ok := formatter.(*output.JSONFormatter); ok {
			return formatter.Print(result)
		}
		_ = formatter.Print("PatchFlow already initialized at " + result.Dir)
		return nil
	},
}

func init() {
	// Wire the real framework detector into the project package to avoid an
	// import cycle (project → frameworks → sast). The cmd layer can import
	// frameworks safely.
	project.SetFrameworkDetector(func(root string) *project.FrameworkDetectionResult {
		detector := frameworks.NewDetector()
		result := detector.Detect(root)
		out := &project.FrameworkDetectionResult{}
		for _, fw := range result.Frameworks {
			out.Frameworks = append(out.Frameworks, project.FrameworkDetection{
				Name:       string(fw.Name),
				Language:   fw.Language,
				Confidence: fw.Confidence,
			})
		}
		return out
	})
	rootCmd.AddCommand(initCmd)
}

// joinStrings joins a slice of strings with sep.
func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}
