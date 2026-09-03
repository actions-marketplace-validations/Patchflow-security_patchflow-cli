package cmd

import (
	"fmt"

	"github.com/Patchflow-security/patchflow-cli/internal/doctor"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/pkg/version"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check the PatchFlow CLI environment",
	Long:  `Performs a series of checks to verify that the PatchFlow CLI environment is correctly configured.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		formatter := FormatterFromContext(cmd.Context())

		report, err := doctor.Run()
		if err != nil {
			return formatter.PrintError(err)
		}

		if _, ok := formatter.(*output.JSONFormatter); ok {
			return formatter.Print(report)
		}

		fmt.Println("PatchFlow Doctor")
		fmt.Println("================")
		fmt.Printf("[OK] Version: %s (commit: %s, go: %s)\n", report.Version, report.Commit, report.GoVersion)

		if report.GitVersion != "" {
			fmt.Printf("[OK] Git installed: %s\n", report.GitVersion)
		} else {
			fmt.Println("[X]  Git not installed")
		}

		if report.IsGitRepo {
			fmt.Printf("[OK] Inside a git repository: %s\n", report.RepoRoot)
		} else {
			fmt.Println("[X]  Not inside a git repository")
		}

		if report.RemoteURL != "" {
			fmt.Printf("[OK] Remote configured: %s\n", report.RemoteURL)
		} else if report.IsGitRepo {
			fmt.Println("[--] No remote origin configured (optional; local scans work without one)")
		}

		// Config checks (B12.8)
		fmt.Println("\nConfiguration:")
		if report.ConfigFound {
			if report.ConfigValid {
				fmt.Printf("[OK] Config found and valid: %s\n", report.ConfigPath)
			} else {
				fmt.Printf("[!]  Config found but invalid: %s (%s)\n", report.ConfigPath, report.ConfigError)
			}
		} else {
			fmt.Println("[--] No .patchflow/rules.yaml found (run 'patchflow rules init' to create one)")
		}

		// Cache checks (B12.8)
		fmt.Println("\nCache:")
		if report.CacheWritable {
			fmt.Printf("[OK] Cache directory writable: %s\n", report.CacheDir)
		} else {
			fmt.Printf("[X]  Cache directory not writable: %s\n", report.CacheDir)
		}

		// SARIF check (B12.8)
		fmt.Println("\nOutput:")
		if report.SARIFWritable {
			fmt.Println("[OK] SARIF output writable")
		} else {
			fmt.Printf("[X]  SARIF output not writable: %s\n", report.SARIFError)
		}

		// Config round-trip check (B11.5.4 regression guard)
		fmt.Println("\nConfig round-trip:")
		if report.ConfigRoundTripOK {
			fmt.Println("[OK] Unified --config loads via both rulesconfig + customrules")
		} else {
			fmt.Printf("[X]  Config round-trip failed: %s\n", report.ConfigRoundTripError)
		}

		// Embedded scanners
		fmt.Println("\nEmbedded SAST Scanners (always available, zero installation):")
		for _, s := range report.EmbeddedScanners {
			fmt.Printf("[OK] %-20s (%s) — %d rules\n", s.Name, s.Language, s.RuleCount)
		}

		// External tools
		fmt.Println("\nExternal SAST Tools (optional supplements):")
		for _, t := range report.ExternalTools {
			if t.Found {
				fmt.Printf("[OK] %-20s (%s) — installed\n", t.Name, t.Language)
			} else {
				fmt.Printf("[--] %-20s (%s) — not installed (optional)\n", t.Name, t.Language)
			}
		}

		if len(report.Errors) > 0 {
			fmt.Println("\nErrors:")
			for _, e := range report.Errors {
				fmt.Printf("  - %s\n", e)
			}
		}

		var printedNextSteps bool
		for _, check := range report.Checks {
			if check.Status == "pass" || check.Remediation == "" {
				continue
			}
			if !printedNextSteps {
				fmt.Println("\nNext steps:")
				printedNextSteps = true
			}
			fmt.Printf("  - %s: %s\n", check.Name, check.Remediation)
		}

		fmt.Printf("\nOverall status: %s\n", report.Status)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

// Ensure version package is used (for go vet)
var _ = version.Short
