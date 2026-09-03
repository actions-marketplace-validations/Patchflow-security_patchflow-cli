package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/container"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	scanImageFormat     string
	scanImageOutput     string
	scanImageTimeout    time.Duration
	scanImageSeverities string
	scanImagePlatform   string
	scanImageInput      string
	scanImageNoVulns    bool
)

var scanImageCmd = &cobra.Command{
	Use:   "image [IMAGE]",
	Short: "Scan a container image for vulnerabilities and misconfigurations",
	Long: `Scan a container image for OS package vulnerabilities, language dependency
vulnerabilities, secrets, hardening issues, and misconfigurations.

This command uses the embedded PatchFlow image scanner — no external tools
required. Images can be pulled from registries, loaded from the local Docker/Podman
daemon, or imported from tarballs/OCI layouts.

Supported formats: json, markdown.

Examples:
  patchflow scan image nginx:1.21
  patchflow scan image myapp:latest --format json --output report.json
  patchflow scan image alpine:3.18 --timeout 5m --severities CRITICAL,HIGH
  patchflow scan image --input ./image.tar --platform linux/amd64
  patchflow scan image docker-daemon:myapp:latest`,
	Args: cobra.ExactArgs(1),
	RunE: runScanImage,
}

func init() {
	scanImageCmd.Flags().StringVar(&scanImageFormat, "format", "", "Output format: json, markdown")
	scanImageCmd.Flags().StringVar(&scanImageOutput, "output", "", "Write report to file (stdout if omitted)")
	scanImageCmd.Flags().DurationVar(&scanImageTimeout, "timeout", 10*time.Minute, "Scan timeout")
	scanImageCmd.Flags().StringVar(&scanImageSeverities, "severities", "", "Comma-separated severities to include (CRITICAL,HIGH,MEDIUM,LOW,INFO)")
	scanImageCmd.Flags().StringVar(&scanImagePlatform, "platform", "", "Platform for multi-arch manifests (e.g. linux/amd64)")
	scanImageCmd.Flags().StringVar(&scanImageInput, "input", "", "Local tarball or OCI layout path")
	scanImageCmd.Flags().BoolVar(&scanImageNoVulns, "no-vulns", false, "Skip vulnerability matching (catalog only)")
	scanCmd.AddCommand(scanImageCmd)
}

func runScanImage(cmd *cobra.Command, args []string) error {
	formatter := FormatterFromContext(cmd.Context())
	imageName := args[0]

	scanner := container.NewImageScanner()
	scanner.Timeout = scanImageTimeout
	scanner.Platform = scanImagePlatform
	scanner.Input = scanImageInput
	scanner.WithVulns = !scanImageNoVulns

	if !output.IsJSON(formatter) {
		formatter.Print(fmt.Sprintf("Scanning container image: %s", imageName))
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), scanImageTimeout)
	defer cancel()

	result, err := scanner.ScanImage(ctx, imageName)
	if err != nil {
		return formatter.PrintError(fmt.Errorf("image scan failed: %w", err))
	}

	result.Findings = filterFindingsBySeverities(result.Findings, parseSeverities(scanImageSeverities))

	// Count by severity
	counts := map[analysis.Severity]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	if output.IsJSON(formatter) {
		return formatter.Print(map[string]interface{}{
			"image":    result.Target,
			"packages": result.Packages,
			"findings": result.Findings,
			"summary": map[string]int{
				"total":    len(result.Findings),
				"critical": counts[analysis.SeverityCritical],
				"high":     counts[analysis.SeverityHigh],
				"medium":   counts[analysis.SeverityMedium],
				"low":      counts[analysis.SeverityLow],
				"info":     counts[analysis.SeverityInfo],
			},
		})
	}

	// Terminal output
	formatter.Print("")
	formatter.Print(fmt.Sprintf("Image: %s", result.Target))
	if result.OS != nil {
		formatter.Print(fmt.Sprintf("OS: %s %s", result.OS.Name, result.OS.VersionID))
	}
	formatter.Print(fmt.Sprintf("Packages: %d", result.Packages))
	formatter.Print(fmt.Sprintf("Total findings: %d", len(result.Findings)))
	if counts[analysis.SeverityCritical] > 0 {
		formatter.Print(fmt.Sprintf("  Critical: %d", counts[analysis.SeverityCritical]))
	}
	if counts[analysis.SeverityHigh] > 0 {
		formatter.Print(fmt.Sprintf("  High:     %d", counts[analysis.SeverityHigh]))
	}
	if counts[analysis.SeverityMedium] > 0 {
		formatter.Print(fmt.Sprintf("  Medium:   %d", counts[analysis.SeverityMedium]))
	}
	if counts[analysis.SeverityLow] > 0 {
		formatter.Print(fmt.Sprintf("  Low:      %d", counts[analysis.SeverityLow]))
	}
	if counts[analysis.SeverityInfo] > 0 {
		formatter.Print(fmt.Sprintf("  Info:     %d", counts[analysis.SeverityInfo]))
	}

	// Show top findings
	if len(result.Findings) > 0 {
		formatter.Print("")
		formatter.Print("Findings:")
		shown := 0
		for _, f := range result.Findings {
			if shown >= 20 {
				formatter.Print(fmt.Sprintf("  ... and %d more", len(result.Findings)-20))
				break
			}
			formatter.Print(fmt.Sprintf("  [%s] %s", f.Severity, f.Title))
			if f.PackageName != "" && f.FixedVersion != "" {
				formatter.Print(fmt.Sprintf("       Fix: upgrade %s to %s", f.PackageName, f.FixedVersion))
			}
			shown++
		}
	}

	// Write to file if requested
	if scanImageOutput != "" {
		format := scanImageFormat
		if format == "" {
			format = "json"
		}
		var writeErr error
		switch strings.ToLower(format) {
		case "json":
			writeErr = writeImageReportJSON(scanImageOutput, result)
		case "markdown":
			writeErr = writeImageReportMarkdown(scanImageOutput, result)
		default:
			return formatter.PrintError(fmt.Errorf("unsupported output format %q: use json or markdown", format))
		}
		if writeErr != nil {
			return formatter.PrintError(fmt.Errorf("write report to %s: %w", scanImageOutput, writeErr))
		}
		formatter.Print(fmt.Sprintf("\nReport written to %s", scanImageOutput))
	}

	return nil
}

// parseSeverities splits a comma-separated severity list into a normalized set.
// An empty string means "include all severities".
func parseSeverities(input string) map[analysis.Severity]bool {
	set := map[analysis.Severity]bool{}
	if input == "" {
		return set
	}
	for _, s := range strings.Split(input, ",") {
		s = strings.TrimSpace(strings.ToUpper(s))
		if s == "" {
			continue
		}
		set[analysis.Severity(s)] = true
	}
	return set
}

// filterFindingsBySeverities returns only findings whose severity is in the set.
// An empty set means no filtering.
func filterFindingsBySeverities(findings []analysis.Finding, allowed map[analysis.Severity]bool) []analysis.Finding {
	if len(allowed) == 0 {
		return findings
	}
	out := make([]analysis.Finding, 0, len(findings))
	for _, f := range findings {
		if allowed[f.Severity] {
			out = append(out, f)
		}
	}
	return out
}

// writeImageReportJSON writes the image scan results as JSON to a file.
func writeImageReportJSON(path string, result *container.ScanResult) error {
	data, err := json.MarshalIndent(map[string]interface{}{
		"image":    result.Target,
		"packages": result.Packages,
		"findings": result.Findings,
		"summary": map[string]int{
			"total": len(result.Findings),
		},
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// writeImageReportMarkdown writes a human-readable Markdown report.
func writeImageReportMarkdown(path string, result *container.ScanResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Image Scan Report: %s\n\n", result.Target)
	fmt.Fprintf(&b, "Packages: %d\n\n", result.Packages)
	fmt.Fprintf(&b, "Total findings: %d\n\n", len(result.Findings))
	if len(result.Findings) == 0 {
		b.WriteString("No findings.\n")
	} else {
		b.WriteString("| Severity | Title | Package | Fixed Version |\n")
		b.WriteString("| --- | --- | --- | --- |\n")
		for _, f := range result.Findings {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				f.Severity, f.Title, f.PackageName, f.FixedVersion)
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
