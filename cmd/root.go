package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/cacheutil"
	"github.com/Patchflow-security/patchflow-cli/internal/config"
	"github.com/Patchflow-security/patchflow-cli/internal/output"
	"github.com/Patchflow-security/patchflow-cli/internal/updatecheck"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type contextKey string

const (
	formatterKey contextKey = "formatter"
	configKey    contextKey = "config"
	loggerKey    contextKey = "logger"
	quietKey     contextKey = "quiet"
)

var rootCmd = &cobra.Command{
	Use:           "patchflow",
	Short:         "PatchFlow CLI - Change Intelligence for engineering teams",
	SilenceErrors: true,
	SilenceUsage:  true,
	Long: `PatchFlow CLI provides change intelligence for engineering teams.

Use this tool to scan, review, and analyze code changes in your repositories.`,
	PersistentPreRunE:  persistentPreRun,
	PersistentPostRunE: persistentPostRun,
}

func persistentPreRun(cmd *cobra.Command, _ []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	apiURL, _ := cmd.Flags().GetString("api-url")
	jsonMode, _ := cmd.Flags().GetBool("json")
	verbose, _ := cmd.Flags().GetBool("verbose")
	noColor, _ := cmd.Flags().GetBool("no-color")
	quiet, _ := cmd.Flags().GetBool("quiet")
	cacheDir, _ := cmd.Flags().GetString("cache-dir")

	// Wire the global cache directory override (from --cache-dir flag).
	// This is used by cacheutil.ResolveCacheDir across all cache operations.
	if cacheDir != "" {
		cacheutil.SetGlobalCacheDir(cacheDir)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if apiURL != "" {
		cfg.APIURL = apiURL
	}

	logger, err := initLogger(verbose)
	if err != nil {
		return err
	}

	formatter := output.NewFormatter(jsonMode, noColor)

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, formatterKey, formatter)
	ctx = context.WithValue(ctx, configKey, cfg)
	ctx = context.WithValue(ctx, loggerKey, logger)
	ctx = context.WithValue(ctx, quietKey, quiet)
	cmd.SetContext(ctx)

	return nil
}

// persistentPostRun runs after any subcommand. It checks for CLI updates
// and prints a non-intrusive notice to stderr if a newer version is available.
// The check is skipped when --json or --quiet is set (to avoid corrupting
// machine-readable output), and is designed to never fail or block.
func persistentPostRun(cmd *cobra.Command, _ []string) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	quiet, _ := cmd.Flags().GetBool("quiet")
	if jsonMode || quiet {
		return nil
	}

	// Skip for completion and version commands — no point checking.
	switch cmd.Name() {
	case "completion", "version":
		return nil
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	notice := updatecheck.Check(ctx)
	if notice != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", notice)
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().String("config", "", "config file path")
	rootCmd.PersistentFlags().String("api-url", "", "PatchFlow API URL")
	rootCmd.PersistentFlags().String("cache-dir", "", "Override cache directory (default: ~/.cache/patchflow/ or $XDG_CACHE_HOME/patchflow/)")
	rootCmd.PersistentFlags().Bool("json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose logging")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable colored output")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "suppress non-essential output (for CI scripting)")
}

// Execute runs the root command.
func Execute() error {
	err := rootCmd.Execute()
	if err == nil || output.IsErrorReported(err) {
		return err
	}

	// Cobra errors that happen before a formatter exists (argument parsing,
	// config loading, and unknown commands) still honor the global JSON
	// contract. Runtime errors already rendered through PrintError carry the
	// ReportedError marker and are not written twice.
	if jsonFlagRequested(os.Args[1:]) {
		_ = output.NewFormatter(true, true).PrintError(err)
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	return err
}

func jsonFlagRequested(args []string) bool {
	requested := false
	for _, arg := range args {
		if arg == "--json" {
			requested = true
			continue
		}
		if strings.HasPrefix(arg, "--json=") {
			enabled, err := strconv.ParseBool(strings.TrimPrefix(arg, "--json="))
			if err == nil {
				requested = enabled
			}
		}
	}
	return requested
}

// ExitCoder is an error that carries a specific exit code for CI integration.
// When a command returns an ExitCoder error, main.go uses ExitCode() instead
// of the default exit code.
type ExitCoder interface {
	error
	ExitCode() int
}

// ExitError is a concrete implementation of ExitCoder.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }
func (e *ExitError) ExitCode() int { return e.Code }

func initLogger(verbose bool) (*zap.Logger, error) {
	if verbose {
		return zap.NewDevelopment()
	}
	return zap.NewProduction()
}

// FormatterFromContext retrieves the output formatter from context.
func FormatterFromContext(ctx context.Context) output.Formatter {
	f, ok := ctx.Value(formatterKey).(output.Formatter)
	if !ok {
		return output.NewFormatter(false, false)
	}
	return f
}

// ConfigFromContext retrieves the config from context.
func ConfigFromContext(ctx context.Context) *config.Config {
	c, ok := ctx.Value(configKey).(*config.Config)
	if !ok {
		return &config.Config{}
	}
	return c
}

// LoggerFromContext retrieves the logger from context.
func LoggerFromContext(ctx context.Context) *zap.Logger {
	l, ok := ctx.Value(loggerKey).(*zap.Logger)
	if !ok {
		logger, _ := zap.NewProduction()
		return logger
	}
	return l
}

// QuietFromContext returns true if --quiet flag is set.
func QuietFromContext(ctx context.Context) bool {
	q, ok := ctx.Value(quietKey).(bool)
	return ok && q
}
