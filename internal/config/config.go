package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config holds PatchFlow CLI configuration.
type Config struct {
	APIURL   string `mapstructure:"apiurl"`
	Token    string `mapstructure:"token"`
	Org      string `mapstructure:"org"`
	LogLevel string `mapstructure:"loglevel"`
}

// GetConfigDir returns the PatchFlow configuration directory.
func GetConfigDir() string {
	// Honour HOME explicitly on every platform. os.UserHomeDir uses
	// USERPROFILE on Windows, which makes CLI invocations and tests that
	// intentionally override HOME read configuration from the wrong account.
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".patchflow")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".patchflow")
}

// Load reads configuration from the given path and environment.
func Load(path string) (*Config, error) {
	v := viper.New()

	v.SetConfigName("config")
	v.SetConfigType("yaml")

	// Add default config paths
	configDir := GetConfigDir()
	v.AddConfigPath(configDir)
	v.AddConfigPath(".")

	// If a specific path is provided, use it
	if path != "" {
		v.SetConfigFile(path)
	}

	// Environment variables
	v.SetEnvPrefix("PATCHFLOW")
	v.BindEnv("apiurl", "PATCHFLOW_API_URL")
	v.BindEnv("token", "PATCHFLOW_TOKEN")
	v.BindEnv("org", "PATCHFLOW_ORG")
	v.BindEnv("loglevel", "PATCHFLOW_LOG_LEVEL")

	// Defaults
	v.SetDefault("apiurl", "https://api.patchflow.dev")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Merge active profile values on top of base config.
	profiles, err := LoadProfiles()
	if err == nil && profiles.Active != "" {
		if prof, ok := profiles.Get(profiles.Active); ok {
			if prof.APIURL != "" {
				cfg.APIURL = prof.APIURL
			}
			if prof.Org != "" {
				cfg.Org = prof.Org
			}
			if prof.LogLevel != "" {
				cfg.LogLevel = prof.LogLevel
			}
		}
	}

	return &cfg, nil
}

// Save writes the configuration to the default config file.
// The token is intentionally NOT written to the config file for security.
func Save(cfg *Config) error {
	configDir := GetConfigDir()

	// Ensure directory exists
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	v := viper.New()
	v.Set("apiurl", cfg.APIURL)
	// Intentionally omit token so it is never persisted to config.yaml.
	v.Set("org", cfg.Org)
	v.Set("loglevel", cfg.LogLevel)

	configFile := filepath.Join(configDir, "config.yaml")
	if err := v.WriteConfigAs(configFile); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
