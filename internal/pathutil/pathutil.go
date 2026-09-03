// Package pathutil provides path validation utilities for user-provided
// file paths, preventing path traversal and other filesystem-based attacks.
package pathutil

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ValidateOutputPath validates that a user-provided output file path is safe.
// It checks for:
//   - Empty paths
//   - Path traversal (..) that escapes the current directory
//   - Symlinks that point outside the expected directory
//
// The path is resolved relative to baseDir. If the path is absolute, it must
// be within baseDir.
func ValidateOutputPath(baseDir, path string) error {
	if path == "" {
		return fmt.Errorf("output path is empty")
	}

	// Clean the path
	cleanPath := filepath.Clean(path)

	// Reject paths with .. components after cleaning
	if strings.HasPrefix(cleanPath, "..") {
		return fmt.Errorf("output path escapes project directory: %s", path)
	}

	// Resolve the absolute base directory (following symlinks)
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("failed to resolve base directory: %w", err)
	}
	// Evaluate symlinks in base dir for consistent comparison
	if resolvedBase, err := filepath.EvalSymlinks(absBase); err == nil {
		absBase = resolvedBase
	}

	// Resolve the full path (following symlinks) and check it's within base
	var fullPath string
	if filepath.IsAbs(path) {
		fullPath = filepath.Clean(path)
	} else {
		fullPath = filepath.Join(absBase, cleanPath)
	}

	// Evaluate symlinks in the path. If the file doesn't exist yet,
	// evaluate the parent directory.
	resolved, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		// File doesn't exist yet — try evaluating the parent directory
		parentDir := filepath.Dir(fullPath)
		resolvedParent, err2 := filepath.EvalSymlinks(parentDir)
		if err2 != nil {
			// Parent doesn't exist either — no symlink risk
			return nil
		}
		resolved = filepath.Join(resolvedParent, filepath.Base(fullPath))
	}

	if !strings.HasPrefix(resolved+string(filepath.Separator), absBase+string(filepath.Separator)) && resolved != absBase {
		return fmt.Errorf("output path resolves outside project directory: %s -> %s — write inside the project root (e.g., .patchflow/report.json) or use --no-gitignore to allow arbitrary paths", path, resolved)
	}

	return nil
}

// ValidateRulesPath validates that a user-provided rules file path is safe.
// Rules files must be within the project directory and have a .yaml or .yml extension.
func ValidateRulesPath(baseDir, path string) error {
	if path == "" {
		return fmt.Errorf("rules path is empty")
	}

	cleanPath := filepath.Clean(path)
	if strings.HasPrefix(cleanPath, "..") {
		return fmt.Errorf("rules path escapes project directory: %s", path)
	}

	// Check extension
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" {
		return fmt.Errorf("rules file must be .yaml or .yml, got: %s", path)
	}

	return ValidateOutputPath(baseDir, path)
}

// ValidateSuppressPath validates that a user-provided suppress file path is safe.
// Suppress files must be within the project directory.
func ValidateSuppressPath(baseDir, path string) error {
	if path == "" {
		return fmt.Errorf("suppress path is empty")
	}

	cleanPath := filepath.Clean(path)
	if strings.HasPrefix(cleanPath, "..") {
		return fmt.Errorf("suppress path escapes project directory: %s", path)
	}

	return ValidateOutputPath(baseDir, path)
}

// ResolveWithinBase resolves a path relative to baseDir and ensures the
// resolved path stays within baseDir. Returns the resolved absolute path.
func ResolveWithinBase(baseDir, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is empty")
	}

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base directory: %w", err)
	}

	var resolved string
	if filepath.IsAbs(path) {
		resolved = filepath.Clean(path)
	} else {
		resolved = filepath.Clean(filepath.Join(absBase, path))
	}

	if !strings.HasPrefix(resolved+string(filepath.Separator), absBase+string(filepath.Separator)) && resolved != absBase {
		return "", fmt.Errorf("path escapes project directory: %s", path)
	}

	return resolved, nil
}
