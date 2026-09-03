package sast

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	fwpatterns "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

// suppressTaintWithSafePatterns suppresses taint-mode findings whose
// containing function also contains a safe pattern match. This bridges
// the gap between pattern-mode safe patterns (which work in the matcher)
// and taint-mode rules (which bypass the matcher).
//
// The algorithm:
//  1. Group findings by file
//  2. For each file, read the source and detect function boundaries
//  3. For each taint finding, find its containing function
//  4. Check if any safe pattern regex matches within that function's line range
//  5. If yes, suppress the finding (drop it)
//
// Only findings with a rule ID in the safePatterns map are considered.
// Non-taint findings and findings without safe patterns are passed through.
//
// Interprocedural taint findings carry a "-IP" suffix on their rule ID
// (e.g., PF-FASTAPI-SQLI-002-IP) while the safePatterns map is keyed by
// the base rule ID (PF-FASTAPI-SQLI-002). We resolve the base ID before
// lookup so safe patterns apply to both base and -IP variants. This
// mirrors the -IP stripping in dedupBaseVsInterprocedural (B10).
func suppressTaintWithSafePatterns(findings []analysis.Finding, safePatterns map[string][]fwpatterns.SafePattern, root string) []analysis.Finding {
	if len(safePatterns) == 0 {
		return findings
	}

	// Group findings by file for efficient batch processing
	byFile := make(map[string][]int) // file → indices into findings
	for i, f := range findings {
		if f.RuleID == "" {
			continue
		}
		// Resolve the base rule ID (strip "-IP") so safe patterns registered
		// against the base rule also suppress interprocedural variants.
		baseID := stripIPSuffixFromRule(f.RuleID)
		if _, has := safePatterns[baseID]; !has {
			continue
		}
		// Only suppress taint-patterns and framework-taint findings
		if f.Analyzer != "taint-patterns" && f.Analyzer != "framework-taint" {
			continue
		}
		byFile[f.FilePath] = append(byFile[f.FilePath], i)
	}

	if len(byFile) == 0 {
		return findings
	}

	suppressed := make(map[int]bool) // indices to suppress

	for file, indices := range byFile {
		fullPath := file
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(root, file)
		}

		// Read source lines
		lines, err := readSourceLines(fullPath)
		if err != nil {
			continue
		}

		// Detect function boundaries
		boundaries := detectFunctionBoundaries(fullPath)
		if len(boundaries) == 0 {
			continue
		}

		for _, idx := range indices {
			f := findings[idx]
			// Find the function containing this finding
			fnBoundary := findFunctionForLine(boundaries, f.LineStart)
			if fnBoundary == nil {
				continue
			}

			// Determine the function's line range
			fnStart := fnBoundary.line
			fnEnd := len(lines)
			// Find the next function boundary after this one
			for _, b := range boundaries {
				if b.line > fnStart {
					fnEnd = b.line - 1
					break
				}
			}

			// Check if any safe pattern matches within the function's line range.
			// Use the base rule ID (strip "-IP") to match the safePatterns map keys.
			patterns := safePatterns[stripIPSuffixFromRule(f.RuleID)]
			for _, sp := range patterns {
				if sp.Regex == nil {
					continue
				}
				if safePatternMatchesInRange(sp.Regex, lines, fnStart, fnEnd) {
					suppressed[idx] = true
					break
				}
			}
		}
	}

	if len(suppressed) == 0 {
		return findings
	}

	result := make([]analysis.Finding, 0, len(findings)-len(suppressed))
	for i, f := range findings {
		if !suppressed[i] {
			result = append(result, f)
		}
	}
	return result
}

// readSourceLines reads a file and returns its lines as a slice.
func readSourceLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// safePatternMatchesInRange checks if a regex matches any line in the
// given 1-based line range [start, end] inclusive.
func safePatternMatchesInRange(re *regexp.Regexp, lines []string, start, end int) bool {
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	for i := start - 1; i < end && i < len(lines); i++ {
		if re.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// suppressTaintWithSafePatternsAndCWE extends suppressTaintWithSafePatterns with
// CWE+language-based suppression. This handles the case where generic taint
// rules (TP-RB001, TP-PY001) fire on code that a framework safe pattern should
// protect. For example, a Rails .where( safe pattern registered for
// PF-RAILS-SQLI-003 (CWE-89, ruby) should also suppress TP-RB001-IP findings
// on the same code, since both rules detect SQL injection in Ruby.
//
// The algorithm:
//  1. Run the existing rule-ID-based suppression (for PF-* findings)
//  2. For remaining findings, look up safe patterns by CWE+language
//  3. Apply the same function-boundary matching as the base suppression
func suppressTaintWithSafePatternsAndCWE(
	findings []analysis.Finding,
	safePatterns map[string][]fwpatterns.SafePattern,
	safePatternsByCWE map[string][]fwpatterns.SafePattern,
	root string,
) []analysis.Finding {
	// Phase 1: existing rule-ID-based suppression
	result := suppressTaintWithSafePatterns(findings, safePatterns, root)

	// Phase 2: CWE+language-based suppression for remaining findings
	if len(safePatternsByCWE) == 0 || len(result) == 0 {
		return result
	}

	// Group remaining taint findings by file
	byFile := make(map[string][]int)
	for i, f := range result {
		if f.CWEID == "" {
			continue
		}
		// Only suppress taint-patterns and framework-taint findings
		if f.Analyzer != "taint-patterns" && f.Analyzer != "framework-taint" {
			continue
		}
		lang := languageFromFilePath(f.FilePath)
		if lang == "" {
			continue
		}
		key := f.CWEID + ":" + lang
		if _, has := safePatternsByCWE[key]; !has {
			continue
		}
		byFile[f.FilePath] = append(byFile[f.FilePath], i)
	}

	if len(byFile) == 0 {
		return result
	}

	suppressed := make(map[int]bool)

	for file, indices := range byFile {
		fullPath := file
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(root, file)
		}

		lines, err := readSourceLines(fullPath)
		if err != nil {
			continue
		}

		boundaries := detectFunctionBoundaries(fullPath)
		if len(boundaries) == 0 {
			continue
		}

		for _, idx := range indices {
			f := result[idx]
			fnBoundary := findFunctionForLine(boundaries, f.LineStart)
			if fnBoundary == nil {
				continue
			}

			fnStart := fnBoundary.line
			fnEnd := len(lines)
			for _, b := range boundaries {
				if b.line > fnStart {
					fnEnd = b.line - 1
					break
				}
			}

			lang := languageFromFilePath(f.FilePath)
			key := f.CWEID + ":" + lang
			patterns := safePatternsByCWE[key]
			for _, sp := range patterns {
				if sp.Regex == nil {
					continue
				}
				if safePatternMatchesInRange(sp.Regex, lines, fnStart, fnEnd) {
					suppressed[idx] = true
					break
				}
			}
		}
	}

	if len(suppressed) == 0 {
		return result
	}

	final := make([]analysis.Finding, 0, len(result)-len(suppressed))
	for i, f := range result {
		if !suppressed[i] {
			final = append(final, f)
		}
	}
	return final
}

// languageFromFilePath infers the programming language from a file extension.
// Returns the language name used in framework rules (e.g., "ruby", "python",
// "java", "javascript", "typescript", "go", "php", "csharp").
func languageFromFilePath(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".py":
		return "python"
	case ".rb":
		return "ruby"
	case ".java":
		return "java"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".tsx":
		return "typescript"
	case ".jsx":
		return "javascript"
	case ".go":
		return "go"
	case ".php":
		return "php"
	case ".cs":
		return "csharp"
	default:
		return ""
	}
}
