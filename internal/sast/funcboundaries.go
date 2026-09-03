package sast

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// functionBoundary represents a function/method/class definition found
// in a source file. Line is the 1-based line number where the function
// starts. Name is the function or method name.
type functionBoundary struct {
	line int
	name string
}

// funcDefPatterns matches common function/method/class definition patterns
// across supported languages. The regex is anchored at the start of the
// trimmed line. Keywords use non-capturing groups so the first capture group
// is always the function/method/class name.
//
// Supported languages: Python, Ruby, Go, JavaScript/TypeScript, Java, C#, PHP.
// Each pattern is alternated with | so the regex engine tries them in order.
// Order matters: more specific patterns (e.g., `def self.`) must come before
// generic ones (e.g., `def`).
var funcDefPatterns = regexp.MustCompile(
	// Ruby: def self.method_name — MUST come before generic def to capture
	// the method name, not "self".
	`^def\s+(?:self\.)?(\w+)` +
		// Python/Ruby: def method_name, class ClassName.
		// Also handles `async def` (Python 3.5+).
		`|^(?:async\s+)?(?:def|class)\s+(\w+)` +
		// Java/C#/PHP class: public class Foo, internal class Bar, class Baz,
		// final class Foo, abstract class Bar, sealed class Foo
		`|^(?:public\s+|private\s+|protected\s+|internal\s+|final\s+|abstract\s+|sealed\s+|open\s+)?class\s+(\w+)` +
		// Go: func methodName, func (recv) methodName
		`|^func\s+(?:\([^)]*\)\s+)?(\w+)` +
		// JavaScript/TypeScript: function methodName, async function methodName
		`|^(?:async\s+)?function\s+(\w+)` +
		// JS/TS arrow functions: const methodName = (args) => {  or  const methodName = async (args) =>
		`|^(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|\w+)\s*=>` +
		// JS/TS class methods: methodName(args) {  or  async methodName(args) {
		// or  methodName(args): ReturnType {  (TypeScript)
		// Requires the opening brace on the same line to avoid matching
		// if-statements/for-loops. The optional `: ReturnType` between ) and {
		// handles TypeScript return type annotations.
		`|^(?:async\s+|static\s+|get\s+|set\s+|public\s+|private\s+|protected\s+)*(\w+)\s*\([^)]*\)\s*(?::\s*[^{]+)?\{` +
		// Java/C#: public/private/protected/internal static? ReturnType? methodName(
		// Handles `public void foo(`, `public foo(` (constructor), `public static void foo(`,
		// C# `internal void foo(`, `async Task foo(`, etc.
		`|^(?:public|private|protected|internal)\s+(?:(?:static|async|final|override|virtual|abstract|sealed|readonly)\s+)*(?:\w+(?:<[^>]*>|\[\])?\s+)?(\w+)\s*\(` +
		// Java/C# package-private or implicit-visibility methods:
		// void methodName(  or  static void methodName(  or  async Task methodName(
		// Requires a known return type before the method name to avoid matching
		// if/for/while/switch statements.
		`|^(?:static\s+|async\s+|final\s+)*(?:void|int|long|float|double|boolean|bool|char|byte|short|string|String|var|Task|Task<[^>]*>|CompletableFuture<[^>]*>|Mono<[^>]*>|Flux<[^>]*>|IEnumerable<[^>]*>|List<[^>]*>|Map<[^>]*>|HashMap<[^>]*>|Set<[^>]*>|Optional<[^>]*>|Stream<[^>]*>|\w+<[^>]*>)\s+(\w+)\s*\(` +
		// Java/C# package-private with custom class return type:
		// User findById(  or  ResponseEntity<String> handle(
		// Java/C# convention: class names start with uppercase. Control flow
		// keywords (if, for, while, switch) are all lowercase, so [A-Z] safely
		// distinguishes custom return types from control flow.
		`|^(?:static\s+|async\s+|final\s+)*[A-Z]\w*(?:<[^>]*>)?\s+(\w+)\s*\(` +
		// PHP: function methodName(  or  public function methodName(
		`|^(?:public\s+|private\s+|protected\s+|static\s+)*\s*function\s+(\w+)`,
)

// controlFlowKeywords are JS/Java/C# keywords that look like function calls
// (keyword followed by parens) but are NOT function definitions. These are
// filtered out after regex matching to avoid false positives.
var controlFlowKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true,
	"catch": true, "return": true, "throw": true, "new": true,
	"typeof": true, "instanceof": true, "delete": true, "void": true,
	"await": true, "yield": true, "super": true, "this": true,
	"else": true, "try": true, "finally": true, "do": true,
	"require": true, "import": true, "export": true,
}

// detectFunctionBoundaries reads a source file and returns a sorted list
// of function boundaries. Each boundary marks the start of a new function,
// method, or class definition. If the file cannot be read, returns nil.
func detectFunctionBoundaries(path string) []functionBoundary {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var boundaries []functionBoundary
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		m := funcDefPatterns.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// Extract the name from whichever capture group matched
		var name string
		for _, g := range m[1:] {
			if g != "" {
				name = g
				break
			}
		}
		if name == "" {
			continue
		}
		// Filter out control flow keywords that match the function-call-like
		// pattern (e.g., `if (...) {`, `for (...) {`) but are not functions.
		if controlFlowKeywords[name] {
			continue
		}
		boundaries = append(boundaries, functionBoundary{line: lineNum, name: name})
	}
	return boundaries
}

// findFunctionForLine returns the function boundary that contains the given
// line number. A finding at line L belongs to the function whose start line
// is the largest value <= L. Returns nil if no enclosing function is found.
func findFunctionForLine(boundaries []functionBoundary, line int) *functionBoundary {
	var result *functionBoundary
	for i := range boundaries {
		if boundaries[i].line <= line {
			result = &boundaries[i]
		} else {
			break
		}
	}
	return result
}

// resolveFilePath resolves a finding's file path relative to the scan root.
// Findings may have absolute or relative paths depending on the scanner.
func resolveFilePath(filePath, root string) string {
	if filepath.IsAbs(filePath) {
		return filePath
	}
	return filepath.Join(root, filePath)
}
