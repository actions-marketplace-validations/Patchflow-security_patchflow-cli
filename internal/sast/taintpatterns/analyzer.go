// Package taintpatterns provides lightweight source-sink taint analysis for
// Python, JavaScript/TypeScript, Ruby, PHP, Java, and C# without requiring
// SSA form. It uses tree-sitter AST to identify taint sources (user input,
// request params, environment variables) and dangerous sinks (SQL queries,
// command execution, HTML output, file operations) within the same function
// scope.
//
// This catches injection vulnerabilities that simple regex pattern matching
// misses, such as:
//   - SQL injection: cursor.execute("SELECT * FROM users WHERE id=" + request.GET["id"])
//   - Command injection: os.system("ls " + input())
//   - XSS: res.send("<h1>" + req.query.name + "</h1>")
//   - Path traversal: open("/tmp/" + request.args.get("file"))
//
// The analysis is intra-procedural (within a single function) and tracks
// variable assignments from sources to sinks.
package taintpatterns

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/ignore"
)

// Rule represents a taint pattern rule (source-sink pair).
type Rule struct {
	ID          string
	Title       string
	Description string
	Severity    analysis.Severity
	Confidence  analysis.Confidence
	Language    string // "python", "javascript", "typescript", "ruby", "php", "java", "c_sharp"
	CWEID       string // associated CWE ID (e.g., "CWE-89" for SQL injection)
	Sources     []SourcePattern
	Sinks       []SinkPattern
	Sanitizers  []SanitizerPattern
}

// SourcePattern defines where tainted data comes from.
type SourcePattern struct {
	FuncName     string // e.g., "request.GET", "req.query", "input"
	IsSubscript  bool   // involves subscript access (e.g., request.GET["key"])
	Annotation   string // e.g., "@RequestParam", "@PathVariable" — for Java/C# annotation-based sources
}

// SinkPattern defines where tainted data should not flow.
type SinkPattern struct {
	FuncName string // e.g., "cursor.execute", "os.system", "res.send"
	ArgIndex int    // 0-based; -1 = any argument
}

// SanitizerPattern defines a function that clears taint when called on tainted data.
type SanitizerPattern struct {
	FuncName string // e.g., "htmlspecialchars", "encodeURIComponent", "quote"
}

// Analyzer performs lightweight taint analysis on Python, JS/TS, Ruby, PHP,
// Java, and C# files.
type Analyzer struct {
	rules         []Rule
	ignoreMatcher *ignore.Matcher
	mu            sync.Mutex
	taintDepth    int // max inter-procedural call hops (0 = disabled)
}

// NewAnalyzer creates a taint pattern analyzer with built-in rules.
func NewAnalyzer() *Analyzer {
	return &Analyzer{rules: builtInRules(), taintDepth: DefaultTaintDepth}
}

// SetTaintDepth configures the maximum inter-procedural call-hop depth.
// A depth of 0 disables inter-procedural analysis. The default is 3.
// This is wired to the --taint-depth CLI flag.
func (a *Analyzer) SetTaintDepth(depth int) {
	a.taintDepth = depth
}

// TaintDepth returns the configured inter-procedural depth.
func (a *Analyzer) TaintDepth() int {
	return a.taintDepth
}

// SetIgnoreMatcher sets the .gitignore matcher for filtering files.
func (a *Analyzer) SetIgnoreMatcher(m *ignore.Matcher) {
	a.ignoreMatcher = m
}

// Rules returns all registered taint pattern rules.
func (a *Analyzer) Rules() []Rule {
	return a.rules
}

// AddRules appends additional taint rules to the analyzer. This is used to
// register framework-pack taint rules (converted from frameworks.FrameworkRule)
// so the engine tracks framework-specific sources/sinks/sanitizers.
func (a *Analyzer) AddRules(rules []Rule) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = append(a.rules, rules...)
}

// Analyze scans all supported language files in the root directory.
func (a *Analyzer) Analyze(ctx context.Context, root string) ([]analysis.Finding, error) {
	var findings []analysis.Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if isIgnoredDir(filepath.Base(path)) {
				return filepath.SkipDir
			}
			if a.ignoreMatcher != nil && !a.ignoreMatcher.IsEmpty() {
				if a.ignoreMatcher.Match(path, true) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if a.ignoreMatcher != nil && !a.ignoreMatcher.IsEmpty() {
			if a.ignoreMatcher.Match(path, false) {
				return nil
			}
		}
		if info.Size() > 2*1024*1024 {
			return nil
		}

		entry := grammars.DetectLanguage(path)
		if entry == nil {
			return nil
		}
		lang := entry.Name
		// TypeScript and TSX share the same taint rules as JavaScript.
		// Normalize to "javascript" so TP-JS* rules apply to .ts/.tsx files.
		if lang == "typescript" || lang == "tsx" {
			lang = "javascript"
		}
		if !a.hasRulesForLanguage(lang) {
			return nil
		}

		fileFindings, err := a.scanFile(path, root, entry, lang)
		if err != nil {
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("taintpatterns: walk failed: %w", err)
	}
	return findings, nil
}

// ScanFilePublic scans a single file (for use by the parallel file collector).
func (a *Analyzer) ScanFilePublic(absPath, root string, entry *grammars.LangEntry) ([]analysis.Finding, error) {
	if entry == nil {
		return nil, nil
	}
	lang := entry.Name
	// TypeScript and TSX share the same taint rules as JavaScript.
	if lang == "typescript" || lang == "tsx" {
		lang = "javascript"
	}
	if !a.hasRulesForLanguage(lang) {
		return nil, nil
	}
	return a.scanFile(absPath, root, entry, lang)
}

func (a *Analyzer) hasRulesForLanguage(lang string) bool {
	for _, r := range a.rules {
		if r.Language == lang {
			return true
		}
	}
	return false
}

// HasRulesForLanguage is the exported version for use by the file collector
// to skip files whose language has no taint pattern rules.
func (a *Analyzer) HasRulesForLanguage(lang string) bool {
	return a.hasRulesForLanguage(lang)
}

func isIgnoredDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "dist", "build", "__pycache__",
		".next", ".nuxt", "target", ".gradle", ".idea", ".vscode",
		"bin", "obj", ".cache", ".pytest_cache", ".mypy_cache",
		".ruff_cache", "coverage", ".turbo", ".svelte-kit",
		"vendor/bundle", ".bundle", "Gemfile.lock",
		"composer.lock", "vendor/autoload.php", ".mvn", ".classpath",
		// Third-party library directories
		"lib", "libs", "wwwroot", "third_party", "thirdparty",
		"external", "deps", "bower_components", "jspm_packages",
		"webjars", "packages", "Content", "Scripts":
		return true
	}
	return false
}

// scanFile parses a file with tree-sitter and runs taint analysis.
func (a *Analyzer) scanFile(absPath, root string, entry *grammars.LangEntry, lang string) ([]analysis.Finding, error) {
	src, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	parser := gotreesitter.NewParser(entry.Language())
	if parser == nil {
		return nil, nil
	}
	tree, err := parser.Parse(src)
	if err != nil || tree == nil {
		return nil, nil
	}
	defer tree.Release()

	bt := gotreesitter.Bind(tree)
	rootNode := bt.RootNode()

	var findings []analysis.Finding
	// Pass 1: intra-procedural taint analysis (existing)
	a.analyzeNode(rootNode, bt, lang, absPath, root, src, &findings)

	// Pass 2: inter-procedural taint analysis (the differentiator vs semgrep)
	if a.taintDepth > 0 {
		ipAnalyzer := NewInterproceduralAnalyzer(a.rules, a.taintDepth)
		ipFindings := ipAnalyzer.Analyze(rootNode, bt, lang, absPath, root, src)
		findings = append(findings, ipFindings...)
	}

	return findings, nil
}

// analyzeNode recursively walks the AST looking for function definitions,
// then analyzes each function for source-sink flows.
func (a *Analyzer) analyzeNode(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang, absPath, root string, src []byte, findings *[]analysis.Finding) {
	if node == nil {
		return
	}

	nt := bt.NodeType(node)
	if isFunctionDef(nt, lang) {
		a.analyzeFunction(node, bt, lang, absPath, root, src, findings)
	}

	// PHP often has top-level code (not wrapped in functions). Treat the
	// root node as a function body for PHP to analyze top-level statements.
	if nt == "program" && lang == "php" {
		a.analyzeFunction(node, bt, lang, absPath, root, src, findings)
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		a.analyzeNode(node.Child(i), bt, lang, absPath, root, src, findings)
	}
}

func isFunctionDef(nodeType, lang string) bool {
	switch lang {
	case "python":
		return nodeType == "function_definition"
	case "javascript", "typescript":
		return nodeType == "function_declaration" || nodeType == "method_definition" ||
			nodeType == "arrow_function" || nodeType == "function_expression"
	case "ruby":
		return nodeType == "method" || nodeType == "singleton_method"
	case "php":
		return nodeType == "function_definition" || nodeType == "method_declaration"
	case "java":
		return nodeType == "method_declaration" || nodeType == "constructor_declaration"
	case "c_sharp":
		return nodeType == "method_declaration" || nodeType == "constructor_declaration"
	case "go":
		return nodeType == "function_declaration" || nodeType == "method_declaration" ||
			nodeType == "func_literal"
	}
	return false
}

// analyzeFunction performs intra-procedural taint analysis on a single function.
func (a *Analyzer) analyzeFunction(fnNode *gotreesitter.Node, bt *gotreesitter.BoundTree, lang, absPath, root string, src []byte, findings *[]analysis.Finding) {
	taintedVars := make(map[string]bool)

	// Pre-taint parameters that carry framework annotations (e.g., Spring
	// @RequestParam, @PathVariable, @RequestBody). This bridges the gap between
	// framework source models and the taint engine: annotation-based sources
	// are not assignment-based, so they need to be seeded before walking the
	// function body.
	a.seedAnnotatedParams(fnNode, bt, lang, src, taintedVars)

	// Pre-taint parameters for GraphQL resolver functions (Python). In GraphQL
	// resolvers, parameters after root/parent/info are user-controlled.
	a.seedGraphQLResolverParams(fnNode, bt, lang, src, taintedVars)

	a.walkFunctionBody(fnNode, bt, lang, absPath, root, src, taintedVars, findings)
}

// seedAnnotatedParams scans a method declaration's parameter list for framework
// annotations (e.g., @RequestParam, @PathVariable) and marks the corresponding
// parameter variables as tainted. This enables Spring/C# annotation-based
// source modeling in the taint engine.
func (a *Analyzer) seedAnnotatedParams(fnNode *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string, src []byte, taintedVars map[string]bool) {
	if lang != "java" && lang != "c_sharp" {
		return
	}

	// Collect all annotation-based source patterns for this language
	annotationSources := map[string]bool{}
	for _, rule := range a.rules {
		if rule.Language != lang {
			continue
		}
		for _, source := range rule.Sources {
			if source.Annotation != "" {
				annotationSources[source.Annotation] = true
			}
		}
	}
	if len(annotationSources) == 0 {
		return
	}

	// Find the parameter list in the method declaration
	// Java: method_declaration → formal_parameters → formal_parameter
	// C#: method_declaration → parameter_list → parameter
	paramsNode := findChildByType(fnNode, bt, "formal_parameters")
	if paramsNode == nil {
		paramsNode = findChildByType(fnNode, bt, "parameters")
	}
	if paramsNode == nil {
		paramsNode = findChildByType(fnNode, bt, "parameter_list")
	}
	if paramsNode == nil {
		return
	}

	for i := 0; i < int(paramsNode.ChildCount()); i++ {
		param := paramsNode.Child(i)
		if param == nil {
			continue
		}
		paramText := bt.NodeText(param)
		// Check if this parameter has any annotation we care about
		for ann := range annotationSources {
			if strings.Contains(paramText, ann) {
				// Extract the parameter variable name
				// The name is typically the last identifier in the parameter
				varName := extractParamName(param, bt)
				if varName != "" {
					taintedVars[varName] = true
				}
				break
			}
		}
	}
}

// seedGraphQLResolverParams detects Python GraphQL resolver functions and
// marks user-controlled parameters as tainted. In GraphQL resolvers, the
// first 1-2 parameters are typically root/parent/info (not user input), and
// subsequent parameters are user-controlled resolver arguments.
func (a *Analyzer) seedGraphQLResolverParams(fnNode *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string, src []byte, taintedVars map[string]bool) {
	if lang != "python" {
		return
	}

	// Get function name to check for resolver patterns
	nameNode := bt.ChildByField(fnNode, "name")
	if nameNode == nil {
		return
	}
	funcName := bt.NodeText(nameNode)

	// Check if this looks like a GraphQL resolver:
	// - Function name starts with "resolve_" (Graphene/Ariadne convention)
	//   AND has an "info" parameter (GraphQL convention)
	// - OR function name is "mutate" (GraphQL mutation convention)
	//   AND has an "info" parameter
	// Both conditions (name pattern + info param) must be true to avoid
	// false positives on functions that happen to start with "resolve_"
	// (e.g., Django ORM methods like resolve_expression_parameter).
	isResolver := strings.HasPrefix(funcName, "resolve_") || funcName == "mutate"

	// Get parameters
	paramsNode := bt.ChildByField(fnNode, "parameters")
	if paramsNode == nil {
		return
	}

	paramNames := []string{}
	for i := 0; i < int(paramsNode.ChildCount()); i++ {
		param := paramsNode.Child(i)
		if param == nil {
			continue
		}
		pt := bt.NodeType(param)
		if pt == "identifier" {
			paramNames = append(paramNames, bt.NodeText(param))
		}
		// Python parameters with default values are wrapped in
		// "default_parameter" nodes (e.g., "filter=None"). The actual
		// parameter name is the first "identifier" child.
		if pt == "default_parameter" || pt == "typed_parameter" {
			nameNode := bt.ChildByField(param, "name")
			if nameNode != nil {
				paramNames = append(paramNames, bt.NodeText(nameNode))
			} else {
				// Fall back to first identifier child
				for j := 0; j < int(param.ChildCount()); j++ {
					child := param.Child(j)
					if child != nil && bt.NodeType(child) == "identifier" {
						paramNames = append(paramNames, bt.NodeText(child))
						break
					}
				}
			}
		}
		// *args and **kwargs
		if pt == "list_splat_pattern" || pt == "dictionary_splat_pattern" {
			for j := 0; j < int(param.ChildCount()); j++ {
				child := param.Child(j)
				if child != nil && bt.NodeType(child) == "identifier" {
					paramNames = append(paramNames, bt.NodeText(child))
					break
				}
			}
		}
	}

	// Check for "info" parameter (GraphQL convention)
	hasInfoParam := false
	for _, p := range paramNames {
		if p == "info" {
			hasInfoParam = true
			break
		}
	}

	// Require BOTH conditions to reduce false positives.
	// "resolve_" alone matches Django ORM methods like resolve_expression_parameter.
	// "info" alone is too generic.
	if !(isResolver && hasInfoParam) {
		return
	}

	// In GraphQL resolvers, the first 1-2 params are root/parent and info.
	// Parameters after those are user-controlled resolver arguments.
	// Common patterns:
	//   def resolve_user(parent, info, id):  → id is tainted
	//   def resolve_search(root, info, query): → query is tainted
	//   def resolve_item(info, id): → id is tainted (only info as non-user)
	skipParams := 0
	if len(paramNames) >= 2 {
		// Typical: root/parent/self, info, then user args
		first := paramNames[0]
		if first == "root" || first == "parent" || first == "_" ||
			first == "obj" || first == "self" || first == "cls" {
			skipParams = 2 // skip root/self + info
		} else if first == "info" {
			skipParams = 1 // skip just info
		}
	} else if len(paramNames) >= 1 && paramNames[0] == "info" {
		skipParams = 1
	}

	// Mark all parameters after the skip count as tainted
	for i := skipParams; i < len(paramNames); i++ {
		taintedVars[paramNames[i]] = true
	}
}

// findChildByType finds the first direct child of a node with the given type.
func findChildByType(node *gotreesitter.Node, bt *gotreesitter.BoundTree, nodeType string) *gotreesitter.Node {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && bt.NodeType(child) == nodeType {
			return child
		}
	}
	return nil
}

// extractParamName extracts the variable name from a parameter declaration.
// For Java: formal_parameter → type + name (e.g., "String name" → "name")
// For C#: parameter → type + name
func extractParamName(param *gotreesitter.Node, bt *gotreesitter.BoundTree) string {
	// Try the "name" field first (works for some grammars)
	nameNode := bt.ChildByField(param, "name")
	if nameNode != nil {
		return bt.NodeText(nameNode)
	}

	// Fall back to finding the last identifier child
	var lastName string
	for i := 0; i < int(param.ChildCount()); i++ {
		child := param.Child(i)
		if child == nil {
			continue
		}
		if bt.NodeType(child) == "identifier" {
			lastName = bt.NodeText(child)
		}
	}
	return lastName
}

// walkFunctionBody walks the function body collecting taint assignments and
// checking sink calls.
func (a *Analyzer) walkFunctionBody(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang, absPath, root string, src []byte, taintedVars map[string]bool, findings *[]analysis.Finding) {
	if node == nil {
		return
	}

	nt := bt.NodeType(node)

	// Check for assignments: var = <taint_source>
	// Python: assignment, JS/TS: lexical_declaration (const/let), variable_declaration (var), assignment_expression
	// Ruby: assignment, operator_assignment
	// PHP: assignment_expression, simple_assignment
	// Java: local_variable_declaration (wraps variable_declarator)
	// C#: local_declaration_statement (wraps variable_declaration → variable_declarator)
	// Go: short_var_declaration (:=), var_declaration (var x = ...), assignment_statement (=)
	if nt == "assignment" || nt == "assignment_expression" || nt == "variable_declarator" ||
		nt == "lexical_declaration" || nt == "variable_declaration" ||
		nt == "operator_assignment" || nt == "simple_assignment" ||
		nt == "local_variable_declaration" || nt == "local_declaration_statement" ||
		nt == "short_var_declaration" || nt == "var_declaration" || nt == "assignment_statement" {
		a.checkAssignment(node, bt, lang, src, taintedVars)
	}

	// Check for sink calls: sink(tainted_var)
	// Python: "call", JS/TS: "call_expression", Ruby: "call",
	// PHP: "function_call_expression", "member_call_expression", "scoped_call_expression"
	// Java: "method_invocation", C#: "invocation_expression"
	// Java/C#: "object_creation_expression" (new keyword constructor calls)
	// Go: "call_expression" (same as JS/TS)
	if nt == "call" || nt == "call_expression" ||
		nt == "function_call_expression" || nt == "method_invocation" ||
		nt == "invocation_expression" || nt == "object_creation_expression" ||
		nt == "member_call_expression" || nt == "scoped_call_expression" {
		a.checkSinkCall(node, bt, lang, absPath, root, src, taintedVars, findings)
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		// Closure capture: when we encounter a func_literal (Go) or
		// arrow_function (JS/TS) inside a function body, analyze it with
		// a COPY of the current taintedVars so captured variables are
		// tainted in the closure's scope.
		ct := bt.NodeType(child)
		if isFunctionDef(ct, lang) {
			closureVars := make(map[string]bool)
			for k, v := range taintedVars {
				closureVars[k] = v
			}
			a.seedAnnotatedParams(child, bt, lang, src, closureVars)
			a.walkFunctionBody(child, bt, lang, absPath, root, src, closureVars, findings)
			continue
		}
		a.walkFunctionBody(child, bt, lang, absPath, root, src, taintedVars, findings)
	}
}

// checkAssignment checks if an assignment sources from a taint source.
func (a *Analyzer) checkAssignment(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string, src []byte, taintedVars map[string]bool) {
	nt := bt.NodeType(node)

	// lexical_declaration / variable_declaration / local_variable_declaration
	// wrap variable_declarator children.
	// C# local_declaration_statement wraps variable_declaration which wraps
	// variable_declarator — handle the extra nesting level.
	if nt == "lexical_declaration" || nt == "variable_declaration" || nt == "local_variable_declaration" ||
		nt == "local_declaration_statement" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			childType := bt.NodeType(child)
			if childType == "variable_declarator" {
				a.checkAssignment(child, bt, lang, src, taintedVars)
			}
			// C# extra nesting: local_declaration_statement → variable_declaration → variable_declarator
			if childType == "variable_declaration" {
				a.checkAssignment(child, bt, lang, src, taintedVars)
			}
		}
		return
	}

	var lhsNode, rhsNode *gotreesitter.Node
	if nt == "assignment" || nt == "operator_assignment" || nt == "simple_assignment" {
		lhsNode = bt.ChildByField(node, "left")
		rhsNode = bt.ChildByField(node, "right")
	} else if nt == "variable_declarator" {
		lhsNode = bt.ChildByField(node, "name")
		rhsNode = bt.ChildByField(node, "value")
		// C# tree-sitter grammar doesn't expose "value" as a field on
		// variable_declarator. Fall back to the last non-punctuation child.
		if rhsNode == nil {
			for i := int(node.ChildCount()) - 1; i >= 0; i-- {
				child := node.Child(i)
				if child == nil || isPunctuation(bt.NodeType(child)) {
					continue
				}
				// Skip the LHS (name) itself
				if child == lhsNode {
					break
				}
				rhsNode = child
				break
			}
		}
	} else if nt == "assignment_expression" {
		lhsNode = bt.ChildByField(node, "left")
		rhsNode = bt.ChildByField(node, "right")
		// PHP/C# may not expose "right" as a field. Fall back to last child.
		if rhsNode == nil {
			for i := int(node.ChildCount()) - 1; i >= 0; i-- {
				child := node.Child(i)
				if child == nil || isPunctuation(bt.NodeType(child)) {
					continue
				}
				if child == lhsNode {
					break
				}
				rhsNode = child
				break
			}
		}
	} else if nt == "short_var_declaration" || nt == "assignment_statement" {
		// Go: short_var_declaration (q := expr) and assignment_statement (q = expr)
		// Both have two expression_list children: LHS and RHS, separated by := or =
		var exprLists []*gotreesitter.Node
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			if bt.NodeType(child) == "expression_list" {
				exprLists = append(exprLists, child)
			}
		}
		if len(exprLists) >= 2 {
			lhsNode = exprLists[0]
			rhsNode = exprLists[1]
		}
	} else if nt == "var_declaration" {
		// Go: var q string = expr
		// Has identifier (name), optional type, and expression_list (value)
		var exprList *gotreesitter.Node
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			ct := bt.NodeType(child)
			if ct == "identifier" && lhsNode == nil {
				lhsNode = child
			}
			if ct == "expression_list" {
				exprList = child
			}
		}
		rhsNode = exprList
	}

	if lhsNode == nil || rhsNode == nil {
		return
	}

	varName := bt.NodeText(lhsNode)
	if varName == "" {
		return
	}
	// Go expression_list may contain multiple identifiers (e.g., "q, err").
	// Extract just the first identifier for taint tracking.
	if nt == "short_var_declaration" || nt == "assignment_statement" || nt == "var_declaration" {
		if first := firstIdentifier(lhsNode, bt); first != "" {
			varName = first
		}
	}

	// Check if the RHS is a call to a sanitizer — if so, clear taint.
	rhsFuncName := extractCallName(rhsNode, bt, lang)
	if rhsFuncName != "" && a.isSanitizer(rhsFuncName, lang) {
		taintedVars[varName] = false
		return
	}

	for _, rule := range a.rules {
		if rule.Language != lang {
			continue
		}
		for _, source := range rule.Sources {
			if matchesSource(rhsNode, bt, src, source) {
				taintedVars[varName] = true
				return
			}
		}
	}

	if referencesTaintedVar(rhsNode, bt, taintedVars) {
		taintedVars[varName] = true
	}
}

// isSanitizer checks if a function name matches any sanitizer pattern for the
// given language. Sanitizers can be rule-specific or language-default.
func (a *Analyzer) isSanitizer(funcName, lang string) bool {
	// Check rule-specific sanitizers.
	for _, rule := range a.rules {
		if rule.Language != lang {
			continue
		}
		for _, san := range rule.Sanitizers {
			if sinkMatches(funcName, san.FuncName) {
				return true
			}
		}
	}
	// Check language-default sanitizers.
	for _, san := range defaultSanitizers(lang) {
		if sinkMatches(funcName, san) {
			return true
		}
	}
	return false
}

// defaultSanitizers returns the built-in sanitizer function names for a language.
func defaultSanitizers(lang string) []string {
	switch lang {
	case "python":
		return []string{"quote", "escape", "bleach.clean", "markupsafe.escape", "html.escape", "shlex.quote"}
	case "javascript", "typescript":
		return []string{"encodeURIComponent", "DOMPurify.sanitize", "escape", "encodeURI"}
	case "ruby":
		return []string{"ERB::Util.html_escape", "sanitize", "CGI.escapeHTML", "h"}
	case "php":
		return []string{"htmlspecialchars", "filter_var", "mysql_real_escape_string", "addslashes"}
	case "java":
		return []string{"StringEscapeUtils.escapeHtml", "URLEncoder.encode", "org.apache.commons.text.StringEscapeUtils.escapeHtml4"}
	case "c_sharp":
		return []string{"HttpUtility.HtmlEncode", "WebUtility.HtmlEncode", "HttpUtility.UrlEncode"}
	case "go":
		return []string{"filepath.Clean", "filepath.Base", "html.EscapeString", "url.QueryEscape", "url.PathEscape", "regexp.MustCompile", "strconv.Atoi", "strconv.ParseInt"}
	default:
		return nil
	}
}

// checkSinkCall checks if a call to a sink function uses tainted arguments.
func (a *Analyzer) checkSinkCall(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang, absPath, root string, src []byte, taintedVars map[string]bool, findings *[]analysis.Finding) {
	// Extract the function name from the call node. Different languages use
	// different tree-sitter field names and node structures.
	funcName := extractCallName(node, bt, lang)
	if funcName == "" {
		return
	}

	argsNode := extractCallArgs(node, bt, lang)
	if argsNode == nil {
		return
	}

	for _, rule := range a.rules {
		if rule.Language != lang {
			continue
		}
		for _, sink := range rule.Sinks {
			if !sinkMatches(funcName, sink.FuncName) {
				continue
			}

			argIdx := 0
			for i := 0; i < int(argsNode.ChildCount()); i++ {
				arg := argsNode.Child(i)
				if arg == nil || isPunctuation(bt.NodeType(arg)) {
					continue
				}

				if sink.ArgIndex >= 0 && argIdx != sink.ArgIndex {
					argIdx++
					continue
				}

				argText := bt.NodeText(arg)
				if isArgTainted(arg, bt, taintedVars) {
					// Check if the argument is wrapped in a sanitizer call
					// (e.g., os.ReadFile(filepath.Clean(file))). If the
					// outermost call in the argument is a sanitizer, skip
					// the finding — the sanitizer neutralizes the taint.
					if !isArgSanitized(arg, bt, lang, a) {
						f := a.makeFinding(rule, node, bt, absPath, root, funcName, argText, taintedVars)
						*findings = append(*findings, f)
						break
					}
				}
				// Also check for direct source-to-sink flows where the source
				// is used inline in the sink argument without being assigned to
				// a variable first (e.g., query(`SELECT ... ${req.body.email}`)).
				// This catches template literals and inline expressions that
				// contain source patterns directly.
				if argContainsSource(arg, bt, src, rule.Sources) {
					f := a.makeFinding(rule, node, bt, absPath, root, funcName, argText, taintedVars)
					*findings = append(*findings, f)
					break
				}
				argIdx++
			}
		}
	}
}

// extractCallName extracts the function/method name from a call node across
// different tree-sitter grammars.
func extractCallName(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) string {
	nt := bt.NodeType(node)

	// Go wraps expressions in expression_list. Unwrap to the first child.
	if nt == "expression_list" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil || isPunctuation(bt.NodeType(child)) {
				continue
			}
			return extractCallName(child, bt, lang)
		}
		return ""
	}

	// Python "call" uses the "function" field
	if nt == "call" && lang == "python" {
		funcNode := bt.ChildByField(node, "function")
		if funcNode != nil {
			return bt.NodeText(funcNode)
		}
		return ""
	}

	// JS/TS "call_expression" uses the "function" field
	if nt == "call_expression" {
		funcNode := bt.ChildByField(node, "function")
		if funcNode != nil {
			return bt.NodeText(funcNode)
		}
		return ""
	}

	// Ruby "call" has: constant/identifier + "." + identifier(method name)
	// Return the full receiver.method path (e.g., "File.open", "User.where")
	if nt == "call" && lang == "ruby" {
		return extractDottedPath(node, bt)
	}

	// PHP "function_call_expression" has a child node of type "name"
	if nt == "function_call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			if bt.NodeType(child) == "name" {
				return bt.NodeText(child)
			}
		}
		return ""
	}

	// PHP "member_call_expression" has: variable_name(receiver) + name(method)
	// Return the full receiver->method path (e.g., "$request->get", "DB::select")
	if nt == "member_call_expression" {
		return extractDottedPath(node, bt)
	}

	// PHP "scoped_call_expression" has: qualified_name(receiver) + name(method)
	// e.g., \DB::select(args) → "DB::select"
	if nt == "scoped_call_expression" {
		return extractDottedPath(node, bt)
	}

	// Java "method_invocation" has: identifier(receiver) + "." + identifier(method)
	// Return the full dotted path (e.g., "request.getParameter") for precise matching.
	if nt == "method_invocation" {
		return extractDottedPath(node, bt)
	}

	// C# "invocation_expression" has: member_access_expression + argument_list
	// member_access_expression has: identifier + "." + identifier(method)
	// Return the full dotted path (e.g., "File.ReadAllText") for precise matching.
	if nt == "invocation_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			ct := bt.NodeType(child)
			if ct == "identifier" {
				// Simple function call: identifier(args)
				if i+1 < int(node.ChildCount()) {
					next := node.Child(i + 1)
					if next != nil && bt.NodeType(next) == "argument_list" {
						return bt.NodeText(child)
					}
				}
			}
			if ct == "member_access_expression" {
				// Method call: obj.method(args) — extract the full dotted path
				return extractDottedPath(child, bt)
			}
		}
		return ""
	}

	// Java/C#/PHP "object_creation_expression" (new Type(args))
	// Extract the type name — it's the last identifier in the type part
	if nt == "object_creation_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			ct := bt.NodeType(child)
			// Java: type_identifier, C#: identifier or qualified_name
			// PHP: name (e.g., RedirectResponse) or qualified_name (e.g., \Symfony\...\RedirectResponse)
			if ct == "type_identifier" || ct == "identifier" || ct == "name" {
				return bt.NodeText(child)
			}
			if ct == "qualified_name" {
				// Extract the last segment after backslashes (PHP) or dots (C#)
				text := bt.NodeText(child)
				text = strings.TrimPrefix(text, "\\")
				// Take the last segment after \
				if idx := strings.LastIndex(text, "\\"); idx >= 0 {
					text = text[idx+1:]
				}
				return text
			}
		}
		return ""
	}

	// Fallback: try "function" field
	funcNode := bt.ChildByField(node, "function")
	if funcNode != nil {
		return bt.NodeText(funcNode)
	}
	return ""
}

// extractLastIdentifier returns the text of the last identifier child of a node.
func extractLastIdentifier(node *gotreesitter.Node, bt *gotreesitter.BoundTree) string {
	var last string
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if bt.NodeType(child) == "identifier" || bt.NodeType(child) == "constant" {
			last = bt.NodeText(child)
		}
	}
	return last
}

// extractDottedPath returns the full receiver.method path from a call node.
// For example, Ruby "File.open(args)" → "File.open", "User.where(args)" → "User.where".
// PHP "$request->get(args)" → "$request->get", "DB::select(args)" → "DB::select".
// It concatenates identifier/constant/variable_name/name children with appropriate
// separators, stopping before the argument_list.
func extractDottedPath(node *gotreesitter.Node, bt *gotreesitter.BoundTree) string {
	var parts []string
	var sep = "."
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		ct := bt.NodeType(child)
		if ct == "argument_list" || ct == "arguments" {
			break
		}
		// PHP member_call_expression uses "->" between receiver and method
		if ct == "->" {
			sep = "->"
			continue
		}
		// PHP scoped call uses "::"
		if ct == "::" {
			sep = "::"
			continue
		}
		if ct == "identifier" || ct == "constant" || ct == "variable_name" || ct == "name" || ct == "qualified_name" {
			text := bt.NodeText(child)
			// Strip leading backslash from PHP qualified names (e.g., "\DB" → "DB")
			text = strings.TrimPrefix(text, "\\")
			parts = append(parts, text)
		}
	}
	if len(parts) < 2 {
		return strings.Join(parts, sep)
	}
	// Use the detected separator between the last two parts (receiver->method)
	// and "." for earlier parts (e.g., package.Class.method in Java)
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		if i == len(parts)-1 && sep != "." {
			result += sep + parts[i]
		} else {
			result += "." + parts[i]
		}
	}
	return result
}

// extractCallArgs extracts the arguments node from a call node across
// different tree-sitter grammars.
func extractCallArgs(node *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string) *gotreesitter.Node {
	// Try "arguments" field (Python, JS, PHP)
	argsNode := bt.ChildByField(node, "arguments")
	if argsNode != nil {
		return argsNode
	}
	// Try "argument_list" field (Java, C#, Ruby)
	argsNode = bt.ChildByField(node, "argument_list")
	if argsNode != nil {
		return argsNode
	}
	// Fallback: look for a child named "argument_list" or "arguments"
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		ct := bt.NodeType(child)
		if ct == "argument_list" || ct == "arguments" || ct == "argument" {
			return child
		}
	}
	return nil
}

func isPunctuation(nodeType string) bool {
	return nodeType == "(" || nodeType == ")" || nodeType == "," ||
		nodeType == "[" || nodeType == "]" || nodeType == "{" || nodeType == "}" ||
		nodeType == ";" || nodeType == "->" || nodeType == "=>" ||
		nodeType == "::" || nodeType == "." || nodeType == ":=" ||
		nodeType == "="
}

// firstIdentifier returns the text of the first identifier descendant of a
// node. Used for Go's expression_list which may contain multiple identifiers
// (e.g., "q, err := ..."). Returns "" if no identifier is found.
func firstIdentifier(node *gotreesitter.Node, bt *gotreesitter.BoundTree) string {
	if node == nil {
		return ""
	}
	nt := bt.NodeType(node)
	if nt == "identifier" || nt == "field_identifier" {
		return bt.NodeText(node)
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if result := firstIdentifier(node.Child(i), bt); result != "" {
			return result
		}
	}
	return ""
}

// matchesSource checks if a node represents a taint source.
func matchesSource(node *gotreesitter.Node, bt *gotreesitter.BoundTree, src []byte, source SourcePattern) bool {
	text := bt.NodeText(node)
	if source.IsSubscript {
		return strings.Contains(text, source.FuncName)
	}
	if strings.HasPrefix(text, source.FuncName) || text == source.FuncName {
		return true
	}
	return strings.Contains(text, source.FuncName+"(")
}

// argContainsSource checks if a sink argument directly contains a taint
// source pattern (without going through a variable assignment). This catches
// inline source usage like:
//   query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)
//   exec(req.body.command)
//   cursor.execute("SELECT * FROM users WHERE id = " + request.args["id"])
//
// Only subscript sources (property access patterns like "req.body", "request.args")
// are checked inline to avoid false positives from function-call sources.
func argContainsSource(arg *gotreesitter.Node, bt *gotreesitter.BoundTree, src []byte, sources []SourcePattern) bool {
	if arg == nil {
		return false
	}
	argText := bt.NodeText(arg)
	for _, source := range sources {
		if source.Annotation != "" {
			continue // annotations are handled by seedAnnotatedParams
		}
		if source.IsSubscript && strings.Contains(argText, source.FuncName) {
			return true
		}
		// Also check non-subscript function-call sources (e.g., request.getParameter)
		if !source.IsSubscript && strings.Contains(argText, source.FuncName+"(") {
			return true
		}
	}
	return false
}

// referencesTaintedVar checks if a node references any tainted variable.
func referencesTaintedVar(node *gotreesitter.Node, bt *gotreesitter.BoundTree, taintedVars map[string]bool) bool {
	if node == nil {
		return false
	}
	nt := bt.NodeType(node)
	// "identifier" covers Python, JS/TS, Ruby, Java, C# variable references.
	// "variable_name" covers PHP variables ($var).
	if nt == "identifier" || nt == "variable_name" {
		if taintedVars[bt.NodeText(node)] {
			return true
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if referencesTaintedVar(node.Child(i), bt, taintedVars) {
			return true
		}
	}
	return false
}

// isArgTainted checks if a call argument contains tainted data.
func isArgTainted(arg *gotreesitter.Node, bt *gotreesitter.BoundTree, taintedVars map[string]bool) bool {
	if arg == nil {
		return false
	}
	nt := bt.NodeType(arg)
	if nt == "identifier" || nt == "variable_name" {
		return taintedVars[bt.NodeText(arg)]
	}
	return referencesTaintedVar(arg, bt, taintedVars)
}

// isArgSanitized checks if the argument is wrapped in a sanitizer call,
// e.g., os.ReadFile(filepath.Clean(file)). It checks if the outermost
// expression in the argument is a call to a known sanitizer function.
func isArgSanitized(arg *gotreesitter.Node, bt *gotreesitter.BoundTree, lang string, a *Analyzer) bool {
	if arg == nil || a == nil {
		return false
	}
	// The argument itself might be a call expression (e.g., filepath.Clean(file))
	// or it might be wrapped in an "argument" node (PHP) or expression_list (Go).
	nt := bt.NodeType(arg)
	// Unwrap wrapper nodes to find the actual expression
	expr := arg
	if nt == "argument" || nt == "expression_list" {
		for i := 0; i < int(arg.ChildCount()); i++ {
			child := arg.Child(i)
			if child == nil || isPunctuation(bt.NodeType(child)) {
				continue
			}
			expr = child
			break
		}
	}
	// Check if the expression is a sanitizer call
	exprType := bt.NodeType(expr)
	if exprType == "call_expression" || exprType == "member_call_expression" ||
		exprType == "scoped_call_expression" || exprType == "function_call_expression" {
		funcName := extractCallName(expr, bt, lang)
		if funcName != "" && a.isSanitizer(funcName, lang) {
			return true
		}
	}
	return false
}

// sinkMatches checks if a function name matches a sink pattern.
func sinkMatches(funcName, sinkPattern string) bool {
	// Exact match
	if funcName == sinkPattern {
		return true
	}
	// Method call: obj.method matches sink "method"
	if strings.HasSuffix(funcName, "."+sinkPattern) {
		return true
	}
	// Qualified call: Module::Class.method matches sink "method"
	if strings.HasSuffix(funcName, "::"+sinkPattern) {
		return true
	}
	// PHP member call: $obj->method matches sink "method"
	if strings.HasSuffix(funcName, "->"+sinkPattern) {
		return true
	}
	return false
}

// makeFinding creates a Finding from a taint rule match.
func (a *Analyzer) makeFinding(rule Rule, node *gotreesitter.Node, bt *gotreesitter.BoundTree, absPath, root, sinkFunc, argText string, taintedVars map[string]bool) analysis.Finding {
	startPoint := node.StartPoint()
	lineStart := int(startPoint.Row) + 1
	lineEnd := int(node.EndPoint().Row) + 1

	relPath, err := filepath.Rel(root, absPath)
	if err != nil {
		relPath = absPath
	}

	evidence := strings.TrimSpace(argText)
	if len(evidence) > 100 {
		evidence = evidence[:97] + "..."
	}

	// Build taint path: collect tainted variable names that appear in the
	// argument, then prepend the source. This gives a trace like:
	//   ["request.GET[\"id\"]", "user_id", "cursor.execute()"]
	var taintPath []string
	for varName := range taintedVars {
		if strings.Contains(argText, varName) {
			taintPath = append(taintPath, varName)
		}
	}
	sort.Strings(taintPath)
	taintPath = append(taintPath, sinkFunc)

	return analysis.Finding{
		ID:             fmt.Sprintf("taint-pattern-%s-%s-%d", rule.ID, filepath.Base(relPath), lineStart),
		Type:           analysis.TypeSAST,
		Analyzer:       "taint-patterns",
		Severity:       rule.Severity,
		Confidence:     rule.Confidence,
		Title:          rule.Title,
		Description:    rule.Description,
		FilePath:       relPath,
		LineStart:      lineStart,
		LineEnd:        lineEnd,
		RuleID:         rule.ID,
		CWEID:          rule.CWEID,
		Evidence:       evidence,
		Recommendation: fmt.Sprintf("Ensure user input flowing into %s is sanitized/validated.", sinkFunc),
		TaintPath:      taintPath,
		DetectedAt:     time.Now(),
	}
}
