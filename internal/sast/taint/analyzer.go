// Package taint provides SSA-based taint analysis for Go code. It tracks
// data flow from taint sources (HTTP request parameters, environment
// variables, command-line flags) to dangerous sinks (SQL queries, command
// execution, file paths, HTTP responses, HTML templates).
//
// This implements rules G701-G710 from the SAST roadmap:
//   G701: SQL injection (tainted data in database/sql Exec/Query)
//   G702: Command injection (tainted data in os/exec.Command)
//   G703: Path traversal (tainted data in file open/read/write)
//   G704: SSRF (tainted data in HTTP client requests)
//   G705: Open redirect (tainted data in HTTP redirect)
//   G706: Log injection (tainted data in log statements)
//   G707: SMTP header injection (tainted data in email headers)
//   G708: SSTI (tainted data in text/template execution)
//   G709: XSS (tainted data in HTTP response writes without escaping)
//   G710: Unsafe deserialization (tainted data in gob/json.Unmarshal)
//
// The analysis uses golang.org/x/tools/go/ssa to build SSA form and
// performs backward taint propagation from sinks to sources.
package taint

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"log"
	"io"
	"runtime"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// Severity levels.
type Severity int

const (
	SeverityLow    Severity = 1
	SeverityMedium Severity = 2
	SeverityHigh   Severity = 3
)

// Confidence levels.
type Confidence int

const (
	ConfidenceLow    Confidence = 1
	ConfidenceMedium Confidence = 2
	ConfidenceHigh   Confidence = 3
)

// Finding is a raw taint finding before normalization.
type Finding struct {
	RuleID     string
	Title      string
	Severity   Severity
	Confidence Confidence
	File       string
	Line       int
	Col        int
	Code       string
	Sink       string
	Source     string
}

// Source represents a taint source — where untrusted data enters the program.
type Source struct {
	// CallPattern matches the function call that produces tainted data.
	// Format: "package.Function" or "*type.Method"
	CallPattern string
	// Description of the source.
	Description string
}

// Sink represents a dangerous sink — where tainted data can cause harm.
type Sink struct {
	// CallPattern matches the function call that consumes data.
	CallPattern string
	// ArgIndex is the index of the argument that is dangerous if tainted.
	ArgIndex int
	// RuleID is the rule that fires when tainted data reaches this sink.
	RuleID string
	// Title describes the vulnerability.
	Title string
	// Severity of the finding.
	Severity Severity
	// Description of the sink.
	Description string
}

// Analyzer runs SSA-based taint analysis on Go packages.
type Analyzer struct {
	sources []Source
	sinks   []Sink
	// Sanitizers are calls that "clean" tainted data (e.g. filepath.Clean,
	// html.EscapeString). If a value passes through a sanitizer, it is no
	// longer considered tainted.
	sanitizers []string
	concurrency int
	logger      *log.Logger
}

// NewAnalyzer creates a taint analyzer with built-in sources and sinks.
func NewAnalyzer() *Analyzer {
	a := &Analyzer{
		concurrency: runtime.NumCPU(),
		logger:      log.New(io.Discard, "[taint] ", log.LstdFlags),
	}
	a.registerDefaults()
	return a
}

// registerDefaults registers the built-in taint sources, sinks, and sanitizers.
func (a *Analyzer) registerDefaults() {
	// --- Taint Sources ---
	a.sources = []Source{
		// HTTP request parameters
		{"*net/http.Request.URL", "HTTP request URL"},
		{"*net/http.Request.Form", "HTTP form data"},
		{"*net/http.Request.PostForm", "HTTP POST form data"},
		{"*net/http.Request.MultipartForm", "HTTP multipart form data"},
		{"*net/http.Request.Header", "HTTP request headers"},
		{"*net/http.Request.Cookie", "HTTP request cookies"},
		{"*net/http.Request.Body", "HTTP request body"},
		{"*net/http.Request.Context", "HTTP request context"},
		{"*net/http.Request.Query", "HTTP query parameters"},
		{"*net/http.Request.PathValue", "HTTP path parameter"},
		// URL.Query() returns tainted values
		{"*net/url.URL.Query", "URL query parameters"},
		// CLI arguments — operator-controlled, but still untrusted in
		// server contexts. Kept for command injection detection.
		{"os.Args", "command-line arguments"},
		{"flag.Arg", "command-line flag"},
		{"flag.Args", "command-line arguments"},
		// stdin
		{"bufio.Scanner.Text", "stdin input"},
		{"bufio.Scanner.Scan", "stdin input"},
		{"fmt.Scan", "stdin input"},
		{"fmt.Sscan", "stdin input"},
		// Generic user input markers
		{"*github.com/gin-gonic/gin.Context.Query", "Gin query parameter"},
		{"*github.com/gin-gonic/gin.Context.Param", "Gin path parameter"},
		{"*github.com/gin-gonic/gin.Context.PostForm", "Gin POST form data"},
		{"*github.com/gin-gonic/gin.Context.Get", "Gin context value"},
	}

	// --- Taint Sinks ---
	a.sinks = []Sink{
		// G701: SQL injection
		{"*database/sql.DB.Exec", 0, "G701", "SQL injection: tainted data in Exec", SeverityHigh, "Tainted data flows into a SQL Exec call without parameterization"},
		{"*database/sql.DB.Query", 0, "G701", "SQL injection: tainted data in Query", SeverityHigh, "Tainted data flows into a SQL Query call without parameterization"},
		{"*database/sql.DB.QueryRow", 0, "G701", "SQL injection: tainted data in QueryRow", SeverityHigh, "Tainted data flows into a SQL QueryRow call without parameterization"},
		{"*database/sql.DB.ExecContext", 1, "G701", "SQL injection: tainted data in ExecContext", SeverityHigh, "Tainted data flows into a SQL ExecContext call without parameterization"},
		{"*database/sql.DB.QueryContext", 1, "G701", "SQL injection: tainted data in QueryContext", SeverityHigh, "Tainted data flows into a SQL QueryContext call without parameterization"},
		{"*database/sql.DB.QueryRowContext", 1, "G701", "SQL injection: tainted data in QueryRowContext", SeverityHigh, "Tainted data flows into a SQL QueryRowContext call without parameterization"},
		{"*database/sql.Tx.Exec", 0, "G701", "SQL injection: tainted data in Tx.Exec", SeverityHigh, "Tainted data flows into a SQL transaction Exec call"},
		{"*database/sql.Tx.Query", 0, "G701", "SQL injection: tainted data in Tx.Query", SeverityHigh, "Tainted data flows into a SQL transaction Query call"},
		{"*database/sql.Tx.QueryRow", 0, "G701", "SQL injection: tainted data in Tx.QueryRow", SeverityHigh, "Tainted data flows into a SQL transaction QueryRow call"},

		// G702: Command injection (ArgIndex -1 = check all args)
		{"os/exec.Command", -1, "G702", "Command injection: tainted data in exec.Command", SeverityHigh, "Tainted data flows into a command execution call"},
		{"os/exec.CommandContext", -1, "G702", "Command injection: tainted data in exec.CommandContext", SeverityHigh, "Tainted data flows into a command execution call"},
		{"syscall.Exec", 0, "G702", "Command injection: tainted data in syscall.Exec", SeverityHigh, "Tainted data flows into a syscall.Exec call"},

		// G703: Path traversal
		{"os.Open", 0, "G703", "Path traversal: tainted data in os.Open", SeverityHigh, "Tainted data flows into a file open call"},
		{"os.OpenFile", 0, "G703", "Path traversal: tainted data in os.OpenFile", SeverityHigh, "Tainted data flows into a file open call"},
		{"os.ReadFile", 0, "G703", "Path traversal: tainted data in os.ReadFile", SeverityHigh, "Tainted data flows into a file read call"},
		{"os.Create", 0, "G703", "Path traversal: tainted data in os.Create", SeverityHigh, "Tainted data flows into a file create call"},
		{"os.WriteFile", 0, "G703", "Path traversal: tainted data in os.WriteFile", SeverityHigh, "Tainted data flows into a file write call"},
		{"ioutil.ReadFile", 0, "G703", "Path traversal: tainted data in ioutil.ReadFile", SeverityHigh, "Tainted data flows into a file read call"},

		// G704: SSRF
		{"http.Get", 0, "G704", "SSRF: tainted data in http.Get", SeverityHigh, "Tainted data flows into an HTTP client request"},
		{"http.Post", 0, "G704", "SSRF: tainted data in http.Post", SeverityHigh, "Tainted data flows into an HTTP client request"},
		{"http.NewRequest", 1, "G704", "SSRF: tainted data in http.NewRequest", SeverityHigh, "Tainted data flows into an HTTP request URL"},
		{"*http.Client.Get", 0, "G704", "SSRF: tainted data in Client.Get", SeverityHigh, "Tainted data flows into an HTTP client request"},
		{"*http.Client.Do", 0, "G704", "SSRF: tainted data in Client.Do", SeverityHigh, "Tainted data flows into an HTTP client request"},

		// G705: Open redirect
		{"http.Redirect", 1, "G705", "Open redirect: tainted data in http.Redirect", SeverityMedium, "Tainted data flows into an HTTP redirect URL"},

		// G706: Log injection
		{"log.Print", 0, "G706", "Log injection: tainted data in log.Print", SeverityLow, "Tainted data flows into a log statement"},
		{"log.Printf", 0, "G706", "Log injection: tainted data in log.Printf", SeverityLow, "Tainted data flows into a log statement"},
		{"log.Println", 0, "G706", "Log injection: tainted data in log.Println", SeverityLow, "Tainted data flows into a log statement"},

		// G708: SSTI (Server-Side Template Injection)
		{"text/template.Template.Execute", 1, "G708", "SSTI: tainted data in template.Execute", SeverityHigh, "Tainted data flows into a template execution call"},
		{"html/template.Template.Execute", 1, "G708", "SSTI: tainted data in template.Execute", SeverityMedium, "Tainted data flows into a template execution call (html/template auto-escapes)"},

		// G709: XSS (direct write to HTTP response)
		{"*http.ResponseWriter.Write", 0, "G709", "XSS: tainted data written to HTTP response", SeverityHigh, "Tainted data written directly to HTTP response without escaping"},

		// G710: Unsafe deserialization
		{"json.Unmarshal", 1, "G710", "Unsafe deserialization: tainted data in json.Unmarshal", SeverityMedium, "Tainted data flows into JSON deserialization"},
		{"gob.NewDecoder.Decode", 1, "G710", "Unsafe deserialization: tainted data in gob.Decode", SeverityHigh, "Tainted data flows into gob deserialization"},
	}

	// --- Sanitizers (calls that clean tainted data) ---
	a.sanitizers = []string{
		"path/filepath.Clean",
		"path.Clean",
		"html.EscapeString",
		"template.HTMLEscapeString",
		"template.HTMLEscaper",
		"template.JSEscapeString",
		"template.JSEscaper",
		"template.URLQueryEscaper",
		"net/url.QueryEscape",
		"net/url.PathEscape",
	}
}

// Analyze runs taint analysis on all Go packages in the root directory.
func (a *Analyzer) Analyze(ctx context.Context, root string) ([]analysis.Finding, error) {
	startTime := time.Now()

	pkgs, err := a.loadPackages(root)
	if err != nil {
		return nil, fmt.Errorf("taint: failed to load packages: %w", err)
	}

	if len(pkgs) == 0 {
		return nil, nil
	}

	// Build a single SSA program for all packages and their dependencies.
	// This is necessary because the SSA builder needs all imported packages
	// to be present in the program to resolve references.
	prog := ssa.NewProgram(pkgs[0].Fset, ssa.InstantiateGenerics)

	// Collect all packages (including dependencies) and create their SSA representations.
	// We track the *ssa.Package handles so we can build them individually
	// instead of calling prog.Build() (which spawns internal goroutines that
	// can panic without recovery).
	allPkgs := collectAllPackages(pkgs)
	var ssaPkgs []*ssa.Package
	for _, p := range allPkgs {
		if p.Types == nil {
			continue
		}
		// Skip packages with type errors — the SSA builder panics on
		// unresolved AST nodes. collectAllPackages already filters these,
		// but double-check here for safety.
		if len(p.Errors) > 0 {
			continue
		}
		// Only create SSA for packages we have syntax and type info for.
		// For dependency packages without syntax, CreatePackage handles nil syntax.
		ssaPkg := prog.CreatePackage(p.Types, p.Syntax, p.TypesInfo, true)
		if ssaPkg != nil {
			ssaPkgs = append(ssaPkgs, ssaPkg)
		}
	}

	// Build each SSA package individually. We can't use prog.Build() because
	// it spawns internal goroutines — a panic in a child goroutine cannot be
	// caught by defer/recover in this goroutine. Building packages one at a
	// time lets us recover from panics per-package and skip just the bad ones.
	buildFailures := 0
	for _, ssaPkg := range ssaPkgs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					buildFailures++
					a.logger.Printf("taint-ssa: SSA build panicked for package %s (skipping): %v", ssaPkg.Pkg.Path(), r)
				}
			}()
			ssaPkg.Build()
		}()
	}

	a.logger.Printf("taint-ssa: built %d SSA packages (%d failures)", len(ssaPkgs)-buildFailures, buildFailures)

	var findings []analysis.Finding
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			for _, e := range pkg.Errors {
				a.logger.Printf("package error in %s: %v", pkg.PkgPath, e)
			}
			continue
		}
		if pkg.TypesInfo == nil || pkg.Syntax == nil || pkg.Types == nil {
			continue
		}

		pkgFindings := a.analyzePackage(pkg, prog)
		findings = append(findings, pkgFindings...)
	}

	a.logger.Printf("taint analysis completed in %v: %d findings", time.Since(startTime), len(findings))
	return findings, nil
}

// collectAllPackages walks the import graph and returns all packages
// (including transitive dependencies) that have type information.
// Packages with type errors are skipped to avoid SSA builder panics
// (e.g., "no type for *ast.CallExpr" when type info is incomplete).
func collectAllPackages(roots []*packages.Package) []*packages.Package {
	seen := make(map[string]bool)
	var result []*packages.Package

	var walk func(p *packages.Package)
	walk = func(p *packages.Package) {
		if p == nil || p.Types == nil {
			return
		}
		if seen[p.PkgPath] {
			return
		}
		seen[p.PkgPath] = true
		// Skip packages with type errors — the SSA builder panics on
		// AST nodes that have no resolved type (e.g., unresolved function
		// calls). This is common in projects with conditional compilation
		// or platform-specific code.
		if len(p.Errors) > 0 {
			return
		}
		result = append(result, p)
		for _, imp := range p.Imports {
			walk(imp)
		}
	}

	for _, root := range roots {
		walk(root)
	}
	return result
}

// loadPackages loads Go packages with SSA-related mode flags.
func (a *Analyzer) loadPackages(root string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedSyntax | packages.NeedModule | packages.NeedDeps,
		Dir:   root,
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}

	var result []*packages.Package
	for _, p := range pkgs {
		if len(p.Syntax) > 0 && p.Types != nil {
			result = append(result, p)
		}
	}
	return result, nil
}

// analyzePackage builds SSA for a package and runs taint analysis.
func (a *Analyzer) analyzePackage(pkg *packages.Package, prog *ssa.Program) []analysis.Finding {
	ssaPkg := prog.Package(pkg.Types)
	if ssaPkg == nil {
		a.logger.Printf("SSA package not found for %s", pkg.PkgPath)
		return nil
	}

	var findings []analysis.Finding

	// Walk all functions in the package and check for taint flows
	for _, member := range ssaPkg.Members {
		fn, ok := member.(*ssa.Function)
		if !ok {
			continue
		}
		// Recover from potential panics during function analysis
		func() {
			defer func() {
				if r := recover(); r != nil {
					a.logger.Printf("panic analyzing function %s: %v", fn.Name(), r)
				}
			}()
			fnFindings := a.analyzeFunction(fn, pkg)
			findings = append(findings, fnFindings...)
		}()
	}

	return findings
}

// analyzeFunction checks a single function for taint flows from sources to sinks.
func (a *Analyzer) analyzeFunction(fn *ssa.Function, pkg *packages.Package) []analysis.Finding {
	if fn == nil || fn.Blocks == nil {
		return nil
	}

	var findings []analysis.Finding
	seenSinks := make(map[string]bool) // dedup by (sink位置+ruleID)

	// Walk all basic blocks and instructions
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}

			// Check if this call is a sink
			sink := a.matchSink(call)
			if sink == nil {
				continue
			}

			// Determine which arguments to check. ArgIndex -1 means check all args.
			// For method calls in SSA, the receiver is the first argument,
			// so we add 1 to the sink's ArgIndex to get the actual position.
			isMethod := a.isMethodCall(call)
			argOffset := 0
			if isMethod {
				argOffset = 1
			}

			var source *Source
			if sink.ArgIndex == -1 {
				// Check all arguments for taint
				for i := argOffset; i < len(call.Call.Args); i++ {
					s := a.traceTaint(call.Call.Args[i], fn, make(map[ssa.Value]bool))
					if s != nil {
						source = s
						break
					}
				}
			} else {
				argIdx := sink.ArgIndex + argOffset
				if argIdx < len(call.Call.Args) {
					source = a.traceTaint(call.Call.Args[argIdx], fn, make(map[ssa.Value]bool))
				}
			}

			if source != nil {
				// Dedup findings by position
				pos := a.instrPos(call)
				key := fmt.Sprintf("%d-%s-%d", pos, sink.RuleID, sink.ArgIndex)
				if seenSinks[key] {
					continue
				}
				seenSinks[key] = true

				finding := a.makeFinding(sink, source, call, pkg)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// matchSink checks if a call matches any registered sink.
func (a *Analyzer) matchSink(call *ssa.Call) *Sink {
	callName := a.callName(call)
	if callName == "" {
		return nil
	}

	for i := range a.sinks {
		s := &a.sinks[i]
		if matchPattern(s.CallPattern, callName) {
			return s
		}
	}
	return nil
}

// callName returns the fully qualified name of a call's target.
// For method calls, it returns the receiver type + method name (e.g.,
// "*database/sql.DB.Query"). For package-level functions, it returns
// the package path + function name (e.g., "os/exec.Command").
func (a *Analyzer) callName(call *ssa.Call) string {
	// Method call via interface or method value
	callee := call.Call.Method
	if callee != nil {
		// Method call — get the receiver type and method name
		sig, ok := callee.Type().(*types.Signature)
		if ok && sig.Recv() != nil {
			recvType := sig.Recv().Type()
			typeStr := recvType.String()
			return typeStr + "." + callee.Name()
		}

		// Package-level function
		if callee.Pkg() != nil {
			return callee.Pkg().Path() + "." + callee.Name()
		}
		return callee.Name()
	}

	// Direct function call (including methods represented as functions in SSA)
	fn, ok := call.Call.Value.(*ssa.Function)
	if !ok {
		return ""
	}

	// Check if this function is actually a method (has a receiver in its signature)
	if fn.Signature != nil {
		if sig := fn.Signature; sig != nil && sig.Recv() != nil {
			recvType := sig.Recv().Type()
			typeStr := recvType.String()
			return typeStr + "." + fn.Name()
		}
	}

	// Package-level function
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fn.Pkg.Pkg.Path() + "." + fn.Name()
	}

	return fn.Name()
}

// isMethodCall returns true if the call is a method call (has a receiver
// argument as the first argument in SSA representation).
func (a *Analyzer) isMethodCall(call *ssa.Call) bool {
	// Method call via interface or method value
	if call.Call.Method != nil {
		return true
	}
	// Direct call to a function that is actually a method
	if fn, ok := call.Call.Value.(*ssa.Function); ok && fn.Signature != nil {
		if sig := fn.Signature; sig != nil {
			return sig.Recv() != nil
		}
	}
	return false
}

// matchPattern checks if a sink/source pattern matches a call name.
// Patterns can be:
//   "package.Function"     — exact match
//   "*type.Method"         — method on a pointer type
//   "type.Method"          — method on a value type
func matchPattern(pattern, callName string) bool {
	// Handle pointer-type patterns: "*database/sql.DB.Exec"
	if strings.HasPrefix(pattern, "*") {
		// The callName from SSA uses the full type path, e.g., "*database/sql.DB"
		// We need to check if the callName starts with the pattern's type
		// and ends with the method name.
		patternType := pattern[:strings.LastIndex(pattern, ".")]
		patternMethod := pattern[strings.LastIndex(pattern, ".")+1:]
		// callName format: "*database/sql.DB.Exec"
		callType := callName[:strings.LastIndex(callName, ".")]
		callMethod := callName[strings.LastIndex(callName, ".")+1:]

		if callMethod != patternMethod {
			return false
		}
		// Match type, ignoring pointer vs value differences
		return typeMatch(patternType, callType)
	}

	// Non-pointer patterns: "os/exec.Command"
	patternType := ""
	patternMethod := ""
	if idx := strings.LastIndex(pattern, "."); idx >= 0 {
		patternMethod = pattern[idx+1:]
		patternType = pattern[:idx]
	} else {
		patternMethod = pattern
	}

	callMethod := ""
	callType := ""
	if idx := strings.LastIndex(callName, "."); idx >= 0 {
		callMethod = callName[idx+1:]
		callType = callName[:idx]
	} else {
		callMethod = callName
	}

	if callMethod != patternMethod {
		return false
	}
	return typeMatch(patternType, callType)
}

// typeMatch checks if two type strings refer to the same type,
// ignoring pointer vs value differences.
func typeMatch(a, b string) bool {
	// Strip leading * from both
	a = strings.TrimPrefix(a, "*")
	b = strings.TrimPrefix(b, "*")
	return a == b
}

// traceTaint performs backward taint tracing from a value to find if it
// originates from a taint source. Returns the source description if tainted,
// or nil if the value is not tainted or has been sanitized.
func (a *Analyzer) traceTaint(v ssa.Value, fn *ssa.Function, visited map[ssa.Value]bool) *Source {
	if v == nil {
		return nil
	}
	if visited[v] {
		return nil
	}
	visited[v] = true

	// Check if this value is directly a source
	if source := a.matchSource(v); source != nil {
		return source
	}

	// Check if this value has been sanitized
	if a.isSanitized(v) {
		return nil
	}

	// Trace back through the value's definition
	switch val := v.(type) {
	case *ssa.Call:
		// The value is the result of a call — check if the call arguments are tainted
		// (for cases where a wrapper function passes tainted data through)
		for _, arg := range val.Call.Args {
			if source := a.traceTaint(arg, fn, visited); source != nil {
				return source
			}
		}
		// Also check if the call itself is a source
		if source := a.matchSourceCall(val); source != nil {
			return source
		}

	case *ssa.Extract:
		// Tuple extraction (e.g., result of a multi-return call)
		if source := a.traceTaint(val.Tuple, fn, visited); source != nil {
			return source
		}

	case *ssa.Parameter:
		// Function parameter — check if the function is called with tainted data
		// For now, we treat parameters of exported functions as potentially tainted
		// (they could be called from HTTP handlers)
		if a.isExportedParam(fn, val) {
			return &Source{CallPattern: "param", Description: fmt.Sprintf("parameter %s of %s", val.Name(), fn.Name())}
		}

	case *ssa.FieldAddr:
		// Field access — trace the struct
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}

	case *ssa.Index:
		// Map/index access — trace the container
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}

	case *ssa.IndexAddr:
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}

	case *ssa.Lookup:
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}

	case *ssa.BinOp:
		// String concatenation — if either side is tainted, result is tainted
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}
		if source := a.traceTaint(val.Y, fn, visited); source != nil {
			return source
		}

	case *ssa.MakeInterface:
		// Interface wrapping — trace the underlying value
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}

	case *ssa.MakeSlice:
		// Slice construction (e.g., variadic args packed into a slice).
		// Elements are stored via separate Store instructions after MakeSlice.
		// We check all Store instructions in the same function that write to
		// this slice for tainted values.
		if source := a.traceStoresToSlice(val, fn, visited); source != nil {
			return source
		}

	case *ssa.Alloc:
		// Heap allocation (e.g., array for variadic args). Elements are
		// stored via separate Store instructions. Check if any stored value
		// is tainted.
		if source := a.traceStoresToSlice(val, fn, visited); source != nil {
			return source
		}

	case *ssa.TypeAssert:
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}

	case *ssa.Slice:
		// Slicing — trace the underlying value
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}

	case *ssa.UnOp:
		// Unary operation (e.g., dereference) — trace the operand
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}

	case *ssa.ChangeType:
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}

	case *ssa.Convert:
		if source := a.traceTaint(val.X, fn, visited); source != nil {
			return source
		}
	}

	return nil
}

// traceStoresToSlice looks for Store instructions in the function that write
// to the given slice (created by MakeSlice). If any stored value is tainted,
// the slice is considered tainted. This handles variadic args packing.
func (a *Analyzer) traceStoresToSlice(slice ssa.Value, fn *ssa.Function, visited map[ssa.Value]bool) *Source {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok {
				continue
			}
			// Check if this store writes to our slice (via IndexAddr)
			idx, ok := store.Addr.(*ssa.IndexAddr)
			if !ok {
				continue
			}
			if idx.X == slice {
				if source := a.traceTaint(store.Val, fn, visited); source != nil {
					return source
				}
			}
		}
	}
	return nil
}

// matchSource checks if a value directly matches a taint source.
func (a *Analyzer) matchSource(v ssa.Value) *Source {
	// Check if the value is a global or parameter that's a known source
	// (e.g., os.Args is a global variable)
	if global, ok := v.(*ssa.Global); ok {
		name := global.RelString(nil)
		if name == "os.Args" {
			return &Source{CallPattern: "os.Args", Description: "command-line arguments"}
		}
	}
	return nil
}

// matchSourceCall checks if a call produces tainted data (is a source).
func (a *Analyzer) matchSourceCall(call *ssa.Call) *Source {
	callName := a.callName(call)
	if callName == "" {
		return nil
	}

	for _, src := range a.sources {
		if matchPattern(src.CallPattern, callName) {
			return &src
		}
	}
	return nil
}

// isSanitized checks if a value has passed through a sanitizer call.
func (a *Analyzer) isSanitized(v ssa.Value) bool {
	// If the value is the result of a sanitizer call, it's clean
	call, ok := v.(*ssa.Call)
	if !ok {
		return false
	}
	callName := a.callName(call)
	for _, san := range a.sanitizers {
		if matchPattern(san, callName) {
			return true
		}
	}
	return false
}

// isExportedParam checks if a parameter belongs to an exported function
// that could be called from HTTP handlers or other entry points.
func (a *Analyzer) isExportedParam(fn *ssa.Function, param *ssa.Parameter) bool {
	if fn == nil {
		return false
	}
	// Exported function (starts with uppercase)
	name := fn.Name()
	if name == "" || !ast.IsExported(name) {
		return false
	}

	// Require package info to make taint decisions. If we can't determine
	// the package, we can't determine if it receives external input —
	// default to not tainted to avoid FPs.
	if fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}

	pkgPath := fn.Pkg.Pkg.Path()

	// Skip packages in documentation, CLI, and internal directories.
	// These are code generators, build scripts, or internal utilities —
	// their exported functions are called internally, not from HTTP handlers.
	for _, segment := range strings.Split(pkgPath, "/") {
		switch segment {
		case "doc", "docs", "internal", "cmd", "script", "scripts",
			"test", "tests", "example", "examples":
			return false
		}
	}

	// Only treat params as tainted if the package imports net/http,
	// indicating it could contain HTTP handlers. This eliminates FPs
	// in CLI tool libraries (cobra, urfave/cli, etc.) where exported
	// functions take path/string parameters for internal file ops.
	if !importsHTTP(fn.Pkg.Pkg) {
		return false
	}

	// Even in packages that import net/http, not all exported functions
	// receive external input. Only treat parameters as tainted if the
	// function signature includes an *http.Request parameter, indicating
	// it's an HTTP handler or directly processes HTTP request data.
	// This eliminates FPs on utility functions like FileLastModified(path string)
	// that happen to live in an HTTP-handling package.
	if !takesHTTPRequest(fn) {
		return false
	}

	return true
}

// importsHTTP returns true if the given package imports "net/http".
func importsHTTP(pkg *types.Package) bool {
	if pkg == nil {
		return false
	}
	for _, imp := range pkg.Imports() {
		if imp.Path() == "net/http" {
			return true
		}
	}
	return false
}

// takesHTTPRequest returns true if the function's signature includes a
// parameter of type *http.Request (or gin.Context, echo.Context, etc.),
// indicating it directly processes HTTP request data.
func takesHTTPRequest(fn *ssa.Function) bool {
	if fn == nil || fn.Signature == nil {
		return false
	}
	sig := fn.Signature
	params := sig.Params()
	for i := 0; i < params.Len(); i++ {
		param := params.At(i)
		typeStr := param.Type().String()
		// Check for common HTTP request/context types
		if strings.Contains(typeStr, "net/http.Request") ||
			strings.Contains(typeStr, "gin.Context") ||
			strings.Contains(typeStr, "echo.Context") ||
			strings.Contains(typeStr, "fiber.Ctx") ||
			strings.Contains(typeStr, "chi.Router") {
			return true
		}
	}
	// Also check the receiver type (for methods on HTTP handler structs)
	if sig.Recv() != nil {
		recvType := sig.Recv().Type().String()
		if strings.Contains(recvType, "Handler") ||
			strings.Contains(recvType, "Server") ||
			strings.Contains(recvType, "Controller") {
			return true
		}
	}
	return false
}

// makeFinding creates a normalized finding from a taint flow.
func (a *Analyzer) makeFinding(sink *Sink, source *Source, call *ssa.Call, pkg *packages.Package) analysis.Finding {
	pos := a.instrPos(call)
	fileName := a.fileName(pkg, pos)
	position := pkg.Fset.Position(pos)

	return analysis.Finding{
		ID:          fmt.Sprintf("taint-%s-%s-%d", sink.RuleID, fileName, position.Line),
		Type:        analysis.TypeSAST,
		Analyzer:    "taint-ssa",
		Severity:    toAnalysisSeverity(sink.Severity),
		Confidence:  analysis.ConfidenceMedium,
		Title:       sink.Title,
		Description: fmt.Sprintf("%s. Source: %s", sink.Description, source.Description),
		FilePath:    fileName,
		LineStart:   position.Line,
		RuleID:      sink.RuleID,
		Evidence:    fmt.Sprintf("Sink: %s, Source: %s", sink.CallPattern, source.Description),
		Recommendation: a.recommendationFor(sink.RuleID),
		CWEID:       a.cweFor(sink.RuleID),
		DetectedAt:  time.Now(),
	}
}

func (a *Analyzer) instrPos(instr ssa.Instruction) token.Pos {
	if instr == nil {
		return token.NoPos
	}
	return instr.Pos()
}

func (a *Analyzer) fileName(pkg *packages.Package, pos token.Pos) string {
	if pos == token.NoPos {
		return ""
	}
	position := pkg.Fset.Position(pos)
	return position.Filename
}

func toAnalysisSeverity(s Severity) analysis.Severity {
	switch s {
	case SeverityHigh:
		return analysis.SeverityHigh
	case SeverityMedium:
		return analysis.SeverityMedium
	case SeverityLow:
		return analysis.SeverityLow
	default:
		return analysis.SeverityMedium
	}
}

func (a *Analyzer) recommendationFor(ruleID string) string {
	switch ruleID {
	case "G701":
		return "Use parameterized queries (prepared statements) instead of string concatenation for SQL queries"
	case "G702":
		return "Use exec.Command with a fixed program name and pass arguments as a slice, not through a shell"
	case "G703":
		return "Validate and sanitize file paths. Use filepath.Clean() and ensure paths stay within allowed directories"
	case "G704":
		return "Validate and restrict URLs to allowed hosts before making HTTP requests"
	case "G705":
		return "Validate redirect URLs against an allowlist of trusted destinations"
	case "G706":
		return "Sanitize log input to prevent log injection (strip newlines, control characters)"
	case "G708":
		return "Do not pass user input directly to template execution. Use html/template for auto-escaping"
	case "G709":
		return "Escape tainted data before writing to HTTP response. Use html.EscapeString or html/template"
	case "G710":
		return "Validate and sanitize input before deserialization. Consider using safe serialization formats"
	default:
		return "Review the data flow and ensure proper input validation"
	}
}

func (a *Analyzer) cweFor(ruleID string) string {
	switch ruleID {
	case "G701":
		return "CWE-89"
	case "G702":
		return "CWE-78"
	case "G703":
		return "CWE-22"
	case "G704":
		return "CWE-918"
	case "G705":
		return "CWE-601"
	case "G706":
		return "CWE-117"
	case "G708":
		return "CWE-1336"
	case "G709":
		return "CWE-79"
	case "G710":
		return "CWE-502"
	default:
		return ""
	}
}

// RuleInfo provides metadata about a taint rule for listing purposes.
type RuleInfo struct {
	ID       string
	Title    string
	Severity string
}

// Rules returns metadata for all registered taint rules.
func (a *Analyzer) Rules() []RuleInfo {
	var infos []RuleInfo
	seen := make(map[string]bool)
	for _, s := range a.sinks {
		if seen[s.RuleID] {
			continue
		}
		seen[s.RuleID] = true
		infos = append(infos, RuleInfo{
			ID:       s.RuleID,
			Title:    s.Title,
			Severity: severityToString(s.Severity),
		})
	}
	return infos
}

func severityToString(s Severity) string {
	switch s {
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

// Ensure unused imports are referenced
var _ = types.Universe
