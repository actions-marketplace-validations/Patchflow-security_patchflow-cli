package sast

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	fwpatterns "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func TestSuppressTaintWithSafePatterns_SuppressesWhenPatternInSameFunction(t *testing.T) {
	// Create a temp file with two functions: one with safe pattern, one without
	dir := t.TempDir()
	src := `public class App {
    public String search(String q) {
        LegacySql.run("SELECT * FROM users WHERE name = '" + q + "'");
        return "result";
    }

    public String safeSearch(String q) {
        TenantAuth.requireOwner();
        LegacySql.run("SELECT * FROM users WHERE name = '" + q + "'");
        return "result";
    }
}`
	path := filepath.Join(dir, "App.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []analysis.Finding{
		{RuleID: "PF-SPRING-SQLI-004", Analyzer: "taint-patterns", FilePath: path, LineStart: 3},
		{RuleID: "PF-SPRING-SQLI-004", Analyzer: "taint-patterns", FilePath: path, LineStart: 8},
	}

	safePatterns := map[string][]fwpatterns.SafePattern{
		"PF-SPRING-SQLI-004": {
			{Regex: regexp.MustCompile(`TenantAuth\.requireOwner`), Reason: "Ownership validation"},
		},
	}

	result := suppressTaintWithSafePatterns(findings, safePatterns, dir)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (1 suppressed), got %d", len(result))
	}
	if result[0].LineStart != 3 {
		t.Errorf("expected remaining finding at line 3 (unsafe), got line %d", result[0].LineStart)
	}
}

func TestSuppressTaintWithSafePatterns_NoSuppressionWhenPatternInDifferentFunction(t *testing.T) {
	dir := t.TempDir()
	src := `public class App {
    public String helper() {
        TenantAuth.requireOwner();
        return "ok";
    }

    public String search(String q) {
        LegacySql.run("SELECT * FROM users WHERE name = '" + q + "'");
        return "result";
    }
}`
	path := filepath.Join(dir, "App.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []analysis.Finding{
		{RuleID: "PF-SPRING-SQLI-004", Analyzer: "taint-patterns", FilePath: path, LineStart: 8},
	}

	safePatterns := map[string][]fwpatterns.SafePattern{
		"PF-SPRING-SQLI-004": {
			{Regex: regexp.MustCompile(`TenantAuth\.requireOwner`), Reason: "Ownership validation"},
		},
	}

	result := suppressTaintWithSafePatterns(findings, safePatterns, dir)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (safe pattern in different function), got %d", len(result))
	}
}

func TestSuppressTaintWithSafePatterns_NoSafePatterns(t *testing.T) {
	findings := []analysis.Finding{
		{RuleID: "PF-SPRING-SQLI-004", Analyzer: "taint-patterns", FilePath: "App.java", LineStart: 3},
	}
	result := suppressTaintWithSafePatterns(findings, nil, "")
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (no safe patterns map), got %d", len(result))
	}
}

func TestSuppressTaintWithSafePatterns_NonTaintFindingsNotAffected(t *testing.T) {
	dir := t.TempDir()
	src := `public class App {
    public String search(String q) {
        TenantAuth.requireOwner();
        LegacySql.run(q);
        return "result";
    }
}`
	path := filepath.Join(dir, "App.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []analysis.Finding{
		{RuleID: "PF-SPRING-SQLI-004", Analyzer: "patterns-embedded", FilePath: path, LineStart: 4},
	}

	safePatterns := map[string][]fwpatterns.SafePattern{
		"PF-SPRING-SQLI-004": {
			{Regex: regexp.MustCompile(`TenantAuth\.requireOwner`), Reason: "Ownership validation"},
		},
	}

	result := suppressTaintWithSafePatterns(findings, safePatterns, dir)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (non-taint not affected), got %d", len(result))
	}
}

func TestSuppressTaintWithSafePatterns_FileNotFound(t *testing.T) {
	findings := []analysis.Finding{
		{RuleID: "PF-SPRING-SQLI-004", Analyzer: "taint-patterns", FilePath: "/nonexistent/file.java", LineStart: 3},
	}
	safePatterns := map[string][]fwpatterns.SafePattern{
		"PF-SPRING-SQLI-004": {
			{Regex: regexp.MustCompile(`TenantAuth`), Reason: "test"},
		},
	}
	result := suppressTaintWithSafePatterns(findings, safePatterns, "")
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (file not found, no suppression), got %d", len(result))
	}
}

func TestSafePatternMatchesInRange(t *testing.T) {
	lines := []string{
		"line 1",
		"TenantAuth.requireOwner()",
		"line 3",
		"line 4",
		"line 5",
	}
	re := regexp.MustCompile(`TenantAuth`)

	if !safePatternMatchesInRange(re, lines, 2, 2) {
		t.Error("expected match at line 2")
	}
	if safePatternMatchesInRange(re, lines, 3, 5) {
		t.Error("expected no match in lines 3-5")
	}
	if !safePatternMatchesInRange(re, lines, 1, 5) {
		t.Error("expected match in range 1-5 (includes line 2)")
	}
}

// TestSuppressTaintWithSafePatterns_InterproceduralIPSuffix verifies that safe
// patterns registered against a base rule ID (e.g., PF-FASTAPI-SQLI-002) also
// suppress interprocedural variants whose rule ID carries the "-IP" suffix
// (e.g., PF-FASTAPI-SQLI-002-IP). This is the real-world scenario from
// Safe-pip-backend where ORM `select(Model).where(Model.col == value)` produced
// PF-FASTAPI-SQLI-002-IP false positives that a `select(` safe pattern should
// have suppressed but didn't, because the map lookup used the suffixed ID.
func TestSuppressTaintWithSafePatterns_InterproceduralIPSuffix(t *testing.T) {
	dir := t.TempDir()
	// Python fixture: a function that uses parameterized SQLAlchemy ORM select()
	// — textbook-safe — but the taint engine flagged it as PF-FASTAPI-SQLI-002-IP.
	src := `async def get_review(db, repo, pr_number, head_sha):
    stmt = select(PrReview).where(
        PrReview.repository == repo,
        PrReview.pr_number == pr_number,
    )
    result = await db.execute(stmt)
    return result.scalars().first()
`
	path := filepath.Join(dir, "pr_reviews.py")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	// Finding carries the -IP suffix (interprocedural variant).
	findings := []analysis.Finding{
		{RuleID: "PF-FASTAPI-SQLI-002-IP", Analyzer: "taint-patterns", FilePath: path, LineStart: 6},
	}

	// Safe pattern registered against the BASE rule ID (no -IP suffix).
	// select( is the ORM parameterization marker.
	safePatterns := map[string][]fwpatterns.SafePattern{
		"PF-FASTAPI-SQLI-002": {
			{Regex: regexp.MustCompile(`select\(`), Reason: "SQLAlchemy ORM select() parameterizes comparisons"},
		},
	}

	result := suppressTaintWithSafePatterns(findings, safePatterns, dir)
	if len(result) != 0 {
		t.Fatalf("expected 0 findings (IP variant suppressed by base-ID safe pattern), got %d: %+v", len(result), result)
	}
}

// TestSuppressTaintWithSafePatterns_IPVariantKeepsWhenNoSafePattern confirms
// that -IP findings are still reported when no safe pattern matches — the fix
// only changes the lookup key, not the suppression logic.
func TestSuppressTaintWithSafePatterns_IPVariantKeepsWhenNoSafePattern(t *testing.T) {
	dir := t.TempDir()
	src := `async def get_review(db, user_input):
    await db.execute(text(f"SELECT * FROM t WHERE x = '{user_input}'"))
    return None
`
	path := filepath.Join(dir, "unsafe.py")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []analysis.Finding{
		{RuleID: "PF-FASTAPI-SQLI-002-IP", Analyzer: "taint-patterns", FilePath: path, LineStart: 2},
	}

	// Safe pattern that does NOT match this function.
	safePatterns := map[string][]fwpatterns.SafePattern{
		"PF-FASTAPI-SQLI-002": {
			{Regex: regexp.MustCompile(`select\(`), Reason: "ORM parameterization"},
		},
	}

	result := suppressTaintWithSafePatterns(findings, safePatterns, dir)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (no safe pattern match, IP variant kept), got %d", len(result))
	}
	if result[0].RuleID != "PF-FASTAPI-SQLI-002-IP" {
		t.Errorf("expected PF-FASTAPI-SQLI-002-IP, got %s", result[0].RuleID)
	}
}
