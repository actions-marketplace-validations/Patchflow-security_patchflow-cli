package angular

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func scanFixture(t *testing.T, name, content string) []analysis.Finding {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, name)
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := frameworks.NewMatcher(New().Rules()).ScanFile(target, root)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func hasFinding(findings []analysis.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestAngularPackContract(t *testing.T) {
	pack := New()
	if pack.Name() != "angular" || pack.Language() != "typescript" {
		t.Fatalf("unexpected pack identity: %s/%s", pack.Name(), pack.Language())
	}
	if len(pack.Rules()) == 0 || len(pack.Sources()) == 0 || len(pack.TemplateExtensions()) == 0 {
		t.Fatal("pack contract should expose rules, sources, and templates")
	}
}

func TestAngularBypassSecurityTrustVulnerable(t *testing.T) {
	findings := scanFixture(t, "component.ts", `this.html = this.sanitizer.bypassSecurityTrustHtml(this.route.queryParams["html"]);`)
	if !hasFinding(findings, "PF-ANGULAR-XSS-001") {
		t.Fatalf("expected XSS finding, got %+v", findings)
	}
}

func TestAngularTemplateInnerHTMLVulnerable(t *testing.T) {
	findings := scanFixture(t, "component.html", `<div [innerHTML]="html"></div>`)
	if !hasFinding(findings, "PF-ANGULAR-XSS-002") {
		t.Fatalf("expected innerHTML finding, got %+v", findings)
	}
}

func TestAngularNormalInterpolationSafe(t *testing.T) {
	findings := scanFixture(t, "component.html", `<div>{{ html }}</div>`)
	if hasFinding(findings, "PF-ANGULAR-XSS-002") {
		t.Fatalf("normal interpolation should not trigger innerHTML rule: %+v", findings)
	}
}

func TestAngularBypassSecurityTrustConstantSafe(t *testing.T) {
	findings := scanFixture(t, "component.ts", `this.html = this.sanitizer.bypassSecurityTrustHtml("<p>static content</p>");`)
	if hasFinding(findings, "PF-ANGULAR-XSS-001") {
		t.Fatalf("constant string should not trigger XSS rule: %+v", findings)
	}
}

func TestAngularDOMPurifySanitizedSafe(t *testing.T) {
	findings := scanFixture(t, "component.ts", `this.html = DOMPurify.sanitize(this.route.queryParams["html"]);`)
	if hasFinding(findings, "PF-ANGULAR-XSS-001") {
		t.Fatalf("DOMPurify sanitizer should not trigger XSS rule: %+v", findings)
	}
}

func TestAngularRedirectVulnerable(t *testing.T) {
	findings := scanFixture(t, "component.ts", `this.router.navigateByUrl(this.route.queryParams["redirect"]);`)
	if !hasFinding(findings, "PF-ANGULAR-REDIRECT-001") {
		t.Fatalf("expected redirect finding, got %+v", findings)
	}
}

func TestAngularRedirectStaticPathSafe(t *testing.T) {
	findings := scanFixture(t, "component.ts", `this.router.navigateByUrl("/dashboard");`)
	if hasFinding(findings, "PF-ANGULAR-REDIRECT-001") {
		t.Fatalf("static path should not trigger redirect rule: %+v", findings)
	}
}

func TestAngularRuleMaturityAndSeverity(t *testing.T) {
	// Pattern/template rules should be Beta; MatchTaint rules are promoted
	// to Beta after smoke test validation.
	for _, rule := range New().Rules() {
		if rule.MatchMode == frameworks.MatchTaint {
			if rule.Maturity != frameworks.MaturityBeta {
				t.Fatalf("taint rule %s maturity = %s, want beta", rule.ID, rule.Maturity)
			}
		} else {
			if rule.Maturity != frameworks.MaturityBeta {
				t.Fatalf("rule %s maturity = %s, want beta", rule.ID, rule.Maturity)
			}
		}
	}
	for _, rule := range New().Rules() {
		if rule.ID == "PF-ANGULAR-REDIRECT-001" {
			if rule.Severity == analysis.SeverityHigh || rule.Severity == analysis.SeverityCritical {
				t.Fatalf("redirect rule severity = %s, want medium (not high/critical)", rule.ID)
			}
			if rule.Severity != analysis.SeverityMedium {
				t.Fatalf("redirect rule severity = %v, want medium", rule.Severity)
			}
		}
	}
}

func TestAngularTaintRuleCount(t *testing.T) {
	pack := New()
	taintCount := 0
	for _, rule := range pack.Rules() {
		if rule.MatchMode == frameworks.MatchTaint {
			taintCount++
		}
	}
	if taintCount < 2 {
		t.Fatalf("expected at least 2 MatchTaint rules, got %d", taintCount)
	}
}

func TestAngularSourceCoverage(t *testing.T) {
	pack := New()
	// Verify key Angular source patterns are present
	sourceNames := map[string]bool{}
	for _, s := range pack.Sources() {
		sourceNames[s.FuncName] = true
	}
	required := []string{
		"route.snapshot.paramMap",
		"route.snapshot.queryParams",
		"route.queryParams",
		"route.params",
		"FormControl.value",
		"FormGroup.value",
		"@Input",
	}
	for _, req := range required {
		if !sourceNames[req] {
			t.Errorf("missing source pattern: %s", req)
		}
	}
}

func TestAngularSinkCoverage(t *testing.T) {
	pack := New()
	// Verify key Angular sink patterns are present
	sinkNames := map[string]bool{}
	for _, s := range pack.Sinks() {
		sinkNames[s.FuncName] = true
	}
	required := []string{
		"bypassSecurityTrustHtml",
		"bypassSecurityTrustUrl",
		"bypassSecurityTrustResourceUrl",
		"innerHTML",
		"nativeElement.innerHTML",
		"insertAdjacentHTML",
		"navigateByUrl",
		"window.location",
		"document.location",
	}
	for _, req := range required {
		if !sinkNames[req] {
			t.Errorf("missing sink pattern: %s", req)
		}
	}
}
