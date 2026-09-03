package angular

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

func Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		{
			ID:             "PF-ANGULAR-XSS-001",
			Framework:      "angular",
			Language:       "typescript",
			CWE:            "CWE-79",
			Title:          "Angular XSS: bypassSecurityTrustHtml with route data",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".ts"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`bypassSecurityTrust(Html|Url|ResourceUrl)\s*\([^)]*(queryParams|paramMap|ActivatedRoute|location|route\.)`),
			Sanitizers:     Sanitizers,
			SafePatterns: []frameworks.SafePattern{
				{Regex: regexp.MustCompile(`DOMPurify\.sanitize`), Reason: "DOMPurify.sanitize on the same line neutralizes the bypass."},
				{Regex: regexp.MustCompile(`sanitizer\.sanitize`), Reason: "Angular DomSanitizer.sanitize on the same line neutralizes the bypass."},
			},
			Recommendation: "Avoid bypassSecurityTrust* for route-controlled data. Use normal Angular bindings or sanitize explicitly.",
		},
		{
			ID:             "PF-ANGULAR-XSS-002",
			Framework:      "angular",
			Language:       "typescript",
			CWE:            "CWE-79",
			Title:          "Angular template XSS: innerHTML binding",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			TemplateTypes:  []string{".html"},
			MatchMode:      frameworks.MatchTemplate,
			Pattern:        regexp.MustCompile(`\[innerHTML\]\s*=`),
			Sanitizers:     Sanitizers,
			Recommendation: "Avoid binding user-controlled values to innerHTML unless they are sanitized.",
		},
		{
			ID:             "PF-ANGULAR-REDIRECT-001",
			Framework:      "angular",
			Language:       "typescript",
			CWE:            "CWE-601",
			Title:          "Angular open redirect: router navigation with route input",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".ts"},
			MatchMode:      frameworks.MatchPattern,
			Pattern:        regexp.MustCompile(`(navigateByUrl|window\.location|document\.location)\s*(\(|=)[^;]*(queryParams|paramMap|ActivatedRoute|location|route\.)`),
			Sanitizers:     Sanitizers,
			Recommendation: "Validate route-controlled navigation targets before client-side redirects.",
		},

		// === MatchTaint rules — source→sink taint tracking ===
		// These rules feed into the taintpatterns engine via ToTaintRules().
		// They enable detection of multi-step flows where route data passes
		// through variables before reaching a sink.

		{
			ID:             "PF-ANGULAR-XSS-003",
			Framework:      "angular",
			Language:       "typescript",
			CWE:            "CWE-79",
			Title:          "Angular XSS: route/form data flows to bypassSecurityTrust* or innerHTML",
			Severity:       analysis.SeverityHigh,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".ts"},
			MatchMode:      frameworks.MatchTaint,
			Sources:        Sources,
			Sinks: []frameworks.SinkPattern{
				{FuncName: "bypassSecurityTrustHtml", ArgIndex: 0},
				{FuncName: "bypassSecurityTrustUrl", ArgIndex: 0},
				{FuncName: "bypassSecurityTrustResourceUrl", ArgIndex: 0},
				{FuncName: "bypassSecurityTrustScript", ArgIndex: 0},
				{FuncName: "innerHTML", ArgIndex: -1},
				{FuncName: "nativeElement.innerHTML", ArgIndex: -1},
				{FuncName: "insertAdjacentHTML", ArgIndex: -1},
			},
			Sanitizers:     Sanitizers,
			Recommendation: "User-controlled data (route params, form values, @Input) flows into a DOM XSS sink. Use Angular's default interpolation or sanitize with DomSanitizer.sanitize().",
		},
		{
			ID:             "PF-ANGULAR-REDIRECT-002",
			Framework:      "angular",
			Language:       "typescript",
			CWE:            "CWE-601",
			Title:          "Angular open redirect: route data flows to router navigation",
			Severity:       analysis.SeverityMedium,
			Confidence:     analysis.ConfidenceMedium,
			Maturity:       frameworks.MaturityBeta,
			FileTypes:      []string{".ts"},
			MatchMode:      frameworks.MatchTaint,
			Sources:        Sources,
			Sinks: []frameworks.SinkPattern{
				{FuncName: "navigateByUrl", ArgIndex: 0},
				{FuncName: "navigate", ArgIndex: 0},
				{FuncName: "window.location", ArgIndex: -1},
				{FuncName: "document.location", ArgIndex: -1},
			},
			Sanitizers:     Sanitizers,
			Recommendation: "User-controlled route data flows into a navigation sink. Validate redirect targets against an allowlist.",
		},
	}
}
