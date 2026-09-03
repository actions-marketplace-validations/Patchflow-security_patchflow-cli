package rails

import (
	"regexp"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	
	"github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"
)

// Rules returns the Rails framework rules. Each rule is typed and carries
// governance maturity. Untested rules stay experimental and non-blocking
// until they gain vulnerable/safe/normal fixtures.
func (Pack) Rules() []frameworks.FrameworkRule {
	return []frameworks.FrameworkRule{
		// === XSS ===
		{
			ID:          "PF-RAILS-XSS-001",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-79",
			Title:       "Rails XSS: unescaped output via raw/html_safe",
			Severity:    analysis.SeverityHigh,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`\.(raw|html_safe)\b`),
			Sanitizers:  Sanitizers,
			Recommendation: "Avoid raw/html_safe on user-controlled data. Use the h() helper or ERB::Util.html_escape to escape output.",
		},
		{
			ID:          "PF-RAILS-XSS-002",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-79",
			Title:       "Rails XSS: render html: with user input",
			Severity:    analysis.SeverityHigh,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`render\s+(html|inline):\s*[^,]+\b(params|request|cookies)\b`),
			Sanitizers:  Sanitizers,
			Recommendation: "Do not render user input as raw HTML. Escape the input or use a template that auto-escapes.",
		},

		// === SQL injection ===
		{
			ID:          "PF-RAILS-SQLI-001",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-89",
			Title:       "Rails SQLi: find_by_sql with interpolated string",
			Severity:    analysis.SeverityHigh,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`find_by_sql\s*\(\s*(["'].*#\{|["'].*\+|<<)`),
			Sanitizers:  Sanitizers,
			Recommendation: "Use parameterized queries or the ActiveRecord query interface (where, find_by) with bound parameters.",
		},
		{
			ID:          "PF-RAILS-SQLI-002",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-89",
			Title:       "Rails SQLi: where with string interpolation",
			Severity:    analysis.SeverityHigh,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`\.where\s*\(\s*["'].*#\{`),
			Sanitizers:  []frameworks.SanitizerPattern{
				{FuncName: "sanitize_sql"},
				{FuncName: "sanitize_sql_array"},
				{FuncName: "sanitize_sql_for"},
				// Parameterized where("col = ?", val) is safe.
				{Regex: regexp.MustCompile(`\.where\s*\(\s*["'][^"']*["']\s*,`)},
			},
			Recommendation: "Use parameterized where clauses: where(\"col = ?\", value). Never interpolate user input into SQL strings.",
		},

		// === Open redirect ===
		{
			ID:          "PF-RAILS-REDIRECT-001",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-601",
			Title:       "Rails open redirect: redirect_to with user input",
			Severity:    analysis.SeverityMedium,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`redirect_to\s+(params|request|cookies)`),
			Sanitizers:  []frameworks.SanitizerPattern{
				{FuncName: "url_for"},
				{FuncName: "URI.parse"},
			},
			Recommendation: "Validate redirect targets against an allowlist of permitted hosts or use url_for with a constrained route.",
		},

		// === File disclosure ===
		{
			ID:          "PF-RAILS-FILE-001",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-73",
			Title:       "Rails file disclosure: send_file with user input",
			Severity:    analysis.SeverityHigh,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`send_file\s+(params|request|cookies)`),
			Recommendation: "Constrain send_file paths to a known directory and validate the basename. Never pass user input directly.",
		},

		// === Deserialization ===
		{
			ID:          "PF-RAILS-DESER-001",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-502",
			Title:       "Rails unsafe deserialization: YAML.load / Marshal.load",
			Severity:    analysis.SeverityHigh,
			Confidence:  analysis.ConfidenceHigh,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`\b(YAML\.load|Marshal\.load|Marshal\.restore)\s*\(`),
			SafePatterns: []frameworks.SafePattern{
				{Regex: regexp.MustCompile(`YAML\.safe_load`), Reason: "YAML.safe_load only permits simple types"},
			},
			Recommendation: "Use YAML.safe_load with an explicit allowlist of permitted classes. Avoid Marshal on untrusted data.",
		},

		// === Mass assignment ===
		{
			ID:          "PF-RAILS-MASS-001",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-915",
			Title:       "Rails mass assignment: permit! allows all attributes",
			Severity:    analysis.SeverityMedium,
			Confidence:  analysis.ConfidenceHigh,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`\.permit!\s*\(?`),
			Recommendation: "Use permit with an explicit field allowlist instead of permit!, which allows all attributes.",
		},

		// === Auth bypass ===
		{
			ID:          "PF-RAILS-AUTH-001",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-306",
			Title:       "Rails auth bypass: skip_before_action :authenticate_user!",
			Severity:    analysis.SeverityMedium,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`skip_before_action\s+:authenticate_user!`),
			Recommendation: "Only skip authentication on genuinely public actions. Document why and constrain the skip with only:/except:.",
		},

		// === Template XSS (ERB) ===
		{
			ID:          "PF-RAILS-XSS-003",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-79",
			Title:       "Rails template XSS: raw/html_safe in ERB",
			Severity:    analysis.SeverityHigh,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			TemplateTypes: []string{".erb", ".rhtml"},
			MatchMode:   frameworks.MatchTemplate,
			Pattern:     regexp.MustCompile(`<%=\s*(raw\s*\(|.*\.html_safe\b)`),
			Sanitizers:  Sanitizers,
			Recommendation: "In ERB, default output is escaped. Only use raw/html_safe for trusted static content, never for user input.",
		},

		// === Taint rules (feed the taint engine) ===
		{
			ID:          "PF-RAILS-SQLI-003",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-89",
			Title:       "Rails SQLi (taint): params -> find_by_sql/where string",
			Severity:    analysis.SeverityHigh,
			Confidence:  analysis.ConfidenceHigh,
			Maturity:    frameworks.MaturityBeta,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchTaint,
			Sources:     Sources,
			Sinks:       []frameworks.SinkPattern{
				{FuncName: "find_by_sql", ArgIndex: 0},
				{FuncName: "execute", ArgIndex: 0},
			},
			Sanitizers:  Sanitizers,
			Recommendation: "Use parameterized queries. Tainted request data reached a raw SQL sink.",
		},
		{
			ID:          "PF-RAILS-REDIRECT-002",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-601",
			Title:       "Rails open redirect (taint): params -> redirect_to",
			Severity:    analysis.SeverityMedium,
			Confidence:  analysis.ConfidenceHigh,
			Maturity:    frameworks.MaturityBeta,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchTaint,
			Sources:     Sources,
			Sinks:       []frameworks.SinkPattern{{FuncName: "redirect_to", ArgIndex: 0}},
			Sanitizers:  []frameworks.SanitizerPattern{{FuncName: "url_for"}, {FuncName: "URI.parse"}},
			Recommendation: "Validate redirect targets against an allowlist. Tainted request data reached redirect_to.",
		},

		// === Command injection ===
		{
			ID:          "PF-RAILS-CMDI-001",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-78",
			Title:       "Rails command injection: system/exec/backticks with params interpolation",
			Severity:    analysis.SeverityCritical,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`(system|exec|` + "`" + `)\s*\(?\s*.*#\{.*params`),
			Sanitizers:  Sanitizers,
			Recommendation: "Use system with separate arguments (system('cmd', arg1, arg2)) instead of string interpolation. Sanitize user input with Shellwords.escape.",
		},

		// === SSRF ===
		{
			ID:          "PF-RAILS-SSRF-001",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-918",
			Title:       "Rails SSRF: Net::HTTP/URI with user-controlled URL",
			Severity:    analysis.SeverityHigh,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`(Net::HTTP\.(get|post|start|new)|URI\.(parse|open))\s*\(?\s*.*#\{.*params`),
			Sanitizers:  Sanitizers,
			Recommendation: "Validate and restrict URLs before making HTTP requests. Use an allow-list of permitted domains and validate the URL scheme.",
		},

		// === Weak crypto ===
		{
			ID:          "PF-RAILS-CRYPTO-001",
			Framework:   "rails",
			Language:    "ruby",
			CWE:         "CWE-327",
			Title:       "Rails weak hash: MD5/SHA1 used for security-sensitive data",
			Severity:    analysis.SeverityHigh,
			Confidence:  analysis.ConfidenceMedium,
			Maturity:    frameworks.MaturityExperimental,
			FileTypes:   []string{".rb"},
			MatchMode:   frameworks.MatchPattern,
			Pattern:     regexp.MustCompile(`(?i)(Digest::(MD5|SHA1)\.(hexdigest|base64digest)|Digest::(MD5|SHA1)\.new)`),
			SafePatterns: []frameworks.SafePattern{
				{Regex: regexp.MustCompile(`(?i)(cache|checksum|etag|fingerprint)`), Reason: "MD5/SHA1 for non-security contexts (cache key, checksum, etag, fingerprint) is acceptable"},
			},
			Recommendation: "Use BCrypt or Argon2 for password hashing. MD5 and SHA1 are cryptographically broken and unsuitable for security purposes.",
		},
	}
}
