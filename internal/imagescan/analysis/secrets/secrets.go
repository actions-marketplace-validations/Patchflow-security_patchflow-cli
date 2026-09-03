// Package secrets scans image filesystems and configuration for hard-coded
// secrets. It only stores redacted evidence and SHA-256 hashes of the raw
// secret material; raw values are never logged or returned.
package secrets

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// Finding is a secret match before normalization to model.Finding.
type Finding struct {
	RuleID       string
	Path         string
	LayerDigest  string
	StartLine    int
	EndLine      int
	RedactedText string
	Confidence   int
	Entropy      float64
	Hash         string // SHA-256 of the raw secret
}

// Scanner runs a configurable rule set against filesystem content and image
// configuration.
type Scanner struct {
	content  []*contentRule
	pkHeader *regexp.Regexp
	pkFooter *regexp.Regexp
}

// New returns a Scanner with the default secret rules.
func New() *Scanner {
	return &Scanner{
		content:  defaultContentRules(),
		pkHeader: regexp.MustCompile(`(?i)^-----BEGIN (?:RSA|DSA|EC|OPENSSH)? ?PRIVATE KEY-----$`),
		pkFooter: regexp.MustCompile(`(?i)^-----END (?:RSA|DSA|EC|OPENSSH)? ?PRIVATE KEY-----$`),
	}
}

// Analyze scans all files in fs plus image config ENV and Labels for secrets.
func (s *Scanner) Analyze(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig) ([]model.Finding, error) {
	var raw []Finding

	if fs != nil {
		err := fs.Walk("/", func(e *model.FileEntry) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if e.IsDeleted || e.IsDir || e.IsSymlink {
				return nil
			}
			rc, err := fs.Open(e.Path)
			if err != nil {
				return nil
			}
			ff, err := s.scanFile(e.Path, e.LayerDigest, rc)
			_ = rc.Close()
			if err != nil {
				return err
			}
			raw = append(raw, ff...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	if cfg != nil {
		raw = append(raw, s.scanEnv(cfg.Env)...)
		raw = append(raw, s.scanLabels(cfg.Labels)...)
	}

	out := make([]model.Finding, 0, len(raw))
	for _, f := range raw {
		out = append(out, toModel(f))
	}
	return out, nil
}

// scanFile scans a single file line by line without loading the whole file
// into memory.
func (s *Scanner) scanFile(path, layer string, r io.Reader) ([]Finding, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var lineNum int
	var inKey bool
	var keyStart int
	var keyLines []string
	var findings []Finding

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if !inKey {
			for _, rule := range s.content {
				findings = append(findings, rule.find(line, lineNum, path, layer)...)
			}
			if s.pkHeader.MatchString(line) {
				inKey = true
				keyStart = lineNum
				keyLines = []string{line}
			}
			continue
		}

		keyLines = append(keyLines, line)
		if s.pkFooter.MatchString(line) {
			secret := strings.Join(keyLines, "\n")
			redacted := keyLines[0] + "\n****\n" + line
			findings = append(findings, Finding{
				RuleID:       "private-key",
				Path:         path,
				LayerDigest:  layer,
				StartLine:    keyStart,
				EndLine:      lineNum,
				RedactedText: redacted,
				Confidence:   90,
				Entropy:      0,
				Hash:         hash(secret),
			})
			inKey = false
			keyLines = nil
		}
	}

	if inKey {
		secret := strings.Join(keyLines, "\n")
		redacted := keyLines[0] + "\n****"
		findings = append(findings, Finding{
			RuleID:       "private-key",
			Path:         path,
			LayerDigest:  layer,
			StartLine:    keyStart,
			EndLine:      lineNum,
			RedactedText: redacted,
			Confidence:   90,
			Entropy:      0,
			Hash:         hash(secret),
		})
	}

	return findings, scanner.Err()
}

func (s *Scanner) scanEnv(env []string) []Finding {
	var out []Finding
	for _, e := range env {
		key, _, _ := strings.Cut(e, "=")
		out = append(out, s.scanText("env:"+key, "", e)...)
	}
	return out
}

func (s *Scanner) scanLabels(labels map[string]string) []Finding {
	var out []Finding
	for k, v := range labels {
		out = append(out, s.scanText("label:"+k, "", k+"="+v)...)
	}
	return out
}

func (s *Scanner) scanText(path, layer, text string) []Finding {
	var out []Finding
	for _, rule := range s.content {
		out = append(out, rule.find(text, 1, path, layer)...)
	}
	return out
}

type contentRule struct {
	id         string
	severity   model.Severity
	confidence int
	re         *regexp.Regexp
	secretIdx  int
	entropyMin float64
}

func (r *contentRule) find(line string, lineNum int, path, layer string) []Finding {
	matches := r.re.FindAllStringSubmatchIndex(line, -1)
	var out []Finding
	for _, m := range matches {
		if r.secretIdx*2 >= len(m) {
			continue
		}
		full := line[m[0]:m[1]]
		secret := line[m[r.secretIdx*2]:m[r.secretIdx*2+1]]
		if r.entropyMin > 0 && entropy(secret) <= r.entropyMin {
			continue
		}
		redacted := full
		if secret != "" {
			redacted = strings.Replace(redacted, secret, "****", 1)
		}
		out = append(out, Finding{
			RuleID:       r.id,
			Path:         path,
			LayerDigest:  layer,
			StartLine:    lineNum,
			EndLine:      lineNum,
			RedactedText: redacted,
			Confidence:   r.confidence,
			Entropy:      entropy(secret),
			Hash:         hash(secret),
		})
	}
	return out
}

func defaultContentRules() []*contentRule {
	return []*contentRule{
		{
			id:         "aws-access-key",
			severity:   model.SeverityHigh,
			confidence: 90,
			re:         regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
			secretIdx:  1,
		},
		{
			id:         "aws-secret-key",
			severity:   model.SeverityHigh,
			confidence: 90,
			re:         regexp.MustCompile(`(?i)(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40}|[0-9a-f]{40})`),
			secretIdx:  1,
		},
		{
			id:         "github-token",
			severity:   model.SeverityHigh,
			confidence: 90,
			re:         regexp.MustCompile(`(?i)(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{59,})`),
			secretIdx:  1,
		},
		{
			id:         "generic-high-entropy",
			severity:   model.SeverityMedium,
			confidence: 40,
			re:         regexp.MustCompile(`(?i)(?:api_key|token|secret|password|credential)s?[^=\n]*[:=]\s*["']?([A-Za-z0-9+/=]{40,}|[0-9a-f]{40,})`),
			secretIdx:  1,
			entropyMin: 4.5,
		},
		{
			id:         "generic-secret",
			severity:   model.SeverityMedium,
			confidence: 50,
			re:         regexp.MustCompile(`(?i)(SECRET|TOKEN|API_KEY|PASSWORD)s?[^=\n]*[:=]\s*["']?([A-Za-z0-9+/=]{16,}|[0-9a-f]{16,})`),
			secretIdx:  2,
			entropyMin: 3.0,
		},
	}
}

func toModel(f Finding) model.Finding {
	return model.Finding{
		ID:          makeID(f),
		Type:        model.FindingTypeSecret,
		Severity:    severityForRule(f.RuleID),
		Confidence:  model.Confidence(f.Confidence),
		Title:       fmt.Sprintf("Secret detected: %s", f.RuleID),
		Description: f.RedactedText,
		LayerDigest: f.LayerDigest,
		Locations:   []model.Location{{Path: f.Path, LayerDigest: f.LayerDigest}},
		Evidence: []model.Evidence{
			{Source: "secrets", MatchField: "rule_id", MatchValue: f.RuleID},
			{Source: "secrets", MatchField: "path", MatchValue: f.Path},
			{Source: "secrets", MatchField: "lines", MatchValue: fmt.Sprintf("%d-%d", f.StartLine, f.EndLine)},
			{Source: "secrets", MatchField: "entropy", MatchValue: strconv.FormatFloat(f.Entropy, 'f', 2, 64)},
			{Source: "secrets", MatchField: "hash", MatchValue: f.Hash},
		},
		DetectedAt: time.Now(),
	}
}

func makeID(f Finding) string {
	h := sha256.Sum256([]byte(f.RuleID + "|" + f.Path + "|" + strconv.Itoa(f.StartLine) + "|" + f.Hash))
	return fmt.Sprintf("%x", h)[:16]
}

func severityForRule(id string) model.Severity {
	switch id {
	case "aws-access-key", "aws-secret-key", "github-token", "private-key":
		return model.SeverityHigh
	case "generic-secret":
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int, len(s))
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

func hash(s string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}
