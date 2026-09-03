// Package licensedetect implements text-based license detection by comparing
// LICENSE file content against known license templates. This is used as a
// final fallback when registry API lookups (npm, PyPI, Maven, RubyGems, GitHub
// API) fail to return a license.
//
// The approach is similar to GitHub's licensee:
//  1. Normalize the license text (lowercase, strip whitespace/punctuation,
//     remove copyright lines).
//  2. Extract n-grams (bigrams) from the normalized text.
//  3. Compare against a database of known license signatures using Dice's
//     coefficient (Sørensen–Dice similarity).
//  4. Return the best match if similarity exceeds a threshold.
package licensedetect

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

// minConfidence is the minimum Dice's coefficient required to accept a match.
const minConfidence = 0.50

// LicenseMatch holds the result of a license detection.
type LicenseMatch struct {
	SPDXID    string  // SPDX identifier (e.g., "MIT", "Apache-2.0")
	Name      string  // Human-readable name
	Confidence float64 // Similarity score (0.0 to 1.0)
}

// LicenseSignature represents a known license template for matching.
type LicenseSignature struct {
	SPDXID string
	Name   string
	// keyPhrases are distinctive substrings that uniquely identify this license.
	// We check these first for a fast path before doing n-gram comparison.
	keyPhrases []string
	// templateBigrams are pre-computed bigrams from the normalized license text.
	templateBigrams map[string]bool
}

// Detect identifies the license from the given file content. It returns the
// best match if confidence >= minConfidence, or nil if no match.
func Detect(content string) *LicenseMatch {
	normalized := normalize(content)
	if len(normalized) < 50 {
		return nil
	}

	contentBigrams := extractBigrams(normalized)
	if len(contentBigrams) == 0 {
		return nil
	}

	// Fast path: check key phrases first
	type score struct {
		sig       *LicenseSignature
		confidence float64
	}
	var scores []score

	for i := range signatures {
		sig := &signatures[i]

		// Fast path: check if any key phrase is present
		phraseMatch := false
		for _, phrase := range sig.keyPhrases {
			if strings.Contains(normalized, phrase) {
				phraseMatch = true
				break
			}
		}

		if phraseMatch {
			// Confirm with n-gram similarity
			dice := diceCoefficient(contentBigrams, sig.templateBigrams)
			if dice >= minConfidence {
				scores = append(scores, score{sig: sig, confidence: dice})
			}
		} else {
			// Also check n-gram similarity for licenses that might not
			// have a key phrase match but are still close
			dice := diceCoefficient(contentBigrams, sig.templateBigrams)
			if dice >= minConfidence+0.15 { // Higher threshold without phrase match
				scores = append(scores, score{sig: sig, confidence: dice})
			}
		}
	}

	if len(scores) == 0 {
		return nil
	}

	// Sort by confidence descending
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].confidence > scores[j].confidence
	})

	best := scores[0]
	return &LicenseMatch{
		SPDXID:    best.sig.SPDXID,
		Name:      best.sig.Name,
		Confidence: best.confidence,
	}
}

// normalize prepares license text for comparison by:
//   - Converting to lowercase
//   - Removing copyright lines (they vary between projects)
//   - Removing all non-alphanumeric characters (keeping spaces)
//   - Collapsing multiple spaces
//   - Trimming leading/trailing whitespace
func normalize(text string) string {
	var sb strings.Builder
	sb.Grow(len(text))

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		// Skip copyright lines — they contain project-specific names/dates
		// and would reduce matching accuracy
		if isCopyrightLine(lower) {
			continue
		}

		// Process character by character
		for _, r := range lower {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				sb.WriteRune(r)
			} else if unicode.IsSpace(r) {
				sb.WriteRune(' ')
			}
			// Drop all other punctuation
		}
		sb.WriteRune(' ')
	}

	result := sb.String()
	// Collapse multiple spaces
	for strings.Contains(result, "  ") {
		result = strings.ReplaceAll(result, "  ", " ")
	}
	return strings.TrimSpace(result)
}

// isCopyrightLine returns true if the line is a copyright notice that should
// be excluded from matching (it contains project-specific information).
func isCopyrightLine(lower string) bool {
	if strings.Contains(lower, "copyright") {
		return true
	}
	if strings.Contains(lower, "all rights reserved") {
		return true
	}
	if strings.Contains(lower, "(c)") {
		return true
	}
	// Match "©" symbol
	if strings.Contains(lower, "©") {
		return true
	}
	return false
}

// extractBigrams returns a set of bigrams (2-character sequences) from the
// normalized text. Bigrams are used for Dice's coefficient comparison.
func extractBigrams(normalized string) map[string]bool {
	if len(normalized) < 2 {
		return nil
	}
	bigrams := make(map[string]bool, len(normalized))
	for i := 0; i < len(normalized)-1; i++ {
		bigrams[normalized[i:i+2]] = true
	}
	return bigrams
}

// diceCoefficient computes the Sørensen–Dice similarity coefficient between
// two bigram sets. Returns a value between 0.0 (no overlap) and 1.0 (identical).
func diceCoefficient(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	intersection := 0
	// Iterate over the smaller set for efficiency
	small, large := a, b
	if len(b) < len(a) {
		small, large = b, a
	}
	for k := range small {
		if large[k] {
			intersection++
		}
	}

	return float64(2*intersection) / float64(len(a)+len(b))
}

// round rounds a float64 to the given precision.
func round(x float64, precision int) float64 {
	pow := math.Pow(10, float64(precision))
	return math.Round(x*pow) / pow
}
