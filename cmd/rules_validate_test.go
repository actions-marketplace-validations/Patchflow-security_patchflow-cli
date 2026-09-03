package cmd

import (
	"regexp"
	"testing"
)

// TestIDPattern_MultiHyphen verifies that the rule ID regex accepts multi-hyphen
// IDs (e.g., MYAPP-XSS-001) as documented in docs/reference/yaml-policy.md.
// The previous regex ^[A-Z][A-Z0-9]{2,}-[A-Z0-9]+$ only allowed a single hyphen,
// rejecting the documented example MYAPP-XSS-001.
func TestIDPattern_MultiHyphen(t *testing.T) {
	tests := []struct {
		id      string
		wantOK  bool
	}{
		// Valid: single hyphen (backward compatible)
		{"CUSTOM-001", true},
		{"SQL-INJECTION", true},
		{"SAFEP-001", true},
		// Valid: multi-hyphen (the fix — matches docs examples)
		{"MYAPP-XSS-001", true},
		{"SAFEP-SECRET-001", true},
		{"TEAM-SEC-002", true},
		{"PF-FASTAPI-SQLI-001", true},
		// Invalid: too short first segment
		{"A-001", false},
		{"AB-001", true}, // exactly 2 chars in first segment is allowed
		// Invalid: lowercase
		{"custom-001", false},
		{"Custom-001", false},
		// Invalid: no hyphen
		{"CUSTOM001", false},
		// Invalid: empty
		{"", false},
		// Invalid: starts with digit
		{"1CUSTOM-001", false},
		// Invalid: trailing hyphen
		{"CUSTOM-", false},
		// Invalid: double hyphen
		{"CUSTOM--001", false},
	}
	for _, tt := range tests {
		got := idPattern.MatchString(tt.id)
		if got != tt.wantOK {
			t.Errorf("idPattern.MatchString(%q) = %v, want %v", tt.id, got, tt.wantOK)
		}
	}
}

// TestIDPattern_CompiledOnce verifies the pattern compiles without error
// (regression guard against regex syntax errors in the pattern itself).
func TestIDPattern_CompiledOnce(t *testing.T) {
	re := regexp.MustCompile(idPattern.String())
	if re == nil {
		t.Fatal("idPattern failed to compile")
	}
}
