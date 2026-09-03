package misconfig

import (
	"context"
	"slices"
	"strconv"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

func TestAnalyzer_Analyze_AllFindings(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{
		WorkingDir:   "/",
		ExposedPorts: []string{"22/tcp"},
	}
	image := model.ImageIdentity{Tag: "latest"}

	findings, err := a.Analyze(context.Background(), cfg, image)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if len(findings) != 12 {
		t.Fatalf("expected 12 findings, got %d", len(findings))
	}

	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
		if f.Type != model.FindingTypeMisconfig {
			t.Errorf("finding %s has unexpected type %s", f.ID, f.Type)
		}
		if f.Description == "" {
			t.Errorf("finding %s has empty description", f.ID)
		}
	}
	for i := 1; i <= 12; i++ {
		want := ruleID(i)
		if !slices.Contains(ids, want) {
			t.Errorf("expected finding %s not returned", want)
		}
	}

	if f := findByID(findings, "PF-MISC-001"); f != nil && f.Severity != model.SeverityHigh {
		t.Errorf("PF-MISC-001 severity = %s, want HIGH", f.Severity)
	}
	if f := findByID(findings, "PF-MISC-008"); f != nil && f.Severity != model.SeverityHigh {
		t.Errorf("PF-MISC-008 severity = %s, want HIGH", f.Severity)
	}
	if f := findByID(findings, "PF-MISC-010"); f != nil && f.Severity != model.SeverityLow {
		t.Errorf("PF-MISC-010 severity = %s, want LOW", f.Severity)
	}
	if f := findByID(findings, "PF-MISC-011"); f != nil && f.Severity != model.SeverityLow {
		t.Errorf("PF-MISC-011 severity = %s, want LOW", f.Severity)
	}
}

func TestAnalyzer_Analyze_NoFindings(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{
		WorkingDir:   "/app",
		ExposedPorts: []string{"80/tcp", "443/tcp"},
		Labels: map[string]string{
			"org.opencontainers.image.title":         "app",
			"org.opencontainers.image.version":       "1.0.0",
			"org.opencontainers.image.description":   "app description",
			"org.opencontainers.image.licenses":      "MIT",
			"org.opencontainers.image.source":        "https://github.com/example/app",
			"org.opencontainers.image.vendor":        "example",
			"org.opencontainers.image.documentation": "https://docs.example.com/app",
		},
		StopSignal:  "SIGTERM",
		Healthcheck: &model.Healthcheck{Test: []string{"CMD", "curl", "-f", "http://localhost/health"}},
	}
	image := model.ImageIdentity{Tag: "v1.0.0"}

	findings, err := a.Analyze(context.Background(), cfg, image)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

func TestAnalyzer_LatestTag(t *testing.T) {
	a := New()

	cases := []struct {
		tag     string
		wantID  string
		wantHit bool
	}{
		{"latest", "PF-MISC-001", true},
		{"", "PF-MISC-001", true},
		{"v1.0.0", "", false},
		{"stable", "", false},
	}

	for _, tc := range cases {
		findings, err := a.Analyze(context.Background(), &model.ImageConfig{WorkingDir: "/app"}, model.ImageIdentity{Tag: tc.tag})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		got := findByID(findings, tc.wantID)
		if tc.wantHit && got == nil {
			t.Errorf("tag %q: expected finding %s", tc.tag, tc.wantID)
		}
		if !tc.wantHit && got != nil {
			t.Errorf("tag %q: unexpected finding %s", tc.tag, got.ID)
		}
	}
}

func TestAnalyzer_LabelRules(t *testing.T) {
	a := New()
	fullLabels := map[string]string{
		"org.opencontainers.image.title":         "app",
		"org.opencontainers.image.version":       "1.0.0",
		"org.opencontainers.image.description":   "desc",
		"org.opencontainers.image.licenses":      "MIT",
		"org.opencontainers.image.source":        "https://example.com/src",
		"org.opencontainers.image.vendor":        "example",
		"org.opencontainers.image.documentation": "https://example.com/docs",
	}

	labelRules := []struct {
		id  string
		key string
	}{
		{"PF-MISC-002", "org.opencontainers.image.title"},
		{"PF-MISC-003", "org.opencontainers.image.version"},
		{"PF-MISC-004", "org.opencontainers.image.description"},
		{"PF-MISC-005", "org.opencontainers.image.licenses"},
		{"PF-MISC-006", "org.opencontainers.image.source"},
		{"PF-MISC-007", "org.opencontainers.image.vendor"},
		{"PF-MISC-012", "org.opencontainers.image.documentation"},
	}

	for _, tc := range labelRules {
		labels := map[string]string{}
		for k, v := range fullLabels {
			if k != tc.key {
				labels[k] = v
			}
		}
		cfg := &model.ImageConfig{
			WorkingDir:   "/app",
			StopSignal:   "SIGTERM",
			Healthcheck:  &model.Healthcheck{Test: []string{"CMD", "true"}},
			Labels:       labels,
			ExposedPorts: []string{"8080/tcp"},
		}
		findings, err := a.Analyze(context.Background(), cfg, model.ImageIdentity{Tag: "v1.0.0"})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(findings) != 1 {
			t.Errorf("missing label %s: expected 1 finding, got %d", tc.key, len(findings))
		}
		if f := findByID(findings, tc.id); f == nil {
			t.Errorf("missing label %s: expected finding %s", tc.key, tc.id)
		}

		complete := copyLabels(fullLabels)
		complete[tc.key] = fullLabels[tc.key]
		cfg.Labels = complete
		findings, err = a.Analyze(context.Background(), cfg, model.ImageIdentity{Tag: "v1.0.0"})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("present label %s: expected 0 findings, got %d", tc.key, len(findings))
		}
	}
}

func TestAnalyzer_DangerousPorts(t *testing.T) {
	a := New()
	base := &model.ImageConfig{WorkingDir: "/app", StopSignal: "SIGTERM", Healthcheck: &model.Healthcheck{Test: []string{"CMD", "true"}}}
	image := model.ImageIdentity{Tag: "v1.0.0"}
	labels := map[string]string{
		"org.opencontainers.image.title":         "app",
		"org.opencontainers.image.version":       "1.0.0",
		"org.opencontainers.image.description":   "desc",
		"org.opencontainers.image.licenses":      "MIT",
		"org.opencontainers.image.source":        "src",
		"org.opencontainers.image.vendor":        "vendor",
		"org.opencontainers.image.documentation": "docs",
	}

	positive := []string{"22", "21/tcp", "23/udp", "3389", "5900/tcp"}
	for _, port := range positive {
		cfg := cloneConfig(base)
		cfg.Labels = labels
		cfg.ExposedPorts = []string{port}
		findings, err := a.Analyze(context.Background(), cfg, image)
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if f := findByID(findings, "PF-MISC-008"); f == nil {
			t.Errorf("port %q: expected PF-MISC-008", port)
		}
		if len(findings) != 1 {
			t.Errorf("port %q: expected 1 finding, got %d", port, len(findings))
		}
	}

	negative := []string{"80", "443", "8080", "8443", "not-a-port"}
	for _, port := range negative {
		cfg := cloneConfig(base)
		cfg.Labels = labels
		cfg.ExposedPorts = []string{port}
		findings, err := a.Analyze(context.Background(), cfg, image)
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if f := findByID(findings, "PF-MISC-008"); f != nil {
			t.Errorf("port %q: unexpected PF-MISC-008", port)
		}
	}
}

func TestAnalyzer_Healthcheck(t *testing.T) {
	a := New()
	base := baseConfig()
	image := model.ImageIdentity{Tag: "v1.0.0"}

	findings, err := a.Analyze(context.Background(), base, image)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if f := findByID(findings, "PF-MISC-009"); f != nil {
		t.Error("expected no PF-MISC-009 when healthcheck present")
	}

	missing := cloneConfig(base)
	missing.Healthcheck = nil
	findings, err = a.Analyze(context.Background(), missing, image)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if f := findByID(findings, "PF-MISC-009"); f == nil {
		t.Error("expected PF-MISC-009 when healthcheck missing")
	}

	empty := cloneConfig(base)
	empty.Healthcheck = &model.Healthcheck{}
	findings, err = a.Analyze(context.Background(), empty, image)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if f := findByID(findings, "PF-MISC-009"); f == nil {
		t.Error("expected PF-MISC-009 when healthcheck test is empty")
	}
}

func TestAnalyzer_WorkingDir(t *testing.T) {
	a := New()
	image := model.ImageIdentity{Tag: "v1.0.0"}

	for _, wd := range []string{"", "/"} {
		cfg := baseConfig()
		cfg.WorkingDir = wd
		findings, err := a.Analyze(context.Background(), cfg, image)
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if f := findByID(findings, "PF-MISC-010"); f == nil {
			t.Errorf("working dir %q: expected PF-MISC-010", wd)
		}
	}

	cfg := baseConfig()
	cfg.WorkingDir = "/app"
	findings, err := a.Analyze(context.Background(), cfg, image)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if f := findByID(findings, "PF-MISC-010"); f != nil {
		t.Error("expected no PF-MISC-010 when working dir is non-root")
	}
}

func TestAnalyzer_StopSignal(t *testing.T) {
	a := New()
	image := model.ImageIdentity{Tag: "v1.0.0"}

	cfg := baseConfig()
	cfg.StopSignal = ""
	findings, err := a.Analyze(context.Background(), cfg, image)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if f := findByID(findings, "PF-MISC-011"); f == nil {
		t.Error("expected PF-MISC-011 when stop signal missing")
	}

	cfg.StopSignal = "SIGTERM"
	findings, err = a.Analyze(context.Background(), cfg, image)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if f := findByID(findings, "PF-MISC-011"); f != nil {
		t.Error("expected no PF-MISC-011 when stop signal set")
	}
}

func TestAnalyzer_NilConfig(t *testing.T) {
	a := New()
	findings, err := a.Analyze(context.Background(), nil, model.ImageIdentity{Tag: "latest"})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if len(findings) != 11 {
		t.Fatalf("expected 11 findings for nil config, got %d", len(findings))
	}
}

func TestParsePort(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"22", 22, true},
		{"22/tcp", 22, true},
		{"80/udp", 80, true},
		{"foo", 0, false},
		{"80/tcp/something", 80, true},
	}
	for _, tc := range cases {
		got, ok := parsePort(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parsePort(%q) = (%d, %v); want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func findByID(findings []model.Finding, id string) *model.Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

func ruleID(n int) string {
	return "PF-MISC-" + padID(n)
}

func padID(n int) string {
	if n < 10 {
		return "00" + strconv.Itoa(n)
	}
	if n < 100 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func baseConfig() *model.ImageConfig {
	return &model.ImageConfig{
		WorkingDir:   "/app",
		ExposedPorts: []string{"80/tcp"},
		Labels: map[string]string{
			"org.opencontainers.image.title":         "app",
			"org.opencontainers.image.version":       "1.0.0",
			"org.opencontainers.image.description":   "desc",
			"org.opencontainers.image.licenses":      "MIT",
			"org.opencontainers.image.source":        "src",
			"org.opencontainers.image.vendor":        "vendor",
			"org.opencontainers.image.documentation": "docs",
		},
		StopSignal:  "SIGTERM",
		Healthcheck: &model.Healthcheck{Test: []string{"CMD", "true"}},
	}
}

func cloneConfig(c *model.ImageConfig) *model.ImageConfig {
	copy := *c
	copy.Env = append([]string(nil), c.Env...)
	copy.Entrypoint = append([]string(nil), c.Entrypoint...)
	copy.Cmd = append([]string(nil), c.Cmd...)
	copy.ExposedPorts = append([]string(nil), c.ExposedPorts...)
	copy.Volumes = append([]string(nil), c.Volumes...)
	copy.Labels = make(map[string]string, len(c.Labels))
	for k, v := range c.Labels {
		copy.Labels[k] = v
	}
	if c.Healthcheck != nil {
		hc := *c.Healthcheck
		hc.Test = append([]string(nil), c.Healthcheck.Test...)
		copy.Healthcheck = &hc
	}
	return &copy
}

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
