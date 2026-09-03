package hardening

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

type fakeFS struct {
	entries map[string]*model.FileEntry
	content map[string][]byte
}

func newFakeFS(entries map[string]*model.FileEntry, content map[string]string) *fakeFS {
	c := make(map[string][]byte, len(content))
	for k, v := range content {
		c[k] = []byte(v)
	}
	return &fakeFS{entries: entries, content: c}
}

func (f *fakeFS) Get(path string) (*model.FileEntry, bool) {
	e, ok := f.entries[path]
	if !ok || e.IsDeleted {
		return nil, false
	}
	return e, true
}

func (f *fakeFS) Open(path string) (model.ContentReader, error) {
	e, ok := f.entries[path]
	if !ok || e.IsDeleted || e.IsDir {
		return nil, fmt.Errorf("not found: %s", path)
	}
	data, ok := f.content[path]
	if !ok {
		data = []byte{}
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (f *fakeFS) Walk(prefix string, fn func(*model.FileEntry) error) error {
	keys := make([]string, 0, len(f.entries))
	for k := range f.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		e := f.entries[k]
		if e.IsDeleted {
			continue
		}
		if err := fn(e); err != nil {
			if err == model.ErrWalkStop {
				return nil
			}
			return err
		}
	}
	return nil
}

func (f *fakeFS) Entries() int { return len(f.entries) }

func entry(path string, mode uint32, size int64, layer string) *model.FileEntry {
	return &model.FileEntry{
		Path:        path,
		Mode:        mode,
		Size:        size,
		LayerDigest: layer,
	}
}

func hasRuleID(t *testing.T, findings []model.Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == ruleID {
			return
		}
	}
	t.Errorf("expected finding %q, got ids %v", ruleID, ids(findings))
}

func notHasRuleID(t *testing.T, findings []model.Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == ruleID {
			t.Errorf("unexpected finding %q", ruleID)
			return
		}
	}
}

func ids(findings []model.Finding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, f.ID)
	}
	return out
}

func TestAnalyzeRoot(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{User: "root"}
	findings, err := a.Analyze(context.Background(), nil, cfg, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-001")
	notHasRuleID(t, findings, "PF-IMG-002")
}

func TestAnalyzeNoUser(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{User: ""}
	findings, err := a.Analyze(context.Background(), nil, cfg, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-001")
	hasRuleID(t, findings, "PF-IMG-002")
}

func TestAnalyzeNonRoot(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{User: "app"}
	findings, err := a.Analyze(context.Background(), nil, cfg, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	notHasRuleID(t, findings, "PF-IMG-001")
	notHasRuleID(t, findings, "PF-IMG-002")
}

func TestAnalyzeSecrets(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{
		Env: []string{"API_KEY=secret123"},
	}
	fs := newFakeFS(map[string]*model.FileEntry{
		"/etc/app/.env": entry("/etc/app/.env", 0o644, 64, "sha256:app"),
	}, map[string]string{
		"/etc/app/.env": "AWS_SECRET_ACCESS_KEY=abc\n",
	})
	findings, err := a.Analyze(context.Background(), fs, cfg, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-003")
}

func TestAnalyzeSSHPort(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{ExposedPorts: []string{"80/tcp", "22/tcp"}}
	findings, err := a.Analyze(context.Background(), nil, cfg, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-004")
}

func TestAnalyzeSSHPortMissing(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{ExposedPorts: []string{"80/tcp"}}
	findings, err := a.Analyze(context.Background(), nil, cfg, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	notHasRuleID(t, findings, "PF-IMG-004")
}

func TestAnalyzePackageCache(t *testing.T) {
	a := New()
	fs := newFakeFS(map[string]*model.FileEntry{
		"/var/cache/apt/archives/curl_1.deb": entry("/var/cache/apt/archives/curl_1.deb", 0o644, 1024, "sha256:app"),
		"/var/cache/apk/x.apk":               entry("/var/cache/apk/x.apk", 0o644, 512, "sha256:app"),
	}, nil)
	findings, err := a.Analyze(context.Background(), fs, &model.ImageConfig{}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-005")
}

func TestAnalyzeShell(t *testing.T) {
	a := New()
	fs := newFakeFS(map[string]*model.FileEntry{
		"/bin/bash": entry("/bin/bash", 0o755, 1024, "sha256:base"),
	}, nil)
	findings, err := a.Analyze(context.Background(), fs, &model.ImageConfig{}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-006")
}

func TestAnalyzeNetworkTools(t *testing.T) {
	a := New()
	fs := newFakeFS(map[string]*model.FileEntry{
		"/usr/bin/curl": entry("/usr/bin/curl", 0o755, 1024, "sha256:app"),
	}, nil)
	findings, err := a.Analyze(context.Background(), fs, &model.ImageConfig{}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-007")
}

func TestAnalyzeSudo(t *testing.T) {
	a := New()
	fs := newFakeFS(map[string]*model.FileEntry{
		"/usr/bin/sudo": entry("/usr/bin/sudo", 0o755, 1024, "sha256:app"),
	}, nil)
	findings, err := a.Analyze(context.Background(), fs, &model.ImageConfig{}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-008")
}

func TestAnalyzeWorldWritable(t *testing.T) {
	a := New()
	fs := newFakeFS(map[string]*model.FileEntry{
		"/tmp": {Path: "/tmp", Mode: 0o707, IsDir: true, LayerDigest: "sha256:app"},
	}, nil)
	findings, err := a.Analyze(context.Background(), fs, &model.ImageConfig{}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-009")
}

func TestAnalyzeWorldWritable777(t *testing.T) {
	a := New()
	fs := newFakeFS(map[string]*model.FileEntry{
		"/tmp": {Path: "/tmp", Mode: 0o777, IsDir: true, LayerDigest: "sha256:app"},
	}, nil)
	findings, err := a.Analyze(context.Background(), fs, &model.ImageConfig{}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	notHasRuleID(t, findings, "PF-IMG-009")
}

func TestAnalyzeHealthcheck(t *testing.T) {
	a := New()
	findings, err := a.Analyze(context.Background(), nil, &model.ImageConfig{}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-010")
}

func TestAnalyzeHealthcheckPresent(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{Healthcheck: &model.Healthcheck{Test: []string{"CMD", "curl", "-f", "http://localhost"}}}
	findings, err := a.Analyze(context.Background(), nil, cfg, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	notHasRuleID(t, findings, "PF-IMG-010")
}

func TestAnalyzeLargeBinary(t *testing.T) {
	a := New()
	fs := newFakeFS(map[string]*model.FileEntry{
		"/usr/bin/big": entry("/usr/bin/big", 0o755, 101*1024*1024, "sha256:app"),
	}, nil)
	findings, err := a.Analyze(context.Background(), fs, &model.ImageConfig{}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-011")
}

func TestAnalyzeMaintainerLabels(t *testing.T) {
	a := New()
	findings, err := a.Analyze(context.Background(), nil, &model.ImageConfig{Labels: map[string]string{}}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-012")
}

func TestAnalyzeMaintainerLabelsPresent(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{Labels: map[string]string{
		"org.opencontainers.image.authors": "team@example.com",
		"org.opencontainers.image.vendor":  "Example Inc",
	}}
	findings, err := a.Analyze(context.Background(), nil, cfg, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	notHasRuleID(t, findings, "PF-IMG-012")
}

func TestAnalyzeSetuid(t *testing.T) {
	a := New()
	fs := newFakeFS(map[string]*model.FileEntry{
		"/usr/bin/sudo": entry("/usr/bin/sudo", 0o4755, 1024, "sha256:app"),
	}, nil)
	findings, err := a.Analyze(context.Background(), fs, &model.ImageConfig{}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-013")
}

func TestAnalyzeSourceLabel(t *testing.T) {
	a := New()
	findings, err := a.Analyze(context.Background(), nil, &model.ImageConfig{Labels: map[string]string{}}, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	hasRuleID(t, findings, "PF-IMG-014")
}

func TestAnalyzeSourceLabelPresent(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{Labels: map[string]string{
		"org.opencontainers.image.source": "https://github.com/example/app",
	}}
	findings, err := a.Analyze(context.Background(), nil, cfg, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	notHasRuleID(t, findings, "PF-IMG-014")
}

func TestAnalyzeClean(t *testing.T) {
	a := New()
	cfg := &model.ImageConfig{
		User:         "app",
		ExposedPorts: []string{"8080/tcp"},
		Healthcheck:  &model.Healthcheck{Test: []string{"CMD", "true"}},
		Labels: map[string]string{
			"org.opencontainers.image.authors": "team@example.com",
			"org.opencontainers.image.vendor":  "Example Inc",
			"org.opencontainers.image.source":  "https://github.com/example/app",
		},
	}
	findings, err := a.Analyze(context.Background(), newFakeFS(nil, nil), cfg, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	for _, f := range findings {
		t.Errorf("unexpected finding: %s", f.ID)
	}
}

func TestAnalyzeCancellation(t *testing.T) {
	a := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := a.Analyze(ctx, nil, &model.ImageConfig{}, nil)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}
