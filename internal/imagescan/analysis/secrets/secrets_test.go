package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

func TestAnalyzeDetectsAndRedactsSecrets(t *testing.T) {
	rawAWS := "AKIA1234567890ABCDEF"
	rawAWSSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	rawGitHub := "ghp_" + strings.Repeat("a", 36)
	rawPassword := "SuperSecret123!"
	rawAPIKey := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"))
	rawKeyBody := "MIIEpAIBAAKCAQEA1234567890abcdefEXAMPLE"
	rawLabelToken := "ghp_label_" + strings.Repeat("b", 36)

	fs := newFakeFS(map[string]string{
		"/app/.env": fmt.Sprintf("AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nGITHUB_TOKEN=%s\nPASSWORD=%s\n",
			rawAWS, rawAWSSecret, rawGitHub, rawPassword),
		"/root/.ssh/id_rsa": fmt.Sprintf("-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\n", rawKeyBody),
		"/app/config.json":  fmt.Sprintf(`{"api_key": "%s"}`, rawAPIKey),
	})

	cfg := &model.ImageConfig{
		Env: []string{
			"AWS_ACCESS_KEY_ID=" + rawAWS,
			"GITHUB_TOKEN=" + rawGitHub,
		},
		Labels: map[string]string{
			"github_token": rawLabelToken,
		},
	}

	scanner := New()
	findings, err := scanner.Analyze(context.Background(), fs, cfg)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings, got none")
	}

	gotRules := map[string]bool{}
	for _, f := range findings {
		for _, ev := range f.Evidence {
			if ev.MatchField == "rule_id" {
				gotRules[ev.MatchValue] = true
			}
		}
	}
	wantRules := []string{"aws-access-key", "aws-secret-key", "github-token", "private-key", "generic-secret", "generic-high-entropy"}
	for _, r := range wantRules {
		if !gotRules[r] {
			t.Errorf("expected rule %s to fire", r)
		}
	}

	for _, f := range findings {
		if !strings.Contains(f.Description, "****") {
			t.Errorf("finding %s description is not redacted: %s", f.ID, f.Description)
		}
	}

	rawSecrets := []string{rawAWS, rawAWSSecret, rawGitHub, rawPassword, rawAPIKey, rawKeyBody, rawLabelToken}
	out, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	for _, s := range rawSecrets {
		if strings.Contains(string(out), s) {
			t.Errorf("raw secret leaked into output: %q", s)
		}
	}
}

func TestAnalyzeEmptyInputs(t *testing.T) {
	scanner := New()
	findings, err := scanner.Analyze(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for nil inputs, got %d", len(findings))
	}
}

func TestFindingFields(t *testing.T) {
	fs := newFakeFS(map[string]string{
		"/etc/secret": "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n",
	})
	scanner := New()
	findings, err := scanner.Analyze(context.Background(), fs, nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings")
	}
	f := findings[0]
	if f.Type != model.FindingTypeSecret {
		t.Errorf("Type = %q, want SECRET", f.Type)
	}
	if f.LayerDigest != "sha256:layer1" {
		t.Errorf("LayerDigest = %q, want sha256:layer1", f.LayerDigest)
	}
	if f.Description == "" {
		t.Errorf("Description should be set")
	}
}

type fakeFS struct {
	entries map[string]*model.FileEntry
	files   map[string]string
}

func newFakeFS(files map[string]string) *fakeFS {
	entries := make(map[string]*model.FileEntry, len(files))
	for p, c := range files {
		entries[p] = &model.FileEntry{
			Path:        p,
			Mode:        0644,
			Size:        int64(len(c)),
			LayerDigest: "sha256:layer1",
		}
	}
	return &fakeFS{entries: entries, files: files}
}

func (f *fakeFS) Get(path string) (*model.FileEntry, bool) {
	e, ok := f.entries[path]
	return e, ok
}

func (f *fakeFS) Open(path string) (model.ContentReader, error) {
	c, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("not found: %s", path)
	}
	return io.NopCloser(strings.NewReader(c)), nil
}

func (f *fakeFS) Walk(prefix string, fn func(*model.FileEntry) error) error {
	paths := make([]string, 0, len(f.entries))
	for p := range f.entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		if err := fn(f.entries[p]); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeFS) Entries() int {
	return len(f.entries)
}
