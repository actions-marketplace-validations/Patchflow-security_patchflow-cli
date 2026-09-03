package hardening

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// Finding is a hardening-rule finding before it is normalized to the shared
// model.Finding shape.
type Finding struct {
	RuleID         string
	Title          string
	Description    string
	Recommendation string
	Severity       model.Severity
	Confidence     int
	Path           string
	LayerDigest    string
	Evidence       []model.Evidence
}

// Analyzer runs the image hardening rule set against a filesystem view and
// image configuration.
type Analyzer struct {
	rules []rule
}

type rule struct {
	id    string
	title string
	check func(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error)
}

// New returns an Analyzer with the default PF-IMG hardening rule set.
func New() *Analyzer {
	return &Analyzer{rules: defaultRules()}
}

// Analyze runs all hardening rules and returns model.Finding findings.
func (a *Analyzer) Analyze(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]model.Finding, error) {
	var out []model.Finding
	for _, r := range a.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		findings, err := r.check(ctx, fs, cfg, layers)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.id, err)
		}
		for _, f := range findings {
			out = append(out, toModelFinding(f))
		}
	}
	return out, nil
}

func defaultRules() []rule {
	return []rule{
		{id: "PF-IMG-001", title: "Image runs as root", check: checkRoot},
		{id: "PF-IMG-002", title: "No USER instruction", check: checkNoUser},
		{id: "PF-IMG-003", title: "Sensitive ENV variable", check: checkSecrets},
		{id: "PF-IMG-004", title: "SSH port exposed", check: checkSSHPort},
		{id: "PF-IMG-005", title: "Package manager cache left behind", check: checkPackageCache},
		{id: "PF-IMG-006", title: "Shell present in production image", check: checkShells},
		{id: "PF-IMG-007", title: "Network tools present", check: checkNetworkTools},
		{id: "PF-IMG-008", title: "sudo installed", check: checkSudo},
		{id: "PF-IMG-009", title: "World-writable path", check: checkWorldWritable},
		{id: "PF-IMG-010", title: "Missing HEALTHCHECK", check: checkHealthcheck},
		{id: "PF-IMG-011", title: "Large unexpected binary", check: checkLargeBinary},
		{id: "PF-IMG-012", title: "No maintainer labels", check: checkMaintainerLabels},
		{id: "PF-IMG-013", title: "setuid binary", check: checkSetuid},
		{id: "PF-IMG-014", title: "Missing image source label", check: checkSourceLabel},
	}
}

func toModelFinding(f Finding) model.Finding {
	return model.Finding{
		ID:             f.RuleID,
		Type:           model.FindingTypeHardening,
		Severity:       f.Severity,
		Confidence:     model.Confidence(f.Confidence),
		Title:          f.Title,
		Description:    f.Description,
		Recommendation: f.Recommendation,
		LayerDigest:    f.LayerDigest,
		Locations:      []model.Location{{Path: f.Path, LayerDigest: f.LayerDigest}},
		Evidence:       f.Evidence,
		DetectedAt:     time.Now(),
	}
}

func evidence(ruleID, field, value, reason string) []model.Evidence {
	return []model.Evidence{{
		Source:     "hardening",
		MatchField: field,
		MatchValue: value,
		Reason:     reason,
	}}
}

func checkRoot(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if cfg == nil {
		return nil, nil
	}
	user := strings.ToLower(cfg.User)
	if user != "" && user != "root" && user != "0" {
		return nil, nil
	}
	rec := "Add a non-root USER instruction and run the container as an unprivileged user."
	return []Finding{{
		RuleID:         "PF-IMG-001",
		Title:          "Image runs as root",
		Description:    fmt.Sprintf("The container user is %q, which runs as root. %s", cfg.User, rec),
		Recommendation: rec,
		Severity:       model.SeverityCritical,
		Confidence:     90,
		Path:           "image config",
		Evidence:       evidence("PF-IMG-001", "config.user", cfg.User, rec),
	}}, nil
}

func checkNoUser(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if cfg != nil && cfg.User != "" {
		return nil, nil
	}
	rec := "Add an explicit USER instruction in the Dockerfile to avoid running as root."
	return []Finding{{
		RuleID:         "PF-IMG-002",
		Title:          "No USER instruction",
		Description:    "The image has no USER instruction. " + rec,
		Recommendation: rec,
		Severity:       model.SeverityCritical,
		Confidence:     90,
		Path:           "image config",
		Evidence:       evidence("PF-IMG-002", "config.user", "", rec),
	}}, nil
}

var secretPatterns = []string{"AWS_SECRET_ACCESS_KEY", "PASSWORD", "TOKEN", "API_KEY"}

func isSensitiveEnv(name string) bool {
	up := strings.ToUpper(name)
	for _, p := range secretPatterns {
		if strings.Contains(up, p) {
			return true
		}
	}
	return false
}

func checkSecrets(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	rec := "Remove secrets from image ENV and files; inject them at runtime from a secret store or orchestrator."
	var findings []Finding
	if cfg != nil {
		for _, env := range cfg.Env {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 0 {
				continue
			}
			if isSensitiveEnv(parts[0]) {
				findings = append(findings, Finding{
					RuleID:         "PF-IMG-003",
					Title:          "Sensitive ENV variable",
					Description:    fmt.Sprintf("The environment variable %q looks sensitive. %s", parts[0], rec),
					Recommendation: rec,
					Severity:       model.SeverityHigh,
					Confidence:     85,
					Path:           "image config",
					Evidence:       evidence("PF-IMG-003", "config.env", parts[0], rec),
				})
			}
		}
	}
	if fs == nil {
		return findings, nil
	}
	err := fs.Walk("/", func(e *model.FileEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDir || e.IsDeleted || e.IsSymlink || e.Size == 0 || e.Size > 1<<20 {
			return nil
		}
		if isSystemPath(e.Path) {
			return nil
		}
		rc, err := fs.Open(e.Path)
		if err != nil {
			return nil
		}
		defer rc.Close()
		data, err := io.ReadAll(io.LimitReader(rc, 8192))
		if err != nil {
			return nil
		}
		upper := strings.ToUpper(string(data))
		for _, p := range secretPatterns {
			if strings.Contains(upper, p) {
				findings = append(findings, Finding{
					RuleID:         "PF-IMG-003",
					Title:          "Sensitive ENV variable",
					Description:    fmt.Sprintf("The file %q contains the sensitive pattern %q. %s", e.Path, p, rec),
					Recommendation: rec,
					Severity:       model.SeverityHigh,
					Confidence:     80,
					Path:           e.Path,
					LayerDigest:    e.LayerDigest,
					Evidence:       evidence("PF-IMG-003", "file", e.Path, p),
				})
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func isSystemPath(path string) bool {
	for _, p := range []string{
		"/etc/ssl/",
		"/etc/ssh/",
		"/etc/openssh/",
		"/etc/services",
		"/etc/protocols",
		"/etc/hosts",
		"/etc/passwd",
		"/etc/group",
		"/etc/shadow",
		"/usr/lib/",
		"/usr/share/",
		"/usr/include/",
		"/usr/src/",
		"/lib/",
		"/lib64/",
		"/usr/bin/",
		"/usr/sbin/",
		"/bin/",
		"/sbin/",
		"/proc/",
		"/sys/",
		"/dev/",
		"/run/",
	} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func checkSSHPort(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if cfg == nil {
		return nil, nil
	}
	for _, p := range cfg.ExposedPorts {
		if strings.Contains(p, "22/tcp") || strings.Contains(p, "22/udp") || strings.Contains(p, "/22") || p == "22" {
			rec := "Remove the SSH port exposure or restrict it with network policy and runtime firewall rules."
			return []Finding{{
				RuleID:         "PF-IMG-004",
				Title:          "SSH port exposed",
				Description:    fmt.Sprintf("Port %q exposes SSH. %s", p, rec),
				Recommendation: rec,
				Severity:       model.SeverityHigh,
				Confidence:     95,
				Path:           "image config",
				Evidence:       evidence("PF-IMG-004", "config.exposed_ports", p, rec),
			}}, nil
		}
	}
	return nil, nil
}

func isCachePath(path string) bool {
	return strings.HasPrefix(path, "/var/cache/apt/archives/") && strings.HasSuffix(path, ".deb") ||
		strings.HasPrefix(path, "/var/cache/apk/") && strings.HasSuffix(path, ".apk") ||
		strings.HasPrefix(path, "/var/lib/apt/lists/")
}

func checkPackageCache(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if fs == nil {
		return nil, nil
	}
	var paths []string
	err := fs.Walk("/", func(e *model.FileEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDeleted {
			return nil
		}
		if isCachePath(e.Path) {
			paths = append(paths, e.Path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, nil
	}
	rec := "Clean package manager caches in the same RUN layer with apt-get clean, rm -rf /var/cache/apt, or apk cache clean."
	return []Finding{{
		RuleID:         "PF-IMG-005",
		Title:          "Package manager cache left behind",
		Description:    fmt.Sprintf("Package manager cache paths were found: %s. %s", strings.Join(paths, ", "), rec),
		Recommendation: rec,
		Severity:       model.SeverityMedium,
		Confidence:     85,
		Path:           paths[0],
		Evidence:       evidence("PF-IMG-005", "paths", strings.Join(paths, ", "), rec),
	}}, nil
}

var shellPaths = map[string]struct{}{
	"/bin/bash": {},
	"/bin/sh":   {},
	"/bin/zsh":  {},
	"/bin/ash":  {},
}

func checkShells(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if fs == nil {
		return nil, nil
	}
	rec := "Remove interactive shells from production images or use a minimal distroless/scratch image."
	var findings []Finding
	err := fs.Walk("/", func(e *model.FileEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDeleted || e.IsDir {
			return nil
		}
		if _, ok := shellPaths[e.Path]; ok {
			findings = append(findings, Finding{
				RuleID:         "PF-IMG-006",
				Title:          "Shell present in production image",
				Description:    fmt.Sprintf("The shell %q is present. %s", e.Path, rec),
				Recommendation: rec,
				Severity:       model.SeverityMedium,
				Confidence:     80,
				Path:           e.Path,
				LayerDigest:    e.LayerDigest,
				Evidence:       evidence("PF-IMG-006", "path", e.Path, rec),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

var networkToolNames = map[string]struct{}{
	"curl":   {},
	"wget":   {},
	"nc":     {},
	"nmap":   {},
	"netcat": {},
}

func checkNetworkTools(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if fs == nil {
		return nil, nil
	}
	rec := "Remove network reconnaissance tools from production images; use multi-stage builds."
	var findings []Finding
	err := fs.Walk("/", func(e *model.FileEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDeleted || e.IsDir {
			return nil
		}
		if _, ok := networkToolNames[filepath.Base(e.Path)]; ok {
			findings = append(findings, Finding{
				RuleID:         "PF-IMG-007",
				Title:          "Network tools present",
				Description:    fmt.Sprintf("The network tool %q was found at %q. %s", filepath.Base(e.Path), e.Path, rec),
				Recommendation: rec,
				Severity:       model.SeverityMedium,
				Confidence:     80,
				Path:           e.Path,
				LayerDigest:    e.LayerDigest,
				Evidence:       evidence("PF-IMG-007", "path", e.Path, rec),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func checkSudo(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if fs == nil {
		return nil, nil
	}
	rec := "Remove sudo from the image; rely on runtime user permissions and avoid privilege escalation helpers."
	var findings []Finding
	err := fs.Walk("/", func(e *model.FileEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDeleted || e.IsDir {
			return nil
		}
		if e.Path == "/usr/bin/sudo" || e.Path == "/bin/sudo" {
			findings = append(findings, Finding{
				RuleID:         "PF-IMG-008",
				Title:          "sudo installed",
				Description:    fmt.Sprintf("sudo is installed at %q. %s", e.Path, rec),
				Recommendation: rec,
				Severity:       model.SeverityCritical,
				Confidence:     90,
				Path:           e.Path,
				LayerDigest:    e.LayerDigest,
				Evidence:       evidence("PF-IMG-008", "path", e.Path, rec),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func checkWorldWritable(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if fs == nil {
		return nil, nil
	}
	rec := "Restrict directory permissions so other users cannot write to production paths."
	var findings []Finding
	err := fs.Walk("/", func(e *model.FileEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDeleted || !e.IsDir {
			return nil
		}
		if e.Mode&0o002 != 0 && e.Mode&0o777 != 0o777 {
			findings = append(findings, Finding{
				RuleID:         "PF-IMG-009",
				Title:          "World-writable path",
				Description:    fmt.Sprintf("The directory %q is world-writable (mode %o). %s", e.Path, e.Mode&0o777, rec),
				Recommendation: rec,
				Severity:       model.SeverityMedium,
				Confidence:     80,
				Path:           e.Path,
				LayerDigest:    e.LayerDigest,
				Evidence:       evidence("PF-IMG-009", "path", e.Path, fmt.Sprintf("mode %o", e.Mode&0o777)),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func checkHealthcheck(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if cfg != nil && cfg.Healthcheck != nil && len(cfg.Healthcheck.Test) > 0 {
		return nil, nil
	}
	rec := "Add a HEALTHCHECK instruction to the Dockerfile so the runtime can detect container health."
	return []Finding{{
		RuleID:         "PF-IMG-010",
		Title:          "Missing HEALTHCHECK",
		Description:    "The image has no HEALTHCHECK. " + rec,
		Recommendation: rec,
		Severity:       model.SeverityLow,
		Confidence:     80,
		Path:           "image config",
		Evidence:       evidence("PF-IMG-010", "config.healthcheck", "", rec),
	}}, nil
}

func checkLargeBinary(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if fs == nil {
		return nil, nil
	}
	const maxSize = 100 * 1024 * 1024
	rec := "Review large binaries in system paths; remove debug symbols and build artifacts from production images."
	var findings []Finding
	err := fs.Walk("/", func(e *model.FileEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDeleted || e.IsDir || e.IsSymlink {
			return nil
		}
		if e.Size <= maxSize {
			return nil
		}
		if strings.HasPrefix(e.Path, "/usr/bin/") ||
			strings.HasPrefix(e.Path, "/usr/local/bin/") ||
			strings.HasPrefix(e.Path, "/bin/") ||
			strings.HasPrefix(e.Path, "/sbin/") {
			findings = append(findings, Finding{
				RuleID:         "PF-IMG-011",
				Title:          "Large unexpected binary",
				Description:    fmt.Sprintf("The binary %q is %d bytes. %s", e.Path, e.Size, rec),
				Recommendation: rec,
				Severity:       model.SeverityMedium,
				Confidence:     85,
				Path:           e.Path,
				LayerDigest:    e.LayerDigest,
				Evidence:       evidence("PF-IMG-011", "path", e.Path, fmt.Sprintf("size=%d", e.Size)),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func checkMaintainerLabels(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if cfg != nil && cfg.Labels != nil {
		if cfg.Labels["org.opencontainers.image.authors"] != "" && cfg.Labels["org.opencontainers.image.vendor"] != "" {
			return nil, nil
		}
	}
	rec := "Add org.opencontainers.image.authors and org.opencontainers.image.vendor labels to the image."
	return []Finding{{
		RuleID:         "PF-IMG-012",
		Title:          "No maintainer labels",
		Description:    "The image is missing maintainer labels. " + rec,
		Recommendation: rec,
		Severity:       model.SeverityLow,
		Confidence:     70,
		Path:           "image config",
		Evidence:       evidence("PF-IMG-012", "config.labels", "", rec),
	}}, nil
}

func checkSetuid(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if fs == nil {
		return nil, nil
	}
	rec := "Audit setuid binaries and remove unnecessary ones; prefer capabilities or privileged helpers."
	var findings []Finding
	err := fs.Walk("/", func(e *model.FileEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDeleted || e.IsDir {
			return nil
		}
		if e.Mode&0o4000 != 0 {
			findings = append(findings, Finding{
				RuleID:         "PF-IMG-013",
				Title:          "setuid binary",
				Description:    fmt.Sprintf("The binary %q has the setuid bit set (mode %o). %s", e.Path, e.Mode&0o777, rec),
				Recommendation: rec,
				Severity:       model.SeverityHigh,
				Confidence:     90,
				Path:           e.Path,
				LayerDigest:    e.LayerDigest,
				Evidence:       evidence("PF-IMG-013", "path", e.Path, fmt.Sprintf("mode %o", e.Mode&0o777)),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func checkSourceLabel(ctx context.Context, fs model.FileSystemView, cfg *model.ImageConfig, layers []model.LayerProvenance) ([]Finding, error) {
	if cfg != nil && cfg.Labels != nil && cfg.Labels["org.opencontainers.image.source"] != "" {
		return nil, nil
	}
	rec := "Add the org.opencontainers.image.source label pointing to the image build source repository."
	return []Finding{{
		RuleID:         "PF-IMG-014",
		Title:          "Missing image source label",
		Description:    "The image is missing the source label. " + rec,
		Recommendation: rec,
		Severity:       model.SeverityLow,
		Confidence:     70,
		Path:           "image config",
		Evidence:       evidence("PF-IMG-014", "config.labels", "", rec),
	}}, nil
}
