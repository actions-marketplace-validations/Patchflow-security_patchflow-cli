// Package misconfig detects common container image misconfigurations such as
// the use of mutable tags, missing OCI labels, dangerous exposed ports, and
// missing runtime hardening.
package misconfig

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
)

// Finding is a single misconfiguration match produced by the Analyzer.
type Finding struct {
	RuleID      string
	Title       string
	Description string
	Severity    model.Severity
	Confidence  model.Confidence
	Path        string
	LayerDigest string
}

func (f Finding) toModel() model.Finding {
	return model.Finding{
		ID:          f.RuleID,
		Type:        model.FindingTypeMisconfig,
		Severity:    f.Severity,
		Confidence:  f.Confidence,
		Title:       f.Title,
		Description: f.Description,
		LayerDigest: f.LayerDigest,
		DetectedAt:  time.Now(),
	}
}

// Analyzer inspects image configuration metadata for misconfigurations.
type Analyzer struct{}

// New creates a misconfiguration Analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Analyze inspects the supplied image configuration and identity, returning all
// misconfiguration findings. A nil cfg is treated as an empty configuration.
func (a *Analyzer) Analyze(ctx context.Context, cfg *model.ImageConfig, image model.ImageIdentity) ([]model.Finding, error) {
	if cfg == nil {
		cfg = &model.ImageConfig{}
	}

	var findings []model.Finding
	for _, r := range rules {
		path, ok := r.check(cfg, image)
		if !ok {
			continue
		}
		findings = append(findings, r.finding(path).toModel())
	}

	return findings, nil
}

type rule struct {
	id          string
	title       string
	description string
	severity    model.Severity
	confidence  model.Confidence
	check       func(cfg *model.ImageConfig, image model.ImageIdentity) (path string, ok bool)
}

func (r rule) finding(path string) Finding {
	return Finding{
		RuleID:      r.id,
		Title:       r.title,
		Description: r.description,
		Severity:    r.severity,
		Confidence:  r.confidence,
		Path:        path,
	}
}

var rules = []rule{
	{
		id:          "PF-MISC-001",
		title:       "Image uses the :latest tag",
		description: "The image reference uses the mutable :latest tag (or no tag). Pin the image to a specific, immutable tag or digest to ensure reproducible and predictable deployments.",
		severity:    model.SeverityHigh,
		confidence:  100,
		check: func(cfg *model.ImageConfig, image model.ImageIdentity) (string, bool) {
			if image.Tag != "latest" && image.Tag != "" {
				return "", false
			}
			return image.OriginalRef, true
		},
	},
	{
		id:          "PF-MISC-002",
		title:       "Missing org.opencontainers.image.title label",
		description: "The image does not provide the org.opencontainers.image.title label. Add this label to document the human-readable name of the image.",
		severity:    model.SeverityMedium,
		confidence:  100,
		check:       labelCheck("org.opencontainers.image.title"),
	},
	{
		id:          "PF-MISC-003",
		title:       "Missing org.opencontainers.image.version label",
		description: "The image does not provide the org.opencontainers.image.version label. Add this label to identify the version of the packaged software.",
		severity:    model.SeverityMedium,
		confidence:  100,
		check:       labelCheck("org.opencontainers.image.version"),
	},
	{
		id:          "PF-MISC-004",
		title:       "Missing org.opencontainers.image.description label",
		description: "The image does not provide the org.opencontainers.image.description label. Add this label to describe the image's purpose and contents.",
		severity:    model.SeverityMedium,
		confidence:  100,
		check:       labelCheck("org.opencontainers.image.description"),
	},
	{
		id:          "PF-MISC-005",
		title:       "Missing org.opencontainers.image.licenses label",
		description: "The image does not provide the org.opencontainers.image.licenses label. Add this label to declare the license(s) under which the image is distributed.",
		severity:    model.SeverityMedium,
		confidence:  100,
		check:       labelCheck("org.opencontainers.image.licenses"),
	},
	{
		id:          "PF-MISC-006",
		title:       "Missing org.opencontainers.image.source label",
		description: "The image does not provide the org.opencontainers.image.source label. Add this label to link the image to its source code repository.",
		severity:    model.SeverityMedium,
		confidence:  100,
		check:       labelCheck("org.opencontainers.image.source"),
	},
	{
		id:          "PF-MISC-007",
		title:       "Missing org.opencontainers.image.vendor label",
		description: "The image does not provide the org.opencontainers.image.vendor label. Add this label to identify the organization that produces the image.",
		severity:    model.SeverityMedium,
		confidence:  100,
		check:       labelCheck("org.opencontainers.image.vendor"),
	},
	{
		id:          "PF-MISC-008",
		title:       "Dangerous administrative port exposed",
		description: "The image exposes one or more dangerous administrative ports (21/FTP, 22/SSH, 23/Telnet, 3389/RDP, 5900/VNC). Remove unnecessary exposed ports and expose only application ports such as 80, 443, 8080, or 8443.",
		severity:    model.SeverityHigh,
		confidence:  100,
		check: func(cfg *model.ImageConfig, image model.ImageIdentity) (string, bool) {
			dangerous := []int{22, 21, 23, 3389, 5900}
			for _, port := range cfg.ExposedPorts {
				n, ok := parsePort(port)
				if !ok {
					continue
				}
				for _, d := range dangerous {
					if n == d {
						return port, true
					}
				}
			}
			return "", false
		},
	},
	{
		id:          "PF-MISC-009",
		title:       "No healthcheck configured",
		description: "The image does not define a HEALTHCHECK. Add a HEALTHCHECK instruction so the container runtime can detect and restart unhealthy containers.",
		severity:    model.SeverityMedium,
		confidence:  100,
		check: func(cfg *model.ImageConfig, image model.ImageIdentity) (string, bool) {
			if cfg.Healthcheck != nil && len(cfg.Healthcheck.Test) > 0 {
				return "", false
			}
			return "", true
		},
	},
	{
		id:          "PF-MISC-010",
		title:       "Working directory is root",
		description: "The image working directory is unset or set to the root filesystem (/). Set a non-root working directory to reduce the impact of accidental writes and improve file organization.",
		severity:    model.SeverityLow,
		confidence:  100,
		check: func(cfg *model.ImageConfig, image model.ImageIdentity) (string, bool) {
			if cfg.WorkingDir != "" && cfg.WorkingDir != "/" {
				return "", false
			}
			return "", true
		},
	},
	{
		id:          "PF-MISC-011",
		title:       "Stop signal not set",
		description: "The image does not set a STOPSIGNAL. Configure an appropriate STOPSIGNAL so the container runtime can gracefully terminate the application.",
		severity:    model.SeverityLow,
		confidence:  100,
		check: func(cfg *model.ImageConfig, image model.ImageIdentity) (string, bool) {
			if cfg.StopSignal != "" {
				return "", false
			}
			return "", true
		},
	},
	{
		id:          "PF-MISC-012",
		title:       "Missing org.opencontainers.image.documentation label",
		description: "The image does not provide the org.opencontainers.image.documentation label. Add this label to link to the image's documentation.",
		severity:    model.SeverityMedium,
		confidence:  100,
		check:       labelCheck("org.opencontainers.image.documentation"),
	},
}

func labelCheck(key string) func(cfg *model.ImageConfig, image model.ImageIdentity) (string, bool) {
	return func(cfg *model.ImageConfig, image model.ImageIdentity) (string, bool) {
		if cfg.Labels != nil {
			if _, ok := cfg.Labels[key]; ok {
				return "", false
			}
		}
		return key, true
	}
}

func parsePort(s string) (int, bool) {
	before, _, _ := strings.Cut(s, "/")
	n, err := strconv.Atoi(before)
	if err != nil {
		return 0, false
	}
	return n, true
}
