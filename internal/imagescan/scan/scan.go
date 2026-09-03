// Package scan orchestrates the full image scan pipeline: resolve the image,
// reconstruct the layered filesystem, detect the OS, catalog packages, match
// vulnerabilities, and assemble a model.ScanResult. It is the single entry point
// used by the CLI subcommands.
//
// When Scanner.Matcher is set, the result includes vulnerability findings with
// layer-blame recommendations. Phase 4 analyzers (secrets, hardening,
// misconfiguration) always run and append their findings to the result.
package scan

import (
	"context"
	"fmt"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/analysis/hardening"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/analysis/layerblame"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/analysis/misconfig"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/analysis/secrets"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog/apk"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog/dpkg"
	gocatalog "github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog/go"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog/java"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog/npm"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog/osdetect"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog/python"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/catalog/rust"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/filesystem/extractor"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/image/resolver"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/model"
	"github.com/Patchflow-security/patchflow-cli/internal/imagescan/pkg/version"
)

// VulnMatcher is the optional Phase 2 vulnerability matching interface.
// When set on Scanner, it is called after package cataloging and populates
// ScanResult.Findings. Using an interface here keeps internal/scan free of
// a direct dependency on internal/vuln/matcher, which simplifies the
// dependency graph and eases testing.
type VulnMatcher interface {
	MatchAll(ctx context.Context, result *model.ScanResult) (int, error)
}

// Scanner is the top-level engine. It composes a resolver, an extractor, and
// a cataloger pipeline. Matcher is optional; set it to enable Phase 2 vuln matching.
type Scanner struct {
	Resolver  resolver.Resolver
	Extractor *extractor.Extractor
	Catalog   *catalog.Pipeline
	// Matcher runs after cataloging when non-nil. Populates ScanResult.Findings.
	Matcher   VulnMatcher
}

// New returns a Scanner with the default Phase 1 configuration: all
// supported input sources and the APK + DPKG catalogers.
func New() *Scanner {
	return &Scanner{
		Resolver:  resolver.New(),
		Extractor: extractor.New(),
		Catalog: catalog.NewPipeline(
			apk.New(),
			dpkg.New(),
			npm.New(),
			python.New(),
			java.New(),
			gocatalog.New(),
			rust.New(),
		),
	}
}

// Request is the input to a scan.
type Request struct {
	// Ref is the image reference (registry, digest, docker-daemon:, podman:).
	// May be empty if Input is set.
	Ref string
	// Input is a local tarball or OCI layout path (used when Ref is empty).
	Input string
	// Platform selects a platform for multi-arch manifests (e.g. linux/amd64).
	Platform string
}

// Scan runs the full pipeline and returns the result. The returned
// FileSystemView must be closed by the caller to release the snapshot dir.
func (s *Scanner) Scan(ctx context.Context, req Request) (*ScanOutput, error) {
	started := time.Now().UTC()

	ri, err := s.Resolver.Resolve(ctx, req.Ref, resolver.Options{
		Platform: req.Platform,
		Input:    req.Input,
	})
	if err != nil {
		return nil, err
	}

	built, err := s.Extractor.Build(ctx, ri.Image)
	if err != nil {
		return nil, fmt.Errorf("reconstruct filesystem: %w", err)
	}

	osInfo, err := osdetect.Detect(ctx, built.FS)
	if err != nil {
		return nil, fmt.Errorf("detect os: %w", err)
	}

	pkgs, err := s.Catalog.Run(ctx, built.FS)
	if err != nil {
		return nil, fmt.Errorf("catalog packages: %w", err)
	}

	// Stamp distro context and layer provenance onto packages so the matcher
	// and SBOM exporter can use them without re-reading os-release.
	if osInfo != nil {
		stampDistro(pkgs, osInfo)
	}
	stampLayerCreatedBy(pkgs, built.Layers)

	imgConfig := extractImageConfig(ri.Image)

	ended := time.Now().UTC()

	result := &model.ScanResult{
		Image:     ri.Identity,
		OS:        osInfo,
		Config:    imgConfig,
		Layers:    built.Layers,
		Packages:  pkgs,
		Findings:  []model.Finding{},
		Scanner: model.ScannerInfo{
			Version:          version.Short(),
			CatalogerVersion: "2",
		},
		StartedAt: started,
		EndedAt:   ended,
	}
	result.SBOM = &model.SBOM{
		Image:       ri.Identity,
		OS:          osInfo,
		Packages:    pkgs,
		GeneratedAt: ended,
	}

	// Phase 2: run the vulnerability matcher if one was configured.
	if s.Matcher != nil {
		if _, err := s.Matcher.MatchAll(ctx, result); err != nil {
			// Non-fatal: return partial result with a warning in ScannerInfo.
			result.Scanner.VulnDBVersion = fmt.Sprintf("error: %v", err)
		}
	}

	// Phase 4: layer-blame recommendations for vulnerability findings.
	layerblame.Analyze(result)

	// Phase 4: secret, hardening, and misconfiguration analyzers.
	if sec, err := secrets.New().Analyze(ctx, built.FS, result.Config); err == nil {
		result.Findings = append(result.Findings, sec...)
	}
	if hard, err := hardening.New().Analyze(ctx, built.FS, result.Config, result.Layers); err == nil {
		result.Findings = append(result.Findings, hard...)
	}
	if mis, err := misconfig.New().Analyze(ctx, result.Config, result.Image); err == nil {
		result.Findings = append(result.Findings, mis...)
	}

	return &ScanOutput{Result: result, FS: built.FS}, nil
}

// ScanOutput bundles the scan result with the filesystem view so the caller
// can close the snapshot dir when done.
type ScanOutput struct {
	Result *model.ScanResult
	FS     *extractor.View
}

// extractImageConfig reads the OCI image config from the resolved image and
// projects it into the PatchFlow-native model.ImageConfig shape used by the
// Phase 4 secret / hardening / misconfiguration analyzers.
func extractImageConfig(img v1.Image) *model.ImageConfig {
	cfg, err := img.ConfigFile()
	if err != nil || cfg == nil {
		return nil
	}
	c := cfg.Config
	out := &model.ImageConfig{
		User:       c.User,
		WorkingDir: c.WorkingDir,
		Env:        append([]string(nil), c.Env...),
		Entrypoint: append([]string(nil), c.Entrypoint...),
		Cmd:        append([]string(nil), c.Cmd...),
		StopSignal: c.StopSignal,
		Labels:     make(map[string]string, len(c.Labels)),
	}
	for k, v := range c.Labels {
		out.Labels[k] = v
	}
	for p := range c.ExposedPorts {
		out.ExposedPorts = append(out.ExposedPorts, p)
	}
	for v := range c.Volumes {
		out.Volumes = append(out.Volumes, v)
	}
	if c.Healthcheck != nil {
		out.Healthcheck = &model.Healthcheck{
			Test:        append([]string(nil), c.Healthcheck.Test...),
			Interval:    int64(c.Healthcheck.Interval),
			Timeout:     int64(c.Healthcheck.Timeout),
			StartPeriod: int64(c.Healthcheck.StartPeriod),
			Retries:     c.Healthcheck.Retries,
		}
	}
	return out
}

// Close releases the filesystem snapshot. It is safe to call multiple times.
func (o *ScanOutput) Close() error {
	if o.FS == nil {
		return nil
	}
	return o.FS.Close()
}

// stampDistro copies OS identity onto every package (not just Type=="os") so
// downstream matching is distro-aware without re-parsing os-release.
func stampDistro(pkgs []model.Package, os *model.OperatingSystem) {
	for i := range pkgs {
		if pkgs[i].DistroName == "" {
			pkgs[i].DistroName = os.Name
		}
		if pkgs[i].DistroVersion == "" {
			pkgs[i].DistroVersion = os.VersionID
		}
	}
}

// stampLayerCreatedBy populates Package.LayerCreatedBy by looking up the
// package's LayerDigest in the image's layer provenance list. This allows
// the matcher and output formatters to include the RUN command that
// introduced a vulnerable package.
func stampLayerCreatedBy(pkgs []model.Package, layers []model.LayerProvenance) {
	byDigest := make(map[string]string, len(layers))
	for _, l := range layers {
		byDigest[l.LayerDigest] = l.CreatedBy
	}
	for i := range pkgs {
		if pkgs[i].LayerCreatedBy == "" && pkgs[i].LayerDigest != "" {
			pkgs[i].LayerCreatedBy = byDigest[pkgs[i].LayerDigest]
		}
	}
}
