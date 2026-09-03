// Package model defines the core domain types shared across the PatchFlow
// Image Scanner engine: image identity, the virtual filesystem view, the
// package catalog, layer provenance, OS detection, and the normalized
// finding/scan-result shapes.
//
// These types are the contract between the resolver, filesystem extractor,
// catalogers, (future) vulnerability matcher, policy evaluator, and output
// exporters. Keeping them in one package avoids import cycles between
// engines and gives every stage a single source of truth for shapes.
package model

import (
	"time"
)

// --- Image identity -------------------------------------------------------

// ImageIdentity is the digest-first identity of a resolved image. The
// Digest is the canonical, content-addressed reference; Tag is advisory
// only and MUST NOT be used as a security identity.
type ImageIdentity struct {
	OriginalRef string `json:"original_ref"`
	Registry    string `json:"registry"`
	Repository  string `json:"repository"`
	Tag         string `json:"tag,omitempty"`
	Digest      string `json:"digest"`
	Platform    string `json:"platform,omitempty"`
	MediaType   string `json:"media_type,omitempty"`
}

// --- Layer provenance -----------------------------------------------------

// LayerProvenance captures one entry from the image config history. It is
// the basis for layer attribution ("which RUN introduced this package") and
// for fix-path recommendations ("rebuild base image").
type LayerProvenance struct {
	LayerDigest string    `json:"layer_digest"`
	CreatedBy   string    `json:"created_by"`
	Comment     string    `json:"comment,omitempty"`
	Author      string    `json:"author,omitempty"`
	EmptyLayer  bool      `json:"empty_layer"`
	Created     time.Time `json:"created,omitempty"`
}

// --- Filesystem view ------------------------------------------------------

// FileEntry is one node in the reconstructed virtual filesystem. LayerDigest
// records the layer that last *added or modified* the path; IsDeleted marks
// whiteout/opaque-whiteout entries so consumers can skip removed paths.
type FileEntry struct {
	Path        string    `json:"path"`
	Mode        uint32    `json:"mode"`
	Size        int64     `json:"size"`
	Digest      string    `json:"digest,omitempty"`
	LayerDigest string    `json:"layer_digest"`
	IsDeleted   bool      `json:"is_deleted,omitempty"`
	ModTime     time.Time `json:"mod_time,omitempty"`
	IsDir       bool      `json:"is_dir,omitempty"`
	IsSymlink   bool      `json:"is_symlink,omitempty"`
	LinkTarget  string    `json:"link_target,omitempty"`
}

// FileSystemView is the merged, layer-aware view of an image's filesystem.
// Implementations may be in-memory or backed by an extracted snapshot; the
// interface below is what catalogers consume.
type FileSystemView interface {
	// Get returns the entry for path, or nil if absent or whiteout-deleted.
	Get(path string) (*FileEntry, bool)
	// Open opens the file content for reading. Returns an error for
	// directories, deleted entries, or symlinks (resolve first).
	Open(path string) (ContentReader, error)
	// Walk iterates over all live (non-deleted) entries under prefix in
	// lexical order. The callback may return ErrWalkStop to halt early.
	Walk(prefix string, fn func(*FileEntry) error) error
	// Entries returns the count of live entries.
	Entries() int
}

// ContentReader is a minimal io.ReadCloser alias kept in-model to avoid an
// "io" import fan-out for callers that only need the type name.
type ContentReader interface {
	Read(p []byte) (n int, err error)
	Close() error
}

// ErrWalkStop is a sentinel a Walk callback may return to stop iteration
// without it being treated as an error by the caller.
var ErrWalkStop = errWalkStop{}

type errWalkStop struct{}

func (errWalkStop) Error() string { return "walk stopped" }

// --- Operating system -----------------------------------------------------

// OperatingSystem is the normalized distro identity parsed from os-release.
// Distro context is mandatory for correct vendor-first vulnerability
// matching: the same package/version can be vulnerable in one distro and
// patched in another.
type OperatingSystem struct {
	Name      string   `json:"name"`       // debian, ubuntu, alpine, rhel, ...
	VersionID string   `json:"version_id"` // 12, 24.04, 3.20
	Codename  string   `json:"codename,omitempty"`
	IDLike    []string `json:"id_like,omitempty"`
	Pretty    string   `json:"pretty,omitempty"`
}

// Version is a convenience alias for VersionID used by the matcher and
// output formatters. Returns VersionID.
func (o OperatingSystem) Version() string { return o.VersionID }

// ImageConfig is the normalized container image configuration used by the
// secret, hardening, and misconfiguration analyzers. It mirrors the OCI
// image config fields without depending on the go-containerregistry package.
type ImageConfig struct {
	User         string            `json:"user,omitempty"`
	WorkingDir   string            `json:"working_dir,omitempty"`
	Env          []string          `json:"env,omitempty"`
	Entrypoint   []string          `json:"entrypoint,omitempty"`
	Cmd          []string          `json:"cmd,omitempty"`
	ExposedPorts []string          `json:"exposed_ports,omitempty"`
	Volumes      []string          `json:"volumes,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	StopSignal   string            `json:"stop_signal,omitempty"`
	Healthcheck  *Healthcheck      `json:"healthcheck,omitempty"`
}

// Healthcheck mirrors the OCI healthcheck configuration.
type Healthcheck struct {
	Test        []string `json:"test,omitempty"`
	Interval    int64    `json:"interval,omitempty"`
	Timeout     int64    `json:"timeout,omitempty"`
	StartPeriod int64    `json:"start_period,omitempty"`
	Retries     int      `json:"retries,omitempty"`
}

// --- Package catalog ------------------------------------------------------

// Package is a discovered installable, OS or language, with layer
// attribution. Locations records every filesystem path that contributed to
// the discovery (e.g. dpkg status + the installed file list is not stored
// here, but the metadata file is).
type Package struct {
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	Type           string            `json:"type"`      // apk, deb, rpm, npm, pypi, maven, golang, cargo
	Ecosystem      string            `json:"ecosystem"` // PURL ecosystem qualifier
	PURL           string            `json:"purl"`
	CPEs           []string          `json:"cpes,omitempty"`
	DistroName     string            `json:"distro_name,omitempty"`
	DistroVersion  string            `json:"distro_version,omitempty"`
	Architecture   string            `json:"architecture,omitempty"`
	SourcePackage  string            `json:"source_package,omitempty"`
	SourceVersion  string            `json:"source_version,omitempty"`
	Locations      []Location        `json:"locations"`
	LayerDigest    string            `json:"layer_digest,omitempty"`
	// LayerCreatedBy is the image config history "created_by" command for the
	// layer that introduced this package. Populated by the scanner pipeline
	// during the cataloging phase using LayerProvenance data.
	LayerCreatedBy string            `json:"layer_created_by,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Location ties a package discovery signal to a filesystem path and the
// layer that introduced it.
type Location struct {
	Path        string `json:"path"`
	LayerDigest string `json:"layer_digest,omitempty"`
}

// --- Findings (forward-compatible with the platform) ----------------------

// Severity is the normalized severity ranking used across all finding types.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence is an integer 0..100 expressing how strongly the matcher
// believes a finding is real and correctly attributed. The thresholds are
// documented in the matching engine; <50 means audit-only, never block.
type Confidence int

// FindingType discriminates the kind of finding. Phase 1 only emits
// SBOM/catalog findings; vulnerability, secret, and hardening types are
// declared now so output consumers can branch without reshaping later.
type FindingType string

const (
	FindingTypeVulnerability FindingType = "VULNERABILITY"
	FindingTypeSecret        FindingType = "SECRET"
	FindingTypeHardening     FindingType = "IMAGE_HARDENING"
	FindingTypeMisconfig     FindingType = "MISCONFIGURATION"
)

// Finding is the normalized, explainable finding shape. It carries enough
// provenance (LayerDigest, MatchType, Evidence) for the platform to render
// "where it came from and how to remove it" without re-running the scanner.
type Finding struct {
	ID               string      `json:"id"`
	Type             FindingType `json:"type"`
	Severity         Severity    `json:"severity"`
	Confidence       Confidence  `json:"confidence"`
	Title            string      `json:"title"`
	Description      string      `json:"description,omitempty"`

	// Vulnerability fields (populated by Phase 2 matcher).
	VulnerabilityID  string    `json:"vulnerability_id,omitempty"`
	Aliases          []string  `json:"aliases,omitempty"`
	CVSSScore        float64   `json:"cvss_score,omitempty"`

	// Package context.
	PackageName      string `json:"package_name,omitempty"`
	PackageVersion   string `json:"package_version,omitempty"`
	PackageType      string `json:"package_type,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`

	// Match provenance.
	MatchType      string     `json:"match_type,omitempty"`
	LayerDigest    string     `json:"layer_digest,omitempty"`
	LayerCreatedBy string     `json:"layer_created_by,omitempty"`
	Locations      []Location `json:"locations,omitempty"`
	Evidence       []Evidence `json:"evidence,omitempty"`

	Recommendation string    `json:"recommendation,omitempty"`
	AdvisoryURL    string    `json:"advisory_url,omitempty"`
	DetectedAt     time.Time `json:"detected_at"`
}

// Evidence is one piece of explainable matching signal. Source names the
// advisory feed. MatchField/MatchValue identify what was compared; Reason is
// a human-readable justification string.
type Evidence struct {
	Source     string `json:"source"`
	MatchField string `json:"match_field,omitempty"`
	MatchValue string `json:"match_value,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// --- Scan result ----------------------------------------------------------

// ScanResult is the top-level engine output. Phase 1 populates Image, OS,
// Packages, Layers, and (optionally) Findings=empty; later phases fill in
// vulnerability/secret/hardening findings and the Policy decision.
type ScanResult struct {
	Image     ImageIdentity      `json:"image"`
	OS        *OperatingSystem   `json:"os,omitempty"`
	Config    *ImageConfig       `json:"config,omitempty"`
	Layers    []LayerProvenance  `json:"layers"`
	Packages  []Package          `json:"packages"`
	Findings  []Finding          `json:"findings"`
	SBOM      *SBOM              `json:"sbom,omitempty"`
	Decision  *PolicyDecision    `json:"decision,omitempty"`
	Scanner   ScannerInfo        `json:"scanner"`
	StartedAt time.Time          `json:"started_at"`
	EndedAt   time.Time          `json:"ended_at"`
}

// SBOM is the PatchFlow-native SBOM envelope. The CycloneDX/SPDX exporters
// project from this shape.
type SBOM struct {
	Image       ImageIdentity    `json:"image"`
	OS          *OperatingSystem `json:"os,omitempty"`
	Packages    []Package        `json:"packages"`
	GeneratedAt time.Time        `json:"generated_at"`
}

// PolicyDecision is the output of the policy evaluator: should this image
// ship, why, and what is the safest patch path. Phase 1 leaves this nil.
type PolicyDecision struct {
	Decision string `json:"decision"` // allow, warn, block
	Reason   string `json:"reason,omitempty"`
}

// ScannerInfo records which engine version produced the result, so cache
// keys and the platform can invalidate on upgrade.
type ScannerInfo struct {
	Version          string `json:"version"`
	CatalogerVersion string `json:"cataloger_version"`
	VulnDBVersion    string `json:"vuln_db_version,omitempty"`
}
