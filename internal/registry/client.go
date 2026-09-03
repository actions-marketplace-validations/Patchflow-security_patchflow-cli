// Package registry provides package registry metadata lookup for license
// information. It queries npm, PyPI, and Maven Central registries to fetch
// license data for dependencies where the lockfile/manifest does not include
// license fields.
//
// All lookups are cached on disk in a global XDG-compliant cache location
// (resolved via cacheutil) so repeated scans skip network calls for unchanged
// packages without polluting the project directory.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
	"github.com/Patchflow-security/patchflow-cli/internal/cacheutil"
	"github.com/Patchflow-security/patchflow-cli/internal/licensedetect"
	"gopkg.in/yaml.v3"
)

const (
	// Registry API endpoints.
	NPMRegistryURL  = "https://registry.npmjs.org"
	PyPIRegistryURL = "https://pypi.org/pypi"
	MavenCentralURL = "https://search.maven.org/solrsearch/select"
	DefaultTimeout  = 30 * time.Second

	// CacheTTL is how long registry metadata is cached before re-fetching.
	CacheTTL = 24 * time.Hour
)

// MetadataClient fetches package license info from public registries.
type MetadataClient struct {
	HTTPClient     *http.Client
	cache          *Cache
	licenseFetcher *licensedetect.Fetcher
}

// NewMetadataClient creates a registry metadata client with default settings.
func NewMetadataClient() *MetadataClient {
	return &MetadataClient{
		HTTPClient:     &http.Client{Timeout: DefaultTimeout},
		licenseFetcher: licensedetect.NewFetcher(),
	}
}

// SetCache attaches an optional disk cache.
func (c *MetadataClient) SetCache(cache *Cache) {
	c.cache = cache
}

// FetchLicenses fetches license info for all dependencies that don't already
// have a license string. Dependencies with a non-empty License field are
// skipped. Returns a map of dep name@version -> license string.
//
// Lookups are parallelized per ecosystem with a concurrency limit to avoid
// overwhelming registry APIs. Network errors for individual packages are
// non-fatal — the function returns whatever it can fetch.
func (c *MetadataClient) FetchLicenses(ctx context.Context, deps []analysis.Dependency) map[string]string {
	results := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore to limit concurrent HTTP requests (avoid rate limiting).
	sem := make(chan struct{}, 20)

	for _, dep := range deps {
		if dep.License != "" {
			// Already have license info from the manifest — skip.
			mu.Lock()
			results[depKey(dep)] = dep.License
			mu.Unlock()
			continue
		}
		if dep.Name == "" || dep.Version == "" {
			continue
		}

		wg.Add(1)
		go func(d analysis.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			license := c.fetchLicenseForDep(ctx, d)
			if license != "" {
				mu.Lock()
				results[depKey(d)] = license
				mu.Unlock()
			}
		}(dep)
	}

	wg.Wait()
	return results
}

// depKey creates a unique key for a dependency: "ecosystem:name@version".
func depKey(d analysis.Dependency) string {
	if d.Repository != "" {
		return fmt.Sprintf("%s:%s:%s@%s", d.Ecosystem, d.Repository, d.Name, d.Version)
	}
	return fmt.Sprintf("%s:%s@%s", d.Ecosystem, d.Name, d.Version)
}

// isUninformativeLicense returns true if the license string is empty or a
// non-informative placeholder that should trigger a fallback lookup.
// Values like "Other", "UNKNOWN", "NOASSERTION", "N/A", "none" provide no
// actionable license information and should be treated as missing.
func isUninformativeLicense(lic string) bool {
	lic = strings.TrimSpace(lic)
	if lic == "" {
		return true
	}
	upper := strings.ToUpper(lic)
	uninformative := []string{
		"OTHER", "UNKNOWN", "NOASSERTION", "N/A", "NA", "NONE", "NULL",
		"NOT SPECIFIED", "NOT SET", "MISSING", "UNLICENSED", "SEE LICENSE FILE",
		"SEE LICENSE FILE FOR DETAILS", "LICENSED", "CUSTOM", "FREE",
	}
	for _, u := range uninformative {
		if upper == u {
			return true
		}
	}
	return false
}

// fetchLicenseForDep dispatches to the appropriate registry based on ecosystem.
func (c *MetadataClient) fetchLicenseForDep(ctx context.Context, dep analysis.Dependency) string {
	// Check cache first. Has() distinguishes "not cached" from "cached as
	// empty" — both return "" from Get(), but we only want to skip the
	// network call when the entry actually exists in the cache.
	if c.cache != nil {
		if c.cache.Has(dep) {
			return c.cache.Get(dep)
		}
	}

	var license string
	switch dep.Ecosystem {
	case analysis.EcosystemNPM:
		license = c.fetchNPMLicense(ctx, dep.Name, dep.Version)
		if isUninformativeLicense(license) {
			if dep.Repository != "" {
				license = c.fetchGitHubLicense(ctx, dep.Repository)
			}
			// If still no luck, try extracting repo from npm full metadata
			if isUninformativeLicense(license) {
				if repo := c.fetchNPMRepositoryURL(ctx, dep.Name); repo != "" {
					license = c.fetchGitHubLicense(ctx, repo)
				}
			}
		}
	case analysis.EcosystemPyPI:
		license = c.fetchPyPILicense(ctx, dep.Name, dep.Version)
		if isUninformativeLicense(license) {
			if dep.Repository != "" {
				license = c.fetchGitHubLicense(ctx, dep.Repository)
			}
			// If still no luck, try extracting repo from PyPI metadata
			if isUninformativeLicense(license) {
				if repo := c.fetchPyPIRepositoryURL(ctx, dep.Name); repo != "" {
					license = c.fetchGitHubLicense(ctx, repo)
				}
			}
		}
	case analysis.EcosystemMaven:
		license = c.fetchMavenLicense(ctx, dep.Name, dep.Version)
		if isUninformativeLicense(license) {
			if dep.Repository != "" {
				license = c.fetchGitHubLicense(ctx, dep.Repository)
			}
		}
	case analysis.EcosystemRubyGems:
		license = c.fetchRubyGemsLicense(ctx, dep.Name, dep.Version)
		if isUninformativeLicense(license) {
			if dep.Repository != "" {
				license = c.fetchGitHubLicense(ctx, dep.Repository)
			}
			// If still no luck, try extracting repo from RubyGems metadata
			if isUninformativeLicense(license) {
				if repo := c.fetchRubyGemsRepositoryURL(ctx, dep.Name); repo != "" {
					license = c.fetchGitHubLicense(ctx, repo)
				}
			}
		}
	case analysis.EcosystemPackagist:
		license = c.fetchPackagistLicense(ctx, dep.Name, dep.Version)
	case analysis.EcosystemHelm:
		license = c.fetchHelmLicense(ctx, dep.Name, dep.Version, dep.Repository)
	case analysis.EcosystemGo:
		// Go modules don't have a registry; try GitHub API if we have a repo URL
		if dep.Repository != "" {
			license = c.fetchGitHubLicense(ctx, dep.Repository)
		} else {
			license = c.fetchGoModuleLicense(ctx, dep.Name)
		}
		// If the module path itself is a GitHub URL and the first lookup
		// returned nothing useful, try fetching directly
		if isUninformativeLicense(license) && strings.HasPrefix(dep.Name, "github.com/") {
			license = c.fetchGitHubLicense(ctx, strings.TrimPrefix(dep.Name, "github.com/"))
		}
	case analysis.EcosystemCargo:
		// Cargo crates: try crates.io API
		license = c.fetchCargoLicense(ctx, dep.Name, dep.Version)
	default:
		return ""
	}

	// Cache the result (including empty results to avoid re-fetching)
	if c.cache != nil {
		c.cache.Set(dep, license)
	}

	return license
}

// fetchHelmLicense fetches license metadata from a Helm repository index.yaml.
func (c *MetadataClient) fetchHelmLicense(ctx context.Context, name, version, repository string) string {
	if repository == "" || strings.HasPrefix(repository, "oci://") {
		return ""
	}

	url := strings.TrimRight(repository, "/") + "/index.yaml"
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var index struct {
		Entries map[string][]struct {
			Version     string            `yaml:"version"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(body, &index); err != nil {
		return ""
	}

	charts := index.Entries[name]
	for _, chart := range charts {
		if chart.Version == version {
			return helmLicenseFromAnnotations(chart.Annotations)
		}
	}
	if len(charts) > 0 {
		return helmLicenseFromAnnotations(charts[0].Annotations)
	}
	return ""
}

func helmLicenseFromAnnotations(annotations map[string]string) string {
	for _, key := range []string{
		"artifacthub.io/license",
		"artifacthub.io/licenses",
		"license",
		"licenses",
	} {
		if value := strings.TrimSpace(annotations[key]); value != "" {
			return value
		}
	}
	return ""
}

// fetchNPMLicense fetches license from the npm registry.
// API: GET https://registry.npmjs.org/{package}/{version}
// Falls back to extracting the repository URL and fetching from GitHub.
func (c *MetadataClient) fetchNPMLicense(ctx context.Context, name, version string) string {
	// Scoped packages (@scope/pkg) need the scope encoded in the URL.
	apiName := name
	if strings.HasPrefix(name, "@") {
		apiName = name
	}

	// First try the version-specific endpoint
	url := fmt.Sprintf("%s/%s/%s", NPMRegistryURL, apiName, version)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		// Fallback: try the package-level endpoint (latest)
		url = fmt.Sprintf("%s/%s", NPMRegistryURL, apiName)
		body, err = c.httpGet(ctx, url)
		if err != nil {
			return ""
		}
	}

	// Try parsing as version-specific response first (has license at top level)
	var resp struct {
		License    string `json:"license"`
		Licenses   []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"licenses"`
		Repository interface{} `json:"repository"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if resp.License != "" && resp.License != "UNKNOWN" && resp.License != "UNLICENSED" {
		return resp.License
	}
	if len(resp.Licenses) > 0 && resp.Licenses[0].Type != "" {
		return resp.Licenses[0].Type
	}

	// No license in registry — try GitHub via repository URL
	repoURL := extractNPMRepository(resp.Repository)
	if repoURL != "" {
		if lic := c.fetchGitHubLicense(ctx, repoURL); lic != "" {
			return lic
		}
	}

	// If the version-specific endpoint didn't have repository info,
	// try the package-level endpoint which has a top-level repository field
	pkgURL := fmt.Sprintf("%s/%s", NPMRegistryURL, apiName)
	pkgBody, err := c.httpGet(ctx, pkgURL)
	if err == nil {
		var pkgResp struct {
			Repository interface{} `json:"repository"`
		}
		if json.Unmarshal(pkgBody, &pkgResp) == nil {
			repoURL = extractNPMRepository(pkgResp.Repository)
			if repoURL != "" {
				return c.fetchGitHubLicense(ctx, repoURL)
			}
		}
	}

	return ""
}

// extractNPMRepository extracts a GitHub owner/repo from the npm repository
// field. The repository field can be:
// - A string: "git+https://github.com/owner/repo.git"
// - An object: { "type": "git", "url": "https://github.com/owner/repo.git" }
func extractNPMRepository(repo interface{}) string {
	if repo == nil {
		return ""
	}

	var url string
	switch v := repo.(type) {
	case string:
		url = v
	case map[string]interface{}:
		if u, ok := v["url"].(string); ok {
			url = u
		}
	default:
		return ""
	}

	return extractGitHubRepo(url)
}

// fetchNPMRepositoryURL fetches the repository URL from the npm registry's
// full package metadata (not version-specific). This is useful when the
// version-specific response doesn't include a repository field.
func (c *MetadataClient) fetchNPMRepositoryURL(ctx context.Context, name string) string {
	url := fmt.Sprintf("%s/%s", NPMRegistryURL, name)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	// The full package metadata has a top-level "repository" field
	var resp struct {
		Repository interface{} `json:"repository"`
		Homepage   string      `json:"homepage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if repo := extractNPMRepository(resp.Repository); repo != "" {
		return repo
	}

	// Try homepage URL — sometimes it's a GitHub URL
	if repo := extractGitHubRepo(resp.Homepage); repo != "" {
		return repo
	}
	return ""
}

// fetchPyPIRepositoryURL fetches the repository URL from PyPI's JSON API.
// PyPI metadata includes project_urls with keys like "Homepage", "Source",
// "Repository" that may point to GitHub.
func (c *MetadataClient) fetchPyPIRepositoryURL(ctx context.Context, name string) string {
	name = strings.Split(name, "[")[0]
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	url := fmt.Sprintf("%s/%s/json", PyPIRegistryURL, name)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var resp struct {
		Info struct {
			ProjectURLs map[string]string `json:"project_urls"`
			Homepage    string            `json:"home_page"`
			PackageURL  string            `json:"package_url"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	// Check project_urls for GitHub links
	for _, u := range resp.Info.ProjectURLs {
		if repo := extractGitHubRepo(u); repo != "" {
			return repo
		}
	}

	// Try homepage
	if repo := extractGitHubRepo(resp.Info.Homepage); repo != "" {
		return repo
	}

	// Try package_url (sometimes it's a GitHub URL for GitHub-hosted packages)
	if repo := extractGitHubRepo(resp.Info.PackageURL); repo != "" {
		return repo
	}
	return ""
}

// fetchRubyGemsRepositoryURL fetches the repository URL from RubyGems API.
// RubyGems returns source_code_uri, homepage_uri, and repository_uri.
func (c *MetadataClient) fetchRubyGemsRepositoryURL(ctx context.Context, name string) string {
	name = strings.TrimSpace(name)
	// Strip version constraints
	for _, sep := range []string{" ", "~", ">", "<", "=", "!"} {
		if idx := strings.Index(name, sep); idx > 0 {
			name = name[:idx]
		}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	url := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", name)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var resp struct {
		SourceCode string `json:"source_code_uri"`
		Homepage   string `json:"homepage_uri"`
		Repo       string `json:"repository_uri"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	for _, u := range []string{resp.SourceCode, resp.Repo, resp.Homepage} {
		if repo := extractGitHubRepo(u); repo != "" {
			return repo
		}
	}
	return ""
}

// fetchPyPILicense fetches license from PyPI JSON API.
// API: GET https://pypi.org/pypi/{package}/{version}/json
// If version is empty, uses the latest version endpoint.
func (c *MetadataClient) fetchPyPILicense(ctx context.Context, name, version string) string {
	// Clean the name — might have extras like "package[extra]" or version constraints
	name = strings.Split(name, "[")[0]
	name = strings.TrimSpace(name)

	var body []byte
	var err error

	if version == "" || version == "unknown" || version == "UNKNOWN" {
		// No version — use the latest endpoint
		url := fmt.Sprintf("%s/%s/json", PyPIRegistryURL, name)
		body, err = c.httpGet(ctx, url)
	} else {
		// Try version-specific endpoint first
		url := fmt.Sprintf("%s/%s/%s/json", PyPIRegistryURL, name, version)
		body, err = c.httpGet(ctx, url)
		if err != nil {
			// Fallback: try without version (latest)
			url = fmt.Sprintf("%s/%s/json", PyPIRegistryURL, name)
			body, err = c.httpGet(ctx, url)
		}
	}
	if err != nil {
		return ""
	}

	var resp struct {
		Info struct {
			License     string   `json:"license"`
			Classifiers []string `json:"classifiers"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if !isUninformativeLicense(resp.Info.License) {
		return resp.Info.License
	}

	// Fallback: extract from classifiers (e.g., "License :: OSI Approved :: MIT License")
	for _, classifier := range resp.Info.Classifiers {
		if strings.HasPrefix(classifier, "License ::") {
			parts := strings.Split(classifier, " :: ")
			if len(parts) >= 3 {
				licName := parts[len(parts)-1]
				// Map common classifier names to SPDX identifiers
				classifierMap := map[string]string{
					"MIT License":              "MIT",
					"Apache Software License":  "Apache-2.0",
					"BSD License":              "BSD-3-Clause",
					"GNU General Public License (GPL)": "GPL-3.0",
					"GNU General Public License v2 (GPLv2)": "GPL-2.0",
					"GNU General Public License v3 (GPLv3)": "GPL-3.0",
					"GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
					"GNU Library or Lesser General Public License (LGPL)": "LGPL-2.1",
					"Mozilla Public License 1.0 (MPL)": "MPL-1.0",
					"Mozilla Public License 1.1 (MPL 1.1)": "MPL-1.1",
					"Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
					"Python Software Foundation License": "Python-2.0",
					"ISC License (ISCL)": "ISC",
					"Academic Free License (AFL)": "AFL-3.0",
					"Eclipse Public License 1.0 (EPL-1.0)": "EPL-1.0",
					"Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
					"GNU Affero General Public License v3": "AGPL-3.0",
					"Creative Commons Attribution 4.0": "CC-BY-4.0",
					"Creative Commons Attribution 3.0": "CC-BY-3.0",
					"Public Domain": "CC0-1.0",
					"Boost Software License 1.0 (BSL-1.0)": "BSL-1.0",
					"The Unlicense (Unlicense)": "Unlicense",
					"WTFPL": "WTFPL",
					"zlib/libpng License": "Zlib",
					"Open Software License 3.0 (OSL-3.0)": "OSL-3.0",
					"Common Development and Distribution License 1.0 (CDDL-1.0)": "CDDL-1.0",
					"European Union Public Licence 1.1 (EUPL 1.1)": "EUPL-1.1",
					"European Union Public Licence 1.2 (EUPL 1.2)": "EUPL-1.2",
					"Microsoft Public License (Ms-PL)": "MS-PL",
					"Microsoft Reciprocal License (Ms-RL)": "MS-RL",
					"Sun Public License v1.0": "SPL-1.0",
					"Sun Industry Standards Source License v1.1": "SISSL",
					"Common Public License 1.0 (CPL)": "CPL-1.0",
					"Netscape Public License (NPL)": "NPL-1.1",
					"IBM Public License 1.0": "IPL-1.0",
					"Intel Open Source License": "Intel",
					"Nokia Open Source License": "Nokia-1.0a",
					"Open Group Test Suite License": "OGTSL",
					"Python License (CNRI Python License)": "CNRI-Python",
					"Q Public License (QPL)": "QPL-1.0",
					"Ricoh Source Code Public License": "RSCPL",
					"Sleepycat License": "Sleepycat",
					"Vovida Software License v1.0": "VSL-1.0",
					"X.Net License": "Xnet",
					"Zope Public License": "ZPL-2.0",
					"Attribution Assurance License": "AAL",
					"BSD 3-Clause License (New BSD)": "BSD-3-Clause",
					"BSD 2-Clause License (Simplified BSD)": "BSD-2-Clause",
				}
				if spdx, ok := classifierMap[licName]; ok {
					return spdx
				}
				return licName
			}
		}
	}
	return ""
}

// fetchMavenLicense fetches license from Maven Central by parsing the POM file.
// The POM XML contains <licenses><license><name>...</name></license></licenses>.
// We fetch the POM directly from Maven Central's repository.
func (c *MetadataClient) fetchMavenLicense(ctx context.Context, name, version string) string {
	// Maven coordinates are groupId:artifactId
	parts := strings.SplitN(name, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	groupID := parts[0]
	artifactID := parts[1]

	// If version is empty or "unknown", try to find latest version via search API
	if version == "" || version == "unknown" || version == "UNKNOWN" {
		version = c.fetchMavenLatestVersion(ctx, groupID, artifactID)
		if version == "" {
			// Can't fetch POM without version — try GitHub fallback directly
			return c.fetchMavenLicenseViaGitHub(ctx, groupID, artifactID)
		}
	}

	// Fetch the POM file from Maven Central
	// Path: {groupID with / instead of .}/{artifactID}/{version}/{artifactID}-{version}.pom
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	pomURL := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.pom",
		groupPath, artifactID, version, artifactID, version)

	body, err := c.httpGet(ctx, pomURL)
	if err != nil {
		// Fallback: try search API which may have license info for some artifacts
		lic := c.fetchMavenLicenseViaSearch(ctx, groupID, artifactID)
		if lic != "" {
			return lic
		}
		// Last resort: try GitHub via common groupId -> repo mapping
		return c.fetchMavenLicenseViaGitHub(ctx, groupID, artifactID)
	}

	// Parse <licenses> from POM XML
	lic := parseMavenPOMLicense(body)
	if lic != "" {
		return lic
	}

	// No license in POM — try extracting SCM URL and fetching from GitHub
	scmRepo := parseMavenPOMSCM(body)
	if scmRepo != "" {
		if ghLic := c.fetchGitHubLicense(ctx, scmRepo); ghLic != "" {
			return ghLic
		}
	}

	// Last resort: try GitHub via common groupId -> repo mapping
	return c.fetchMavenLicenseViaGitHub(ctx, groupID, artifactID)
}

// fetchMavenLatestVersion fetches the latest version of a Maven artifact
// via the search API. Tries multiple query formats.
func (c *MetadataClient) fetchMavenLatestVersion(ctx context.Context, groupID, artifactID string) string {
	// Try 1: standard query with core=gav
	url := fmt.Sprintf("%s?q=g:%s+AND+a:%s&core=gav&rows=1&wt=json", MavenCentralURL, groupID, artifactID)
	body, err := c.httpGet(ctx, url)
	if err == nil {
		var resp struct {
			Response struct {
				Docs []struct {
					Version string `json:"v"`
				} `json:"docs"`
			} `json:"response"`
		}
		if json.Unmarshal(body, &resp) == nil && len(resp.Response.Docs) > 0 {
			return resp.Response.Docs[0].Version
		}
	}

	// Try 2: without core param
	url = fmt.Sprintf("%s?q=g:%s+AND+a:%s&rows=1&wt=json", MavenCentralURL, groupID, artifactID)
	body, err = c.httpGet(ctx, url)
	if err == nil {
		var resp struct {
			Response struct {
				Docs []struct {
					Version string `json:"v"`
				} `json:"docs"`
			} `json:"response"`
		}
		if json.Unmarshal(body, &resp) == nil && len(resp.Response.Docs) > 0 {
			return resp.Response.Docs[0].Version
		}
	}

	// Try 3: URL-encoded query (some artifacts need this)
	url = fmt.Sprintf("%s?q=g:%%22%s%%22+AND+a:%%22%s%%22&rows=1&wt=json", MavenCentralURL, groupID, artifactID)
	body, err = c.httpGet(ctx, url)
	if err == nil {
		var resp struct {
			Response struct {
				Docs []struct {
					Version string `json:"v"`
				} `json:"docs"`
			} `json:"response"`
		}
		if json.Unmarshal(body, &resp) == nil && len(resp.Response.Docs) > 0 {
			return resp.Response.Docs[0].Version
		}
	}
	return ""
}

// fetchMavenLicenseViaSearch tries the Maven Solr search API which sometimes
// has license info embedded.
func (c *MetadataClient) fetchMavenLicenseViaSearch(ctx context.Context, groupID, artifactID string) string {
	url := fmt.Sprintf("%s?q=g:%s+AND+a:%s&rows=1&wt=json", MavenCentralURL, groupID, artifactID)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var resp struct {
		Response struct {
			Docs []struct {
				Licenses []string `json:"licenses"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if len(resp.Response.Docs) > 0 && len(resp.Response.Docs[0].Licenses) > 0 {
		return resp.Response.Docs[0].Licenses[0]
	}
	return ""
}

// parseMavenPOMLicense extracts the first license name from a POM XML body.
func parseMavenPOMLicense(body []byte) string {
	// Simple XML parsing without full DOM — extract <license> blocks
	text := string(body)
	// Find all <name>...</name> within <licenses>...</licenses>
	licensesStart := strings.Index(text, "<licenses>")
	if licensesStart < 0 {
		// Try namespace-prefixed: <licenses xmlns=...>
		licensesStart = strings.Index(text, "<licenses")
	}
	if licensesStart < 0 {
		return ""
	}
	licensesEnd := strings.Index(text[licensesStart:], "</licenses>")
	if licensesEnd < 0 {
		return ""
	}
	licensesBlock := text[licensesStart : licensesStart+licensesEnd+11]

	// Find first <name>...</name> within the licenses block
	nameStart := strings.Index(licensesBlock, "<name>")
	if nameStart < 0 {
		// Try namespace-prefixed
		nameStart = strings.Index(licensesBlock, "<name ")
		if nameStart >= 0 {
			// Skip to the > after attributes
			gt := strings.Index(licensesBlock[nameStart:], ">")
			if gt >= 0 {
				nameStart += gt + 1
				nameEnd := strings.Index(licensesBlock[nameStart:], "</name>")
				if nameEnd >= 0 {
					return strings.TrimSpace(licensesBlock[nameStart : nameStart+nameEnd])
				}
			}
		}
		return ""
	}
	nameStart += 6 // length of "<name>"
	nameEnd := strings.Index(licensesBlock[nameStart:], "</name>")
	if nameEnd < 0 {
		return ""
	}
	return strings.TrimSpace(licensesBlock[nameStart : nameStart+nameEnd])
}

// parseMavenPOMSCM extracts the SCM URL from a POM XML body and normalizes
// it to an owner/repo format for GitHub. Returns "" if no GitHub SCM URL found.
func parseMavenPOMSCM(body []byte) string {
	text := string(body)

	// Find <scm>...</scm> block
	scmStart := strings.Index(text, "<scm>")
	if scmStart < 0 {
		scmStart = strings.Index(text, "<scm ")
	}
	if scmStart < 0 {
		return ""
	}
	scmEnd := strings.Index(text[scmStart:], "</scm>")
	if scmEnd < 0 {
		return ""
	}
	scmBlock := text[scmStart : scmStart+scmEnd+6]

	// Look for <url> or <connection> or <developerConnection> within scm
	for _, tag := range []string{"<url>", "<connection>", "<developerConnection>"} {
		tagStart := strings.Index(scmBlock, tag)
		if tagStart < 0 {
			// Try namespace-prefixed
			tagShort := strings.TrimSuffix(tag, ">")
			tagStart = strings.Index(scmBlock, tagShort+" ")
			if tagStart >= 0 {
				gt := strings.Index(scmBlock[tagStart:], ">")
				if gt >= 0 {
					tagStart += gt + 1
					tagEnd := strings.Index(scmBlock[tagStart:], "</"+tagShort[1:]+">")
					if tagEnd >= 0 {
						url := strings.TrimSpace(scmBlock[tagStart : tagStart+tagEnd])
						if repo := extractGitHubRepo(url); repo != "" {
							return repo
						}
					}
				}
			}
			continue
		}
		tagStart += len(tag)
		tagEndTag := "</" + tag[1:]
		tagEnd := strings.Index(scmBlock[tagStart:], tagEndTag)
		if tagEnd >= 0 {
			url := strings.TrimSpace(scmBlock[tagStart : tagStart+tagEnd])
			if repo := extractGitHubRepo(url); repo != "" {
				return repo
			}
		}
	}
	return ""
}

// extractGitHubRepo tries to extract an owner/repo string from a URL.
// Handles: https://github.com/owner/repo, git@github.com:owner/repo.git,
// scm:git:https://github.com/owner/repo.git, etc.
func extractGitHubRepo(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}

	// Strip common prefixes
	for _, prefix := range []string{"scm:git:", "scm:svn:", "git:", "git+ssh:", "git+https:"} {
		url = strings.TrimPrefix(url, prefix)
	}

	// Normalize git@github.com:owner/repo -> github.com/owner/repo
	if strings.HasPrefix(url, "git@github.com:") {
		url = "github.com/" + strings.TrimPrefix(url, "git@github.com:")
	}

	// Strip protocol
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Must be github.com/owner/repo
	if !strings.HasPrefix(url, "github.com/") {
		return ""
	}

	url = strings.TrimPrefix(url, "github.com/")
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")

	// Take first two segments
	parts := strings.Split(url, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

// fetchMavenLicenseViaGitHub tries to guess the GitHub repository from the
// Maven groupId and fetch the license from there. This is a last-resort
// fallback when the POM has no license info and no SCM URL.
func (c *MetadataClient) fetchMavenLicenseViaGitHub(ctx context.Context, groupID, artifactID string) string {
	// Common mappings: many open-source projects use their GitHub org
	// as the Maven groupId (reversed domain). Try to map:
	// com.fasterxml.jackson.core -> github.com/FasterXML/jackson
	// org.apache.logging.log4j -> github.com/apache/logging-log4j2
	// org.springframework -> github.com/spring-projects/spring-framework
	knownMappings := map[string]string{
		"com.fasterxml.jackson.core":            "FasterXML/jackson",
		"com.fasterxml.jackson.dataformat":      "FasterXML/jackson-dataformat-xml",
		"com.fasterxml.jackson.datatype":        "FasterXML/jackson-datatypes-misc",
		"com.fasterxml.jackson.module":          "FasterXML/jackson-modules-java8",
		"org.apache.logging.log4j":              "apache/logging-log4j2",
		"org.apache.commons":                    "apache/commons-lang",
		"org.apache.maven":                      "apache/maven",
		"org.apache.velocity":                   "apache/velocity-engine-core",
		"org.apache.felix":                      "apache/felix",
		"org.apache.httpcomponents":             "apache/httpcomponents-client",
		"org.apache.httpcomponents.core5":       "apache/httpcomponents-core",
		"org.apache.kafka":                      "apache/kafka",
		"org.apache.zookeeper":                  "apache/zookeeper",
		"org.apache.curator":                    "apache/curator",
		"org.apache.avro":                       "apache/avro",
		"org.apache.thrift":                     "apache/thrift",
		"org.apache.poi":                        "apache/poi",
		"org.apache.camel":                      "apache/camel",
		"org.apache.activemq":                   "apache/activemq",
		"org.apache.lucene":                     "apache/lucene",
		"org.apache.solr":                       "apache/solr",
		"org.apache.tomcat":                     "apache/tomcat",
		"org.apache.tomcat.embed":               "apache/tomcat",
		"org.apache.dubbo":                      "apache/dubbo",
		"org.apache.shardingsphere":             "apache/shardingsphere",
		"org.springframework":                   "spring-projects/spring-framework",
		"org.springframework.boot":              "spring-projects/spring-boot",
		"org.springframework.data":              "spring-projects/spring-data-jpa",
		"org.springframework.security":          "spring-projects/spring-security",
		"org.springframework.cloud":             "spring-cloud/spring-cloud-commons",
		"org.springframework.amqp":              "spring-projects/spring-amqp",
		"org.springframework.batch":             "spring-projects/spring-batch",
		"org.springframework.ws":                "spring-projects/spring-ws",
		"org.hibernate":                         "hibernate/hibernate-orm",
		"org.hibernate.validator":               "hibernate/hibernate-validator",
		"org.hibernate.search":                  "hibernate/hibernate-search",
		"org.hibernate.common":                  "hibernate/hibernate-commons-annotations",
		"org.jboss":                             "jboss/jboss-parent",
		"org.jboss.spec.javax.jms":              "jboss/jboss-jms-api-spec",
		"org.jboss.logging":                     "jboss-logging/jboss-logging",
		"org.jboss.netty":                       "netty/netty",
		"org.junit.jupiter":                     "junit-team/junit5",
		"org.junit.vintage":                     "junit-team/junit5",
		"org.junit.platform":                    "junit-team/junit5",
		"org.eclipse.tycho":                     "eclipse/tycho",
		"org.eclipse.osgi":                      "eclipse-equinox/equinox",
		"org.eclipse.persistence":               "eclipse-ee4j/eclipselink",
		"com.google.guava":                      "google/guava",
		"com.google.protobuf":                   "protocolbuffers/protobuf",
		"com.google.code.gson":                  "google/gson",
		"com.google.code.findbugs":              "findbugsproject/findbugs",
		"com.google.errorprone":                 "google/error-prone",
		"com.google.inject":                     "google/guice",
		"com.google.android":                    "google/android",
		"com.google.api-client":                 "googleapis/google-api-java-client",
		"com.google.oauth-client":               "googleapis/google-oauth-java-client",
		"com.google.http-client":                "googleapis/google-http-java-client",
		"com.google.cloud":                      "googleapis/google-cloud-java",
		"com.google.firebase":                   "firebase/firebase-admin-java",
		"io.netty":                              "netty/netty",
		"io.grpc":                               "grpc/grpc-java",
		"io.opentelemetry":                      "open-telemetry/opentelemetry-java",
		"io.micrometer":                         "micrometer-metrics/micrometer",
		"io.projectreactor":                     "reactor/reactor-core",
		"io.prometheus":                         "prometheus/client_java",
		"com.squareup.okhttp3":                  "square/okhttp",
		"com.squareup.okio":                     "square/okio",
		"com.squareup.retrofit2":                "square/retrofit",
		"com.squareup.moshi":                    "square/moshi",
		"com.squareup.javapoet":                 "square/javapoet",
		"com.squareup.kotlinpoet":               "square/kotlinpoet",
		"com.zaxxer":                            "brettwooldridge/HikariCP",
		"com.zaxxer.hikari":                     "brettwooldridge/HikariCP",
		"com.h2database":                        "h2database/h2database",
		"com.mysql":                             "mysql/mysql-connector-j",
		"com.mysql.jdbc":                        "mysql/mysql-connector-j",
		"org.postgresql":                        "pgjdbc/pgjdbc",
		"com.github.spullara.mustache.java":     "spullara/mustache.java",
		"com.github.javafaker":                  "DiUS/java-faker",
		"com.github.docker-java":                "docker-java/docker-java",
		"com.github.jknack":                     "jknack/handlebars.java",
		"com.github.tomakehurst":                "WireMock/wiremock-standalone",
		"commons-io":                            "apache/commons-io",
		"commons-codec":                         "apache/commons-codec",
		"commons-lang":                          "apache/commons-lang",
		"commons-logging":                       "apache/commons-logging",
		"commons-net":                           "apache/commons-net",
		"commons-collections":                   "apache/commons-collections",
		"commons-fileupload":                    "apache/commons-fileupload",
		"commons-beanutils":                     "apache/commons-beanutils",
		"commons-cli":                           "apache/commons-cli",
		"commons-compress":                      "apache/commons-compress",
		"commons-text":                          "apache/commons-text",
		"commons-math3":                         "apache/commons-math",
		"commons-configuration2":                "apache/commons-configuration",
		"junit":                                 "junit-team/junit4",
		"org.mockito":                           "mockito/mockito",
		"org.powermock":                         "powermock/powermock",
		"org.assertj":                           "assertj/assertj",
		"org.hamcrest":                          "hamcrest/JavaHamcrest",
		"org.slf4j":                             "qos-ch/slf4j",
		"ch.qos.logback":                        "qos-ch/logback",
		"org.reflections":                       "ronmamo/reflections",
		"org.projectlombok":                     "projectlombok/lombok",
		"org.jetbrains.kotlin":                  "JetBrains/kotlin",
		"org.jetbrains.kotlinx":                 "Kotlin/kotlinx.coroutines",
		"org.jetbrains.annotations":             "JetBrains/java-annotations",
		"org.scala-lang":                        "scala/scala",
		"org.scala-lang.modules":                "scala/scala-java8-compat",
		"org.codehaus.groovy":                   "apache/groovy",
		"org.codehaus.jackson":                  "codehaus/jackson",
		"org.codehaus.mojo":                     "mojohaus/versions-maven-plugin",
		"org.aspectj":                           "eclipse/org.aspectj",
		"org.ow2.asm":                           "eed3si9n/asm",
		"org.openjdk.nashorn":                   "openjdk/nashorn",
		"net.bytebuddy":                         "raphw/byte-buddy",
		"net.sf.json":                           "net.sf.json/json-lib",
		"net.sourceforge.htmlunit":              "HtmlUnit/htmlunit",
		"net.sourceforge.saxon":                 "Saxonica/Saxon-HE",
		"info.picocli":                          "remkop/picocli",
		"info.cukes":                            "cucumber/cucumber-jvm",
		"io.cucumber":                           "cucumber/cucumber-jvm",
		"jakarta.xml.bind":                      "eclipse-ee4j/jaxb-api",
		"jakarta.persistence":                   "eclipse-ee4j/eclipselink",
		"jakarta.annotation":                    "eclipse-ee4j/annotation-api",
		"jakarta.servlet":                       "eclipse-ee4j/servlet-api",
		"jakarta.validation":                    "eclipse-ee4j/bean-validation",
		"jakarta.transaction":                   "eclipse-ee4j/transactions-api",
		"jakarta.mail":                          "eclipse-ee4j/mail",
		"jakarta.ws.rs":                         "eclipse-ee4j/jaxrs-api",
		"javax.xml.bind":                        "javaee/jaxb-spec",
		"javax.servlet":                         "javaee/servlet-spec",
		"javax.persistence":                     "javaee/javaee-spec",
		"javax.validation":                      "javaee/bean-validation-spec",
		"javax.jms":                             "javaee/javaee-spec",
		"javax.annotation":                      "javaee/annotation-spec",
		"javax.mail":                            "javaee/mail",
		"javax.ws.rs":                           "javaee/jaxrs-spec",
		"p6spy":                                 "p6spy/p6spy",
		"redis.clients":                         "xetorthio/jedis",
		"org.redisson":                          "redisson/redisson",
		"org.lz4":                               "lz4/lz4-java",
		"org.xerial.snappy":                     "xerial/snappy-java",
		"org.conscrypt":                         "conscrypt/conscrypt",
		"org.bouncycastle":                      "bcgit/bc-java",
		"com.nimbusds":                          "Connect2Id/nimbus-jose-jwt",
		"net.minidev":                           "netplex/json-smart-v2",
		"org.dom4j":                             "dom4j/dom4j",
		"org.jdom":                              "hunterhacker/jdom",
		"org.yaml.snakeyaml":                    "snakeyaml/snakeyaml",
		"com.thoughtworks.xstream":              "x-stream/xstream",
		"com.esotericsoftware":                  "EsotericSoftware/yamlbeans",
		"org.eclipse.jgit":                      "eclipse-jgit/jgit",
		"org.eclipse.jdt":                       "eclipse/eclipse.jdt",
		"org.eclipse.core":                      "eclipse-platform/eclipse.platform",
	}

	// Try exact groupId match
	if repo, ok := knownMappings[groupID]; ok {
		if lic := c.fetchGitHubLicense(ctx, repo); lic != "" {
			return lic
		}
	}

	// Try prefix match (for sub-packages)
	for prefix, repo := range knownMappings {
		if strings.HasPrefix(groupID, prefix) {
			if lic := c.fetchGitHubLicense(ctx, repo); lic != "" {
				return lic
			}
		}
	}

	return ""
}
// API: GET https://rubygems.org/api/v1/gems/{name}.json
func (c *MetadataClient) fetchRubyGemsLicense(ctx context.Context, name, version string) string {
	// Clean the name — strip version constraints, quotes, etc.
	name = strings.TrimSpace(name)
	name = strings.Trim(name, `"'`)
	// Strip any version constraint that might be embedded
	for _, sep := range []string{" ", "~", ">", "<", "=", "!"} {
		if idx := strings.Index(name, sep); idx > 0 {
			name = name[:idx]
		}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	url := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", name)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var resp struct {
		Licenses   []string `json:"licenses"`
		License    string   `json:"license"`
		SourceCode string   `json:"source_code_uri"`
		Homepage   string   `json:"homepage_uri"`
		Repo       string   `json:"repository_uri"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if len(resp.Licenses) > 0 && !isUninformativeLicense(resp.Licenses[0]) {
		return resp.Licenses[0]
	}
	if !isUninformativeLicense(resp.License) {
		return resp.License
	}

	// Fallback: try GitHub via source_code/homepage/repo URI
	for _, url := range []string{resp.SourceCode, resp.Repo, resp.Homepage} {
		if repo := extractGitHubRepo(url); repo != "" {
			if lic := c.fetchGitHubLicense(ctx, repo); lic != "" {
				return lic
			}
		}
	}
	return ""
}

// fetchPackagistLicense fetches license from Packagist API.
// API: GET https://repo.packagist.org/p2/{vendor/package}.json
func (c *MetadataClient) fetchPackagistLicense(ctx context.Context, name, version string) string {
	url := fmt.Sprintf("https://repo.packagist.org/p2/%s.json", name)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var resp struct {
		Packages map[string][]struct {
			Version string   `json:"version"`
			License []string `json:"license"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if pkgs, ok := resp.Packages[name]; ok {
		for _, p := range pkgs {
			if p.Version == version && len(p.License) > 0 {
				return p.License[0]
			}
		}
		// Fallback: first entry
		if len(pkgs) > 0 && len(pkgs[0].License) > 0 {
			return pkgs[0].License[0]
		}
	}
	return ""
}

// fetchGitHubLicense fetches the license file from a GitHub repository
// using the GitHub API. The repository should be in "owner/repo" format.
// Returns the SPDX license identifier (e.g., "MIT", "Apache-2.0").
// If the GitHub API returns NOASSERTION or fails, falls back to fetching
// the raw LICENSE file and using text-based detection (licensee-style).
func (c *MetadataClient) fetchGitHubLicense(ctx context.Context, repo string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return ""
	}
	// Normalize: strip "github.com/" prefix if present
	repo = strings.TrimPrefix(repo, "github.com/")
	repo = strings.TrimPrefix(repo, "https://github.com/")
	repo = strings.TrimPrefix(repo, "http://github.com/")
	repo = strings.TrimSuffix(repo, ".git")

	// Must be in owner/repo format (possibly with extra path segments for
	// Go modules like owner/repo/v2 or owner/repo/subpath — take first 2).
	parts := strings.Split(repo, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	// Use only the first two segments (owner/repo). Extra segments like
	// /v2, /subpath, /proto are common in Go module paths.
	repo = fmt.Sprintf("%s/%s", parts[0], parts[1])

	// Try the GitHub API first
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/license", parts[0], parts[1])
	body, err := c.httpGet(ctx, url)
	if err == nil {
		var resp struct {
			License struct {
				SPDXID string `json:"spdx_id"`
				Name   string `json:"name"`
			} `json:"license"`
		}
		if json.Unmarshal(body, &resp) == nil {
			if resp.License.SPDXID != "" && resp.License.SPDXID != "NOASSERTION" {
				return resp.License.SPDXID
			}
			if resp.License.Name != "" && !isUninformativeLicense(resp.License.Name) {
				return resp.License.Name
			}
		}
	}

	// Fallback: fetch the raw LICENSE file and use text-based detection
	if c.licenseFetcher != nil {
		if lic := c.licenseFetcher.FetchLicenseFileFromRepo(ctx, repo); lic != "" {
			return lic
		}
	}

	return ""
}

// fetchGoModuleLicense fetches license info for a Go module by looking up
// the module's repository. Go modules follow the convention that the module
// path often corresponds to a VCS repository (e.g., github.com/owner/repo,
// golang.org/x/net -> go.googlesource.com/net).
func (c *MetadataClient) fetchGoModuleLicense(ctx context.Context, modulePath string) string {
	modulePath = strings.TrimSpace(modulePath)
	if modulePath == "" {
		return ""
	}

	// If the module path is a GitHub URL, use fetchGitHubLicense directly
	if strings.HasPrefix(modulePath, "github.com/") {
		return c.fetchGitHubLicense(ctx, strings.TrimPrefix(modulePath, "github.com/"))
	}

	// golang.org/x/* modules are hosted on go.googlesource.com.
	// The mapping is: golang.org/x/<name> -> go.googlesource.com/<name>
	// These repos all use the BSD-3-Clause license.
	if strings.HasPrefix(modulePath, "golang.org/x/") {
		return c.fetchGooglesourceLicense(ctx, strings.TrimPrefix(modulePath, "golang.org/x/"))
	}

	// google.golang.org/* modules (protobuf, grpc, etc.) are hosted on
	// github.com/golang/* or github.com/protocolbuffers/*
	if strings.HasPrefix(modulePath, "google.golang.org/") {
		// Map common google.golang.org modules to their GitHub repos
		googleModuleMap := map[string]string{
			"google.golang.org/protobuf":   "protocolbuffers/protobuf-go",
			"google.golang.org/grpc":        "grpc/grpc-go",
			"google.golang.org/genproto":    "googleapis/go-genproto",
			"google.golang.org/api":         "googleapis/google-api-go-client",
			"google.golang.org/appengine":   "golang/appengine",
			"google.golang.org/genproto/googleapis/api": "googleapis/go-genproto",
			"google.golang.org/genproto/googleapis/rpc": "googleapis/go-genproto",
		}
		// Try exact match first
		if repo, ok := googleModuleMap[modulePath]; ok {
			if lic := c.fetchGitHubLicense(ctx, repo); lic != "" {
				return lic
			}
		}
		// Try prefix match for sub-packages
		for prefix, repo := range googleModuleMap {
			if strings.HasPrefix(modulePath, prefix) {
				if lic := c.fetchGitHubLicense(ctx, repo); lic != "" {
					return lic
				}
			}
		}
	}

	// gopkg.in modules: gopkg.in/yaml.v3 -> github.com/go-yaml/yaml
	if strings.HasPrefix(modulePath, "gopkg.in/") {
		return c.fetchGopkginLicense(ctx, modulePath)
	}

	// For other non-GitHub modules, try the Go module proxy to get the
	// .mod file and find the VCS URL
	proxyURL := fmt.Sprintf("https://proxy.golang.org/%s/@latest", modulePath)
	body, err := c.httpGet(ctx, proxyURL)
	if err != nil {
		return ""
	}

	var resp struct {
		Version string `json:"Version"`
		Origin  struct {
			VCS  string `json:"VCS"`
			URL  string `json:"URL"`
		} `json:"Origin"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	// If we have a VCS URL, try to extract a GitHub repo from it
	if resp.Origin.URL != "" {
		repo := resp.Origin.URL
		repo = strings.TrimPrefix(repo, "https://")
		repo = strings.TrimPrefix(repo, "http://")
		repo = strings.TrimPrefix(repo, "git+")
		repo = strings.TrimPrefix(repo, "git://")
		repo = strings.TrimSuffix(repo, ".git")
		if strings.HasPrefix(repo, "github.com/") {
			return c.fetchGitHubLicense(ctx, strings.TrimPrefix(repo, "github.com/"))
		}
		if strings.HasPrefix(repo, "go.googlesource.com/") {
			return c.fetchGooglesourceLicense(ctx, strings.TrimPrefix(repo, "go.googlesource.com/"))
		}
	}

	return ""
}

// fetchGooglesourceLicense fetches license info for a repository hosted on
// go.googlesource.com. These repos (golang.org/x/*) use the BSD-3-Clause
// license. We try the GitHub mirror first (golang/* repos are mirrored on
// GitHub), then fall back to the known license.
func (c *MetadataClient) fetchGooglesourceLicense(ctx context.Context, repoName string) string {
	repoName = strings.TrimSpace(repoName)
	if repoName == "" {
		return ""
	}

	// Strip any sub-path after the repo name (e.g., "net/html" -> "net")
	parts := strings.SplitN(repoName, "/", 2)
	repoName = parts[0]

	// Try GitHub mirror: golang/<repoName>
	// Most golang.org/x/* repos are mirrored at github.com/golang/<name>
	githubMirrors := map[string]string{
		"net":      "golang/net",
		"crypto":   "golang/crypto",
		"sys":      "golang/sys",
		"text":     "golang/text",
		"arch":     "golang/arch",
		"tools":    "golang/tools",
		"sync":     "golang/sync",
		"term":     "golang/term",
		"time":     "golang/time",
		"exp":      "golang/exp",
		"image":    "golang/image",
		"mobile":   "golang/mobile",
		"mod":      "golang/mod",
		"lint":     "golang/lint",
		"review":   "golang/review",
		"vuln":     "golang/vuln",
		"perf":     "golang/perf",
		"debug":    "golang/debug",
		"build":    "golang/build",
		"example":  "golang/example",
		"playground": "golang/playground",
		"tour":     "golang/tour",
		"proposal": "golang/proposal",
		"scratch":  "golang/scratch",
		"benchmarks": "golang/benchmarks",
		"oauth2":   "golang/oauth2",
		"appengine": "golang/appengine",
		"grpc":     "golang/grpc",
	}

	if mirror, ok := githubMirrors[repoName]; ok {
		if lic := c.fetchGitHubLicense(ctx, mirror); lic != "" {
			return lic
		}
	}

	// All golang.org/x/* repos use BSD-3-Clause license
	// (https://go.dev/LICENSE)
	return "BSD-3-Clause"
}

// fetchGopkginLicense fetches license for gopkg.in modules.
// gopkg.in/yaml.v3 -> github.com/go-yaml/yaml.v3
// gopkg.in/check.v1 -> github.com/go-check/check
func (c *MetadataClient) fetchGopkginLicense(ctx context.Context, modulePath string) string {
	// gopkg.in/<name>.<version> or gopkg.in/<owner>/<name>.<version>
	rest := strings.TrimPrefix(modulePath, "gopkg.in/")

	// Check if it's the owner/name format: gopkg.in/owner/name.v3
	if strings.Contains(rest, "/") {
		parts := strings.SplitN(rest, "/", 2)
		owner := parts[0]
		repoWithVersion := parts[1]
		// Strip version suffix (.v1, .v2, etc.)
		repoName := strings.Split(repoWithVersion, ".")[0]
		if owner != "" && repoName != "" {
			return c.fetchGitHubLicense(ctx, owner+"/"+repoName)
		}
	}

	// Simple format: gopkg.in/yaml.v3 -> github.com/go-yaml/yaml
	// The convention is: gopkg.in/<name>.v<N> -> github.com/go-<name>/<name>
	// But some use different mappings, so try common ones first.
	gopkgMap := map[string]string{
		"gopkg.in/yaml.v2": "go-yaml/yaml",
		"gopkg.in/yaml.v3": "go-yaml/yaml",
		"gopkg.in/yaml.v1": "go-yaml/yaml",
		"gopkg.in/check.v1": "go-check/check",
		"gopkg.in/fsnotify.v1": "fsnotify/fsnotify",
		"gopkg.in/ini.v1": "go-ini/ini",
		"gopkg.in/mgo.v2": "go-mgo/mgo",
		"gopkg.in/redis.v5": "go-redis/redis",
		"gopkg.in/redis.v6": "go-redis/redis",
		"gopkg.in/redis.v7": "go-redis/redis",
		"gopkg.in/redis.v8": "go-redis/redis",
		"gopkg.in/sourcemap.v1": "dustmop/go-sourcemap",
		"gopkg.in/tomb.v1": "go-tomb/tomb",
		"gopkg.in/tomb.v2": "go-tomb/tomb",
		"gopkg.in/urfave/cli.v1": "urfave/cli",
		"gopkg.in/urfave/cli.v2": "urfave/cli",
		"gopkg.in/natefinch/lumberjack.v2": "natefinch/lumberjack",
		"gopkg.in/alecthomas/kingpin.v2": "alecthomas/kingpin",
		"gopkg.in/mail.v2": "go-mail/mail",
		"gopkg.in/gomail.v2": "go-gomail/gomail",
		"gopkg.in/asn1-ber.v1": "go-asn1-ber/asn1-ber",
		"gopkg.in/ldap.v2": "go-ldap/ldap",
		"gopkg.in/ldap.v3": "go-ldap/ldap",
		"gopkg.in/jcmturner/gokrb5.v7": "jcmturner/gokrb5",
		"gopkg.in/jcmturner/rpc.v1": "jcmturner/rpc",
		"gopkg.in/h2non/gock.v1": "h2non/gock",
		"gopkg.in/h2non/baloo.v3": "h2non/baloo",
		"gopkg.in/dancannon/gorethink.v4": "dancannon/gorethink",
		"gopkg.in/gorethink/gorethink.v4": "gorethink/gorethink",
		"gopkg.in/olivere/elastic.v5": "olivere/elastic",
		"gopkg.in/olivere/elastic.v6": "olivere/elastic",
		"gopkg.in/olivere/elastic.v7": "olivere/elastic",
		"gopkg.in/soberstein/redis.v1": "soberstein/redis",
		"gopkg.in/src-d/go-git.v4": "go-git/go-git",
		"gopkg.in/warnings.v0": "go-warnings/warnings",
		"gopkg.in/tylerb/graceful.v1": "tylerb/graceful",
		"gopkg.in/validator.v2": "go-validator/validator",
		"gopkg.in/validator.v1": "go-validator/validator",
		"gopkg.in/mickael-menu/zk.nvim": "mickael-menu/zk",
	}

	if repo, ok := gopkgMap[modulePath]; ok {
		if lic := c.fetchGitHubLicense(ctx, repo); lic != "" {
			return lic
		}
	}

	// Generic fallback: gopkg.in/<name>.v<N> -> github.com/go-<name>/<name>
	// Strip version suffix
	baseName := strings.SplitN(rest, ".", 2)[0]
	if baseName != "" {
		// Try go-<name>/<name> pattern
		repo := "go-" + baseName + "/" + baseName
		if lic := c.fetchGitHubLicense(ctx, repo); lic != "" {
			return lic
		}
	}

	return ""
}

// fetchCargoLicense fetches license info from crates.io API.
// API: GET https://crates.io/api/v1/crates/{name}
func (c *MetadataClient) fetchCargoLicense(ctx context.Context, name, version string) string {
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s", name)
	body, err := c.httpGet(ctx, url)
	if err != nil {
		return ""
	}

	var resp struct {
		Crate struct {
			License     string `json:"license"`
			Repository  string `json:"repository"`
			Description string `json:"description"`
		} `json:"crate"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}

	if resp.Crate.License != "" {
		return resp.Crate.License
	}

	// Fallback: try GitHub API if we have a repo URL
	if resp.Crate.Repository != "" {
		return c.fetchGitHubLicense(ctx, resp.Crate.Repository)
	}
	return ""
}

// httpGet performs an HTTP GET request and returns the response body.
func (c *MetadataClient) httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, application/x-yaml, text/yaml, */*")
	req.Header.Set("User-Agent", "PatchFlow-CLI/0.1")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned %d for %s", resp.StatusCode, url)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
}

// ─── Disk Cache ──────────────────────────────────────────────────────

// Cache stores registry metadata on disk to avoid repeated API calls.
type Cache struct {
	dir string
	mu  sync.RWMutex
}

// NewCache creates a disk cache for the given repository root. The cache
// directory is resolved via cacheutil (XDG-compliant global location).
func NewCache(repoRoot string) *Cache {
	dir := cacheutil.ResolveSubdir(repoRoot, "registry")
	return &Cache{dir: dir}
}

// Get returns a cached license string, or "" if not cached or expired.
func (c *Cache) Get(dep analysis.Dependency) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.cachePath(dep)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return ""
	}

	// Check TTL
	if time.Since(entry.FetchedAt) > CacheTTL {
		return ""
	}

	return entry.License
}

// Has returns true if a cache entry exists and is not expired, regardless of
// whether the cached license is empty. This distinguishes "not cached" from
// "cached as empty" — both return "" from Get(), but only Has() tells us
// whether we already attempted to fetch the license and should skip the
// network call.
func (c *Cache) Has(dep analysis.Dependency) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.cachePath(dep)
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return false
	}

	return time.Since(entry.FetchedAt) <= CacheTTL
}

// Set stores a license string in the cache.
func (c *Cache) Set(dep analysis.Dependency, license string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir := filepath.Dir(c.cachePath(dep))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}

	entry := cacheEntry{
		License:   license,
		FetchedAt: time.Now(),
		Ecosystem: string(dep.Ecosystem),
		Package:   dep.Name,
		Version:   dep.Version,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	_ = os.WriteFile(c.cachePath(dep), data, 0o644)
}

type cacheEntry struct {
	License   string    `json:"license"`
	FetchedAt time.Time `json:"fetched_at"`
	Ecosystem string    `json:"ecosystem"`
	Package   string    `json:"package"`
	Version   string    `json:"version"`
}

func (c *Cache) cachePath(dep analysis.Dependency) string {
	// Sanitize package name for filesystem (scoped npm packages have @ and /)
	safeName := strings.ReplaceAll(dep.Name, "/", "_")
	safeName = strings.ReplaceAll(safeName, "@", "_at_")
	if dep.Repository != "" {
		replacer := strings.NewReplacer("/", "_", ":", "_", "@", "_at_", "?", "_", "&", "_", "=", "_")
		safeName = replacer.Replace(dep.Repository) + "_" + safeName
	}
	return filepath.Join(c.dir, string(dep.Ecosystem), safeName+"@"+dep.Version+".json")
}
