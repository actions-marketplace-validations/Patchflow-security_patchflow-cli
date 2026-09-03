package licensedetect

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// licenseFileNames are the common names for license files in repositories,
// checked in order of priority.
var licenseFileNames = []string{
	"LICENSE",
	"LICENSE.md",
	"LICENSE.txt",
	"LICENSE.rst",
	"LICENCE",
	"LICENCE.md",
	"LICENCE.txt",
	"COPYING",
	"COPYING.md",
	"COPYING.txt",
	"UNLICENSE",
	"NOTICE",
}

// defaultBranches are the branch names to try when fetching from raw.githubusercontent.com
var defaultBranches = []string{"main", "master", "HEAD", "develop", "trunk"}

// Fetcher fetches LICENSE file content from remote repositories.
type Fetcher struct {
	HTTPClient *http.Client
}

// NewFetcher creates a new LICENSE file fetcher.
func NewFetcher() *Fetcher {
	return &Fetcher{
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// FetchGitHubLicenseFile fetches the LICENSE file content from a GitHub
// repository. It tries multiple file names (LICENSE, LICENSE.md, COPYING, etc.)
// and multiple default branches (main, master, HEAD).
// Returns the file content and the file name that was found, or empty string
// if no license file was found.
func (f *Fetcher) FetchGitHubLicenseFile(ctx context.Context, owner, repo string) (string, string) {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	if owner == "" || repo == "" {
		return "", ""
	}

	client := f.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	// Try each branch
	for _, branch := range defaultBranches {
		// Try each license file name
		for _, filename := range licenseFileNames {
			url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
				owner, repo, branch, filename)

			content, err := f.fetchURL(ctx, client, url)
			if err == nil && len(content) > 0 {
				return content, filename
			}

			// Check if context is cancelled
			if ctx.Err() != nil {
				return "", ""
			}
		}
	}

	return "", ""
}

// FetchLicenseFileFromRepo fetches the LICENSE file from a repository
// specified as "owner/repo" (GitHub format). Returns the detected license
// SPDX ID or empty string.
func (f *Fetcher) FetchLicenseFileFromRepo(ctx context.Context, repo string) string {
	repo = strings.TrimSpace(repo)
	repo = strings.TrimPrefix(repo, "github.com/")
	repo = strings.TrimPrefix(repo, "https://github.com/")
	repo = strings.TrimPrefix(repo, "http://github.com/")
	repo = strings.TrimSuffix(repo, ".git")

	parts := strings.Split(repo, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	owner := parts[0]
	repoName := parts[1]

	content, _ := f.FetchGitHubLicenseFile(ctx, owner, repoName)
	if content == "" {
		return ""
	}

	match := Detect(content)
	if match != nil {
		return match.SPDXID
	}
	return ""
}

// fetchURL fetches content from a URL with a 1MB limit.
func (f *Fetcher) fetchURL(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "PatchFlow-CLI/0.1")
	req.Header.Set("Accept", "text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return "", err
	}

	return string(body), nil
}
