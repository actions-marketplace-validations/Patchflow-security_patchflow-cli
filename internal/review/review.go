package review

import (
	"path/filepath"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/git"
)

// Context holds structured review context for a repository.
type Context struct {
	RepoRoot               string   `json:"repo_root"`
	RemoteURL              string   `json:"remote_url"`
	Branch                 string   `json:"branch"`
	CommitSHA              string   `json:"commit_sha"`
	BaseBranch             string   `json:"base_branch"`
	FilesChanged           int      `json:"files_changed"`
	AddedLines             int      `json:"added_lines"`
	DeletedLines           int      `json:"deleted_lines"`
	Manifests              []string `json:"manifests"`
	DependencyFilesChanged bool     `json:"dependency_files_changed"`
	CIWorkflowChanged      bool     `json:"ci_workflow_changed"`
	AuthFilesChanged       bool     `json:"auth_files_changed"`
}

// CollectContext gathers review context from a git repository.
func CollectContext(repo *git.Repository) (*Context, error) {
	ctx := &Context{
		RepoRoot:     repo.Root,
		RemoteURL:    repo.RemoteURL,
		Branch:       repo.CurrentBranch,
		CommitSHA:    repo.CommitSHA,
		BaseBranch:   repo.BaseBranch,
		FilesChanged: len(repo.ChangedFiles),
		AddedLines:   repo.AddedLines,
		DeletedLines: repo.DeletedLines,
	}

	for _, f := range repo.ChangedFiles {
		if isDependencyFile(f) {
			ctx.DependencyFilesChanged = true
		}
		if isCIWorkflow(f) {
			ctx.CIWorkflowChanged = true
		}
		if isAuthFile(f) {
			ctx.AuthFilesChanged = true
		}
	}

	return ctx, nil
}

// DetectManifests finds dependency manifest files up to depth 1.
// Returns unique relative paths (from root) to avoid duplicates.
func DetectManifests(root string) []string {
	seen := make(map[string]bool)
	entries, err := filepath.Glob(filepath.Join(root, "*"))
	if err != nil {
		return []string{}
	}
	subEntries, err := filepath.Glob(filepath.Join(root, "*", "*"))
	if err == nil {
		entries = append(entries, subEntries...)
	}

	for _, entry := range entries {
		name := filepath.Base(entry)
		if isManifestName(name) {
			rel, _ := filepath.Rel(root, entry)
			rel = filepath.ToSlash(rel)
			if rel != "" && !seen[rel] {
				seen[rel] = true
			}
		}
	}

	manifests := make([]string, 0, len(seen))
	for m := range seen {
		manifests = append(manifests, m)
	}
	return manifests
}

func isManifestName(name string) bool {
	switch name {
	case "requirements.txt", "pyproject.toml", "package.json",
		"package-lock.json", "pnpm-lock.yaml", "yarn.lock",
		"go.mod", "Cargo.toml", "composer.json",
		"Gemfile.lock", "pom.xml", "build.gradle":
		return true
	}
	return false
}

func isDependencyFile(path string) bool {
	name := filepath.Base(path)
	switch name {
	case "requirements.txt", "pyproject.toml", "package.json",
		"package-lock.json", "pnpm-lock.yaml", "yarn.lock",
		"go.mod", "Cargo.toml", "composer.json",
		"Gemfile.lock", "pom.xml", "build.gradle":
		return true
	}
	return false
}

func isCIWorkflow(path string) bool {
	return strings.Contains(path, ".github/workflows/") ||
		strings.Contains(path, ".gitlab-ci.yml") ||
		strings.Contains(path, "Jenkinsfile") ||
		strings.Contains(path, ".circleci/")
}

func isAuthFile(path string) bool {
	lower := strings.ToLower(path)
	patterns := []string{"auth", "login", "session", "jwt", "oauth", "password", "credential"}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
