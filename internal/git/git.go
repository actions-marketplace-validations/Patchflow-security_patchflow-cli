package git

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Executor abstracts the execution of git commands.
type Executor interface {
	Run(dir string, args ...string) (string, error)
}

// ShellExecutor runs git commands using exec.Command.
type ShellExecutor struct{}

// Run executes a git command in the given directory and returns its combined output.
func (s *ShellExecutor) Run(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Repository holds metadata about a git repository.
type Repository struct {
	Root          string
	RemoteURL     string
	CurrentBranch string
	CommitSHA     string
	BaseBranch    string
	ChangedFiles  []string
	AddedLines    int
	DeletedLines  int

	executor Executor
}

// NewRepository creates a new Repository using the provided executor.
// If executor is nil, a ShellExecutor is used.
func NewRepository(executor Executor) (*Repository, error) {
	if executor == nil {
		executor = &ShellExecutor{}
	}

	r := &Repository{executor: executor}

	root, err := r.executor.Run("", "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, errors.New("not a git repository")
	}
	r.Root = strings.TrimSpace(root)

	branch, _ := r.executor.Run(r.Root, "rev-parse", "--abbrev-ref", "HEAD")
	r.CurrentBranch = strings.TrimSpace(branch)

	sha, _ := r.executor.Run(r.Root, "rev-parse", "HEAD")
	r.CommitSHA = strings.TrimSpace(sha)

	remote, remoteErr := r.executor.Run(r.Root, "remote", "get-url", "origin")
	if remoteErr == nil {
		r.RemoteURL = strings.TrimSpace(remote)
	}

	r.BaseBranch = r.detectBaseBranch()

	return r, nil
}

// Detect returns a Repository for the current working directory.
func Detect() (*Repository, error) {
	return NewRepository(nil)
}

// DetectOrLocal returns git metadata when available, otherwise a local project
// rooted at the current working directory. This lets full scans work on
// unpacked source trees that are not git checkouts.
func DetectOrLocal() (*Repository, bool, error) {
	repo, err := Detect()
	if err == nil {
		return repo, true, nil
	}

	cwd, cwdErr := os.Getwd()
	if cwdErr != nil {
		return nil, false, cwdErr
	}
	root, absErr := filepath.Abs(cwd)
	if absErr != nil {
		return nil, false, absErr
	}
	// Normalize symlinks and Windows short (8.3) path aliases so callers see
	// the same canonical root regardless of how the working directory was
	// entered.
	if canonicalRoot, evalErr := filepath.EvalSymlinks(root); evalErr == nil {
		root = canonicalRoot
	}

	return &Repository{
		Root:          root,
		CurrentBranch: "local",
	}, false, nil
}

// detectBaseBranch tries to determine the default base branch.
func (r *Repository) detectBaseBranch() string {
	out, err := r.executor.Run(r.Root, "symbolic-ref", "refs/remotes/origin/HEAD")
	if err == nil {
		ref := strings.TrimSpace(out)
		if strings.HasPrefix(ref, "refs/remotes/origin/") {
			return strings.TrimPrefix(ref, "refs/remotes/origin/")
		}
		return ref
	}

	_, err = r.executor.Run(r.Root, "rev-parse", "--verify", "origin/main")
	if err == nil {
		return "main"
	}

	_, err = r.executor.Run(r.Root, "rev-parse", "--verify", "origin/master")
	if err == nil {
		return "master"
	}

	return ""
}

// DetectChangedFiles populates ChangedFiles by diffing against the base branch.
func (r *Repository) DetectChangedFiles() error {
	var out string
	var err error

	if r.BaseBranch != "" {
		out, err = r.executor.Run(r.Root, "diff", "--name-only", r.BaseBranch+"...HEAD")
	}

	if r.BaseBranch == "" || err != nil {
		out, err = r.executor.Run(r.Root, "diff", "--name-only", "HEAD")
	}

	if err != nil {
		return fmt.Errorf("failed to detect changed files: %w", err)
	}

	files := strings.Split(strings.TrimSpace(out), "\n")
	var result []string
	for _, f := range files {
		if f != "" {
			result = append(result, f)
		}
	}
	r.ChangedFiles = result
	return nil
}

// DetectStagedFiles populates ChangedFiles with only staged (cached) files.
// This is useful for pre-commit hooks that want to scan only staged changes.
func (r *Repository) DetectStagedFiles() error {
	out, err := r.executor.Run(r.Root, "diff", "--name-only", "--cached")
	if err != nil {
		return fmt.Errorf("failed to detect staged files: %w", err)
	}

	files := strings.Split(strings.TrimSpace(out), "\n")
	var result []string
	for _, f := range files {
		if f != "" {
			result = append(result, f)
		}
	}
	r.ChangedFiles = result
	return nil
}

// DetectDiffStats populates AddedLines and DeletedLines by diffing against the base branch.
func (r *Repository) DetectDiffStats() error {
	var out string
	var err error

	if r.BaseBranch != "" {
		out, err = r.executor.Run(r.Root, "diff", "--stat", r.BaseBranch+"...HEAD")
	}

	if r.BaseBranch == "" || err != nil {
		out, err = r.executor.Run(r.Root, "diff", "--stat", "HEAD")
	}

	if err != nil {
		return fmt.Errorf("failed to detect diff stats: %w", err)
	}

	added, deleted := parseDiffStat(out)
	r.AddedLines = added
	r.DeletedLines = deleted
	return nil
}

var insertionRe = regexp.MustCompile(`(\d+)\s+insertion`)
var deletionRe = regexp.MustCompile(`(\d+)\s+deletion`)

func parseDiffStat(stat string) (int, int) {
	totalAdded := 0
	totalDeleted := 0

	for _, line := range strings.Split(stat, "\n") {
		if m := insertionRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				totalAdded += n
			}
		}
		if m := deletionRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				totalDeleted += n
			}
		}
	}

	return totalAdded, totalDeleted
}

// ChangedFilesSince returns the list of files changed between the given ref
// (branch, tag, or commit) and HEAD, using `git diff --name-only <ref>...HEAD`.
// The three-dot syntax compares the merge-base of <ref> and HEAD against HEAD,
// so only changes introduced on the current branch are reported.
//
// The returned list is filtered to remove:
//   - deleted files (no longer present on disk)
//   - files inside ignored directories (vendor, node_modules, .git, ...)
//   - binary files (by extension)
//   - oversized files (larger than maxBytes)
//
// If maxBytes <= 0, a default of 2 MiB is used.
func (r *Repository) ChangedFilesSince(ref string) ([]string, error) {
	if ref == "" {
		return nil, fmt.Errorf("ChangedFilesSince: ref is required")
	}

	// Verify the ref exists before diffing so we can return a clear error.
	if _, err := r.executor.Run(r.Root, "rev-parse", "--verify", ref); err != nil {
		return nil, fmt.Errorf("git ref %q does not exist: %w", ref, err)
	}

	out, err := r.executor.Run(r.Root, "diff", "--name-only", ref+"...HEAD")
	if err != nil {
		// Fall back to two-dot diff if three-dot fails (e.g. no merge-base).
		out, err = r.executor.Run(r.Root, "diff", "--name-only", ref, "HEAD")
		if err != nil {
			return nil, fmt.Errorf("failed to diff against %q: %w", ref, err)
		}
	}

	raw := strings.Split(strings.TrimSpace(out), "\n")
	return r.filterChangedFiles(raw), nil
}

// filterChangedFiles applies the production filtering rules to a raw list of
// changed file paths: drops empties, deleted files, ignored dirs, binary
// extensions, and oversized files.
func (r *Repository) filterChangedFiles(raw []string) []string {
	const defaultMaxBytes int64 = 2 * 1024 * 1024 // 2 MiB

	var result []string
	for _, f := range raw {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		// Skip deleted files (no longer on disk).
		abs := filepath.Join(r.Root, f)
		info, err := os.Stat(abs)
		if err != nil {
			continue
		}
		// Skip ignored directories.
		if isInIgnoredDir(f) {
			continue
		}
		// Skip binary files by extension.
		if isBinaryExt(filepath.Ext(f)) {
			continue
		}
		// Skip oversized files.
		if info.Size() > defaultMaxBytes {
			continue
		}
		result = append(result, f)
	}
	return result
}

// ignoredDirSet lists directory names whose contents are never scanned.
var ignoredDirSet = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, "dist": true,
	"build": true, "__pycache__": true, ".next": true, ".nuxt": true,
	"target": true, ".gradle": true, ".idea": true, ".vscode": true,
	"bin": true, "obj": true, ".cache": true, ".pytest_cache": true,
	".mypy_cache": true, ".ruff_cache": true, "coverage": true,
	".turbo": true, ".svelte-kit": true,
}

func isInIgnoredDir(path string) bool {
	path = filepath.ToSlash(path)
	for _, part := range strings.Split(path, "/") {
		if ignoredDirSet[part] {
			return true
		}
	}
	return false
}

// binaryExts lists file extensions that are never source-scannable.
var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true,
	".ico": true, ".webp": true, ".mp3": true, ".mp4": true, ".avi": true,
	".mov": true, ".wav": true, ".flv": true, ".zip": true, ".tar": true,
	".gz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".o": true,
	".a": true, ".class": true, ".jar": true, ".war": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".pyc": true, ".pyo": true, ".wasm": true,
}

func isBinaryExt(ext string) bool {
	return binaryExts[strings.ToLower(ext)]
}

// MockExecutor is a test double for git commands.
type MockExecutor struct {
	Responses map[string]string
	Errors    map[string]error
	Calls     []string
}

// Run returns a pre-configured response or error for the given arguments.
func (m *MockExecutor) Run(dir string, args ...string) (string, error) {
	key := strings.Join(args, " ")
	m.Calls = append(m.Calls, key)
	if err, ok := m.Errors[key]; ok {
		return m.Responses[key], err
	}
	if resp, ok := m.Responses[key]; ok {
		return resp, nil
	}
	return "", fmt.Errorf("unexpected mock command: %s", key)
}
