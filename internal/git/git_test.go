package git

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewRepositoryWithMockExecutor(t *testing.T) {
	mock := &MockExecutor{
		Responses: map[string]string{
			"rev-parse --show-toplevel":             "/tmp/repo",
			"rev-parse --abbrev-ref HEAD":           "feature",
			"rev-parse HEAD":                        "abc123def456",
			"remote get-url origin":                 "https://github.com/user/repo.git",
			"symbolic-ref refs/remotes/origin/HEAD": "refs/remotes/origin/main",
		},
	}

	repo, err := NewRepository(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.Root != "/tmp/repo" {
		t.Fatalf("expected root %q, got %q", "/tmp/repo", repo.Root)
	}
	if repo.CurrentBranch != "feature" {
		t.Fatalf("expected branch %q, got %q", "feature", repo.CurrentBranch)
	}
	if repo.CommitSHA != "abc123def456" {
		t.Fatalf("expected sha %q, got %q", "abc123def456", repo.CommitSHA)
	}
	if repo.RemoteURL != "https://github.com/user/repo.git" {
		t.Fatalf("expected remote %q, got %q", "https://github.com/user/repo.git", repo.RemoteURL)
	}
	if repo.BaseBranch != "main" {
		t.Fatalf("expected base branch %q, got %q", "main", repo.BaseBranch)
	}
	if repo.executor != mock {
		t.Fatal("expected executor to be the mock")
	}
}

func TestNewRepositoryNonGitRepo(t *testing.T) {
	mock := &MockExecutor{
		Errors: map[string]error{
			"rev-parse --show-toplevel": errors.New("fatal: not a git repository"),
		},
	}

	_, err := NewRepository(mock)
	if err == nil {
		t.Fatal("expected error for non-git repo, got nil")
	}
	if err.Error() != "not a git repository" {
		t.Fatalf("expected error %q, got %q", "not a git repository", err.Error())
	}
}

func TestNewRepositoryDoesNotTreatFailedRemoteLookupAsURL(t *testing.T) {
	mock := &MockExecutor{
		Responses: map[string]string{
			"rev-parse --show-toplevel":   "/tmp/repo",
			"rev-parse --abbrev-ref HEAD": "main",
			"rev-parse HEAD":              "abc123def456",
			"remote get-url origin":       "error: No such remote 'origin'\n",
		},
		Errors: map[string]error{
			"remote get-url origin": errors.New("exit status 2"),
		},
	}

	repo, err := NewRepository(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.RemoteURL != "" {
		t.Fatalf("expected no remote URL after failed lookup, got %q", repo.RemoteURL)
	}
}

func TestDetectOrLocalNonGitRepo(t *testing.T) {
	dir := t.TempDir()
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	defer os.Chdir(original)

	repo, isGit, err := DetectOrLocal()
	if err != nil {
		t.Fatalf("DetectOrLocal failed: %v", err)
	}
	if isGit {
		t.Fatal("expected non-git fallback")
	}
	expectedRoot, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("eval symlink: %v", err)
	}
	if repo.Root != expectedRoot {
		t.Fatalf("expected root %q, got %q", expectedRoot, repo.Root)
	}
	if repo.CurrentBranch != "local" {
		t.Fatalf("expected local branch marker, got %q", repo.CurrentBranch)
	}
}

func TestDetectBaseBranchSymbolicRef(t *testing.T) {
	mock := &MockExecutor{
		Responses: map[string]string{
			"rev-parse --show-toplevel":             "/tmp/repo",
			"rev-parse --abbrev-ref HEAD":           "feature",
			"rev-parse HEAD":                        "abc123",
			"remote get-url origin":                 "https://github.com/user/repo.git",
			"symbolic-ref refs/remotes/origin/HEAD": "refs/remotes/origin/develop",
		},
	}

	repo, err := NewRepository(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.BaseBranch != "develop" {
		t.Fatalf("expected base branch %q, got %q", "develop", repo.BaseBranch)
	}
}

func TestDetectBaseBranchFallbackToMain(t *testing.T) {
	mock := &MockExecutor{
		Responses: map[string]string{
			"rev-parse --show-toplevel":      "/tmp/repo",
			"rev-parse --abbrev-ref HEAD":    "feature",
			"rev-parse HEAD":                 "abc123",
			"remote get-url origin":          "https://github.com/user/repo.git",
			"rev-parse --verify origin/main": "abc456",
		},
		Errors: map[string]error{
			"symbolic-ref refs/remotes/origin/HEAD": errors.New("fatal: ref missing"),
		},
	}

	repo, err := NewRepository(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.BaseBranch != "main" {
		t.Fatalf("expected base branch %q, got %q", "main", repo.BaseBranch)
	}
}

func TestDetectBaseBranchFallbackToMaster(t *testing.T) {
	mock := &MockExecutor{
		Responses: map[string]string{
			"rev-parse --show-toplevel":        "/tmp/repo",
			"rev-parse --abbrev-ref HEAD":      "feature",
			"rev-parse HEAD":                   "abc123",
			"remote get-url origin":            "https://github.com/user/repo.git",
			"rev-parse --verify origin/master": "abc789",
		},
		Errors: map[string]error{
			"symbolic-ref refs/remotes/origin/HEAD": errors.New("fatal: ref missing"),
			"rev-parse --verify origin/main":        errors.New("fatal: invalid reference"),
		},
	}

	repo, err := NewRepository(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.BaseBranch != "master" {
		t.Fatalf("expected base branch %q, got %q", "master", repo.BaseBranch)
	}
}

func TestDetectChangedFilesWithMock(t *testing.T) {
	mock := &MockExecutor{
		Responses: map[string]string{
			"diff --name-only main...HEAD": "file1.go\nfile2.go\n",
		},
	}

	repo := &Repository{
		Root:       "/tmp/repo",
		BaseBranch: "main",
		executor:   mock,
	}

	err := repo.DetectChangedFiles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repo.ChangedFiles) != 2 {
		t.Fatalf("expected 2 changed files, got %d: %+v", len(repo.ChangedFiles), repo.ChangedFiles)
	}
	if repo.ChangedFiles[0] != "file1.go" {
		t.Fatalf("expected first file %q, got %q", "file1.go", repo.ChangedFiles[0])
	}
	if repo.ChangedFiles[1] != "file2.go" {
		t.Fatalf("expected second file %q, got %q", "file2.go", repo.ChangedFiles[1])
	}
}

func TestDetectChangedFilesEmptyBaseBranch(t *testing.T) {
	mock := &MockExecutor{
		Responses: map[string]string{
			"diff --name-only HEAD": "uncommitted.go\n",
		},
	}

	repo := &Repository{
		Root:       "/tmp/repo",
		BaseBranch: "",
		executor:   mock,
	}

	err := repo.DetectChangedFiles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repo.ChangedFiles) != 1 {
		t.Fatalf("expected 1 changed file, got %d: %+v", len(repo.ChangedFiles), repo.ChangedFiles)
	}
	if repo.ChangedFiles[0] != "uncommitted.go" {
		t.Fatalf("expected file %q, got %q", "uncommitted.go", repo.ChangedFiles[0])
	}
}

func TestDetectDiffStatsParsesCorrectly(t *testing.T) {
	stat := ` README.md | 5 +++++
 main.go   | 10 +++++++---
 2 files changed, 12 insertions(+), 3 deletions(-)
`

	mock := &MockExecutor{
		Responses: map[string]string{
			"diff --stat main...HEAD": stat,
		},
	}

	repo := &Repository{
		Root:       "/tmp/repo",
		BaseBranch: "main",
		executor:   mock,
	}

	err := repo.DetectDiffStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.AddedLines != 12 {
		t.Fatalf("expected 12 added lines, got %d", repo.AddedLines)
	}
	if repo.DeletedLines != 3 {
		t.Fatalf("expected 3 deleted lines, got %d", repo.DeletedLines)
	}
}

func TestDetectDiffStatsEmptyBaseBranch(t *testing.T) {
	stat := ` README.md | 5 +++++
 1 file changed, 5 insertions(+)
`

	mock := &MockExecutor{
		Responses: map[string]string{
			"diff --stat HEAD": stat,
		},
	}

	repo := &Repository{
		Root:       "/tmp/repo",
		BaseBranch: "",
		executor:   mock,
	}

	err := repo.DetectDiffStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.AddedLines != 5 {
		t.Fatalf("expected 5 added lines, got %d", repo.AddedLines)
	}
}

func TestParseDiffStat(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		added   int
		deleted int
	}{
		{
			name:    "single file insertions only",
			input:   " file.go | 3 +++\n 1 file changed, 3 insertions(+)\n",
			added:   3,
			deleted: 0,
		},
		{
			name:    "single file deletions only",
			input:   " file.go | 2 --\n 1 file changed, 2 deletions(-)\n",
			added:   0,
			deleted: 2,
		},
		{
			name:    "multiple files",
			input:   " a.go | 5 +++++\n b.go | 3 ---\n 2 files changed, 5 insertions(+), 3 deletions(-)\n",
			added:   5,
			deleted: 3,
		},
		{
			name:    "complex changes",
			input:   " README.md | 5 +++++\n main.go   | 10 +++++++---\n 2 files changed, 12 insertions(+), 3 deletions(-)\n",
			added:   12,
			deleted: 3,
		},
		{
			name:    "empty",
			input:   "",
			added:   0,
			deleted: 0,
		},
		{
			name:    "summary line only",
			input:   " 1 file changed, 7 insertions(+), 2 deletions(-)\n",
			added:   7,
			deleted: 2,
		},
		{
			name:    "binary file",
			input:   " image.png | Bin 1234 -> 5678 bytes\n 1 file changed, 0 insertions(+), 0 deletions(-)\n",
			added:   0,
			deleted: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			added, deleted := parseDiffStat(tc.input)
			if added != tc.added {
				t.Fatalf("expected %d added, got %d", tc.added, added)
			}
			if deleted != tc.deleted {
				t.Fatalf("expected %d deleted, got %d", tc.deleted, deleted)
			}
		})
	}
}

func TestMockExecutorTracksCalls(t *testing.T) {
	mock := &MockExecutor{
		Responses: map[string]string{
			"rev-parse --show-toplevel": "/tmp/repo",
		},
		Errors: map[string]error{
			"rev-parse --abbrev-ref HEAD": errors.New("fatal: ambiguous argument"),
		},
	}

	_, err := mock.Run("/tmp/repo", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = mock.Run("/tmp/repo", "rev-parse", "--abbrev-ref", "HEAD")
	if err == nil {
		t.Fatal("expected error")
	}

	if len(mock.Calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(mock.Calls))
	}
	if mock.Calls[0] != "rev-parse --show-toplevel" {
		t.Fatalf("expected first call %q, got %q", "rev-parse --show-toplevel", mock.Calls[0])
	}
	if mock.Calls[1] != "rev-parse --abbrev-ref HEAD" {
		t.Fatalf("expected second call %q, got %q", "rev-parse --abbrev-ref HEAD", mock.Calls[1])
	}
}

func TestChangedFilesSinceWithMock(t *testing.T) {
	dir := t.TempDir()
	// Create a couple of source files so the "still on disk" filter keeps them.
	mustWrite(t, dir, "app/main.go", "package main\n")
	mustWrite(t, dir, "lib/util.py", "print('hi')\n")

	mock := &MockExecutor{
		Responses: map[string]string{
			"rev-parse --show-toplevel":    dir,
			"rev-parse --abbrev-ref HEAD":  "feature",
			"rev-parse HEAD":               "abc123",
			"remote get-url origin":        "",
			"rev-parse --verify main":      "main-sha\n",
			"diff --name-only main...HEAD": "app/main.go\nlib/util.py\ndeleted.go\nnode_modules/x.js\nbig.bin\n",
		},
	}
	repo, err := NewRepository(mock)
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}

	files, err := repo.ChangedFilesSince("main")
	if err != nil {
		t.Fatalf("ChangedFilesSince: %v", err)
	}
	// deleted.go is absent on disk, node_modules is ignored, .bin is binary.
	want := map[string]bool{"app/main.go": true, "lib/util.py": true}
	if len(files) != len(want) {
		t.Fatalf("expected %d files, got %d: %v", len(want), len(files), files)
	}
	for _, f := range files {
		if !want[f] {
			t.Errorf("unexpected file %q in filtered result", f)
		}
	}
}

func TestChangedFilesSinceMissingRef(t *testing.T) {
	dir := t.TempDir()
	mock := &MockExecutor{
		Responses: map[string]string{
			"rev-parse --show-toplevel":   dir,
			"rev-parse --abbrev-ref HEAD": "feature",
			"rev-parse HEAD":              "abc123",
			"remote get-url origin":       "",
		},
		Errors: map[string]error{
			"rev-parse --verify nope": errors.New("not found"),
		},
	}
	repo, err := NewRepository(mock)
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	if _, err := repo.ChangedFilesSince("nope"); err == nil {
		t.Fatal("expected error for missing ref")
	}
}

func TestIsInIgnoredDir(t *testing.T) {
	cases := map[string]bool{
		"node_modules/foo.js": true,
		"vendor/pkg.go":       true,
		"src/app/main.go":     false,
		".git/config":         true,
		"foo/bar.go":          false,
	}
	for path, want := range cases {
		if got := isInIgnoredDir(path); got != want {
			t.Errorf("isInIgnoredDir(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsBinaryExt(t *testing.T) {
	if !isBinaryExt(".PNG") {
		t.Error(".PNG should be binary (case-insensitive)")
	}
	if isBinaryExt(".go") {
		t.Error(".go should not be binary")
	}
}

func mustWrite(t *testing.T, dir, rel, content string) {
	t.Helper()
	abs := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(abs, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
