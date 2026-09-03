# PatchFlow CLI Release Process

This document describes how to cut a release of PatchFlow CLI.

## Repository source of truth

`Patchflow-security/patchflow-cli` is the canonical repository. All development pull
requests, release tags, GitHub Releases, and release automation originate there.

The legacy `malik111110/Patch-flow-cli` repository may be retained as a read-only,
one-way continuity mirror. It must never be used as an upstream and must not create
tags or publish artifacts. The scheduled `Canonical Repository Drift` workflow uses
`scripts/check-canonical-drift.sh` to fail when a mirrored `main` does not exactly
match the public canonical commit.

Recommended maintainer remotes:

```bash
git remote set-url origin git@github.com:Patchflow-security/patchflow-cli.git
git remote add private-mirror git@github.com:malik111110/Patch-flow-cli.git
git remote set-url --push private-mirror DISABLED
git remote -v
```

Normal development fetches from and pushes to `origin`. The `private-mirror` remote
is optional and fetch-only; synchronization must be performed by explicitly reviewed
automation, never by release jobs running in the private repository.

Before cutting a release, prove that the tag resolves to a public commit reachable
from canonical `main`:

```bash
git fetch origin main --tags
tag_commit="$(git rev-list -n 1 "${TAG}")"
git merge-base --is-ancestor "${tag_commit}" origin/main
gh release view "${TAG}" --repo Patchflow-security/patchflow-cli
```

The ancestry command must exit successfully. Record the tag, commit SHA, workflow run,
checksums, signatures, and SBOM asset links in the release verification notes.

## Prerequisites

### Repository setup

The release pipeline publishes to:

| Target | Repository | Purpose |
|--------|-----------|---------|
| GitHub Releases | `Patchflow-security/patchflow-cli` | Binary archives, checksums, SBOMs, cosign signatures |
| Docker images | `ghcr.io/patchflow-security/cli` | Multi-arch (amd64 + arm64) container images |
| Homebrew tap | `Patchflow-security/homebrew-tap` | macOS/Linux formula auto-update |
| Scoop bucket | `Patchflow-security/scoop-bucket` | Windows manifest auto-update |

### Required secrets

Configure these as repository secrets on `Patchflow-security/patchflow-cli`:

| Secret | Scope | Purpose |
|--------|-------|---------|
| `GITHUB_TOKEN` | auto-provided | GitHub releases, GHCR push |
| `HOMEBREW_TAP_GITHUB_TOKEN` | org-wide | Push formula to `homebrew-tap` repo (needs `repo` scope on the org) |
| `SCOOP_BUCKET_GITHUB_TOKEN` | org-wide | Push manifest to `scoop-bucket` repo (needs `repo` scope on the org) |

> If the tap tokens are not set, goreleaser will fail on the brews/scoops publish step.
> The GitHub release and Docker images will still publish successfully.

### Local tooling (optional, for manual releases)

```bash
make install-tools   # installs goreleaser, syft, cosign
```

## Cutting a release

### 1. Ensure CI is green

Verify the [CI workflow](.github/workflows/ci.yml) passes on the branch you're releasing from.

### 2. Create and push a tag

```bash
git tag v0.1.0
git push origin v0.1.0
```

This triggers the [Release workflow](.github/workflows/release.yml) automatically.

### 3. Monitor the release

The workflow will:
1. Run tests
2. Build binaries for linux/darwin/windows (amd64 + arm64)
3. Generate archives (tar.gz for unix, zip for windows)
4. Generate SHA-256 checksums
5. Generate SPDX SBOMs for each archive (via syft)
6. Publish GitHub release (draft)
7. Push Docker images to GHCR (multi-arch manifest)
8. Sign Docker images with cosign (keyless, OIDC)
9. Sign checksums.txt with cosign (keyless, OIDC)
10. Upload cosign signatures + SBOMs to the GitHub release
11. Push Homebrew formula to `homebrew-tap`
12. Push Scoop manifest to `scoop-bucket`
13. Verify all checksums and signatures

### 4. Review and publish the draft release

The GitHub release is created as a **draft**. Review the release notes, then click "Publish release" in the GitHub UI.

### 5. Verify the release

```bash
# Verify the install script works
curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash

# Or install via Homebrew
brew install Patchflow-security/homebrew-tap/patchflow

# Or install via Scoop (Windows)
scoop bucket add patchflow https://github.com/Patchflow-security/scoop-bucket
scoop install patchflow

# Or pull the Docker image
podman pull ghcr.io/patchflow-security/cli:latest

# Verify
patchflow version
```

## Snapshot / dry-run releases

To test the release pipeline without publishing:

### Via GitHub Actions (workflow_dispatch)

Go to Actions → Release → Run workflow. Manually dispatched runs are always
non-publishing snapshots; only a pushed semantic `vX.Y.Z` tag can publish.

For a publishing run, automation rejects a malformed tag or a tag whose commit
is not reachable from canonical `origin/main`. It also validates the public
launch manifest and live evidence links before building artifacts.

### Locally

```bash
make release-snapshot
# Artifacts appear in dist/
```

## Rollback

To roll back a release:

1. Delete the GitHub release (GitHub UI → Releases → Delete)
2. Delete the git tag: `git push origin :refs/tags/v0.1.0`
3. Re-pull or delete the Docker images from GHCR (GitHub UI → Packages)
4. The Homebrew/Scoop taps will retain the old formula; manually revert if needed

## Version numbering

PatchFlow CLI follows [semver](https://semver.org/):

- `v0.x.y` — pre-1.0, breaking changes allowed in minor bumps
- `v1.0.0+` — stable, follow strict semver

Tags must be in the format `vX.Y.Z` (e.g., `v0.1.0`, `v1.2.3`).

## Supply chain security

Each release includes:

- **SHA-256 checksums** (`checksums.txt`) for all archives
- **Cosign signatures** (`checksums.txt.sig` + `checksums.txt.pem`) for checksums
- **Cosign signatures** on all Docker images (keyless, OIDC-based)
- **SPDX SBOMs** for each archive (via syft)

Users can verify:

```bash
# Verify checksums
sha256sum -c checksums.txt   # Linux
shasum -a 256 -c checksums.txt  # macOS

# Verify cosign signature on checksums
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt

# Verify Docker image signature
cosign verify ghcr.io/patchflow-security/cli:latest
```
