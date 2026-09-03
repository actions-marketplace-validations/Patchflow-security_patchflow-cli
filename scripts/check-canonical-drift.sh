#!/usr/bin/env bash

set -euo pipefail

canonical_repository="${PATCHFLOW_CANONICAL_REPOSITORY:-Patchflow-security/patchflow-cli}"
canonical_ref="${PATCHFLOW_CANONICAL_REF:-main}"
canonical_url="${PATCHFLOW_CANONICAL_URL:-https://github.com/${canonical_repository}.git}"
current_repository="${GITHUB_REPOSITORY:-local checkout}"
current_sha="${GITHUB_SHA:-$(git rev-parse HEAD)}"
remote_ref="refs/remotes/patchflow-canonical/${canonical_ref}"

git fetch --quiet --no-tags "${canonical_url}" \
  "refs/heads/${canonical_ref}:${remote_ref}"

canonical_sha="$(git rev-parse "${remote_ref}")"

if [[ "${current_sha}" != "${canonical_sha}" ]]; then
  echo "Repository drift detected." >&2
  echo "Current repository: ${current_repository}" >&2
  echo "Current commit:    ${current_sha}" >&2
  echo "Canonical source:  ${canonical_repository}:${canonical_ref}" >&2
  echo "Canonical commit:  ${canonical_sha}" >&2
  echo "Only Patchflow-security/patchflow-cli may act as the upstream." >&2
  exit 1
fi

echo "Repository is synchronized with ${canonical_repository}:${canonical_ref} (${canonical_sha})."
