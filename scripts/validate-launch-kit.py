#!/usr/bin/env python3
"""Validate the reproducible PatchFlow public-launch kit."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_MANIFEST = Path("docs/launch/manifest.json")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
HTTP_URL_PATTERN = re.compile(r"https://[^\s)<>`\"']+")
LAUNCH_CONTENT_MARKERS = (
    "claims/registry.json",
    "SUPPORT.md",
    "SECURITY.md",
    "LICENSE",
    "MACHINE_READABLE_OUTPUTS.md",
    "/issues",
)


class ValidationError(ValueError):
    """Raised when launch evidence is incomplete or inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot read {path}: {error}") from error
    require(isinstance(data, dict), f"{path} must contain a JSON object")
    return data


def resolve_local_link(source: Path, target: str) -> Path | None:
    target = target.strip().split("#", 1)[0]
    if not target or target.startswith(("#", "http://", "https://", "mailto:")):
        return None
    return (source.parent / urllib.parse.unquote(target)).resolve()


def validate_local_links(paths: Iterable[Path], root: Path) -> None:
    root = root.resolve()
    for source in paths:
        text = source.read_text(encoding="utf-8")
        for target in MARKDOWN_LINK_PATTERN.findall(text):
            resolved = resolve_local_link(source, target)
            if resolved is None:
                continue
            require(resolved == root or root in resolved.parents, f"{source}: link escapes repository: {target}")
            require(resolved.exists(), f"{source}: broken local link: {target}")


def collect_remote_urls(paths: Iterable[Path], manifest: dict[str, Any]) -> list[str]:
    urls: set[str] = set()
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for url in HTTP_URL_PATTERN.findall(text):
            normalized = url.rstrip(".,;:\"'")
            if any(character in normalized for character in "${}"):
                continue
            urls.add(normalized)
    for value in (
        manifest["issue"],
        manifest["repository"],
        manifest["release"]["url"],
        manifest["release"]["checksums_url"],
        manifest["release"]["signature_url"],
        manifest["fixture"]["archive_url"],
        manifest["demo"].get("recording_url"),
    ):
        if value:
            urls.add(value)
    return sorted(urls)


def check_remote_url(url: str, attempts: int = 3) -> None:
    headers = {
        "Accept": "*/*",
        "Range": "bytes=0-0",
        "User-Agent": "PatchFlow-launch-kit-validator/1.0",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token and urllib.parse.urlparse(url).hostname in {
        "api.github.com",
        "github.com",
        "raw.githubusercontent.com",
    }:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                require(200 <= response.status < 400, f"remote link returned HTTP {response.status}: {url}")
                response.read(1)
                return
        except (OSError, urllib.error.URLError, ValidationError) as error:
            last_error = error
            if attempt + 1 < attempts:
                time.sleep(attempt + 1)
    raise ValidationError(f"remote link unavailable after {attempts} attempts: {url}: {last_error}")


def fetch_json(url: str) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "PatchFlow-launch-kit-validator/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise ValidationError(f"GitHub API request failed: {url}: {error}") from error
    require(isinstance(data, dict), f"GitHub API returned an unexpected document: {url}")
    return data


def verify_github_pins(manifest: dict[str, Any], fetch: Any = fetch_json) -> None:
    repository = urllib.parse.urlparse(manifest["repository"]).path.strip("/")
    require(repository.count("/") == 1, "repository URL must identify one GitHub owner/repository")
    api = f"https://api.github.com/repos/{repository}"

    release = manifest["release"]
    tag = urllib.parse.quote(release["tag"], safe="")
    ref = fetch(f"{api}/git/ref/tags/{tag}")
    target = ref.get("object")
    require(isinstance(target, dict), "release tag response has no target object")
    if target.get("type") == "tag":
        annotated = fetch(target.get("url", ""))
        target = annotated.get("object")
        require(isinstance(target, dict), "annotated release tag has no commit target")
    require(target.get("type") == "commit", "release tag does not resolve to a commit")
    require(target.get("sha") == release["commit"], "release tag does not resolve to the manifest commit")

    fixture = manifest["fixture"]
    fetch(f"{api}/git/commits/{fixture['commit']}")
    for key in ("vulnerable_path", "clean_path"):
        path = urllib.parse.quote(fixture[key], safe="/")
        content = fetch(f"{api}/contents/{path}?ref={fixture['commit']}")
        require(content.get("type") == "file", f"pinned fixture is not a public file: {fixture[key]}")

    verified_commit = manifest["verification"].get("verified_commit")
    if verified_commit:
        fetch(f"{api}/git/commits/{verified_commit}")


def parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ValidationError("last_verified_at must be an ISO-8601 timestamp") from error
    require(parsed.tzinfo is not None, "last_verified_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_manifest(manifest: dict[str, Any], root: Path, require_ready: bool) -> list[Path]:
    require(manifest.get("schema_version") == "1.0", "schema_version must be 1.0")
    require(manifest.get("status") in {"preparing", "ready"}, "status must be preparing or ready")
    require_ready = require_ready or manifest["status"] == "ready"
    require(isinstance(manifest.get("issue"), str), "issue URL is required")
    require(isinstance(manifest.get("repository"), str), "repository URL is required")

    release = manifest.get("release")
    fixture = manifest.get("fixture")
    demo = manifest.get("demo")
    verification = manifest.get("verification")
    for name, value in (("release", release), ("fixture", fixture), ("demo", demo), ("verification", verification)):
        require(isinstance(value, dict), f"{name} must be an object")

    require(re.fullmatch(r"v\d+\.\d+\.\d+", release.get("tag", "")) is not None, "invalid release tag")
    require(SHA_PATTERN.fullmatch(release.get("commit", "")) is not None, "release commit must be a full SHA")
    require(type(release.get("launch_candidate")) is bool, "release launch_candidate must be boolean")
    limitations = release.get("known_limitations")
    require(isinstance(limitations, list), "release known_limitations must be a list")
    if not release["launch_candidate"]:
        require(bool(limitations), "a rehearsal-only release must document its limitation")
    require(release["tag"] in release.get("url", ""), "release URL must contain the release tag")
    require(release["tag"] in release.get("checksums_url", ""), "checksums URL must contain the release tag")
    require(release["tag"] in release.get("signature_url", ""), "signature URL must contain the release tag")

    require(SHA_PATTERN.fullmatch(fixture.get("commit", "")) is not None, "fixture commit must be a full SHA")
    require(fixture["commit"] in fixture.get("archive_url", ""), "fixture archive must be pinned to fixture commit")
    require(fixture.get("expected_rule") == "PY001", "public demo must retain its expected PY001 contract")
    for key in ("vulnerable_path", "clean_path"):
        path = root / fixture.get(key, "")
        require(path.is_file(), f"fixture path does not exist: {path}")

    require(demo.get("configuration") == "none", "demo configuration must be explicit")
    require(demo.get("offline") is True, "demo must remain offline")
    require(demo.get("account_required") is False, "demo must not require an account")
    require(demo.get("source_upload") is False, "demo must not upload source")

    paths = [
        root / demo.get("runbook", ""),
        root / demo.get("transcript", ""),
        root / manifest.get("claims_registry", ""),
    ]
    launch_copy = manifest.get("launch_copy")
    require(isinstance(launch_copy, list) and launch_copy, "launch_copy must list the publication drafts")
    paths.extend(root / value for value in launch_copy)
    for path in paths:
        require(path.is_file(), f"required launch file does not exist: {path}")

    runbook = paths[0].read_text(encoding="utf-8")
    for value in (release["tag"], release["commit"], fixture["commit"]):
        require(value in runbook, f"runbook is not pinned to {value}")
    require("Configuration: none" in runbook, "runbook must declare the exact configuration")

    for path in (root / value for value in launch_copy):
        text = path.read_text(encoding="utf-8")
        for marker in LAUNCH_CONTENT_MARKERS:
            require(marker in text, f"{path} must link {marker}")

    require(verification.get("command") == "python3 scripts/validate-launch-kit.py --require-ready --check-remote", "invalid final verification command")
    require(verification.get("required_age_hours") == 24, "final verification window must be 24 hours")
    signoffs = verification.get("owner_signoffs")
    require(isinstance(signoffs, dict), "owner_signoffs must be an object")
    require(set(signoffs) == {"product", "cli", "website", "launch_copy"}, "owner_signoffs has unexpected owners")

    if require_ready:
        require(manifest["status"] == "ready", "launch manifest status is not ready")
        require(release["launch_candidate"] is True, "pinned release is not approved as the launch candidate")
        recording_url = demo.get("recording_url")
        require(isinstance(recording_url, str) and recording_url.startswith("https://"), "demo recording URL is required")
        duration = demo.get("recording_duration_seconds")
        require(isinstance(duration, (int, float)) and 0 < duration <= 120, "demo recording must be no longer than two minutes")
        verified_at = parse_timestamp(verification.get("last_verified_at"))
        age_hours = (datetime.now(timezone.utc) - verified_at).total_seconds() / 3600
        require(0 <= age_hours <= 24, f"launch evidence is stale ({age_hours:.1f} hours old)")
        require(SHA_PATTERN.fullmatch(verification.get("verified_commit", "")) is not None, "verified_commit must be a full SHA")
        require(all(isinstance(value, str) and value for value in signoffs.values()), "all four owners must sign off")
    else:
        require(manifest["status"] == "preparing" or demo.get("recording_url"), "ready manifest requires a recording")

    validate_local_links(paths, root)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--require-ready", action="store_true")
    parser.add_argument("--check-remote", action="store_true")
    args = parser.parse_args()

    root = Path.cwd()
    try:
        manifest = read_json(args.manifest)
        paths = validate_manifest(manifest, root, args.require_ready)
        urls = collect_remote_urls(paths, manifest)
        if args.check_remote:
            for url in urls:
                check_remote_url(url)
            verify_github_pins(manifest)
    except (KeyError, TypeError, ValidationError) as error:
        print(f"Launch kit invalid: {error}", file=sys.stderr)
        return 1

    readiness = manifest["status"]
    remote = f", {len(urls)} remote links and Git pins checked" if args.check_remote else ""
    print(f"Launch kit valid: status={readiness}, {len(paths)} documents{remote}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
