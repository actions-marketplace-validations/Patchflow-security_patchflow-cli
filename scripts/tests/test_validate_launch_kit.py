import importlib.util
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "validate-launch-kit.py"
SPEC = importlib.util.spec_from_file_location("validate_launch_kit", SCRIPT)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


SHA_A = "a" * 40
SHA_B = "b" * 40


class LaunchKitValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for path in (
            "examples/quickstart/vulnerable/app.py",
            "examples/quickstart/clean/app.py",
            "docs/claims/registry.json",
            "docs/MACHINE_READABLE_OUTPUTS.md",
            "SUPPORT.md",
            "SECURITY.md",
            "LICENSE",
        ):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("{}\n" if path.endswith(".json") else "# document\n", encoding="utf-8")
        marker_links = (
            "[Claims](../claims/registry.json) "
            "[Support](../../SUPPORT.md) "
            "[Security](../../SECURITY.md) "
            "[License](../../LICENSE) "
            "[SARIF](../MACHINE_READABLE_OUTPUTS.md) "
            "[Feedback](https://github.com/Patchflow-security/patchflow-cli/issues)\n"
        )
        for path in ("TECHNICAL_LAUNCH.md", "SHOW_HN.md", "COMMUNITY_VARIANTS.md"):
            target = self.root / "docs/launch" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(marker_links, encoding="utf-8")
        runbook = self.root / "docs/launch/DEMO.md"
        runbook.write_text(f"Configuration: none\n{SHA_A}\n{SHA_B}\nv1.2.3\n", encoding="utf-8")
        transcript = self.root / "docs/launch/TRANSCRIPT.md"
        transcript.write_text("# transcript\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manifest(self) -> dict:
        return {
            "schema_version": "1.0",
            "status": "preparing",
            "issue": "https://github.com/Patchflow-security/patchflow-cli/issues/8",
            "repository": "https://github.com/Patchflow-security/patchflow-cli",
            "release": {
                "tag": "v1.2.3",
                "commit": SHA_A,
                "launch_candidate": False,
                "known_limitations": ["rehearsal release"],
                "url": "https://github.com/release/v1.2.3",
                "checksums_url": "https://github.com/release/v1.2.3/checksums.txt",
                "signature_url": "https://github.com/release/v1.2.3/checksums.txt.sig",
            },
            "fixture": {
                "commit": SHA_B,
                "archive_url": f"https://github.com/archive/{SHA_B}.tar.gz",
                "vulnerable_path": "examples/quickstart/vulnerable/app.py",
                "clean_path": "examples/quickstart/clean/app.py",
                "expected_rule": "PY001",
            },
            "demo": {
                "runbook": "docs/launch/DEMO.md",
                "transcript": "docs/launch/TRANSCRIPT.md",
                "configuration": "none",
                "offline": True,
                "account_required": False,
                "source_upload": False,
                "recording_url": None,
                "recording_duration_seconds": None,
            },
            "launch_copy": [
                "docs/launch/TECHNICAL_LAUNCH.md",
                "docs/launch/SHOW_HN.md",
                "docs/launch/COMMUNITY_VARIANTS.md",
            ],
            "claims_registry": "docs/claims/registry.json",
            "verification": {
                "command": "python3 scripts/validate-launch-kit.py --require-ready --check-remote",
                "required_age_hours": 24,
                "last_verified_at": None,
                "verified_commit": None,
                "owner_signoffs": {"product": None, "cli": None, "website": None, "launch_copy": None},
            },
        }

    def test_preparing_manifest_is_valid_but_not_launch_ready(self) -> None:
        manifest = self.manifest()
        validator.validate_manifest(manifest, self.root, require_ready=False)
        with self.assertRaisesRegex(validator.ValidationError, "status is not ready"):
            validator.validate_manifest(manifest, self.root, require_ready=True)

    def test_ready_manifest_requires_recent_verification_and_signoffs(self) -> None:
        manifest = self.manifest()
        manifest["status"] = "ready"
        manifest["release"]["launch_candidate"] = True
        manifest["release"]["known_limitations"] = []
        manifest["demo"]["recording_url"] = "https://example.com/demo"
        manifest["demo"]["recording_duration_seconds"] = 119
        manifest["verification"]["last_verified_at"] = datetime.now(timezone.utc).isoformat()
        manifest["verification"]["verified_commit"] = "c" * 40
        manifest["verification"]["owner_signoffs"] = {
            "product": "product-owner",
            "cli": "cli-owner",
            "website": "website-owner",
            "launch_copy": "copy-owner",
        }
        validator.validate_manifest(manifest, self.root, require_ready=True)

    def test_rehearsal_release_cannot_pass_final_gate(self) -> None:
        manifest = self.manifest()
        manifest["status"] = "ready"
        manifest["demo"]["recording_url"] = "https://example.com/demo"
        manifest["demo"]["recording_duration_seconds"] = 119
        manifest["verification"]["last_verified_at"] = datetime.now(timezone.utc).isoformat()
        manifest["verification"]["verified_commit"] = "c" * 40
        manifest["verification"]["owner_signoffs"] = {
            key: "owner" for key in ("product", "cli", "website", "launch_copy")
        }
        with self.assertRaisesRegex(validator.ValidationError, "not approved"):
            validator.validate_manifest(manifest, self.root, require_ready=True)

    def test_stale_verification_is_rejected(self) -> None:
        manifest = self.manifest()
        manifest["status"] = "ready"
        manifest["release"]["launch_candidate"] = True
        manifest["release"]["known_limitations"] = []
        manifest["demo"]["recording_url"] = "https://example.com/demo"
        manifest["demo"]["recording_duration_seconds"] = 100
        manifest["verification"]["last_verified_at"] = (
            datetime.now(timezone.utc) - timedelta(hours=25)
        ).isoformat()
        manifest["verification"]["verified_commit"] = "c" * 40
        manifest["verification"]["owner_signoffs"] = {key: "owner" for key in ("product", "cli", "website", "launch_copy")}
        with self.assertRaisesRegex(validator.ValidationError, "stale"):
            validator.validate_manifest(manifest, self.root, require_ready=True)

    def test_unpinned_fixture_archive_is_rejected(self) -> None:
        manifest = self.manifest()
        manifest["fixture"]["archive_url"] = "https://github.com/archive/main.tar.gz"
        with self.assertRaisesRegex(validator.ValidationError, "pinned"):
            validator.validate_manifest(manifest, self.root, require_ready=False)

    def test_broken_local_markdown_link_is_rejected(self) -> None:
        source = self.root / "docs/launch/TECHNICAL_LAUNCH.md"
        source.write_text("[Missing](missing.md)\n", encoding="utf-8")
        with self.assertRaisesRegex(validator.ValidationError, "broken local link"):
            validator.validate_local_links([source], self.root)

    def test_remote_url_collection_strips_json_quotes_and_skips_templates(self) -> None:
        source = self.root / "docs/claims/registry.json"
        source.write_text(
            '{"url":"https://example.com/report.md",'
            '"template":"https://example.com/${COMMIT}/archive.tar.gz"}\n',
            encoding="utf-8",
        )
        urls = validator.collect_remote_urls([source], self.manifest())
        self.assertIn("https://example.com/report.md", urls)
        self.assertFalse(any("${COMMIT}" in url for url in urls))

    def test_github_pins_match_release_and_fixture_commits(self) -> None:
        manifest = self.manifest()

        def fake_fetch(url: str) -> dict:
            if "/git/ref/tags/" in url:
                return {"object": {"type": "commit", "sha": SHA_A}}
            if "/contents/" in url:
                return {"type": "file"}
            if f"/git/commits/{SHA_B}" in url:
                return {"sha": SHA_B}
            self.fail(f"unexpected URL: {url}")

        validator.verify_github_pins(manifest, fetch=fake_fetch)

    def test_mismatched_release_tag_commit_is_rejected(self) -> None:
        manifest = self.manifest()

        def fake_fetch(url: str) -> dict:
            return {"object": {"type": "commit", "sha": "c" * 40}}

        with self.assertRaisesRegex(validator.ValidationError, "does not resolve"):
            validator.verify_github_pins(manifest, fetch=fake_fetch)


if __name__ == "__main__":
    unittest.main()
