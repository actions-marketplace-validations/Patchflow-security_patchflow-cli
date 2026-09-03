import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "validate-onboarding-sessions.py"
SPEC = importlib.util.spec_from_file_location("validate_onboarding_sessions", SCRIPT)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def session(identifier: str, elapsed: int = 120, success: bool = True) -> dict:
    return {
        "id": identifier,
        "date": "2026-07-18",
        "participant_role": "developer",
        "os": "Linux",
        "architecture": "x64",
        "shell": "bash",
        "prior_patchflow_exposure": "none",
        "elapsed_seconds": elapsed,
        "useful_result_reached": success,
        "explained_risk": success,
        "identified_next_action": success,
        "account_required": False,
        "believed_source_uploaded": "no",
        "first_confusion": None,
        "blocking_defect": None,
        "follow_up_issue": None,
    }


def document(sessions: list[dict]) -> dict:
    summary = validator.calculate_summary(sessions)
    return {
        "schema_version": "1.0",
        "status": {
            "pass": "passed",
            "fail": "failed",
            "pending": "recruiting",
        }[summary["gate"]],
        "issue": "https://github.com/Patchflow-security/patchflow-cli/issues/5",
        "methodology": "docs/launch/FRESH_USER_SESSIONS.md",
        "sessions": sessions,
        "summary": summary,
    }


class OnboardingSessionValidationTests(unittest.TestCase):
    def test_pending_empty_cohort_is_valid(self) -> None:
        summary = validator.validate_document(document([]))
        self.assertEqual("pending", summary["gate"])

    def test_four_of_five_successes_pass(self) -> None:
        sessions = [session(f"PF-ONB-{index:02}") for index in range(1, 5)]
        sessions.append(session("PF-ONB-05", elapsed=301, success=False))
        summary = validator.validate_document(document(sessions))
        self.assertEqual("pass", summary["gate"])
        self.assertEqual(120, summary["median_elapsed_seconds"])

    def test_automation_or_prior_exposure_cannot_count(self) -> None:
        sessions = [session("PF-ONB-01")]
        sessions[0]["prior_patchflow_exposure"] = "limited"
        with self.assertRaisesRegex(validator.ValidationError, "not a fresh-user"):
            validator.validate_document(document(sessions))

    def test_tampered_summary_is_rejected(self) -> None:
        evidence = document([session("PF-ONB-01")])
        evidence["summary"]["successful_under_300_seconds"] = 0
        with self.assertRaisesRegex(validator.ValidationError, "summary does not match"):
            validator.validate_document(evidence)

    def test_exactly_five_sessions_are_required_to_pass(self) -> None:
        sessions = [session(f"PF-ONB-{index:02}") for index in range(1, 5)]
        summary = validator.validate_document(document(sessions))
        self.assertEqual("pending", summary["gate"])

    def test_completed_cohort_with_too_few_successes_fails(self) -> None:
        sessions = [session(f"PF-ONB-{index:02}") for index in range(1, 4)]
        sessions.extend(
            [
                session("PF-ONB-04", elapsed=300, success=False),
                session("PF-ONB-05", elapsed=301, success=False),
            ]
        )
        summary = validator.validate_document(document(sessions))
        self.assertEqual("fail", summary["gate"])

    def test_blocking_defect_requires_follow_up_issue(self) -> None:
        sessions = [session("PF-ONB-01")]
        sessions[0]["blocking_defect"] = "installer checksum failed"
        with self.assertRaisesRegex(validator.ValidationError, "must link a follow-up issue"):
            validator.validate_document(document(sessions))


if __name__ == "__main__":
    unittest.main()
