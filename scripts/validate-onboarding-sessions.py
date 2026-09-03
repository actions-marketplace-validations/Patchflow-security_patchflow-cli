#!/usr/bin/env python3
"""Validate and summarize anonymized fresh-user onboarding evidence."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import date
from pathlib import Path
from typing import Any


DEFAULT_RESULTS = Path("docs/launch/onboarding-session-results.json")
ALLOWED_EXPOSURE = {"none"}
ALLOWED_UPLOAD_BELIEF = {"no", "yes", "unsure"}
REQUIRED_SESSION_FIELDS = {
    "id",
    "date",
    "participant_role",
    "os",
    "architecture",
    "shell",
    "prior_patchflow_exposure",
    "elapsed_seconds",
    "useful_result_reached",
    "explained_risk",
    "identified_next_action",
    "account_required",
    "believed_source_uploaded",
    "first_confusion",
    "blocking_defect",
    "follow_up_issue",
}


class ValidationError(ValueError):
    """Raised when session evidence does not satisfy the public schema."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def session_succeeded(session: dict[str, Any]) -> bool:
    return bool(
        session["elapsed_seconds"] < 300
        and session["useful_result_reached"]
        and session["explained_risk"]
        and session["identified_next_action"]
        and not session["account_required"]
    )


def calculate_summary(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    elapsed = [session["elapsed_seconds"] for session in sessions]
    success_count = sum(session_succeeded(session) for session in sessions)
    gate_passed = len(sessions) == 5 and success_count >= 4
    gate_failed = len(sessions) == 5 and success_count < 4
    return {
        "total_sessions": len(sessions),
        "successful_under_300_seconds": success_count,
        "median_elapsed_seconds": statistics.median(elapsed) if elapsed else None,
        "gate": "pass" if gate_passed else "fail" if gate_failed else "pending",
    }


def validate_document(document: dict[str, Any]) -> dict[str, Any]:
    _require(document.get("schema_version") == "1.0", "schema_version must be 1.0")
    _require(document.get("status") in {"recruiting", "passed", "failed"}, "invalid status")
    _require(isinstance(document.get("issue"), str) and document["issue"], "issue is required")
    _require(
        document.get("methodology") == "docs/launch/FRESH_USER_SESSIONS.md",
        "methodology must reference the moderated protocol",
    )
    sessions = document.get("sessions")
    _require(isinstance(sessions, list), "sessions must be a list")
    _require(len(sessions) <= 5, "the launch cohort must contain exactly five or fewer sessions")

    seen_ids: set[str] = set()
    for index, session in enumerate(sessions, start=1):
        _require(isinstance(session, dict), f"session {index} must be an object")
        missing = REQUIRED_SESSION_FIELDS - session.keys()
        _require(not missing, f"session {index} is missing fields: {sorted(missing)}")
        _require(isinstance(session["id"], str) and session["id"], f"session {index} has invalid id")
        _require(session["id"] not in seen_ids, f"duplicate session id: {session['id']}")
        seen_ids.add(session["id"])
        try:
            date.fromisoformat(session["date"])
        except (TypeError, ValueError) as error:
            raise ValidationError(f"session {index} has invalid ISO date") from error
        _require(
            session["prior_patchflow_exposure"] in ALLOWED_EXPOSURE,
            f"session {index} is not a fresh-user session",
        )
        _require(
            isinstance(session["elapsed_seconds"], (int, float))
            and not isinstance(session["elapsed_seconds"], bool)
            and session["elapsed_seconds"] > 0,
            f"session {index} has invalid elapsed_seconds",
        )
        for field in (
            "useful_result_reached",
            "explained_risk",
            "identified_next_action",
            "account_required",
        ):
            _require(type(session[field]) is bool, f"session {index} field {field} must be boolean")
        _require(
            session["believed_source_uploaded"] in ALLOWED_UPLOAD_BELIEF,
            f"session {index} has invalid source-upload belief",
        )
        for field in ("participant_role", "os", "architecture", "shell"):
            _require(isinstance(session[field], str) and session[field], f"session {index} field {field} is required")
        for field in ("first_confusion", "blocking_defect", "follow_up_issue"):
            _require(
                session[field] is None or isinstance(session[field], str),
                f"session {index} field {field} must be a string or null",
            )
        if session["blocking_defect"]:
            _require(
                bool(session["follow_up_issue"]),
                f"session {index} blocking defect must link a follow-up issue",
            )

    calculated = calculate_summary(sessions)
    _require(document.get("summary") == calculated, "summary does not match calculated session evidence")
    expected_status = {
        "pass": "passed",
        "fail": "failed",
        "pending": "recruiting",
    }[calculated["gate"]]
    _require(document["status"] == expected_status, f"status must be {expected_status}")
    return calculated


def load_document(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot read {path}: {error}") from error
    _require(isinstance(document, dict), "results document must be an object")
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--write-summary", action="store_true")
    parser.add_argument("--require-pass", action="store_true")
    args = parser.parse_args()

    try:
        document = load_document(args.results)
        if args.write_summary:
            sessions = document.get("sessions")
            _require(isinstance(sessions, list), "sessions must be a list")
            candidate = dict(document)
            candidate["summary"] = calculate_summary(sessions)
            candidate["status"] = {
                "pass": "passed",
                "fail": "failed",
                "pending": "recruiting",
            }[candidate["summary"]["gate"]]
            summary = validate_document(candidate)
            args.results.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
        else:
            summary = validate_document(document)
        if args.require_pass:
            _require(summary["gate"] == "pass", "fresh-user launch gate has not passed")
    except (KeyError, TypeError, ValidationError) as error:
        print(f"Onboarding session evidence invalid: {error}", file=sys.stderr)
        return 1

    print(
        "Onboarding session evidence valid: "
        f"{summary['total_sessions']} sessions, "
        f"{summary['successful_under_300_seconds']} successful, "
        f"gate={summary['gate']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
