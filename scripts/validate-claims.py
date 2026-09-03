#!/usr/bin/env python3
"""Validate the dated launch-claim registry using only the Python stdlib."""

import datetime as dt
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docs" / "claims" / "registry.json"
VALID_STATUSES = {"approved", "pending", "hold", "retired"}


def main() -> int:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    maximum_age = int(data["policy"]["maximum_age_days"])
    today = dt.date.today()
    errors = []
    seen = set()

    for claim in data.get("claims", []):
        claim_id = claim.get("id", "<missing-id>")
        if claim_id in seen:
            errors.append(f"duplicate claim id: {claim_id}")
        seen.add(claim_id)
        for field in ("id", "type", "statement", "status", "scope", "evidence", "limitations", "owner", "last_verified"):
            if not claim.get(field):
                errors.append(f"{claim_id}: missing {field}")
        if claim.get("status") not in VALID_STATUSES:
            errors.append(f"{claim_id}: invalid status {claim.get('status')!r}")
        if claim.get("type") == "metric" and not claim.get("methodology"):
            errors.append(f"{claim_id}: metric has no methodology")
        try:
            verified = dt.date.fromisoformat(claim["last_verified"])
            if claim.get("status") == "approved" and (today - verified).days > maximum_age:
                errors.append(f"{claim_id}: approved claim is stale ({verified})")
        except (KeyError, ValueError):
            errors.append(f"{claim_id}: invalid last_verified date")
        for evidence in claim.get("evidence", []):
            if evidence.startswith("https://"):
                continue
            if not (ROOT / evidence).exists():
                errors.append(f"{claim_id}: evidence path does not exist: {evidence}")

    if errors:
        print("Claim registry validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"Claim registry valid: {len(seen)} claims")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
