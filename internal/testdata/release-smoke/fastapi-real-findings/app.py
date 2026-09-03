"""FastAPI real-findings fixture: actual vulnerabilities from Safe-pip-backend.

These are real findings that the scanner should detect:
1. verify=False on httpx.AsyncClient (CWE-295, TLS bypass)
2. hashlib.sha1 in a security context (CWE-327, weak hash)
3. text(f"...") with interpolation (CWE-89, SQLi)

Regression source: Safe-pip-backend scan (2026-07-05)
  - app/services/adapter_argocd_service.py:252  (verify=False)
  - app/services/pr_review_evidence_aggregator.py:529  (sha1)
  - app/api/deps.py:91  (text(f"..."))
"""
import hashlib
import httpx
from sqlalchemy import text
from fastapi import FastAPI

app = FastAPI()


@app.get("/fetch")
async def fetch_internal(url: str):
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get(url)
        return resp.json()


def compute_digest(raw: str) -> str:
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return digest


@app.post("/set-context")
async def set_context(user_id: int, db):
    await db.execute(text(f"SET app.current_user_id = '{user_id}'"))
    return {"status": "ok"}
