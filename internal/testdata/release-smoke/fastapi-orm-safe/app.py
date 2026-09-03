"""FastAPI ORM safe fixture: parameterized SQLAlchemy select().where().

This fixture represents textbook-safe ORM code that was falsely flagged as
PF-FASTAPI-SQLI-002-IP (interprocedural taint SQLi) before the -IP safe-pattern
suppression fix. The `select(` safe pattern in the config should suppress any
taint findings because select() parameterizes comparisons.

Regression source: Safe-pip-backend app/api/v1/endpoints/pr_reviews.py:410-415
"""
from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

app = FastAPI()


class PrReview:
    repository: str
    pr_number: int
    head_sha: str


async def get_db():
    yield None


@app.post("/webhook")
async def webhook(
    repository: str,
    pr_number: int,
    head_sha: str,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(PrReview).where(
        PrReview.repository == repository,
        PrReview.pr_number == pr_number,
        PrReview.head_sha == head_sha,
    )
    result = await db.execute(stmt)
    return result.scalars().first()
