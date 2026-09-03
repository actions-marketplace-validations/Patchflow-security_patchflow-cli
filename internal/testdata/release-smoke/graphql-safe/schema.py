"""GraphQL safe fixture: parameterized SQLAlchemy ORM query in resolver.
The safe pattern "select(" should suppress PF-GRAPHQL-SQLI-001 -IP false positives.
"""
import graphene
from sqlalchemy import select
from sqlalchemy.orm import Session


class User(graphene.ObjectType):
    id = graphene.ID()
    name = graphene.String()


class Query(graphene.ObjectType):
    user = graphene.Field(User, id=graphene.ID(required=True))

    def resolve_user(self, info, id):
        db: Session = info.context["db"]
        # SAFE: parameterized SQLAlchemy ORM select
        stmt = select(User).where(User.id == id)
        result = db.execute(stmt)
        return result.scalars().first()
