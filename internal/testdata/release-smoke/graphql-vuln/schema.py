"""GraphQL vulnerable fixture: f-string SQL in resolver.
PF-GRAPHQL-SQLI-001 should fire on the f-string SQL.
PF-GRAPHQL-SSRF-001 should fire on the user-controlled URL fetch.
"""
import graphene
import requests


class User(graphene.ObjectType):
    id = graphene.ID()
    name = graphene.String()


class Query(graphene.ObjectType):
    user = graphene.Field(User, name=graphene.String(required=True))

    def resolve_user(self, info, name):
        db = info.context["db"]
        # VULNERABLE: f-string SQL injection in GraphQL resolver
        cursor = db.execute(f"SELECT * FROM users WHERE name = '{name}'")
        row = cursor.fetchone()
        return User(id=row[0], name=row[1])

    fetch = graphene.Field(graphene.String, url=graphene.String(required=True))

    def resolve_fetch(self, info, url):
        # VULNERABLE: SSRF — user-controlled URL in GraphQL resolver
        resp = requests.get(url)
        return resp.text
