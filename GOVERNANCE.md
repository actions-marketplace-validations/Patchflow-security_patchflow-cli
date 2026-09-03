# Governance

PatchFlow CLI uses lightweight maintainer governance intended to keep technical
decisions reviewable while the contributor community grows.

## Roles

| Role | Responsibilities | How the role is obtained |
| --- | --- | --- |
| User | Uses the CLI and provides feedback | Open to everyone |
| Contributor | Submits issues, code, rules, fixtures, docs, or reviews | Any accepted participation under the Code of Conduct |
| Maintainer | Triages, reviews, merges, moderates, and stewards an area | Invited by consensus of current maintainers after sustained trusted contribution |
| Release maintainer | Creates tags/releases and verifies provenance and artifacts | Explicit delegation by organization owners |
| Security maintainer | Receives private reports and coordinates advisories | Explicit delegation with repository security access |

The current organization owner and initial maintainer is
[@malik111110](https://github.com/malik111110). Repository permissions are the
authoritative record of current merge, release, and security access.

## Decisions

Routine changes use the normal issue and pull-request process. A maintainer may
merge once required checks pass, review feedback is resolved, and the change has
the necessary approval under branch protection.

Open a public design issue or architecture decision record for changes that:

- break CLI flags, configuration, output schemas, rule IDs, or exit codes;
- change local-first/privacy behavior or source upload boundaries;
- add a required network service or external scanner;
- alter licensing, contribution terms, governance, release provenance, or the
  supported platform matrix;
- create substantial false-positive, performance, or binary-size risk.

The issue should state the user outcome, alternatives, compatibility plan,
security/privacy impact, evidence, and rollback. Maintainers seek rough
consensus; when consensus is not possible, the organization owner records the
decision and rationale publicly. Security-sensitive details may be decided in a
private advisory and summarized after disclosure.

## Review and merge authority

- Authors do not approve their own pull requests when another maintainer is
  available.
- Required CI and review rules may not be bypassed for convenience.
- Emergency security fixes may use a private fork/advisory, but the public
  history, advisory, tests, and release provenance are reconciled after release.
- Force-pushes to protected default and release branches are prohibited.
- Maintainers may close stale or out-of-scope proposals with a reason and a path
  to reconsideration.

## Releases

Release maintainers are the only role authorized to create official tags and
publish GitHub/GHCR/Homebrew/Scoop artifacts. A release must originate from a
reviewed public commit, pass the release workflow, use the versioning and
compatibility policy in `RELEASE.md`, and publish checksums/provenance required by
the release configuration.

No date or feature commitment is binding until it appears in a published release.

## Becoming or leaving a maintainer

A nomination should cite sustained contributions, sound review judgment,
security awareness, respectful conduct, and availability. Existing maintainers
record the decision in a public issue unless privacy or safety requires a private
record. Access follows least privilege and is reviewed when responsibilities
change.

Maintainers may step down at any time. Inactive access may be removed after an
attempt to contact the maintainer. Conduct violations or security abuse may lead
to immediate suspension by organization owners, followed by a documented review.

## Governance changes

Changes to this document require a dedicated pull request, public rationale, and
approval from the organization owner plus any other active maintainer. The
change takes effect only after merge; contribution or licensing terms do not
change retroactively without explicit legal review.
