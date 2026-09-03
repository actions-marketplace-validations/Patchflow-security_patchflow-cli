# Issue triage and response policy

Last reviewed: 2026-07-18

This policy sets service targets, not guarantees. Security reports follow the
private security process and are never triaged in public issues.

## Labels

Every accepted issue should have one type or contribution label, one area when
available, and a priority only when it affects a committed launch outcome.

| Label | Use |
| --- | --- |
| `bug` | reproducible behavior that differs from the documented contract |
| `enhancement` | a new or materially changed product behavior |
| `documentation` | documentation-only correction or clarification |
| `question` | support or usage question with no confirmed defect |
| `good first issue` | bounded change with named files, fixtures, and commands |
| `help wanted` | accepted work that needs contributor capacity or domain expertise |
| `area:*` | owning product surface such as CI, standards, onboarding, or community |
| `priority:P0` | blocks a safe, reproducible public launch |
| `priority:P1` | required before or immediately after launch |
| `duplicate` | another issue owns the same outcome; link it before closing |
| `invalid` | cannot be acted on after the missing evidence was requested |
| `wontfix` | intentionally outside the product direction; record the reason |

Maturity (`experimental`, `beta`, `stable`, `enterprise`) is rule metadata in
source, not a GitHub priority. A maturity change requires vulnerable, safe, and
normal/no-noise evidence plus the relevant regression suite.

## Response targets

Targets are measured in business days from a complete report:

| Report | First response | Triage target |
| --- | ---: | ---: |
| suspected security vulnerability | use private reporting; acknowledge within 2 days | initial severity and next update within 5 days |
| release, data-loss, or false-negative blocker | 1 day | owner and decision within 3 days |
| false positive or reproducible bug | 3 days | reproduce, request evidence, or close within 7 days |
| rule or feature request | 5 days | roadmap fit and next action within 10 days |
| question | 5 days | answer or redirect within 10 days |

Maintainers may shorten these targets based on severity. Public comments must not
ask reporters to disclose secrets, proprietary source, tokens, or exploit details.

## Triage flow

1. Confirm the report contains the CLI version, platform, minimal fixture or
   public reproduction, expected result, and actual result.
2. Remove secrets and move possible vulnerabilities to private reporting.
3. Reproduce on a supported release and current `main` when safe.
4. Apply labels, link duplicates, and state the user outcome in one sentence.
5. Add acceptance criteria, exact test commands, and maintainer guidance before
   applying `good first issue` or `help wanted`.
6. Record a close reason and evidence. Reopen when new reproducible evidence
   changes the decision.

## Inactivity and closure

- Maintainer-owned launch work is never auto-closed for inactivity.
- A report waiting on required reproduction details may be marked inactive after
  30 days without a response and closed after another 14 days.
- Questions answered with a documented path may close after 7 days without a
  follow-up.
- Accepted enhancements may remain open without activity when they still match a
  roadmap outcome; otherwise maintainers close them with a rationale.
- A pull request may be closed after 30 days without author response to requested
  changes, after a final 7-day notice. Its linked issue stays open when the outcome
  is still wanted.

No bot should apply these rules until maintainers have reviewed its permissions,
messages, exemptions, and dry-run output.

## Contributor-ready definition

A newcomer task must name the relevant files and existing test pattern, provide a
minimal fixture, avoid hidden services or private data, and list the exact local
commands expected to pass. A guided task must additionally name the risky boundary
and the evidence a maintainer will review before merge.
