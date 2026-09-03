# PatchFlow CLI public roadmap

Last reviewed: 2026-07-18

This roadmap communicates outcomes and contribution opportunities. It is not a
promise of dates or scope. Maintainers move work between horizons when evidence,
security risk, or contributor capacity changes.

## Now: make the public CLI trustworthy to adopt

User outcome: a developer can install the public release, run a local scan, and
consume the result in automation without private context.

- Keep the public repository canonical, reviewed, and protected from source drift.
- Keep Linux, macOS, Windows, release, and self-scan checks reproducible and green.
- Make JSON and SARIF output deterministic and standards-conformant.
- Publish contribution, security, support, governance, and triage paths.
- Validate the five-minute install-to-first-trusted-result journey.

Exit signal: the release candidate is traceable to public source, the default
branch is green, and a new user can obtain and understand a local result.

## Next: improve signal quality and reproducible proof

User outcome: teams can decide whether a finding matters and verify PatchFlow's
claims against public evidence.

- Expand safe, vulnerable, and normal/no-noise fixtures for framework rules.
- Promote rules only when fixture and regression evidence meets the maturity bar.
- Publish a dated capability and benchmark claim registry.
- Improve rule explanations, suppression guidance, and framework-pack discovery.
- Ship a reproducible install-to-scan-to-SARIF technical demo.

Exit signal: important claims point to repeatable evidence and framework maturity
reflects measured false-positive and detection behavior.

## Later: deepen integrations without weakening local-first use

User outcome: organizations can adopt richer workflows while retaining a useful
offline/local path and an explicit data boundary.

- Broaden language, framework, and template coverage based on user evidence.
- Harden signed release, SBOM, provenance, and update workflows.
- Add optional cloud submission and pull-request workflows behind documented
  authentication, privacy, tenancy, and idempotency contracts.
- Improve performance and incremental analysis for larger repositories.

Entry requires: the local scan contract and public release gate remain stable.

## Framework-rule maturity snapshot

Maturity is assigned per rule in `internal/sast/frameworks/<pack>/rules.go`.
It describes evidence, not marketing priority:

- `experimental`: expected to change; contributors should add fixtures and noise evidence.
- `beta`: useful with positive and safe cases; broader regression evidence is still wanted.
- `stable`: release-gated behavior with representative regression evidence.
- `enterprise`: stable behavior with additional support or policy guarantees.

The registered public packs currently contain:

| Pack | Beta rules | Experimental rules | Contribution need |
| --- | ---: | ---: | --- |
| Angular | 3 | 2 | fixtures for experimental redirect and XSS rules |
| ASP.NET | 5 | 3 | normal/no-noise fixtures for experimental rules |
| Django | 7 | 0 | broader clean-repository regression evidence |
| Echo | 3 | 0 | safe SQL and redirect fixtures |
| Express | 9 | 0 | strict real-repository source-to-sink regression |
| FastAPI | 0 | 9 | positive, safe, and normal fixtures before promotion |
| Flask | 7 | 2 | fixtures for experimental SQLi and SSRF rules |
| Gin | 4 | 0 | command-injection positive and safe fixtures |
| GraphQL | 4 | 1 | strict source modeling and DoS regression evidence |
| Laravel | 6 | 0 | broader clean-repository regression evidence |
| NestJS | 4 | 0 | SSRF positive and safe fixtures |
| Next.js | 4 | 0 | broader clean-repository regression evidence |
| Rails | 0 | 15 | maturity review backed by the existing fixture corpus |
| Razor | 2 | 0 | coverage for the second XSS rule |
| React | 4 | 0 | broader clean-repository regression evidence |
| Spring | 1 | 30 | strict annotation-source regression and maturity review |
| Spring Security | 4 | 0 | broader clean-repository regression evidence |
| Symfony | 3 | 0 | safe SQL and redirect fixtures |

This table is a dated view of the source registry. A pull request that changes
rule maturity must update the table and include the evidence required by the
[triage policy](docs/TRIAGE.md).

## How to contribute

- Choose a bounded [`good first issue`](https://github.com/Patchflow-security/patchflow-cli/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
- Choose a guided [`help wanted`](https://github.com/Patchflow-security/patchflow-cli/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) task.
- Use the [issue chooser](https://github.com/Patchflow-security/patchflow-cli/issues/new/choose) for a bug, false positive, rule request, or proposal.
- Read the [triage and response policy](docs/TRIAGE.md) before proposing a maturity change.

Security vulnerabilities must use GitHub's
[private reporting flow](https://github.com/Patchflow-security/patchflow-cli/security/advisories/new),
never a public issue.
