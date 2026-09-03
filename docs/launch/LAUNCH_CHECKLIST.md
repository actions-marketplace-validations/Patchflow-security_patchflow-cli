# Public launch checklist

## Technical gate

- [ ] Five-minute onboarding workflow green on Linux x64/arm64, macOS Intel/arm64, Windows x64, and container.
- [ ] Per-platform JSON evidence downloaded and reviewed.
- [ ] Release archive checksums and signatures verified.
- [ ] Demo fixture pinned to the launch commit and release version.
- [ ] Vulnerable scan, clean scan, `explain`, and SARIF commands rerun within 24 hours.
- [ ] Core path reconfirmed without login, `--submit`, or source upload.

## Product gate

- [ ] Five fresh-user sessions complete under the
  [moderated protocol](FRESH_USER_SESSIONS.md).
- [ ] At least four participants reach and understand a useful result in under
  five minutes.
- [ ] `python3 scripts/validate-onboarding-sessions.py --require-pass` succeeds.
- [ ] Median time and anonymized failure notes from
  [`onboarding-session-results.json`](onboarding-session-results.json) are linked
  from CLI issue #5.
- [ ] Every launch metric is `approved` in the dated claim registry.
- [ ] Product, CLI, website, and launch-copy owners sign off on the same registry.

## Publication gate

- [ ] Technical post final copy reviewed.
- [ ] Show HN and community variants checked against current limitations.
- [ ] `docs/launch/manifest.json` pins the release, release commit, fixture
  commit, configuration, recording, verified commit, and owner sign-offs.
- [ ] Repository, release, support, license, security-policy, and SARIF links tested.
- [ ] `python3 scripts/validate-launch-kit.py --require-ready --check-remote`
  passes less than 24 hours before publication.
- [ ] Support owner available for the launch window.
- [ ] Go/no-go decision and rollback owner recorded.
