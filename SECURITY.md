# Security policy

PatchFlow CLI is a security tool. Please report vulnerabilities privately so
users can receive a fix before exploit details are public.

## Supported versions

| Version | Security support |
| --- | --- |
| Latest published release series | Supported |
| Earlier release series | Upgrade required unless a maintainer announces an exception |
| `main` and unreleased snapshots | Best effort; not a supported production release |

The current release is listed on the
[GitHub releases page](https://github.com/Patchflow-security/patchflow-cli/releases/latest).

## Private reporting

Use GitHub's private vulnerability reporting form:

**[Report a vulnerability privately](https://github.com/Patchflow-security/patchflow-cli/security/advisories/new)**

Do not disclose the vulnerability in a public issue, discussion, pull request,
commit message, benchmark, or fixture. If the form is unavailable, contact a
Patchflow-security organization owner through an existing private channel and
ask for a private advisory to be opened; do not send exploit details publicly.

Include when possible:

- affected version, platform, and installation method;
- vulnerability class and realistic impact;
- minimal reproduction or proof of concept;
- whether untrusted repository content is required;
- logs with tokens, source, credentials, paths, and personal data removed;
- suggested remediation and disclosure constraints.

Examples in scope include arbitrary command execution, path traversal, unsafe
archive handling, secret leakage, authentication/token compromise, malicious
repository content escaping expected boundaries, report tampering, and release
artifact or update-channel compromise. A scanner false positive without a
security boundary impact belongs in the false-positive issue form.

## Response targets

These are service targets, not guarantees:

| Stage | Target |
| --- | --- |
| Initial acknowledgement | 2 business days |
| Reproduction and severity triage | 5 business days |
| Status update while unresolved | At least every 7 calendar days |
| Fix/disclosure plan | As soon as impact is understood |

Urgent actively exploited reports are prioritized immediately. Timing depends on
severity, affected releases, downstream coordination, and reporter availability.

## Coordinated disclosure

PatchFlow maintainers will validate the report, agree on severity and scope,
prepare a fix and regression test, and coordinate publication with the reporter.
The default disclosure target is within 90 days, but it may be shortened for
active exploitation or extended by mutual agreement for ecosystem coordination.

A public advisory should credit the reporter if requested, identify affected and
fixed versions, explain mitigations, and avoid unnecessary exploit detail. Please
allow maintainers to publish a fixed release before public disclosure.

## Safe-harbor intent

Good-faith research that avoids privacy violations, service degradation,
unauthorized persistence, data destruction, and access beyond what is necessary
to demonstrate the issue will not be treated as malicious by the project. This
statement does not authorize testing systems or data that PatchFlow does not own.
