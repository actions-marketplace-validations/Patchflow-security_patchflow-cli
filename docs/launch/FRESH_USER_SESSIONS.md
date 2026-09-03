# Fresh-user onboarding protocol

This protocol is the human launch gate for CLI issue
[#5](https://github.com/Patchflow-security/patchflow-cli/issues/5). Automation
proves that commands work; only observed sessions can prove that a new developer
can install PatchFlow and understand a useful result in under five minutes.

## Pass condition

Run exactly five sessions with people whose PatchFlow exposure is `none`. A
session succeeds only when all of the following are true:

- elapsed time is less than 300 seconds;
- the participant reaches a real PatchFlow finding;
- the participant explains why the finding matters in their own words;
- the participant identifies a plausible next action;
- no PatchFlow account is required.

The launch gate passes when at least four of five sessions succeed. Every
session, including failures, must appear in the anonymized roll-up. The median
is calculated across all five elapsed times, not only successful sessions.

## Recruit without biasing the test

Recruit developers, AppSec engineers, or DevSecOps practitioners who have not
used PatchFlow. Do not send the demo transcript, screenshots, expected rule ID,
or troubleshooting guidance before the session. Ask them to bring a machine
with Git and access to GitHub Releases. Cover more than one operating-system
family when practical.

Suggested invitation:

> We are testing the first five minutes of an open-source security CLI. The
> moderated session takes about 15 minutes. We measure the product, not you; no
> name, company, repository, source code, or screen recording will be published.

## Moderator setup

1. Create a private copy of [`SESSION_NOTES_TEMPLATE.md`](SESSION_NOTES_TEMPLATE.md).
2. Confirm prior PatchFlow exposure is `none`. Otherwise do not count the session.
3. Ask the participant to share only a safe terminal or use the public fixture.
   Never request a private repository, token, secret, or customer identifier.
4. Open the public [README](../../README.md) at “Install and scan in under five
   minutes.” Do not explain the commands before timing starts.
5. Start the clock immediately before the participant reads or executes the
   installation command.

## During the session

- Remain silent unless the participant would expose sensitive data or damage
  their machine.
- Record the first point of confusion and every `doctor` warning verbatim after
  removing paths, usernames, and identifiers.
- The participant may use README links and `--help`; that is part of the product.
- Stop the clock only when the participant can point to a finding, explain the
  risk, and state a next action.
- If the participant is blocked at 300 seconds, record a failed session before
  offering help. Continue afterward to learn what remediation would unblock them.
- Ask whether they believed an account was needed or source code was uploaded.

## Publish the evidence

Raw notes stay private. Add one anonymized object to
[`onboarding-session-results.json`](onboarding-session-results.json) after each
session. Do not include names, companies, repository names, file paths, email
addresses, IP addresses, terminal recordings, or source excerpts.

Update the summary using the validator:

```bash
python3 scripts/validate-onboarding-sessions.py --write-summary
```

After the fifth session, run the launch gate:

```bash
python3 scripts/validate-onboarding-sessions.py --require-pass
```

Commit the anonymized roll-up, link that commit and any follow-up issues from
CLI issue #5, and change the `fresh-user-five-minute-success` claim to
`approved` only after the gate passes and Product reviews the evidence.

## Interpreting failures

A failed session is product evidence, not a reason to replace the participant.
Create a follow-up issue for every blocking defect. Fix material onboarding
friction, rerun automation, and conduct a new session with a different fresh
participant. Preserve the original failure in the roll-up; add the replacement
session only after deciding publicly whether the five-session cohort is being
restarted.
