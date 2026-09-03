# Onboarding rehearsal transcript

## Local rehearsal — 2026-07-18

Environment: macOS arm64. Published release installed: `v0.1.6`, commit
`c5e304a2f9463c98f8a56701c8b0061d40d56922`. Candidate source branch:
`agent/five-minute-onboarding`.

### Clean installation

```text
Downloading PatchFlow CLI v0.1.6 for macos/arm64...
Verifying checksum...
patchflow_0.1.6_macos_arm64.tar.gz: OK
Extracting...
Installed PatchFlow CLI v0.1.6
Installation verified.
patchflow version 0.1.6 (commit: c5e304a2f9463c98f8a56701c8b0061d40d56922)
```

Command:

```bash
INSTALL_DIR="$(mktemp -d)" ./scripts/install.sh --version v0.1.6
```

### Candidate quickstart verification

Command:

```bash
go build -o /tmp/patchflow-onboarding .
./scripts/verify-quickstart.sh /tmp/patchflow-onboarding /tmp/onboarding-evidence.json
```

Observed result:

```text
Quickstart verified in 9s; evidence: /tmp/onboarding-evidence.json
```

The vulnerable fixture produced both the regex `PY001` and AST-confirmed
`TS-PY001` views of the same unsafe call. The visible report’s leading finding
was:

```text
[MEDIUM] [AST] Use of eval() (AST-confirmed)
File: app.py:6
CWE: CWE-95
Fix: Avoid eval() entirely. Use ast.literal_eval() for literals only.
```

The clean fixture did not contain `PY001`. `patchflow explain --rule PY001`
included the rule identity and fix section. The generated file declared SARIF
`2.1.0` and contained `PY001`. `doctor --json` returned structured checks, and
every non-pass check included a remediation. No command used login or `--submit`.

### Verification commands

```text
go test ./... -timeout 10m              PASS
go vet ./...                            PASS
go build ./...                          PASS
python3 scripts/validate-claims.py      Claim registry valid: 5 claims
git diff --check                        PASS
```

This transcript is one engineering rehearsal, not a fresh-user session and not
the full platform matrix. The authoritative multi-platform evidence will be the
JSON artifacts from `.github/workflows/onboarding.yml`.

## Pinned public-release rehearsal — 2026-07-18

The launch-kit audit repeated the exact immutable inputs now recorded in
`docs/launch/manifest.json`:

- release `v0.1.6` at `c5e304a2f9463c98f8a56701c8b0061d40d56922`;
- fixture archive at `97585554172cfec430527a1a0c6d62713a3557ef`;
- no configuration file;
- offline scan with license and reachability lookups disabled.

Observed install-to-completed-demo time on macOS arm64 was 41 seconds. The
installer verified the release checksum. The vulnerable fixture produced
`PY001`, `explain` returned the rule and fix, SARIF 2.1.0 contained `PY001`, and
the clean fixture did not contain `PY001`.

The rehearsal also found a launch-blocking diagnostic defect: in a Git
repository without `origin`, `v0.1.6` prints:

```text
[OK] Remote configured: error: No such remote 'origin'
```

The Git executor was retaining combined stderr after the failed remote lookup.
The Phase 5 launch-kit branch now discards output from failed remote commands
and includes a regression test. For that reason, `v0.1.6` remains a rehearsal
release and the final recording must use a new release containing the fix.

## Launch-candidate release verification — 2026-07-18

Release `v0.1.7` was published from commit
`56d7909628b5b02756529bc4d79f2bed28b03642` after PR #23 merged to `main`.
The release workflow verified the semantic tag on canonical `origin/main`,
validated the public launch kit, ran Go tests, published GoReleaser artifacts,
signed Docker images, signed `checksums.txt`, uploaded SBOMs, and verified the
release checksums/signature before completing successfully.

Local macOS arm64 smoke test against the published release:

```text
patchflow_0.1.7_macos_arm64.tar.gz: OK
patchflow version 0.1.7 (commit: 56d7909628b5b02756529bc4d79f2bed28b03642, built: 2026-07-18T16:05:23Z)
Quickstart verified in 11s
```

The quickstart verification used the published `v0.1.7` binary and confirmed
the vulnerable fixture produced `PY001`, the clean fixture did not produce
`PY001`, `explain --rule PY001` returned rule and fix text, SARIF output was
`2.1.0`, no login was required, and no source upload was used.
