# Two-minute public demo

## Promise

Install PatchFlow, scan one intentionally vulnerable file, understand the
finding, compare it with a clean equivalent, and generate SARIF. The scan is
local, requires no account, and uses no source upload.

## Pinned inputs

- Release: `v0.1.7`
- Release commit: `56d7909628b5b02756529bc4d79f2bed28b03642`
- Fixture commit: `97585554172cfec430527a1a0c6d62713a3557ef`
- Fixture paths: `examples/quickstart/vulnerable/app.py` and
  `examples/quickstart/clean/app.py`
- Rule: `PY001` (`eval()` with potential user input)
- Configuration: none
- Mode: offline, embedded scanners available with no extra install, no license
  or reachability lookup; supported external scanners may supplement if present

The release binary and public fixture intentionally have separate immutable
commits: `v0.1.7` is the published launch-candidate binary, while the fixture
commit pins the public demo inputs. The authoritative machine-readable mapping
is [`manifest.json`](manifest.json).

## Commands

Install on macOS or Linux:

```bash
PATCHFLOW_RELEASE=v0.1.7
PATCHFLOW_RELEASE_COMMIT=56d7909628b5b02756529bc4d79f2bed28b03642
PATCHFLOW_FIXTURE_COMMIT=97585554172cfec430527a1a0c6d62713a3557ef

curl -fsSL \
  "https://raw.githubusercontent.com/Patchflow-security/patchflow-cli/${PATCHFLOW_RELEASE_COMMIT}/scripts/install.sh" |
  bash -s -- --version "${PATCHFLOW_RELEASE}"
export PATH="$HOME/.local/bin:$PATH"
patchflow version --json
```

Prepare isolated copies of the public fixtures. Isolation prevents the demo scan
from treating the CLI source repository as its Git root:

```bash
DEMO_ROOT="$(mktemp -d)"
curl -fsSL \
  "https://github.com/Patchflow-security/patchflow-cli/archive/${PATCHFLOW_FIXTURE_COMMIT}.tar.gz" |
  tar -xz -C "$DEMO_ROOT"
mv "$DEMO_ROOT/patchflow-cli-${PATCHFLOW_FIXTURE_COMMIT}" "$DEMO_ROOT/source"
cp -R "$DEMO_ROOT/source/examples/quickstart/vulnerable" "$DEMO_ROOT/vulnerable"
cp -R "$DEMO_ROOT/source/examples/quickstart/clean" "$DEMO_ROOT/clean"
git -C "$DEMO_ROOT/vulnerable" init -q
git -C "$DEMO_ROOT/clean" init -q
git -C "$DEMO_ROOT/vulnerable" -c user.name=PatchFlow -c user.email=demo@patchflow.dev add .
git -C "$DEMO_ROOT/vulnerable" -c user.name=PatchFlow -c user.email=demo@patchflow.dev commit -qm fixture
git -C "$DEMO_ROOT/clean" -c user.name=PatchFlow -c user.email=demo@patchflow.dev add .
git -C "$DEMO_ROOT/clean" -c user.name=PatchFlow -c user.email=demo@patchflow.dev commit -qm fixture
```

Scan, explain, and export:

```bash
cd "$DEMO_ROOT/vulnerable"
patchflow doctor
patchflow scan run --offline --no-licenses --no-reachability
patchflow explain --rule PY001
patchflow scan run --offline --no-licenses --no-reachability \
  --format sarif --output patchflow-results.sarif --quiet

cd "$DEMO_ROOT/clean"
patchflow scan run --offline --no-licenses --no-reachability
```

Expected proof points:

- the vulnerable scan includes `PY001` and a fix hint;
- `explain` describes why `eval()` is unsafe and provides suppression syntax;
- `patchflow-results.sarif` is SARIF 2.1.0 and contains `PY001`;
- the clean scan does not contain `PY001`;
- none of the commands uses `login`, `--submit`, or a source-upload endpoint.

## Automated rehearsal

From a CLI checkout:

```bash
./scripts/verify-quickstart.sh "$(command -v patchflow)"
```

The script creates isolated fixtures, enforces the five-minute ceiling, and
writes `onboarding-evidence.json`. CI uploads one evidence file per supported
platform. The automated timing is not a replacement for the five human sessions.

## Final publication gate

The final recording URL, duration, verified commit, timestamp, and four owner
sign-offs belong in [`manifest.json`](manifest.json). Within 24 hours of
publication, run:

```bash
python3 scripts/validate-launch-kit.py --require-ready --check-remote
```

The command fails while the recording or sign-offs are missing, when evidence is
older than 24 hours, when a local link is broken, or when a pinned remote URL is
unavailable.

## Failure handling

- Installer failure: retain the checksum or HTTP error and stop the demo.
- `doctor` warning: follow the printed `Next steps`; every non-pass structured
  check must include a remediation.
- Missing `PY001`: stop launch and treat the onboarding workflow as failed.
- Network outage: the scan still runs because the demo is offline; installation
  still requires GitHub release access.

Support and security reports: use the repository issue forms. Do not place a
real secret or undisclosed vulnerability in a public issue.
