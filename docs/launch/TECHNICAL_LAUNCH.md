# Technical launch post

## PatchFlow CLI public beta: local security feedback before code leaves your machine

Security scanners are most useful when developers can run them before a pull
request and understand the result without first configuring a platform. Today
we are preparing PatchFlow CLI for a public beta around that workflow.

PatchFlow scans source code, dependency manifests, and secrets locally. The core
local path does not require an account, and source upload only occurs on an
explicit submission path. For a deterministic first run, `--offline` disables
OSV network calls as well.

```bash
curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
patchflow doctor
patchflow scan run --offline --no-licenses --no-reachability
```

The public quickstart includes a deliberately vulnerable Python file and a safe
counterpart. It demonstrates one `eval()` finding, explains the rule and fix,
then exports SARIF for code-scanning systems. The exact fixture, commands, and
automated rehearsal live in [the demo runbook](DEMO.md).

What this beta is for:

- fast local feedback with embedded scanners;
- findings that link rule identity, evidence, severity, and remediation;
- machine-readable JSON and SARIF for CI integration;
- reproducible feedback on installation and result usefulness.

Current limitations:

- offline mode does not query OSV for fresh dependency advisories;
- external scanners remain optional supplements and can change runtime/noise;
- framework packs have different maturity levels;
- automated timing proves reproducibility, not human usability;
- historical benchmark numbers are on hold for launch copy until inconsistencies
  are rerun and reviewed in the [claim registry](../claims/registry.json).

We want feedback from AppSec, DevSecOps, and engineering teams on the first five
minutes: install, first useful result, explanation quality, and CI export. Open a
GitHub issue for bugs or onboarding friction. Use private security reporting for
undisclosed vulnerabilities or sensitive data.

Repository: https://github.com/Patchflow-security/patchflow-cli

Evidence and help: [dated claim registry](../claims/registry.json) ·
[support](../../SUPPORT.md) · [security reporting](../../SECURITY.md) ·
[license](../../LICENSE) · [JSON/SARIF contract](../MACHINE_READABLE_OUTPUTS.md) ·
[onboarding feedback](https://github.com/Patchflow-security/patchflow-cli/issues/new/choose)
