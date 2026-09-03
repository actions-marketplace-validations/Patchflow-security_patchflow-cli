# Show HN draft

## Title

Show HN: PatchFlow – a local-first open-source security scanner for code and dependencies

## Post

Hi HN — we are preparing the public beta of PatchFlow CLI, an Apache-2.0 local
security scanner written in Go.

The goal is a useful result before you configure a hosted platform: install the
binary, run `patchflow scan run`, inspect the evidence and fix hint, then export
SARIF if you want it in CI. Core local scans do not require an account or upload
source. An explicit offline mode avoids OSV network calls for a deterministic
first run.

The repository includes a tiny vulnerable/clean fixture and the exact script CI
uses to verify doctor diagnostics, a PY001 finding, explanation output, and SARIF
in under five minutes:

https://github.com/Patchflow-security/patchflow-cli

We are especially looking for candid feedback on installation friction, false
positives, whether the explanation helps you decide what to do, and what is
missing from the SARIF/CI path.

Known limitations are documented in the [demo](DEMO.md) and
[launch post](TECHNICAL_LAUNCH.md). We have also put
historical benchmark claims on hold for launch copy while we reconcile internal
report inconsistencies rather than repeat numbers we cannot currently defend.

What language/framework and repository size would make a useful next test?

Evidence and help: [dated claim registry](../claims/registry.json) ·
[support](../../SUPPORT.md) · [security reporting](../../SECURITY.md) ·
[license](../../LICENSE) · [JSON/SARIF contract](../MACHINE_READABLE_OUTPUTS.md) ·
[onboarding feedback](https://github.com/Patchflow-security/patchflow-cli/issues/new/choose)
