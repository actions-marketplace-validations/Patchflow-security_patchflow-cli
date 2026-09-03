#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${1:-patchflow}
EVIDENCE=${2:-"${ROOT}/onboarding-evidence.json"}

case "$BIN" in
    /*) ;;
    *) BIN=$(CDPATH= cd -- "$(dirname -- "$BIN")" && pwd)/$(basename -- "$BIN") ;;
esac

if [ ! -x "$BIN" ]; then
    printf 'PatchFlow binary is not executable: %s\n' "$BIN" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp -R "${ROOT}/examples/quickstart/vulnerable" "${WORK}/vulnerable"
cp -R "${ROOT}/examples/quickstart/clean" "${WORK}/clean"
git -C "${WORK}/vulnerable" init -q
git -C "${WORK}/clean" init -q
git -C "${WORK}/vulnerable" -c user.name=PatchFlow -c user.email=demo@patchflow.dev add .
git -C "${WORK}/vulnerable" -c user.name=PatchFlow -c user.email=demo@patchflow.dev commit -qm fixture
git -C "${WORK}/clean" -c user.name=PatchFlow -c user.email=demo@patchflow.dev add .
git -C "${WORK}/clean" -c user.name=PatchFlow -c user.email=demo@patchflow.dev commit -qm fixture

if [ -n "${PATCHFLOW_ONBOARDING_STARTED_AT:-}" ]; then
    START="$PATCHFLOW_ONBOARDING_STARTED_AT"
    TIMING_SCOPE="install_to_completed_quickstart"
else
    START=$(date +%s)
    TIMING_SCOPE="doctor_to_completed_quickstart"
fi

(cd "${WORK}/vulnerable" && "$BIN" doctor --json > doctor.json)
python3 - "${WORK}/vulnerable/doctor.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
checks = report.get("checks", [])
assert checks, "doctor returned no structured checks"
missing = [c["name"] for c in checks if c["status"] != "pass" and not c.get("remediation")]
assert not missing, f"doctor checks without remediation: {missing}"
PY

(cd "${WORK}/vulnerable" && "$BIN" scan run --offline --no-licenses --no-reachability --json --quiet > scan.json)
grep -q 'PY001' "${WORK}/vulnerable/scan.json"

(cd "${WORK}/clean" && "$BIN" scan run --offline --no-licenses --no-reachability --json --quiet > scan.json)
if grep -q 'PY001' "${WORK}/clean/scan.json"; then
    printf 'Clean fixture unexpectedly produced PY001\n' >&2
    exit 1
fi

(cd "${WORK}/vulnerable" && "$BIN" explain --rule PY001 --no-color > explain.txt)
grep -q 'Rule: PY001' "${WORK}/vulnerable/explain.txt"
grep -q 'Fix' "${WORK}/vulnerable/explain.txt"

(cd "${WORK}/vulnerable" && "$BIN" scan run --offline --no-licenses --no-reachability --format sarif --output results.sarif --quiet > /dev/null)
grep -q '"2.1.0"' "${WORK}/vulnerable/results.sarif"
grep -q 'PY001' "${WORK}/vulnerable/results.sarif"

END=$(date +%s)
ELAPSED=$((END - START))
if [ "$ELAPSED" -ge 300 ]; then
    printf 'Quickstart took %ss; target is under 300s\n' "$ELAPSED" >&2
    exit 1
fi

OS=$(uname -s)
ARCH=$(uname -m)
VERSION=$($BIN version 2>&1 | head -n 1 | sed 's/"/\\"/g')
python3 - "$EVIDENCE" "$OS" "$ARCH" "$ELAPSED" "$VERSION" "$TIMING_SCOPE" <<'PY'
import json, sys
path, os_name, arch, elapsed, version, timing_scope = sys.argv[1:]
with open(path, "w", encoding="utf-8") as handle:
    json.dump({
        "schema_version": "1.0",
        "os": os_name,
        "architecture": arch,
        "elapsed_seconds": int(elapsed),
        "target_seconds": 300,
        "timing_scope": timing_scope,
        "version": version,
        "vulnerable_fixture": {"expected_rule": "PY001", "result": "pass"},
        "clean_fixture": {"forbidden_rule": "PY001", "result": "pass"},
        "explain": "pass",
        "sarif": "pass",
        "login_required": False,
        "source_upload": False,
    }, handle, indent=2)
    handle.write("\n")
PY

printf 'Quickstart verified in %ss; evidence: %s\n' "$ELAPSED" "$EVIDENCE"
