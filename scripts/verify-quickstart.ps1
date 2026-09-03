param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [string]$Evidence = "$PSScriptRoot\..\onboarding-evidence.json"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..").Path
$binaryPath = (Resolve-Path $Binary).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("patchflow-onboarding-" + [guid]::NewGuid())
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$externalStart = $env:PATCHFLOW_ONBOARDING_STARTED_AT

try {
    New-Item -ItemType Directory -Path $work | Out-Null
    Copy-Item "$root\examples\quickstart\vulnerable" "$work\vulnerable" -Recurse
    Copy-Item "$root\examples\quickstart\clean" "$work\clean" -Recurse
    git -C "$work\vulnerable" init -q
    git -C "$work\clean" init -q
    git -C "$work\vulnerable" -c user.name=PatchFlow -c user.email=demo@patchflow.dev add .
    git -C "$work\vulnerable" -c user.name=PatchFlow -c user.email=demo@patchflow.dev commit -qm fixture
    git -C "$work\clean" -c user.name=PatchFlow -c user.email=demo@patchflow.dev add .
    git -C "$work\clean" -c user.name=PatchFlow -c user.email=demo@patchflow.dev commit -qm fixture

    Push-Location "$work\vulnerable"
    & $binaryPath doctor --json | Out-File doctor.json -Encoding utf8
    $doctor = Get-Content doctor.json -Raw | ConvertFrom-Json
    if (-not $doctor.checks) { throw "doctor returned no structured checks" }
    $missing = $doctor.checks | Where-Object { $_.status -ne "pass" -and -not $_.remediation }
    if ($missing) { throw "doctor returned a non-pass check without remediation" }
    & $binaryPath scan run --offline --no-licenses --no-reachability --json --quiet | Out-File scan.json -Encoding utf8
    if (-not (Select-String -Path scan.json -Pattern "PY001" -Quiet)) { throw "vulnerable fixture did not produce PY001" }
    & $binaryPath explain --rule PY001 --no-color | Out-File explain.txt -Encoding utf8
    if (-not (Select-String -Path explain.txt -Pattern "Rule: PY001" -Quiet)) { throw "PY001 explanation was not produced" }
    & $binaryPath scan run --offline --no-licenses --no-reachability --format sarif --output results.sarif --quiet | Out-Null
    if (-not (Select-String -Path results.sarif -Pattern '"2.1.0"' -Quiet)) { throw "SARIF 2.1.0 output was not produced" }
    Pop-Location

    Push-Location "$work\clean"
    & $binaryPath scan run --offline --no-licenses --no-reachability --json --quiet | Out-File scan.json -Encoding utf8
    if (Select-String -Path scan.json -Pattern "PY001" -Quiet) { throw "clean fixture unexpectedly produced PY001" }
    Pop-Location

    $stopwatch.Stop()
    if ($externalStart) {
        $elapsedSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [long]$externalStart
        $timingScope = "install_to_completed_quickstart"
    }
    else {
        $elapsedSeconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
        $timingScope = "doctor_to_completed_quickstart"
    }
    if ($elapsedSeconds -ge 300) { throw "quickstart exceeded the five-minute target" }
    $version = (& $binaryPath version | Select-Object -First 1)
    $result = [ordered]@{
        schema_version = "1.0"
        os = "Windows"
        architecture = $env:PROCESSOR_ARCHITECTURE
        elapsed_seconds = $elapsedSeconds
        target_seconds = 300
        timing_scope = $timingScope
        version = $version
        vulnerable_fixture = @{ expected_rule = "PY001"; result = "pass" }
        clean_fixture = @{ forbidden_rule = "PY001"; result = "pass" }
        explain = "pass"
        sarif = "pass"
        login_required = $false
        source_upload = $false
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content $Evidence -Encoding utf8
    Write-Host "Quickstart verified in ${elapsedSeconds}s; evidence: $Evidence"
}
finally {
    while ((Get-Location).Path.StartsWith($work)) { Pop-Location }
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
