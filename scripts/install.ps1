param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\PatchFlow\bin",
    [switch]$NoVerify
)

$ErrorActionPreference = "Stop"
$repository = "Patchflow-security/patchflow-cli"

if ($Version -eq "latest") {
    Write-Host "Fetching latest release version..."
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repository/releases/latest" -Headers @{ "User-Agent" = "patchflow-installer" }
    $Version = $release.tag_name
}
if (-not $Version) { throw "Unable to resolve a PatchFlow release version." }
if (-not $Version.StartsWith("v")) { $Version = "v$Version" }

$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
switch ($architecture) {
    "x64" { $releaseArch = "x86_64" }
    "arm64" { $releaseArch = "arm64" }
    default { throw "Unsupported Windows architecture: $architecture. PatchFlow supports x86_64 and arm64." }
}

$versionNumber = $Version.TrimStart("v")
$archive = "patchflow_${versionNumber}_windows_${releaseArch}.zip"
$releaseBase = "https://github.com/$repository/releases/download/$Version"
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("patchflow-install-" + [guid]::NewGuid())

try {
    New-Item -ItemType Directory -Path $work | Out-Null
    Write-Host "Downloading PatchFlow CLI $Version for windows/$releaseArch..."
    Invoke-WebRequest -Uri "$releaseBase/$archive" -OutFile "$work\$archive"
    Invoke-WebRequest -Uri "$releaseBase/checksums.txt" -OutFile "$work\checksums.txt"

    $checksumLine = Get-Content "$work\checksums.txt" | Where-Object { $_ -match "\s+$([regex]::Escape($archive))$" } | Select-Object -First 1
    if (-not $checksumLine) { throw "Checksum entry for $archive was not found." }
    $expected = ($checksumLine -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash "$work\$archive" -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "Checksum verification failed for $archive." }
    Write-Host "Checksum verified."

    Expand-Archive -Path "$work\$archive" -DestinationPath "$work\expanded"
    $binary = Join-Path "$work\expanded" "patchflow.exe"
    if (-not (Test-Path $binary)) { throw "Archive did not contain patchflow.exe." }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item $binary "$InstallDir\patchflow.exe" -Force

    Write-Host "Installed PatchFlow CLI $Version to $InstallDir\patchflow.exe"
    if (-not $NoVerify) {
        & "$InstallDir\patchflow.exe" version
        if ($LASTEXITCODE -ne 0) { throw "Installation verification failed." }
    }

    $pathEntries = @($env:Path -split ";")
    if ($pathEntries -notcontains $InstallDir) {
        Write-Host ""
        Write-Host "$InstallDir is not in PATH. Add it for future terminals with:"
        Write-Host ('[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";{0}", "User")' -f $InstallDir)
        Write-Host "For this terminal, run: `$env:Path = `"$InstallDir;`$env:Path`""
    }
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
