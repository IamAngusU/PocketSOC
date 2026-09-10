[CmdletBinding()]
param(
    [string]$Destination,
    [string]$Python
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SharedPython = "C:\Dev\Projects\SceneIndex\.venv\Scripts\python.exe"
if (-not $Python) {
    $Python = if ($env:POCKETSOC_PYTHON) {
        $env:POCKETSOC_PYTHON
    } elseif (Test-Path -LiteralPath $SharedPython) {
        $SharedPython
    } else {
        "python"
    }
}
if (-not $Destination) {
    $Destination = if (Test-Path -LiteralPath "C:\Dev\_shared\Toolchains") {
        "C:\Dev\_shared\Toolchains\python-quality"
    } else {
        Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "PocketSOC\quality-tools"
    }
}

$QualityPython = Join-Path $Destination "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $QualityPython)) {
    if ((Test-Path -LiteralPath $Destination) -and (Get-ChildItem -LiteralPath $Destination -Force | Select-Object -First 1)) {
        throw "Destination exists but is not a Python virtual environment: $Destination"
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
    & $Python -m venv $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create quality-tool environment (exit $LASTEXITCODE)."
    }
}

& $QualityPython -m pip install --requirement (Join-Path $ProjectRoot "quality-tools.lock")
if ($LASTEXITCODE -ne 0) {
    throw "Could not install pinned quality tools (exit $LASTEXITCODE)."
}
& $QualityPython -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "Quality-tool environment is inconsistent (exit $LASTEXITCODE)."
}

Write-Host "Quality tools are ready: $QualityPython" -ForegroundColor Green
Write-Host "PocketSOC check.ps1 will discover this environment automatically."
