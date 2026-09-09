$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = if ($env:POCKETSOC_PYTHON) { $env:POCKETSOC_PYTHON } else { "C:\Dev\Projects\SceneIndex\.venv\Scripts\python.exe" }
$PreviousData = $env:POCKETSOC_DATA
$PreviousWireshark = $env:POCKETSOC_WIRESHARK
$PreviousLocation = Get-Location
try {
    $env:POCKETSOC_DATA = "D:\DevData\AppData\PocketSOC-Test"
    $env:POCKETSOC_WIRESHARK = "D:\DevData\Toolchains\Wireshark\Wireshark"
    Set-Location -LiteralPath $ProjectRoot
    & $Python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "Unit tests failed with exit code $LASTEXITCODE" }
    & $Python -m compileall -q pocketsoc
    if ($LASTEXITCODE -ne 0) { throw "Compile check failed with exit code $LASTEXITCODE" }
    Write-Host "PocketSOC checks passed."
}
finally {
    $env:POCKETSOC_DATA = $PreviousData
    $env:POCKETSOC_WIRESHARK = $PreviousWireshark
    Set-Location -LiteralPath $PreviousLocation
}
