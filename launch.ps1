param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8794,
    [ValidateSet("desktop-lite", "desktop-full", "sensor", "server", "air-gapped", "developer")]
    [string]$Profile = "desktop-lite"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SharedPython = "C:\Dev\Projects\SceneIndex\.venv\Scripts\python.exe"
$Python = if ($env:POCKETSOC_PYTHON) { $env:POCKETSOC_PYTHON } elseif (Test-Path -LiteralPath $SharedPython) { $SharedPython } else { "python" }

$env:POCKETSOC_DATA = if ($env:POCKETSOC_DATA) { $env:POCKETSOC_DATA } else { "D:\DevData\AppData\PocketSOC" }
$env:POCKETSOC_WIRESHARK = if ($env:POCKETSOC_WIRESHARK) { $env:POCKETSOC_WIRESHARK } else { "D:\DevData\Toolchains\Wireshark\Wireshark" }
$env:POCKETSOC_HOST = $HostAddress
$env:POCKETSOC_PROFILE = $Profile

if ($HostAddress -notin @("127.0.0.1", "localhost", "::1")) {
    throw "Network exposure is intentionally disabled until authentication/TLS is configured. Use 127.0.0.1."
}

function Get-PocketSOCHealth([int]$CandidatePort) {
    try {
        $Health = Invoke-RestMethod -Uri "http://127.0.0.1:$CandidatePort/api/health" -TimeoutSec 2
        if ($Health.service -eq "PocketSOC" -and $Health.ok) { return $Health }
    }
    catch { return $null }
    return $null
}

function Test-PortOpen([int]$CandidatePort) {
    $Client = [System.Net.Sockets.TcpClient]::new()
    try {
        $Task = $Client.ConnectAsync("127.0.0.1", $CandidatePort)
        return $Task.Wait(300) -and $Client.Connected
    }
    catch { return $false }
    finally { $Client.Dispose() }
}

$Existing = Get-PocketSOCHealth $Port
if ($Existing) {
    Write-Host "PocketSOC $($Existing.version) is already ready at http://127.0.0.1:$Port/"
    exit 0
}

$SelectedPort = $null
foreach ($CandidatePort in $Port..($Port + 20)) {
    if (-not (Test-PortOpen $CandidatePort)) { $SelectedPort = $CandidatePort; break }
    $Existing = Get-PocketSOCHealth $CandidatePort
    if ($Existing) {
        Write-Host "PocketSOC $($Existing.version) is already ready at http://127.0.0.1:$CandidatePort/"
        exit 0
    }
}
if (-not $SelectedPort) { throw "No free PocketSOC port found in range $Port-$($Port + 20)." }
$env:POCKETSOC_PORT = [string]$SelectedPort
$PidFile = Join-Path $env:POCKETSOC_DATA "pocketsoc-launcher.json"
$PidDirectory = Split-Path -Parent $PidFile
New-Item -ItemType Directory -Path $PidDirectory -Force | Out-Null
@{ pid = $PID; port = $SelectedPort; profile = $Profile; started_at = (Get-Date).ToUniversalTime().ToString("o") } | ConvertTo-Json -Compress | Set-Content -LiteralPath $PidFile -Encoding UTF8

Set-Location -LiteralPath $ProjectRoot
Write-Host "Starting PocketSOC profile '$Profile' at http://127.0.0.1:$SelectedPort/"
try {
    & $Python -m uvicorn pocketsoc.main:app --host $HostAddress --port $SelectedPort
}
finally {
    if (Test-Path -LiteralPath $PidFile) {
        try {
            $State = Get-Content -LiteralPath $PidFile -Raw | ConvertFrom-Json
            if ($State.pid -eq $PID) { Remove-Item -LiteralPath $PidFile -Force }
        }
        catch { }
    }
}
