[CmdletBinding()]
param(
    [ValidateSet("Quick", "Full", "Release")]
    [string]$Profile = "Full",
    [string]$ReportDirectory,
    [switch]$KeepBuildArtifacts,
    [ValidateRange(1, 1000)]
    [int]$ReportRetention = 50,
    [ValidateRange(1, 100)]
    [int]$ArtifactRetention = 10
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SharedPython = "C:\Dev\Projects\SceneIndex\.venv\Scripts\python.exe"
$CentralQualityPython = "C:\Dev\_shared\Toolchains\python-quality\Scripts\python.exe"
$PortableQualityPython = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "PocketSOC\quality-tools\Scripts\python.exe"
$Python = if ($env:POCKETSOC_PYTHON) {
    $env:POCKETSOC_PYTHON
} elseif (Test-Path -LiteralPath $SharedPython) {
    $SharedPython
} else {
    "python"
}
$QualityPython = if ($env:POCKETSOC_QUALITY_PYTHON) {
    $env:POCKETSOC_QUALITY_PYTHON
} elseif (Test-Path -LiteralPath $CentralQualityPython) {
    $CentralQualityPython
} elseif (Test-Path -LiteralPath $PortableQualityPython) {
    $PortableQualityPython
} else {
    $Python
}

$DefaultDataRoot = if ($env:POCKETSOC_DATA) {
    $env:POCKETSOC_DATA
} elseif (Test-Path -LiteralPath "D:\DevData\AppData") {
    "D:\DevData\AppData\PocketSOC"
} else {
    Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "PocketSOC"
}
if (-not $ReportDirectory) {
    $ReportDirectory = Join-Path $DefaultDataRoot "quality-reports"
}

$PreviousData = $env:POCKETSOC_DATA
$PreviousWireshark = $env:POCKETSOC_WIRESHARK
$PreviousLocation = Get-Location
$RunId = [guid]::NewGuid().ToString()
$StartedAt = [DateTimeOffset]::Now
$Steps = [System.Collections.Generic.List[object]]::new()
$Artifacts = [System.Collections.Generic.List[object]]::new()
$HasFailures = $false
$BuildRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("pocketsoc-quality-" + $RunId)
$AuditCache = Join-Path $DefaultDataRoot "quality-cache\pip-audit-2.10.1"

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

function Invoke-QualityStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    Write-Host "`n==> $Name" -ForegroundColor Cyan
    $Timer = [System.Diagnostics.Stopwatch]::StartNew()
    $Status = "passed"
    $Detail = $null
    try {
        & $Action
    }
    catch {
        $Status = "failed"
        $Detail = $_.Exception.Message
        $script:HasFailures = $true
        Write-Host "FAILED: $Detail" -ForegroundColor Red
    }
    finally {
        $Timer.Stop()
        $script:Steps.Add([pscustomobject]@{
            name = $Name
            status = $Status
            duration_ms = [math]::Round($Timer.Elapsed.TotalMilliseconds)
            detail = $Detail
        })
    }
}

function Get-NativeVersion {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    try {
        $Output = & $FilePath @Arguments 2>$null
        if ($LASTEXITCODE -eq 0) {
            return (($Output | Select-Object -First 1) -as [string]).Trim()
        }
    }
    catch {
        return $null
    }
    return $null
}

try {
    New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $AuditCache -Force | Out-Null
    $env:POCKETSOC_DATA = Join-Path $DefaultDataRoot "quality-test-data"
    $env:POCKETSOC_WIRESHARK = if ($PreviousWireshark) { $PreviousWireshark } else { "D:\DevData\Toolchains\Wireshark\Wireshark" }
    Set-Location -LiteralPath $ProjectRoot

    Invoke-QualityStep "Unit tests" {
        Invoke-NativeCommand $Python @("-m", "unittest", "discover", "-s", "tests", "-v")
    }
    Invoke-QualityStep "Python compilation" {
        Invoke-NativeCommand $Python @("-m", "compileall", "-q", "pocketsoc", "tests")
    }
    Invoke-QualityStep "Frontend syntax" {
        $Node = Get-Command node -ErrorAction SilentlyContinue
        if (-not $Node) {
            throw "Node.js is required for the frontend syntax check."
        }
        Invoke-NativeCommand $Node.Source @("--check", "static/app.js")
    }

    if ($Profile -in @("Full", "Release")) {
        Invoke-QualityStep "Installed dependency consistency" {
            Invoke-NativeCommand $Python @("-m", "pip", "check")
        }
        Invoke-QualityStep "Static security scan" {
            Invoke-NativeCommand $QualityPython @("-m", "bandit", "-r", "pocketsoc", "-ll", "-ii", "-q")
        }
        Invoke-QualityStep "Locked dependency vulnerability audit" {
            Invoke-NativeCommand $QualityPython @("-m", "pip_audit", "-r", "requirements.lock", "--strict", "--progress-spinner", "off", "--cache-dir", $AuditCache)
        }
        Invoke-QualityStep "Wheel build" {
            Invoke-NativeCommand $QualityPython @("-m", "build", "--wheel", "--no-isolation", "--outdir", $BuildRoot)
        }
        Invoke-QualityStep "Packaged UI verification" {
            $Wheel = Get-ChildItem -LiteralPath $BuildRoot -Filter "*.whl" | Select-Object -First 1
            if (-not $Wheel) {
                throw "Wheel build did not produce an artifact."
            }
            $VerifyCode = @'
import sys
import zipfile

wheel = sys.argv[1]
names = set(zipfile.ZipFile(wheel).namelist())
required = {"pocketsoc/cli.py", "pocketsoc/main.py"}
missing = sorted(required - names)
for asset in ("index.html", "app.js", "style.css"):
    if not any(name.endswith(f"share/pocketsoc/static/{asset}") for name in names):
        missing.append(f"share/pocketsoc/static/{asset}")
if missing:
    raise SystemExit("missing packaged files: " + ", ".join(missing))
'@
            Invoke-NativeCommand $Python @("-c", $VerifyCode, $Wheel.FullName)
            $Digest = Get-FileHash -LiteralPath $Wheel.FullName -Algorithm SHA256
            $script:Artifacts.Add([pscustomobject]@{
                kind = "wheel"
                name = $Wheel.Name
                bytes = $Wheel.Length
                sha256 = $Digest.Hash.ToLowerInvariant()
                temporary = -not $KeepBuildArtifacts
            })
        }
    }

    if ($Profile -eq "Release") {
        Invoke-QualityStep "Git whitespace validation" {
            Invoke-NativeCommand "git" @("diff", "--check")
        }
        Invoke-QualityStep "Clean tracked release state" {
            $Dirty = & git status --porcelain --untracked-files=all
            if ($LASTEXITCODE -ne 0) {
                throw "git status failed with exit code $LASTEXITCODE"
            }
            if ($Dirty) {
                throw "Release profile requires a clean working tree."
            }
        }
    }
}
finally {
    $env:POCKETSOC_DATA = $PreviousData
    $env:POCKETSOC_WIRESHARK = $PreviousWireshark
    Set-Location -LiteralPath $PreviousLocation
}

$FinishedAt = [DateTimeOffset]::Now
$Commit = (& git -C $ProjectRoot rev-parse HEAD 2>$null)
$Branch = (& git -C $ProjectRoot branch --show-current 2>$null)
$WorkingTree = (& git -C $ProjectRoot status --porcelain --untracked-files=all 2>$null)
$Report = [ordered]@{
    schema_version = 1
    run_id = $RunId
    status = if ($HasFailures) { "failed" } else { "passed" }
    profile = $Profile.ToLowerInvariant()
    started_at = $StartedAt.ToString("o")
    finished_at = $FinishedAt.ToString("o")
    duration_ms = [math]::Round(($FinishedAt - $StartedAt).TotalMilliseconds)
    repository = [ordered]@{
        path = $ProjectRoot
        branch = ($Branch -as [string]).Trim()
        commit = ($Commit -as [string]).Trim()
        dirty = [bool]$WorkingTree
    }
    environment = [ordered]@{
        os = [System.Environment]::OSVersion.VersionString
        powershell = $PSVersionTable.PSVersion.ToString()
        python = Get-NativeVersion $Python @("--version")
        quality_python = Get-NativeVersion $QualityPython @("--version")
        node = Get-NativeVersion "node" @("--version")
        quality_tools = [ordered]@{
            bandit = Get-NativeVersion $QualityPython @("-m", "bandit", "--version")
            build = Get-NativeVersion $QualityPython @("-m", "build", "--version")
            pip_audit = Get-NativeVersion $QualityPython @("-m", "pip_audit", "--version")
        }
    }
    steps = $Steps
    artifacts = $Artifacts
}

$ReportStamp = $StartedAt.ToString("yyyyMMdd-HHmmss")
$JsonPath = Join-Path $ReportDirectory ("quality-$ReportStamp-$RunId.json")
$LatestJsonPath = Join-Path $ReportDirectory "latest.json"
$LatestMarkdownPath = Join-Path $ReportDirectory "latest.md"
$Json = $Report | ConvertTo-Json -Depth 8
$Json | Set-Content -LiteralPath $JsonPath -Encoding utf8
$Json | Set-Content -LiteralPath $LatestJsonPath -Encoding utf8

$Markdown = [System.Collections.Generic.List[string]]::new()
$Markdown.Add("# PocketSOC local quality report")
$Markdown.Add("")
$Markdown.Add("- Status: **$($Report.status)**")
$Markdown.Add("- Profile: ``$($Report.profile)``")
$Markdown.Add("- Commit: ``$($Report.repository.commit)``")
$Markdown.Add("- Started: $($Report.started_at)")
$Markdown.Add("- Duration: $($Report.duration_ms) ms")
$Markdown.Add("")
$Markdown.Add("| Check | Status | Duration | Detail |")
$Markdown.Add("| --- | --- | ---: | --- |")
foreach ($Step in $Steps) {
    $SafeDetail = if ($Step.detail) { ($Step.detail -replace "\|", "\\|") } else { "" }
    $Markdown.Add("| $($Step.name) | $($Step.status) | $($Step.duration_ms) ms | $SafeDetail |")
}
$Markdown | Set-Content -LiteralPath $LatestMarkdownPath -Encoding utf8

if ($KeepBuildArtifacts -and (Test-Path -LiteralPath $BuildRoot)) {
    $ArtifactDirectory = Join-Path $ReportDirectory ("artifacts-$ReportStamp-$RunId")
    Move-Item -LiteralPath $BuildRoot -Destination $ArtifactDirectory
}
elseif (Test-Path -LiteralPath $BuildRoot) {
    Remove-Item -LiteralPath $BuildRoot -Recurse -Force
}

Get-ChildItem -LiteralPath $ReportDirectory -File -Filter "quality-*.json" |
    Sort-Object Name -Descending |
    Select-Object -Skip $ReportRetention |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
Get-ChildItem -LiteralPath $ReportDirectory -Directory -Filter "artifacts-*" |
    Sort-Object Name -Descending |
    Select-Object -Skip $ArtifactRetention |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }

Write-Host "`nQuality report: $LatestMarkdownPath"
if ($HasFailures) {
    throw "PocketSOC local quality gate failed. See $LatestMarkdownPath"
}
Write-Host "PocketSOC $Profile checks passed." -ForegroundColor Green
