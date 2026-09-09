$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SharedPython = "C:\Dev\Projects\SceneIndex\.venv\Scripts\python.exe"
$Python = if ($env:POCKETSOC_PYTHON) { $env:POCKETSOC_PYTHON } elseif (Test-Path -LiteralPath $SharedPython) { $SharedPython } else { "python" }
$env:POCKETSOC_DATA = if ($env:POCKETSOC_DATA) { $env:POCKETSOC_DATA } else { "D:\DevData\AppData\PocketSOC" }
$env:POCKETSOC_WIRESHARK = if ($env:POCKETSOC_WIRESHARK) { $env:POCKETSOC_WIRESHARK } else { "D:\DevData\Toolchains\Wireshark\Wireshark" }
Set-Location -LiteralPath $ProjectRoot
& $Python -c "import json; from pocketsoc.config import settings; from pocketsoc.db import Database; from pocketsoc.doctor import doctor; print(json.dumps(doctor(settings, Database(settings.db_path)), ensure_ascii=False, indent=2))"
