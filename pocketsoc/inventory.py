from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx

from .config import PROFILE_POLICIES, Settings


PREFERRED_OLLAMA_MODELS = ("qwen2.5:pocketsoc-845dbda0", "qwen3:8b", "qwen2.5:latest")


def _run_json(script: str) -> Any:
    executable = shutil.which("pwsh") or shutil.which("powershell") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    try:
        out = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if out.returncode != 0 or not out.stdout.strip():
            return []
        return json.loads(out.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []


def _version(path: Path, arg: str = "--version") -> str | None:
    if not path.exists():
        return None
    try:
        result = subprocess.run([str(path), arg], capture_output=True, text=True, timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return (result.stdout or result.stderr).splitlines()[0].strip()
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def ollama_status(settings: Settings) -> dict[str, Any]:
    for base in settings.ollama_urls:
        try:
            response = httpx.get(f"{base}/api/tags", timeout=1.5)
            response.raise_for_status()
            items = response.json().get("models", [])
            models = [item.get("name") for item in items]
            manifests = [{"name": item.get("name"), "digest": item.get("digest"), "size_bytes": item.get("size"), "modified_at": item.get("modified_at"), "details": item.get("details", {}), "source": "ollama-local", "license": "not reported by local registry"} for item in items]
            return {"available": True, "url": base, "models": models, "manifests": manifests}
        except Exception:
            continue
    return {"available": False, "url": None, "models": [], "manifests": []}


def select_ollama_model(status: dict[str, Any]) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    if not status.get("available") or not status.get("models"):
        return None, None
    model = next((name for name in PREFERRED_OLLAMA_MODELS if name in status["models"]), status["models"][0])
    manifest = next((item for item in status.get("manifests", []) if item.get("name") == model), {})
    identity = {"name": model, "digest": manifest.get("digest"), "size_bytes": manifest.get("size_bytes"), "source": manifest.get("source", "ollama-local")}
    return model, identity


def capture_interfaces(settings: Settings) -> list[dict[str, Any]]:
    if not settings.dumpcap_path.exists():
        return []
    try:
        result = subprocess.run([str(settings.dumpcap_path), "-D"], capture_output=True, text=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired):
        return []
    interfaces = []
    for line in result.stdout.splitlines():
        if ". " not in line:
            continue
        number, label = line.split(". ", 1)
        if number.isdigit():
            interfaces.append({"id": int(number), "label": label})
    return interfaces


def system_inventory(settings: Settings) -> dict[str, Any]:
    disks = _run_json("Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter,FileSystemLabel,@{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}},@{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}} | ConvertTo-Json -Compress")
    adapters = _run_json("Get-NetIPConfiguration | Where-Object {$_.IPv4Address} | Select-Object InterfaceAlias,@{n='IPv4';e={$_.IPv4Address.IPAddress -join ','}},@{n='Prefix';e={$_.IPv4Address.PrefixLength -join ','}},@{n='Gateway';e={$_.IPv4DefaultGateway.NextHop -join ','}},@{n='DNS';e={$_.DNSServer.ServerAddresses -join ','}} | ConvertTo-Json -Compress")
    gpu = _run_json("Get-CimInstance Win32_VideoController | Select-Object Name,@{n='VRAMGB';e={[math]::Round($_.AdapterRAM/1GB,1)}},DriverVersion | ConvertTo-Json -Compress")
    memory = _run_json("Get-CimInstance Win32_ComputerSystem | Select-Object @{n='RAMGB';e={[math]::Round($_.TotalPhysicalMemory/1GB,1)}},NumberOfLogicalProcessors | ConvertTo-Json -Compress")
    nmap_path = settings.nmap_path or shutil.which("nmap")
    burp = Path(os.getenv("LOCALAPPDATA", "")) / "Programs" / "BurpSuite" / "BurpSuite.exe"
    return {
        "profile": {"id": settings.profile, **PROFILE_POLICIES[settings.profile]},
        "os": {"system": platform.system(), "release": platform.release(), "version": platform.version(), "machine": platform.machine()},
        "memory": memory,
        "gpu": gpu,
        "disks": disks,
        "adapters": adapters,
        "capabilities": {
            "wireshark": {"available": settings.wireshark_path.exists(), "path": str(settings.wireshark_path), "version": _version(settings.tshark_path)},
            "dumpcap": {"available": settings.dumpcap_path.exists(), "path": str(settings.dumpcap_path)},
            "nmap": {"available": bool(nmap_path), "path": nmap_path},
            "burp": {"available": burp.exists(), "path": str(burp) if burp.exists() else None, "integration": "planned"},
            "zeek": {"available": bool(shutil.which("zeek")), "integration": "adapter-ready"},
            "suricata": {"available": bool(shutil.which("suricata")), "integration": "adapter-ready"},
            "sysmon": {"available": bool(_run_json("Get-Service Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Select-Object Name,Status | ConvertTo-Json -Compress")), "integration": "read-only-adapter-ready"},
        },
        "capture_interfaces": capture_interfaces(settings),
        "ollama": ollama_status(settings),
    }
