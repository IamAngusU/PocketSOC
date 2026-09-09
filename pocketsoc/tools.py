from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

from .config import Settings
from .db import Database


HOST_RE = re.compile(r"(?=^.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
PRIVATE_RANGES = tuple(
    ipaddress.ip_network(item)
    for item in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)
COMMON_PORTS = (22, 53, 80, 443, 445, 554, 631, 1883, 3389, 5353, 8000, 8080, 8443)


@dataclass
class CommandResult:
    tool: str
    argv: list[str]
    ok: bool
    exit_code: int
    elapsed_ms: int
    stdout: str
    stderr: str
    engine: str

    def dict(self) -> dict:
        return asdict(self)


class ToolError(ValueError):
    pass


def _private_target(value: str, allow_network: bool = False) -> str:
    try:
        parsed = ipaddress.ip_network(value, strict=False) if allow_network else ipaddress.ip_address(value)
    except ValueError as exc:
        raise ToolError("Target must be a literal private IP address" + (" or CIDR" if allow_network else "")) from exc
    if not any(parsed.subnet_of(net) if allow_network else parsed in net for net in PRIVATE_RANGES if net.version == parsed.version):
        raise ToolError("Only loopback, link-local, or RFC1918/ULA private targets are permitted")
    if allow_network and parsed.num_addresses > 256:
        raise ToolError("A scan is limited to at most one /24-equivalent (256 addresses)")
    return str(parsed)


def _hostname(value: str) -> str:
    candidate = value.rstrip(".")
    if not HOST_RE.fullmatch(candidate):
        raise ToolError("Invalid hostname")
    return candidate


class ToolBroker:
    """Runs only typed, read-only and rate-bounded diagnostic actions."""

    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db

    def _run(self, tool: str, argv: Sequence[str], timeout: int, engine: str = "native") -> CommandResult:
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                list(argv),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            limit = self.settings.max_tool_output_bytes
            result = CommandResult(
                tool=tool,
                argv=list(argv),
                ok=completed.returncode == 0,
                exit_code=completed.returncode,
                elapsed_ms=round((time.perf_counter() - started) * 1000),
                stdout=completed.stdout[:limit],
                stderr=completed.stderr[:limit],
                engine=engine,
            )
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(
                tool=tool,
                argv=list(argv),
                ok=False,
                exit_code=124,
                elapsed_ms=round((time.perf_counter() - started) * 1000),
                stdout=(exc.stdout or "")[: self.settings.max_tool_output_bytes],
                stderr="Time limit exceeded",
                engine=engine,
            )
        self.db.audit(
            "tool.run",
            "ok" if result.ok else "failed",
            target=tool,
            detail={"argv": result.argv, "elapsed_ms": result.elapsed_ms, "exit_code": result.exit_code},
        )
        return result

    def _powershell(self, tool: str, script: str, timeout: int = 15) -> CommandResult:
        executable = shutil.which("pwsh") or shutil.which("powershell") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        return self._run(tool, [executable, "-NoProfile", "-NonInteractive", "-Command", script], timeout, "powershell")

    def run(self, tool: str, target: str | None = None, profile: str = "discovery") -> dict:
        if tool == "ping":
            safe = _private_target(target or "")
            return self._run(tool, ["ping.exe", "-n", "3", "-w", "1200", safe], 8).dict()
        if tool == "trace":
            safe = _private_target(target or "")
            return self._run(tool, ["tracert.exe", "-d", "-h", "12", "-w", "800", safe], 20).dict()
        if tool == "dns":
            safe = _hostname(target or "")
            started = time.perf_counter()
            try:
                answers = sorted({item[4][0] for item in socket.getaddrinfo(safe, None)})
                result = CommandResult(tool, ["resolve", safe], True, 0, round((time.perf_counter() - started) * 1000), json.dumps(answers), "", "stdlib")
            except socket.gaierror as exc:
                result = CommandResult(tool, ["resolve", safe], False, 1, round((time.perf_counter() - started) * 1000), "", str(exc), "stdlib")
            self.db.audit("tool.run", "ok" if result.ok else "failed", target=tool, detail={"target": safe})
            return result.dict()
        if tool == "neighbors":
            script = "Get-NetNeighbor -AddressFamily IPv4 | Where-Object {$_.State -ne 'Unreachable'} | Select-Object InterfaceAlias,IPAddress,LinkLayerAddress,@{n='State';e={$_.State.ToString()}} | ConvertTo-Json -Compress"
            return self._powershell(tool, script).dict()
        if tool == "listeners":
            script = "Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort,OwningProcess,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | ConvertTo-Json -Compress"
            return self._powershell(tool, script).dict()
        if tool == "connections":
            script = "Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | ConvertTo-Json -Compress"
            return self._powershell(tool, script).dict()
        if tool == "network_scan":
            safe = _private_target(target or "", allow_network=True)
            return self._network_scan(safe, profile)
        raise ToolError(f"Unsupported tool: {tool}")

    def _network_scan(self, target: str, profile: str) -> dict:
        nmap = self.settings.nmap_path or shutil.which("nmap")
        if nmap and Path(nmap).exists():
            if profile == "common_ports":
                argv = [nmap, "-sT", "-Pn", "-n", "-T3", "--max-rate", "100", "--max-retries", "1", "--host-timeout", "60s", "-p", ",".join(map(str, COMMON_PORTS)), target]
            else:
                argv = [nmap, "-sn", "-n", "--max-retries", "1", "--host-timeout", "45s", target]
            return self._run("network_scan", argv, 75, "nmap").dict()
        if "/" in target and ipaddress.ip_network(target, strict=False).num_addresses > 32:
            raise ToolError("Nmap is unavailable; the built-in fallback is limited to 32 addresses")
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts()) or [network.network_address]
        started = time.perf_counter()
        found: list[dict] = []
        ports = COMMON_PORTS if profile == "common_ports" else (80, 443)
        for host in hosts[:32]:
            open_ports = []
            for port in ports:
                try:
                    with socket.create_connection((str(host), port), timeout=0.18):
                        open_ports.append(port)
                except OSError:
                    pass
            if open_ports:
                found.append({"ip": str(host), "open_ports": open_ports})
        result = CommandResult("network_scan", ["builtin-connect", target, profile], True, 0, round((time.perf_counter() - started) * 1000), json.dumps(found), "", "stdlib")
        self.db.audit("tool.run", "ok", target="network_scan", detail={"target": target, "profile": profile, "engine": "stdlib"})
        return result.dict()
