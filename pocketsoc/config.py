from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _default_data_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "PocketSOC"
    return Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "pocketsoc"


def _default_wireshark_dir() -> Path:
    discovered = shutil.which("tshark")
    if discovered:
        return Path(discovered).resolve().parent
    if sys.platform == "win32":
        return Path(os.getenv("ProgramFiles", r"C:\Program Files")) / "Wireshark"
    return Path("/usr/bin")

PROFILE_POLICIES = {
    "desktop-lite": {"capture": "bounded", "retention": "5 GiB", "models": "shared local", "remote_ingest": False, "description": "Default workstation profile."},
    "desktop-full": {"capture": "bounded", "retention": "operator configured", "models": "shared local", "remote_ingest": True, "description": "Workstation with optional sensor imports."},
    "sensor": {"capture": "continuous ring buffer", "retention": "sensor policy", "models": "optional", "remote_ingest": True, "description": "Dedicated capture host; not enabled by this MVP."},
    "server": {"capture": "import only", "retention": "server policy", "models": "central local", "remote_ingest": True, "description": "Multi-sensor control plane; authentication required before network exposure."},
    "air-gapped": {"capture": "bounded", "retention": "local only", "models": "local only", "remote_ingest": False, "description": "No external enrichment or downloads."},
    "developer": {"capture": "fixtures first", "retention": "ephemeral test data", "models": "optional", "remote_ingest": False, "description": "Schema, regression and adapter development."},
}


@dataclass(frozen=True)
class Settings:
    profile: str = os.getenv("POCKETSOC_PROFILE", "desktop-lite").lower()
    data_dir: Path = Path(os.getenv("POCKETSOC_DATA", str(_default_data_dir())))
    wireshark_dir: Path = Path(os.getenv("POCKETSOC_WIRESHARK", str(_default_wireshark_dir())))
    datasets_dir: Path = Path(os.getenv("POCKETSOC_DATASETS", str(_default_data_dir() / "datasets")))
    nmap_path: str | None = os.getenv("POCKETSOC_NMAP") or None
    ollama_urls: tuple[str, ...] = tuple(
        item.strip()
        for item in os.getenv(
            "POCKETSOC_OLLAMA_URLS", "http://127.0.0.1:11435,http://127.0.0.1:11434"
        ).split(",")
        if item.strip()
    )
    bind_host: str = os.getenv("POCKETSOC_HOST", "127.0.0.1")
    port: int = int(os.getenv("POCKETSOC_PORT", "8794"))
    max_tool_output_bytes: int = 1_000_000
    max_capture_seconds: int = 120
    max_capture_packets: int = 25_000
    max_capture_files: int = 250
    max_capture_storage_bytes: int = 5 * 1024**3

    def __post_init__(self) -> None:
        if self.profile not in PROFILE_POLICIES:
            raise ValueError(f"Unknown POCKETSOC_PROFILE: {self.profile}")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "pocketsoc.sqlite3"

    @property
    def captures_dir(self) -> Path:
        return self.data_dir / "captures"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"

    @property
    def tshark_path(self) -> Path:
        return self._tool("tshark")

    @property
    def dumpcap_path(self) -> Path:
        return self._tool("dumpcap")

    @property
    def wireshark_path(self) -> Path:
        return self._tool("wireshark", "Wireshark")

    def _tool(self, portable_name: str, windows_name: str | None = None) -> Path:
        candidates = [self.wireshark_dir / portable_name]
        if sys.platform == "win32":
            candidates.insert(0, self.wireshark_dir / f"{windows_name or portable_name}.exe")
        for candidate in candidates:
            if candidate.exists():
                return candidate
        discovered = shutil.which(portable_name)
        return Path(discovered) if discovered else candidates[0]


settings = Settings()
for directory in (settings.data_dir, settings.captures_dir, settings.artifacts_dir, settings.datasets_dir):
    directory.mkdir(parents=True, exist_ok=True)
