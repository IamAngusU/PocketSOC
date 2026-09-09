from __future__ import annotations

import ctypes
import shutil
import sqlite3
from pathlib import Path
from typing import Any

from .config import PROFILE_POLICIES, Settings
from .db import Database
from .inventory import capture_interfaces, ollama_status


def _check(name: str, status: str, detail: Any, action: str | None = None) -> dict[str, Any]:
    return {"name": name, "status": status, "detail": detail, "action": action}


def doctor(settings: Settings, db: Database, *, repair_safe: bool = False) -> dict[str, Any]:
    """Deterministic health report. Safe repair only recreates PocketSOC-owned directories."""
    repaired: list[str] = []
    if repair_safe:
        for path in (settings.data_dir, settings.captures_dir, settings.artifacts_dir):
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                repaired.append(str(path))
    checks: list[dict[str, Any]] = []
    for label, path in (("data", settings.data_dir), ("captures", settings.captures_dir), ("artifacts", settings.artifacts_dir)):
        checks.append(_check(f"storage.{label}", "healthy" if path.is_dir() else "action_required", str(path), "Run safe repair or create the directory" if not path.is_dir() else None))
    try:
        conn = sqlite3.connect(db.path, timeout=5)
        integrity = conn.execute("PRAGMA quick_check").fetchone()[0]
        journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        checks.append(_check("database.integrity", "healthy" if integrity == "ok" else "action_required", {"quick_check": integrity, "journal_mode": journal}, "Restore from a verified backup before further writes" if integrity != "ok" else None))
    except sqlite3.Error as exc:
        checks.append(_check("database.integrity", "unavailable", str(exc), "Check storage permissions and free space"))
    wireshark_ready = all(path.exists() for path in (settings.tshark_path, settings.dumpcap_path, settings.wireshark_path))
    checks.append(_check("wireshark.toolchain", "healthy" if wireshark_ready else "unavailable", str(settings.wireshark_dir), "Install/point to a verified Wireshark toolchain" if not wireshark_ready else None))
    interfaces = capture_interfaces(settings) if wireshark_ready else []
    checks.append(_check("capture.interfaces", "healthy" if interfaces else "degraded", {"count": len(interfaces)}, "Check Npcap service/permissions" if not interfaces else None))
    model = ollama_status(settings)
    model_required = settings.profile not in {"sensor", "developer"}
    checks.append(_check("models.local", "healthy" if model["available"] else ("degraded" if not model_required else "action_required"), {"available": model["available"], "models": model["models"]}, "Start the central Ollama service" if model_required and not model["available"] else None))
    active_filters = db.one("SELECT COUNT(*) AS n FROM filters WHERE status='active'")["n"]
    rejected_filters = db.one("SELECT COUNT(*) AS n FROM filters WHERE status='rejected'")["n"]
    checks.append(_check("filters.validated", "healthy" if active_filters else "degraded", {"active": active_filters, "rejected": rejected_filters}, "Create or activate a Wireshark-validated filter" if not active_filters else None))
    ready_firewalls = db.one("SELECT COUNT(*) AS n FROM firewall_bindings WHERE status='ready'")["n"]
    checks.append(_check("firewall.bindings", "healthy" if ready_firewalls else "degraded", {"ready": ready_firewalls, "policy": "review_hash_required", "automatic_apply": False}, "Probe/configure a firewall adapter" if not ready_firewalls else None))
    try:
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        elevated = False
    checks.append(_check("firewall.enforcement", "healthy" if elevated else "degraded", {"elevated_broker": elevated, "review_required": True, "rollback_required": True}, None if elevated else "Start PocketSOC through a separately authorized elevated broker only when reviewed firewall enforcement is wanted"))
    free = shutil.disk_usage(settings.data_dir).free if settings.data_dir.exists() else 0
    storage_status = "healthy" if free >= 10 * 1024**3 else ("degraded" if free >= 2 * 1024**3 else "action_required")
    checks.append(_check("storage.free_space", storage_status, {"free_bytes": free, "capture_budget_bytes": settings.max_capture_storage_bytes}, "Free space or move the data directory before long captures" if storage_status != "healthy" else None))
    rank = {"healthy": 0, "degraded": 1, "action_required": 2, "unsafe": 3, "unavailable": 4}
    overall = max((item["status"] for item in checks), key=lambda value: rank[value])
    return {"overall": overall, "profile": {"id": settings.profile, **PROFILE_POLICIES[settings.profile]}, "checks": checks, "safe_repairs_applied": repaired, "destructive_repairs": False}
