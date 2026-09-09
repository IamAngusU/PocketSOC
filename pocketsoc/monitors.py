from __future__ import annotations

import json
import ipaddress
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import Database, utcnow
from .tools import ToolBroker


class MonitorScheduler:
    def __init__(self, db: Database, tools: ToolBroker, tool_lab: Any | None = None, detections: Any | None = None, firewall_service: Any | None = None, sensors: Any | None = None):
        self.db = db
        self.tools = tools
        self.tool_lab = tool_lab
        self.detections = detections
        self.firewall_service = firewall_service
        self.sensors = sensors
        self._started = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="pocketsoc-monitor-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        self._thread = None
        self._started = False

    def create(self, name: str, kind: str, interval_seconds: int, config: dict[str, Any]) -> dict[str, Any]:
        if kind == "tool_evolution" and interval_seconds < 86_400:
            raise ValueError("Tool evolution may run at most once per day")
        if kind == "sensor_ingest":
            if not self.sensors:
                raise ValueError("Sensor ingestion is unavailable")
            source_id = str(config.get("source_id") or "")
            if not source_id:
                raise ValueError("sensor_ingest requires config.source_id")
            self.sensors.get_source(source_id)
        monitor_id = f"mon_{uuid.uuid4().hex}"
        now = datetime.now(timezone.utc)
        self.db.execute(
            "INSERT INTO monitors(id,name,kind,interval_seconds,enabled,config_json,next_run_at,created_at) VALUES(?,?,?,?,1,?,?,?)",
            (monitor_id, name, kind, interval_seconds, json.dumps(config), now.isoformat(timespec="milliseconds"), now.isoformat(timespec="milliseconds")),
        )
        self.db.audit("monitor.create", "ok", target=monitor_id, detail={"kind": kind, "interval_seconds": interval_seconds})
        return self.db.one("SELECT * FROM monitors WHERE id=?", (monitor_id,)) or {"id": monitor_id}

    def set_enabled(self, monitor_id: str, enabled: bool) -> dict[str, Any] | None:
        next_run = utcnow() if enabled else None
        self.db.execute("UPDATE monitors SET enabled=?,next_run_at=? WHERE id=?", (1 if enabled else 0, next_run, monitor_id))
        self.db.audit("monitor.toggle", "ok", target=monitor_id, detail={"enabled": enabled})
        return self.db.one("SELECT * FROM monitors WHERE id=?", (monitor_id,))

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self.firewall_service:
                    self.firewall_service.expire_due()
                due = self.db.rows("SELECT * FROM monitors WHERE enabled=1 AND (next_run_at IS NULL OR next_run_at<=?) ORDER BY next_run_at LIMIT 3", (utcnow(),))
                for monitor in due:
                    self._run(monitor)
            except Exception as exc:
                self.db.audit("monitor.scheduler", "failed", detail={"error": f"{type(exc).__name__}: {exc}"})
            self._stop.wait(5)

    def _run(self, monitor: dict[str, Any]) -> None:
        kind = monitor["kind"]
        try:
            if kind in {"neighbors", "connections"}:
                result = self.tools.run(kind)
            elif kind == "system_events":
                script = "$since=(Get-Date).AddMinutes(-10); Get-WinEvent -FilterHashtable @{LogName='System','Application';StartTime=$since} -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json -Compress"
                result = self.tools._powershell("system_events", script, timeout=25).dict()
            elif kind == "tool_evolution" and self.tool_lab:
                candidate = self.db.one("SELECT id FROM generated_tools WHERE status IN ('active','proposal_passed') ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,created_at DESC LIMIT 1")
                result = self.tool_lab.evolve(candidate["id"], bool(json.loads(monitor["config_json"] or "{}").get("use_llm", True))) if candidate else {"skipped": True, "reason": "No validated analyzer exists"}
            elif kind == "detections" and self.detections:
                result = self.detections.run(int(json.loads(monitor["config_json"] or "{}").get("window_minutes", 60)))
            elif kind == "sensor_ingest" and self.sensors:
                config = json.loads(monitor["config_json"] or "{}")
                result = self.sensors.ingest(str(config["source_id"]), int(config.get("max_records", 10_000)))
            else:
                raise ValueError(f"Unsupported monitor kind: {kind}")
            if kind not in {"tool_evolution", "detections", "sensor_ingest"}:
                self._store_result(monitor, result)
            outcome = "ok" if kind in {"tool_evolution", "detections", "sensor_ingest"} or result.get("ok") else "failed"
        except Exception as exc:
            outcome = "failed"
            result = {"error": f"{type(exc).__name__}: {exc}"}
        next_run = datetime.now(timezone.utc) + timedelta(seconds=monitor["interval_seconds"])
        self.db.execute("UPDATE monitors SET last_run_at=?,next_run_at=? WHERE id=?", (utcnow(), next_run.isoformat(timespec="milliseconds"), monitor["id"]))
        self.db.audit("monitor.run", outcome, target=monitor["id"], detail={"kind": kind, "result": result if not result.get("stdout") else {"ok": result.get("ok"), "elapsed_ms": result.get("elapsed_ms")}})

    def _store_result(self, monitor: dict[str, Any], result: dict[str, Any]) -> None:
        raw = result.get("stdout", "")
        try:
            items = json.loads(raw) if raw else []
        except json.JSONDecodeError:
            items = [{"raw": raw[:4000]}]
        if isinstance(items, dict):
            items = [items]
        now = utcnow()
        with self.db.tx() as conn:
            for item in items[:250]:
                if monitor["kind"] == "neighbors" and not self._is_real_neighbor(item):
                    continue
                device_key = item.get("IPAddress") or item.get("LocalAddress") or item.get("ProviderName")
                conn.execute(
                    "INSERT INTO events(id,ts,event_type,source,device_key,severity,data_json,evidence_ref) VALUES(?,?,?,?,?,?,?,?)",
                    (f"evt_{uuid.uuid4().hex}", now, f"monitor.{monitor['kind']}", monitor["id"], device_key, "info", json.dumps(item, ensure_ascii=False, default=str), f"monitor:{monitor['id']}"),
                )
                if monitor["kind"] == "neighbors" and item.get("IPAddress"):
                    key = item["IPAddress"]
                    existing = conn.execute("SELECT 1 FROM devices WHERE device_key=?", (key,)).fetchone()
                    if existing:
                        conn.execute("UPDATE devices SET last_seen=?,metadata_json=? WHERE device_key=?", (now, json.dumps(item), key))
                    else:
                        conn.execute("INSERT INTO devices(device_key,display_name,state,first_seen,last_seen,addresses_json,metadata_json) VALUES(?,?,?,?,?,?,?)", (key, key, "unclassified", now, now, json.dumps([key]), json.dumps(item)))
                        conn.execute("INSERT INTO observations(id,ts,kind,device_key,title,detail,confidence,state,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)", (f"obs_{uuid.uuid4().hex}", now, "new_device", key, "Neues Gerät beobachtet", f"{key} erschien erstmals in der lokalen Nachbartabelle.", 1.0, "open", json.dumps([f"monitor:{monitor['id']}"])))

    @staticmethod
    def _is_real_neighbor(item: dict[str, Any]) -> bool:
        value = item.get("IPAddress")
        if not value:
            return False
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        if address.is_multicast or address.is_unspecified:
            return False
        if address.version == 4 and (value == "255.255.255.255" or value.endswith(".255")):
            return False
        link = str(item.get("LinkLayerAddress") or "").replace(":", "-").upper()
        return link not in {"00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF"}
