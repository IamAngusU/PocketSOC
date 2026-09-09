from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .db import Database, utcnow


MAX_LINE_BYTES = 1_048_576
MAX_RUN_BYTES = 64 * 1024 * 1024


class SensorError(ValueError):
    pass


class SensorAdapter(Protocol):
    kind: str
    label: str

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]: ...


def _text(value: Any, limit: int = 1000) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    return rendered[:limit] or None


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _timestamp(value: Any) -> str:
    if not value:
        return utcnow()
    rendered = str(value)
    try:
        parsed = datetime.fromisoformat(rendered.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")
    except ValueError:
        return rendered[:100]


def _severity(value: Any) -> str:
    numeric = _integer(value)
    if numeric == 1:
        return "high"
    if numeric == 2:
        return "medium"
    if numeric == 3:
        return "low"
    return "info"


class SuricataEveAdapter:
    kind = "suricata_eve"
    label = "Suricata EVE JSON"

    _detail_fields: dict[str, tuple[str, ...]] = {
        "alert": ("signature_id", "rev", "gid", "signature", "category", "severity", "action"),
        "dns": ("type", "id", "rrname", "rrtype", "rcode", "ttl"),
        "http": ("hostname", "url", "http_user_agent", "http_content_type", "http_method", "protocol", "status"),
        "tls": ("sni", "version", "subject", "issuerdn", "fingerprint", "ja3", "ja3s"),
        "ssh": ("client", "server", "proto_version", "software_version"),
        "fileinfo": ("filename", "magic", "state", "stored", "size", "md5", "sha1", "sha256"),
        "flow": ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "start", "end", "age", "state", "reason"),
        "anomaly": ("type", "event", "layer", "code"),
    }

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        event_type = _text(record.get("event_type"), 80) or "unknown"
        alert = record.get("alert") if isinstance(record.get("alert"), dict) else {}
        nested = record.get(event_type) if isinstance(record.get(event_type), dict) else {}
        allowed = self._detail_fields.get(event_type, ())
        details = {key: nested[key] for key in allowed if key in nested and not isinstance(nested[key], (dict, list))}
        if event_type == "alert":
            details = {key: alert[key] for key in allowed if key in alert and not isinstance(alert[key], (dict, list))}
        normalized = {
            "event_type": event_type,
            "timestamp": _timestamp(record.get("timestamp")),
            "severity": _severity(alert.get("severity")) if event_type == "alert" else "info",
            "signature": _text(alert.get("signature"), 500),
            "category": _text(alert.get("category"), 200),
            "action": _text(alert.get("action"), 80),
            "src_ip": _text(record.get("src_ip"), 64),
            "dst_ip": _text(record.get("dest_ip") or record.get("dst_ip"), 64),
            "src_port": _integer(record.get("src_port")),
            "dst_port": _integer(record.get("dest_port") or record.get("dst_port")),
            "proto": _text(record.get("proto"), 32),
            "app_proto": _text(record.get("app_proto"), 80),
            "flow_id": _text(record.get("flow_id"), 100),
            "community_id": _text(record.get("community_id"), 200),
            "in_iface": _text(record.get("in_iface"), 200),
            "details": details,
        }
        return normalized


class SensorService:
    """Checkpointed, bounded ingestion for typed local sensor adapters."""

    def __init__(self, db: Database):
        self.db = db
        adapters: list[SensorAdapter] = [SuricataEveAdapter()]
        self._adapters = {adapter.kind: adapter for adapter in adapters}

    def adapters(self) -> list[dict[str, Any]]:
        return [
            {
                "kind": adapter.kind,
                "label": adapter.label,
                "format": "newline-delimited JSON",
                "checkpointed": True,
                "rotation_aware": True,
                "stores_raw_payload": False,
            }
            for adapter in self._adapters.values()
        ]

    @staticmethod
    def _resolve_source(path: str) -> Path:
        try:
            resolved = Path(path).expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise SensorError(f"Sensor source does not exist or cannot be resolved: {path}") from exc
        if not resolved.is_file():
            raise SensorError("Sensor source must be a regular local file")
        if resolved.suffix.lower() not in {".json", ".jsonl", ".eve"}:
            raise SensorError("Sensor source must be .json, .jsonl or .eve newline-delimited JSON")
        return resolved

    @staticmethod
    def _identity(stat: os.stat_result) -> str:
        return f"{stat.st_dev}:{stat.st_ino}"

    def create_source(self, name: str, kind: str, path: str, enabled: bool = True) -> dict[str, Any]:
        if kind not in self._adapters:
            raise SensorError(f"Unsupported sensor adapter: {kind}")
        resolved = self._resolve_source(path)
        existing = self.db.one("SELECT * FROM sensor_sources WHERE path=?", (str(resolved),))
        now = utcnow()
        if existing:
            if existing["kind"] != kind:
                raise SensorError("This file is already registered with another adapter")
            self.db.execute(
                "UPDATE sensor_sources SET name=?,enabled=?,updated_at=? WHERE id=?",
                (name.strip(), int(enabled), now, existing["id"]),
            )
            source_id = existing["id"]
            action = "sensor.source.update"
        else:
            source_id = f"src_{uuid.uuid4().hex}"
            stat = resolved.stat()
            self.db.execute(
                "INSERT INTO sensor_sources(id,kind,name,path,enabled,file_identity,last_size,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (source_id, kind, name.strip(), str(resolved), int(enabled), self._identity(stat), stat.st_size, now, now),
            )
            action = "sensor.source.create"
        self.db.audit(action, "ok", target=source_id, detail={"kind": kind, "path": str(resolved), "enabled": enabled})
        return self.get_source(source_id)

    def update_source(self, source_id: str, *, name: str | None = None, enabled: bool | None = None) -> dict[str, Any]:
        current = self.db.one("SELECT * FROM sensor_sources WHERE id=?", (source_id,))
        if not current:
            raise SensorError("Sensor source not found")
        next_name = name.strip() if name is not None else current["name"]
        next_enabled = int(enabled) if enabled is not None else current["enabled"]
        self.db.execute(
            "UPDATE sensor_sources SET name=?,enabled=?,updated_at=? WHERE id=?",
            (next_name, next_enabled, utcnow(), source_id),
        )
        self.db.audit("sensor.source.update", "ok", target=source_id, detail={"name": next_name, "enabled": bool(next_enabled)})
        return self.get_source(source_id)

    def get_source(self, source_id: str) -> dict[str, Any]:
        row = self.db.one(
            """SELECT s.*,
                      (SELECT COUNT(*) FROM sensor_records r WHERE r.source_id=s.id) AS records,
                      (SELECT COUNT(*) FROM sensor_records r WHERE r.source_id=s.id AND r.sensor_event_type='alert') AS alerts
                 FROM sensor_sources s WHERE s.id=?""",
            (source_id,),
        )
        if not row:
            raise SensorError("Sensor source not found")
        row["enabled"] = bool(row["enabled"])
        return row

    def sources(self) -> list[dict[str, Any]]:
        rows = self.db.rows(
            """SELECT s.*,
                      (SELECT COUNT(*) FROM sensor_records r WHERE r.source_id=s.id) AS records,
                      (SELECT COUNT(*) FROM sensor_records r WHERE r.source_id=s.id AND r.sensor_event_type='alert') AS alerts
                 FROM sensor_sources s ORDER BY s.created_at DESC"""
        )
        for row in rows:
            row["enabled"] = bool(row["enabled"])
        return rows

    def records(self, *, source_id: str | None = None, event_type: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if source_id and event_type:
            rows = self.db.rows(
                "SELECT * FROM sensor_records WHERE source_id=? AND sensor_event_type=? ORDER BY ts DESC LIMIT ?",
                (source_id, event_type, limit),
            )
        elif source_id:
            rows = self.db.rows(
                "SELECT * FROM sensor_records WHERE source_id=? ORDER BY ts DESC LIMIT ?",
                (source_id, limit),
            )
        elif event_type:
            rows = self.db.rows(
                "SELECT * FROM sensor_records WHERE sensor_event_type=? ORDER BY ts DESC LIMIT ?",
                (event_type, limit),
            )
        else:
            rows = self.db.rows("SELECT * FROM sensor_records ORDER BY ts DESC LIMIT ?", (limit,))
        for row in rows:
            row["data"] = json.loads(row.pop("data_json"))
        return rows

    def ingest(self, source_id: str, max_records: int = 10_000, reset_checkpoint: bool = False) -> dict[str, Any]:
        try:
            return self._ingest(source_id, max_records, reset_checkpoint)
        except Exception as exc:
            if self.db.one("SELECT 1 AS ok FROM sensor_sources WHERE id=?", (source_id,)):
                error = f"{type(exc).__name__}: {exc}"[:2000]
                self.db.execute("UPDATE sensor_sources SET last_error=?,updated_at=? WHERE id=?", (error, utcnow(), source_id))
                self.db.audit("sensor.ingest", "failed", target=source_id, detail={"error": error})
            raise

    def _ingest(self, source_id: str, max_records: int, reset_checkpoint: bool) -> dict[str, Any]:
        source = self.db.one("SELECT * FROM sensor_sources WHERE id=?", (source_id,))
        if not source:
            raise SensorError("Sensor source not found")
        if not source["enabled"]:
            raise SensorError("Sensor source is disabled")
        adapter = self._adapters.get(source["kind"])
        if not adapter:
            raise SensorError(f"Sensor adapter is unavailable: {source['kind']}")
        path = self._resolve_source(source["path"])
        max_records = max(1, min(int(max_records), 100_000))
        imported = duplicates = malformed = oversized = 0
        bytes_read = 0
        last_ts: str | None = None
        rotated = False

        with path.open("rb") as handle:
            stat = os.fstat(handle.fileno())
            identity = self._identity(stat)
            checkpoint = int(source["checkpoint_bytes"] or 0)
            rotated = source.get("file_identity") != identity or stat.st_size < checkpoint
            if reset_checkpoint or rotated:
                checkpoint = 0
            handle.seek(checkpoint)
            committed_offset = checkpoint
            while imported + duplicates + malformed + oversized < max_records and bytes_read < MAX_RUN_BYTES:
                line_start = handle.tell()
                line = handle.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                bytes_read += len(line)
                if len(line) > MAX_LINE_BYTES:
                    oversized += 1
                    while line and not line.endswith(b"\n") and bytes_read < MAX_RUN_BYTES:
                        line = handle.readline(MAX_LINE_BYTES + 1)
                        bytes_read += len(line)
                    if line.endswith(b"\n"):
                        committed_offset = handle.tell()
                    else:
                        handle.seek(line_start)
                    continue
                if not line.endswith(b"\n"):
                    handle.seek(line_start)
                    break
                committed_offset = handle.tell()
                raw = line.rstrip(b"\r\n")
                if not raw:
                    continue
                try:
                    decoded = json.loads(raw.decode("utf-8"))
                    if not isinstance(decoded, dict):
                        raise ValueError("record is not an object")
                    normalized = adapter.normalize(decoded)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
                    malformed += 1
                    continue
                raw_hash = hashlib.sha256(raw).hexdigest()
                if self._store_record(source_id, normalized, raw_hash):
                    imported += 1
                    last_ts = max(last_ts or normalized["timestamp"], normalized["timestamp"])
                else:
                    duplicates += 1

        now = utcnow()
        self.db.execute(
            "UPDATE sensor_sources SET checkpoint_bytes=?,file_identity=?,last_size=?,last_event_at=COALESCE(?,last_event_at),last_error=NULL,updated_at=? WHERE id=?",
            (committed_offset, identity, stat.st_size, last_ts, now, source_id),
        )
        result = {
            "source_id": source_id,
            "adapter": adapter.kind,
            "imported": imported,
            "duplicates": duplicates,
            "malformed": malformed,
            "oversized": oversized,
            "bytes_read": bytes_read,
            "checkpoint_bytes": committed_offset,
            "file_size": stat.st_size,
            "caught_up": committed_offset >= stat.st_size,
            "rotation_detected": rotated,
            "raw_payload_stored": False,
        }
        self.db.audit("sensor.ingest", "ok", target=source_id, detail=result)
        return result

    def _store_record(self, source_id: str, item: dict[str, Any], raw_hash: str) -> bool:
        record_id = f"sen_{hashlib.sha256(f'{source_id}:{raw_hash}'.encode()).hexdigest()[:32]}"
        evidence_ref = f"sensor:{source_id}:{record_id}"
        now = utcnow()
        event_type = str(item["event_type"])
        with self.db.tx() as conn:
            cursor = conn.execute(
                """INSERT OR IGNORE INTO sensor_records(
                       id,source_id,sensor_event_type,ts,severity,signature,category,action,
                       src_ip,dst_ip,src_port,dst_port,proto,app_proto,flow_id,data_json,raw_sha256,ingested_at
                     ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    record_id, source_id, event_type, item["timestamp"], item["severity"], item.get("signature"),
                    item.get("category"), item.get("action"), item.get("src_ip"), item.get("dst_ip"),
                    item.get("src_port"), item.get("dst_port"), item.get("proto"), item.get("app_proto"),
                    item.get("flow_id"), json.dumps(item, ensure_ascii=False, separators=(",", ":")), raw_hash, now,
                ),
            )
            if cursor.rowcount == 0:
                return False
            device_key = self._local_endpoint(item.get("src_ip"), item.get("dst_ip"))
            conn.execute(
                "INSERT INTO events(id,ts,event_type,source,device_key,severity,data_json,evidence_ref) VALUES(?,?,?,?,?,?,?,?)",
                (f"evt_{record_id[4:]}", item["timestamp"], f"sensor.suricata.{event_type}", source_id, device_key, item["severity"], json.dumps(item, ensure_ascii=False, separators=(",", ":")), evidence_ref),
            )
            if device_key:
                existing = conn.execute("SELECT 1 FROM devices WHERE device_key=?", (device_key,)).fetchone()
                if existing:
                    conn.execute("UPDATE devices SET last_seen=? WHERE device_key=?", (item["timestamp"], device_key))
                else:
                    conn.execute(
                        "INSERT INTO devices(device_key,display_name,state,first_seen,last_seen,addresses_json) VALUES(?,?,?,?,?,?)",
                        (device_key, device_key, "unclassified", item["timestamp"], item["timestamp"], json.dumps([device_key])),
                    )
            if event_type == "alert":
                signature = item.get("signature") or "Unbenannter Suricata-Alert"
                detail = f"Suricata meldete „{signature}“"
                if item.get("category"):
                    detail += f" ({item['category']})"
                detail += ". Externer Sensorbefund; lokal noch nicht bestätigt."
                confidence = {"high": 0.95, "medium": 0.80, "low": 0.65}.get(item["severity"], 0.50)
                conn.execute(
                    "INSERT OR IGNORE INTO observations(id,ts,kind,device_key,title,detail,confidence,state,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)",
                    (f"obs_{record_id[4:]}", item["timestamp"], "suricata_alert", device_key, signature, detail, confidence, "open", json.dumps([evidence_ref])),
                )
        return True

    @staticmethod
    def _local_endpoint(src_ip: str | None, dst_ip: str | None) -> str | None:
        for value in (src_ip, dst_ip):
            if not value:
                continue
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_private or address.is_link_local or address.is_loopback:
                return value
        return src_ip or dst_ip
