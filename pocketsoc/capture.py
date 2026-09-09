from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from .analysis import ingest_network_events
from .config import Settings
from .db import Database, utcnow
from .inventory import capture_interfaces


FIELDS = (
    "frame.time_epoch",
    "frame.number",
    "frame.len",
    "_ws.col.Protocol",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "dns.flags.response",
    "tls.handshake.extensions_server_name",
    "http.host",
    "http.request.method",
    "arp.opcode",
    "arp.src.hw_mac",
    "arp.src.proto_ipv4",
    "dhcp.option.dhcp_server_id",
    "dhcp.option.router",
    "dhcp.option.domain_name_server",
    "dns.id",
    "dns.a",
    "dns.aaaa",
    "tcp.stream",
    "tcp.analysis.retransmission",
    "tcp.analysis.duplicate_ack",
    "http.request.uri",
    "tls.handshake.ja4",
    "wlan.fc.retry",
    "wlan.fc.type_subtype",
    "wlan.bssid",
    "tcp.flags.syn",
    "tcp.flags.ack",
)
KEYS = (
    "ts",
    "frame_number",
    "frame_length",
    "protocol",
    "eth_src",
    "eth_dst",
    "ip_src",
    "ip_dst",
    "ipv6_src",
    "ipv6_dst",
    "tcp_src_port",
    "tcp_dst_port",
    "udp_src_port",
    "udp_dst_port",
    "dns_name",
    "dns_response",
    "tls_sni",
    "http_host",
    "http_method",
    "arp_opcode",
    "arp_src_mac",
    "arp_src_ip",
    "dhcp_server_id",
    "dhcp_router",
    "dhcp_dns_server",
    "dns_id",
    "dns_a",
    "dns_aaaa",
    "tcp_stream",
    "tcp_retransmission",
    "tcp_duplicate_ack",
    "http_uri",
    "tls_ja4",
    "wlan_retry",
    "wlan_type_subtype",
    "wlan_bssid",
    "tcp_syn",
    "tcp_ack",
)


class CaptureError(RuntimeError):
    pass


class CaptureService:
    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db

    def list_interfaces(self) -> list[dict[str, Any]]:
        return capture_interfaces(self.settings)

    def capture(self, interface: int, duration_seconds: int, max_packets: int) -> dict[str, Any]:
        ids = {item["id"] for item in self.list_interfaces()}
        if interface not in ids:
            raise CaptureError("The selected capture interface is not available")
        duration_seconds = max(2, min(duration_seconds, self.settings.max_capture_seconds))
        max_packets = max(10, min(max_packets, self.settings.max_capture_packets))
        capture_id = f"cap_{uuid.uuid4().hex}"
        destination = self.settings.captures_dir / f"{capture_id}.pcapng"
        argv = [
            str(self.settings.dumpcap_path),
            "-i",
            str(interface),
            "-a",
            f"duration:{duration_seconds}",
            "-c",
            str(max_packets),
            "-s",
            "256",
            "-w",
            str(destination),
        ]
        started = time.perf_counter()
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=duration_seconds + 20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        self.db.audit("capture.run", "ok" if result.returncode == 0 else "failed", target=str(interface), detail={"path": str(destination), "elapsed_ms": elapsed_ms, "stderr": result.stderr[-2000:]})
        if result.returncode != 0 or not destination.exists():
            raise CaptureError((result.stderr or "Capture failed")[-2000:])
        analysis = self.analyze(destination)
        retention = self._enforce_retention()
        return {"capture_id": capture_id, "path": str(destination), "bytes": destination.stat().st_size, "elapsed_ms": elapsed_ms, "analysis": analysis, "retention": retention}

    def analyze(self, path: str | Path) -> dict[str, Any]:
        capture = Path(path).expanduser().resolve()
        if capture.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
            raise CaptureError("Unsupported capture file extension")
        if not capture.is_file():
            raise CaptureError("Capture file does not exist")
        if capture.stat().st_size > 4 * 1024**3:
            raise CaptureError("Capture exceeds the 4 GiB local safety limit")
        if not self.settings.tshark_path.exists():
            raise CaptureError("TShark is unavailable")
        argv = [str(self.settings.tshark_path), "-n", "-r", str(capture), "-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f"]
        for field in FIELDS:
            argv.extend(["-e", field])
        started = time.perf_counter()
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            raise CaptureError((result.stderr or "TShark decoding failed")[-3000:])
        rows: list[dict[str, str]] = []
        reader = csv.reader(result.stdout.splitlines(), delimiter="\t", quotechar='"')
        for index, values in enumerate(reader):
            if index >= 100_000:
                break
            padded = list(values[: len(KEYS)]) + [""] * (len(KEYS) - len(values))
            row = {key: value for key, value in zip(KEYS, padded) if value != ""}
            if row:
                rows.append(row)
        digest = hashlib.sha256()
        with capture.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        evidence_ref = f"pcap:{digest.hexdigest()[:20]}"
        summary = ingest_network_events(self.db, rows, evidence_ref)
        summary.update({
            "path": str(capture),
            "sha256": digest.hexdigest(),
            "bytes": capture.stat().st_size,
            "decoded_rows": len(rows),
            "decode_elapsed_ms": round((time.perf_counter() - started) * 1000),
            "evidence_ref": evidence_ref,
            "privacy": "Only metadata and the first 256 bytes per live packet are retained by default.",
        })
        self.db.execute(
            "INSERT INTO capture_artifacts(id,path,evidence_ref,sha256,bytes,retention_state,created_at,updated_at) VALUES(?,?,?,?,?,'rolling',?,?) ON CONFLICT(path) DO UPDATE SET evidence_ref=excluded.evidence_ref,sha256=excluded.sha256,bytes=excluded.bytes,updated_at=excluded.updated_at",
            (f"cart_{uuid.uuid4().hex}", str(capture), evidence_ref, digest.hexdigest(), capture.stat().st_size, self.db.one("SELECT COALESCE(MIN(ts),'') AS ts FROM events WHERE evidence_ref=?", (evidence_ref,))["ts"] or utcnow(), utcnow()),
        )
        self.db.audit("pcap.analyze", "ok", target=str(capture), detail={"rows": len(rows), "evidence_ref": evidence_ref})
        return summary

    def open_in_wireshark(self, path: str | Path, display_filter: str | None = None) -> dict[str, Any]:
        capture = Path(path).expanduser().resolve()
        if not capture.is_file() or capture.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
            raise CaptureError("Valid capture file required")
        argv = [str(self.settings.wireshark_path), "-r", str(capture)]
        if display_filter:
            if len(display_filter) > 500 or any(ch in display_filter for ch in "\r\n\x00"):
                raise CaptureError("Invalid display filter")
            argv.extend(["-Y", display_filter])
        process = subprocess.Popen(argv, close_fds=True)
        self.db.audit("wireshark.open", "ok", target=str(capture), detail={"pid": process.pid, "filter": display_filter})
        return {"ok": True, "pid": process.pid, "path": str(capture), "filter": display_filter}

    def _enforce_retention(self) -> dict[str, Any]:
        """Prunes only PocketSOC-owned cap_*.pcapng files, oldest first."""
        files = sorted(
            (path for path in self.settings.captures_dir.glob("cap_*.pcapng") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        total = sum(path.stat().st_size for path in files)
        locked = {row["path"].lower() for row in self.db.rows("SELECT path FROM capture_artifacts WHERE retention_state IN ('incident_locked','manually_locked','pending_export')")}
        removed: list[str] = []
        while files and (len(files) > self.settings.max_capture_files or total > self.settings.max_capture_storage_bytes):
            deletable_index = next((index for index in range(len(files) - 1, -1, -1) if str(files[index]).lower() not in locked), None)
            if deletable_index is None:
                self.db.audit("capture.retention", "degraded", detail={"reason": "Only locked captures remain", "remaining_bytes": total})
                break
            path = files.pop(deletable_index)
            size = path.stat().st_size
            path.unlink()
            total -= size
            removed.append(str(path))
            self.db.execute("UPDATE capture_artifacts SET retention_state='deletable',updated_at=? WHERE path=?", (utcnow(), str(path)))
        if removed:
            self.db.audit("capture.retention", "ok", detail={"removed": removed, "remaining_bytes": total})
        return {"removed": removed, "remaining_files": len(files), "remaining_bytes": total, "max_files": self.settings.max_capture_files, "max_bytes": self.settings.max_capture_storage_bytes}
