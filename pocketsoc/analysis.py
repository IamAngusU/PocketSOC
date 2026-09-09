from __future__ import annotations

import json
import ipaddress
import uuid
from collections import Counter
from typing import Any

from datetime import datetime, timezone

from .db import Database, utcnow


def _event_id() -> str:
    return f"evt_{uuid.uuid4().hex}"


def _normalized_timestamp(value: str | None, fallback: str) -> str:
    if not value:
        return fallback
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, TypeError, OSError):
        return value


def _is_local_address(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
        return address.is_private or address.is_link_local or address.is_loopback
    except ValueError:
        return False


def _device_and_peer(row: dict[str, Any]) -> tuple[str, str, str]:
    source_ip = row.get("ip_src") or row.get("ipv6_src")
    destination_ip = row.get("ip_dst") or row.get("ipv6_dst")
    source_local = _is_local_address(source_ip)
    destination_local = _is_local_address(destination_ip)
    if source_local and not destination_local:
        return source_ip, destination_ip or "unknown", "outbound"
    if destination_local and not source_local:
        return destination_ip, source_ip or "unknown", "inbound"
    if source_ip or destination_ip:
        return source_ip or destination_ip, destination_ip or source_ip or "unknown", "local"
    return row.get("eth_src") or "unknown", row.get("eth_dst") or "unknown", "layer2"


def ingest_network_events(db: Database, rows: list[dict[str, Any]], evidence_ref: str) -> dict[str, Any]:
    protocol_counts: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    new_features: list[tuple[str, str, str]] = []
    now = utcnow()
    with db.tx() as conn:
        for row in rows:
            source, destination, direction = _device_and_peer(row)
            row["device_key"] = source
            row["peer"] = destination
            row["direction"] = direction
            protocol = row.get("protocol") or "unknown"
            ts = _normalized_timestamp(row.get("ts"), now)
            row["ts"] = ts
            protocol_counts[protocol] += 1
            destinations[destination] += 1
            if row.get("dns_name"):
                domains[row["dns_name"]] += 1
            conn.execute(
                "INSERT INTO events(id,ts,event_type,source,device_key,severity,data_json,evidence_ref) VALUES(?,?,?,?,?,?,?,?)",
                (_event_id(), ts, "network.packet", "tshark", source, "info", json.dumps(row, ensure_ascii=False), evidence_ref),
            )
            existing = conn.execute("SELECT 1 FROM devices WHERE device_key=?", (source,)).fetchone()
            if existing:
                conn.execute("UPDATE devices SET last_seen=? WHERE device_key=?", (ts, source))
            else:
                conn.execute("INSERT INTO devices(device_key,display_name,state,first_seen,last_seen,addresses_json) VALUES(?,?,?,?,?,?)", (source, source, "unclassified", ts, ts, json.dumps([source])))
            if destination != "unknown":
                baseline = conn.execute("SELECT seen_count FROM baselines WHERE device_key=? AND feature='destination' AND value=?", (source, destination)).fetchone()
                if baseline:
                    conn.execute("UPDATE baselines SET last_seen=?,seen_count=seen_count+1 WHERE device_key=? AND feature='destination' AND value=?", (ts, source, destination))
                else:
                    conn.execute("INSERT INTO baselines(device_key,feature,value,first_seen,last_seen,seen_count,confirmed) VALUES(?,?,?,?,?,1,0)", (source, "destination", destination, ts, ts))
                    new_features.append((source, "destination", destination))
            protocol_features = []
            if row.get("arp_src_ip") and row.get("arp_src_mac"):
                protocol_features.append((row["arp_src_ip"], "arp_identity", f"{row['arp_src_ip']}|{row['arp_src_mac']}"))
            if row.get("dhcp_server_id"):
                protocol_features.append((source, "dhcp_server", row["dhcp_server_id"]))
            if row.get("dhcp_router"):
                protocol_features.append((source, "dhcp_router", row["dhcp_router"]))
            if row.get("dhcp_dns_server"):
                protocol_features.append((source, "dhcp_dns", row["dhcp_dns_server"]))
            for feature_device, feature, value in protocol_features:
                baseline = conn.execute("SELECT seen_count FROM baselines WHERE device_key=? AND feature=? AND value=?", (feature_device, feature, value)).fetchone()
                if baseline:
                    conn.execute("UPDATE baselines SET last_seen=?,seen_count=seen_count+1 WHERE device_key=? AND feature=? AND value=?", (ts, feature_device, feature, value))
                else:
                    conn.execute("INSERT INTO baselines(device_key,feature,value,first_seen,last_seen,seen_count,confirmed) VALUES(?,?,?,?,?,1,0)", (feature_device, feature, value, ts, ts))
        for device, feature, value in new_features[:100]:
            obs_id = f"obs_{uuid.uuid4().hex}"
            conn.execute(
                "INSERT INTO observations(id,ts,kind,device_key,title,detail,confidence,state,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)",
                (obs_id, now, "new_destination", device, "Neues Ziel beobachtet", f"{device} kommunizierte erstmals mit {value}. Das ist eine Beobachtung, kein bestätigter Angriff.", 1.0, "open", json.dumps([evidence_ref])),
            )
    return {
        "events_ingested": len(rows),
        "protocols": protocol_counts.most_common(20),
        "top_destinations": destinations.most_common(20),
        "domains": domains.most_common(20),
        "new_baseline_features": len(new_features),
    }


def dashboard_summary(db: Database) -> dict[str, Any]:
    count_queries = (
        ("events", "SELECT COUNT(*) AS n FROM events"),
        ("devices", "SELECT COUNT(*) AS n FROM devices"),
        ("observations", "SELECT COUNT(*) AS n FROM observations"),
        ("jobs", "SELECT COUNT(*) AS n FROM jobs"),
        ("monitors", "SELECT COUNT(*) AS n FROM monitors"),
        ("generated_tools", "SELECT COUNT(*) AS n FROM generated_tools"),
        ("filters", "SELECT COUNT(*) AS n FROM filters"),
        ("recipes", "SELECT COUNT(*) AS n FROM recipes"),
        ("firewall_proposals", "SELECT COUNT(*) AS n FROM firewall_proposals"),
        ("incidents", "SELECT COUNT(*) AS n FROM incidents"),
        ("knowledge_documents", "SELECT COUNT(*) AS n FROM knowledge_documents"),
        ("sensor_sources", "SELECT COUNT(*) AS n FROM sensor_sources"),
        ("sensor_records", "SELECT COUNT(*) AS n FROM sensor_records"),
    )
    counts = {name: db.one(query)["n"] for name, query in count_queries}
    counts["open_observations"] = db.one("SELECT COUNT(*) AS n FROM observations WHERE state='open'")["n"]
    counts["running_jobs"] = db.one("SELECT COUNT(*) AS n FROM jobs WHERE status IN ('queued','running')")["n"]
    return counts
