from __future__ import annotations

import hashlib
import ipaddress
import json
import statistics
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import psutil

from .db import Database, utcnow


RULES: tuple[dict[str, Any], ...] = (
    {"id": "det_mitm_arp_identity", "name": "Possible ARP identity conflict", "category": "mitm", "severity": "high", "confidence_floor": 0.88, "knowledge": ["mitre-t1557", "mitre-t1557-002"], "spec": {"signal": "same_ipv4_multiple_sender_macs", "min_macs": 2}},
    {"id": "det_arp_reply_burst", "name": "ARP reply burst", "category": "mitm", "severity": "medium", "confidence_floor": 0.65, "knowledge": ["mitre-t1557-002"], "spec": {"signal": "arp_reply_count", "threshold": 30}},
    {"id": "det_rogue_dhcp", "name": "Multiple DHCP server identities", "category": "mitm", "severity": "high", "confidence_floor": 0.78, "knowledge": ["mitre-t1557-003"], "spec": {"signal": "multiple_dhcp_servers", "min_servers": 2}},
    {"id": "det_dns_answer_churn", "name": "DNS answer churn", "category": "dns", "severity": "low", "confidence_floor": 0.45, "knowledge": ["mitre-t1557-001"], "spec": {"signal": "same_name_many_answers", "threshold": 8}},
    {"id": "det_outbound_scan", "name": "Possible outbound service enumeration", "category": "reconnaissance", "severity": "medium", "confidence_floor": 0.70, "knowledge": ["mitre-t1046"], "spec": {"signal": "many_peers_or_ports", "min_peers": 40, "min_ports": 20}},
    {"id": "det_possible_http_replay", "name": "Possible repeated non-idempotent transaction", "category": "replay", "severity": "medium", "confidence_floor": 0.55, "knowledge": ["mitre-t1557"], "spec": {"signal": "same_non_idempotent_request_multiple_streams", "methods": ["POST", "PUT", "PATCH", "DELETE"], "min_streams": 2}},
    {"id": "det_wifi_deauth_burst", "name": "Wi-Fi deauthentication burst", "category": "mitm", "severity": "high", "confidence_floor": 0.82, "knowledge": ["mitre-t1557-004"], "spec": {"signal": "deauth_frames", "threshold": 5}},
    {"id": "det_tcp_retransmission_spike", "name": "TCP retransmission spike", "category": "availability", "severity": "low", "confidence_floor": 0.40, "knowledge": [], "spec": {"signal": "retransmission_ratio", "min_packets": 50, "ratio": 0.20}},
    {"id": "det_dns_tunnel_candidate", "name": "Possible DNS tunneling pattern", "category": "command-and-control", "severity": "medium", "confidence_floor": 0.58, "knowledge": ["mitre-t1071-004"], "spec": {"signal": "many_unique_long_dns_labels", "min_queries": 25, "min_unique": 20, "long_label": 30}},
    {"id": "det_periodic_beacon_candidate", "name": "Possible periodic beacon", "category": "command-and-control", "severity": "medium", "confidence_floor": 0.62, "knowledge": ["mitre-t1071"], "spec": {"signal": "regular_outbound_syn_intervals", "min_starts": 8, "max_interval_cv": 0.15}},
    {"id": "det_private_lateral_fanout", "name": "Possible private lateral fan-out", "category": "lateral-movement", "severity": "medium", "confidence_floor": 0.60, "knowledge": ["mitre-t1046"], "spec": {"signal": "many_private_peers", "min_peers": 20}},
    {"id": "det_repeated_connection_attempts", "name": "Repeated connection attempts", "category": "credential-access", "severity": "low", "confidence_floor": 0.38, "knowledge": ["mitre-t1110"], "spec": {"signal": "many_outbound_syn_same_service", "threshold": 50}},
    {"id": "det_outbound_volume", "name": "Unusual outbound volume candidate", "category": "exfiltration", "severity": "medium", "confidence_floor": 0.42, "knowledge": ["mitre-t1041"], "spec": {"signal": "outbound_frame_bytes", "threshold_bytes": 52428800}},
)


class DetectionService:
    def __init__(self, db: Database):
        self.db = db

    def ensure_rules(self) -> None:
        with self.db.tx() as conn:
            for rule in RULES:
                previous = conn.execute("SELECT spec_json FROM detection_rules WHERE id=?", (rule["id"],)).fetchone()
                configured_spec = {**rule["spec"], **(json.loads(previous[0]) if previous else {})}
                conn.execute(
                    "INSERT INTO detection_rules(id,name,category,version,enabled,severity,confidence_floor,spec_json,knowledge_refs_json,created_at) VALUES(?,?,?,?,1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,category=excluded.category,severity=excluded.severity,spec_json=excluded.spec_json,knowledge_refs_json=excluded.knowledge_refs_json",
                    (rule["id"], rule["name"], rule["category"], 1, rule["severity"], rule["confidence_floor"], json.dumps(configured_spec), json.dumps(rule["knowledge"]), utcnow()),
                )

    def rules(self) -> list[dict[str, Any]]:
        rows = self.db.rows("SELECT * FROM detection_rules ORDER BY category,name")
        for row in rows:
            row["enabled"] = bool(row["enabled"])
            row["spec"] = json.loads(row.pop("spec_json") or "{}")
            row["knowledge_refs"] = json.loads(row.pop("knowledge_refs_json") or "[]")
        return rows

    def update_rule(self, rule_id: str, *, enabled: bool | None, confidence_floor: float | None, spec: dict[str, Any] | None) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM detection_rules WHERE id=?", (rule_id,))
        if not row:
            raise ValueError("Detection rule not found")
        current = json.loads(row["spec_json"] or "{}")
        if spec is not None:
            unknown = set(spec) - set(current)
            if unknown:
                raise ValueError(f"Unknown detector parameters: {sorted(unknown)}")
            merged = dict(current)
            for key, value in spec.items():
                original = current[key]
                if isinstance(original, bool) or type(value) is not type(original):
                    raise ValueError(f"Detector parameter {key} must keep type {type(original).__name__}")
                if isinstance(value, int) and not 1 <= value <= 1_000_000_000_000:
                    raise ValueError(f"Detector parameter {key} is outside the safe range")
                if key in {"min_macs", "min_servers", "min_streams"} and value < 2:
                    raise ValueError(f"Detector parameter {key} must be at least 2")
                if isinstance(value, float) and not 0 < value <= 1:
                    raise ValueError(f"Detector ratio {key} must be greater than 0 and at most 1")
                if isinstance(value, list) and (not value or len(value) > 20 or any(not isinstance(item, str) or len(item) > 40 for item in value)):
                    raise ValueError(f"Detector list {key} is invalid")
                merged[key] = value
        else:
            merged = current
        next_enabled = bool(row["enabled"]) if enabled is None else enabled
        next_floor = float(row["confidence_floor"]) if confidence_floor is None else confidence_floor
        self.db.execute("UPDATE detection_rules SET enabled=?,confidence_floor=?,spec_json=? WHERE id=?", (1 if next_enabled else 0, next_floor, json.dumps(merged), rule_id))
        self.db.audit("detection.rule.update", "ok", target=rule_id, detail={"enabled": next_enabled, "confidence_floor": next_floor, "spec": merged})
        return next(item for item in self.rules() if item["id"] == rule_id)

    @staticmethod
    def _claim(text: str, classification: str, confidence: float, sources: list[str], limitations: list[str] | None = None) -> dict[str, Any]:
        return {"claim": text, "classification": classification, "confidence": confidence, "sources": sources, "limitations": limitations or []}

    @staticmethod
    def _fingerprint(rule_id: str, key: str) -> str:
        return hashlib.sha256(f"{rule_id}|{key}".encode()).hexdigest()

    def _store_finding(self, finding: dict[str, Any]) -> str:
        fingerprint = self._fingerprint(finding["rule_id"], finding["key"])
        existing = self.db.one("SELECT id,status FROM incidents WHERE fingerprint=? AND status IN ('open','acknowledged') ORDER BY last_seen DESC LIMIT 1", (fingerprint,))
        now = utcnow()
        if existing:
            incident_id = existing["id"]
            self.db.execute("UPDATE incidents SET last_seen=?,confidence=?,summary=?,claims_json=?,evidence_json=?,alternatives_json=? WHERE id=?", (now, finding["confidence"], finding["summary"], json.dumps(finding["claims"], ensure_ascii=False), json.dumps(finding["evidence"]), json.dumps(finding["alternatives"], ensure_ascii=False), incident_id))
        else:
            previous = self.db.one("SELECT id,status FROM incidents WHERE fingerprint=? ORDER BY last_seen DESC LIMIT 1", (fingerprint,))
            if previous and previous["status"] == "false_positive":
                return previous["id"]
            if previous:
                incident_id = previous["id"]
                with self.db.tx() as conn:
                    conn.execute("UPDATE incidents SET status='open',last_seen=?,confidence=?,summary=?,claims_json=?,evidence_json=?,alternatives_json=? WHERE id=?", (now, finding["confidence"], finding["summary"], json.dumps(finding["claims"], ensure_ascii=False), json.dumps(finding["evidence"]), json.dumps(finding["alternatives"], ensure_ascii=False), incident_id))
                    conn.execute("INSERT INTO incident_history(id,incident_id,ts,actor,from_status,to_status,note) VALUES(?,?,?,?,?,?,?)", (f"ih_{uuid.uuid4().hex}", incident_id, now, "detector", previous["status"], "open", "Pattern was observed again"))
            else:
                incident_id = f"inc_{uuid.uuid4().hex}"
                self.db.execute(
                    "INSERT INTO incidents(id,fingerprint,rule_id,first_seen,last_seen,title,severity,confidence,status,target,summary,claims_json,evidence_json,alternatives_json,response_state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (incident_id, fingerprint, finding["rule_id"], now, now, finding["title"], finding["severity"], finding["confidence"], "open", finding.get("target"), finding["summary"], json.dumps(finding["claims"], ensure_ascii=False), json.dumps(finding["evidence"]), json.dumps(finding["alternatives"], ensure_ascii=False), "none"),
                )
        refs = [item for item in finding["evidence"] if item.startswith("pcap:")]
        if refs:
            with self.db.tx() as conn:
                for evidence_ref in refs:
                    artifacts = conn.execute("SELECT id FROM capture_artifacts WHERE evidence_ref=?", (evidence_ref,)).fetchall()
                    conn.execute("UPDATE capture_artifacts SET retention_state='incident_locked',lock_reason=?,updated_at=? WHERE evidence_ref=?", (incident_id, now, evidence_ref))
                    for artifact in artifacts:
                        conn.execute("INSERT OR IGNORE INTO incident_artifacts(incident_id,capture_artifact_id,linked_at) VALUES(?,?,?)", (incident_id, artifact["id"], now))
        return incident_id

    @staticmethod
    def _evidence(bucket: dict[str, Any]) -> tuple[list[str], list[str]]:
        event_ids = bucket.get("event_ids", [])[:20]
        refs = sorted(bucket.get("refs", set()))
        return event_ids, refs

    def run(self, window_minutes: int = 60) -> dict[str, Any]:
        window_minutes = max(1, min(int(window_minutes), 1440))
        started_at = utcnow(); started = time.perf_counter(); cpu_started = time.process_time()
        rss_started = psutil.Process().memory_info().rss
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
        rows = self.db.rows("SELECT id,ts,device_key,data_json,evidence_ref FROM events WHERE event_type='network.packet' AND ts>=? ORDER BY ts DESC LIMIT 100000", (cutoff,))
        configured = {row["id"]: row for row in self.rules()}
        specs = {rule_id: row["spec"] for rule_id, row in configured.items()}
        arp: dict[str, dict[str, Any]] = defaultdict(lambda: {"macs": set(), "replies": defaultdict(int), "event_ids": [], "refs": set()})
        dhcp = {"servers": set(), "event_ids": [], "refs": set()}
        dns: dict[str, dict[str, Any]] = defaultdict(lambda: {"answers": set(), "event_ids": [], "refs": set()})
        outbound: dict[str, dict[str, Any]] = defaultdict(lambda: {"peers": set(), "ports": set(), "event_ids": [], "refs": set()})
        replay: dict[tuple[str, str, str, str], dict[str, Any]] = defaultdict(lambda: {"streams": set(), "count": 0, "event_ids": [], "refs": set()})
        wifi: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "event_ids": [], "refs": set()})
        tcp: dict[str, dict[str, Any]] = defaultdict(lambda: {"packets": 0, "retransmissions": 0, "event_ids": [], "refs": set()})
        dns_activity: dict[str, dict[str, Any]] = defaultdict(lambda: {"names": set(), "long": 0, "queries": 0, "event_ids": [], "refs": set()})
        connection_starts: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(lambda: {"timestamps": [], "event_ids": [], "refs": set()})
        connection_attempts: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(lambda: {"count": 0, "event_ids": [], "refs": set()})

        def remember(bucket: dict[str, Any], row: dict[str, Any]) -> None:
            if len(bucket["event_ids"]) < 20:
                bucket["event_ids"].append(row["id"])
            if row.get("evidence_ref"):
                bucket["refs"].add(row["evidence_ref"])

        for row in rows:
            try:
                data = json.loads(row["data_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            arp_ip, arp_mac = data.get("arp_src_ip"), str(data.get("arp_src_mac") or "").lower()
            if arp_ip and arp_mac:
                bucket = arp[arp_ip]; bucket["macs"].add(arp_mac)
                if str(data.get("arp_opcode")) == "2":
                    bucket["replies"][arp_mac] += 1
                remember(bucket, row)
            if data.get("dhcp_server_id"):
                dhcp["servers"].add(data["dhcp_server_id"]); remember(dhcp, row)
            if data.get("dns_name") and (data.get("dns_a") or data.get("dns_aaaa")):
                bucket = dns[data["dns_name"].lower()]
                bucket["answers"].add(data.get("dns_a") or data.get("dns_aaaa")); remember(bucket, row)
            if data.get("dns_name") and str(data.get("dns_response") or "0").lower() in {"0", "false", ""}:
                device = data.get("device_key") or row.get("device_key") or "unknown"
                bucket = dns_activity[device]; name = str(data["dns_name"]).lower().rstrip(".")
                bucket["queries"] += 1; bucket["names"].add(name)
                if len(name.split(".", 1)[0]) >= specs["det_dns_tunnel_candidate"]["long_label"]: bucket["long"] += 1
                remember(bucket, row)
            if data.get("direction") == "outbound":
                device = data.get("device_key") or row.get("device_key") or "unknown"
                bucket = outbound[device]
                if data.get("peer"): bucket["peers"].add(data["peer"])
                peer_port = data.get("tcp_dst_port") or data.get("udp_dst_port")
                if peer_port: bucket["ports"].add(str(peer_port))
                try: bucket["bytes"] = bucket.get("bytes", 0) + int(data.get("frame_length") or 0)
                except (TypeError, ValueError): pass
                remember(bucket, row)
                syn = str(data.get("tcp_syn") or "").lower() in {"1", "true"}
                ack = str(data.get("tcp_ack") or "").lower() in {"1", "true"}
                if syn and not ack and data.get("peer") and data.get("tcp_dst_port"):
                    start_key = (device, str(data["peer"]), str(data["tcp_dst_port"])); start_bucket = connection_starts[start_key]
                    try: start_bucket["timestamps"].append(datetime.fromisoformat(str(row["ts"]).replace("Z", "+00:00")).timestamp())
                    except (TypeError, ValueError): pass
                    remember(start_bucket, row)
                    attempt_bucket = connection_attempts[start_key]; attempt_bucket["count"] += 1; remember(attempt_bucket, row)
            method = str(data.get("http_method") or "").upper()
            if method in set(specs["det_possible_http_replay"]["methods"]) and data.get("http_host") and data.get("http_uri"):
                key = (data.get("device_key") or row.get("device_key") or "unknown", method, data["http_host"], data["http_uri"])
                bucket = replay[key]; bucket["count"] += 1
                if data.get("tcp_stream") is not None: bucket["streams"].add(str(data["tcp_stream"]))
                remember(bucket, row)
            if str(data.get("wlan_type_subtype") or "").lower() in {"0x000c", "12"}:
                bucket = wifi[str(data.get("wlan_bssid") or "unknown")]; bucket["count"] += 1; remember(bucket, row)
            if data.get("protocol") in {"TCP", "TLSv1.2", "TLSv1.3", "SSL"}:
                bucket = tcp[str(data.get("peer") or "unknown")]; bucket["packets"] += 1
                if data.get("tcp_retransmission"): bucket["retransmissions"] += 1
                remember(bucket, row)

        findings: list[dict[str, Any]] = []
        for ip, bucket in arp.items():
            event_ids, refs = self._evidence(bucket); sources = event_ids + refs
            if len(bucket["macs"]) >= specs["det_mitm_arp_identity"]["min_macs"]:
                findings.append({"rule_id": "det_mitm_arp_identity", "key": ip, "target": ip, "title": "Möglicher ARP-Identitätskonflikt", "severity": "high", "confidence": 0.88, "summary": f"Für {ip} wurden im Zeitfenster {len(bucket['macs'])} Sender-MAC-Adressen beobachtet.", "claims": [self._claim(f"Die ARP-Absender-IP {ip} erschien mit mehreren MAC-Adressen.", "observed", 1.0, sources), self._claim("Das Muster ist mit ARP-Spoofing/MITM vereinbar, beweist es aber nicht.", "hypothesis", 0.88, sources, ["Router-Failover", "NIC-/Routerwechsel", "fehlerhafte Bridge"])], "evidence": sources, "alternatives": ["legitimer Router-Failover", "Hardwarewechsel", "Netzwerkvirtualisierung"]})
            for mac, count in bucket["replies"].items():
                if count >= specs["det_arp_reply_burst"]["threshold"]:
                    findings.append({"rule_id": "det_arp_reply_burst", "key": f"{ip}|{mac}", "target": ip, "title": "ARP-Antwortburst", "severity": "medium", "confidence": 0.65, "summary": f"{count} ARP-Antworten von {mac} für {ip} im Zeitfenster.", "claims": [self._claim("Der ARP-Antwortzähler überschritt die Regelgrenze.", "derived", 1.0, sources), self._claim("Ein ARP-Burst kann Spoofing unterstützen.", "hypothesis", 0.65, sources, ["legitime Netzwerkwiederherstellung", "Failover"])], "evidence": sources, "alternatives": ["ARP-Refresh nach Netzstörung", "Gateway-Failover"]})
        if len(dhcp["servers"]) >= specs["det_rogue_dhcp"]["min_servers"]:
            event_ids, refs = self._evidence(dhcp); sources = event_ids + refs
            findings.append({"rule_id": "det_rogue_dhcp", "key": "|".join(sorted(dhcp["servers"])), "title": "Mehrere DHCP-Serveridentitäten", "severity": "high", "confidence": 0.78, "summary": f"Im Zeitfenster wurden {len(dhcp['servers'])} DHCP-Server-IDs beobachtet.", "claims": [self._claim("Mehrere DHCP-Server-IDs wurden direkt dekodiert.", "observed", 1.0, sources), self._claim("Ein Rogue-DHCP-/MITM-Szenario ist möglich.", "hypothesis", 0.78, sources, ["autorisierter zweiter DHCP-Server", "Failover"] )], "evidence": sources, "alternatives": ["autorisierter DHCP-Failover", "Gastnetz/VLAN-Überlagerung"]})
        for name, bucket in dns.items():
            if len(bucket["answers"]) >= specs["det_dns_answer_churn"]["threshold"]:
                event_ids, refs = self._evidence(bucket); sources = event_ids + refs
                findings.append({"rule_id": "det_dns_answer_churn", "key": name, "title": "Hohe DNS-Antwortvarianz", "severity": "low", "confidence": 0.45, "summary": f"{name} lieferte mindestens {len(bucket['answers'])} unterschiedliche Antworten.", "claims": [self._claim("Mehrere DNS-Antwortadressen wurden dekodiert.", "observed", 1.0, sources), self._claim("DNS-Manipulation ist nur eine von mehreren Erklärungen.", "hypothesis", 0.45, sources, ["CDN", "Geo-DNS", "Round-robin DNS"])], "evidence": sources, "alternatives": ["CDN/Geo-DNS", "legitimes Load-Balancing"]})
        for device, bucket in outbound.items():
            if len(bucket["peers"]) >= specs["det_outbound_scan"]["min_peers"] or len(bucket["ports"]) >= specs["det_outbound_scan"]["min_ports"]:
                event_ids, refs = self._evidence(bucket); sources = event_ids + refs
                findings.append({"rule_id": "det_outbound_scan", "key": device, "target": device, "title": "Mögliche Service-Erkundung", "severity": "medium", "confidence": 0.70, "summary": f"{device} kontaktierte {len(bucket['peers'])} Ziele und {len(bucket['ports'])} Zielports.", "claims": [self._claim("Ziele und Ports wurden aus ausgehenden Paketgruppen gezählt.", "derived", 1.0, sources), self._claim("Das Muster ist mit Port-/Servicescans vereinbar.", "hypothesis", 0.70, sources, ["Inventarisierung", "Updater", "Browser/CDN-Verkehr"])], "evidence": sources, "alternatives": ["autorisierter Scanner", "Softwareverteilung", "Browser/CDN-Fan-out"]})
        for key, bucket in replay.items():
            if len(bucket["streams"]) >= specs["det_possible_http_replay"]["min_streams"]:
                event_ids, refs = self._evidence(bucket); sources = event_ids + refs
                device, method, host, uri = key
                findings.append({"rule_id": "det_possible_http_replay", "key": "|".join(key), "target": device, "title": "Mögliche wiederholte Transaktion", "severity": "medium", "confidence": 0.55, "summary": f"Dieselbe {method}-Route bei {host} erschien in {len(bucket['streams'])} TCP-Streams.", "claims": [self._claim("Methode, Host, URI und unterschiedliche TCP-Streams wurden dekodiert.", "observed", 1.0, sources), self._claim("Ein Replay ist möglich, aber ohne Payload, Nonce und Serverzustand nicht nachweisbar.", "hypothesis", 0.55, sources, ["legitime Wiederholung", "Client-Retry", "Load-Balancer"])], "evidence": sources, "alternatives": ["legitimer Retry", "Benutzeraktion wiederholt", "Anwendungs-Timeout"]})
        for bssid, bucket in wifi.items():
            if bucket["count"] >= specs["det_wifi_deauth_burst"]["threshold"]:
                event_ids, refs = self._evidence(bucket); sources = event_ids + refs
                findings.append({"rule_id": "det_wifi_deauth_burst", "key": bssid, "title": "Wi-Fi-Deauthentication-Burst", "severity": "high", "confidence": 0.82, "summary": f"{bucket['count']} Deauthentication-Frames für BSSID {bssid}.", "claims": [self._claim("Deauthentication-Frames überschritten die Regelgrenze.", "derived", 1.0, sources), self._claim("Evil-Twin-/MITM-Vorbereitung ist möglich.", "hypothesis", 0.82, sources, ["Access-Point-Neustart", "Roaming", "Administrationsaktion"])], "evidence": sources, "alternatives": ["AP-Neustart", "Roaming", "legitime WLAN-Administration"]})
        for peer, bucket in tcp.items():
            ratio = bucket["retransmissions"] / bucket["packets"] if bucket["packets"] else 0
            if bucket["packets"] >= specs["det_tcp_retransmission_spike"]["min_packets"] and ratio >= specs["det_tcp_retransmission_spike"]["ratio"]:
                event_ids, refs = self._evidence(bucket); sources = event_ids + refs
                findings.append({"rule_id": "det_tcp_retransmission_spike", "key": peer, "target": peer, "title": "TCP-Retransmission-Spitze", "severity": "low", "confidence": 0.40, "summary": f"{bucket['retransmissions']} von {bucket['packets']} TCP-Paketen zu {peer} wurden als Retransmission markiert.", "claims": [self._claim("TShark markierte einen hohen Retransmission-Anteil.", "observed", 1.0, sources), self._claim("Dies ist kein Replay-Nachweis; Paketverlust oder Überlastung sind wahrscheinliche Alternativen.", "derived", 1.0, sources)], "evidence": sources, "alternatives": ["Paketverlust", "WLAN-Störung", "Überlastung", "Capture-Artefakt"]})
        for device, bucket in dns_activity.items():
            unique = len(bucket["names"]); long_ratio = bucket["long"] / bucket["queries"] if bucket["queries"] else 0
            dns_spec = specs["det_dns_tunnel_candidate"]
            if bucket["queries"] >= dns_spec["min_queries"] and unique >= dns_spec["min_unique"] and bucket["long"] >= max(1, bucket["queries"] // 2):
                event_ids, refs = self._evidence(bucket); sources = event_ids + refs
                findings.append({"rule_id": "det_dns_tunnel_candidate", "key": device, "target": device, "title": "Mögliches DNS-Tunnelmuster", "severity": "medium", "confidence": 0.58, "summary": f"{device} erzeugte {bucket['queries']} DNS-Anfragen mit {unique} Namen; {long_ratio:.0%} hatten lange erste Labels.", "claims": [self._claim("Anzahl, Eindeutigkeit und Label-Längen wurden aus DNS-Anfragen berechnet.", "derived", 1.0, sources), self._claim("Das Muster ist mit DNS-Tunneling vereinbar, aber ohne Inhalts-/Baselinevergleich nicht beweisend.", "hypothesis", 0.58, sources, ["CDN-/Tracking-Domains", "legitime Geräte-IDs", "Security-Software"])], "evidence": sources, "alternatives": ["CDN/Tracking", "legitime zufällige Subdomains", "Endpoint-Security-Abfragen"]})
        for key, bucket in connection_starts.items():
            timestamps = sorted(bucket["timestamps"]); intervals = [right - left for left, right in zip(timestamps, timestamps[1:]) if right > left]
            beacon_spec = specs["det_periodic_beacon_candidate"]
            if len(timestamps) >= beacon_spec["min_starts"] and intervals:
                mean = statistics.fmean(intervals); cv = statistics.pstdev(intervals) / mean if mean else 1.0
                if mean >= 1 and cv <= beacon_spec["max_interval_cv"]:
                    event_ids, refs = self._evidence(bucket); sources = event_ids + refs; device, peer, port = key
                    findings.append({"rule_id": "det_periodic_beacon_candidate", "key": "|".join(key), "target": peer, "title": "Mögliches periodisches Beacon", "severity": "medium", "confidence": 0.62, "summary": f"{len(timestamps)} neue TCP-Verbindungsstarts von {device} zu {peer}:{port}, mittleres Intervall {mean:.1f}s, Variationskoeffizient {cv:.3f}.", "claims": [self._claim("Nur ausgehende SYN-Verbindungsstarts ohne ACK wurden zeitlich gruppiert.", "derived", 1.0, sources), self._claim("Regelmäßigkeit kann C2-Beaconing anzeigen, ist aber auch bei legitimen Pollern üblich.", "hypothesis", 0.62, sources, ["Health-Checks", "Telemetrie", "IoT-Polling"])], "evidence": sources, "alternatives": ["legitimer Health-Check", "Telemetrie", "IoT-Cloud-Polling"]})
        for device, bucket in outbound.items():
            private_peers = []
            for peer in bucket["peers"]:
                try:
                    if ipaddress.ip_address(peer).is_private: private_peers.append(peer)
                except ValueError: pass
            if len(private_peers) >= specs["det_private_lateral_fanout"]["min_peers"]:
                event_ids, refs = self._evidence(bucket); sources = event_ids + refs
                findings.append({"rule_id": "det_private_lateral_fanout", "key": device, "target": device, "title": "Mögliche laterale Erkundung", "severity": "medium", "confidence": 0.60, "summary": f"{device} kontaktierte {len(private_peers)} private Gegenstellen.", "claims": [self._claim("Private Zieladressen wurden deterministisch gezählt.", "derived", 1.0, sources), self._claim("Die breite interne Kommunikation ist mit lateraler Erkundung vereinbar.", "hypothesis", 0.60, sources, ["Inventarisierung", "Monitoring", "Service-Discovery"])], "evidence": sources, "alternatives": ["autorisierte Inventarisierung", "Netzwerkmonitoring", "lokale Service-Discovery"]})
            if bucket.get("bytes", 0) >= specs["det_outbound_volume"]["threshold_bytes"]:
                event_ids, refs = self._evidence(bucket); sources = event_ids + refs
                findings.append({"rule_id": "det_outbound_volume", "key": device, "target": device, "title": "Hohes ausgehendes Datenvolumen", "severity": "medium", "confidence": 0.42, "summary": f"Für {device} wurden im Zeitfenster {bucket['bytes']} ausgehende Frame-Bytes gezählt.", "claims": [self._claim("Die Frame-Längen ausgehender Pakete wurden summiert.", "derived", 1.0, sources), self._claim("Exfiltration ist nur eine schwache Hypothese; Backups und Uploads sind häufigere Erklärungen.", "hypothesis", 0.42, sources, ["Backup", "Cloud-Sync", "Video-Upload"])], "evidence": sources, "alternatives": ["Backup", "Cloud-Synchronisierung", "Medien-Upload", "Softwareverteilung"]})
        for key, bucket in connection_attempts.items():
            if bucket["count"] >= specs["det_repeated_connection_attempts"]["threshold"]:
                event_ids, refs = self._evidence(bucket); sources = event_ids + refs; device, peer, port = key
                findings.append({"rule_id": "det_repeated_connection_attempts", "key": "|".join(key), "target": peer, "title": "Viele Verbindungsversuche", "severity": "low", "confidence": 0.38, "summary": f"{bucket['count']} ausgehende TCP-Verbindungsstarts von {device} zu {peer}:{port}.", "claims": [self._claim("Ausgehende SYN-Starts ohne ACK wurden gezählt.", "derived", 1.0, sources), self._claim("Brute Force ist ohne Authentifizierungs-/Fehlerlogs nicht nachweisbar.", "hypothesis", 0.38, sources, ["Dienst nicht erreichbar", "Client-Retry", "Health-Check"])], "evidence": sources, "alternatives": ["Dienststörung", "Client-Retry", "Health-Check", "fehlkonfigurierter Agent"]})

        findings = [item for item in findings if configured[item["rule_id"]]["enabled"] and item["confidence"] >= float(configured[item["rule_id"]]["confidence_floor"])]
        incident_ids = [self._store_finding(item) for item in findings]
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        metrics = {"cpu_seconds": round(time.process_time() - cpu_started, 6), "rss_start_bytes": rss_started, "rss_end_bytes": psutil.Process().memory_info().rss, "rule_count": len(RULES)}
        run_id = f"drun_{uuid.uuid4().hex}"
        self.db.execute("INSERT INTO detection_runs(id,started_at,finished_at,window_minutes,events_examined,findings,elapsed_ms,metrics_json) VALUES(?,?,?,?,?,?,?,?)", (run_id, started_at, utcnow(), window_minutes, len(rows), len(findings), elapsed_ms, json.dumps(metrics)))
        self.db.audit("detection.run", "ok", target=run_id, detail={"events": len(rows), "findings": len(findings), "elapsed_ms": elapsed_ms})
        return {"run_id": run_id, "window_minutes": window_minutes, "events_examined": len(rows), "findings": len(findings), "incident_ids": incident_ids, "elapsed_ms": elapsed_ms, "metrics": metrics, "limitations": ["Encrypted application replay usually requires endpoint/application logs.", "A signal is an indicator, not proof of an attacker."]}

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.rows("SELECT i.*,r.knowledge_refs_json FROM incidents i JOIN detection_rules r ON r.id=i.rule_id ORDER BY i.last_seen DESC LIMIT ?", (limit,))
        return [self._hydrate_incident(row) for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT i.*,r.knowledge_refs_json FROM incidents i JOIN detection_rules r ON r.id=i.rule_id WHERE i.id=?", (incident_id,))
        if not row:
            raise ValueError("Incident not found")
        return self._hydrate_incident(row)

    def _hydrate_incident(self, row: dict[str, Any]) -> dict[str, Any]:
        for source, target in (("claims_json", "claims"), ("evidence_json", "evidence"), ("alternatives_json", "alternatives")):
            row[target] = json.loads(row.pop(source))
        row["knowledge_refs"] = json.loads(row.pop("knowledge_refs_json") or "[]")
        row["history"] = self.db.rows("SELECT id,ts,actor,from_status,to_status,note FROM incident_history WHERE incident_id=? ORDER BY ts DESC", (row["id"],))
        return row

    def update_incident(self, incident_id: str, status: str, note: str = "", actor: str = "local-user") -> dict[str, Any]:
        if status not in {"open", "acknowledged", "closed", "false_positive"}:
            raise ValueError("Unsupported incident status")
        row = self.db.one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not row:
            raise ValueError("Incident not found")
        previous = row["status"]
        if previous == status and not note:
            return self.get_incident(incident_id)
        now = utcnow()
        with self.db.tx() as conn:
            conn.execute("UPDATE incidents SET status=? WHERE id=?", (status, incident_id))
            conn.execute("INSERT INTO incident_history(id,incident_id,ts,actor,from_status,to_status,note) VALUES(?,?,?,?,?,?,?)", (f"ih_{uuid.uuid4().hex}", incident_id, now, actor, previous, status, note))
        if status in {"closed", "false_positive"}:
            for link in self.db.rows("SELECT capture_artifact_id FROM incident_artifacts WHERE incident_id=?", (incident_id,)):
                active_links = self.db.rows("SELECT i.id FROM incident_artifacts ia JOIN incidents i ON i.id=ia.incident_id WHERE ia.capture_artifact_id=? AND i.status IN ('open','acknowledged')", (link["capture_artifact_id"],))
                if active_links:
                    self.db.execute("UPDATE capture_artifacts SET retention_state='incident_locked',lock_reason=?,updated_at=? WHERE id=?", (active_links[0]["id"], now, link["capture_artifact_id"]))
                else:
                    self.db.execute("UPDATE capture_artifacts SET retention_state='rolling',lock_reason=NULL,updated_at=? WHERE id=? AND retention_state='incident_locked'", (now, link["capture_artifact_id"]))
        self.db.audit("incident.status.update", "ok", target=incident_id, detail={"from": previous, "to": status, "note": note})
        return self.get_incident(incident_id)
