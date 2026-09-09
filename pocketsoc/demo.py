from __future__ import annotations

import json
from datetime import datetime, timezone

from .db import Database, utcnow


def seed_demo(db: Database) -> dict[str, object]:
    """Insert a harmless, idempotent metadata fixture so the product can be evaluated without capture rights."""
    if db.one("SELECT 1 AS ok FROM audit WHERE action='demo.seed' AND outcome='ok' LIMIT 1"):
        return {"seeded": False, "reason": "already seeded"}
    now = datetime.now(timezone.utc).isoformat()
    events: list[tuple[str, dict[str, str]]] = []
    for index, mac in enumerate(("02:00:00:00:00:01", "02:00:00:00:00:02")):
        events.append((f"demo_arp_{index}", {"protocol": "ARP", "arp_src_ip": "192.168.56.1", "arp_src_mac": mac, "arp_opcode": "2", "device_key": "192.168.56.1", "peer": "broadcast", "direction": "layer2"}))
    for index, stream in enumerate(("101", "102")):
        events.append((f"demo_replay_{index}", {"protocol": "HTTP", "device_key": "192.168.56.10", "peer": "192.168.56.20", "direction": "outbound", "http_method": "POST", "http_host": "demo.service.local", "http_uri": "/fixture/action", "tcp_stream": stream, "tcp_dst_port": "80"}))
    for index in range(25):
        label = f"harmlessdemofixturesegment{index:02d}abcdefghijk"
        events.append((f"demo_dns_{index}", {"protocol": "DNS", "device_key": "192.168.56.10", "peer": "192.168.56.1", "direction": "outbound", "dns_name": f"{label}.example.invalid", "dns_response": "0", "udp_dst_port": "53"}))
    with db.tx() as conn:
        for event_id, data in events:
            conn.execute("INSERT OR IGNORE INTO events(id,ts,event_type,source,device_key,severity,data_json,evidence_ref) VALUES(?,?,?,?,?,?,?,?)", (event_id, now, "network.packet", "demo-fixture", data["device_key"], "info", json.dumps(data), "fixture:demo"))
        for address in ("192.168.56.1", "192.168.56.10"):
            conn.execute("INSERT OR IGNORE INTO devices(device_key,display_name,state,first_seen,last_seen,addresses_json,metadata_json) VALUES(?,?,?,?,?,?,?)", (address, f"Demo {address}", "unclassified", now, now, json.dumps([address]), json.dumps({"fixture": True})))
    db.audit("demo.seed", "ok", detail={"events": len(events), "synthetic": True, "created_at": utcnow()})
    return {"seeded": True, "events": len(events), "synthetic": True}
