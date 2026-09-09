from __future__ import annotations

import json
import re
from typing import Any

import httpx

from .config import Settings
from .db import Database, utcnow
from .inventory import ollama_status, select_ollama_model
from .knowledge import KnowledgeIndex


def evidence_for_question(db: Database, question: str, settings: Settings | None = None) -> dict[str, Any]:
    lower = question.lower()
    evidence: dict[str, Any] = {"question": question, "classification": "deterministic_query", "generated_at": utcnow(), "scope": "local_database_only"}
    if any(word in lower for word in ("alert", "auffällig", "bedroh", "beobachtung", "neu", "new")):
        evidence["observations"] = db.rows("SELECT id,ts,kind,device_key,title,detail,confidence,state,evidence_json FROM observations ORDER BY ts DESC LIMIT 30")
    if any(word in lower for word in ("gerät", "device", "inventar", "netzwerk")):
        evidence["devices"] = db.rows("SELECT device_key,display_name,state,first_seen,last_seen,addresses_json FROM devices ORDER BY last_seen DESC LIMIT 50")
    if any(word in lower for word in ("job", "worker", "aufgabe", "status")):
        evidence["jobs"] = db.rows("SELECT id,kind,status,stage,created_at,started_at,finished_at,elapsed_ms,error FROM jobs ORDER BY created_at DESC LIMIT 25")
    if any(word in lower for word in ("dns", "domain", "ziel", "verbindung", "connection", "paket")):
        raw_events = db.rows("SELECT id,ts,event_type,device_key,severity,data_json,evidence_ref FROM events WHERE event_type='network.packet' ORDER BY ts DESC LIMIT 500")
        groups: dict[tuple, dict[str, Any]] = {}
        for row in raw_events:
            try:
                data = json.loads(row["data_json"])
            except (json.JSONDecodeError, TypeError):
                data = {}
            direction = data.get("direction", "unknown")
            tcp_src, tcp_dst = data.get("tcp_src_port"), data.get("tcp_dst_port")
            udp_src, udp_dst = data.get("udp_src_port"), data.get("udp_dst_port")
            src_port, dst_port = tcp_src or udp_src, tcp_dst or udp_dst
            local_port, peer_port = (dst_port, src_port) if direction == "inbound" else (src_port, dst_port)
            key = (data.get("device_key") or row.get("device_key"), data.get("peer"), direction, data.get("protocol"), local_port, peer_port)
            if key not in groups:
                groups[key] = {
                    "device_key": key[0], "peer": key[1], "direction": key[2], "protocol": key[3],
                    "local_port": key[4], "peer_port": key[5], "packet_count": 0, "bytes": 0,
                    "first_ts": data.get("ts") or row["ts"], "last_ts": data.get("ts") or row["ts"],
                    "dns_names": set(), "tls_sni": set(), "http_hosts": set(), "event_ids": [], "evidence_refs": set(),
                }
            group = groups[key]
            group["packet_count"] += 1
            try:
                group["bytes"] += int(data.get("frame_length", 0))
            except (TypeError, ValueError):
                pass
            current_ts = data.get("ts") or row["ts"]
            group["first_ts"] = min(group["first_ts"], current_ts)
            group["last_ts"] = max(group["last_ts"], current_ts)
            for field, target in (("dns_name", "dns_names"), ("tls_sni", "tls_sni"), ("http_host", "http_hosts")):
                if data.get(field):
                    group[target].add(data[field])
            if len(group["event_ids"]) < 5:
                group["event_ids"].append(row["id"])
            if row.get("evidence_ref"):
                group["evidence_refs"].add(row["evidence_ref"])
        flows = []
        for group in groups.values():
            for field in ("dns_names", "tls_sni", "http_hosts", "evidence_refs"):
                group[field] = sorted(group[field])
            flows.append(group)
        evidence["flows"] = sorted(flows, key=lambda item: item["packet_count"], reverse=True)[:50]
    if any(word in lower for word in ("filter", "wireshark", "capture")):
        evidence["filters"] = db.rows("SELECT id,name,version,kind,status,expression_template,validation_json,score_json FROM filters ORDER BY created_at DESC LIMIT 30")
    if any(word in lower for word in ("recipe", "rezept", "workflow")):
        evidence["recipes"] = db.rows("SELECT id,name,version,status,description,validation_json FROM recipes ORDER BY created_at DESC LIMIT 30")
    if any(word in lower for word in ("firewall", "sperr", "block")):
        evidence["firewall_bindings"] = db.rows("SELECT id,name,adapter,endpoint,status,last_checked_at FROM firewall_bindings ORDER BY created_at")
        evidence["firewall_proposals"] = db.rows("SELECT id,binding_id,action,target,reason,ttl_seconds,status,evidence_json,created_at FROM firewall_proposals ORDER BY created_at DESC LIMIT 30")
    if any(word in lower for word in ("dataset", "datensatz", "suricata", "zeek", "rita", "arkime")):
        evidence["datasets"] = db.rows("SELECT id,name,publisher,purpose,scale,risk,local_status,recommendation FROM dataset_catalog ORDER BY name")
        evidence["integrations"] = db.rows("SELECT id,name,role,platform,status,fit,constraints FROM integration_catalog ORDER BY name")
    if any(word in lower for word in ("suricata", "sensor", "alert", "alarm", "angriff", "attack")):
        evidence["sensor_records"] = db.rows(
            "SELECT id,source_id,sensor_event_type,ts,severity,signature,category,action,src_ip,dst_ip,src_port,dst_port,proto,app_proto,flow_id FROM sensor_records ORDER BY ts DESC LIMIT 50"
        )
    if any(word in lower for word in ("incident", "angriff", "attack", "mitm", "replay", "spoof", "tunnel", "beacon", "exfil", "lateral", "brute")):
        evidence["incidents"] = db.rows("SELECT id,rule_id,last_seen,title,severity,confidence,status,target,summary,claims_json,evidence_json,alternatives_json FROM incidents WHERE status='open' ORDER BY last_seen DESC LIMIT 50")
    if settings:
        evidence["knowledge_hits"] = KnowledgeIndex(settings, db).search(question, 6)
    evidence["summary"] = {
        "events": db.one("SELECT COUNT(*) AS n FROM events")["n"],
        "devices": db.one("SELECT COUNT(*) AS n FROM devices")["n"],
        "open_observations": db.one("SELECT COUNT(*) AS n FROM observations WHERE state='open'")["n"],
        "active_jobs": db.one("SELECT COUNT(*) AS n FROM jobs WHERE status IN ('queued','running')")["n"],
        "sensor_records": db.one("SELECT COUNT(*) AS n FROM sensor_records")["n"],
    }
    return evidence


def _verified_facts(evidence: dict[str, Any]) -> list[str]:
    facts: list[str] = []
    if "summary" in evidence:
        summary = evidence["summary"]
        facts.append(f"Lokal gespeichert: {summary['events']} Ereignisse, {summary['devices']} Geräte und {summary['open_observations']} offene Beobachtungen.")
    if "flows" in evidence:
        flows = evidence["flows"]
        facts.append(f"Die letzten 500 Pakete wurden deterministisch zu {len(flows)} Verbindungsgruppen zusammengefasst.")
        if flows:
            top = flows[0]
            facts.append(f"Größte Gruppe: Gerät {top.get('device_key') or 'unbekannt'} ↔ Gegenstelle {top.get('peer') or 'unbekannt'}, {top.get('packet_count', 0)} Pakete; Evidenz {', '.join(top.get('evidence_refs') or ['ohne Referenz'])}.")
            for flow in flows[:5]:
                facts.append(f"Flow-Gruppe {flow.get('direction', 'unknown')}: {flow.get('device_key') or 'unbekannt'} ↔ {flow.get('peer') or 'unbekannt'}, Protokoll {flow.get('protocol') or 'unbekannt'}, lokal:{flow.get('local_port') or '–'} / peer:{flow.get('peer_port') or '–'}, {flow.get('packet_count', 0)} Pakete, {flow.get('bytes', 0)} Bytes; Evidenz {', '.join(flow.get('evidence_refs') or ['ohne Referenz'])}.")
    if "observations" in evidence:
        facts.append(f"Ausgewertet wurden {len(evidence['observations'])} aktuelle Beobachtungen; eine Beobachtung ist kein bestätigter Angriff.")
    if "filters" in evidence:
        facts.append(f"{sum(item['status'] == 'active' for item in evidence['filters'])} der aufgeführten Filterversionen sind aktiv.")
    if "firewall_proposals" in evidence:
        facts.append(f"Es gibt {len(evidence['firewall_proposals'])} Firewall-Vorschläge; PocketSOC wendet keinen davon selbständig an.")
    if "incidents" in evidence:
        facts.append(f"Lokal sind {len(evidence['incidents'])} offene, korrelierte Incidents gespeichert; jeder bleibt eine prüfpflichtige Einstufung.")
        for incident in evidence["incidents"][:5]:
            refs = json.loads(incident.get("evidence_json") or "[]")
            facts.append(f"Incident {incident['id']} ({incident['rule_id']}): {incident['summary']} Konfidenz {float(incident['confidence']):.0%}; Evidenz {', '.join(refs[:5]) or 'ohne Referenz'}.")
    if "sensor_records" in evidence:
        alerts = [item for item in evidence["sensor_records"] if item["sensor_event_type"] == "alert"]
        facts.append(f"Der lokale Sensorimport enthält in diesem Ausschnitt {len(evidence['sensor_records'])} normalisierte Records, darunter {len(alerts)} externe Alerts; Payloads wurden nicht übernommen.")
    for item in evidence.get("knowledge_hits", [])[:3]:
        facts.append(f"Wissensindex ({item['title']}): {item['excerpt']} Quelle: {item['source_url']}")
    return facts or ["Für diese Frage liegt nur die lokale Bestandsübersicht vor; es wurde nichts extern ergänzt."]


def _known_ips(evidence: dict[str, Any]) -> set[str]:
    return set(re.findall(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])", json.dumps(evidence, ensure_ascii=False)))


def answer_question(db: Database, settings: Settings, question: str, use_llm: bool) -> dict[str, Any]:
    evidence = evidence_for_question(db, question, settings)
    facts = _verified_facts(evidence)
    if not use_llm:
        return {"answer": "\n".join(f"- {fact}" for fact in facts), "facts": facts, "evidence": evidence, "mode": "deterministic", "quality": {"grounded": True, "language": "de", "model_claims": False}}
    status = ollama_status(settings)
    if not status["available"] or not status["models"]:
        return {"answer": "Lokales Modell ist nicht erreichbar.\n" + "\n".join(f"- {fact}" for fact in facts), "facts": facts, "evidence": evidence, "mode": "deterministic-fallback", "quality": {"grounded": True, "language": "de", "model_claims": False}}
    model, model_identity = select_ollama_model(status)
    if not model or not model_identity:
        return {"answer": "Kein freigegebenes lokales Modell gefunden.\n" + "\n".join(f"- {fact}" for fact in facts), "facts": facts, "evidence": evidence, "mode": "deterministic-fallback", "quality": {"grounded": True, "language": "de", "model_claims": False}}
    system = "Du bist ein lokaler defensiver Netzwerk-Analyst. Nutze ausschließlich das bereitgestellte Evidenz-JSON. Das Feld flows enthält deterministisch aggregierte Paketgruppen, nicht bewiesene Anwendungen oder Sitzungen. Die verifizierten Fakten werden separat vom Programm ausgegeben. Antworte nur mit der Überschrift 'Offene Fragen:' und zwei bis vier hilfreichen Fragen für die nächste Untersuchung. Wiederhole oder bewerte keine Zahlen, IPs, Protokolle, Dauer, Gefährlichkeit oder Entwarnung. Erfinde keine Ursachen oder Identitäten. Keine offensiven Anleitungen, keine Shellbefehle und keine selbständigen Änderungen."
    try:
        model_evidence = dict(evidence)
        serialized = json.dumps(model_evidence, ensure_ascii=False)
        if len(serialized) > 60000:
            for key, limit in (("flows", 20), ("observations", 15), ("devices", 30), ("jobs", 15)):
                if isinstance(model_evidence.get(key), list):
                    model_evidence[key] = model_evidence[key][:limit]
            model_evidence["model_context_truncated"] = True
            serialized = json.dumps(model_evidence, ensure_ascii=False)
        user_content = "Antworte ausschließlich auf Deutsch. Beantworte die Frage direkt und bleibe streng bei den Fakten in diesem Evidenzpaket. Nenne bei konkreten Aussagen die zugehörige ID oder evidence_ref:\n" + serialized
        response = httpx.post(f"{status['url']}/api/chat", json={"model": model, "stream": False, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user_content}], "options": {"temperature": 0.05, "num_predict": 900}}, timeout=90)
        response.raise_for_status()
        raw_model_output = response.json().get("message", {}).get("content", "")
        answer = raw_model_output
        translated = False
        english_markers = (
            "the provided", "here's", "key observations", "based on", "it appears", "appears to",
            "network monitoring", "this json", "device key", "packet count", "outbound traffic",
            "inbound traffic", "potential insights", "whether the", "the device",
            "open questions",
        )
        if sum(marker in answer.lower() for marker in english_markers) >= 2:
            translation = httpx.post(
                f"{status['url']}/api/chat",
                json={
                    "model": model,
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": "Übersetze den folgenden Text vollständig ins Deutsche. Füge keine Fakten, Deutungen oder Erklärungen hinzu. Gib nur die Übersetzung aus."},
                        {"role": "user", "content": answer[:20000]},
                    ],
                    "options": {"temperature": 0, "num_predict": 1000},
                },
                timeout=90,
            )
            translation.raise_for_status()
            answer = translation.json().get("message", {}).get("content", answer)
            translated = answer != raw_model_output
        questions_marker = re.search(r"offene\s+fragen\s*:", answer, re.I)
        if questions_marker:
            answer = answer[questions_marker.start():]
        mentioned_ips = _known_ips({"answer": answer})
        unsupported_ips = sorted(mentioned_ips - _known_ips(evidence))
        unsafe_certainty = bool(re.search(r"keine\s+(?:offensichtlichen\s+)?(?:anomal|bedroh|angriff)", answer.lower()))
        structure_ok = bool(questions_marker)
        grounded = bool(answer.strip()) and not unsupported_ips and not unsafe_certainty and structure_ok
        model_assessment = answer if grounded else "Verworfen: Die Modellformulierung hielt das erlaubte Format für offene Fragen nicht ein."
        verified_answer = "Verifizierte lokale Fakten:\n" + "\n".join(f"- {fact}" for fact in facts)
        return {
            "answer": verified_answer,
            "model_assessment": model_assessment,
            "raw_model_output": raw_model_output,
            "localized_model_output": answer,
            "facts": facts,
            "evidence": evidence,
            "mode": "local-llm" if grounded else "guarded-local-llm",
            "model": model,
            "model_identity": model_identity,
            "quality": {
                "passed_guard": grounded,
                "validation_scope": "model output is restricted to open questions; factual answer is deterministic",
                "unsupported_ips": unsupported_ips,
                "unsafe_certainty": unsafe_certainty,
                "structure_ok": structure_ok,
                "language": "de",
                "translated": translated,
                "raw_output_preserved": True,
                "context_truncated": bool(model_evidence.get("model_context_truncated")),
                "separation": ["observed", "derived", "model_questions", "unknown"],
            },
        }
    except Exception as exc:
        return {"answer": f"Das lokale Modell ist ausgefallen ({type(exc).__name__}).\n" + "\n".join(f"- {fact}" for fact in facts), "facts": facts, "evidence": evidence, "mode": "deterministic-fallback", "quality": {"grounded": True, "language": "de", "model_claims": False}}
