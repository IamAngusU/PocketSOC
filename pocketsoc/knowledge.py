from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .config import Settings
from .db import Database, utcnow


CORE_DOCS = (
    {
        "id": "pocketsoc-evidence-contract",
        "title": "PocketSOC evidence and claim contract",
        "body": "Observed claims come directly from decoded events. Derived claims are deterministic calculations over cited events. Hypotheses must include confidence, limitations, and alternative explanations. A network indicator is not proof of compromise. Firewall response requires a policy, bounded target, TTL, audit, connectivity check, and rollback.",
        "source_url": "local://pocketsoc/evidence-contract",
        "source_type": "local-policy",
        "revision": "1",
    },
    {
        "id": "pocketsoc-replay-limitations",
        "title": "Replay detection limitations",
        "body": "TCP retransmission, duplicate acknowledgements, Wi-Fi retries, repeated application transactions, and a cryptographic replay are different events. Reliable replay detection usually needs protocol nonces, transaction identifiers, timestamps, authenticated-message fields, or server-side state. Encrypted traffic often requires endpoint or application logs. Report possible replay indicators, never a confirmed replay without the required evidence.",
        "source_url": "local://pocketsoc/replay-limitations",
        "source_type": "local-policy",
        "revision": "1",
    },
)


class KnowledgeIndex:
    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db

    def upsert(self, document: dict[str, Any]) -> None:
        body = str(document["body"])
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO knowledge_documents(id,title,body,source_url,source_type,revision,sha256,metadata_json,indexed_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,body=excluded.body,source_url=excluded.source_url,source_type=excluded.source_type,revision=excluded.revision,sha256=excluded.sha256,metadata_json=excluded.metadata_json,indexed_at=excluded.indexed_at",
                (document["id"], document["title"], body, document["source_url"], document["source_type"], document["revision"], digest, json.dumps(document.get("metadata", {}), ensure_ascii=False), utcnow()),
            )
            conn.execute("DELETE FROM knowledge_fts WHERE id=?", (document["id"],))
            conn.execute("INSERT INTO knowledge_fts(id,title,body) VALUES(?,?,?)", (document["id"], document["title"], body))

    def ensure_core(self) -> None:
        for document in CORE_DOCS:
            self.upsert(document)

    def import_attack_stix(self, raw_path: str, revision: str) -> dict[str, Any]:
        path = Path(raw_path).expanduser().resolve()
        root = self.settings.datasets_dir.resolve()
        if not path.is_relative_to(root) or not path.is_file() or path.suffix.lower() != ".json":
            raise ValueError(f"ATT&CK STIX must be a JSON file below {root}")
        if path.stat().st_size > 250 * 1024**2:
            raise ValueError("ATT&CK bundle exceeds the 250 MiB import limit")
        payload = json.loads(path.read_text(encoding="utf-8"))
        objects = payload.get("objects", [])
        imported = 0
        types: dict[str, int] = {}
        for item in objects:
            if item.get("revoked") or item.get("x_mitre_deprecated") or item.get("type") not in {"attack-pattern", "course-of-action", "x-mitre-data-component", "x-mitre-data-source"}:
                continue
            refs = item.get("external_references") or []
            attack_ref = next((ref for ref in refs if ref.get("source_name") == "mitre-attack"), {})
            external_id = attack_ref.get("external_id")
            name = item.get("name") or external_id or item.get("id")
            description = re.sub(r"\[(.*?)\]\([^)]*\)", r"\1", item.get("description") or "")
            if not description and item.get("type") not in {"x-mitre-data-component", "x-mitre-data-source"}:
                continue
            document = {
                "id": f"attack-{external_id or item['id']}",
                "title": f"{external_id + ' · ' if external_id else ''}{name}",
                "body": description or f"MITRE ATT&CK data object: {name}",
                "source_url": attack_ref.get("url") or "https://attack.mitre.org/",
                "source_type": f"mitre-attack-{item['type']}",
                "revision": revision,
                "metadata": {"stix_id": item.get("id"), "modified": item.get("modified"), "kill_chain_phases": item.get("kill_chain_phases", [])},
            }
            self.upsert(document)
            imported += 1
            types[item["type"]] = types.get(item["type"], 0) + 1
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.db.audit("knowledge.attack.import", "ok", target=str(path), detail={"revision": revision, "documents": imported, "sha256": digest})
        return {"path": str(path), "revision": revision, "sha256": digest, "documents_imported": imported, "types": types}

    def search(self, query: str, limit: int = 8) -> list[dict[str, Any]]:
        terms = [term.lower() for term in re.findall(r"[A-Za-zÄÖÜäöüß0-9_.-]{3,}", query) if term.lower() not in {"und", "oder", "the", "and", "was", "wie", "eine", "einer"}]
        if not terms:
            return []
        match = " OR ".join(f'"{term.replace(chr(34), "")}"' for term in terms[:16])
        rows = self.db.rows(
            "SELECT d.id,d.title,d.source_url,d.source_type,d.revision,d.sha256,d.metadata_json,snippet(knowledge_fts,2,'[',']',' … ',20) AS excerpt,bm25(knowledge_fts,5.0,1.0) AS rank FROM knowledge_fts JOIN knowledge_documents d ON d.id=knowledge_fts.id WHERE knowledge_fts MATCH ? ORDER BY rank LIMIT ?",
            (match, max(1, min(limit, 20))),
        )
        for row in rows:
            row["metadata"] = json.loads(row.pop("metadata_json") or "{}")
            row["relevance"] = round(1 / (1 + abs(float(row.pop("rank")))), 5)
        return rows

    def stats(self) -> dict[str, Any]:
        return {
            "documents": self.db.one("SELECT COUNT(*) AS n FROM knowledge_documents")["n"],
            "by_source": self.db.rows("SELECT source_type,COUNT(*) AS documents FROM knowledge_documents GROUP BY source_type ORDER BY documents DESC"),
            "engine": "SQLite FTS5/BM25",
            "raw_packet_vectors": False,
            "policy": "Structured evidence stays in SQL; vectors/BM25 are for knowledge and prose only.",
        }
