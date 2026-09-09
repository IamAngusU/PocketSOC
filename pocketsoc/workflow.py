from __future__ import annotations

import json
import re
import statistics
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

from .config import Settings
from .db import Database, utcnow
from .inventory import ollama_status, select_ollama_model


class Condition(BaseModel):
    field: Literal["count", "unique_destinations", "bytes_sent", "dns_name_length", "interval_variance"]
    op: Literal["gt", "gte", "lt", "lte", "eq"]
    value: float = Field(ge=0, le=1_000_000_000)


class Action(BaseModel):
    type: Literal["create_observation", "create_alert", "add_tag", "propose_capture", "propose_firewall_block"]
    value: str | None = Field(default=None, max_length=200)
    ttl_seconds: int | None = Field(default=None, ge=60, le=86_400)


class GeneratedToolSpec(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,47}$")
    description: str = Field(min_length=8, max_length=300)
    event_type: Literal["network.packet", "network.connection", "dns.query", "endpoint.event"]
    group_by: Literal["device_key", "ip_dst", "dns_name", "protocol"]
    window_seconds: int = Field(ge=10, le=86_400)
    conditions: list[Condition] = Field(min_length=1, max_length=8)
    actions: list[Action] = Field(min_length=1, max_length=5)
    permissions: dict[str, Literal[False, "read_evidence_only", "propose_only"]]


def _fallback(prompt: str) -> dict[str, Any]:
    lower = prompt.lower()
    if "dns" in lower or "domain" in lower:
        return {
            "name": "dns_outlier_watch",
            "description": "Detects unusually frequent DNS activity in a bounded time window.",
            "event_type": "dns.query",
            "group_by": "dns_name",
            "window_seconds": 300,
            "conditions": [{"field": "count", "op": "gte", "value": 25}],
            "actions": [{"type": "create_observation", "value": "DNS frequency anomaly"}, {"type": "propose_capture", "ttl_seconds": 120}],
            "permissions": {"network": False, "filesystem": "read_evidence_only", "subprocess": False, "firewall": "propose_only"},
        }
    if "beacon" in lower or "regelmäßig" in lower or "period" in lower:
        return {
            "name": "periodic_connection_watch",
            "description": "Flags unusually stable connection intervals for analyst review.",
            "event_type": "network.connection",
            "group_by": "ip_dst",
            "window_seconds": 1800,
            "conditions": [{"field": "count", "op": "gte", "value": 8}, {"field": "interval_variance", "op": "lte", "value": 2.5}],
            "actions": [{"type": "create_observation", "value": "Possible periodic connection pattern"}],
            "permissions": {"network": False, "filesystem": "read_evidence_only", "subprocess": False, "firewall": "propose_only"},
        }
    return {
        "name": "new_destination_volume_watch",
        "description": "Reviews high-volume destination activity without executing host commands.",
        "event_type": "network.connection",
        "group_by": "ip_dst",
        "window_seconds": 900,
        "conditions": [{"field": "count", "op": "gte", "value": 20}],
        "actions": [{"type": "create_observation", "value": "High destination activity"}],
        "permissions": {"network": False, "filesystem": "read_evidence_only", "subprocess": False, "firewall": "propose_only"},
    }


class SafeToolLab:
    """Generates a constrained analyzer DSL; never executes generated Python or shell."""

    def __init__(self, settings: Settings, db: Database, firewall_service: Any | None = None):
        self.settings = settings
        self.db = db
        self.firewall_service = firewall_service
        self._last_model_identity: dict[str, Any] | None = None

    def _ask_ollama(self, prompt: str, errors: list[str] | None = None) -> dict[str, Any] | None:
        status = ollama_status(self.settings)
        if not status["available"] or not status["models"]:
            return None
        model, identity = select_ollama_model(status)
        if not model or not identity:
            return None
        self._last_model_identity = identity
        system = "You create defensive network analyzers in a tiny JSON DSL. Return JSON only. Never return code, commands, URLs, credentials, active exploitation, evasion, persistence, or unrestricted actions. Firewall is proposal-only. Required keys: name, description, event_type, group_by, window_seconds, conditions, actions, permissions. Allowed event_type: network.packet, network.connection, dns.query, endpoint.event. Allowed group_by: device_key, ip_dst, dns_name, protocol. Conditions use field=count|unique_destinations|bytes_sent|dns_name_length|interval_variance, op=gt|gte|lt|lte|eq, numeric value. Actions use type=create_observation|create_alert|add_tag|propose_capture|propose_firewall_block. permissions must be exactly network=false, filesystem=read_evidence_only, subprocess=false, firewall=propose_only."
        if errors:
            system += " Repair the previous invalid proposal. Validation errors: " + "; ".join(errors)[:1000]
        try:
            response = httpx.post(f"{status['url']}/api/chat", json={"model": model, "stream": False, "format": "json", "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}], "options": {"temperature": 0.1, "num_predict": 900}}, timeout=60)
            response.raise_for_status()
            content = response.json().get("message", {}).get("content", "")
            match = re.search(r"\{.*\}", content, re.S)
            return json.loads(match.group(0) if match else content)
        except Exception:
            return None

    def generate(self, prompt: str, use_llm: bool = True) -> dict[str, Any]:
        self._last_model_identity = None
        attempts: list[dict[str, Any]] = []
        candidate = self._ask_ollama(prompt) if use_llm else None
        if candidate is None:
            candidate = _fallback(prompt)
            attempts.append({"source": "deterministic-fallback", "valid": None})
        spec: GeneratedToolSpec | None = None
        for attempt in range(2):
            try:
                spec = GeneratedToolSpec.model_validate(candidate)
                attempts.append({"attempt": attempt + 1, "valid": True})
                break
            except ValidationError as exc:
                errors = [f"{'.'.join(map(str, item['loc']))}: {item['msg']}" for item in exc.errors()]
                attempts.append({"attempt": attempt + 1, "valid": False, "errors": errors})
                candidate = self._ask_ollama(prompt, errors) if use_llm and attempt == 0 else None
                if candidate is None:
                    candidate = _fallback(prompt)
        if spec is None:
            spec = GeneratedToolSpec.model_validate(_fallback(prompt))
            attempts.append({"source": "safe-final-fallback", "valid": True})
        test = self._smoke_test(spec)
        benchmark = self._benchmark(spec)
        tool_id = f"tool_{uuid.uuid4().hex}"
        status = "proposal_passed" if test["passed"] else "proposal_failed"
        self.db.execute(
            "INSERT INTO generated_tools(id,name,prompt,version,status,spec_json,validation_json,created_at,lineage_id,parent_id,score_json,activated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (tool_id, spec.name, prompt, 1, status, spec.model_dump_json(), json.dumps({"attempts": attempts, "test": test, "model_identity": self._last_model_identity}), utcnow(), tool_id, None, json.dumps(benchmark), None),
        )
        self._record_evaluation(tool_id, benchmark, "initial_proposal")
        self.db.audit("tool_lab.generate", status, target=tool_id, detail={"name": spec.name, "attempts": attempts})
        return {"id": tool_id, "status": status, "spec": spec.model_dump(), "validation": {"attempts": attempts, "test": test, "model_identity": self._last_model_identity}, "benchmark": benchmark, "activation": "Initial proposals require review. Later versions are promoted only after an objective benchmark improvement."}

    @staticmethod
    def _smoke_test(spec: GeneratedToolSpec) -> dict[str, Any]:
        fixture = {"count": 30.0, "unique_destinations": 4.0, "bytes_sent": 1024.0, "dns_name_length": 18.0, "interval_variance": 1.2}
        checks = []
        for condition in spec.conditions:
            left = fixture[condition.field]
            right = condition.value
            passed = {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right, "eq": left == right}[condition.op]
            checks.append({"field": condition.field, "left": left, "op": condition.op, "right": right, "passed": passed})
        permissions_ok = spec.permissions == {"network": False, "filesystem": "read_evidence_only", "subprocess": False, "firewall": "propose_only"}
        return {"passed": permissions_ok and bool(checks), "permissions_ok": permissions_ok, "fixture_checks": checks, "note": "Conditions may intentionally be false; execution and permission checks must pass."}

    @staticmethod
    def _matches_metrics(spec: GeneratedToolSpec, metrics: dict[str, float]) -> bool:
        for condition in spec.conditions:
            left, right = metrics[condition.field], condition.value
            if not {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right, "eq": left == right}[condition.op]:
                return False
        return True

    def _benchmark(self, spec: GeneratedToolSpec) -> dict[str, Any]:
        """A small labeled regression corpus catches behavioral and permission regressions."""
        baseline = {"count": 4.0, "unique_destinations": 2.0, "bytes_sent": 512.0, "dns_name_length": 12.0, "interval_variance": 80.0}
        suspicious = {"count": 60.0, "unique_destinations": 45.0, "bytes_sent": 8_000_000.0, "dns_name_length": 70.0, "interval_variance": 0.2}
        expected = [False, True]
        actual = [self._matches_metrics(spec, baseline), self._matches_metrics(spec, suspicious)]
        tp = int(actual[1]); fp = int(actual[0]); fn = int(not actual[1]); tn = int(not actual[0])
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        permissions_ok = spec.permissions == {"network": False, "filesystem": "read_evidence_only", "subprocess": False, "firewall": "propose_only"}
        score = round((f1 * 0.9 + (0.1 if permissions_ok else 0.0)), 4)
        return {"corpus": "local-synthetic-regression-v1", "expected": expected, "actual": actual, "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}, "precision": precision, "recall": recall, "f1": f1, "permissions_ok": permissions_ok, "score": score, "limitations": "Synthetic fixtures detect regressions; they do not establish real-world detection accuracy."}

    def _record_evaluation(self, tool_id: str, benchmark: dict[str, Any], decision: str) -> None:
        self.db.execute("INSERT INTO tool_evaluations(id,tool_id,ts,corpus,metrics_json,decision) VALUES(?,?,?,?,?,?)", (f"eval_{uuid.uuid4().hex}", tool_id, utcnow(), benchmark["corpus"], json.dumps(benchmark), decision))

    def activate(self, tool_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM generated_tools WHERE id=?", (tool_id,))
        if not row:
            raise ValueError("Generated tool not found")
        spec = GeneratedToolSpec.model_validate_json(row["spec_json"])
        benchmark = self._benchmark(spec)
        if not benchmark["permissions_ok"] or benchmark["score"] < 0.9:
            raise ValueError("Analyzer did not pass the activation benchmark")
        with self.db.tx() as conn:
            conn.execute("UPDATE generated_tools SET status='retired' WHERE lineage_id=? AND status='active'", (row.get("lineage_id") or row["id"],))
            conn.execute("UPDATE generated_tools SET status='active',activated_at=?,score_json=? WHERE id=?", (utcnow(), json.dumps(benchmark), tool_id))
        self._record_evaluation(tool_id, benchmark, "manual_activation")
        self.db.audit("tool_lab.activate", "ok", target=tool_id, detail={"score": benchmark["score"]})
        return self.describe(tool_id)

    def describe(self, tool_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM generated_tools WHERE id=?", (tool_id,))
        if not row:
            raise ValueError("Generated tool not found")
        row["spec"] = json.loads(row["spec_json"])
        row["validation"] = json.loads(row["validation_json"])
        row["score"] = json.loads(row.get("score_json") or "{}")
        row["evaluations"] = self.db.rows("SELECT id,ts,corpus,metrics_json,decision FROM tool_evaluations WHERE tool_id=? ORDER BY ts DESC LIMIT 20", (tool_id,))
        return row

    def evolve(self, tool_id: str, use_llm: bool = True) -> dict[str, Any]:
        parent = self.db.one("SELECT * FROM generated_tools WHERE id=?", (tool_id,))
        if not parent:
            raise ValueError("Generated tool not found")
        parent_spec = GeneratedToolSpec.model_validate_json(parent["spec_json"])
        parent_score = self._benchmark(parent_spec)
        prompt = "Improve this defensive analyzer only if you can reduce false positives without losing the intended detection. Keep the same safe DSL and permissions. Original request: " + parent["prompt"] + "\nCurrent spec: " + parent_spec.model_dump_json()
        candidate = self._ask_ollama(prompt) if use_llm else None
        try:
            candidate_spec = GeneratedToolSpec.model_validate(candidate) if candidate else parent_spec.model_copy(deep=True)
        except ValidationError:
            candidate_spec = parent_spec.model_copy(deep=True)
        candidate_spec = candidate_spec.model_copy(update={"name": parent_spec.name})
        candidate_smoke = self._smoke_test(candidate_spec)
        candidate_score = self._benchmark(candidate_spec)
        child_id = f"tool_{uuid.uuid4().hex}"
        lineage_id = parent.get("lineage_id") or parent["id"]
        latest = self.db.one("SELECT MAX(version) AS version FROM generated_tools WHERE lineage_id=?", (lineage_id,))
        version = int(latest["version"] or parent["version"]) + 1
        objectively_better = candidate_smoke["passed"] and candidate_score["score"] > parent_score["score"]
        child_status = "active" if objectively_better else "candidate_not_better"
        with self.db.tx() as conn:
            if objectively_better:
                conn.execute("UPDATE generated_tools SET status='retired' WHERE lineage_id=? AND status='active'", (lineage_id,))
            conn.execute(
                "INSERT INTO generated_tools(id,name,prompt,version,status,spec_json,validation_json,created_at,lineage_id,parent_id,score_json,activated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (child_id, candidate_spec.name, parent["prompt"], version, child_status, candidate_spec.model_dump_json(), json.dumps({"test": candidate_smoke}), utcnow(), lineage_id, parent["id"], json.dumps(candidate_score), utcnow() if objectively_better else None),
            )
        decision = "promoted" if objectively_better else "kept_for_history_not_better"
        self._record_evaluation(child_id, candidate_score, decision)
        self.db.audit("tool_lab.evolve", decision, target=child_id, detail={"parent": parent["id"], "parent_score": parent_score["score"], "candidate_score": candidate_score["score"]})
        return {"parent_id": parent["id"], "candidate_id": child_id, "version": version, "promoted": objectively_better, "decision": decision, "comparison": {"parent": parent_score, "candidate": candidate_score}, "history_preserved": True}

    def run_proposal(self, tool_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM generated_tools WHERE id=?", (tool_id,))
        if not row:
            raise ValueError("Generated tool not found")
        spec = GeneratedToolSpec.model_validate_json(row["spec_json"])
        source_type = "network.packet" if spec.event_type in {"network.packet", "network.connection", "dns.query"} else "endpoint.event"
        source_rows = self.db.rows("SELECT id,ts,device_key,data_json,evidence_ref FROM events WHERE event_type=? ORDER BY ts DESC LIMIT 5000", (source_type,))
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=spec.window_seconds)
        groups: dict[str, dict[str, Any]] = {}
        for source in source_rows:
            try:
                ts = datetime.fromisoformat(str(source["ts"]).replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < cutoff:
                    continue
                data = json.loads(source["data_json"])
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
            key_map = {
                "device_key": data.get("device_key") or source.get("device_key"),
                "ip_dst": data.get("peer") or data.get("ip_dst"),
                "dns_name": data.get("dns_name"),
                "protocol": data.get("protocol"),
            }
            group_key = str(key_map.get(spec.group_by) or "")
            if not group_key:
                continue
            group = groups.setdefault(group_key, {"count": 0.0, "destinations": set(), "bytes_sent": 0.0, "dns_name_length": 0.0, "timestamps": [], "event_ids": [], "evidence_refs": set()})
            group["count"] += 1
            if data.get("peer"):
                group["destinations"].add(data["peer"])
            if data.get("direction") == "outbound":
                try:
                    group["bytes_sent"] += float(data.get("frame_length", 0))
                except (TypeError, ValueError):
                    pass
            group["dns_name_length"] = max(group["dns_name_length"], float(len(data.get("dns_name", ""))))
            group["timestamps"].append(ts.timestamp())
            if len(group["event_ids"]) < 20:
                group["event_ids"].append(source["id"])
            if source.get("evidence_ref"):
                group["evidence_refs"].add(source["evidence_ref"])

        matches = []
        for group_key, group in groups.items():
            ordered = sorted(group["timestamps"])
            intervals = [b - a for a, b in zip(ordered, ordered[1:])]
            metrics = {
                "count": group["count"],
                "unique_destinations": float(len(group["destinations"])),
                "bytes_sent": group["bytes_sent"],
                "dns_name_length": group["dns_name_length"],
                "interval_variance": statistics.pvariance(intervals) if len(intervals) >= 2 else 1_000_000_000.0,
            }
            checks = []
            for condition in spec.conditions:
                left, right = metrics[condition.field], condition.value
                passed = {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right, "eq": left == right}[condition.op]
                checks.append({"field": condition.field, "op": condition.op, "expected": right, "actual": left, "passed": passed})
            if not all(item["passed"] for item in checks):
                continue
            actions = []
            marker = f"[{tool_id}:{group_key}]"
            for action in spec.actions:
                record = {"type": action.type, "value": action.value, "ttl_seconds": action.ttl_seconds, "effect": "proposal_only" if action.type.startswith("propose_") else "recorded"}
                actions.append(record)
                if action.type in {"create_observation", "create_alert", "propose_capture", "propose_firewall_block"}:
                    existing = self.db.one("SELECT id FROM observations WHERE kind='generated_tool' AND detail LIKE ? LIMIT 1", (f"{marker}%",))
                    if not existing:
                        title = action.value or action.type.replace("_", " ").title()
                        detail = f"{marker} Analyzer {spec.name} matched group {group_key}. Action remains local and {'requires approval' if action.type.startswith('propose_') else 'was recorded as an observation'}."
                        self.db.execute("INSERT INTO observations(id,ts,kind,device_key,title,detail,confidence,state,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)", (f"obs_{uuid.uuid4().hex}", utcnow(), "generated_tool", group_key, title, detail, 1.0, "open", json.dumps(sorted(group["evidence_refs"]))))
                        if action.type == "propose_firewall_block" and self.firewall_service:
                            binding = self.db.one("SELECT id FROM firewall_bindings WHERE status='ready' ORDER BY created_at LIMIT 1")
                            if binding:
                                try:
                                    proposal = self.firewall_service.propose_block(binding["id"], group_key, title, action.ttl_seconds, sorted(group["evidence_refs"]))
                                    record["proposal_id"] = proposal["id"]
                                except ValueError as exc:
                                    record["proposal_error"] = str(exc)
            matches.append({"group": group_key, "metrics": metrics, "checks": checks, "event_ids": group["event_ids"], "evidence_refs": sorted(group["evidence_refs"]), "actions": actions})
        self.db.audit("tool_lab.run", "ok", target=tool_id, detail={"source_rows": len(source_rows), "groups": len(groups), "matches": len(matches)})
        return {"tool_id": tool_id, "name": spec.name, "source_rows": len(source_rows), "groups_evaluated": len(groups), "matches": matches, "permissions": spec.permissions, "note": "No generated host code, network call, subprocess or firewall change was executed."}
