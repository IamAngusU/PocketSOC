from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

from .config import Settings
from .db import Database, utcnow
from .inventory import ollama_status, select_ollama_model


NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
SAFE_TEXT_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")


class FilterError(ValueError):
    pass


class FilterService:
    """Versioned Wireshark filters, rendered from typed parameters and tested by Wireshark itself."""

    KINDS = {"wireshark_display", "capture_bpf"}

    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db

    @staticmethod
    def _value(definition: dict[str, Any], supplied: Any) -> str:
        kind = definition.get("type")
        value = supplied if supplied is not None else definition.get("default")
        if value is None:
            raise FilterError("Every filter parameter needs a value or default")
        try:
            if kind == "ip":
                return str(ipaddress.ip_address(str(value)))
            if kind == "cidr":
                return str(ipaddress.ip_network(str(value), strict=False))
            if kind == "port":
                number = int(value)
                if not 1 <= number <= 65535:
                    raise FilterError("Port parameters must be between 1 and 65535")
                return str(number)
            if kind == "integer":
                number = int(value)
                minimum, maximum = int(definition.get("min", 0)), int(definition.get("max", 1_000_000))
                if not minimum <= number <= maximum:
                    raise FilterError(f"Integer parameter must be between {minimum} and {maximum}")
                return str(number)
        except (ValueError, TypeError) as exc:
            raise FilterError(f"Invalid {kind} parameter value") from exc
        if kind == "enum":
            choices = [str(item) for item in definition.get("choices", [])]
            if str(value) not in choices or not choices:
                raise FilterError("Enum value is not in the declared choices")
            return str(value)
        if kind in {"hostname", "text"} and SAFE_TEXT_RE.fullmatch(str(value)):
            return str(value)
        raise FilterError(f"Unsupported or unsafe parameter type/value: {kind}")

    def render(self, expression_template: str, parameters: dict[str, Any], values: dict[str, Any] | None = None) -> str:
        if not expression_template or len(expression_template) > 1000 or any(char in expression_template for char in "\r\n\x00"):
            raise FilterError("Filter expression must be a single line of at most 1000 characters")
        placeholders = set(PLACEHOLDER_RE.findall(expression_template))
        if placeholders != set(parameters):
            missing = sorted(placeholders - set(parameters))
            unused = sorted(set(parameters) - placeholders)
            raise FilterError(f"Parameter/template mismatch (missing={missing}, unused={unused})")
        rendered = expression_template
        values = values or {}
        for name in sorted(placeholders):
            definition = parameters[name]
            if not isinstance(definition, dict):
                raise FilterError("Parameter definitions must be objects")
            rendered = rendered.replace("{" + name + "}", self._value(definition, values.get(name)))
        return rendered

    def _empty_pcap(self) -> Path:
        path = self.settings.artifacts_dir / "validator-empty.pcap"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
        return path

    def validate(self, kind: str, expression_template: str, parameters: dict[str, Any]) -> dict[str, Any]:
        if kind not in self.KINDS:
            raise FilterError("Unsupported filter kind")
        rendered = self.render(expression_template, parameters)
        started = time.perf_counter()
        if kind == "wireshark_display":
            executable = self.settings.tshark_path
            argv = [str(executable), "-n", "-r", str(self._empty_pcap()), "-Y", rendered, "-c", "1"]
        else:
            executable = self.settings.dumpcap_path
            argv = [str(executable), "-d", "-f", rendered]
        if not executable.exists():
            return {"passed": False, "engine": executable.name, "rendered": rendered, "error": "Wireshark engine unavailable"}
        try:
            result = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            passed = result.returncode == 0
            return {
                "passed": passed,
                "engine": executable.name,
                "rendered": rendered,
                "elapsed_ms": round((time.perf_counter() - started) * 1000),
                "exit_code": result.returncode,
                "diagnostic": (result.stderr or result.stdout)[-2000:],
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"passed": False, "engine": executable.name, "rendered": rendered, "error": f"{type(exc).__name__}: {exc}"}

    def create(self, name: str, kind: str, expression_template: str, parameters: dict[str, Any], *, created_by: str = "local-user", activate: bool = True) -> dict[str, Any]:
        if not NAME_RE.fullmatch(name):
            raise FilterError("Name must be lower_snake_case and 3-64 characters")
        validation = self.validate(kind, expression_template, parameters)
        previous = self.db.one("SELECT * FROM filters WHERE name=? ORDER BY version DESC LIMIT 1", (name,))
        version = int(previous["version"]) + 1 if previous else 1
        filter_id = f"flt_{uuid.uuid4().hex}"
        lineage_id = previous["lineage_id"] if previous else filter_id
        status = "active" if activate and validation["passed"] else ("candidate" if validation["passed"] else "rejected")
        activated_at = utcnow() if status == "active" else None
        with self.db.tx() as conn:
            if status == "active":
                conn.execute("UPDATE filters SET status='retired' WHERE name=? AND status='active'", (name,))
            conn.execute(
                "INSERT INTO filters(id,lineage_id,parent_id,name,version,kind,expression_template,parameters_json,status,validation_json,score_json,created_by,created_at,activated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (filter_id, lineage_id, previous["id"] if previous else None, name, version, kind, expression_template, json.dumps(parameters, ensure_ascii=False), status, json.dumps(validation, ensure_ascii=False), "{}", created_by, utcnow(), activated_at),
            )
        self.db.audit("filter.create", status, target=filter_id, detail={"name": name, "version": version, "kind": kind, "validation": validation})
        return self.get(filter_id)

    def get(self, filter_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM filters WHERE id=?", (filter_id,))
        if not row:
            raise FilterError("Filter not found")
        for source, target in (("parameters_json", "parameters"), ("validation_json", "validation"), ("score_json", "score")):
            row[target] = json.loads(row[source] or "{}")
        return row

    def list(self) -> list[dict[str, Any]]:
        return [self.get(row["id"]) for row in self.db.rows("SELECT id FROM filters ORDER BY created_at DESC LIMIT 200")]

    def activate(self, filter_id: str) -> dict[str, Any]:
        row = self.get(filter_id)
        validation = self.validate(row["kind"], row["expression_template"], row["parameters"])
        if not validation["passed"]:
            raise FilterError("Filter no longer passes the installed Wireshark validator")
        with self.db.tx() as conn:
            conn.execute("UPDATE filters SET status='retired' WHERE name=? AND status='active'", (row["name"],))
            conn.execute("UPDATE filters SET status='active',activated_at=?,validation_json=? WHERE id=?", (utcnow(), json.dumps(validation), filter_id))
        self.db.audit("filter.activate", "ok", target=filter_id, detail={"version": row["version"]})
        return self.get(filter_id)

    def test(self, filter_id: str, values: dict[str, Any] | None = None, capture_path: str | None = None) -> dict[str, Any]:
        row = self.get(filter_id)
        rendered = self.render(row["expression_template"], row["parameters"], values)
        validation = self.validate(row["kind"], row["expression_template"], {
            key: {**definition, "default": (values or {}).get(key, definition.get("default"))}
            for key, definition in row["parameters"].items()
        })
        result: dict[str, Any] = {"filter_id": filter_id, "rendered": rendered, "validation": validation, "matched_frames": None, "capture": None}
        capture = Path(capture_path).expanduser().resolve() if capture_path else next(iter(sorted(self.settings.captures_dir.glob("*.pcap*"), key=lambda item: item.stat().st_mtime, reverse=True)), None)
        if validation["passed"] and row["kind"] == "wireshark_display" and capture and capture.is_file():
            argv = [str(self.settings.tshark_path), "-n", "-r", str(capture), "-Y", rendered, "-T", "fields", "-e", "frame.number"]
            started = time.perf_counter()
            completed = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            result.update({"capture": str(capture), "matched_frames": len([line for line in completed.stdout.splitlines() if line.strip()]), "test_elapsed_ms": round((time.perf_counter() - started) * 1000), "test_exit_code": completed.returncode})
        self.db.execute("UPDATE filters SET score_json=? WHERE id=?", (json.dumps(result, ensure_ascii=False), filter_id))
        self.db.audit("filter.test", "ok" if validation["passed"] else "failed", target=filter_id, detail=result)
        return result

    def generate(self, prompt: str, use_llm: bool = True) -> dict[str, Any]:
        lower = prompt.lower()
        fallback: dict[str, Any]
        if "dns" in lower:
            fallback = {"name": "dns_queries", "kind": "wireshark_display", "expression_template": "dns.qry.name contains \"{term}\"", "parameters": {"term": {"type": "text", "default": "local"}}}
        elif "port" in lower:
            fallback = {"name": "tcp_port_focus", "kind": "wireshark_display", "expression_template": "tcp.port == {port}", "parameters": {"port": {"type": "port", "default": 443}}}
        else:
            fallback = {"name": "host_focus", "kind": "wireshark_display", "expression_template": "ip.addr == {host}", "parameters": {"host": {"type": "ip", "default": "192.168.2.1"}}}
        candidate = None
        model_identity = None
        if use_llm:
            status = ollama_status(self.settings)
            if status["available"] and status["models"]:
                model, model_identity = select_ollama_model(status)
                system = "Return JSON only for a defensive Wireshark filter. Keys: name, kind, expression_template, parameters. kind is wireshark_display or capture_bpf. Every adjustable value must be a {placeholder} with a matching typed parameter (ip,cidr,port,integer,enum,hostname,text) and safe default. No shell, code, URLs, credentials, payloads, evasion, exploitation, or destructive actions."
                try:
                    response = httpx.post(f"{status['url']}/api/chat", json={"model": model, "stream": False, "format": "json", "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}], "options": {"temperature": 0.05, "num_predict": 600}}, timeout=60)
                    response.raise_for_status()
                    candidate = json.loads(response.json().get("message", {}).get("content", "{}"))
                except Exception:
                    candidate = None
        candidate = candidate if isinstance(candidate, dict) else fallback
        try:
            result = self.create(str(candidate["name"]), str(candidate["kind"]), str(candidate["expression_template"]), dict(candidate.get("parameters") or {}), created_by="local-model" if candidate is not fallback else "deterministic-fallback")
            if model_identity and candidate is not fallback:
                validation = {**result["validation"], "model_identity": model_identity}
                self.db.execute("UPDATE filters SET validation_json=? WHERE id=?", (json.dumps(validation, ensure_ascii=False), result["id"]))
                result["validation"] = validation
            return result
        except (KeyError, TypeError, FilterError):
            return self.create(**fallback, created_by="safe-final-fallback")
