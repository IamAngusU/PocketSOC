from __future__ import annotations

import ipaddress
import hashlib
import json
import re
import shutil
import subprocess
import uuid
import ctypes
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from .db import Database, utcnow


class FirewallError(ValueError):
    pass


ADAPTERS: dict[str, dict[str, Any]] = {
    "windows": {"label": "Windows Defender Firewall", "local": True, "proposal_formats": ["powershell", "structured"]},
    "opnsense": {"label": "OPNsense Automation API", "local": False, "proposal_formats": ["api_payload"]},
    "openwrt": {"label": "OpenWrt firewall4", "local": False, "proposal_formats": ["uci_model"]},
}


def _powershell_json(script: str) -> Any:
    executable = shutil.which("pwsh") or shutil.which("powershell") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    try:
        result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode != 0 or not result.stdout.strip():
            return []
        return json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []


class FirewallService:
    """Review-gated firewall bindings with exact-payload confirmation and rollback."""

    def __init__(self, db: Database):
        self.db = db
        self._expiry_failures: set[str] = set()

    def ensure_local_binding(self) -> None:
        if not self.db.one("SELECT 1 AS ok FROM firewall_bindings WHERE id='fw_windows_local'"):
            self.db.execute(
                "INSERT INTO firewall_bindings(id,name,adapter,endpoint,secret_ref,status,capabilities_json,last_checked_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("fw_windows_local", "Dieser Windows-PC", "windows", "local://windows-firewall", None, "ready", json.dumps(ADAPTERS["windows"]), utcnow(), utcnow()),
            )
        self.db.execute(
            "INSERT INTO response_policies(id,name,enabled,mode,min_confidence,max_actions_per_hour,ttl_seconds,allowed_rules_json,binding_id,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,mode=excluded.mode,min_confidence=excluded.min_confidence,max_actions_per_hour=excluded.max_actions_per_hour,ttl_seconds=excluded.ttl_seconds,binding_id=excluded.binding_id,updated_at=excluded.updated_at",
            ("response_default_review", "Manual reviewed response", 1, "reviewed_apply", 0.95, 3, 3600, "[]", "fw_windows_local", utcnow()),
        )

    def list_policies(self) -> list[dict[str, Any]]:
        rows = self.db.rows("SELECT * FROM response_policies ORDER BY updated_at DESC")
        for row in rows:
            row["enabled"] = bool(row["enabled"])
            row["allowed_rules"] = json.loads(row.pop("allowed_rules_json") or "[]")
        return rows

    @staticmethod
    def adapters() -> list[dict[str, Any]]:
        return [{"id": key, **value, "mutation_policy": "review_hash_required" if key == "windows" else "proposal_only"} for key, value in ADAPTERS.items()]

    @staticmethod
    def _endpoint(adapter: str, endpoint: str | None) -> str:
        if adapter == "windows":
            return "local://windows-firewall"
        parsed = urlparse(endpoint or "")
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise FirewallError("Remote firewall endpoints must be credential-free HTTPS URLs")
        host = parsed.hostname
        try:
            address = ipaddress.ip_address(host)
            if not (address.is_private or address.is_link_local):
                raise FirewallError("Remote firewall endpoint must be on an authorized private network")
        except ValueError:
            if not (host.endswith(".local") or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host)):
                raise FirewallError("Invalid firewall hostname")
        return endpoint or ""

    def create_binding(self, name: str, adapter: str, endpoint: str | None, secret_ref: str | None) -> dict[str, Any]:
        if adapter not in ADAPTERS:
            raise FirewallError("Unsupported firewall adapter")
        if not name or len(name) > 80:
            raise FirewallError("Binding name must be 1-80 characters")
        safe_endpoint = self._endpoint(adapter, endpoint)
        if secret_ref and (len(secret_ref) > 200 or not re.fullmatch(r"(?:windows-credential|keyring):[A-Za-z0-9_.:-]+", secret_ref)):
            raise FirewallError("Only an OS keychain reference may be stored, never a secret")
        binding_id = f"fw_{uuid.uuid4().hex}"
        status = "ready" if adapter == "windows" else "configured_unverified"
        self.db.execute("INSERT INTO firewall_bindings(id,name,adapter,endpoint,secret_ref,status,capabilities_json,last_checked_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (binding_id, name, adapter, safe_endpoint, secret_ref, status, json.dumps(ADAPTERS[adapter]), None, utcnow()))
        self.db.audit("firewall.binding.create", status, target=binding_id, detail={"adapter": adapter, "endpoint": safe_endpoint, "secret_ref_present": bool(secret_ref)})
        return self.get_binding(binding_id)

    def get_binding(self, binding_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT id,name,adapter,endpoint,secret_ref,status,capabilities_json,last_checked_at,created_at FROM firewall_bindings WHERE id=?", (binding_id,))
        if not row:
            raise FirewallError("Firewall binding not found")
        row["capabilities"] = json.loads(row.pop("capabilities_json") or "{}")
        row["has_secret_reference"] = bool(row.pop("secret_ref"))
        return row

    def list_bindings(self) -> list[dict[str, Any]]:
        return [self.get_binding(row["id"]) for row in self.db.rows("SELECT id FROM firewall_bindings ORDER BY created_at")]

    def probe(self, binding_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM firewall_bindings WHERE id=?", (binding_id,))
        if not row:
            raise FirewallError("Firewall binding not found")
        if row["adapter"] == "windows":
            profiles = _powershell_json("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked,LogFileName | ConvertTo-Json -Compress")
            adapters = _powershell_json("Get-NetConnectionProfile | Select-Object InterfaceAlias,NetworkCategory,IPv4Connectivity,IPv6Connectivity | ConvertTo-Json -Compress")
            status = "ready" if profiles else "degraded"
            result = {"status": status, "profiles": profiles, "network_profiles": adapters, "mutation_policy": "review_hash_required", "automatic_apply": False}
        else:
            status = "configured_unverified"
            result = {"status": status, "endpoint": row["endpoint"], "secret_reference_present": bool(row["secret_ref"]), "note": "No credential was resolved and no remote request was sent. Add a keychain resolver before capability testing."}
        self.db.execute("UPDATE firewall_bindings SET status=?,last_checked_at=? WHERE id=?", (status, utcnow(), binding_id))
        self.db.audit("firewall.binding.probe", status, target=binding_id, detail=result)
        return result

    @staticmethod
    def _safe_target(target: str) -> str:
        try:
            address = ipaddress.ip_address(target)
        except ValueError as exc:
            raise FirewallError("Firewall proposals require a literal IP address") from exc
        if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
            raise FirewallError("Loopback, link-local, multicast and unspecified addresses are protected")
        return str(address)

    @staticmethod
    def _protected_local_addresses() -> set[str]:
        data = _powershell_json("Get-NetIPConfiguration | Where-Object {$_.IPv4Address} | Select-Object @{n='Local';e={$_.IPv4Address.IPAddress -join ','}},@{n='Gateway';e={$_.IPv4DefaultGateway.NextHop -join ','}},@{n='DNS';e={$_.DNSServer.ServerAddresses -join ','}} | ConvertTo-Json -Compress")
        if isinstance(data, dict):
            data = [data]
        protected: set[str] = set()
        for item in data or []:
            for key in ("Local", "Gateway", "DNS"):
                for value in str(item.get(key) or "").split(","):
                    try:
                        protected.add(str(ipaddress.ip_address(value.strip())))
                    except ValueError:
                        pass
        return protected

    def propose_block(self, binding_id: str, target: str, reason: str, ttl_seconds: int | None, evidence: list[str] | None = None) -> dict[str, Any]:
        binding = self.db.one("SELECT * FROM firewall_bindings WHERE id=?", (binding_id,))
        if not binding:
            raise FirewallError("Firewall binding not found")
        safe_target = self._safe_target(target)
        if binding["adapter"] == "windows" and safe_target in self._protected_local_addresses():
            raise FirewallError("The local host, active gateway and DNS servers are protected targets")
        if not reason or len(reason) > 500:
            raise FirewallError("A concise reason is required")
        if ttl_seconds is not None and not 300 <= ttl_seconds <= 604800:
            raise FirewallError("TTL must be between 5 minutes and 7 days")
        proposal_id = f"fwp_{uuid.uuid4().hex}"
        rule_name = f"PocketSOC-{proposal_id[-12:]}"
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat() if ttl_seconds else None
        if binding["adapter"] == "windows":
            payload = {"adapter": "windows", "cmdlet": "New-NetFirewallRule", "parameters": {"DisplayName": rule_name, "Direction": "Outbound", "Action": "Block", "RemoteAddress": safe_target, "Profile": "Any"}, "preview": f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Outbound -Action Block -RemoteAddress {safe_target} -Profile Any"}
            rollback = {"cmdlet": "Remove-NetFirewallRule", "parameters": {"DisplayName": rule_name}, "preview": f"Remove-NetFirewallRule -DisplayName '{rule_name}'"}
        elif binding["adapter"] == "opnsense":
            payload = {"adapter": "opnsense", "operation": "firewall.alias.add_item + firewall.filter.add_rule", "alias": {"name": rule_name.replace("-", "_"), "type": "host", "content": safe_target}, "rule": {"action": "block", "direction": "out", "description": rule_name, "enabled": "1"}, "apply": False}
            rollback = {"operation": "delete created automation rule and alias, then apply", "requires_returned_uuids": True}
        else:
            payload = {"adapter": "openwrt", "uci_model": {"type": "rule", "name": rule_name, "src": "lan", "dest": "wan", "dest_ip": safe_target, "target": "REJECT", "enabled": "1"}, "apply": False}
            rollback = {"operation": "delete the exact generated UCI section and reload firewall4", "requires_section_id": True}
        payload["expires_at"] = expires_at
        with self.db.tx() as conn:
            conn.execute("INSERT INTO firewall_proposals(id,binding_id,action,target,reason,ttl_seconds,status,payload_json,rollback_json,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (proposal_id, binding_id, "block", safe_target, reason, ttl_seconds, "pending_review", json.dumps(payload, ensure_ascii=False), json.dumps(rollback, ensure_ascii=False), json.dumps(evidence or []), utcnow()))
        self.db.audit("firewall.proposal.create", "pending_review", target=proposal_id, detail={"binding": binding_id, "target": safe_target, "ttl_seconds": ttl_seconds})
        return self.get_proposal(proposal_id)

    def get_proposal(self, proposal_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM firewall_proposals WHERE id=?", (proposal_id,))
        if not row:
            raise FirewallError("Firewall proposal not found")
        raw_payload = row.pop("payload_json")
        row["confirmation_hash"] = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
        row["payload"] = json.loads(raw_payload)
        row["rollback"] = json.loads(row.pop("rollback_json"))
        row["evidence"] = json.loads(row.pop("evidence_json"))
        return row

    def list_proposals(self) -> list[dict[str, Any]]:
        return [self.get_proposal(row["id"]) for row in self.db.rows("SELECT id FROM firewall_proposals ORDER BY created_at DESC LIMIT 200")]

    @staticmethod
    def _is_admin() -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def apply_proposal(self, proposal_id: str, confirmation_hash: str) -> dict[str, Any]:
        row = self.db.one("SELECT p.*,b.adapter FROM firewall_proposals p JOIN firewall_bindings b ON b.id=p.binding_id WHERE p.id=?", (proposal_id,))
        if not row:
            raise FirewallError("Firewall proposal not found")
        if row["status"] != "pending_review":
            raise FirewallError("Only pending proposals can be applied")
        expected = hashlib.sha256(row["payload_json"].encode("utf-8")).hexdigest()
        if confirmation_hash != expected:
            raise FirewallError("Confirmation hash does not match the reviewed proposal")
        if row["adapter"] != "windows":
            raise FirewallError("This adapter has no credentialed apply driver yet")
        policy = self.db.one("SELECT * FROM response_policies WHERE binding_id=? AND enabled=1 ORDER BY updated_at DESC LIMIT 1", (row["binding_id"],))
        if not policy or policy["mode"] != "reviewed_apply":
            raise FirewallError("No enabled reviewed-apply policy is bound to this firewall")
        if row["ttl_seconds"] is None or int(row["ttl_seconds"]) > int(policy["ttl_seconds"]):
            raise FirewallError(f"Reviewed rules require a TTL no longer than {policy['ttl_seconds']} seconds")
        applied_last_hour = self.db.one("SELECT COUNT(*) AS n FROM audit WHERE action='firewall.proposal.apply' AND outcome='ok' AND datetime(ts)>=datetime('now','-1 hour')")["n"]
        if applied_last_hour >= int(policy["max_actions_per_hour"]):
            raise FirewallError("The reviewed response rate limit has been reached")
        if not self._is_admin():
            raise FirewallError("Applying Windows Firewall rules requires a separately authorized elevated broker; PocketSOC will not trigger UAC itself")
        target = self._safe_target(row["target"])
        if target in self._protected_local_addresses():
            raise FirewallError("Target became protected since proposal creation")
        payload = json.loads(row["payload_json"])
        rule_name = payload["parameters"]["DisplayName"]
        executable = shutil.which("pwsh") or shutil.which("powershell") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        script = "param($n,$ip) New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any -ErrorAction Stop | Select-Object Name,DisplayName,Enabled | ConvertTo-Json -Compress"
        result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-Command", script, rule_name, target], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode != 0:
            self.db.audit("firewall.proposal.apply", "failed", target=proposal_id, detail={"error": result.stderr[-2000:]})
            raise FirewallError("Firewall rejected the exact reviewed rule")
        self.db.execute("UPDATE firewall_proposals SET status='applied' WHERE id=?", (proposal_id,))
        self.db.audit("firewall.proposal.apply", "ok", target=proposal_id, detail={"rule_name": rule_name, "target": target})
        return {"id": proposal_id, "status": "applied", "rule_name": rule_name, "target": target, "rollback_available": True, "output": result.stdout[-2000:]}

    def rollback_proposal(self, proposal_id: str, confirmation_hash: str) -> dict[str, Any]:
        row = self.db.one("SELECT p.*,b.adapter FROM firewall_proposals p JOIN firewall_bindings b ON b.id=p.binding_id WHERE p.id=?", (proposal_id,))
        if not row or row["status"] not in {"applied", "rollback_required"}:
            raise FirewallError("Applied firewall proposal not found")
        expected = hashlib.sha256(row["payload_json"].encode("utf-8")).hexdigest()
        if confirmation_hash != expected:
            raise FirewallError("Confirmation hash does not match the applied proposal")
        if row["adapter"] != "windows" or not self._is_admin():
            raise FirewallError("Rollback requires the authorized Windows firewall broker context")
        payload = json.loads(row["payload_json"]); rule_name = payload["parameters"]["DisplayName"]
        executable = shutil.which("pwsh") or shutil.which("powershell") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        script = "param($n) Remove-NetFirewallRule -DisplayName $n -ErrorAction Stop"
        result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-Command", script, rule_name], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode != 0:
            raise FirewallError("Firewall rollback failed; manual review required")
        self.db.execute("UPDATE firewall_proposals SET status='rolled_back' WHERE id=?", (proposal_id,))
        self.db.audit("firewall.proposal.rollback", "ok", target=proposal_id, detail={"rule_name": rule_name})
        return {"id": proposal_id, "status": "rolled_back", "rule_name": rule_name}

    def expire_due(self) -> list[dict[str, Any]]:
        """Roll back expired applied rules; failures are surfaced once per process and remain reviewable."""
        results: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc)
        for row in self.db.rows("SELECT id,payload_json FROM firewall_proposals WHERE status IN ('applied','rollback_required')"):
            try:
                payload = json.loads(row["payload_json"])
                expires_at = payload.get("expires_at")
                if not expires_at or datetime.fromisoformat(expires_at.replace("Z", "+00:00")) > now:
                    continue
                if row["id"] in self._expiry_failures:
                    continue
                confirmation_hash = hashlib.sha256(row["payload_json"].encode("utf-8")).hexdigest()
                results.append(self.rollback_proposal(row["id"], confirmation_hash))
            except Exception as exc:
                self._expiry_failures.add(row["id"])
                self.db.execute("UPDATE firewall_proposals SET status='rollback_required' WHERE id=?", (row["id"],))
                self.db.audit("firewall.proposal.expire", "action_required", target=row["id"], detail={"error": f"{type(exc).__name__}: {exc}"})
                results.append({"id": row["id"], "status": "rollback_required", "error": str(exc)})
        return results
