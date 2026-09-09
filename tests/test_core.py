from __future__ import annotations

import tempfile
import time
import unittest
import json
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pocketsoc.analysis import _device_and_peer, _normalized_timestamp
from pocketsoc.config import Settings
from pocketsoc.catalog import catalog, register_artifact, sync_catalog
from pocketsoc.db import Database
from pocketsoc.detection import DetectionService
from pocketsoc.filters import FilterError, FilterService
from pocketsoc.firewall import FirewallService
from pocketsoc.monitors import MonitorScheduler
from pocketsoc.knowledge import KnowledgeIndex
from pocketsoc.inventory import select_ollama_model
from pocketsoc.jobs import JobRunner
from pocketsoc.metering import MeterRegistry, ResourceMeter, update_energy_settings
from pocketsoc.recipes import RecipeError, RecipeService
from pocketsoc.sensors import SensorError, SensorService
from pocketsoc.tools import ToolBroker, ToolError, _private_target
from pocketsoc.workflow import SafeToolLab


LOCAL_WIRESHARK = Path(r"D:\DevData\Toolchains\Wireshark\Wireshark\tshark.exe")


class PocketSOCTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.settings = Settings(data_dir=self.root, datasets_dir=self.root / "datasets", wireshark_dir=Path(r"D:\DevData\Toolchains\Wireshark\Wireshark"))
        self.db = Database(self.root / "test.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_private_scope_allows_lan_and_rejects_public(self):
        self.assertEqual(_private_target("192.168.2.1"), "192.168.2.1")
        self.assertEqual(_private_target("192.168.2.0/24", allow_network=True), "192.168.2.0/24")
        with self.assertRaises(ToolError):
            _private_target("8.8.8.8")
        with self.assertRaises(ToolError):
            _private_target("10.0.0.0/8", allow_network=True)

    def test_broker_has_no_arbitrary_command_entrypoint(self):
        broker = ToolBroker(self.settings, self.db)
        with self.assertRaises(ToolError):
            broker.run("shell", "whoami")

    def test_safe_tool_lab_uses_non_executable_dsl(self):
        lab = SafeToolLab(self.settings, self.db)
        result = lab.generate("Beobachte sehr regelmäßige Beacon-Verbindungen", use_llm=False)
        self.assertEqual(result["status"], "proposal_passed")
        self.assertFalse(result["spec"]["permissions"]["network"])
        self.assertFalse(result["spec"]["permissions"]["subprocess"])
        self.assertEqual(result["spec"]["permissions"]["firewall"], "propose_only")
        self.assertNotIn("code", result["spec"])

    def test_generated_dsl_runs_only_on_stored_evidence(self):
        lab = SafeToolLab(self.settings, self.db)
        proposal = lab.generate("Beobachte sehr regelmäßige Beacon-Verbindungen", use_llm=False)
        base = datetime.now(timezone.utc) - timedelta(seconds=20)
        for index in range(10):
            ts = (base + timedelta(seconds=index)).isoformat()
            data = {"ts": ts, "device_key": "192.168.2.10", "peer": "192.168.2.20", "direction": "outbound", "protocol": "TCP", "frame_length": "100"}
            self.db.execute("INSERT INTO events(id,ts,event_type,source,device_key,severity,data_json,evidence_ref) VALUES(?,?,?,?,?,?,?,?)", (f"evt_{index}", ts, "network.packet", "test", "192.168.2.10", "info", json.dumps(data), "fixture:pcap"))
        result = lab.run_proposal(proposal["id"])
        self.assertEqual(result["source_rows"], 10)
        self.assertTrue(result["matches"])
        self.assertFalse(result["permissions"]["network"])
        self.assertFalse(result["permissions"]["subprocess"])

    def test_wal_database_and_audit(self):
        self.db.audit("test.action", "ok", target="fixture")
        row = self.db.one("SELECT * FROM audit WHERE action='test.action'")
        self.assertEqual(row["outcome"], "ok")

    def test_capture_direction_keeps_private_endpoint_as_device(self):
        inbound = _device_and_peer({"ip_src": "35.181.67.163", "ip_dst": "192.168.2.188"})
        outbound = _device_and_peer({"ip_src": "192.168.2.188", "ip_dst": "35.181.67.163"})
        self.assertEqual(inbound, ("192.168.2.188", "35.181.67.163", "inbound"))
        self.assertEqual(outbound, ("192.168.2.188", "35.181.67.163", "outbound"))

    def test_neighbor_inventory_excludes_multicast_and_broadcast(self):
        self.assertFalse(MonitorScheduler._is_real_neighbor({"IPAddress": "224.0.0.251", "LinkLayerAddress": "01-00-5E-00-00-FB"}))
        self.assertFalse(MonitorScheduler._is_real_neighbor({"IPAddress": "192.168.2.255", "LinkLayerAddress": "FF-FF-FF-FF-FF-FF"}))
        self.assertTrue(MonitorScheduler._is_real_neighbor({"IPAddress": "192.168.2.42", "LinkLayerAddress": "AA-BB-CC-DD-EE-FF"}))

    def test_pcap_epoch_is_normalized_to_utc(self):
        value = _normalized_timestamp("1788963519.858658000", "fallback")
        self.assertTrue(value.endswith("+00:00"))
        self.assertIn("T", value)

    @unittest.skipUnless(LOCAL_WIRESHARK.exists(), "requires a local Wireshark integration")
    def test_versioned_filter_is_typed_and_validated_by_tshark(self):
        filters = FilterService(self.settings, self.db)
        first = filters.create("host_focus", "wireshark_display", "ip.addr == {host}", {"host": {"type": "ip", "default": "192.168.2.1"}})
        second = filters.create("host_focus", "wireshark_display", "ip.addr == {host}", {"host": {"type": "ip", "default": "192.168.2.2"}})
        self.assertEqual((first["version"], second["version"]), (1, 2))
        self.assertEqual(first["lineage_id"], second["lineage_id"])
        self.assertEqual(second["status"], "active")
        self.assertEqual(filters.render(second["expression_template"], second["parameters"], {"host": "192.168.2.3"}), "ip.addr == 192.168.2.3")
        with self.assertRaises(FilterError):
            filters.render(second["expression_template"], second["parameters"], {"host": "1.2.3.4 or tcp"})

    def test_recipe_runs_allowlisted_steps_and_keeps_history(self):
        filters = FilterService(self.settings, self.db)
        lab = SafeToolLab(self.settings, self.db)
        recipes = RecipeService(self.db, filters, lab)
        recipe = recipes.create("Triage", "Local summary", {"steps": [{"type": "evidence_summary", "event_limit": 5}]})
        result = recipes.run(recipe["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["steps"][0]["type"], "evidence_summary")
        with self.assertRaises(RecipeError):
            recipes.create("Unsafe", "", {"steps": [{"type": "shell", "command": "whoami"}]})

    def test_firewall_adapter_only_creates_reviewable_proposal(self):
        firewalls = FirewallService(self.db)
        binding = firewalls.create_binding("Lab OPNsense", "opnsense", "https://192.168.2.1", "windows-credential:pocketsoc-opnsense")
        proposal = firewalls.propose_block(binding["id"], "203.0.113.25", "Fixture test", 3600, ["fixture:pcap"])
        self.assertEqual(proposal["status"], "pending_review")
        self.assertFalse(proposal["payload"]["apply"])
        self.assertTrue(proposal["rollback"])

    def test_expired_firewall_rule_uses_rollback_path(self):
        firewalls = FirewallService(self.db); firewalls.ensure_local_binding()
        proposal = firewalls.propose_block("fw_windows_local", "203.0.113.25", "Fixture test", 300, ["fixture:pcap"])
        payload = proposal["payload"]; payload["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        self.db.execute("UPDATE firewall_proposals SET status='applied',payload_json=? WHERE id=?", (json.dumps(payload), proposal["id"]))
        with patch.object(firewalls, "rollback_proposal", return_value={"id": proposal["id"], "status": "rolled_back"}) as rollback:
            result = firewalls.expire_due()
        self.assertEqual(result[0]["status"], "rolled_back")
        rollback.assert_called_once()

    def test_model_selector_prefers_stable_pocketsoc_alias(self):
        status = {"available": True, "models": ["qwen2.5:latest", "qwen2.5:pocketsoc-845dbda0"], "manifests": [{"name": "qwen2.5:pocketsoc-845dbda0", "digest": "digest-fixture"}]}
        model, identity = select_ollama_model(status)
        self.assertEqual(model, "qwen2.5:pocketsoc-845dbda0")
        self.assertEqual(identity["digest"], "digest-fixture")

    def test_job_runner_stops_cleanly(self):
        runner = JobRunner(self.db, workers=1)
        runner.register("fixture", lambda payload: {"ok": True, "payload": payload})
        runner.start()
        runner.stop()
        self.assertFalse(runner._started)

    def test_cli_refuses_remote_binding_before_importing_server(self):
        from pocketsoc.cli import main
        with patch("sys.argv", ["pocketsoc", "--host", "0.0.0.0"]):
            with self.assertRaises(SystemExit) as raised:
                main()
        self.assertIn("refuses non-loopback", str(raised.exception))

    def test_tool_evolution_preserves_candidate_when_not_better(self):
        lab = SafeToolLab(self.settings, self.db)
        original = lab.generate("Beobachte regelmäßige Beacon-Verbindungen", use_llm=False)
        evolved = lab.evolve(original["id"], use_llm=False)
        self.assertFalse(evolved["promoted"])
        self.assertTrue(evolved["history_preserved"])
        versions = self.db.one("SELECT COUNT(*) AS n FROM generated_tools WHERE lineage_id=?", (original["id"],))["n"]
        self.assertEqual(versions, 2)

    def test_catalog_is_manifest_only_except_synthetic_fixture(self):
        sync_catalog(self.db)
        result = catalog(self.db)
        self.assertGreaterEqual(len(result["datasets"]), 5)
        ready = [item["id"] for item in result["datasets"] if item["local_status"] == "ready"]
        self.assertEqual(ready, ["local-synthetic-regression"])

    @unittest.skipUnless(LOCAL_WIRESHARK.exists(), "requires a local Wireshark integration")
    def test_dataset_artifact_is_scoped_hashed_and_tshark_validated(self):
        sync_catalog(self.db)
        self.settings.datasets_dir.mkdir(parents=True, exist_ok=True)
        fixture = self.settings.datasets_dir / "empty.pcap"
        fixture.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
        artifact = register_artifact(self.settings, self.db, "wireshark-sample-captures", str(fixture))
        self.assertEqual(len(artifact["sha256"]), 64)
        self.assertEqual(artifact["bytes"], 24)
        with self.assertRaises(ValueError):
            register_artifact(self.settings, self.db, "wireshark-sample-captures", str(self.root / "outside.pcap"))

    def test_arp_identity_conflict_creates_claimed_incident(self):
        service = DetectionService(self.db)
        service.ensure_rules()
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute("INSERT INTO capture_artifacts(id,path,evidence_ref,sha256,bytes,retention_state,created_at,updated_at) VALUES(?,?,?,?,?,'rolling',?,?)", ("cart_fixture", str(self.root / "arp.cap"), "pcap:arpfixture", "a" * 64, 1, now, now))
        for index, mac in enumerate(("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02")):
            data = {"protocol": "ARP", "arp_src_ip": "192.168.2.1", "arp_src_mac": mac, "arp_opcode": "2"}
            self.db.execute("INSERT INTO events(id,ts,event_type,source,device_key,severity,data_json,evidence_ref) VALUES(?,?,?,?,?,?,?,?)", (f"arp_{index}", now, "network.packet", "test", "192.168.2.1", "info", json.dumps(data), "pcap:arpfixture"))
        result = service.run(60)
        self.assertEqual(result["findings"], 1)
        incident = service.list_incidents()[0]
        self.assertEqual(incident["rule_id"], "det_mitm_arp_identity")
        self.assertEqual([claim["classification"] for claim in incident["claims"]], ["observed", "hypothesis"])
        self.assertTrue(incident["alternatives"])
        self.assertEqual(self.db.one("SELECT retention_state FROM capture_artifacts WHERE id='cart_fixture'")["retention_state"], "incident_locked")
        service.update_incident(incident["id"], "acknowledged", "Analyst is checking")
        closed = service.update_incident(incident["id"], "closed", "Fixture resolved")
        self.assertEqual(closed["status"], "closed")
        self.assertEqual(len(closed["history"]), 2)
        self.assertEqual(self.db.one("SELECT retention_state FROM capture_artifacts WHERE id='cart_fixture'")["retention_state"], "rolling")

    def test_detection_rule_configuration_is_enforced_and_preserved(self):
        service = DetectionService(self.db); service.ensure_rules()
        updated = service.update_rule("det_mitm_arp_identity", enabled=True, confidence_floor=None, spec={"min_macs": 3})
        self.assertEqual(updated["spec"]["min_macs"], 3)
        service.ensure_rules()
        self.assertEqual(next(row for row in service.rules() if row["id"] == "det_mitm_arp_identity")["spec"]["min_macs"], 3)
        now = datetime.now(timezone.utc).isoformat()
        for index, mac in enumerate(("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02")):
            data = {"protocol": "ARP", "arp_src_ip": "192.168.2.1", "arp_src_mac": mac, "arp_opcode": "2"}
            self.db.execute("INSERT INTO events(id,ts,event_type,source,device_key,severity,data_json,evidence_ref) VALUES(?,?,?,?,?,?,?,?)", (f"configured_arp_{index}", now, "network.packet", "test", "192.168.2.1", "info", json.dumps(data), "pcap:configured"))
        self.assertEqual(service.run(60)["findings"], 0)

    def test_possible_replay_requires_non_idempotent_request_and_multiple_streams(self):
        service = DetectionService(self.db); service.ensure_rules(); now = datetime.now(timezone.utc).isoformat()
        for index, stream in enumerate(("1", "2")):
            data = {"protocol": "HTTP", "device_key": "192.168.2.10", "http_method": "POST", "http_host": "device.local", "http_uri": "/action", "tcp_stream": stream, "direction": "outbound", "peer": "192.168.2.20", "tcp_dst_port": "80"}
            self.db.execute("INSERT INTO events(id,ts,event_type,source,device_key,severity,data_json,evidence_ref) VALUES(?,?,?,?,?,?,?,?)", (f"http_{index}", now, "network.packet", "test", "192.168.2.10", "info", json.dumps(data), "pcap:replayfixture"))
        service.run(60)
        replay = next(item for item in service.list_incidents() if item["rule_id"] == "det_possible_http_replay")
        self.assertLess(replay["confidence"], 0.60)
        self.assertIn("nicht nachweisbar", replay["claims"][1]["claim"])

    def test_dns_tunnel_candidate_stays_a_hypothesis(self):
        service = DetectionService(self.db); service.ensure_rules(); now = datetime.now(timezone.utc).isoformat()
        for index in range(25):
            label = f"encodedpayloadsegment{index:02d}abcdefghijklmno"
            data = {"protocol": "DNS", "device_key": "192.168.2.10", "dns_name": f"{label}.example.test", "dns_response": "0"}
            self.db.execute("INSERT INTO events(id,ts,event_type,source,device_key,severity,data_json,evidence_ref) VALUES(?,?,?,?,?,?,?,?)", (f"dns_{index}", now, "network.packet", "test", "192.168.2.10", "info", json.dumps(data), "pcap:dnsfixture"))
        service.run(60)
        finding = next(item for item in service.list_incidents() if item["rule_id"] == "det_dns_tunnel_candidate")
        self.assertEqual(finding["claims"][1]["classification"], "hypothesis")
        self.assertLess(finding["confidence"], 0.60)

    def test_suricata_eve_ingest_is_checkpointed_and_payload_safe(self):
        service = SensorService(self.db)
        eve = self.root / "eve.json"
        alert = {
            "timestamp": "2026-09-09T10:00:00.123456+00:00", "event_type": "alert",
            "src_ip": "192.168.2.50", "src_port": 51515, "dest_ip": "203.0.113.9", "dest_port": 443,
            "proto": "TCP", "app_proto": "tls", "flow_id": 42, "payload": "must-not-be-stored",
            "alert": {"signature_id": 900001, "signature": "Fixture callback", "category": "Fixture", "severity": 1, "action": "allowed"},
        }
        dns = {
            "timestamp": "2026-09-09T10:00:01+00:00", "event_type": "dns", "src_ip": "192.168.2.50",
            "dest_ip": "192.168.2.1", "proto": "UDP", "dns": {"type": "query", "rrname": "example.test", "rrtype": "A"},
        }
        partial = b'{"timestamp":"2026-09-09T10:00:02+00:00","event_type":"flow"'
        eve.write_bytes((json.dumps(alert) + "\n" + json.dumps(dns) + "\n").encode() + partial)
        source = service.create_source("Fixture EVE", "suricata_eve", str(eve))
        first = service.ingest(source["id"])
        self.assertEqual(first["imported"], 2)
        self.assertFalse(first["caught_up"])
        self.assertFalse(first["raw_payload_stored"])
        stored = service.records(source_id=source["id"], limit=10)
        self.assertEqual(len(stored), 2)
        self.assertNotIn("payload", json.dumps(stored))
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM observations WHERE kind='suricata_alert'")["n"], 1)
        with eve.open("ab") as handle:
            handle.write(b"}\n")
        second = service.ingest(source["id"])
        self.assertEqual(second["imported"], 1)
        self.assertTrue(second["caught_up"])
        replay = service.ingest(source["id"], reset_checkpoint=True)
        self.assertEqual(replay["duplicates"], 3)
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM events WHERE source=?", (source["id"],))["n"], 3)

    def test_sensor_source_rejects_unsupported_or_missing_input(self):
        service = SensorService(self.db)
        with self.assertRaises(SensorError):
            service.create_source("Missing", "suricata_eve", str(self.root / "missing.json"))
        unsupported = self.root / "eve.txt"
        unsupported.write_text("{}\n", encoding="utf-8")
        with self.assertRaises(SensorError):
            service.create_source("Wrong suffix", "suricata_eve", str(unsupported))

    def test_local_knowledge_uses_bm25_without_packet_vectors(self):
        index = KnowledgeIndex(self.settings, self.db); index.ensure_core()
        hits = index.search("Replay retransmission nonce", 5)
        self.assertTrue(hits)
        self.assertEqual(index.stats()["engine"], "SQLite FTS5/BM25")
        self.assertFalse(index.stats()["raw_packet_vectors"])

    def test_resource_meter_reports_raw_units_and_estimated_cost(self):
        update_energy_settings(self.db, 0.30, 241, 12)
        self.db.execute(
            "INSERT INTO jobs(id,kind,input_hash,payload_json,status,stage,created_at) VALUES(?,?,?,?,?,?,?)",
            ("job_fixture", "benchmark", "fixture", "{}", "running", "running", datetime.now(timezone.utc).isoformat()),
        )
        meter = ResourceMeter(self.db, "job_fixture", MeterRegistry())
        time.sleep(0.1)
        metrics = meter.finish()
        self.assertGreaterEqual(metrics["process_cpu_seconds"], 0)
        self.assertGreaterEqual(metrics["total_energy_kwh_estimated"], 0)
        self.assertIn(metrics["confidence"], {"low", "medium"})
        self.assertIn("cpu", metrics["sources"])


if __name__ == "__main__":
    unittest.main()
