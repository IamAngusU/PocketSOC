from __future__ import annotations

import json
import hashlib
import subprocess
import uuid
from pathlib import Path
from typing import Any

from .config import Settings
from .db import Database, utcnow


DATASETS: tuple[dict[str, str], ...] = (
    {
        "id": "wireshark-sample-captures",
        "name": "Wireshark Sample Captures",
        "source_url": "https://wiki.wireshark.org/SampleCaptures",
        "publisher": "Wireshark Foundation community wiki",
        "purpose": "Small protocol-specific PCAP regression fixtures for filters and decoders.",
        "scale": "Selective small files; varies by sample",
        "license_note": "Check the individual sample provenance before redistribution.",
        "risk": "May contain captured payload/identifiers; import only selected files into the isolated test corpus.",
        "local_status": "registry_only",
        "recommendation": "Best first source: select a few harmless DNS, DHCP, ARP and TLS captures; hash and pin every file.",
    },
    {
        "id": "cic-iot-2023",
        "name": "CICIoT2023",
        "source_url": "https://www.unb.ca/cic/datasets/iotdataset-2023.html",
        "publisher": "Canadian Institute for Cybersecurity, UNB",
        "purpose": "Labeled IoT attack/benign evaluation across 105 devices, 33 attacks and seven categories.",
        "scale": "Very large PCAP/CSV corpus (do not download as a default dependency)",
        "license_note": "Review the publisher's current dataset terms and citation requirements before use.",
        "risk": "Large disk/time cost and attack traffic; offline evaluation only.",
        "local_status": "manifest_only",
        "recommendation": "Use a documented, stratified subset in shadow benchmarks; never train/evaluate on live household evidence.",
    },
    {
        "id": "iot-23",
        "name": "IoT-23",
        "source_url": "https://www.stratosphereips.org/datasets",
        "publisher": "Stratosphere Laboratory",
        "purpose": "Labeled real IoT malware and benign traffic for detector evaluation.",
        "scale": "Small/full variants; capture sizes vary",
        "license_note": "Publisher permits research use with citation; verify current terms for the intended use.",
        "risk": "Some archives are explicitly malware datasets; quarantine and offline-only handling required.",
        "local_status": "manifest_only",
        "recommendation": "Useful for beacon/DNS-tunneling regression only inside an isolated corpus; never auto-open protected archives.",
    },
    {
        "id": "mawi-working-group-traffic-archive",
        "name": "MAWI Working Group Traffic Archive",
        "source_url": "https://mawi.wide.ad.jp/mawi/",
        "publisher": "WIDE Project",
        "purpose": "Anonymized backbone traces for scale and traffic-distribution research.",
        "scale": "Large recurring trace archive",
        "license_note": "Research-only constraints and privacy rules apply; verify terms before every use.",
        "risk": "Not representative of a home LAN; privacy/usage constraints make it unsuitable as a default corpus.",
        "local_status": "not_recommended_default",
        "recommendation": "Registry reference only; do not download automatically or use as product training data.",
    },
    {
        "id": "local-synthetic-regression",
        "name": "PocketSOC Synthetic Regression Fixtures",
        "source_url": "local://pocketsoc/tests",
        "publisher": "PocketSOC",
        "purpose": "Deterministic benign/suspicious DSL and filter behavior tests without private packet payloads.",
        "scale": "Tiny",
        "license_note": "Project-local fixtures.",
        "risk": "Synthetic data cannot prove real-world detection quality.",
        "local_status": "ready",
        "recommendation": "Always run first; supplement with pinned public PCAP subsets and separately measured live shadow data.",
    },
    {
        "id": "cic-ids-2017",
        "name": "CICIDS2017",
        "source_url": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "publisher": "Canadian Institute for Cybersecurity, UNB",
        "purpose": "Labeled benign and common attack traffic for offline IDS regression.",
        "scale": "Large multi-day PCAP/flow corpus",
        "license_note": "Review current publisher terms and citation requirements.",
        "risk": "Attack traffic and dated traffic mix; unsuitable as sole quality benchmark.",
        "local_status": "manifest_only",
        "recommendation": "Use stratified, hashed subsets for scan/brute-force/DDoS regression and document dataset age bias.",
    },
    {
        "id": "cse-cic-ids-2018",
        "name": "CSE-CIC-IDS2018",
        "source_url": "https://www.unb.ca/cic/datasets/ids-2018.html",
        "publisher": "Canadian Institute for Cybersecurity, UNB",
        "purpose": "Labeled enterprise-style attack scenarios and network/system profiles.",
        "scale": "Very large multi-machine corpus",
        "license_note": "Review current AWS/publisher access and usage terms.",
        "risk": "High storage/processing cost and domain shift from a home LAN.",
        "local_status": "manifest_only",
        "recommendation": "Use only selected scenarios after the local synthetic and Wireshark regression suites pass.",
    },
)


INTEGRATIONS: tuple[dict[str, str], ...] = (
    {
        "id": "suricata-eve",
        "name": "Suricata EVE JSON",
        "source_url": "https://docs.suricata.io/en/latest/output/eve/eve-json-format.html",
        "role": "IDS alerts, anomalies and protocol metadata correlated back to PCAP identifiers.",
        "platform": "Best as Linux/container sensor; EVE JSON can be imported anywhere.",
        "status": "adapter_planned",
        "fit": "High for a future sensor profile; complements rather than replaces Wireshark.",
        "constraints": "Ruleset/version must be pinned; alerts are hypotheses and need evidence correlation.",
    },
    {
        "id": "zeek",
        "name": "Zeek + Spicy",
        "source_url": "https://docs.zeek.org/en/current/install.html",
        "role": "Rich protocol logs and extensible parsers for PCAP/live sensor input.",
        "platform": "Official packages/containers target Linux and macOS; no native Windows package.",
        "status": "adapter_planned",
        "fit": "High on a WSL2/Docker or separate Linux sensor, not as a forced native-Windows dependency.",
        "constraints": "Container/WSL network visibility and resource limits must be tested before declaring ready.",
    },
    {
        "id": "rita",
        "name": "RITA",
        "source_url": "https://github.com/activecm/rita",
        "role": "Beaconing, long-connection and DNS-tunneling analytics over Zeek logs.",
        "platform": "Supported Linux with Docker Compose.",
        "status": "optional_future",
        "fit": "Useful evaluation/reference engine after a Zeek sensor exists.",
        "constraints": "Not a direct Windows module and too heavy for the current Desktop Lite profile.",
    },
    {
        "id": "arkime",
        "name": "Arkime",
        "source_url": "https://arkime.com/index",
        "role": "Large-scale indexed full-packet capture and session search with PCAP export.",
        "platform": "Linux/container plus OpenSearch/Elasticsearch.",
        "status": "scale_out_option",
        "fit": "Excellent later for a dedicated sensor/server; excessive for this workstation MVP.",
        "constraints": "Material storage/operations footprint; TLS, auth and retention design are mandatory.",
    },
    {
        "id": "mitre-attack-stix",
        "name": "MITRE ATT&CK STIX",
        "source_url": "https://github.com/mitre-attack/attack-stix-data",
        "role": "Versioned adversary-technique, mitigation and data-source knowledge for local retrieval.",
        "platform": "Portable STIX 2.1 JSON",
        "status": "indexed_local",
        "fit": "High for cited explanations and detector mapping; not a signature engine by itself.",
        "constraints": "Pin a release and digest; ATT&CK context must not be presented as proof of compromise.",
    },
    {
        "id": "sigma",
        "name": "Sigma detection format and rules",
        "source_url": "https://sigmahq.io/docs/basics/rules.html",
        "role": "Portable log detection knowledge for future Sysmon/Windows event correlation.",
        "platform": "YAML rules translated to a supported backend",
        "status": "knowledge_candidate",
        "fit": "High after a typed Sysmon/log schema and rule sandbox exist.",
        "constraints": "Rule status, log source and backend semantics must be validated; do not ingest every rule blindly.",
    },
    {
        "id": "cisa-kev",
        "name": "CISA Known Exploited Vulnerabilities",
        "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "role": "Authoritative prioritization input for vulnerabilities exploited in the wild.",
        "platform": "JSON/CSV feed",
        "status": "inventory_correlation_candidate",
        "fit": "Useful only when reliable local software/firmware inventory exists.",
        "constraints": "A matching CVE does not prove exploitation; version detection and vendor mapping need evidence.",
    },
    {
        "id": "suricata-update",
        "name": "Suricata-Update managed rules",
        "source_url": "https://docs.suricata.io/en/latest/rule-management/suricata-update.html",
        "role": "Pinned IDS rule-source management for a future Suricata sensor.",
        "platform": "Suricata sensor",
        "status": "sensor_profile_candidate",
        "fit": "Preferred rule-management path once Suricata is installed and benchmarked.",
        "constraints": "Pin source revisions, profile rules, test false positives, and deploy in IDS/shadow mode before IPS.",
    },
)


def sync_catalog(db: Database) -> None:
    now = utcnow()
    with db.tx() as conn:
        for item in DATASETS:
            conn.execute(
                "INSERT INTO dataset_catalog(id,name,source_url,publisher,purpose,scale,license_note,risk,local_status,recommendation,manifest_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,source_url=excluded.source_url,publisher=excluded.publisher,purpose=excluded.purpose,scale=excluded.scale,license_note=excluded.license_note,risk=excluded.risk,recommendation=excluded.recommendation,manifest_json=excluded.manifest_json,updated_at=excluded.updated_at",
                (item["id"], item["name"], item["source_url"], item["publisher"], item["purpose"], item["scale"], item["license_note"], item["risk"], item["local_status"], item["recommendation"], json.dumps({"auto_download": False, "provenance_required": True}), now),
            )
        for item in INTEGRATIONS:
            conn.execute(
                "INSERT INTO integration_catalog(id,name,source_url,role,platform,status,fit,constraints,manifest_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,source_url=excluded.source_url,role=excluded.role,platform=excluded.platform,status=excluded.status,fit=excluded.fit,constraints=excluded.constraints,manifest_json=excluded.manifest_json,updated_at=excluded.updated_at",
                (item["id"], item["name"], item["source_url"], item["role"], item["platform"], item["status"], item["fit"], item["constraints"], json.dumps({"installed": False, "verified": False}), now),
            )


def catalog(db: Database) -> dict[str, list[dict[str, Any]]]:
    return {
        "datasets": db.rows("SELECT * FROM dataset_catalog ORDER BY CASE local_status WHEN 'ready' THEN 0 ELSE 1 END,name"),
        "integrations": db.rows("SELECT * FROM integration_catalog ORDER BY name"),
        "artifacts": db.rows("SELECT * FROM dataset_artifacts ORDER BY registered_at DESC"),
        "policy": [
            {"rule": "No automatic corpus downloads", "reason": "Size, license, privacy and malware risk are dataset-specific."},
            {"rule": "Hash and pin every imported artifact", "reason": "Benchmarks must remain reproducible."},
            {"rule": "Train, shadow-test and live evidence remain separate", "reason": "Prevents leakage and misleading quality claims."},
        ],
    }


def register_artifact(settings: Settings, db: Database, dataset_id: str, raw_path: str) -> dict[str, Any]:
    if not db.one("SELECT 1 AS ok FROM dataset_catalog WHERE id=?", (dataset_id,)):
        raise ValueError("Dataset is not present in the curated registry")
    path = Path(raw_path).expanduser().resolve()
    root = settings.datasets_dir.resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"Artifact must be an existing file below {root}")
    if path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise ValueError("Only PCAP/PCAPNG/CAP artifacts are currently accepted")
    size = path.stat().st_size
    if size > 5 * 1024**3:
        raise ValueError("Register large corpora as shards below 5 GiB")
    completed = subprocess.run([str(settings.tshark_path), "-n", "-r", str(path), "-c", "1", "-T", "fields", "-e", "frame.number"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    validation = {"passed": completed.returncode == 0, "engine": "tshark", "exit_code": completed.returncode, "diagnostic": (completed.stderr or completed.stdout)[-2000:]}
    if not validation["passed"]:
        raise ValueError("TShark rejected the capture artifact")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    artifact_id = f"dsa_{uuid.uuid4().hex}"
    db.execute("INSERT INTO dataset_artifacts(id,dataset_id,path,sha256,bytes,validation_json,registered_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET dataset_id=excluded.dataset_id,sha256=excluded.sha256,bytes=excluded.bytes,validation_json=excluded.validation_json,registered_at=excluded.registered_at", (artifact_id, dataset_id, str(path), digest.hexdigest(), size, json.dumps(validation), utcnow()))
    db.execute("UPDATE dataset_catalog SET local_status='ready_subset' WHERE id=?", (dataset_id,))
    db.audit("dataset.artifact.register", "ok", target=dataset_id, detail={"path": str(path), "sha256": digest.hexdigest(), "bytes": size})
    return db.one("SELECT * FROM dataset_artifacts WHERE path=?", (str(path),)) or {}
