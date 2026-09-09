from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .analysis import dashboard_summary
from .assistant import answer_question
from .benchmark import BenchmarkService
from .capture import CaptureError, CaptureService
from .catalog import catalog, register_artifact, sync_catalog
from .config import PROJECT_ROOT, settings
from .db import Database
from .detection import DetectionService
from .demo import seed_demo
from .doctor import doctor
from .filters import FilterError, FilterService
from .firewall import FirewallError, FirewallService
from .inventory import system_inventory
from .jobs import JobRunner
from .knowledge import KnowledgeIndex
from .metering import MeterRegistry, energy_settings, update_energy_settings
from .models import (
    CaptureRequest,
    CaptureRetentionRequest,
    BenchmarkRequest,
    DetectionRunRequest,
    DetectionRuleUpdateRequest,
    DeviceUpdateRequest,
    DatasetArtifactRequest,
    FilterGenerateRequest,
    FilterRequest,
    FilterTestRequest,
    FirewallBindingRequest,
    FirewallActionRequest,
    FirewallProposalRequest,
    EnergySettingsRequest,
    KnowledgeImportRequest,
    KnowledgeSearchRequest,
    IncidentUpdateRequest,
    MonitorRequest,
    PcapAnalyzeRequest,
    QueryRequest,
    RecipeRequest,
    SensorIngestRequest,
    SensorSourceRequest,
    SensorSourceUpdateRequest,
    ToolEvolveRequest,
    ToolLabRequest,
    ToolRunRequest,
    WiresharkOpenRequest,
)
from .monitors import MonitorScheduler
from .recipes import RecipeError, RecipeService
from .sensors import SensorError, SensorService
from .tools import ToolBroker, ToolError
from .workflow import SafeToolLab


db = Database(settings.db_path)
broker = ToolBroker(settings, db)
captures = CaptureService(settings, db)
firewalls = FirewallService(db)
tool_lab = SafeToolLab(settings, db, firewalls)
filters = FilterService(settings, db)
recipes = RecipeService(db, filters, tool_lab)
knowledge = KnowledgeIndex(settings, db)
detections = DetectionService(db)
sensors = SensorService(db)
benchmarks = BenchmarkService(settings, db, detections, knowledge)
meter_registry = MeterRegistry()
jobs = JobRunner(db, workers=2, meter_registry=meter_registry)
monitors = MonitorScheduler(db, broker, tool_lab, detections, firewalls, sensors)
jobs.register("tool", lambda p: broker.run(p["tool"], p.get("target"), p.get("profile", "discovery")))
jobs.register("capture", lambda p: captures.capture(p["interface"], p["duration_seconds"], p["max_packets"]))
jobs.register("pcap_analyze", lambda p: captures.analyze(p["path"]))
jobs.register("query", lambda p: answer_question(db, settings, p["question"], p.get("use_llm", False)))
jobs.register("tool_lab", lambda p: tool_lab.generate(p["prompt"], p.get("use_llm", True)))
jobs.register("tool_evolve", lambda p: tool_lab.evolve(p["tool_id"], p.get("use_llm", True)))
jobs.register("filter_generate", lambda p: filters.generate(p["prompt"], p.get("use_llm", True)))
jobs.register("recipe_run", lambda p: recipes.run(p["recipe_id"]))
jobs.register("detection", lambda p: detections.run(p.get("window_minutes", 60)))
jobs.register("benchmark", lambda p: benchmarks.run(p.get("repeats", 5)))
jobs.register("sensor_ingest", lambda p: sensors.ingest(p["source_id"], p.get("max_records", 10_000), p.get("reset_checkpoint", False)))

_inventory_cache: dict = {"at": 0.0, "data": None}


def _ensure_defaults() -> None:
    if not db.one("SELECT 1 AS ok FROM filters LIMIT 1"):
        filters.create("host_focus", "wireshark_display", "ip.addr == {host}", {"host": {"type": "ip", "default": "192.168.2.1"}}, created_by="system-default")
        filters.create("tls_port_focus", "wireshark_display", "tcp.port == {port}", {"port": {"type": "port", "default": 443}}, created_by="system-default")
        filters.create("dns_term_focus", "wireshark_display", "dns.qry.name contains \"{term}\"", {"term": {"type": "text", "default": "local"}}, created_by="system-default")
    if not db.one("SELECT 1 AS ok FROM recipes LIMIT 1"):
        active_filter = db.one("SELECT id FROM filters WHERE status='active' ORDER BY created_at LIMIT 1")
        if active_filter:
            recipes.create("PCAP-Schnellprüfung", "Testet einen anpassbaren Filter und erstellt danach eine lokale Evidenzübersicht.", {"steps": [{"type": "filter_test", "filter_id": active_filter["id"]}, {"type": "evidence_summary", "event_limit": 25}], "stop_on_error": True}, created_by="system-default")
    if not db.one("SELECT 1 AS ok FROM monitors WHERE kind='tool_evolution' LIMIT 1"):
        now = datetime.now(timezone.utc)
        db.execute(
            "INSERT INTO monitors(id,name,kind,interval_seconds,enabled,config_json,next_run_at,created_at) VALUES(?,?,?,?,1,?,?,?)",
            (f"mon_{uuid.uuid4().hex}", "Analyzer-Qualität monatlich prüfen", "tool_evolution", 2_592_000, json.dumps({"use_llm": True}), (now + timedelta(days=30)).isoformat(timespec="milliseconds"), now.isoformat(timespec="milliseconds")),
        )
    if not db.one("SELECT 1 AS ok FROM monitors WHERE kind='detections' LIMIT 1"):
        now = datetime.now(timezone.utc)
        db.execute(
            "INSERT INTO monitors(id,name,kind,interval_seconds,enabled,config_json,next_run_at,created_at) VALUES(?,?,?,?,1,?,?,?)",
            (f"mon_{uuid.uuid4().hex}", "Angriffsmuster korrelieren", "detections", 60, json.dumps({"window_minutes": 60}), now.isoformat(timespec="milliseconds"), now.isoformat(timespec="milliseconds")),
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    sync_catalog(db)
    knowledge.ensure_core()
    detections.ensure_rules()
    firewalls.ensure_local_binding()
    _ensure_defaults()
    if os.getenv("POCKETSOC_DEMO") == "1" and seed_demo(db)["seeded"]:
        detections.run(60)
    jobs.start()
    monitors.start()
    db.audit("server.start", "ok", detail={"bind": settings.bind_host, "port": settings.port})
    try:
        yield
    finally:
        monitors.stop()
        jobs.stop()
        db.audit("server.stop", "ok")


app = FastAPI(title="PocketSOC", version="0.4.0", lifespan=lifespan, docs_url="/api/docs", redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"])


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:"
    return response


STATIC_DIR = next(
    (path for path in (Path(__file__).parent / "static", PROJECT_ROOT / "static", Path(sys.prefix) / "share" / "pocketsoc" / "static") if path.is_dir()),
    PROJECT_ROOT / "static",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "service": "PocketSOC", "version": app.version, "storage": str(settings.data_dir), "mode": "local-defensive", "demo": os.getenv("POCKETSOC_DEMO") == "1"}


@app.get("/api/system")
def system(refresh: bool = False):
    now = time.monotonic()
    if refresh or _inventory_cache["data"] is None or now - _inventory_cache["at"] > 30:
        _inventory_cache.update({"at": now, "data": system_inventory(settings)})
    return _inventory_cache["data"]


@app.get("/api/doctor")
def system_doctor(repair_safe: bool = False):
    return doctor(settings, db, repair_safe=repair_safe)


@app.get("/api/dashboard")
def dashboard():
    return dashboard_summary(db)


@app.get("/api/jobs")
def list_jobs(limit: int = Query(default=30, ge=1, le=200)):
    return db.rows("SELECT id,kind,status,stage,attempt,created_at,started_at,finished_at,elapsed_ms,error FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,))


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    row = db.one("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not row:
        raise HTTPException(404, "Job not found")
    for key in ("payload_json", "result_json"):
        if row.get(key):
            try:
                row[key.removesuffix("_json")] = json.loads(row[key])
            except json.JSONDecodeError:
                row[key.removesuffix("_json")] = row[key]
    metrics = db.one("SELECT * FROM job_metrics WHERE job_id=?", (job_id,))
    if metrics:
        metrics["sources"] = json.loads(metrics.pop("sources_json"))
        row["metrics"] = metrics
    return row


@app.post("/api/tools/run", status_code=202)
def run_tool(request: ToolRunRequest):
    try:
        return jobs.submit("tool", request.model_dump())
    except ToolError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/capture/interfaces")
def interfaces():
    return captures.list_interfaces()


@app.post("/api/capture/start", status_code=202)
def start_capture(request: CaptureRequest):
    return jobs.submit("capture", request.model_dump())


@app.post("/api/pcap/analyze", status_code=202)
def analyze_pcap(request: PcapAnalyzeRequest):
    return jobs.submit("pcap_analyze", request.model_dump())


@app.post("/api/pcap/open")
def open_pcap(request: WiresharkOpenRequest):
    try:
        return captures.open_in_wireshark(request.path, request.display_filter)
    except CaptureError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/captures")
def list_captures():
    rows = []
    for path in sorted(settings.captures_dir.glob("*.pcap*"), key=lambda item: item.stat().st_mtime, reverse=True)[:100]:
        artifact = db.one("SELECT id,evidence_ref,retention_state,lock_reason FROM capture_artifacts WHERE path=?", (str(path.resolve()),)) or {}
        rows.append({"path": str(path), "name": path.name, "bytes": path.stat().st_size, "modified": path.stat().st_mtime, **artifact})
    return rows


@app.get("/api/sensors/adapters")
def sensor_adapters():
    return sensors.adapters()


@app.get("/api/sensors/sources")
def sensor_sources():
    return sensors.sources()


@app.post("/api/sensors/sources")
def create_sensor_source(request: SensorSourceRequest):
    try:
        return sensors.create_source(request.name, request.kind, request.path, request.enabled)
    except SensorError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.patch("/api/sensors/sources/{source_id}")
def update_sensor_source(source_id: str, request: SensorSourceUpdateRequest):
    try:
        return sensors.update_source(source_id, name=request.name, enabled=request.enabled)
    except SensorError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/sensors/sources/{source_id}/ingest", status_code=202)
def ingest_sensor_source(source_id: str, request: SensorIngestRequest):
    try:
        sensors.get_source(source_id)
    except SensorError as exc:
        raise HTTPException(404, str(exc)) from exc
    return jobs.submit("sensor_ingest", {"source_id": source_id, **request.model_dump()})


@app.get("/api/sensors/records")
def sensor_records(
    source_id: str | None = None,
    event_type: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
):
    return sensors.records(source_id=source_id, event_type=event_type, limit=limit)


@app.patch("/api/captures/{capture_id}/retention")
def update_capture_retention(capture_id: str, request: CaptureRetentionRequest):
    row = db.one("SELECT * FROM capture_artifacts WHERE id=?", (capture_id,))
    if not row:
        raise HTTPException(404, "Capture artifact not found")
    if row["retention_state"] == "incident_locked" and request.state != "incident_locked":
        raise HTTPException(409, "Incident evidence cannot be unlocked from the capture endpoint; close/export the incident first")
    db.execute("UPDATE capture_artifacts SET retention_state=?,lock_reason=?,updated_at=? WHERE id=?", (request.state, request.reason, datetime.now(timezone.utc).isoformat(timespec="milliseconds"), capture_id))
    db.audit("capture.retention.update", "ok", target=capture_id, detail=request.model_dump())
    return db.one("SELECT * FROM capture_artifacts WHERE id=?", (capture_id,))


@app.get("/api/events")
def events(limit: int = Query(default=100, ge=1, le=1000), event_type: str | None = None):
    if event_type:
        return db.rows("SELECT * FROM events WHERE event_type=? ORDER BY ts DESC LIMIT ?", (event_type, limit))
    return db.rows("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))


@app.get("/api/observations")
def observations(limit: int = Query(default=100, ge=1, le=500)):
    return db.rows("SELECT * FROM observations ORDER BY ts DESC LIMIT ?", (limit,))


@app.get("/api/devices")
def devices(limit: int = Query(default=200, ge=1, le=1000)):
    return db.rows("SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?", (limit,))


@app.patch("/api/devices/{device_key}")
def update_device(device_key: str, request: DeviceUpdateRequest):
    row = db.one("SELECT * FROM devices WHERE device_key=?", (device_key,))
    if not row:
        raise HTTPException(404, "Device not found")
    display_name = request.display_name if request.display_name is not None else row["display_name"]
    state = request.state if request.state is not None else row["state"]
    db.execute("UPDATE devices SET display_name=?,state=? WHERE device_key=?", (display_name, state, device_key))
    db.audit("device.update", "ok", target=device_key, detail={"display_name": display_name, "state": state})
    return db.one("SELECT * FROM devices WHERE device_key=?", (device_key,))


@app.get("/api/monitors")
def list_monitors():
    return db.rows("SELECT * FROM monitors ORDER BY created_at DESC")


@app.post("/api/monitors")
def create_monitor(request: MonitorRequest):
    try:
        return monitors.create(request.name, request.kind, request.interval_seconds, request.config)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/monitors/{monitor_id}/{action}")
def toggle_monitor(monitor_id: str, action: str):
    if action not in {"start", "stop"}:
        raise HTTPException(400, "Action must be start or stop")
    result = monitors.set_enabled(monitor_id, action == "start")
    if not result:
        raise HTTPException(404, "Monitor not found")
    return result


@app.post("/api/query", status_code=202)
def query(request: QueryRequest):
    return jobs.submit("query", request.model_dump())


@app.post("/api/tool-lab/generate", status_code=202)
def generate_tool(request: ToolLabRequest):
    return jobs.submit("tool_lab", request.model_dump())


@app.get("/api/tool-lab")
def generated_tools():
    return db.rows("SELECT * FROM generated_tools ORDER BY created_at DESC LIMIT 100")


@app.post("/api/tool-lab/{tool_id}/run")
def run_generated_tool(tool_id: str):
    try:
        return tool_lab.run_proposal(tool_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.post("/api/tool-lab/{tool_id}/activate")
def activate_generated_tool(tool_id: str):
    try:
        return tool_lab.activate(tool_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/tool-lab/{tool_id}/evolve", status_code=202)
def evolve_generated_tool(tool_id: str, request: ToolEvolveRequest):
    if not db.one("SELECT 1 AS ok FROM generated_tools WHERE id=?", (tool_id,)):
        raise HTTPException(404, "Generated tool not found")
    return jobs.submit("tool_evolve", {"tool_id": tool_id, **request.model_dump()})


@app.get("/api/filters")
def list_filters():
    return filters.list()


@app.post("/api/filters")
def create_filter(request: FilterRequest):
    try:
        return filters.create(request.name, request.kind, request.expression_template, request.parameters, activate=request.activate)
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/filters/generate", status_code=202)
def generate_filter(request: FilterGenerateRequest):
    return jobs.submit("filter_generate", request.model_dump())


@app.post("/api/filters/{filter_id}/test")
def test_filter(filter_id: str, request: FilterTestRequest):
    try:
        return filters.test(filter_id, request.values, request.capture_path)
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/filters/{filter_id}/activate")
def activate_filter(filter_id: str):
    try:
        return filters.activate(filter_id)
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/recipes")
def list_recipes():
    return recipes.list()


@app.post("/api/recipes")
def create_recipe(request: RecipeRequest):
    try:
        return recipes.create(request.name, request.description, request.spec, activate=request.activate)
    except RecipeError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/recipes/{recipe_id}/run", status_code=202)
def run_recipe(recipe_id: str):
    if not db.one("SELECT 1 AS ok FROM recipes WHERE id=?", (recipe_id,)):
        raise HTTPException(404, "Recipe not found")
    return jobs.submit("recipe_run", {"recipe_id": recipe_id})


@app.post("/api/recipes/{recipe_id}/activate")
def activate_recipe(recipe_id: str):
    try:
        return recipes.activate(recipe_id)
    except RecipeError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/catalog")
def knowledge_catalog():
    return catalog(db)


@app.post("/api/catalog/artifacts")
def add_dataset_artifact(request: DatasetArtifactRequest):
    try:
        return register_artifact(settings, db, request.dataset_id, request.path)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/detections/rules")
def detection_rules():
    return detections.rules()


@app.patch("/api/detections/rules/{rule_id}")
def update_detection_rule(rule_id: str, request: DetectionRuleUpdateRequest):
    try:
        return detections.update_rule(rule_id, enabled=request.enabled, confidence_floor=request.confidence_floor, spec=request.spec)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/detections/run", status_code=202)
def run_detections(request: DetectionRunRequest):
    return jobs.submit("detection", request.model_dump())


@app.get("/api/detections/runs")
def detection_runs(limit: int = Query(default=50, ge=1, le=200)):
    return db.rows("SELECT * FROM detection_runs ORDER BY started_at DESC LIMIT ?", (limit,))


@app.get("/api/incidents")
def incidents(limit: int = Query(default=100, ge=1, le=500)):
    return detections.list_incidents(limit)


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str):
    try:
        return detections.get_incident(incident_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, request: IncidentUpdateRequest):
    try:
        return detections.update_incident(incident_id, request.status, request.note)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/knowledge")
def knowledge_stats():
    return knowledge.stats()


@app.post("/api/knowledge/search")
def search_knowledge(request: KnowledgeSearchRequest):
    return {"query": request.query, "results": knowledge.search(request.query, request.limit), "stats": knowledge.stats()}


@app.post("/api/knowledge/import/attack-stix")
def import_attack_knowledge(request: KnowledgeImportRequest):
    try:
        return knowledge.import_attack_stix(request.path, request.revision)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/energy/settings")
def get_energy_settings():
    return energy_settings(db)


@app.put("/api/energy/settings")
def set_energy_settings(request: EnergySettingsRequest):
    try:
        return update_energy_settings(db, request.electricity_eur_per_kwh, request.cpu_max_watts, request.cpu_idle_watts)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/energy/live")
def live_energy_metrics():
    return {"active": meter_registry.live(), "settings": energy_settings(db), "note": "GPU power is attributed from board-level samples; CPU energy is TDP-based estimation."}


@app.post("/api/benchmarks/run", status_code=202)
def run_benchmark(request: BenchmarkRequest):
    return jobs.submit("benchmark", request.model_dump())


@app.get("/api/benchmarks")
def benchmark_history(limit: int = Query(default=20, ge=1, le=100)):
    rows = db.rows("SELECT * FROM benchmark_runs ORDER BY started_at DESC LIMIT ?", (limit,))
    for row in rows:
        row["result"] = json.loads(row.pop("result_json"))
    return rows


@app.get("/api/firewalls/adapters")
def firewall_adapters():
    return firewalls.adapters()


@app.get("/api/firewalls/bindings")
def firewall_bindings():
    return firewalls.list_bindings()


@app.get("/api/firewalls/policies")
def firewall_policies():
    return firewalls.list_policies()


@app.post("/api/firewalls/bindings")
def create_firewall_binding(request: FirewallBindingRequest):
    try:
        return firewalls.create_binding(request.name, request.adapter, request.endpoint, request.secret_ref)
    except FirewallError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/firewalls/bindings/{binding_id}/probe")
def probe_firewall_binding(binding_id: str):
    try:
        return firewalls.probe(binding_id)
    except FirewallError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/firewalls/proposals")
def firewall_proposals():
    return firewalls.list_proposals()


@app.post("/api/firewalls/proposals")
def create_firewall_proposal(request: FirewallProposalRequest):
    try:
        return firewalls.propose_block(request.binding_id, request.target, request.reason, request.ttl_seconds, request.evidence)
    except FirewallError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/firewalls/proposals/{proposal_id}/apply")
def apply_firewall_proposal(proposal_id: str, request: FirewallActionRequest):
    try:
        return firewalls.apply_proposal(proposal_id, request.confirmation_hash)
    except FirewallError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/firewalls/proposals/{proposal_id}/rollback")
def rollback_firewall_proposal(proposal_id: str, request: FirewallActionRequest):
    try:
        return firewalls.rollback_proposal(proposal_id, request.confirmation_hash)
    except FirewallError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/audit")
def audit(limit: int = Query(default=100, ge=1, le=1000)):
    return db.rows("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,))


@app.get("/api/stream")
async def stream():
    async def generate():
        previous = None
        while True:
            payload = dashboard_summary(db)
            serialized = json.dumps(payload, ensure_ascii=False)
            if serialized != previous:
                yield f"event: status\ndata: {serialized}\n\n"
                previous = serialized
            await asyncio.sleep(2)
    return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})
