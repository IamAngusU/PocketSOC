from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL,
  stage TEXT NOT NULL DEFAULT 'queued',
  attempt INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  elapsed_ms INTEGER,
  result_json TEXT,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  event_type TEXT NOT NULL,
  source TEXT NOT NULL,
  device_key TEXT,
  severity TEXT NOT NULL DEFAULT 'info',
  data_json TEXT NOT NULL,
  evidence_ref TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_key, ts DESC);

CREATE TABLE IF NOT EXISTS devices (
  device_key TEXT PRIMARY KEY,
  display_name TEXT,
  state TEXT NOT NULL DEFAULT 'unclassified',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  addresses_json TEXT NOT NULL DEFAULT '[]',
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,
  device_key TEXT,
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  confidence REAL NOT NULL,
  state TEXT NOT NULL DEFAULT 'open',
  evidence_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_observations_ts ON observations(ts DESC);

CREATE TABLE IF NOT EXISTS baselines (
  device_key TEXT NOT NULL,
  feature TEXT NOT NULL,
  value TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  seen_count INTEGER NOT NULL DEFAULT 1,
  confirmed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(device_key, feature, value)
);

CREATE TABLE IF NOT EXISTS monitors (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  interval_seconds INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  config_json TEXT NOT NULL DEFAULT '{}',
  last_run_at TEXT,
  next_run_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS generated_tools (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  prompt TEXT NOT NULL,
  version INTEGER NOT NULL,
  status TEXT NOT NULL,
  spec_json TEXT NOT NULL,
  validation_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_evaluations (
  id TEXT PRIMARY KEY,
  tool_id TEXT NOT NULL REFERENCES generated_tools(id),
  ts TEXT NOT NULL,
  corpus TEXT NOT NULL,
  metrics_json TEXT NOT NULL,
  decision TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tool_evaluations_tool ON tool_evaluations(tool_id, ts DESC);

CREATE TABLE IF NOT EXISTS filters (
  id TEXT PRIMARY KEY,
  lineage_id TEXT NOT NULL,
  parent_id TEXT,
  name TEXT NOT NULL,
  version INTEGER NOT NULL,
  kind TEXT NOT NULL,
  expression_template TEXT NOT NULL,
  parameters_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL,
  validation_json TEXT NOT NULL DEFAULT '{}',
  score_json TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL DEFAULT 'local-user',
  created_at TEXT NOT NULL,
  activated_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_filters_name_version ON filters(name, version);
CREATE INDEX IF NOT EXISTS idx_filters_lineage ON filters(lineage_id, version DESC);

CREATE TABLE IF NOT EXISTS recipes (
  id TEXT PRIMARY KEY,
  lineage_id TEXT NOT NULL,
  parent_id TEXT,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  version INTEGER NOT NULL,
  status TEXT NOT NULL,
  spec_json TEXT NOT NULL,
  validation_json TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL DEFAULT 'local-user',
  created_at TEXT NOT NULL,
  activated_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_recipes_name_version ON recipes(name, version);
CREATE INDEX IF NOT EXISTS idx_recipes_lineage ON recipes(lineage_id, version DESC);

CREATE TABLE IF NOT EXISTS recipe_runs (
  id TEXT PRIMARY KEY,
  recipe_id TEXT NOT NULL REFERENCES recipes(id),
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  status TEXT NOT NULL,
  result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recipe_runs_recipe ON recipe_runs(recipe_id, started_at DESC);

CREATE TABLE IF NOT EXISTS dataset_catalog (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  source_url TEXT NOT NULL,
  publisher TEXT NOT NULL,
  purpose TEXT NOT NULL,
  scale TEXT NOT NULL,
  license_note TEXT NOT NULL,
  risk TEXT NOT NULL,
  local_status TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  manifest_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integration_catalog (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  source_url TEXT NOT NULL,
  role TEXT NOT NULL,
  platform TEXT NOT NULL,
  status TEXT NOT NULL,
  fit TEXT NOT NULL,
  constraints TEXT NOT NULL,
  manifest_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dataset_artifacts (
  id TEXT PRIMARY KEY,
  dataset_id TEXT NOT NULL REFERENCES dataset_catalog(id),
  path TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  validation_json TEXT NOT NULL,
  registered_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dataset_artifacts_dataset ON dataset_artifacts(dataset_id, registered_at DESC);

CREATE TABLE IF NOT EXISTS capture_artifacts (
  id TEXT PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  evidence_ref TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  retention_state TEXT NOT NULL DEFAULT 'rolling',
  lock_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_capture_artifacts_evidence ON capture_artifacts(evidence_ref);

CREATE TABLE IF NOT EXISTS detection_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  version INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  severity TEXT NOT NULL,
  confidence_floor REAL NOT NULL,
  spec_json TEXT NOT NULL,
  knowledge_refs_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detection_runs (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  window_minutes INTEGER NOT NULL,
  events_examined INTEGER NOT NULL,
  findings INTEGER NOT NULL,
  elapsed_ms INTEGER NOT NULL,
  metrics_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  rule_id TEXT NOT NULL REFERENCES detection_rules(id),
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  target TEXT,
  summary TEXT NOT NULL,
  claims_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  alternatives_json TEXT NOT NULL,
  response_state TEXT NOT NULL DEFAULT 'none',
  UNIQUE(fingerprint, status)
);
CREATE INDEX IF NOT EXISTS idx_incidents_seen ON incidents(last_seen DESC);

CREATE TABLE IF NOT EXISTS incident_history (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  from_status TEXT,
  to_status TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_incident_history_incident ON incident_history(incident_id, ts DESC);

CREATE TABLE IF NOT EXISTS incident_artifacts (
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  capture_artifact_id TEXT NOT NULL REFERENCES capture_artifacts(id),
  linked_at TEXT NOT NULL,
  PRIMARY KEY(incident_id, capture_artifact_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_artifacts_capture ON incident_artifacts(capture_artifact_id);

CREATE TABLE IF NOT EXISTS sensor_sources (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  path TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  checkpoint_bytes INTEGER NOT NULL DEFAULT 0,
  file_identity TEXT,
  last_size INTEGER NOT NULL DEFAULT 0,
  last_event_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sensor_sources_kind ON sensor_sources(kind, enabled);

CREATE TABLE IF NOT EXISTS sensor_records (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES sensor_sources(id),
  sensor_event_type TEXT NOT NULL,
  ts TEXT NOT NULL,
  severity TEXT NOT NULL,
  signature TEXT,
  category TEXT,
  action TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  proto TEXT,
  app_proto TEXT,
  flow_id TEXT,
  data_json TEXT NOT NULL,
  raw_sha256 TEXT NOT NULL,
  ingested_at TEXT NOT NULL,
  UNIQUE(source_id, raw_sha256)
);
CREATE INDEX IF NOT EXISTS idx_sensor_records_source ON sensor_records(source_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_sensor_records_alert ON sensor_records(sensor_event_type, severity, ts DESC);
CREATE INDEX IF NOT EXISTS idx_sensor_records_src ON sensor_records(src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS idx_sensor_records_dst ON sensor_records(dst_ip, ts DESC);

CREATE TABLE IF NOT EXISTS response_policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  mode TEXT NOT NULL DEFAULT 'propose',
  min_confidence REAL NOT NULL DEFAULT 0.95,
  max_actions_per_hour INTEGER NOT NULL DEFAULT 3,
  ttl_seconds INTEGER NOT NULL DEFAULT 3600,
  allowed_rules_json TEXT NOT NULL DEFAULT '[]',
  binding_id TEXT REFERENCES firewall_bindings(id),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_documents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  source_url TEXT NOT NULL,
  source_type TEXT NOT NULL,
  revision TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  indexed_at TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(id UNINDEXED, title, body, tokenize='unicode61 remove_diacritics 2');

CREATE TABLE IF NOT EXISTS energy_settings (
  id TEXT PRIMARY KEY CHECK(id='default'),
  electricity_eur_per_kwh REAL NOT NULL DEFAULT 0.30,
  cpu_max_watts REAL NOT NULL DEFAULT 241.0,
  cpu_idle_watts REAL NOT NULL DEFAULT 12.0,
  gpu_meter TEXT NOT NULL DEFAULT 'nvidia-smi',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS job_metrics (
  job_id TEXT PRIMARY KEY REFERENCES jobs(id),
  samples INTEGER NOT NULL,
  wall_seconds REAL NOT NULL,
  process_cpu_seconds REAL NOT NULL,
  peak_rss_bytes INTEGER NOT NULL,
  avg_system_cpu_percent REAL,
  gpu_active_seconds REAL,
  gpu_energy_kwh REAL,
  cpu_energy_kwh_estimated REAL,
  total_energy_kwh_estimated REAL,
  electricity_cost_eur_estimated REAL,
  compute_units REAL,
  confidence TEXT NOT NULL,
  sources_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS benchmark_runs (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  profile TEXT NOT NULL,
  result_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS firewall_bindings (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  adapter TEXT NOT NULL,
  endpoint TEXT,
  secret_ref TEXT,
  status TEXT NOT NULL,
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  last_checked_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS firewall_proposals (
  id TEXT PRIMARY KEY,
  binding_id TEXT REFERENCES firewall_bindings(id),
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  reason TEXT NOT NULL,
  ttl_seconds INTEGER,
  status TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  rollback_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_firewall_proposals_created ON firewall_proposals(created_at DESC);

CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  outcome TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}'
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Database:
    def __init__(self, path: Path):
        self.path = path
        self._write_lock = threading.RLock()
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = self.connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
            self._migrate(conn)
            conn.execute("INSERT OR IGNORE INTO energy_settings(id,updated_at) VALUES('default',?)", (utcnow(),))
            conn.execute(
                "UPDATE jobs SET status='queued', stage='recovered' WHERE status='running'"
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Small additive migrations keep existing local evidence/history intact."""
        columns = {row[1] for row in conn.execute("PRAGMA table_info(generated_tools)")}
        additions = {
            "lineage_id": "TEXT",
            "parent_id": "TEXT",
            "score_json": "TEXT NOT NULL DEFAULT '{}'",
            "activated_at": "TEXT",
        }
        for name, declaration in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE generated_tools ADD COLUMN {name} {declaration}")
        conn.execute("UPDATE generated_tools SET lineage_id=id WHERE lineage_id IS NULL OR lineage_id='' ")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._write_lock:
            conn = self.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        conn = self.connect()
        try:
            return [dict(row) for row in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = self.rows(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self.tx() as conn:
            conn.execute(sql, params)

    def audit(
        self,
        action: str,
        outcome: str,
        *,
        target: str | None = None,
        detail: dict[str, Any] | None = None,
        actor: str = "local-user",
    ) -> None:
        self.execute(
            "INSERT INTO audit(ts,actor,action,target,outcome,detail_json) VALUES(?,?,?,?,?,?)",
            (utcnow(), actor, action, target, outcome, json.dumps(detail or {}, ensure_ascii=False)),
        )
