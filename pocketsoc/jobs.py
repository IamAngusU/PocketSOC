from __future__ import annotations

import hashlib
import json
import queue
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from typing import Any

from .db import Database, utcnow
from .metering import MeterRegistry, ResourceMeter


Handler = Callable[[dict[str, Any]], dict[str, Any]]


class JobRunner:
    def __init__(self, db: Database, workers: int = 2, meter_registry: MeterRegistry | None = None):
        self.db = db
        self.workers = max(1, min(workers, 4))
        self.handlers: dict[str, Handler] = {}
        self.queue: queue.Queue[str | None] = queue.Queue(maxsize=100)
        self._started = False
        self._threads: list[threading.Thread] = []
        self.meter_registry = meter_registry or MeterRegistry()

    def register(self, kind: str, handler: Handler) -> None:
        self.handlers[kind] = handler

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        for index in range(self.workers):
            thread = threading.Thread(target=self._worker, name=f"pocketsoc-worker-{index}", daemon=True)
            thread.start(); self._threads.append(thread)
        for row in self.db.rows("SELECT id FROM jobs WHERE status='queued' ORDER BY created_at"):
            try:
                self.queue.put_nowait(row["id"])
            except queue.Full:
                break

    def stop(self) -> None:
        if not self._started:
            return
        for _ in self._threads:
            try:
                self.queue.put_nowait(None)
            except queue.Full:
                break
        for thread in self._threads:
            thread.join(timeout=10)
        self._threads.clear()
        self._started = False

    def submit(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if kind not in self.handlers:
            raise ValueError(f"No handler registered for {kind}")
        canonical = json.dumps({"kind": kind, "payload": payload}, sort_keys=True, separators=(",", ":"))
        input_hash = hashlib.sha256(canonical.encode()).hexdigest()
        existing = self.db.one("SELECT * FROM jobs WHERE input_hash=? AND status IN ('queued','running') ORDER BY created_at DESC LIMIT 1", (input_hash,))
        if existing:
            return existing
        job_id = f"job_{uuid.uuid4().hex}"
        self.db.execute(
            "INSERT INTO jobs(id,kind,input_hash,payload_json,status,stage,created_at) VALUES(?,?,?,?,?,?,?)",
            (job_id, kind, input_hash, json.dumps(payload), "queued", "queued", utcnow()),
        )
        self.db.audit("job.submit", "ok", target=job_id, detail={"kind": kind, "input_hash": input_hash})
        self.queue.put_nowait(job_id)
        return self.db.one("SELECT * FROM jobs WHERE id=?", (job_id,)) or {"id": job_id}

    def _worker(self) -> None:
        while True:
            job_id = self.queue.get()
            try:
                if job_id is None:
                    return
                self._execute(job_id)
            finally:
                self.queue.task_done()

    def _execute(self, job_id: str) -> None:
        job = self.db.one("SELECT * FROM jobs WHERE id=?", (job_id,))
        if not job or job["status"] not in {"queued", "running"}:
            return
        handler = self.handlers.get(job["kind"])
        if not handler:
            self.db.execute("UPDATE jobs SET status='failed',stage='dispatch',finished_at=?,error=? WHERE id=?", (utcnow(), "Handler unavailable", job_id))
            return
        started_wall = utcnow()
        started = time.perf_counter()
        self.db.execute("UPDATE jobs SET status='running',stage='executing',started_at=?,attempt=attempt+1 WHERE id=?", (started_wall, job_id))
        meter = ResourceMeter(self.db, job_id, self.meter_registry)
        try:
            result = handler(json.loads(job["payload_json"]))
            try:
                result["resource_cost"] = meter.finish()
            except Exception as metric_exc:
                result["resource_cost"] = {"available": False, "error": f"{type(metric_exc).__name__}: {metric_exc}"}
            elapsed = round((time.perf_counter() - started) * 1000)
            self.db.execute("UPDATE jobs SET status='completed',stage='done',finished_at=?,elapsed_ms=?,result_json=?,error=NULL WHERE id=?", (utcnow(), elapsed, json.dumps(result, ensure_ascii=False), job_id))
            self.db.audit("job.complete", "ok", target=job_id, detail={"kind": job["kind"], "elapsed_ms": elapsed})
        except Exception as exc:
            try:
                meter.finish()
            except Exception:
                pass
            elapsed = round((time.perf_counter() - started) * 1000)
            error = f"{type(exc).__name__}: {exc}"
            self.db.execute("UPDATE jobs SET status='failed',stage='failed',finished_at=?,elapsed_ms=?,error=? WHERE id=?", (utcnow(), elapsed, error[:4000], job_id))
            self.db.audit("job.complete", "failed", target=job_id, detail={"kind": job["kind"], "elapsed_ms": elapsed, "error": error, "trace": traceback.format_exc()[-4000:]})
