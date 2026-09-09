from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any

import psutil

from .db import Database, utcnow


@dataclass
class Sample:
    at: float
    system_cpu_percent: float
    rss_bytes: int
    gpu_power_watts: float | None
    gpu_util_percent: float | None
    gpu_memory_mib: float | None


def _gpu_sample() -> tuple[float | None, float | None, float | None]:
    executable = shutil.which("nvidia-smi")
    if not executable:
        return None, None, None
    try:
        result = subprocess.run([executable, "--query-gpu=power.draw,utilization.gpu,memory.used", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=3, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode != 0 or not result.stdout.strip():
            return None, None, None
        first = result.stdout.splitlines()[0].split(",")
        return tuple(float(value.strip()) for value in first[:3])  # type: ignore[return-value]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None, None, None


class MeterRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._active: dict[str, dict[str, Any]] = {}

    def update(self, job_id: str, sample: Sample, started_at: float) -> None:
        with self._lock:
            self._active[job_id] = {"job_id": job_id, "wall_seconds": round(sample.at - started_at, 3), "system_cpu_percent": sample.system_cpu_percent, "rss_bytes": sample.rss_bytes, "gpu_power_watts": sample.gpu_power_watts, "gpu_util_percent": sample.gpu_util_percent, "gpu_memory_mib": sample.gpu_memory_mib, "source": "live sampler"}

    def remove(self, job_id: str) -> None:
        with self._lock:
            self._active.pop(job_id, None)

    def live(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._active.values())


class ResourceMeter:
    def __init__(self, db: Database, job_id: str, registry: MeterRegistry):
        self.db = db
        self.job_id = job_id
        self.registry = registry
        self.process = psutil.Process()
        self.started = time.monotonic()
        cpu = self.process.cpu_times()
        self.cpu_started = cpu.user + cpu.system
        self.samples: list[Sample] = []
        self._stop = threading.Event()
        psutil.cpu_percent(interval=None)
        self._sample()
        self._thread = threading.Thread(target=self._loop, name=f"meter-{job_id[-8:]}", daemon=True)
        self._thread.start()

    def _sample(self) -> None:
        try:
            power, util, memory = _gpu_sample()
            sample = Sample(time.monotonic(), psutil.cpu_percent(interval=None), self.process.memory_info().rss, power, util, memory)
            self.samples.append(sample)
            self.registry.update(self.job_id, sample, self.started)
        except (psutil.Error, OSError):
            pass

    def _loop(self) -> None:
        while not self._stop.wait(0.5):
            self._sample()

    def finish(self) -> dict[str, Any]:
        self._stop.set(); self._thread.join(timeout=2); self._sample()
        wall = max(time.monotonic() - self.started, 0.0001)
        cpu = self.process.cpu_times(); process_cpu = max(0.0, cpu.user + cpu.system - self.cpu_started)
        settings = self.db.one("SELECT * FROM energy_settings WHERE id='default'") or {"electricity_eur_per_kwh": 0.30, "cpu_max_watts": 241.0, "cpu_idle_watts": 12.0}
        avg_cpu = sum(sample.system_cpu_percent for sample in self.samples) / len(self.samples) if self.samples else 0.0
        peak_rss = max((sample.rss_bytes for sample in self.samples), default=self.process.memory_info().rss)
        logical = max(psutil.cpu_count(logical=True) or 1, 1)
        attributed_cpu_util = min(1.0, process_cpu / (wall * logical))
        cpu_watts = float(settings["cpu_idle_watts"]) + (float(settings["cpu_max_watts"]) - float(settings["cpu_idle_watts"])) * attributed_cpu_util
        cpu_energy = cpu_watts * wall / 3_600_000
        gpu_energy = 0.0; gpu_active_seconds = 0.0
        gpu_available = False
        for left, right in zip(self.samples, self.samples[1:]):
            if left.gpu_power_watts is None or left.gpu_util_percent is None:
                continue
            gpu_available = True
            seconds = max(0.0, right.at - left.at)
            fraction = max(0.0, min(1.0, left.gpu_util_percent / 100))
            gpu_active_seconds += seconds * fraction
            gpu_energy += left.gpu_power_watts * fraction * seconds / 3_600_000
        total = cpu_energy + gpu_energy
        cost = total * float(settings["electricity_eur_per_kwh"])
        ram_gib_seconds = (peak_rss / 1024**3) * wall
        compute_units = process_cpu + 4 * gpu_active_seconds + ram_gib_seconds / 8
        sources = {"cpu": "TDP-based attribution from process CPU time (estimated)", "gpu": "nvidia-smi board power weighted by GPU utilization (attributed)" if gpu_available else "unavailable", "ram": "process RSS samples", "price": "user configuration"}
        confidence = "medium" if gpu_available and len(self.samples) >= 3 else "low"
        metrics = {"job_id": self.job_id, "samples": len(self.samples), "wall_seconds": round(wall, 6), "process_cpu_seconds": round(process_cpu, 6), "peak_rss_bytes": peak_rss, "avg_system_cpu_percent": round(avg_cpu, 3), "gpu_active_seconds": round(gpu_active_seconds, 6), "gpu_energy_kwh": gpu_energy, "cpu_energy_kwh_estimated": cpu_energy, "total_energy_kwh_estimated": total, "electricity_cost_eur_estimated": cost, "compute_units": round(compute_units, 6), "confidence": confidence, "sources": sources}
        self.db.execute("INSERT OR REPLACE INTO job_metrics(job_id,samples,wall_seconds,process_cpu_seconds,peak_rss_bytes,avg_system_cpu_percent,gpu_active_seconds,gpu_energy_kwh,cpu_energy_kwh_estimated,total_energy_kwh_estimated,electricity_cost_eur_estimated,compute_units,confidence,sources_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (self.job_id, metrics["samples"], metrics["wall_seconds"], metrics["process_cpu_seconds"], peak_rss, metrics["avg_system_cpu_percent"], metrics["gpu_active_seconds"], gpu_energy, cpu_energy, total, cost, metrics["compute_units"], confidence, json.dumps(sources), utcnow()))
        self.registry.remove(self.job_id)
        return metrics


def energy_settings(db: Database) -> dict[str, Any]:
    return db.one("SELECT * FROM energy_settings WHERE id='default'") or {}


def update_energy_settings(db: Database, electricity_eur_per_kwh: float, cpu_max_watts: float, cpu_idle_watts: float) -> dict[str, Any]:
    if not 0 <= electricity_eur_per_kwh <= 5:
        raise ValueError("Electricity price must be between 0 and 5 EUR/kWh")
    if not 10 <= cpu_max_watts <= 1000 or not 0 <= cpu_idle_watts < cpu_max_watts:
        raise ValueError("CPU watt assumptions are inconsistent")
    db.execute("UPDATE energy_settings SET electricity_eur_per_kwh=?,cpu_max_watts=?,cpu_idle_watts=?,updated_at=? WHERE id='default'", (electricity_eur_per_kwh, cpu_max_watts, cpu_idle_watts, utcnow()))
    db.audit("energy.settings.update", "ok", detail={"electricity_eur_per_kwh": electricity_eur_per_kwh, "cpu_max_watts": cpu_max_watts, "cpu_idle_watts": cpu_idle_watts})
    return energy_settings(db)
