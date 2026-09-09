from __future__ import annotations

import json
import statistics
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable

import psutil

from .config import Settings
from .db import Database, utcnow
from .detection import DetectionService
from .knowledge import KnowledgeIndex


class BenchmarkService:
    def __init__(self, settings: Settings, db: Database, detections: DetectionService, knowledge: KnowledgeIndex):
        self.settings = settings
        self.db = db
        self.detections = detections
        self.knowledge = knowledge

    @staticmethod
    def _measure(function: Callable[[], Any], repeats: int) -> tuple[list[float], Any]:
        timings = []; last = None
        for _ in range(repeats):
            started = time.perf_counter(); last = function(); timings.append((time.perf_counter() - started) * 1000)
        return timings, last

    @staticmethod
    def _summary(timings: list[float]) -> dict[str, float]:
        ordered = sorted(timings)
        p95_index = max(0, min(len(ordered) - 1, round(0.95 * (len(ordered) - 1))))
        return {"runs": len(ordered), "p50_ms": round(statistics.median(ordered), 3), "p95_ms": round(ordered[p95_index], 3), "min_ms": round(min(ordered), 3), "max_ms": round(max(ordered), 3)}

    def _decode(self, path: Path, display_filter: str | None = None) -> dict[str, Any]:
        argv = [str(self.settings.tshark_path), "-n", "-r", str(path)]
        if display_filter:
            argv.extend(["-Y", display_filter])
        argv.extend(["-T", "fields", "-e", "frame.number"])
        completed = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or "TShark benchmark failed")[-2000:])
        return {"frames": len([line for line in completed.stdout.splitlines() if line.strip()]), "bytes": path.stat().st_size}

    def run(self, repeats: int = 5) -> dict[str, Any]:
        repeats = max(3, min(int(repeats), 20))
        started_at = utcnow(); cpu_started = time.process_time(); process = psutil.Process(); rss_started = process.memory_info().rss
        official = self.settings.datasets_dir / "wireshark-sample-captures" / "dns.cap"
        captures = sorted(self.settings.captures_dir.glob("*.pcap*"), key=lambda path: path.stat().st_size, reverse=True)
        corpus = official if official.is_file() else (captures[0] if captures else None)
        if not corpus:
            raise RuntimeError("No validated PCAP benchmark corpus is available")
        decode_times, decode_result = self._measure(lambda: self._decode(corpus), repeats)
        filter_times, filter_result = self._measure(lambda: self._decode(corpus, "dns"), repeats)
        sql_times, sql_result = self._measure(lambda: self.db.rows("SELECT device_key,event_type,COUNT(*) AS n FROM events GROUP BY device_key,event_type ORDER BY n DESC LIMIT 50"), 50)
        rag_times, rag_result = self._measure(lambda: self.knowledge.search("ARP cache poisoning adversary in the middle replay", 8), 20)
        detection_times, detection_result = self._measure(lambda: self.detections.run(1440), 3)
        decode = self._summary(decode_times); filtered = self._summary(filter_times)
        seconds = max(decode["p50_ms"] / 1000, 0.000001)
        decode.update({"frames": decode_result["frames"], "bytes": decode_result["bytes"], "frames_per_second": round(decode_result["frames"] / seconds, 1), "mib_per_second": round((decode_result["bytes"] / 1024**2) / seconds, 3)})
        result = {
            "profile": self.settings.profile,
            "corpus": {"path": str(corpus), "bytes": corpus.stat().st_size, "limitation": "This installed corpus is small; results measure local overhead, not maximum sustained capture throughput."},
            "tshark_decode": decode,
            "tshark_dns_filter": {**self._summary(filter_times), "matched_frames": filter_result["frames"]},
            "sqlite_aggregate": {**self._summary(sql_times), "rows": len(sql_result)},
            "knowledge_bm25": {**self._summary(rag_times), "hits": len(rag_result)},
            "detection_engine": {**self._summary(detection_times), "events_examined": detection_result["events_examined"], "findings": detection_result["findings"]},
            "process": {"cpu_seconds": round(time.process_time() - cpu_started, 6), "rss_start_bytes": rss_started, "rss_end_bytes": process.memory_info().rss},
            "not_measured": ["capture packet-loss ceiling", "sustained Mbit/s", "energy from a wall meter", "dataset recall/false-positive rate"],
        }
        run_id = f"bench_{uuid.uuid4().hex}"
        self.db.execute("INSERT INTO benchmark_runs(id,started_at,finished_at,profile,result_json) VALUES(?,?,?,?,?)", (run_id, started_at, utcnow(), self.settings.profile, json.dumps(result, ensure_ascii=False)))
        self.db.audit("benchmark.run", "ok", target=run_id, detail={"corpus": str(corpus), "repeats": repeats})
        return {"run_id": run_id, **result}
