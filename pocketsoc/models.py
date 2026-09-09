from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class ToolRunRequest(BaseModel):
    tool: Literal[
        "ping", "trace", "dns", "neighbors", "listeners", "connections", "network_scan"
    ]
    target: str | None = Field(default=None, max_length=253)
    profile: Literal["discovery", "common_ports"] = "discovery"


class CaptureRequest(BaseModel):
    interface: int = Field(ge=1, le=128)
    duration_seconds: int = Field(default=10, ge=2, le=120)
    max_packets: int = Field(default=2500, ge=10, le=25_000)


class PcapAnalyzeRequest(BaseModel):
    path: str = Field(min_length=1, max_length=1024)

    @field_validator("path")
    @classmethod
    def capture_extension(cls, value: str) -> str:
        suffix = Path(value).suffix.lower()
        if suffix not in {".pcap", ".pcapng", ".cap"}:
            raise ValueError("Only .pcap, .pcapng and .cap files are accepted")
        return value


class WiresharkOpenRequest(PcapAnalyzeRequest):
    display_filter: str | None = Field(default=None, max_length=500)


class MonitorRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    kind: Literal["neighbors", "connections", "system_events", "tool_evolution", "detections", "sensor_ingest"]
    interval_seconds: int = Field(default=300, ge=60, le=86_400)
    config: dict[str, Any] = Field(default_factory=dict)


class QueryRequest(BaseModel):
    question: str = Field(min_length=2, max_length=1000)
    use_llm: bool = False


class ToolLabRequest(BaseModel):
    prompt: str = Field(min_length=8, max_length=2000)
    use_llm: bool = True


class ToolEvolveRequest(BaseModel):
    use_llm: bool = True


class FilterRequest(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    kind: Literal["wireshark_display", "capture_bpf"]
    expression_template: str = Field(min_length=1, max_length=1000)
    parameters: dict[str, Any] = Field(default_factory=dict)
    activate: bool = True


class FilterGenerateRequest(BaseModel):
    prompt: str = Field(min_length=5, max_length=1500)
    use_llm: bool = True


class FilterTestRequest(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)
    capture_path: str | None = Field(default=None, max_length=1024)


class RecipeRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)
    spec: dict[str, Any]
    activate: bool = True


class FirewallBindingRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    adapter: Literal["windows", "opnsense", "openwrt"]
    endpoint: str | None = Field(default=None, max_length=500)
    secret_ref: str | None = Field(default=None, max_length=200)


class FirewallProposalRequest(BaseModel):
    binding_id: str = Field(min_length=3, max_length=80)
    target: str = Field(min_length=2, max_length=64)
    reason: str = Field(min_length=3, max_length=500)
    ttl_seconds: int | None = Field(default=3600, ge=300, le=604800)
    evidence: list[str] = Field(default_factory=list, max_length=100)


class FirewallActionRequest(BaseModel):
    confirmation_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class DatasetArtifactRequest(BaseModel):
    dataset_id: str = Field(min_length=2, max_length=100)
    path: str = Field(min_length=3, max_length=1024)


class DetectionRunRequest(BaseModel):
    window_minutes: int = Field(default=60, ge=1, le=1440)


class DetectionRuleUpdateRequest(BaseModel):
    enabled: bool | None = None
    confidence_floor: float | None = Field(default=None, ge=0, le=1)
    spec: dict[str, Any] | None = None


class IncidentUpdateRequest(BaseModel):
    status: Literal["open", "acknowledged", "closed", "false_positive"]
    note: str = Field(default="", max_length=1000)


class SensorSourceRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    kind: Literal["suricata_eve"] = "suricata_eve"
    path: str = Field(min_length=3, max_length=1024)
    enabled: bool = True


class SensorSourceUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    enabled: bool | None = None


class SensorIngestRequest(BaseModel):
    max_records: int = Field(default=10_000, ge=1, le=100_000)
    reset_checkpoint: bool = False


class KnowledgeSearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=1000)
    limit: int = Field(default=8, ge=1, le=20)


class KnowledgeImportRequest(BaseModel):
    path: str = Field(min_length=3, max_length=1024)
    revision: str = Field(min_length=1, max_length=40)


class EnergySettingsRequest(BaseModel):
    electricity_eur_per_kwh: float = Field(ge=0, le=5)
    cpu_max_watts: float = Field(ge=10, le=1000)
    cpu_idle_watts: float = Field(ge=0, le=500)


class CaptureRetentionRequest(BaseModel):
    state: Literal["rolling", "incident_locked", "manually_locked", "pending_export", "deletable"]
    reason: str | None = Field(default=None, max_length=500)


class BenchmarkRequest(BaseModel):
    repeats: int = Field(default=5, ge=3, le=20)


class DeviceUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=100)
    state: Literal["unclassified", "known", "trusted", "guest", "blocked"] | None = None
