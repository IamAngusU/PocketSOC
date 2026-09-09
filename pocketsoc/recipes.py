from __future__ import annotations

import json
import time
import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, model_validator

from .db import Database, utcnow
from .filters import FilterService
from .workflow import SafeToolLab


class RecipeError(ValueError):
    pass


class RecipeStep(BaseModel):
    type: Literal["filter_test", "analyzer_run", "evidence_summary"]
    filter_id: str | None = Field(default=None, pattern=r"^flt_[a-f0-9]{32}$")
    tool_id: str | None = Field(default=None, pattern=r"^tool_[a-f0-9]{32}$")
    values: dict[str, Any] = Field(default_factory=dict)
    capture_path: str | None = Field(default=None, max_length=1024)
    event_limit: int = Field(default=100, ge=1, le=1000)

    @model_validator(mode="after")
    def references_match_step(self):
        if self.type == "filter_test" and not self.filter_id:
            raise ValueError("filter_test requires filter_id")
        if self.type == "analyzer_run" and not self.tool_id:
            raise ValueError("analyzer_run requires tool_id")
        return self


class RecipeSpec(BaseModel):
    steps: list[RecipeStep] = Field(min_length=1, max_length=12)
    stop_on_error: bool = True


class RecipeService:
    """Runs only a small declarative workflow language; recipes never contain host code."""

    def __init__(self, db: Database, filters: FilterService, tool_lab: SafeToolLab):
        self.db = db
        self.filters = filters
        self.tool_lab = tool_lab

    def _validate_refs(self, spec: RecipeSpec) -> dict[str, Any]:
        checks = []
        for index, step in enumerate(spec.steps):
            exists = True
            if step.filter_id:
                exists = bool(self.db.one("SELECT 1 AS ok FROM filters WHERE id=? AND status!='rejected'", (step.filter_id,)))
            if step.tool_id:
                exists = bool(self.db.one("SELECT 1 AS ok FROM generated_tools WHERE id=? AND status='active'", (step.tool_id,)))
            checks.append({"step": index, "type": step.type, "reference_ok": exists})
        return {"passed": all(item["reference_ok"] for item in checks), "checks": checks, "execution_model": "declarative_allowlist"}

    def create(self, name: str, description: str, raw_spec: dict[str, Any], *, activate: bool = True, created_by: str = "local-user") -> dict[str, Any]:
        if not name or len(name) > 80:
            raise RecipeError("Recipe name must be 1-80 characters")
        try:
            spec = RecipeSpec.model_validate(raw_spec)
        except ValidationError as exc:
            raise RecipeError(str(exc)) from exc
        validation = self._validate_refs(spec)
        previous = self.db.one("SELECT * FROM recipes WHERE name=? ORDER BY version DESC LIMIT 1", (name,))
        version = int(previous["version"]) + 1 if previous else 1
        recipe_id = f"rcp_{uuid.uuid4().hex}"
        lineage_id = previous["lineage_id"] if previous else recipe_id
        status = "active" if activate and validation["passed"] else ("candidate" if validation["passed"] else "rejected")
        with self.db.tx() as conn:
            if status == "active":
                conn.execute("UPDATE recipes SET status='retired' WHERE name=? AND status='active'", (name,))
            conn.execute(
                "INSERT INTO recipes(id,lineage_id,parent_id,name,description,version,status,spec_json,validation_json,created_by,created_at,activated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (recipe_id, lineage_id, previous["id"] if previous else None, name, description[:500], version, status, spec.model_dump_json(), json.dumps(validation), created_by, utcnow(), utcnow() if status == "active" else None),
            )
        self.db.audit("recipe.create", status, target=recipe_id, detail={"name": name, "version": version, "validation": validation})
        return self.get(recipe_id)

    def get(self, recipe_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM recipes WHERE id=?", (recipe_id,))
        if not row:
            raise RecipeError("Recipe not found")
        row["spec"] = json.loads(row["spec_json"])
        row["validation"] = json.loads(row["validation_json"])
        return row

    def list(self) -> list[dict[str, Any]]:
        return [self.get(row["id"]) for row in self.db.rows("SELECT id FROM recipes ORDER BY created_at DESC LIMIT 200")]

    def activate(self, recipe_id: str) -> dict[str, Any]:
        row = self.get(recipe_id)
        spec = RecipeSpec.model_validate(row["spec"])
        validation = self._validate_refs(spec)
        if not validation["passed"]:
            raise RecipeError("A referenced filter or analyzer no longer exists")
        with self.db.tx() as conn:
            conn.execute("UPDATE recipes SET status='retired' WHERE name=? AND status='active'", (row["name"],))
            conn.execute("UPDATE recipes SET status='active',activated_at=?,validation_json=? WHERE id=?", (utcnow(), json.dumps(validation), recipe_id))
        self.db.audit("recipe.activate", "ok", target=recipe_id, detail={"version": row["version"]})
        return self.get(recipe_id)

    def run(self, recipe_id: str) -> dict[str, Any]:
        row = self.get(recipe_id)
        spec = RecipeSpec.model_validate(row["spec"])
        started_at = utcnow()
        started = time.perf_counter()
        results = []
        status = "completed"
        for index, step in enumerate(spec.steps):
            try:
                if step.type == "filter_test":
                    value = self.filters.test(step.filter_id or "", step.values, step.capture_path)
                elif step.type == "analyzer_run":
                    value = self.tool_lab.run_proposal(step.tool_id or "")
                else:
                    value = {
                        "events": self.db.one("SELECT COUNT(*) AS n FROM events")["n"],
                        "devices": self.db.one("SELECT COUNT(*) AS n FROM devices")["n"],
                        "open_observations": self.db.one("SELECT COUNT(*) AS n FROM observations WHERE state='open'")["n"],
                        "latest_observations": self.db.rows("SELECT id,ts,title,device_key,confidence,evidence_json FROM observations ORDER BY ts DESC LIMIT ?", (step.event_limit,)),
                    }
                results.append({"step": index, "type": step.type, "ok": True, "result": value})
            except Exception as exc:
                status = "failed"
                results.append({"step": index, "type": step.type, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
                if spec.stop_on_error:
                    break
        result = {"recipe_id": recipe_id, "version": row["version"], "status": status, "elapsed_ms": round((time.perf_counter() - started) * 1000), "steps": results}
        run_id = f"rrun_{uuid.uuid4().hex}"
        self.db.execute("INSERT INTO recipe_runs(id,recipe_id,started_at,finished_at,status,result_json) VALUES(?,?,?,?,?,?)", (run_id, recipe_id, started_at, utcnow(), status, json.dumps(result, ensure_ascii=False)))
        self.db.audit("recipe.run", status, target=recipe_id, detail={"run_id": run_id, "steps": len(results)})
        result["run_id"] = run_id
        return result
