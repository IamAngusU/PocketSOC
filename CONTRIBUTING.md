# Contributing to PocketSOC

PocketSOC welcomes defensive, evidence-first improvements. Open an issue before a large architectural change so its threat model and data implications can be agreed first.

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\setup-quality-tools.ps1 -Python .\.venv\Scripts\python.exe
.\check.ps1
.\.venv\Scripts\pocketsoc --demo
```

On Linux/macOS, replace the interpreter paths with `.venv/bin/python` and `.venv/bin/pocketsoc`, then run the equivalent commands documented in `check.ps1`. Tests that require a real TShark installation are skipped when it is unavailable. Hosted GitHub Actions are intentionally disabled; the checked-in workflows are opt-in templates rather than the project's authority.

## Contribution rules

- Use synthetic or sanitized fixtures. Never commit unrestricted PCAPs, secrets, private IP inventories or personal traffic.
- Preserve the `observed` / `derived` / `hypothesis` contract and cite evidence references for factual claims.
- Keep active operations typed, allowlisted, bounded and local/private-network scoped.
- Generated analyzers remain declarative data. Do not add an unrestricted Python, PowerShell or shell execution path.
- Detection changes need a positive fixture, a benign alternative and a false-positive limitation.
- Sensor adapters must stream bounded input, survive partial records/rotation, checkpoint durably, normalize through an explicit allowlist and include a payload-redaction regression test.
- Schema changes must be additive or include a tested, backup-conscious migration.
- Run the unit suite, compilation check and frontend syntax check before a pull request.

## Pull requests

Describe the user-visible behavior, failure mode, safety boundary and validation performed. Maintainers may request a shadow/benchmark phase before enabling a new detector by default.
