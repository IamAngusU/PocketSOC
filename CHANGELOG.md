# Changelog

## Unreleased

- Add a tiered local quality gate with unit, compile, frontend, dependency, security, wheel and package-content checks.
- Add timestamped JSON/Markdown quality reports and a centrally shared, version-pinned quality-tool environment.
- Keep GitHub workflow definitions available but disable hosted Actions at repository level by maintainer policy.

## 0.4.0 - 2026-09-09

- Make detector enablement, confidence floors and validated thresholds effective at runtime.
- Add incident acknowledgement, closure, false-positive suppression, history and safe evidence unlock.
- Add graceful job/scheduler shutdown.
- Add an isolated synthetic demo mode and portable CLI.
- Add build metadata, complete runtime dependencies, pinned validated requirements and packaged static UI.
- Add Windows/Linux CI, CodeQL, Dependabot and contributor/security templates.
- Add checkpointed, rotation-aware Suricata EVE JSON ingestion with duplicate suppression, allowlisted metadata and UI/API controls.
- Add MIT licensing and release/adoption documentation.

## 0.3.0 - 2026-09-09

- Add passive MITM/replay/C2/lateral/exfiltration indicators with explicit claim classes.
- Add ATT&CK 19.1 BM25 knowledge indexing, per-job cost estimates and local benchmarks.
- Add reviewed Windows firewall apply/rollback with TTL and audit controls.
