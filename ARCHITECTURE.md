# Architecture

PocketSOC separates evidence collection, deterministic analysis, optional model language and network response.

```text
dumpcap / PCAP / Suricata EVE / local diagnostics
              |       |
              |   checkpointed typed adapter
              v       v
      bounded normalized events -----> immutable evidence references
              |                                  |
              v                                  v
  deterministic detectors                  capture retention lock
              |
              v
 claims + incidents + alternatives -----> operator lifecycle
              |                                  |
              +---- local ATT&CK/BM25 context    v
              |                           reviewed firewall proposal
              v                                  |
 optional local LLM questions              hash + rate + TTL + rollback
```

## Trust boundaries

- Packet and endpoint evidence is untrusted input.
- Sensor files are untrusted line-delimited input: reads are byte/record bounded, incomplete lines remain uncommitted, rotation resets the checkpoint safely, and payload fields are dropped by an allowlist normalizer.
- Knowledge text can explain a technique but cannot prove that it occurred.
- The local model cannot modify evidence, execute generated code or directly mutate a firewall.
- Diagnostics are fixed operations with typed parameters, timeouts and private-network scope.
- Windows firewall application requires an already elevated process plus exact reviewed-payload confirmation.
- Remote HTTP exposure is rejected until authentication, authorization and TLS exist.

## Storage

SQLite/WAL owns the control plane, sensor checkpoints, normalized records, structured events, rule configuration, incidents, audit and compact knowledge index. Live captures and each sensor-ingest run are bounded. Incident-linked artifacts are excluded from rolling deletion until every linked incident is closed or marked false-positive.

SQLite is appropriate for a single workstation. Sustained multi-sensor ingestion should use a dedicated event/flow store while keeping the same claims and response contracts.
