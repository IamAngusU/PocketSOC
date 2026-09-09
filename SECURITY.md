# Security policy

## Supported versions

PocketSOC is pre-1.0 software. Security fixes are applied to the latest development release only.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose captures, credentials, local model data or firewall control. Use GitHub's private vulnerability reporting / Security Advisory flow for the repository. Include a minimal reproduction with synthetic data and avoid attaching real packet payloads.

PocketSOC deliberately refuses remote binding without an authentication and TLS design. Reports that bypass loopback restrictions, cross the typed tool allowlist, execute model-generated code, alter a protected network target, or leak raw evidence/payload fields through a sensor adapter are considered high priority.

## Scope

The project is intended only for systems and networks the operator owns or is explicitly authorized to inspect. It does not accept offensive exploitation, evasion, persistence or credential-theft features.
