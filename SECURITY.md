# Security Policy

DetectAI processes security telemetry — alerts, logs, process/network data — which is itself sensitive and, per the project's own threat model (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), section 8), potentially adversarial. Security issues in this project are taken seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately by [opening a GitHub Security Advisory](../../security/advisories/new) on this repository (Security tab → "Report a vulnerability"), or by contacting the maintainer directly.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (or a proof-of-concept)
- Affected version/commit

You should expect an initial response within a few days. This is a student-maintained open-source project, not a funded security team, so response times will vary — but every report is read.

## Scope

Security-relevant areas of particular interest:

- **Prompt injection**: any way untrusted alert content (`command_line`, `description`, `raw_event`, etc.) could cause the AI layer to treat data as instructions, or bypass the evidence-validation boundary (architecture doc §15).
- **Authentication / authorization**: RBAC bypass, privilege escalation, token handling.
- **Secret handling**: credentials or API keys appearing in logs, error messages, API responses, or committed config.
- **Input validation**: malformed or oversized connector payloads causing crashes, resource exhaustion, or injection into the database layer.
- **Container/deployment hardening**: issues with the Docker Compose setup, non-root enforcement, network segmentation.

## Supported versions

This project is pre-1.0 and under active phased development (see the roadmap in `docs/ARCHITECTURE.md`). Only the latest commit on `main` is currently supported — there is no long-term-support branch yet.

## Out of scope

- Vulnerabilities in third-party SIEM/EDR products that DetectAI connects to — report those to the respective vendor.
- Vulnerabilities requiring an already-compromised deployment (e.g. an attacker with direct database access) are documented as accepted risk in the threat model rather than tracked as bugs, unless they reveal a missing control DetectAI itself should have had.
