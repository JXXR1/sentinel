# Changelog

All notable changes to SENTINEL v2 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-02-21

### Added
- **Sensitive service hardlist** — named services (Qdrant, Ollama, Redis, CrowdSec, OpenClaw gateways) that must never appear on 0.0.0.0; immediate hard escalation if detected
- **Detailed alert JSON** — escalation file includes exact port numbers, process names, and binding addresses (not just "check ports")
- **Allowlist for intentional exposure** — declare ports that are deliberately public; everything else triggers escalation
- **Dual-server coverage** — runs locally on HIVE, SSHes to EVE and runs the same checks; one cron job, full picture
- **Miner detection** — checks running processes and listening ports for known mining signatures
- **Suspicious cron detection** — flags jobs piping curl/wget directly to shell or writing to /tmp
- **Disk usage check** — escalates above 90%
- **CRITICAL-ACTIVE.json protocol** — single file your monitoring agent reads; exists = alert, deleted = clean
- **Structured logging** — timestamped logs per run in /root/hive/logs/

### Changed (from v1)
- Alert format upgraded from generic string to structured JSON with summary + detail fields
- Port exposure detection now filters against allowlist (eliminates false positives)
- Escalation includes process name and binding address, not just port number

---

## Roadmap

### [1.1.0] - Planned
- High-frequency watchdog mode for critical service checks (every 5 minutes)
- Separate alert channels for critical vs. informational findings
- Configurable alert thresholds per service
- Support for 3+ server topologies