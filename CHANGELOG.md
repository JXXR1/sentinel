# Changelog

All notable changes to SENTINEL v2 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-02-21

### Added
- **sentinel-watchdog.sh** — fast critical alert layer, runs every 1–2 minutes
  - Checks sensitive service hardlist only (Qdrant, Ollama, Redis, CrowdSec, OpenClaw gateways)
  - Writes CRITICAL-ACTIVE.json immediately on detection — does not wait for 6h scan
  - Checks both HIVE and EVE in a single lightweight run
  - Shares the same CRITICAL-ACTIVE.json protocol as the full scan; monitoring agent reads one file regardless of which layer fired
  - Source field (`"source": "sentinel-watchdog"`) distinguishes watchdog alerts from full scan alerts
  - Cleans up its own alerts on clear; does not interfere with full SENTINEL alerts
- **Two-layer architecture documented in README** — fire alarm (watchdog) vs. comprehensive audit (full scan)

### Architecture note
The watchdog closes the notification gap. UFW, CrowdSec, and AppArmor already close the exploitation gap. SENTINEL v2 now covers both detection layers.

---

## [1.0.0] - 2026-02-21

### Added
- **Sensitive service hardlist** — named services (Qdrant, Ollama, Redis, CrowdSec, OpenClaw gateways) that must never appear on 0.0.0.0; immediate hard escalation if detected
- **Detailed alert JSON** — escalation file includes exact port numbers, process names, and binding addresses
- **Allowlist for intentional exposure** — declare ports that are deliberately public; everything else triggers escalation
- **Dual-server coverage** — runs locally on HIVE, SSHes to EVE and runs the same checks; one cron job, full picture
- **Miner detection** — checks running processes and listening ports for known mining signatures
- **Suspicious cron detection** — flags jobs piping curl/wget directly to shell or writing to /tmp
- **Disk usage check** — escalates above 90%
- **CRITICAL-ACTIVE.json protocol** — single file your monitoring agent reads; exists = alert, deleted = clean
- **Structured logging** — timestamped logs per run in /root/hive/logs/