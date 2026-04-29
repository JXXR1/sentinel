# Changelog

All notable changes to SENTINEL v2 will be documented in this file.

---

## [1.6.0] - 2026-04-29

### Added — agent-platform monitoring (OpenClaw-specific)

- **OpenClaw scope-upgrade burst detection** in `sentinel-check-v2.sh`. Counts
  pending pairing requests in `~/.openclaw/devices/pending.json`; flags as
  escalation when more than 2 are pending simultaneously. A single tool
  needing scope is normal; a burst is suspicious — could indicate a compromised
  tool spamming requests, or an external actor probing the pairing surface.
  Alert detail includes the union of scopes being requested.
- **`paired.json` SHA-256 integrity baseline + drift detection**. Captures a
  baseline of the device pairing record on first run; flags drift on subsequent
  runs. Detects manual edits granting elevated scope, token rotation events,
  or unauthorized pairing additions. Refresh baseline by deleting
  `/root/hive/baseline/paired.json.sha256`.
- **Subagent registry drift detection**. Compares actual subagents
  (`~/.openclaw/agents/`) against the configurable expected set
  (`OPENCLAW_EXPECTED_AGENTS` env var, comma-separated). Flags unexpected
  subagent additions — relevant for catching unauthorized subagent spawns.

### Why this update

Between Feb and April 2026, the AI-agent platform threat landscape shifted
materially. Google Threat Intelligence flagged indirect prompt injection (IPI)
as the #1 attack vector for AI agents in 2026; schema-leakage research
identified latent-capability surface as a real risk; and our own operational
experience surfaced scope-upgrade abuse as a concrete attack pattern on
OpenClaw pairings. SENTINEL v1.5.0 monitored host-level posture but had no
detections for these agent-platform-specific threats.

This release adds runtime monitoring for those gaps. The static-analysis side
is covered by skill-scanner v3.3.0 (separate project, see Modules 32/33/34).

---

## [1.3.1] - 2026-02-28

### Fixed
- **Critical detection gap in sentinel-watchdog.sh** — watchdog previously only checked a hardcoded list of known sensitive ports. A new arbitrary port (e.g. a game server, dev tool) opened on `0.0.0.0` would go undetected for up to 6 hours until `sentinel-check-v2.sh` ran. Watchdog now scans ALL ports bound to `0.0.0.0` and alerts on anything not in the `ALLOWED_PUBLIC_PORTS` allowlist — same logic as the full audit, but at 2-minute frequency.

---

## [1.3.0] - 2026-02-28

### Added
- **sentinel-daily.sh** — deep nightly audit across all servers; checks security stack health (ClamAV, CrowdSec, Wazuh, fail2ban, Maldet), disk, auth logs, and rootkit indicators. Runs at 3am.
- **sentinel-intel.sh** — threat intel layer; CVE feed checks, package vulnerability scans, update status. Runs every 6 hours offset from full audit.

### Changed
- README: updated component table to include all 5 scripts; added three-layer architecture table; updated install instructions; fixed cross-reference to Skill Scanner v3 (28 modules)
- CHANGELOG: backfilled all releases to match live versions

---

## [1.2.0] - 2026-02-21

### Added
- **Delta-based change detection** in `sentinel-check-v2.sh` — fingerprints findings on each run; only escalates when findings change since last scan. Suppresses repeat alerts for known issues. Reduces noise significantly on stable systems.
- **sentinel-file-watch.sh** — sensitive path monitor running as a persistent systemd service
  - Watches critical files (credentials, config, identity) for unexpected access events
  - Fires `CRITICAL-ACTIVE.json` immediately on open/read/modify/delete events
  - Configurable watch paths — deploy one instance per server
  - Smart suppression: high-frequency files only alert on delete/move, not routine reads
  - Shares the same `CRITICAL-ACTIVE.json` protocol as watchdog and full scan

### Three alert layers now active
| Layer | Script | Trigger | Frequency |
|-------|--------|---------|-----------|
| File access | `sentinel-file-watch.sh` | Immediate (inotify) | Persistent daemon |
| Port exposure | `sentinel-watchdog.sh` | Immediate | Every 2 min |
| Full audit | `sentinel-check-v2.sh` | Delta-based | Every 6h |

---

## [1.1.0] - 2026-02-21

### Added
- **sentinel-watchdog.sh** — fast critical alert layer, runs every 1–2 minutes
- Two-layer architecture documented in README

---

## [1.0.0] - 2026-02-21

### Added
- Initial release — full security audit, sensitive service hardlist, dual-server coverage
## [1.4.0] - 2026-03-01

### Added
- **Credential hygiene audit** in `sentinel-daily.sh` — runs on both servers nightly:
  - Plaintext credentials in config files (JSON, YAML, TOML, conf) outside `.env`
  - Shell history secrets (passwords, tokens, API keys in bash/zsh history)
  - Scattered `.env`, `.pem`, `.key`, `id_rsa` files across home directory
  - Stale credential files (30+ days untouched — likely forgotten)
  - World-readable `.env` files (permission check)

## [1.5.0] - 2026-03-01

### Added
- **Remediation guidance** in credential hygiene alerts — when credentials are found, the daily log now includes a 7-step remediation checklist: rotate, audit access logs, check lateral movement, invalidate spawned sessions, clean history, harden permissions, verify. Inspired by u/samma_sentinel's feedback on the remediation delta.
- **Pre-commit hook audit** — nightly check that all git repos under /root have git-secrets hooks installed. Reports repos without credential guards.
- **git-secrets + truffleHog** added to recommended install (README)
