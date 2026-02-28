# Changelog

All notable changes to SENTINEL v2 will be documented in this file.

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