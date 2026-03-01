# Changelog

All notable changes to SENTINEL v2 will be documented in this file.

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
