# Changelog

All notable changes to SENTINEL v2 will be documented in this file.

---

## [1.7.0] - 2026-05-12

### Added — Supply-chain integration + outbound recon + backup integrity (sentinel-daily)

- **Skill-Scanner Supply-Chain Audit.** sentinel-daily.sh runs `skill-scan-v2.sh`
  (v3.4 + v3.5) against every installed skill directory under configurable roots
  (default `~/.openclaw/agents/*/skills` and `~/.openclaw/skills`). Skill identified
  by `SKILL.md` or `manifest.json` presence. MALICIOUS exit (rc ≥ 10) escalates
  with skill name + path; WARN (rc 1-9) logs only; clean = `OK`. Silent skip if
  no skill dirs match — works whether or not the host has skills installed today.
  Config: `SENTINEL_SKILL_SCANNER_BIN`, `SENTINEL_SKILL_ROOTS`.

- **LLM-Vendor Outbound Audit (Squid-log based).** Scans `/var/log/squid/access.log`
  for last-24h outbound calls to AI/LLM vendor endpoints: OpenAI, Anthropic,
  HuggingFace, Telnyx, Soniox, Replicate, Together, Mistral, DeepSeek, xAI,
  Google Gemini, Cohere. Cross-references each unique destination host against
  the workspace `.egress-known-domains.json` allowlist via jq. Escalates if any
  vendor host hit in last 24h is NOT on the allowlist — potential
  credential-theft / data-exfil signal. Config: `SENTINEL_EGRESS_ALLOWLIST`,
  `SENTINEL_SQUID_LOG`.

- **Backup Integrity Verification.** Per `feedback_rsync_silent_success.md` —
  silent success ≠ correct. Verifies each layer of the EVE backup chain
  produced files in the expected size band within the expected window:
  fast-incremental (< 30 min), daily (< 26 h), Hetzner Box sync log (< 26 h).
  Each layer skips silently if path not present (host-tunable). Config:
  `SENTINEL_BACKUP_FAST_DIR`, `SENTINEL_BACKUP_DAILY_DIR`, `SENTINEL_BACKUP_BOX_LOG`.

- **Tailscale Posture Audit.** Tracks tailnet peer count vs baseline; alerts
  on drift (refresh baseline by removing `$SENTINEL_TS_PEER_BASELINE`). Scans
  `ss -tlnH` for any `0.0.0.0:<port>` bindings; consults a UFW-protected-ports
  allowlist (currently mirrored from `sentinel-check-v2.sh`; consolidation TODO)
  so legitimate bindings like `wazuh-authd:1515` don't generate false positives.
  Non-allowlisted 0.0.0.0 bindings escalate per `feedback_no_public_binding.md`.

### Changed

- `sentinel-check-v2.sh` header comment "Pairs with skill-scanner v3.3.0"
  bumped to v3.5.0 and expanded to reflect the v3.4 supply-chain modules +
  v3.5 release-signature verification that landed today.

### Notes

- These v1.7 additions are intentionally read-only audits — they log + escalate,
  never auto-remediate. Per `feedback_never_break_self_remediating.md`.
- All new sections gracefully skip when their data source is missing
  (no Squid log = skip vendor audit; no skill dirs = skip skill-scanner audit;
  etc.), so the script remains usable on hosts that don't have every layer.

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
