# SENTINEL v2

**Security monitoring agent for multi-server AI infrastructure.**

Companion to [Skill Scanner v2](https://github.com/JXXR1/skill-scanner-v2) — scanner catches threats before install, SENTINEL catches what slips through at runtime.

---

## Two scripts. Two layers.

| Script | Purpose | Frequency | Scope |
|--------|---------|-----------|-------|
| `sentinel-watchdog.sh` | Fire alarm | Every 1–2 min | Sensitive services only |
| `sentinel-check-v2.sh` | Full audit | Every 6h | Everything |

**sentinel-watchdog.sh** is the fast layer. It checks only the services that must never be publicly exposed (Qdrant, Ollama, Redis, OpenClaw gateways). If any appear on `0.0.0.0`, it writes `CRITICAL-ACTIVE.json` within minutes. Minimal overhead — `ss` check per service, nothing else.

**sentinel-check-v2.sh** is the comprehensive layer. Miners, suspicious crons, disk usage, broad port sweep, dual-server audit. Runs every 6 hours. The watchdog handles the fire; SENTINEL handles the investigation.

Both write to the same `CRITICAL-ACTIVE.json` protocol so your monitoring agent reads one file regardless of which layer fired.

---

## sentinel-watchdog.sh

### What it checks
Sensitive services that must never be bound to `0.0.0.0` or `*`:
- **Qdrant** (6333, 6334)
- **Ollama** (11434)
- **Redis** (6379)
- **CrowdSec** (8080, 6060)
- **OpenClaw gateways** (8337, 8334)

Checks both HIVE and EVE in a single run via SSH.

### Alert format
```json
{
  "timestamp": "2026-02-21_08-30-00",
  "alert_type": "WATCHDOG_CRITICAL",
  "source": "sentinel-watchdog",
  "summary": "SENSITIVE SERVICE EXPOSED ON 0.0.0.0 — IMMEDIATE ACTION REQUIRED",
  "details": "[HIVE] Sensitive service violations:\n  CRITICAL: Qdrant-HTTP (port 6333) EXPOSED ON 0.0.0.0 — process: qdrant"
}
```

### Setup
```bash
# Copy to HIVE
scp sentinel-watchdog.sh root@your-hive-server:/root/hive/
chmod +x /root/hive/sentinel-watchdog.sh

# Add to crontab (every 2 minutes)
crontab -e
*/2 * * * * /root/hive/sentinel-watchdog.sh
```

---

## sentinel-check-v2.sh

### What it checks
1. **Sensitive service hardlist** — named services that must never be publicly exposed
2. **Front door scan** — all ports on `0.0.0.0` filtered against your allowlist
3. **Miner detection** — running processes and listening ports for known mining signatures
4. **Suspicious cron scan** — jobs piping curl/wget to shell or writing to /tmp
5. **Disk check** — escalates above 90%
6. **Dual-server coverage** — HIVE and EVE in one job

### Alert format
```json
{
  "timestamp": "2026-02-21_08-00",
  "alert_type": "SECURITY_ESCALATION",
  "summary": "[HIVE] SENSITIVE SERVICES EXPOSED - IMMEDIATE ACTION REQUIRED",
  "details": "[HIVE] Sensitive service violations:\n  CRITICAL: Qdrant-HTTP port 6333 is PUBLIC"
}
```

### Setup
```bash
scp sentinel-check-v2.sh root@your-hive-server:/root/hive/
chmod +x /root/hive/sentinel-check-v2.sh

# Add to crontab (every 6 hours)
crontab -e
0 */6 * * * /root/hive/sentinel-check-v2.sh >> /root/hive/logs/sentinel-cron.log 2>&1
```

---

## CRITICAL-ACTIVE.json protocol

Both scripts write to `/root/hive/escalations/CRITICAL-ACTIVE.json` when something is wrong. Your monitoring agent checks for this file:
- **File exists** → alert, read contents, act
- **File absent** → all clear

When the issue is resolved, the file is deleted on the next clean run. Handled alerts move to `/root/hive/escalations/handled/`.

---

## Note on the security stack

UFW, CrowdSec, and AppArmor already provide real-time blocking at the network and process level. Even during the watchdog check interval, an exposed port is not automatically reachable externally. SENTINEL and the watchdog close the *detection and notification* gap — the security stack closes the *exploitation* gap.

---

## Requirements

- Bash
- `ss` (iproute2)
- `jq`
- `python3` (for JSON source check in watchdog)
- SSH key access from HIVE to EVE

---

## Related

- [Skill Scanner v2](https://github.com/JXXR1/skill-scanner-v2) — pre-installation skill auditing, 24 detection modules