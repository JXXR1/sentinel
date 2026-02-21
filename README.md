# SENTINEL v2

Lightweight bash security monitor for Linux servers. Detects exposed services, open ports, and suspicious process behaviour. Writes structured JSON escalations for downstream alerting.

Built after a real incident — two services sat exposed on `0.0.0.0` for days with no alert. No bells, no SaaS dependency, no agent to maintain. Just a script that tells you when something is wrong.

---

## What it checks

- Open ports vs. your defined allowlist (anything unexpected = alert)
- Sensitive services bound to `0.0.0.0` vs. `127.0.0.1`/private IPs only
- Processes running as root that shouldn't be
- World-writable files in critical paths
- SSH authorised keys changes
- Failed login spikes
- Cron and systemd changes since last run (delta detection)

---

## Components

| Script | Purpose | Frequency |
|--------|---------|-----------|
| `sentinel-check-v2.sh` | Full comprehensive audit | Every 6 hours |
| `sentinel-watchdog.sh` | Fast sensitive-service check | Every 2 minutes |

They share the same alert format and complement each other. Watchdog catches acute exposures fast; full scan catches everything else on a rolling basis.

---

## Setup

### 1. Copy the scripts

```bash
scp sentinel-check-v2.sh sentinel-watchdog.sh root@your-server:/usr/local/bin/
chmod +x /usr/local/bin/sentinel-check-v2.sh /usr/local/bin/sentinel-watchdog.sh
```

### 2. Configure your allowlist

Edit the `ALLOWED_PUBLIC_PORTS` array in `sentinel-check-v2.sh` for ports you deliberately expose (e.g. 80/443 for a web server). Leave empty if nothing should be public.

### 3. Configure sensitive services

Edit the `SENSITIVE_SERVICES` array to match your stack. Defaults cover common self-hosted services — adjust to fit your environment.

### 4. Schedule it

```bash
crontab -e

# Full audit every 6 hours
0 */6 * * * /usr/local/bin/sentinel-check-v2.sh >> /var/log/sentinel-cron.log 2>&1

# Fast watchdog every 2 minutes
*/2 * * * * /usr/local/bin/sentinel-watchdog.sh >> /var/log/sentinel-watchdog.log 2>&1
```

### 5. Wire up alerting

SENTINEL writes `/var/log/sentinel/CRITICAL-ACTIVE.json` when something needs attention. Point whatever monitoring or alerting agent you use at that file.

Example: a heartbeat agent that checks the file and sends a notification.

---

## Alert format

```json
{
  "timestamp": "2026-02-21_09-00-00",
  "alert_type": "PORT_EXPOSURE",
  "source": "sentinel-check-v2",
  "summary": "Unexpected port open on 0.0.0.0",
  "details": "Port 6333 bound to 0.0.0.0 — not in allowlist"
}
```

---

## Requirements

- Bash
- `ss` (iproute2)
- `jq`

---

## Architecture note

SENTINEL runs on a schedule. The watchdog closes the gap for time-sensitive exposures, but for true real-time detection combine with `inotifywait` (see `sentinel-file-watch.sh` in this repo) for filesystem-level monitoring.

---

## Related

**Skill Scanner v2** — pre-installation skill auditing, 24 detection modules  
`github.com/JXXR1/skill-scanner-v2`
