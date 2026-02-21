# SENTINEL v2

**Security monitoring agent for multi-server AI infrastructure.**

Companion to [Skill Scanner v2](https://github.com/JXXR1/skill-scanner-v2) — scanner catches threats before install, SENTINEL catches what slips through at runtime.

---

## What it does

SENTINEL runs on a schedule and audits both servers in one pass. It checks for the things that matter and escalates with enough detail to act on — not just that something is wrong, but exactly what, where, and what process is responsible.

### Checks

**1. Sensitive service hardlist**
Named services that must never be publicly exposed: Qdrant, Ollama, Redis, CrowdSec, OpenClaw gateways. If any appear on `0.0.0.0`, it escalates immediately with the service name.

**2. Front door scan**
All ports bound to `0.0.0.0` or `*` are logged. Ports you intentionally expose go in `ALLOWED_PUBLIC_PORTS`. Everything else triggers escalation.

**3. Miner detection**
Checks running processes and listening ports for known mining signatures (xmrig, minerd, cgminer, etc.).

**4. Suspicious cron scan**
Flags cron jobs that pipe curl/wget directly to shell, or write to /tmp.

**5. Disk check**
Escalates if disk usage exceeds 90%.

**6. Dual-server coverage**
Runs locally on HIVE, then SSHes to EVE and runs the same checks there. One cron job, full picture.

---

## Alert format

When something is wrong, SENTINEL writes a structured `CRITICAL-ACTIVE.json` to `/root/hive/escalations/`:

```json
{
  "timestamp": "2026-02-20_17-15",
  "alert_type": "SECURITY_ESCALATION",
  "summary": "[HIVE] SENSITIVE SERVICES EXPOSED - IMMEDIATE ACTION REQUIRED",
  "details": "[HIVE] Sensitive service violations:
  CRITICAL: Qdrant-HTTP port 6333 is PUBLIC (should be Tailscale/localhost only)"
}
```

Your monitoring layer reads this file. If it exists, alert fires. If checks pass, the file is deleted.

---

## Setup

**1. Copy the script to your HIVE server**
```bash
scp sentinel-check-v2.sh root@your-hive-server:/root/hive/
chmod +x /root/hive/sentinel-check-v2.sh
```

**2. Configure your allowlist**
Edit the `ALLOWED_PUBLIC_PORTS` array for ports you deliberately expose (e.g. 80/443 for nginx). Leave empty if nothing should be public.

**3. Configure sensitive services**
Edit the `SENSITIVE_SERVICES` array to match your stack. Default covers Qdrant, Ollama, Redis, CrowdSec, OpenClaw.

**4. Schedule it**
```bash
crontab -e
# Run every 6 hours
0 */6 * * * /root/hive/sentinel-check-v2.sh >> /root/hive/logs/sentinel-cron.log 2>&1
```

**5. Wire up alerting**
SENTINEL writes `/root/hive/escalations/CRITICAL-ACTIVE.json` when something is wrong. Point your monitoring agent at that file.

---

## Architecture note

SENTINEL runs on a 6-hour schedule. That means the detection window for an exposed port is up to 6 hours. For critical services, consider a separate high-frequency watchdog (every few minutes) checking only the sensitive service list, with SENTINEL as the comprehensive periodic audit layer. They serve different purposes.

---

## Requirements

- Bash
- `ss` (iproute2)
- `jq` (for JSON escalation output)
- SSH key access from HIVE to EVE (if running dual-server mode)

---

## Related

- [Skill Scanner v2](https://github.com/JXXR1/skill-scanner-v2) — pre-installation skill auditing, 24 detection modules

---

*Built after a real incident. Two services sat exposed on 0.0.0.0 for days. No breach, but too close. SENTINEL v2 would have caught them on day one.*
