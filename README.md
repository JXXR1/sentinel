# SENTINEL v2

Lightweight bash security monitor for Linux servers. Detects exposed services, open ports, suspicious processes, file access events, and threat intel. Writes structured JSON escalations for downstream alerting.

Built after a real incident — two services sat exposed on `0.0.0.0` for days with no alert. No bells, no SaaS dependency, no agent to maintain. Just scripts that tell you when something is wrong.

---

## What it checks

- Open ports vs. your defined allowlist (anything unexpected = alert)
- Sensitive services bound to `0.0.0.0` vs. `127.0.0.1`/private IPs only
- Processes running as root that shouldn't be
- World-writable files in critical paths
- SSH authorised keys changes
- Failed login spikes
- Cron and systemd changes since last run (delta detection)
- Sensitive file access (credentials, config, identity files)
- Security stack health (ClamAV, CrowdSec, Wazuh, fail2ban)
- Threat intel: CVE feeds, package vulnerability checks
- **Skill-scanner supply-chain audit** *(v1.7)* — runs `skill-scan-v2.sh` against every installed agent skill directory; MALICIOUS exit escalates with name + path
- **LLM-vendor outbound audit** *(v1.7)* — Squid-log-based scan of last 24h for calls to AI/LLM vendor endpoints (OpenAI, Anthropic, HuggingFace, Telnyx, Soniox, Replicate, Mistral, DeepSeek, xAI, Gemini, Cohere); cross-references against egress allowlist, escalates on non-allowlist hits (credential-theft / data-exfil signal)
- **Backup integrity verification** *(v1.7)* — per-layer checks against expected file sizes + windows (catches the "rsync silent success" failure mode: empty log ≠ healthy backup)
- **Tailscale posture audit** *(v1.7)* — tracks tailnet peer count vs baseline (alerts on drift), scans `ss -tlnH` for any `0.0.0.0:<port>` bindings with a UFW-protected-ports allowlist
- **Multi-host coverage** *(v1.8)* — `sentinel-daily`, `sentinel-check-v2`, `sentinel-watchdog` audit multiple servers from one central aggregator over SSH (default: HIVE + EVE + VN pattern; re-configurable per deployment)

---

## Components

| Script | Purpose | Frequency |
|--------|---------|-----------|
| `sentinel-watchdog.sh` | Fast sensitive-service + stack health check | Every 2 min |
| `sentinel-check-v2.sh` | Full comprehensive audit, delta-based escalation | Every 6 hours |
| `sentinel-file-watch.sh` | Real-time sensitive file access monitor (inotify daemon) | Persistent |
| `sentinel-daily.sh` | Deep security stack audit across all servers | Daily (3am) |
| `sentinel-intel.sh` | Threat intel: CVE feeds, update checks, vulnerability scan | Every 6 hours |
| `sentinel-outbound-guard.sh` *(v1.9, Layer 27)* | Egress allowlist — flags non-allowlisted outbound from selected processes | Every 1–2 min |
| `sentinel-stack-health.sh` *(v1.9, Layer 30)* | Stack alive/fresh/vocal check + safe auto-remediation | Every 4 hours |

### Alert layers (latency tiers)

| Layer | Script | Trigger | Latency |
|-------|--------|---------|---------|
| File access | `sentinel-file-watch.sh` | Immediate (inotify) | < 1 second |
| Port/service exposure | `sentinel-watchdog.sh` | Polling | < 2 minutes |
| Egress violation *(v1.9, Layer 27)* | `sentinel-outbound-guard.sh` | Polling | < 2 minutes |
| Full audit + intel | `sentinel-check-v2.sh` + `sentinel-intel.sh` | Delta-based | 6 hours |
| Stack alive/fresh/vocal *(v1.9, Layer 30)* | `sentinel-stack-health.sh` | Polling | < 4 hours |
| Deep daily | `sentinel-daily.sh` | Scheduled | 24 hours |

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/JXXR1/sentinel-v2.git
cd sentinel-v2
chmod +x install.sh && ./install.sh
```

Or manually:

```bash
cp sentinel-*.sh /usr/local/bin/
chmod +x /usr/local/bin/sentinel-*.sh
```

### 2. Configure your allowlist

Edit the `ALLOWED_PUBLIC_PORTS` array in `sentinel-check-v2.sh` for ports you deliberately expose (e.g. 80/443 for a web server). Leave empty if nothing should be public.

### 3. Schedule it

```bash
crontab -e

# Fast watchdog every 2 minutes
*/2 * * * * /usr/local/bin/sentinel-watchdog.sh >> /var/log/sentinel-watchdog.log 2>&1

# Full audit every 6 hours
30 */6 * * * /usr/local/bin/sentinel-check-v2.sh >> /var/log/sentinel.log 2>&1

# Threat intel every 6 hours (offset)
15 */6 * * * /usr/local/bin/sentinel-intel.sh >> /var/log/sentinel.log 2>&1

# Deep daily audit at 3am
0 3 * * * /usr/local/bin/sentinel-daily.sh >> /var/log/sentinel-daily.log 2>&1
```

### 4. Start the file watcher

```bash
# As a systemd service (recommended)
cp sentinel-file-watch.sh /usr/local/bin/
systemctl enable --now sentinel-file-watch

# Or run manually
nohup /usr/local/bin/sentinel-file-watch.sh &
```

### 5. Wire up alerting

SENTINEL writes `/root/escalations/CRITICAL-ACTIVE.json` when something needs attention. Point whatever monitoring or alerting agent you use at that file.

Example: a heartbeat agent that checks the file on every poll and notifies you.

---

## Alert format

```json
{
  "timestamp": "2026-02-21_09-00-00",
  "alert_type": "PORT_EXPOSURE",
  "source": "sentinel-watchdog",
  "summary": "Unexpected port open on 0.0.0.0",
  "details": "Port 6333 bound to 0.0.0.0 — not in allowlist"
}
```

---

## Requirements

- Bash
- `ss` (iproute2)
- `jq`
- `inotifywait` (inotify-tools) — for `sentinel-file-watch.sh`

---

## Related

**Skill Scanner v3.5** — pre-installation skill auditing for AI agent skills, 38 detection modules covering pattern matching, AST taint tracking, YARA, LLM semantic analysis, supply-chain provenance, and PGP release-signature verification.
`github.com/JXXR1/skill-scanner-v2`

## Recommended Companion Tools

| Tool | Purpose | Install |
|------|---------|---------|
| `git-secrets` | Pre-commit hook preventing credential commits | `git clone https://github.com/awslabs/git-secrets.git && cd git-secrets && make install` |
| `truffleHog` | Git history credential scanner | `pip3 install trufflehog` |
| Skill Scanner v3.5 | Pre-install skill security auditing (38 modules, harness-agnostic) | [JXXR1/skill-scanner-v2](https://github.com/JXXR1/skill-scanner-v2) |
