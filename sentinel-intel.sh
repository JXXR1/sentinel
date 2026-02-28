#!/bin/bash
# SENTINEL Threat Intel & Update Check
# Runs on HIVE, checks for threats and updates

LOG_DIR="/root/hive/logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date -u +"%Y-%m-%d_%H-%M")
LOG="$LOG_DIR/intel-$TIMESTAMP.log"
ALERTS=""

echo "=== SENTINEL Intel Check $TIMESTAMP ===" > "$LOG"

# --- System Updates ---
echo -e "\n--- HIVE Updates ---" >> "$LOG"
apt-get update -qq 2>/dev/null
HIVE_UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst")
echo "Packages to update: $HIVE_UPDATES" >> "$LOG"
HIVE_SECURITY=$(apt-get -s upgrade 2>/dev/null | grep -i security | wc -l)
[ "$HIVE_SECURITY" -gt 0 ] && ALERTS="$ALERTS\n[HIVE] $HIVE_SECURITY security updates available"

echo -e "\n--- EVE Updates ---" >> "$LOG"
EVE_UPDATES=$(ssh 100.79.182.103 'apt-get update -qq 2>/dev/null; apt-get -s upgrade 2>/dev/null | grep -c "^Inst"')
echo "Packages to update: $EVE_UPDATES" >> "$LOG"
EVE_SECURITY=$(ssh 100.79.182.103 'apt-get -s upgrade 2>/dev/null | grep -i security | wc -l')
[ "$EVE_SECURITY" -gt 0 ] && ALERTS="$ALERTS\n[EVE] $EVE_SECURITY security updates available"

# --- npm audit (if node projects exist) ---
echo -e "\n--- npm Audit ---" >> "$LOG"
if [ -d "/root/openclaw" ]; then
    cd /root/openclaw
    NPM_VULNS=$(npm audit --json 2>/dev/null | grep -o '"vulnerabilities":{[^}]*}' | grep -oE '"(critical|high)":[0-9]+' || echo "none")
    echo "OpenClaw vulns: $NPM_VULNS" >> "$LOG"
    echo "$NPM_VULNS" | grep -qE '(critical|high):[1-9]' && ALERTS="$ALERTS\n[HIVE] npm vulnerabilities found"
fi

# --- CISA KEV (recent additions) ---
echo -e "\n--- CISA KEV Check ---" >> "$LOG"
CISA_RECENT=$(curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" 2>/dev/null | \
    grep -oE '"dateAdded":"[0-9-]+"' | head -5 | grep "$(date -u +%Y-%m)" | wc -l)
echo "New KEV entries this month: $CISA_RECENT" >> "$LOG"

# --- Check our stack keywords in recent CVEs ---
echo -e "\n--- Stack CVE Check ---" >> "$LOG"
STACK_KEYWORDS="ubuntu|node.js|chromium|tailscale|ollama"
# Quick check via NVD API (last 7 days, our stack)
NVD_HITS=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=$(date -u -d '7 days ago' +%Y-%m-%dT00:00:00.000)&pubEndDate=$(date -u +%Y-%m-%dT23:59:59.999)" 2>/dev/null | \
    grep -iE "$STACK_KEYWORDS" | wc -l || echo "0")
echo "Stack-related CVEs (7 days): $NVD_HITS" >> "$LOG"
[ "$NVD_HITS" -gt 0 ] && ALERTS="$ALERTS\n[INTEL] $NVD_HITS CVEs found for our stack in last 7 days"

# --- Final status ---
if [ -n "$ALERTS" ]; then
    echo -e "\n!!! ALERTS !!!" >> "$LOG"
    echo -e "$ALERTS" >> "$LOG"
    mkdir -p /root/hive/escalations
    echo -e "SENTINEL INTEL ALERT $TIMESTAMP\n$ALERTS" > "/root/hive/escalations/intel-$TIMESTAMP.md"
    /root/hive/alert-eve.sh "$ALERTS"
echo "ALERT"
else
    echo -e "\nNo critical intel." >> "$LOG"
    echo "OK"
fi
