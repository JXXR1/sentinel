#!/bin/bash
# SENTINEL Watchdog — Fast Critical Alert Script
# Companion to sentinel-check-v2.sh
#
# Purpose: Checks sensitive service exposure AND security stack health.
#          Fires CRITICAL-ACTIVE.json within 2 minutes of any issue.
#
# Author: EVE (OpenClaw Security)
# License: MIT
# Version: 1.2.0

ESCALATION_DIR="/root/hive/escalations"
ACTIVE_FILE="$ESCALATION_DIR/CRITICAL-ACTIVE.json"
TIMESTAMP=$(date -u +"%Y-%m-%d_%H-%M-%S")

mkdir -p "$ESCALATION_DIR"
mkdir -p "$ESCALATION_DIR/handled"

# ============================================================
# SENSITIVE SERVICES: must NEVER be bound to 0.0.0.0 or *
# ============================================================
SENSITIVE_SERVICES=(
    "6333:Qdrant-HTTP"
    "6334:Qdrant-gRPC"
    "11434:Ollama"
    "6379:Redis"
    "8080:CrowdSec"
    "6060:CrowdSec-Prometheus"
    "8337:OpenClaw-gateway"
    "8334:OpenClaw-gateway"
    "1514:Wazuh-remoted"
    "55000:Wazuh-API"
)

# ============================================================
# SECURITY STACK: all layers must be running
# ============================================================
REQUIRED_SERVICES="tailscaled crowdsec crowdsec-firewall-bouncer fail2ban sophos-spl clamav-daemon auditd osqueryd"
OPTIONAL_WAZUH="wazuh-clusterd wazuh-maild wazuh-dbd wazuh-csyslogd wazuh-agentlessd wazuh-integratord wazuh-authd"

check_host() {
    local host_label=$1
    local cmd_prefix=$2
    local findings=""

    # --- Port exposure check ---
    for entry in "${SENSITIVE_SERVICES[@]}"; do
        svc_port=$(echo "$entry" | cut -d: -f1)
        svc_name=$(echo "$entry" | cut -d: -f2)

        if [ -z "$cmd_prefix" ]; then
            BINDING=$(ss -tlnp 2>/dev/null | grep -E "0\.0\.0\.0:${svc_port}\b|\*:${svc_port}\b")
        else
            BINDING=$($cmd_prefix "ss -tlnp 2>/dev/null | grep -E '0\.0\.0\.0:${svc_port}\b|\*:${svc_port}\b'" 2>/dev/null)
        fi

        if [ -n "$BINDING" ]; then
            PROCESS=$(echo "$BINDING" | grep -oP 'users:\(\("[^"]+' | grep -oP '(?<=")[^"]+' | head -1)
            findings="$findings\n  CRITICAL: $svc_name (port $svc_port) EXPOSED ON 0.0.0.0${PROCESS:+ — process: $PROCESS}"
        fi
    done

    # --- Security stack health check ---
    for svc in $REQUIRED_SERVICES; do
        if [ -z "$cmd_prefix" ]; then
            STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "not-found")
        else
            STATUS=$($cmd_prefix "systemctl is-active $svc 2>/dev/null || echo not-found" 2>/dev/null)
        fi
        [ "$STATUS" != "active" ] && findings="$findings\n  DOWN: $svc (status: $STATUS)"
    done

    # --- Wazuh core check ---
    if [ -z "$cmd_prefix" ]; then
        WAZUH_DOWN=$(/var/ossec/bin/wazuh-control status 2>/dev/null | grep "not running" | grep -Ev "$(echo $OPTIONAL_WAZUH | tr ' ' '|')" | wc -l)
    else
        WAZUH_DOWN=$($cmd_prefix "/var/ossec/bin/wazuh-control status 2>/dev/null | grep 'not running' | grep -Ev 'wazuh-clusterd|wazuh-maild|wazuh-dbd|wazuh-csyslogd|wazuh-agentlessd|wazuh-integratord|wazuh-authd' | wc -l" 2>/dev/null)
    fi
    [ "${WAZUH_DOWN:-0}" -gt 0 ] 2>/dev/null && findings="$findings\n  DOWN: wazuh ($WAZUH_DOWN core processes not running)"

    # --- UFW check ---
    if [ -z "$cmd_prefix" ]; then
        UFW_DROP=$(/sbin/iptables -L INPUT -n 2>/dev/null | head -1 | grep -c DROP || echo 0)
    else
        UFW_DROP=$($cmd_prefix "/sbin/iptables -L INPUT -n 2>/dev/null | head -1 | grep -c DROP || echo 0" 2>/dev/null)
    fi
    [ "${UFW_DROP:-0}" -eq 0 ] 2>/dev/null && findings="$findings\n  DOWN: ufw (INPUT policy not DROP)"

    echo "$findings"
}

# Check both servers
HIVE_FINDINGS=$(check_host "HIVE" "")
EVE_FINDINGS=$(check_host "EVE" "ssh 100.79.182.103")

ALL_FINDINGS=""
[ -n "$HIVE_FINDINGS" ] && ALL_FINDINGS="$ALL_FINDINGS\n[HIVE]:$HIVE_FINDINGS"
[ -n "$EVE_FINDINGS"  ] && ALL_FINDINGS="$ALL_FINDINGS\n[EVE]:$EVE_FINDINGS"

if [ -n "$ALL_FINDINGS" ]; then
    cat > "$ACTIVE_FILE" << EOFJSON
{
  "timestamp": "$TIMESTAMP",
  "alert_type": "WATCHDOG_CRITICAL",
  "source": "sentinel-watchdog",
  "summary": "SECURITY ISSUE DETECTED — IMMEDIATE ACTION REQUIRED",
  "details": $(echo -e "$ALL_FINDINGS" | jq -Rs .)
}
EOFJSON
    python3 /root/hive/redis-memory.py write "sentinel_alert" "Watchdog ALERT: $ALL_FINDINGS" "CRITICAL-ACTIVE.json written" 2>/dev/null
    exit 1
else
    if [ -f "$ACTIVE_FILE" ]; then
        SOURCE=$(python3 -c "import json; d=json.load(open('$ACTIVE_FILE')); print(d.get('source',''))" 2>/dev/null)
        [ "$SOURCE" = "sentinel-watchdog" ] && rm -f "$ACTIVE_FILE"
    fi
    python3 /root/hive/redis-memory.py write "sentinel" "Watchdog: all clear" "Stack healthy, no ports exposed" 2>/dev/null
    exit 0
fi
