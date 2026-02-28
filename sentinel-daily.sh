#!/bin/bash
LOG="/root/hive/logs/daily-$(date -u +%Y-%m-%d).log"
ESCALATE=""
EVE_IP="100.79.182.103"

echo "=== SENTINEL Daily Scan $(date -u) ===" > "$LOG"

# ============================================================
# SECURITY STACK HEALTH CHECK — both servers
# ============================================================
check_stack() {
    local name=$1
    local prefix=$2
    local FAIL=""

    echo -e "\n--- Security Stack: $name ---" >> "$LOG"

    SYSTEMD_SVCS="tailscaled crowdsec crowdsec-firewall-bouncer fail2ban sophos-spl clamav-daemon auditd osqueryd"
    for svc in $SYSTEMD_SVCS; do
        if [ -z "$prefix" ]; then
            STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "not-found")
        else
            STATUS=$($prefix "systemctl is-active $svc 2>/dev/null || echo not-found")
        fi
        if [ "$STATUS" != "active" ]; then
            FAIL="$FAIL\n  DOWN: $svc ($STATUS)"
            echo "  FAIL: $svc is $STATUS" >> "$LOG"
        else
            echo "  OK: $svc" >> "$LOG"
        fi
    done

    # Wazuh core processes
    if [ -z "$prefix" ]; then
        WAZUH_DOWN=$(/var/ossec/bin/wazuh-control status 2>/dev/null | grep "not running" | grep -Ev "wazuh-clusterd|wazuh-maild|wazuh-dbd|wazuh-csyslogd|wazuh-agentlessd|wazuh-integratord|wazuh-authd" | wc -l)
    else
        WAZUH_DOWN=$($prefix "/var/ossec/bin/wazuh-control status 2>/dev/null | grep 'not running' | grep -Ev 'wazuh-clusterd|wazuh-maild|wazuh-dbd|wazuh-csyslogd|wazuh-agentlessd|wazuh-integratord|wazuh-authd' | wc -l")
    fi
    if [ "${WAZUH_DOWN:-0}" -gt 0 ] 2>/dev/null; then
        FAIL="$FAIL\n  DOWN: wazuh ($WAZUH_DOWN core processes)"
        echo "  FAIL: wazuh has $WAZUH_DOWN core processes down" >> "$LOG"
    else
        echo "  OK: wazuh" >> "$LOG"
    fi

    # UFW/iptables default DROP
    if [ -z "$prefix" ]; then
        UFW_DROP=$(/sbin/iptables -L INPUT -n 2>/dev/null | head -1 | grep -c DROP || echo 0)
    else
        UFW_DROP=$($prefix "/sbin/iptables -L INPUT -n 2>/dev/null | head -1 | grep -c DROP || echo 0")
    fi
    if [ "${UFW_DROP:-0}" -eq 0 ] 2>/dev/null; then
        FAIL="$FAIL\n  DOWN: ufw (INPUT policy not DROP)"
        echo "  FAIL: ufw not enforcing DROP" >> "$LOG"
    else
        echo "  OK: ufw" >> "$LOG"
    fi

    if [ -n "$FAIL" ]; then
        echo "  => ESCALATING stack failures for $name" >> "$LOG"
        ESCALATE="$ESCALATE\n[$name] SECURITY STACK DEGRADED:$FAIL"
    else
        echo "  All services healthy." >> "$LOG"
    fi
}

check_stack "HIVE" ""
check_stack "EVE" "ssh $EVE_IP"

# ============================================================
# AUTO-UPDATES
# ============================================================
echo -e "\n--- HIVE Updates ---" >> "$LOG"
apt-get update -qq && apt-get upgrade -y >> "$LOG" 2>&1

echo -e "\n--- EVE Updates ---" >> "$LOG"
ssh $EVE_IP "apt-get update -qq && apt-get upgrade -y" >> "$LOG" 2>&1

# ============================================================
# CLAMSCAN — both servers
# ============================================================
echo -e "\n--- ClamAV: HIVE ---" >> "$LOG"
freshclam --quiet 2>/dev/null
CLAM_HIVE=$(clamscan -r /root --quiet --infected 2>/dev/null)
[ -n "$CLAM_HIVE" ] && ESCALATE="$ESCALATE\n[HIVE] ClamAV infections found: $CLAM_HIVE"
echo "${CLAM_HIVE:-Clean}" >> "$LOG"

echo -e "\n--- ClamAV: EVE ---" >> "$LOG"
CLAM_EVE=$(ssh $EVE_IP "freshclam --quiet 2>/dev/null; clamscan -r /root --quiet --infected 2>/dev/null" || echo "")
[ -n "$CLAM_EVE" ] && ESCALATE="$ESCALATE\n[EVE] ClamAV infections found: $CLAM_EVE"
echo "${CLAM_EVE:-Clean}" >> "$LOG"

# ============================================================
# RKHUNTER — both servers
# ============================================================
echo -e "\n--- rkhunter: HIVE ---" >> "$LOG"
RKH_HIVE=$(rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | grep -E 'Warning|Found' || echo "Clean")
[ "$RKH_HIVE" != "Clean" ] && ESCALATE="$ESCALATE\n[HIVE] rkhunter warnings: $RKH_HIVE"
echo "$RKH_HIVE" >> "$LOG"

echo -e "\n--- rkhunter: EVE ---" >> "$LOG"
RKH_EVE=$(ssh $EVE_IP "rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | grep -E 'Warning|Found' || echo 'Clean'" || echo "SSH failed")
[ "$RKH_EVE" != "Clean" ] && ESCALATE="$ESCALATE\n[EVE] rkhunter warnings: $RKH_EVE"
echo "$RKH_EVE" >> "$LOG"

# ============================================================
# ESCALATION
# ============================================================
if [ -n "$ESCALATE" ]; then
    echo -e "\n!!! ESCALATION NEEDED !!!" >> "$LOG"
    echo -e "$ESCALATE" >> "$LOG"
    TIMESTAMP=$(date -u +"%Y-%m-%d_%H-%M")
    mkdir -p /root/hive/escalations
    cat > /root/hive/escalations/CRITICAL-ACTIVE.json << EOFJSON
{
  "timestamp": "$TIMESTAMP",
  "alert_type": "DAILY_SCAN_ESCALATION",
  "summary": $(echo -e "$ESCALATE" | jq -Rs .),
  "details": "See daily log: /root/hive/logs/daily-$(date -u +%Y-%m-%d).log"
}
EOFJSON
else
    echo -e "\n=== Daily scan complete. All clear. ===" >> "$LOG"
fi

# Write result to Redis short-term memory
if [ -n "$ESCALATE" ]; then
    python3 /root/hive/redis-memory.py write 'sentinel_alert' "Daily scan: ALERT" "$(echo -e "$ESCALATE" | head -5)" 2>/dev/null
else
    python3 /root/hive/redis-memory.py write 'sentinel' "Daily scan: all clear — ClamAV clean, rkhunter clean, stack healthy" "Sat Feb 21 10:08:42 PM UTC 2026" 2>/dev/null
fi
