#!/bin/bash
# SENTINEL Security Check Script v1.2.0
# Runs on HIVE, checks both HIVE and EVE

LOG_DIR="/root/hive/logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date -u +"%Y-%m-%d_%H-%M")
LOG="$LOG_DIR/check-$TIMESTAMP.log"
STATE_FILE="/root/hive/escalations/.last-state"
ESCALATE=""
ESCALATE_DETAIL=""

echo "=== SENTINEL Check $TIMESTAMP ===" > "$LOG"

# ============================================================
# ALLOWLIST: ports bound to 0.0.0.0 but UFW-protected (not truly public)
# Format: "PORT:REASON"
# ============================================================
ALLOWED_PUBLIC_PORTS=(
    "1515:Wazuh-authd-UFW-Tailscale-only"  # Cannot bind to specific interface, UFW blocks public access
)

# ============================================================
# SENSITIVE SERVICES: must NEVER be bound to 0.0.0.0 or *
# These get an immediate hard escalation if found exposed
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

check_server() {
    local name=$1
    local cmd_prefix=$2

    echo -e "\n--- $name ---" >> "$LOG"

    # CPU check
    echo "Top CPU:" >> "$LOG"
    if [ -z "$cmd_prefix" ]; then
        ps aux --sort=-%cpu | head -5 >> "$LOG" 2>&1
        CPU_CHECK=$(ps aux | awk '$3 > 80 {print $11}' | grep -vE "(ps|awk|openclaw|clawdbot|ollama|chromium|node|clamscan|rkhunter|pgrep|curl|python3|fail2ban)")
    else
        $cmd_prefix "ps aux --sort=-%cpu | head -5" >> "$LOG" 2>&1
        CPU_CHECK=$($cmd_prefix "ps aux | awk '\$3 > 80 {print \$11}' | grep -vE '(ps|awk|openclaw|clawdbot|ollama|chromium|node|clamscan|rkhunter)'")
    fi
    [ -n "$CPU_CHECK" ] && ESCALATE="$ESCALATE\n[$name] High CPU: $CPU_CHECK"

    # Cron check
    echo "Cron check:" >> "$LOG"
    if [ -z "$cmd_prefix" ]; then
        CRON_SUS=$(crontab -l 2>/dev/null | grep -E "curl.*\|.*sh|wget.*\|.*sh|/tmp/|/var/tmp/|\.X0|snap")
    else
        CRON_SUS=$($cmd_prefix "crontab -l 2>/dev/null | grep -E 'curl.*\|.*sh|wget.*\|.*sh|/tmp/|/var/tmp/|\.X0|snap'")
    fi
    if [ -n "$CRON_SUS" ]; then
        echo "SUSPICIOUS: $CRON_SUS" >> "$LOG"
        ESCALATE="$ESCALATE\n[$name] Suspicious cron: $CRON_SUS"
    else
        echo "Clean" >> "$LOG"
    fi

    # Mining check
    echo "Mining check:" >> "$LOG"
    if [ -z "$cmd_prefix" ]; then
        MINER_PROC=$(ps aux | grep -E "xmrig|minerd|cgminer|bfgminer|cpuminer|ethminer" | grep -v grep)
        MINER_PORT=$(ss -tuln 2>/dev/null | grep -E ":3333|:4444|:5555|:7777|:8888|:9999")
    else
        MINER_PROC=$($cmd_prefix "ps aux | grep -E 'xmrig|minerd|cgminer|bfgminer|cpuminer|ethminer' | grep -v grep")
        MINER_PORT=$($cmd_prefix "ss -tuln 2>/dev/null | grep -E ':3333|:4444|:5555|:7777|:8888|:9999'")
    fi
    if [ -n "$MINER_PROC" ] || [ -n "$MINER_PORT" ]; then
        echo "MINING DETECTED" >> "$LOG"
        ESCALATE="$ESCALATE\n[$name] MINER DETECTED!"
    else
        echo "Clean" >> "$LOG"
    fi

    # ============================================================
    # FRONT DOOR CHECK - External port exposure (IMPROVED)
    # ============================================================
    echo "Front door check:" >> "$LOG"

    if [ -z "$cmd_prefix" ]; then
        RAW_EXPOSED=$(ss -tlnp 2>/dev/null | grep -E "0\.0\.0\.0:[0-9]|\*:[0-9]" | grep -v "127.0.0.1")
    else
        RAW_EXPOSED=$($cmd_prefix "ss -tlnp 2>/dev/null | grep -E '0\.0\.0\.0:[0-9]|\*:[0-9]' | grep -v '127.0.0.1'")
    fi

    # Filter out allowlisted ports
    UNEXPECTED_EXPOSED=""
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        PORT=$(echo "$line" | grep -oP '(?<=:)\d+(?=\s)' | head -1)
        ALLOWED=0
        for allowed in "${ALLOWED_PUBLIC_PORTS[@]}"; do
            allowed_port=$(echo "$allowed" | cut -d: -f1)
            [ "$PORT" = "$allowed_port" ] && ALLOWED=1 && break
        done
        [ "$ALLOWED" -eq 0 ] && UNEXPECTED_EXPOSED="$UNEXPECTED_EXPOSED\n  $line"
    done <<< "$RAW_EXPOSED"

    if [ -n "$UNEXPECTED_EXPOSED" ]; then
        echo "EXPOSED PORTS DETECTED:" >> "$LOG"
        echo -e "$UNEXPECTED_EXPOSED" >> "$LOG"
        ESCALATE="$ESCALATE\n[$name] EXPOSED PORTS - check immediately"
        ESCALATE_DETAIL="$ESCALATE_DETAIL\n[$name] Exposed port details:\n$UNEXPECTED_EXPOSED"
    else
        echo "Clean - all doors closed" >> "$LOG"
    fi

    # ============================================================
    # SENSITIVE SERVICE CHECK
    # Hard fail if any sensitive service is on 0.0.0.0 or *
    # ============================================================
    echo "Sensitive service check:" >> "$LOG"
    SENSITIVE_FAIL=""
    for entry in "${SENSITIVE_SERVICES[@]}"; do
        svc_port=$(echo "$entry" | cut -d: -f1)
        svc_name=$(echo "$entry" | cut -d: -f2)
        if [ -z "$cmd_prefix" ]; then
            BINDING=$(ss -tlnp 2>/dev/null | grep -E "0\.0\.0\.0:${svc_port}|\*:${svc_port}" | grep -v "127.0.0.1")
        else
            BINDING=$($cmd_prefix "ss -tlnp 2>/dev/null | grep -E '0\.0\.0\.0:${svc_port}|\*:${svc_port}' | grep -v '127.0.0.1'")
        fi
        if [ -n "$BINDING" ]; then
            echo "  CRITICAL: $svc_name (port $svc_port) EXPOSED ON 0.0.0.0" >> "$LOG"
            SENSITIVE_FAIL="$SENSITIVE_FAIL\n  CRITICAL: $svc_name port $svc_port is PUBLIC (should be Tailscale/localhost only)"
        fi
    done

    if [ -n "$SENSITIVE_FAIL" ]; then
        ESCALATE="$ESCALATE\n[$name] SENSITIVE SERVICES EXPOSED - IMMEDIATE ACTION REQUIRED"
        ESCALATE_DETAIL="$ESCALATE_DETAIL\n[$name] Sensitive service violations:$SENSITIVE_FAIL"
    else
        echo "  All sensitive services properly bound" >> "$LOG"
    fi


    # ============================================================
    # SECURITY STACK HEALTH CHECK
    # All 24 layers must be running — alert if any are down
    # ============================================================
    echo "Security stack health:" >> "$LOG"

    SYSTEMD_SERVICES="tailscaled crowdsec crowdsec-firewall-bouncer fail2ban sophos-spl clamav-daemon auditd osqueryd"
    STACK_FAIL=""

    for svc in $SYSTEMD_SERVICES; do
        if [ -z "$cmd_prefix" ]; then
            STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "not-found")
        else
            STATUS=$($cmd_prefix "systemctl is-active $svc 2>/dev/null || echo not-found")
        fi
        if [ "$STATUS" != "active" ]; then
            STACK_FAIL="$STACK_FAIL
  DOWN: $svc (status: $STATUS)"
            echo "  FAIL: $svc is $STATUS" >> "$LOG"
        else
            echo "  OK: $svc" >> "$LOG"
        fi
    done

    # Wazuh check (uses wazuh-control, not systemctl)
    if [ -z "$cmd_prefix" ]; then
        WAZUH_DOWN=$(/var/ossec/bin/wazuh-control status 2>/dev/null | grep "not running" | grep -Ev "wazuh-clusterd|wazuh-maild|wazuh-dbd|wazuh-csyslogd|wazuh-agentlessd|wazuh-integratord|wazuh-authd" | wc -l)
    else
        WAZUH_DOWN=$($cmd_prefix "/var/ossec/bin/wazuh-control status 2>/dev/null | grep 'not running' | grep -Ev 'wazuh-clusterd|wazuh-maild|wazuh-dbd|wazuh-csyslogd|wazuh-agentlessd|wazuh-integratord|wazuh-authd' | wc -l")
    fi
    if [ "$WAZUH_DOWN" -gt 0 ] 2>/dev/null; then
        STACK_FAIL="$STACK_FAIL
  DOWN: wazuh ($WAZUH_DOWN core processes not running)"
        echo "  FAIL: wazuh has $WAZUH_DOWN processes down" >> "$LOG"
    else
        echo "  OK: wazuh" >> "$LOG"
    fi

    # UFW check via iptables policy
    if [ -z "$cmd_prefix" ]; then
        UFW_POLICY=$(/sbin/iptables -L INPUT -n 2>/dev/null | grep -c "policy DROP\|policy ACCEPT" || echo "0")
        UFW_DROP=$(/sbin/iptables -L INPUT -n 2>/dev/null | head -1 | grep -c "DROP" || echo "0")
    else
        UFW_DROP=$($cmd_prefix "/sbin/iptables -L INPUT -n 2>/dev/null | head -1 | grep -c DROP || echo 0")
    fi
    if [ "${UFW_DROP:-0}" -eq 0 ] 2>/dev/null; then
        STACK_FAIL="$STACK_FAIL
  DOWN: ufw/iptables (INPUT policy is not DROP)";
        echo "  FAIL: ufw INPUT policy not DROP" >> "$LOG"
    else
        echo "  OK: ufw (INPUT DROP policy active)" >> "$LOG"
    fi

    if [ -n "$STACK_FAIL" ]; then
        ESCALATE="$ESCALATE
[$name] SECURITY STACK DEGRADED - services down"
        ESCALATE_DETAIL="$ESCALATE_DETAIL
[$name] Security stack failures:$STACK_FAIL"
        echo "  => Escalating stack failures" >> "$LOG"
    else
        echo "  All security services healthy" >> "$LOG"
    fi

    # Disk check
    if [ -z "$cmd_prefix" ]; then
        DISK=$(df -h / | tail -1 | awk '{print $5}' | tr -d '%')
    else
        DISK=$($cmd_prefix "df -h / | tail -1 | awk '{print \$5}' | tr -d '%'")
    fi
    echo "Disk: ${DISK}%" >> "$LOG"
    [ "$DISK" -gt 90 ] && ESCALATE="$ESCALATE\n[$name] Disk critical: ${DISK}%"
}

check_server "HIVE" ""
check_server "EVE" "ssh 100.79.182.103"

# ============================================================
# AI FILE INTEGRITY CHECK (Layer 29)
# ============================================================
echo "AI file integrity check:" >> "$LOG"
FIM_RESULT=$(ssh 100.79.182.103 "bash /root/.openclaw/workspace/file-integrity-monitor.sh 2>/dev/null" 2>/dev/null)
FIM_EXIT=$?
if [ $FIM_EXIT -eq 2 ]; then
    ESCALATE="$ESCALATE
[EVE] FILE INTEGRITY VIOLATION: $FIM_RESULT"
    ESCALATE_DETAIL="$ESCALATE_DETAIL
[EVE] AI stack file tamper detected"
    echo "  => File integrity ALERT" >> "$LOG"
else
    echo "  => File integrity OK" >> "$LOG"
fi

if [ -n "$ESCALATE" ]; then
    echo -e "\n!!! ESCALATION NEEDED !!!" >> "$LOG"
    echo -e "$ESCALATE" >> "$LOG"
    mkdir -p /root/hive/escalations
    mkdir -p /root/hive/escalations/handled

    # ============================================================
    # DELTA DETECTION: only escalate if findings changed since last run
    # Suppresses repeat alerts for known issues
    # ============================================================
    CURRENT_FINGERPRINT=$(echo -e "$ESCALATE" | md5sum | cut -d' ' -f1)
    LAST_FINGERPRINT=$(cat "$STATE_FILE" 2>/dev/null || echo "")

    if [ "$CURRENT_FINGERPRINT" = "$LAST_FINGERPRINT" ]; then
        echo -e "\n[DELTA] Same findings as last run — suppressing repeat escalation" >> "$LOG"
        echo "KNOWN"
    else
        echo "$CURRENT_FINGERPRINT" > "$STATE_FILE"
        echo -e "SENTINEL ALERT $TIMESTAMP\n$ESCALATE" > "/root/hive/escalations/$TIMESTAMP.md"

        # Create CRITICAL-ACTIVE file — includes full details so EVE knows exactly what's wrong
        cat > /root/hive/escalations/CRITICAL-ACTIVE.json << EOFJSON
{
  "timestamp": "$TIMESTAMP",
  "alert_type": "SECURITY_ESCALATION",
  "summary": $(echo -e "$ESCALATE" | jq -Rs .),
  "details": $(echo -e "$ESCALATE_DETAIL" | jq -Rs .)
}
EOFJSON

        echo "ALERT"
    fi
else
    echo -e "\nAll clear." >> "$LOG"
    rm -f /root/hive/escalations/CRITICAL-ACTIVE.json
    rm -f "$STATE_FILE"
    echo "OK"
fi

# Write result to Redis short-term memory
if [ -n "$ESCALATE" ]; then
    python3 /root/hive/redis-memory.py write 'sentinel_alert' "SENTINEL 6h scan: ALERT" "$(echo -e "$ESCALATE" | head -5)" 2>/dev/null
else
    python3 /root/hive/redis-memory.py write 'sentinel' "SENTINEL 6h scan: all clear" "Both servers healthy" 2>/dev/null
fi
