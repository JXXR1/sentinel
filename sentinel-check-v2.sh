#!/bin/bash
# SENTINEL Security Check Script
# Runs on HIVE, checks both HIVE and EVE

LOG_DIR="/root/hive/logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date -u +"%Y-%m-%d_%H-%M")
LOG="$LOG_DIR/check-$TIMESTAMP.log"
ESCALATE=""
ESCALATE_DETAIL=""

echo "=== SENTINEL Check $TIMESTAMP ===" > "$LOG"

# ============================================================
# ALLOWLIST: ports that are intentionally public-facing
# Format: "PORT:REASON"
# Only add here if you explicitly want it reachable from internet
# ============================================================
ALLOWED_PUBLIC_PORTS=(
    # Add ports here if deliberately public, e.g. "80:nginx" "443:nginx"
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
)

check_server() {
    local name=$1
    local cmd_prefix=$2

    echo -e "
--- $name ---" >> "$LOG"

    # CPU check
    echo "Top CPU:" >> "$LOG"
    if [ -z "$cmd_prefix" ]; then
        ps aux --sort=-%cpu | head -5 >> "$LOG" 2>&1
        CPU_CHECK=$(ps aux | awk '$3 > 80 {print $11}' | grep -vE "(ps|awk|openclaw|clawdbot|ollama|chromium|node|clamscan|rkhunter|pgrep|curl|python3|fail2ban)")
    else
        $cmd_prefix "ps aux --sort=-%cpu | head -5" >> "$LOG" 2>&1
        CPU_CHECK=$($cmd_prefix "ps aux | awk '\$3 > 80 {print \$11}' | grep -vE '(ps|awk|openclaw|clawdbot|ollama|chromium|node|clamscan|rkhunter)'")
    fi
    [ -n "$CPU_CHECK" ] && ESCALATE="$ESCALATE
[$name] High CPU: $CPU_CHECK"

    # Cron check
    echo "Cron check:" >> "$LOG"
    if [ -z "$cmd_prefix" ]; then
        CRON_SUS=$(crontab -l 2>/dev/null | grep -E "curl.*\|.*sh|wget.*\|.*sh|/tmp/|/var/tmp/|\.X0|snap")
    else
        CRON_SUS=$($cmd_prefix "crontab -l 2>/dev/null | grep -E 'curl.*\|.*sh|wget.*\|.*sh|/tmp/|/var/tmp/|\.X0|snap'")
    fi
    if [ -n "$CRON_SUS" ]; then
        echo "SUSPICIOUS: $CRON_SUS" >> "$LOG"
        ESCALATE="$ESCALATE
[$name] Suspicious cron: $CRON_SUS"
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
        ESCALATE="$ESCALATE
[$name] MINER DETECTED!"
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
        [ "$ALLOWED" -eq 0 ] && UNEXPECTED_EXPOSED="$UNEXPECTED_EXPOSED
  $line"
    done <<< "$RAW_EXPOSED"

    if [ -n "$UNEXPECTED_EXPOSED" ]; then
        echo "EXPOSED PORTS DETECTED:" >> "$LOG"
        echo -e "$UNEXPECTED_EXPOSED" >> "$LOG"
        ESCALATE="$ESCALATE
[$name] EXPOSED PORTS - check immediately"
        ESCALATE_DETAIL="$ESCALATE_DETAIL
[$name] Exposed port details:
$UNEXPECTED_EXPOSED"
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
            SENSITIVE_FAIL="$SENSITIVE_FAIL
  CRITICAL: $svc_name port $svc_port is PUBLIC (should be Tailscale/localhost only)"
        fi
    done

    if [ -n "$SENSITIVE_FAIL" ]; then
        ESCALATE="$ESCALATE
[$name] SENSITIVE SERVICES EXPOSED - IMMEDIATE ACTION REQUIRED"
        ESCALATE_DETAIL="$ESCALATE_DETAIL
[$name] Sensitive service violations:$SENSITIVE_FAIL"
    else
        echo "  All sensitive services properly bound" >> "$LOG"
    fi

    # Disk check
    if [ -z "$cmd_prefix" ]; then
        DISK=$(df -h / | tail -1 | awk '{print $5}' | tr -d '%')
    else
        DISK=$($cmd_prefix "df -h / | tail -1 | awk '{print \$5}' | tr -d '%'")
    fi
    echo "Disk: ${DISK}%" >> "$LOG"
    [ "$DISK" -gt 90 ] && ESCALATE="$ESCALATE
[$name] Disk critical: ${DISK}%"
}

check_server "HIVE" ""
check_server "EVE" "ssh 100.92.34.75"

if [ -n "$ESCALATE" ]; then
    echo -e "
!!! ESCALATION NEEDED !!!" >> "$LOG"
    echo -e "$ESCALATE" >> "$LOG"
    mkdir -p /root/hive/escalations
    mkdir -p /root/hive/escalations/handled

    echo -e "SENTINEL ALERT $TIMESTAMP
$ESCALATE" > "/root/hive/escalations/$TIMESTAMP.md"

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
else
    echo -e "
All clear." >> "$LOG"
    rm -f /root/hive/escalations/CRITICAL-ACTIVE.json
    echo "OK"
fi
