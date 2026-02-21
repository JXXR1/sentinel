#!/bin/bash
# SENTINEL Watchdog — Fast Critical Alert Script
# Companion to sentinel-check-v2.sh
#
# Purpose: Checks sensitive services ONLY, runs every 1-2 minutes via cron.
#          Fires CRITICAL-ACTIVE.json the moment a sensitive service is found
#          on 0.0.0.0 — does not wait for the full 6h SENTINEL scan.
#

# License: MIT
# Version: 1.0.0

ESCALATION_DIR="${SENTINEL_DIR:-/var/lib/sentinel}/escalations"
ACTIVE_FILE="$ESCALATION_DIR/CRITICAL-ACTIVE.json"
TIMESTAMP=$(date -u +"%Y-%m-%d_%H-%M-%S")

mkdir -p "$ESCALATION_DIR"
mkdir -p "$ESCALATION_DIR/handled"

# ============================================================
# SENSITIVE SERVICES: must NEVER be bound to 0.0.0.0 or *
# Mirror this list with sentinel-check-v2.sh
# ============================================================
SENSITIVE_SERVICES=(
    "6333:Qdrant-HTTP"
    "6334:Qdrant-gRPC"
    "11434:Ollama"
    "6379:Redis"
    "8080:CrowdSec"
    "6060:CrowdSec-Prometheus"
    "8080:myapp-service"  # replace with your application ports
    
)

check_host() {
    local host_label=$1
    local cmd_prefix=$2
    local findings=""

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

    echo "$findings"
}

# Check both servers
LOCAL_FINDINGS=$(check_host "local" "")
# REMOTE_FINDINGS=$(check_host "remote" "ssh user@remote-server")  # optional

ALL_FINDINGS=""
[ -n "$LOCAL_FINDINGS" ] && ALL_FINDINGS="$ALL_FINDINGS\n[local] Sensitive service violations:$LOCAL_FINDINGS"
# [ -n "$REMOTE_FINDINGS" ] && ALL_FINDINGS="$ALL_FINDINGS\n[remote] $REMOTE_FINDINGS"

if [ -n "$ALL_FINDINGS" ]; then
    # Write CRITICAL-ACTIVE.json — same format as full SENTINEL scan
    cat > "$ACTIVE_FILE" << EOFJSON
{
  "timestamp": "$TIMESTAMP",
  "alert_type": "WATCHDOG_CRITICAL",
  "source": "sentinel-watchdog",
  "summary": "SENSITIVE SERVICE EXPOSED ON 0.0.0.0 — IMMEDIATE ACTION REQUIRED",
  "details": $(echo -e "$ALL_FINDINGS" | jq -Rs .)
}
EOFJSON
    exit 1
else
    # All clear — remove stale watchdog alert if present (full SENTINEL manages its own)
    if [ -f "$ACTIVE_FILE" ]; then
        SOURCE=$(python3 -c "import json; d=json.load(open('$ACTIVE_FILE')); print(d.get('source',''))" 2>/dev/null)
        [ "$SOURCE" = "sentinel-watchdog" ] && rm -f "$ACTIVE_FILE"
    fi
    exit 0
fi
