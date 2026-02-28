#!/bin/bash
# SENTINEL File Watcher — Sensitive Path Monitor (HIVE)
# Version: 1.0.0
# Runs as systemd service: sentinel-file-watch.service

ESCALATION_DIR="/root/hive/escalations"
ACTIVE_FILE="$ESCALATION_DIR/CRITICAL-ACTIVE.json"
LOG_DIR="/root/hive/logs"
LOG="$LOG_DIR/file-watch.log"
mkdir -p "$ESCALATION_DIR/handled" "$LOG_DIR"

PROTECTED_FILES=(
    "/root/.openclaw/credentials"
)

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $1" | tee -a "$LOG"; }

escalate() {
    local file=$1 event=$2
    local ts=$(date -u +'%Y-%m-%d_%H-%M-%S')
    log "ALERT: $event on $file"
    cat > "$ACTIVE_FILE" << EOFJSON
{
  "timestamp": "$ts",
  "alert_type": "FILE_ACCESS_ALERT",
  "source": "sentinel-file-watch",
  "summary": "SENSITIVE FILE ACCESS DETECTED — possible exfiltration or context-clone attack",
  "details": "Event: $event\nFile: $file\nTimestamp: $ts"
}
EOFJSON
}

WATCH_LIST=()
for f in "${PROTECTED_FILES[@]}"; do
    [ -e "$f" ] && WATCH_LIST+=("$f")
done

if [ ${#WATCH_LIST[@]} -eq 0 ]; then
    log "No protected files found on this host. Exiting."
    exit 1
fi

log "Starting SENTINEL File Watcher — monitoring ${#WATCH_LIST[@]} paths"

inotifywait -m -e open,access,modify,moved_from,delete     --format '%w%f|%e'     "${WATCH_LIST[@]}" 2>/dev/null | while IFS='|' read filepath event; do
    if [ -f "$ACTIVE_FILE" ]; then
        SOURCE=$(python3 -c "import json; print(json.load(open('$ACTIVE_FILE')).get('source',''))" 2>/dev/null)
        [ "$SOURCE" = "sentinel-file-watch" ] && continue
    fi
    escalate "$filepath" "$event"
done
