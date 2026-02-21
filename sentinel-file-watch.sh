#!/bin/bash
# SENTINEL File Watcher — Sensitive Path Monitor
# Companion to sentinel-check-v2.sh and sentinel-watchdog.sh
#
# Purpose: Watches critical identity/memory files for unexpected access.
#          Fires CRITICAL-ACTIVE.json immediately on any read or write
#          to protected files — catches a live exfiltration or context-clone
#          attack that slipped past the pre-install scanner.
#
# Runs as: systemd service (sentinel-file-watch.service)

# License: MIT
# Version: 1.0.0

ESCALATION_DIR="${SENTINEL_DIR:-/var/lib/sentinel}/escalations"
ACTIVE_FILE="$ESCALATION_DIR/CRITICAL-ACTIVE.json"
LOG_DIR="${SENTINEL_DIR:-/var/lib/sentinel}/logs"
LOG="$LOG_DIR/file-watch.log"

mkdir -p "$ESCALATION_DIR/handled" "$LOG_DIR"

# ============================================================
# PROTECTED FILES: any unexpected access triggers immediate alert
# Add paths relevant to your setup
# ============================================================
PROTECTED_FILES=(
    "$HOME/.config/myapp/memory.md"  # configure for your setup
    "$HOME/.config/myapp/soul.md"
    "$HOME/.config/myapp/identity.md"
    "$HOME/.config/myapp/tools.md"
    "$HOME/.config/myapp/memory.json"
    "$HOME/.config/myapp/cache.json"
    "$HOME/.env"  # or wherever your credentials are stored
)

# ============================================================
# TRUSTED PROCESSES: access from these is expected — suppress
# ============================================================
TRUSTED_PROCESSES=(
    "myapp"  # add your application name here
    "node"
    "bash"
    "cat"
    "grep"
    "python3"
)

log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $1" | tee -a "$LOG"
}

escalate() {
    local file=$1
    local event=$2
    local proc=$3
    local ts=$(date -u +"%Y-%m-%d_%H-%M-%S")

    log "ALERT: $event on $file (process: $proc)"

    cat > "$ACTIVE_FILE" << EOFJSON
{
  "timestamp": "$ts",
  "alert_type": "FILE_ACCESS_ALERT",
  "source": "sentinel-file-watch",
  "summary": "SENSITIVE FILE ACCESS DETECTED — possible exfiltration or context-clone attack",
  "details": "Event: $event\nFile: $file\nProcess: $proc\nTimestamp: $ts"
}
EOFJSON
}

# Build watch list (only include files that exist)
WATCH_LIST=()
for f in "${PROTECTED_FILES[@]}"; do
    [ -f "$f" ] && WATCH_LIST+=("$f")
done

if [ ${#WATCH_LIST[@]} -eq 0 ]; then
    log "No protected files found to watch. Exiting."
    exit 1
fi

log "Starting SENTINEL File Watcher — monitoring ${#WATCH_LIST[@]} files"
log "Protected: ${WATCH_LIST[*]}"

# Watch for open (read), access, and modify events
inotifywait -m -e open,access,modify,moved_from,delete \
    --format '%w%f %e %T' \
    --timefmt '%Y-%m-%dT%H:%M:%SZ' \
    "${WATCH_LIST[@]}" 2>/dev/null | \
while read filepath event timestamp; do
    # Skip if already have an active alert from this watcher
    if [ -f "$ACTIVE_FILE" ]; then
        SOURCE=$(python3 -c "import json; print(json.load(open('$ACTIVE_FILE')).get('source',''))" 2>/dev/null)
        [ "$SOURCE" = "sentinel-file-watch" ] && continue
    fi

    # Log and escalate
    escalate "$filepath" "$event" "unknown"
done
