#!/bin/bash
# SENTINEL — Layer 27: Outbound Guard
#
# Monitors established outbound connections from selected processes and flags
# anything heading to a non-allowlisted destination host or non-standard port.
# Writes a JSON escalation file when violations are detected.
#
# Designed to be cheap (uses `ss`, no packet capture) and run frequently
# (every 1-2 minutes) alongside sentinel-watchdog.sh.
#
# Tunable via env vars (override in cron or wrapper):
#
#   SENTINEL_OUTBOUND_PROCESSES   Regex matching process names to inspect
#                                 (default: "openclaw|node|python|claude")
#   SENTINEL_OUTBOUND_PORTS_OK    Pipe-separated list of allowed dest ports
#                                 (default: "443|80|53|22|587|993|8443|8080")
#   SENTINEL_OUTBOUND_HOSTS_OK    Regex of trusted destination hostnames.
#                                 If set, hostname lookup is attempted for
#                                 unknown ports; matching hosts are excluded.
#                                 (default: empty — port allowlist only)
#   SENTINEL_OUTBOUND_KILL        If "true" AND a process pattern matches,
#                                 send TERM to the offending PID. Default: false.
#                                 Use with care.
#   SENTINEL_ESCALATION_DIR       Directory for JSON escalations
#                                 (default: /var/lib/sentinel/escalations)
#
# Exit code: 0 always (escalation conveyed via JSON file presence).

set -u

PROCESSES="${SENTINEL_OUTBOUND_PROCESSES:-openclaw|node|python|claude}"
PORTS_OK="${SENTINEL_OUTBOUND_PORTS_OK:-443|80|53|22|587|993|8443|8080}"
HOSTS_OK="${SENTINEL_OUTBOUND_HOSTS_OK:-}"
DO_KILL="${SENTINEL_OUTBOUND_KILL:-false}"
ESCALATION_DIR="${SENTINEL_ESCALATION_DIR:-/var/lib/sentinel/escalations}"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
mkdir -p "$ESCALATION_DIR" "$ESCALATION_DIR/handled"
ACTIVE_FILE="$ESCALATION_DIR/OUTBOUND-GUARD.json"

FINDINGS=()
KILLED=()

while read -r RQ SQ LOCAL PEER PROC; do
    PORT="${PEER##*:}"
    case "$PORT" in
        ''|*[!0-9]*) continue ;;
    esac
    case "$PORT" in
        $(echo "$PORTS_OK" | sed 's/|/|/g')) continue ;;
    esac
    # Port not on allowlist. If host allowlist is configured, give it a chance.
    if [ -n "$HOSTS_OK" ]; then
        HOST_IP="${PEER%:*}"
        HOST_IP="${HOST_IP#[}"; HOST_IP="${HOST_IP%]}"
        HOSTNAME=$(getent hosts "$HOST_IP" 2>/dev/null | awk '{print $2}' | head -1)
        if [ -n "$HOSTNAME" ] && echo "$HOSTNAME" | grep -qE "$HOSTS_OK"; then
            continue
        fi
    fi
    FINDINGS+=("port=$PORT peer=$PEER proc=$PROC")

    if [ "$DO_KILL" = "true" ]; then
        PID=$(echo "$PROC" | grep -oP 'pid=\K[0-9]+' | head -1)
        if [ -n "$PID" ]; then
            kill -TERM "$PID" 2>/dev/null && KILLED+=("$PID")
        fi
    fi
done < <(ss -tnp state established 2>/dev/null | grep -E "$PROCESSES")

if [ "${#FINDINGS[@]}" -eq 0 ]; then
    # Clean run — clear any stale escalation
    if [ -f "$ACTIVE_FILE" ]; then
        mv "$ACTIVE_FILE" "$ESCALATION_DIR/handled/OUTBOUND-GUARD-$TIMESTAMP.json"
    fi
    exit 0
fi

# JSON escalation
{
    echo '{'
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"alert_type\": \"OUTBOUND_VIOLATION\","
    echo "  \"source\": \"sentinel-outbound-guard\","
    echo "  \"summary\": \"${#FINDINGS[@]} non-allowlisted outbound connection(s) from monitored processes\","
    echo '  "findings": ['
    first=1
    for f in "${FINDINGS[@]}"; do
        esc=$(printf '%s' "$f" | sed 's/\\/\\\\/g; s/"/\\"/g')
        if [ "$first" -eq 1 ]; then first=0; else echo ','; fi
        printf '    "%s"' "$esc"
    done
    echo
    echo '  ],'
    echo '  "killed_pids": ['
    first=1
    for k in "${KILLED[@]}"; do
        if [ "$first" -eq 1 ]; then first=0; else echo ','; fi
        printf '    "%s"' "$k"
    done
    echo
    echo '  ]'
    echo '}'
} > "$ACTIVE_FILE"
chmod 600 "$ACTIVE_FILE"

exit 0
