#!/bin/bash
# SENTINEL — Layer 30: Stack Health
#
# Verifies the security stack is *alive, fresh, and vocal*:
#   - Alive   = daemon is running
#   - Fresh   = signature/rule databases recently updated
#   - Vocal   = log files actively written (not silently broken)
#
# Catches the failure mode where ClamAV / Suricata / Wazuh / CrowdSec are
# technically "running" but their detection capability has degraded
# (stale signatures, silent log pipeline) and conventional `systemctl
# is-active` would still report green.
#
# Attempts safe auto-remediation for well-understood drift (stale sigs,
# missed AIDE rebaseline post-apt activity, etc.) with hard guards against
# touching agent-critical services and a cascade-safety threshold.
#
# Tunable via env vars:
#
#   SENTINEL_STACK_DAEMONS         Space-separated list of systemd services to verify.
#                                  Default: "ufw fail2ban suricata falco crowdsec
#                                            crowdsec-firewall-bouncer wazuh-manager
#                                            osqueryd squid auditd tailscaled"
#   SENTINEL_STACK_CRITICAL        Space-separated list of services the script
#                                  must NEVER auto-restart (would risk taking
#                                  down a co-resident agent/app).
#                                  Default: "redis-server qdrant tailscaled ufw auditd"
#   SENTINEL_STACK_CASCADE_MAX     If alert count exceeds this, quarantine all
#                                  (don't auto-act). Default: 5.
#   SENTINEL_STACK_LOG             Path to append-only log (default
#                                  /var/log/sentinel-stack-health.log).
#   SENTINEL_ESCALATION_DIR        Directory for JSON escalations
#                                  (default /var/lib/sentinel/escalations).
#
# Exit code: 0 always (escalation conveyed via JSON file presence).

set -u

DAEMONS="${SENTINEL_STACK_DAEMONS:-ufw fail2ban suricata falco crowdsec crowdsec-firewall-bouncer wazuh-manager osqueryd squid auditd tailscaled}"
CRITICAL="${SENTINEL_STACK_CRITICAL:-redis-server qdrant tailscaled ufw auditd}"
CASCADE_MAX="${SENTINEL_STACK_CASCADE_MAX:-5}"
LOG="${SENTINEL_STACK_LOG:-/var/log/sentinel-stack-health.log}"
ESCALATION_DIR="${SENTINEL_ESCALATION_DIR:-/var/lib/sentinel/escalations}"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
mkdir -p "$ESCALATION_DIR" "$ESCALATION_DIR/handled" "$(dirname "$LOG")"
ACTIVE_FILE="$ESCALATION_DIR/STACK-HEALTH.json"

ALERTS=()
REMEDIATED=()
QUARANTINED=()
REMAINING=()

age_hours() {
    local f=$1
    [ -e "$f" ] || { echo 9999; return; }
    echo $(( ($(date +%s) - $(stat -c %Y "$f")) / 3600 ))
}
age_days() { echo $(( $(age_hours "$1") / 24 )); }
is_active() { [ "$(systemctl is-active "$1" 2>/dev/null)" = "active" ]; }
is_critical() {
    local svc="$1"
    for c in $CRITICAL; do [ "$svc" = "$c" ] && return 0; done
    return 1
}
log_line() { echo "[$(date -u +%FT%TZ)] $*" >> "$LOG"; }

# --- ALIVE -----------------------------------------------------------------
for svc in $DAEMONS; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
        is_active "$svc" || ALERTS+=("DAEMON DOWN: $svc")
    fi
done

# --- FRESH (signature / rule databases) ------------------------------------
H=$(age_hours /var/lib/suricata/rules/suricata.rules)
[ -e /var/lib/suricata/rules/suricata.rules ] && [ "$H" -gt 48 ] && \
    ALERTS+=("Suricata rules stale: ${H}h (SLA 48h)")

H=$(age_hours /var/lib/clamav/daily.cld)
[ -e /var/lib/clamav/daily.cld ] && [ "$H" -gt 48 ] && \
    ALERTS+=("ClamAV daily DB stale: ${H}h")

# AIDE rebaseline overdue — only flag if dpkg also old (legit drift expected after apt activity)
if [ -e /var/lib/aide/aide.db ]; then
    AIDE_AGE=$(age_days /var/lib/aide/aide.db)
    DPKG_AGE=$(age_days /var/log/dpkg.log)
    if [ "$AIDE_AGE" -gt "$DPKG_AGE" ] && [ "$AIDE_AGE" -gt 7 ]; then
        ALERTS+=("AIDE baseline ${AIDE_AGE}d old vs dpkg ${DPKG_AGE}d ago — rebaseline overdue")
    fi
fi

# --- VOCAL (proves daemon actually emitting events) ------------------------
[ -e /var/log/suricata/eve.json ] && \
    { H=$(age_hours /var/log/suricata/eve.json); [ "$H" -gt 2 ] && \
      ALERTS+=("Suricata eve.json silent: ${H}h since last write"); }

[ -e /var/log/auth.log ] && \
    { H=$(age_hours /var/log/auth.log); [ "$H" -gt 6 ] && \
      ALERTS+=("auth.log silent: ${H}h"); }

[ -e /var/log/aide-check.log ] && \
    { H=$(age_hours /var/log/aide-check.log); [ "$H" -gt 25 ] && \
      ALERTS+=("AIDE daily check missed: ${H}h since last run"); }

if [ -e /var/lib/crowdsec/data/crowdsec.db ] && is_active crowdsec; then
    H=$(age_hours /var/lib/crowdsec/data/crowdsec.db)
    [ "$H" -gt 24 ] && ALERTS+=("CrowdSec DB silent: ${H}h since last write (SLA 24h)")
fi

# --- FIREWALL --------------------------------------------------------------
if command -v ufw >/dev/null 2>&1; then
    /usr/sbin/ufw status 2>/dev/null | grep -q "Status: active" || \
        ALERTS+=("UFW reports inactive (firewall down)")
fi

# --- REBOOT-REQUIRED FLAG --------------------------------------------------
if [ -f /var/run/reboot-required ]; then
    PKGS=$(head -3 /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')
    ALERTS+=("Reboot required: ${PKGS:-pending kernel/library update}")
fi

# --- CASCADE GUARD ---------------------------------------------------------
# Too many alerts = systemic problem. Don't auto-act; quarantine all.
if [ "${#ALERTS[@]}" -gt "$CASCADE_MAX" ]; then
    log_line "CASCADE GUARD: ${#ALERTS[@]} alerts (> $CASCADE_MAX) — quarantining all"
    REMAINING=("${ALERTS[@]}")
    QUARANTINED+=("cascade-guard:${#ALERTS[@]}-alerts")
    ALERTS=()
fi

# --- AUTO-REMEDIATION ------------------------------------------------------
attempt_remediate() {
    local alert="$1"
    case "$alert" in
        "DAEMON DOWN: "*)
            local svc="${alert##*: }"
            if is_critical "$svc"; then
                QUARANTINED+=("$alert (critical, never auto-restart)")
                return 1
            fi
            log_line "remediate: starting $svc"
            if systemctl start "$svc" >>"$LOG" 2>&1 && is_active "$svc"; then
                REMEDIATED+=("$alert -> systemctl start $svc")
                return 0
            fi
            ;;
        "Suricata rules stale"*)
            log_line "remediate: suricata-update + reload"
            if command -v suricata-update >/dev/null 2>&1 && \
               suricata-update >>"$LOG" 2>&1 && \
               systemctl reload suricata >>"$LOG" 2>&1; then
                REMEDIATED+=("$alert -> suricata-update + reload")
                return 0
            fi
            ;;
        "ClamAV daily DB stale"*)
            log_line "remediate: freshclam"
            if command -v freshclam >/dev/null 2>&1 && freshclam >>"$LOG" 2>&1; then
                REMEDIATED+=("$alert -> freshclam")
                return 0
            fi
            ;;
        "AIDE baseline"*)
            local dpkg_h
            dpkg_h=$(age_hours /var/log/dpkg.log)
            if [ "$dpkg_h" -gt 168 ]; then
                QUARANTINED+=("$alert (dpkg.log ${dpkg_h}h old — suspicious drift, manual review)")
                return 1
            fi
            log_line "remediate: aide --init (dpkg activity ${dpkg_h}h ago)"
            if aide --init --config /etc/aide/aide.conf >>"$LOG" 2>&1 \
               && [ -f /var/lib/aide/aide.db.new ] \
               && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db; then
                REMEDIATED+=("$alert -> aide --init + promote")
                return 0
            fi
            ;;
        "CrowdSec DB silent"*)
            if is_critical crowdsec; then
                QUARANTINED+=("$alert (crowdsec marked critical)")
                return 1
            fi
            log_line "remediate: restart crowdsec"
            if systemctl restart crowdsec >>"$LOG" 2>&1 && is_active crowdsec; then
                REMEDIATED+=("$alert -> systemctl restart crowdsec")
                return 0
            fi
            ;;
        "Suricata eve.json silent"*)
            if is_critical suricata; then
                QUARANTINED+=("$alert (suricata marked critical)")
                return 1
            fi
            log_line "remediate: restart suricata"
            if systemctl restart suricata >>"$LOG" 2>&1 && is_active suricata; then
                REMEDIATED+=("$alert -> systemctl restart suricata")
                return 0
            fi
            ;;
    esac
    return 1
}

for a in "${ALERTS[@]}"; do
    if ! attempt_remediate "$a"; then
        REMAINING+=("$a")
    fi
done

# --- OUTPUT ----------------------------------------------------------------
{
    echo "=== $TIMESTAMP stack-health ==="
    if [ "${#REMAINING[@]}" -eq 0 ] && [ "${#REMEDIATED[@]}" -eq 0 ] && [ "${#QUARANTINED[@]}" -eq 0 ]; then
        echo "OK — all checks pass"
    else
        for d in "${ALERTS[@]}"   ; do echo "DETECTED:    $d"; done
        for r in "${REMEDIATED[@]}"; do echo "FIXED:       $r"; done
        for q in "${QUARANTINED[@]}"; do echo "QUARANTINED: $q"; done
        for u in "${REMAINING[@]}"  ; do echo "UNFIXED:     $u"; done
    fi
} >> "$LOG"

if [ "${#REMAINING[@]}" -eq 0 ] && [ "${#QUARANTINED[@]}" -eq 0 ]; then
    # Either nothing detected OR everything auto-fixed cleanly
    if [ -f "$ACTIVE_FILE" ]; then
        mv "$ACTIVE_FILE" "$ESCALATION_DIR/handled/STACK-HEALTH-$TIMESTAMP.json"
    fi
    exit 0
fi

{
    echo '{'
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"alert_type\": \"STACK_HEALTH_DRIFT\","
    echo "  \"source\": \"sentinel-stack-health\","
    echo "  \"log\": \"$LOG\","
    echo '  "auto_remediated": ['
    first=1
    for r in "${REMEDIATED[@]}"; do
        esc=$(printf '%s' "$r" | sed 's/\\/\\\\/g; s/"/\\"/g')
        if [ "$first" -eq 1 ]; then first=0; else echo ','; fi
        printf '    "%s"' "$esc"
    done
    echo
    echo '  ],'
    echo '  "quarantined": ['
    first=1
    for q in "${QUARANTINED[@]}"; do
        esc=$(printf '%s' "$q" | sed 's/\\/\\\\/g; s/"/\\"/g')
        if [ "$first" -eq 1 ]; then first=0; else echo ','; fi
        printf '    "%s"' "$esc"
    done
    echo
    echo '  ],'
    echo '  "needs_action": ['
    first=1
    for u in "${REMAINING[@]}"; do
        esc=$(printf '%s' "$u" | sed 's/\\/\\\\/g; s/"/\\"/g')
        if [ "$first" -eq 1 ]; then first=0; else echo ','; fi
        printf '    "%s"' "$esc"
    done
    echo
    echo '  ]'
    echo '}'
} > "$ACTIVE_FILE"
chmod 600 "$ACTIVE_FILE"

exit 0
