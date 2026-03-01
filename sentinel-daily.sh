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
# CREDENTIAL HYGIENE — both servers
# ============================================================
credential_audit() {
    local name=$1
    local prefix=$2
    local FINDINGS=""

    echo -e "\n--- Credential Hygiene: $name ---" >> "$LOG"

    # 1. Plaintext credentials in config files (outside .env)
    if [ -z "$prefix" ]; then
        CRED_FILES=$(grep -rln "sk_\|sk-ant-\|Bearer \|api_key=\|apikey=\|API_KEY=\|password=" /root --include="*.json" --include="*.yaml" --include="*.toml" --include="*.conf" --include="*.cfg" --include="*.ini" 2>/dev/null | grep -v node_modules | grep -v ".git/" | grep -v "/backups/" | head -20)
    else
        CRED_FILES=$($prefix "grep -rln 'sk_\|sk-ant-\|Bearer \|api_key=\|apikey=\|API_KEY=\|password=' /root --include='*.json' --include='*.yaml' --include='*.toml' --include='*.conf' --include='*.cfg' --include='*.ini' 2>/dev/null | grep -v node_modules | grep -v '.git/' | grep -v '/backups/' | head -20")
    fi
    if [ -n "$CRED_FILES" ]; then
        COUNT=$(echo "$CRED_FILES" | wc -l)
        echo "  WARN: $COUNT file(s) with plaintext credentials:" >> "$LOG"
        echo "$CRED_FILES" | while read f; do echo "    $f" >> "$LOG"; done
        FINDINGS="$FINDINGS\n  $COUNT config file(s) with plaintext credentials"
    else
        echo "  OK: No stray plaintext credentials in config files" >> "$LOG"
    fi

    # 2. Shell history secrets
    if [ -z "$prefix" ]; then
        HIST_SECRETS=$(grep -n "password\|passwd\|secret\|token\|Bearer\|sk-ant-\|sk_live\|api_key" ~/.bash_history ~/.zsh_history 2>/dev/null | grep -v "grep\|history" | wc -l)
    else
        HIST_SECRETS=$($prefix "grep -n 'password\|passwd\|secret\|token\|Bearer\|sk-ant-\|sk_live\|api_key' ~/.bash_history ~/.zsh_history 2>/dev/null | grep -v 'grep\|history' | wc -l")
    fi
    if [ "${HIST_SECRETS:-0}" -gt 0 ] 2>/dev/null; then
        echo "  WARN: $HIST_SECRETS line(s) with potential secrets in shell history" >> "$LOG"
        FINDINGS="$FINDINGS\n  $HIST_SECRETS credential(s) in shell history"
    else
        echo "  OK: Shell history clean" >> "$LOG"
    fi

    # 3. Scattered .env / .pem / key files
    if [ -z "$prefix" ]; then
        SCATTERED=$(find /root -maxdepth 5 \( -name "*.pem" -o -name "*.key" -o -name "id_rsa" -o -name ".env" \) 2>/dev/null | grep -v node_modules | grep -v ".git/" | grep -v "/backups/" | sort)
    else
        SCATTERED=$($prefix "find /root -maxdepth 5 \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa' -o -name '.env' \) 2>/dev/null | grep -v node_modules | grep -v '.git/' | grep -v '/backups/' | sort")
    fi
    if [ -n "$SCATTERED" ]; then
        COUNT=$(echo "$SCATTERED" | wc -l)
        echo "  INFO: $COUNT credential/key file(s) found:" >> "$LOG"
        echo "$SCATTERED" | while read f; do echo "    $f" >> "$LOG"; done

        # Check for stale ones (not modified in 30+ days)
        if [ -z "$prefix" ]; then
            STALE=$(find /root -maxdepth 5 \( -name "*.pem" -o -name "*.key" -o -name ".env" \) -mtime +30 2>/dev/null | grep -v node_modules | grep -v ".git/" | grep -v "/backups/" | wc -l)
        else
            STALE=$($prefix "find /root -maxdepth 5 \( -name '*.pem' -o -name '*.key' -o -name '.env' \) -mtime +30 2>/dev/null | grep -v node_modules | grep -v '.git/' | grep -v '/backups/' | wc -l")
        fi
        if [ "${STALE:-0}" -gt 0 ] 2>/dev/null; then
            echo "  WARN: $STALE file(s) not modified in 30+ days — may contain stale credentials" >> "$LOG"
            FINDINGS="$FINDINGS\n  $STALE stale credential file(s) (30+ days untouched)"
        fi
    else
        echo "  OK: No scattered credential files" >> "$LOG"
    fi

    # 4. World-readable credential files
    if [ -z "$prefix" ]; then
        WORLD_READ=$(find /root -maxdepth 5 -name ".env" -perm -o=r 2>/dev/null | grep -v "/backups/" | head -10)
    else
        WORLD_READ=$($prefix "find /root -maxdepth 5 -name '.env' -perm -o=r 2>/dev/null | grep -v '/backups/' | head -10")
    fi
    if [ -n "$WORLD_READ" ]; then
        COUNT=$(echo "$WORLD_READ" | wc -l)
        echo "  WARN: $COUNT .env file(s) are world-readable!" >> "$LOG"
        echo "$WORLD_READ" | while read f; do echo "    $f" >> "$LOG"; done
        FINDINGS="$FINDINGS\n  $COUNT world-readable .env file(s)"
    fi

    if [ -n "$FINDINGS" ]; then
        echo "  => Credential hygiene issues on $name" >> "$LOG"
        ESCALATE="$ESCALATE\n[$name] CREDENTIAL HYGIENE:$FINDINGS"
        # Remediation guidance
        echo -e "\n  REMEDIATION STEPS:" >> "$LOG"
        echo "  1. ROTATE: Generate new keys/tokens for any exposed credentials" >> "$LOG"
        echo "  2. AUDIT: Check access logs for unauthorized usage (Moltbook: /settings/security, API provider dashboards)" >> "$LOG"
        echo "  3. LATERAL: Check if compromised credentials were used to access other services or spawn sessions" >> "$LOG"
        echo "  4. INVALIDATE: Revoke any sessions/tokens spawned using the leaked credentials" >> "$LOG"
        echo "  5. CLEAN: Remove credentials from shell history (history -c or edit ~/.bash_history)" >> "$LOG"
        echo "  6. HARDEN: Restrict .env file permissions (chmod 600), add git-secrets pre-commit hooks" >> "$LOG"
        echo "  7. VERIFY: Re-run this audit to confirm remediation is complete" >> "$LOG"
    else
        echo "  All credential checks passed." >> "$LOG"
    fi
}

credential_audit "HIVE" ""
credential_audit "EVE" "ssh $EVE_IP"

# ============================================================
# PRE-COMMIT HOOK AUDIT — check git repos for credential guards
# ============================================================
echo -e "\n--- Pre-commit Hook Audit ---" >> "$LOG"
REPOS_WITHOUT_HOOKS=0
for repo in $(find /root -maxdepth 4 -name ".git" -type d 2>/dev/null | grep -v node_modules | grep -v backups); do
    REPO_DIR=$(dirname "$repo")
    if [ ! -f "$repo/hooks/pre-commit" ] || ! grep -q "git.secrets" "$repo/hooks/pre-commit" 2>/dev/null; then
        echo "  WARN: No git-secrets hook in $REPO_DIR" >> "$LOG"
        ((REPOS_WITHOUT_HOOKS++))
    fi
done
if [ "$REPOS_WITHOUT_HOOKS" -gt 0 ]; then
    echo "  $REPOS_WITHOUT_HOOKS repo(s) without git-secrets pre-commit hooks" >> "$LOG"
    echo "  Fix: cd <repo> && git secrets --install" >> "$LOG"
else
    echo "  OK: All repos have git-secrets hooks" >> "$LOG"
fi

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
