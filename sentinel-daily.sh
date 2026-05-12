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
# SKILL-SCANNER AUDIT — supply-chain integrity of installed AI-agent skills
# v1.7: runs skill-scan-v2.sh against every installed skill directory.
# MALICIOUS exit (≥10 issues) escalates with skill name + path.
# Per `feedback_third_party_provenance.md` — vet third-party skills.
# ============================================================
SKILL_SCANNER_BIN="${SENTINEL_SKILL_SCANNER_BIN:-/root/skill-scanner/skill-scan-v2.sh}"
SKILL_ROOT_GLOBS="${SENTINEL_SKILL_ROOTS:-/root/.openclaw/agents/*/skills /root/.openclaw/skills}"

echo -e "\n--- Skill-Scanner Supply-Chain Audit ---" >> "$LOG"
if [ ! -x "$SKILL_SCANNER_BIN" ]; then
    echo "  SKIP: skill-scanner not found at $SKILL_SCANNER_BIN (set SENTINEL_SKILL_SCANNER_BIN to override)" >> "$LOG"
else
    SKILLS_SCANNED=0
    SKILLS_MALICIOUS=0
    SKILLS_WARN=0
    # Disable pathname-glob inside the loop body but not for the for-list itself
    for root_glob in $SKILL_ROOT_GLOBS; do
        for root in $root_glob; do
            [ -d "$root" ] || continue
            # Find skill directories — defined as a dir containing SKILL.md or manifest.json
            for skill_dir in "$root"/*/; do
                [ -d "$skill_dir" ] || continue
                if [ -f "${skill_dir}SKILL.md" ] || [ -f "${skill_dir}manifest.json" ]; then
                    SKILLS_SCANNED=$((SKILLS_SCANNED+1))
                    skill_name=$(basename "$skill_dir")
                    scan_out=$("$SKILL_SCANNER_BIN" --no-llm --yes "$skill_dir" 2>&1 | tail -3)
                    rc=$?
                    if [ "$rc" -ge 10 ]; then
                        echo "  🚫 MALICIOUS: $skill_name ($skill_dir) — issues=$rc" >> "$LOG"
                        echo "$scan_out" | sed 's/^/      /' >> "$LOG"
                        SKILLS_MALICIOUS=$((SKILLS_MALICIOUS+1))
                        ESCALATE="${ESCALATE}🚫 Skill-scanner: MALICIOUS finding on $skill_name at $skill_dir (issues=$rc)\n"
                    elif [ "$rc" -gt 0 ]; then
                        echo "  ⚠️  WARN: $skill_name — issues=$rc" >> "$LOG"
                        SKILLS_WARN=$((SKILLS_WARN+1))
                    else
                        echo "  OK: $skill_name — clean" >> "$LOG"
                    fi
                fi
            done
        done
    done
    if [ "$SKILLS_SCANNED" -eq 0 ]; then
        echo "  INFO: No installed skill directories found under expected roots" >> "$LOG"
    else
        echo "  Summary: $SKILLS_SCANNED scanned · $SKILLS_MALICIOUS malicious · $SKILLS_WARN warn" >> "$LOG"
    fi
fi

# ============================================================
# LLM-VENDOR OUTBOUND AUDIT — Squid-log based
# v1.7: scans Squid access log for outbound calls to AI/LLM vendor
# endpoints (OpenAI, Anthropic, HuggingFace, Telnyx, Soniox, Replicate,
# Together, Mistral, DeepSeek, xAI, Google Gemini, Cohere). Cross-
# references hits against the workspace egress-known-domains allowlist.
# Alerts on hits to vendors not on the allowlist — potential
# credential-theft, data-exfil, or unauthorized model-vendor access.
# ============================================================
LVO_ALLOWLIST="${SENTINEL_EGRESS_ALLOWLIST:-/root/.openclaw/workspace/.egress-known-domains.json}"
LVO_SQUID_LOG="${SENTINEL_SQUID_LOG:-/var/log/squid/access.log}"
LVO_VENDORS="api\.openai\.com|api\.anthropic\.com|huggingface\.co|hf-mirror\.com|api\.telnyx\.com|api\.soniox\.com|replicate\.com|replicate\.delivery|api\.cohere\.ai|api\.together\.xyz|api\.mistral\.ai|api\.deepseek\.com|api\.x\.ai|generativelanguage\.googleapis\.com"

echo -e "\n--- LLM-Vendor Outbound Audit ---" >> "$LOG"

if [ ! -f "$LVO_SQUID_LOG" ]; then
    echo "  SKIP: Squid access log not found at $LVO_SQUID_LOG" >> "$LOG"
elif [ ! -f "$LVO_ALLOWLIST" ]; then
    echo "  SKIP: egress allowlist not found at $LVO_ALLOWLIST" >> "$LOG"
elif ! command -v jq >/dev/null 2>&1; then
    echo "  SKIP: jq required for allowlist lookup, not installed" >> "$LOG"
else
    SINCE_TS=$(date -u -d '24 hours ago' +%s)
    # Extract unique vendor hostnames hit in last 24h
    LVO_HITS=$(awk -v since="$SINCE_TS" -v pat="($LVO_VENDORS)" '
        $1 >= since && $0 ~ pat {
            # Squid line: ts elapsed client TCP_/result size METHOD url - HIER ...
            # For CONNECT: url is host:port. For others: full URL.
            u = $7
            sub(/^.*:\/\//, "", u)   # strip scheme://
            sub(/\/.*$/, "", u)       # strip path
            sub(/:[0-9]+$/, "", u)    # strip :port
            if (u ~ pat) print u
        }' "$LVO_SQUID_LOG" 2>/dev/null | sort -u)

    if [ -z "$LVO_HITS" ]; then
        echo "  OK: No LLM-vendor outbound traffic in last 24h" >> "$LOG"
    else
        LVO_UNAUTH=0
        LVO_AUTH=0
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            if jq -e --arg h "$host" 'has($h)' "$LVO_ALLOWLIST" >/dev/null 2>&1; then
                LVO_AUTH=$((LVO_AUTH+1))
            else
                echo "  ⚠️  NON-ALLOWLISTED vendor hit: $host" >> "$LOG"
                LVO_UNAUTH=$((LVO_UNAUTH+1))
            fi
        done <<< "$LVO_HITS"
        echo "  Summary: $LVO_AUTH allowlisted · $LVO_UNAUTH non-allowlisted vendor host(s) in 24h" >> "$LOG"
        if [ "$LVO_UNAUTH" -gt 0 ]; then
            ESCALATE="${ESCALATE}⚠️  LLM-vendor outbound: $LVO_UNAUTH non-allowlisted endpoint(s) in last 24h — see daily log\n"
        fi
    fi
fi

# ============================================================
# BACKUP INTEGRITY VERIFICATION
# v1.7: per feedback_rsync_silent_success.md — silent success ≠ correct.
# Verifies each layer of the EVE backup chain produced files in the
# expected size band within the expected window. Catches silent failures
# of fast-incremental, daily, or Hetzner Box layers.
# ============================================================
BIV_FAST_DIR="${SENTINEL_BACKUP_FAST_DIR:-/root/backups/fast-incremental}"
BIV_DAILY_DIR="${SENTINEL_BACKUP_DAILY_DIR:-/root/backups/daily}"
BIV_BOX_LOG="${SENTINEL_BACKUP_BOX_LOG:-/var/log/hetzner-box-sync.log}"

echo -e "\n--- Backup Integrity ---" >> "$LOG"

# Layer 1: fast-incremental (expected: file written within last 30 min)
if [ -d "$BIV_FAST_DIR" ]; then
    NEWEST_FAST=$(find "$BIV_FAST_DIR" -type f -mmin -30 2>/dev/null | head -1)
    if [ -n "$NEWEST_FAST" ]; then
        SIZE=$(stat -c %s "$NEWEST_FAST" 2>/dev/null || echo 0)
        echo "  OK: fast-incremental — newest file <30min old, ${SIZE}B" >> "$LOG"
    else
        echo "  ⚠️  fast-incremental — no files modified in last 30 min" >> "$LOG"
        ESCALATE="${ESCALATE}⚠️  Backup chain: fast-incremental appears stale (>30 min since last write)\n"
    fi
else
    echo "  SKIP: fast-incremental dir $BIV_FAST_DIR not present" >> "$LOG"
fi

# Layer 2: daily (expected: file written within last 26 hours)
if [ -d "$BIV_DAILY_DIR" ]; then
    NEWEST_DAILY=$(find "$BIV_DAILY_DIR" -type f -mmin -1560 2>/dev/null | head -1)
    if [ -n "$NEWEST_DAILY" ]; then
        SIZE=$(stat -c %s "$NEWEST_DAILY" 2>/dev/null || echo 0)
        echo "  OK: daily — newest file <26h old, ${SIZE}B" >> "$LOG"
    else
        echo "  ⚠️  daily backup appears stale (>26h since last write)" >> "$LOG"
        ESCALATE="${ESCALATE}⚠️  Backup chain: daily layer appears stale (>26h)\n"
    fi
else
    echo "  SKIP: daily dir $BIV_DAILY_DIR not present" >> "$LOG"
fi

# Layer 3: Hetzner Box sync log
if [ -f "$BIV_BOX_LOG" ]; then
    BOX_AGE_HOURS=$(( ( $(date +%s) - $(stat -c %Y "$BIV_BOX_LOG") ) / 3600 ))
    if [ "$BOX_AGE_HOURS" -gt 26 ]; then
        echo "  ⚠️  Hetzner Box sync log not updated in ${BOX_AGE_HOURS}h" >> "$LOG"
        ESCALATE="${ESCALATE}⚠️  Backup chain: Hetzner Box sync log stale (${BOX_AGE_HOURS}h)\n"
    else
        echo "  OK: Hetzner Box sync log updated ${BOX_AGE_HOURS}h ago" >> "$LOG"
    fi
else
    echo "  SKIP: Hetzner Box log $BIV_BOX_LOG not present" >> "$LOG"
fi

# ============================================================
# TAILSCALE POSTURE AUDIT
# v1.7: per feedback_tailscale_bound_services_systemd.md and
# feedback_no_public_binding.md — sensitive services must bind to
# tailscale0 / 127.0.0.1 only, never 0.0.0.0. Also tracks tailnet
# peer count drift (alert on unexpected peer changes).
# ============================================================
TSP_PEER_BASELINE="${SENTINEL_TS_PEER_BASELINE:-/root/hive/baseline/tailscale-peers.count}"

echo -e "\n--- Tailscale Posture ---" >> "$LOG"

if ! command -v tailscale >/dev/null 2>&1; then
    echo "  SKIP: tailscale not installed" >> "$LOG"
else
    TS_STATUS=$(tailscale status --json 2>/dev/null)
    if [ -z "$TS_STATUS" ]; then
        echo "  ⚠️  Tailscale not running or status unavailable" >> "$LOG"
        ESCALATE="${ESCALATE}⚠️  Tailscale: not running\n"
    else
        TS_PEER_COUNT=$(echo "$TS_STATUS" | jq '.Peer | length' 2>/dev/null || echo 0)
        echo "  Peer count: $TS_PEER_COUNT" >> "$LOG"
        mkdir -p "$(dirname "$TSP_PEER_BASELINE")" 2>/dev/null
        if [ ! -f "$TSP_PEER_BASELINE" ]; then
            echo "$TS_PEER_COUNT" > "$TSP_PEER_BASELINE"
            echo "  INFO: peer-count baseline written ($TS_PEER_COUNT)" >> "$LOG"
        else
            BASELINE_COUNT=$(cat "$TSP_PEER_BASELINE")
            if [ "$TS_PEER_COUNT" != "$BASELINE_COUNT" ]; then
                echo "  ⚠️  Peer count drift: was $BASELINE_COUNT, now $TS_PEER_COUNT" >> "$LOG"
                ESCALATE="${ESCALATE}⚠️  Tailscale peer count drift: $BASELINE_COUNT → $TS_PEER_COUNT (refresh baseline if expected)\n"
            else
                echo "  OK: peer count matches baseline ($BASELINE_COUNT)" >> "$LOG"
            fi
        fi

        # Audit 0.0.0.0 bindings — forbidden per locked rule, with allowlist
        # for UFW-protected ports (mirror of sentinel-check-v2.sh
        # ALLOWED_PUBLIC_PORTS — keep in sync; future: extract to shared
        # config). Format: "PORT:REASON".
        TSP_ALLOWED_PUBLIC_PORTS=(
            "1515:Wazuh-authd-UFW-Tailscale-only"
        )
        PUBLIC_BINDS=$(ss -tlnH 2>/dev/null | awk '$4 ~ /^0\.0\.0\.0:/ {print $4}' | sort -u)
        if [ -n "$PUBLIC_BINDS" ]; then
            VIOLATIONS=""
            ALLOWED_FOUND=""
            while IFS= read -r bind; do
                [ -z "$bind" ] && continue
                port="${bind##*:}"
                IS_ALLOWED=0
                for allow in "${TSP_ALLOWED_PUBLIC_PORTS[@]}"; do
                    allow_port="${allow%%:*}"
                    if [ "$port" = "$allow_port" ]; then
                        IS_ALLOWED=1
                        ALLOWED_FOUND="${ALLOWED_FOUND}      $bind (${allow#*:})\n"
                        break
                    fi
                done
                [ "$IS_ALLOWED" -eq 0 ] && VIOLATIONS="${VIOLATIONS}      $bind\n"
            done <<< "$PUBLIC_BINDS"
            [ -n "$ALLOWED_FOUND" ] && echo -e "  Allowlisted 0.0.0.0 bindings:\n$ALLOWED_FOUND" >> "$LOG"
            if [ -n "$VIOLATIONS" ]; then
                echo -e "  🚫 0.0.0.0 binding violations (not on allowlist):\n$VIOLATIONS" >> "$LOG"
                ESCALATE="${ESCALATE}🚫 0.0.0.0 binding(s) not on allowlist — violates feedback_no_public_binding.md\n"
            else
                echo "  OK: all 0.0.0.0 bindings are allowlisted" >> "$LOG"
            fi
        else
            echo "  OK: no 0.0.0.0 bindings" >> "$LOG"
        fi
    fi
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
