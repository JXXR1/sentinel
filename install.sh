#!/bin/bash
# SENTINEL v2 Installation Script
# License: MIT

set -e

echo "=== SENTINEL v2 Installation ==="
echo ""

# Check dependencies
echo "Checking dependencies..."
MISSING=""
for dep in ss jq; do
  if ! command -v $dep &> /dev/null; then
    echo "  Missing: $dep"
    MISSING="$MISSING $dep"
  fi
done

# inotifywait is optional (needed for sentinel-file-watch.sh)
if ! command -v inotifywait &> /dev/null; then
  echo "  Optional missing: inotifywait (needed for sentinel-file-watch.sh)"
  echo "    Install: apt install -y inotify-tools"
fi

if [ -n "$MISSING" ]; then
  echo ""
  echo "Install missing required dependencies:"
  echo "  apt install -y iproute2 jq"
  exit 1
fi
echo "All required dependencies found."
echo ""

# Copy scripts to /usr/local/bin
echo "Installing scripts to /usr/local/bin..."
for script in sentinel-watchdog.sh sentinel-check-v2.sh sentinel-file-watch.sh sentinel-daily.sh sentinel-intel.sh; do
  if [ -f "$script" ]; then
    cp "$script" /usr/local/bin/
    chmod +x "/usr/local/bin/$script"
    echo "  ✅ $script"
  else
    echo "  ⚠️  $script not found — skipping"
  fi
done
echo ""

# Create log and escalation dirs
mkdir -p /var/log/sentinel /root/escalations /root/escalations/handled
echo "Directories created: /var/log/sentinel, /root/escalations"
echo ""

# Cron setup
echo "Add cron jobs? [y/N]"
read -r CRON_CONFIRM
if [ "$CRON_CONFIRM" = "y" ] || [ "$CRON_CONFIRM" = "Y" ]; then
  (crontab -l 2>/dev/null
  echo "# SENTINEL v2"
  echo "*/2 * * * * /usr/local/bin/sentinel-watchdog.sh >> /var/log/sentinel/watchdog.log 2>&1"
  echo "30 */6 * * * /usr/local/bin/sentinel-check-v2.sh >> /var/log/sentinel/audit.log 2>&1"
  echo "15 */6 * * * /usr/local/bin/sentinel-intel.sh >> /var/log/sentinel/intel.log 2>&1"
  echo "0 3 * * * /usr/local/bin/sentinel-daily.sh >> /var/log/sentinel/daily.log 2>&1"
  ) | crontab -
  echo "Cron jobs added."
else
  echo "Skipped. Add manually:"
  echo "  */2 * * * * /usr/local/bin/sentinel-watchdog.sh"
  echo "  30 */6 * * * /usr/local/bin/sentinel-check-v2.sh"
  echo "  15 */6 * * * /usr/local/bin/sentinel-intel.sh"
  echo "  0 3 * * * /usr/local/bin/sentinel-daily.sh"
fi
echo ""

echo "=== Done ==="
echo ""
echo "Next steps:"
echo "  1. Edit /usr/local/bin/sentinel-check-v2.sh — set ALLOWED_PUBLIC_PORTS for your stack"
echo "  2. Edit /usr/local/bin/sentinel-watchdog.sh — set TELEGRAM_BOT_TOKEN + CHAT_ID for alerts"
echo "  3. CRITICAL-ACTIVE.json writes to /root/escalations/ — wire up your alerting agent"
echo ""
echo "Related: Skill Scanner v3 — pre-install skill auditing (28 modules)"
echo "  https://github.com/JXXR1/skill-scanner-v2"
