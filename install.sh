#!/bin/bash
# SENTINEL v2 Installation Script

# License: MIT

set -e

echo "=== SENTINEL v2 Installation ==="
echo ""

# Check dependencies
echo "Checking dependencies..."
for dep in ss jq ssh; do
  if ! command -v $dep &> /dev/null; then
    echo "Missing: $dep"
    MISSING="$MISSING $dep"
  fi
done

if [ -n "$MISSING" ]; then
  echo ""
  echo "Install missing dependencies:"
  echo "  apt install -y iproute2 jq openssh-client"
  exit 1
fi
echo "All dependencies found."
echo ""

# Determine install location
INSTALL_DIR="${1:-/opt/sentinel}"
echo "Installing to: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/escalations"
mkdir -p "$INSTALL_DIR/escalations/handled"

# Copy script
cp sentinel-check-v2.sh "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/sentinel-check-v2.sh"
echo "Script installed."
echo ""

# Cron setup
echo "Add to crontab? (runs every 6 hours) [y/N]"
read -r CRON_CONFIRM
if [ "$CRON_CONFIRM" = "y" ] || [ "$CRON_CONFIRM" = "Y" ]; then
  CRON_LINE="0 */6 * * * $INSTALL_DIR/sentinel-check-v2.sh >> $INSTALL_DIR/logs/sentinel-cron.log 2>&1"
  (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
  echo "Cron job added."
else
  echo "Skipped. Add manually:"
  echo "  0 */6 * * * $INSTALL_DIR/sentinel-check-v2.sh >> $INSTALL_DIR/logs/sentinel-cron.log 2>&1"
fi

echo ""
echo "=== Done ==="
echo "Edit $INSTALL_DIR/sentinel-check-v2.sh to configure:"
echo "  - ALLOWED_PUBLIC_PORTS (ports deliberately exposed)"
echo "  - SENSITIVE_SERVICES (add any extra services for your stack)"
echo "  - Add remote servers via check_server calls (examples in script)"