#!/bin/bash
# Push blocklist to Juniper router via SSH
#
# Usage: ./push_to_router.sh router.example.com
#
# Prerequisites:
# - SSH key authentication to router
# - User with configure permissions
#
# Cron example (update every hour):
# 0 * * * * /opt/sip-honeypot/scripts/push_to_router.sh router.example.com

set -e

ROUTER="${1:-router.example.com}"
SSH_USER="${SSH_USER:-admin}"
SSH_KEY="${SSH_KEY:-/root/.ssh/juniper_key}"
TEMP_FILE="/tmp/honeypot-blocklist-$$.conf"
SCRIPT_DIR="$(dirname "$0")"

echo "Exporting blocklist..."
python3 "$SCRIPT_DIR/export_to_juniper.py" --format prefix-list --output "$TEMP_FILE"

if [ ! -s "$TEMP_FILE" ]; then
    echo "Error: Export failed or empty"
    rm -f "$TEMP_FILE"
    exit 1
fi

IP_COUNT=$(grep -c "prefix-list" "$TEMP_FILE" || true)
echo "Pushing $IP_COUNT IPs to $ROUTER..."

# Push to router
ssh -i "$SSH_KEY" "$SSH_USER@$ROUTER" << EOF
configure
# Delete existing list
delete policy-options prefix-list HONEYPOT-BLOCKLIST

# Load new configuration
$(cat "$TEMP_FILE")

# Commit
commit comment "Honeypot blocklist update: $IP_COUNT IPs"
exit
EOF

rm -f "$TEMP_FILE"
echo "Done. $IP_COUNT IPs pushed to $ROUTER"
