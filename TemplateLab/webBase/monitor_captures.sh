#!/bin/bash
# Credential Monitor Script
# Run this on the web1 container to monitor captured credentials in real-time

LOG_FILE="/tmp/captured_credentials.log"

echo "=========================================="
echo "  CREDENTIAL CAPTURE MONITOR"
echo "=========================================="
echo "Monitoring: $LOG_FILE"
echo "Press Ctrl+C to stop"
echo "=========================================="
echo

if [ ! -f "$LOG_FILE" ]; then
    echo "[*] No captures yet. Waiting for credentials..."
    touch "$LOG_FILE"
fi

tail -f "$LOG_FILE"
