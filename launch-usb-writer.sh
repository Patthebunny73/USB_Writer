#!/bin/bash
# Kognit USB Writer Launcher
# This script launches the USB Writer with elevated privileges

# Allow X display access for root
xhost +local: 2>/dev/null

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Path to the application
APP_PATH="$SCRIPT_DIR/src-tauri/target/release/kognit-usb-writer"

# Check if the app exists
if [ ! -f "$APP_PATH" ]; then
    echo "Error: USB Writer not found at $APP_PATH"
    echo "Please build the application first with: cd src-tauri && cargo build --release"
    exit 1
fi

# Launch with sudo, preserving the display
echo "Launching Kognit USB Writer..."
sudo DISPLAY=:0 "$APP_PATH" "$@"
