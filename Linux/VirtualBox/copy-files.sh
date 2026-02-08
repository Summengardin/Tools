#!/bin/bash
# Installation script for VirtualBox tools

set -e  # Exit on error

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Get the script's directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Installing VirtualBox tools..."

# Copy service file
echo "Installing use-vbox.service..."
cp "$SCRIPT_DIR/use-vbox.service" /etc/systemd/system/use-vbox.service
chmod 644 /etc/systemd/system/use-vbox.service

# Copy windows script
echo "Installing windows command..."
cp "$SCRIPT_DIR/windows" /usr/local/bin/windows
chmod 755 /usr/local/bin/windows

# Reload systemd and enable service
echo "Enabling use-vbox service..."
systemctl daemon-reload
systemctl enable use-vbox.service

echo "Installation complete!"
echo "Service will run on next boot. To start now: sudo systemctl start use-vbox.service"
