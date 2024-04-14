#!/bin/bash

# Replace these paths with the actual paths to your files
EXECUTABLE_PATH="/home/ofek/dist/cdlog"
CONFIG_FILE_PATH="/home/ofek/dist/cdlog.conf"
SERVICE_UNIT_FILE_PATH="/home/ofek/cdlog.service"

# Copy executable to /usr/local/bin
sudo cp $EXECUTABLE_PATH /usr/local/bin/cdlog

#recreating the directory
sudo rm -rf /etc/cdlog
sudo mkdir /etc/cdlog

# Copy configuration file to /etc/cdlog
sudo cp $CONFIG_FILE_PATH /etc/cdlog/cdlog.conf

# Copy service unit file to /etc/systemd/system
sudo cp $SERVICE_UNIT_FILE_PATH /etc/systemd/system/cdlog.service

# Reload systemd to pick up new service unit file
sudo systemctl daemon-reload

# Enable and start the service
sudo systemctl enable cdlog.service
sudo systemctl start cdlog.service

echo "Service installed successfully."
