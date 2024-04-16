#!/bin/bash

# Replace these paths with the actual paths to your files
EXECUTABLE_PATH="./cdlog"
CONFIG_FILE_PATH="./cdlog.conf"
SERVICE_UNIT_FILE_PATH="./cdlog.service"

#recreating the directory
sudo rm -rf /etc/cdlog
sudo mkdir /etc/cdlog

# premissions
sudo chmod +x $EXECUTABLE_PATH

# Copy executable to /usr/local/bin
sudo cp $EXECUTABLE_PATH /usr/local/bin/cdlog
sudo cp $EXECUTABLE_PATH /etc/cdlog/cdlog

# Copy configuration file to /etc/cdlog
sudo cp $CONFIG_FILE_PATH /etc/cdlog/cdlog.conf

# creating user cdlog and giving minimum premissions
sudo useradd cdlog
sudo chmod o+r /var/log

# Copy service unit file to /etc/systemd/system
sudo cp $SERVICE_UNIT_FILE_PATH /etc/systemd/system/cdlog.service

# Reload systemd to pick up new service unit file
sudo systemctl daemon-reload

# Enable and start the service
sudo systemctl enable cdlog.service
sudo systemctl start cdlog.service

echo "Service installed successfully."
