#!/bin/bash

# Stop the print spooler
sudo launchctl stop org.cups.cupsd

# Wait for a few seconds
sleep 5

# Start the print spooler
sudo launchctl start org.cups.cupsd

echo "Print spooler has been restarted"
