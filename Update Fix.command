#!/bin/bash

# Stop the software update service
sudo launchctl unload /System/Library/LaunchDaemons/com.apple.softwareupdate.plist

# Remove the downloaded update files
sudo rm -rf /Library/Updates/*

# Restart the software update service
sudo launchctl load /System/Library/LaunchDaemons/com.apple.softwareupdate.plist

# Check for updates
softwareupdate -l

# Install available updates
# sudo softwareupdate -i -a