#!/bin/zsh

# Define the output file on the desktop
output_file="$HOME/Desktop/Maintenance.txt"

echo "Starting macOS system checkup and maintenance tasks..."

# Check macOS file system for errors
echo "Checking file system for errors..." >> "$output_file"
diskutil verifyVolume / >> "$output_file" 2>&1
echo "" >> "$output_file"

# Verify and repair disk
echo "Verifying and repairing disk..." >> "$output_file"
diskutil verifyDisk /dev/disk0 >> "$output_file" 2>&1
sudo diskutil repairDisk /dev/disk0 >> "$output_file" 2>&1
echo "" >> "$output_file"

# Check startup items
echo "Checking startup items..." >> "$output_file"
sudo launchctl list >> "$output_file" 2>&1
echo "" >> "$output_file"

# Check launch agents and daemons
echo "Checking launch agents and daemons..." >> "$output_file"
sudo launchctl list | grep -v apple >> "$output_file" 2>&1
echo "" >> "$output_file"

# Check for system updates
echo "Checking for system updates..." >> "$output_file"
softwareupdate -l >> "$output_file" 2>&1
echo "" >> "$output_file"

# WORKING ON THIS!
# Install available system updates
# echo "Installing available system updates..." >> "$output_file"
# sudo softwareupdate -ia >> "$output_file" 2>&1
# echo "" >> "$output_file"

# Restart the computer
echo "Restarting the computer..." >> "$output_file"
sudo shutdown -r now
