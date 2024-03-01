#!/bin/zsh

# Define the output file on the desktop
output_file="$HOME/Desktop/Repair_Tool.txt"

echo "Starting Repair Tool..."

# Check macOS file system for errors
echo "Checking file system for errors..." >> "$output_file"
diskutil verifyVolume / >> "$output_file" 2>&1
echo "" >> "$output_file"

# Verify and repair disk
echo "Verifying and repairing disk..." >> "$output_file"
diskutil verifyDisk /dev/disk0 >> "$output_file" 2>&1
sudo diskutil repairDisk /dev/disk0 >> "$output_file" 2>&1
echo "" >> "$output_file"

echo "Repair Tool completed. Results saved to $output_file"
