#!/bin/bash

# Define the output file on the Desktop
output_file="$HOME/Desktop/System_Info.txt"

# Gather system information and save it to the output file
echo "Gathering system information..."
echo "Date: $(date)" > "$output_file"
echo "" >> "$output_file"
echo "### Hostname ###" >> "$output_file"
hostname >> "$output_file"
echo "" >> "$output_file"
echo "### Operating System ###" >> "$output_file"
sw_vers >> "$output_file"
echo "" >> "$output_file"
echo "### Processor ###" >> "$output_file"
sysctl -n machdep.cpu.brand_string >> "$output_file"
echo "" >> "$output_file"
echo "### Memory ###" >> "$output_file"
sysctl -n hw.memsize | awk '{print "Total Memory: " $0/1024/1024 " MB"}' >> "$output_file"
echo "" >> "$output_file"
echo "### Disk Information ###" >> "$output_file"
diskutil list >> "$output_file"
echo "" >> "$output_file"
echo "### Network Interfaces ###" >> "$output_file"
ifconfig -a >> "$output_file"
echo "" >> "$output_file"
echo "System information gathered successfully. Results saved to $output_file"
