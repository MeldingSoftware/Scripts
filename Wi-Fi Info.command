#!/bin/zsh

# Define the path for the output text file (in the script's directory)
output_file="$(dirname "$0")/Wi-Fi_Info.txt"

# Function to retrieve Wi-Fi SSID and password
get_wifi_info() {
    ssid=$(networksetup -getairportnetwork en0 | awk -F ": " '{print $2}')
    password=$(security find-generic-password -ga "$ssid" 2>&1 | grep password | cut -d \" -f2)
    echo "Wi-Fi SSID: $ssid"
    echo "Wi-Fi Password: $password"
    echo "Wi-Fi SSID: $ssid" > "$output_file"
    echo "Wi-Fi Password: $password" >> "$output_file"
    echo "Wi-Fi information saved to $output_file"
}

# Main script
get_wifi_info
