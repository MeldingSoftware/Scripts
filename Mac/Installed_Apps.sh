#!/bin/zsh

# Define the output file on the Desktop
output_file="$HOME/Desktop/Installed_Applications_List.txt"

# Retrieve a list of installed applications
installed_apps=$(ls /Applications)

# Append default applications to the list
default_apps=$(ls /System/Applications)
installed_apps="$installed_apps"$'\n'"$default_apps"

# Save the list to a text file
echo "Installed Applications:" > "$output_file"
echo "$installed_apps" >> "$output_file"

# Display message indicating where the list of installed applications is saved
echo "List of installed applications saved to $output_file"
