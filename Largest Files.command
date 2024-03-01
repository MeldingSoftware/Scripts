#!/bin/bash

# Define the path for the output text file
output_file="$HOME/Desktop/Largest_Files.txt"

# Prompt to proceed
read -p "This script will find and list the top 10 largest files on your hard drive. Do you want to continue? (y/n): " response

if [[ $response == [Yy] ]]; then
    # Find and display the top 10 largest files
    echo "Finding the top 10 largest files..."
    echo "Top 10 Largest Files:" > "$output_file"
    sudo du -ah / | sort -rh | head -n 11 >> "$output_file"

    echo "Operation completed. Results saved to $output_file"
else
    echo "Operation canceled."
fi
