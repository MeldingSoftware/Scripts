#!/bin/bash
# Largest Files (current user only) with Full Disk Access (FDA) check + prompt
# Output: ~/Desktop/Largest_Files.txt

set -u

output_file="$HOME/Desktop/Largest_Files.txt"
scan_path="$HOME"

# --- Helper: attempt to detect whether this terminal app likely has Full Disk Access ---
# There is no official, reliable CLI/API to read the FDA toggle directly.
# Instead, we probe access to TCC-protected locations in your home folder.
has_full_disk_access() {
  local paths=(
    "$HOME/Library/Mail"
    "$HOME/Library/Messages"
    "$HOME/Library/Safari"
    "$HOME/Library/Application Support/com.apple.TCC/TCC.db"
  )

  for p in "${paths[@]}"; do
    # If the path doesn't exist on this Mac, try the next probe.
    [[ -e "$p" ]] || continue

    # Try to list/read it; capture stderr for permission messaging.
    local err
    err=$( (ls -la "$p" >/dev/null) 2>&1 )
    local rc=$?

    if [[ $rc -eq 0 ]]; then
      return 0  # probe succeeded, FDA is likely enabled
    fi

    # If we got the classic TCC denial, treat as "no FDA"
    if echo "$err" | grep -qi "Operation not permitted"; then
      return 1
    fi
  done

  # If none of the probes exist, we can't conclusively detect.
  # Return "unknown" by exiting with code 2.
  return 2
}

echo "Largest Files (current user only)"
echo "This script will list the top 10 largest items in: $scan_path"
echo

read -p "Continue? (y/n): " response
if [[ ! $response == [Yy] ]]; then
  echo "Operation canceled."
  exit 0
fi

# --- FDA check ---
has_full_disk_access
fda_status=$?

if [[ $fda_status -eq 1 ]]; then
  echo
  echo "Full Disk Access does NOT appear to be enabled for this terminal app."
  echo "Without it, macOS may block access to some folders and your results may be incomplete."
  echo
  echo "Opening: System Settings -> Privacy & Security -> Full Disk Access"
  open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
  echo
  echo "Please:"
  echo "  1) Enable Full Disk Access for the terminal app you're using (Terminal/iTerm/etc.)"
  echo "  2) QUIT and RE-OPEN the terminal app"
  echo "  3) Re-run this script"
  echo
  read -p "Press ENTER to close this script now: "
  exit 0

elif [[ $fda_status -eq 2 ]]; then
  echo
  echo "Note: I couldn't conclusively detect Full Disk Access on this Mac (probe paths not found)."
  echo "If you see 'Operation not permitted' or missing results, enable Full Disk Access:"
  echo "System Settings -> Privacy & Security -> Full Disk Access"
  echo
fi

echo
echo "Finding the top 10 largest items in $scan_path..."
echo "Top 10 Largest Items in $scan_path:" > "$output_file"

# Scan only the current user's home folder.
# Suppress permission noise; if FDA isn't granted you'll see fewer results.
du -ah "$scan_path" 2>/dev/null | sort -rh | head -n 10 >> "$output_file"

echo
echo "Done. Results saved to: $output_file"
