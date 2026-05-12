#!/usr/bin/env bash

# If someone runs this with sh/dash, re-run with bash automatically.
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi


# ================================================================
# macOS Bloatware Remover – SAFE(ish) version (user-removable apps only)
# WARNING: Only removes apps that are typically allowed to be deleted
# Does NOT touch protected /System/Applications apps (SIP)
# ================================================================

echo ""
echo "macOS Application Debloat Tool"
echo "Only targets commonly removable Apple apps"
echo "Protected system apps (Chess, Stocks, News, Podcasts, etc.) CANNOT be removed without disabling SIP"
echo "Run with sudo? → NO — we use normal user permissions where possible"
echo ""

# List of apps to attempt to remove (full .app names as they appear in /Applications)
apps=(
    "iMovie.app"
    "GarageBand.app"
    "Keynote.app"
    "Numbers.app"
    "Pages.app"
    "Clips.app"               # Sometimes preinstalled
    "Xcode.app"               # If somehow present without you wanting it
    # Add your own here if you have other third-party crap in /Applications
)

removed_count=0
not_found_count=0
protected_count=0

for app in "${apps[@]}"; do
    path="/Applications/$app"

    if [ -d "$path" ]; then
        echo "→ Found: $app"

        # Try to quit if running
        appname="${app%.app}"
        osascript -e "tell application \"$appname\" to quit" 2>/dev/null

        # Actually remove
        if rm -rf "$path" 2>/dev/null; then
            echo "  Deleted: $app"
            ((removed_count++))
        else
            echo "  ERROR deleting $app (probably in use or permissions)"
        fi
    elif [ -d "/System/Applications/$app" ]; then
        echo "→ Protected (SIP): /System/Applications/$app — skipping"
        ((protected_count++))
    else
        echo "→ Not present: $app"
        ((not_found_count++))
    fi
done

echo ""
echo "Summary:"
echo "  Removed     : $removed_count"
echo "  Not found   : $not_found_count"
echo "  Protected   : $protected_count"
echo ""
echo "Done. Some very common 'bloat' apps cannot be removed without disabling SIP."
echo "If you really want to go further → research 'disable SIP' (not recommended)."
echo ""

read -p "Press Enter to close..."
