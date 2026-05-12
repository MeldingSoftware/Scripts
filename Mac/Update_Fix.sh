#!/bin/bash
set -u  # (no -e) we want to continue even if a delete fails, and show guidance

PLIST="/System/Library/LaunchDaemons/com.apple.softwareupdate.plist"
UPDATES_DIR="/Library/Updates"
FILES_TO_NUKE=(
  "/Library/Updates/index.plist"
  "/Library/Updates/ProductMetadata.plist"
)

echo "macOS Update Fix"
echo "Stopping the software update service (system domain)"
sudo -v

# Stop service / processes (ignore errors across macOS versions)
sudo launchctl bootout system "$PLIST" 2>/dev/null || true
sudo pkill -x softwareupdated 2>/dev/null || true
sudo pkill -x softwareupdate 2>/dev/null || true

echo "Removing downloaded update files"
sudo mkdir -p "$UPDATES_DIR"

# Show status before
echo "Before:"
ls -lOe "$UPDATES_DIR" 2>/dev/null || true

# Clear immutable flags on the directory and key plists
sudo chflags -R nouchg,noschg "$UPDATES_DIR" 2>/dev/null || true
for f in "${FILES_TO_NUKE[@]}"; do
  sudo chflags nouchg,noschg "$f" 2>/dev/null || true
done

# Remove everything we can; keep going even if some are protected
sudo rm -rf "$UPDATES_DIR"/* 2>/dev/null || true
for f in "${FILES_TO_NUKE[@]}"; do
  sudo rm -f "$f" 2>/dev/null || true
done

# Show status after
echo "After:"
ls -lOe "$UPDATES_DIR" 2>/dev/null || true

# If the two plists still exist, explain the usual cause and next steps.
still=0
for f in "${FILES_TO_NUKE[@]}"; do
  if [[ -e "$f" ]]; then still=1; fi
done

if [[ "$still" -eq 1 ]]; then
  echo ""
  echo "⚠️  Some files are still present and macOS is returning 'Operation not permitted'."
  echo "This is usually because they have the *system immutable* flag (schg) or SIP/rootless protections."
  echo ""
  echo "Run this to confirm flags:"
  echo "  ls -lOe /Library/Updates"
  echo ""
  echo "If you see 'schg' on those files, you have two options:"
  echo "  A) Boot to macOS Recovery -> Terminal:"
  echo "     csrutil disable"
  echo "     reboot"
  echo "     (then run this script again, or: sudo chflags -R noschg,nouchg /Library/Updates && sudo rm -f /Library/Updates/index.plist /Library/Updates/ProductMetadata.plist)"
  echo "     Then re-enable SIP (recommended):"
  echo "     Boot to Recovery -> Terminal: csrutil enable"
  echo ""
  echo "  B) If you *don't* see schg, paste the output of:"
  echo "     ls -lOe /Library/Updates"
  echo "     xattr -lr /Library/Updates 2>/dev/null | head"
  echo "…and I’ll tailor the fix."
  echo ""
fi

echo "Restarting the software update service"
sudo launchctl bootstrap system "$PLIST" 2>/dev/null || true
sudo launchctl kickstart -k system/com.apple.softwareupdate 2>/dev/null || true

echo "Update Fix completed"
echo "Tip: Reboot once after running this if Software Update is still stuck."
