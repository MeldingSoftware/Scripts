#!/bin/bash
set -euo pipefail

# ---------------------------
# macOS Disk Scan & Repair
# ---------------------------

TITLE="macOS Disk Scan & Repair"
STAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
LOG="$HOME/Desktop/Disk_Repair_Report_${STAMP}.log"

log() {
  echo "$*" | tee -a "$LOG"
}

run() {
  log ""
  log ">>> $*"
  # shellcheck disable=SC2068
  "$@" 2>&1 | tee -a "$LOG"
}

need_sudo() {
  if [[ $EUID -ne 0 ]]; then
    log ""
    log "This script needs admin rights for repair operations."
    log "Prompting for password..."
    sudo -v
  fi
}

is_recovery() {
  # In Recovery, the boot volume is typically "Recovery" and root is on a RAM disk.
  local boot
  boot="$(/usr/sbin/diskutil info / 2>/dev/null | /usr/bin/awk -F': *' '/Boot Volume/ {print $2}')"
  [[ "${boot:-}" == "Recovery" ]] && return 0
  return 1
}

get_root_device() {
  /usr/sbin/diskutil info / 2>/dev/null | /usr/bin/awk -F': *' '/Device Identifier/ {print $2}'
}

get_root_volume_name() {
  /usr/sbin/diskutil info / 2>/dev/null | /usr/bin/awk -F': *' '/Volume Name/ {print $2}'
}

get_root_fs() {
  /usr/sbin/diskutil info / 2>/dev/null | /usr/bin/awk -F': *' '/Type \(Bundle\)/ {print $2}'
}

get_physical_disk_of_root() {
  /usr/sbin/diskutil info / 2>/dev/null | /usr/bin/awk -F': *' '/Part of Whole/ {print $2}'
}

get_apfs_container_of_root() {
  /usr/sbin/diskutil info / 2>/dev/null | /usr/bin/awk -F': *' '/APFS Container Reference/ {print $2}'
}

main() {
  : > "$LOG"
  log "=============================="
  log "$TITLE"
  log "Started: $(date)"
  log "Log: $LOG"
  log "=============================="

  local ROOT_DEV ROOT_NAME ROOT_FS ROOT_DISK APFS_CONTAINER
  ROOT_DEV="$(get_root_device)"
  ROOT_NAME="$(get_root_volume_name)"
  ROOT_FS="$(get_root_fs)"
  ROOT_DISK="$(get_physical_disk_of_root)"
  APFS_CONTAINER="$(get_apfs_container_of_root)"

  log ""
  log "Detected system volume:"
  log "  Root mount: /"
  log "  Device:     ${ROOT_DEV:-unknown}"
  log "  Name:       ${ROOT_NAME:-unknown}"
  log "  FS:         ${ROOT_FS:-unknown}"
  log "  Disk:       ${ROOT_DISK:-unknown}"
  log "  APFS Ctr:   ${APFS_CONTAINER:-unknown}"

  log ""
  log "---- Quick inventory ----"
  run /usr/sbin/diskutil list

  # SMART status (best-effort; may be 'Not Supported' on some devices)
  if [[ -n "${ROOT_DISK:-}" ]]; then
    log ""
    log "---- SMART status (best-effort) ----"
    run /usr/sbin/diskutil info "$ROOT_DISK" | /usr/bin/egrep -i "SMART|Protocol|Device Location|Solid State|Media Name|Disk Size|Device / Media Name" || true
  fi

  log ""
  log "---- Verify volume (First Aid-style check) ----"
  # For APFS, verifyVolume works on the APFS volume; for HFS it still applies
  if [[ -n "${ROOT_DEV:-}" ]]; then
    run /usr/sbin/diskutil verifyVolume "/"
  else
    log "Could not determine root device; skipping verifyVolume."
  fi

  # Verify the whole disk (partition map, etc.)
  if [[ -n "${ROOT_DISK:-}" ]]; then
    log ""
    log "---- Verify disk (partition map & structures) ----"
    run /usr/sbin/diskutil verifyDisk "$ROOT_DISK"
  fi

  # APFS-specific checks
  if [[ -n "${APFS_CONTAINER:-}" && "${APFS_CONTAINER:-}" != "Not found" ]]; then
    log ""
    log "---- APFS: verify container ----"
    run /usr/sbin/diskutil apfs list
    # diskutil doesn't have a universal "verify container" command, but verifyVolume covers it.
    # We'll additionally attempt to verify the physical store if discoverable.
    run /usr/sbin/diskutil info "$APFS_CONTAINER" || true
  fi

  log ""
  log "---- Attempt repair ----"
  need_sudo

  if is_recovery; then
    log "You appear to be in macOS Recovery. Repair is more likely to succeed here."

    # In Recovery, we can repair the root volume more effectively (if it's not mounted read-write).
    run sudo /usr/sbin/diskutil repairVolume "/"

    if [[ -n "${ROOT_DISK:-}" ]]; then
      run sudo /usr/sbin/diskutil repairDisk "$ROOT_DISK"
    fi

    # Optional fsck check (best-effort; APFS uses fsck_apfs)
    if [[ "${ROOT_FS:-}" == "apfs" ]]; then
      log ""
      log "---- fsck_apfs (best-effort) ----"
      # Running fsck on a mounted volume may be limited; still useful in Recovery.
      run sudo /sbin/fsck_apfs -y "/dev/${ROOT_DEV}" || true
    else
      log ""
      log "---- fsck (best-effort) ----"
      run sudo /sbin/fsck -fy "/dev/${ROOT_DEV}" || true
    fi

  else
    log "You are booted into normal macOS."
    log "Repairing the active system volume is limited while it's in use."
    log "We'll run safe repair attempts; if issues persist, run this from Recovery."

    # Safe-ish repair attempts
    run sudo /usr/sbin/diskutil repairVolume "/"

    if [[ -n "${ROOT_DISK:-}" ]]; then
      run sudo /usr/sbin/diskutil repairDisk "$ROOT_DISK"
    fi

    log ""
    log "NOTE:"
    log "If diskutil reports it cannot repair the root volume while mounted,"
    log "restart into Recovery and run this script again."
    log "Recovery steps:"
    log "  1) Restart"
    log "  2) Hold Command (⌘) + R (Intel) OR hold Power -> Options (Apple Silicon)"
    log "  3) Open Terminal and run this .command from there (or run Disk Utility First Aid)."
  fi

  log ""
  log "---- Re-verify after repair ----"
  run /usr/sbin/diskutil verifyVolume "/"
  if [[ -n "${ROOT_DISK:-}" ]]; then
    run /usr/sbin/diskutil verifyDisk "$ROOT_DISK"
  fi

  log ""
  log "=============================="
  log "Finished: $(date)"
  log "Report saved to:"
  log "$LOG"
  log "=============================="

  echo ""
  echo "Done. Report created:"
  echo "$LOG"
  echo ""
  echo "Press Enter to close..."
  read -r
}

main
