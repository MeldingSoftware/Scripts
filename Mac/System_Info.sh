#!/bin/zsh
# Mac System Info Collector (local-only)
#
# Output:
#   ~/Desktop/System Info Results/System Info.txt

set -o errexit
set -o pipefail
set -o nounset

# ---------- Output location ----------
DESKTOP_DIR="$HOME/Desktop"
if [[ ! -d "$DESKTOP_DIR" ]]; then
  DESKTOP_DIR="$HOME"
fi

OUT_DIR="$DESKTOP_DIR/System Info Results"
mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/System Info.txt"

# Write to screen AND file
exec > >(tee "$OUT_FILE") 2>&1

# ---------- helpers ----------
hr() {
  print -r -- "------------------------------------------------------------"
}

section() {
  hr
  print -r -- "$1"
  hr
}

cmd_exists() {
  command -v "$1" >/dev/null 2>&1
}

run() {
  local label="$1"; shift
  print -r -- ""
  print -r -- "### $label"
  print -r -- "\$ $*"
  set +e
  "$@" 2>&1
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    print -r -- "[exit code: $rc]"
  fi
}

run_if_exists() {
  local label="$1"; shift
  local bin="$1"; shift
  if cmd_exists "$bin"; then
    run "$label" "$bin" "$@"
  else
    print -r -- ""
    print -r -- "### $label"
    print -r -- "(Skipped: '$bin' not found)"
  fi
}

bytes_to_gb() {
  # best-effort conversion using awk
  awk -v b="$1" 'BEGIN { printf "%.2f", (b/1024/1024/1024) }'
}

# ---------- Start ----------
section "Mac System Info"
print -r -- "Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
print -r -- "User:      $USER"
print -r -- "Hostname:  $(hostname)"
print -r -- "Output:    $OUT_FILE"

section "Computer Names"
run_if_exists "ComputerName / HostName / LocalHostName" scutil --get ComputerName
run_if_exists "HostName" scutil --get HostName
run_if_exists "LocalHostName" scutil --get LocalHostName

section "Operating System"
run_if_exists "macOS version (sw_vers)" sw_vers
run "Kernel / architecture (uname -a)" uname -a
run "Uptime" uptime
run "Boot time" sysctl kern.boottime

section "Hardware Overview"
run_if_exists "Hardware (system_profiler SPHardwareDataType)" system_profiler SPHardwareDataType

section "CPU"
run "CPU brand (sysctl)" sysctl -n machdep.cpu.brand_string
run "CPU counts" sysctl -n hw.physicalcpu hw.logicalcpu hw.ncpu
run "CPU frequency (Hz)" sysctl -n hw.cpufrequency

section "Memory (RAM)"
if cmd_exists sysctl; then
  MEM_BYTES="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
  if [[ "$MEM_BYTES" != "0" ]]; then
    print -r -- "Total RAM: $(bytes_to_gb "$MEM_BYTES") GB (${MEM_BYTES} bytes)"
  fi
fi
run_if_exists "Memory modules (system_profiler SPMemoryDataType)" system_profiler SPMemoryDataType

section "Graphics / Displays"
run_if_exists "Displays (system_profiler SPDisplaysDataType)" system_profiler SPDisplaysDataType

section "Storage"
run_if_exists "Storage (system_profiler SPStorageDataType)" system_profiler SPStorageDataType
run_if_exists "Disk list (diskutil list)" diskutil list
run_if_exists "APFS volumes (diskutil apfs list)" diskutil apfs list

section "Network"
run_if_exists "Hardware ports (networksetup -listallhardwareports)" networksetup -listallhardwareports

# Default route + IP best-effort
DEFAULT_IF=""
set +e
DEFAULT_IF="$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')"
set -e

if [[ -n "$DEFAULT_IF" ]]; then
  print -r -- ""
  print -r -- "Default route interface: $DEFAULT_IF"
  run "IP for default interface" ipconfig getifaddr "$DEFAULT_IF"
fi

run_if_exists "DNS (scutil --dns)" scutil --dns
run_if_exists "Routes (netstat -rn)" netstat -rn

# Wi-Fi details (best-effort)
AIRPORT_BIN="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
if [[ -x "$AIRPORT_BIN" ]]; then
  run "Wi-Fi status (airport -I)" "$AIRPORT_BIN" -I
else
  print -r -- ""
  print -r -- "### Wi-Fi status (airport -I)"
  print -r -- "(Skipped: airport tool not found)"
fi

section "Battery / Power"
run_if_exists "Battery status (pmset -g batt)" pmset -g batt
run_if_exists "Battery details (ioreg AppleSmartBattery)" ioreg -r -c AppleSmartBattery
run_if_exists "Power details (system_profiler SPPowerDataType)" system_profiler SPPowerDataType

section "Security (quick checks)"
run_if_exists "Gatekeeper (spctl --status)" spctl --status
run_if_exists "FileVault (fdesetup status)" fdesetup status
run_if_exists "SIP (csrutil status)" csrutil status

# Firewall state (best-effort)
if [[ -f "/Library/Preferences/com.apple.alf.plist" ]]; then
  run "Application Firewall (defaults read com.apple.alf globalstate)" defaults read /Library/Preferences/com.apple.alf globalstate
fi

section "Software Updates (recent history)"
if cmd_exists softwareupdate; then
  print -r -- "(Showing up to first 100 lines of softwareupdate --history)"
  set +e
  softwareupdate --history 2>&1 | head -n 100
  set -e
else
  print -r -- "(Skipped: softwareupdate not found)"
fi

section "Top Processes (CPU)"
# Note: pcpu output can vary; this is a lightweight snapshot.
run "Top 15 by CPU" ps -A -o pid,ppid,user,%cpu,%mem,command | head -n 1
set +e
ps -A -o pid,ppid,user,%cpu,%mem,command 2>/dev/null | tail -n +2 | sort -nr -k4 | head -n 15
set -e

section "Done"
print -r -- "Saved: $OUT_FILE"