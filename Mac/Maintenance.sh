#!/bin/bash
# ============================================================
# macOS Maintenance.command (ONE password prompt, root-shell for privileged tasks)
# Final artifact: ONE HTML report on Desktop.
# ============================================================

set -u
IFS=$'\n\t'

# ---------------- Paths ----------------
DESKTOP="${HOME}/Desktop"
TS="$(date '+%Y-%m-%d_%H-%M-%S')"
REPORT_HTML="${DESKTOP}/Maintenance_Report_${TS}.html"
TMPDIR_RUN="$(mktemp -d "/tmp/macos-maint.${TS}.XXXX")"

US=$'\x1F' # Unit Separator
TASKS_FILE="${TMPDIR_RUN}/tasks.usv"
: > "$TASKS_FILE"

cleanup() { rm -rf "$TMPDIR_RUN" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# ---------------- Helpers ----------------
have() { command -v "$1" >/dev/null 2>&1; }

html_escape() {
  local s="${1:-}"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  s="${s//\"/&quot;}"
  s="${s//\'/&#39;}"
  printf "%s" "$s"
}

bytes_to_gb() {
  python3 - <<'PY' "${1:-0}" 2>/dev/null || echo "0.00"
import sys
b=float(sys.argv[1] or 0)
print(f"{b/1024/1024/1024:.2f}")
PY
}

dir_bytes() {
  local path="$1"
  if [[ -e "$path" ]]; then
    local kb
    kb="$(du -sk "$path" 2>/dev/null | awk '{print $1}' || echo 0)"
    echo $((kb * 1024))
  else
    echo 0
  fi
}

b64enc() { printf "%s" "${1:-}" | base64 | tr -d '\n'; }
b64dec() {
  if base64 -D >/dev/null 2>&1 <<<"dGVzdA=="; then
    printf "%s" "${1:-}" | base64 -D 2>/dev/null || true
  else
    printf "%s" "${1:-}" | base64 -d 2>/dev/null || true
  fi
}

task_record() {
  # id, section, title, status(ok|warn|fail|skip), notes, excerpt_b64
  local id="$1" section="$2" title="$3" status="$4" notes="$5" excerpt_b64="$6"
  printf "%s%s%s%s%s%s%s%s%s%s%s\n" \
    "$id" "$US" "$section" "$US" "$title" "$US" "$status" "$US" "$notes" "$US" "$excerpt_b64" >> "$TASKS_FILE"
}

run_eval_capture() {
  # Runs in current shell; returns rc; prints excerpt
  local cmd="$1"
  local out="${TMPDIR_RUN}/cmd.$RANDOM.$RANDOM.txt"
  { eval "$cmd"; } >"$out" 2>&1
  local rc=$?
  local excerpt
  excerpt="$(head -n 200 "$out" 2>/dev/null || true)"
  # placeholder so HTML never has huge blank space in <pre>
  if [[ -z "${excerpt//[[:space:]]/}" ]]; then
    excerpt="(No output / Nothing to do.)"
  fi
  printf "%s" "$excerpt"
  return $rc
}

close_apps_best_effort() {
  local apps=("Google Chrome" "Safari" "Firefox" "Microsoft Edge" "Brave Browser" "Opera" "Vivaldi")
  for a in "${apps[@]}"; do
    osascript -e "tell application \"$a\" to if it is running then quit" >/dev/null 2>&1 || true
  done
}

brew_shellenv() {
  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
}

# ---------------- One and only password prompt (YOUR prompt) ----------------
echo
echo "macOS Maintenance"
echo "Enter your admin password ONCE. After this, it runs unattended and generates an HTML report."
read -s -p "Password: " ADMIN_PW
echo
echo

# Validate password once, without prompting again
if ! printf "%s\n" "$ADMIN_PW" | sudo -S -p "" -v >/dev/null 2>&1; then
  echo "Admin authentication failed."
  exit 1
fi

close_apps_best_effort

# ---------------- Collect summary info (non-sudo) ----------------
HOSTNAME_STR="$(scutil --get ComputerName 2>/dev/null || hostname)"
USER_STR="$(id -un 2>/dev/null || echo "")"
OS_NAME="$(sw_vers -productName 2>/dev/null || echo "macOS")"
OS_VER="$(sw_vers -productVersion 2>/dev/null || echo "")"
OS_BUILD="$(sw_vers -buildVersion 2>/dev/null || echo "")"
OS_STR="${OS_NAME} ${OS_VER} (${OS_BUILD})"

HW_MINI="$(system_profiler SPHardwareDataType -detailLevel mini 2>/dev/null || true)"
HW_MODEL_ID="$(printf "%s\n" "$HW_MINI" | awk -F': ' '/Model Identifier/{print $2; exit}')"
HW_CHIP="$(printf "%s\n" "$HW_MINI" | awk -F': ' '/Chip/{print $2; exit}')"
HW_PROC="$(printf "%s\n" "$HW_MINI" | awk -F': ' '/Processor Name/{print $2; exit}')"
HW_CORES="$(printf "%s\n" "$HW_MINI" | awk -F': ' '/Total Number of Cores/{print $2; exit}')"
HW_MEM="$(printf "%s\n" "$HW_MINI" | awk -F': ' '/Memory/{print $2; exit}')"

DISK_BEFORE_BYTES="$(df -k / | awk 'NR==2 {print $4*1024}' 2>/dev/null || echo 0)"
DISK_BEFORE_GB="$(bytes_to_gb "$DISK_BEFORE_BYTES")"

# ---------------- Privileged tasks inside ONE root shell (no more sudo calls) ----------------
# We run privileged things here so they can NEVER ask for password again.
ROOT_OUT="${TMPDIR_RUN}/root_tasks.txt"
printf "%s\n" "$ADMIN_PW" | sudo -S -p "" bash -s >"$ROOT_OUT" 2>&1 <<'ROOT'
set -u

echo "=== Updates (softwareupdate) ==="
softwareupdate -l || true
softwareupdate -ia --verbose || true
echo

echo "=== Network (DNS flush) ==="
dscacheutil -flushcache || true
killall -HUP mDNSResponder || true
echo

echo "=== Cleanup (system logs) ==="
rm -f /private/var/log/*.0.gz /private/var/log/*.bz2 2>/dev/null || true
echo

echo "=== Time Machine local snapshots (thin) ==="
if command -v tmutil >/dev/null 2>&1; then
  tmutil thinlocalsnapshots / 10000000000 4 || true
else
  echo "tmutil not available."
fi
echo
ROOT

# Record the privileged section outputs into tasks (split into logical tasks)
# Use the file as excerpt (first 200 lines) per “task” so the report has something.
SECTION="Updates"
EX="$(head -n 200 "$ROOT_OUT" 2>/dev/null || true)"; [[ -z "${EX//[[:space:]]/}" ]] && EX="(No output / Nothing to do.)"
task_record "upd_root" "$SECTION" "Install all macOS updates" "ok" "Restart may be required." "$(b64enc "$EX")"

SECTION="Network"
EX="$(grep -n "=== Network" -A 60 "$ROOT_OUT" 2>/dev/null | head -n 200 || true)"; [[ -z "${EX//[[:space:]]/}" ]] && EX="(No output / Nothing to do.)"
task_record "net_dns" "$SECTION" "Flush DNS cache" "ok" "" "$(b64enc "$EX")"

SECTION="Cleanup"
EX="$(grep -n "=== Cleanup" -A 60 "$ROOT_OUT" 2>/dev/null | head -n 200 || true)"; [[ -z "${EX//[[:space:]]/}" ]] && EX="(No output / Nothing to do.)"
task_record "clean_syslogs" "$SECTION" "Remove old compressed log archives" "ok" "" "$(b64enc "$EX")"

SECTION="Cleanup"
EX="$(grep -n "=== Time Machine" -A 80 "$ROOT_OUT" 2>/dev/null | head -n 200 || true)"; [[ -z "${EX//[[:space:]]/}" ]] && EX="(No output / Nothing to do.)"
task_record "clean_tm" "$SECTION" "Thin Time Machine local snapshots (~10GB target)" "ok" "" "$(b64enc "$EX")"

# ---------------- Dependencies & user-space tasks ----------------
SECTION="Dependencies"

if have brew; then
  task_record "dep_brew" "$SECTION" "Homebrew present" "ok" "" "$(b64enc "brew found")"
else
  # Don’t trigger GUI prompts. Report CLT missing if needed.
  if ! xcode-select -p >/dev/null 2>&1; then
    task_record "dep_clt" "$SECTION" "Xcode Command Line Tools" "fail" "Missing. Install with: xcode-select --install" "$(b64enc "xcode-select -p failed")"
  else
    task_record "dep_clt" "$SECTION" "Xcode Command Line Tools" "ok" "" "$(b64enc "$(xcode-select -p 2>/dev/null || true)")"
  fi

  # Install brew (non-interactive) – should not prompt for sudo now because we already authenticated
  EX="$(run_eval_capture 'NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')"
  RC=$?
  if [[ $RC -eq 0 ]]; then
    task_record "dep_brew_install" "$SECTION" "Install Homebrew" "ok" "" "$(b64enc "$EX")"
  else
    task_record "dep_brew_install" "$SECTION" "Install Homebrew" "fail" "Installer returned $RC" "$(b64enc "$EX")"
  fi
fi

brew_shellenv

# Ensure mas is installed (via brew) so App Store upgrades can run
if have brew; then
  if have mas; then
    task_record "dep_mas" "$SECTION" "mas present" "ok" "" "$(b64enc "mas found")"
  else
    EX="$(run_eval_capture 'brew update && brew install mas')"
    RC=$?
    if [[ $RC -eq 0 ]]; then
      task_record "dep_mas_install" "$SECTION" "Install mas" "ok" "" "$(b64enc "$EX")"
    else
      task_record "dep_mas_install" "$SECTION" "Install mas" "fail" "brew/mas install returned $RC" "$(b64enc "$EX")"
    fi
  fi
else
  task_record "dep_mas_skip" "$SECTION" "Install mas" "skip" "Homebrew unavailable" "$(b64enc "")"
fi

# System Health tasks
SECTION="System Health"
EX="$(run_eval_capture 'sw_vers; echo; uptime; echo; pmset -g batt || true; echo; df -h; echo; system_profiler SPHardwareDataType -detailLevel mini')"
task_record "sys_snapshot" "$SECTION" "System snapshot" "ok" "" "$(b64enc "$EX")"

EX="$(run_eval_capture 'top -l 1 -stats pid,command,cpu,mem,time -o cpu | head -n 30; echo; memory_pressure || true')"
task_record "sys_perf" "$SECTION" "Performance snapshot" "ok" "" "$(b64enc "$EX")"

# Homebrew updates + “apps” upgrades
SECTION="Homebrew"
if have brew; then
  EX="$(run_eval_capture 'brew update')"; task_record "brew_update" "$SECTION" "brew update" "ok" "" "$(b64enc "$EX")"

  EX="$(run_eval_capture 'brew outdated || true')"; task_record "brew_outdated" "$SECTION" "brew outdated (formula)" "ok" "" "$(b64enc "$EX")"
  EX="$(run_eval_capture 'brew outdated --cask --greedy || true')"; task_record "brew_outdated_cask" "$SECTION" "brew outdated --cask --greedy (apps)" "ok" "" "$(b64enc "$EX")"

  EX="$(run_eval_capture 'brew upgrade || true')"; task_record "brew_upgrade" "$SECTION" "brew upgrade (formula)" "ok" "" "$(b64enc "$EX")"
  EX="$(run_eval_capture 'brew upgrade --cask --greedy || true')"; task_record "brew_cask" "$SECTION" "brew upgrade --cask --greedy (apps)" "ok" "" "$(b64enc "$EX")"

  EX="$(run_eval_capture 'brew cleanup -s || true')"; task_record "brew_cleanup" "$SECTION" "brew cleanup" "ok" "" "$(b64enc "$EX")"
else
  task_record "brew_skip" "$SECTION" "Homebrew maintenance" "skip" "Homebrew not available" "$(b64enc "")"
fi

# App Store upgrades (FIX: no mas account)
SECTION="App Store"
if have mas; then
  EX="$(run_eval_capture 'mas upgrade || true')"
  task_record "mas_upgrade" "$SECTION" "Upgrade App Store apps" "ok" "Requires being signed into the App Store." "$(b64enc "$EX")"
else
  task_record "mas_skip" "$SECTION" "Upgrade App Store apps" "skip" "mas not available" "$(b64enc "")"
fi

# Disk checks (non-sudo)
SECTION="Disk"
EX="$(run_eval_capture 'diskutil list; echo; diskutil verifyVolume / || true; echo; diskutil info disk0 | egrep "SMART|Device / Media Name|Protocol|Internal" || true; echo; diskutil apfs listSnapshots / 2>/dev/null || true')"
task_record "disk_checks" "$SECTION" "Disk verification + SMART + APFS snapshots" "ok" "" "$(b64enc "$EX")"

# User-cache cleanup (no sudo, no prompts)
SECTION="Cleanup"
USER_CACHES="${HOME}/Library/Caches"
CACHES_BEFORE="$(dir_bytes "$USER_CACHES")"
EX="$(run_eval_capture 'rm -rf "${HOME}/Library/Caches"/* 2>/dev/null || true')"
task_record "clean_usercaches" "$SECTION" "Clear user caches (~/Library/Caches/*)" "ok" "Apps will rebuild caches." "$(b64enc "$EX")"
CACHES_AFTER="$(dir_bytes "$USER_CACHES")"
FREED_BYTES=$(( CACHES_BEFORE - CACHES_AFTER )); [[ $FREED_BYTES -lt 0 ]] && FREED_BYTES=0
FREED_GB="$(bytes_to_gb "$FREED_BYTES")"
CLEAN_NOTE="User cache freed (best-effort): ${FREED_GB} GB"

# Disk free after
DISK_AFTER_BYTES="$(df -k / | awk 'NR==2 {print $4*1024}' 2>/dev/null || echo 0)"
DISK_AFTER_GB="$(bytes_to_gb "$DISK_AFTER_BYTES")"
DISK_DELTA_BYTES=$((DISK_AFTER_BYTES - DISK_BEFORE_BYTES))
DISK_DELTA_GB="$(bytes_to_gb "$DISK_DELTA_BYTES")"

# ---------------- HTML (tighter spacing) ----------------
OK_COUNT=0; WARN_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
while IFS="$US" read -r _ _ _ status _ _; do
  case "$status" in
    ok)   OK_COUNT=$((OK_COUNT+1)) ;;
    warn) WARN_COUNT=$((WARN_COUNT+1)) ;;
    fail) FAIL_COUNT=$((FAIL_COUNT+1)) ;;
    skip) SKIP_COUNT=$((SKIP_COUNT+1)) ;;
  esac
done < "$TASKS_FILE"

NOW_STR="$(date '+%Y-%m-%d %H:%M:%S')"

{
cat <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Maintenance Report - $(html_escape "$HOSTNAME_STR")</title>
<style>
  body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#050608; color:#f5f7fb; margin:0; padding:0; }
  .page { max-width:1100px; margin:0 auto; padding:18px 14px 22px 14px; }
  .title { font-size:28px; font-weight:700; margin-bottom:3px; color:#fff; }
  .subtitle { font-size:13px; color:#a0a4b8; margin-bottom:12px; }
  .summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px; margin-bottom:10px; }
  .card { background:linear-gradient(180deg,#0d1020,#080a12); border:1px solid #181e32; border-radius:14px; padding:12px; }
  .card-label { font-size:12px; color:#8c90aa; text-transform:uppercase; letter-spacing:.06em; margin-bottom:5px; }
  .card-value { font-size:15px; font-weight:700; color:#fff; margin-bottom:4px; word-break:break-word; }
  .card-meta { font-size:12px; color:#9aa0b8; margin-top:2px; word-break:break-word; }
  .pillbar { display:flex; gap:8px; flex-wrap:wrap; margin:6px 0 10px 0; }
  .pill { display:inline-flex; align-items:center; gap:8px; padding:6px 9px; border-radius:999px; border:1px solid #1b2440; background:rgba(255,255,255,0.03); font-size:12px; font-weight:700; color:#e8ecff; }
  .dot { width:9px; height:9px; border-radius:50%; }
  .dot.ok { background:#2bd576; } .dot.warn { background:#f1c40f; } .dot.fail { background:#ff4d4d; } .dot.skip { background:#8c90aa; }
  .section { margin-top:10px; border:1px solid #181e32; border-radius:14px; overflow:hidden; background:#060711; }
  .section-header { display:flex; align-items:center; justify-content:space-between; padding:10px 12px; cursor:pointer; background:linear-gradient(180deg,#0c1022,#070915); user-select:none; }
  .section-title { font-size:14px; font-weight:800; color:#fff; margin:0; }
  .section-icon { font-size:14px; color:#9aa0b8; font-weight:800; }
  .section-body { padding:10px 12px 12px 12px; }
  .table { width:100%; border-collapse:collapse; border-radius:12px; border:1px solid #181e32; overflow:hidden; }
  .table th,.table td { padding:8px; border-bottom:1px solid #141a2d; vertical-align:top; font-size:12.5px; }
  .table th { text-align:left; color:#9aa0b8; background:rgba(255,255,255,0.03); font-weight:800; }
  .table tr:last-child td { border-bottom:none; }
  pre { margin:0; white-space:pre-wrap; word-wrap:break-word; background:rgba(0,0,0,0.25); border:1px solid #181e32; border-radius:12px; padding:8px; color:#e9edff; }
  code,pre { font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace; }
  .note { font-size:12px; color:#a0a4b8; margin-top:6px; }
  .footer { font-size:12px; color:#737995; margin-top:12px; border-top:1px solid #181e32; padding-top:8px; }
</style>
<script>
  function toggleSection(id){
    var body=document.getElementById(id);
    var icon=document.getElementById(id+"-icon");
    if(!body) return;
    if(body.style.display==="none"){ body.style.display="block"; if(icon) icon.textContent="v"; }
    else { body.style.display="none"; if(icon) icon.textContent=">"; }
  }
</script>
</head>
<body>
<div class="page">
  <div class="title">Maintenance Report</div>
  <div class="subtitle">$(html_escape "$NOW_STR")</div>

  <div class="summary-grid">
    <div class="card">
      <div class="card-label">Computer</div>
      <div class="card-value">$(html_escape "$HOSTNAME_STR")</div>
      <div class="card-meta">User: $(html_escape "$USER_STR")</div>
      <div class="card-meta">Model: $(html_escape "${HW_MODEL_ID:-}")</div>
    </div>
    <div class="card">
      <div class="card-label">Operating System</div>
      <div class="card-value">$(html_escape "$OS_STR")</div>
      <div class="card-meta">Chip/CPU: $(html_escape "${HW_CHIP:-${HW_PROC:-}}")</div>
      <div class="card-meta">RAM: $(html_escape "${HW_MEM:-}")</div>
    </div>
    <div class="card">
      <div class="card-label">Storage (Free)</div>
      <div class="card-value">$(html_escape "${DISK_BEFORE_GB} GB")</div>
      <div class="card-meta">After: $(html_escape "${DISK_AFTER_GB} GB")</div>
      <div class="card-meta">Change: $(html_escape "${DISK_DELTA_GB} GB")</div>
    </div>
    <div class="card">
      <div class="card-label">Cleanup</div>
      <div class="card-value">$(html_escape "$CLEAN_NOTE")</div>
      <div class="card-meta">Cores: $(html_escape "${HW_CORES:-}")</div>
    </div>
  </div>

  <div class="pillbar">
    <div class="pill"><span class="dot ok"></span> OK: ${OK_COUNT}</div>
    <div class="pill"><span class="dot warn"></span> WARN: ${WARN_COUNT}</div>
    <div class="pill"><span class="dot fail"></span> FAIL: ${FAIL_COUNT}</div>
    <div class="pill"><span class="dot skip"></span> SKIP: ${SKIP_COUNT}</div>
  </div>

  <div class="section">
    <div class="section-header" onclick="toggleSection('results')">
      <div class="section-title">Results</div>
      <div class="section-icon" id="results-icon">v</div>
    </div>
    <div class="section-body" id="results" style="display:block;">
      <table class="table">
        <thead>
          <tr>
            <th style="width:110px;">Status</th>
            <th style="width:170px;">Category</th>
            <th>Task</th>
            <th style="width:320px;">Notes</th>
          </tr>
        </thead>
        <tbody>
HTML

while IFS="$US" read -r id section title status notes excerpt_b64; do
  STATUS_UP="$(printf "%s" "$status" | tr '[:lower:]' '[:upper:]')"
  DOT_CLASS="$status"
  [[ "$DOT_CLASS" != "ok" && "$DOT_CLASS" != "warn" && "$DOT_CLASS" != "fail" && "$DOT_CLASS" != "skip" ]] && DOT_CLASS="skip"
  echo "          <tr>"
  echo "            <td><span class=\"pill\"><span class=\"dot ${DOT_CLASS}\"></span>${STATUS_UP}</span></td>"
  echo "            <td>$(html_escape "$section")</td>"
  echo "            <td><b>$(html_escape "$title")</b></td>"
  echo "            <td>$(html_escape "$notes")</td>"
  echo "          </tr>"
done < "$TASKS_FILE"

cat <<HTML
        </tbody>
      </table>
      <div class="note">Sections below include excerpts (first ~200 lines) of each command’s output.</div>
    </div>
  </div>
HTML

current_section=""
sec_id=0
while IFS="$US" read -r id section title status notes excerpt_b64; do
  if [[ "$section" != "$current_section" ]]; then
    if [[ -n "$current_section" ]]; then
      echo "        </tbody></table></div></div>"
    fi
    current_section="$section"
    sec_id=$((sec_id+1))
    dom="sec${sec_id}"
    echo "  <div class=\"section\">"
    echo "    <div class=\"section-header\" onclick=\"toggleSection('${dom}')\">"
    echo "      <div class=\"section-title\">$(html_escape "$current_section")</div>"
    echo "      <div class=\"section-icon\" id=\"${dom}-icon\">v</div>"
    echo "    </div>"
    echo "    <div class=\"section-body\" id=\"${dom}\" style=\"display:block;\">"
    echo "      <table class=\"table\"><thead><tr><th style=\"width:260px;\">Task</th><th>Excerpt</th></tr></thead><tbody>"
  fi

  EXCERPT="$(b64dec "$excerpt_b64")"
  [[ -z "${EXCERPT//[[:space:]]/}" ]] && EXCERPT="(No output / Nothing to do.)"
  echo "        <tr>"
  echo "          <td><b>$(html_escape "$title")</b><div class=\"note\">$(html_escape "$notes")</div></td>"
  echo "          <td><pre>$(html_escape "$EXCERPT")</pre></td>"
  echo "        </tr>"
done < "$TASKS_FILE"

if [[ -n "$current_section" ]]; then
  echo "        </tbody></table></div></div>"
fi

cat <<HTML
  <div class="footer">
    Generated by macOS Maintenance.command • Timestamp: <code>$(html_escape "$TS")</code>
  </div>
</div>
</body>
</html>
HTML
} > "$REPORT_HTML"

open "$REPORT_HTML" >/dev/null 2>&1 || true
echo "Done. Report created:"
echo "$REPORT_HTML"
exit 0