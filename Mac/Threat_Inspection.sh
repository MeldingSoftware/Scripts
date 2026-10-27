#!/usr/bin/env bash
set -u
set -o pipefail

# ================================================================
# Threat Inspection v1.0 for macOS
# Melding Software
#
# Native macOS counterpart to the Windows Threat Inspection script.
# Inspects and reports only. It does not remove/quarantine findings or
# change inspected security settings. A small per-user URL-handler app
# is installed only to support clickable Finder/System Settings links
# from the HTML report.
# ================================================================

VERSION="1.0"
RECENT_DAYS=30
NO_OPEN_REPORT=0

usage() {
  cat <<'EOF'
Threat Inspection for macOS

Usage:
  Threat_Inspection.sh [--recent-days N] [--no-open-report]

Options:
  --recent-days N   Recent-file/application lookback in days (1-365). Default: 30
  --no-open-report  Create the HTML report without opening it automatically
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --recent-days)
      shift
      [[ $# -gt 0 ]] || { echo "Missing value for --recent-days"; exit 2; }
      RECENT_DAYS="$1"
      ;;
    --no-open-report)
      NO_OPEN_REPORT=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 2
      ;;
  esac
  shift
done

case "$RECENT_DAYS" in
  ''|*[!0-9]*) echo "--recent-days must be a number from 1 to 365"; exit 2 ;;
esac
if (( RECENT_DAYS < 1 || RECENT_DAYS > 365 )); then
  echo "--recent-days must be from 1 to 365"
  exit 2
fi

# Elevate so system-wide persistence/security state can be inspected.
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo ""
  echo "Threat Inspection requires administrator access."
  echo "macOS will prompt for an administrator password."
  echo ""
  exec sudo /bin/bash "$0" --recent-days "$RECENT_DAYS" $([[ "$NO_OPEN_REPORT" -eq 1 ]] && printf '%s' '--no-open-report')
fi

CONSOLE_USER="${SUDO_USER:-}"
if [[ -z "$CONSOLE_USER" || "$CONSOLE_USER" == "root" ]]; then
  CONSOLE_USER="$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null || true)"
fi
if [[ -z "$CONSOLE_USER" || "$CONSOLE_USER" == "root" || "$CONSOLE_USER" == "loginwindow" ]]; then
  CONSOLE_USER="$(/usr/bin/who | /usr/bin/awk 'NR==1 {print $1}')"
fi
if [[ -z "$CONSOLE_USER" ]]; then
  echo "Could not determine the logged-in user."
  exit 1
fi

USER_HOME="$(/usr/bin/dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{$1=""; sub(/^ /,""); print}' || true)"
if [[ -z "$USER_HOME" ]]; then
  USER_HOME="/Users/$CONSOLE_USER"
fi

DESKTOP_DIR="$USER_HOME/Desktop"
mkdir -p "$DESKTOP_DIR" 2>/dev/null || true

HOSTNAME_SHORT="$(/usr/sbin/scutil --get ComputerName 2>/dev/null || /bin/hostname -s 2>/dev/null || echo "Mac")"
STARTED_AT="$(/bin/date '+%Y-%m-%d %H:%M:%S')"
REPORT_DATE="$(/bin/date '+%m-%d-%y')"
REPORT_PATH="$DESKTOP_DIR/Threat Inspection $REPORT_DATE.html"

WORK_DIR="$(/usr/bin/mktemp -d "/tmp/ThreatInspection.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM HUP

SEP=$'\037'
SECTION_IDS=(remote programs persistence background files browsers network security)
SECTION_TITLES=("Remote Access" "Programs & Login Items" "LaunchAgents / Persistence" "Background Services / Processes" "Suspicious Files" "Browsers" "Network" "macOS Security")
SECTION_SUMMARIES=(
  "Built-in sharing/remote-login state plus remote-access/RMM software and runtime activity."
  "PUP/PUA watchlist matches, compact installed-app context, Login Items, and background-item context."
  "Third-party LaunchAgents and LaunchDaemons with path, signature, and watchlist-aware filtering."
  "User-writable running-process checks plus third-party system-extension inventory."
  "Grouped remote-access/PUP artifacts plus targeted recent-file review with self-generated files excluded."
  "Chromium/Firefox extensions, selected browser settings, allowed notification origins, and Safari coverage notes."
  "Proxy, DNS, interfaces/VPN context, hosts file, Application Firewall state, rules, and attention-worthy connections."
  "Security software, Gatekeeper, SIP, FileVault, XProtect/MRT context, security-data updates, and management state."
)

for sid in "${SECTION_IDS[@]}"; do
  : > "$WORK_DIR/$sid.findings"
done

sanitize_field() {
  local v="${1:-}"
  v="${v//$'\037'/ }"
  v="${v//$'\r'/ }"
  v="${v//$'\n'/ }"
  printf '%s' "$v"
}

add_finding() {
  local section="$1" status="$2" text="$3" detail="${4:-}" link="${5:-}"
  text="$(sanitize_field "$text")"
  detail="$(sanitize_field "$detail")"
  link="$(sanitize_field "$link")"
  printf '%s%s%s%s%s%s%s\n' "$status" "$SEP" "$text" "$SEP" "$detail" "$SEP" "$link" >> "$WORK_DIR/$section.findings"
}

write_section_console() {
  local sid="$1" title="$2"
  echo ""
  echo "$title"
  echo "------------------------------------------------------------"
  while IFS="$SEP" read -r status text detail link; do
    [[ -n "$status" ]] || continue
    printf '[%s] %s\n' "$status" "$text"
    [[ -n "${detail:-}" ]] && printf '  %s\n' "$detail"
  done < "$WORK_DIR/$sid.findings"
}

html_escape() {
  local v="${1:-}"
  v="${v//&/&amp;}"
  v="${v//</&lt;}"
  v="${v//>/&gt;}"
  v="${v//\"/&quot;}"
  v="${v//\'/&#39;}"
  printf '%s' "$v"
}

section_status() {
  local file="$1"
  if /usr/bin/grep -q "^Warning${SEP}" "$file" 2>/dev/null; then
    printf 'Warning'
  elif /usr/bin/grep -q "^Review${SEP}" "$file" 2>/dev/null; then
    printf 'Review'
  elif /usr/bin/grep -q "^Good${SEP}" "$file" 2>/dev/null; then
    printf 'Good'
  else
    printf 'Info'
  fi
}

count_status() {
  local wanted="$1" count=0 sid
  for sid in "${SECTION_IDS[@]}"; do
    count=$((count + $(/usr/bin/awk -F "$SEP" -v s="$wanted" '$1==s{n++} END{print n+0}' "$WORK_DIR/$sid.findings")))
  done
  printf '%s' "$count"
}

# -----------------------------
# Watchlists
# -----------------------------
REMOTE_WATCHLIST=$(cat <<'EOF'
Action1	action1
AeroAdmin	aeroadmin
Ammyy Admin	ammyy
AnyDesk	anydesk
AnyViewer	anyviewer
Atera	(^|[/ ._-])atera([/ ._-]|$)
BeyondTrust / Bomgar	beyondtrust|bomgar
ConnectWise Automate	connectwise.*automate|labtech
ConnectWise ScreenConnect	screenconnect|connectwise.*control
Dameware	dameware
Datto RMM / CentraStage	datto|centrastage
DWService	dwservice|dwagent
FixMe.IT	fixme[.]?it|techinline
FleetDeck	fleetdeck
GoTo Resolve / GoToAssist	goto.*resolve|gotoassist
GoToMyPC	gotomypc
Goverlan	goverlan
Gorelo RMM	gorelo
Heartbeat RM	heartbeat.*rm
HelpWire	helpwire
ImmyBot	immybot
ISL Online	isl.*online
ITarian / Comodo RMM	itarian|comodo.*rmm
Jump Desktop	jump desktop|jumpdesktop
Kaseya VSA	kaseya
Level.io	(^|[/ ._-])level[.]?io([/ ._-]|$)
LiteManager	litemanager
LogMeIn	logmein
ManageEngine Remote Access Plus	remote access plus
MeshCentral / MeshAgent	meshcentral|meshagent
Miradore	miradore
N-able / N-central / N-sight	n-able|ncentral|n-central|n-sight
NetSupport Manager	netsupport
NinjaOne / NinjaRMM	ninjaone|ninjarmm|ninja.*rmm
NoMachine	nomachine
Parsec	(^|[/ ._-])parsec([/ ._-]|$)
PDQ Connect / PDQ Deploy	pdq.*connect|pdq.*deploy
Pulseway	pulseway
Remote Utilities	remote utilities
RemotePC	remotepc
RemoteToPC	remotetopc
RPort	(^|[/ ._-])rport([/ ._-]|$)
RustDesk	rustdesk
SimpleHelp	simplehelp
Splashtop	splashtop
Supremo	supremo
Syncro	(^|[/ ._-])syncro([/ ._-]|$)
Tactical RMM	tactical.*rmm
TeamViewer	teamviewer
TightVNC	tightvnc
Tiflux	tiflux
TigerVNC	tigervnc
TSplus Remote Support	tsplus
UltraViewer	ultraviewer
UltraVNC / WinVNC	ultravnc|winvnc
Zoho Assist	zoho.*assist
Chrome Remote Desktop	chrome remote desktop|chromoting
RealVNC / VNC Connect	realvnc|vnc connect
Radmin	radmin
Iperius Remote	iperius.*remote
Getscreen.me	getscreen
HopToDesk	hoptodesk
DeskIn	(^|[/ ._-])deskin([/ ._-]|$)
ShowMyPC	showmypc
Mikogo	mikogo
eHorus	ehorus
Microsoft Quick Assist	quick assist
EOF
)

PUP_WATCHLIST=$(cat <<'EOF'
Wave Browser	(^|[/ ._-])wave browser([/ ._-]|$)|wavebrowser
OneStart	(^|[/ ._-])onestart([/ ._-]|$)
One Browser	(^|[/ ._-])one browser([/ ._-]|$)
Driver Support / Driver Support One	driver support|driversupportone
Generic Driver Updater Installer	driver[_ -]?updater([_ -]?(setup|installer))?
Web Companion	web companion
Search Protect	search protect
Browser Assistant	browser assistant
PDF Tools	(^|[/ ._-])pdf tools([/ ._-]|$)
PDF Hub	(^|[/ ._-])pdf hub([/ ._-]|$)
PC App Store	pc app store
Clear / ClearBrowser	clearbrowser
OneLaunch	onelaunch
WebDiscover Browser	webdiscover
WebNavigator Browser	webnavigator
Chromstera Browser	chromstera
SAntivirus / Segurazo	segurazo|santivirus
ByteFence	bytefence
PremierOpinion	premieropinion
RelevantKnowledge	relevantknowledge
Optimizer Pro	optimizer pro
MyCleanPC	mycleanpc
SlimCleaner / Slimware	slimcleaner|slimware
PC HelpSoft Driver Updater	pchelpsoft
Quick Driver Updater	quick driver updater
WinZip Driver Updater	winzip driver updater
Ask Toolbar	ask toolbar
Babylon Toolbar	babylon toolbar
MyWay / Mindspark	myway|mindspark
Search Manager	search manager
Universal Browser / Web Browser Solutions	universal browser|web browser solutions
Artificius / Artificus	artificius|artificus
Custom Search Bar	custom search bar
Active Search Bar	active search bar
DriverHive	driverhive
DriverFix	(^|[/ ._-])driverfix([/ ._-]|$)
DriverPack	driverpack
WiperSoft	wipersoft
WinThruster	winthruster
Restoro / Reimage	restoro|reimage
SearchEncrypt	searchencrypt
Trovi	(^|[/ ._-])trovi([/ ._-]|$)
Spigot	(^|[/ ._-])spigot([/ ._-]|$)
Wajam	wajam
Webbar	(^|[/ ._-])webbar([/ ._-]|$)
CrossBrowse	crossbrowse
BrowseFox	browsefox
OpenCandy	opencandy
Softonic Downloader	softonic.*downloader
Advanced Mac Cleaner	advanced mac cleaner
Mac Auto Fixer	mac auto fixer
Mac Cleanup Pro	mac cleanup pro
Mac Tonic	mac tonic
Mac Optimizer Pro	mac optimizer pro
Mac Mechanic	mac mechanic
Genieo	(^|[/ ._-])genieo([/ ._-]|$)
VSearch	(^|[/ ._-])vsearch([/ ._-]|$)
Search Marquis	search marquis
Search Baron	search baron
Safe Finder	safe finder
Any Search Manager	any search manager
Chill Tab	chill tab
MyShopcoupon	myshopcoupon
InstallCore	installcore
EOF
)

shopt -s nocasematch
watchlist_match() {
  local text="$1" list="$2" name pattern
  MATCH_NAME=""
  while IFS=$'\t' read -r name pattern; do
    [[ -n "$name" && -n "$pattern" ]] || continue
    if [[ "$text" =~ $pattern ]]; then
      MATCH_NAME="$name"
      return 0
    fi
  done <<< "$list"
  return 1
}

is_self_path() {
  local p="$1"
  case "$p" in
    "$USER_HOME/Library/Application Support/MeldingSoftware/Threat Inspection"* ) return 0 ;;
    "$USER_HOME/.MeldingSoftware/"* ) return 0 ;;
    "$WORK_DIR/"* ) return 0 ;;
    "$REPORT_PATH" ) return 0 ;;
  esac
  return 1
}

# -----------------------------
# Signature / path helpers
# -----------------------------
signature_info() {
  local p="$1" out auth team
  SIG_STATUS="Unknown"
  SIG_PUBLISHER=""

  [[ -e "$p" ]] || { SIG_STATUS="Missing"; return; }

  out="$(/usr/bin/codesign -dv --verbose=4 "$p" 2>&1 || true)"
  if [[ "$out" == *"Authority="* || "$out" == *"TeamIdentifier="* || "$out" == *"Signature=adhoc"* ]]; then
    auth="$(printf '%s\n' "$out" | /usr/bin/sed -n 's/^Authority=//p' | /usr/bin/head -n 1)"
    team="$(printf '%s\n' "$out" | /usr/bin/sed -n 's/^TeamIdentifier=//p' | /usr/bin/head -n 1)"
    if /usr/bin/codesign --verify --deep --strict "$p" >/dev/null 2>&1; then
      SIG_STATUS="Valid"
    else
      SIG_STATUS="Signed"
    fi
    SIG_PUBLISHER="$auth"
    [[ -z "$SIG_PUBLISHER" ]] && SIG_PUBLISHER="$team"
  else
    SIG_STATUS="NotSigned"
  fi
}

is_user_writable_unusual() {
  local p="$1"
  case "$p" in
    /tmp/*|/private/tmp/*|/private/var/tmp/*|/Users/*/Downloads/*|/Users/*/Desktop/*|/Users/*/Library/Application\ Support/*|/Users/*/Library/LaunchAgents/* ) return 0 ;;
  esac
  return 1
}

file_mtime_text() {
  /usr/bin/stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$1" 2>/dev/null || printf 'Unknown'
}

file_size_kb() {
  local b
  b="$(/usr/bin/stat -f '%z' "$1" 2>/dev/null || echo 0)"
  /usr/bin/awk -v b="$b" 'BEGIN{printf "%.1f", b/1024}'
}

plist_value() {
  local plist="$1" key="$2"
  /usr/libexec/PlistBuddy -c "Print :$key" "$plist" 2>/dev/null | /usr/bin/head -n 1 || true
}

launch_target_from_plist() {
  local plist="$1" p
  p="$(plist_value "$plist" "Program")"
  if [[ -z "$p" ]]; then
    p="$(plist_value "$plist" "ProgramArguments:0")"
  fi
  printf '%s' "$p"
}

app_version() {
  local app="$1" plist="$app/Contents/Info.plist" v
  [[ -f "$plist" ]] || { printf ''; return; }
  v="$(plist_value "$plist" "CFBundleShortVersionString")"
  [[ -z "$v" ]] && v="$(plist_value "$plist" "CFBundleVersion")"
  printf '%s' "$v"
}

folder_link() {
  local p="$1" hex
  if [[ "$p" == *.app || "$p" == *.app/ ]]; then
    p="${p%/}"
    p="$(/usr/bin/dirname "$p")"
  elif [[ ! -d "$p" ]]; then
    p="$(/usr/bin/dirname "$p")"
  fi
  [[ -d "$p" ]] || { printf ''; return; }
  hex="$(printf '%s' "$p" | /usr/bin/xxd -p | /usr/bin/tr -d '\n')"
  printf 'threatinspection-mac://folder/%s' "$hex"
}

tool_link() {
  printf 'threatinspection-mac://tool/%s' "$1"
}

# -----------------------------
# Install narrow report URL handler
# -----------------------------
install_link_helper() {
  local helper_root helper_app plist script_file lsregister
  helper_root="$USER_HOME/Library/Application Support/MeldingSoftware/Threat Inspection"
  helper_app="$helper_root/ThreatInspectionLink.app"
  plist="$helper_app/Contents/Info.plist"
  script_file="$WORK_DIR/ThreatInspectionLink.applescript"

  mkdir -p "$helper_root" || return 1

  cat > "$script_file" <<'APPLESCRIPT'
on open location theURL
    try
        if theURL starts with "threatinspection-mac://folder/" then
            set prefixText to "threatinspection-mac://folder/"
            set hexValue to text ((length of prefixText) + 1) thru -1 of theURL
            if hexValue is "" then return
            set targetPath to do shell script "/bin/echo " & quoted form of hexValue & " | /usr/bin/xxd -r -p"
            if targetPath is not "" then
                do shell script "/usr/bin/open " & quoted form of targetPath
            end if
            return
        end if

        if theURL starts with "threatinspection-mac://tool/" then
            set prefixText to "threatinspection-mac://tool/"
            set toolName to text ((length of prefixText) + 1) thru -1 of theURL
            if toolName ends with "/" then set toolName to text 1 thru -2 of toolName

            if toolName is "sharing" then
                do shell script "/usr/bin/open 'x-apple.systempreferences:com.apple.Sharing-Settings.extension' || /usr/bin/open -a 'System Settings'"
            else if toolName is "loginitems" then
                do shell script "/usr/bin/open 'x-apple.systempreferences:com.apple.LoginItems-Settings.extension' || /usr/bin/open -a 'System Settings'"
            else if toolName is "network" then
                do shell script "/usr/bin/open 'x-apple.systempreferences:com.apple.Network-Settings.extension' || /usr/bin/open -a 'System Settings'"
            else if toolName is "firewall" then
                do shell script "/usr/bin/open 'x-apple.systempreferences:com.apple.Network-Settings.extension' || /usr/bin/open -a 'System Settings'"
            else if toolName is "security" then
                do shell script "/usr/bin/open 'x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension' || /usr/bin/open -a 'System Settings'"
            else if toolName is "notifications" then
                do shell script "/usr/bin/open 'x-apple.systempreferences:com.apple.Notifications-Settings.extension' || /usr/bin/open -a 'System Settings'"
            else if toolName is "activity" then
                do shell script "/usr/bin/open -a 'Activity Monitor'"
            else if toolName is "profiles" then
                do shell script "/usr/bin/open 'x-apple.systempreferences:com.apple.Profiles-Settings.extension' || /usr/bin/open -a 'System Settings'"
            end if
        end if
    end try
end open location
APPLESCRIPT

  rm -rf "$helper_app"
  if ! /usr/bin/osacompile -o "$helper_app" "$script_file" >/dev/null 2>&1; then
    return 1
  fi

  /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier com.meldingsoftware.ThreatInspectionLink" "$plist" >/dev/null 2>&1 || \
    /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string com.meldingsoftware.ThreatInspectionLink" "$plist" >/dev/null 2>&1 || true
  /usr/libexec/PlistBuddy -c "Delete :CFBundleURLTypes" "$plist" >/dev/null 2>&1 || true
  /usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes array" "$plist" >/dev/null
  /usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0 dict" "$plist" >/dev/null
  /usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLName string com.meldingsoftware.threatinspection.mac" "$plist" >/dev/null
  /usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes array" "$plist" >/dev/null
  /usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string threatinspection-mac" "$plist" >/dev/null

  /usr/sbin/chown -R "$CONSOLE_USER":staff "$helper_root" >/dev/null 2>&1 || true

  lsregister="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
  if [[ -x "$lsregister" ]]; then
    sudo -u "$CONSOLE_USER" "$lsregister" -f "$helper_app" >/dev/null 2>&1 || true
  fi
  return 0
}

LINK_HELPER_READY=0
if install_link_helper; then
  LINK_HELPER_READY=1
fi

folder_link_safe() {
  [[ "$LINK_HELPER_READY" -eq 1 ]] || { printf ''; return; }
  folder_link "$1"
}
tool_link_safe() {
  [[ "$LINK_HELPER_READY" -eq 1 ]] || { printf ''; return; }
  tool_link "$1"
}

# -----------------------------
# User homes / installed apps
# -----------------------------
USER_HOMES=()
for d in /Users/*; do
  [[ -d "$d" ]] || continue
  case "$d" in
    /Users/Shared|/Users/Guest) continue ;;
  esac
  if [[ -d "$d/Library" ]]; then
    USER_HOMES[${#USER_HOMES[@]}]="$d"
  fi
done
if [[ ${#USER_HOMES[@]} -eq 0 ]]; then
  USER_HOMES[0]="$USER_HOME"
fi

APP_PATHS_FILE="$WORK_DIR/apps.txt"
: > "$APP_PATHS_FILE"
for root in /Applications /System/Applications; do
  [[ -d "$root" ]] || continue
  for app in "$root"/*.app; do
    [[ -d "$app" ]] && printf '%s\n' "$app" >> "$APP_PATHS_FILE"
  done
done
for home in "${USER_HOMES[@]}"; do
  [[ -d "$home/Applications" ]] || continue
  for app in "$home/Applications"/*.app; do
    [[ -d "$app" ]] && printf '%s\n' "$app" >> "$APP_PATHS_FILE"
  done
done
/usr/bin/sort -u "$APP_PATHS_FILE" -o "$APP_PATHS_FILE"

REMOTE_EVIDENCE="$WORK_DIR/remote.evidence"
PUP_EVIDENCE="$WORK_DIR/pup.evidence"
: > "$REMOTE_EVIDENCE"
: > "$PUP_EVIDENCE"

while IFS= read -r app; do
  [[ -n "$app" ]] || continue
  label="$(/usr/bin/basename "$app" .app)"
  version="$(app_version "$app")"
  if watchlist_match "$label $app" "$REMOTE_WATCHLIST"; then
    printf '%s%sInstalled%s%s%s%s\n' "$MATCH_NAME" "$SEP" "$SEP" "$app" "$SEP" "$version" >> "$REMOTE_EVIDENCE"
  fi
  if watchlist_match "$label $app" "$PUP_WATCHLIST"; then
    printf '%s%sInstalled%s%s%s%s\n' "$MATCH_NAME" "$SEP" "$SEP" "$app" "$SEP" "$version" >> "$PUP_EVIDENCE"
  fi
done < "$APP_PATHS_FILE"

# Process runtime watchlist evidence.
PS_FILE="$WORK_DIR/ps.txt"
/bin/ps -axo pid=,user=,command= -ww > "$PS_FILE" 2>/dev/null || true
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  if watchlist_match "$line" "$REMOTE_WATCHLIST"; then
    pid="$(printf '%s\n' "$line" | /usr/bin/awk '{print $1}')"
    printf '%s%sProcess%s%s%s%s\n' "$MATCH_NAME" "$SEP" "$SEP" "$pid" "$SEP" "$line" >> "$REMOTE_EVIDENCE"
  fi
  if watchlist_match "$line" "$PUP_WATCHLIST"; then
    pid="$(printf '%s\n' "$line" | /usr/bin/awk '{print $1}')"
    printf '%s%sProcess%s%s%s%s\n' "$MATCH_NAME" "$SEP" "$SEP" "$pid" "$SEP" "$line" >> "$PUP_EVIDENCE"
  fi
done < "$PS_FILE"

# -----------------------------
# SECTION 1: Remote Access
# -----------------------------
echo ""
echo "Inspecting Remote Access..."

REMOTE_SETTINGS_LINK="$(tool_link_safe sharing)"

remote_login="$(/usr/sbin/systemsetup -getremotelogin 2>/dev/null || true)"
if [[ "$remote_login" == *"On"* ]]; then
  add_finding remote Review "Remote Login (SSH): Enabled" "Confirm SSH access is expected." "$REMOTE_SETTINGS_LINK"
elif [[ "$remote_login" == *"Off"* ]]; then
  add_finding remote Good "Remote Login (SSH): Disabled" "" ""
else
  add_finding remote Info "Remote Login (SSH) state could not be read." "" "$REMOTE_SETTINGS_LINK"
fi

remote_events="$(/usr/sbin/systemsetup -getremoteappleevents 2>/dev/null || true)"
if [[ "$remote_events" == *"On"* ]]; then
  add_finding remote Review "Remote Apple Events: Enabled" "Confirm remote Apple Events are expected." "$REMOTE_SETTINGS_LINK"
elif [[ "$remote_events" == *"Off"* ]]; then
  add_finding remote Good "Remote Apple Events: Disabled" "" ""
else
  add_finding remote Info "Remote Apple Events state could not be read." "" "$REMOTE_SETTINGS_LINK"
fi

if /bin/launchctl print system/com.apple.screensharing >/dev/null 2>&1; then
  add_finding remote Review "Screen Sharing service: Loaded" "Screen Sharing is available through macOS Sharing settings; verify this is expected." "$REMOTE_SETTINGS_LINK"
else
  add_finding remote Good "Screen Sharing service: Not loaded" "" ""
fi

if /bin/launchctl print system/com.apple.RemoteManagement.agent >/dev/null 2>&1 || /usr/bin/pgrep -f '/ARDAgent.app/' >/dev/null 2>&1; then
  add_finding remote Review "Remote Management (Apple Remote Desktop): Enabled or active" "Verify Remote Management authorization in Sharing settings." "$REMOTE_SETTINGS_LINK"
else
  add_finding remote Good "Remote Management (Apple Remote Desktop): Not detected as active" "" ""
fi

REMOTE_PRODUCTS="$WORK_DIR/remote.products"
if [[ -s "$REMOTE_EVIDENCE" ]]; then
  /usr/bin/awk -F "$SEP" '{print $1}' "$REMOTE_EVIDENCE" | /usr/bin/sort -u > "$REMOTE_PRODUCTS"
else
  : > "$REMOTE_PRODUCTS"
fi

if [[ -s "$REMOTE_PRODUCTS" ]]; then
  while IFS= read -r product; do
    [[ -n "$product" ]] || continue
    installed_examples=""
    process_count=0
    first_path=""
    while IFS="$SEP" read -r p kind value extra; do
      [[ "$p" == "$product" ]] || continue
      if [[ "$kind" == "Installed" ]]; then
        [[ -z "$first_path" ]] && first_path="$value"
        if [[ -z "$installed_examples" ]]; then
          installed_examples="$value"
          [[ -n "$extra" ]] && installed_examples="$installed_examples (v$extra)"
        fi
      elif [[ "$kind" == "Process" ]]; then
        process_count=$((process_count + 1))
      fi
    done < "$REMOTE_EVIDENCE"

    detail=""
    [[ -n "$installed_examples" ]] && detail="Installed: $installed_examples"
    [[ "$process_count" -gt 0 ]] && detail="${detail}${detail:+ | }Processes: $process_count detected"
    detail="${detail}${detail:+ | }Presence does not prove malicious use; verify authorization."
    remote_link="$(tool_link_safe activity)"
    [[ -n "$first_path" ]] && remote_link="$(folder_link_safe "$first_path")"
    add_finding remote Warning "Known remote-access/RMM software detected: $product" "$detail" "$remote_link"
  done < "$REMOTE_PRODUCTS"
else
  add_finding remote Good "No installed/running matches were found in the built-in remote-access/RMM watchlist." "" ""
fi

write_section_console remote "Remote Access"

# -----------------------------
# SECTION 2: Programs & Login Items
# -----------------------------
echo ""
echo "Inspecting Programs & Login Items..."

PUP_PRODUCTS="$WORK_DIR/pup.products"
if [[ -s "$PUP_EVIDENCE" ]]; then
  /usr/bin/awk -F "$SEP" '{print $1}' "$PUP_EVIDENCE" | /usr/bin/sort -u > "$PUP_PRODUCTS"
else
  : > "$PUP_PRODUCTS"
fi

if [[ -s "$PUP_PRODUCTS" ]]; then
  while IFS= read -r product; do
    [[ -n "$product" ]] || continue
    details=""
    first_path=""
    count=0
    while IFS="$SEP" read -r p kind value extra; do
      [[ "$p" == "$product" ]] || continue
      count=$((count + 1))
      if [[ "$kind" == "Installed" && -z "$first_path" ]]; then
        first_path="$value"
        details="Installed: $value"
        [[ -n "$extra" ]] && details="$details (v$extra)"
      fi
    done < "$PUP_EVIDENCE"
    details="${details}${details:+ | }Evidence records: $count | Verify whether this software is wanted."
    link="$(tool_link_safe loginitems)"
    [[ -n "$first_path" ]] && link="$(folder_link_safe "$first_path")"
    add_finding programs Warning "PUP/PUA watchlist software detected: $product" "$details" "$link"
  done < "$PUP_PRODUCTS"
else
  add_finding programs Good "No installed/runtime matches were found in the built-in PUP/PUA watchlist." "" ""
fi

app_count="$(/usr/bin/wc -l < "$APP_PATHS_FILE" | /usr/bin/tr -d ' ')"
add_finding programs Info "$app_count application bundle(s) were enumerated from system and user Applications folders." "Normal applications are intentionally omitted from detailed output." ""

recent_apps=0
while IFS= read -r app; do
  [[ -d "$app" ]] || continue
  if /usr/bin/find "$app" -prune -mtime "-$RECENT_DAYS" -print 2>/dev/null | /usr/bin/grep -q .; then
    recent_apps=$((recent_apps + 1))
  fi
done < "$APP_PATHS_FILE"
add_finding programs Info "$recent_apps application bundle(s) have a modification time within the last $RECENT_DAYS days." "Modification time is context only; app updates can change it." ""

LOGIN_ITEMS_RAW="$(sudo -u "$CONSOLE_USER" /usr/bin/osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || true)"
if [[ -n "$LOGIN_ITEMS_RAW" ]]; then
  login_count=0
  oldifs="$IFS"
  IFS=','
  for item in $LOGIN_ITEMS_RAW; do
    IFS="$oldifs"
    item="$(printf '%s' "$item" | /usr/bin/sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -n "$item" ]] || { IFS=','; continue; }
    login_count=$((login_count + 1))
    if watchlist_match "$item" "$REMOTE_WATCHLIST"; then
      add_finding programs Warning "Login Item matches remote-access/RMM watchlist: $item" "Product: $MATCH_NAME" "$(tool_link_safe loginitems)"
    elif watchlist_match "$item" "$PUP_WATCHLIST"; then
      add_finding programs Warning "Login Item matches PUP/PUA watchlist: $item" "Product: $MATCH_NAME" "$(tool_link_safe loginitems)"
    else
      add_finding programs Info "Login Item: $item" "" ""
    fi
    IFS=','
  done
  IFS="$oldifs"
  add_finding programs Info "$login_count Login Item(s) were returned by System Events." "Background items managed by newer macOS Service Management may also appear in System Settings > General > Login Items." ""
else
  add_finding programs Info "Login Items could not be enumerated through System Events, or none were returned." "Review System Settings > General > Login Items when needed." "$(tool_link_safe loginitems)"
fi

if [[ -x /usr/bin/sfltool ]]; then
  btm_lines="$(/usr/bin/sfltool dumpbtm 2>/dev/null | /usr/bin/grep -c 'Name:' || true)"
  add_finding programs Info "Background Task Management database is available." "sfltool returned approximately $btm_lines named background-item record(s); LaunchAgents/Daemons are inspected separately below." "$(tool_link_safe loginitems)"
fi

write_section_console programs "Programs & Login Items"

# -----------------------------
# SECTION 3: LaunchAgents / Persistence
# -----------------------------
echo ""
echo "Inspecting LaunchAgents / Persistence..."

LAUNCH_PLISTS="$WORK_DIR/launch.plists"
: > "$LAUNCH_PLISTS"
for root in /Library/LaunchAgents /Library/LaunchDaemons; do
  [[ -d "$root" ]] || continue
  for p in "$root"/*.plist; do
    [[ -f "$p" ]] && printf '%s\n' "$p" >> "$LAUNCH_PLISTS"
  done
done
for home in "${USER_HOMES[@]}"; do
  root="$home/Library/LaunchAgents"
  [[ -d "$root" ]] || continue
  for p in "$root"/*.plist; do
    [[ -f "$p" ]] && printf '%s\n' "$p" >> "$LAUNCH_PLISTS"
  done
done
/usr/bin/sort -u "$LAUNCH_PLISTS" -o "$LAUNCH_PLISTS"

launch_total=0
launch_attention=0
while IFS= read -r plist; do
  [[ -f "$plist" ]] || continue
  launch_total=$((launch_total + 1))
  label="$(plist_value "$plist" "Label")"
  [[ -z "$label" ]] && label="$(/usr/bin/basename "$plist" .plist)"
  target="$(launch_target_from_plist "$plist")"
  combined="$label $plist $target"
  severity="Info"
  reason=""
  link="$(folder_link_safe "$plist")"

  if watchlist_match "$combined" "$REMOTE_WATCHLIST"; then
    severity="Warning"
    reason="Launch persistence matches remote-access/RMM watchlist: $MATCH_NAME"
  elif watchlist_match "$combined" "$PUP_WATCHLIST"; then
    severity="Warning"
    reason="Launch persistence matches PUP/PUA watchlist: $MATCH_NAME"
  elif [[ -n "$target" && ! -e "$target" && "$target" != /*.app/* ]]; then
    if is_user_writable_unusual "$target" || [[ "$target" == /tmp/* || "$target" == /private/var/tmp/* ]]; then
      severity="Review"
      reason="Launch target is missing from a user-writable/unusual path."
    fi
  elif [[ -n "$target" && -e "$target" ]]; then
    if is_user_writable_unusual "$target"; then
      signature_info "$target"
      if [[ "$SIG_STATUS" != "Valid" && "$SIG_STATUS" != "Signed" ]]; then
        severity="Review"
        reason="Launch target is in a user-writable/unusual path and is not code-signed."
      fi
    fi
  fi

  if [[ "$severity" == "Info" ]]; then
    continue
  fi
  launch_attention=$((launch_attention + 1))
  detail="Plist: $plist"
  [[ -n "$target" ]] && detail="$detail | Target: $target"
  [[ -n "$reason" ]] && detail="$detail | Reason: $reason"
  add_finding persistence "$severity" "Launch item: $label" "$detail" "$link"
done < "$LAUNCH_PLISTS"

add_finding persistence Info "$launch_total third-party/user LaunchAgent/LaunchDaemon plist(s) were enumerated outside /System/Library." "Only watchlist, missing unusual target, or unsigned unusual-path entries are detailed." ""
if [[ "$launch_attention" -eq 0 ]]; then
  add_finding persistence Good "No LaunchAgent/LaunchDaemon entry met the refined Warning/Review criteria." "" ""
fi

# Cron / at persistence context.
cron_text="$(/usr/bin/crontab -l -u "$CONSOLE_USER" 2>/dev/null || true)"
if [[ -n "$cron_text" ]]; then
  add_finding persistence Review "User crontab contains scheduled command(s)." "$cron_text" ""
else
  add_finding persistence Good "No user crontab entries were found for $CONSOLE_USER." "" ""
fi

if [[ -f /etc/rc.local ]]; then
  add_finding persistence Review "/etc/rc.local exists." "Legacy startup script: /etc/rc.local" "$(folder_link_safe /etc)"
fi

write_section_console persistence "LaunchAgents / Persistence"

# -----------------------------
# SECTION 4: Background Services / Processes
# -----------------------------
echo ""
echo "Inspecting Background Services / Processes..."

process_attention=0
process_candidates=0
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  case "$line" in
    *"/Users/"*|*"/tmp/"*|*"/private/var/tmp/"*)
      process_candidates=$((process_candidates + 1))
      pid="$(printf '%s\n' "$line" | /usr/bin/awk '{print $1}')"
      exe="$(/usr/sbin/lsof -a -p "$pid" -d txt -Fn 2>/dev/null | /usr/bin/sed -n 's/^n//p' | /usr/bin/head -n 1)"
      [[ -n "$exe" && -e "$exe" ]] || continue
      is_self_path "$exe" && continue

      if watchlist_match "$line $exe" "$REMOTE_WATCHLIST"; then
        # Already represented prominently in Remote Access.
        continue
      fi
      if watchlist_match "$line $exe" "$PUP_WATCHLIST"; then
        continue
      fi

      if is_user_writable_unusual "$exe"; then
        signature_info "$exe"
        if [[ "$SIG_STATUS" != "Valid" && "$SIG_STATUS" != "Signed" ]]; then
          process_attention=$((process_attention + 1))
          add_finding background Review "Process executable in user-writable/unusual path: $(/usr/bin/basename "$exe")" "PID: $pid | Path: $exe | Signature: $SIG_STATUS" "$(folder_link_safe "$exe")"
        fi
      fi
      ;;
  esac
done < "$PS_FILE"

add_finding background Info "$process_candidates running process command(s) referenced user-writable/temp paths and were evaluated with targeted filtering." "" ""
if [[ "$process_attention" -eq 0 ]]; then
  add_finding background Good "No non-watchlist running process met the unsigned/untrusted unusual-path criteria." "" ""
fi

if [[ -x /usr/bin/systemextensionsctl ]]; then
  SYS_EXT="$WORK_DIR/systemextensions.txt"
  /usr/bin/systemextensionsctl list > "$SYS_EXT" 2>/dev/null || true
  ext_count="$(/usr/bin/grep -E '^[[:space:]]*\*?[[:space:]]*[A-Z0-9]{10}[[:space:]]' "$SYS_EXT" 2>/dev/null | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
  [[ -z "$ext_count" ]] && ext_count=0
  add_finding background Info "$ext_count third-party/system extension record(s) were returned by systemextensionsctl." "System extensions can provide endpoint security, networking, USB, or other background functionality." ""
  while IFS= read -r line; do
    if watchlist_match "$line" "$REMOTE_WATCHLIST"; then
      add_finding background Warning "System extension matches remote-access/RMM watchlist: $MATCH_NAME" "$line" "$(tool_link_safe security)"
    elif watchlist_match "$line" "$PUP_WATCHLIST"; then
      add_finding background Warning "System extension matches PUP/PUA watchlist: $MATCH_NAME" "$line" "$(tool_link_safe security)"
    fi
  done < "$SYS_EXT"
fi

write_section_console background "Background Services / Processes"

# -----------------------------
# SECTION 5: Suspicious Files
# -----------------------------
echo ""
echo "Inspecting Suspicious Files..."

ARTIFACT_CANDIDATES="$WORK_DIR/artifact.candidates"
: > "$ARTIFACT_CANDIDATES"

append_depth2() {
  local root="$1" a b
  [[ -d "$root" ]] || return
  for a in "$root"/*; do
    [[ -e "$a" ]] || continue
    printf '%s\n' "$a" >> "$ARTIFACT_CANDIDATES"
    if [[ -d "$a" ]]; then
      case "$a" in
        */Caches|*/Cache|*/node_modules|*/Containers|*/Group\ Containers) continue ;;
      esac
      for b in "$a"/*; do
        [[ -e "$b" ]] && printf '%s\n' "$b" >> "$ARTIFACT_CANDIDATES"
      done
    fi
  done
}

for home in "${USER_HOMES[@]}"; do
  append_depth2 "$home/Downloads"
  append_depth2 "$home/Desktop"
  append_depth2 "$home/Library/Application Support"
  append_depth2 "$home/Library/LaunchAgents"
done
append_depth2 "/Applications"
append_depth2 "/Library/Application Support"
append_depth2 "/Library/LaunchAgents"
append_depth2 "/Library/LaunchDaemons"

/usr/bin/sort -u "$ARTIFACT_CANDIDATES" -o "$ARTIFACT_CANDIDATES"
ARTIFACT_HITS="$WORK_DIR/artifact.hits"
: > "$ARTIFACT_HITS"

while IFS= read -r p; do
  [[ -e "$p" ]] || continue
  is_self_path "$p" && continue
  if watchlist_match "$p" "$REMOTE_WATCHLIST"; then
    printf 'Remote Access%s%s%s%s\n' "$SEP" "$MATCH_NAME" "$SEP" "$p" >> "$ARTIFACT_HITS"
  elif watchlist_match "$p" "$PUP_WATCHLIST"; then
    printf 'PUP/PUA%s%s%s%s\n' "$SEP" "$MATCH_NAME" "$SEP" "$p" >> "$ARTIFACT_HITS"
  fi
done < "$ARTIFACT_CANDIDATES"

if [[ -s "$ARTIFACT_HITS" ]]; then
  ARTIFACT_GROUPS="$WORK_DIR/artifact.groups"
  /usr/bin/awk -F "$SEP" '{print $1 FS $2}' "$ARTIFACT_HITS" | /usr/bin/sort -u > "$ARTIFACT_GROUPS"
  while IFS="$SEP" read -r kind product; do
    [[ -n "$kind" && -n "$product" ]] || continue
    count=0
    examples=""
    first=""
    while IFS="$SEP" read -r hk hp path; do
      [[ "$hk" == "$kind" && "$hp" == "$product" ]] || continue
      count=$((count + 1))
      [[ -z "$first" ]] && first="$path"
      if (( count <= 5 )); then
        examples="${examples}${examples:+ | }$path"
      fi
    done < "$ARTIFACT_HITS"
    omitted=$((count - 5))
    detail="Artifacts found: $count | Examples: $examples"
    (( omitted > 0 )) && detail="$detail | $omitted additional related artifact(s) omitted."
    if [[ "$kind" == "Remote Access" ]]; then
      detail="$detail | Related artifacts corroborate remote-access software or remnants; verify authorization."
      add_finding files Warning "Remote Access artifacts detected: $product ($count related item(s))" "$detail" "$(folder_link_safe "$first")"
    else
      add_finding files Warning "PUP/PUA artifacts detected: $product ($count related item(s))" "$detail" "$(folder_link_safe "$first")"
    fi
  done < "$ARTIFACT_GROUPS"
else
  add_finding files Good "No remote-access/RMM or PUP/PUA artifact paths were found in the selected locations." "" ""
fi

RECENT_CANDIDATES="$WORK_DIR/recent.files"
: > "$RECENT_CANDIDATES"
for home in "${USER_HOMES[@]}"; do
  for root in "$home/Downloads" "$home/Desktop" "$home/Library/LaunchAgents"; do
    [[ -d "$root" ]] || continue
    /usr/bin/find "$root" -type f -mtime "-$RECENT_DAYS" \( \
      -name '*.command' -o -name '*.sh' -o -name '*.zsh' -o -name '*.bash' -o \
      -name '*.py' -o -name '*.pl' -o -name '*.scpt' -o -name '*.pkg' -o \
      -name '*.dmg' -o -name '*.js' -o -name '*.jar' \
    \) -print 2>/dev/null >> "$RECENT_CANDIDATES"
  done
done
for root in /tmp /private/var/tmp; do
  [[ -d "$root" ]] || continue
  /usr/bin/find "$root" -type f -mtime "-$RECENT_DAYS" \( \
    -name '*.command' -o -name '*.sh' -o -name '*.zsh' -o -name '*.bash' -o \
    -name '*.py' -o -name '*.pl' -o -name '*.scpt' \
  \) -print 2>/dev/null >> "$RECENT_CANDIDATES"
done
/usr/bin/sort -u "$RECENT_CANDIDATES" -o "$RECENT_CANDIDATES"

recent_evaluated=0
recent_review=0
while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  is_self_path "$f" && continue
  recent_evaluated=$((recent_evaluated + 1))
  if watchlist_match "$f" "$REMOTE_WATCHLIST" || watchlist_match "$f" "$PUP_WATCHLIST"; then
    continue
  fi

  ext="${f##*.}"
  severity=""
  reason=""
  case "$ext" in
    command|sh|zsh|bash|py|pl|scpt|js)
      # Scripts in Downloads/Desktop/Temp warrant review; scripts in LaunchAgents are handled
      # by the persistence section and are not duplicated here unless in other high-risk roots.
      case "$f" in
        */Downloads/*|*/Desktop/*|/tmp/*|/private/var/tmp/*)
          severity="Review"
          reason="Recently modified script in Downloads/Desktop/Temp."
          ;;
      esac
      ;;
    pkg)
      if ! /usr/sbin/spctl -a -vv -t install "$f" >/dev/null 2>&1; then
        severity="Review"
        reason="Recent installer package was not accepted by Gatekeeper assessment."
      fi
      ;;
    dmg)
      # Disk images aren't directly code-signed like executable bundles; retain only as context.
      ;;
    jar)
      case "$f" in
        */Downloads/*|*/Desktop/*)
          severity="Review"
          reason="Recent Java archive in a user download/desktop location."
          ;;
      esac
      ;;
  esac

  if [[ -n "$severity" ]]; then
    recent_review=$((recent_review + 1))
    add_finding files "$severity" "$f" "Modified: $(file_mtime_text "$f") | Size: $(file_size_kb "$f") KB | $reason" "$(folder_link_safe "$f")"
  fi
done < "$RECENT_CANDIDATES"

add_finding files Info "$recent_evaluated recent script/installer/archive file(s) were evaluated from selected user-writable locations within the last $RECENT_DAYS days." "This is a targeted review, not an antivirus scan." ""
if [[ "$recent_review" -eq 0 ]]; then
  add_finding files Good "No recent non-watchlist file met the targeted Review criteria." "" ""
fi

write_section_console files "Suspicious Files"

# -----------------------------
# SECTION 6: Browsers
# -----------------------------
echo ""
echo "Inspecting Browsers..."

browser_ext_count=0
browser_profile_count=0
notification_count=0
notification_attention=0

chromium_notification_origins() {
  local prefs="$1"
  /usr/bin/plutil -extract profile.content_settings.exceptions.notifications xml1 -o - "$prefs" 2>/dev/null | /usr/bin/awk '
    /<dict>/ { depth++; next }
    /<\/dict>/ { depth--; want=0; next }
    depth==1 && /<key>/ {
      line=$0
      sub(/^.*<key>/,"",line); sub(/<\/key>.*$/,"",line)
      origin=line
      gsub(/&amp;/,"&",origin); gsub(/&lt;/,"<",origin); gsub(/&gt;/,">",origin)
      next
    }
    depth==2 && /<key>setting<\/key>/ { want=1; next }
    want==1 && /<integer>1<\/integer>/ { print origin; want=0; next }
    want==1 && /<(integer|string)>/ { want=0 }
  ' 2>/dev/null
}

inspect_chromium_root() {
  local browser="$1" root="$2" profile prefs extroot extid versiondir manifest name version origin sev reason
  [[ -d "$root" ]] || return
  for profile in "$root/Default" "$root"/Profile\ *; do
    [[ -d "$profile" ]] || continue
    browser_profile_count=$((browser_profile_count + 1))
    prefs="$profile/Preferences"

    extroot="$profile/Extensions"
    if [[ -d "$extroot" ]]; then
      for extid in "$extroot"/*; do
        [[ -d "$extid" ]] || continue
        versiondir="$(/bin/ls -1dt "$extid"/* 2>/dev/null | /usr/bin/head -n 1)"
        [[ -d "$versiondir" ]] || continue
        manifest="$versiondir/manifest.json"
        [[ -f "$manifest" ]] || continue
        name="$(/usr/bin/plutil -extract name raw "$manifest" 2>/dev/null || true)"
        version="$(/usr/bin/plutil -extract version raw "$manifest" 2>/dev/null || true)"
        [[ -z "$name" || "$name" == __MSG_* ]] && name="$extid"
        browser_ext_count=$((browser_ext_count + 1))
        add_finding browsers Info "$browser extension: $name" "Profile: $(/usr/bin/basename "$profile") | ID: $(/usr/bin/basename "$extid") | Version: $version" ""
      done
    fi

    if [[ -f "$prefs" ]]; then
      homepage="$(/usr/bin/plutil -extract homepage raw "$prefs" 2>/dev/null || true)"
      [[ -n "$homepage" ]] && add_finding browsers Info "$browser homepage" "Profile: $(/usr/bin/basename "$profile") | $homepage" ""

      while IFS= read -r origin; do
        [[ -n "$origin" ]] || continue
        notification_count=$((notification_count + 1))
        sev="Review"
        reason="Notifications are allowed; confirm this site is expected."
        if watchlist_match "$origin" "$PUP_WATCHLIST"; then
          sev="Warning"
          reason="Allowed notification origin matches PUP/PUA watchlist: $MATCH_NAME"
        elif [[ "$origin" == http://* ]]; then
          sev="Warning"
          reason="Notifications are allowed from a non-HTTPS origin."
        elif [[ "$origin" == *"xn--"* ]]; then
          sev="Warning"
          reason="Notification host uses Punycode; verify the domain carefully."
        fi
        notification_attention=$((notification_attention + 1))
        add_finding browsers "$sev" "$browser allowed notification: $origin" "$reason" "$(tool_link_safe notifications)"
      done < <(chromium_notification_origins "$prefs")
    fi
  done
}

inspect_chromium_root "Chrome" "$USER_HOME/Library/Application Support/Google/Chrome"
inspect_chromium_root "Edge" "$USER_HOME/Library/Application Support/Microsoft Edge"
inspect_chromium_root "Brave" "$USER_HOME/Library/Application Support/BraveSoftware/Brave-Browser"
inspect_chromium_root "Vivaldi" "$USER_HOME/Library/Application Support/Vivaldi"
inspect_chromium_root "Opera" "$USER_HOME/Library/Application Support/com.operasoftware.Opera"
inspect_chromium_root "Opera GX" "$USER_HOME/Library/Application Support/com.operasoftware.OperaGX"

# Firefox notifications via sqlite3, using a copy to avoid profile DB locks.
FF_ROOT="$USER_HOME/Library/Application Support/Firefox/Profiles"
if [[ -d "$FF_ROOT" ]]; then
  for profile in "$FF_ROOT"/*; do
    [[ -d "$profile" ]] || continue
    browser_profile_count=$((browser_profile_count + 1))
    db="$profile/permissions.sqlite"
    if [[ -f "$db" && -x /usr/bin/sqlite3 ]]; then
      copy="$WORK_DIR/firefox-$(/usr/bin/basename "$profile").sqlite"
      /bin/cp "$db" "$copy" 2>/dev/null || true
      if [[ -f "$copy" ]]; then
        while IFS='|' read -r origin perm; do
          [[ -n "$origin" ]] || continue
          notification_count=$((notification_count + 1))
          sev="Review"
          reason="Firefox desktop notifications are allowed; confirm this site is expected."
          if watchlist_match "$origin" "$PUP_WATCHLIST"; then
            sev="Warning"
            reason="Allowed notification origin matches PUP/PUA watchlist: $MATCH_NAME"
          elif [[ "$origin" == http://* ]]; then
            sev="Warning"
            reason="Notifications are allowed from a non-HTTPS origin."
          elif [[ "$origin" == *"xn--"* ]]; then
            sev="Warning"
            reason="Notification host uses Punycode; verify the domain carefully."
          fi
          notification_attention=$((notification_attention + 1))
          add_finding browsers "$sev" "Firefox allowed notification: $origin" "$reason" "$(tool_link_safe notifications)"
        done < <(/usr/bin/sqlite3 -separator '|' "$copy" "SELECT origin, permission FROM moz_perms WHERE type='desktop-notification' AND permission=1;" 2>/dev/null || true)
      fi
    fi

    extjson="$profile/extensions.json"
    if [[ -f "$extjson" ]]; then
      # Full Firefox extension parsing is intentionally omitted to avoid requiring jq/Python.
      add_finding browsers Info "Firefox profile detected: $(/usr/bin/basename "$profile")" "extensions.json is present; notification permissions were queried with sqlite3 when available." ""
    fi
  done
fi

if [[ "$notification_count" -eq 0 ]]; then
  add_finding browsers Good "No allowed website-notification origins were found in readable Chromium/Firefox profiles." "" ""
fi
add_finding browsers Info "$browser_ext_count Chromium extension record(s) were enumerated across $browser_profile_count readable browser profile(s)." "" ""
add_finding browsers Info "Safari automated coverage is intentionally limited by macOS privacy/TCC controls." "Review Safari website permissions and System Settings > Notifications manually when a browser-specific concern exists." "$(tool_link_safe notifications)"

write_section_console browsers "Browsers"

# -----------------------------
# SECTION 7: Network
# -----------------------------
echo ""
echo "Inspecting Network..."

NETWORK_LINK="$(tool_link_safe network)"
FIREWALL_LINK="$(tool_link_safe firewall)"

PROXY_OUT="$WORK_DIR/proxy.txt"
/usr/sbin/scutil --proxy > "$PROXY_OUT" 2>/dev/null || true
proxy_enabled=0
if /usr/bin/grep -Eq '(HTTPEnable|HTTPSEnable|SOCKSEnable) : 1' "$PROXY_OUT"; then
  proxy_enabled=1
fi
if [[ "$proxy_enabled" -eq 1 ]]; then
  proxy_summary="$(/usr/bin/grep -E '(HTTPEnable|HTTPSEnable|SOCKSEnable|HTTPProxy|HTTPSProxy|SOCKSProxy|HTTPPort|HTTPSPort|SOCKSPort)' "$PROXY_OUT" | /usr/bin/tr '\n' ' ' | /usr/bin/sed 's/[[:space:]][[:space:]]*/ /g')"
  add_finding network Review "Network proxy configuration is enabled." "$proxy_summary" "$NETWORK_LINK"
else
  add_finding network Good "No HTTP/HTTPS/SOCKS proxy is enabled in the active System Configuration proxy state." "" ""
fi

DNS_OUT="$WORK_DIR/dns.txt"
/usr/sbin/scutil --dns > "$DNS_OUT" 2>/dev/null || true
dns_servers="$(/usr/bin/grep 'nameserver\[[0-9]*\]' "$DNS_OUT" | /usr/bin/sed 's/.*: //' | /usr/bin/sort -u | /usr/bin/paste -sd ', ' -)"
[[ -n "$dns_servers" ]] && add_finding network Info "DNS server(s): $dns_servers" "" ""

active_ifaces="$(/sbin/ifconfig -lu 2>/dev/null || true)"
[[ -n "$active_ifaces" ]] && add_finding network Info "Active network interface(s): $active_ifaces" "" ""
utuns="$(printf '%s\n' "$active_ifaces" | /usr/bin/tr ' ' '\n' | /usr/bin/grep '^utun' | /usr/bin/paste -sd ', ' - || true)"
[[ -n "$utuns" ]] && add_finding network Info "VPN/tunnel interface(s) detected: $utuns" "utun interfaces can be created by VPNs, privacy software, and Apple networking services." ""

HOSTS_CUSTOM="$WORK_DIR/hosts.custom"
: > "$HOSTS_CUSTOM"
if [[ -f /etc/hosts ]]; then
  /usr/bin/awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
    {
      line=$0
      gsub(/^[[:space:]]+|[[:space:]]+$/,"",line)
      if (line ~ /(^|[[:space:]])localhost([[:space:]]|$)/) next
      if (line ~ /(^|[[:space:]])broadcasthost([[:space:]]|$)/) next
      print line
    }
  ' /etc/hosts > "$HOSTS_CUSTOM"
fi
if [[ -s "$HOSTS_CUSTOM" ]]; then
  while IFS= read -r line; do
    add_finding network Review "Hosts: $line" "Confirm this redirect/block is expected." "$(folder_link_safe /etc)"
  done < "$HOSTS_CUSTOM"
else
  add_finding network Good "No custom hosts-file redirects were found." "" ""
fi

SOCKETFW="/usr/libexec/ApplicationFirewall/socketfilterfw"
if [[ -x "$SOCKETFW" ]]; then
  fw_state="$("$SOCKETFW" --getglobalstate 2>/dev/null || true)"
  if [[ "$fw_state" == *"enabled"* ]]; then
    add_finding network Good "macOS Application Firewall: Enabled" "" "$FIREWALL_LINK"
  else
    add_finding network Review "macOS Application Firewall: Disabled or state unavailable" "$fw_state" "$FIREWALL_LINK"
  fi

  stealth="$("$SOCKETFW" --getstealthmode 2>/dev/null || true)"
  if [[ "$stealth" == *"enabled"* ]]; then
    add_finding network Good "Firewall stealth mode: Enabled" "" "$FIREWALL_LINK"
  else
    add_finding network Info "Firewall stealth mode: Disabled or state unavailable" "$stealth" "$FIREWALL_LINK"
  fi

  FW_APPS="$WORK_DIR/firewall.apps"
  "$SOCKETFW" --listapps > "$FW_APPS" 2>/dev/null || true
  fw_review=0
  while IFS= read -r line; do
    path="$(printf '%s\n' "$line" | /usr/bin/sed -n 's/^[^:]*: \(.*\) ( .*$/\1/p')"
    [[ -z "$path" ]] && path="$(printf '%s\n' "$line" | /usr/bin/sed -n 's/^[^:]*: //p')"
    [[ "$path" == /* && -e "$path" ]] || continue
    if is_user_writable_unusual "$path"; then
      signature_info "$path"
      if [[ "$SIG_STATUS" != "Valid" && "$SIG_STATUS" != "Signed" ]]; then
        fw_review=$((fw_review + 1))
        add_finding network Review "Firewall application in user-writable/unusual path: $(/usr/bin/basename "$path")" "Path: $path | Signature: $SIG_STATUS" "$FIREWALL_LINK"
      fi
    fi
  done < "$FW_APPS"
  add_finding network Info "$fw_review firewall application entry/entries met the unsigned unusual-path Review criteria." "" ""
fi

CONN_OUT="$WORK_DIR/connections.txt"
/usr/sbin/lsof -nP -iTCP -sTCP:ESTABLISHED > "$CONN_OUT" 2>/dev/null || true
conn_count="$(/usr/bin/tail -n +2 "$CONN_OUT" 2>/dev/null | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
[[ -z "$conn_count" ]] && conn_count=0
add_finding network Info "$conn_count established TCP connection(s) were captured at inspection time." "Connections are not individually listed unless tied to a watchlist process." ""

conn_watch=0
while IFS= read -r line; do
  if watchlist_match "$line" "$REMOTE_WATCHLIST"; then
    conn_watch=$((conn_watch + 1))
    add_finding network Warning "Established connection owned by remote-access/RMM watchlist process: $MATCH_NAME" "$line" "$(tool_link_safe activity)"
  elif watchlist_match "$line" "$PUP_WATCHLIST"; then
    conn_watch=$((conn_watch + 1))
    add_finding network Warning "Established connection owned by PUP/PUA watchlist process: $MATCH_NAME" "$line" "$(tool_link_safe activity)"
  fi
done < "$CONN_OUT"
if [[ "$conn_watch" -eq 0 ]]; then
  add_finding network Good "No established TCP connection line matched the built-in remote-access or PUP/PUA watchlists." "" ""
fi

write_section_console network "Network"

# -----------------------------
# SECTION 8: macOS Security
# -----------------------------
echo ""
echo "Inspecting macOS Security..."

SECURITY_LINK="$(tool_link_safe security)"
SECURITY_PRODUCTS=()

# Built-in XProtect is part of macOS; include as baseline provider.
SECURITY_PRODUCTS[${#SECURITY_PRODUCTS[@]}]="Apple XProtect"

detect_security_app() {
  local display="$1" pattern="$2" app
  while IFS= read -r app; do
    [[ -n "$app" ]] || continue
    if [[ "$(basename "$app")" =~ $pattern ]]; then
      SECURITY_PRODUCTS[${#SECURITY_PRODUCTS[@]}]="$display"
      add_finding security Info "Third-party security software detected: $display" "Application: $app" "$(folder_link_safe "$app")"
      return
    fi
  done < "$APP_PATHS_FILE"
}

detect_security_app "Malwarebytes" 'Malwarebytes'
detect_security_app "Microsoft Defender" 'Microsoft Defender'
detect_security_app "Norton" 'Norton'
detect_security_app "Bitdefender" 'Bitdefender'
detect_security_app "Sophos" 'Sophos'
detect_security_app "ESET" 'ESET'
detect_security_app "McAfee" 'McAfee'
detect_security_app "Avast" 'Avast'
detect_security_app "AVG" 'AVG'
detect_security_app "Trend Micro" 'Trend Micro'
detect_security_app "Intego" 'Intego'
detect_security_app "SentinelOne" 'Sentinel'
detect_security_app "CrowdStrike Falcon" 'Falcon'

gatekeeper="$(/usr/sbin/spctl --status 2>/dev/null || true)"
if [[ "$gatekeeper" == *"enabled"* ]]; then
  add_finding security Good "Gatekeeper assessments: Enabled" "$gatekeeper" "$SECURITY_LINK"
else
  add_finding security Warning "Gatekeeper assessments: Disabled or state unavailable" "$gatekeeper" "$SECURITY_LINK"
fi

sip="$(/usr/bin/csrutil status 2>/dev/null || true)"
if [[ "$sip" == *"enabled"* ]]; then
  add_finding security Good "System Integrity Protection (SIP): Enabled" "$sip" "$SECURITY_LINK"
elif [[ "$sip" == *"disabled"* ]]; then
  add_finding security Warning "System Integrity Protection (SIP): Disabled" "$sip" "$SECURITY_LINK"
else
  add_finding security Info "System Integrity Protection (SIP) state could not be determined." "$sip" "$SECURITY_LINK"
fi

fv="$(/usr/bin/fdesetup status 2>/dev/null || true)"
if [[ "$fv" == *"FileVault is On"* ]]; then
  add_finding security Good "FileVault: On" "$fv" "$SECURITY_LINK"
elif [[ "$fv" == *"FileVault is Off"* ]]; then
  add_finding security Review "FileVault: Off" "Disk encryption is not enabled for the startup volume." "$SECURITY_LINK"
else
  add_finding security Info "FileVault state could not be fully determined." "$fv" "$SECURITY_LINK"
fi

xprotect_version=""
for plist in \
  "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" \
  "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" \
  "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"; do
  if [[ -f "$plist" ]]; then
    xprotect_version="$(plist_value "$plist" "CFBundleShortVersionString")"
    [[ -z "$xprotect_version" ]] && xprotect_version="$(plist_value "$plist" "CFBundleVersion")"
    [[ -n "$xprotect_version" ]] && break
  fi
done
if [[ -n "$xprotect_version" ]]; then
  add_finding security Good "Apple XProtect component detected" "Version: $xprotect_version" "$SECURITY_LINK"
else
  add_finding security Info "Apple XProtect version path was not resolved by this inspection." "XProtect is a built-in macOS malware defense; component locations can vary by macOS release." "$SECURITY_LINK"
fi

mrt_version=""
for plist in \
  "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist" \
  "/System/Library/CoreServices/MRT.app/Contents/Info.plist"; do
  if [[ -f "$plist" ]]; then
    mrt_version="$(plist_value "$plist" "CFBundleShortVersionString")"
    [[ -z "$mrt_version" ]] && mrt_version="$(plist_value "$plist" "CFBundleVersion")"
    [[ -n "$mrt_version" ]] && break
  fi
done
[[ -n "$mrt_version" ]] && add_finding security Info "Apple malware-remediation component detected (MRT)" "Version: $mrt_version" "$SECURITY_LINK"

auto_check="$(/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || true)"
if [[ "$auto_check" == "0" ]]; then
  add_finding security Review "Automatic software-update checks: Disabled" "" "$SECURITY_LINK"
elif [[ "$auto_check" == "1" ]]; then
  add_finding security Good "Automatic software-update checks: Enabled" "" "$SECURITY_LINK"
else
  add_finding security Info "Automatic software-update check preference is not explicitly configured." "macOS may be using the system default." "$SECURITY_LINK"
fi

config_data="$(/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null || true)"
critical_updates="$(/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || true)"
if [[ "$config_data" == "0" || "$critical_updates" == "0" ]]; then
  add_finding security Review "Automatic security-data/critical update installation is disabled by preference." "ConfigDataInstall=$config_data | CriticalUpdateInstall=$critical_updates" "$SECURITY_LINK"
elif [[ "$config_data" == "1" || "$critical_updates" == "1" ]]; then
  add_finding security Good "Automatic security-data/critical update installation is enabled." "ConfigDataInstall=${config_data:-default} | CriticalUpdateInstall=${critical_updates:-default}" "$SECURITY_LINK"
else
  add_finding security Info "Security-data/critical update preferences are not explicitly configured." "macOS may be using system defaults." "$SECURITY_LINK"
fi

profiles_status="$(/usr/bin/profiles status -type enrollment 2>/dev/null || true)"
if [[ -n "$profiles_status" ]]; then
  add_finding security Info "Device management enrollment status captured." "$profiles_status" "$(tool_link_safe profiles)"
fi

# Unique security product list for the top Antivirus card.
SECURITY_PRODUCTS_FILE="$WORK_DIR/security.products"
printf '%s\n' "${SECURITY_PRODUCTS[@]}" | /usr/bin/awk 'NF' | /usr/bin/sort -u > "$SECURITY_PRODUCTS_FILE"
ANTIVIRUS_SUMMARY="$(/usr/bin/awk 'NF { if (n++) printf " + "; printf "%s", $0 } END { print "" }' "$SECURITY_PRODUCTS_FILE" 2>/dev/null)"
[[ -z "$ANTIVIRUS_SUMMARY" ]] && ANTIVIRUS_SUMMARY="Apple XProtect"

write_section_console security "macOS Security"

# -----------------------------
# Build report
# -----------------------------
INFO_COUNT="$(count_status Info)"
GOOD_COUNT="$(count_status Good)"
REVIEW_COUNT="$(count_status Review)"
WARNING_COUNT="$(count_status Warning)"
COMPLETED_AT="$(/bin/date '+%Y-%m-%d %H:%M:%S')"

{
cat <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
HTML
printf '<title>Threat Inspection Report - %s</title>\n' "$(html_escape "$HOSTNAME_SHORT")"
cat <<'HTML'
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#050608;color:#f5f7fb;margin:0;padding:0}
.page{max-width:1100px;margin:0 auto;padding:24px 16px 40px}
.title{font-size:30px;font-weight:700;margin-bottom:4px;color:#fff}
.subtitle{font-size:14px;color:#a0a4b8;margin-bottom:20px}
.summary-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:18px}
@media(max-width:900px){.summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:520px){.summary-grid{grid-template-columns:1fr}}
.card{background:radial-gradient(circle at top left,#17223b,#090b11);border-radius:12px;padding:12px 14px;border:1px solid #1b2338;box-shadow:0 6px 18px rgba(0,0,0,.6)}
.card-info{border-color:#244f80}.card-good{border-color:#225c3c}.card-review{border-color:#80621f}.card-warning{border-color:#7a2b32}.card-antivirus{border-color:#3f3d78}
.card-info .card-value{color:#7fc4ff}.card-good .card-value{color:#77db9d}.card-review .card-value{color:#f0c969}.card-warning .card-value{color:#ff8a92}
.card-label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#7c829a;margin-bottom:4px}
.card-value{font-size:15px;font-weight:600;color:#f5f7fb;overflow-wrap:anywhere}.card-meta{font-size:12px;color:#8f95ad;margin-top:2px;overflow-wrap:anywhere}
.status-row{margin:16px 0 22px;display:flex;flex-wrap:wrap;gap:6px}
.status-pill,.section-status-pill,.finding-status{font-size:12px;padding:4px 8px;border-radius:999px;border:1px solid transparent;background:rgba(20,25,40,.95);text-decoration:none;display:inline-block;white-space:nowrap}
.status-good{background:rgba(34,92,60,.26);color:#77db9d;border-color:#225c3c}
.status-review{background:rgba(128,98,31,.28);color:#f0c969;border-color:#80621f}
.status-warning{background:rgba(122,43,50,.30);color:#ff8a92;border-color:#7a2b32}
.status-info{background:rgba(36,79,128,.26);color:#7fc4ff;border-color:#244f80}
.section{border-radius:12px;border:1px solid #1c2336;margin-bottom:10px;overflow:hidden;background:rgba(10,12,20,.96);box-shadow:0 5px 14px rgba(0,0,0,.55);scroll-margin-top:16px}
.section-header{display:flex;align-items:center;justify-content:space-between;padding:10px 12px;cursor:pointer;background:linear-gradient(90deg,rgba(31,45,85,.9),rgba(16,23,42,.9))}
.section-header:hover{background:linear-gradient(90deg,rgba(45,65,120,.95),rgba(18,26,48,.9))}
.section-left{display:flex;align-items:center;gap:8px}.section-icon{font-size:13px;width:18px;text-align:center;color:#9fa6c6}.section-title{font-size:14px;font-weight:600;color:#f5f7ff}
.section-body{padding:10px 12px 12px;display:block}.section-summary{font-size:13px;color:#b4bad6;margin:0 0 10px}
.findings{display:flex;flex-direction:column;gap:6px;max-height:540px;overflow:auto;padding-right:2px}
.finding{display:grid;grid-template-columns:86px 1fr;gap:8px;align-items:start;background:#05070f;border:1px solid #12182c;border-radius:8px;padding:8px}
.finding-main{min-width:0}.finding-text{font-family:"SFMono-Regular","Menlo","Monaco",monospace;font-size:12px;color:#e6e9f3;white-space:pre-wrap;word-break:break-word}
.finding-detail{margin-top:4px;font-family:"SFMono-Regular","Menlo","Monaco",monospace;font-size:11px;color:#8f95ad;white-space:pre-wrap;word-break:break-word}
.legend{font-size:12px;color:#9298af;margin:-8px 0 18px}.footer{font-size:12px;color:#737995;margin-top:20px;border-top:1px solid #181e32;padding-top:10px;line-height:1.5}
</style>
<script>
function toggleSection(id){var body=document.getElementById(id),icon=document.getElementById(id+"-icon");if(!body)return;if(body.style.display==="none"){body.style.display="block";if(icon)icon.textContent="v"}else{body.style.display="none";if(icon)icon.textContent=">"}}
</script>
</head>
<body>
<div class="page">
HTML
printf '<div class="title">Malicious Threat Inspection</div>\n'
printf '<div class="subtitle">%s - Threat Inspection v%s for macOS - technician inspection</div>\n' "$(html_escape "$STARTED_AT")" "$VERSION"
printf '<div class="summary-grid">\n'
printf '<div class="card card-info"><div class="card-label">Info</div><div class="card-value">%s</div><div class="card-meta">Inventory/context findings</div></div>\n' "$INFO_COUNT"
printf '<div class="card card-good"><div class="card-label">Good</div><div class="card-value">%s</div><div class="card-meta">Expected security-state findings</div></div>\n' "$GOOD_COUNT"
printf '<div class="card card-review"><div class="card-label">Review</div><div class="card-value">%s</div><div class="card-meta">Findings requiring technician review</div></div>\n' "$REVIEW_COUNT"
printf '<div class="card card-warning"><div class="card-label">Warning</div><div class="card-value">%s</div><div class="card-meta">Stronger-risk findings</div></div>\n' "$WARNING_COUNT"
printf '<div class="card card-antivirus"><div class="card-label">Antivirus</div><div class="card-value">%s</div><div class="card-meta">Built-in and detected security software</div></div>\n' "$(html_escape "$ANTIVIRUS_SUMMARY")"
printf '</div>\n'
printf '<div class="legend">Info = inventory/context &nbsp; | &nbsp; Good = expected security state &nbsp; | &nbsp; Review = verify legitimacy &nbsp; | &nbsp; Warning = stronger risk indicator</div>\n'
printf '<div class="status-row">\n'

i=0
while (( i < ${#SECTION_IDS[@]} )); do
  sid="${SECTION_IDS[$i]}"
  title="${SECTION_TITLES[$i]}"
  st="$(section_status "$WORK_DIR/$sid.findings")"
  # Browser coverage remains informational when it has no Review/Warning.
  if [[ "$sid" == "browsers" && "$st" != "Review" && "$st" != "Warning" ]]; then st="Info"; fi
  printf '<a class="status-pill status-%s" href="#section-%s">%s - %s</a>\n' "$(printf '%s' "$st" | /usr/bin/tr '[:upper:]' '[:lower:]')" "$sid" "$(html_escape "$title")" "$st"
  i=$((i + 1))
done
printf '</div>\n'

i=0
while (( i < ${#SECTION_IDS[@]} )); do
  sid="${SECTION_IDS[$i]}"
  title="${SECTION_TITLES[$i]}"
  summary="${SECTION_SUMMARIES[$i]}"
  st="$(section_status "$WORK_DIR/$sid.findings")"
  if [[ "$sid" == "browsers" && "$st" != "Review" && "$st" != "Warning" ]]; then st="Info"; fi
  secnum=$((i + 1))
  printf '<div id="section-%s" class="section">\n' "$sid"
  printf '<div class="section-header" onclick="toggleSection('\''sec%s'\'')">\n' "$secnum"
  printf '<div class="section-left"><span id="sec%s-icon" class="section-icon">v</span><span class="section-title">%s</span></div>\n' "$secnum" "$(html_escape "$title")"
  printf '<span class="section-status-pill status-%s">%s</span></div>\n' "$(printf '%s' "$st" | /usr/bin/tr '[:upper:]' '[:lower:]')" "$st"
  printf '<div id="sec%s" class="section-body"><p class="section-summary">%s</p><div class="findings">\n' "$secnum" "$(html_escape "$summary")"

  while IFS="$SEP" read -r status ftext detail link; do
    [[ -n "$status" ]] || continue
    cls="$(printf '%s' "$status" | /usr/bin/tr '[:upper:]' '[:lower:]')"
    printf '<div class="finding">\n'
    if [[ ( "$status" == "Review" || "$status" == "Warning" ) && -n "${link:-}" ]]; then
      printf '<div><a class="finding-status status-%s" href="%s" title="Open related macOS location">%s</a></div>\n' "$cls" "$(html_escape "$link")" "$status"
    else
      printf '<div><span class="finding-status status-%s">%s</span></div>\n' "$cls" "$status"
    fi
    printf '<div class="finding-main"><div class="finding-text">%s</div>\n' "$(html_escape "$ftext")"
    [[ -n "${detail:-}" ]] && printf '<div class="finding-detail">%s</div>\n' "$(html_escape "$detail")"
    printf '</div></div>\n'
  done < "$WORK_DIR/$sid.findings"

  printf '</div></div></div>\n'
  i=$((i + 1))
done

printf '<div class="footer">Threat inspection completed at %s.<br>\n' "$(html_escape "$COMPLETED_AT")"
printf 'Summary cards count the actual finding rows shown in the report: %s Info / %s Good / %s Review / %s Warning.<br>\n' "$INFO_COUNT" "$GOOD_COUNT" "$REVIEW_COUNT" "$WARNING_COUNT"
printf 'This is a targeted technician inspection, not a malware-remediation engine. Review and Warning findings require context and verification.<br>\n'
printf 'Some browser/privacy-protected locations may be inaccessible without Full Disk Access. No inspected threat item is removed, quarantined, or modified.</div>\n'
printf '</div></body></html>\n'
} > "$REPORT_PATH"

# Make the report owned by the logged-in user.
chown "$CONSOLE_USER":staff "$REPORT_PATH" >/dev/null 2>&1 || true

echo ""
echo "Threat Inspection complete"
echo "------------------------------------------------------------"
echo "Info findings: $INFO_COUNT"
echo "Good findings: $GOOD_COUNT"
echo "Review findings: $REVIEW_COUNT"
echo "Warning findings: $WARNING_COUNT"
echo "Antivirus: $ANTIVIRUS_SUMMARY"
echo "Report: $REPORT_PATH"
echo ""

if [[ "$NO_OPEN_REPORT" -eq 0 ]]; then
  sudo -u "$CONSOLE_USER" /usr/bin/open "$REPORT_PATH" >/dev/null 2>&1 || true
fi

exit 0
