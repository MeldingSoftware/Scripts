#!/usr/bin/env bash
set -euo pipefail

TITLE="Melder"
DIALOG="/usr/local/bin/dialog"

DIALOG_WIDTH="920"
DIALOG_HEIGHT="580"

log(){ echo "[$(date '+%H:%M:%S')] $*"; }


FAILED_ITEMS=()

# ----------------------------
# Dialog helpers
# ----------------------------
show_msg() {
  local msg="$1"

  if [[ -n "${DIALOG:-}" && -x "$DIALOG" ]]; then
    "$DIALOG" \
      --title "$TITLE" \
      --message "$msg" \
      --button1text "OK" \
      --width 700 --height 250 >/dev/null || true
  else
    echo ""
    echo "$msg"
    echo ""
  fi
}

show_error() {
  local msg="$1"

  if [[ -n "${DIALOG:-}" && -x "$DIALOG" ]]; then
    "$DIALOG" \
      --title "$TITLE" \
      --message "$msg" \
      --button1text "OK" \
      --width 740 --height 280 \
      --icon "SF=exclamationmark.triangle.fill,colour=red" >/dev/null || true
  else
    echo ""
    echo "ERROR: $msg"
    echo ""
  fi
}

# ----------------------------
# swiftDialog install/verify
# ----------------------------
ensure_dialog() {
  # Use installed binary if present
  if command -v dialog >/dev/null 2>&1; then
    DIALOG="$(command -v dialog)"
    return 0
  fi
  if [[ -x "$DIALOG" ]]; then
    return 0
  fi

  log "swiftDialog not found — installing…"

  # swiftDialog 3.x requires macOS 15+; use v2.5.6 for macOS 14 or earlier.
  local mac_major release_api json url tmpdir pkg
  mac_major="$(/usr/bin/sw_vers -productVersion | /usr/bin/awk -F. '{print $1}')"
  if [[ "${mac_major:-0}" -ge 15 ]]; then
    release_api="https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest"
  else
    release_api="https://api.github.com/repos/swiftDialog/swiftDialog/releases/tags/v2.5.6"
  fi

  # Fetch release JSON with headers that discourage HTML responses
  json="$(/usr/bin/curl -fsSL --retry 3 --retry-delay 2 \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: Melder" \
    "$release_api")" || {
      echo "Failed to fetch swiftDialog release info."
      exit 1
    }

  # Quick sanity check: if GitHub returned HTML (captive portal / block / etc.), fail with a clearer error
  if [[ "${json:0:1}" != "{" ]]; then
    echo "GitHub API did not return JSON (got unexpected content)."
    echo "This is often caused by a captive portal, blocked network, or GitHub being unreachable."
    echo "Try opening a browser and loading github.com, then run Melder again."
    exit 1
  fi

  # Parse the first .pkg asset URL using Ruby (more reliable than JXA across systems)
  url="$(/usr/bin/printf '%s' "$json" | /usr/bin/ruby -rjson -e '
    data = JSON.parse(STDIN.read) rescue {}
    assets = data["assets"] || []
    pkg = assets.find { |a| a["browser_download_url"].to_s.downcase.end_with?(".pkg") }
    print(pkg ? pkg["browser_download_url"].to_s : "")
  ')" || url=""

  if [[ -z "${url:-}" ]]; then
    echo "Could not find swiftDialog .pkg download URL in the GitHub release metadata."
    exit 1
  fi

  tmpdir="$(mktemp -d)"
  pkg="$tmpdir/Dialog.pkg"

  if ! /usr/bin/curl -fL --retry 3 --retry-delay 2 "$url" -o "$pkg"; then
    rm -rf "$tmpdir"
    echo "swiftDialog download failed."
    exit 1
  fi
  sudo -v || { echo "Admin password is required to install swiftDialog."; exit 1; }
  sudo /usr/sbin/installer -pkg "$pkg" -target / || {
    rm -rf "$tmpdir"
    echo "swiftDialog installer failed."
    exit 1
  }
  rm -rf "$tmpdir"

  if command -v dialog >/dev/null 2>&1; then
    DIALOG="$(command -v dialog)"
    return 0
  fi

  [[ -x "$DIALOG" ]] || { echo "swiftDialog installed but dialog not found."; exit 1; }
}
# ----------------------------
# Homebrew install (only once, after selections)
# ----------------------------
ensure_brew() {
  if command -v brew >/dev/null 2>&1; then
    # Ensure brew env loaded (helps when launched from Finder/USB)
    if [[ -x "/opt/homebrew/bin/brew" ]]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -x "/usr/local/bin/brew" ]]; then
      eval "$(/usr/local/bin/brew shellenv)"
    fi
    return 0
  fi

  show_msg "Homebrew is required for some installs.

Melder will install Homebrew now (requires password)."

  # Run official installer
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || {
    show_error "Homebrew installation failed."
    return 1
  }

  # Load brew into PATH for this session (Apple Silicon or Intel)
  if [[ -x "/opt/homebrew/bin/brew" ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -x "/usr/local/bin/brew" ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi

  if ! command -v brew >/dev/null 2>&1; then
    show_error "Homebrew installed, but 'brew' is still not in PATH.

Open a new Terminal window or add Homebrew to your shell profile, then run Melder again."
    return 1
  fi

  return 0
}
install_pkg() {
  local pkg="$1"
  ensure_brew || { FAILED_ITEMS+=("$pkg"); return 0; }
  log "Installing (brew): $pkg"
  if ! brew install "$pkg"; then
    log "Failed: $pkg"
    FAILED_ITEMS+=("$pkg")
  fi
}

install_cask() {
  local token="$1"
  ensure_brew || { FAILED_ITEMS+=("$token"); return 0; }
  log "Installing (cask): $token"
  if ! brew install --cask "$token"; then
    log "Failed: $token"
    FAILED_ITEMS+=("$token")
  fi
}

# ----------------------------
# Terminal search loop (optional)
# ----------------------------
terminal_cask_search_loop() {
  echo ""
  echo "------------------------------------------------------------"
  echo "Custom App Search (Homebrew Casks)"
  echo "Search and install apps that aren't listed in the GUI."
  echo "Type 'done' at any prompt to stop searching and continue."
  echo "------------------------------------------------------------"
  echo ""

  ensure_brew || return 0

  while true; do
    echo ""
    read -r -p "Search for an app (or type 'done'): " term
    term="${term:-}"
    if [[ "$term" == "done" ]]; then
      echo "Finished searching."
      break
    fi
    if [[ -z "$term" ]]; then
      continue
    fi

    matches=()
    while IFS= read -r line; do
      [[ -n "$line" ]] && matches+=("$line")
    done < <(brew search --cask "$term" 2>/dev/null | head -n 30)

    if [[ ${#matches[@]} -eq 0 ]]; then
      echo "No matches found for: $term"
      continue
    fi

    echo ""
    echo "Matches:"
    i=1
    for token in "${matches[@]}"; do
      printf "  %2d) %s\n" "$i" "$token"
      i=$((i+1))
    done

    echo ""
    echo "Choose what to do:"
    echo "  - Enter a number to install (example: 3)"
    echo "  - Enter multiple numbers separated by commas (example: 1,4,7)"
    echo "  - Type 's' to search again without installing"
    echo "  - Type 'done' to stop searching and continue"
    read -r -p "Your choice: " choice
    choice="${choice:-}"

    if [[ "$choice" == "done" ]]; then
      echo "Finished searching."
      break
    fi
    if [[ "$choice" == "s" ]]; then
      continue
    fi
    if [[ -z "$choice" ]]; then
      continue
    fi

    IFS=',' read -r -a nums <<< "$choice"
    any_installed=false
    for n in "${nums[@]}"; do
      n="$(echo "$n" | tr -d '[:space:]')"
      [[ -z "$n" ]] && continue
      if [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#matches[@]} )); then
        token="${matches[$((n-1))]}"
        echo ""
        echo "Installing: $token"
        install_cask "$token"
        any_installed=true
      else
        echo "Skipping invalid selection: $n"
      fi
    done

    if ! $any_installed; then
      echo "No valid selections were installed."
    fi
  done

  echo ""
  echo "Continuing Melder..."
  echo ""
}

# ----------------------------
# sudo keepalive (only if needed)
# ----------------------------
need_sudo=false
SUDO_KEEPALIVE_PID=""
ensure_sudo_if_needed() {
  if $need_sudo; then
  sudo -v || { echo "Admin password is required to install swiftDialog."; exit 1; }
    ( while true; do sudo -n true 2>/dev/null; sleep 60; done ) &
    SUDO_KEEPALIVE_PID=$!
    trap '[[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true' EXIT
  fi
}

# ----------------------------
# Rosetta 2 (Apple Silicon) for Steam
# ----------------------------
rosetta_installed() {
  /usr/bin/pgrep -q oahd 2>/dev/null
}

ensure_rosetta_for_steam() {
  if [[ "$(uname -m)" != "arm64" ]]; then
    return 0
  fi

  if rosetta_installed; then
    return 0
  fi

  log "Steam selected on Apple Silicon — installing Rosetta 2…"
  sudo -v || { echo "Admin password is required to install Rosetta 2."; return 1; }

  if ! /usr/sbin/softwareupdate --install-rosetta --agree-to-license; then
    log "Failed to install Rosetta 2."
    FAILED_ITEMS+=("rosetta2")
    return 1
  fi

  return 0
}

# ----------------------------
# Tweaks
# ----------------------------
tweak_disable_recent_apps() {
  log "Tweak: Disable Recent Apps…"
  defaults write com.apple.dock show-recents -bool false
  killall Dock 2>/dev/null || true
}
tweak_enable_automatic_updates() {
  log "Tweak: Enable Automatic Updates…"
  sudo softwareupdate --schedule on >/dev/null || true
}
tweak_enable_firewall() {
  log "Tweak: Enable Firewall…"
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on >/dev/null
}
tweak_install_mac_updates() {
  log "Tweak: Install Mac Updates…"
  sudo softwareupdate -l || true
  sudo softwareupdate -ia --verbose || true
}
tweak_screenshots_folder() {
  log "Tweak: Screenshots saved to ~/Pictures/Screenshots…"
  mkdir -p "$HOME/Pictures/Screenshots"
  defaults write com.apple.screencapture location "$HOME/Pictures/Screenshots"
  killall SystemUIServer 2>/dev/null || true
}
tweak_set_dock_autohide() {
  log "Tweak: Set Dock to Auto-hide…"
  defaults write com.apple.dock autohide -bool true
  killall Dock 2>/dev/null || true
}
tweak_show_file_extensions() {
  log "Tweak: Show file extensions…"
  defaults write NSGlobalDomain AppleShowAllExtensions -bool true
}
tweak_show_path_bar() {
  log "Tweak: Show path bar…"
  defaults write com.apple.finder ShowPathbar -bool true
}
tweak_show_status_bar() {
  log "Tweak: Show status bar…"
  defaults write com.apple.finder ShowStatusBar -bool true
}
restart_finder(){ killall Finder 2>/dev/null || true; }
tweak_tap_to_click() {
  log "Tweak: Tap to Click…"
  defaults write com.apple.driver.AppleBluetoothMultitouch.trackpad Clicking -bool true
  defaults write NSGlobalDomain com.apple.mouse.tapBehavior -int 1
}

# ----------------------------
# JSON helpers
# ----------------------------
json_is_true() {
  # args: <json> <key>  -> outputs yes/no
  local json="$1"
  local key="$2"
  /usr/bin/printf '%s' "$json" | /usr/bin/ruby -rjson -e '
    j = JSON.parse(STDIN.read) rescue {}
    key = ARGV[0]
    puts(j[key] == true ? "yes" : "no")
  ' "$key"
}
json_any_true() {
  # args: <json> -> outputs yes/no
  local json="$1"
  /usr/bin/printf '%s' "$json" | /usr/bin/ruby -rjson -e '
    j = JSON.parse(STDIN.read) rescue {}
    vals = j.values rescue []
    puts(vals.any? { |v| v == true } ? "yes" : "no")
  '
}
# ----------------------------
# Dialog wrapper (Next+Cancel / Run+Cancel)
# ----------------------------
dialog_json_safe_2btn() {
  set +e
  "$DIALOG" "$@" --json
  rc=$?
  set -e
  return $rc
}

build_checkbox_args() {
  CHECK_ARGS=()
  while IFS= read -r label; do
    [[ -z "$label" ]] && continue
    CHECK_ARGS+=( --checkbox "$label" )
  done <<< "$1"
}

page_next_cancel() {
  local category="$1"
  local icon="$2"
  local items="$3"
  build_checkbox_args "$items"

  dialog_json_safe_2btn \
    --title "$TITLE" \
    --message "$category" \
    --icon "$icon" \
    --width "$DIALOG_WIDTH" --height "$DIALOG_HEIGHT" \
    --checkboxstyle "switch" \
    --button1text "Next" \
    --button2text "Cancel" \
    "${CHECK_ARGS[@]}"
}

page_run_cancel() {
  local category="$1"
  local icon="$2"
  local items="$3"
  build_checkbox_args "$items"

  dialog_json_safe_2btn \
    --title "$TITLE" \
    --message "$category" \
    --icon "$icon" \
    --width "$DIALOG_WIDTH" --height "$DIALOG_HEIGHT" \
    --checkboxstyle "switch" \
    --button1text "Run" \
    --button2text "Cancel" \
    "${CHECK_ARGS[@]}"
}

# ----------------------------
# Page content (ALPHABETIZED)
# ----------------------------
BROWSERS_ITEMS=$'Brave\nChrome\nDuckDuckGo\nFirefox\nOpera\nOpera GX\nTor'

# Productivity (alphabetized)
PRODUCTIVITY_ITEMS=$'Acrobat Reader\nAppCleaner\nEvernote\nGrammarly\nLibre Office\nMicrosoft Office\nObsidian\nOpen Office\nRaycast\nVisual Studio Code'

# Media (alphabetized)
MEDIA_ITEMS=$'Amazon Music\nAudacity\nCapCut\nHandbrake\nKodi\nLightworks\nPlex\nSpotify\nVLC Player'

# Social (alphabetized)
SOCIAL_ITEMS=$'Discord\nSlack\nTeams\nTelegram\nWhatsApp\nZoom'

# Gaming (alphabetized)
GAMING_ITEMS=$'Battle.net\nEA Desktop\nEpic Games Launcher\nLeague of Legends\nMinecraft Launcher\nRetroArch\nRoblox\nSteam'

# Diagnostic (alphabetized; lowercase coconutBattery kept first due to case, but visually fine)
DIAG_ITEMS=$'Cinebench\ncoconutBattery\nEtreCheck\nGeekbench\nWireshark'

# Security (alphabetized)
SEC_ITEMS=$'1Password\nBitwarden\nBlockBlock\nKnockKnock\nLuLu\nMalwarebytes\nNordVPN\nProtonVPN\nVeraCrypt'

# Tweaks (alphabetized; includes Rectangle + iTerm2)
TWEAKS_ITEMS=$'Disable Recent Apps\nEnable Automatic Updates\nEnable Firewall\niTerm2\nInstall Mac Updates\nRectangle\nScreenshots saved to ~/Pictures/Screenshots\nSet Dock to Auto-hide\nShow file extensions\nShow path bar\nShow status bar\nTap to Click'

# Search (optional)
SEARCH_ITEMS=$'Search'


# ----------------------------
# Main
# ----------------------------
ensure_dialog

ICON_BROWSERS="SF=safari.fill"
ICON_PRODUCTIVITY="SF=doc.text.fill"
ICON_MEDIA="SF=play.rectangle.fill"
ICON_SOCIAL="SF=message.fill"
ICON_GAMING="SF=gamecontroller.fill"
ICON_DIAG="SF=stethoscope"
ICON_SECURITY="SF=lock.shield.fill"
ICON_TWEAKS="SF=gearshape.2.fill"

BROWSERS_JSON="$(page_next_cancel "Browsers" "$ICON_BROWSERS" "$BROWSERS_ITEMS")"; rc=$?; [[ $rc -eq 2 ]] && exit 0
PROD_JSON="$(page_next_cancel "Productivity" "$ICON_PRODUCTIVITY" "$PRODUCTIVITY_ITEMS")"; rc=$?; [[ $rc -eq 2 ]] && exit 0
MEDIA_JSON="$(page_next_cancel "Media" "$ICON_MEDIA" "$MEDIA_ITEMS")"; rc=$?; [[ $rc -eq 2 ]] && exit 0
SOCIAL_JSON="$(page_next_cancel "Social" "$ICON_SOCIAL" "$SOCIAL_ITEMS")"; rc=$?; [[ $rc -eq 2 ]] && exit 0
GAMING_JSON="$(page_next_cancel "Gaming" "$ICON_GAMING" "$GAMING_ITEMS")"; rc=$?; [[ $rc -eq 2 ]] && exit 0
DIAG_JSON="$(page_next_cancel "Diagnostic" "$ICON_DIAG" "$DIAG_ITEMS")"; rc=$?; [[ $rc -eq 2 ]] && exit 0
SEC_JSON="$(page_next_cancel "Security" "$ICON_SECURITY" "$SEC_ITEMS")"; rc=$?; [[ $rc -eq 2 ]] && exit 0

ICON_SEARCH="SF=magnifyingglass"
SEARCH_PAGE_MESSAGE="$(cat <<'EOF'
Search

Enable this if you want to install apps that aren't listed in the GUI.

After you click Run, Melder will prompt you in the Terminal to:

• Type a search term (example: chrome, steam, spotify)

• See a numbered list of matching Homebrew casks

• Install by entering a number (or 1,4,7)

• Search again without installing (type s)

• Type done when you're finished and want Melder to continue.
EOF
)"
SEARCH_JSON="$(page_next_cancel "$SEARCH_PAGE_MESSAGE" "$ICON_SEARCH" "$SEARCH_ITEMS")"; rc=$?; [[ $rc -eq 2 ]] && exit 0



TWEAKS_JSON="$(page_run_cancel "System Tweaks" "$ICON_TWEAKS" "$TWEAKS_ITEMS")"; rc=$?; [[ $rc -eq 2 ]] && exit 0

# sudo needed?
need_sudo=false
if [[ "$(json_is_true "$TWEAKS_JSON" "Enable Firewall")" == "yes" ]] || \
   [[ "$(json_is_true "$TWEAKS_JSON" "Enable Automatic Updates")" == "yes" ]] || \
   [[ "$(json_is_true "$TWEAKS_JSON" "Install Mac Updates")" == "yes" ]]; then
  need_sudo=true
fi
ensure_sudo_if_needed

# brew needed if any app/tool selected (including iTerm2/Rectangle in Tweaks)
ANY_SELECTED=false
for j in "$BROWSERS_JSON" "$PROD_JSON" "$MEDIA_JSON" "$SOCIAL_JSON" "$GAMING_JSON" "$DIAG_JSON" "$SEC_JSON" "$SEARCH_JSON" "$TWEAKS_JSON"; do
  if [[ "$(json_any_true "$j")" == "yes" ]]; then ANY_SELECTED=true; break; fi
done
if $ANY_SELECTED; then
  ensure_brew
fi

# Optional terminal search loop (runs after Run is clicked)
if [[ "$(json_is_true "$SEARCH_JSON" "Search")" == "yes" ]]; then
  terminal_cask_search_loop
fi

# Installs
# Browsers
[[ "$(json_is_true "$BROWSERS_JSON" "Brave")" == "yes" ]] && install_cask brave-browser
[[ "$(json_is_true "$BROWSERS_JSON" "Chrome")" == "yes" ]] && install_cask google-chrome
[[ "$(json_is_true "$BROWSERS_JSON" "DuckDuckGo")" == "yes" ]] && install_cask duckduckgo
[[ "$(json_is_true "$BROWSERS_JSON" "Firefox")" == "yes" ]] && install_cask firefox
[[ "$(json_is_true "$BROWSERS_JSON" "Opera")" == "yes" ]] && install_cask opera
[[ "$(json_is_true "$BROWSERS_JSON" "Opera GX")" == "yes" ]] && install_cask opera-gx
[[ "$(json_is_true "$BROWSERS_JSON" "Tor")" == "yes" ]] && install_cask tor-browser

# Productivity
[[ "$(json_is_true "$PROD_JSON" "Acrobat Reader")" == "yes" ]] && install_cask adobe-acrobat-reader
[[ "$(json_is_true "$PROD_JSON" "AppCleaner")" == "yes" ]] && install_cask appcleaner
[[ "$(json_is_true "$PROD_JSON" "Evernote")" == "yes" ]] && install_cask evernote
[[ "$(json_is_true "$PROD_JSON" "Grammarly")" == "yes" ]] && install_cask grammarly-desktop
[[ "$(json_is_true "$PROD_JSON" "Libre Office")" == "yes" ]] && install_cask libreoffice
[[ "$(json_is_true "$PROD_JSON" "Microsoft Office")" == "yes" ]] && install_cask microsoft-office
[[ "$(json_is_true "$PROD_JSON" "Obsidian")" == "yes" ]] && install_cask obsidian
[[ "$(json_is_true "$PROD_JSON" "Open Office")" == "yes" ]] && install_cask openoffice
[[ "$(json_is_true "$PROD_JSON" "Raycast")" == "yes" ]] && install_cask raycast
[[ "$(json_is_true "$PROD_JSON" "Visual Studio Code")" == "yes" ]] && install_cask visual-studio-code

# Media
[[ "$(json_is_true "$MEDIA_JSON" "Amazon Music")" == "yes" ]] && install_cask amazon-music
[[ "$(json_is_true "$MEDIA_JSON" "Audacity")" == "yes" ]] && install_cask audacity
[[ "$(json_is_true "$MEDIA_JSON" "CapCut")" == "yes" ]] && install_cask capcut
[[ "$(json_is_true "$MEDIA_JSON" "Handbrake")" == "yes" ]] && install_cask handbrake-app
[[ "$(json_is_true "$MEDIA_JSON" "Kodi")" == "yes" ]] && install_cask kodi
[[ "$(json_is_true "$MEDIA_JSON" "Lightworks")" == "yes" ]] && install_cask lightworks
[[ "$(json_is_true "$MEDIA_JSON" "Plex")" == "yes" ]] && install_cask plex
[[ "$(json_is_true "$MEDIA_JSON" "Spotify")" == "yes" ]] && install_cask spotify
[[ "$(json_is_true "$MEDIA_JSON" "VLC Player")" == "yes" ]] && install_cask vlc

# Social
[[ "$(json_is_true "$SOCIAL_JSON" "Discord")" == "yes" ]] && install_cask discord
[[ "$(json_is_true "$SOCIAL_JSON" "Slack")" == "yes" ]] && install_cask slack
[[ "$(json_is_true "$SOCIAL_JSON" "Teams")" == "yes" ]] && install_cask microsoft-teams
[[ "$(json_is_true "$SOCIAL_JSON" "Telegram")" == "yes" ]] && install_cask telegram
[[ "$(json_is_true "$SOCIAL_JSON" "WhatsApp")" == "yes" ]] && install_cask whatsapp
[[ "$(json_is_true "$SOCIAL_JSON" "Zoom")" == "yes" ]] && install_cask zoom

# Gaming
[[ "$(json_is_true "$GAMING_JSON" "Battle.net")" == "yes" ]] && install_cask battle-net
[[ "$(json_is_true "$GAMING_JSON" "EA Desktop")" == "yes" ]] && install_cask ea
[[ "$(json_is_true "$GAMING_JSON" "Epic Games Launcher")" == "yes" ]] && install_cask epic-games
[[ "$(json_is_true "$GAMING_JSON" "League of Legends")" == "yes" ]] && install_cask league-of-legends
[[ "$(json_is_true "$GAMING_JSON" "Minecraft Launcher")" == "yes" ]] && install_cask minecraft
[[ "$(json_is_true "$GAMING_JSON" "RetroArch")" == "yes" ]] && install_cask retroarch
[[ "$(json_is_true "$GAMING_JSON" "Roblox")" == "yes" ]] && install_cask roblox
[[ "$(json_is_true "$GAMING_JSON" "Steam")" == "yes" ]] && { ensure_rosetta_for_steam || true; install_cask steam; }

# Diagnostic
[[ "$(json_is_true "$DIAG_JSON" "Cinebench")" == "yes" ]] && install_cask cinebench
[[ "$(json_is_true "$DIAG_JSON" "coconutBattery")" == "yes" ]] && install_cask coconutbattery
[[ "$(json_is_true "$DIAG_JSON" "EtreCheck")" == "yes" ]] && install_cask etrecheckpro
[[ "$(json_is_true "$DIAG_JSON" "Geekbench")" == "yes" ]] && install_cask geekbench
[[ "$(json_is_true "$DIAG_JSON" "Wireshark")" == "yes" ]] && install_cask wireshark-app

# Security
[[ "$(json_is_true "$SEC_JSON" "1Password")" == "yes" ]] && install_cask 1password
[[ "$(json_is_true "$SEC_JSON" "Bitwarden")" == "yes" ]] && install_cask bitwarden
[[ "$(json_is_true "$SEC_JSON" "BlockBlock")" == "yes" ]] && install_cask blockblock
[[ "$(json_is_true "$SEC_JSON" "KnockKnock")" == "yes" ]] && install_cask knockknock
[[ "$(json_is_true "$SEC_JSON" "LuLu")" == "yes" ]] && install_cask lulu
[[ "$(json_is_true "$SEC_JSON" "Malwarebytes")" == "yes" ]] && install_cask malwarebytes
[[ "$(json_is_true "$SEC_JSON" "NordVPN")" == "yes" ]] && install_cask nordvpn
[[ "$(json_is_true "$SEC_JSON" "ProtonVPN")" == "yes" ]] && install_cask protonvpn
[[ "$(json_is_true "$SEC_JSON" "VeraCrypt")" == "yes" ]] && install_cask veracrypt

# Tweaks: Rectangle + iTerm2 are installs
[[ "$(json_is_true "$TWEAKS_JSON" "Rectangle")" == "yes" ]] && install_cask rectangle
[[ "$(json_is_true "$TWEAKS_JSON" "iTerm2")" == "yes" ]] && install_cask iterm2

# Tweaks: system settings
finder_changed=false
[[ "$(json_is_true "$TWEAKS_JSON" "Show file extensions")" == "yes" ]] && { tweak_show_file_extensions; finder_changed=true; }
[[ "$(json_is_true "$TWEAKS_JSON" "Show path bar")" == "yes" ]] && { tweak_show_path_bar; finder_changed=true; }
[[ "$(json_is_true "$TWEAKS_JSON" "Show status bar")" == "yes" ]] && { tweak_show_status_bar; finder_changed=true; }
$finder_changed && restart_finder

[[ "$(json_is_true "$TWEAKS_JSON" "Screenshots saved to ~/Pictures/Screenshots")" == "yes" ]] && tweak_screenshots_folder
[[ "$(json_is_true "$TWEAKS_JSON" "Tap to Click")" == "yes" ]] && tweak_tap_to_click
[[ "$(json_is_true "$TWEAKS_JSON" "Set Dock to Auto-hide")" == "yes" ]] && tweak_set_dock_autohide
[[ "$(json_is_true "$TWEAKS_JSON" "Disable Recent Apps")" == "yes" ]] && tweak_disable_recent_apps
[[ "$(json_is_true "$TWEAKS_JSON" "Enable Firewall")" == "yes" ]] && tweak_enable_firewall
[[ "$(json_is_true "$TWEAKS_JSON" "Enable Automatic Updates")" == "yes" ]] && tweak_enable_automatic_updates
[[ "$(json_is_true "$TWEAKS_JSON" "Install Mac Updates")" == "yes" ]] && tweak_install_mac_updates

"$DIALOG" --title "$TITLE" --message "Done" --icon "SF=checkmark.seal.fill" \
  --width "$DIALOG_WIDTH" --height "220" --button1text "OK" >/dev/null || true
