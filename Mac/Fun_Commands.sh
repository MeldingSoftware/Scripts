#!/bin/bash

# Fun Commands.command
# A small menu of terminal toys with sensible defaults and graceful fallbacks.

set -u  # error on unset variables (but do not use -e; we want to handle failures gracefully)

# Don't let Ctrl+C kill the whole script; it should stop the running toy and return to menu.
trap '' INT

# ---------- helpers ----------

maximize_terminal() {
  # Some launch contexts don't have a Terminal window yet; ignore errors.
  osascript -e 'tell application "Terminal" to if (count of windows) > 0 then tell window 1 to set zoomed to true' 2>/dev/null || true
}

pause_return() {
  echo ""
  read -r -p "Press Enter to return to the menu..." _
}

warn() { printf "\n[!] %s\n" "$*"; }
info() { printf "\n[i] %s\n" "$*"; }

# Try to make brew available in PATH for Intel + Apple Silicon.
# If brew is installed but not in PATH, this will usually fix it.
setup_brew_env() {
  if [ -x "/opt/homebrew/bin/brew" ]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
    return 0
  fi
  if [ -x "/usr/local/bin/brew" ]; then
    eval "$(/usr/local/bin/brew shellenv)"
    return 0
  fi
  # If brew is already in PATH, use it.
  if command -v brew >/dev/null 2>&1; then
    eval "$(brew shellenv)" 2>/dev/null || true
    return 0
  fi
  return 1
}

ensure_brew() {
  if setup_brew_env; then
    info "Homebrew (brew) detected."
    return 0
  fi

  warn "Homebrew (brew) is not installed. Installing Homebrew..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if [ $? -ne 0 ]; then
    warn "Failed to install Homebrew. Please install it manually and re-run this script."
    return 1
  fi

  # Try again after install
  if setup_brew_env; then
    info "Homebrew has been successfully installed."
    return 0
  fi

  warn "Homebrew installed, but couldn't add it to PATH in this session."
  warn "Try opening a new Terminal window and re-running the script."
  return 1
}

# Install a brew formula if its command isn't available.
# Usage: ensure_cmd <command> <brew_formula>
ensure_cmd() {
  local cmd="$1"
  local formula="$2"

  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi

  if ! command -v brew >/dev/null 2>&1; then
    ensure_brew || return 1
  fi

  info "Installing '$formula' (to provide '$cmd')..."
  brew install "$formula"
  if [ $? -ne 0 ]; then
    warn "Failed to install '$formula'."
    return 1
  fi

  if ! command -v "$cmd" >/dev/null 2>&1; then
    warn "Installed '$formula', but '$cmd' still isn't available in PATH."
    return 1
  fi

  return 0
}

# ---------- features ----------

show_birthstones_flowers() {
  # Built-in mapping so we don't depend on /usr/share/misc/* files.
  local month_raw="$1"
  local month
  month="$(printf "%s" "$month_raw" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

  case "$month" in
    january|jan)
      echo "January  — Birthstone: Garnet | Birth flower: Carnation / Snowdrop";;
    february|feb)
      echo "February — Birthstone: Amethyst | Birth flower: Violet / Primrose";;
    march|mar)
      echo "March    — Birthstone: Aquamarine | Birth flower: Daffodil";;
    april|apr)
      echo "April    — Birthstone: Diamond | Birth flower: Daisy / Sweet Pea";;
    may)
      echo "May      — Birthstone: Emerald | Birth flower: Lily of the Valley";;
    june|jun)
      echo "June     — Birthstone: Pearl / Alexandrite / Moonstone | Birth flower: Rose / Honeysuckle";;
    july|jul)
      echo "July     — Birthstone: Ruby | Birth flower: Larkspur / Water Lily";;
    august|aug)
      echo "August   — Birthstone: Peridot / Spinel | Birth flower: Gladiolus / Poppy";;
    september|sep|sept)
      echo "September— Birthstone: Sapphire | Birth flower: Aster / Morning Glory";;
    october|oct)
      echo "October  — Birthstone: Opal / Tourmaline | Birth flower: Marigold / Cosmos";;
    november|nov)
      echo "November — Birthstone: Topaz / Citrine | Birth flower: Chrysanthemum";;
    december|dec)
      echo "December — Birthstone: Turquoise / Zircon / Tanzanite | Birth flower: Narcissus / Holly";;
    *)
      warn "I didn't recognize '$month_raw'. Try e.g. 'July' or 'jul'.";;
  esac
}

snow_fallback_python() {
  # A tiny snow effect in python if ruby isn't present.
  python3 - <<'PY'
import os, random, sys, time
cols = 80
try:
    import shutil
    cols = shutil.get_terminal_size((80, 20)).columns
except Exception:
    pass
flakes = {}
print("\033[2J", end="")
while True:
    if random.random() < 0.25:
        flakes[random.randrange(cols)] = 0
    for x in list(flakes.keys()):
        flakes[x] += 1
        y = flakes[x]
        if y > 30:
            flakes.pop(x, None)
            continue
        sys.stdout.write(f"\033[{y};{x+1}H*")
    sys.stdout.write("\033[0;0H")
    sys.stdout.flush()
    time.sleep(0.08)
PY
}

historical_events() {
  local opt="$1"

  # Prefer the system calendar files if they exist.
  local history_file="/usr/share/calendar/calendar.history"
  if [ ! -f "$history_file" ]; then
    warn "I couldn't find $history_file on this Mac."
    if [ -d "/usr/share/calendar" ]; then
      echo "Available calendar files on your system:" 
      ls -1 /usr/share/calendar | sed 's/^/  - /'
      echo ""
      echo "Tip: You can still use the built-in 'calendar' command for date-based results:" 
      echo "  calendar  (shows near today's date)"
    fi
    return 0
  fi

  case "$opt" in
    1)
      read -r -p "Enter name/keyword to search for: " name
      if [ -z "${name// }" ]; then
        warn "No keyword entered."
        return 0
      fi
      echo ""
      # -i for case-insensitive, -n to show line numbers
      grep -in -- "$name" "$history_file" | head -n 60 || warn "No matches found for '$name'."
      ;;
    2)
      read -r -p "Enter date (MM/DD): " date
      if [[ ! "$date" =~ ^[0-1][0-9]/[0-3][0-9]$ ]]; then
        warn "That doesn't look like MM/DD (example: 07/04)."
        return 0
      fi
      echo ""
      grep -n -- "$date" "$history_file" | head -n 60 || warn "No matches found for '$date'."
      ;;
    *)
      warn "Invalid option"
      ;;
  esac
}

play_starwars() {
  info "ASCII Star Wars (Ctrl+C to stop)"
  if ! command -v nc >/dev/null 2>&1; then
    warn "'nc' (netcat) isn't available on this system."
    return 0
  fi

  # First try towel.blinkenlights.nl (classic). If port 23 is closed/refused, fall back to telehack.
  if nc -vz -w 3 towel.blinkenlights.nl 23 >/dev/null 2>&1; then
    nc towel.blinkenlights.nl 23
    return 0
  fi

  warn "towel.blinkenlights.nl isn't accepting connections on port 23 right now. Trying telehack.com..."
  if nc -vz -w 3 telehack.com 23 >/dev/null 2>&1; then
    # Telehack requires sending the command after connecting.
    { sleep 1; echo starwars; sleep 99999; } | nc telehack.com 23
    return 0
  fi

  warn "Couldn't connect to either towel.blinkenlights.nl:23 or telehack.com:23."
  return 0
}


# ---------- startup ----------

maximize_terminal

# Ensure brew + packages. (emacs is big; keep it, but only install if user runs it.)
ensure_brew || true

# Tools used by menu items.
ensure_cmd cmatrix cmatrix || true
ensure_cmd sl sl || true
ensure_cmd cowsay cowsay || true
# 'fortune' command is usually provided by 'fortune' on brew, but some setups use 'fortune-mod'. Try both.
if ! command -v fortune >/dev/null 2>&1; then
  ensure_cmd fortune fortune || ensure_cmd fortune fortune-mod || true
fi
# Banner replacement
ensure_cmd figlet figlet || true

# ---------- menu loop ----------
while true; do
  clear
  echo ""
  echo "0. Exit"
  echo "1. Games (Emacs)"
  echo "2. The Matrix Rain (cmatrix)"
  echo "3. Make It Snow"
  echo "4. ASCII Star Wars (towel.blinkenlights.nl)"
  echo "5. ASCII Train (sl)"
  echo "6. Random Quote (fortune)"
  echo "7. Create A Banner (figlet)"
  echo "8. Check Birthstones and Flowers"
  echo "9. Learn Historical Events"
  echo "10. Cowsay"
  echo "11. Let Your Terminal Speak"
  echo ""

  read -r -p "Enter a number (0 to exit): " choice

  case "$choice" in
    0)
      # Just exit (closing Terminal windows can be annoying/unexpected)
      exit 0
      ;;

    1)
      if ! command -v emacs >/dev/null 2>&1; then
        info "Emacs isn't installed. Installing via Homebrew..."
        ensure_cmd emacs emacs || { pause_return; continue; }
      fi
      info "Launching emacs (quit with: Ctrl+X then Ctrl+C)"
      emacs
      pause_return
      ;;

    2)
      if command -v cmatrix >/dev/null 2>&1; then
        info "Matrix Rain (quit with: q)"
        cmatrix
      else
        warn "cmatrix isn't available. Try: brew install cmatrix"
      fi
      pause_return
      ;;

    3)
      info "Make It Snow (Ctrl+C to stop)"
      if command -v ruby >/dev/null 2>&1; then
        ruby -e 'C=`stty size`.scan(/\d+/)[1].to_i;S=["2743".to_i(16)].pack("U*");a={};puts "\033[2J";loop{a[rand(C)]=0;a.each{|x,o|;a[x]+=1;print "\033[#{o};#{x}H \033[#{a[x]};#{x}H#{S} \033[0;0H"};$stdout.flush;sleep 0.1}'
      elif command -v python3 >/dev/null 2>&1; then
        snow_fallback_python
      else
        warn "Neither ruby nor python3 is available to run the snow effect."
      fi
      pause_return
      ;;

    4)
      play_starwars
      pause_return
      ;;

    5)
      if command -v sl >/dev/null 2>&1; then
        sl
      else
        warn "sl isn't available. Try: brew install sl"
      fi
      pause_return
      ;;

    6)
      if command -v fortune >/dev/null 2>&1; then
        fortune
      else
        warn "fortune isn't available. Try: brew install fortune (or fortune-mod)"
      fi
      pause_return
      ;;

    7)
      read -r -p "Enter text for banner: " banner_text
      if [ -z "${banner_text// }" ]; then
        warn "No text entered."
        pause_return
        continue
      fi
      if command -v figlet >/dev/null 2>&1; then
        figlet "$banner_text"
      else
        warn "figlet isn't available. Try: brew install figlet"
        echo "$banner_text"
      fi
      pause_return
      ;;

    8)
      read -r -p "Enter your birth month (e.g., July or jul): " birth_month
      show_birthstones_flowers "$birth_month"
      pause_return
      ;;

    9)
      echo ""
      read -r -p "Select an option: 1) Keyword  2) Date (MM/DD): " event_option
      historical_events "$event_option"
      pause_return
      ;;

    10)
      read -r -p "Enter text for Cowsay: " cowsay_text
      if command -v cowsay >/dev/null 2>&1; then
        cowsay "$cowsay_text"
      else
        warn "cowsay isn't available. Try: brew install cowsay"
      fi
      pause_return
      ;;

    11)
      read -r -p "Enter text for terminal to speak: " speak_text
      if command -v say >/dev/null 2>&1; then
        say "$speak_text"
      else
        warn "The 'say' command isn't available on this system."
      fi
      pause_return
      ;;

    *)
      warn "Invalid choice. Please select a number from the menu."
      pause_return
      ;;
  esac

done
