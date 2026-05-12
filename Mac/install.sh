#!/usr/bin/env bash
set -euo pipefail

# ================================================================
# MeldingSoftware Installer for macOS
# Downloads all Mac scripts from GitHub and installs the launcher command.
# Repo: https://github.com/MeldingSoftware/Scripts/tree/main/Mac
# ================================================================

BASE_URL="https://raw.githubusercontent.com/MeldingSoftware/Scripts/main/Mac"

INSTALL_DIR="$HOME/.MeldingSoftware"
SCRIPTS_DIR="$INSTALL_DIR/scripts"
BIN_DIR="$HOME/.local/bin"
LAUNCHER="$BIN_DIR/MeldingSoftware"

echo ""
echo "MeldingSoftware Installer"
echo "Installing to: $INSTALL_DIR"
echo ""

mkdir -p "$SCRIPTS_DIR"
mkdir -p "$BIN_DIR"

download_script() {
  local name="$1"
  local url="$BASE_URL/$name"
  local dest="$SCRIPTS_DIR/$name"

  echo "Downloading $name..."
  curl -fsSL "$url" -o "$dest"
  chmod +x "$dest"
}

# Download Mac scripts
download_script "DeBloater.sh"
download_script "Fun_Commands.sh"
download_script "Installed_Apps.sh"
download_script "Largest_Files.sh"
download_script "Maintenance.sh"
download_script "Melder.sh"
download_script "Print_Spooler_Fix.sh"
download_script "Recon.sh"
download_script "Repair_Tool.sh"
download_script "System_Info.sh"
download_script "Update_Fix.sh"
download_script "Wi-Fi_Info.sh"

# Download launcher
echo "Installing launcher command..."
curl -fsSL "$BASE_URL/bin/MeldingSoftware" -o "$LAUNCHER"
chmod +x "$LAUNCHER"

# Add ~/.local/bin to PATH if needed
SHELL_PROFILE=""
case "${SHELL:-}" in
  */zsh) SHELL_PROFILE="$HOME/.zshrc" ;;
  */bash) SHELL_PROFILE="$HOME/.bash_profile" ;;
  *) SHELL_PROFILE="$HOME/.zshrc" ;;
esac

if ! echo "$PATH" | grep -q "$BIN_DIR"; then
  touch "$SHELL_PROFILE"
  echo "" >> "$SHELL_PROFILE"
  echo '# MeldingSoftware launcher path' >> "$SHELL_PROFILE"
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_PROFILE"
  export PATH="$BIN_DIR:$PATH"
fi

echo ""
echo "Done."
echo ""
echo "Run this command to open the MeldingSoftware menu:"
echo "  MeldingSoftware"
echo ""
echo "If the command is not found, close Terminal and open it again."
echo ""
