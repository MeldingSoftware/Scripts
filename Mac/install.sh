#!/usr/bin/env bash
set -euo pipefail

# ================================================================
# MeldingSoftware ZIP Installer for macOS
# Downloads one ZIP archive from GitHub, extracts scripts, and installs
# the launcher command.
# ================================================================

BASE_URL="https://raw.githubusercontent.com/MeldingSoftware/Scripts/main/Mac"

# This ZIP should exist in your GitHub Mac folder:
# Mac/MeldingSoftware_Mac_Scripts.zip
ZIP_NAME="MeldingSoftware_Mac_Scripts.zip"
ZIP_URL="$BASE_URL/$ZIP_NAME"

INSTALL_DIR="$HOME/.MeldingSoftware"
SCRIPTS_DIR="$INSTALL_DIR/scripts"
BIN_DIR="$HOME/.local/bin"
LAUNCHER="$BIN_DIR/MeldingSoftware"

TMP_DIR="$(mktemp -d)"
ZIP_PATH="$TMP_DIR/$ZIP_NAME"
EXTRACT_DIR="$TMP_DIR/extract"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo ""
echo "MeldingSoftware Installer"
echo "Installing to: $INSTALL_DIR"
echo ""

mkdir -p "$INSTALL_DIR"
mkdir -p "$SCRIPTS_DIR"
mkdir -p "$BIN_DIR"
mkdir -p "$EXTRACT_DIR"

echo "Downloading MeldingSoftware scripts package..."
curl -fsSL "$ZIP_URL" -o "$ZIP_PATH"

echo "Extracting scripts..."
/usr/bin/unzip -q "$ZIP_PATH" -d "$EXTRACT_DIR"

# The ZIP may contain files directly, or inside a folder.
# Find the first directory/file set that contains Melder.sh or DeBloater.sh.
SOURCE_DIR=""
if [[ -f "$EXTRACT_DIR/Melder.sh" ]] || [[ -f "$EXTRACT_DIR/DeBloater.sh" ]]; then
  SOURCE_DIR="$EXTRACT_DIR"
else
  while IFS= read -r dir; do
    if [[ -f "$dir/Melder.sh" ]] || [[ -f "$dir/DeBloater.sh" ]]; then
      SOURCE_DIR="$dir"
      break
    fi
  done < <(find "$EXTRACT_DIR" -type d)
fi

if [[ -z "$SOURCE_DIR" ]]; then
  echo "Could not find scripts inside the ZIP."
  echo "The ZIP should contain files like Melder.sh, Maintenance.sh, etc."
  exit 1
fi

echo "Installing scripts..."
rm -rf "$SCRIPTS_DIR"
mkdir -p "$SCRIPTS_DIR"

# Copy only .sh files from the package root we detected.
find "$SOURCE_DIR" -maxdepth 1 -type f -name "*.sh" -exec cp "{}" "$SCRIPTS_DIR/" \;

chmod +x "$SCRIPTS_DIR"/*.sh 2>/dev/null || true

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
echo "IMPORTANT:"
echo "Close this Terminal window, open a new Terminal window, then run:"
echo "  MeldingSoftware"
echo ""
echo "This lets Terminal reload the PATH update added by the installer."
echo ""
read -r -p "Press Enter to close this installer message..." _ </dev/tty || true
