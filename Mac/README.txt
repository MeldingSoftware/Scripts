MeldingSoftware ZIP Installer Setup

GitHub repository:
https://github.com/MeldingSoftware/Scripts

Expected Mac folder layout:

Scripts/
  Windows/
  Mac/
    install.sh
    MeldingSoftware_Mac_Scripts.zip
    bin/
      MeldingSoftware

The ZIP should contain these raw .sh files at the root of the ZIP:

  DeBloater.sh
  Fun_Commands.sh
  Installed_Apps.sh
  Largest_Files.sh
  Maintenance.sh
  Melder.sh
  Print_Spooler_Fix.sh
  Recon.sh
  Repair_Tool.sh
  System_Info.sh
  Update_Fix.sh
  Wi-Fi_Info.sh

Notes:
- StartMyDay.sh was intentionally removed because it requires user API keys.
- The installer downloads one ZIP instead of downloading every script separately.
- The launcher command is installed to:
  ~/.local/bin/MeldingSoftware
- Scripts are extracted to:
  ~/.MeldingSoftware/scripts

Website install command:

curl -fsSL https://raw.githubusercontent.com/MeldingSoftware/Scripts/main/Mac/install.sh | bash

After install:
1. Close the current Terminal window.
2. Open a new Terminal window.
3. Run:

MeldingSoftware

Update flow:
- Users can run MeldingSoftware and choose:
  13) Update MeldingSoftware

This downloads the latest ZIP and replaces the local scripts.

Uninstall flow:
- Users can run MeldingSoftware and choose:
  14) Uninstall MeldingSoftware

This removes:
  ~/.MeldingSoftware
  ~/.local/bin/MeldingSoftware

It does not remove Homebrew, installed apps, or other files in ~/.local/bin.
