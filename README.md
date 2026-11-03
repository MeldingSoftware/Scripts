# Melding Software Scripts

Free Windows and macOS scripts from **Melding Software** for maintenance, repairs, cleanup, diagnostics, software setup, security inspection, automation, and useful system tools.

🌐 **Website:** https://meldingsoftware.com  
💻 **Website Repository:** https://github.com/MeldingSoftware/Website

---

## Windows Scripts

The Windows section contains PowerShell utilities for PC maintenance, troubleshooting, repair, system information, cleanup, security inspection, backup, software setup, and everyday tasks.

### Windows Tools

- BitLocker Recovery Key
- DeBloater
- Fun Commands
- Group Policy Editor
- Installed Apps
- Largest Files
- Maintenance
- Media Player
- Melder
- Mouse Jiggler
- Network Fix
- OneDrive Backup
- Print Spooler Fix
- Repair Tool
- Start My Day
- System Info
- Threat Inspection
- Update Fix
- Wi-Fi Info
- Windows Security Fix

### Windows Usage

Download the ZIP file for the tool you want, extract it, then run the included PowerShell script.

Some tools require administrator permission depending on what they need to inspect, repair, install, remove, or change.

---

## macOS Scripts

The Mac section contains shell scripts for macOS maintenance, troubleshooting, repair, system information, security inspection, application management, and Terminal utilities.

### Install macOS Scripts

Copy and paste this command into Terminal to install the Melding Software macOS scripts:

```bash
curl -fsSL https://raw.githubusercontent.com/MeldingSoftware/Scripts/main/Mac/install.sh | bash
```

After reopening Terminal, type `MeldingSoftware` anytime to open the Melding Software menu.

### macOS Tools

- DeBloater
- Fun Commands
- Installed Apps
- Largest Files
- Maintenance
- Melder
- Print Spooler Fix
- Repair Tool
- System Info
- Threat Inspection
- Update Fix
- Wi-Fi Info

---

## Versioning

Melding Software tools use semantic versioning in the form:

```text
MAJOR.MINOR.PATCH
```

- **MAJOR** — significant redesigns, major behavior changes, or compatibility changes
- **MINOR** — new features or meaningful new capabilities that remain compatible with the existing tool
- **PATCH** — bug fixes, reliability improvements, false-positive corrections, wording/output fixes, and other small compatible changes

Where practical, initial published version numbers are based on the tool's existing development and Git history rather than automatically assigning every established tool version `1.0.0`.

ZIP download names remain stable (for example, `Maintenance.zip`) so website and direct-download links do not need to change when a tool version increases.

---

## Important Notes

These scripts are provided as-is. Always review scripts before running them, especially scripts that modify system settings, clean files, repair system components, install software, or remove applications.

Some antivirus programs may flag PowerShell or shell scripts because they automate system tasks. This does not necessarily mean a script is malicious, but you should still review the source before running it.

---

## License

Melding Software is free and open source and is distributed under the **MIT License**.
