#!/bin/bash
set -u

# ================================================================
# Melding Software Screenshot Helper - Global Hotkey
#
# Control + Option + S:
#   - Works even while cmatrix or another program owns the Terminal
#   - Does not type anything into the running program
#   - Resizes/centers the FRONT Terminal window before capture
#   - Captures that Terminal window automatically
#
# Screenshots:
#   ~/Desktop/Melding Software Screenshots
#
# This helper does not modify GitHub or the installed MeldingSoftware
# launcher. It runs installed scripts directly.
# ================================================================

MAX_WIDTH=1440
MAX_HEIGHT=810
MARGIN_X=48
MARGIN_TOP=48
MARGIN_BOTTOM=130

SCRIPTS_DIR="$HOME/.MeldingSoftware/scripts"
SCREENSHOT_DIR="$HOME/Desktop/Melding Software Screenshots"
RUNTIME_DIR="$HOME/.MeldingScreenshotRuntime"
SWIFT_FILE="$RUNTIME_DIR/MeldingScreenshotHotKey.swift"
READY_FILE="$RUNTIME_DIR/hotkey-ready"
LOG_FILE="$RUNTIME_DIR/hotkey.log"

mkdir -p "$SCREENSHOT_DIR" "$RUNTIME_DIR"
rm -f "$READY_FILE" "$LOG_FILE"

# ------------------------------------------------------------
# Verify Swift is available.
# Carbon's RegisterEventHotKey gives us a true global shortcut
# without Accessibility/Input Monitoring permission.
# ------------------------------------------------------------
if ! /usr/bin/xcrun --find swift >/dev/null 2>&1; then
    clear
    echo ""
    echo "The macOS Command Line Tools are required for the global screenshot hotkey."
    echo ""
    echo "Install them with:"
    echo "  xcode-select --install"
    echo ""
    echo "After installation finishes, run this helper again."
    echo ""
    read -r -p "Press Enter to exit..."
    exit 1
fi

cat > "$SWIFT_FILE" <<'SWIFT'
import Foundation
import AppKit
import Carbon.HIToolbox

let args = CommandLine.arguments
guard args.count >= 9 else {
    fputs("Missing arguments\n", stderr)
    exit(2)
}

let screenshotDir = args[1]
let readyFile = args[2]
let maxWidth = Int(args[3]) ?? 1440
let maxHeight = Int(args[4]) ?? 810
let marginX = Int(args[5]) ?? 48
let marginTop = Int(args[6]) ?? 48
let marginBottom = Int(args[7]) ?? 130
let parentPID = Int32(args[8]) ?? 0

func runProcess(_ executable: String, _ arguments: [String]) -> (Int32, String) {
    let p = Process()
    let pipe = Pipe()
    p.executableURL = URL(fileURLWithPath: executable)
    p.arguments = arguments
    p.standardOutput = pipe
    p.standardError = pipe

    do {
        try p.run()
        p.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    } catch {
        return (127, error.localizedDescription)
    }
}

func captureFrontTerminal() {
    DispatchQueue.global(qos: .userInitiated).async {
        let appleScript = """
        tell application "Finder"
            set desktopBounds to bounds of window of desktop
        end tell

        set screenLeft to item 1 of desktopBounds
        set screenTop to item 2 of desktopBounds
        set screenRight to item 3 of desktopBounds
        set screenBottom to item 4 of desktopBounds

        set screenWidth to screenRight - screenLeft
        set screenHeight to screenBottom - screenTop

        set maxWidth to \(maxWidth)
        set maxHeight to \(maxHeight)
        set marginX to \(marginX)
        set marginTop to \(marginTop)
        set marginBottom to \(marginBottom)

        set availableWidth to screenWidth - (marginX * 2)
        set availableHeight to screenHeight - marginTop - marginBottom

        set targetWidth to maxWidth
        if targetWidth > availableWidth then
            set targetWidth to availableWidth
        end if

        set targetHeight to (targetWidth * 9) div 16

        if targetHeight > availableHeight then
            set targetHeight to availableHeight
            set targetWidth to (targetHeight * 16) div 9
        end if

        if targetHeight > maxHeight then
            set targetHeight to maxHeight
            set targetWidth to (targetHeight * 16) div 9
        end if

        set targetLeft to screenLeft + ((screenWidth - targetWidth) div 2)
        set targetTop to screenTop + marginTop + ((availableHeight - targetHeight) div 2)
        set targetRight to targetLeft + targetWidth
        set targetBottom to targetTop + targetHeight

        tell application "Terminal"
            if not (exists front window) then return ""
            set bounds of front window to {targetLeft, targetTop, targetRight, targetBottom}
            delay 0.15
            set b to bounds of front window
            return (item 1 of b as text) & "," & (item 2 of b as text) & "," & (item 3 of b as text) & "," & (item 4 of b as text)
        end tell
        """

        let (_, rawBounds) = runProcess("/usr/bin/osascript", ["-e", appleScript])
        let trimmed = rawBounds.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: ",").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }

        guard parts.count == 4 else { return }

        let left = parts[0]
        let top = parts[1]
        let right = parts[2]
        let bottom = parts[3]
        let width = right - left
        let height = bottom - top

        guard width > 0 && height > 0 else { return }

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd_HH-mm-ss-SSS"
        let stamp = formatter.string(from: Date())

        let output = "\(screenshotDir)/Melding Software Screenshot \(stamp).png"
        let region = "\(left),\(top),\(width),\(height)"

        let (status, _) = runProcess(
            "/usr/sbin/screencapture",
            ["-x", "-R\(region)", output]
        )

        if status == 0 {
            _ = runProcess(
                "/usr/bin/afplay",
                ["/System/Library/Sounds/Glass.aiff"]
            )
        }
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.prohibited)

var eventType = EventTypeSpec(
    eventClass: OSType(kEventClassKeyboard),
    eventKind: UInt32(kEventHotKeyPressed)
)

let handler: EventHandlerUPP = { _, _, _ in
    captureFrontTerminal()
    return noErr
}

var eventHandler: EventHandlerRef?
let installStatus = InstallEventHandler(
    GetApplicationEventTarget(),
    handler,
    1,
    &eventType,
    nil,
    &eventHandler
)

guard installStatus == noErr else {
    try? "ERROR: InstallEventHandler \(installStatus)".write(
        toFile: readyFile,
        atomically: true,
        encoding: .utf8
    )
    exit(3)
}

let hotKeyID = EventHotKeyID(
    signature: OSType(0x4D534353), // 'MSCS'
    id: 1
)

var hotKeyRef: EventHotKeyRef?

// S key + Control + Option.
// Carbon hotkeys are global and consume the shortcut before the
// foreground command (such as cmatrix) receives it.
let registerStatus = RegisterEventHotKey(
    UInt32(kVK_ANSI_S),
    UInt32(controlKey | optionKey),
    hotKeyID,
    GetApplicationEventTarget(),
    0,
    &hotKeyRef
)

guard registerStatus == noErr else {
    try? "ERROR: RegisterEventHotKey \(registerStatus)".write(
        toFile: readyFile,
        atomically: true,
        encoding: .utf8
    )
    exit(4)
}

try? "READY".write(
    toFile: readyFile,
    atomically: true,
    encoding: .utf8
)

// Shut down automatically if the .command parent exits.
if parentPID > 0 {
    DispatchQueue.global().async {
        while true {
            if kill(parentPID, 0) != 0 {
                DispatchQueue.main.async {
                    NSApplication.shared.terminate(nil)
                }
                return
            }
            Thread.sleep(forTimeInterval: 1.0)
        }
    }
}

app.run()

if let ref = hotKeyRef {
    UnregisterEventHotKey(ref)
}
if let eventHandler {
    RemoveEventHandler(eventHandler)
}
SWIFT

# ------------------------------------------------------------
# Start the true global hotkey process.
# ------------------------------------------------------------
/usr/bin/xcrun swift "$SWIFT_FILE" \
    "$SCREENSHOT_DIR" \
    "$READY_FILE" \
    "$MAX_WIDTH" \
    "$MAX_HEIGHT" \
    "$MARGIN_X" \
    "$MARGIN_TOP" \
    "$MARGIN_BOTTOM" \
    "$$" \
    >"$LOG_FILE" 2>&1 &

HOTKEY_PID=$!

cleanup_helper() {
    if kill -0 "$HOTKEY_PID" >/dev/null 2>&1; then
        kill "$HOTKEY_PID" >/dev/null 2>&1 || true
    fi
    rm -f "$READY_FILE"
}
trap cleanup_helper EXIT

# Wait for Swift compilation/hotkey registration to finish.
for _ in {1..150}; do
    if [[ -f "$READY_FILE" ]]; then
        break
    fi

    if ! kill -0 "$HOTKEY_PID" >/dev/null 2>&1; then
        break
    fi

    sleep 0.1
done

if [[ ! -f "$READY_FILE" ]]; then
    clear
    echo ""
    echo "The global screenshot helper could not start."
    echo ""
    echo "Diagnostic log:"
    cat "$LOG_FILE" 2>/dev/null || true
    echo ""
    read -r -p "Press Enter to exit..."
    exit 1
fi

HOTKEY_STATUS="$(cat "$READY_FILE" 2>/dev/null || true)"
if [[ "$HOTKEY_STATUS" != "READY" ]]; then
    clear
    echo ""
    echo "The global screenshot hotkey could not be registered."
    echo "$HOTKEY_STATUS"
    echo ""
    echo "Try closing any app that may already use Control + Option + S."
    echo ""
    read -r -p "Press Enter to exit..."
    exit 1
fi

# ------------------------------------------------------------
# Resize and center the initial Terminal window.
# The global hotkey repeats this sizing before every screenshot,
# including Terminal windows opened later by other scripts.
# ------------------------------------------------------------
osascript <<APPLESCRIPT >/dev/null 2>&1
tell application "Finder"
    set desktopBounds to bounds of window of desktop
end tell

set screenLeft to item 1 of desktopBounds
set screenTop to item 2 of desktopBounds
set screenRight to item 3 of desktopBounds
set screenBottom to item 4 of desktopBounds

set screenWidth to screenRight - screenLeft
set screenHeight to screenBottom - screenTop

set maxWidth to $MAX_WIDTH
set maxHeight to $MAX_HEIGHT
set marginX to $MARGIN_X
set marginTop to $MARGIN_TOP
set marginBottom to $MARGIN_BOTTOM

set availableWidth to screenWidth - (marginX * 2)
set availableHeight to screenHeight - marginTop - marginBottom

set targetWidth to maxWidth
if targetWidth > availableWidth then
    set targetWidth to availableWidth
end if

set targetHeight to (targetWidth * 9) div 16

if targetHeight > availableHeight then
    set targetHeight to availableHeight
    set targetWidth to (targetHeight * 16) div 9
end if

if targetHeight > maxHeight then
    set targetHeight to maxHeight
    set targetWidth to (targetHeight * 16) div 9
end if

set targetLeft to screenLeft + ((screenWidth - targetWidth) div 2)
set targetTop to screenTop + marginTop + ((availableHeight - targetHeight) div 2)
set targetRight to targetLeft + targetWidth
set targetBottom to targetTop + targetHeight

tell application "Terminal"
    activate

    if not (exists front window) then
        do script ""
        delay 0.2
    end if

    set bounds of front window to {targetLeft, targetTop, targetRight, targetBottom}
end tell
APPLESCRIPT

sleep 0.4
printf '\033]0;Melding Software - Screenshot Mode\007'

pause_menu() {
    echo ""
    read -r -p "Press Enter to return to the menu..." _ </dev/tty || true
}

run_script() {
    local script="$1"
    local script_path="$SCRIPTS_DIR/$script"

    if [[ ! -f "$script_path" ]]; then
        echo ""
        echo "Missing script: $script"
        echo "Expected location: $script_path"
        pause_menu
        return
    fi

    chmod +x "$script_path" 2>/dev/null || true
    clear
    echo "Running $script"
    echo "------------------------------------------------------------"
    "$script_path"
    pause_menu
}

if [[ ! -d "$SCRIPTS_DIR" ]]; then
    clear
    echo ""
    echo "Melding Software scripts were not found."
    echo ""
    echo "Expected location:"
    echo "  $SCRIPTS_DIR"
    echo ""
    echo "Install Melding Software first, then run this helper again."
    echo ""
    read -r -p "Press Enter to exit..."
    exit 1
fi

while true; do
    clear
    echo "MeldingSoftware"
    echo "------------------------------------------------------------"
    echo "Select a script to run:"
    echo ""
    echo "  0) Exit"
    echo "  1) DeBloater"
    echo "  2) Fun Commands"
    echo "  3) Installed Apps"
    echo "  4) Largest Files"
    echo "  5) Maintenance"
    echo "  6) Melder"
    echo "  7) Print Spooler Fix"
    echo "  8) Repair Tool"
    echo "  9) System Info"
    echo " 10) Threat Inspection"
    echo " 11) Update Fix"
    echo " 12) Wi-Fi Info"
    echo ""
    read -r -p "Enter a number: " choice </dev/tty || choice=""

    case "$choice" in
        0) clear; break ;;
        1) run_script "DeBloater.sh" ;;
        2) run_script "Fun_Commands.sh" ;;
        3) run_script "Installed_Apps.sh" ;;
        4) run_script "Largest_Files.sh" ;;
        5) run_script "Maintenance.sh" ;;
        6) run_script "Melder.sh" ;;
        7) run_script "Print_Spooler_Fix.sh" ;;
        8) run_script "Repair_Tool.sh" ;;
        9) run_script "System_Info.sh" ;;
        10) run_script "Threat_Inspection.sh" ;;
        11) run_script "Update_Fix.sh" ;;
        12) run_script "Wi-Fi_Info.sh" ;;
        *) echo "Invalid choice."; sleep 1 ;;
    esac
done

echo ""
read -r -p "Press Enter to exit..."
