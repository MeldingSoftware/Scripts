#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Performs a Windows 10/11 malicious-threat inspection and creates an HTML report.

.DESCRIPTION
    Inspects the locations and settings from the Windows 10/11 Malicious Threat Checklist:
    remote access, installed programs/startup, Autoruns/persistence, scheduled tasks,
    services/drivers/processes, suspicious recent files, browsers, network configuration, and
    Windows Security. Findings are classified as Good, Review, Warning, or Info.

    The script does not remediate or delete inspected files, disable security settings, quarantine threats, or upload files/hashes.
    To support one-click File Explorer links from the HTML report, it places a hidden link helper
    in the Threat Inspection script folder (or Desktop\Threat Inspection when run elsewhere),
    not under AppData, and registers the threatinspection:// URL protocol under HKCU.
    If Microsoft Autorunsc is not already available, it can be downloaded temporarily from
    download.sysinternals.com, verified as Microsoft-signed, used locally, and removed afterward.

.PARAMETER RecentDays
    Number of days used for recent-app and recent-file review. Default: 30.

.PARAMETER SkipAutorunsDownload
    Do not download Autoruns if Autorunsc is not already available in PATH.

.PARAMETER NoOpenReport
    Create the HTML report but do not automatically open it when inspection completes.

.PARAMETER DeepScan
    Run a broad fixed-drive scan without prompting. Traverses fixed-drive roots to a maximum
    depth of 64, includes cache/package trees, and can take substantially longer.

.PARAMETER NoScanPrompt
    Select the standard targeted scan without the interactive Deep Scan question.
    For automated deep scans, supply -DeepScan instead.

.PARAMETER NoReportLinks
    Do not register or update the threatinspection:// Windows URI handler or its
    persistent helper. Existing registrations from earlier runs are not changed.

.PARAMETER UnregisterReportLinks
    Remove a previously generated threatinspection:// registration when its command
    is clearly identified as this script's own helper. No unrelated protocol is removed.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$RecentDays = 30,

    [switch]$SkipAutorunsDownload,
    [switch]$NoOpenReport,
    [switch]$DeepScan,
    [switch]$NoScanPrompt,
    [switch]$NoReportLinks,
    [switch]$UnregisterReportLinks
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ----------------------------------------------------
# Threat Inspection v2.4
# Windows 10/11 inspection and HTML report.
# v1.7: Split Accounts and Remote Access sections; recognize Codex sandbox accounts as expected inventory; remote-tool path fallback. (Accounts inspection removed in v1.13.)
# v1.8: Tightened artifact matching (Wave Browser/DriverFix/DeskIn), HomeGroupUser$ inventory handling, Remote Assistance Info state, and Autoruns invalid-path resilience.
# v1.9: Reduced ScreenConnect/RMM detail noise, resolved Startup .lnk targets, suppressed Teams WindowsApps Autoruns false positives, added generic Driver_Updater_setup detection, excluded known Threat Inspector AppData footprints, and made remote-access artifacts Warning.
# v1.10: Excluded Threat Inspection ZIP/temp launcher remnants, suppressed known OneDrive scheduled updater task false positives in native/Autoruns checks, and added clickable local folder links to path-backed Review/Warning finding pills.
# v1.11: Treats Maintenance CHKDSK Injection tasks as expected, replaces file:// report links with File Explorer search-ms links, adds Windows Settings/Windows Security links for non-filesystem findings, and expands Review/Warning click-through coverage across sections.
# v1.12: Fixes Maintenance CHKDSK task recognition with leading task-path slashes, stops validly signed scripts from being Review solely by extension, suppresses the known OneDrive CollectSyncLogsLite.bat helper, and expands section-specific Review/Warning links to Task Scheduler, File Explorer, Windows Settings, and Windows Security.
# v1.13: Removed Accounts inspection entirely (local-user/admin enumeration, console output, HTML section/status pill, findings, and account-specific link fallback).
# v1.14: Remote-access software warnings open Installed Apps, remote-access artifacts open their user-root folder (LocalAppData/Roaming/Downloads/Desktop when applicable), and Defender findings use more specific Windows Security destinations for protection settings, PUA settings, and Protection history.
# v1.15: Replaces search-ms folder links with a narrow per-user threatinspection:// URL handler that launches the actual folder in explorer.exe. The helper only accepts encoded local/UNC folder paths and cannot execute arbitrary commands.
# v1.16: Excludes the persistent Threat Inspection link helper from Suspicious Files, forces AppData artifact links to the correct Local/Roaming AppData root, links hosts-file findings directly to the etc folder, and adds custom protocol tool actions so firewall findings open Windows Defender Firewall with Advanced Security (wf.msc).
# v1.17: Replaces the Computer/Operating System/System summary cards with a five-card security dashboard ordered Info, Good, Review, Warning, Antivirus; uses unique counts for all four finding statuses; and reorders the status legend to match.
# v1.18: Aligns finding-pill colors with the top summary cards: Info blue, Good green, Review yellow, and Warning red.
# v1.19: Summary status cards now count the actual Info/Good/Review/Warning finding rows shown in the report instead of deduplicating related concern keys, so card totals always match the visible findings below.
# v1.20: Defender exclusion findings now open the Windows Security Add or remove exclusions page directly via windowsdefender://exclusions/.
# v1.21: Downgrades known-safe recent helper scripts to Info instead of Review: Threat Inspection temporary Run Me.bat launchers, Microsoft OneDrive CollectSyncLogs/CollectSyncLogsLite.bat, and GoogleUpdater uninstall.cmd.
# v1.22: Batch/CMD files are no longer Review merely because they are unsigned scripts. They are surfaced only when filename/content inspection matches common malware behaviors such as encoded PowerShell, download-and-execute chains, Defender/firewall disabling, shadow-copy deletion, suspicious LOLBin use, credential theft, persistence, or known malware-style filenames.
# v1.23: Treats TAP-Windows/OpenVPN virtual adapters as Info rather than Review, and filters stale SecurityCenter2 antivirus registrations from the Antivirus card unless a third-party provider still has a matching installed application or live provider executable. Stale registrations remain visible as Info in Windows Security.
# v1.24: Normalizes Windows duplicate-download suffixes such as (1), (2), etc. before remote-access/PUP artifact matching. This applies centrally to every artifact watchlist entry, so files such as Wave Browser (1).exe and Driver_Updater_setup (2).exe are matched the same as their original names.
# v1.25: Individual Suspicious Files and grouped temporary-bundle Review/Warning links now use the same smart navigation roots as artifact findings. Files under AppData\Local open that user's Local AppData root; Roaming, Downloads, and Desktop map likewise.
# v1.26: Firefox Certificates enterprise-policy values such as ImportEnterpriseRoots=1 are treated as Info rather than Review. Browser-policy rendering now honors each policy finding's stored severity instead of hard-coding every configured policy as Review.
# v1.27: When a verified third-party antivirus provider is present, the Antivirus summary card shows only the verified third-party provider(s) and omits Windows Defender. Defender remains shown when no verified third-party antivirus is present.
# v1.28: Recognizes versioned Microsoft OneDrive Startup/Reporting scheduled-task paths as expected in both native task inspection and Autoruns, and suppresses LG Software false positives where Gram Chat GSearch SearchManager.exe matched the generic Search Manager PUP rule and LG OSD Launcher Radmin.exe matched the Radmin remote-access rule.
# v1.29: Caps excessively long report text/tokens so RMM command lines and generated identifiers cannot dominate the page. Defender status now uses corroborating signals (AMRunningMode, WinDefend service, MsMpEng process, and Defender preferences) before raising a Warning, and Tamper Protection cross-checks the read-only Defender registry state when Get-MpComputerStatus disagrees.
# v1.30: Defender state disagreements are no longer Warning solely because Get-MpComputerStatus/services report inactive while Windows Security Center still registers Defender; ambiguous conflicts become Info unless an explicit disable state is corroborated. Firefox allowed website-notification permissions are read from permissions.sqlite via the built-in Windows SQLite library.
# v1.31: Expands PUP/RMM installer artifact detection for MSI/MSIX/MSP packages and observed Shift, Clear Manuals Library, and Blazer installer filenames. Adds live Windows toast-notification inspection from each user's wpndatabase.db so malicious Edge/Chrome/Brave/Vivaldi/Opera/Firefox notification spam can be detected even when Chromium Preferences do not expose the permission cleanly. Random-looking notification hosts and common fake-virus/license-expired toast language are escalated to Warning.
# v1.32: Adds centralized family-first artifact matching for every PUP/PUA and remote-access/RAT/RMM watchlist entry. Stable product-family names are matched independently of changing version/build numbers, GUIDs, timestamps, random installer suffixes, and Windows duplicate-download suffixes such as (1)/(2). Existing exact patterns and false-positive exclusions remain authoritative.
# v1.33: Optimizes family-first PUP/RMM artifact matching by caching aliases and normalizing artifact filenames only once per lookup. Family matching no longer examines arbitrary command-line arguments, preventing false matches such as UpdateOrchestrator UIEOrchestrator /SendHeartbeat -> Heartbeat RM. The built-in Microsoft UIEOrchestrator task is also explicitly recognized as expected.
# v1.34: Keeps the folder-link helper beside the desktop HTML report instead of under AppData\Melding Software; removes the obsolete known helper safely. Eliminates fixed result limits for known-software artifacts, recent suspicious files and browser notifications and lists each matching artifact path. Reads browser toast payloads as UTF-8/UTF-16 binary XML, follows live SQLite WAL for Firefox permissions, exposes per-profile coverage and read errors, and includes all supported Chromium profile folders and notification permissions. Prunes excluded cache trees before enumeration and caches repeated filename matches to avoid the prior multi-minute artifact scan slowdown.
# v1.4: Large remote-access/RMM and PUP/PUA watchlists; warning matches across apps, runtime, startup, browser extensions, and common folders.
# v1.2: Windows PowerShell 5.1 compatibility fixes for empty Generic List<T> results.
# No inspected files, tasks, services, browser settings, Defender settings,
# firewall rules, or user accounts are modified. The script does register a
# per-user threatinspection:// URL handler under HKCU for report navigation.
# ----------------------------------------------------

# v1.35: Places the hidden report-link helper inside the existing Threat Inspection script folder, or Desktop\Threat Inspection as a fallback, instead of directly on the Desktop. Updates the URL-protocol target, removes the generated old Desktop helper when safe, and excludes the new helper from its own scan.
# v1.36: Corrects broad known-software family false positives by removing automatically generated individual-word aliases (e.g., Chrome, Utilities, Assistant, Deploy, Universal, Protect, Repair). Family matching uses complete branded product/family names, with explicit curated filename patterns retained for dynamically suffixed installers. Artifact matching evaluates each file or directory name rather than inherited parent path text. Separately highlights suspicious, randomly named Run entries that launch a hidden Node.js process from user-writable AppData via conhost --headless.
# v1.37: Treat narrowly identified stale Cisco Webex/CiscoSpark startup shortcuts and legacy WebexHost launchers as Info rather than Review across native Startup and Autoruns, without suppressing suspicious commands or watchlist hits. Add resilient Autorunsc retrieval with HTTPS retries and BITS fallback; require a valid Microsoft Authenticode signature before execution.
# v1.38: Prevents false PUP/RMM artifact matches when a product name appears in the middle of an unrelated filename (e.g. NVIDIA NvDriverUpdateCheck64.dll falsely matched Slimware DriverUpdate). Stable aliases must start the artifact filename, optionally after a conventional installer prefix. Version/build/random suffix matching remains supported.
# v1.39: Fixes the browser notification assessment crash caused by assigning to PowerShell's read-only $Host variable (case-insensitive); uses $notificationHost instead. Surfaces Chromium per-profile allowed/activity counts, reports permission reader failures instead of suppressing them, and marks notification read failures for Review rather than treating them as clean.
# v1.40: Review/Warning browser notification badges launch the matching browser's website-notification settings via a strict allowlisted threatinspection://browser-notifications/<browser> helper route. Recognized Windows toast providers link to the correct browser; unattributed toasts link to Windows notifications. Firefox opens Privacy & Security where notification permissions are managed. No notification permissions are changed automatically.
# v1.41: Deduplicates native scheduled-task Review/Warning findings from Autoruns, keeping the task only in Scheduled Tasks / Services / Processes. Adds per-provider antivirus Active/Off/Snoozed/Expired status via the Windows Security Center product-state COM API (with unknown fallback) and signature freshness where available; displays status in the Antivirus card and Windows Security. Retains all existing Suspicious Files checks for AppData Microsoft and Python directories.
# v2.0: Consolidates the full accuracy, coverage, antivirus, PUP/RMM matching, scan performance, Deep Scan, deduplication, execution-chain detection, navigation-helper controls, HTML search/filter, and regression-test improvements into one release. File scanning shares one enumeration pipeline, reports access failures, and does not exclude AppData Python/Microsoft trees in normal mode. Version and report-section fallback corrected.
# v2.1: Adds an interactive Y/N scan mode prompt (Enter defaults to Standard; -DeepScan bypasses the prompt; -NoScanPrompt supports unattended standard scans). Merges Windows Defender and Microsoft Defender Antivirus into one canonical provider and shows a single status without repeating its name in the Antivirus card.
# v2.2: Corrects mass Deep Scan false positives: signature-validation errors in Windows servicing InFlight files are not by themselves suspicious, and generic recent scripts and executables require actionable path/persistence context. Restricts known-software artifact evidence to executable installers and meaningful product folders; excludes unrelated browser caches, code assets, driver stores, and built-in Quick Assist packages from PUP/RMM warnings. Product-family suffixes require recognizable installer/version structure, and deep-scan coverage is separated into protected OS folders versus other unreadable locations. Maintains Python/Microsoft AppData inspection and distinct Defender/execution-chain warnings.
# v2.3: Classifies Defender threat detection history using ThreatStatusID, successful remediation, additional actions, reported error and execution state. Removed/Cleaned/Quarantined/Blocked detections with confirmed successful handling become Info; allowed or uncertain entries remain Review; failures and executing threats remain Warning. Preserves detailed status and paths in the report.
# v2.4: Treats historical Defender records with an unreported/Unknown final ThreatStatusID as Info only when the cleaning action explicitly succeeded, no additional actions or status errors remain, and execution status is Blocked or NotExecuting. Reports the exact remediation type as unavailable rather than assuming Removed; raw status and human-readable execution details are retained. Failed, executing, allowed, and incomplete evidence stay Review/Warning.
# ----------------------------------------------------
# Console Helpers
# ----------------------------------------------------
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern System.IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(System.IntPtr hWnd, System.Int32 nCmdShow);

[DllImport("user32.dll")]
public static extern bool SetForegroundWindow(System.IntPtr hWnd);
' -ErrorAction SilentlyContinue

function Show-Console {
    try {
        $consolePtr = [Console.Window]::GetConsoleWindow()
        if ($consolePtr -eq [IntPtr]::Zero) {
            $consolePtr = (Get-Process -Id $PID -ErrorAction SilentlyContinue).MainWindowHandle
        }
        if ($consolePtr -ne [IntPtr]::Zero) {
            [Console.Window]::ShowWindow($consolePtr, 3) | Out-Null
            [Console.Window]::SetForegroundWindow($consolePtr) | Out-Null
        }
        try {
            $raw = $Host.UI.RawUI
            $raw.WindowSize = $raw.MaxPhysicalWindowSize
        } catch { }
    } catch { }
}

function Write-SectionHeader {
    param([Parameter(Mandatory)][string]$Title)
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ""
}

function Write-ResultLine {
    param(
        [ValidateSet('Good','Review','Warning','Info')]
        [string]$Status,
        [string]$Text
    )

    $color = switch ($Status) {
        'Good'    { 'Green' }
        'Review'  { 'Yellow' }
        'Warning' { 'Red' }
        default   { 'Gray' }
    }

    Write-Host ("[{0}] {1}" -f $Status, $Text) -ForegroundColor $color
}

function Write-FindingsConsole {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.IEnumerable]$Findings,
        [int]$MaxAttentionLines = 20
    )

    $itemsList = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Findings) {
        foreach ($findingItem in $Findings) {
            if ($null -ne $findingItem) { $itemsList.Add($findingItem) | Out-Null }
        }
    }
    $items = $itemsList.ToArray()
    $warnings = @($items | Where-Object Status -eq 'Warning')
    $reviews  = @($items | Where-Object Status -eq 'Review')
    $good     = @($items | Where-Object Status -eq 'Good')
    $info     = @($items | Where-Object Status -eq 'Info')

    $attention = @($warnings + $reviews)
    foreach ($finding in $attention | Select-Object -First $MaxAttentionLines) {
        Write-ResultLine $finding.Status $finding.Text
    }
    if ($attention.Count -gt $MaxAttentionLines) {
        Write-Host ("... {0} additional Review/Warning item(s) are in the HTML report." -f ($attention.Count - $MaxAttentionLines)) -ForegroundColor DarkGray
    }

    if ($attention.Count -eq 0) {
        Write-Host "No Review or Warning items were generated for this section." -ForegroundColor Green
    }

    Write-Host ("Captured: {0} Good | {1} Review | {2} Warning | {3} Info" -f $good.Count, $reviews.Count, $warnings.Count, $info.Count) -ForegroundColor DarkGray
    Write-Host ""
}

try { Show-Console } catch { }

function Resolve-InspectionDeepScan {
    param(
        [bool]$Requested = $false,
        [bool]$Explicit = $false,
        [bool]$SkipPrompt = $false
    )

    # Command-line selection takes precedence and prevents prompts in scripts.
    if ($Explicit) { return $Requested }
    if ($SkipPrompt) { return $false }

    # Never block a scheduled/background run waiting for console input.
    $interactiveConsole = $false
    try {
        $interactiveConsole = [Environment]::UserInteractive -and (-not [Console]::IsInputRedirected)
    } catch { $interactiveConsole = $false }
    if (-not $interactiveConsole) {
        Write-Host 'No interactive console detected; using Standard Scan.' -ForegroundColor DarkGray
        return $false
    }

    Write-Host ''
    Write-Host 'Scan Mode' -ForegroundColor Cyan
    Write-Host 'Standard Scan: Common high-risk locations (recommended)' -ForegroundColor Gray
    Write-Host 'Deep Scan: All local fixed drives, including large caches; may take much longer' -ForegroundColor Gray
    Write-Host ''
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        try { $answer = [string](Read-Host 'Run a deep scan? (y/n, Enter = n)') }
        catch {
            Write-Host 'Unable to read a response; using Standard Scan.' -ForegroundColor Yellow
            return $false
        }
        $answer = $answer.Trim()
        if ($answer -match '^(?i:y|yes)$') { return $true }
        if ($answer -eq '' -or $answer -match '^(?i:n|no)$') { return $false }
        Write-Host 'Please enter y or n.' -ForegroundColor Yellow
    }
    Write-Host 'No valid selection; using Standard Scan.' -ForegroundColor Yellow
    return $false
}

$DeepScan = [bool](Resolve-InspectionDeepScan -Requested ([bool]$DeepScan) -Explicit ($PSBoundParameters.ContainsKey('DeepScan')) -SkipPrompt ([bool]$NoScanPrompt))
Write-Host ('Selected: ' + $(if ($DeepScan) { 'Deep Scan' } else { 'Standard Scan' })) -ForegroundColor Cyan
Write-Host ''

# ----------------------------------------------------
# Paths & Base Setup
# ----------------------------------------------------
$desktopRoot      = [Environment]::GetFolderPath('Desktop')
$localAppDataRoot = [Environment]::GetFolderPath('LocalApplicationData')
$dateStamp        = Get-Date -Format 'MM-dd-yy'
$timeStamp        = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$reportName       = "Threat Inspection $dateStamp.html"
$finalReportPath  = Join-Path $desktopRoot $reportName
$tempRoot         = Join-Path $localAppDataRoot 'Threat Inspection Temp'
$autorunsRoot     = Join-Path $tempRoot 'Autoruns'
$autorunsZip      = Join-Path $tempRoot 'Autoruns.zip'
$autorunsCsv      = Join-Path $tempRoot 'Autoruns.csv'
$script:SelfPath = if ($PSCommandPath) { [System.IO.Path]::GetFullPath($PSCommandPath) } else { '' }
$script:SelfRoot = if ($script:SelfPath) { Split-Path -Parent $script:SelfPath } else { '' }

if (Test-Path -LiteralPath $tempRoot) {
    try { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    (Get-Item -LiteralPath $tempRoot -Force).Attributes = ((Get-Item -LiteralPath $tempRoot -Force).Attributes -bor [System.IO.FileAttributes]::Hidden)
} catch { }

# ----------------------------------------------------
# Generic Helpers
# ----------------------------------------------------
function Limit-DisplayText {
    param(
        [AllowNull()][string]$Text,
        [int]$MaxLength = 1000,
        [int]$MaxTokenLength = 220
    )

    if ([string]::IsNullOrEmpty($Text)) { return '' }

    $value = [string]$Text

    # Generated support tokens, encoded payloads, hashes, GUID-like blobs, etc.
    # can be thousands of characters long with no spaces. Shorten only the
    # display copy; the underlying finding/link data remains unchanged.
    if ($MaxTokenLength -gt 20) {
        try {
            $tokenPattern = '\S{' + ($MaxTokenLength + 1) + ',}'
            $value = [regex]::Replace(
                $value,
                $tokenPattern,
                {
                    param($m)
                    $keep = [Math]::Min($MaxTokenLength, $m.Value.Length)
                    $m.Value.Substring(0, $keep) + '…[token truncated]'
                }
            )
        } catch { }
    }

    if ($MaxLength -gt 20 -and $value.Length -gt $MaxLength) {
        $omitted = $value.Length - $MaxLength
        $value = $value.Substring(0, $MaxLength).TrimEnd() + " … [truncated $omitted chars]"
    }

    return $value
}

function Convert-ToHtmlSafe {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Names
    )
    foreach ($name in $Names) {
        $prop = $Object.PSObject.Properties[$name]
        if ($prop) { return $prop.Value }
    }
    return $null
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$List,
        [Parameter(Mandatory)][ValidateSet('Good','Review','Warning','Info')][string]$Status,
        [Parameter(Mandatory)][string]$Text,
        [string]$Detail = '',
        [string]$ConcernKey = '',
        [string]$LinkPath = '',
        [string]$LinkUri = ''
    )

    $List.Add([PSCustomObject]@{
        Status     = $Status
        Text       = $Text
        Detail     = $Detail
        ConcernKey = $ConcernKey
        LinkPath   = $LinkPath
        LinkUri    = $LinkUri
    }) | Out-Null
}

function Get-ArtifactNavigationRoot {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }

    $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))

    # Preserve the exact user profile represented by the artifact rather than
    # assuming the currently elevated account owns it.
    if ($expanded -match '(?i)^(?<root>[A-Z]:\\Users\\[^\\]+\\AppData\\Local)(?:\\|$)') {
        return $matches['root']
    }
    if ($expanded -match '(?i)^(?<root>[A-Z]:\\Users\\[^\\]+\\AppData\\Roaming)(?:\\|$)') {
        return $matches['root']
    }
    if ($expanded -match '(?i)^(?<root>[A-Z]:\\Users\\[^\\]+\\Downloads)(?:\\|$)') {
        return $matches['root']
    }
    if ($expanded -match '(?i)^(?<root>[A-Z]:\\Users\\[^\\]+\\Desktop)(?:\\|$)') {
        return $matches['root']
    }

    try {
        if (Test-Path -LiteralPath $expanded -PathType Container -ErrorAction SilentlyContinue) {
            return $expanded
        }
        $parent = Split-Path -Path $expanded -Parent
        if ($parent) { return $parent }
    } catch { }

    return ''
}

function Install-ThreatInspectionProtocolHandler {
    try {
        # Keep the persistent navigation helper inside the Threat Inspection
        # folder, never directly on the Desktop or under AppData\Melding Software.
        # Prefer the existing folder containing this script. If this script was
        # launched from Downloads or a ZIP's temporary extraction folder, use a
        # stable Desktop\Threat Inspection folder instead.
        $helperFolder = ''
        if ($script:SelfRoot) {
            $candidateFolder = $script:SelfRoot
            while ($candidateFolder -and (Test-Path -LiteralPath $candidateFolder -PathType Container -ErrorAction SilentlyContinue)) {
                $candidateName = Split-Path -Path $candidateFolder -Leaf
                $isTemporaryExtraction = ($candidateFolder -match '(?i)\\(?:AppData\\Local\\Temp|Windows\\Temp)(?:\\|$)') -or
                    ($candidateFolder -match '(?i)\.zip(?:[._ -]\d+)?(?:\\|$)')
                if (-not $isTemporaryExtraction -and
                    $candidateName -match '(?i)^Threat[ _-]+Inspection(?:[ _.-]*v?\d+(?:\.\d+)*)?$') {
                    $helperFolder = $candidateFolder
                    break
                }
                $parentFolder = Split-Path -Path $candidateFolder -Parent
                if (-not $parentFolder -or $parentFolder -eq $candidateFolder) { break }
                $candidateFolder = $parentFolder
            }
        }
        if (-not $helperFolder) {
            $helperFolder = Join-Path $desktopRoot 'Threat Inspection'
            if (-not (Test-Path -LiteralPath $helperFolder -PathType Container)) {
                New-Item -ItemType Directory -Path $helperFolder -Force -ErrorAction Stop | Out-Null
            }
        }

        $helperPath = Join-Path $helperFolder '.ThreatInspectionLink.ps1'
        $script:ThreatInspectionHelperPath = $helperPath

        $helperCode = @'
param(
    [Parameter(Position=0)]
    [string]$Uri
)

if ([string]::IsNullOrWhiteSpace($Uri)) { exit }

try {
    # Only a small hard-coded set of Windows tools can be launched.
    if ($Uri -match '^threatinspection://tool/(?<tool>[a-z0-9-]+)/?$') {
        $tool = $matches['tool'].ToLowerInvariant()
        switch ($tool) {
            'firewall' {
                $target = Join-Path $env:SystemRoot 'System32\wf.msc'
                if (Test-Path -LiteralPath $target) { Start-Process -FilePath $target }
            }
            'scheduler' {
                $target = Join-Path $env:SystemRoot 'System32\taskschd.msc'
                if (Test-Path -LiteralPath $target) { Start-Process -FilePath $target }
            }
            'services' {
                $target = Join-Path $env:SystemRoot 'System32\services.msc'
                if (Test-Path -LiteralPath $target) { Start-Process -FilePath $target }
            }
            'devicemanager' {
                $target = Join-Path $env:SystemRoot 'System32\devmgmt.msc'
                if (Test-Path -LiteralPath $target) { Start-Process -FilePath $target }
            }
            'taskmanager' {
                $target = Join-Path $env:SystemRoot 'System32\Taskmgr.exe'
                if (Test-Path -LiteralPath $target) { Start-Process -FilePath $target }
            }
        }
        exit
    }

    # Browser notification settings are fixed internal browser pages, never
    # arbitrary user-supplied URLs or commands. Only known browser IDs can
    # pass through this route; the URL and executable names are hard-coded.
    if ($Uri -match '^threatinspection://browser-notifications/(?<browser>chrome|edge|brave|vivaldi|opera-gx|opera|firefox)/?$') {
        $browserId = $matches['browser'].ToLowerInvariant()
        $settingsPage = ''
        $relativePaths = @()
        $appPathExecutables = @()
        switch ($browserId) {
            'chrome' {
                $settingsPage = 'chrome://settings/content/notifications'
                $relativePaths = @('Google\Chrome\Application\chrome.exe')
                $appPathExecutables = @('chrome.exe')
            }
            'edge' {
                $settingsPage = 'edge://settings/content/notifications'
                $relativePaths = @('Microsoft\Edge\Application\msedge.exe')
                $appPathExecutables = @('msedge.exe')
            }
            'brave' {
                $settingsPage = 'brave://settings/content/notifications'
                $relativePaths = @('BraveSoftware\Brave-Browser\Application\brave.exe')
                $appPathExecutables = @('brave.exe')
            }
            'vivaldi' {
                # Chromium's protected content-settings page is accessible
                # from Vivaldi through its internal chrome:// settings pages.
                $settingsPage = 'chrome://settings/content/notifications'
                $relativePaths = @('Vivaldi\Application\vivaldi.exe')
                $appPathExecutables = @('vivaldi.exe')
            }
            'opera-gx' {
                $settingsPage = 'opera://settings/content/notifications'
                $relativePaths = @('Programs\Opera GX\launcher.exe', 'Programs\Opera GX\opera.exe', 'Opera GX\launcher.exe', 'Opera GX\opera.exe')
            }
            'opera' {
                $settingsPage = 'opera://settings/content/notifications'
                $relativePaths = @('Programs\Opera\launcher.exe', 'Programs\Opera\opera.exe', 'Opera\launcher.exe', 'Opera\opera.exe')
            }
            'firefox' {
                # Firefox exposes website-notification permissions from the
                # Privacy & Security pane, under Permissions > Notifications.
                $settingsPage = 'about:preferences#privacy'
                $relativePaths = @('Mozilla Firefox\firefox.exe', 'Programs\Mozilla Firefox\firefox.exe')
                $appPathExecutables = @('firefox.exe')
            }
        }

        # Resolve the installed browser itself, not the browser displaying the
        # HTML report. Never execute an executable or URL supplied in the URI.
        $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
        $browserExe = ''
        foreach ($root in $roots) {
            foreach ($relative in $relativePaths) {
                $candidate = Join-Path $root $relative
                if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) {
                    $browserExe = $candidate
                    break
                }
            }
            if ($browserExe) { break }
        }

        # App Paths supports Chrome/Edge/Brave/Firefox/Vivaldi installed in
        # non-default locations. Only an exact allowlisted executable basename
        # is acceptable; registry values are not treated as command strings.
        if (-not $browserExe) {
            foreach ($exeName in $appPathExecutables) {
                foreach ($hive in @('HKLM:', 'HKCU:')) {
                    $appKey = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$exeName"
                    try {
                        $regKey = Get-Item -LiteralPath $appKey -ErrorAction Stop
                        $registered = [string]$regKey.GetValue('')
                        if ($registered -and
                            [IO.Path]::GetFileName($registered).Equals($exeName, [StringComparison]::OrdinalIgnoreCase) -and
                            (Test-Path -LiteralPath $registered -PathType Leaf -ErrorAction SilentlyContinue)) {
                            $browserExe = $registered
                            break
                        }
                    } catch { }
                }
                if ($browserExe) { break }
            }
        }

        if ($browserExe -and $settingsPage) {
            Start-Process -FilePath $browserExe -ArgumentList @($settingsPage)
        }
        exit
    }

    if ($Uri -notmatch '^threatinspection://folder/(?<payload>[A-Za-z0-9_-]+)/?$') {
        exit
    }

    $payload = $matches['payload'].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
        1 { exit }
    }

    $bytes = [Convert]::FromBase64String($payload)
    $path = [Text.Encoding]::UTF8.GetString($bytes)
    if ([string]::IsNullOrWhiteSpace($path)) { exit }

    $path = [Environment]::ExpandEnvironmentVariables($path.Trim().Trim('"'))

    # Only allow rooted local-drive or UNC filesystem paths.
    if ($path -notmatch '^(?:[A-Za-z]:\\|\\\\)') { exit }

    $target = ''
    if (Test-Path -LiteralPath $path -PathType Container -ErrorAction SilentlyContinue) {
        $target = $path
    } elseif (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction SilentlyContinue) {
        $target = Split-Path -LiteralPath $path -Parent
    } else {
        try {
            $parent = Split-Path -Path $path -Parent
            if ($parent -and (Test-Path -LiteralPath $parent -PathType Container -ErrorAction SilentlyContinue)) {
                $target = $parent
            }
        } catch { }
    }

    if ([string]::IsNullOrWhiteSpace($target)) { exit }

    # Opening a directory directly through the Windows shell launches normal File Explorer.
    Start-Process -FilePath $target
} catch { }
'@

        Set-Content -LiteralPath $helperPath -Value $helperCode -Encoding UTF8 -Force
        try {
            $helperFile = Get-Item -LiteralPath $helperPath -Force -ErrorAction Stop
            $helperFile.Attributes = $helperFile.Attributes -bor [IO.FileAttributes]::Hidden
        } catch { }

        $protocolRoot = 'HKCU:\Software\Classes\threatinspection'
        $commandKey = Join-Path $protocolRoot 'shell\open\command'
        $iconKey = Join-Path $protocolRoot 'DefaultIcon'

        New-Item -Path $protocolRoot -Force | Out-Null
        Set-Item -Path $protocolRoot -Value 'URL:Threat Inspection'
        New-ItemProperty -Path $protocolRoot -Name 'URL Protocol' -Value '' -PropertyType String -Force | Out-Null

        New-Item -Path $iconKey -Force | Out-Null
        Set-Item -Path $iconKey -Value (Join-Path $env:SystemRoot 'explorer.exe')

        New-Item -Path $commandKey -Force | Out-Null
        $powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $command = '"{0}" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{1}" "%1"' -f $powershellExe, $helperPath
        Set-Item -Path $commandKey -Value $command

        # Remove the v1.34 helper from the Desktop only if it is recognizably
        # ours. Do not remove any unrelated user-created script.
        try {
            $oldDesktopHelper = Join-Path $desktopRoot '.ThreatInspectionLink.ps1'
            if ($oldDesktopHelper -ine $helperPath -and
                (Test-Path -LiteralPath $oldDesktopHelper -PathType Leaf)) {
                $oldDesktopText = Get-Content -LiteralPath $oldDesktopHelper -Raw -ErrorAction Stop
                if ($oldDesktopText -match [regex]::Escape('threatinspection://tool/') -and
                    $oldDesktopText -match [regex]::Escape('threatinspection://folder/')) {
                    Remove-Item -LiteralPath $oldDesktopHelper -Force -ErrorAction SilentlyContinue
                }
            }
        } catch { }

        # Clean up only the helper created by prior script versions, and only
        # when the exact generated content markers are present. Never delete
        # unrelated files in a user's existing Melding Software directory.
        try {
            $oldRoot = Join-Path $env:LOCALAPPDATA 'Melding Software\Threat Inspection'
            $oldHelper = Join-Path $oldRoot 'ThreatInspectionLink.ps1'
            if (Test-Path -LiteralPath $oldHelper -PathType Leaf) {
                $oldText = Get-Content -LiteralPath $oldHelper -Raw -ErrorAction Stop
                if ($oldText -match [regex]::Escape('threatinspection://tool/') -and
                    $oldText -match [regex]::Escape('threatinspection://folder/')) {
                    Remove-Item -LiteralPath $oldHelper -Force -ErrorAction SilentlyContinue
                }
            }
            if ((Test-Path -LiteralPath $oldRoot -PathType Container) -and
                @(Get-ChildItem -LiteralPath $oldRoot -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                Remove-Item -LiteralPath $oldRoot -ErrorAction SilentlyContinue
            }
            $oldParent = Join-Path $env:LOCALAPPDATA 'Melding Software'
            if ((Test-Path -LiteralPath $oldParent -PathType Container) -and
                @(Get-ChildItem -LiteralPath $oldParent -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                Remove-Item -LiteralPath $oldParent -ErrorAction SilentlyContinue
            }
        } catch { }

        return $true
    } catch {
        return $false
    }
}

function Convert-FolderToThreatInspectionUri {
    param([AllowNull()][string]$Folder)

    if ([string]::IsNullOrWhiteSpace($Folder)) { return '' }
    if (-not $script:ThreatInspectionProtocolReady) { return '' }

    try {
        $expanded = [Environment]::ExpandEnvironmentVariables($Folder.Trim().Trim('"'))
        if (-not (Test-Path -LiteralPath $expanded -PathType Container -ErrorAction SilentlyContinue)) {
            return ''
        }

        $full = $expanded
        try { $full = [System.IO.Path]::GetFullPath($expanded) } catch { }

        $bytes = [Text.Encoding]::UTF8.GetBytes($full)
        $payload = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        return ('threatinspection://folder/' + $payload)
    } catch { }

    return ''
}

function Convert-LocalPathToExplorerUri {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    if (-not $script:ThreatInspectionProtocolReady) { return '' }

    try {
        $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
        if ($expanded -match '(?i)^File not found:\s*(.+)$') {
            $expanded = $matches[1].Trim().Trim('"')
        }

        $folder = ''
        if (Test-Path -LiteralPath $expanded -PathType Container -ErrorAction SilentlyContinue) {
            $folder = $expanded
        } elseif (Test-Path -LiteralPath $expanded -PathType Leaf -ErrorAction SilentlyContinue) {
            $folder = Split-Path -LiteralPath $expanded -Parent
        } else {
            try {
                $folder = Split-Path -Path $expanded -Parent
            } catch {
                $folder = ''
            }
        }

        if ([string]::IsNullOrWhiteSpace($folder)) { return '' }

        $full = $folder
        try { $full = [System.IO.Path]::GetFullPath($folder) } catch { }

        $bytes = [Text.Encoding]::UTF8.GetBytes($full)
        $payload = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        return ('threatinspection://folder/' + $payload)
    } catch { }

    return ''
}

function Unregister-ThreatInspectionOwnProtocol {
    $protocolRoot = 'HKCU:\Software\Classes\threatinspection'
    try {
        $command = [string](Get-Item -LiteralPath (Join-Path $protocolRoot 'shell\open\command') -ErrorAction Stop).GetValue('')
        if ($command -match '(?i)ThreatInspectionLink\.ps1' -and
            $command -match '(?i)WindowsPowerShell\\v1\.0\\powershell\.exe') {
            Remove-Item -LiteralPath $protocolRoot -Recurse -Force -ErrorAction Stop
            return $true
        }
    } catch { }
    return $false
}

$script:ThreatInspectionProtocolReady = $false
if ($UnregisterReportLinks) {
    if (Unregister-ThreatInspectionOwnProtocol) {
        Write-Host 'Previous Threat Inspection report-link registration was removed.' -ForegroundColor DarkGray
    } else {
        Write-Host 'No owned report-link registration was removed.' -ForegroundColor DarkGray
    }
}
if (-not $NoReportLinks -and -not $UnregisterReportLinks) {
    $script:ThreatInspectionProtocolReady = Install-ThreatInspectionProtocolHandler
}

function Get-SectionStatus {
    param([AllowEmptyCollection()][System.Collections.IEnumerable]$Findings)

    $hasWarning = $false
    $hasReview  = $false
    $hasGood    = $false

    if ($null -ne $Findings) {
        foreach ($item in $Findings) {
            if ($null -eq $item) { continue }
            switch ([string]$item.Status) {
                'Warning' { $hasWarning = $true }
                'Review'  { $hasReview  = $true }
                'Good'    { $hasGood    = $true }
            }
        }
    }

    if ($hasWarning) { return 'Warning' }
    if ($hasReview)  { return 'Review' }
    if ($hasGood)    { return 'Good' }
    return 'Info'
}

function Get-SeverityRank {
    param([string]$Status)
    switch ($Status) {
        'Warning' { return 4 }
        'Review'  { return 3 }
        'Info'    { return 2 }
        'Good'    { return 1 }
        default   { return 0 }
    }
}


function Get-UniqueConcernCount {
    param(
        [AllowEmptyCollection()][System.Collections.IEnumerable]$Findings,
        [Parameter(Mandatory)][ValidateSet('Info','Good','Review','Warning')][string]$Status
    )

    $seen = @{}
    if ($null -ne $Findings) {
        foreach ($item in $Findings) {
            if ($null -eq $item -or [string]$item.Status -ne $Status) { continue }
            $key = if ($item.PSObject.Properties['ConcernKey'] -and -not [string]::IsNullOrWhiteSpace([string]$item.ConcernKey)) {
                ([string]$item.ConcernKey).Trim().ToLowerInvariant()
            } else {
                ([string]$item.Text).Trim().ToLowerInvariant()
            }
            if ($key) { $seen[$key] = $true }
        }
    }
    return $seen.Count
}

function Test-IsInspectionOwnPath {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { $full = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))) } catch { $full = $Path }

    if ($script:SelfPath -and $full -ieq $script:SelfPath) { return $true }
    if ($script:SelfRoot -and $full -ieq (Join-Path $script:SelfRoot 'ThreatInspection_v2.3_Tests.ps1')) { return $true }
    if ($finalReportPath -and $full -ieq $finalReportPath) { return $true }
    # The persistent URL navigation helper is generated by this script.
    if ($script:ThreatInspectionHelperPath -and $full -ieq $script:ThreatInspectionHelperPath) { return $true }
    # Ignore the generated v1.34 Desktop helper if cleanup could not remove it.
    $oldDesktopHelper = Join-Path $desktopRoot '.ThreatInspectionLink.ps1'
    if ($full -ieq $oldDesktopHelper) { return $true }
    if ($tempRoot -and $full.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }

    # Known Threat Inspection / Threat Inspector application footprints under AppData.
    # These are retained as trusted tool paths so the inspector does not flag its own
    # supporting application files as suspicious simply because AppData is user-writable.
    if ($full -match '(?i)\\AppData\\(?:Local|Roaming)\\Threat\s*Inspect(?:ion|or)(?:\\|$)') { return $true }

    # Persistent report-link helper created by Threat Inspection itself.
    if ($full -match '(?i)\\AppData\\Local\\Melding Software\\Threat Inspection(?:\\|$)') { return $true }

    # Windows/Explorer may execute the ZIP contents from a temporary extraction folder
    # named like "Threat Inspection.zip.724". Exclude only the known launcher/script/report
    # files from those extraction folders so unrelated Temp content is still inspected.
    try {
        $leaf = Split-Path -Path $full -Leaf
        $parentLeaf = Split-Path -Path (Split-Path -Path $full -Parent) -Leaf
        if ($leaf -match '(?i)^(?:Run Me\.bat|ThreatInspection(?:_v[\d.]+)?\.ps1|Threat Inspection.*\.html)$' -and
            $parentLeaf -match '(?i)^Threat\s*Inspect(?:ion|or)(?:\.zip)?(?:[._ -].*)?$') {
            return $true
        }
    } catch { }

    if ($script:SelfRoot -and (Test-Path -LiteralPath $script:SelfRoot -PathType Container -ErrorAction SilentlyContinue)) {
        $rootLeaf = Split-Path $script:SelfRoot -Leaf
        if ($rootLeaf -match '(?i)^Threat\s*Inspection') {
            if ($full.StartsWith($script:SelfRoot, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        } elseif ((Split-Path $full -Parent) -ieq $script:SelfRoot -and (Split-Path $full -Leaf) -match '(?i)^(Run Me\.bat|ThreatInspection(?:_v[\d.]+)?\.ps1)$') {
            return $true
        }
    }
    return $false
}

function Get-Sha256Safe {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    try { return [string](Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return '' }
}

function Get-IfeoVerifierReferences {
    param([Parameter(Mandatory)][string]$TargetPath)
    $results = New-Object System.Collections.Generic.List[string]
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    $targetName = [System.IO.Path]::GetFileName($TargetPath)
    try {
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            try {
                $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
                foreach ($name in @('VerifierDlls','Debugger')) {
                    $prop = $props.PSObject.Properties[$name]
                    if (-not $prop -or [string]::IsNullOrWhiteSpace([string]$prop.Value)) { continue }
                    $value = [string]$prop.Value
                    $fullMatch = $value.IndexOf($TargetPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
                    $nameMatch = $targetName -and ($value.IndexOf($targetName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
                    if ($fullMatch -or $nameMatch) {
                        $results.Add(("{0} | {1}={2}" -f $key.PSChildName, $name, $prop.Value)) | Out-Null
                    }
                }
            } catch { }
        }
    } catch { }
    return $results.ToArray()
}

# ----------------------------------------------------
# Known Software Watchlists
# ----------------------------------------------------
# A match means "technician attention required", not "confirmed malware".
# Remote-access/RMM tools are legitimate in many environments but are commonly abused.
# PUP/PUA entries are a technician watchlist and can be customized for local policy.

$script:RemoteAccessWatchlist = @(
    [PSCustomObject]@{ Name='Action1'; NamePattern='(?i)Action1'; ArtifactPattern='(?i)Action1' },
    [PSCustomObject]@{ Name='AeroAdmin'; NamePattern='(?i)AeroAdmin'; ArtifactPattern='(?i)AeroAdmin' },
    [PSCustomObject]@{ Name='Ammyy Admin'; NamePattern='(?i)Ammyy(?:\s*Admin)?'; ArtifactPattern='(?i)Ammyy|AA_v\d+\.exe' },
    [PSCustomObject]@{ Name='AnyDesk'; NamePattern='(?i)AnyDesk'; ArtifactPattern='(?i)AnyDesk' },
    [PSCustomObject]@{ Name='AnyViewer'; NamePattern='(?i)AnyViewer'; ArtifactPattern='(?i)AnyViewer' },
    [PSCustomObject]@{ Name='Atera'; NamePattern='(?i)^\s*Atera(?:Agent)?\b|AteraAgent'; ArtifactPattern='(?i)AteraAgent|Atera Networks|\\Atera(?:Agent)?\\' },
    [PSCustomObject]@{ Name='BeyondTrust / Bomgar'; NamePattern='(?i)BeyondTrust|Bomgar'; ArtifactPattern='(?i)BeyondTrust|Bomgar|bomgar-scc' },
    [PSCustomObject]@{ Name='ConnectWise Automate'; NamePattern='(?i)ConnectWise\s+Automate|LabTech'; ArtifactPattern='(?i)ConnectWise\s*Automate|LabTech|LTService|LTSvcMon' },
    [PSCustomObject]@{ Name='ConnectWise ScreenConnect'; NamePattern='(?i)ScreenConnect|ConnectWise\s+(?:Control|ScreenConnect)'; ArtifactPattern='(?i)ScreenConnect|ConnectWiseControl|ScreenConnect\.Client' },
    [PSCustomObject]@{ Name='Dameware'; NamePattern='(?i)Dameware'; ArtifactPattern='(?i)Dameware|DWRCS' },
    [PSCustomObject]@{ Name='Datto RMM / CentraStage'; NamePattern='(?i)Datto\s*RMM|CentraStage'; ArtifactPattern='(?i)Datto\s*RMM|CentraStage|CagService' },
    [PSCustomObject]@{ Name='DWService'; NamePattern='(?i)DWService'; ArtifactPattern='(?i)DWService|dwagent' },
    [PSCustomObject]@{ Name='FixMe.IT'; NamePattern='(?i)FixMe\.IT|Techinline'; ArtifactPattern='(?i)FixMe\.IT|Techinline' },
    [PSCustomObject]@{ Name='FleetDeck'; NamePattern='(?i)FleetDeck'; ArtifactPattern='(?i)FleetDeck' },
    [PSCustomObject]@{ Name='GoTo Resolve / GoToAssist'; NamePattern='(?i)GoTo\s*(?:Resolve|Assist)|GoToAssist'; ArtifactPattern='(?i)GoTo\s*(?:Resolve|Assist)|GoToAssist|g2ax_' },
    [PSCustomObject]@{ Name='GoToMyPC'; NamePattern='(?i)GoToMyPC'; ArtifactPattern='(?i)GoToMyPC|g2comm|g2pre' },
    [PSCustomObject]@{ Name='Goverlan'; NamePattern='(?i)Goverlan'; ArtifactPattern='(?i)Goverlan' },
    [PSCustomObject]@{ Name='Gorelo RMM'; NamePattern='(?i)Gorelo'; ArtifactPattern='(?i)Gorelo' },
    [PSCustomObject]@{ Name='Heartbeat RM'; NamePattern='(?i)Heartbeat\s*RM'; ArtifactPattern='(?i)Heartbeat\s*RM' },
    [PSCustomObject]@{ Name='HelpWire'; NamePattern='(?i)HelpWire'; ArtifactPattern='(?i)HelpWire' },
    [PSCustomObject]@{ Name='ImmyBot'; NamePattern='(?i)ImmyBot'; ArtifactPattern='(?i)ImmyBot' },
    [PSCustomObject]@{ Name='ISL Online'; NamePattern='(?i)ISL\s*(?:Online|Light|AlwaysOn)'; ArtifactPattern='(?i)ISL\s*(?:Online|Light|AlwaysOn)|ISLLight|ISLAlwaysOn' },
    [PSCustomObject]@{ Name='ITarian / Comodo RMM'; NamePattern='(?i)ITarian|Comodo\s+(?:One|RMM)'; ArtifactPattern='(?i)ITarian|Comodo\s*(?:One|RMM)|RmmService' },
    [PSCustomObject]@{ Name='Jump Desktop'; NamePattern='(?i)Jump\s*Desktop'; ArtifactPattern='(?i)Jump\s*Desktop|JumpDesktop' },
    [PSCustomObject]@{ Name='Kaseya VSA'; NamePattern='(?i)Kaseya|VSA\s*Agent'; ArtifactPattern='(?i)Kaseya|KaseyaAgent' },
    [PSCustomObject]@{ Name='Level.io'; NamePattern='(?i)Level\.io'; ArtifactPattern='(?i)Level\.io|level-agent' },
    [PSCustomObject]@{ Name='LiteManager'; NamePattern='(?i)LiteManager'; ArtifactPattern='(?i)LiteManager|ROMServer' },
    [PSCustomObject]@{ Name='LogMeIn'; NamePattern='(?i)LogMeIn'; ArtifactPattern='(?i)LogMeIn|LMIGuardian|LogMeInSystray' },
    [PSCustomObject]@{ Name='ManageEngine Remote Access Plus'; NamePattern='(?i)Remote\s*Access\s*Plus'; ArtifactPattern='(?i)Remote\s*Access\s*Plus|UEMS_RemoteAccess' },
    [PSCustomObject]@{ Name='MeshCentral / MeshAgent'; NamePattern='(?i)MeshCentral|MeshAgent'; ArtifactPattern='(?i)MeshCentral|MeshAgent' },
    [PSCustomObject]@{ Name='Miradore'; NamePattern='(?i)Miradore'; ArtifactPattern='(?i)Miradore' },
    [PSCustomObject]@{ Name='N-able / N-central / N-sight'; NamePattern='(?i)N-able|N-central|N-sight|SolarWinds\s+RMM'; ArtifactPattern='(?i)N-able|N-central|N-sight|SolarWinds\s*RMM|winagent' },
    [PSCustomObject]@{ Name='NetSupport Manager'; NamePattern='(?i)NetSupport'; ArtifactPattern='(?i)NetSupport' },
    [PSCustomObject]@{ Name='NinjaOne / NinjaRMM'; NamePattern='(?i)NinjaOne|NinjaRMM|NinjaRMMAgent'; ArtifactPattern='(?i)NinjaOne|NinjaRMM|NinjaRMMAgent' },
    [PSCustomObject]@{ Name='NoMachine'; NamePattern='(?i)NoMachine'; ArtifactPattern='(?i)NoMachine|nxserver|nxplayer' },
    [PSCustomObject]@{ Name='Parsec'; NamePattern='(?i)^\s*Parsec\b'; ArtifactPattern='(?i)\\Parsec\\|parsecd\.exe|parsec\.exe' },
    [PSCustomObject]@{ Name='PDQ Connect / PDQ Deploy'; NamePattern='(?i)PDQ\s+(?:Connect|Deploy)'; ArtifactPattern='(?i)PDQ\s*(?:Connect|Deploy)|PDQConnectAgent' },
    [PSCustomObject]@{ Name='Pulseway'; NamePattern='(?i)Pulseway|PC\s*Monitor'; ArtifactPattern='(?i)Pulseway|PCMonitorManager' },
    [PSCustomObject]@{ Name='Remote Utilities'; NamePattern='(?i)Remote\s+Utilities'; ArtifactPattern='(?i)Remote\s*Utilities|rutserv|rfusclient' },
    [PSCustomObject]@{ Name='RemotePC'; NamePattern='(?i)^\s*RemotePC\b|IDrive\s+RemotePC'; ArtifactPattern='(?i)RemotePC|RemotePCService' },
    [PSCustomObject]@{ Name='RemoteToPC'; NamePattern='(?i)RemoteToPC'; ArtifactPattern='(?i)RemoteToPC' },
    [PSCustomObject]@{ Name='RPort'; NamePattern='(?i)^\s*RPort\b'; ArtifactPattern='(?i)\\RPort\\|rport\.exe' },
    [PSCustomObject]@{ Name='RustDesk'; NamePattern='(?i)RustDesk'; ArtifactPattern='(?i)RustDesk' },
    [PSCustomObject]@{ Name='SimpleHelp'; NamePattern='(?i)SimpleHelp'; ArtifactPattern='(?i)SimpleHelp' },
    [PSCustomObject]@{ Name='Splashtop'; NamePattern='(?i)Splashtop'; ArtifactPattern='(?i)Splashtop|SRManager|SplashtopRemoteService' },
    [PSCustomObject]@{ Name='Supremo'; NamePattern='(?i)^\s*Supremo\b'; ArtifactPattern='(?i)Supremo' },
    [PSCustomObject]@{ Name='Syncro'; NamePattern='(?i)Syncro(?:MSP)?|SyncroLive'; ArtifactPattern='(?i)Syncro(?:MSP)?|SyncroLive|Kabuto' },
    [PSCustomObject]@{ Name='Tactical RMM'; NamePattern='(?i)Tactical\s*RMM'; ArtifactPattern='(?i)Tactical\s*RMM|tacticalrmm|tacticalagent' },
    [PSCustomObject]@{ Name='TeamViewer'; NamePattern='(?i)TeamViewer'; ArtifactPattern='(?i)TeamViewer' },
    [PSCustomObject]@{ Name='TightVNC'; NamePattern='(?i)TightVNC'; ArtifactPattern='(?i)TightVNC|tvnserver|tvnviewer' },
    [PSCustomObject]@{ Name='Tiflux'; NamePattern='(?i)Tiflux'; ArtifactPattern='(?i)Tiflux' },
    [PSCustomObject]@{ Name='TigerVNC'; NamePattern='(?i)TigerVNC'; ArtifactPattern='(?i)TigerVNC|winvnc4' },
    [PSCustomObject]@{ Name='TSplus Remote Support'; NamePattern='(?i)TSplus\s+Remote\s+Support'; ArtifactPattern='(?i)TSplus|TSplusRemoteSupport' },
    [PSCustomObject]@{ Name='UltraViewer'; NamePattern='(?i)UltraViewer'; ArtifactPattern='(?i)UltraViewer' },
    [PSCustomObject]@{ Name='UltraVNC / WinVNC'; NamePattern='(?i)UltraVNC|WinVNC'; ArtifactPattern='(?i)UltraVNC|WinVNC|uvnc_service' },
    [PSCustomObject]@{ Name='Zoho Assist'; NamePattern='(?i)Zoho\s+Assist'; ArtifactPattern='(?i)Zoho\s*Assist|ZohoAssist' },
    [PSCustomObject]@{ Name='Chrome Remote Desktop'; NamePattern='(?i)Chrome\s+Remote\s+Desktop'; ArtifactPattern='(?i)Chrome\s*Remote\s*Desktop|remoting_host\.exe' },
    [PSCustomObject]@{ Name='RealVNC / VNC Connect'; NamePattern='(?i)RealVNC|VNC\s+Connect'; ArtifactPattern='(?i)RealVNC|VNC\s*Connect|vncserver(?:ui)?\.exe' },
    [PSCustomObject]@{ Name='Radmin'; NamePattern='(?i)^\s*Radmin\b|Famatech'; ArtifactPattern='(?i)Radmin|Famatech|r_server\.exe'; ExcludePattern='(?i)[\\/]LG Software[\\/]LG OSD[\\/]Launcher[\\/]Radmin\.exe$' },
    [PSCustomObject]@{ Name='Iperius Remote'; NamePattern='(?i)Iperius\s+Remote'; ArtifactPattern='(?i)Iperius\s*Remote|IperiusRemote' },
    [PSCustomObject]@{ Name='Getscreen.me'; NamePattern='(?i)GetScreen(?:\.me)?'; ArtifactPattern='(?i)GetScreen(?:\.me)?|getscreen\.exe' },
    [PSCustomObject]@{ Name='HopToDesk'; NamePattern='(?i)HopToDesk'; ArtifactPattern='(?i)HopToDesk' },
    [PSCustomObject]@{ Name='DeskIn'; NamePattern='(?i)^\s*DeskIn\b'; ArtifactPattern='(?i)(?:^|[\\/])DeskIn(?:[\\/]|\.exe|$)|(?:^|[\\/])DeskIn(?:Client|Remote)?\.exe$' },
    [PSCustomObject]@{ Name='ShowMyPC'; NamePattern='(?i)ShowMyPC'; ArtifactPattern='(?i)ShowMyPC' },
    [PSCustomObject]@{ Name='Mikogo'; NamePattern='(?i)Mikogo'; ArtifactPattern='(?i)Mikogo' },
    [PSCustomObject]@{ Name='eHorus'; NamePattern='(?i)eHorus'; ArtifactPattern='(?i)eHorus' },
    [PSCustomObject]@{ Name='Microsoft Quick Assist'; NamePattern='(?i)^\s*(?:Microsoft\s+)?Quick\s+Assist\s*$'; ArtifactPattern='(?i)QuickAssist(?:\.exe)?' }
)

$script:PupPuaWatchlist = @(
    # User/workplace-observed items
    [PSCustomObject]@{ Name='Blazer'; NamePattern='(?i)^\s*Blazer(?:\s+Browser)?\s*$'; ArtifactPattern='(?i)(?:^|[\\/])Blazer(?:\s+Browser)?(?:[\\/]|$)|(?:^|[\\/])blazer(?:[_ -](?:installer|setup))?(?:[_ -][^\\/]*)?\.exe$' },
    [PSCustomObject]@{ Name='Wave Browser'; NamePattern='(?i)^\s*Wave(?:\s+Browser)?\s*$'; ArtifactPattern='(?i)(?:^|[\\/])Wave(?:\s+Browser)?(?:[\\/]|$)|(?:^|[\\/])Wave\s+Browser(?:\s*[-_]\s*[^\\/]*)?\.exe$|wavebrowser(?:\.exe)?' },
    [PSCustomObject]@{ Name='Shift Browser'; NamePattern='(?i)^\s*Shift(?:\s+Browser)?\s*$'; ArtifactPattern='(?i)(?:^|[\\/])Shift(?:\s+Browser)?(?:[\\/]|$)|(?:^|[\\/])Shift[-_]{1,2}[^\\/]+\.exe$|(?:^|[\\/])shift\.exe$' },
    [PSCustomObject]@{ Name='OneStart'; NamePattern='(?i)^\s*OneStart(?:\.ai)?\s*$'; ArtifactPattern='(?i)OneStart(?:\.ai)?' },
    [PSCustomObject]@{ Name='One Browser'; NamePattern='(?i)^\s*One\s+Browser\s*$'; ArtifactPattern='(?i)(?:^|[\\/])One\s*Browser(?:[\\/]|$)|OneBrowser' },
    [PSCustomObject]@{ Name='Driver Support / Driver Support One'; NamePattern='(?i)^\s*Driver\s+Support(?:\s+One)?\b'; ArtifactPattern='(?i)Driver\s*Support(?:\s*One)?|DriverSupportOne' },
    [PSCustomObject]@{ Name='Generic Driver Updater Installer'; NamePattern='(?i)^\s*Driver[_ -]?Updater(?:\s+Setup)?\s*$'; ArtifactPattern='(?i)(?:^|[\\/])Driver[_ -]?Updater[_ -]?(?:setup|installer)?(?:[_ -][^\\/]*)?\.exe$' },
    [PSCustomObject]@{ Name='Web Companion'; NamePattern='(?i)^\s*(?:Adaware\s+)?Web\s+Companion\b'; ArtifactPattern='(?i)Web\s*Companion|WebCompanion|Lavasoft' },
    [PSCustomObject]@{ Name='Search Protect'; NamePattern='(?i)^\s*Search\s+Protect\b'; ArtifactPattern='(?i)Search\s*Protect|SearchProtect|Conduit' },
    [PSCustomObject]@{ Name='Browser Assistant'; NamePattern='(?i)^\s*Browser\s+Assistant\b'; ArtifactPattern='(?i)(?:^|[\\/])Browser(?:\s|_)?Assistant(?:\.exe|[\\/]|$)|BrowserAssistant(?:\.exe|[\\/]|$)'; ExcludePattern='(?i)Opera\s+GX|[\\/]Opera GX[\\/]|Opera Software' },
    [PSCustomObject]@{ Name='PDF Tools'; NamePattern='(?i)^\s*PDF\s+Tools\s*$'; ArtifactPattern='(?i)^(?:PDF[ _-]*Tools)(?:(?:[ _-]*(?:Setup|Installer|Install|Portable|v?\d)[\w.-]*)?\.(?:exe|msi|msix|msp)|)$' },
    [PSCustomObject]@{ Name='PDF Hub'; NamePattern='(?i)^\s*PDF\s+Hub\s*$'; ArtifactPattern='(?i)(?:^|[\\/])PDF\s*Hub(?:[\\/]|$)|PDFHub' },
    [PSCustomObject]@{ Name='PC App Store'; NamePattern='(?i)^\s*PC\s*App\s*Store\b'; ArtifactPattern='(?i)PC\s*App\s*Store|PCAppStore' },
    [PSCustomObject]@{ Name='Clear / ClearBrowser'; NamePattern='(?i)^\s*(?:Clear|Clear\s+Browser|ClearBrowser)\s*$'; ArtifactPattern='(?i)ClearBrowser(?:\.exe)?|(?:^|[\\/])Clear(?:[\\/]|$)|(?:^|[\\/])Clear-ManualsLibrary(?:[._-][^\\/]*)?\.exe$' },

    # Additional higher-signal PUP/PUA names commonly seen in cleanup work
    [PSCustomObject]@{ Name='OneLaunch'; NamePattern='(?i)^\s*OneLaunch\b'; ArtifactPattern='(?i)OneLaunch' },
    [PSCustomObject]@{ Name='WebDiscover Browser'; NamePattern='(?i)^\s*WebDiscover(?:\s+Browser)?\b'; ArtifactPattern='(?i)WebDiscover' },
    [PSCustomObject]@{ Name='WebNavigator Browser'; NamePattern='(?i)^\s*WebNavigator(?:\s+Browser)?\b'; ArtifactPattern='(?i)WebNavigator' },
    [PSCustomObject]@{ Name='Chromstera Browser'; NamePattern='(?i)^\s*Chromstera(?:\s+Browser)?\b'; ArtifactPattern='(?i)Chromstera' },
    [PSCustomObject]@{ Name='SAntivirus / Segurazo'; NamePattern='(?i)^\s*(?:SAntivirus|Segurazo)\b'; ArtifactPattern='(?i)^(?:SAntivirus|Segurazo)(?:(?:[_ .-]*(?:Setup|Installer|Install|Agent|Service|v?\d)[\w.-]*)?\.(?:exe|msi|msix|msp)|)$' },
    [PSCustomObject]@{ Name='ByteFence'; NamePattern='(?i)^\s*ByteFence\b'; ArtifactPattern='(?i)ByteFence' },
    [PSCustomObject]@{ Name='PremierOpinion'; NamePattern='(?i)^\s*PremierOpinion\b'; ArtifactPattern='(?i)PremierOpinion' },
    [PSCustomObject]@{ Name='RelevantKnowledge'; NamePattern='(?i)^\s*RelevantKnowledge\b'; ArtifactPattern='(?i)RelevantKnowledge|rlvknlg' },
    [PSCustomObject]@{ Name='PC Accelerate Pro'; NamePattern='(?i)^\s*PC\s+Accelerate\s+Pro\b'; ArtifactPattern='(?i)PC\s*Accelerate\s*Pro|PCAcceleratePro' },
    [PSCustomObject]@{ Name='PC Speed Maximizer'; NamePattern='(?i)^\s*PC\s+Speed\s+Maximizer\b'; ArtifactPattern='(?i)PC\s*Speed\s*Maximizer|PCSpeedMaximizer' },
    [PSCustomObject]@{ Name='Optimizer Pro'; NamePattern='(?i)^\s*(?:Super\s+)?Optimizer\s+Pro\b'; ArtifactPattern='(?i)Optimizer\s*Pro|SuperOptimizer' },
    [PSCustomObject]@{ Name='MyCleanPC'; NamePattern='(?i)^\s*MyCleanPC\b'; ArtifactPattern='(?i)MyCleanPC' },
    [PSCustomObject]@{ Name='SlimCleaner / Slimware'; NamePattern='(?i)^\s*SlimCleaner|Slimware'; ArtifactPattern='(?i)SlimCleaner|Slimware' },
    [PSCustomObject]@{ Name='DriverUpdate / Slimware DriverUpdate'; NamePattern='(?i)^\s*DriverUpdate\b|Slimware\s+Driver'; ArtifactPattern='(?i)(?:^|[\\/])DriverUpdate(?:[\\/]|\.exe|$)|Slimware' },
    [PSCustomObject]@{ Name='PC HelpSoft Driver Updater'; NamePattern='(?i)^\s*PC\s+HelpSoft\s+Driver\s+Updater\b'; ArtifactPattern='(?i)PCHelpSoft|PC\s*HelpSoft\s*Driver' },
    [PSCustomObject]@{ Name='Quick Driver Updater'; NamePattern='(?i)^\s*Quick\s+Driver\s+Updater\b'; ArtifactPattern='(?i)Quick\s*Driver\s*Updater|QuickDriverUpdater' },
    [PSCustomObject]@{ Name='WinZip Driver Updater'; NamePattern='(?i)^\s*WinZip\s+Driver\s+Updater\b'; ArtifactPattern='(?i)WinZip\s*Driver\s*Updater|WinZipDriverUpdater' },
    [PSCustomObject]@{ Name='Ask Toolbar'; NamePattern='(?i)^\s*Ask(?:\.com)?\s+Toolbar\b'; ArtifactPattern='(?i)Ask(?:\.com)?\s*Toolbar' },
    [PSCustomObject]@{ Name='Babylon Toolbar'; NamePattern='(?i)^\s*Babylon(?:\s+Toolbar)?\b'; ArtifactPattern='(?i)Babylon\s*Toolbar|BabylonToolbar' },
    [PSCustomObject]@{ Name='MyWay / Mindspark'; NamePattern='(?i)MyWay|Mindspark'; ArtifactPattern='(?i)MyWay|Mindspark|AskPartnerNetwork' },
    [PSCustomObject]@{ Name='Search Manager'; NamePattern='(?i)^\s*Search\s+Manager\b'; ArtifactPattern='(?i)Search\s*Manager|SearchManager'; ExcludePattern='(?i)[\\/]LG Software[\\/]gram chat[\\/]GSearch[\\/]SearchManager\.exe$' },
    [PSCustomObject]@{ Name='Universal Browser / Web Browser Solutions'; NamePattern='(?i)^\s*(?:Universal\s+Browser|Web\s+Browser\s+Solutions)\b'; ArtifactPattern='(?i)UniversalBrowserSolutions|WebBrowserSolutions|Universal\s*Browser' },
    [PSCustomObject]@{ Name='Artificius / Artificus'; NamePattern='(?i)^\s*Artific(?:ius|us)\b'; ArtifactPattern='(?i)Artificius|Artificus' },
    [PSCustomObject]@{ Name='Wise Care 365'; NamePattern='(?i)^\s*Wise\s+Care(?:\s+365)?\b'; ArtifactPattern='(?i)WiseCare|Wise\s*Care' },
    [PSCustomObject]@{ Name='Custom Search Bar'; NamePattern='(?i)^\s*Custom\s+Search\s+Bar\b'; ArtifactPattern='(?i)CustomSearchBar|Custom\s*Search\s*Bar' },
    [PSCustomObject]@{ Name='Active Search Bar'; NamePattern='(?i)^\s*Active\s+Search\s+Bar\b'; ArtifactPattern='(?i)ActiveSearchBar|Active\s*Search\s*Bar' },
    [PSCustomObject]@{ Name='Auslogics Driver Updater'; NamePattern='(?i)^\s*Auslogics\s+Driver\s+Updater\b'; ArtifactPattern='(?i)Auslogics\s*Driver\s*Updater|AuslogicsDriverUpdater' },
    [PSCustomObject]@{ Name='DriverHive'; NamePattern='(?i)^\s*DriverHive\b'; ArtifactPattern='(?i)DriverHive' },
    [PSCustomObject]@{ Name='DriverFix'; NamePattern='(?i)^\s*DriverFix\b'; ArtifactPattern='(?i)(?:^|[\\/ _-])DriverFix(?:Setup|Installer)?(?:[\\/ ._-]|$)' },
    [PSCustomObject]@{ Name='DriverPack'; NamePattern='(?i)^\s*DriverPack\b'; ArtifactPattern='(?i)DriverPack' },
    [PSCustomObject]@{ Name='DriverToolkit'; NamePattern='(?i)^\s*DriverToolkit\b'; ArtifactPattern='(?i)DriverToolkit' },
    [PSCustomObject]@{ Name='DriverTuner'; NamePattern='(?i)^\s*DriverTuner\b'; ArtifactPattern='(?i)DriverTuner' },
    [PSCustomObject]@{ Name='DriveTheLife'; NamePattern='(?i)^\s*DriveTheLife\b'; ArtifactPattern='(?i)DriveTheLife' },
    [PSCustomObject]@{ Name='WiperSoft'; NamePattern='(?i)^\s*WiperSoft\b'; ArtifactPattern='(?i)WiperSoft' },
    [PSCustomObject]@{ Name='WinThruster'; NamePattern='(?i)^\s*WinThruster\b'; ArtifactPattern='(?i)WinThruster' },
    [PSCustomObject]@{ Name='PCSpeedCat'; NamePattern='(?i)^\s*PCSpeedCat\b'; ArtifactPattern='(?i)PCSpeedCat' },
    [PSCustomObject]@{ Name='SystemKeeper Pro'; NamePattern='(?i)^\s*SystemKeeper\s+Pro\b'; ArtifactPattern='(?i)SystemKeeperPro|SystemKeeper\s*Pro' },
    [PSCustomObject]@{ Name='Restoro / Reimage'; NamePattern='(?i)^\s*(?:Restoro|Reimage)\b'; ArtifactPattern='(?i)Restoro|ReimagePlus|Reimage' },
    [PSCustomObject]@{ Name='Super Cleanup'; NamePattern='(?i)^\s*Super\s+Cleanup\b'; ArtifactPattern='(?i)SuperCleanup|Super\s*Cleanup' },
    [PSCustomObject]@{ Name='SearchEncrypt'; NamePattern='(?i)^\s*SearchEncrypt\b'; ArtifactPattern='(?i)SearchEncrypt' },
    [PSCustomObject]@{ Name='Trovi'; NamePattern='(?i)^\s*Trovi\b'; ArtifactPattern='(?i)Trovi|trovigo' },
    [PSCustomObject]@{ Name='Spigot'; NamePattern='(?i)^\s*Spigot\b'; ArtifactPattern='(?i)Spigot' },
    [PSCustomObject]@{ Name='Wajam'; NamePattern='(?i)^\s*Wajam\b'; ArtifactPattern='(?i)Wajam' },
    [PSCustomObject]@{ Name='Webbar'; NamePattern='(?i)^\s*Webbar\b'; ArtifactPattern='(?i)Webbar' },
    [PSCustomObject]@{ Name='CrossBrowse'; NamePattern='(?i)^\s*CrossBrowse\b'; ArtifactPattern='(?i)CrossBrowse' },
    [PSCustomObject]@{ Name='BrowseFox'; NamePattern='(?i)^\s*BrowseFox\b'; ArtifactPattern='(?i)BrowseFox' },
    [PSCustomObject]@{ Name='MyPCBackup'; NamePattern='(?i)^\s*MyPCBackup\b'; ArtifactPattern='(?i)MyPCBackup' },
    [PSCustomObject]@{ Name='OpenCandy'; NamePattern='(?i)^\s*OpenCandy\b'; ArtifactPattern='(?i)OpenCandy' },
    [PSCustomObject]@{ Name='Softonic Downloader'; NamePattern='(?i)^\s*Softonic(?:\s+Downloader)?\b'; ArtifactPattern='(?i)Softonic' },
    [PSCustomObject]@{ Name='Advanced System Repair'; NamePattern='(?i)^\s*Advanced\s+System\s+Repair\b'; ArtifactPattern='(?i)AdvancedSystemRepair|Advanced\s*System\s*Repair' },
    [PSCustomObject]@{ Name='WinZip System Utilities Suite'; NamePattern='(?i)^\s*WinZip\s+System\s+Utilities\s+Suite\b'; ArtifactPattern='(?i)WinZip\s*System\s*Utilities|WinZipSystemUtilities' }
)

function Remove-WindowsDuplicateNameSuffix {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }

    # Explorer/browser duplicate downloads commonly become:
    #   Name (1).exe, Name (2).zip, Name (15).msi
    # and duplicate folders can become:
    #   Name (1)
    #
    # Normalize only the FINAL path component, immediately before the extension
    # (or at end-of-name for a directory), so unrelated parentheses elsewhere in
    # a path are preserved.
    try {
        return [regex]::Replace(
            $Text,
            '\s+\(\d+\)(?=(?:\.[^\\/:*?"<>|\r\n]+)?$)',
            ''
        )
    } catch {
        return $Text
    }
}

$script:WatchlistAliasCache = @{}

function Convert-ToArtifactFamilyKey {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }

    try {
        $value = Remove-WindowsDuplicateNameSuffix -Text $Text
        $leaf = Split-Path -Path $value -Leaf
        if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = $value }

        try {
            $ext = [IO.Path]::GetExtension($leaf)
            if ($ext) { $leaf = $leaf.Substring(0, $leaf.Length - $ext.Length) }
        } catch { }

        return (($leaf -replace '[^A-Za-z0-9]', '').ToLowerInvariant())
    } catch {
        return ''
    }
}

function Get-ArtifactFamilyKeys {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    $keys = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $normalized = Remove-WindowsDuplicateNameSuffix -Text $Text

    # Family matching is intentionally limited to actual artifact filenames.
    # Command-line arguments are not product artifacts. This prevents strings
    # such as "/SendHeartbeat" from matching an unrelated "Heartbeat RM" family.
    $filePattern = '(?i)(?:^|[\\/])([^\\/"\r\n]+?\.(?:exe|com|msi|msix|msp|dll|bat|cmd|ps1|vbs|vbe|js|jse|hta|sys|scr|lnk))(?=\s|$|["''|;,])'
    foreach ($m in [regex]::Matches($normalized, $filePattern)) {
        $leaf = [string]$m.Groups[1].Value
        $key = Convert-ToArtifactFamilyKey -Text $leaf
        if ($key -and -not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $keys.Add($key) | Out-Null
        }
    }

    # Standalone filename without a path.
    if ($normalized -match '(?i)^\s*[^\\/"\r\n]+?\.(?:exe|com|msi|msix|msp|dll|bat|cmd|ps1|vbs|vbe|js|jse|hta|sys|scr|lnk)\s*$') {
        $key = Convert-ToArtifactFamilyKey -Text $normalized.Trim()
        if ($key -and -not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $keys.Add($key) | Out-Null
        }
    }

    # Direct folder/path artifact. Only use this fallback when the text itself
    # looks like one filesystem path rather than a combined process/task string.
    $trimmed = $normalized.Trim().Trim('"')
    if ($keys.Count -eq 0 -and
        $trimmed -match '^(?:[A-Za-z]:\\|\\\\)' -and
        $trimmed -notmatch '\s+\S+\s+/') {
        $leaf = ''
        try { $leaf = Split-Path -Path $trimmed -Leaf } catch { }
        if ($leaf) {
            $key = Convert-ToArtifactFamilyKey -Text $leaf
            if ($key -and -not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $keys.Add($key) | Out-Null
            }
        }
    }

    return $keys.ToArray()
}

function Get-WatchlistStableArtifactAliases {
    param([Parameter(Mandatory)]$Entry)

    $cacheKey = "{0}|{1}" -f ([string]$Entry.Name), ([string]$Entry.ArtifactPattern)
    if ($script:WatchlistAliasCache.ContainsKey($cacheKey)) {
        return @($script:WatchlistAliasCache[$cacheKey])
    }

    $aliases = New-Object System.Collections.Generic.List[string]
    $seen = @{}

    # IMPORTANT: Never invent aliases by splitting a product name into words.
    # "Chrome Remote Desktop" must NOT match normal Chrome, and "Remote
    # Utilities" must NOT match legitimate Microsoft *.Utilities.dll files.
    # Keep each full slash-separated product name intact; v1.31's curated
    # ArtifactPattern covers distinctive short names and installer prefixes.
    # Additional product-specific aliases may be specified explicitly in
    # Entry.ArtifactAliases when a different stable filename is documented.
    $genericFullNames = @(
        'clear','one','remote','browser','client','utilities','assist',
        'support','search','driver','protect','repair','universal',
        'deploy','online','custom','cleanup','manager','tools'
    )

    $name = [string]$Entry.Name
    if (-not [string]::IsNullOrWhiteSpace($name)) {
        foreach ($part in @($name -split '\s*/\s*')) {
            $clean = ($part -replace '\([^)]*\)', '').Trim()
            $key = (($clean -replace '[^A-Za-z0-9]', '').ToLowerInvariant())
            if ($key.Length -lt 5 -or $genericFullNames -contains $key) { continue }
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $aliases.Add($key) | Out-Null
            }
        }
    }

    if ($Entry.PSObject.Properties['ArtifactAliases']) {
        foreach ($explicitAlias in @($Entry.ArtifactAliases)) {
            $key = (([string]$explicitAlias -replace '[^A-Za-z0-9]', '').ToLowerInvariant())
            if ($key.Length -lt 5 -or $genericFullNames -contains $key) { continue }
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $aliases.Add($key) | Out-Null
            }
        }
    }

    $cached = $aliases.ToArray()
    $script:WatchlistAliasCache[$cacheKey] = $cached
    return @($cached)
}

function Test-WatchlistStableArtifactFamilyKeys {
    param(
        [AllowEmptyCollection()][string[]]$FamilyKeys,
        [Parameter(Mandatory)]$Entry
    )
    if (-not $FamilyKeys -or $FamilyKeys.Count -eq 0) { return $false }

    foreach ($alias in @(Get-WatchlistStableArtifactAliases -Entry $Entry)) {
        if ([string]::IsNullOrWhiteSpace($alias)) { continue }
        foreach ($familyKey in $FamilyKeys) {
            if ([string]::IsNullOrWhiteSpace($familyKey) -or
                -not $familyKey.StartsWith($alias,[StringComparison]::OrdinalIgnoreCase)) { continue }

            $tail = $familyKey.Substring($alias.Length)
            # Identical product names, version numbers and recognized installer/
            # executable modifiers match. An arbitrary continuation does not.
            # Examples: Parsec != parse-command.js; DriverUpdate !=
            # DriverUpdateRecommendation.dll; PDFTools != PDFToolsDropdown.js.
            if ($tail.Length -eq 0 -or
                $tail -match '^(?:\d|v\d|setup|installer|install|client|server|host|service|agent|portable|app\d|update\d|updater\d|qs\d|quick\d|x64|x86|amd64|win64|win32|release|build\d|beta\d|alpha\d)') {
                return $true
            }
        }
    }
    return $false
}

function Find-WatchlistEntry {
    param(
        [AllowNull()][string]$Text,
        [Parameter(Mandatory)][object[]]$Watchlist,
        [ValidateSet('Name','Artifact')][string]$Mode = 'Artifact'
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $textsToCheck = @($Text)
    $familyKeys = @()

    if ($Mode -eq 'Artifact') {
        $normalizedText = Remove-WindowsDuplicateNameSuffix -Text $Text
        if (-not [string]::IsNullOrWhiteSpace($normalizedText) -and $normalizedText -ne $Text) {
            $textsToCheck += $normalizedText
        }

        # Compute filename family keys once per lookup, not once per watchlist
        # entry. Normalize well-known installer filename prefixes once here as
        # well, so Setup-TeamViewer-15.99.exe still matches the TeamViewer family
        # without allowing accidental mid-name matches in unrelated DLLs.
        $familyKeys = @(Get-ArtifactFamilyKeys -Text $Text)
        $installerPrefixes = @('setup','installer','install','download')
        foreach ($key in @($familyKeys)) {
            foreach ($prefix in $installerPrefixes) {
                if ($key.Length -gt ($prefix.Length + 4) -and
                    $key.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $suffixKey = $key.Substring($prefix.Length)
                    if ($familyKeys -cnotcontains $suffixKey) {
                        $familyKeys += $suffixKey
                    }
                    break
                }
            }
        }
    }

    foreach ($entry in $Watchlist) {
        $pattern = if ($Mode -eq 'Name') { [string]$entry.NamePattern } else { [string]$entry.ArtifactPattern }
        if (-not $pattern) { continue }

        $matched = $false

        foreach ($candidateText in $textsToCheck) {
            if ($candidateText -match $pattern) {
                $matched = $true
                break
            }
        }

        if (-not $matched -and $Mode -eq 'Artifact' -and $familyKeys.Count -gt 0) {
            $matched = Test-WatchlistStableArtifactFamilyKeys -FamilyKeys $familyKeys -Entry $entry
        }

        if (-not $matched) { continue }

        if ($entry.PSObject.Properties['ExcludePattern']) {
            $exclude = [string]$entry.ExcludePattern
            if ($exclude) {
                $excluded = $false
                foreach ($candidateText in $textsToCheck) {
                    if ($candidateText -match $exclude) {
                        $excluded = $true
                        break
                    }
                }
                if ($excluded) { continue }
            }
        }

        return $entry
    }

    return $null
}

function Find-WatchlistExecutable {
    param(
        [AllowNull()][string]$Executable,
        [AllowNull()][string]$ProductName,
        [Parameter(Mandatory)][object[]]$Watchlist
    )
    # Product names are evaluated against curated software-name expressions.
    # Artifact expressions only receive the leaf filename, never concatenated
    # arguments, signing-company strings, unrelated parent directories, or URLs.
    $candidate = [string]$ProductName
    if ($candidate) {
        $found = Find-WatchlistEntry -Text $candidate -Watchlist $Watchlist -Mode Name
        if ($found) { return $found }
    }
    $filePath = Get-ExecutablePathFromCommand ([string]$Executable)
    if (-not $filePath) { return $null }
    $leaf = [IO.Path]::GetFileName($filePath.Trim().Trim('"'))
    if (-not $leaf) { return $null }
    return Find-WatchlistEntry -Text $leaf -Watchlist $Watchlist -Mode Artifact
}

function Get-WatchlistInstalledMatches {
    param(
        [object[]]$Apps,
        [Parameter(Mandatory)][object[]]$Watchlist,
        [Parameter(Mandatory)][string]$Kind
    )

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($app in @($Apps)) {
        $match = Find-WatchlistEntry -Text ([string]$app.Name) -Watchlist $Watchlist -Mode Name
        if ($match) {
            $results.Add([PSCustomObject]@{ Kind=$Kind; Product=$match.Name; App=$app }) | Out-Null
        }
    }
    return @($results.ToArray() | Sort-Object Product, @{Expression={$_.App.Name}} -Unique)
}

function Get-WatchlistRuntimeMatches {
    param(
        [Parameter(Mandatory)][object[]]$Watchlist,
        [Parameter(Mandatory)][string]$Kind
    )

    $results = New-Object System.Collections.Generic.List[object]
    $genericHelperNames = '(?i)^(crashpad_handler|crashpad|update|updater|uninstall|unins\d*)\.exe$'

    try {
        foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
            $match = Find-WatchlistExecutable -Executable ([string]$proc.ExecutablePath) -ProductName ([string]$proc.Name) -Watchlist $Watchlist
            if (-not $match) { continue }
            if ($Kind -eq 'Remote Access' -and [string]$proc.Name -match $genericHelperNames) { continue }
            $results.Add([PSCustomObject]@{
                Kind=$Kind; Product=$match.Name; Type='Process'; Name=[string]$proc.Name;
                Path=[string]$proc.ExecutablePath; Detail=[string]$proc.CommandLine
            }) | Out-Null
        }
    } catch { }

    try {
        foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
            $match = Find-WatchlistExecutable -Executable ([string]$svc.PathName) -ProductName ([string]$svc.DisplayName) -Watchlist $Watchlist
            if (-not $match) { continue }
            $results.Add([PSCustomObject]@{
                Kind=$Kind; Product=$match.Name; Type='Service'; Name=[string]$svc.DisplayName;
                Path=[string]$svc.PathName; Detail="State: $($svc.State) | Start mode: $($svc.StartMode)"
            }) | Out-Null
        }
    } catch { }

    return @($results.ToArray() | Sort-Object Product, Type, Name, Path -Unique)
}

function Get-InspectionTreeEntries {
    param(
        [Parameter(Mandatory)][string]$Root,
        [ValidateRange(0,128)][int]$Depth = 3,
        [switch]$FilesOnly,
        [switch]$IncludeCaches,
        [AllowNull()]$Stats
    )
    $skipFolders = @('cache','caches','code cache','gpucache','node_modules','windowsapps','packages')
    $pending = New-Object 'System.Collections.Generic.Queue[object]'
    $pending.Enqueue([PSCustomObject]@{ Path=$Root; Level=0 })
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        try {
            # Stop on access/IO errors so coverage reports them. Never assume
            # a partially inaccessible root was fully inspected.
            $children = @(Get-ChildItem -LiteralPath $current.Path -Force -ErrorAction Stop)
            if ($Stats) { $Stats.DirectoriesVisited++ }
            foreach ($item in $children) {
                $isReparse = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
                if ($isReparse) {
                    if ($Stats) { $Stats.SkippedReparsePoints++ }
                    continue   # Avoid junction loops and ambiguous off-volume files
                }
                if ($item.PSIsContainer) {
                    if ((Test-IsInspectionOwnPath -Path $item.FullName) -or
                        (-not $IncludeCaches -and $skipFolders -contains $item.Name.ToLowerInvariant())) {
                        if ($Stats) { $Stats.SkippedDirectories++ }
                        continue
                    }
                    if (-not $FilesOnly) { $item }
                    if ($current.Level -lt $Depth) {
                        $pending.Enqueue([PSCustomObject]@{ Path=$item.FullName; Level=($current.Level + 1) })
                    } else {
                        if ($Stats) { $Stats.DepthLimitedDirectories++ }
                    }
                } else {
                    if ($Stats) { $Stats.FilesVisited++ }
                    $item
                }
            }
        } catch {
            if ($Stats) {
                $Stats.Errors++
                if ($Stats.ErrorSamples.Count -lt 15) {
                    $Stats.ErrorSamples.Add(('{0}: {1}' -f $current.Path,$_.Exception.Message)) | Out-Null
                }
            }
        }
    }
}


function Get-WatchlistArtifactMatches {
    $results = New-Object System.Collections.Generic.List[object]
    $roots = New-Object System.Collections.Generic.List[object]
    $fileExtensions = @('.exe','.com','.bat','.cmd','.ps1','.vbs','.vbe','.hta','.scr','.lnk','.msi','.msix','.msp')

    foreach ($profile in Get-UserProfileRoots) {
        foreach ($relative in @('Downloads','Desktop','AppData\Local','AppData\Roaming')) {
            $path = Join-Path $profile $relative
            if (Test-Path -LiteralPath $path -PathType Container) {
                $roots.Add([PSCustomObject]@{ Path=$path; Depth=3 }) | Out-Null
            }
        }
    }
    foreach ($base in @($env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($base -and (Test-Path -LiteralPath $base -PathType Container)) {
            $roots.Add([PSCustomObject]@{ Path=$base; Depth=3 }) | Out-Null
        }
    }

    $seen = @{}
    $nameMatchCache = @{}
    foreach ($root in $roots) {
        try {
            # Stream rather than materializing all directory entries. Do not stop
            # at 200 hits; all watchlist-matching artifacts are returned.
            Get-InspectionTreeEntries -Root $root.Path -Depth $root.Depth |
                ForEach-Object {
                    $item = $_
                    if (-not $item.PSIsContainer -and $fileExtensions -notcontains $item.Extension.ToLowerInvariant()) { return }
                    if ((Test-IsInspectionOwnPath $item.FullName) -or
                        $item.FullName -match '(?i)\\(cache|caches|code cache|gpucache|node_modules|windowsapps|packages)\\') { return }

                    # Match only the artifact's OWN name, for files and folders.
                    # Parent folders cannot prove the identity of a child. This
                    # prevents a normal Chrome folder/library from becoming a
                    # Chrome Remote Desktop result or an ordinary SDK Utilities
                    # library from becoming Remote Utilities/WinZip PUP.
                    $matchText = [string]$item.Name
                    $cacheKey = $matchText.ToLowerInvariant()
                    if ($nameMatchCache.ContainsKey($cacheKey)) {
                        $remote = $nameMatchCache[$cacheKey].Remote
                        $pup = $nameMatchCache[$cacheKey].Pup
                    } else {
                        $remote = Find-WatchlistEntry -Text $matchText -Watchlist $script:RemoteAccessWatchlist -Mode Artifact
                        $pup = Find-WatchlistEntry -Text $matchText -Watchlist $script:PupPuaWatchlist -Mode Artifact
                        # Only cache file names. Directory paths are rare and
                        # retaining them all would waste memory on large profiles.
                        if (-not $item.PSIsContainer) {
                            $nameMatchCache[$cacheKey] = [PSCustomObject]@{ Remote=$remote; Pup=$pup }
                        }
                    }
                    foreach ($hit in @(
                        $(if ($remote) { [PSCustomObject]@{ Kind='Remote Access'; Product=$remote.Name; Entry=$remote } }),
                        $(if ($pup) { [PSCustomObject]@{ Kind='PUP/PUA'; Product=$pup.Name; Entry=$pup } })
                    )) {
                        if (-not $hit) { continue }
                        if ($hit.Entry.PSObject.Properties['ExcludePattern'] -and
                            [string]$hit.Entry.ExcludePattern -and
                            $item.FullName -match [string]$hit.Entry.ExcludePattern) { continue }
                        $key = "$($hit.Kind)|$($hit.Product)|$($item.FullName)"
                        if ($seen.ContainsKey($key)) { continue }
                        $seen[$key] = $true
                        $results.Add([PSCustomObject]@{
                            Kind=$hit.Kind; Product=$hit.Product; Path=$item.FullName;
                            ItemType=$(if ($item.PSIsContainer) { 'Folder' } else { 'File' });
                            Modified=$item.LastWriteTime
                        }) | Out-Null
                    }
                }
        } catch { }
    }

    return [PSCustomObject]@{ Matches=$results.ToArray(); Limited=$false; Roots=$roots.Count }
}


$script:SignatureCache = @{}
function Get-SignatureInfo {
    param([AllowNull()][string]$Path)

    $result = [PSCustomObject]@{
        Path      = $Path
        Exists    = $false
        Status    = 'Unknown'
        Signer    = ''
        Company   = ''
        LastWrite = $null
        Length    = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }

    $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    $expanded = $expanded -replace '^\\\?\?\\', ''
    $expanded = $expanded -replace '^\\\\\?\\', ''
    if ($expanded -like '\SystemRoot\*') {
        $expanded = Join-Path $env:SystemRoot ($expanded.Substring(12))
    } elseif ($expanded -like 'System32\*') {
        $expanded = Join-Path $env:SystemRoot $expanded
    } else {
        # Autorunsc can return malformed/control-character paths. IsPathRooted()
        # throws on illegal path characters, so never let one bad row abort the
        # entire Autoruns inspection.
        $isRooted = $false
        try {
            $isRooted = [System.IO.Path]::IsPathRooted($expanded)
        } catch {
            $result.Status = 'InvalidPath'
            return $result
        }

        if (-not $isRooted) {
            try {
                $resolvedCommand = Get-Command $expanded -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($resolvedCommand -and $resolvedCommand.Source) { $expanded = $resolvedCommand.Source }
            } catch { }
        }
    }
    if ($script:SignatureCache.ContainsKey($expanded)) {
        return $script:SignatureCache[$expanded]
    }

    try {
        if (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) {
            $script:SignatureCache[$expanded] = $result
            return $result
        }

        $item = Get-Item -LiteralPath $expanded -Force -ErrorAction Stop
        $result.Exists = $true
        $result.LastWrite = $item.LastWriteTime
        $result.Length = $item.Length

        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $expanded -ErrorAction Stop
            $result.Status = [string]$sig.Status
            if ($sig.SignerCertificate) {
                $result.Signer = [string]$sig.SignerCertificate.Subject
            }
        } catch {
            $result.Status = 'Unknown'
        }

        try {
            $result.Company = [string]$item.VersionInfo.CompanyName
        } catch { }
    } catch { }

    $script:SignatureCache[$expanded] = $result
    return $result
}

function Get-ExecutablePathFromCommand {
    param([AllowNull()][string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    $expanded = $expanded -replace '^\\\?\?\\', ''
    $expanded = $expanded -replace '^\\\\\?\\', ''

    if ($expanded -match '^\s*"([^"]+)"') {
        return $matches[1]
    }

    # Handles unquoted executable paths that contain spaces, such as service ImagePath values.
    if ($expanded -match '^\s*(.+?\.(?:exe|com|bat|cmd|ps1|vbs|vbe|js|jse|hta|dll|sys|scr))(?=\s|$)') {
        return $matches[1].Trim().Trim('"')
    }

    $first = ($expanded -split '\s+', 2)[0].Trim('"')
    if ($first) { return $first }
    return $null
}

function Get-ReferencedScriptPaths {
    param([AllowNull()][string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine)
    $results = New-Object System.Collections.Generic.List[string]

    $patterns = @(
        '"([^"\r\n]+\.(?:ps1|vbs|vbe|js|jse|hta|bat|cmd|dll|scr|exe))"',
        '(?i)([A-Z]:\\[^\s"'']+\.(?:ps1|vbs|vbe|js|jse|hta|bat|cmd|dll|scr|exe))'
    )

    foreach ($pattern in $patterns) {
        foreach ($match in [regex]::Matches($expanded, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $value = $match.Groups[1].Value
            if ($value -and -not $results.Contains($value)) {
                $results.Add($value) | Out-Null
            }
        }
    }

    return $results.ToArray()
}

function Test-UserWritableOrUnusualPath {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"')).ToLowerInvariant()

    $needles = @(
        '\appdata\',
        '\temp\',
        '\downloads\',
        '\desktop\',
        '\users\public\',
        '\programdata\'
    )

    foreach ($needle in $needles) {
        if ($p.Contains($needle)) { return $true }
    }

    if ($p -match '^[a-z]:\\[^\\]+\.(exe|dll|bat|cmd|ps1|vbs|js|hta|scr)$') { return $true }
    return $false
}

function Test-SuspiciousCommandLine {
    param([AllowNull()][string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    $c = $CommandLine.ToLowerInvariant()

    if ($c -match '(powershell|pwsh)(\.exe)?\s+.*(-enc|-encodedcommand)\b') { return $true }
    if ($c -match '\bmshta(\.exe)?\b.*https?://') { return $true }
    if ($c -match '\b(rundll32|regsvr32)(\.exe)?\b.*https?://') { return $true }
    if ($c -match '\b(wscript|cscript)(\.exe)?\b.*\\(appdata|temp|downloads)\\') { return $true }
    return $false
}

function Get-ExecutionChainRisk {
    param([AllowNull()][string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
    $c = [string]$CommandLine
    if ($c -match '(?i)\bconhost(?:\.exe)?\b\s+--headless\b' -and
        $c -match '(?i)\\AppData\\(?:Local|Roaming)\\[^\s"'']+\\(?:[^\s"'']+\\)?node\.exe\b' -and
        $c -match '(?i)\\AppData\\(?:Local|Roaming)\\[^\s"'']+\.(?:xml|js|jse)\b') {
        return 'Hidden console launches Node.js and a configuration/script from user-writable AppData'
    }
    if ($c -match '(?i)\b(?:rundll32|regsvr32|mshta)(?:\.exe)?\b' -and
        $c -match '(?i)(?:https?://|\\AppData\\(?:Local|Roaming)\\[^\s"'']+\.(?:dll|sct|hta|js))') {
        return 'Signed Windows host launches a remote or user-writable code payload'
    }
    if ($c -match '(?i)\b(?:powershell|pwsh)(?:\.exe)?\b' -and
        $c -match '(?i)(?:-encodedcommand|-enc\b)' -and
        $c -match '(?i)(?:-windowstyle\s+hidden|-w\s+hidden|-nop\b)') {
        return 'PowerShell hidden/encoded launch chain'
    }
    return ''
}

function Test-KnownStaleWebexStartup {
    param(
        [AllowNull()][string]$Name,
        [AllowNull()][string]$Path,
        [AllowNull()][string]$Command,
        [AllowNull()][string]$ExtraText
    )

    # This is a stale-entry classification ONLY, not an allowlist for binaries.
    # Never suppress a suspicious executable, a command with dangerous arguments,
    # or an entry whose actual target still exists.
    $itemName = ([string]$Name).Trim().Trim('"')
    if ($itemName -notmatch '(?i)^(?:CiscoSpark|CiscoMeetingDaemon|Webex|WebexApp|Webex Meetings|Webex Desktop App)(?:\.lnk)?$') { return $false }
    if (Test-SuspiciousCommandLine $Command) { return $false }
    if ($Command -match '(?i)(?:\|\||&&|\b(?:powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)(?:\.exe)?\b)') { return $false }
    # Do not excuse extra executable/script arguments tacked onto a Webex
    # shortcut. A normal shortcut startup references only the shortcut.
    if ($Command -match '(?i)\.lnk\b' -and $Command -notmatch '(?i)\.lnk"?\s*$') { return $false }
    if ($Command -match '(?i)WebexHost\.exe\b' -and
        $Command -notmatch '(?i)WebexHost\.exe"?\s*(?:/daemon\s*/runFrom=autorun)?\s*$') { return $false }
    if ($Command -match '(?i)\.exe\b' -and $Command -notmatch '(?i)WebexHost\.exe\b') { return $false }

    $actualPath = ([string]$Path).Trim().Trim('"')
    if ($actualPath -and (Test-Path -LiteralPath $actualPath -PathType Leaf -ErrorAction SilentlyContinue)) { return $false }

    # Cisco still uses its legacy CiscoSpark folder and names for Webex. This
    # exact Start Menu shortcut path is a typical orphan after app updates.
    $specificWebexShortcut = '(?i)\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\(?:Webex|Cisco Spark)\\[^\\"<>|\r\n]+\.lnk\b'
    $legacyMeetingHost = '(?i)\\AppData\\Local\\WebEx\\WebexHost\.exe\b'

    $details = "$actualPath $Command $ExtraText"
    if ($itemName -match '(?i)^(?:CiscoSpark|Webex|WebexApp|Webex Meetings|Webex Desktop App)(?:\.lnk)?$' -and
        $details -match $specificWebexShortcut) {
        return $true
    }

    if ($itemName -ieq 'CiscoMeetingDaemon' -and
        $details -match $legacyMeetingHost -and
        $details -notmatch '(?i)(?:-enc(?:odedcommand)?\b|[;&|]{2})') {
        return $true
    }

    return $false
}

function Format-FileContext {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $info = Get-SignatureInfo $Path
    if (-not $info.Exists) { return "Path: $Path | File not found" }

    $company = if ($info.Company) { $info.Company } elseif ($info.Signer) { $info.Signer } else { 'Unknown publisher' }
    $date = if ($info.LastWrite) { $info.LastWrite.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown date' }
    return "Path: $Path | Signature: $($info.Status) | Publisher: $company | Modified: $date"
}

function Get-UserProfileRoots {
    $profiles = New-Object System.Collections.Generic.List[string]
    try {
        Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
            Where-Object { -not $_.Special -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath -PathType Container) } |
            ForEach-Object {
                if (-not $profiles.Contains([string]$_.LocalPath)) {
                    $profiles.Add([string]$_.LocalPath) | Out-Null
                }
            }
    } catch { }

    if ($profiles.Count -eq 0) {
        try {
            Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } |
                ForEach-Object { $profiles.Add($_.FullName) | Out-Null }
        } catch { }
    }

    return @($profiles.ToArray() | Sort-Object -Unique)
}

function Get-LoadedUserRegistryRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($key in Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue) {
            if ($key.PSChildName -match '^S-1-5-21-(\d+-){2,}\d+$') {
                $roots.Add("Registry::HKEY_USERS\$($key.PSChildName)") | Out-Null
            }
        }
    } catch { }
    return $roots.ToArray()
}

function Convert-InstallDate {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $formats = @('yyyyMMdd','yyyy-MM-dd','MM/dd/yyyy','M/d/yyyy')
    foreach ($format in $formats) {
        $parsed = [datetime]::MinValue
        if ([datetime]::TryParseExact($Value, $format, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            return $parsed
        }
    }

    $fallback = [datetime]::MinValue
    if ([datetime]::TryParse($Value, [ref]$fallback)) { return $fallback }
    return $null
}

function Get-InstalledApplications {
    $apps = New-Object System.Collections.Generic.List[object]
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $paths) {
        try {
            foreach ($item in @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
                if ([string]::IsNullOrWhiteSpace($item.DisplayName)) { continue }
                $apps.Add([PSCustomObject]@{
                    Name        = [string]$item.DisplayName
                    Version     = [string]$item.DisplayVersion
                    Publisher   = [string]$item.Publisher
                    InstallDate = Convert-InstallDate ([string]$item.InstallDate)
                    InstallPath = [string]$item.InstallLocation
                    Uninstall   = [string]$item.UninstallString
                }) | Out-Null
            }
        } catch { }
    }

    return @($apps.ToArray() | Sort-Object Name, Version -Unique)
}

function Get-ThirdPartyAppxPackages {
    $results = New-Object System.Collections.Generic.List[object]
    try {
        if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
            foreach ($pkg in @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)) {
                $publisher = [string]$pkg.Publisher
                if ($publisher -match '(?i)(CN=Microsoft|O=Microsoft Corporation)') { continue }
                $results.Add([PSCustomObject]@{
                    Name = [string]$pkg.Name
                    Version = [string]$pkg.Version
                    Publisher = $publisher
                    InstallLocation = [string]$pkg.InstallLocation
                }) | Out-Null
            }
        }
    } catch { }
    return @($results.ToArray() | Sort-Object Name, Version -Unique)
}

function Get-RemoteToolMatches {
    param([object[]]$Apps)
    return @(Get-WatchlistInstalledMatches -Apps $Apps -Watchlist $script:RemoteAccessWatchlist -Kind 'Remote Access')
}

function Get-RemoteToolRuntimeMatches {
    return @(Get-WatchlistRuntimeMatches -Watchlist $script:RemoteAccessWatchlist -Kind 'Remote Access')
}

function Get-PupPuaInstalledMatches {
    param([object[]]$Apps)
    return @(Get-WatchlistInstalledMatches -Apps $Apps -Watchlist $script:PupPuaWatchlist -Kind 'PUP/PUA')
}

function Get-PupPuaRuntimeMatches {
    return @(Get-WatchlistRuntimeMatches -Watchlist $script:PupPuaWatchlist -Kind 'PUP/PUA')
}

function Get-WmiPersistenceItems {
    $results = New-Object System.Collections.Generic.List[object]

    try {
        foreach ($item in @(Get-CimInstance -Namespace 'root\subscription' -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue)) {
            $results.Add([PSCustomObject]@{
                Type = 'CommandLineEventConsumer'
                Name = [string]$item.Name
                Detail = "Executable: $($item.ExecutablePath) | Command: $($item.CommandLineTemplate)"
                Severity = 'Review'
            }) | Out-Null
        }
    } catch { }

    try {
        foreach ($item in @(Get-CimInstance -Namespace 'root\subscription' -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue)) {
            $scriptText = [string]$item.ScriptText
            if ($scriptText.Length -gt 700) { $scriptText = $scriptText.Substring(0,700) + '...' }
            $results.Add([PSCustomObject]@{
                Type = 'ActiveScriptEventConsumer'
                Name = [string]$item.Name
                Detail = "Engine: $($item.ScriptingEngine) | Script: $scriptText"
                Severity = 'Review'
            }) | Out-Null
        }
    } catch { }

    return $results.ToArray()
}

function Resolve-ShortcutTarget {
    param([AllowNull()][string]$ShortcutPath)

    $result = [PSCustomObject]@{
        TargetPath = ''
        Arguments  = ''
    }

    if ([string]::IsNullOrWhiteSpace($ShortcutPath) -or
        [System.IO.Path]::GetExtension($ShortcutPath) -ine '.lnk' -or
        -not (Test-Path -LiteralPath $ShortcutPath -PathType Leaf)) {
        return $result
    }

    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($ShortcutPath)
        $result.TargetPath = [string]$shortcut.TargetPath
        $result.Arguments = [string]$shortcut.Arguments
    } catch { }

    return $result
}

function Get-StartupEntries {
    $entries = New-Object System.Collections.Generic.List[object]

    try {
        foreach ($item in @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue)) {
            $startupName = [string]$item.Name
            $startupCommand = [string]$item.Command
            if ([string]::IsNullOrWhiteSpace($startupName) -and [string]::IsNullOrWhiteSpace($startupCommand)) { continue }
            $entries.Add([PSCustomObject]@{
                Source  = 'Win32_StartupCommand'
                Name    = $startupName
                Command = $startupCommand
                User    = [string]$item.User
                Path    = Get-ExecutablePathFromCommand $startupCommand
            }) | Out-Null
        }
    } catch { }

    $registryTargets = New-Object System.Collections.Generic.List[object]
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion')) {
        foreach ($leaf in @('Run','RunOnce')) {
            $registryTargets.Add([PSCustomObject]@{ Label = "$base\$leaf"; Path = "$base\$leaf" }) | Out-Null
        }
    }

    foreach ($root in Get-LoadedUserRegistryRoots) {
        foreach ($leaf in @('Run','RunOnce')) {
            $path = "$root\Software\Microsoft\Windows\CurrentVersion\$leaf"
            $registryTargets.Add([PSCustomObject]@{ Label = $path; Path = $path }) | Out-Null
        }
    }

    foreach ($target in $registryTargets) {
        try {
            if (-not (Test-Path -LiteralPath $target.Path)) { continue }
            $props = Get-ItemProperty -LiteralPath $target.Path -ErrorAction SilentlyContinue
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
                $command = [string]$prop.Value
                if ([string]::IsNullOrWhiteSpace($command)) { continue }
                $entries.Add([PSCustomObject]@{
                    Source  = $target.Label
                    Name    = $prop.Name
                    Command = $command
                    User    = ''
                    Path    = Get-ExecutablePathFromCommand $command
                }) | Out-Null
            }
        } catch { }
    }

    foreach ($profile in Get-UserProfileRoots) {
        $startupFolder = Join-Path $profile 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        if (-not (Test-Path -LiteralPath $startupFolder -PathType Container)) { continue }
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $startupFolder -Force -File -ErrorAction SilentlyContinue)) {
                if ($file.Name -ieq 'desktop.ini') { continue }

                $command = $file.FullName
                $resolvedPath = $file.FullName
                if ($file.Extension -ieq '.lnk') {
                    $shortcut = Resolve-ShortcutTarget $file.FullName
                    if (-not [string]::IsNullOrWhiteSpace([string]$shortcut.TargetPath)) {
                        $resolvedPath = [string]$shortcut.TargetPath
                        $command = ('"{0}" {1}' -f $shortcut.TargetPath, $shortcut.Arguments).Trim()
                    }
                }

                $entries.Add([PSCustomObject]@{
                    Source  = $startupFolder
                    Name    = $file.Name
                    Command = $command
                    User    = Split-Path $profile -Leaf
                    Path    = $resolvedPath
                }) | Out-Null
            }
        } catch { }
    }

    $commonStartup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
    if (Test-Path -LiteralPath $commonStartup -PathType Container) {
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $commonStartup -Force -File -ErrorAction SilentlyContinue)) {
                if ($file.Name -ieq 'desktop.ini') { continue }

                $command = $file.FullName
                $resolvedPath = $file.FullName
                if ($file.Extension -ieq '.lnk') {
                    $shortcut = Resolve-ShortcutTarget $file.FullName
                    if (-not [string]::IsNullOrWhiteSpace([string]$shortcut.TargetPath)) {
                        $resolvedPath = [string]$shortcut.TargetPath
                        $command = ('"{0}" {1}' -f $shortcut.TargetPath, $shortcut.Arguments).Trim()
                    }
                }

                $entries.Add([PSCustomObject]@{
                    Source  = $commonStartup
                    Name    = $file.Name
                    Command = $command
                    User    = 'All Users'
                    Path    = $resolvedPath
                }) | Out-Null
            }
        } catch { }
    }

    # Win32_StartupCommand overlaps heavily with Run/RunOnce. Deduplicate by normalized path/command.
    $dedup = @{}
    $ordered = New-Object System.Collections.Generic.List[object]
    foreach ($entry in @($entries.ToArray() | Sort-Object @{Expression={ if ($_.Source -eq 'Win32_StartupCommand') { 2 } else { 1 } }}, Source, Name)) {
        $pathKey = ([string]$entry.Path).Trim().Trim('"').ToLowerInvariant()
        $commandKey = ([string]$entry.Command).Trim().ToLowerInvariant()
        if ($pathKey) {
            $key = $pathKey + '|' + ($commandKey -replace '^\s*"?[^" ]+"?\s*','')
        } else {
            $key = $commandKey
        }
        if (-not $key) { $key = (([string]$entry.Name) + '|' + ([string]$entry.Source)).ToLowerInvariant() }
        if ($dedup.ContainsKey($key)) { continue }
        $dedup[$key] = $true
        $ordered.Add($entry) | Out-Null
    }
    return $ordered.ToArray()
}

function Test-KnownMaintenanceChkdskTask {
    param(
        [AllowNull()][string]$TaskName,
        [AllowNull()][string]$Command
    )

    if ([string]::IsNullOrWhiteSpace($TaskName)) { return $false }

    return (
        ($TaskName -match '(?i)^\\?Maintenance\s+CHKDSK\s+Injection\b') -and
        ($Command -match '(?i)(?:Maintenance(?:\s+Files)?[\\/].*Run\s+Me\.bat|Maintenance\.exe\s+Files[\\/]Run\s+Me\.bat)')
    )
}

function Test-KnownWindowsUpdateOrchestratorTask {
    param(
        [AllowNull()][string]$TaskPath,
        [AllowNull()][string]$TaskName,
        [AllowNull()][string]$Command
    )

    if ([string]::IsNullOrWhiteSpace($TaskPath) -or
        [string]::IsNullOrWhiteSpace($TaskName) -or
        [string]::IsNullOrWhiteSpace($Command)) {
        return $false
    }

    # Built-in Windows Update Orchestrator heartbeat task.
    if ($TaskPath -ieq '\Microsoft\Windows\UpdateOrchestrator\' -and
        $TaskName -ieq 'UIEOrchestrator' -and
        $Command -match '(?i)\\Windows\\System32\\UIEOrchestrator(?:Stub)?\.exe\s+/SendHeartbeat\b') {
        return $true
    }

    return $false
}

function Get-SuspiciousScheduledTasks {
    $results = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            foreach ($action in @($task.Actions)) {
                if (-not $action) { continue }
                $command = (([string]$action.Execute) + ' ' + ([string]$action.Arguments)).Trim()
                $exePath = Get-ExecutablePathFromCommand ([string]$action.Execute)
                $targets = @(Get-ReferencedScriptPaths $command)
                $severity = 'Info'
                $reason = New-Object System.Collections.Generic.List[string]

                $isKnownOneDriveTask = ([string]$task.TaskName -match '(?i)^OneDrive\s+(?:Reporting|Startup)\s+Task-') -and
                                       ($command -match '(?i)\\Microsoft\\OneDrive\\(?:[^\\]+\\)*(?:OneDriveStandaloneUpdater|OneDriveLauncher)\.exe')
                $isKnownMaintenanceTask = Test-KnownMaintenanceChkdskTask -TaskName ([string]$task.TaskName) -Command $command
                $isKnownUpdateOrchestratorTask = Test-KnownWindowsUpdateOrchestratorTask -TaskPath ([string]$task.TaskPath) -TaskName ([string]$task.TaskName) -Command $command
                if ($isKnownOneDriveTask -or $isKnownMaintenanceTask -or $isKnownUpdateOrchestratorTask) { continue }

                $remoteHit = Find-WatchlistExecutable -Executable ([string]$action.Execute) -Watchlist $script:RemoteAccessWatchlist
                $pupHit = Find-WatchlistExecutable -Executable ([string]$action.Execute) -Watchlist $script:PupPuaWatchlist
                if ($remoteHit -or $pupHit) {
                    $severity = 'Warning'
                    if ($remoteHit) { $reason.Add("Remote-access watchlist: $($remoteHit.Name)") | Out-Null }
                    if ($pupHit) { $reason.Add("PUP/PUA watchlist: $($pupHit.Name)") | Out-Null }
                } elseif ((Get-ExecutionChainRisk $command) -or (Test-SuspiciousCommandLine $command)) {
                    $severity = 'Warning'
                    $chainReason = Get-ExecutionChainRisk $command
                    $reason.Add($(if ($chainReason) { $chainReason } else { 'Strongly suspicious command pattern' })) | Out-Null
                } else {
                    $needsReview = $false
                    if (Test-UserWritableOrUnusualPath $exePath) {
                        $sig = Get-SignatureInfo $exePath
                        if (-not $sig.Exists -or $sig.Status -ne 'Valid') {
                            $needsReview = $true
                            $reason.Add("Executable in user-writable/unusual path with signature $($sig.Status)") | Out-Null
                        }
                    }
                    foreach ($target in $targets) {
                        if (-not (Test-UserWritableOrUnusualPath $target)) { continue }
                        $sig = Get-SignatureInfo $target
                        if (-not $sig.Exists -or $sig.Status -ne 'Valid') {
                            $needsReview = $true
                            $reason.Add("Referenced target needs review: $target ($($sig.Status))") | Out-Null
                        }
                    }
                    if ($needsReview) { $severity = 'Review' }
                }

                if ($severity -eq 'Info') { continue }
                $results.Add([PSCustomObject]@{
                    TaskName  = $task.TaskName
                    TaskPath  = $task.TaskPath
                    State     = [string]$task.State
                    Command   = $command
                    Path      = $exePath
                    Severity  = $severity
                    Reason    = ($reason -join '; ')
                    RemoteHit = if ($remoteHit) { $remoteHit.Name } else { '' }
                    PupHit    = if ($pupHit) { $pupHit.Name } else { '' }
                }) | Out-Null
            }
        }
    } catch { }
    return @($results.ToArray() | Sort-Object TaskPath, TaskName, Command -Unique)
}

function Get-ServiceDriverFindings {
    $results = New-Object System.Collections.Generic.List[object]

    try {
        foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
            $raw = [string]$svc.PathName
            $path = Get-ExecutablePathFromCommand $raw
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            $chainReason = Get-ExecutionChainRisk $raw
            if (-not $chainReason -and -not (Test-UserWritableOrUnusualPath $path)) { continue }
            $sig = Get-SignatureInfo $path
            if (-not $chainReason -and $sig.Exists -and $sig.Status -eq 'Valid') { continue }
            $results.Add([PSCustomObject]@{
                Type      = 'Service'
                Name      = [string]$svc.Name
                Display   = [string]$svc.DisplayName
                State     = [string]$svc.State
                StartMode = [string]$svc.StartMode
                Path      = $path
                Signature = $sig.Status
                Severity  = $(if ($chainReason) { 'Warning' } else { 'Review' })
                Reason    = $chainReason
            }) | Out-Null
        }
    } catch { }

    try {
        foreach ($drv in @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
            $raw = [string]$drv.PathName
            $path = Get-ExecutablePathFromCommand $raw
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            if ($path -like '\SystemRoot\*') { $path = Join-Path $env:SystemRoot ($path.Substring(12)) }
            if ($path -like 'System32\*') { $path = Join-Path $env:SystemRoot $path }
            $sig = Get-SignatureInfo $path
            $review = (-not $sig.Exists) -or ($sig.Status -ne 'Valid' -and (Test-UserWritableOrUnusualPath $path))
            if (-not $review) { continue }
            $results.Add([PSCustomObject]@{
                Type      = 'Driver'
                Name      = [string]$drv.Name
                Display   = [string]$drv.DisplayName
                State     = [string]$drv.State
                StartMode = [string]$drv.StartMode
                Path      = $path
                Signature = $sig.Status
                Severity  = 'Review'
            }) | Out-Null
        }
    } catch { }

    return @($results.ToArray() | Sort-Object Type, Name, Path -Unique)
}

function Get-ProcessFindings {
    $rawResults = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
            $path = [string]$proc.ExecutablePath
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            $warning = (Test-SuspiciousCommandLine ([string]$proc.CommandLine)) -or [bool](Get-ExecutionChainRisk ([string]$proc.CommandLine))
            $unusual = Test-UserWritableOrUnusualPath $path
            $sig = if ($warning -or $unusual) { Get-SignatureInfo $path } else { $null }
            $review = $unusual -and (-not $sig.Exists -or $sig.Status -ne 'Valid')
            if (-not $warning -and -not $review) { continue }

            $rawResults.Add([PSCustomObject]@{
                Name        = [string]$proc.Name
                PID         = [int]$proc.ProcessId
                Path        = $path
                CommandLine = [string]$proc.CommandLine
                Signature   = if ($sig) { $sig.Status } else { 'Unknown' }
                Publisher   = if ($sig) { if ($sig.Company) { $sig.Company } else { $sig.Signer } } else { '' }
                Severity    = if ($warning) { 'Warning' } else { 'Review' }
            }) | Out-Null
        }
    } catch { }

    # Aggregate multi-process applications (Chromium/Electron/etc.) by executable path and severity.
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($group in @($rawResults.ToArray() | Group-Object Severity, Path, Name)) {
        $first = $group.Group | Select-Object -First 1
        $pids = @($group.Group | Select-Object -ExpandProperty PID | Sort-Object -Unique)
        $results.Add([PSCustomObject]@{
            Name        = $first.Name
            PID         = ($pids -join ', ')
            InstanceCount = $group.Count
            Path        = $first.Path
            CommandLine = $first.CommandLine
            Signature   = $first.Signature
            Publisher   = $first.Publisher
            Severity    = $first.Severity
        }) | Out-Null
    }
    return $results.ToArray()
}

function Get-BatchThreatIndicators {
    param([Parameter(Mandatory)][string]$Path)

    $indicators = New-Object System.Collections.Generic.List[string]

    if ([string]::IsNullOrWhiteSpace($Path)) { return @() }
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -notin @('.bat','.cmd')) { return @() }

    $name = [IO.Path]::GetFileNameWithoutExtension($Path)

    # Common malware/PUA-style batch filenames. This is intentionally narrower
    # than matching generic words like "update", "install", or "uninstall".
    if ($name -match '(?i)(?:^|[_ .-])(?:payload|dropper|stealer|password.?stealer|token.?grabber|grabber|backdoor|ransom(?:ware)?|crypt(?:er|or)|miner|rat|keygen|crack|activator|kmsauto|kmspico)(?:$|[_ .-])') {
        $indicators.Add('Filename resembles a common malware/credential-theft/activation tool pattern') | Out-Null
    }

    $content = ''
    try {
        # Batch files are normally small. Cap content inspection so an unusually
        # large file cannot consume excessive memory.
        $fileInfo = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fileInfo.Length -le 1MB) {
            $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        } else {
            $reader = New-Object System.IO.StreamReader($Path)
            try {
                $buffer = New-Object char[] 262144
                $read = $reader.Read($buffer, 0, $buffer.Length)
                if ($read -gt 0) { $content = New-Object string($buffer, 0, $read) }
            } finally {
                $reader.Dispose()
            }
        }
    } catch {
        return $indicators.ToArray()
    }

    if ([string]::IsNullOrWhiteSpace($content)) { return $indicators.ToArray() }

    # Encoded/obfuscated or downloader-oriented PowerShell.
    if ($content -match '(?is)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*(?:-enc(?:odedcommand)?\b|FromBase64String|Invoke-Expression|\bIEX\b|DownloadString|DownloadFile)') {
        $indicators.Add('Encoded/obfuscated or downloader-oriented PowerShell') | Out-Null
    }

    # High-signal living-off-the-land execution patterns commonly abused by malware.
    if ($content -match '(?is)\bmshta(?:\.exe)?\b[^\r\n]*https?://' -or
        $content -match '(?is)\bregsvr32(?:\.exe)?\b[^\r\n]*(?:https?://|scrobj\.dll)' -or
        $content -match '(?is)\brundll32(?:\.exe)?\b[^\r\n]*(?:javascript:|vbscript:|https?://)') {
        $indicators.Add('Suspicious LOLBin-based remote/script execution') | Out-Null
    }

    # Download utility + an execution target or user-writable drop location.
    $downloadPattern = '(?is)\b(?:certutil(?:\.exe)?\b[^\r\n]*-urlcache|bitsadmin(?:\.exe)?\b[^\r\n]*/transfer|curl(?:\.exe)?\b[^\r\n]*https?://|wget(?:\.exe)?\b[^\r\n]*https?://)'
    $executePattern = '(?is)\b(?:start|call|cmd(?:\.exe)?\s+/c|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\b'
    $dropPattern = '(?is)\\(?:AppData|Temp|Downloads|Users\\Public)\\[^\r\n"]+\.(?:exe|dll|ps1|vbs|js|hta|scr|bat|cmd)'
    if ($content -match $downloadPattern -and ($content -match $executePattern -or $content -match $dropPattern)) {
        $indicators.Add('Download-and-execute/drop chain') | Out-Null
    }

    # Defender or firewall weakening.
    if ($content -match '(?is)Set-MpPreference[^\r\n]*-DisableRealtimeMonitoring[^\r\n]*(?:\$?true|1)' -or
        $content -match '(?is)(?:Add|Set)-MpPreference[^\r\n]*-Exclusion(?:Path|Process|Extension)' -or
        $content -match '(?is)\bnetsh\b[^\r\n]*advfirewall[^\r\n]*set[^\r\n]*state\s+off' -or
        $content -match '(?is)\b(?:sc|net)\b[^\r\n]*(?:stop|config)[^\r\n]*(?:WinDefend|WdNisSvc)') {
        $indicators.Add('Attempts to weaken Microsoft Defender or Windows Firewall') | Out-Null
    }

    # Ransomware/anti-recovery behaviors.
    if ($content -match '(?is)\bvssadmin\b[^\r\n]*delete\s+shadows' -or
        $content -match '(?is)\bwmic\b[^\r\n]*shadowcopy[^\r\n]*delete' -or
        $content -match '(?is)\bwbadmin\b[^\r\n]*delete\s+catalog' -or
        $content -match '(?is)\bbcdedit\b[^\r\n]*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)') {
        $indicators.Add('Recovery/shadow-copy deletion commonly associated with ransomware') | Out-Null
    }

    # Security-log clearing.
    if ($content -match '(?is)\bwevtutil\b\s+cl\s+\S+') {
        $indicators.Add('Clears Windows event logs') | Out-Null
    }

    # Credential access.
    if ($content -match '(?is)\breg\b\s+save\s+HKLM\\(?:SAM|SECURITY|SYSTEM)\b' -or
        $content -match '(?is)\bprocdump(?:64)?(?:\.exe)?\b[^\r\n]*\blsass(?:\.exe)?\b' -or
        $content -match '(?is)\brundll32(?:\.exe)?\b[^\r\n]*comsvcs\.dll[^\r\n]*MiniDump') {
        $indicators.Add('Credential-dumping behavior') | Out-Null
    }

    # Persistence is only considered high signal when it launches from a user-writable location.
    if (($content -match '(?is)\bschtasks\b[^\r\n]*/create' -or
         $content -match '(?is)\breg\b[^\r\n]*add[^\r\n]*\\CurrentVersion\\Run(?:Once)?\b') -and
        $content -match '(?is)\\(?:AppData|Temp|Downloads|Users\\Public)\\') {
        $indicators.Add('Creates persistence from a user-writable location') | Out-Null
    }

    # Local account creation + administrator promotion is uncommon in normal helper batch files.
    if ($content -match '(?is)\bnet\s+user\b[^\r\n]*/add\b' -and
        $content -match '(?is)\bnet\s+localgroup\s+administrators\b[^\r\n]*/add\b') {
        $indicators.Add('Creates a local user and adds it to Administrators') | Out-Null
    }

    return @($indicators.ToArray() | Sort-Object -Unique)
}

function Get-RecentFileCandidates {
    param(
        [int]$Days
    )

    $cutoff = (Get-Date).AddDays(-1 * $Days)
    $extensions = @('.exe','.dll','.bat','.cmd','.ps1','.vbs','.vbe','.js','.jse','.hta','.scr')
    $results = New-Object System.Collections.Generic.List[object]
    $scanned = 0

    $targets = New-Object System.Collections.Generic.List[object]
    foreach ($profile in Get-UserProfileRoots) {
        foreach ($relative in @('AppData\Roaming','AppData\Local','Downloads','Desktop')) {
            $path = Join-Path $profile $relative
            if (Test-Path -LiteralPath $path -PathType Container) {
                $depth = if ($relative -in @('Downloads','Desktop')) { 4 } else { 4 }
                $targets.Add([PSCustomObject]@{ Path = $path; Depth = $depth }) | Out-Null
            }
        }
    }

    if (Test-Path -LiteralPath $env:ProgramData -PathType Container) {
        $targets.Add([PSCustomObject]@{ Path = $env:ProgramData; Depth = 4 }) | Out-Null
    }

    foreach ($target in $targets) {
        try {
            Get-InspectionTreeEntries -Root $target.Path -Depth $target.Depth -FilesOnly | ForEach-Object {
                $file = $_
                if ($file.LastWriteTime -lt $cutoff) { return }
                if ($extensions -notcontains $file.Extension.ToLowerInvariant()) { return }
                $scanned++

                $skip = (Test-IsInspectionOwnPath $file.FullName) -or ($file.FullName -match '(?i)\\(cache|caches|code cache|gpucache|node_modules|windowsapps|packages)\\')
                if ($skip) { return }

                # Known RMM/PUP artifacts are reported by the dedicated watchlist scan
                # with the stronger Warning classification; don't duplicate them here.
                if ((Find-WatchlistEntry -Text $file.FullName -Watchlist $script:RemoteAccessWatchlist -Mode Artifact) -or
                    (Find-WatchlistEntry -Text $file.FullName -Watchlist $script:PupPuaWatchlist -Mode Artifact)) {
                    return
                }

                $sig = Get-SignatureInfo $file.FullName
                $ext = $file.Extension.ToLowerInvariant()

                $note = ''

                if ($ext -in @('.bat','.cmd')) {
                    # Batch/CMD files are neutral by default. Only surface them when
                    # filename/content inspection finds common malware behaviors.
                    $batchIndicators = @(Get-BatchThreatIndicators -Path $file.FullName)
                    if ($batchIndicators.Count -eq 0) { return }
                    $review = $true
                    $note = 'Batch threat indicator(s): ' + ($batchIndicators -join '; ')
                } else {
                    # Other active script types remain signature-aware.
                    $highSignalScript = ($ext -in @('.ps1','.vbs','.vbe','.jse','.hta','.scr')) -and ($sig.Status -ne 'Valid')
                    $unsignedExecutable = ($ext -eq '.exe' -and $sig.Status -ne 'Valid')
                    $noisyTypeInHighRiskLocation = ($ext -in @('.dll','.js')) -and ($sig.Status -ne 'Valid') -and ($file.FullName -match '(?i)\\(temp|downloads|desktop)\\')
                    $review = $highSignalScript -or $unsignedExecutable -or $noisyTypeInHighRiskLocation
                    if (-not $review) { return }
                }

                $results.Add([PSCustomObject]@{
                    Path       = $file.FullName
                    Modified   = $file.LastWriteTime
                    SizeKB     = [math]::Round($file.Length / 1KB, 1)
                    Signature  = $sig.Status
                    Publisher  = if ($sig.Company) { $sig.Company } else { $sig.Signer }
                    Severity   = 'Review'
                    Note       = $note
                }) | Out-Null
            }
        } catch { }
    }

    # C:\ root only, not recursive.
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath "$env:SystemDrive\" -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.LastWriteTime -lt $cutoff) { continue }
            if ($extensions -notcontains $file.Extension.ToLowerInvariant()) { continue }
            if (Test-IsInspectionOwnPath $file.FullName) { continue }
            $sig = Get-SignatureInfo $file.FullName
            $ext = $file.Extension.ToLowerInvariant()

            $rootNote = ''
            if ($ext -in @('.bat','.cmd')) {
                $batchIndicators = @(Get-BatchThreatIndicators -Path $file.FullName)
                if ($batchIndicators.Count -eq 0) { continue }
                $rootNote = 'Batch threat indicator(s): ' + ($batchIndicators -join '; ')
            } elseif ($sig.Status -eq 'Valid') {
                continue
            }

            $results.Add([PSCustomObject]@{
                Path       = $file.FullName
                Modified   = $file.LastWriteTime
                SizeKB     = [math]::Round($file.Length / 1KB, 1)
                Signature  = $sig.Status
                Publisher  = if ($sig.Company) { $sig.Company } else { $sig.Signer }
                Severity   = 'Review'
                Note       = $rootNote
            }) | Out-Null
        }
    } catch { }

    return [PSCustomObject]@{
        Files   = $results.ToArray()
        Scanned = $scanned
        Limited = $false
    }
}

function Get-ChromiumProfileLocations {
    $results = New-Object System.Collections.Generic.List[object]
    $browserDefs = @(
        @{ Name='Chrome';   Relative='AppData\Local\Google\Chrome\User Data';                     Direct=$false },
        @{ Name='Edge';     Relative='AppData\Local\Microsoft\Edge\User Data';                    Direct=$false },
        @{ Name='Brave';    Relative='AppData\Local\BraveSoftware\Brave-Browser\User Data';       Direct=$false },
        @{ Name='Vivaldi';  Relative='AppData\Local\Vivaldi\User Data';                           Direct=$false },
        @{ Name='Opera GX'; Relative='AppData\Roaming\Opera Software\Opera GX Stable';            Direct=$true  },
        @{ Name='Opera';    Relative='AppData\Roaming\Opera Software\Opera Stable';               Direct=$true  }
    )

    foreach ($profileRoot in Get-UserProfileRoots) {
        $userName = Split-Path $profileRoot -Leaf
        foreach ($browser in $browserDefs) {
            $base = Join-Path $profileRoot $browser.Relative
            if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }

            if ($browser.Direct) {
                if (Test-Path -LiteralPath (Join-Path $base 'Preferences') -PathType Leaf) {
                    $results.Add([PSCustomObject]@{
                        Browser=$browser.Name; User=$userName; Profile='Default'; Path=$base
                    }) | Out-Null
                }
            } else {
                foreach ($profile in @(Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notin @('System Profile','Guest Profile','Crashpad','GrShaderCache','ShaderCache') })) {
                    if (-not (Test-Path -LiteralPath (Join-Path $profile.FullName 'Preferences') -PathType Leaf)) { continue }
                    $results.Add([PSCustomObject]@{
                        Browser=$browser.Name; User=$userName; Profile=$profile.Name; Path=$profile.FullName
                    }) | Out-Null
                }
            }
        }
    }

    return $results.ToArray()
}

function Resolve-ChromiumExtensionName {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [AllowNull()][string]$RawName
    )

    if ([string]::IsNullOrWhiteSpace($RawName)) { return 'Unknown extension' }
    if ($RawName -notmatch '^__MSG_(.+)__$') { return $RawName }

    $key = $matches[1]
    $versionFolder = Split-Path $ManifestPath -Parent
    $locales = New-Object System.Collections.Generic.List[string]

    try {
        $manifestJson = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($manifestJson.default_locale) { $locales.Add([string]$manifestJson.default_locale) | Out-Null }
    } catch { }

    foreach ($locale in @('en','en_US','en_GB')) {
        if (-not $locales.Contains($locale)) { $locales.Add($locale) | Out-Null }
    }

    $localeRoot = Join-Path $versionFolder '_locales'
    if (Test-Path -LiteralPath $localeRoot -PathType Container) {
        try {
            foreach ($dir in @(Get-ChildItem -LiteralPath $localeRoot -Directory -Force -ErrorAction SilentlyContinue)) {
                if (-not $locales.Contains($dir.Name)) { $locales.Add($dir.Name) | Out-Null }
            }
        } catch { }
    }

    foreach ($locale in $locales) {
        $messages = Join-Path $versionFolder "_locales\$locale\messages.json"
        if (-not (Test-Path -LiteralPath $messages -PathType Leaf)) { continue }
        try {
            $json = Get-Content -LiteralPath $messages -Raw -ErrorAction Stop | ConvertFrom-Json
            $prop = $json.PSObject.Properties[$key]
            if ($prop -and $prop.Value.message) { return [string]$prop.Value.message }
        } catch { }
    }
    return $RawName
}

function Get-ChromiumExtensions {
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($browserProfile in @(Get-ChromiumProfileLocations)) {
        $extensionsRoot = Join-Path $browserProfile.Path 'Extensions'
        if (-not (Test-Path -LiteralPath $extensionsRoot -PathType Container)) { continue }

        foreach ($extensionId in @(Get-ChildItem -LiteralPath $extensionsRoot -Directory -Force -ErrorAction SilentlyContinue)) {
            $versions = @(Get-ChildItem -LiteralPath $extensionId.FullName -Directory -Force -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
            if ($versions.Count -eq 0) { continue }
            $manifest = Join-Path $versions[0].FullName 'manifest.json'
            if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { continue }
            try {
                $json = Get-Content -LiteralPath $manifest -Raw -ErrorAction Stop | ConvertFrom-Json
                $name = Resolve-ChromiumExtensionName -ManifestPath $manifest -RawName ([string]$json.name)
                $results.Add([PSCustomObject]@{
                    Browser   = $browserProfile.Browser
                    User      = $browserProfile.User
                    Profile   = $browserProfile.Profile
                    Name      = $name
                    ID        = $extensionId.Name
                    Version   = [string]$json.version
                    UpdateURL = [string]$json.update_url
                }) | Out-Null
            } catch { }
        }
    }

    return $results.ToArray()
}

function Get-BrowserNotificationSettingsUri {
    param([AllowNull()][string]$Browser)
    if ([string]::IsNullOrWhiteSpace($Browser)) { return 'ms-settings:notifications' }
    switch -Regex ($Browser.Trim()) {
        '^Chrome$'       { return 'threatinspection://browser-notifications/chrome' }
        '^Edge$'         { return 'threatinspection://browser-notifications/edge' }
        '^Brave$'        { return 'threatinspection://browser-notifications/brave' }
        '^Vivaldi$'      { return 'threatinspection://browser-notifications/vivaldi' }
        '^Opera GX$'     { return 'threatinspection://browser-notifications/opera-gx' }
        '^Opera$'        { return 'threatinspection://browser-notifications/opera' }
        '^Firefox$'      { return 'threatinspection://browser-notifications/firefox' }
        default          { return 'ms-settings:notifications' }
    }
}

function Get-WindowsToastSourceBrowser {
    param([AllowNull()][string]$Handler, [AllowNull()][string]$PlainText)

    $sourceText = [string]$Handler
    # The Windows provider identity takes priority. Where the AUMID is opaque,
    # only accept an explicit "via <browser>" label from the toast text; do
    # not confuse a scam message mentioning Chrome/Edge with its true sender.
    if ($sourceText -notmatch '(?i)(MSEdge|Microsoft\s*Edge|\bEdge\b|Google\s*Chrome|\bChrome\b|Brave|Vivaldi|Opera|Firefox)' -and
        [string]$PlainText -match '(?i)\bvia\s+(?<browser>Microsoft\s*Edge|Google\s*Chrome|Brave|Vivaldi|Opera\s*GX|Opera|Firefox)\b') {
        $sourceText = [string]$matches['browser']
    }
    if ($sourceText -match '(?i)(?:Opera\s*GX|OperaGX)') { return 'Opera GX' }
    if ($sourceText -match '(?i)(?:MSEdge|Microsoft\s*Edge|\bEdge\b)') { return 'Edge' }
    if ($sourceText -match '(?i)(?:Google\s*Chrome|\bChrome\b)') { return 'Chrome' }
    if ($sourceText -match '(?i)\bBrave\b') { return 'Brave' }
    if ($sourceText -match '(?i)\bVivaldi\b') { return 'Vivaldi' }
    if ($sourceText -match '(?i)\bOpera\b') { return 'Opera' }
    if ($sourceText -match '(?i)\bFirefox\b') { return 'Firefox' }
    return ''
}

function Get-BrowserNotificationAssessment {
    param([Parameter(Mandatory)][string]$Origin)

    $displayOrigin = ($Origin -split ',',2)[0].Trim()
    $severity = 'Review'
    $reason = 'Notifications are allowed; confirm this site is expected.'
    $notificationHost = ''
    $scheme = ''
    $port = ''

    if ($displayOrigin -match '^(?<scheme>https?)://(?:\[\*\.\])?(?<host>[^/:,]+)(?::(?<port>\d+))?') {
        $scheme = $matches['scheme'].ToLowerInvariant()
        $notificationHost = $matches['host'].Trim().TrimEnd('.').ToLowerInvariant()
        $port = $matches['port']
    } elseif ($displayOrigin -match '^(?:\[\*\.\])?(?<host>[^/:,]+)') {
        $notificationHost = $matches['host'].Trim().TrimEnd('.').ToLowerInvariant()
    }

    $pupHit = Find-WatchlistEntry -Text $notificationHost -Watchlist $script:PupPuaWatchlist -Mode Name
    if ($pupHit) {
        return [PSCustomObject]@{
            Severity='Warning'; Display=$displayOrigin; Host=$notificationHost
            Reason="Allowed notification origin matches PUP/PUA watchlist: $($pupHit.Name)"
        }
    }

    if ($scheme -eq 'http') {
        return [PSCustomObject]@{
            Severity='Warning'; Display=$displayOrigin; Host=$notificationHost
            Reason='Notifications are allowed from a non-HTTPS origin.'
        }
    }

    # Brand-spoofing/security-scare language in the notifying host is a higher
    # signal than a generic HTTPS permission. Do not classify official vendor
    # domains as suspicious solely because their names include the product.
    if ($notificationHost -and $notificationHost -match '(?i)(?:virus|malware|antivirus|critical-alert|criticalerror|security-warning|license-expired|mcafee|norton)' -and
        $notificationHost -notmatch '(?i)(?:^|\.)(?:mcafee\.com|norton\.com|microsoft\.com|google\.com)$') {
        return [PSCustomObject]@{
            Severity='Warning'; Display=$displayOrigin; Host=$notificationHost
            Reason='Notification domain contains security-scare or antivirus-brand language; verify whether it impersonates a security product.'
        }
    }

    if ($notificationHost -match '(^|\.)xn--') {
        return [PSCustomObject]@{
            Severity='Warning'; Display=$displayOrigin; Host=$notificationHost
            Reason='Allowed notification host uses Punycode; verify the domain carefully.'
        }
    }

    # Notification-spam campaigns commonly use long, randomly generated
    # alphanumeric subdomains. This is intentionally applied only to sites that
    # are allowed to notify or that actually produced a browser toast.
    if ($notificationHost) {
        $labels = @($notificationHost -split '\.')
        if ($labels.Count -ge 3) {
            $left = [string]$labels[0]
            $digitCount = ([regex]::Matches($left, '\d')).Count
            $letterCount = ([regex]::Matches($left, '[a-z]')).Count
            if ($left.Length -ge 12 -and $digitCount -ge 2 -and $letterCount -ge 6 -and $left -match '^[a-z0-9-]+$') {
                return [PSCustomObject]@{
                    Severity='Warning'; Display=$displayOrigin; Host=$notificationHost
                    Reason='Allowed/observed notification host uses a long random-looking subdomain commonly associated with notification spam.'
                }
            }
        }
    }

    $ip = [System.Net.IPAddress]::None
    if ($notificationHost -and [System.Net.IPAddress]::TryParse($notificationHost, [ref]$ip)) {
        $bytes = $ip.GetAddressBytes()
        $isPrivate = $false
        if ($bytes.Length -eq 4) {
            $isPrivate = ($bytes[0] -eq 10) -or
                         ($bytes[0] -eq 127) -or
                         ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
                         ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31)
        }
        if (-not $isPrivate) {
            return [PSCustomObject]@{
                Severity='Warning'; Display=$displayOrigin; Host=$notificationHost
                Reason='Notifications are allowed directly from a public IP address.'
            }
        }
    }

    if ($port -and $port -notin @('443','80')) {
        $reason = "Notifications are allowed on nonstandard port $port; confirm this site is expected."
    }

    return [PSCustomObject]@{
        Severity=$severity; Display=$displayOrigin; Host=$notificationHost; Reason=$reason
    }
}

function Get-JsonNestedValue {
    param([AllowNull()]$Object, [string[]]$Keys)
    $value = $Object
    foreach ($key in $Keys) {
        if ($null -eq $value) { return $null }
        if ($value -is [System.Collections.IDictionary]) {
            $dictionary = [System.Collections.IDictionary]$value
            if (-not $dictionary.Contains($key)) { return $null }
            $value = $dictionary[$key]
        } else {
            $property = $value.PSObject.Properties[$key]
            if ($null -eq $property) { return $null }
            $value = $property.Value
        }
    }
    return $value
}

function Get-JsonObjectEntries {
    param([AllowNull()]$Object)
    if ($null -eq $Object) { return @() }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            [PSCustomObject]@{ Name=[string]$key; Value=$Object[$key] }
        }
    } else {
        foreach ($property in $Object.PSObject.Properties) {
            [PSCustomObject]@{ Name=[string]$property.Name; Value=$property.Value }
        }
    }
}

function ConvertFrom-ChromiumJson {
    param([string]$Raw)
    try { return ConvertFrom-Json -InputObject $Raw -ErrorAction Stop }
    catch {
        # Windows PowerShell 5.1's JSON conversion cannot represent some
        # objects containing keys that differ only by capitalization. Use the
        # native .NET JSON parser as a compatible fallback in that case.
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = [int]::MaxValue
        $serializer.RecursionLimit = 1024
        return $serializer.DeserializeObject($Raw)
    }
}

function Get-ChromiumBrowserSettings {
    $results = New-Object System.Collections.Generic.List[object]
    $seenNotifications = @{}
    $script:BrowserNotificationCoverage = New-Object System.Collections.Generic.List[string]
    $script:BrowserNotificationSuccessfulReads = 0

    foreach ($browserProfile in @(Get-ChromiumProfileLocations)) {
        $preferencesPath = Join-Path $browserProfile.Path 'Preferences'
        if (-not (Test-Path -LiteralPath $preferencesPath -PathType Leaf)) { continue }

        # Use a temporary snapshot. Browsers can update Preferences while the
        # inspection is running; reading a copy avoids transient partial reads.
        $snapshot = Join-Path $env:TEMP ("ThreatInspection_Preferences_{0}_{1}.json" -f $PID, ([Guid]::NewGuid().ToString('N')))
        try {
            Copy-Item -LiteralPath $preferencesPath -Destination $snapshot -Force -ErrorAction Stop
            $raw = Get-Content -LiteralPath $snapshot -Raw -ErrorAction Stop
            $json = ConvertFrom-ChromiumJson -Raw $raw
            $script:BrowserNotificationSuccessfulReads++
            $allowedNotificationCount = 0
            $observedNotificationCount = 0

            $homepage = [string](Get-JsonNestedValue -Object $json -Keys @('homepage'))
            $startupMode = [string](Get-JsonNestedValue -Object $json -Keys @('session','restore_on_startup'))
            $startupUrls = @(Get-JsonNestedValue -Object $json -Keys @('session','startup_urls')) -join ', '
            $searchName = [string](Get-JsonNestedValue -Object $json -Keys @('default_search_provider_data','template_url_data','short_name'))
            if (-not $searchName) {
                $searchName = [string](Get-JsonNestedValue -Object $json -Keys @('default_search_provider','name'))
            }

            $detailParts = New-Object System.Collections.Generic.List[string]
            if ($homepage) { $detailParts.Add("Homepage: $homepage") | Out-Null }
            if ($startupMode) { $detailParts.Add("Startup mode: $startupMode") | Out-Null }
            if ($startupUrls) { $detailParts.Add("Startup URLs: $startupUrls") | Out-Null }
            if ($searchName) { $detailParts.Add("Search: $searchName") | Out-Null }
            if ($detailParts.Count -gt 0) {
                $results.Add([PSCustomObject]@{
                    Type='Settings'; Browser=$browserProfile.Browser; User=$browserProfile.User; Profile=$browserProfile.Profile;
                    Name='Homepage / Startup / Search'; Detail=($detailParts -join ' | '); Severity='Info'; Path=$browserProfile.Path
                }) | Out-Null
            }

            # Current per-origin notification permissions.
            try {
                $notificationRoot = Get-JsonNestedValue -Object $json -Keys @('profile','content_settings','exceptions','notifications')
                if ($notificationRoot) {
                    foreach ($prop in @(Get-JsonObjectEntries -Object $notificationRoot)) {
                        $setting = $null
                        try { $setting = [int](Get-JsonNestedValue -Object $prop.Value -Keys @('setting')) } catch { }
                        if ($setting -ne 1) { continue }

                        $origin = [string]$prop.Name
                        $key = "$($browserProfile.Browser)|$($browserProfile.User)|$($browserProfile.Profile)|$origin"
                        $seenNotifications[$key] = $true

                        $assessment = Get-BrowserNotificationAssessment -Origin $origin
                        $allowedNotificationCount++
                        $results.Add([PSCustomObject]@{
                            Type='Notification'; Browser=$browserProfile.Browser; User=$browserProfile.User; Profile=$browserProfile.Profile;
                            Name=$assessment.Display; Detail=("Notifications allowed | " + $assessment.Reason); Severity=$assessment.Severity; Path=$browserProfile.Path
                        }) | Out-Null
                    }
                }
            } catch {
                $script:BrowserNotificationCoverage.Add("$($browserProfile.Browser) / $($browserProfile.User) / $($browserProfile.Profile): Notification permission inspection failed: $($_.Exception.Message)") | Out-Null
            }

            # Chromium also records notification display/click activity. This is
            # useful when a site is visibly producing toasts but the current
            # permission dictionary cannot be read or was changed after delivery.
            try {
                $interactionRoot = Get-JsonNestedValue -Object $json -Keys @('profile','content_settings','exceptions','notification_interactions')
                if ($interactionRoot) {
                    foreach ($prop in @(Get-JsonObjectEntries -Object $interactionRoot)) {
                        $origin = [string]$prop.Name
                        $key = "$($browserProfile.Browser)|$($browserProfile.User)|$($browserProfile.Profile)|$origin"
                        if ($seenNotifications.ContainsKey($key)) { continue }

                        $activityFound = $false
                        try {
                            $settingObj = Get-JsonNestedValue -Object $prop.Value -Keys @('setting')
                            if ($settingObj) {
                                foreach ($day in @(Get-JsonObjectEntries -Object $settingObj)) {
                                    $displayCount = 0
                                    try { $displayCount = [int](Get-JsonNestedValue -Object $day.Value -Keys @('display_count')) } catch { }
                                    if ($displayCount -gt 0) {
                                        $activityFound = $true
                                        break
                                    }
                                }
                            }
                        } catch { }

                        if (-not $activityFound) { continue }

                        $assessment = Get-BrowserNotificationAssessment -Origin $origin
                        $observedNotificationCount++
                        $results.Add([PSCustomObject]@{
                            Type='NotificationActivity'; Browser=$browserProfile.Browser; User=$browserProfile.User; Profile=$browserProfile.Profile;
                            Name=$assessment.Display; Detail=("Browser notification activity was recorded | " + $assessment.Reason); Severity=$assessment.Severity; Path=$browserProfile.Path
                        }) | Out-Null
                    }
                }
            } catch {
                $script:BrowserNotificationCoverage.Add("$($browserProfile.Browser) / $($browserProfile.User) / $($browserProfile.Profile): Notification activity inspection failed: $($_.Exception.Message)") | Out-Null
            }
            $script:BrowserNotificationCoverage.Add("$($browserProfile.Browser) / $($browserProfile.User) / $($browserProfile.Profile): Preferences read; $allowedNotificationCount allowed origin(s), $observedNotificationCount additional observed notification origin(s).") | Out-Null
        } catch {
            $script:BrowserNotificationCoverage.Add("$($browserProfile.Browser) / $($browserProfile.User) / $($browserProfile.Profile): Preferences could not be parsed ($($_.Exception.Message)).") | Out-Null
        }
        finally {
            Remove-Item -LiteralPath $snapshot -Force -ErrorAction SilentlyContinue
        }
    }

    return $results.ToArray()
}

function Initialize-WinSQLite {
    if ('ThreatInspection.WinSQLite' -as [type]) { return $true }

    $code = @'
using System;
using System.Runtime.InteropServices;

namespace ThreatInspection {
    public static class WinSQLite {
        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int sqlite3_open_v2(string filename, out IntPtr db, int flags, IntPtr zvfs);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int sqlite3_prepare_v2(IntPtr db, string sql, int nByte, out IntPtr stmt, IntPtr pzTail);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_step(IntPtr stmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr sqlite3_column_text(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr sqlite3_column_blob(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_column_bytes(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_column_int(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_finalize(IntPtr stmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_close(IntPtr db);
    }
}
'@

    try {
        Add-Type -TypeDefinition $code -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Convert-SqliteText {
    param([IntPtr]$Pointer)
    if ($Pointer -eq [IntPtr]::Zero) { return '' }
    try {
        # SQLite column_text returns UTF-8, not Windows ANSI.
        $length = 0
        while ([Runtime.InteropServices.Marshal]::ReadByte($Pointer, $length) -ne 0 -and $length -lt 1048576) { $length++ }
        if ($length -eq 0) { return '' }
        $bytes = New-Object byte[] $length
        [Runtime.InteropServices.Marshal]::Copy($Pointer, $bytes, 0, $length)
        return [Text.Encoding]::UTF8.GetString($bytes)
    } catch { return '' }
}

function Convert-SqliteBlobToString {
    param([IntPtr]$Statement, [int]$Column)
    try {
        $length = [ThreatInspection.WinSQLite]::sqlite3_column_bytes($Statement, $Column)
        $pointer = [ThreatInspection.WinSQLite]::sqlite3_column_blob($Statement, $Column)
        if ($length -le 0 -or $length -gt 4194304 -or $pointer -eq [IntPtr]::Zero) { return '' }
        $bytes = New-Object byte[] $length
        [Runtime.InteropServices.Marshal]::Copy($pointer, $bytes, 0, $length)
        if ($length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) { return [Text.Encoding]::Unicode.GetString($bytes, 2, $length - 2) }
        if ($length -ge 2 -and $bytes[0] -eq 254 -and $bytes[1] -eq 255) { return [Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $length - 2) }
        # For some Windows builds the toast XML uses UTF-16LE without a BOM.
        if ($length -ge 8 -and $bytes[1] -eq 0 -and $bytes[3] -eq 0) { return [Text.Encoding]::Unicode.GetString($bytes) }
        return [Text.Encoding]::UTF8.GetString($bytes)
    } catch { return '' }
}


function Get-FirefoxNotificationPermissions {
    $results = New-Object System.Collections.Generic.List[object]

    if (-not (Initialize-WinSQLite)) {
        $script:BrowserNotificationCoverage.Add('Firefox notification permissions: SQLite reader was unavailable.') | Out-Null
        return $results.ToArray()
    }

    foreach ($profileRoot in Get-UserProfileRoots) {
        $userName = Split-Path $profileRoot -Leaf
        $profilesRoot = Join-Path $profileRoot 'AppData\Roaming\Mozilla\Firefox\Profiles'
        if (-not (Test-Path -LiteralPath $profilesRoot -PathType Container)) { continue }

        foreach ($ffProfile in @(Get-ChildItem -LiteralPath $profilesRoot -Directory -Force -ErrorAction SilentlyContinue)) {
            $dbPath = Join-Path $ffProfile.FullName 'permissions.sqlite'
            if (-not (Test-Path -LiteralPath $dbPath -PathType Leaf)) { continue }

            # Direct read-only open sees committed changes in permissions.sqlite-wal.
            # Copying the main file alone could silently miss recent grants.
            $db = [IntPtr]::Zero
            $stmt = [IntPtr]::Zero
            $foundPermissions = 0
            try {
                $openRc = [ThreatInspection.WinSQLite]::sqlite3_open_v2($dbPath, [ref]$db, 1, [IntPtr]::Zero)
                if ($openRc -ne 0 -or $db -eq [IntPtr]::Zero) {
                    $script:BrowserNotificationCoverage.Add("Firefox / $userName / $($ffProfile.Name): permissions.sqlite could not be opened (SQLite status $openRc).") | Out-Null
                    continue
                }

                $queries = @(
                    "SELECT origin, type, permission FROM moz_perms WHERE type='desktop-notification' AND permission=1;",
                    "SELECT host, type, permission FROM moz_perms WHERE type='desktop-notification' AND permission=1;"
                )

                $prepared = $false
                foreach ($query in $queries) {
                    $stmt = [IntPtr]::Zero
                    $prepRc = [ThreatInspection.WinSQLite]::sqlite3_prepare_v2($db, $query, -1, [ref]$stmt, [IntPtr]::Zero)
                    if ($prepRc -eq 0 -and $stmt -ne [IntPtr]::Zero) {
                        $prepared = $true
                        break
                    }
                    if ($stmt -ne [IntPtr]::Zero) {
                        [void][ThreatInspection.WinSQLite]::sqlite3_finalize($stmt)
                        $stmt = [IntPtr]::Zero
                    }
                }

                if (-not $prepared) {
                    $script:BrowserNotificationCoverage.Add("Firefox / $userName / $($ffProfile.Name): permissions.sqlite query could not be prepared.") | Out-Null
                    continue
                }

                while ($true) {
                    $stepRc = [ThreatInspection.WinSQLite]::sqlite3_step($stmt)
                    if ($stepRc -eq 100) {
                        $origin = Convert-SqliteText ([ThreatInspection.WinSQLite]::sqlite3_column_text($stmt, 0))
                        if ([string]::IsNullOrWhiteSpace($origin)) { continue }
                        if ($origin -notmatch '^[a-z][a-z0-9+.-]*://') {
                            $origin = 'https://' + $origin.Trim()
                        }

                        $assessment = Get-BrowserNotificationAssessment -Origin $origin
                        $foundPermissions++
                        $results.Add([PSCustomObject]@{
                            Type='Notification'; Browser='Firefox'; User=$userName; Profile=$ffProfile.Name;
                            Name=$assessment.Display; Detail=("Notifications allowed | " + $assessment.Reason);
                            Severity=$assessment.Severity; Path=$ffProfile.FullName
                        }) | Out-Null
                    } elseif ($stepRc -eq 101) {
                        break
                    } else {
                        $script:BrowserNotificationCoverage.Add("Firefox / $userName / $($ffProfile.Name): SQLite read stopped with status $stepRc.") | Out-Null
                        break
                    }
                }
                $script:BrowserNotificationCoverage.Add("Firefox / $userName / $($ffProfile.Name): $foundPermissions allowed notification origin(s) found.") | Out-Null
            } catch {
                $script:BrowserNotificationCoverage.Add("Firefox / $userName / $($ffProfile.Name): notification permission read error: $($_.Exception.Message)") | Out-Null
            }
            finally {
                if ($stmt -ne [IntPtr]::Zero) {
                    try { [void][ThreatInspection.WinSQLite]::sqlite3_finalize($stmt) } catch { }
                }
                if ($db -ne [IntPtr]::Zero) {
                    try { [void][ThreatInspection.WinSQLite]::sqlite3_close($db) } catch { }
                }
            }
        }
    }

    return $results.ToArray()
}

function Get-ManagedBrowserNotificationPermissions {
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($browser in @(
        [PSCustomObject]@{ Name='Chrome'; Relative='Google\Chrome' },
        [PSCustomObject]@{ Name='Edge'; Relative='Microsoft\Edge' },
        [PSCustomObject]@{ Name='Brave'; Relative='BraveSoftware\Brave' }
    )) {
        foreach ($hive in @('HKLM:','HKCU:')) {
            $policyKey = $hive + '\SOFTWARE\Policies\' + $browser.Relative + '\NotificationsAllowedForUrls'
            if (-not (Test-Path -LiteralPath $policyKey -ErrorAction SilentlyContinue)) { continue }
            try {
                $policyValues = Get-ItemProperty -LiteralPath $policyKey -ErrorAction Stop
                foreach ($property in $policyValues.PSObject.Properties) {
                    if ($property.Name -notmatch '^\d+$') { continue }
                    $origin = [string]$property.Value
                    if ([string]::IsNullOrWhiteSpace($origin)) { continue }
                    $assessment = Get-BrowserNotificationAssessment -Origin $origin
                    $results.Add([PSCustomObject]@{
                        Type='NotificationPolicy'; Browser=$browser.Name; User=$hive; Profile='Managed browser policy';
                        Name=$assessment.Display; Detail=('Notifications allowed by browser policy | ' + $assessment.Reason);
                        Severity=$assessment.Severity; Path=$policyKey
                    }) | Out-Null
                }
            } catch {
                $script:BrowserNotificationCoverage.Add("$($browser.Name): browser policy notifications could not be read from $hive.") | Out-Null
            }
        }
    }
    return $results.ToArray()
}

function Merge-BrowserNotificationRecords {
    param([AllowEmptyCollection()][object[]]$Settings = @())
    $notifications = @($Settings | Where-Object { $_.Type -in @('Notification','NotificationActivity','NotificationToast','NotificationPolicy') })
    $other = @($Settings | Where-Object { $_.Type -notin @('Notification','NotificationActivity','NotificationToast','NotificationPolicy') })
    $groups = @{}
    foreach ($item in $notifications) {
        $browser = ([string]$item.Browser).Trim().ToLowerInvariant()
        $user = ([string]$item.User).Trim().ToLowerInvariant()
        $origin = ([string]$item.Name).Trim().ToLowerInvariant()
        $origin = ($origin -split ',',2)[0].Trim()
        if ($origin -match '(?i)^https?://(?<domain>[a-z0-9.-]+)') { $origin = $matches['domain'] }
        # Do not merge unrelated profiles or unrelated notification sources by
        # a generic handler label. Domain-matched records from one browser and
        # user are consolidated, retaining every underlying observation in Detail.
        $domainLike = $origin -match '(?i)^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}'
        $key = if ($domainLike) {
            "$browser|$user|$origin"
        } else {
            "$browser|$user|$([string]$item.Profile)|$([string]$item.Type)|$origin"
        }
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = New-Object System.Collections.Generic.List[object]
        }
        $groups[$key].Add($item) | Out-Null
    }
    $combined = New-Object System.Collections.Generic.List[object]
    foreach ($item in $other) { $combined.Add($item) | Out-Null }
    foreach ($group in $groups.Values) {
        $rows = @($group.ToArray())
        $primary = $rows | Sort-Object @{Expression={Get-SeverityRank ([string]$_.Severity)};Descending=$true} | Select-Object -First 1
        $sources = @($rows | ForEach-Object { [string]$_.Type } | Sort-Object -Unique)
        $profiles = @($rows | ForEach-Object { [string]$_.Profile } | Where-Object { $_ } | Sort-Object -Unique)
        $details = @($rows | ForEach-Object { [string]$_.Detail } | Where-Object { $_ } | Sort-Object -Unique)
        $combined.Add([PSCustomObject]@{
            Type=$(if ($sources.Count -gt 1) { 'Notification' } else { [string]$primary.Type })
            Browser=[string]$primary.Browser; User=[string]$primary.User
            Profile=$(if ($profiles.Count) {$profiles -join ', '} else {[string]$primary.Profile})
            Name=[string]$primary.Name
            Detail=("Sources: $($sources -join ', ') | Observations: $($rows.Count) | " + (($details | Select-Object -First 6) -join ' | '))
            Severity=[string]$primary.Severity; Path=[string]$primary.Path
        }) | Out-Null
    }
    return $combined.ToArray()
}

function Get-WindowsBrowserToastNotifications {
    $results = New-Object System.Collections.Generic.List[object]
    if (-not (Initialize-WinSQLite)) {
        $script:BrowserNotificationCoverage.Add('Windows notifications: SQLite reader was unavailable.') | Out-Null
        return $results.ToArray()
    }

    $browserHandlerPattern = '(?i)(Edge|MSEdge|Chrome|Brave|Vivaldi|Opera|Firefox)'
    $scamTextPattern = '(?i)(critical\s+error|harmful\s+viruses?|viruses?\s+found|remove\s+viruses?|scan\s+now|license\s+expired|version\s+expired|protect\s+(?:your\s+)?data|renew\s+now|important\s+data\s+(?:is\s+)?(?:at\s+)?risk|your\s+(?:computer|pc|device)\s+(?:is|has\s+been)\s+(?:infected|compromised)|(?:malware|virus)\s+detected.*(?:click|scan|remove))'
    $knownNonBrowserHandler = '(?i)(Microsoft\.Windows\.(?:Security|Defender)|Windows\.Security|Microsoft\.Office|Outlook|Teams|Windows\.Explorer)'

    foreach ($profileRoot in Get-UserProfileRoots) {
        $userName = Split-Path $profileRoot -Leaf
        $dbPath = Join-Path $profileRoot 'AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db'
        if (-not (Test-Path -LiteralPath $dbPath -PathType Leaf)) {
            $script:BrowserNotificationCoverage.Add("$($userName): Windows toast database was not present or readable at the expected path.") | Out-Null
            continue
        }

        $db = [IntPtr]::Zero
        $stmt = [IntPtr]::Zero
        $toastRows = 0
        $browserRows = 0
        try {
            # Read-only live SQLite includes committed WAL entries. Database is
            # never modified. No 150-row cap or hidden truncation.
            $openRc = [ThreatInspection.WinSQLite]::sqlite3_open_v2($dbPath, [ref]$db, 1, [IntPtr]::Zero)
            if ($openRc -ne 0 -or $db -eq [IntPtr]::Zero) {
                $script:BrowserNotificationCoverage.Add("$($userName): Windows toast database could not be opened (SQLite status $openRc).") | Out-Null
                continue
            }

            $query = @"
SELECT COALESCE(h.PrimaryId,''), n.Payload
FROM Notification n
LEFT JOIN NotificationHandler h ON n.HandlerId = h.RecordId
WHERE n.Payload IS NOT NULL
ORDER BY n.[Order] DESC;
"@
            $prepRc = [ThreatInspection.WinSQLite]::sqlite3_prepare_v2($db, $query, -1, [ref]$stmt, [IntPtr]::Zero)
            if ($prepRc -ne 0 -or $stmt -eq [IntPtr]::Zero) {
                $script:BrowserNotificationCoverage.Add("$($userName): Windows notification database schema/query could not be read (SQLite status $prepRc).") | Out-Null
                continue
            }

            while ($true) {
                $stepRc = [ThreatInspection.WinSQLite]::sqlite3_step($stmt)
                if ($stepRc -eq 101) { break }
                if ($stepRc -ne 100) {
                    $script:BrowserNotificationCoverage.Add("$($userName): Windows notification database read stopped with SQLite status $stepRc.") | Out-Null
                    break
                }
                $toastRows++
                $handler = Convert-SqliteText ([ThreatInspection.WinSQLite]::sqlite3_column_text($stmt, 0))
                $payload = Convert-SqliteBlobToString -Statement $stmt -Column 1
                if ([string]::IsNullOrWhiteSpace($payload)) { continue }

                # Keep XML attributes containing source URLs, and render only
                # user-facing strings for the scam language classification.
                $plain = [System.Net.WebUtility]::HtmlDecode(($payload -replace '(?s)<[^>]+>', ' '))
                $plain = ($plain -replace '\s+', ' ').Trim()
                $isBrowserToast = ($handler -match $browserHandlerPattern) -or
                    ($plain -match '(?i)via\s+(Microsoft\s+Edge|Google\s+Chrome|Brave|Vivaldi|Opera|Firefox)')
                $toastLooksScam = $plain -match $scamTextPattern
                $toastSourceBrowser = Get-WindowsToastSourceBrowser -Handler $handler -PlainText $plain

                # Some Chromium AUMIDs are opaque. Strong fake-security lures
                # are still relevant unless they came from a clearly identified
                # Windows/Office security or productivity notification provider.
                if (-not $isBrowserToast -and -not $toastLooksScam) { continue }
                if (-not $isBrowserToast -and $handler -match $knownNonBrowserHandler) { continue }
                $browserRows++

                $domains = New-Object System.Collections.Generic.List[string]
                foreach ($candidate in @($payload, $plain)) {
                    foreach ($m in [regex]::Matches($candidate, '(?i)https?://[a-z0-9.-]+(?::\d+)?')) {
                        try {
                            $u = [Uri]$m.Value
                            if ($u.Host -and -not $domains.Contains($u.Host.ToLowerInvariant())) {
                                $domains.Add($u.Host.ToLowerInvariant()) | Out-Null
                            }
                        } catch { }
                    }
                }
                foreach ($m in [regex]::Matches($plain, '(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b')) {
                    $d = $m.Value.Trim('.').ToLowerInvariant()
                    if ($d -match '(?i)^(?:www\.)?(?:microsoft\.com|windows\.com|google\.com|googleapis\.com)$') { continue }
                    if (-not $domains.Contains($d)) { $domains.Add($d) | Out-Null }
                }

                if ($domains.Count -eq 0) {
                    if ($toastLooksScam) {
                        $results.Add([PSCustomObject]@{
                            Type='NotificationToast'; Browser=$(if ($toastSourceBrowser) { $toastSourceBrowser } else { 'Windows browser/security toast' }); User=$userName; Profile='';
                            Name=$(if ($handler) { $handler } else { 'Unattributed security-scare toast' });
                            Detail=('Security-scare notification observed in Windows notification history | ' + (Limit-DisplayText -Text $plain -MaxLength 500 -MaxTokenLength 160));
                            Severity='Warning'; Path=(Split-Path $dbPath -Parent)
                        }) | Out-Null
                    }
                    continue
                }

                foreach ($domain in $domains) {
                    $assessment = Get-BrowserNotificationAssessment -Origin ('https://' + $domain)
                    $severity = if ($toastLooksScam) { 'Warning' } else { $assessment.Severity }
                    $reason = if ($toastLooksScam) {
                        'Observed toast uses fake-virus/license-expired/security-scare wording.'
                    } else { $assessment.Reason }
                    $results.Add([PSCustomObject]@{
                        Type='NotificationToast'; Browser=$(if ($toastSourceBrowser) { $toastSourceBrowser } else { 'Windows browser toast' }); User=$userName; Profile='';
                        Name=$domain;
                        Detail=("Windows notification history | Handler: $handler | $reason | Text: " + (Limit-DisplayText -Text $plain -MaxLength 500 -MaxTokenLength 160));
                        Severity=$severity; Path=(Split-Path $dbPath -Parent)
                    }) | Out-Null
                }
            }
            $script:BrowserNotificationCoverage.Add("$($userName): Windows notification database read $toastRows retained record(s); $browserRows matched browser or security-scare criteria.") | Out-Null
        } catch {
            $script:BrowserNotificationCoverage.Add("$($userName): Windows notification database error: $($_.Exception.Message)") | Out-Null
        }
        finally {
            if ($stmt -ne [IntPtr]::Zero) {
                try { [void][ThreatInspection.WinSQLite]::sqlite3_finalize($stmt) } catch { }
            }
            if ($db -ne [IntPtr]::Zero) {
                try { [void][ThreatInspection.WinSQLite]::sqlite3_close($db) } catch { }
            }
        }
    }

    return @($results.ToArray() | Sort-Object User, Name, Detail -Unique)
}


function Get-FirefoxBrowserSettings {
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($profileRoot in Get-UserProfileRoots) {
        $userName = Split-Path $profileRoot -Leaf
        $profilesRoot = Join-Path $profileRoot 'AppData\Roaming\Mozilla\Firefox\Profiles'
        if (-not (Test-Path -LiteralPath $profilesRoot -PathType Container)) { continue }
        try {
            foreach ($ffProfile in @(Get-ChildItem -LiteralPath $profilesRoot -Directory -Force -ErrorAction SilentlyContinue)) {
                $prefsPath = Join-Path $ffProfile.FullName 'prefs.js'
                if (-not (Test-Path -LiteralPath $prefsPath -PathType Leaf)) { continue }
                $interesting = @()
                try {
                    $interesting = @(Get-Content -LiteralPath $prefsPath -ErrorAction SilentlyContinue | Where-Object {
                        $_ -match 'user_pref\("browser\.startup\.(homepage|page)"' -or
                        $_ -match 'user_pref\("browser\.search\.(defaultenginename|selectedEngine)"'
                    })
                } catch { }
                if ($interesting.Count -gt 0) {
                    $results.Add([PSCustomObject]@{
                        Type='Settings'; Browser='Firefox'; User=$userName; Profile=$ffProfile.Name;
                        Name='Homepage / Startup / Search'; Detail=($interesting -join ' | '); Severity='Info'
                    }) | Out-Null
                }
            }
        } catch { }
    }
    return $results.ToArray()
}

function Get-FirefoxExtensions {
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($profileRoot in Get-UserProfileRoots) {
        $userName = Split-Path $profileRoot -Leaf
        $profilesRoot = Join-Path $profileRoot 'AppData\Roaming\Mozilla\Firefox\Profiles'
        if (-not (Test-Path -LiteralPath $profilesRoot -PathType Container)) { continue }
        try {
            foreach ($ffProfile in @(Get-ChildItem -LiteralPath $profilesRoot -Directory -Force -ErrorAction SilentlyContinue)) {
                $extensionsJson = Join-Path $ffProfile.FullName 'extensions.json'
                if (-not (Test-Path -LiteralPath $extensionsJson -PathType Leaf)) { continue }
                try {
                    $json = Get-Content -LiteralPath $extensionsJson -Raw -ErrorAction Stop | ConvertFrom-Json
                    foreach ($addon in @($json.addons)) {
                        if (-not $addon.active) { continue }
                        $results.Add([PSCustomObject]@{
                            Browser    = 'Firefox'
                            User       = $userName
                            Profile    = $ffProfile.Name
                            Name       = if ($addon.defaultLocale.name) { [string]$addon.defaultLocale.name } else { [string]$addon.id }
                            ID         = [string]$addon.id
                            Version    = [string]$addon.version
                            SignedState= [string]$addon.signedState
                        }) | Out-Null
                    }
                } catch { }
            }
        } catch { }
    }
    return $results.ToArray()
}

function Get-BrowserPolicyFindings {
    $results = New-Object System.Collections.Generic.List[object]
    $targets = @(
        @{ Browser='Chrome'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome' },
        @{ Browser='Chrome'; Path='HKCU:\SOFTWARE\Policies\Google\Chrome' },
        @{ Browser='Edge'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge' },
        @{ Browser='Edge'; Path='HKCU:\SOFTWARE\Policies\Microsoft\Edge' },
        @{ Browser='Brave'; Path='HKLM:\SOFTWARE\Policies\BraveSoftware\Brave' },
        @{ Browser='Brave'; Path='HKCU:\SOFTWARE\Policies\BraveSoftware\Brave' },
        @{ Browser='Firefox'; Path='HKLM:\SOFTWARE\Policies\Mozilla\Firefox' },
        @{ Browser='Firefox'; Path='HKCU:\SOFTWARE\Policies\Mozilla\Firefox' }
    )

    foreach ($target in $targets) {
        if (-not (Test-Path -LiteralPath $target.Path)) { continue }
        try {
            $props = Get-ItemProperty -LiteralPath $target.Path -ErrorAction SilentlyContinue
            $named = @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' })
            if ($named.Count -gt 0) {
                $text = ($named | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
                $severity = 'Review'
                if ($target.Browser -eq 'Firefox' -and $target.Path -match '(?i)\\Mozilla\\Firefox\\Certificates$') {
                    $severity = 'Info'
                }
                $results.Add([PSCustomObject]@{ Browser=$target.Browser; Path=$target.Path; Values=$text; Severity=$severity }) | Out-Null
            }

            foreach ($sub in @(Get-ChildItem -LiteralPath $target.Path -Recurse -ErrorAction SilentlyContinue)) {
                $subProps = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
                $values = @($subProps.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' })
                if ($values.Count -eq 0) { continue }
                $text = ($values | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '

                $severity = 'Review'
                if ($target.Browser -eq 'Firefox' -and $sub.Name -match '(?i)\\Mozilla\\Firefox\\Certificates(?:\\|$)') {
                    $severity = 'Info'
                }

                $results.Add([PSCustomObject]@{ Browser=$target.Browser; Path=$sub.Name; Values=$text; Severity=$severity }) | Out-Null
            }
        } catch { }
    }

    return @($results.ToArray() | Sort-Object Browser, Path -Unique)
}

function Get-HostsEntries {
    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $entries = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($line in @(Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {
            $trim = $line.Trim()
            if (-not $trim -or $trim.StartsWith('#')) { continue }
            if ($trim -match '^\s*(127\.0\.0\.1|::1)\s+localhost\s*$') { continue }
            $entries.Add($trim) | Out-Null
        }
    } catch { }
    return $entries.ToArray()
}

function Get-ExternalEstablishedConnections {
    $results = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($conn in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
            $remote = [string]$conn.RemoteAddress
            if ($remote -in @('127.0.0.1','::1','0.0.0.0','::')) { continue }
            $procName = ''
            $procPath = ''
            try {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
                $procName = $proc.ProcessName
                try { $procPath = $proc.Path } catch { }
            } catch { }

            $severity = 'Info'
            $product = ''
            $remoteHit = Find-WatchlistExecutable -Executable $procPath -ProductName $procName -Watchlist $script:RemoteAccessWatchlist
            $pupHit = Find-WatchlistExecutable -Executable $procPath -ProductName $procName -Watchlist $script:PupPuaWatchlist
            if ($remoteHit -or $pupHit) {
                $severity = 'Warning'
                $product = if ($remoteHit) { $remoteHit.Name } else { $pupHit.Name }
            } elseif (Test-UserWritableOrUnusualPath $procPath) {
                $sig = Get-SignatureInfo $procPath
                if (-not $sig.Exists -or $sig.Status -ne 'Valid') { $severity = 'Review' }
            }

            $results.Add([PSCustomObject]@{
                Process     = $procName
                PID         = [int]$conn.OwningProcess
                Local       = "$($conn.LocalAddress):$($conn.LocalPort)"
                Remote      = "$($conn.RemoteAddress):$($conn.RemotePort)"
                ProcessPath = $procPath
                Severity    = $severity
                Product     = $product
            }) | Out-Null
        }
    } catch { }
    return $results.ToArray()
}

function Get-AutorunsData {
    param([switch]$SkipDownload)

    $result = [PSCustomObject]@{
        Available = $false
        Downloaded = $false
        Message = ''
        Entries = @()
    }

    try {
        New-Item -ItemType Directory -Path $autorunsRoot -Force | Out-Null

        $exeName = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
            'Autorunsc64a.exe'
        } elseif ([Environment]::Is64BitOperatingSystem) {
            'Autorunsc64.exe'
        } else {
            'Autorunsc.exe'
        }

        $autorunExe = $null
        $candidateNames = @($exeName, 'Autorunsc64.exe', 'Autorunsc.exe') | Select-Object -Unique

        foreach ($candidate in $candidateNames) {
            $cmd = Get-Command $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cmd -and $cmd.Source) {
                $autorunExe = $cmd.Source
                break
            }
        }

        if (-not $autorunExe -and -not $SkipDownload) {
            try {
                # Windows PowerShell 5.1 may encounter transient TLS/proxy
                # disconnects with Invoke-WebRequest. Retry, then use the native
                # BITS transfer service as a separate transport when available.
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                $sourceUrl = 'https://download.sysinternals.com/files/Autoruns.zip'
                $downloaded = $false
                $downloadErrors = New-Object System.Collections.Generic.List[string]
                for ($attempt = 1; $attempt -le 2; $attempt++) {
                    try {
                        Remove-Item -LiteralPath $autorunsZip -Force -ErrorAction SilentlyContinue
                        Invoke-WebRequest -Uri $sourceUrl -OutFile $autorunsZip -UseBasicParsing -ErrorAction Stop
                        if (-not (Test-Path -LiteralPath $autorunsZip -PathType Leaf) -or
                            (Get-Item -LiteralPath $autorunsZip).Length -lt 1024) {
                            throw 'Downloaded file is empty or incomplete.'
                        }
                        $downloaded = $true
                        break
                    } catch {
                        $downloadErrors.Add("HTTPS attempt ${attempt}: $($_.Exception.Message)") | Out-Null
                    }
                }
                if (-not $downloaded -and (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue)) {
                    try {
                        Remove-Item -LiteralPath $autorunsZip -Force -ErrorAction SilentlyContinue
                        Start-BitsTransfer -Source $sourceUrl -Destination $autorunsZip -ErrorAction Stop
                        if (-not (Test-Path -LiteralPath $autorunsZip -PathType Leaf) -or
                            (Get-Item -LiteralPath $autorunsZip).Length -lt 1024) {
                            throw 'BITS returned an empty or incomplete file.'
                        }
                        $downloaded = $true
                    } catch {
                        $downloadErrors.Add("BITS: $($_.Exception.Message)") | Out-Null
                    }
                }
                if (-not $downloaded) {
                    throw ('Autoruns.zip could not be downloaded. ' + ($downloadErrors -join ' | '))
                }
                Expand-Archive -LiteralPath $autorunsZip -DestinationPath $autorunsRoot -Force -ErrorAction Stop
                $autorunExe = Join-Path $autorunsRoot $exeName
                if (-not (Test-Path -LiteralPath $autorunExe -PathType Leaf)) {
                    foreach ($candidate in $candidateNames) {
                        $fallback = Join-Path $autorunsRoot $candidate
                        if (Test-Path -LiteralPath $fallback -PathType Leaf) {
                            $autorunExe = $fallback
                            break
                        }
                    }
                }
                $result.Downloaded = $true
            } catch {
                $result.Message = "Autorunsc download failed: $($_.Exception.Message)"
            }
        }

        if (-not $autorunExe -or -not (Test-Path -LiteralPath $autorunExe -PathType Leaf)) {
            if (-not $result.Message) {
                $result.Message = if ($SkipDownload) { 'Autorunsc was not found and download was skipped.' } else { 'Autorunsc was not found.' }
            }
            return $result
        }

        $sig = Get-AuthenticodeSignature -LiteralPath $autorunExe -ErrorAction Stop
        $signerSubject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' }
        if ($sig.Status -ne 'Valid' -or $signerSubject -notmatch 'Microsoft') {
            $result.Message = "Autorunsc was not executed because its Microsoft signature could not be verified. Signature: $($sig.Status); Signer: $signerSubject"
            return $result
        }

        $autorunsStdOut = Join-Path $tempRoot 'Autoruns.stdout.txt'
        $autorunsStdErr = Join-Path $tempRoot 'Autoruns.stderr.txt'
        Remove-Item -LiteralPath $autorunsStdOut, $autorunsStdErr -Force -ErrorAction SilentlyContinue

        $autorunsProcess = Start-Process -FilePath $autorunExe `
            -ArgumentList @('-accepteula','-a','*','-c','-s','-m') `
            -RedirectStandardOutput $autorunsStdOut `
            -RedirectStandardError $autorunsStdErr `
            -WindowStyle Hidden -Wait -PassThru

        $outputLines = @()
        if (Test-Path -LiteralPath $autorunsStdOut -PathType Leaf) {
            $outputLines = @(Get-Content -LiteralPath $autorunsStdOut -ErrorAction SilentlyContinue | ForEach-Object { [string]$_ })
        }
        $errorLines = @()
        if (Test-Path -LiteralPath $autorunsStdErr -PathType Leaf) {
            $errorLines = @(Get-Content -LiteralPath $autorunsStdErr -ErrorAction SilentlyContinue | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        if ($outputLines.Count -eq 0) {
            $diagnostic = if ($errorLines.Count -gt 0) { ($errorLines -join ' | ') } else { "Exit code $($autorunsProcess.ExitCode)" }
            $result.Message = "Autorunsc returned no parseable output. $diagnostic"
            return $result
        }
        $headerIndex = -1
        for ($i = 0; $i -lt $outputLines.Count; $i++) {
            if ($outputLines[$i] -match '(?i)Entry Location' -and $outputLines[$i] -match '(?i)Entry') {
                $headerIndex = $i
                break
            }
        }
        if ($headerIndex -lt 0) {
            $result.Message = 'Autorunsc output was returned, but its CSV header could not be recognized.'
            return $result
        }
        if ($headerIndex -gt 0) {
            $outputLines = @($outputLines[$headerIndex..($outputLines.Count - 1)])
        }
        $outputLines | Set-Content -LiteralPath $autorunsCsv -Encoding UTF8
        $rows = @($outputLines | ConvertFrom-Csv)
        $parsed = New-Object System.Collections.Generic.List[object]

        $seenRows = @{}
        foreach ($row in $rows) {
            $entry = [string](Get-PropertyValue -Object $row -Names @('Entry','Entry Name'))
            $location = [string](Get-PropertyValue -Object $row -Names @('Entry Location','Location'))
            $category = [string](Get-PropertyValue -Object $row -Names @('Category'))
            $profile = [string](Get-PropertyValue -Object $row -Names @('Profile'))
            $description = [string](Get-PropertyValue -Object $row -Names @('Description'))
            $signer = [string](Get-PropertyValue -Object $row -Names @('Signer'))
            $company = [string](Get-PropertyValue -Object $row -Names @('Company'))
            $image = [string](Get-PropertyValue -Object $row -Names @('Image Path','Image'))
            $launch = [string](Get-PropertyValue -Object $row -Names @('Launch String','Launch'))
            $enabled = [string](Get-PropertyValue -Object $row -Names @('Enabled'))
            $sha256 = [string](Get-PropertyValue -Object $row -Names @('SHA-256','SHA256'))

            # Suppress empty structural rows (commonly seen in Winsock categories).
            if ([string]::IsNullOrWhiteSpace($entry) -and [string]::IsNullOrWhiteSpace($image) -and [string]::IsNullOrWhiteSpace($launch) -and [string]::IsNullOrWhiteSpace($description)) { continue }

            $normalizedLocation = ($location -replace '(?i)\\Wow6432Node', '')
            $rowKey = ("{0}|{1}|{2}|{3}|{4}" -f $category,$entry,$normalizedLocation,$image,$launch).ToLowerInvariant()
            if ($seenRows.ContainsKey($rowKey)) { continue }
            $seenRows[$rowKey] = $true

            $combined = "$entry $description $image $launch $signer $company"
            $severity = 'Info'
            $reason = ''
            $remoteHit = Find-WatchlistExecutable -Executable $image -ProductName $entry -Watchlist $script:RemoteAccessWatchlist
            $pupHit = Find-WatchlistExecutable -Executable $image -ProductName $entry -Watchlist $script:PupPuaWatchlist

            if ($remoteHit -or $pupHit) {
                $severity = 'Warning'
                $reason = if ($remoteHit) { "Remote-access watchlist: $($remoteHit.Name)" } else { "PUP/PUA watchlist: $($pupHit.Name)" }
            } elseif ((Test-SuspiciousCommandLine $launch) -or (Get-ExecutionChainRisk $launch)) {
                $severity = 'Warning'
                $chainReason = Get-ExecutionChainRisk $launch
                $reason = if ($chainReason) { $chainReason } else { 'Strongly suspicious launch command' }
            } else {
                $reportedMissing = $combined -match '(?i)file not found'
                $knownDllNoise = ($category -match '(?i)Known DLLs') -or ($location -match '(?i)KnownDlls')
                $candidatePath = Get-ExecutablePathFromCommand $image
                if (-not $candidatePath) { $candidatePath = Get-ExecutablePathFromCommand $launch }
                $sigInfo = if ($candidatePath) { Get-SignatureInfo $candidatePath } else { $null }

                $isWindowsAppAlias = ($candidatePath -and ($candidatePath -match '(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\')) -or
                                     ($combined -match '(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\') -or
                                     (($entry -match '(?i)^(?:Microsoft\s+)?Teams$') -and ($combined -match '(?i)MSTeams_8wekyb3d8bbwe'))
                $isKnownOneDriveTask = ($category -match '(?i)Scheduled Tasks') -and
                                       ($entry -match '(?i)^\\?OneDrive\s+(?:Reporting|Startup)\s+Task-') -and
                                       ($combined -match '(?i)\\Microsoft\\OneDrive\\(?:[^\\]+\\)*(?:OneDriveStandaloneUpdater|OneDriveLauncher)\.exe')
                $isKnownMaintenanceTask = ($category -match '(?i)Scheduled Tasks') -and
                                          (Test-KnownMaintenanceChkdskTask -TaskName $entry -Command $combined)
                $isWindowsComponent = (($category -match '(?i)Scheduled Tasks') -and ($entry -match '^\\Microsoft\\Windows\\') -and ($candidatePath -match '(?i)^C:\\Windows\\')) -or
                                      (($location -match '(?i)Font Drivers') -and ($launch -match '(?i)^atmfd\.dll$'))
                $cleanLaunch = ($launch -replace '[\x00-\x1F]', '').Trim()
                $malformedMissingRow = $reportedMissing -and ($image -match '(?i)file not found:\s*\.exe\s*$') -and [string]::IsNullOrWhiteSpace($cleanLaunch)
                $knownStaleWebex = $reportedMissing -and
                                   (Test-KnownStaleWebexStartup -Name $entry -Path $candidatePath -Command $launch -ExtraText "$image $location")

                if ($malformedMissingRow) {
                    $severity = 'Info'
                    $reason = 'Malformed/empty Autoruns structural row suppressed from attention'
                } elseif ($isKnownMaintenanceTask) {
                    $severity = 'Info'
                    $reason = 'Known Maintenance CHKDSK Injection task retained as inventory'
                } elseif ($isKnownOneDriveTask) {
                    $severity = 'Info'
                    $reason = 'Known Microsoft OneDrive scheduled updater task retained as inventory'
                } elseif ($isWindowsAppAlias) {
                    $severity = 'Info'
                    $reason = 'WindowsApps/MSIX app-execution alias retained as inventory'
                } elseif ($knownStaleWebex) {
                    $severity = 'Info'
                    $reason = 'Known stale Cisco Webex startup shortcut/legacy meeting launcher retained as inventory'
                } elseif ($reportedMissing -and -not $knownDllNoise -and -not $isWindowsComponent) {
                    if ($candidatePath -and (Test-UserWritableOrUnusualPath $candidatePath)) {
                        $severity = 'Review'
                        $reason = 'Autoruns reports a missing target in a user-writable/unusual location'
                    } else {
                        $severity = 'Info'
                        $reason = 'Stale/missing target in a normal vendor/system location'
                    }
                } elseif ($candidatePath -and (Test-UserWritableOrUnusualPath $candidatePath)) {
                    if (-not $sigInfo.Exists -or $sigInfo.Status -ne 'Valid') {
                        $severity = 'Review'
                        $reason = "User-writable/unusual path; signature $($sigInfo.Status)"
                    }
                }
                # "Not verified" alone is not sufficient to flag files in normal Program Files locations.
            }

            $parsed.Add([PSCustomObject]@{
                Entry       = $entry
                Location    = $location
                Category    = $category
                Profile     = $profile
                Description = $description
                Signer      = $signer
                Company     = $company
                ImagePath   = $image
                Launch      = $launch
                Enabled     = $enabled
                SHA256      = $sha256
                Severity    = $severity
                Reason      = $reason
                Product     = if ($remoteHit) { $remoteHit.Name } elseif ($pupHit) { $pupHit.Name } else { '' }
                LinkPath    = $candidatePath
            }) | Out-Null
        }

        $result.Available = $true
        $result.Entries = $parsed.ToArray()
        $result.Message = "Autorunsc inspected all autostart categories for the current user and system-wide locations while hiding Microsoft entries. $($parsed.Count) third-party/non-Microsoft entries were returned."
        $unexpectedDiagnostics = @($errorLines | Where-Object { $_ -notmatch '(?i)^Error expanding profile path for NT AUTHORITY\\(?:LOCAL SERVICE|NETWORK SERVICE|SYSTEM)' })
        if ($unexpectedDiagnostics.Count -gt 0) {
            $result.Message += " Autorunsc diagnostic: " + (($unexpectedDiagnostics | Select-Object -First 3) -join ' | ')
        }
        return $result
    } catch {
        $result.Message = "Autorunsc inspection failed: $($_.Exception.Message)"
        return $result
    }
}

function Get-CanonicalAntivirusName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $clean = $Name.Trim()
    if ($clean -match '^(?i:(?:Windows Defender|Microsoft Defender)(?: Antivirus)?)$') {
        return 'Microsoft Defender Antivirus'
    }
    return $clean
}

function Get-WscAntivirusProductStates {
    # IWSCProductList is a supported Windows Security Center interface. Unlike
    # an undocumented interpretation of SecurityCenter2 productState, it has
    # explicit On/Off/Snoozed/Expired states and signature freshness values.
    try {
        if (-not ('ThreatInspectionAvStateV141.Reader' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ThreatInspectionAvStateV141 {
    public sealed class Product {
        public string Name { get; set; }
        public int State { get; set; }
        public int SignatureStatus { get; set; }
    }

    public static class Reader {
        [DllImport("ole32.dll", ExactSpelling=true)]
        private static extern int CoCreateInstance(ref Guid clsid, IntPtr outer, uint context, ref Guid iid, out IntPtr result);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int InitializeDelegate(IntPtr self, uint provider);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int GetCountDelegate(IntPtr self, out int count);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int GetItemDelegate(IntPtr self, uint index, out IntPtr product);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int GetStringDelegate(IntPtr self, out IntPtr value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int GetIntDelegate(IntPtr self, out int value);

        private static T Method<T>(IntPtr instance, int slot) where T : class {
            IntPtr table = Marshal.ReadIntPtr(instance);
            IntPtr method = Marshal.ReadIntPtr(table, slot * IntPtr.Size);
            return Marshal.GetDelegateForFunctionPointer(method, typeof(T)) as T;
        }
        private static void Check(int result) {
            if (result < 0) Marshal.ThrowExceptionForHR(result);
        }
        public static Product[] Read() {
            var records = new List<Product>();
            var classId = new Guid("17072F7B-9ABE-4A74-A261-1EB76B55107A");
            var interfaceId = new Guid("722A338C-6E8E-4E72-AC27-1417FB0C81C2");
            IntPtr list = IntPtr.Zero;
            Check(CoCreateInstance(ref classId, IntPtr.Zero, 1, ref interfaceId, out list));
            try {
                // IDispatch (7 vtable methods) precedes IWSCProductList methods.
                Check(Method<InitializeDelegate>(list, 7)(list, 4)); // Antivirus
                int count;
                Check(Method<GetCountDelegate>(list, 8)(list, out count));
                if (count < 0 || count > 100) throw new InvalidOperationException("Unexpected antivirus product count");
                for (uint i = 0; i < (uint)count; i++) {
                    IntPtr item = IntPtr.Zero;
                    try {
                        if (Method<GetItemDelegate>(list, 9)(list, i, out item) < 0 || item == IntPtr.Zero) continue;
                        IntPtr bstr = IntPtr.Zero;
                        string name;
                        try {
                            if (Method<GetStringDelegate>(item, 7)(item, out bstr) < 0) continue;
                            name = bstr == IntPtr.Zero ? "" : Marshal.PtrToStringBSTR(bstr);
                        } finally {
                            if (bstr != IntPtr.Zero) Marshal.FreeBSTR(bstr);
                        }
                        if (String.IsNullOrWhiteSpace(name)) continue;
                        int state, signature;
                        if (Method<GetIntDelegate>(item, 8)(item, out state) < 0) continue;
                        if (Method<GetIntDelegate>(item, 9)(item, out signature) < 0) signature = -1;
                        records.Add(new Product { Name = name, State = state, SignatureStatus = signature });
                    } finally {
                        if (item != IntPtr.Zero) Marshal.Release(item);
                    }
                }
            } finally {
                if (list != IntPtr.Zero) Marshal.Release(list);
            }
            return records.ToArray();
        }
    }
}
'@ -ErrorAction Stop
        }

        $results = New-Object System.Collections.Generic.List[object]
        foreach ($product in @([ThreatInspectionAvStateV141.Reader]::Read())) {
            $state = switch ([int]$product.State) {
                0 { 'Active' }
                1 { 'Off' }
                2 { 'Snoozed' }
                3 { 'Expired' }
                default { 'Unknown' }
            }
            $signatures = switch ([int]$product.SignatureStatus) {
                1 { 'Current' }
                0 { 'Outdated' }
                default { 'Unknown' }
            }
            $results.Add([PSCustomObject]@{
                Name = [string]$product.Name
                State = $state
                Signatures = $signatures
                Source = 'Windows Security Center'
            }) | Out-Null
        }
        return @($results.ToArray())
    } catch {
        # Never call AV active or expired solely from a retained WMI
        # registration if the supported state API was not available.
        return @()
    }
}

function Find-WscAntivirusProductState {
    param(
        [AllowNull()][string]$Name,
        [AllowEmptyCollection()][object[]]$States = @()
    )
    if (-not $Name) { return $null }

    $canonical = Get-CanonicalAntivirusName -Name $Name
    if ($canonical -eq 'Microsoft Defender Antivirus') {
        $defenderEntries = @($States | Where-Object {
            (Get-CanonicalAntivirusName -Name ([string]$_.Name)) -eq $canonical
        })
        if ($defenderEntries.Count -eq 0) { return $null }

        # The Security Center API can expose aliases for the same built-in AV.
        # Conflicting states should be shown as unavailable, not guessed Active.
        $distinctStates = @($defenderEntries | ForEach-Object { [string]$_.State } | Sort-Object -Unique)
        if ($distinctStates.Count -gt 1) {
            return [PSCustomObject]@{
                Name = $canonical; State = 'Unknown'; Signatures = 'Unknown'
                Source = 'Conflicting Windows Security Center provider states'
            }
        }
        # Prefer a concrete signature status over Unknown if aliases agree.
        $withSignature = @($defenderEntries | Where-Object { $_.Signatures -ne 'Unknown' } | Select-Object -First 1)
        if ($withSignature.Count -gt 0) { return $withSignature[0] }
        return $defenderEntries[0]
    }

    $exact = @($States | Where-Object { [string]$_.Name -ieq $Name } | Select-Object -First 1)
    if ($exact.Count) { return $exact[0] }
    # Allow a difference such as "Norton 360" vs "Norton 360 Antivirus",
    # but never a loose token match across unrelated vendors.
    $cleanName = (($Name -replace '[^a-zA-Z0-9]', '').ToLowerInvariant())
    foreach ($row in $States) {
        $cleanRow = (([string]$row.Name -replace '[^a-zA-Z0-9]', '').ToLowerInvariant())
        if ($cleanName.Length -ge 8 -and $cleanRow.Length -ge 8 -and
            ($cleanName.StartsWith($cleanRow) -or $cleanRow.StartsWith($cleanName))) {
            return $row
        }
    }
    return $null
}

function Test-AntivirusRegistrationPresent {
    param(
        [Parameter(Mandatory)]$Product,
        [AllowEmptyCollection()][object[]]$InstalledApps = @()
    )

    $name = [string]$Product.displayName
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }

    # Microsoft Defender is built into Windows and is validated separately by
    # Get-MpComputerStatus later in the Windows Security section.
    if ($name -match '(?i)Microsoft Defender|Windows Defender') {
        return $true
    }

    $installedText = (($InstalledApps | ForEach-Object { [string]$_.Name }) -join ' | ')

    # Match common AV vendor/product families against installed-program inventory.
    $vendorPatterns = @(
        @{ Product='(?i)Webroot'; Installed='(?i)Webroot|SecureAnywhere' },
        @{ Product='(?i)Norton|Symantec'; Installed='(?i)Norton|Symantec' },
        @{ Product='(?i)McAfee'; Installed='(?i)McAfee' },
        @{ Product='(?i)Avast'; Installed='(?i)Avast' },
        @{ Product='(?i)\bAVG\b'; Installed='(?i)\bAVG\b' },
        @{ Product='(?i)Bitdefender'; Installed='(?i)Bitdefender' },
        @{ Product='(?i)Kaspersky'; Installed='(?i)Kaspersky' },
        @{ Product='(?i)\bESET\b|NOD32'; Installed='(?i)\bESET\b|NOD32' },
        @{ Product='(?i)Malwarebytes'; Installed='(?i)Malwarebytes' },
        @{ Product='(?i)Trend Micro'; Installed='(?i)Trend Micro' },
        @{ Product='(?i)Sophos'; Installed='(?i)Sophos' },
        @{ Product='(?i)Avira'; Installed='(?i)Avira' },
        @{ Product='(?i)F-Secure'; Installed='(?i)F-Secure' },
        @{ Product='(?i)Panda'; Installed='(?i)Panda' },
        @{ Product='(?i)SentinelOne'; Installed='(?i)SentinelOne' },
        @{ Product='(?i)CrowdStrike'; Installed='(?i)CrowdStrike|Falcon Sensor' },
        @{ Product='(?i)Cylance|BlackBerry'; Installed='(?i)Cylance|BlackBerry' }
    )

    foreach ($rule in $vendorPatterns) {
        if ($name -match $rule.Product -and $installedText -match $rule.Installed) {
            return $true
        }
    }

    # Generic fallback: compare meaningful words from the Security Center display
    # name to installed application names. Avoid generic AV words that would match
    # unrelated software.
    $stopWords = @(
        'antivirus','anti-virus','security','secure','internet','endpoint',
        'protection','premium','total','suite','agent','client','service'
    )
    $tokens = @(
        [regex]::Matches($name, '[A-Za-z0-9][A-Za-z0-9._-]{2,}') |
        ForEach-Object { $_.Value } |
        Where-Object {
            $token = $_.ToLowerInvariant()
            ($stopWords -notcontains $token) -and
            ($token -notmatch '^\d+$')
        } |
        Sort-Object -Unique
    )
    foreach ($token in $tokens) {
        if ($installedText -match [regex]::Escape($token)) {
            return $true
        }
    }

    # SecurityCenter2 can retain a registration after uninstall. A provider whose
    # signed product/reporting executable still exists is treated as present even
    # if the uninstall inventory did not match its display name.
    foreach ($rawPath in @(
        [string]$Product.pathToSignedProductExe,
        [string]$Product.pathToSignedReportingExe
    )) {
        if ([string]::IsNullOrWhiteSpace($rawPath)) { continue }
        $candidate = Get-ExecutablePathFromCommand $rawPath
        if ($candidate) {
            try {
                $candidate = [Environment]::ExpandEnvironmentVariables($candidate)
                if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) {
                    return $true
                }
            } catch { }
        }
    }

    return $false
}

function Get-ExpectedRecentComponentContext {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    # A typical pip launcher is unsigned; don't call it unsafe solely for that.
    # Never exclude Python/Microsoft trees. This only changes classification
    # for an exact expected Python layout corroborated by python.exe's presence.
    if ($Path -match '(?i)^(?<base>[A-Z]:\\Users\\[^\\]+\\AppData\\Local\\Programs\\Python\\Python\d{2,3})\\Scripts\\pip(?:\d+(?:\.\d+)?)?\.exe$') {
        $pythonPath = Join-Path $matches['base'] 'python.exe'
        if (Test-Path -LiteralPath $pythonPath -PathType Leaf -ErrorAction SilentlyContinue) {
            return 'Standard pip launcher under a detected Python installation (unsigned launchers are expected)'
        }
    }
    return ''
}


function Test-KnownArtifactFindingEligible {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Leaf,
        [Parameter(Mandatory)][string]$Product,
        [switch]$IsDirectory
    )
    $p = $Path.ToLowerInvariant()
    $ext = [IO.Path]::GetExtension($Leaf).ToLowerInvariant()
    # Inspection continues through these trees. This gate only determines
    # whether their normal components are evidence of a named PUP/RMM.
    # A PUP/RMM executable installer is still assessed separately.
    $isInstaller = -not $IsDirectory -and $ext -in @('.exe','.com','.msi','.msix','.msp','.bat','.cmd','.scr')

    # DLL/JS/library source files are not proof of an installed product on a
    # filename match alone; other sections can still flag active execution.
    if (-not $IsDirectory -and -not $isInstaller -and $ext -notin @('.lnk','.ps1','.vbs','.vbe','.hta')) {
        return $false
    }

    # Windows package/servicing/driver directories contain generic names and
    # benign installer manifests. Remote-access evidence in installed-app and
    # active-process checks remains independent of this artifact gate.
    if ($p -match '(?i)\\(?:winsxs|driverstore|windowsapps)\\' -or
        $p -match '(?i)\\system32\\driverstore\\') {
        return $false
    }
    if ($Product -eq 'Microsoft Quick Assist' -and
        $p -match '(?i)\\microsoftcorporationii\.quickassist') {
        return $false
    }

    # Ignore generic folder/source-code artwork names in completely unrelated
    # applications. Genuine executables/installers are *not* suppressed merely
    # for being inside a cache, package directory, or backup folder.
    if (-not $isInstaller -and $p -match '(?i)\\(?:node_modules|artwork|graphicmods|materials|shadergraph|cef(?:sharp)?cache|gpucache|code cache|packagecache|extensions|content_scripts|dist|\.git|\.cache)\\') {
        return $false
    }

    # A standalone, generic short folder name ("Wave", "Blazer", "Clear",
    # "Conduit") counts as software evidence only in plausible installation
    # locations, never in a deeply nested game asset or development project.
    if ($IsDirectory -and $Leaf -match '(?i)^(?:wave|blazer|clear|conduit)$') {
        if ($p -notmatch '(?i)^(?:[a-z]:\\Program Files(?: \(x86\))?\\[^\\]+|[a-z]:\\ProgramData\\[^\\]+|[a-z]:\\Users\\[^\\]+\\AppData\\(?:Local|Roaming)\\[^\\]+)$') {
            return $false
        }
    }

    # .lnk files inside backup profiles are historical inventory rather than
    # proof a remote-access program is currently installed/running.
    return $true
}

function Test-ExpectedOsCoverageRestriction {
    param([AllowNull()][string]$ErrorLine)
    if ([string]::IsNullOrWhiteSpace($ErrorLine)) { return $false }
    return $ErrorLine -match '(?i)^[a-z]:\\(?:System Volume Information|Windows\\(?:CSC|System32\\(?:WebThreatDefSvc|config)|WinSxS)|ProgramData\\Microsoft\\(?:Windows|Windows Defender)|Program Files\\Windows Defender)' -or
           $ErrorLine -match '(?i)^[a-z]:\\Program Files\\Windows Defender Advanced Threat Protection\\'
}

function Get-RecentFileRisk {
    param([Parameter(Mandatory)]$File, [Parameter(Mandatory)][datetime]$Cutoff)
    if ($File.LastWriteTime -lt $Cutoff) { return $null }
    $ext = ([string]$File.Extension).ToLowerInvariant()
    if ($ext -notin @('.exe','.dll','.bat','.cmd','.ps1','.vbs','.vbe','.js','.jse','.hta','.scr')) { return $null }
    $path = [string]$File.FullName
    if (Test-IsInspectionOwnPath -Path $path) { return $null }

    $activePersistence = $false
    if ($script:StartupExecutionPaths) {
        $activePersistence = $script:StartupExecutionPaths.ContainsKey($path.ToLowerInvariant())
    }

    # WinSxS InFlight files are still enumerated. The context-aware checks
    # below never label them suspicious solely for an UnknownError signature.
    # Dangerous batch behavior or active persistence is still assessed.

    # Do not mistake Windows\Temp, installed product resources, SDK scripts,
    # Python Lib\test, or package-cache scripts for downloaded active payloads.
    $highExposure = $path -match '(?i)\\(?:Users\\[^\\]+\\AppData\\Local\\Temp|Users\\Public|Users\\[^\\]+\\Downloads|Users\\[^\\]+\\Desktop)\\'
    $userWritable = $path -match '(?i)\\Users\\[^\\]+\\AppData\\(?:Local|Roaming)\\'
    $risk = ''
    $note = ''
    $sig = $null

    if ($ext -in @('.bat','.cmd')) {
        $indicators = @(Get-BatchThreatIndicators -Path $path)
        if ($indicators.Count -eq 0 -and -not $activePersistence) { return $null }
        $risk = 'Review'
        $note = if ($indicators.Count -gt 0) { 'Batch threat indicator(s): ' + ($indicators -join '; ') } else { 'Active startup reference to an unverified batch file' }
        if ($note -match '(?i)credential|defender|firewall|shadow|download.and.execute|encoded') { $risk = 'Warning' }
    } else {
        # Avoid expensive signature inspection of routine libraries and scripts
        # in protected application/component trees when no actionable execution
        # indicator is present. Missing signatures alone aren't suspicious.
        if (-not $activePersistence -and -not $highExposure -and
            $ext -in @('.dll','.js','.ps1','.vbs','.vbe','.jse','.hta','.scr')) {
            return $null
        }
        if ($ext -eq '.exe' -and -not $highExposure -and -not $activePersistence -and -not $userWritable) {
            return $null
        }
        $sig = Get-SignatureInfo $path
        if ($sig.Status -eq 'Valid') { return $null }
        $expected = Get-ExpectedRecentComponentContext -Path $path
        if ($expected) {
            $risk = 'Info'
            $note = $expected
        } elseif ($activePersistence) {
            $risk = 'Review'
            $note = 'Unverified file is referenced by an active startup entry'
        } elseif ($ext -eq '.exe') {
            $basename = [IO.Path]::GetFileNameWithoutExtension($path)
            $randomLeaf = $basename -match '(?i)^(?=[a-z0-9]{12,}$)(?=(?:.*\d){3})(?=(?:.*[a-z]){5})[a-z0-9]+$'
            if ($highExposure -or ($userWritable -and $randomLeaf)) {
                $risk = 'Review'
                $note = if ($randomLeaf) { 'Unverified executable with randomized-looking name in a user-writable location' } else { 'Unverified executable in Downloads/Desktop/user Temp/Public' }
            }
        } elseif ($highExposure -and $ext -in @('.ps1','.vbs','.vbe','.js','.jse','.hta','.scr')) {
            $risk = 'Review'
            $note = 'Unverified active script in Downloads/Desktop/user Temp/Public'
        } elseif ($highExposure -and $ext -eq '.dll') {
            # A DLL in a temporary folder is not inherently suspicious;
            # active load/persistence evidence is evaluated separately.
            return $null
        }
    }
    if (-not $risk) { return $null }
    if (-not $sig) { $sig = Get-SignatureInfo $path }
    return [PSCustomObject]@{
        Path=$path; Modified=$File.LastWriteTime
        SizeKB=[math]::Round($File.Length/1KB,1)
        Signature=$sig.Status
        Publisher=$(if ($sig.Company) { $sig.Company } else { $sig.Signer })
        Severity=$risk; Note=$note
    }
}

function Get-CombinedFileInspection {
    param([ValidateRange(1,365)][int]$Days=30, [switch]$Deep)
    $watchMatches = New-Object System.Collections.Generic.List[object]
    $recentFiles = New-Object System.Collections.Generic.List[object]
    $roots = New-Object System.Collections.Generic.List[object]
    $seenRoots = @{}
    $seenPaths = @{}
    $seenFindings = @{}
    $filenameCache = @{}
    $cutoff = (Get-Date).AddDays(-$Days)
    $startTime = Get-Date
    $fileExtensions = @('.exe','.com','.bat','.cmd','.ps1','.vbs','.vbe','.hta','.scr','.lnk','.msi','.msix','.msp')
    $recentEvaluated = 0
    $stats = [PSCustomObject]@{
        DirectoriesVisited=0; FilesVisited=0; SkippedDirectories=0
        SkippedReparsePoints=0; DepthLimitedDirectories=0; Errors=0
        ErrorSamples=(New-Object System.Collections.Generic.List[string])
    }
    if ($Deep) {
        # Fixed disks only. Not network, removable, or optical volumes.
        foreach ($disk in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
            if ($disk.DeviceID) {
                $root = ([string]$disk.DeviceID).TrimEnd([char]92) + [char]92
                if (-not $seenRoots.ContainsKey($root.ToLowerInvariant())) {
                    $seenRoots[$root.ToLowerInvariant()] = $true
                    $roots.Add([PSCustomObject]@{Path=$root;Depth=64}) | Out-Null
                }
            }
        }
        if ($roots.Count -eq 0) {
            $stats.Errors++
            $stats.ErrorSamples.Add('No fixed-drive roots could be enumerated for Deep Scan') | Out-Null
        }
    } else {
        foreach ($profile in Get-UserProfileRoots) {
            foreach ($relative in @('Downloads','Desktop','AppData\Local','AppData\Roaming')) {
                $path = Join-Path $profile $relative
                if (Test-Path -LiteralPath $path -PathType Container) {
                    $key = $path.TrimEnd([char]92).ToLowerInvariant()
                    if (-not $seenRoots.ContainsKey($key)) {
                        $seenRoots[$key] = $true
                        $roots.Add([PSCustomObject]@{Path=$path;Depth=4}) | Out-Null
                    }
                }
            }
        }
        foreach ($base in @($env:ProgramData,$env:ProgramFiles,${env:ProgramFiles(x86)})) {
            if ($base -and (Test-Path -LiteralPath $base -PathType Container)) {
                $key = $base.TrimEnd([char]92).ToLowerInvariant()
                if (-not $seenRoots.ContainsKey($key)) {
                    $seenRoots[$key] = $true
                    $roots.Add([PSCustomObject]@{Path=$base;Depth=4}) | Out-Null
                }
            }
        }
        if ($env:SystemDrive) {
            $root = ([string]$env:SystemDrive).TrimEnd([char]92) + [char]92
            $roots.Add([PSCustomObject]@{Path=$root;Depth=0}) | Out-Null
        }
    }
    foreach ($root in $roots) {
        # Program Files is still scanned for known artifacts, but routine recent
        # signature checks stay focused on user-writable locations in Standard mode.
        $assessRecent = $Deep -or (($root.Path -ine $env:ProgramFiles) -and ($root.Path -ine ${env:ProgramFiles(x86)}))
        Get-InspectionTreeEntries -Root $root.Path -Depth $root.Depth -IncludeCaches:$Deep -Stats $stats |
            ForEach-Object {
                $item = $_
                if (Test-IsInspectionOwnPath -Path $item.FullName) { return }
                if ($item.PSIsContainer) {
                    $watchEligible = $true
                } else {
                    $watchEligible = $item.Extension.ToLowerInvariant() -in $fileExtensions
                }
                if ($watchEligible) {
                    $leaf = [string]$item.Name
                    $cacheKey = $(if ($item.PSIsContainer) {'D|'} else {'F|'}) + $leaf.ToLowerInvariant()
                    if ($filenameCache.ContainsKey($cacheKey)) {
                        $remote = $filenameCache[$cacheKey].Remote
                        $pup = $filenameCache[$cacheKey].Pup
                    } else {
                        $remote = Find-WatchlistEntry -Text $leaf -Watchlist $script:RemoteAccessWatchlist -Mode Artifact
                        $pup = Find-WatchlistEntry -Text $leaf -Watchlist $script:PupPuaWatchlist -Mode Artifact
                        # Cache primarily file names; directories often have unique IDs.
                        if (-not $item.PSIsContainer) {
                            if ($filenameCache.Count -gt 50000) { $filenameCache.Clear() }
                            $filenameCache[$cacheKey] = [PSCustomObject]@{ Remote=$remote; Pup=$pup }
                        }
                    }
                    foreach ($hit in @(
                        $(if ($remote) { [PSCustomObject]@{ Kind='Remote Access'; Product=$remote.Name; Entry=$remote } }),
                        $(if ($pup) { [PSCustomObject]@{ Kind='PUP/PUA'; Product=$pup.Name; Entry=$pup } })
                    )) {
                        if (-not $hit) { continue }
                        if (-not (Test-KnownArtifactFindingEligible -Path ([string]$item.FullName) -Leaf ([string]$item.Name) -Product ([string]$hit.Product) -IsDirectory:([bool]$item.PSIsContainer))) { continue }
                        $exclude = if ($hit.Entry.PSObject.Properties['ExcludePattern']) { [string]$hit.Entry.ExcludePattern } else { '' }
                        if ($exclude -and $item.FullName -match $exclude) { continue }
                        $hitKey = "$($hit.Kind)|$($hit.Product)|$($item.FullName)".ToLowerInvariant()
                        if ($seenFindings.ContainsKey($hitKey)) { continue }
                        $seenFindings[$hitKey] = $true
                        $watchMatches.Add([PSCustomObject]@{
                            Kind=$hit.Kind; Product=$hit.Product; Path=$item.FullName
                            ItemType=$(if ($item.PSIsContainer) {'Folder'} else {'File'})
                            Modified=$item.LastWriteTime
                        }) | Out-Null
                    }
                    if ($remote) {
                        $remoteKey = "Remote Access|$($remote.Name)|$($item.FullName)".ToLowerInvariant()
                        if ($seenFindings.ContainsKey($remoteKey)) { return }
                    }
                    if ($pup) {
                        $pupKey = "PUP/PUA|$($pup.Name)|$($item.FullName)".ToLowerInvariant()
                        if ($seenFindings.ContainsKey($pupKey)) { return }
                    } # recent review only suppressed for an actually recorded artifact
                }
                if ($item.PSIsContainer) { return }
                if (-not $assessRecent) { return }
                if ($item.LastWriteTime -lt $cutoff -or
                    $item.Extension.ToLowerInvariant() -notin @('.exe','.dll','.bat','.cmd','.ps1','.vbs','.vbe','.js','.jse','.hta','.scr')) { return }
                $pathKey = ([string]$item.FullName).ToLowerInvariant()
                if ($seenPaths.ContainsKey($pathKey)) { return }
                $seenPaths[$pathKey] = $true
                $recentEvaluated++
                $assessment = Get-RecentFileRisk -File $item -Cutoff $cutoff
                if ($assessment) { $recentFiles.Add($assessment) | Out-Null }
            }
    }
    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds,1)
    return [PSCustomObject]@{
        Artifacts=[PSCustomObject]@{Matches=$watchMatches.ToArray();Limited=$false;Roots=$roots.Count}
        Recent=[PSCustomObject]@{Files=$recentFiles.ToArray();Scanned=$recentEvaluated;Limited=$false}
        Coverage=$stats; DurationSeconds=$elapsed
        Mode=$(if ($Deep) {'Deep'} else {'Standard'})
    }
}

# ----------------------------------------------------
# System Information
# ----------------------------------------------------
$now = Get-Date
$hostname = $env:COMPUTERNAME
$userName = [Environment]::UserName
$os = $null
$cs = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }
$osName = if ($os.Caption) { [string]$os.Caption } else { 'Unknown Windows version' }
$osBuild = if ($os.BuildNumber) { [string]$os.BuildNumber } else { 'Unknown' }
$manufacturer = if ($cs.Manufacturer) { [string]$cs.Manufacturer } else { 'Unknown' }
$model = if ($cs.Model) { [string]$cs.Model } else { 'Unknown' }
$profiles = @(Get-UserProfileRoots)

$installedApps = @(Get-InstalledApplications)
$thirdPartyAppx = @(Get-ThirdPartyAppxPackages)

# Security Center antivirus inventory used by Windows Security section and summary.
# SecurityCenter2 can retain stale products after uninstall, so third-party rows
# are verified against installed applications and provider executable paths.
$avProducts = @()
try {
    $avProducts = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState, pathToSignedProductExe, pathToSignedReportingExe)
} catch { }

$verifiedAvProducts = New-Object System.Collections.Generic.List[object]
$staleAvProducts = New-Object System.Collections.Generic.List[object]

foreach ($product in $avProducts) {
    if (Test-AntivirusRegistrationPresent -Product $product -InstalledApps $installedApps) {
        $verifiedAvProducts.Add($product) | Out-Null
    } else {
        $staleAvProducts.Add($product) | Out-Null
    }
}

$avNames = @($verifiedAvProducts.ToArray() | ForEach-Object { Get-CanonicalAntivirusName -Name ([string]$_.displayName) } | Where-Object { $_ } | Sort-Object -Unique)
$staleAvNames = @($staleAvProducts.ToArray() | ForEach-Object { $_.displayName } | Where-Object { $_ } | Sort-Object -Unique)

$thirdPartyAvNames = @($avNames | Where-Object { $_ -notmatch '(?i)Microsoft Defender|Windows Defender' })
$thirdPartyAvPresent = $thirdPartyAvNames.Count -gt 0
$wscAvStates = @(Get-WscAntivirusProductStates)

$avProductStates = New-Object System.Collections.Generic.List[object]
$avCardStatuses = New-Object System.Collections.Generic.List[string]
$avCardStatusOnly = New-Object System.Collections.Generic.List[string]
$providerCandidates = New-Object System.Collections.Generic.List[string]
foreach ($name in $avNames) {
    $canonicalName = Get-CanonicalAntivirusName -Name ([string]$name)
    if ($canonicalName -and @($providerCandidates | Where-Object { $_ -ieq $canonicalName }).Count -eq 0) {
        $providerCandidates.Add($canonicalName) | Out-Null
    }
}
# The supported Windows Security Center API reports currently registered AVs.
# Use an active provider even if the uninstall inventory failed to recognize it.
foreach ($stateRow in $wscAvStates) {
    $providerName = Get-CanonicalAntivirusName -Name ([string]$stateRow.Name)
    if (-not $providerName -or $stateRow.State -ne 'Active') { continue }
    if (@($providerCandidates | Where-Object { $_ -ieq $providerName }).Count -eq 0) {
        $providerCandidates.Add($providerName) | Out-Null
    }
}
foreach ($providerName in $providerCandidates) {
    $wscEntry = Find-WscAntivirusProductState -Name $providerName -States $wscAvStates
    $state = if ($wscEntry) { [string]$wscEntry.State } else { 'Unknown' }
    $signatures = if ($wscEntry) { [string]$wscEntry.Signatures } else { 'Unknown' }
    $display = if ($state -eq 'Unknown') { 'Status unavailable' } else { $state }
    if ($signatures -eq 'Outdated') { $display += ' - signatures outdated' }
    elseif ($state -eq 'Active' -and $signatures -eq 'Current') { $display += ' - signatures current' }
    $avCardStatuses.Add(('{0}: {1}' -f $providerName,$display)) | Out-Null
    $avCardStatusOnly.Add($display) | Out-Null
    $avProductStates.Add([PSCustomObject]@{Name=$providerName;State=$state;Signatures=$signatures}) | Out-Null
}
$activeProviders = @($avProductStates.ToArray() | Where-Object State -eq 'Active' | Select-Object -ExpandProperty Name)
$avSummary = if ($activeProviders.Count -gt 0) {
    $activeProviders -join ', '
} elseif ($providerCandidates.Count -gt 0) {
    $providerCandidates -join ', '
} else {
    'No verified antivirus provider found'
}
# Defender should only be considered passive because an ACTIVE third-party AV
# exists, not merely because a third-party program is installed but expired.
$thirdPartyAvPresent = @($avProductStates.ToArray() | Where-Object {
    $_.State -eq 'Active' -and $_.Name -notmatch '(?i)Microsoft Defender|Windows Defender'
}).Count -gt 0
$avCardMeta = if ($avCardStatuses.Count -eq 1) {
    # The card already shows the sole provider as its title.
    $avCardStatusOnly[0]
} elseif ($avCardStatuses.Count -gt 1) {
    ($avCardStatuses -join ' | ')
} else { 'No verified antivirus state available' }


# ----------------------------------------------------
# Remote Access
# ----------------------------------------------------
Write-SectionHeader 'Remote Access'
$remoteAccessFindings = New-Object System.Collections.Generic.List[object]

$rdpEnabled = $false
try {
    $rdp = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
    $rdpEnabled = ([int]$rdp.fDenyTSConnections -eq 0)
    Add-Finding $remoteAccessFindings $(if ($rdpEnabled) { 'Review' } else { 'Good' }) ("Remote Desktop: {0}" -f $(if ($rdpEnabled) { 'Enabled - confirm this is expected' } else { 'Disabled' })) '' $(if ($rdpEnabled) { 'remote-desktop' } else { '' }) '' $(if ($rdpEnabled) { 'ms-settings:remotedesktop' } else { '' })
} catch {
    Add-Finding $remoteAccessFindings 'Review' 'Remote Desktop state could not be determined.' '' 'remote-desktop:unknown'
}

try {
    $ra = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -ErrorAction Stop
    $raEnabled = ([int]$ra.fAllowToGetHelp -eq 1)
    Add-Finding $remoteAccessFindings $(if ($raEnabled) { 'Info' } else { 'Good' }) ("Remote Assistance: {0}" -f $(if ($raEnabled) { 'Enabled' } else { 'Disabled' })) ''
} catch {
    Add-Finding $remoteAccessFindings 'Info' 'Remote Assistance state was not available.'
}

$remoteMatches = @(Get-RemoteToolMatches $installedApps)
$remoteRuntime = @(Get-RemoteToolRuntimeMatches)
$remoteProducts = @((@($remoteMatches | Select-Object -ExpandProperty Product) + @($remoteRuntime | Select-Object -ExpandProperty Product)) | Where-Object { $_ } | Sort-Object -Unique)
if ($remoteProducts.Count -gt 0) {
    foreach ($product in $remoteProducts) {
        $details = New-Object System.Collections.Generic.List[string]
        $remoteLinkPath = ''

        $installedForProduct = @($remoteMatches | Where-Object Product -eq $product)
        $runtimeForProduct = @($remoteRuntime | Where-Object Product -eq $product)
        $processForProduct = @($runtimeForProduct | Where-Object Type -eq 'Process')
        $serviceForProduct = @($runtimeForProduct | Where-Object Type -eq 'Service')

        # One installed-software example is enough; duplicate uninstall records add noise.
        foreach ($match in @($installedForProduct | Select-Object -First 1)) {
            $app = $match.App
            $installPath = [string]$app.InstallPath
            if ([string]::IsNullOrWhiteSpace($installPath)) {
                $runtimePath = @($runtimeForProduct | Where-Object { $_.Path } | Select-Object -First 1 -ExpandProperty Path)
                if ($runtimePath) { $installPath = [string]$runtimePath }
            }
            $pathText = if ([string]::IsNullOrWhiteSpace($installPath)) { 'Not recorded' } else { $installPath }
            if (-not $remoteLinkPath -and -not [string]::IsNullOrWhiteSpace($installPath)) { $remoteLinkPath = $installPath }
            $details.Add(("Installed: {0} {1} | Publisher: {2} | Path: {3}" -f $app.Name,$app.Version,$app.Publisher,$pathText).Trim()) | Out-Null
        }

        # RMM products such as ScreenConnect may spawn many related processes. Summarize
        # counts and show only one representative process/service instead of every instance.
        if ($processForProduct.Count -gt 0) {
            $sample = $processForProduct | Select-Object -First 1
            if (-not $remoteLinkPath -and $sample.Path) { $remoteLinkPath = [string]$sample.Path }
            $details.Add(("Processes: {0} detected | Example: {1} | Path: {2}" -f $processForProduct.Count,$sample.Name,$sample.Path)) | Out-Null
        }
        if ($serviceForProduct.Count -gt 0) {
            $sample = $serviceForProduct | Select-Object -First 1
            if (-not $remoteLinkPath -and $sample.Path) { $remoteLinkPath = [string]$sample.Path }
            $serviceDetail = Limit-DisplayText -Text ([string]$sample.Detail) -MaxLength 320 -MaxTokenLength 180
            $details.Add(("Services: {0} detected | Example: {1} | Path: {2} | {3}" -f $serviceForProduct.Count,$sample.Name,$sample.Path,$serviceDetail)) | Out-Null
        }

        Add-Finding $remoteAccessFindings 'Warning' ("Known remote-access/RMM software detected: $product") (($details -join ' || ') + ' || Presence does not prove malicious use; verify authorization.') ("remote:" + $product) '' 'ms-settings:appsfeatures'
    }
} else {
    Add-Finding $remoteAccessFindings 'Good' ("No matches were found in the built-in remote-access/RMM watchlist ({0} products/aliases)." -f $script:RemoteAccessWatchlist.Count)
}

Write-FindingsConsole $remoteAccessFindings

# ----------------------------------------------------
# Programs & Startup
# ----------------------------------------------------
Write-SectionHeader 'Programs & Startup'
$programsFindings = New-Object System.Collections.Generic.List[object]
$recentCutoff = (Get-Date).AddDays(-1 * $RecentDays)
$recentApps = @($installedApps | Where-Object { $_.InstallDate -and $_.InstallDate -ge $recentCutoff } | Sort-Object InstallDate -Descending)

$pupInstalledMatches = @(Get-PupPuaInstalledMatches $installedApps)
$pupRuntimeMatches = @(Get-PupPuaRuntimeMatches)
$pupProducts = @((@($pupInstalledMatches | Select-Object -ExpandProperty Product) + @($pupRuntimeMatches | Select-Object -ExpandProperty Product)) | Where-Object { $_ } | Sort-Object -Unique)
if ($pupProducts.Count -gt 0) {
    foreach ($product in $pupProducts) {
        $details = New-Object System.Collections.Generic.List[string]
        $pupLinkPath = ''
        foreach ($match in @($pupInstalledMatches | Where-Object Product -eq $product)) {
            $app = $match.App
            if (-not $pupLinkPath -and $app.InstallPath) { $pupLinkPath = [string]$app.InstallPath }
            $details.Add(("Installed: {0} {1} | Publisher: {2} | Path: {3}" -f $app.Name,$app.Version,$app.Publisher,$app.InstallPath).Trim()) | Out-Null
        }
        foreach ($item in @($pupRuntimeMatches | Where-Object Product -eq $product)) {
            if (-not $pupLinkPath -and $item.Path) { $pupLinkPath = [string]$item.Path }
            $details.Add(("{0}: {1} | Path: {2} | {3}" -f $item.Type,$item.Name,$item.Path,$item.Detail)) | Out-Null
        }
        Add-Finding $programsFindings 'Warning' ("PUP/PUA watchlist software detected: $product") (($details -join ' || ') + ' || Verify whether this software is wanted.') ("pup:" + $product) $pupLinkPath
    }
} else {
    Add-Finding $programsFindings 'Good' ("No installed/runtime matches were found in the built-in PUP/PUA watchlist ({0} names/aliases)." -f $script:PupPuaWatchlist.Count)
}

# Check Appx/MSIX names against both watchlists, but keep normal package inventory compact.
foreach ($pkg in $thirdPartyAppx) {
    $remotePkg = Find-WatchlistEntry -Text ([string]$pkg.Name) -Watchlist $script:RemoteAccessWatchlist -Mode Name
    $pupPkg = Find-WatchlistEntry -Text ([string]$pkg.Name) -Watchlist $script:PupPuaWatchlist -Mode Name
    if ($remotePkg) { Add-Finding $programsFindings 'Warning' ("Remote-access/RMM Appx/MSIX match: $($remotePkg.Name) - $($pkg.Name)") ("Publisher: $($pkg.Publisher) | Location: $($pkg.InstallLocation)") ("remote:" + $remotePkg.Name) ([string]$pkg.InstallLocation) }
    if ($pupPkg) { Add-Finding $programsFindings 'Warning' ("PUP/PUA Appx/MSIX match: $($pupPkg.Name) - $($pkg.Name)") ("Publisher: $($pkg.Publisher) | Location: $($pkg.InstallLocation)") ("pup:" + $pupPkg.Name) ([string]$pkg.InstallLocation) }
}

if ($recentApps.Count -gt 0) {
    Add-Finding $programsFindings 'Info' "$($recentApps.Count) installed application(s) report an install date within the last $RecentDays days."
    $recentPublisherGroups = @($recentApps | Group-Object { if ([string]::IsNullOrWhiteSpace([string]$_.Publisher)) { 'Unknown publisher' } else { [string]$_.Publisher } } | Sort-Object @{Expression='Count';Descending=$true}, Name)
    foreach ($group in $recentPublisherGroups | Select-Object -First 10) {
        $names = @($group.Group | Sort-Object @{Expression='InstallDate';Descending=$true}, Name | Select-Object -First 5 | ForEach-Object { $_.Name })
        $extra = if ($group.Count -gt $names.Count) { " | $($group.Count - $names.Count) additional" } else { '' }
        Add-Finding $programsFindings 'Info' ("Recent apps by publisher: $($group.Name) - $($group.Count)") (("Examples: " + ($names -join ' | ')) + $extra)
    }
    if ($recentPublisherGroups.Count -gt 10) { Add-Finding $programsFindings 'Info' "$($recentPublisherGroups.Count - 10) additional recent publisher group(s) were omitted from detail." }
} else {
    Add-Finding $programsFindings 'Good' "No applications with a recorded install date in the last $RecentDays days were found."
}

Add-Finding $programsFindings 'Info' "$($installedApps.Count) installed application record(s) were enumerated. Normal older applications are intentionally omitted from the detailed report to reduce noise."
if ($thirdPartyAppx.Count -gt 0) { Add-Finding $programsFindings 'Info' "$($thirdPartyAppx.Count) non-Microsoft Appx/MSIX package record(s) were enumerated; only watchlist matches are detailed." }

$startupEntries = @(Get-StartupEntries)
$script:StartupExecutionPaths = @{}
foreach ($item in $startupEntries) {
    if ($item.Path) { $script:StartupExecutionPaths[([string]$item.Path).ToLowerInvariant()] = $true }
}
if ($startupEntries.Count -gt 0) {
    Add-Finding $programsFindings 'Info' "$($startupEntries.Count) unique startup/Run/RunOnce/Startup-folder item(s) were found after deduplication."
    foreach ($entry in $startupEntries) {
        $severity = 'Info'
        $remoteHit = Find-WatchlistExecutable -Executable ([string]$entry.Path) -ProductName ([string]$entry.Name) -Watchlist $script:RemoteAccessWatchlist
        $pupHit = Find-WatchlistExecutable -Executable ([string]$entry.Path) -ProductName ([string]$entry.Name) -Watchlist $script:PupPuaWatchlist
        $concernKey = ''
        $knownStaleWebexStartup = Test-KnownStaleWebexStartup -Name ([string]$entry.Name) -Path ([string]$entry.Path) -Command ([string]$entry.Command)
        if ($remoteHit) { $severity = 'Warning'; $concernKey = 'remote:' + $remoteHit.Name }
        elseif ($pupHit) { $severity = 'Warning'; $concernKey = 'pup:' + $pupHit.Name }
        elseif (([string]$entry.Name -match '(?i)^[a-f0-9]{10,16}$') -and
                ([string]$entry.Command -match '(?i)\bconhost(?:\.exe)?\s+--headless\b') -and
                ([string]$entry.Command -match '(?i)\\AppData\\(?:Local|Roaming)\\[^\\\s"]+\\[^\\\s"]+\\node\.exe\b') -and
                ([string]$entry.Command -match '(?i)\\AppData\\(?:Local|Roaming)\\[^\\\s"]+\\[^\\\s"]+\.xml\b')) {
            $severity = 'Warning'
            $concernKey = 'startup:unusual-hidden-node:' + ([string]$entry.Name)
        }
        elseif ((Test-SuspiciousCommandLine $entry.Command) -or (Get-ExecutionChainRisk $entry.Command)) { $severity = 'Warning'; $concernKey = 'startup:suspicious:' + ([string]$entry.Name) }
        elseif ($entry.Path) {
            $sig = Get-SignatureInfo $entry.Path
            $isWindowsAppAlias = ([string]$entry.Path) -match '(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\'
            $knownBenignShortcut = (([string]$entry.Name) -match '(?i)^(?:(?:Microsoft\s+)?Teams|McAfee\s+Security\s+Scan\s+Plus)(?:\.lnk)?$') -or $knownStaleWebexStartup

            if ($knownBenignShortcut) {
                # Keep these common startup shortcuts visible as inventory. Their shortcut
                # files/aliases are not Authenticode-signed in the same way as executables.
                $severity = 'Info'
                $concernKey = ''
            } elseif (-not $sig.Exists -and -not $isWindowsAppAlias) {
                if (Test-UserWritableOrUnusualPath $entry.Path) {
                    $severity = 'Review'
                    $concernKey = 'startup:missing:' + ([string]$entry.Path).ToLowerInvariant()
                } else {
                    $severity = 'Info'
                }
            } elseif ((Test-UserWritableOrUnusualPath $entry.Path) -and $sig.Exists -and $sig.Status -ne 'Valid') {
                $severity = 'Review'
                $concernKey = 'startup:' + ([string]$entry.Path).ToLowerInvariant()
            }
        }
        $detail = "Source: $($entry.Source) | Command: $($entry.Command)"
        if ($knownStaleWebexStartup -and $severity -eq 'Info') {
            $detail += ' | Known Cisco Webex startup location with a missing legacy shortcut/launcher. Stale-entry inventory; not evidence of malware.'
        }
        if ($remoteHit) { $detail += " | Remote-access watchlist: $($remoteHit.Name)" }
        if ($pupHit) { $detail += " | PUP/PUA watchlist: $($pupHit.Name)" }
        if ($concernKey -like 'startup:unusual-hidden-node:*') {
            $detail += ' | Investigation needed: randomly named startup entry launches Node.js from AppData through conhost --headless and references an XML file. Check the actual Node executable, XML content, signer, and origin; a Microsoft-signed conhost.exe does not establish the other files are safe.'
        }
        if ($entry.Path) {
            $detail += " | $(Format-FileContext $entry.Path)"
            if (([string]$entry.Path) -match '(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\' -and -not (Test-Path -LiteralPath $entry.Path -PathType Leaf)) {
                $detail += ' | WindowsApps/MSIX app-execution alias; Test-Path may report the target as absent.'
            }
        }
        $startupLinkPath = $(if ($severity -in @('Review','Warning')) { [string]$entry.Path } else { '' })
        $startupLinkUri = $(if ($severity -in @('Review','Warning') -and [string]::IsNullOrWhiteSpace($startupLinkPath)) { 'ms-settings:startupapps' } else { '' })
        Add-Finding $programsFindings $severity ("Startup: {0}" -f $entry.Name) $detail $concernKey $startupLinkPath $startupLinkUri
    }
} else {
    Add-Finding $programsFindings 'Good' 'No startup entries were returned by the automated checks.'
}

Write-FindingsConsole $programsFindings

# ----------------------------------------------------
# Canonical native task inventory for cross-section deduplication
# ----------------------------------------------------
$taskResults = @(Get-SuspiciousScheduledTasks)
$nativeTaskFindingNames = @{}
foreach ($nativeTask in $taskResults) {
    $canonicalTaskName = ('{0}{1}' -f ([string]$nativeTask.TaskPath), ([string]$nativeTask.TaskName))
    $canonicalTaskName = ($canonicalTaskName -replace '/', '\').Trim().TrimStart([char]'\').ToLowerInvariant()
    if ($canonicalTaskName) { $nativeTaskFindingNames[$canonicalTaskName] = $true }
}

# ----------------------------------------------------
# Autoruns / Persistence
# ----------------------------------------------------
Write-SectionHeader 'Autoruns / Persistence'
$autorunsFindings = New-Object System.Collections.Generic.List[object]
$autoruns = Get-AutorunsData -SkipDownload:$SkipAutorunsDownload

if ($autoruns.Available) {
    Add-Finding $autorunsFindings 'Info' $autoruns.Message
    $allAttentionAutoruns = @($autoruns.Entries | Where-Object { $_.Severity -in @('Review','Warning') })
    $duplicateScheduledAutoruns = New-Object System.Collections.Generic.List[object]
    $attentionAutoruns = @($allAttentionAutoruns | Where-Object {
        $entry = $_
        $canonicalAutorunsTask = ([string]$entry.Entry -replace '/', '\').Trim().TrimStart([char]'\').ToLowerInvariant()
        if (([string]$entry.Category -match '(?i)Scheduled Tasks') -and
            $nativeTaskFindingNames.ContainsKey($canonicalAutorunsTask)) {
            $duplicateScheduledAutoruns.Add($entry) | Out-Null
            return $false
        }
        return $true
    })
    if ($duplicateScheduledAutoruns.Count -gt 0) {
        Add-Finding $autorunsFindings 'Info' ("{0} duplicate scheduled-task finding(s) were listed only under Scheduled Tasks / Services / Processes." -f $duplicateScheduledAutoruns.Count)
    }
    if ($attentionAutoruns.Count -gt 0) {
        Add-Finding $autorunsFindings 'Info' "$($attentionAutoruns.Count) Autoruns entr$(if ($attentionAutoruns.Count -eq 1) { 'y needs' } else { 'ies need' }) technician attention after signature/path/noise filtering."
        foreach ($entry in $attentionAutoruns | Sort-Object @{Expression={Get-SeverityRank $_.Severity};Descending=$true}, Category, Entry) {
            $detail = "Category: $($entry.Category) | Location: $($entry.Location) | Profile: $($entry.Profile) | Image: $($entry.ImagePath) | Signer: $($entry.Signer) | Launch: $($entry.Launch)"
            if ($entry.PSObject.Properties['Reason'] -and $entry.Reason) { $detail += " | Reason: $($entry.Reason)" }
            $key = if ($entry.Product) {
                $kind = if ((Find-WatchlistExecutable -Executable ([string]$entry.ImagePath) -ProductName ([string]$entry.Entry) -Watchlist $script:RemoteAccessWatchlist)) { 'remote:' } else { 'pup:' }
                $kind + $entry.Product
            } else { 'autoruns:' + (("$($entry.Category)|$($entry.Entry)|$($entry.ImagePath)|$($entry.Launch)").ToLowerInvariant()) }
            $autorunsLinkPath = [string]$entry.LinkPath
            $autorunsLinkUri = ''
            if ($entry.Category -match '(?i)Scheduled Tasks') {
                $autorunsLinkPath = ''
                $autorunsLinkUri = 'threatinspection://tool/scheduler'
            }
            Add-Finding $autorunsFindings $entry.Severity ("Autoruns: {0}" -f $(if ($entry.Entry) { $entry.Entry } else { $entry.Description })) $detail $key $autorunsLinkPath $autorunsLinkUri
        }
    } else {
        Add-Finding $autorunsFindings 'Good' 'Autorunsc returned no third-party entries that met the refined Warning/Review criteria.'
    }
    $lowRiskAutoruns = @($autoruns.Entries | Where-Object { $_.Severity -eq 'Info' }).Count
    if ($lowRiskAutoruns -gt 0) { Add-Finding $autorunsFindings 'Info' "$lowRiskAutoruns lower-risk third-party Autoruns entries were inventoried but omitted from detail." }
} else {
    Add-Finding $autorunsFindings 'Review' $autoruns.Message '' 'autoruns:unavailable'
    Add-Finding $autorunsFindings 'Info' 'Native startup, scheduled-task, service, driver, process, and WMI subscription checks continue even when Autorunsc is unavailable.'
}

$wmiPersistence = @(Get-WmiPersistenceItems)
if ($wmiPersistence.Count -gt 0) {
    Add-Finding $autorunsFindings 'Info' "$($wmiPersistence.Count) persistent WMI command/script consumer(s) were found."
    foreach ($item in $wmiPersistence) {
        Add-Finding $autorunsFindings $item.Severity ("WMI persistence: $($item.Type) - $($item.Name)") $item.Detail ("wmi:$($item.Type):$($item.Name)")
    }
} else {
    Add-Finding $autorunsFindings 'Good' 'No persistent WMI CommandLineEventConsumer or ActiveScriptEventConsumer entries were found.'
}

Write-FindingsConsole $autorunsFindings

# ----------------------------------------------------
# Scheduled Tasks / Services / Processes
# ----------------------------------------------------
Write-SectionHeader 'Scheduled Tasks / Services / Processes'
$taskProcessFindings = New-Object System.Collections.Generic.List[object]

if ($taskResults.Count -gt 0) {
    Add-Finding $taskProcessFindings 'Info' "$($taskResults.Count) scheduled task action(s) met the refined Warning/Review criteria. Validly signed updater tasks in normal per-user locations are not flagged solely for being under AppData."
    foreach ($task in $taskResults | Sort-Object @{Expression={Get-SeverityRank $_.Severity};Descending=$true}, TaskPath, TaskName) {
        $key = if ($task.RemoteHit) { 'remote:' + $task.RemoteHit } elseif ($task.PupHit) { 'pup:' + $task.PupHit } else { 'task:' + (("$($task.TaskPath)$($task.TaskName)|$($task.Command)").ToLowerInvariant()) }
        Add-Finding $taskProcessFindings $task.Severity ("Task: {0}{1}" -f $task.TaskPath, $task.TaskName) ("State: $($task.State) | Command: $($task.Command) | Reason: $($task.Reason)") $key '' 'threatinspection://tool/scheduler'
    }
} else {
    Add-Finding $taskProcessFindings 'Good' 'No scheduled-task actions met the refined suspicious-command or unsigned/untrusted unusual-path criteria.'
}

$svcDrv = @(Get-ServiceDriverFindings)
if ($svcDrv.Count -gt 0) {
    Add-Finding $taskProcessFindings 'Info' "$($svcDrv.Count) service/driver item(s) met the refined unusual-path/signature criteria. Validly signed items are not flagged solely for their path."
    foreach ($item in $svcDrv) {
        Add-Finding $taskProcessFindings $item.Severity ("$($item.Type): $($item.Name) - $($item.Display)") ("State: $($item.State) | Start: $($item.StartMode) | Path: $($item.Path) | Signature: $($item.Signature) | Reason: $($item.Reason)") ("$($item.Type.ToLowerInvariant()):$($item.Name)") ([string]$item.Path)
    }
} else {
    Add-Finding $taskProcessFindings 'Good' 'No unsigned/untrusted services or drivers in selected unusual locations were detected.'
}

$processResults = @(Get-ProcessFindings)
if ($processResults.Count -gt 0) {
    Add-Finding $taskProcessFindings 'Info' "$($processResults.Count) unique running executable(s) met the refined unsigned/untrusted unusual-path or suspicious-command criteria. Multi-process apps are aggregated by executable path."
    foreach ($proc in $processResults | Sort-Object @{Expression={Get-SeverityRank $_.Severity};Descending=$true}, Name) {
        $instanceText = if ($proc.InstanceCount -gt 1) { " | Instances: $($proc.InstanceCount) | PIDs: $($proc.PID)" } else { " | PID: $($proc.PID)" }
        Add-Finding $taskProcessFindings $proc.Severity ("Process: $($proc.Name)") ("Path: $($proc.Path) | Signature: $($proc.Signature) | Publisher: $($proc.Publisher)$instanceText | Example command: $($proc.CommandLine)") ("process:" + ([string]$proc.Path).ToLowerInvariant()) ([string]$proc.Path)
    }
} else {
    Add-Finding $taskProcessFindings 'Good' 'No running processes met the refined suspicious-command or unsigned/untrusted unusual-path criteria.'
}

Write-FindingsConsole $taskProcessFindings

# ----------------------------------------------------
# Suspicious Files
# ----------------------------------------------------
Write-SectionHeader 'Suspicious Files'
$fileFindings = New-Object System.Collections.Generic.List[object]
Add-Finding $fileFindings 'Info' ("Checking common program/user locations against {0} remote-access/RMM and {1} PUP/PUA watchlist entries." -f $script:RemoteAccessWatchlist.Count, $script:PupPuaWatchlist.Count)
$combinedFileScan = Get-CombinedFileInspection -Days $RecentDays -Deep:$DeepScan
$watchArtifacts = $combinedFileScan.Artifacts
$scanCoverage = $combinedFileScan.Coverage
Add-Finding $fileFindings 'Info' ("$($combinedFileScan.Mode) scan: $($scanCoverage.FilesVisited) file(s), $($scanCoverage.DirectoriesVisited) directories enumerated in $($combinedFileScan.DurationSeconds) second(s). Skipped directories: $($scanCoverage.SkippedDirectories); depth-limited: $($scanCoverage.DepthLimitedDirectories); reparse points: $($scanCoverage.SkippedReparsePoints); errors: $($scanCoverage.Errors).")
if ($scanCoverage.Errors -gt 0) {
    $unexpectedSamples = @($scanCoverage.ErrorSamples | Where-Object { -not (Test-ExpectedOsCoverageRestriction -ErrorLine $_) })
    $coverageSeverity = if ($unexpectedSamples.Count -gt 0) { 'Review' } else { 'Info' }
    $coverageReason = if ($coverageSeverity -eq 'Review') { 'Some access errors are outside typical protected Windows folders.' } else { 'The sampled errors are in normally protected Windows locations.' }
    Add-Finding $fileFindings $coverageSeverity ("Scan coverage incomplete: $($scanCoverage.Errors) location(s) could not be enumerated.") ($coverageReason + ' Examples: ' + ($scanCoverage.ErrorSamples -join ' | ')) 'files:coverage-incomplete'
} elseif ($scanCoverage.DepthLimitedDirectories -gt 0) {
    Add-Finding $fileFindings 'Info' ("Scan depth limit reached in $($scanCoverage.DepthLimitedDirectories) directorie(s); choose Deep Scan at the beginning of the next run for broader coverage.")
}
Add-Finding $fileFindings 'Info' ("Known-software scan traversed $($watchArtifacts.Roots) targeted root location(s) with no result count limit; coverage and cache handling follow the selected scan mode.")
if ($watchArtifacts.Matches.Count -gt 0) {
    Add-Finding $fileFindings 'Info' ("$($watchArtifacts.Matches.Count) known-software artifact match(es) found; each match is listed below. The scan has no result-count limit.")
    foreach ($artifact in @($watchArtifacts.Matches | Sort-Object Kind, Product, Path)) {
        $isRemote = $artifact.Kind -eq 'Remote Access'
        $alreadyDetected = if ($isRemote) { $remoteProducts -contains $artifact.Product } else { $pupProducts -contains $artifact.Product }
        # Active/nonhistorical remote-access artifacts remain Warning even if
        # installed. Backups/stale service-profile traces are Info without
        # installed/runtime corroboration. PUP installed/runtime matches are Info.
        $historicalArtifact = ([string]$artifact.Path) -match '(?i)^[a-z]:\\(?:Backup|Backups|Old|Archive)\\|^[a-z]:\\Windows\\(?:ServiceProfiles\\(?:LocalService|NetworkService)|System32\\config\\systemprofile)\\|\\(?:WinGet\\cache|Windows\\SendTo)\\'
        $artifactSeverity = if ($historicalArtifact -and -not $alreadyDetected) { 'Info' } elseif ($isRemote -or -not $alreadyDetected) { 'Warning' } else { 'Info' }
        $keyPrefix = if ($isRemote) { 'remote:' } else { 'pup:' }
        $artifactLinkPath = Get-ArtifactNavigationRoot -Path ([string]$artifact.Path)
        $artifactLinkUri = if ($artifactLinkPath) { Convert-FolderToThreatInspectionUri -Folder $artifactLinkPath } else { '' }
        $detail = "Type: $($artifact.ItemType) | Full path: $($artifact.Path) | Modified: $($artifact.Modified.ToString('yyyy-MM-dd HH:mm'))"
        if ($historicalArtifact -and -not $alreadyDetected) { $detail += ' | Backup/stale service-profile artifact; presence alone is not evidence that remote access is active.' }
        elseif ($alreadyDetected) { $detail += ' | Related software also detected in installed/runtime inventory.' }
        else { $detail += ' | Verify whether this software/installer is expected.' }
        Add-Finding $fileFindings $artifactSeverity ("$($artifact.Kind) artifact: $($artifact.Product) — $($artifact.Path)") $detail $(if ($artifactSeverity -eq 'Warning') { $keyPrefix + $artifact.Product + ':' + $artifact.Path } else { '' }) $artifactLinkPath $artifactLinkUri
    }
} else {
    Add-Finding $fileFindings $(if ($scanCoverage.Errors -gt 0) {'Info'} else {'Good'}) 'No remote-access/RMM or PUP/PUA artifacts were found within the locations that could be read.'
}

Add-Finding $fileFindings 'Info' "Scanning selected locations for executable/script types modified within the last $RecentDays days using the same file traversal as the watchlist scan. The inspection script and generated workspace are excluded."
$fileScan = $combinedFileScan.Recent
Add-Finding $fileFindings 'Info' "$($fileScan.Scanned) recent file(s) with checklist extensions were evaluated before noise/signature filtering."

if ($fileScan.Files.Count -gt 0) {
    # Collapse .NET single-file extraction bundles (for example installers) into one review item.
    $bundleGroups = @{}
    $individual = New-Object System.Collections.Generic.List[object]
    foreach ($file in $fileScan.Files) {
        $bundleKey = ''
        if ($file.Path -match '(?i)\\Temp\\\.net\\([^\\]+)\\') { $bundleKey = "Temp .NET bundle: $($matches[1])" }
        if ($bundleKey) {
            if (-not $bundleGroups.ContainsKey($bundleKey)) { $bundleGroups[$bundleKey] = New-Object System.Collections.Generic.List[object] }
            $bundleGroups[$bundleKey].Add($file) | Out-Null
        } else { $individual.Add($file) | Out-Null }
    }

    Add-Finding $fileFindings 'Info' "$($fileScan.Files.Count) recent candidate file(s) remained after filtering. Batch/CMD files are only included when common malware behavior is detected; related temporary bundles are grouped below."
    foreach ($bundleKey in $bundleGroups.Keys | Sort-Object) {
        $group = $bundleGroups[$bundleKey]
        $examples = @($group | Sort-Object Modified -Descending | Select-Object -First 5 | ForEach-Object { $_.Path })
        $activeTypes = @($group | Where-Object { [IO.Path]::GetExtension([string]$_.Path).ToLowerInvariant() -in @('.exe','.ps1','.bat','.cmd','.vbs','.vbe','.js','.jse','.hta','.scr') })
        $bundleSeverity = if (@($group | Where-Object Severity -eq 'Warning').Count -gt 0) {'Warning'} elseif (@($group | Where-Object Severity -eq 'Review').Count -gt 0) {'Review'} else {'Info'}
        $bundleDetail = "Examples: " + ($examples -join ' | ')
        if ($bundleSeverity -eq 'Info') { $bundleDetail += ' | DLL-only .NET single-file extraction bundle; retained as context rather than a threat concern.' }
        $bundleFirstPath = @($group | Select-Object -First 1 -ExpandProperty Path)
        $bundleLinkPath = ''
        $bundleLinkUri = ''
        if ($bundleFirstPath) {
            $bundleLinkPath = Get-ArtifactNavigationRoot -Path ([string]$bundleFirstPath[0])
            if (-not [string]::IsNullOrWhiteSpace($bundleLinkPath)) {
                $bundleLinkUri = Convert-FolderToThreatInspectionUri -Folder $bundleLinkPath
            }
        }
        Add-Finding $fileFindings $bundleSeverity "$bundleKey ($($group.Count) candidate file(s))" $bundleDetail $(if ($bundleSeverity -eq 'Review') { "file-bundle:" + $bundleKey.ToLowerInvariant() } else { '' }) $bundleLinkPath $bundleLinkUri
    }
    foreach ($file in $individual | Sort-Object Modified -Descending) {
        $fileDetail = "Modified: $($file.Modified.ToString('yyyy-MM-dd HH:mm')) | Size: $($file.SizeKB) KB | Signature: $($file.Signature) | Publisher: $($file.Publisher)"
        if ($file.PSObject.Properties['Note'] -and -not [string]::IsNullOrWhiteSpace([string]$file.Note)) {
            $fileDetail += " | $($file.Note)"
        }

        $fileLinkPath = ''
        $fileLinkUri = ''
        if ($file.Severity -in @('Review','Warning')) {
            $fileLinkPath = Get-ArtifactNavigationRoot -Path ([string]$file.Path)
            if (-not [string]::IsNullOrWhiteSpace($fileLinkPath)) {
                $fileLinkUri = Convert-FolderToThreatInspectionUri -Folder $fileLinkPath
            }
        }

        Add-Finding $fileFindings $file.Severity $file.Path $fileDetail $(if ($file.Severity -in @('Review','Warning')) { "file:" + ([string]$file.Path).ToLowerInvariant() } else { '' }) $fileLinkPath $fileLinkUri
    }
} else {
    Add-Finding $fileFindings $(if ($scanCoverage.Errors -gt 0) {'Info'} else {'Good'}) 'No recent candidate files matched the refined inspection criteria in readable locations.'
}
Add-Finding $fileFindings 'Info' ('All matching artifacts in the configured scan scope are listed. ' + $(if ($DeepScan) {'Deep Scan traverses fixed drives without normal cache exclusions, but inaccessible locations and reparse points remain unscanned.'} else {'Standard mode inspects targeted roots; choose Deep Scan at the beginning of the next run for broader fixed-drive coverage.'}))

Write-FindingsConsole $fileFindings

# ----------------------------------------------------
# Browsers
# ----------------------------------------------------
Write-SectionHeader 'Browsers'
$browserFindings = New-Object System.Collections.Generic.List[object]
$chromiumExt = @(Get-ChromiumExtensions)
$firefoxExt = @(Get-FirefoxExtensions)
$chromiumSettings = @(Get-ChromiumBrowserSettings)
$firefoxSettings = @(Get-FirefoxBrowserSettings)
$firefoxNotifications = @(Get-FirefoxNotificationPermissions)
$managedNotifications = @(Get-ManagedBrowserNotificationPermissions)
$windowsBrowserToasts = @(Get-WindowsBrowserToastNotifications)
$browserPolicies = @(Get-BrowserPolicyFindings)

$allExtensions = @($chromiumExt) + @($firefoxExt)
if ($allExtensions.Count -gt 0) {
    Add-Finding $browserFindings 'Info' "$($allExtensions.Count) active/installed browser extension record(s) were found across available user profiles."
    foreach ($ext in $allExtensions | Sort-Object Browser, User, Profile, Name) {
        $detail = "User: $($ext.User) | Profile: $($ext.Profile) | ID: $($ext.ID) | Version: $($ext.Version)"
        if ($ext.PSObject.Properties['SignedState'] -and $ext.SignedState) { $detail += " | Firefox signed state: $($ext.SignedState)" }
        if ($ext.PSObject.Properties['UpdateURL'] -and $ext.UpdateURL) { $detail += " | Update URL: $($ext.UpdateURL)" }
        $remoteExtHit = Find-WatchlistEntry -Text ([string]$ext.Name) -Watchlist $script:RemoteAccessWatchlist -Mode Name
        $pupExtHit = Find-WatchlistEntry -Text ([string]$ext.Name) -Watchlist $script:PupPuaWatchlist -Mode Name
        $extSeverity = if ($remoteExtHit -or $pupExtHit) { 'Warning' } else { 'Info' }
        $key = ''
        if ($remoteExtHit) { $detail += " | Remote-access watchlist: $($remoteExtHit.Name)"; $key = 'remote:' + $remoteExtHit.Name }
        if ($pupExtHit) { $detail += " | PUP/PUA watchlist: $($pupExtHit.Name)"; $key = 'pup:' + $pupExtHit.Name }
        Add-Finding $browserFindings $extSeverity ("$($ext.Browser) extension: $($ext.Name)") $detail $key
    }
} else {
    Add-Finding $browserFindings 'Info' 'No supported browser extension inventories were found in the available user profiles.'
}

$browserSettings = @(Merge-BrowserNotificationRecords -Settings @($chromiumSettings + $firefoxSettings + $firefoxNotifications + $managedNotifications + $windowsBrowserToasts))
$notificationSettings = @($browserSettings | Where-Object { $_.Type -in @('Notification','NotificationActivity','NotificationToast','NotificationPolicy') })
if ($browserSettings.Count -gt 0) {
    Add-Finding $browserFindings 'Info' "$($browserSettings.Count) browser setting/notification record(s) were captured."
    # Every notification and setting is included; no 100-item display cap.
    foreach ($setting in $browserSettings | Sort-Object @{Expression={if ($_.Type -like 'Notification*') {0} else {1}}}, Browser, User, Profile, Type, Name) {
        $notificationLink = ''
        if ($setting.Type -in @('Notification','NotificationActivity','NotificationToast','NotificationPolicy') -and
            $setting.Severity -in @('Review','Warning')) {
            $notificationLink = Get-BrowserNotificationSettingsUri -Browser ([string]$setting.Browser)
        }
        Add-Finding $browserFindings $setting.Severity ("$($setting.Browser) $($setting.Type.ToLowerInvariant()): $($setting.Name)") ("User: $($setting.User) | Profile: $($setting.Profile) | $($setting.Detail)") $(if ($setting.Severity -in @('Review','Warning')) { "browser-setting:$($setting.Browser):$($setting.User):$($setting.Profile):$($setting.Type):$($setting.Name)" } else { '' }) $(if ($setting.PSObject.Properties['Path']) { [string]$setting.Path } else { '' }) $notificationLink
    }
}
if ($script:BrowserNotificationCoverage.Count -gt 0) {
    foreach ($coverage in $script:BrowserNotificationCoverage) {
        $coverageStatus = if ($coverage -match '(?i)could not|error|unavailable|failed') { 'Review' } else { 'Info' }
        $coverageLink = ''
        if ($coverageStatus -eq 'Review') {
            if ($coverage -match '^(?<browser>Chrome|Edge|Brave|Vivaldi|Opera GX|Opera|Firefox)\s*(?:/|:)') {
                $coverageLink = Get-BrowserNotificationSettingsUri -Browser $matches['browser']
            } else {
                $coverageLink = 'ms-settings:notifications'
            }
        }
        Add-Finding $browserFindings $coverageStatus ("Notification scan coverage: $coverage") '' '' '' $coverageLink
    }
}
if ($notificationSettings.Count -eq 0) {
    Add-Finding $browserFindings 'Info' 'No allowed/observed website-notification origins were extracted from readable sources. This is not proof that website notifications are disabled; use the coverage results above and verify browser Settings > Notifications.'
} else {
    $warningNotifications = @($notificationSettings | Where-Object { $_.Severity -eq 'Warning' }).Count
    $reviewNotifications = @($notificationSettings | Where-Object { $_.Severity -eq 'Review' }).Count
    Add-Finding $browserFindings 'Info' "$($notificationSettings.Count) allowed/observed notification record(s) were found ($warningNotifications Warning / $reviewNotifications Review)."
}

if ($browserPolicies.Count -gt 0) {
    Add-Finding $browserFindings 'Info' "$($browserPolicies.Count) browser policy location(s) contain configured values."
    foreach ($policy in $browserPolicies) {
        $policySeverity = [string]$policy.Severity
        if ([string]::IsNullOrWhiteSpace($policySeverity)) { $policySeverity = 'Review' }

        if ($policy.Browser -eq 'Firefox' -and [string]$policy.Path -match '(?i)\\Mozilla\\Firefox\\Certificates(?:\\|$)') {
            $policySeverity = 'Info'
        }

        Add-Finding $browserFindings $policySeverity ("$($policy.Browser) policy: $($policy.Path)") $policy.Values $(if ($policySeverity -in @('Review','Warning')) { "browser-policy:$($policy.Browser):$($policy.Path)" } else { '' })
    }
} else {
    Add-Finding $browserFindings 'Good' 'No configured Chrome, Edge, Brave, or Firefox policy values were found in the checked policy locations.'
}

Add-Finding $browserFindings 'Info' 'Notification evidence is reconciled across Chromium preferences/activity, Firefox permissions, enterprise policies, and retained Windows toasts by browser and origin. A clean result is not proof that all previous notifications were captured. Per-source coverage and failures are listed above.'

Write-FindingsConsole $browserFindings

# ----------------------------------------------------
# Network
# ----------------------------------------------------
Write-SectionHeader 'Network'
$networkFindings = New-Object System.Collections.Generic.List[object]

try {
    $proxy = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($proxy -and [int]$proxy.ProxyEnable -eq 1) {
        Add-Finding $networkFindings 'Review' "User proxy is enabled: $($proxy.ProxyServer)" '' 'network:proxy'
    } else {
        Add-Finding $networkFindings 'Good' 'Current-user Internet proxy is disabled.'
    }
} catch { Add-Finding $networkFindings 'Info' 'Current-user Internet proxy state could not be read.' }

try {
    $winHttpProxy = (netsh winhttp show proxy 2>$null | Out-String).Trim()
    if ($winHttpProxy) { Add-Finding $networkFindings 'Info' 'WinHTTP proxy configuration captured.' $winHttpProxy }
} catch { }

try {
    $dnsRows = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses.Count -gt 0 })
    foreach ($row in $dnsRows) { Add-Finding $networkFindings 'Info' ("DNS: $($row.InterfaceAlias)") (($row.ServerAddresses -join ', ')) }
} catch { }

try {
    $vpn = New-Object System.Collections.Generic.List[object]
    if (Get-Command Get-VpnConnection -ErrorAction SilentlyContinue) {
        try { foreach ($v in @(Get-VpnConnection -ErrorAction SilentlyContinue)) { $vpn.Add($v) | Out-Null } } catch { }
        try { foreach ($v in @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue)) { $vpn.Add($v) | Out-Null } } catch { }
    }
    foreach ($v in @($vpn | Sort-Object Name -Unique)) { Add-Finding $networkFindings 'Info' ("VPN connection: $($v.Name)") ("Server: $($v.ServerAddress) | Tunnel: $($v.TunnelType) | Split tunneling: $($v.SplitTunneling)") }
} catch { }

try {
    $installedNameText = (($installedApps | Select-Object -ExpandProperty Name) -join ' | ')
    foreach ($adapter in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
        $adapterText = "$($adapter.Name) $($adapter.InterfaceDescription)"
        $adapterStatus = 'Info'
        $expectedVirtual = $false
        $adapterNote = ''

        if ($adapterText -match '(?i)tap-windows|openvpn') {
            # TAP-Windows/OpenVPN adapters are standard VPN virtual adapters and
            # are not suspicious merely because the parent VPN app is absent or
            # the adapter is disconnected.
            $expectedVirtual = $true
            $adapterNote = 'Standard OpenVPN/TAP virtual network adapter.'
        } elseif ($adapterText -match '(?i)nordlynx|openvpn.*nordvpn') {
            $expectedVirtual = $true
            $adapterNote = 'VPN virtual network adapter.'
        } elseif ($adapterText -match '(?i)wireguard|wintun') {
            $expectedVirtual = $installedNameText -match '(?i)WireGuard|NordVPN|Mullvad|ProtonVPN|Surfshark|Windscribe|Private Internet Access|IVPN'
        } elseif ($adapterText -match '(?i)hamachi') {
            $expectedVirtual = $installedNameText -match '(?i)Hamachi|LogMeIn'
        } elseif ($adapterText -match '(?i)zerotier') {
            $expectedVirtual = $installedNameText -match '(?i)ZeroTier'
        } elseif ($adapterText -match '(?i)tailscale') {
            $expectedVirtual = $installedNameText -match '(?i)Tailscale'
        }

        if (($adapterText -match '(?i)(hamachi|zerotier|tailscale|wireguard|wintun)') -and -not $expectedVirtual) {
            $adapterStatus = 'Review'
        }

        $adapterDetail = "Status: $($adapter.Status) | Description: $($adapter.InterfaceDescription) | MAC: $($adapter.MacAddress) | Link: $($adapter.LinkSpeed)"
        if ($adapterNote) { $adapterDetail += " | $adapterNote" }

        Add-Finding $networkFindings $adapterStatus ("Network adapter: $($adapter.Name)") $adapterDetail $(if ($adapterStatus -eq 'Review') { "network-adapter:$($adapter.Name)" } else { '' })
    }
} catch { }

$hostsEntries = @(Get-HostsEntries)
if ($hostsEntries.Count -gt 0) {
    Add-Finding $networkFindings 'Info' "$($hostsEntries.Count) custom hosts-file entr$(if ($hostsEntries.Count -eq 1) { 'y was' } else { 'ies were' }) found."
    $hostsFolderPath = Join-Path $env:SystemRoot 'System32\drivers\etc'
    $hostsFolderUri = Convert-FolderToThreatInspectionUri -Folder $hostsFolderPath
    foreach ($line in $hostsEntries) { Add-Finding $networkFindings 'Review' "Hosts: $line" 'Confirm this redirect/block is expected.' ("hosts:" + $line.ToLowerInvariant()) $hostsFolderPath $hostsFolderUri }
} else { Add-Finding $networkFindings 'Good' 'No custom hosts-file redirects were found.' }

try {
    $fwProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    foreach ($profile in $fwProfiles) {
        $status = if ($profile.Enabled) { 'Good' } else { 'Warning' }
        Add-Finding $networkFindings $status ("Windows Firewall $($profile.Name): " + $(if ($profile.Enabled) { 'Enabled' } else { 'Disabled' })) '' $(if (-not $profile.Enabled) { "firewall-profile:$($profile.Name)" } else { '' }) '' $(if (-not $profile.Enabled) { 'threatinspection://tool/firewall' } else { '' })
    }

    $attentionRules = New-Object System.Collections.Generic.List[object]
    $enabledRules = @(Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue)
    $ruleById = @{}
    foreach ($rule in $enabledRules) { if ($rule.InstanceID) { $ruleById[[string]$rule.InstanceID] = $rule } }
    $ruleSeen = @{}
    try {
        foreach ($appFilter in @($enabledRules | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)) {
            $program = [Environment]::ExpandEnvironmentVariables([string]$appFilter.Program).Trim('"')
            if (-not $program -or $program -eq 'Any' -or -not (Test-UserWritableOrUnusualPath $program)) { continue }
            $rule = $ruleById[[string]$appFilter.InstanceID]
            $sig = Get-SignatureInfo $program
            if ($sig.Exists -and $sig.Status -eq 'Valid') { continue }
            $name = if ($rule) { [string]$rule.DisplayName } else { [string]$appFilter.InstanceID }
            $direction = if ($rule) { [string]$rule.Direction } else { '' }
            $action = if ($rule) { [string]$rule.Action } else { '' }
            $key = ("$name|$direction|$action|$program").ToLowerInvariant()
            if ($ruleSeen.ContainsKey($key)) { continue }
            $ruleSeen[$key] = $true
            $attentionRules.Add([PSCustomObject]@{ Name=$name; Direction=$direction; Action=$action; Program=$program; Exists=$sig.Exists; Signature=$sig.Status }) | Out-Null
        }
    } catch { }
    if ($attentionRules.Count -gt 0) {
        $missingRules = @($attentionRules | Where-Object { -not $_.Exists })
        $untrustedRules = @($attentionRules | Where-Object { $_.Exists -and $_.Signature -ne 'Valid' })

        if ($missingRules.Count -gt 0) {
            foreach ($group in @($missingRules | Group-Object Name)) {
                $examples = @($group.Group | Select-Object -ExpandProperty Program -Unique | Select-Object -First 4)
                Add-Finding $networkFindings 'Info' ("Stale firewall rule(s): $($group.Name) - $($group.Count) missing executable target(s)") ("Examples: " + ($examples -join ' | ') + ' | Stale rules are retained as cleanup context, not a threat concern.')
            }
        }

        if ($untrustedRules.Count -gt 0) {
            Add-Finding $networkFindings 'Info' "$($untrustedRules.Count) enabled firewall rule(s) reference existing unsigned/untrusted executables in user-writable/unusual paths."
            foreach ($rule in $untrustedRules) {
                Add-Finding $networkFindings 'Review' ("Firewall rule: $($rule.Name)") ("$($rule.Direction) $($rule.Action) | Program: $($rule.Program) | Exists: $($rule.Exists) | Signature: $($rule.Signature)") ("firewall-rule:" + (("$($rule.Name)|$($rule.Program)").ToLowerInvariant())) '' 'threatinspection://tool/firewall'
            }
        }
    }
} catch { Add-Finding $networkFindings 'Info' 'Windows Firewall rules could not be fully enumerated.' }

$connections = @(Get-ExternalEstablishedConnections)
if ($connections.Count -gt 0) {
    Add-Finding $networkFindings 'Info' "$($connections.Count) established TCP connection(s) were captured at inspection time. Normal connections from validly signed applications are not individually listed."
    $attentionConnections = @($connections | Where-Object { $_.Severity -in @('Review','Warning') })
    foreach ($group in @($attentionConnections | Group-Object Severity, ProcessPath, Process, Product)) {
        $first = $group.Group | Select-Object -First 1
        $remotes = @($group.Group | Select-Object -ExpandProperty Remote -Unique | Select-Object -First 8)
        $key = if ($first.Product) {
            $remoteHit = Find-WatchlistExecutable -Executable ([string]$first.ProcessPath) -ProductName ([string]$first.Process) -Watchlist $script:RemoteAccessWatchlist
            if ($remoteHit) { 'remote:' + $first.Product } else { 'pup:' + $first.Product }
        } else { 'connection:' + ([string]$first.ProcessPath).ToLowerInvariant() }
        Add-Finding $networkFindings $first.Severity ("Connection activity: $($first.Process) ($($group.Count) established connection(s))") ("Process path: $($first.ProcessPath) | Remote examples: " + ($remotes -join ', ')) $key ([string]$first.ProcessPath)
    }
    if ($attentionConnections.Count -eq 0) { Add-Finding $networkFindings 'Good' 'No established connection was owned by a watchlist tool or an unsigned/untrusted process in an unusual path.' }
}

Write-FindingsConsole $networkFindings

# ----------------------------------------------------
# Windows Security
# ----------------------------------------------------
Write-SectionHeader 'Windows Security'
$securityFindings = New-Object System.Collections.Generic.List[object]
Add-Finding $securityFindings 'Info' "Verified antivirus provider(s): $avSummary"
foreach ($avState in @($avProductStates.ToArray())) {
    $stateSeverity = switch ([string]$avState.State) {
        'Active' { if ($avState.Signatures -eq 'Outdated') { 'Review' } else { 'Good' } }
        'Expired' { 'Warning' }
        'Off' { if ($thirdPartyAvPresent -and $avState.Name -match '(?i)Microsoft Defender|Windows Defender') { 'Info' } else { 'Review' } }
        'Snoozed' { 'Review' }
        default { 'Info' }
    }
    $detail = 'Status source: Windows Security Center product-state API'
    if ($avState.State -eq 'Unknown') { $detail = 'Status unavailable from the Windows Security Center product-state API. This does not establish that protection is active or expired.' }
    $detail += " | Signature status: $($avState.Signatures). This is not the vendor subscription expiration date."
    Add-Finding $securityFindings $stateSeverity ("Antivirus: {0} - {1}" -f $avState.Name, $(if ($avState.State -eq 'Unknown') { 'Status unavailable' } else { $avState.State })) $detail '' '' 'ms-settings:windowsdefender'
}

if ($staleAvNames.Count -gt 0) {
    Add-Finding $securityFindings 'Info' ("Ignored stale Security Center antivirus registration(s): " + ($staleAvNames -join ', ')) 'No matching installed application or live provider executable was found, so these registrations are not included in the Antivirus card.'
}

$mpStatus = $null
$mpPref = $null
try { if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { $mpStatus = Get-MpComputerStatus -ErrorAction Stop } } catch { }
try { if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) { $mpPref = Get-MpPreference -ErrorAction Stop } } catch { }

if ($mpStatus) {
    $rtEnabled = [bool]$mpStatus.RealTimeProtectionEnabled
    $avEnabled = [bool]$mpStatus.AntivirusEnabled

    $amRunningMode = ''
    if ($mpStatus.PSObject.Properties['AMRunningMode']) { $amRunningMode = [string]$mpStatus.AMRunningMode }

    $amServiceEnabled = $false
    if ($mpStatus.PSObject.Properties['AMServiceEnabled']) { $amServiceEnabled = [bool]$mpStatus.AMServiceEnabled }

    $behaviorEnabled = $false
    if ($mpStatus.PSObject.Properties['BehaviorMonitorEnabled']) { $behaviorEnabled = [bool]$mpStatus.BehaviorMonitorEnabled }

    $onAccessEnabled = $false
    if ($mpStatus.PSObject.Properties['OnAccessProtectionEnabled']) { $onAccessEnabled = [bool]$mpStatus.OnAccessProtectionEnabled }

    $ioavEnabled = $false
    if ($mpStatus.PSObject.Properties['IoavProtectionEnabled']) { $ioavEnabled = [bool]$mpStatus.IoavProtectionEnabled }

    $winDefendRunning = $false
    try {
        $winDefendService = Get-Service -Name 'WinDefend' -ErrorAction Stop
        $winDefendRunning = ($winDefendService.Status -eq 'Running')
    } catch { }

    $msMpEngRunning = $false
    try {
        $msMpEngRunning = @(
            Get-Process -Name 'MsMpEng' -ErrorAction SilentlyContinue
        ).Count -gt 0
    } catch { }

    $preferenceRealtimeDisabled = $null
    if ($mpPref -and $mpPref.PSObject.Properties['DisableRealtimeMonitoring']) {
        try { $preferenceRealtimeDisabled = [bool]$mpPref.DisableRealtimeMonitoring } catch { }
    }

    $modeLooksActive = $amRunningMode -match '(?i)^Normal$'
    $preferenceAllowsRealtime = ($null -eq $preferenceRealtimeDisabled -or -not $preferenceRealtimeDisabled)

    # The two headline booleans can occasionally disagree with the effective
    # Defender state. Require corroboration before calling Defender disabled.
    $corroboratedActive = (
        $modeLooksActive -and
        $amServiceEnabled -and
        $winDefendRunning -and
        $preferenceAllowsRealtime -and
        ($msMpEngRunning -or $behaviorEnabled -or $onAccessEnabled -or $ioavEnabled)
    )

    $defenderRegistered = @($avNames | Where-Object { $_ -match '(?i)Microsoft Defender|Windows Defender' }).Count -gt 0
    $explicitRealtimeDisable = ($preferenceRealtimeDisabled -eq $true)

    if ($thirdPartyAvPresent -and (-not $rtEnabled -or -not $avEnabled)) {
        Add-Finding $securityFindings 'Info' 'Microsoft Defender real-time antivirus is not fully active while a verified third-party antivirus provider is installed.'
    } elseif ($avEnabled -and $rtEnabled) {
        Add-Finding $securityFindings 'Good' ("Microsoft Defender antivirus/real-time protection: AV={0}, Real-time={1}" -f $avEnabled, $rtEnabled)
    } elseif ($corroboratedActive) {
        $detail = "Get-MpComputerStatus reported AV=$avEnabled, Real-time=$rtEnabled, but corroborating signals indicate Defender is active: AMRunningMode=$amRunningMode; AMServiceEnabled=$amServiceEnabled; WinDefend running=$winDefendRunning; MsMpEng running=$msMpEngRunning; DisableRealtimeMonitoring=$preferenceRealtimeDisabled."
        Add-Finding $securityFindings 'Good' 'Microsoft Defender antivirus/real-time protection: Active (status fields were inconsistent)' $detail
    } elseif ($defenderRegistered -and -not $explicitRealtimeDisable) {
        $detail = "Windows Security Center still registers Microsoft Defender, but Defender status signals disagree: AV=$avEnabled | Real-time=$rtEnabled | AMRunningMode=$amRunningMode | AMServiceEnabled=$amServiceEnabled | WinDefend running=$winDefendRunning | MsMpEng running=$msMpEngRunning | DisableRealtimeMonitoring=$preferenceRealtimeDisabled. Verify the Windows Security provider page if needed."
        Add-Finding $securityFindings 'Info' 'Microsoft Defender status is inconsistent; Windows Security still reports Defender as the installed provider.' $detail '' '' 'windowsdefender://threat/'
    } else {
        $detail = "AV=$avEnabled | Real-time=$rtEnabled | AMRunningMode=$amRunningMode | AMServiceEnabled=$amServiceEnabled | WinDefend running=$winDefendRunning | MsMpEng running=$msMpEngRunning | DisableRealtimeMonitoring=$preferenceRealtimeDisabled"
        Add-Finding $securityFindings 'Warning' 'Microsoft Defender antivirus/real-time protection appears inactive or explicitly disabled.' $detail 'defender-realtime' '' 'windowsdefender://threatsettings/'
    }

    # Tamper Protection: use Get-MpComputerStatus first, then a read-only
    # registry cross-check because the UI/provider state can occasionally lag.
    $tamperCmdlet = $null
    if ($mpStatus.PSObject.Properties['IsTamperProtected']) {
        try { $tamperCmdlet = [bool]$mpStatus.IsTamperProtected } catch { }
    }

    $tamperRegistryValue = $null
    try {
        $tp = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -ErrorAction Stop
        if ($tp.PSObject.Properties['TamperProtection']) {
            $tamperRegistryValue = [int]$tp.TamperProtection
        }
    } catch { }

    $tamperRegistryEnabled = ($tamperRegistryValue -eq 5)
    $tamperRegistryDisabled = ($tamperRegistryValue -in @(0,4))

    if ($tamperCmdlet -eq $true -or $tamperRegistryEnabled) {
        $tamperDetail = ''
        if ($tamperCmdlet -eq $false -and $tamperRegistryEnabled) {
            $tamperDetail = "Get-MpComputerStatus reported False, but the Defender Features registry state reports TamperProtection=$tamperRegistryValue (enabled)."
        }
        Add-Finding $securityFindings 'Good' 'Tamper Protection: Enabled' $tamperDetail
    } elseif ($tamperCmdlet -eq $false -and $tamperRegistryDisabled) {
        Add-Finding $securityFindings 'Review' 'Tamper Protection: Disabled' ("Get-MpComputerStatus=False | Registry TamperProtection=$tamperRegistryValue") 'defender-tamper' '' 'windowsdefender://threatsettings/'
    } elseif ($null -ne $tamperCmdlet -or $null -ne $tamperRegistryValue) {
        Add-Finding $securityFindings 'Info' 'Tamper Protection status is inconsistent or could not be fully corroborated.' ("Get-MpComputerStatus=$tamperCmdlet | Registry TamperProtection=$tamperRegistryValue") '' '' 'windowsdefender://threatsettings/'
    }

    if ($mpStatus.AntivirusSignatureLastUpdated) {
        $sigAge = (New-TimeSpan -Start $mpStatus.AntivirusSignatureLastUpdated -End (Get-Date)).TotalDays
        $sigStatus = if ($sigAge -le 3) { 'Good' } else { 'Review' }
        Add-Finding $securityFindings $sigStatus ("Defender security intelligence last updated: $($mpStatus.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm'))") '' $(if ($sigStatus -eq 'Review') { 'defender-signatures' } else { '' }) '' $(if ($sigStatus -eq 'Review') { 'windowsdefender://threat/' } else { '' })
    }
} else {
    Add-Finding $securityFindings $(if ($thirdPartyAvPresent) { 'Info' } else { 'Warning' }) 'Microsoft Defender status cmdlets were unavailable or Defender status could not be read.' '' $(if ($thirdPartyAvPresent) { '' } else { 'defender-status' }) '' $(if ($thirdPartyAvPresent) { '' } else { 'windowsdefender://threat/' })
}

if ($mpPref) {
    $maps = [int]$mpPref.MAPSReporting
    Add-Finding $securityFindings $(if ($maps -gt 0) { 'Good' } else { 'Review' }) ("Cloud-delivered protection (MAPS reporting): " + $(if ($maps -gt 0) { "Enabled (level $maps)" } else { 'Disabled' })) '' $(if ($maps -gt 0) { '' } else { 'defender-maps' }) '' $(if ($maps -gt 0) { '' } else { 'windowsdefender://threatsettings/' })

    if ($mpPref.PSObject.Properties['PUAProtection']) {
        $puaMode = [int]$mpPref.PUAProtection
        $puaText = switch ($puaMode) { 1 { 'Block' } 2 { 'Audit' } 0 { 'Disabled' } default { "Unknown ($puaMode)" } }
        $puaStatus = if ($puaMode -eq 1) { 'Good' } elseif ($puaMode -eq 2) { 'Info' } else { 'Review' }
        Add-Finding $securityFindings $puaStatus "Microsoft Defender PUA protection: $puaText" '' $(if ($puaStatus -eq 'Review') { 'defender-pua' } else { '' }) '' $(if ($puaStatus -eq 'Review') { 'windowsdefender://smartscreenpua/' } else { '' })
    }

    $exclusions = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($mpPref.ExclusionPath))      { if ($x) { $exclusions.Add([PSCustomObject]@{ Type='Path'; Value=[string]$x }) | Out-Null } }
    foreach ($x in @($mpPref.ExclusionProcess))   { if ($x) { $exclusions.Add([PSCustomObject]@{ Type='Process'; Value=[string]$x }) | Out-Null } }
    foreach ($x in @($mpPref.ExclusionExtension)) { if ($x) { $exclusions.Add([PSCustomObject]@{ Type='Extension'; Value=[string]$x }) | Out-Null } }
    foreach ($x in @($mpPref.ExclusionIpAddress)) { if ($x) { $exclusions.Add([PSCustomObject]@{ Type='IP'; Value=[string]$x }) | Out-Null } }

    if ($exclusions.Count -gt 0) {
        Add-Finding $securityFindings 'Info' "$($exclusions.Count) Microsoft Defender exclusion(s) are configured. Each exclusion is evaluated below."
        foreach ($x in $exclusions) {
            $severity = 'Review'
            $detailParts = New-Object System.Collections.Generic.List[string]
            $detailParts.Add('Confirm this exclusion is expected; excluded content may be skipped by Defender scanning.') | Out-Null

            if ($x.Type -eq 'Path') {
                $expanded = [Environment]::ExpandEnvironmentVariables($x.Value)
                $isDirectory = Test-Path -LiteralPath $expanded -PathType Container -ErrorAction SilentlyContinue
                if ($isDirectory) {
                    $detailParts.Add('Exists: True | Type: Directory') | Out-Null
                } else {
                    $sig = Get-SignatureInfo $expanded
                    if ($sig.Exists) {
                        $detailParts.Add("Exists: True | Type: File | Signature: $($sig.Status) | Publisher: $(if ($sig.Company) { $sig.Company } else { $sig.Signer }) | Modified: $($sig.LastWrite)") | Out-Null
                        $hash = Get-Sha256Safe $expanded
                        if ($hash) { $detailParts.Add("SHA-256: $hash") | Out-Null }
                        if ($sig.Status -ne 'Valid') { $severity = 'Warning' }
                    } else {
                        $detailParts.Add('Exists: False (the exclusion remains configured even though the exact file/path was not found).') | Out-Null
                    }
                }

                if ([System.IO.Path]::GetFileName($expanded) -ieq 'SppExtComObjHook.dll') {
                    $severity = 'Warning'
                    $detailParts.Add('High-priority review: SppExtComObjHook.dll is not treated as a normal Windows Defender exclusion by this inspection policy.') | Out-Null
                    $ifeoRefs = @(Get-IfeoVerifierReferences -TargetPath $expanded)
                    if ($ifeoRefs.Count -gt 0) { $detailParts.Add('IFEO reference(s): ' + ($ifeoRefs -join ' || ')) | Out-Null }
                    else { $detailParts.Add('No matching IFEO VerifierDlls/Debugger reference was found in the checked Image File Execution Options keys.') | Out-Null }
                }
            }

            Add-Finding $securityFindings $severity ("Defender exclusion: $($x.Type): $($x.Value)") ($detailParts -join ' | ') (("defender-exclusion:{0}:{1}" -f $x.Type, $x.Value).ToLowerInvariant()) '' 'windowsdefender://exclusions/'
        }
    } else {
        Add-Finding $securityFindings 'Good' 'No Microsoft Defender path/process/extension/IP exclusions were returned.'
    }

    $rawIds = @($mpPref.ThreatIDDefaultAction_Ids)
    $rawActions = @($mpPref.ThreatIDDefaultAction_Actions)
    $threatMappings = New-Object System.Collections.Generic.List[object]

    for ($i = 0; $i -lt $rawIds.Count; $i++) {
        $idText = if ($null -ne $rawIds[$i]) { ([string]$rawIds[$i]).Trim() } else { '' }
        if ([string]::IsNullOrWhiteSpace($idText)) { continue }

        $actionText = 'Unknown'
        if ($i -lt $rawActions.Count -and $null -ne $rawActions[$i]) {
            $candidateAction = ([string]$rawActions[$i]).Trim()
            if (-not [string]::IsNullOrWhiteSpace($candidateAction)) {
                $actionText = $candidateAction
            }
        }

        $threatMappings.Add([PSCustomObject]@{
            ThreatID = $idText
            Action   = $actionText
        }) | Out-Null
    }

    if ($threatMappings.Count -gt 0) {
        Add-Finding $securityFindings 'Info' "$($threatMappings.Count) custom Defender threat action mapping(s) are configured. Review individual mappings below."
        foreach ($mapping in $threatMappings) {
            Add-Finding $securityFindings 'Review' "Threat ID $($mapping.ThreatID) -> Action $($mapping.Action)" '' ("defender-threat-action:$($mapping.ThreatID)") '' 'windowsdefender://threatsettings/'
        }
    }
}

# Classify each Defender detection by its final remediation state rather than
# treating every past detection as an outstanding threat. Get-MpThreatDetection
# returns historical records as well as current detections. Status IDs follow
# MSFT_MpThreatDetection: 2=Cleaned, 3=Quarantined, 4=Removed, 6=Blocked;
# 5=Allowed and 101-107 represent failed/abandoned actions.
function Get-DefenderDetectionAssessment {
    param([Parameter(Mandatory)][object]$Detection)

    $statusId = -1
    $rawStatus = 'Unavailable'
    if ($Detection.PSObject.Properties['ThreatStatusID'] -and $null -ne $Detection.ThreatStatusID) {
        $rawStatus = ([string]$Detection.ThreatStatusID).Trim()
        $parsedStatus = 0
        if ([int]::TryParse($rawStatus, [ref]$parsedStatus)) {
            $statusId = $parsedStatus
        } else {
            $statusId = switch -Regex ($rawStatus) {
                '^Detected$' { 1 }
                '^Cleaned$' { 2 }
                '^Quarantined$' { 3 }
                '^Removed$' { 4 }
                '^Allowed$' { 5 }
                '^Blocked$' { 6 }
                default { -1 }
            }
        }
    }

    $statusText = switch ($statusId) {
        0 { 'Unknown' }
        1 { 'Detected' }
        2 { 'Cleaned' }
        3 { 'Quarantined' }
        4 { 'Removed' }
        5 { 'Allowed' }
        6 { 'Blocked' }
        101 { 'Clean failed' }
        102 { 'Quarantine failed' }
        103 { 'Removal failed' }
        104 { 'Allow failed' }
        105 { 'Abandoned' }
        107 { 'Block failed' }
        default { 'Unknown' }
    }

    $actionKnown = ($null -ne $Detection.PSObject.Properties['ActionSuccess'] -and $null -ne $Detection.ActionSuccess)
    $actionSuccess = ($actionKnown -and [bool]$Detection.ActionSuccess)
    $additionalKnown = ($null -ne $Detection.PSObject.Properties['AdditionalActionsBitMask'] -and $null -ne $Detection.AdditionalActionsBitMask)
    $additional = 0
    if ($additionalKnown) {
        try { $additional = [int]$Detection.AdditionalActionsBitMask }
        catch { $additionalKnown = $false }
    }
    $errorKnown = ($null -ne $Detection.PSObject.Properties['ThreatStatusErrorCode'] -and $null -ne $Detection.ThreatStatusErrorCode)
    $statusError = 0
    if ($errorKnown) {
        try { $statusError = [int]$Detection.ThreatStatusErrorCode }
        catch { $errorKnown = $false }
    }
    $executionKnown = ($null -ne $Detection.PSObject.Properties['CurrentThreatExecutionStatusID'] -and $null -ne $Detection.CurrentThreatExecutionStatusID)
    $executionId = -1
    if ($executionKnown) {
        try { $executionId = [int]$Detection.CurrentThreatExecutionStatusID }
        catch { $executionKnown = $false }
    }

    $severity = 'Review'
    $reason = 'Defender detection status is not sufficiently verified as resolved.'
    if ($statusId -in @(101,102,103,104,105,107)) {
        $severity = 'Warning'
        $reason = 'Defender reported a failed or abandoned remediation action.'
    } elseif ($executionId -eq 3) {
        $severity = 'Warning'
        $reason = 'Defender reports that the detected threat is executing.'
    } elseif ($errorKnown -and $statusError -ne 0) {
        $severity = 'Warning'
        $reason = 'Defender reported an error for this threat status.'
    } elseif ($statusId -eq 5) {
        $reason = 'This threat was allowed; verify whether the exception is intentional.'
    } elseif ($statusId -in @(2,3,4,6)) {
        if (-not $actionKnown -or -not $actionSuccess) {
            $reason = 'The remediation action was not confirmed successful.'
        } elseif (-not $additionalKnown) {
            $reason = 'Defender did not expose whether additional remediation is required.'
        } elseif ($additional -ne 0) {
            $reason = 'Defender requires additional remediation steps.'
        } else {
            $severity = 'Info'
            $reason = 'Historical detection; Defender reports successful handling and no additional remediation required.'
        }
    } elseif ($statusId -eq 1) {
        $reason = 'Detection is not reported as remediated.'
    } elseif ($statusId -in @(-1,0) -and $actionKnown -and $actionSuccess -and
              $additionalKnown -and $additional -eq 0 -and
              $errorKnown -and $statusError -eq 0 -and
              $executionKnown -and $executionId -in @(1,4)) {
        # Some Windows builds expose ThreatStatusID as Unknown even though
        # the cleaning action completed. Blocked (1) and NotExecuting (4)
        # are execution states, NOT remediation actions. Never call these
        # records Removed or Quarantined without a final status value.
        $severity = 'Info'
        $statusText = 'Handled (exact action unknown)'
        $reason = 'Historical detection; Defender reports a successful cleaning action, no pending steps or status errors, and a blocked/not-executing threat. Exact final remediation status was not supplied.'
    }

    $actionText = if ($actionKnown) { [string]$Detection.ActionSuccess } else { 'Unavailable' }
    $additionalText = if ($additionalKnown) { [string]$additional } else { 'Unavailable' }
    $errorText = if ($errorKnown) { [string]$statusError } else { 'Unavailable' }
    $executionText = if ($executionKnown) {
        switch ($executionId) {
            0 { 'Unknown (0)' }
            1 { 'Blocked (1)' }
            2 { 'Allowed (2)' }
            3 { 'Executing (3)' }
            4 { 'Not executing (4)' }
            default { "Unrecognized ($executionId)" }
        }
    } else { 'Unavailable' }
    return [PSCustomObject]@{
        Severity = $severity
        Status = $statusText
        RawStatus = $rawStatus
        Reason = $reason
        ActionSuccess = $actionText
        AdditionalActions = $additionalText
        StatusError = $errorText
        ExecutionStatus = $executionText
    }
}

try {
    if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
        $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending)
        if ($detections.Count -gt 0) {
            Add-Finding $securityFindings 'Info' "$($detections.Count) Defender detection history record(s) returned. All records are listed with their remediation state."
            foreach ($d in $detections) {
                $assessment = Get-DefenderDetectionAssessment -Detection $d
                $resources = @($d.Resources) -join '; '
                $detail = "Initial: $($d.InitialDetectionTime) | Status: $($assessment.Status) | Raw status ID: $($assessment.RawStatus) | Action success: $($assessment.ActionSuccess) | Additional actions: $($assessment.AdditionalActions) | Status error: $($assessment.StatusError) | Execution: $($assessment.ExecutionStatus) | $($assessment.Reason) | Resources: $resources"
                Add-Finding $securityFindings $assessment.Severity ("Defender detection: Threat ID $($d.ThreatID) - $($assessment.Status)") $detail ("defender-detection:$($d.ThreatID):$($d.InitialDetectionTime)") '' 'windowsdefender://history/'
            }
        } else {
            Add-Finding $securityFindings 'Good' 'No Defender threat-detection records were returned.'
        }
    }
} catch {
    Add-Finding $securityFindings 'Info' 'Defender protection history could not be fully enumerated.'
}

Write-FindingsConsole $securityFindings

function Merge-DuplicateReportConcerns {
    param([Parameter(Mandatory)][object[]]$Sections)
    $seen = @{}
    foreach ($section in $Sections) {
        $retained = New-Object System.Collections.Generic.List[object]
        $duplicateCount = 0
        foreach ($finding in @($section.Findings)) {
            $key = ([string]$finding.ConcernKey).Trim().ToLowerInvariant()
            if ($finding.Status -in @('Review','Warning') -and $key -and
                $key -notmatch '^(?:remote:|pup:|file:|file-bundle:|browser-setting:)' -and
                $key -notmatch '^defender-' -and $seen.ContainsKey($key)) {
                $duplicateCount++
                continue
            }
            if ($key -and $finding.Status -in @('Review','Warning')) { $seen[$key] = $true }
            $retained.Add($finding) | Out-Null
        }
        if ($duplicateCount -gt 0) {
            $retained.Add([PSCustomObject]@{
                Status='Info'
                Text=("$duplicateCount exact duplicate concern(s) are listed in an earlier section.")
                Detail='Original highest-priority findings remain visible in their primary sections.'
                ConcernKey='';LinkPath='';LinkUri=''
            }) | Out-Null
        }
        $section.Findings = $retained.ToArray()
        $section.Status = Get-SectionStatus $section.Findings
    }
    return $Sections
}

# ----------------------------------------------------
# Build Section Objects
# ----------------------------------------------------
$browserSectionStatus = Get-SectionStatus $browserFindings
if ($browserSectionStatus -notin @('Warning','Review')) { $browserSectionStatus = 'Info' }

$sections = @(
    [PSCustomObject]@{ Id='remote-access'; Title='Remote Access'; Summary='Remote Desktop, Remote Assistance, and the remote-access/RMM watchlist across installed software and runtime activity.'; Findings=$remoteAccessFindings.ToArray(); Status=(Get-SectionStatus $remoteAccessFindings) },
    [PSCustomObject]@{ Id='programs'; Title='Programs & Startup'; Summary='PUP/PUA watchlist matches, compact installed-software context, and deduplicated startup persistence.'; Findings=$programsFindings.ToArray(); Status=(Get-SectionStatus $programsFindings) },
    [PSCustomObject]@{ Id='autoruns'; Title='Autoruns / Persistence'; Summary='Sysinternals Autorunsc plus WMI persistence, with duplicates of native scheduled-task findings removed.'; Findings=$autorunsFindings.ToArray(); Status=(Get-SectionStatus $autorunsFindings) },
    [PSCustomObject]@{ Id='tasks'; Title='Scheduled Tasks / Services / Processes'; Summary='Signature-aware scheduled-task, service/driver, and aggregated process checks.'; Findings=$taskProcessFindings.ToArray(); Status=(Get-SectionStatus $taskProcessFindings) },
    [PSCustomObject]@{ Id='files'; Title='Suspicious Files'; Summary='Shared single-pass artifact and recent-file inspection, with explicit completeness/coverage indicators and optional Deep Scan.'; Findings=$fileFindings.ToArray(); Status=(Get-SectionStatus $fileFindings) },
    [PSCustomObject]@{ Id='browsers'; Title='Browsers'; Summary='Chrome/Edge/Brave/Vivaldi/Opera/Opera GX/Firefox extensions, selected settings, notification origins, and configured browser policies. Automated coverage is partial.'; Findings=$browserFindings.ToArray(); Status=$browserSectionStatus },
    [PSCustomObject]@{ Id='network'; Title='Network'; Summary='Proxy, DNS, VPN/adapters, hosts file, signature-aware firewall rules, and grouped attention-worthy connections.'; Findings=$networkFindings.ToArray(); Status=(Get-SectionStatus $networkFindings) },
    [PSCustomObject]@{ Id='security'; Title='Windows Security'; Summary='Antivirus providers, Defender protection state, PUA protection, exclusions with file inspection, and detection history.'; Findings=$securityFindings.ToArray(); Status=(Get-SectionStatus $securityFindings) }
)

$sections = @(Merge-DuplicateReportConcerns -Sections $sections)
$allFindings = @($sections | ForEach-Object { $_.Findings })
$infoCount    = @($allFindings | Where-Object Status -eq 'Info').Count
$goodCount    = @($allFindings | Where-Object Status -eq 'Good').Count
$reviewCount  = @($allFindings | Where-Object Status -eq 'Review').Count
$warningCount = @($allFindings | Where-Object Status -eq 'Warning').Count

# ----------------------------------------------------
# Build HTML
# ----------------------------------------------------
$completedAt = Get-Date
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine('<!DOCTYPE html>')
$null = $sb.AppendLine('<html lang="en">')
$null = $sb.AppendLine('<head>')
$null = $sb.AppendLine('<meta charset="utf-8" />')
$null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1" />')
$null = $sb.AppendLine('<title>Threat Inspection Report - ' + (Convert-ToHtmlSafe $hostname) + '</title>')
$null = $sb.AppendLine(@'
<style>
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #050608;
        color: #f5f7fb;
        margin: 0;
        padding: 0;
    }
    .page {
        max-width: 1100px;
        margin: 0 auto;
        padding: 24px 16px 40px 16px;
    }
    .title {
        font-size: 30px;
        font-weight: 700;
        margin-bottom: 4px;
        color: #ffffff;
    }
    .subtitle {
        font-size: 14px;
        color: #a0a4b8;
        margin-bottom: 20px;
    }
    .summary-grid {
        display: grid;
        grid-template-columns: repeat(5, minmax(0, 1fr));
        gap: 12px;
        margin-bottom: 18px;
    }
    @media (max-width: 900px) {
        .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 520px) {
        .summary-grid { grid-template-columns: 1fr; }
    }
    .card {
        background: radial-gradient(circle at top left, #17223b, #090b11);
        border-radius: 12px;
        padding: 12px 14px;
        border: 1px solid #1b2338;
        box-shadow: 0 6px 18px rgba(0,0,0,0.6);
    }
    .card-info { border-color: #244f80; }
    .card-good { border-color: #225c3c; }
    .card-review { border-color: #80621f; }
    .card-warning { border-color: #7a2b32; }
    .card-antivirus { border-color: #3f3d78; }

    .card-info .card-value { color: #7fc4ff; }
    .card-good .card-value { color: #77db9d; }
    .card-review .card-value { color: #f0c969; }
    .card-warning .card-value { color: #ff8a92; }
    .card-label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #7c829a;
        margin-bottom: 4px;
    }
    .card-value {
        font-size: 15px;
        font-weight: 600;
        color: #f5f7fb;
        overflow-wrap: anywhere;
    }
    .card-meta {
        font-size: 12px;
        color: #8f95ad;
        margin-top: 2px;
        overflow-wrap: anywhere;
    }
    .status-row {
        margin: 16px 0 22px 0;
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
    }
    .status-pill, .section-status-pill, .finding-status {
        font-size: 12px;
        padding: 4px 8px;
        border-radius: 999px;
        border: 1px solid transparent;
        background: rgba(20,25,40,0.95);
        text-decoration: none;
        display: inline-block;
        white-space: nowrap;
    }
    .status-pill:hover { filter: brightness(1.08); }
    .status-good {
        background: rgba(34,92,60,0.26);
        color: #77db9d;
        border-color: #225c3c;
    }
    .status-review {
        background: rgba(128,98,31,0.28);
        color: #f0c969;
        border-color: #80621f;
    }
    .status-warning {
        background: rgba(122,43,50,0.30);
        color: #ff8a92;
        border-color: #7a2b32;
    }
    .status-info {
        background: rgba(36,79,128,0.26);
        color: #7fc4ff;
        border-color: #244f80;
    }
    .section {
        border-radius: 12px;
        border: 1px solid #1c2336;
        margin-bottom: 10px;
        overflow: hidden;
        background: rgba(10,12,20,0.96);
        box-shadow: 0 5px 14px rgba(0,0,0,0.55);
        scroll-margin-top: 16px;
    }
    .section-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 12px;
        cursor: pointer;
        background: linear-gradient(90deg, rgba(31,45,85,0.9), rgba(16,23,42,0.9));
    }
    .section-header:hover {
        background: linear-gradient(90deg, rgba(45,65,120,0.95), rgba(18,26,48,0.9));
    }
    .section-left { display: flex; align-items: center; gap: 8px; }
    .section-icon { font-size: 13px; width: 18px; text-align: center; color: #9fa6c6; }
    .section-title { font-size: 14px; font-weight: 600; color: #f5f7ff; }
    .section-body { padding: 10px 12px 12px 12px; display: block; }
    .section-summary { font-size: 13px; color: #b4bad6; margin-top: 0; margin-bottom: 10px; }
    .findings {
        display: flex;
        flex-direction: column;
        gap: 6px;
        max-height: 540px;
        overflow: auto;
        padding-right: 2px;
    }
    .finding {
        display: grid;
        grid-template-columns: 86px 1fr;
        gap: 8px;
        align-items: start;
        background: #05070f;
        border: 1px solid #12182c;
        border-radius: 8px;
        padding: 8px;
    }
    .finding-main { min-width: 0; }
    .finding-text {
        font-family: "Cascadia Code", "Consolas", "Fira Code", monospace;
        font-size: 12px;
        color: #e6e9f3;
        white-space: pre-wrap;
        word-break: break-word;
    }
    .finding-detail {
        margin-top: 4px;
        font-family: "Cascadia Code", "Consolas", "Fira Code", monospace;
        font-size: 11px;
        color: #8f95ad;
        white-space: pre-wrap;
        word-break: break-word;
    }
    .report-tools {
        display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
        padding: 10px 0 14px 0;
    }
    .report-tools input, .report-tools select, .report-tools button {
        background: #121827; color: #f5f7fb; border: 1px solid #2f3a55;
        border-radius: 7px; padding: 9px 11px; font: inherit;
    }
    .report-tools input { flex: 1 1 210px; min-width: 170px; }
    .report-tools button { cursor: pointer; }
    .report-tools .result-count { color: #b4bad6; font-size: 12px; }
    .finding[hidden], .section[hidden] { display: none !important; }
    .legend {
        font-size: 12px;
        color: #9298af;
        margin: -8px 0 18px 0;
    }
    .footer {
        font-size: 12px;
        color: #737995;
        margin-top: 20px;
        border-top: 1px solid #181e32;
        padding-top: 10px;
        line-height: 1.5;
    }
</style>
<script>
    function filterFindings() {
        var query = (document.getElementById('finding-search').value || '').toLowerCase().trim();
        var severity = document.getElementById('severity-filter').value;
        var shown = 0, total = 0;
        document.querySelectorAll('.section').forEach(function(section) {
            var sectionShown = 0;
            section.querySelectorAll('.finding').forEach(function(finding) {
                total++;
                var status = finding.getAttribute('data-status');
                var matchesStatus = severity === 'All' || severity === status;
                var matchesQuery = !query || finding.textContent.toLowerCase().indexOf(query) !== -1;
                finding.hidden = !(matchesStatus && matchesQuery);
                if (!finding.hidden) { shown++; sectionShown++; }
            });
            section.hidden = sectionShown === 0;
            if (sectionShown && (query || severity !== 'All')) {
                var body = section.querySelector('.section-body');
                if (body) body.style.display = 'block';
            }
        });
        document.getElementById('result-count').textContent = shown + ' of ' + total + ' findings shown';
    }
    function clearFilters() {
        document.getElementById('finding-search').value = '';
        document.getElementById('severity-filter').value = 'All';
        filterFindings();
    }
    function toggleSection(id) {
        var body = document.getElementById(id);
        var icon = document.getElementById(id + "-icon");
        if (!body) return;
        if (body.style.display === "none") {
            body.style.display = "block";
            if (icon) icon.textContent = "v";
        } else {
            body.style.display = "none";
            if (icon) icon.textContent = ">";
        }
    }
</script>
'@)
$null = $sb.AppendLine('</head>')
$null = $sb.AppendLine('<body>')
$null = $sb.AppendLine('<div class="page">')
$null = $sb.AppendLine('<div class="title">Malicious Threat Inspection</div>')
$null = $sb.AppendLine('<div class="subtitle">' + (Convert-ToHtmlSafe $timeStamp) + ' - Threat Inspection v2.4 - ' + $(if ($DeepScan) { 'Deep Scan' } else { 'Standard Scan' }) + ' - inspection-only (report-link helper optional)</div>')

$null = $sb.AppendLine('<div class="summary-grid">')
$null = $sb.AppendLine('<div class="card card-info"><div class="card-label">Info</div><div class="card-value">' + $infoCount + '</div><div class="card-meta">Inventory/context findings</div></div>')
$null = $sb.AppendLine('<div class="card card-good"><div class="card-label">Good</div><div class="card-value">' + $goodCount + '</div><div class="card-meta">Expected security-state findings</div></div>')
$null = $sb.AppendLine('<div class="card card-review"><div class="card-label">Review</div><div class="card-value">' + $reviewCount + '</div><div class="card-meta">Findings requiring technician review</div></div>')
$null = $sb.AppendLine('<div class="card card-warning"><div class="card-label">Warning</div><div class="card-value">' + $warningCount + '</div><div class="card-meta">Stronger-risk findings</div></div>')
$null = $sb.AppendLine('<div class="card card-antivirus"><div class="card-label">Antivirus</div><div class="card-value">' + (Convert-ToHtmlSafe $avSummary) + '</div><div class="card-meta">' + (Convert-ToHtmlSafe $avCardMeta) + '</div></div>')
$null = $sb.AppendLine('</div>')

$null = $sb.AppendLine('<div class="report-tools"><input id="finding-search" type="search" aria-label="Search findings" placeholder="Search findings, paths, products..." oninput="filterFindings()"/><select id="severity-filter" aria-label="Filter by severity" onchange="filterFindings()"><option>All</option><option>Warning</option><option>Review</option><option>Info</option><option>Good</option></select><button type="button" onclick="clearFilters()">Clear</button><span id="result-count" class="result-count"></span></div>')
$null = $sb.AppendLine('<div class="legend">Info = inventory/context &nbsp; | &nbsp; Good = expected security state &nbsp; | &nbsp; Review = verify legitimacy &nbsp; | &nbsp; Warning = stronger risk indicator</div>')

$null = $sb.AppendLine('<div class="status-row">')
foreach ($sec in $sections) {
    $cls = 'status-' + $sec.Status.ToLowerInvariant()
    $label = "$($sec.Title) - $($sec.Status)"
    $null = $sb.AppendLine('<a class="status-pill ' + $cls + '" href="#section-' + $sec.Id + '">' + (Convert-ToHtmlSafe $label) + '</a>')
}
$null = $sb.AppendLine('</div>')

$index = 0
foreach ($sec in $sections) {
    $index++
    $bodyId = "sec$index"
    $iconId = "$bodyId-icon"
    $cls = 'status-' + $sec.Status.ToLowerInvariant()

    $null = $sb.AppendLine('<div id="section-' + $sec.Id + '" class="section">')
    $null = $sb.AppendLine('<div class="section-header" onclick="toggleSection(''' + $bodyId + ''')">')
    $null = $sb.AppendLine('<div class="section-left"><span id="' + $iconId + '" class="section-icon">v</span><span class="section-title">' + (Convert-ToHtmlSafe $sec.Title) + '</span></div>')
    $null = $sb.AppendLine('<span class="section-status-pill ' + $cls + '">' + (Convert-ToHtmlSafe $sec.Status) + '</span>')
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine('<div id="' + $bodyId + '" class="section-body">')
    $null = $sb.AppendLine('<p class="section-summary">' + (Convert-ToHtmlSafe $sec.Summary) + '</p>')
    $null = $sb.AppendLine('<div class="findings">')

    foreach ($finding in $sec.Findings) {
        $fcls = 'status-' + $finding.Status.ToLowerInvariant()
        $null = $sb.AppendLine('<div class="finding" data-status="' + (Convert-ToHtmlSafe $finding.Status) + '">')

        $findingLink = ''
        $findingLinkTitle = 'Open related location'

        if ($finding.PSObject.Properties['LinkUri'] -and -not [string]::IsNullOrWhiteSpace([string]$finding.LinkUri)) {
            $findingLink = [string]$finding.LinkUri
            if ($findingLink -match '^threatinspection://browser-notifications/') {
                $findingLinkTitle = 'Open website notification permissions in this browser'
                if ($findingLink -match '/firefox$') {
                    $findingLinkTitle = 'Open Firefox Privacy & Security, then Notifications > Settings'
                }
            } elseif ($findingLink -eq 'ms-settings:notifications') {
                $findingLinkTitle = 'Open Windows notification settings (browser not identified)'
            } elseif ($findingLink -eq 'windowsdefender://exclusions/') {
                $findingLinkTitle = 'Open Windows Security exclusions'
            } elseif ($findingLink -eq 'threatinspection://tool/firewall') {
                $findingLinkTitle = 'Open Windows Defender Firewall with Advanced Security'
            } elseif ($findingLink -eq 'threatinspection://tool/scheduler') {
                $findingLinkTitle = 'Open Task Scheduler'
            } elseif ($findingLink -eq 'threatinspection://tool/services') {
                $findingLinkTitle = 'Open Services'
            } elseif ($findingLink -eq 'threatinspection://tool/devicemanager') {
                $findingLinkTitle = 'Open Device Manager'
            } elseif ($findingLink -eq 'threatinspection://tool/taskmanager') {
                $findingLinkTitle = 'Open Task Manager'
            } elseif ($findingLink -like 'windowsdefender://history*') {
                $findingLinkTitle = 'Open Windows Security Protection history'
            } elseif ($findingLink -like 'windowsdefender://threatsettings*') {
                $findingLinkTitle = 'Open Virus & threat protection settings'
            } elseif ($findingLink -like 'windowsdefender://smartscreenpua*') {
                $findingLinkTitle = 'Open Reputation-based protection'
            } elseif ($findingLink -like 'windowsdefender://threat*') {
                $findingLinkTitle = 'Open Virus & threat protection'
            } elseif ($findingLink -like 'ms-settings:windowsdefender*') {
                $findingLinkTitle = 'Open Windows Security'
            } elseif ($findingLink -eq 'ms-settings:appsfeatures') {
                $findingLinkTitle = 'Open Installed Apps'
            } elseif ($findingLink -like 'ms-settings:*') {
                $findingLinkTitle = 'Open related Windows Settings'
            }
        } elseif ($finding.PSObject.Properties['LinkPath'] -and -not [string]::IsNullOrWhiteSpace([string]$finding.LinkPath)) {
            $findingLink = Convert-LocalPathToExplorerUri ([string]$finding.LinkPath)
            if ($findingLink) { $findingLinkTitle = 'Open actual folder in File Explorer' }
        }

        # Every Review/Warning gets a useful section-specific destination when the
        # individual finding did not provide one.
        if ($finding.Status -in @('Review','Warning') -and -not $findingLink) {
            switch ($sec.Id) {
                'remote-access' {
                    $findingLink = 'ms-settings:remotedesktop'
                    $findingLinkTitle = 'Open Remote Desktop settings'
                }
                'programs' {
                    if ([string]$finding.Text -match '(?i)^Startup:') {
                        $findingLink = 'ms-settings:startupapps'
                        $findingLinkTitle = 'Open Startup Apps settings'
                    } else {
                        $findingLink = 'ms-settings:appsfeatures'
                        $findingLinkTitle = 'Open Installed Apps settings'
                    }
                }
                'autoruns' {
                    if ([string]$finding.Detail -match '(?i)Category:\s*Scheduled Tasks') {
                        $findingLink = 'threatinspection://tool/scheduler'
                        $findingLinkTitle = 'Open Task Scheduler'
                    } else {
                        $findingLink = Convert-LocalPathToExplorerUri (Join-Path $env:SystemRoot 'System32')
                        $findingLinkTitle = 'Open related Windows system folder'
                    }
                }
                'tasks' {
                    if ([string]$finding.Text -match '(?i)^Task:') {
                        $findingLink = 'threatinspection://tool/scheduler'
                        $findingLinkTitle = 'Open Task Scheduler'
                    } elseif ([string]$finding.Text -match '(?i)^Service:') {
                        $findingLink = 'threatinspection://tool/services'
                        $findingLinkTitle = 'Open Services'
                    } elseif ([string]$finding.Text -match '(?i)^Driver:') {
                        $findingLink = 'threatinspection://tool/devicemanager'
                        $findingLinkTitle = 'Open Device Manager'
                    } else {
                        $findingLink = 'threatinspection://tool/taskmanager'
                        $findingLinkTitle = 'Open Task Manager'
                    }
                }
                'files' {
                    $findingLink = Convert-LocalPathToExplorerUri $env:USERPROFILE
                    $findingLinkTitle = 'Open actual user profile folder in File Explorer'
                }
                'browsers' {
                    $findingLink = 'ms-settings:defaultapps'
                    $findingLinkTitle = 'Open Default Apps settings'
                }
                'network' {
                    $findingLink = 'ms-settings:network-status'
                    $findingLinkTitle = 'Open Network settings'
                }
                'security' {
                    $findingLink = 'ms-settings:windowsdefender'
                    $findingLinkTitle = 'Open Windows Security'
                }
            }
        }

        if (-not $script:ThreatInspectionProtocolReady -and $findingLink -like 'threatinspection://*') { $findingLink = '' }
        if ($finding.Status -in @('Review','Warning') -and $findingLink) {
            $null = $sb.AppendLine('<div><a class="finding-status ' + $fcls + '" href="' + (Convert-ToHtmlSafe $findingLink) + '" title="' + (Convert-ToHtmlSafe $findingLinkTitle) + '">' + (Convert-ToHtmlSafe $finding.Status) + '</a></div>')
        } else {
            $null = $sb.AppendLine('<div><span class="finding-status ' + $fcls + '">' + (Convert-ToHtmlSafe $finding.Status) + '</span></div>')
        }

        $displayFindingText = Limit-DisplayText -Text ([string]$finding.Text) -MaxLength 320 -MaxTokenLength 180
        $null = $sb.AppendLine('<div class="finding-main"><div class="finding-text">' + (Convert-ToHtmlSafe $displayFindingText) + '</div>')
        if (-not [string]::IsNullOrWhiteSpace([string]$finding.Detail)) {
            $displayFindingDetail = Limit-DisplayText -Text ([string]$finding.Detail) -MaxLength 1100 -MaxTokenLength 220
            $null = $sb.AppendLine('<div class="finding-detail">' + (Convert-ToHtmlSafe $displayFindingDetail) + '</div>')
        }
        $null = $sb.AppendLine('</div></div>')
    }

    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine('</div>')
}

$null = $sb.AppendLine('<div class="footer">')
$null = $sb.AppendLine('Threat inspection completed at ' + (Convert-ToHtmlSafe ($completedAt.ToString('yyyy-MM-dd HH:mm:ss'))) + '.<br>')
$null = $sb.AppendLine('This report is an inspection aid, not a malware verdict. Review items may be legitimate. The script does not remediate or delete inspected files, disable settings, quarantine threats, or upload files/hashes.<br>')
$null = $sb.AppendLine('Summary cards count the actual finding rows shown in the report: ' + $infoCount + ' Info / ' + $goodCount + ' Good / ' + $reviewCount + ' Review / ' + $warningCount + ' Warning.<br>')
$null = $sb.AppendLine('File scanning: ' + (Convert-ToHtmlSafe $combinedFileScan.Mode) + ' mode, ' + $scanCoverage.Errors + ' access/IO errors, ' + $scanCoverage.DepthLimitedDirectories + ' depth-limited directories. Standard mode uses targeted roots and excludes caches; Deep mode examines fixed drives to depth 64 but does not follow reparse points. <br>')
$null = $sb.AppendLine('Browser permissions and notification history may be unavailable or stale in locked/offline profiles; evidence is reconciled where available. No result proves the absence of malware.')
$null = $sb.AppendLine('</div>')
$null = $sb.AppendLine('</div>')
$null = $sb.AppendLine('<script>filterFindings();</script>')
$null = $sb.AppendLine('</body>')
$null = $sb.AppendLine('</html>')

[System.IO.File]::WriteAllText($finalReportPath, $sb.ToString(), [System.Text.Encoding]::UTF8)

# ----------------------------------------------------
# Final
# ----------------------------------------------------
Write-Host "Threat Inspection" -ForegroundColor Cyan
Write-Host ""
Write-Host "Report: $finalReportPath" -ForegroundColor Green
Write-Host "Review findings: $reviewCount" -ForegroundColor Yellow
Write-Host "Warning findings: $warningCount" -ForegroundColor $(if ($warningCount -gt 0) { 'Red' } else { 'Green' })
Write-Host ""
Write-Host "Threat inspection completed." -ForegroundColor Green

if (-not $NoOpenReport) {
    try { Start-Process $finalReportPath | Out-Null } catch { }
}

try { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
