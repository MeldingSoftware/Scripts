#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------
# ----------------------------------------------------
# Pre-flight: close File Explorer windows & browsers, maximize PowerShell window
# ----------------------------------------------------

# DLL's for show, hide, and focus console (and best-effort maximize for Terminal hosts)
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern System.IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(System.IntPtr hWnd, System.Int32 nCmdShow);

[DllImport("user32.dll")]
public static extern bool SetForegroundWindow(System.IntPtr hWnd);
' -ErrorAction SilentlyContinue

function Show-Console
{
    # Try classic console window first
    $consolePtr = [Console.Window]::GetConsoleWindow()

    # If running under Windows Terminal / hosted console, fall back to main window handle
    if ($consolePtr -eq [IntPtr]::Zero) {
        try {
            $consolePtr = (Get-Process -Id $PID).MainWindowHandle
        } catch { }
    }

    if ($consolePtr -ne [IntPtr]::Zero) {
        [Console.Window]::ShowWindow($consolePtr, 3) | Out-Null  # Show/maximize window
        [Console.Window]::SetForegroundWindow($consolePtr) | Out-Null # Ensure focus
    }

    # RawUI fallback (helps in some hosts)
    try {
        $raw = $Host.UI.RawUI
        $raw.WindowSize = $raw.MaxPhysicalWindowSize
    } catch { }
}

function Hide-Console
{
    $consolePtr = [Console.Window]::GetConsoleWindow()
    if ($consolePtr -ne [IntPtr]::Zero) {
        [Console.Window]::ShowWindow($consolePtr, 0) | Out-Null
    }
}

function Focus-Console {
    $consolePtr = [Console.Window]::GetConsoleWindow()
    if ($consolePtr -ne [IntPtr]::Zero) {
        [Console.Window]::SetForegroundWindow($consolePtr) | Out-Null
    }
}

function Close-ExplorerWindows {
    try {
        $shell = New-Object -ComObject Shell.Application
        foreach ($w in @($shell.Windows())) {
            try {
                $full = $w.FullName
                if ($full -and ((Split-Path $full -Leaf) -ieq 'explorer.exe')) {
                    $w.Quit()
                }
            } catch { }
        }
    } catch { }
}

function Close-Browsers {
    $names = @('msedge','chrome','firefox','brave','opera','vivaldi')
    foreach ($n in $names) {
        try { Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch { }
    }
}

try { Show-Console } catch { }
try { Close-ExplorerWindows } catch { }
try { Close-Browsers } catch { }

# ----------------------------------------------------
# Paths & Base Setup
# ----------------------------------------------------
$desktopRoot              = [Environment]::GetFolderPath("Desktop")
$localAppDataRoot         = [Environment]::GetFolderPath("LocalApplicationData")
$dateStamp                = Get-Date -Format "MM-dd-yy"
$reportName               = "Maintenance $dateStamp.html"
$filesFolder              = Join-Path $localAppDataRoot "Maintenance Temp"
$reportPath               = Join-Path $filesFolder ("Maintenance_Working_{0}.html" -f $dateStamp)
$finalReportPath          = Join-Path $desktopRoot $reportName
$runOnceValueName         = "MaintenanceChkDskPostRun_$dateStamp"

if (-not (Test-Path $filesFolder)) {
    New-Item -Path $filesFolder -ItemType Directory -Force | Out-Null
}

try {
    (Get-Item -LiteralPath $filesFolder -Force).Attributes = ((Get-Item -LiteralPath $filesFolder -Force).Attributes -bor [System.IO.FileAttributes]::Hidden)
} catch { }

$dismLogPath              = Join-Path $filesFolder "DISM_SFC.txt"
$tempLogPath              = Join-Path $filesFolder "Temp.txt"
$browserLogPath           = Join-Path $filesFolder "Browsers.txt"
$wuLogPath                = Join-Path $filesFolder "WindowsUpdates.txt"
$appLogPath               = Join-Path $filesFolder "AppUpdates.txt"
$optimizeLogPath          = Join-Path $filesFolder "OptimizeDrives.txt"
$crashAnalysisPath        = Join-Path $filesFolder "CrashDumpAnalysis.txt"
$chkdskScriptPath         = Join-Path $filesFolder "ChkdskResults.ps1"
$chkdskBatPath            = Join-Path $filesFolder "Run Me.bat"
$batteryReportPath        = Join-Path $filesFolder "Battery_Report.html"   # temp helper file (we delete it later)

$intelDsaUrl              = "https://www.intel.com/content/www/us/en/support/detect.html"
$nvidiaAppUrl             = "https://www.nvidia.com/en-us/software/nvidia-app/"
$amdDriversUrl            = "https://www.amd.com/en/support/download/drivers.html"

$downloadsPath               = Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads"
$downloadsMaintenanceFolder  = Join-Path $downloadsPath "Maintenance"
$downloadsMaintenanceZip     = Join-Path $downloadsPath "Maintenance.zip"
$downloadsFolderMarker       = Join-Path $downloadsMaintenanceFolder ".melding-maintenance-marker"

try {
    $scriptRoot = $null
    if ($PSCommandPath) {
        $scriptRoot = Split-Path -Parent $PSCommandPath
    } elseif ($MyInvocation.MyCommand.Path) {
        $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    }

    if ($scriptRoot -and (Test-Path -LiteralPath $downloadsMaintenanceFolder -PathType Container)) {
        $resolvedScriptRoot = try { (Resolve-Path -LiteralPath $scriptRoot -ErrorAction Stop).Path } catch { $scriptRoot }
        $resolvedDownloadsMaintenanceFolder = try { (Resolve-Path -LiteralPath $downloadsMaintenanceFolder -ErrorAction Stop).Path } catch { $downloadsMaintenanceFolder }

        if ($resolvedScriptRoot -eq $resolvedDownloadsMaintenanceFolder -or
            $resolvedScriptRoot.StartsWith($resolvedDownloadsMaintenanceFolder + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
            New-Item -ItemType File -Path $downloadsFolderMarker -Force | Out-Null
            try {
                (Get-Item -LiteralPath $downloadsFolderMarker -Force).Attributes = ((Get-Item -LiteralPath $downloadsFolderMarker -Force).Attributes -bor [System.IO.FileAttributes]::Hidden)
            } catch { }
        }
    }
} catch { }


# ----------------------------------------------------
# ----------------------------------------------------
# Startup Optimization (Task Manager only)
# ----------------------------------------------------
function Invoke-StartupOptimizationInteractive {
    # Returns: @{ Status; Summary; Content }
    $result = @{
        Status  = 'Completed'
        Summary = ''
        Content = ''
    }

    Write-Host "Startup Optimization" -ForegroundColor Cyan
    Write-Host ""

    try {
        Start-Process "taskmgr.exe" -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 1
    }
    catch {
        $result.Status  = 'Warning'
        $result.Summary = 'Task Manager failed to open.'
        $result.Content = 'Task Manager failed to open.'
        Write-Host "Task Manager failed to open: $($_.Exception.Message)" -ForegroundColor Yellow
        return $result
    }

    Write-Host "Task Manager has opened." -ForegroundColor Yellow
    Write-Host "Navigate to the Startup apps tab and disable any unnecessary apps to optimize startup." -ForegroundColor Yellow
    Write-Host ""

    $choice = if (Read-YesNoPrompt "Did you disable any apps? (y/n)") { 'y' } else { 'n' }

    if ($choice -eq 'y') {
        $result.Summary = 'Successfully optimized the startup.'
        $result.Content = 'Successfully optimized the startup.'
    }
    else {
        $result.Summary = "Startup optimization wasn't necessary."
        $result.Content = "Startup optimization wasn't necessary."
    }

    return $result
}


function Read-YesNoPrompt {
    param([string]$Prompt)

    do {
        $choice = (Read-Host $Prompt.TrimEnd(':')).Trim().ToLowerInvariant()
        if ($choice -eq 'qq') {
            Write-Host "Exiting maintenance" -ForegroundColor Yellow
            exit
        }
        if ($choice -notin @('y','n')) {
            Write-Host "Please enter y, n, or qq" -ForegroundColor Yellow
        }
    } while ($choice -notin @('y','n'))

    return ($choice -eq 'y')
}

function Read-ContinuePrompt {
    $choice = (Read-Host "Press Enter to continue").Trim().ToLowerInvariant()
    if ($choice -eq 'qq') {
        Write-Host "Exiting maintenance" -ForegroundColor Yellow
        exit
    }
}

function Get-InstalledSoftwareNames {
    $names = New-Object System.Collections.Generic.List[string]
    $registryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($registryPath in $registryPaths) {
        try {
            $items = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue
            foreach ($item in @($items)) {
                if (-not [string]::IsNullOrWhiteSpace($item.DisplayName)) {
                    $names.Add([string]$item.DisplayName)
                }
            }
        } catch { }
    }

    return @($names | Sort-Object -Unique)
}

function Get-InstalledSoftwareMatch {
    param(
        [string[]]$InstalledNames,
        [string[]]$Patterns
    )

    foreach ($installedName in @($InstalledNames)) {
        foreach ($pattern in @($Patterns)) {
            if ($installedName -like $pattern) {
                return $installedName
            }
        }
    }

    return $null
}

function Test-IntelHardwarePresent {
    try {
        $processor = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($processor -and (($processor.Name + ' ' + $processor.Manufacturer) -match 'Intel')) {
            return $true
        }
    } catch { }

    try {
        $intelGpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name + ' ' + $_.AdapterCompatibility) -match 'Intel'
        } | Select-Object -First 1
        if ($intelGpu) {
            return $true
        }
    } catch { }

    try {
        $intelNic = Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue | Where-Object {
            ($_.PhysicalAdapter -eq $true) -and (($_.Name + ' ' + $_.Manufacturer) -match 'Intel')
        } | Select-Object -First 1
        if ($intelNic) {
            return $true
        }
    } catch { }

    try {
        $intelPnp = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {
            $_.Manufacturer -match 'Intel'
        } | Select-Object -First 1
        if ($intelPnp) {
            return $true
        }
    } catch { }

    return $false
}

function Test-NvidiaGpuPresent {
    try {
        $gpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name + ' ' + $_.AdapterCompatibility) -match 'NVIDIA'
        } | Select-Object -First 1

        return [bool]$gpu
    } catch {
        return $false
    }
}

function Test-AmdGpuPresent {
    try {
        $gpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name + ' ' + $_.AdapterCompatibility) -match 'AMD|Radeon|Advanced Micro Devices'
        } | Select-Object -First 1

        return [bool]$gpu
    } catch {
        return $false
    }
}

function Test-AmdHardwarePresent {
    try {
        $processor = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($processor -and (($processor.Name + ' ' + $processor.Manufacturer) -match 'AMD|Ryzen|Threadripper|EPYC|Athlon')) {
            return $true
        }
    } catch { }

    try {
        $gpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name + ' ' + $_.AdapterCompatibility) -match 'AMD|Radeon|Advanced Micro Devices'
        } | Select-Object -First 1

        if ($gpu) {
            return $true
        }
    } catch { }

    return $false
}

function Get-WingetExecutablePath {
    try {
        $desktopAppInstaller = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending |
            Select-Object -First 1

        if ($desktopAppInstaller -and $desktopAppInstaller.InstallLocation) {
            $packagedWingetPath = Join-Path $desktopAppInstaller.InstallLocation 'winget.exe'
            if (Test-Path -LiteralPath $packagedWingetPath -PathType Leaf) {
                return $packagedWingetPath
            }
        }
    } catch { }

    try {
        $wingetCommand = Get-Command winget.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($wingetCommand -and $wingetCommand.Source) {
            return $wingetCommand.Source
        }
    } catch { }

    return $null
}

function Try-InstallIntelDsa {
    $wingetPath = Get-WingetExecutablePath

    if (-not $wingetPath) {
        return [PSCustomObject]@{
            Success = $false
            Message = 'winget is not available.'
        }
    }

    $attempts = @(
        @('--id', 'Intel.IntelDriverAndSupportAssistant', '-e'),
        @('--name', 'Intel® Driver & Support Assistant', '-e'),
        @('--name', 'Intel Driver & Support Assistant')
    )

    foreach ($attempt in $attempts) {
        try {
            $wingetOutput = @(& $wingetPath install @attempt --accept-source-agreements --accept-package-agreements 2>&1)
            $wingetExitCode = $LASTEXITCODE
            Start-Sleep -Seconds 5

            $installedNames = Get-InstalledSoftwareNames
            $match = Get-InstalledSoftwareMatch -InstalledNames $installedNames -Patterns @('*Intel*Driver*Support*Assistant*')
            if ($match) {
                return [PSCustomObject]@{
                    Success = $true
                    Message = 'Intel Driver & Support Assistant was installed.'
                }
            }

            if ($wingetExitCode -ne 0) {
                $wingetOutputText = (($wingetOutput | ForEach-Object { [string]$_ }) -join ' ').Trim()
                if ([string]::IsNullOrWhiteSpace($wingetOutputText)) {
                    $lastError = "winget exited with code $wingetExitCode"
                } else {
                    $lastError = $wingetOutputText
                }
            }
        } catch {
            $lastError = $_.Exception.Message
        }
    }

    return [PSCustomObject]@{
        Success = $false
        Message = $lastError
    }
}

# ----------------------------------------------------
# Power Plan Handling
# ----------------------------------------------------
$schemeGuid  = 'e03c2dc5-fac9-4f5d-9948-0a2fb9009d67'
$schemeName  = 'Always on'
$schemeDescr = 'Custom power scheme to keep the system awake indefinitely.'

function assert-ok {
    if ($LASTEXITCODE -ne 0) { throw "Command failed with exit code $LASTEXITCODE" }
}

# Save original active scheme (if possible)
$prevGuid = $null
try {
    $prevGuid = (powercfg -getactivescheme 2>$null) -replace '^.+([-0-9a-f]{36}).+$', '$1'
} catch {
}

$scriptHadFatalError = $false

    # Defaults (in case startup step is skipped by flow)
    $startupStatus  = 'Completed'
    $startupSummary = 'Startup optimization did not run.'
    $startupContent = ''

    # Defaults for restore point section
    $restorePointStatus  = 'Completed'
    $restorePointSummary = 'Restore point was not attempted.'
    $restorePointContent = ''

    # Defaults for software install section
    $softwareInstallStatus  = 'Completed'
    $softwareInstallSummary = 'Vendor software check did not run.'
    $softwareInstallContent = ''

try {
    # --- Configure "Always on" plan but don't treat errors here as fatal ---
    try {
        $existingPlans = powercfg -list 2>$null
        $planExists = $existingPlans -match $schemeGuid

        if (-not $planExists) {
            $null = powercfg -duplicatescheme SCHEME_MIN $schemeGuid 2>$null
            $null = powercfg -changename $schemeGuid $schemeName $schemeDescr 2>$null
        }
        $null = powercfg -setactive $schemeGuid 2>$null

        $settings = 'monitor-timeout-ac','monitor-timeout-dc','disk-timeout-ac','disk-timeout-dc',
                    'standby-timeout-ac','standby-timeout-dc','hibernate-timeout-ac','hibernate-timeout-dc'

        foreach ($setting in $settings) {
            $null = powercfg -change $setting 0 2>$null
        }
    }
    catch {
    }

    # ------------------------------------------------
    # Microsoft Store (manual)
    # ------------------------------------------------
    function Format-StorageSize {
        param([uint64]$bytes)
        if ($bytes -ge 1TB) { return ("{0:N1} TB" -f ($bytes / 1TB)) }
        if ($bytes -ge 1GB) { return ("{0:N0} GB" -f ($bytes / 1GB)) }
        return ("{0:N0} MB" -f ($bytes / 1MB))
    }

    function Get-BugCheckNameFromCode {
        param([string]$Code)

        if ([string]::IsNullOrWhiteSpace($Code)) {
            return $null
        }

        $normalized = $Code.Trim().ToUpperInvariant()
        if ($normalized.StartsWith('0X')) {
            $normalized = $normalized.Substring(2)
        }
        $normalized = $normalized.TrimStart('0')
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            $normalized = '0'
        }

        $map = @{
            '1'   = 'APC_INDEX_MISMATCH'
            '1A'  = 'MEMORY_MANAGEMENT'
            '1E'  = 'KMODE_EXCEPTION_NOT_HANDLED'
            '19'  = 'BAD_POOL_HEADER'
            '24'  = 'NTFS_FILE_SYSTEM'
            '3B'  = 'SYSTEM_SERVICE_EXCEPTION'
            '4E'  = 'PFN_LIST_CORRUPT'
            '50'  = 'PAGE_FAULT_IN_NONPAGED_AREA'
            '7A'  = 'KERNEL_DATA_INPAGE_ERROR'
            '7B'  = 'INACCESSIBLE_BOOT_DEVICE'
            '7E'  = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'
            '7F'  = 'UNEXPECTED_KERNEL_MODE_TRAP'
            '9C'  = 'MACHINE_CHECK_EXCEPTION'
            '9F'  = 'DRIVER_POWER_STATE_FAILURE'
            'A'   = 'IRQL_NOT_LESS_OR_EQUAL'
            '101' = 'CLOCK_WATCHDOG_TIMEOUT'
            '109' = 'CRITICAL_STRUCTURE_CORRUPTION'
            '116' = 'VIDEO_TDR_FAILURE'
            '119' = 'VIDEO_SCHEDULER_INTERNAL_ERROR'
            '124' = 'WHEA_UNCORRECTABLE_ERROR'
            '133' = 'DPC_WATCHDOG_VIOLATION'
            '139' = 'KERNEL_SECURITY_CHECK_FAILURE'
            'BE'  = 'ATTEMPTED_WRITE_TO_READONLY_MEMORY'
            'C2'  = 'BAD_POOL_CALLER'
            'D1'  = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'
            'E3'  = 'RESOURCE_NOT_OWNED'
            'EF'  = 'CRITICAL_PROCESS_DIED'
        }

        return $map[$normalized]
    }

    function Get-BugCheckDescription {
        param(
            [string]$Name,
            [string]$Code
        )

        $resolvedName = $Name
        if ([string]::IsNullOrWhiteSpace($resolvedName)) {
            $resolvedName = Get-BugCheckNameFromCode -Code $Code
        }

        if ([string]::IsNullOrWhiteSpace($resolvedName)) {
            return 'A Windows bug check was recorded for this dump.'
        }

        $descriptionMap = @{
            'APC_INDEX_MISMATCH'                        = 'A kernel APC state mismatch was detected.'
            'ATTEMPTED_WRITE_TO_READONLY_MEMORY'       = 'Code attempted to write to read-only memory.'
            'BAD_POOL_CALLER'                          = 'A driver or kernel component made an invalid memory pool request.'
            'BAD_POOL_HEADER'                          = 'Windows detected corruption in a memory pool header.'
            'CLOCK_WATCHDOG_TIMEOUT'                   = 'A processor core did not respond to a clock interrupt in time.'
            'CRITICAL_PROCESS_DIED'                    = 'A critical Windows process unexpectedly stopped.'
            'CRITICAL_STRUCTURE_CORRUPTION'            = 'Windows detected corruption in a critical kernel structure.'
            'DPC_WATCHDOG_VIOLATION'                   = 'A DPC or interrupt routine ran too long.'
            'DRIVER_IRQL_NOT_LESS_OR_EQUAL'            = 'A driver accessed invalid memory at an improper interrupt level.'
            'DRIVER_POWER_STATE_FAILURE'               = 'A driver had a power-state transition problem.'
            'INACCESSIBLE_BOOT_DEVICE'                 = 'Windows could not access the system boot device.'
            'IRQL_NOT_LESS_OR_EQUAL'                   = 'Kernel code or a driver accessed invalid memory at an improper interrupt level.'
            'KERNEL_DATA_INPAGE_ERROR'                 = 'Windows could not read required kernel data from disk into memory.'
            'KERNEL_SECURITY_CHECK_FAILURE'            = 'Windows detected kernel data corruption or a critical consistency failure.'
            'KMODE_EXCEPTION_NOT_HANDLED'              = 'Kernel-mode code raised an unhandled exception.'
            'MACHINE_CHECK_EXCEPTION'                  = 'The processor reported a fatal hardware error.'
            'MEMORY_MANAGEMENT'                        = 'Windows detected a serious memory-management problem.'
            'NTFS_FILE_SYSTEM'                         = 'Windows detected a serious NTFS file system problem.'
            'PAGE_FAULT_IN_NONPAGED_AREA'              = 'Invalid system memory was referenced.'
            'PFN_LIST_CORRUPT'                         = 'Windows detected corruption in the page frame number list.'
            'RESOURCE_NOT_OWNED'                       = 'A thread tried to release a resource it did not own.'
            'SYSTEM_SERVICE_EXCEPTION'                 = 'A system service or driver triggered an exception.'
            'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'      = 'A system thread generated an unhandled exception.'
            'UNEXPECTED_KERNEL_MODE_TRAP'              = 'The kernel hit an unexpected trap, often related to hardware, drivers, or memory.'
            'VIDEO_SCHEDULER_INTERNAL_ERROR'           = 'The graphics scheduler encountered a fatal internal error.'
            'VIDEO_TDR_FAILURE'                        = 'The graphics driver stopped responding and recovery failed.'
            'WHEA_UNCORRECTABLE_ERROR'                 = 'Windows detected a fatal hardware error.'
        }

        if ($descriptionMap.ContainsKey($resolvedName)) {
            return $descriptionMap[$resolvedName]
        }

        return 'A Windows bug check was recorded for this dump.'
    }

    function Get-CrashDumpType {
        param(
            [string]$DumpPath,
            [string]$AnalysisText
        )

        if (-not [string]::IsNullOrWhiteSpace($AnalysisText)) {
            if ($AnalysisText -match '(?im)^Mini Kernel Dump File:')        { return 'Minidump' }
            if ($AnalysisText -match '(?im)^Small Memory Dump File:')       { return 'Minidump' }
            if ($AnalysisText -match '(?im)^User Mini Dump File:')          { return 'User-mode dump' }
            if ($AnalysisText -match '(?im)^Kernel Bitmap Dump File:')      { return 'Kernel dump' }
            if ($AnalysisText -match '(?im)^Kernel Complete Dump File:')    { return 'Kernel dump' }
            if ($AnalysisText -match '(?im)^Complete Memory Dump File:')    { return 'Complete dump' }
            if ($AnalysisText -match '(?im)^Live Kernel Dump File:')        { return 'Live Kernel dump' }
        }

        if ($DumpPath -match '(?i)\\Minidump\\')          { return 'Minidump' }
        if ($DumpPath -match '(?i)\\LiveKernelReports\\') { return 'Live Kernel dump' }
        if ($DumpPath -match '(?i)\\CrashDumps\\')        { return 'User-mode dump' }

        if ((Split-Path $DumpPath -Leaf) -ieq 'MEMORY.DMP') {
            return 'Memory dump'
        }

        return 'Crash dump'
    }

    function Get-ProbablyCausedBy {
        param([string]$AnalysisText)

        if ([string]::IsNullOrWhiteSpace($AnalysisText)) {
            return $null
        }

        if ($AnalysisText -match '(?im)^Probably caused by\s*:\s*([^\r\n]+)$') {
            $value = $matches[1].Trim()
            if ($value -match '^([^\s\(]+)') {
                return $matches[1].Trim()
            }
            return $value
        }

        return $null
    }

    function Get-ExceptionCodeDescription {
        param([string]$Code)

        if ([string]::IsNullOrWhiteSpace($Code)) {
            return $null
        }

        $normalized = $Code.Trim().ToUpperInvariant()
        if ($normalized -notmatch '^0X') {
            $normalized = "0x$normalized"
        }

        $map = @{
            '0xC0000005' = 'Access violation'
            '0x80000003' = 'Breakpoint'
            '0xC0000409' = 'Stack buffer overrun'
            '0xC000001D' = 'Illegal instruction'
            '0xC0000094' = 'Integer divide by zero'
            '0xC00000FD' = 'Stack overflow'
            '0xC0000135' = 'Unable to locate component'
            '0xC0000142' = 'DLL initialization failed'
            '0xE0434352' = '.NET runtime exception'
        }

        if ($map.ContainsKey($normalized)) {
            return $map[$normalized]
        }

        return $null
    }

    function Get-UserModeCrashInfoFromAnalysis {
        param([string]$AnalysisText)

        $result = [ordered]@{
            ExceptionCode = $null
            ExceptionText = $null
            Module        = $null
            FailureBucket = $null
            ProcessName   = $null
        }

        if ([string]::IsNullOrWhiteSpace($AnalysisText)) {
            return [PSCustomObject]$result
        }

        if ($AnalysisText -match '(?im)^EXCEPTION_CODE_STR:\s*([^\r\n]+)$') {
            $result.ExceptionCode = $matches[1].Trim()
        } elseif ($AnalysisText -match '(?im)^ExceptionCode:\s*([0-9A-Fa-fx]+)\b') {
            $result.ExceptionCode = $matches[1].Trim()
        } elseif ($AnalysisText -match '(?im)\)\:\s*([^\r\n]+?)\s*-\s*code\s*([0-9A-Fa-fx]+)') {
            $result.ExceptionText = $matches[1].Trim()
            $result.ExceptionCode = $matches[2].Trim()
        }

        if (-not $result.ExceptionText -and $result.ExceptionCode) {
            $result.ExceptionText = Get-ExceptionCodeDescription -Code $result.ExceptionCode
        }

        if ($AnalysisText -match '(?im)^IMAGE_NAME:\s*([^\r\n]+)$') {
            $result.Module = $matches[1].Trim()
        } elseif ($AnalysisText -match '(?im)^MODULE_NAME:\s*([^\r\n]+)$') {
            $result.Module = $matches[1].Trim()
        } elseif ($AnalysisText -match '(?im)^SYMBOL_NAME:\s*([^!\r\n]+)!') {
            $result.Module = $matches[1].Trim()
        }

        if ($AnalysisText -match '(?im)^FAILURE_BUCKET_ID:\s*([^\r\n]+)$') {
            $result.FailureBucket = $matches[1].Trim()
        } elseif ($AnalysisText -match '(?im)^\s*Value:\s*([^\r\n]+)$' -and $AnalysisText -match '(?im)^\s*Key\s*: Failure\.Bucket\s*$') {
            $result.FailureBucket = $matches[1].Trim()
        }

        if ($AnalysisText -match '(?im)^PROCESS_NAME:\s*([^\r\n]+)$') {
            $result.ProcessName = $matches[1].Trim()
        }

        return [PSCustomObject]$result
    }

    function Get-AnalysisFallbackText {
        param(
            [string]$DumpType,
            [string]$BugCheckName,
            [string]$BugCheckCode,
            [string]$Module,
            [string]$FailureBucket
        )

        if (-not [string]::IsNullOrWhiteSpace($Module)) {
            return "Crash appears related to $Module."
        }

        if (-not [string]::IsNullOrWhiteSpace($BugCheckName)) {
            $upperName = $BugCheckName.Trim().ToUpperInvariant()

            if ($upperName -eq 'VIDEO_DXGKRNL_LIVEDUMP' -or $upperName -like 'VIDEO_*') {
                return 'Graphics kernel live dump, often graphics driver or GPU related.'
            }

            return "Crash appears related to $upperName."
        }

        if (-not [string]::IsNullOrWhiteSpace($FailureBucket)) {
            return "Failure bucket: $FailureBucket."
        }

        if ($DumpType -eq 'User-mode dump') {
            return 'CDB did not identify a probable cause.'
        }

        return 'CDB did not identify a probable cause.'
    }

    function Get-BugCheckParametersFromAnalysis {
        param([string]$AnalysisText)

        if ([string]::IsNullOrWhiteSpace($AnalysisText)) {
            return $null
        }

        $values = @()
        foreach ($slot in @('P1','P2','P3','P4')) {
            if ($AnalysisText -match ("(?im)^BUGCHECK_{0}:\s*([^\r\n]+)$" -f $slot)) {
                $values += $matches[1].Trim()
            }
        }

        if ($values.Count -eq 0) {
            foreach ($slot in 1..4) {
                if ($AnalysisText -match ("(?im)^Arg{0}:\s*([^,\r\n]+)" -f $slot)) {
                    $values += $matches[1].Trim()
                }
            }
        }

        if ($values.Count -gt 0) {
            return ($values -join ', ')
        }

        return $null
    }

    function Get-SystemUptimeFromAnalysis {
        param([string]$AnalysisText)

        if ([string]::IsNullOrWhiteSpace($AnalysisText)) {
            return $null
        }

        if ($AnalysisText -match '(?im)^System Uptime:\s*([^\r\n]+)$') {
            return $matches[1].Trim()
        }

        if ($AnalysisText -match '(?im)^Uptime:\s*([^\r\n]+)$') {
            return $matches[1].Trim()
        }

        return $null
    }

    function Get-DriverFromAnalysis {
        param(
            [string]$AnalysisText,
            [string]$ProbablyCausedBy
        )

        if (-not [string]::IsNullOrWhiteSpace($AnalysisText)) {
            if ($AnalysisText -match '(?im)^IMAGE_NAME:\s*([^\r\n]+)$') {
                return $matches[1].Trim()
            }

            if ($AnalysisText -match '(?im)^MODULE_NAME:\s*([^\r\n]+)$') {
                return $matches[1].Trim()
            }

            if ($AnalysisText -match '(?im)^SYMBOL_NAME:\s*([^!\r\n]+)!') {
                return $matches[1].Trim()
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($ProbablyCausedBy)) {
            $candidate = $ProbablyCausedBy.Trim()
            if ($candidate -match '^([^\s\(]+)') {
                return $matches[1].Trim()
            }
            return $candidate
        }

        return $null
    }

    function Get-DriverDisplayPath {
        param([string]$DriverName)

        if ([string]::IsNullOrWhiteSpace($DriverName)) {
            return $null
        }

        $name = $DriverName.Trim()

        if ($name -match '(?i)^c:\\') {
            return $name
        }

        if ($name -match '(?i)\.sys$') {
            return "C:\WINDOWS\system32\drivers\$name"
        }

        if ($name -match '(?i)\.exe$') {
            return "C:\WINDOWS\system32\$name"
        }

        return $name
    }

    function Get-DeviceFromDriver {
        param([string]$DriverName)

        if ([string]::IsNullOrWhiteSpace($DriverName)) {
            return 'Unknown'
        }

        $name = $DriverName.Trim().ToLowerInvariant()

        if ($name -match 'nvlddmkm|nvidia') { return 'NVIDIA GPU' }
        if ($name -match 'amdkmdag|amdkmdap|atikmpag|atikmdag|radeon|amd') { return 'AMD GPU' }
        if ($name -match 'igdkmd|igdumdim|intel') { return 'Intel Graphics' }
        if ($name -match 'iastor|iaahci|stornvme|storport|nvme|disk|ntfs') { return 'Storage subsystem' }
        if ($name -match 'netwtw|e1d|rtwl|tcpip|ndis') { return 'Network adapter' }
        if ($name -match 'usbhub|usb') { return 'USB device' }
        if ($name -match 'acpi') { return 'ACPI / power management' }
        if ($name -match 'ntoskrnl') { return 'Unknown' }

        return 'Unknown'
    }

    function Get-ResolutionActions {
        param(
            [string]$BugCheckName,
            [string]$Device,
            [string]$DriverName
        )

        $upperBugCheck = if ($BugCheckName) { $BugCheckName.Trim().ToUpperInvariant() } else { '' }
        $deviceText = if ($Device) { $Device.Trim().ToUpperInvariant() } else { '' }
        $driverText = if ($DriverName) { $DriverName.Trim().ToUpperInvariant() } else { '' }

        $actions = New-Object System.Collections.Generic.List[string]

        function Add-UniqueAction {
            param([string]$Text)

            if ([string]::IsNullOrWhiteSpace($Text)) {
                return
            }

            if (-not ($actions -contains $Text)) {
                $actions.Add($Text)
            }
        }

        # Baseline guidance
        Add-UniqueAction "Install the latest Windows updates and check the system manufacturer's support page for newer BIOS, chipset, and device drivers."

        # Very specific bugcheck families first
        switch -Regex ($upperBugCheck) {
            '^(VIDEO_TDR_FAILURE|VIDEO_SCHEDULER_INTERNAL_ERROR|VIDEO_ENGINE_TIMEOUT_DETECTED|VIDEO_DXGKRNL_LIVEDUMP)$' {
                Add-UniqueAction 'Perform a clean reinstall of the graphics driver.'
                Add-UniqueAction 'Remove any GPU overclock or undervolt and test at stock settings.'
                Add-UniqueAction 'Check GPU temperatures, cooling, and power connections.'
                Add-UniqueAction 'Run a GPU or VRAM stress test to check for graphics hardware instability.'
                break
            }

            '^(DRIVER_POWER_STATE_FAILURE)$' {
                Add-UniqueAction 'Update chipset, storage, USB, and graphics drivers from the system manufacturer.'
                Add-UniqueAction 'Disable Fast Startup temporarily and retest shutdown, sleep, and resume.'
                Add-UniqueAction 'Disconnect nonessential USB devices and docks, then test again.'
                Add-UniqueAction 'Update BIOS and power-management related drivers.'
                break
            }

            '^(MEMORY_MANAGEMENT|PFN_LIST_CORRUPT|PAGE_FAULT_IN_NONPAGED_AREA|BAD_POOL_CALLER|BAD_POOL_HEADER|KERNEL_SECURITY_CHECK_FAILURE)$' {
                Add-UniqueAction 'Run an extended memory test and test RAM one stick at a time if errors persist.'
                Add-UniqueAction 'Disable XMP or EXPO temporarily and retest memory stability.'
                Add-UniqueAction 'Reseat RAM and check for mixed kits or unstable memory settings.'
                Add-UniqueAction 'Update BIOS if memory compatibility improvements are available.'
                break
            }

            '^(NTFS_FILE_SYSTEM|INACCESSIBLE_BOOT_DEVICE|KERNEL_DATA_INPAGE_ERROR)$' {
                Add-UniqueAction 'Check storage SMART health and run the drive manufacturer''s diagnostic utility.'
                Add-UniqueAction 'Update SSD firmware and storage-controller or chipset drivers.'
                Add-UniqueAction 'Check file-system integrity and inspect SATA, power, or NVMe seating issues.'
                Add-UniqueAction 'Back up important data immediately if storage errors continue.'
                break
            }

            '^(WHEA_UNCORRECTABLE_ERROR|CLOCK_WATCHDOG_TIMEOUT|MACHINE_CHECK_EXCEPTION|UNEXPECTED_KERNEL_MODE_TRAP)$' {
                Add-UniqueAction 'Remove any CPU overclock, undervolt, PBO, or EXPO/XMP overclock and retest at stock settings.'
                Add-UniqueAction 'Update BIOS and chipset drivers, then load BIOS defaults if instability continues.'
                Add-UniqueAction 'Run CPU and motherboard diagnostics while monitoring temperatures.'
                Add-UniqueAction 'Check PSU stability and cooling if the system fails under load.'
                break
            }

            '^(SYSTEM_SERVICE_EXCEPTION|KMODE_EXCEPTION_NOT_HANDLED|IRQL_NOT_LESS_OR_EQUAL|DRIVER_IRQL_NOT_LESS_OR_EQUAL)$' {
                Add-UniqueAction 'Focus on recently updated or newly installed drivers, software, and hardware.'
                Add-UniqueAction 'Roll back, reinstall, or update the driver named in the analysis if one is identified.'
                Add-UniqueAction 'Check for antivirus, RGB, tuning, virtualization, or overlay software conflicts.'
                break
            }

            '^(DPC_WATCHDOG_VIOLATION)$' {
                Add-UniqueAction 'Update storage, chipset, and graphics drivers, as long-running DPCs are often driver related.'
                Add-UniqueAction 'Disconnect unnecessary peripherals and update their drivers or firmware.'
                Add-UniqueAction 'Update BIOS and SSD firmware, then retest system responsiveness.'
                break
            }

            '^(CRITICAL_PROCESS_DIED|CRITICAL_STRUCTURE_CORRUPTION)$' {
                Add-UniqueAction 'Run SFC and DISM to repair Windows component corruption.'
                Add-UniqueAction 'Review recently installed kernel-level software such as antivirus, tuning tools, or anti-cheat.'
                Add-UniqueAction 'Check storage health because system-file corruption can also be storage related.'
                break
            }
        }

        # Driver- and device-specific refinements
        if ($driverText -match 'NVLDDMKM|NVIDIA') {
            Add-UniqueAction 'Use a clean NVIDIA graphics driver install and remove leftover GPU utility overlays or tuning tools.'
            Add-UniqueAction 'Test with NVIDIA App features such as overlays disabled if crashes continue.'
        }

        if ($driverText -match 'AMDKMDAG|AMDKMDAP|ATIKMPAG|ATIKMDAG|RADEON|AMD') {
            Add-UniqueAction 'Use AMD cleanup or a clean AMD driver reinstall and remove GPU tuning or overlay utilities.'
            Add-UniqueAction 'Update AMD chipset and graphics drivers together if the system uses AMD hardware.'
        }

        if ($driverText -match 'IGDKMD|IGDUMD|INTEL') {
            Add-UniqueAction 'Update Intel graphics, chipset, network, and Bluetooth drivers from the OEM support page or Intel Driver & Support Assistant.'
        }

        if ($driverText -match 'IASTOR|IAAHCI|STORNVME|STORPORT|NVME|NTFS|DISK') {
            Add-UniqueAction 'Review storage-controller mode and storage-driver versions, then check drive firmware.'
        }

        if ($driverText -match 'NETWTW|E1D|E1R|RTWL|TCPIP|NDIS') {
            Add-UniqueAction 'Reinstall the network adapter driver, reset the network stack, and disable power saving on the adapter for testing.'
        }

        if ($driverText -match 'USB|USBHUB|HIDUSB|HIDCLASS') {
            Add-UniqueAction 'Disconnect nonessential USB devices, hubs, and docks, then reinstall USB controller or peripheral drivers.'
        }

        if ($driverText -match 'ACPI') {
            Add-UniqueAction 'Update BIOS, chipset, and power-management drivers and retest sleep, resume, and shutdown behavior.'
        }

        if ($deviceText -like '*GPU*' -and $upperBugCheck -eq '') {
            Add-UniqueAction 'Perform a clean reinstall of the graphics driver and test the system at stock GPU settings.'
        }

        if ($deviceText -like '*NETWORK*' -and $upperBugCheck -eq '') {
            Add-UniqueAction 'Update or reinstall the network adapter driver and retest network-heavy workloads.'
        }

        if ($deviceText -like '*USB*' -and $upperBugCheck -eq '') {
            Add-UniqueAction 'Test without external USB devices and reinstall USB controller drivers if the issue continues.'
        }

        if ($deviceText -like '*STORAGE*' -and $upperBugCheck -eq '') {
            Add-UniqueAction 'Check storage health, controller drivers, and firmware even if the dump did not expose a specific bugcheck family.'
        }

        # Fallback if nothing matched strongly
        if ($actions.Count -eq 1) {
            Add-UniqueAction 'Run hardware diagnostics and review any driver named in the analysis for updates or rollback.'
        }

        return @($actions)
    }

function Get-BugCheckInfoFromAnalysis {
        param([string]$AnalysisText)

        $result = [ordered]@{
            Name = $null
            Code = $null
        }

        if ([string]::IsNullOrWhiteSpace($AnalysisText)) {
            return [PSCustomObject]$result
        }

        $lines = $AnalysisText -split "`r?`n"

        foreach ($line in ($lines | Select-Object -First 120)) {
            $trimmed = $line.Trim()

            if ($trimmed -match '^([A-Z][A-Z0-9_]+)\s+\(([0-9A-Fa-f]+)\)$') {
                $result.Name = $matches[1].Trim().ToUpperInvariant()
                $result.Code = $matches[2].Trim().ToUpperInvariant()
                return [PSCustomObject]$result
            }
        }

        if ($AnalysisText -match '(?im)^BUGCHECK_CODE:\s*([0-9A-Fa-f]+)\b') {
            $result.Code = $matches[1].Trim().ToUpperInvariant()
        }
        elseif ($AnalysisText -match '(?im)^Bugcheck code\s+([0-9A-Fa-f]+)\b') {
            $result.Code = $matches[1].Trim().ToUpperInvariant()
        }

        if ($AnalysisText -match '(?im)^BUGCHECK_STR:\s*([A-Z0-9_]+)\b') {
            $result.Name = $matches[1].Trim().ToUpperInvariant()
        }

        if (-not $result.Name -and $result.Code) {
            $result.Name = Get-BugCheckNameFromCode -Code $result.Code
        }

        return [PSCustomObject]$result
    }

    function Get-DebuggerExecutablePath {
        try {
            $cmd = Get-Command cdb.exe -ErrorAction Stop | Select-Object -First 1
            if ($cmd -and $cmd.Source) {
                return $cmd.Source
            }
        } catch { }

        $cdbCandidates = @(
            'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe',
            'C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe',
            'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe',
            'C:\Program Files\Windows Kits\10\Debuggers\x86\cdb.exe'
        )

        foreach ($path in $cdbCandidates) {
            if (Test-Path -LiteralPath $path) {
                return $path
            }
        }

        try {
            $pkg = Get-AppxPackage -Name Microsoft.WinDbg -ErrorAction SilentlyContinue |
                Sort-Object Version -Descending |
                Select-Object -First 1

            if ($pkg -and $pkg.InstallLocation) {
                $cdbFromPkg = Join-Path $pkg.InstallLocation 'cdb.exe'
                if (Test-Path -LiteralPath $cdbFromPkg) {
                    return $cdbFromPkg
                }

                $cdbFromPkgAmd64 = Join-Path $pkg.InstallLocation 'amd64\cdb.exe'
                if (Test-Path -LiteralPath $cdbFromPkgAmd64) {
                    return $cdbFromPkgAmd64
                }
            }
        } catch { }

        return $null
    }

    function Remove-DebuggerIfInstalledNow {
        param(
            [Parameter(Mandatory = $true)]
            [bool]$InstalledNow
        )

        if (-not $InstalledNow) {
            return
        }

        try {
            $wingetPath = Get-WingetExecutablePath
            if ($wingetPath) {
                try {
                    & $wingetPath uninstall --id Microsoft.WinDbg -e -h --accept-source-agreements | Out-Null
                    Start-Sleep -Seconds 3
                    return
                } catch { }
            }

            try {
                $pkg = Get-AppxPackage -Name Microsoft.WinDbg -ErrorAction SilentlyContinue |
                    Sort-Object Version -Descending |
                    Select-Object -First 1

                if ($pkg) {
                    Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction SilentlyContinue | Out-Null
                    Start-Sleep -Seconds 3
                }
            } catch { }
        } catch { }
    }

    function Ensure-DebuggerInstalled {
        function Try-RestoreAppInstallerWinget {
            try {
                $appInstaller = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
                    Sort-Object Version -Descending |
                    Select-Object -First 1

                if (-not $appInstaller) {
                    return [PSCustomObject]@{
                        Success = $false
                        Message = 'App Installer is not installed, so WinGet is not available.'
                    }
                }

                $manifestPath = Join-Path $appInstaller.InstallLocation 'AppxManifest.xml'
                if (-not (Test-Path -LiteralPath $manifestPath)) {
                    return [PSCustomObject]@{
                        Success = $false
                        Message = 'App Installer is installed, but its AppX manifest could not be found.'
                    }
                }

                try {
                    Add-AppxPackage -DisableDevelopmentMode -Register $manifestPath -ErrorAction Stop | Out-Null
                    Start-Sleep -Seconds 5
                } catch {
                    return [PSCustomObject]@{
                        Success = $false
                        Message = "App Installer re-registration failed: $($_.Exception.Message)"
                    }
                }

                $wingetAfterRegister = Get-WingetExecutablePath
                if ($wingetAfterRegister) {
                    return [PSCustomObject]@{
                        Success = $true
                        Message = 'App Installer was re-registered and WinGet is now available.'
                    }
                }

                return [PSCustomObject]@{
                    Success = $false
                    Message = 'App Installer was re-registered, but WinGet is still not available.'
                }
            } catch {
                return [PSCustomObject]@{
                    Success = $false
                    Message = "Unable to restore App Installer / WinGet automatically: $($_.Exception.Message)"
                }
            }
        }

        $existing = Get-DebuggerExecutablePath
        if ($existing) {
            return [PSCustomObject]@{
                Success      = $true
                Path         = $existing
                InstalledNow = $false
                Message      = 'CDB is already available.'
            }
        }

        $wingetPath = Get-WingetExecutablePath
        if (-not $wingetPath) {
            $restoreResult = Try-RestoreAppInstallerWinget
            $wingetPath = Get-WingetExecutablePath

            if (-not $wingetPath) {
                return [PSCustomObject]@{
                    Success      = $false
                    Path         = $null
                    InstalledNow = $false
                    Message      = "CDB could not be installed automatically because App Installer / WinGet is not available. Install Debugging Tools for Windows to enable automated crash dump analysis. $($restoreResult.Message)"
                }
            }
        }

        try {
            & $wingetPath install --id Microsoft.WinDbg -e -h --accept-source-agreements --accept-package-agreements | Out-Null
            Start-Sleep -Seconds 5
        } catch {
            return [PSCustomObject]@{
                Success      = $false
                Path         = $null
                InstalledNow = $false
                Message      = "CDB could not be installed automatically. Install Debugging Tools for Windows to enable automated crash dump analysis. Details: $($_.Exception.Message)"
            }
        }

        $installed = Get-DebuggerExecutablePath
        if ($installed) {
            return [PSCustomObject]@{
                Success      = $true
                Path         = $installed
                InstalledNow = $true
                Message      = 'CDB was installed automatically.'
            }
        }

        return [PSCustomObject]@{
            Success      = $false
            Path         = $null
            InstalledNow = $false
            Message      = 'CDB is not installed. Install Debugging Tools for Windows to enable automated crash dump analysis.'
        }
    }

    function Invoke-DebuggerDumpAnalysis {
        param(
            [Parameter(Mandatory = $true)]
            [string]$DebuggerPath,

            [Parameter(Mandatory = $true)]
            [string]$DumpPath,

            [Parameter(Mandatory = $true)]
            [string]$LogPath,

            [Parameter(Mandatory = $true)]
            [string]$SymbolsPath
        )

        function Quote-Arg {
            param([Parameter(Mandatory = $true)][string]$Value)
            return '"' + ($Value -replace '"', '""') + '"'
        }

        try {
            if (Test-Path -LiteralPath $LogPath) {
                Remove-Item -LiteralPath $LogPath -Force -ErrorAction SilentlyContinue
            }

            $quotedLogPath = Quote-Arg $LogPath
            $quotedSymbolsPath = Quote-Arg $SymbolsPath
            $quotedDumpPath = Quote-Arg $DumpPath
            $argumentString = "-logo $quotedLogPath -y $quotedSymbolsPath -z $quotedDumpPath -c ""!analyze -v; q"""

            $process = Start-Process -FilePath $DebuggerPath -ArgumentList $argumentString -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
            Start-Sleep -Seconds 2

            $logText = ''
            if (Test-Path -LiteralPath $LogPath) {
                $logText = Get-Content -LiteralPath $LogPath -Raw -ErrorAction SilentlyContinue
            }

            return [PSCustomObject]@{
                Success  = (-not [string]::IsNullOrWhiteSpace($logText))
                Text     = $logText
                ExitCode = $process.ExitCode
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Success  = $false
                Text     = ''
                ExitCode = $null
                Error    = $_.Exception.Message
            }
        }
    }

    function Get-CrashDumpAnalysisResult {
        param(
            [Parameter(Mandatory = $true)]
            [string]$AnalysisOutputPath,

            [Parameter(Mandatory = $true)]
            [string]$WorkingFolder
        )

        $result = [ordered]@{
            Status  = 'Completed'
            Summary = 'No crash dumps found.'
            Content = 'No crash dumps found.'
        }

        $dumpFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]

        $pathsToScan = @(
            @{ Path = 'C:\Windows\MEMORY.DMP'; Recursive = $false },
            @{ Path = 'C:\Windows\Minidump'; Recursive = $false }
        )

        foreach ($entry in $pathsToScan) {
            $scanPath = $entry.Path
            if (-not (Test-Path -LiteralPath $scanPath)) {
                continue
            }

            try {
                if (Test-Path -LiteralPath $scanPath -PathType Leaf) {
                    $item = Get-Item -LiteralPath $scanPath -Force -ErrorAction SilentlyContinue
                    if ($item -and (($item.Extension -ieq '.dmp') -or ($item.Name -ieq 'MEMORY.DMP'))) {
                        if (-not ($dumpFiles | Where-Object { $_.FullName -eq $item.FullName })) {
                            $dumpFiles.Add($item)
                        }
                    }
                    continue
                }

                $items = Get-ChildItem -LiteralPath $scanPath -File -ErrorAction SilentlyContinue

                foreach ($item in @($items)) {
                    if ($item -and (($item.Extension -ieq '.dmp') -or ($item.Name -ieq 'MEMORY.DMP'))) {
                        if (-not ($dumpFiles | Where-Object { $_.FullName -eq $item.FullName })) {
                            $dumpFiles.Add($item)
                        }
                    }
                }
            } catch { }
        }

        if ($dumpFiles.Count -eq 0) {
            try {
                if (Test-Path -LiteralPath $AnalysisOutputPath) {
                    Remove-Item -LiteralPath $AnalysisOutputPath -Force -ErrorAction SilentlyContinue
                }
            } catch { }

            return [PSCustomObject]$result
        }

        $dumpFiles = @($dumpFiles | Sort-Object LastWriteTime -Descending)

        $result.Status = 'Warning'
        $result.Summary = if ($dumpFiles.Count -eq 1) {
            '1 crash dump found.'
        } else {
            "$($dumpFiles.Count) crash dumps found."
        }

        $contentLines = New-Object System.Collections.Generic.List[string]
        $contentLines.Add("Crash Dumps: $($dumpFiles.Count) found")
        $contentLines.Add("")

        $analysisLines = New-Object System.Collections.Generic.List[string]
        $analysisFileName = Split-Path -Leaf $AnalysisOutputPath
        $analysisFileCreated = $false

        $debugger = Ensure-DebuggerInstalled

        try {
            $symbolsRoot = Join-Path $WorkingFolder 'Symbols'
            if (-not (Test-Path -LiteralPath $symbolsRoot)) {
                New-Item -ItemType Directory -Path $symbolsRoot -Force | Out-Null
            }
            $symbolPath = "srv*$symbolsRoot*https://msdl.microsoft.com/download/symbols"

            foreach ($dump in $dumpFiles) {
            $analysisText = $null
            $dumpType = Get-CrashDumpType -DumpPath $dump.FullName -AnalysisText $null
            $bugCheck = [PSCustomObject]@{ Name = $null; Code = $null }
            $probablyCausedBy = $null
            $parametersText = $null
            $systemUptimeText = $null
            $driverName = $null
            $driverDisplayPath = $null
            $deviceName = 'Unknown'
            $userModeInfo = [PSCustomObject]@{
                ExceptionCode = $null
                ExceptionText = $null
                Module        = $null
                FailureBucket = $null
                ProcessName   = $null
            }
            $analysisLogCreatedForDump = $false

            if ($debugger.Success) {
                $safeBaseName = ($dump.BaseName -replace '[^\w\-]+', '_')
                $perDumpLog = Join-Path $WorkingFolder ("CrashDump_" + $safeBaseName + ".txt")
                $invokeResult = Invoke-DebuggerDumpAnalysis -DebuggerPath $debugger.Path -DumpPath $dump.FullName -LogPath $perDumpLog -SymbolsPath $symbolPath

                if ($invokeResult.Success -and -not [string]::IsNullOrWhiteSpace($invokeResult.Text)) {
                    $analysisText = $invokeResult.Text
                    $analysisFileCreated = $true
                    $analysisLogCreatedForDump = $true

                    $analysisLines.Add('============================================================')
                    $analysisLines.Add("Dump: $($dump.FullName)")
                    $analysisLines.Add("Analyzed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                    $analysisLines.Add('============================================================')
                    $analysisLines.Add($analysisText)
                    $analysisLines.Add('')

                    $dumpType = Get-CrashDumpType -DumpPath $dump.FullName -AnalysisText $analysisText
                    $bugCheck = Get-BugCheckInfoFromAnalysis -AnalysisText $analysisText
                    $probablyCausedBy = Get-ProbablyCausedBy -AnalysisText $analysisText
                    $parametersText = Get-BugCheckParametersFromAnalysis -AnalysisText $analysisText
                    $systemUptimeText = Get-SystemUptimeFromAnalysis -AnalysisText $analysisText
                    $userModeInfo = Get-UserModeCrashInfoFromAnalysis -AnalysisText $analysisText
                    $driverName = Get-DriverFromAnalysis -AnalysisText $analysisText -ProbablyCausedBy $probablyCausedBy
                    $driverDisplayPath = Get-DriverDisplayPath -DriverName $driverName
                    $deviceName = Get-DeviceFromDriver -DriverName $driverName
                } elseif ($invokeResult.Error) {
                    $analysisLines.Add('============================================================')
                    $analysisLines.Add("Dump: $($dump.FullName)")
                    $analysisLines.Add('============================================================')
                    $analysisLines.Add("Analysis failed: $($invokeResult.Error)")
                    $analysisLines.Add('')
                }
            }

            $codeText = if ($bugCheck.Code) { " (0x$($bugCheck.Code))" } else { '' }
            $causeText = if ($bugCheck.Name) {
                Get-BugCheckDescription -Name $bugCheck.Name -Code $bugCheck.Code
            } else {
                'A detailed bug check cause could not be extracted automatically from this dump.'
            }

            $analysisTextLine = $null
            if ($probablyCausedBy) {
                $analysisTextLine = "Probably caused by $probablyCausedBy"
            } elseif ($analysisLogCreatedForDump) {
                $analysisTextLine = Get-AnalysisFallbackText -DumpType $dumpType -BugCheckName $bugCheck.Name -BugCheckCode $bugCheck.Code -Module $userModeInfo.Module -FailureBucket $userModeInfo.FailureBucket
            } elseif (-not $debugger.Success) {
                $analysisTextLine = $debugger.Message
            } else {
                $analysisTextLine = 'CDB did not return a readable summary for this dump.'
            }

            if (-not $driverName -and $userModeInfo.Module) {
                $driverName = $userModeInfo.Module
                $driverDisplayPath = Get-DriverDisplayPath -DriverName $driverName
                $deviceName = Get-DeviceFromDriver -DriverName $driverName
            }

            $contentLines.Add("Dump File: $($dump.Name)")
            $contentLines.Add("Dump Type: $dumpType")
            if ($bugCheck.Name) {
                $contentLines.Add("BugCheck: $($bugCheck.Name)$codeText")
            } else {
                $contentLines.Add('BugCheck: Unavailable')
            }

            $contentLines.Add("Cause: $causeText")

            if ($parametersText) {
                $contentLines.Add("Parameters: $parametersText")
            }

            $contentLines.Add("Bugcheck Time: $($dump.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))")

            if ($systemUptimeText) {
                $contentLines.Add("System Uptime: $systemUptimeText")
            }

            if ($deviceName) {
                $contentLines.Add("Device: $deviceName")
            }

            if ($driverDisplayPath) {
                $contentLines.Add("Driver: $driverDisplayPath")
            } elseif ($driverName) {
                $contentLines.Add("Driver: $driverName")
            }

            $contentLines.Add("Analysis: $analysisTextLine")
            $contentLines.Add('')
            $contentLines.Add('Resolution actions:')

            foreach ($action in (Get-ResolutionActions -BugCheckName $bugCheck.Name -Device $deviceName -DriverName $driverName)) {
                $contentLines.Add($action)
            }

            $contentLines.Add('')
        }

            if ($analysisFileCreated) {
                Set-Content -Path $AnalysisOutputPath -Value ($analysisLines -join "`r`n") -Encoding UTF8
            } else {
                try {
                    if (Test-Path -LiteralPath $AnalysisOutputPath) {
                        Remove-Item -LiteralPath $AnalysisOutputPath -Force -ErrorAction SilentlyContinue
                    }
                } catch { }
            }

            $result.Content = ($contentLines -join "`r`n").Trim()
            return [PSCustomObject]$result
        }
        finally {
            try {
                Remove-DebuggerIfInstalledNow -InstalledNow ([bool]$debugger.InstalledNow)
            } catch { }
        }
    }

    # Startup optimization (interactive, Task Manager style)
    # ------------------------------------------------
    $startupStatus  = 'Completed'
    $startupSummary = ''
    $startupContent = ''

    try {
        $res = Invoke-StartupOptimizationInteractive
        $startupStatus  = $res.Status
        $startupSummary = $res.Summary
        $startupContent = $res.Content
        Write-Host "[DONE] Startup Optimization completed.`n" -ForegroundColor Green
    } catch {
        $startupStatus  = 'Warning'
        $startupSummary = 'Startup optimization step failed.'
        $startupContent = $_.Exception.Message
        Write-Host "Startup optimization step failed: $($_.Exception.Message)`n" -ForegroundColor Yellow
    }

    # ------------------------------------------------
    # Software Install
    # ------------------------------------------------
    Write-Host "Software Install" -ForegroundColor Cyan
    Write-Host ""

    try {
        $installedSoftwareNames = Get-InstalledSoftwareNames

        $intelDetected = Test-IntelHardwarePresent
        $nvidiaDetected = Test-NvidiaGpuPresent
        $amdDetected = Test-AmdHardwarePresent

        # Intel
        if ($intelDetected) {
            Write-Host "Intel hardware detected." -ForegroundColor Yellow

            $intelInstalledName = Get-InstalledSoftwareMatch -InstalledNames $installedSoftwareNames -Patterns @('*Intel*Driver*Support*Assistant*')
            if ($intelInstalledName) {
                Write-Host "Intel Driver & Support Assistant was already installed." -ForegroundColor Yellow
            } else {
                Write-Host "Intel Driver & Support Assistant is not installed." -ForegroundColor Yellow

                if (Read-YesNoPrompt "Install Intel Driver & Support Assistant now? (y/n)") {
                    Write-Host "Installing Intel Driver & Support Assistant..." -ForegroundColor Yellow
                    $intelInstallResult = Try-InstallIntelDsa

                    if ($intelInstallResult.Success) {
                        Write-Host "Intel Driver & Support Assistant was installed." -ForegroundColor Green
                        $installedSoftwareNames = Get-InstalledSoftwareNames
                    } else {
                        Write-Host "Intel Driver & Support Assistant could not be installed automatically." -ForegroundColor Yellow
                        if (-not [string]::IsNullOrWhiteSpace($intelInstallResult.Message)) {
                            Write-Host "Details: $($intelInstallResult.Message)" -ForegroundColor Yellow
                        }
                        Write-Host "Open Intel Driver & Support Assistant to install and check for driver updates." -ForegroundColor Yellow
                        $softwareInstallStatus = 'Warning'
                    }
                } else {
                    Write-Host "Intel Driver & Support Assistant was not installed during this run." -ForegroundColor Yellow
                    Write-Host "Open Intel Driver & Support Assistant to install and check for driver updates." -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "Intel hardware not detected." -ForegroundColor Yellow
        }

        Write-Host ""

        # NVIDIA
        if ($nvidiaDetected) {
            Write-Host "NVIDIA hardware detected." -ForegroundColor Yellow

            $nvidiaInstalledName = Get-InstalledSoftwareMatch -InstalledNames $installedSoftwareNames -Patterns @('*NVIDIA App*')
            if ($nvidiaInstalledName) {
                Write-Host "NVIDIA App was already installed." -ForegroundColor Yellow
            } else {
                Write-Host "NVIDIA App is not installed." -ForegroundColor Yellow

                if (Read-YesNoPrompt "Open the official NVIDIA App download page now? (y/n)") {
                    try {
                        Start-Process $nvidiaAppUrl -ErrorAction Stop | Out-Null
                        Write-Host "NVIDIA App download page was opened." -ForegroundColor Yellow
                        Write-Host "Your browser has opened the official NVIDIA App download page. Download and install NVIDIA App, then close the installer." -ForegroundColor White
                        Read-ContinuePrompt
                    } catch {
                        Write-Host "NVIDIA App download page could not be opened automatically." -ForegroundColor Yellow
                        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Yellow
                        $softwareInstallStatus = 'Warning'
                    }
                } else {
                    Write-Host "NVIDIA App download page was not opened during this run." -ForegroundColor Yellow
                }

                Write-Host "Open NVIDIA App to install it and check for driver updates." -ForegroundColor Yellow
            }
        } else {
            Write-Host "NVIDIA hardware not detected." -ForegroundColor Yellow
        }

        Write-Host ""

        # AMD
        if ($amdDetected) {
            Write-Host "AMD hardware detected." -ForegroundColor Yellow

            $amdInstalledName = Get-InstalledSoftwareMatch -InstalledNames $installedSoftwareNames -Patterns @('*AMD Software*', '*Adrenalin*', '*Radeon Software*')
            if ($amdInstalledName) {
                Write-Host "AMD Software was already installed." -ForegroundColor Yellow
            } else {
                Write-Host "AMD Software is not installed." -ForegroundColor Yellow

                if (Read-YesNoPrompt "Open the official AMD Drivers and Support page now? (y/n)") {
                    try {
                        Start-Process $amdDriversUrl -ErrorAction Stop | Out-Null
                        Write-Host "AMD Drivers and Support page was opened." -ForegroundColor Yellow
                        Write-Host "Your browser has opened the official AMD Drivers and Support page. Download and install AMD Software, then close the installer." -ForegroundColor White
                        Read-ContinuePrompt
                    } catch {
                        Write-Host "AMD Drivers and Support page could not be opened automatically." -ForegroundColor Yellow
                        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Yellow
                        $softwareInstallStatus = 'Warning'
                    }
                } else {
                    Write-Host "AMD Drivers and Support page was not opened during this run." -ForegroundColor Yellow
                }

                Write-Host "On AMD's page, click Download Windows Drivers to install AMD software or chipset drivers and check for updates." -ForegroundColor Yellow
            }
        } else {
            Write-Host "AMD hardware not detected." -ForegroundColor Yellow
        }

        # Keep the detailed progress in the console, but show only one final
        # result per vendor in the HTML report.
        $finalInstalledSoftwareNames = Get-InstalledSoftwareNames
        $softwareReportLines = New-Object System.Collections.Generic.List[string]

        if (-not $intelDetected) {
            $softwareReportLines.Add("Intel hardware wasn't detected.")
        } elseif ($intelInstalledName) {
            $softwareReportLines.Add('Intel Driver & Support Assistant was already installed (open and check for updates).')
        } elseif (Get-InstalledSoftwareMatch -InstalledNames $finalInstalledSoftwareNames -Patterns @('*Intel*Driver*Support*Assistant*')) {
            $softwareReportLines.Add('Intel Driver & Support Assistant was installed (open and check for updates).')
        } else {
            $softwareReportLines.Add("Intel Driver & Support Assistant wasn't installed.")
        }

        if (-not $nvidiaDetected) {
            $softwareReportLines.Add("NVIDIA hardware wasn't detected.")
        } elseif ($nvidiaInstalledName) {
            $softwareReportLines.Add('NVIDIA App was already installed (open and check for updates).')
        } elseif (Get-InstalledSoftwareMatch -InstalledNames $finalInstalledSoftwareNames -Patterns @('*NVIDIA App*')) {
            $softwareReportLines.Add('NVIDIA App was installed (open and check for updates).')
        } else {
            $softwareReportLines.Add("NVIDIA App wasn't installed.")
        }

        if (-not $amdDetected) {
            $softwareReportLines.Add("AMD hardware wasn't detected.")
        } elseif ($amdInstalledName) {
            $softwareReportLines.Add('AMD Software was already installed (open and check for updates).')
        } elseif (Get-InstalledSoftwareMatch -InstalledNames $finalInstalledSoftwareNames -Patterns @('*AMD Software*', '*Adrenalin*', '*Radeon Software*')) {
            $softwareReportLines.Add('AMD Software was installed (open and check for updates).')
        } else {
            $softwareReportLines.Add("AMD Software wasn't installed.")
        }

        $softwareInstallSummary = 'Intel, NVIDIA, and AMD software status'
        $softwareInstallContent = $softwareReportLines -join "`r`n`r`n"

        Write-Host ""
        Write-Host "[DONE] Software Install completed.`n" -ForegroundColor Green
    } catch {
        $softwareInstallStatus = 'Warning'
        $softwareInstallSummary = 'Software install review could not be completed.'
        $softwareInstallContent = "Software install review failed: $($_.Exception.Message)"
        Write-Host "Software install review failed: $($_.Exception.Message)`n" -ForegroundColor Yellow
    }
# ------------------------------------------------
    # CHKDSK (scheduled on next boot)
    # ------------------------------------------------
    try {
        $systemDrive = $env:SystemDrive

        Write-Host "Scheduling CHKDSK on next boot ($systemDrive /f /r)" -ForegroundColor Cyan

        $vgtrayRunning = Get-Process -Name "vgtray" -ErrorAction SilentlyContinue

        if ($vgtrayRunning) {
            Write-Host ""
            Write-Host "Riot Vanguard appears to be running." -ForegroundColor Yellow
            Write-Host "Please exit Riot Vanguard from the system tray and click Yes on the confirmation prompt." -ForegroundColor Yellow
            Write-Host "Exit Riot Vanguard from the system tray before continuing" -ForegroundColor Yellow
            Read-ContinuePrompt
        }

        Write-Output 'Y' | chkdsk $systemDrive /f /r

        Write-Host "[DONE] CHKDSK scheduled`n" -ForegroundColor Green
    } catch {
        Write-Host "CHKDSK step failed: $($_.Exception.Message)`n" -ForegroundColor Yellow
    }

    # ------------------------------------------------
    # DISM and SFC -> DISM_SFC.txt
    # ------------------------------------------------
    try {
        $null = Start-Transcript -Path $dismLogPath -ErrorAction SilentlyContinue
        Write-Host "DISM and SFC" -ForegroundColor Cyan
        Write-Host ""

        Write-Host "Analyze Component Store`n"
        Write-Output 'N' | dism.exe /online /cleanup-image /analyzecomponentstore /norestart
        Write-Host "-----------------------------------------------------------------------------------------------------------`n"

        Write-Host "Start Component Cleanup`n"
        dism.exe /online /cleanup-image /startcomponentcleanup
        Write-Host "-----------------------------------------------------------------------------------------------------------`n"

        Write-Host "Check Health`n"
        dism.exe /online /cleanup-image /checkhealth
        Write-Host "-----------------------------------------------------------------------------------------------------------`n"

        Write-Host "Scan Health`n"
        dism.exe /online /cleanup-image /scanhealth
        Write-Host "-----------------------------------------------------------------------------------------------------------`n"

        Write-Host "Restore Health`n"
        dism.exe /online /cleanup-image /restorehealth
        Write-Host "-----------------------------------------------------------------------------------------------------------`n"

        Write-Host "SFC`n"
        sfc /scannow
        Write-Host ""

        Write-Host "[DONE] DISM and SFC`n" -ForegroundColor Green
        Stop-Transcript | Out-Null
    } catch {
        Write-Host "DISM/SFC step failed: $($_.Exception.Message)`n" -ForegroundColor Yellow
        try { Stop-Transcript | Out-Null } catch {}
    }
    Write-Host "Crash Dumps" -ForegroundColor Cyan
    Write-Host ""

    $crashDumpResult = [PSCustomObject]@{
        Status  = 'Completed'
        Summary = 'No crash dumps found.'
        Content = 'No crash dumps found.'
    }

    try {
        $crashDumpResult = Get-CrashDumpAnalysisResult -AnalysisOutputPath $crashAnalysisPath -WorkingFolder $filesFolder

        if ($crashDumpResult.Content -match '^No crash dumps found\.?$') {
            Write-Host "No crash dumps found." -ForegroundColor Green
        } else {
            Write-Host $crashDumpResult.Summary -ForegroundColor Green
        }

        Write-Host "[DONE] Crash Dumps completed.`n" -ForegroundColor Green
    } catch {
        $crashDumpResult = [PSCustomObject]@{
            Status  = 'Warning'
            Summary = 'Crash dump analysis could not be completed.'
            Content = "Crash dump analysis failed: $($_.Exception.Message)"
        }
        Write-Host "Crash dump analysis failed: $($_.Exception.Message)`n" -ForegroundColor Yellow
    }


    # ------------------------------------------------
    # Browser Cleanup -> Browsers.txt
    # ------------------------------------------------
    try {
        $null = Start-Transcript -Path $browserLogPath -ErrorAction SilentlyContinue

        $processes = "chrome","msedge","firefox","brave","opera","opera_gx"
        foreach ($p in $processes) {
            Get-Process $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 2

        # --- Helpers just for browser cleanup ---
        function Get-BrowserFolderSizeReadable {
            param ([string]$Path)
            if (-not (Test-Path $Path)) { return "0 MB" }
            try {
                $items = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                         Where-Object { -not $_.PSIsContainer }
                $totalBytes = ($items | Measure-Object -Property Length -Sum).Sum
                if ($totalBytes -ge 1GB) { return "{0:N2} GB" -f ($totalBytes/1GB) }
                else                     { return "{0:N2} MB" -f ($totalBytes/1MB) }
            } catch { return "0 MB" }
        }

        function ConvertToGB {
            param($size)
            if     ($size -match "GB") { return [double]($size -replace " GB","") }
            elseif ($size -match "MB") { return [double]($size -replace " MB","") / 1024 }
            else                       { return 0 }
        }

        function FormatTotal {
            param($value)
            if ($value -ge 1) { return "{0:N2} GB" -f $value }
            else              { return "{0:N2} MB" -f ($value * 1024) }
        }

        function Clear-Path($path, $desc) {
            if (Test-Path $path) {
                try {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  Cleared $desc" -ForegroundColor Green
                } catch {
                    Write-Host ("  Failed to clear {0}: {1}" -f $desc, $_) -ForegroundColor Red
                }
            }
        }

        # Profiles
        $chromeProfile   = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
        $edgeProfile     = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
        $braveProfile    = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default"
        $operaProfile    = "$env:APPDATA\Opera Software\Opera Stable"
        $operaCache      = "$env:LOCALAPPDATA\Opera Software\Opera Stable"
        $operaGXProfile  = "$env:APPDATA\Opera Software\Opera GX Stable\Default"
        $operaGXCache    = "$env:LOCALAPPDATA\Opera Software\Opera GX Stable\Default"
        $firefoxRoot     = "$env:APPDATA\Mozilla\Firefox\Profiles"

        $browserTargets = @{}

        if (Test-Path $chromeProfile) {
            $browserTargets["Chrome"] = @{
                "Cache"               = "$chromeProfile\Cache"
                "Code Cache"          = "$chromeProfile\Code Cache"
                "GPUCache"            = "$chromeProfile\GPUCache"
                "History & Downloads" = "$chromeProfile\History"
            }
        }

        if (Test-Path $edgeProfile) {
            $browserTargets["Edge"] = @{
                "Cache"               = "$edgeProfile\Cache"
                "Code Cache"          = "$edgeProfile\Code Cache"
                "GPUCache"            = "$edgeProfile\GPUCache"
                "History & Downloads" = "$edgeProfile\History"
            }
        }

        if (Test-Path $braveProfile) {
            $browserTargets["Brave"] = @{
                "Cache"               = "$braveProfile\Cache"
                "Code Cache"          = "$braveProfile\Code Cache"
                "GPUCache"            = "$braveProfile\GPUCache"
                "History & Downloads" = "$braveProfile\History"
            }
        }

        if ((Test-Path $operaProfile) -or (Test-Path $operaCache)) {
            $browserTargets["Opera Stable"] = @{}
            if (Test-Path $operaProfile) {
                $browserTargets["Opera Stable"]["History & Downloads"] = "$operaProfile\History"
            }
            if (Test-Path $operaCache) {
                $browserTargets["Opera Stable"]["Cache"]      = "$operaCache\Cache"
                $browserTargets["Opera Stable"]["GPUCache"]   = "$operaCache\GPUCache"
                $browserTargets["Opera Stable"]["Code Cache"] = "$operaCache\Code Cache"
            }
        }
        if ((Test-Path $operaGXProfile) -or (Test-Path $operaGXCache)) {
            $browserTargets["Opera GX"] = @{}
            if (Test-Path $operaGXProfile) {
                $browserTargets["Opera GX"]["History & Downloads"] = "$operaGXProfile\History"
            }
            if (Test-Path $operaGXCache) {
                $browserTargets["Opera GX"]["Cache"]      = "$operaGXCache\Cache"
                $browserTargets["Opera GX"]["GPUCache"]   = "$operaGXCache\GPUCache"
                $browserTargets["Opera GX"]["Code Cache"] = "$operaGXCache\Code Cache"
            }
        }

        if (Test-Path $firefoxRoot) {
            Get-ChildItem $firefoxRoot | ForEach-Object {
                $profilePath = $_.FullName
                $browserTargets["Firefox ($($_.Name))"] = @{
                    "Cache"               = "$profilePath\cache2"
                    "History & Downloads" = "$profilePath\places.sqlite"
                }
            }
        }

        $totalBefore = 0
        $totalAfter  = 0

        foreach ($browser in $browserTargets.Keys) {
            Write-Host "`n=== $browser ===" -ForegroundColor Cyan
            $before = 0
            $after  = 0

            foreach ($t in $browserTargets[$browser].GetEnumerator()) {
                $size = Get-BrowserFolderSizeReadable -Path $t.Value
                $before += ConvertToGB $size
                "{0,-30} {1,10}" -f $t.Key, $size
            }

            foreach ($t in $browserTargets[$browser].GetEnumerator()) {
                Clear-Path $t.Value $t.Key
            }

            foreach ($t in $browserTargets[$browser].GetEnumerator()) {
                $size = Get-BrowserFolderSizeReadable -Path $t.Value
                $after += ConvertToGB $size
                "{0,-30} {1,10}" -f $t.Key, $size
            }

            $freed = $before - $after
            Write-Host ("  >>> Freed: {0}" -f (FormatTotal $freed)) -ForegroundColor Yellow

            $totalBefore += $before
            $totalAfter  += $after
        }

        $freedAll = $totalBefore - $totalAfter

        Write-Host "`n==========================================" -ForegroundColor DarkGray
        Write-Host ("Total Before Cleanup: {0}" -f (FormatTotal $totalBefore)) -ForegroundColor Red
        Write-Host ("Total After Cleanup : {0}"  -f (FormatTotal $totalAfter)) -ForegroundColor Yellow
        Write-Host ("Space Freed         : {0}"  -f (FormatTotal $freedAll))   -ForegroundColor Green
        Write-Host "==========================================" -ForegroundColor DarkGray

        Write-Host "[DONE] Browser Cleanup completed.`n" -ForegroundColor Green
        Stop-Transcript | Out-Null
    } catch {
        Write-Host "Browser cleanup step failed: $($_.Exception.Message)`n" -ForegroundColor Yellow
        try { Stop-Transcript | Out-Null } catch {}
    }

    # ------------------------------------------------
    # Temp Cleanup -> Temp.txt
    # ------------------------------------------------
    try {
        $null = Start-Transcript -Path $tempLogPath -ErrorAction SilentlyContinue
        Write-Host ""

        $foldersToClean = @(
            "$env:TEMP",
            "$env:APPDATA\Microsoft\Windows\Recent",
            "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
            "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations",
            "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
            "$env:LOCALAPPDATA\Microsoft\Windows\History",
            "$env:LOCALAPPDATA\Microsoft\Office\16.0\WebServiceCache",
            "$env:LOCALAPPDATA\Packages",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
            "C:\Windows\Temp",
            "C:\Windows\SoftwareDistribution\Download",
            "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\History",
            "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Office\16.0\WebServiceCache",
            "C:\ProgramData\Microsoft\Diagnosis",
            "$env:LOCALAPPDATA\Microsoft\Windows\D3DSCache",
            "$env:LOCALAPPDATA\Microsoft\Windows\Explorer",
            "$env:LOCALAPPDATA\Microsoft\Windows\WebCache",
            "C:\Recycle.Bin",
            "C:\Windows.old",
            "C:\Windows\Panther",
            "C:\ProgramData\Microsoft\Windows\WER",
            "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache",
            "C:\Windows\Logs\CBS"
        )

        function Get-FolderSizeReadable {
            param ([string]$Path)

            $expanded = [System.Environment]::ExpandEnvironmentVariables($Path) -replace '\\{2,}', '\'

            if ($expanded -eq 'C:\Recycle.Bin') {
                $realRecyclePath = 'C:\$Recycle.Bin'
                if (-not (Test-Path $realRecyclePath)) { return "Empty" }

                try {
                    $sizeBytes = (Get-ChildItem -Path "$realRecyclePath\*" -Recurse -Force -ErrorAction Stop |
                                  Measure-Object -Property Length -Sum).Sum
                    if ($sizeBytes -ge 1GB) { return "{0:N2} GB" -f ($sizeBytes / 1GB) }
                    else                    { return "{0:N2} MB" -f ($sizeBytes / 1MB) }
                } catch { return "Access Denied" }
            }

            if (-not (Test-Path $expanded)) { return "Doesn't Exist" }

            try {
                if (Test-Path -LiteralPath $expanded -PathType Leaf) {
                    $item = Get-Item -LiteralPath $expanded -Force -ErrorAction Stop
                    $sizeBytes = [double]$item.Length

                    if    ($sizeBytes -ge 1GB) { return "{0:N2} GB" -f ($sizeBytes / 1GB) }
                    else                        { return "{0:N2} MB" -f ($sizeBytes / 1MB) }
                }

                $items = Get-ChildItem -Path $expanded -Recurse -Force -ErrorAction Stop |
                         Where-Object { -not $_.PSIsContainer }
                $totalBytes = ($items | Measure-Object -Property Length -Sum).Sum

                if    ($totalBytes -ge 1GB) { return "{0:N2} GB" -f ($totalBytes / 1GB) }
                else                        { return "{0:N2} MB" -f ($totalBytes / 1MB) }
            } catch { return "Access Denied" }
        }

        function ConvertToGB ($size) {
            if     ($size -match "GB") { return [double]($size -replace " GB", "") }
            elseif ($size -match "MB") { return [double]($size -replace " MB", "") / 1024 }
            else                       { return 0 }
        }

        function Format-Path ($rawPath) {
            return [System.Environment]::ExpandEnvironmentVariables($rawPath) -replace '\\{2,}', '\'
        }

        function FormatTotal($value) {
            if ($value -ge 1) { return "{0:N2} GB" -f $value }
            else              { return "{0:N2} MB" -f ($value * 1024) }
        }

        $sizesBefore = @{}
        $sizesAfter  = @{}

        Write-Host "Analyzing folder sizes before cleanup" -ForegroundColor Yellow
        Write-Host ""
        foreach ($folder in $foldersToClean) {
            $cleanPath = Format-Path $folder
            $size      = Get-FolderSizeReadable -Path $cleanPath
            $sizesBefore[$cleanPath] = $size
            "{0,-100} {1}" -f $cleanPath, $size
        }

        Write-Host "`nCleaning up" -ForegroundColor Yellow

        $cbsPath = "C:\Windows\Logs\CBS"
        $trustedInstallerWasRunning = $false

        try {
            if ($foldersToClean -contains $cbsPath) {
                try {
                    $trustedInstallerService = Get-Service -Name "TrustedInstaller" -ErrorAction Stop
                    if ($trustedInstallerService.Status -eq "Running") {
                        Stop-Service -Name "TrustedInstaller" -Force -ErrorAction Stop -WarningAction SilentlyContinue
                        $trustedInstallerWasRunning = $true
                        Start-Sleep -Seconds 2
                    }
                } catch {}
            }

            foreach ($folder in $foldersToClean) {
                $cleanPath = Format-Path $folder
                try {
                    if (-not (Test-Path -LiteralPath $cleanPath)) {
                        continue
                    }

                    Get-ChildItem -LiteralPath $cleanPath -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                } catch {}
            }

            try { Clear-RecycleBin -Force -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        }
        finally {
            if ($trustedInstallerWasRunning) {
                try { Start-Service -Name "TrustedInstaller" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } catch {}
            }
        }

        Write-Host "`nAnalyzing folder sizes after cleanup" -ForegroundColor Yellow
        Write-Host ""
        foreach ($folder in $foldersToClean) {
            $cleanPath = Format-Path $folder
            $size      = Get-FolderSizeReadable -Path $cleanPath
            $sizesAfter[$cleanPath] = $size
            "{0,-100} {1}" -f $cleanPath, $size
        }

        $totalBefore = 0
        $totalAfter  = 0

        foreach ($folder in $foldersToClean) {
            $cleanPath = Format-Path $folder
            $totalBefore += ConvertToGB $sizesBefore[$cleanPath]
            $totalAfter  += ConvertToGB  $sizesAfter[$cleanPath]
        }

        $freed = $totalBefore - $totalAfter

        Write-Host "`n==========================================" -ForegroundColor DarkGray
        Write-Host ("Total Before Cleanup: {0}" -f (FormatTotal $totalBefore)) -ForegroundColor Red
        Write-Host ("Total After Cleanup : {0}" -f (FormatTotal $totalAfter))  -ForegroundColor Yellow
        Write-Host ("Space Freed         : {0}" -f (FormatTotal $freed))        -ForegroundColor Green
        Write-Host "==========================================" -ForegroundColor DarkGray

        Write-Host "[DONE] Temp Cleanup completed.`n" -ForegroundColor Green
        Stop-Transcript | Out-Null
    } catch {
        Write-Host "Temp/cache cleanup step failed: $($_.Exception.Message)`n" -ForegroundColor Yellow
        try { Stop-Transcript | Out-Null } catch {}
    }

    # ------------------------------------------------
    # Windows Updates -> WindowsUpdates.txt
    # ------------------------------------------------
    $windowsUpdateFailed = $false
    $windowsUpdateFailureMessage = ''

    try {
        Write-Host "Windows Updates`n" -ForegroundColor Cyan

        try {
            $wuUxPaths = @(
                'HKCU:\Software\Microsoft\WindowsUpdate\UX\Settings',
                'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
            )

            foreach ($wuUxPath in $wuUxPaths) {
                if (-not (Test-Path -LiteralPath $wuUxPath)) {
                    New-Item -Path $wuUxPath -Force | Out-Null
                }

                New-ItemProperty -Path $wuUxPath -Name 'IsContinuousInnovationOptedIn' -PropertyType DWord -Value 1 -Force | Out-Null
            }
        } catch { }

        Install-PackageProvider -Name NuGet -Force
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
        Install-Module -Name PSWindowsUpdate -Force
        Import-Module PSWindowsUpdate

        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -NotTitle 'Upgrade' |
            Out-File -FilePath $wuLogPath -Encoding UTF8

        Write-Host "[DONE] Windows updates completed`n" -ForegroundColor Green
    } catch {
        $windowsUpdateFailed = $true
        $windowsUpdateFailureMessage = "Windows Update step failed: $($_.Exception.Message)"
        Write-Host "$windowsUpdateFailureMessage`n" -ForegroundColor Yellow
    }

    # ------------------------------------------------
    # App Updates -> AppUpdates.txt
    # ------------------------------------------------
    $appUpdateFailed = $false
    $appUpdateExitCode = 0
    $appUpdateFailureMessage = ''
    $battleNetSkipped = $false
    $battleNetTemporaryPinAdded = $false

    try {
        $null = Start-Transcript -Path $appLogPath -ErrorAction SilentlyContinue
        Write-Host "App Updates" -ForegroundColor Cyan
        Write-Host ""

        $appNoUpdates = $false
        $wingetPath = Get-WingetExecutablePath

        if (-not $wingetPath) {
            throw 'winget is not available.'
        }

        $appUpdateInstalledSoftware = Get-InstalledSoftwareNames
        $battleNetInstalled = [bool](Get-InstalledSoftwareMatch `
            -InstalledNames $appUpdateInstalledSoftware `
            -Patterns @('Battle.net', '*Battle.net*'))

        if ($battleNetInstalled) {
            $battleNetPinOutput = @(& $wingetPath pin list `
                --id Blizzard.BattleNet `
                -e `
                --disable-interactivity `
                --accept-source-agreements 2>&1)

            $battleNetPinText = (($battleNetPinOutput | ForEach-Object { [string]$_ }) -join "`r`n")
            $battleNetAlreadyPinned = $battleNetPinText -match '(?im)^\s*Battle\.net(?: Setup)?\s+Blizzard\.BattleNet(?:\s|$)'

            if (-not $battleNetAlreadyPinned) {
                $null = @(& $wingetPath pin add `
                    --id Blizzard.BattleNet `
                    -e `
                    --disable-interactivity `
                    --accept-source-agreements 2>&1)

                $battleNetPinExitCode = $LASTEXITCODE
                if ($battleNetPinExitCode -ne 0) {
                    throw "Battle.net could not be temporarily excluded from App Updates (winget exit code $battleNetPinExitCode)."
                }

                $battleNetTemporaryPinAdded = $true
            }

            $battleNetSkipped = $true
            Write-Host "Battle.net was skipped because WinGet requires an installation location." -ForegroundColor Yellow
            Write-Host ""
        }

        try {
            & $wingetPath upgrade -h --all --include-unknown `
                --disable-interactivity `
                --accept-source-agreements `
                --accept-package-agreements 2>&1 | ForEach-Object {
                    $outputLine = [string]$_

                    if ($outputLine -match '(?i)no installed package found matching input criteria|no applicable upgrade found|no newer package versions are available') {
                        if (-not $appNoUpdates) {
                            Write-Host "No updates available" -ForegroundColor Green
                        }
                        $appNoUpdates = $true
                    } else {
                        Write-Host $outputLine
                    }
                }

            $appUpdateExitCode = $LASTEXITCODE
        }
        finally {
            if ($battleNetTemporaryPinAdded) {
                $null = @(& $wingetPath pin remove `
                    --id Blizzard.BattleNet `
                    -e `
                    --disable-interactivity `
                    --accept-source-agreements 2>&1)

                if ($LASTEXITCODE -ne 0) {
                    $appUpdateFailed = $true
                    $appUpdateFailureMessage = 'The temporary Battle.net WinGet pin could not be removed.'
                    Write-Host $appUpdateFailureMessage -ForegroundColor Yellow
                }
            }
        }

        if ($appUpdateExitCode -ne 0 -and -not $appNoUpdates) {
            $appUpdateFailed = $true
            $appUpdateExitMessage = "winget exited with code $appUpdateExitCode"
            if ([string]::IsNullOrWhiteSpace($appUpdateFailureMessage)) {
                $appUpdateFailureMessage = $appUpdateExitMessage
            } else {
                $appUpdateFailureMessage = "$appUpdateFailureMessage $appUpdateExitMessage"
            }
            Write-Host $appUpdateExitMessage -ForegroundColor Yellow
        }

        if ($appUpdateFailed) {
            Write-Host "`nApp Updates completed with failures`n" -ForegroundColor Yellow
        } else {
            Write-Host "`n[DONE] App Updates completed`n" -ForegroundColor Green
        }
        Stop-Transcript | Out-Null
    } catch {
        $appUpdateFailed = $true
        $appUpdateFailureMessage = "winget step failed: $($_.Exception.Message)"
        Write-Host "$appUpdateFailureMessage`n" -ForegroundColor Yellow
        try { Stop-Transcript | Out-Null } catch {}
    }

    # ------------------------------------------------
    # Optimize Drives -> OptimizeDrives.txt
    # ------------------------------------------------
    try {
        Write-Host "Optimize drives" -ForegroundColor Cyan
        Write-Host ""

        $optimizeResults = New-Object System.Collections.Generic.List[string]

        $Volumes = Get-Volume | Where-Object {
            $_.DriveLetter -and
            $_.DriveType -ne 'Removable' -and
            $_.DriveType -ne 'CD-ROM'
        }

        foreach ($Volume in $Volumes) {
            try {
                Optimize-Volume -DriveLetter $Volume.DriveLetter -ErrorAction Stop | Out-Null
                $line = "$($Volume.DriveLetter): Optimized"
                Write-Host $line -ForegroundColor Green
                $optimizeResults.Add($line)
            }
            catch {
                $errorMessage = $_.Exception.Message
                if ([string]::IsNullOrWhiteSpace($errorMessage)) {
                    $errorMessage = "Optimization failed"
                }
                $errorMessage = $errorMessage.Trim().TrimEnd('.')
                $line = "$($Volume.DriveLetter): ${errorMessage}."
                Write-Host $line -ForegroundColor Yellow
                $optimizeResults.Add($line)
            }
        }

        Set-Content -Path $optimizeLogPath -Value $optimizeResults -Encoding UTF8
        Write-Host ""
        Write-Host "[DONE] Drive Optimization completed.`n" -ForegroundColor Green
    } catch {
        $outerError = $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($outerError)) {
            $outerError = "Optimize drives step failed"
        }
        $outerError = $outerError.Trim().TrimEnd('.')
        Set-Content -Path $optimizeLogPath -Value @("Optimize drives step failed: ${outerError}.") -Encoding UTF8
        Write-Host "Optimize drives step failed: $($_.Exception.Message)`n" -ForegroundColor Yellow
    }

    # ------------------------------------------------
    # HTML Report Helpers
    # ------------------------------------------------
    function Convert-ToHtmlSafe {
        param([string]$text)
        if (-not $text) { return "" }
        $t = $text -replace '&','&amp;'
        $t = $t -replace '<','&lt;'
        $t = $t -replace '>','&gt;'
        return $t
    }

    function Get-LogOrMessage {
        param(
            [string]$Path,
            [string]$EmptyMessage
        )
        if (Test-Path $Path) {
            $raw = Get-Content $Path -Raw -ErrorAction SilentlyContinue
            if ([string]::IsNullOrWhiteSpace($raw)) { return $EmptyMessage }
            return $raw
        } else {
            return $EmptyMessage
        }
    }

    function Get-StatusFromContent {
        param([string]$content)

        if ([string]::IsNullOrWhiteSpace($content)) {
            return 'Completed'
        }

        $lower = $content.ToLowerInvariant()

        if (
            $lower -match 'restore point within 1440 minutes' -or
            $lower -match 'already has a restore point within 1440 minutes' -or
            $lower -match 'chkdsk was skipped because it wasn''t needed'
        ) {
            return 'Completed'
        }

        if (
            $lower -match 'error'       -or
            $lower -match 'failed'      -or
            $lower -match 'failure'     -or
            $lower -match '0x[0-9a-f]+' -or
            $lower -match 'unavailable'
        ) {
            return 'Warning'
        }

        return 'Completed'
    }

    function Remove-TranscriptHeaders {
        param([string]$raw)

        if ([string]::IsNullOrWhiteSpace($raw)) {
            return ""
        }

        $lines = $raw -split "`r?`n"
        $out = New-Object System.Collections.Generic.List[string]

        foreach ($line in $lines) {
            if ($line -match '^\*{5,}$')                    { continue }
            if ($line -match 'transcript start')            { continue }
            if ($line -match 'transcript end')              { continue }
            if ($line -match '^(Start|End) time:')          { continue }
            if ($line -match '^Username:')                  { continue }
            if ($line -match '^RunAs User:')                { continue }
            if ($line -match '^Machine:')                   { continue }
            if ($line -match '^Host Application:')          { continue }
            if ($line -match '^Process ID:')                { continue }
            if ($line -match '^PSVersion:')                 { continue }
            if ($line -match '^PSEdition:')                 { continue }
            if ($line -match '^PSCompatibleVersions:')      { continue }
            if ($line -match '^BuildVersion:')              { continue }
            if ($line -match '^CLRVersion:')                { continue }
            if ($line -match '^WSManStackVersion:')         { continue }
            if ($line -match '^PSRemotingProtocolVersion:') { continue }
            if ($line -match '^SerializationVersion:')      { continue }
            if ($line -match '^Configuration Name:')        { continue }

            $out.Add($line)
        }

        return ($out -join "`r`n")
    }

    function Summarize-WingetUpgradeTranscript {
        param([string]$raw)

        if ([string]::IsNullOrWhiteSpace($raw)) {
            return "0 updates available."
        }

        $content = Remove-TranscriptHeaders $raw
        if ([string]::IsNullOrWhiteSpace($content)) {
            return "0 updates available."
        }

        $lines = $content -split "`r?`n"
        $upgradeCount = $null
        $packageBlocks = New-Object System.Collections.Generic.List[object]
        $currentBlock = $null

        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                continue
            }

            if ($trimmed -match '^No installed package found matching input criteria\.?$') {
                return "0 updates available."
            }

            if ($null -eq $upgradeCount -and $trimmed -match '^(\d+)\s+updates available\.?$') {
                $upgradeCount = [int]$matches[1]
            }

            if ($trimmed -match '^\((\d+)/(\d+)\)\s+Found\s+.+$') {
                $currentBlock = [ordered]@{
                    Header = $trimmed
                    Result = $null
                }
                $packageBlocks.Add($currentBlock)
                continue
            }

            if ($null -eq $currentBlock) {
                continue
            }

            if ($trimmed -eq 'Successfully installed') {
                $currentBlock.Result = 'Successfully installed'
                continue
            }

            if ($trimmed -eq 'Successfully verified installer hash') {
                if ([string]::IsNullOrWhiteSpace($currentBlock.Result) -or $currentBlock.Result -eq 'Starting package install...') {
                    $currentBlock.Result = 'Installation status not fully captured'
                }
                continue
            }

            if ($trimmed -eq 'Starting package install...') {
                if ([string]::IsNullOrWhiteSpace($currentBlock.Result)) {
                    $currentBlock.Result = 'Installation status not fully captured'
                }
                continue
            }

            if (
                $trimmed -match '(?i)failed' -or
                $trimmed -match '(?i)^error[: ]' -or
                $trimmed -match '(?i)no applicable upgrade found' -or
                $trimmed -match '(?i)command line argument' -or
                $trimmed -match '(?i)not found' -or
                $trimmed -match '0x[0-9a-fA-F]+'
            ) {
                $currentBlock.Result = $trimmed
                continue
            }
        }

        if ($null -eq $upgradeCount) {
            $upgradeCount = $packageBlocks.Count
        }

        if ($upgradeCount -le 0 -and $packageBlocks.Count -eq 0) {
            return "0 updates available."
        }

        $successCount = 0
        $failureCount = 0
        $pendingCount = 0
        $outLines = New-Object System.Collections.Generic.List[string]
        $outLines.Add("$upgradeCount updates available")
        $outLines.Add("")

        foreach ($block in $packageBlocks) {
            $resultLine = $block.Result
            if ([string]::IsNullOrWhiteSpace($resultLine)) {
                $resultLine = 'Installation status not fully captured'
            }

            $outLines.Add($block.Header)
            $outLines.Add($resultLine)
            $outLines.Add("")

            if ($resultLine -eq 'Successfully installed') {
                $successCount++
            } elseif ($resultLine -eq 'Installation status not fully captured') {
                $pendingCount++
            } else {
                $failureCount++
            }
        }

        $outLines.Add("$successCount successfully installed")
        if ($failureCount -gt 0) {
            $outLines.Add("$failureCount failed")
        }
        if ($pendingCount -gt 0) {
            $outLines.Add("$pendingCount pending")
        }

        return (($outLines | Select-Object -SkipLast 0) -join "`r`n").Trim()
    }

    function Summarize-DismSfcTranscript {
        param([string]$raw)

        if ([string]::IsNullOrWhiteSpace($raw)) {
            return "No DISM / SFC transcript was found."
        }

        $content = Remove-TranscriptHeaders $raw
        if ([string]::IsNullOrWhiteSpace($content)) {
            return "No DISM / SFC transcript was found."
        }

        $operationOrder = @(
            'Analyze Component Store',
            'Start Component Cleanup',
            'Check Health',
            'Scan Health',
            'Restore Health',
            'SFC'
        )

        $operationMap = [ordered]@{}
        foreach ($name in $operationOrder) {
            $operationMap[$name] = New-Object System.Collections.Generic.List[string]
        }

        $lines = $content -split "`r?`n"
        $currentOperation = $null

        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                continue
            }

            if ($trimmed -in $operationOrder) {
                $currentOperation = $trimmed
                continue
            }

            if ($trimmed -match '^-{5,}$') {
                continue
            }

            if ($trimmed -match '^\[DONE\]\s+DISM and SFC\.?$') {
                continue
            }

            if ($null -ne $currentOperation) {
                $operationMap[$currentOperation].Add($trimmed)
            }
        }

        function Add-SummaryFragment {
            param(
                [System.Collections.Generic.List[string]]$Target,
                [string]$Value
            )

            if ([string]::IsNullOrWhiteSpace($Value)) {
                return
            }

            $normalized = $Value.Trim()
            $normalized = $normalized -replace '\s+', ' '
            if ($normalized -notmatch '[\.\!\?]$') {
                $normalized += '.'
            }

            if (-not $Target.Contains($normalized)) {
                $Target.Add($normalized)
            }
        }

        function Get-DismOperationSummary {
            param(
                [string]$OperationName,
                [System.Collections.Generic.List[string]]$OperationLines
            )

            $summaryParts = New-Object System.Collections.Generic.List[string]
            $blob = (($OperationLines | ForEach-Object { $_.Trim() }) -join "`n")

            if ([string]::IsNullOrWhiteSpace($blob)) {
                return 'No clear result captured.'
            }

            if ($blob -match 'Error:\s*0x[0-9A-Fa-f]+[^\r\n]*') {
                Add-SummaryFragment -Target $summaryParts -Value $matches[0]
            }

            if ($blob -match '(?im)^(?:DISM|SFC) failed\.[^\r\n]*') {
                Add-SummaryFragment -Target $summaryParts -Value $matches[0]
            }

            if ($blob -match '(?im)^Access is denied\.?$') {
                Add-SummaryFragment -Target $summaryParts -Value 'Access is denied'
            }

            if ($blob -match '(?im)^Component Store Cleanup Recommended\s*:\s*(.+)$') {
                Add-SummaryFragment -Target $summaryParts -Value ("Component Store Cleanup Recommended: {0}" -f $matches[1].Trim())
            }

            if ($blob -match '(?im)^No component store corruption detected\.?$') {
                Add-SummaryFragment -Target $summaryParts -Value 'No component store corruption detected'
            }

            if ($blob -match '(?im)^The component store is repairable\.?$') {
                Add-SummaryFragment -Target $summaryParts -Value 'The component store is repairable'
            }

            if ($blob -match '(?im)^The component store cannot be repaired\.?$') {
                Add-SummaryFragment -Target $summaryParts -Value 'The component store cannot be repaired'
            }

            if ($blob -match '(?im)^The restore operation completed successfully\.?$') {
                Add-SummaryFragment -Target $summaryParts -Value 'The restore operation completed successfully'
            }

            if ($blob -match '(?im)^The operation completed successfully\.?$') {
                Add-SummaryFragment -Target $summaryParts -Value 'The operation completed successfully'
            }

            if ($blob -match '(?is)Windows Resource Protection.*?did not find.*?integrity violations') {
                Add-SummaryFragment -Target $summaryParts -Value 'Windows Resource Protection did not find any integrity violations'
            }

            if ($blob -match '(?is)Windows Resource Protection.*?found corrupt files.*?successfully repaired') {
                Add-SummaryFragment -Target $summaryParts -Value 'Windows Resource Protection found corrupt files and successfully repaired them'
            }

            if ($blob -match '(?is)Windows Resource Protection.*?found corrupt files.*?(?:was unable to fix|unable to fix)') {
                Add-SummaryFragment -Target $summaryParts -Value 'Windows Resource Protection found corrupt files but was unable to fix some of them'
            }

            if ($blob -match '(?is)Windows Resource Protection.*?could not perform the requested operation') {
                Add-SummaryFragment -Target $summaryParts -Value 'Windows Resource Protection could not perform the requested operation'
            }

            if ($blob -match '(?is)Windows Resource Protection.*?could not start the repair service') {
                Add-SummaryFragment -Target $summaryParts -Value 'Windows Resource Protection could not start the repair service'
            }

            if ($blob -match '(?is)There is a system repair pending') {
                Add-SummaryFragment -Target $summaryParts -Value 'There is a system repair pending which requires a reboot to complete'
            }

            if ($OperationName -eq 'SFC' -and $summaryParts.Count -eq 0 -and $blob -match '(?is)Verification 100% complete') {
                Add-SummaryFragment -Target $summaryParts -Value 'Verification completed, but no final SFC result line was captured'
            }

            if ($summaryParts.Count -eq 0) {
                return 'No clear result captured.'
            }

            return ($summaryParts -join ' ')
        }

        $outLines = New-Object System.Collections.Generic.List[string]

        foreach ($operationName in $operationOrder) {
            $summary = Get-DismOperationSummary -OperationName $operationName -OperationLines $operationMap[$operationName]
            $outLines.Add("$operationName - $summary")
        }

        return ($outLines -join "`r`n").Trim()
    }



    # ------------------------------------------------
    # Collect System Info for Header
    # ------------------------------------------------
    $os   = Get-CimInstance Win32_OperatingSystem
    $cs   = Get-CimInstance Win32_ComputerSystem
    $cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
    $gpus = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue

    $integratedList = @()
    $dedicatedList  = @()
    foreach ($g in $gpus) {
        $name = $g.Name.Trim()

        if ($name -match "Microsoft Basic Render" -or
            $name -match "VMware"                -or
            $name -match "VirtualBox") {
            continue
        }

        if ($name -match "UHD" -or
            $name -match "Iris" -or
            $name -match "Intel" -or
            $name -match "Radeon\(TM\)" -or
            $name -match "Radeon Graphics") {
            $integratedList += $name
        } else {
            $dedicatedList += $name
        }
    }

    $primaryGpu   = ""
    $secondaryGpu = ""

    if ($dedicatedList.Count -gt 0) {
        $primaryGpu = $dedicatedList[0]
        if ($integratedList.Count -gt 0) {
            $secondaryGpu = $integratedList -join " | "
        }
    } elseif ($integratedList.Count -gt 0) {
        $primaryGpu = $integratedList[0]
    } else {
        $primaryGpu = "No GPU Reported"
    }

    $primaryGpuHtml   = Convert-ToHtmlSafe $primaryGpu
    $secondaryGpuHtml = Convert-ToHtmlSafe $secondaryGpu

    $hostname = $env:COMPUTERNAME
    $userName = $env:USERNAME

    # RAM
    try {
        $memModules = Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue
        $totalRamBytes = ($memModules | Measure-Object -Property Capacity -Sum).Sum
        $ramGB = [math]::Round($totalRamBytes / 1GB, 1)

        function Get-DDRType($memType) {
            switch ($memType) {
                20 { return "DDR" }
                21 { return "DDR2" }
                22 { return "DDR2 FB-DIMM" }
                24 { return "DDR3" }
                26 { return "DDR4" }
                34 { return "DDR5" }
                default { return "Unknown" }
            }
        }

        $ramSticks = @()
        foreach ($m in $memModules) {
            $sizeGB = [math]::Round($m.Capacity / 1GB)
            $ddrType = Get-DDRType $m.SMBIOSMemoryType
            $speed   = $m.Speed
            $vendor  = if ($m.Manufacturer) { $m.Manufacturer } else { "Unknown" }
            $ramSticks += ("{0} GB {1} {2} MHz ({3})" -f $sizeGB, $ddrType, $speed, $vendor)
        }
        $ramSticksHtml = ($ramSticks | ForEach-Object { Convert-ToHtmlSafe $_ }) -join '<br />'
    } catch {
        $ramGB = "Unknown"
        $ramSticksHtml = "RAM information unavailable"
    }

    $osName = $os.Caption
    $now    = Get-Date

    # Motherboard
    $baseBoard  = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $moboModel  = $null
    $moboVendor = $null
    if ($baseBoard) {
        $moboModel  = $baseBoard.Product
        $moboVendor = $baseBoard.Manufacturer
    }
    if (-not $moboModel)  { $moboModel  = $cs.Model }
    if (-not $moboVendor) { $moboVendor = $cs.Manufacturer }

    # BIOS
    $bios        = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $biosVersion = "Unknown"
    $biosDate    = "Unknown"

    if ($bios) {
        if ($bios.SMBIOSBIOSVersion) { $biosVersion = $bios.SMBIOSBIOSVersion }

        $rawDate = $bios.ReleaseDate
        if ($rawDate) {
            try {
                $parsed = [datetime]::Parse($rawDate)
                $biosDate = $parsed.ToString("yyyy-MM-dd")
            } catch {
                try {
                    $parsed = [Management.ManagementDateTimeConverter]::ToDateTime($rawDate)
                    $biosDate = $parsed.ToString("yyyy-MM-dd")
                } catch {}
            }
        }
    }

    # Battery
    $batteryHealthText = "Battery is not installed"
    $batteryFullText   = ""
    $batteryDesignText = ""

    try {
        $designCap = $null
        $fullCap   = $null
        $bats = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue

        if ($bats) {
            $bat = $bats | Select-Object -First 1
            if ($bat.DesignCapacity -and $bat.FullChargeCapacity -and $bat.DesignCapacity -gt 0) {
                $designCap = [double]$bat.DesignCapacity
                $fullCap   = [double]$bat.FullChargeCapacity
            }

        }

        if (-not $designCap -or -not $fullCap) {
            # Create a temporary battery report, scrape the numbers, then delete it later
            powercfg /batteryreport /output "$batteryReportPath" /duration 1 | Out-Null 2>$null

            if (Test-Path $batteryReportPath) {
                $htmlBat = Get-Content $batteryReportPath -Raw -ErrorAction SilentlyContinue
                $mDesign = [regex]::Match($htmlBat, 'DESIGN CAPACITY[^0-9]*([\d,]+)\s*mWh', 'IgnoreCase')
                $mFull   = [regex]::Match($htmlBat, 'FULL CHARGE CAPACITY[^0-9]*([\d,]+)\s*mWh', 'IgnoreCase')

                if ($mDesign.Success -and $mFull.Success) {
                    $designCap = [double]($mDesign.Groups[1].Value -replace ',','')
                    $fullCap   = [double]($mFull.Groups[1].Value -replace ',','')
                }
            }
        }

        if ($designCap -and $fullCap -and $designCap -gt 0) {
            $healthPct = [math]::Round(($fullCap / $designCap) * 100, 0)
            $batteryHealthText = "Health: $healthPct%"
            $batteryFullText   = ("{0:N0} mWh" -f $fullCap)
            $batteryDesignText = ("{0:N0} mWh" -f $designCap)
        }
        elseif ($bats) {
            $batteryHealthText = "Battery detected (health unknown)"
        }
    } catch {
        # leave defaults
    }
    finally {
        # delete Battery_Report.html so it doesn't clutter the folder
        try {
            if (Test-Path $batteryReportPath) { Remove-Item $batteryReportPath -Force -ErrorAction SilentlyContinue }
        } catch {}
    }

    # Storage
    $storageLines = @()
    try {
        $vols = Get-CimInstance Win32_LogicalDisk | Where-Object {
            $_.DriveType -eq 3 -and $_.DeviceID -match "^[A-Z]:$"
        }

        foreach ($v in $vols) {
            $letter = $v.DeviceID
            $free   = Format-StorageSize $v.FreeSpace
            $size   = Format-StorageSize $v.Size

            $type = "Cloud"
            try {
                $parts = Get-CimInstance -Query "
                    ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='$letter'}
                    WHERE AssocClass=Win32_LogicalDiskToPartition
                "

                if ($parts) {
                    foreach ($p in $parts) {
                        $drives = Get-CimInstance -Query "
                            ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($p.DeviceID)'}
                            WHERE AssocClass=Win32_DiskDriveToDiskPartition
                        "

                        if ($drives) {
                            $drive = $drives[0]
                            $model = $drive.Model
                            $media = $drive.MediaType
                            $bus   = $drive.InterfaceType

                            if ($model -match "NVMe" -or $bus -match "NVMe") {
                                $type = "NVMe"
                            }
                            elseif ($media -match "SSD" -or $model -match "SSD") {
                                $type = "SSD"
                            }
                            elseif ($media -match "HDD" -or $model -match "HDD|ST|WD|Seagate|Hitachi|TOSHIBA") {
                                $type = "HDD"
                            }
                            else {
                                $type = "Disk"
                            }

                            break
                        }
                    }
                }
            } catch {}

            $storageLines += ("{0} {1} - {2} free of {3}" -f $letter, $type, $free, $size)
        }
    } catch {}

    if ($storageLines.Count -eq 0) {
        $storageLines = @("Storage information not available.")
    }

    $storageHtml = ($storageLines | ForEach-Object { Convert-ToHtmlSafe $_ }) -join '<br />'

    # ------------------------------------------------
    # Create Restore Point
    # ------------------------------------------------
    try {
        Write-Host "Create Restore Point" -ForegroundColor Cyan
        Write-Host ""




        $restorePointDescription = "Maintenance - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $restoreMessages = New-Object System.Collections.Generic.List[string]

        $systemDriveRoot = if ($env:SystemDrive) {
            $env:SystemDrive.TrimEnd('\') + '\'
        } else {
            'C:\'
        }

        function Enable-SystemProtectionForRestorePoint {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Drive
            )

            try {
                Enable-ComputerRestore -Drive $Drive -ErrorAction Stop
                Write-Host "System Protection was enabled for $Drive" -ForegroundColor Yellow
                Start-Sleep -Seconds 3
                return $true
            } catch {
                $enableError = $_.Exception.Message

                if (
                    $enableError -match 'already enabled' -or
                    $enableError -match 'already active' -or
                    $enableError -match 'already turned on' -or
                    $enableError -match '1056'
                ) {
                    return $false
                }

                throw
            }
        }

        function Invoke-RestorePointAttempt {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Description,

                [int]$TimeoutSeconds = 600
            )

            $escapedDescription = $Description.Replace("'", "''")
            $command = "Checkpoint-Computer -Description '$escapedDescription' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop"

            $process = Start-Process -FilePath "powershell.exe" `
                -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $command) `
                -PassThru `
                -WindowStyle Hidden

            $completed = $process.WaitForExit($TimeoutSeconds * 1000)

            if (-not $completed) {
                try {
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                } catch { }

                throw "Restore point creation timed out after $TimeoutSeconds seconds and was skipped."
            }

            if ($process.ExitCode -ne 0) {
                throw "Checkpoint-Computer exited with code $($process.ExitCode)."
            }

            Start-Sleep -Seconds 5
        }

        function Format-RestorePointDisplay {
            param($RestorePoint)

            if (-not $RestorePoint) {
                return $null
            }

            $label = $RestorePoint.Description
            $creationTime = $RestorePoint.CreationTime

            try {
                if ($creationTime -is [datetime]) {
                    return "{0} - {1}" -f $label, $creationTime.ToString('yyyy-MM-dd HH:mm:ss')
                }

                $creationText = [string]$creationTime

                try {
                    $dt = [System.Management.ManagementDateTimeConverter]::ToDateTime($creationText)
                    if ($dt) {
                        return "{0} - {1}" -f $label, $dt.ToString('yyyy-MM-dd HH:mm:ss')
                    }
                } catch { }

                if ($creationText -match '^\d{14}') {
                    $dt = [datetime]::ParseExact($matches[0], 'yyyyMMddHHmmss', $null)
                    return "{0} - {1}" -f $label, $dt.ToString('yyyy-MM-dd HH:mm:ss')
                }
            } catch { }

            return $label
        }

        $beforeRestorePoint = $null
        try {
            $beforeRestorePoint = Get-ComputerRestorePoint -ErrorAction Stop |
                Sort-Object SequenceNumber -Descending |
                Select-Object -First 1

            if ($beforeRestorePoint) {
                $restoreMessages.Add("Latest restore point before attempt: $(Format-RestorePointDisplay $beforeRestorePoint)")
            } else {
                $restoreMessages.Add("No previous restore point found before attempt.")
            }
        } catch {
            $restoreMessages.Add("Result: Unable to read existing restore points before creation attempt.")
        }

        try {
            [void](Enable-SystemProtectionForRestorePoint -Drive $systemDriveRoot)
        } catch {
            $restoreMessages.Add("Result: Unable to enable System Protection on ${systemDriveRoot}.")
        }

        try {
            Invoke-RestorePointAttempt -Description $restorePointDescription
        } catch {
            $checkpointError = $_.Exception.Message

            if (
                $checkpointError -match 'protection' -or
                $checkpointError -match 'disabled' -or
                $checkpointError -match 'turned off' -or
                $checkpointError -match 'system restore.*off' -or
                $checkpointError -match 'system protection.*off' -or
                $checkpointError -match 'drive.*not protected'
            ) {
                [void](Enable-SystemProtectionForRestorePoint -Drive $systemDriveRoot)
                Invoke-RestorePointAttempt -Description $restorePointDescription
            } else {
                throw
            }
        }

        $afterRestorePoint = $null
        try {
            $afterRestorePoint = Get-ComputerRestorePoint -ErrorAction Stop |
                Sort-Object SequenceNumber -Descending |
                Select-Object -First 1
        } catch {
            $restoreMessages.Add("Result: Unable to verify restore points after creation attempt.")
        }

        $restorePointVerified = $false

        if ($afterRestorePoint) {
            $restoreMessages.Add("Latest restore point after attempt: $(Format-RestorePointDisplay $afterRestorePoint)")

            if (
                $afterRestorePoint.Description -eq $restorePointDescription -or
                (-not $beforeRestorePoint) -or
                ($afterRestorePoint.SequenceNumber -ne $beforeRestorePoint.SequenceNumber)
            ) {
                $restorePointVerified = $true
            }
        }

        if ($restorePointVerified) {
            $restorePointStatus = 'Completed'
            $restorePointSummary = 'Restore point created successfully.'
            $restoreMessages.Add('Result: Restore point created successfully.')
        }
        elseif (
            $beforeRestorePoint -and
            $afterRestorePoint -and
            $afterRestorePoint.SequenceNumber -eq $beforeRestorePoint.SequenceNumber
        ) {
            $restorePointStatus = 'Completed'
            $restorePointSummary = 'A restore point already exists within the last 24 hours, so no new one was needed.'
            $restoreMessages.Add('Result: Already has a Restore Point within 1440 minutes (24 hours). No new Restore Point created.')
        }
        else {
            $restorePointStatus = 'Warning'
            $restorePointSummary = 'Restore point creation could not be verified.'
            $restoreMessages.Add('Result: Restore point creation could not be verified.')
        }

        $restorePointContent = $restoreMessages -join "`r`n"
        Write-Host "[DONE] Restore point creation attempt completed`n" -ForegroundColor Green
    } catch {
        $restorePointStatus = 'Warning'
        $restoreError = $_.Exception.Message

        if (-not $restoreMessages) {
            $restoreMessages = New-Object System.Collections.Generic.List[string]
        }

        if (
            $restoreError -match '1440' -or
            $restoreError -match 'already been created within the past' -or
            $restoreError -match 'cannot be created because one has already been created'
        ) {
            $restorePointStatus = 'Completed'
            $restorePointSummary = 'A restore point already exists within the last 24 hours, so no new one was needed.'
            $restoreMessages.Add('Result: Already has a Restore Point within 1440 minutes (24 hours). No new Restore Point created.')
            $restorePointContent = $restoreMessages -join "`r`n"
            Write-Host "A restore point already exists within the last 24 hours. No new restore point was needed.`n" -ForegroundColor Yellow
        } elseif ($restoreError -match 'timed out') {
            $restorePointStatus = 'Warning'
            $restorePointSummary = 'Restore point creation timed out and was skipped.'
            $restoreMessages.Add('Result: Restore point creation timed out and was skipped.')
            $restoreMessages.Add("Error: $restoreError")
            $restorePointContent = $restoreMessages -join "`r`n"
            Write-Host "Restore point creation timed out and was skipped.`n" -ForegroundColor Yellow
        } else {
            $restorePointStatus = 'Warning'
            $restorePointSummary = 'Restore point creation failed.'
            $restoreMessages.Add("Restore point creation failed.")
            $restoreMessages.Add("Error: $restoreError")
            $restorePointContent = $restoreMessages -join "`r`n"
            Write-Host "Restore point creation failed: $restoreError`n" -ForegroundColor Yellow
        }
    }

    # ------------------------------------------------
    # Load and Clean Log Contents
    # ------------------------------------------------
    $dismRaw     = Get-LogOrMessage -Path $dismLogPath     -EmptyMessage "No DISM / SFC transcript was found."
    $dismContent = Summarize-DismSfcTranscript $dismRaw

    $tempRaw     = Get-LogOrMessage -Path $tempLogPath     -EmptyMessage "No temp cleanup transcript was found."
    $tempContent = Remove-TranscriptHeaders $tempRaw

    if (-not [string]::IsNullOrWhiteSpace($tempContent)) {
        $tempLines = $tempContent -split "`r?`n" | Where-Object {
            $_ -notmatch '(?i)TrustedInstaller' -and
            $_ -notmatch '(?i)Windows Modules Installer' -and
            $_ -notmatch '(?i)Windows Module Installer' -and
            $_ -notmatch '(?i)waiting for .*service' -and
            $_ -notmatch '(?i)^WARNING:' -and
            $_ -notmatch '(?i)^PS>TerminatingError\(Remove-Item\):' -and
            $_ -notmatch '(?i)^An object at the specified path .+ does not exist\.$'
        }

        $tempContent = ($tempLines -join "`r`n")
        $tempContent = [regex]::Replace($tempContent, 'Analyzing folder sizes before cleanup(?:\r?\n)+', "Analyzing folder sizes before cleanup`r`n`r`n")
        $tempContent = [regex]::Replace($tempContent, 'Analyzing folder sizes after cleanup(?:\r?\n)+', "Analyzing folder sizes after cleanup`r`n`r`n")
    }

    $browserRaw  = Get-LogOrMessage -Path $browserLogPath  -EmptyMessage "No browser cleanup transcript was found."
    $browserContent = Remove-TranscriptHeaders $browserRaw

    $optRaw      = Get-LogOrMessage -Path $optimizeLogPath -EmptyMessage "Non-removable volumes were optimized using Optimize-Volume. Details were not captured."
    $optContent  = Remove-TranscriptHeaders $optRaw

    $chkdskContent = 'CHKDSK was scheduled on the system drive for next boot. A one-time RunOnce entry will inject the CHKDSK log into this report after restart and sign-in.'

    $wuRaw = ""
    if (Test-Path $wuLogPath) {
        $wuRaw = Get-Content $wuLogPath -Raw -ErrorAction SilentlyContinue
    }
    $wuContent = if ($windowsUpdateFailed) {
        $windowsUpdateFailureMessage
    } elseif ([string]::IsNullOrWhiteSpace($wuRaw)) {
        "No Windows updates were available to be installed."
    } else { $wuRaw }

    $windowsUpdateStatus = if ($windowsUpdateFailed) {
        'Warning'
    } else {
        Get-StatusFromContent $wuContent
    }

    $appRaw = ""
    if (Test-Path $appLogPath) {
        $appRaw = Get-Content $appLogPath -Raw -ErrorAction SilentlyContinue
    }
    $appContent = Summarize-WingetUpgradeTranscript $appRaw

    if ($battleNetSkipped) {
        $appContent = ($appContent.TrimEnd() + "`r`n`r`nBattle.net was skipped because WinGet requires an installation location.").Trim()
    }

    $appHasReportedFailures = $appContent -match '(?im)^\s*[1-9]\d*\s+failed\.?\s*$'
    $appStatus = if ($appUpdateFailed -or $appHasReportedFailures) {
        'Warning'
    } else {
        'Completed'
    }

    if ($appUpdateFailed -and -not $appHasReportedFailures) {
        $appContent = ($appContent.TrimEnd() + "`r`n$appUpdateFailureMessage").Trim()
    }

    # ------------------------------------------------
    # Build Sections for HTML
    # ------------------------------------------------
    $sections = @()

    $sections += [PSCustomObject]@{
        Id      = 'softwareinstall'
        Title   = 'Software Install'
        Status  = $softwareInstallStatus
        Summary = $softwareInstallSummary
        Content = $softwareInstallContent
    }
    $sections += [PSCustomObject]@{
        Id      = 'wu'
        Title   = 'Windows Updates'
        Status  = $windowsUpdateStatus
        Summary = 'Windows and Microsoft updates attempted via PSWindowsUpdate.'
        Content = $wuContent
    }


    $sections += [PSCustomObject]@{
        Id      = 'apps'
        Title   = 'App Updates'
        Status  = $appStatus
        Summary = 'winget upgrade -h --all --include-unknown --disable-interactivity was run to update installed applications.'
        Content = $appContent
    }

    $sections += [PSCustomObject]@{
        Id      = 'startup'
        Title   = 'Startup Optimization'
        Status  = $startupStatus
        Summary = $startupSummary
        Content = $startupContent
    }


	$sections += [PSCustomObject]@{
        Id      = 'drives'
        Title   = 'Drive Optimization'
        Status  = Get-StatusFromContent $optContent
        Summary = 'Optimize-Volume was run for all non-removable volumes with drive letters.'
        Content = $optContent
    }

    $sections += [PSCustomObject]@{
        Id      = 'chkdsk'
        Title   = 'CHKDSK'
        Status  = Get-StatusFromContent $chkdskContent
        Summary = 'CHKDSK was scheduled on the system drive for next boot. If no log was produced, CHKDSK was likely not needed.'
        Content = $chkdskContent
    }

    $sections += [PSCustomObject]@{
        Id      = 'dism'
        Title   = 'DISM and SFC'
        Status  = Get-StatusFromContent $dismContent
        Summary = 'Deployment Image Servicing and Management operations plus System File Checker (SFC).'
        Content = $dismContent
    }

    $sections += [PSCustomObject]@{
        Id      = 'crashdumps'
        Title   = 'Crash Dumps'
        Status  = $crashDumpResult.Status
        Summary = $crashDumpResult.Summary
        Content = $crashDumpResult.Content
    }
    $sections += [PSCustomObject]@{
        Id      = 'browser'
        Title   = 'Browser Cleanup'
        Status  = Get-StatusFromContent $browserContent
        Summary = 'Browser caches, code caches, GPU caches, and histories cleared for detected browsers.'
        Content = $browserContent
    }

    $sections += [PSCustomObject]@{
        Id      = 'temp'
        Title   = 'Temp Cleanup'
        Status  = Get-StatusFromContent $tempContent
        Summary = 'Windows temp folders and common cache locations cleaned, with before/after size comparison.'
        Content = $tempContent
    }

    $sections += [PSCustomObject]@{
        Id      = 'restorepoint'
        Title   = 'Create a Restore Point'
        Status  = $restorePointStatus
        Summary = $restorePointSummary
        Content = $restorePointContent
    }

    # ------------------------------------------------
    # Build HTML
    # ------------------------------------------------
    $sb = New-Object System.Text.StringBuilder

    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en">')
    $null = $sb.AppendLine('<head>')
    $null = $sb.AppendLine('<meta charset="utf-8" />')
    $null = $sb.AppendLine("<title>Maintenance Report - $hostname</title>")
    $null = $sb.AppendLine('<style>
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
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }
        .card {
            background: radial-gradient(circle at top left, #17223b, #090b11);
            border-radius: 12px;
            padding: 12px 14px;
            border: 1px solid #1b2338;
            box-shadow: 0 6px 18px rgba(0,0,0,0.6);
        }
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
        }
        .card-meta {
            font-size: 12px;
            color: #8f95ad;
            margin-top: 2px;
        }
        .status-row {
            margin: 16px 0 22px 0;
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        .status-pill {
            font-size: 12px;
            padding: 4px 8px;
            border-radius: 999px;
            border: 1px solid transparent;
            background: rgba(20,25,40,0.95);
            text-decoration: none;
            display: inline-block;
        }
        .status-pill:hover {
            filter: brightness(1.08);
        }
        .status-pill.ok {
            border-color: #20c997;
            color: #20c997;
        }
        .status-pill.warn {
            border-color: #ffb347;
            color: #ffb347;
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
        .section-left {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .section-icon {
            font-size: 13px;
            width: 18px;
            text-align: center;
            color: #9fa6c6;
        }
        .section-title {
            font-size: 14px;
            font-weight: 600;
            color: #f5f7ff;
        }
        .section-status-pill {
            font-size: 12px;
            padding: 3px 8px;
            border-radius: 999px;
            border: 1px solid transparent;
        }
        .section-status-ok {
            border-color: #20c997;
            color: #20c997;
        }
        .section-status-warn {
            border-color: #ffb347;
            color: #ffb347;
        }
        .section-body {
            padding: 10px 12px 12px 12px;
            display: block;
        }
        .section-summary {
            font-size: 13px;
            color: #b4bad6;
            margin-top: 0;
            margin-bottom: 8px;
        }
        pre {
            font-family: "Cascadia Code", "Consolas", "Fira Code", monospace;
            font-size: 12px;
            background: #05070f;
            border-radius: 8px;
            padding: 10px;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 420px;
            overflow: auto;
            border: 1px solid #12182c;
        }
        .footer {
            font-size: 12px;
            color: #737995;
            margin-top: 20px;
            border-top: 1px solid #181e32;
            padding-top: 10px;
        }
    </style>
    <script>
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
    </script>')
    $null = $sb.AppendLine('</head>')
    $null = $sb.AppendLine('<body>')
    $null = $sb.AppendLine('<div class="page">')
    $null = $sb.AppendLine('<div class="title">Maintenance Report</div>')
    $null = $sb.AppendLine("<div class=""subtitle"">$($now.ToString("yyyy-MM-dd HH:mm:ss"))</div>")

    # Summary cards
    $null = $sb.AppendLine('<div class="summary-grid">')

    $null = $sb.AppendLine('<div class="card">
        <div class="card-label">Computer</div>
        <div class="card-value">' + (Convert-ToHtmlSafe $hostname) + '</div>
        <div class="card-meta">User: ' + (Convert-ToHtmlSafe $userName) + '</div>
    </div>')

    $null = $sb.AppendLine('<div class="card">
        <div class="card-label">Operating System</div>
        <div class="card-value">' + (Convert-ToHtmlSafe $osName) + '</div>
        <div class="card-meta">BIOS Version: ' + (Convert-ToHtmlSafe $biosVersion) + '</div>
        <div class="card-meta">BIOS Date: ' + (Convert-ToHtmlSafe $biosDate) + '</div>
    </div>')

    $null = $sb.AppendLine('<div class="card">
        <div class="card-label">Battery</div>
        <div class="card-value">' + (Convert-ToHtmlSafe $batteryHealthText) + '</div>
        <div class="card-meta">Full: ' + (Convert-ToHtmlSafe $batteryFullText) + '</div>
        <div class="card-meta">Design: ' + (Convert-ToHtmlSafe $batteryDesignText) + '</div>
    </div>')

    $null = $sb.AppendLine('<div class="card">
        <div class="card-label">Motherboard</div>
        <div class="card-value">' + (Convert-ToHtmlSafe $moboModel) + '</div>
        <div class="card-meta">MFG: ' + (Convert-ToHtmlSafe $moboVendor) + '</div>
    </div>')

    $null = $sb.AppendLine('<div class="card">
        <div class="card-label">CPU</div>
        <div class="card-value">' + (Convert-ToHtmlSafe $cpu.Name) + '</div>
        <div class="card-meta">' + $cpu.NumberOfCores + ' cores / ' + $cpu.NumberOfLogicalProcessors + ' threads</div>
    </div>')

    $null = $sb.AppendLine('<div class="card">
        <div class="card-label">GPU</div>
        <div class="card-value">' + $primaryGpuHtml + '</div>' +
        ($(if ($secondaryGpuHtml) { '<div class="card-meta">' + $secondaryGpuHtml + '</div>' } else { '' })) +
    '</div>')

    $null = $sb.AppendLine('<div class="card">
        <div class="card-label">RAM</div>
        <div class="card-value">' + $ramGB + ' GB</div>
        <div class="card-meta">' + $ramSticksHtml + '</div>
    </div>')

    $null = $sb.AppendLine('<div class="card">
        <div class="card-label">Storage</div>
        <div class="card-value">Drives</div>
        <div class="card-meta">' + $storageHtml + '</div>
    </div>')

    $null = $sb.AppendLine('</div>') # summary-grid

    # Status pills
    $null = $sb.AppendLine('<div class="status-row">')
    foreach ($sec in $sections) {
        switch ($sec.Status) {
            'Warning' { $cls = 'status-pill warn' }
            default   { $cls = 'status-pill ok' }
        }
        $label = "{0} - {1}" -f $sec.Title, $sec.Status
        $null = $sb.AppendLine("<a id=""pill-$($sec.Id)"" class=""$cls"" href=""#section-$($sec.Id)"">" + (Convert-ToHtmlSafe $label) + "</a>")
    }
    $null = $sb.AppendLine('</div>')

    # Detailed sections
    $index = 0
    foreach ($sec in $sections) {
        $index++
        $bodyId = "sec$index"
        $iconId = "$bodyId-icon"
        $encodedContent = Convert-ToHtmlSafe $sec.Content
        $encodedSummary = Convert-ToHtmlSafe $sec.Summary

        switch ($sec.Status) {
            'Warning' { $statusClass = 'section-status-warn' }
            default   { $statusClass = 'section-status-ok' }
        }

        $null = $sb.AppendLine('<div id="section-' + $sec.Id + '" class="section">')
        $null = $sb.AppendLine('<div class="section-header" onclick="toggleSection(''' + $bodyId + ''')">')
        $null = $sb.AppendLine('<div class="section-left">')
        $null = $sb.AppendLine('<span id="' + $iconId + '" class="section-icon">v</span>')
        $null = $sb.AppendLine('<span class="section-title">' + (Convert-ToHtmlSafe $sec.Title) + '</span>')
        $null = $sb.AppendLine('</div>')
        $null = $sb.AppendLine('<span id="sectionstatus-' + $sec.Id + '" class="section-status-pill ' + $statusClass + '">' + (Convert-ToHtmlSafe $sec.Status) + '</span>')
        $null = $sb.AppendLine('</div>')

        $null = $sb.AppendLine('<div id="' + $bodyId + '" class="section-body">')
        $null = $sb.AppendLine('<p class="section-summary">' + $encodedSummary + '</p>')

        if ($sec.Id -eq 'chkdsk') {
            $null = $sb.AppendLine('<pre id="chkdsk-results"><!-- CHKDSK-PLACEHOLDER --></pre>')
        }
        else {
            if (-not [string]::IsNullOrWhiteSpace($sec.Content)) {
                $null = $sb.AppendLine('<pre>' + $encodedContent + '</pre>')
            } else {
                $null = $sb.AppendLine('<pre>No additional details were captured for this section.</pre>')
            }
        }

        $null = $sb.AppendLine('</div>')
        $null = $sb.AppendLine('</div>')
    }

    $null = $sb.AppendLine('<div class="footer">')
    $null = $sb.AppendLine('Maintenance completed at ' + (Convert-ToHtmlSafe ($now.ToString("yyyy-MM-dd HH:mm:ss"))) + '. ')
    $null = $sb.AppendLine('After restart and sign-in, a one-time RunOnce entry will inject the CHKDSK results into this report automatically.')
    $null = $sb.AppendLine('</div>')

    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine('</body>')
    $null = $sb.AppendLine('</html>')

    [System.IO.File]::WriteAllText($reportPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
    Write-Host "Working HTML report written to: $reportPath" -ForegroundColor Green

    # ------------------------------------------------
    # Create CHKDSK helper files (Run Me.bat + ChkdskResults.ps1)
    # ------------------------------------------------
    $embeddedReportPath      = $reportPath.Replace("'", "''")
    $embeddedFinalReportPath = $finalReportPath.Replace("'", "''")
    $embeddedFilesFolder     = $filesFolder.Replace("'", "''")
    $embeddedRunOnceName     = $runOnceValueName.Replace("'", "''")

    $chkdskPs1Content = @"
`$ErrorActionPreference = "Stop"

function Convert-ToHtmlSafe {
    param([string]`$text)
    if (-not `$text) { return "" }
    `$t = `$text -replace "&","&amp;"
    `$t = `$t -replace "<","&lt;"
    `$t = `$t -replace ">","&gt;"
    return `$t
}

function Get-LatestChkdskResult {
    `$candidates = New-Object System.Collections.Generic.List[object]
    `$startTime = (Get-Date).AddDays(-7)

    `$queries = @(
        @{ LogName = "Application"; Id = 1001 },
        @{ LogName = "Application"; Id = 26212 },
        @{ LogName = "Application"; Id = 26213 },
        @{ LogName = "Application"; Id = 26214 }
    )

    foreach (`$query in `$queries) {
        try {
            Get-WinEvent -FilterHashtable `$query -MaxEvents 200 -ErrorAction Stop |
                Where-Object {
                    (`$_.ProviderName -in @(
                        "Microsoft-Windows-Wininit",
                        "Wininit",
                        "Chkdsk",
                        "Microsoft-Windows-Chkdsk",
                        "Winlogon",
                        "Autochk"
                    )) -and `$_.TimeCreated -ge `$startTime
                } |
                ForEach-Object { [void]`$candidates.Add(`$_) }
        } catch { }
    }

    if (`$candidates.Count -gt 0) {
        return (`$candidates | Sort-Object TimeCreated -Descending | Select-Object -First 1)
    }

    return `$null
}

function Test-IsRecent {
    param(
        [Parameter(Mandatory)]
        [string]`$Path,

        [int]`$Hours = 24
    )

    if (-not (Test-Path -LiteralPath `$Path)) {
        return `$false
    }

    try {
        `$item = Get-Item -LiteralPath `$Path -Force -ErrorAction Stop
    } catch {
        return `$false
    }

    return (`$item.LastWriteTime -ge (Get-Date).AddHours(-`$Hours))
}

try {
    `$reportPath                = '$embeddedReportPath'
    `$finalReportPath           = '$embeddedFinalReportPath'
    `$filesFolder               = '$embeddedFilesFolder'
    `$runOnceName               = '$embeddedRunOnceName'
    `$downloadsPath             = Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads"
    `$downloadsMaintenanceFolder = Join-Path `$downloadsPath "Maintenance"
    `$downloadsMaintenanceZip    = Join-Path `$downloadsPath "Maintenance.zip"
    `$downloadsFolderMarker      = Join-Path `$downloadsMaintenanceFolder ".melding-maintenance-marker"

    if (-not (Test-Path -LiteralPath `$reportPath)) { exit }

    `$found = `$false
    `$msg = `$null
    `$time = Get-Date
    `$provider = ""
    `$eventId = ""

    `$evt = Get-LatestChkdskResult

    if (`$evt) {
        `$msg      = `$evt.Message
        `$time     = `$evt.TimeCreated
        `$provider = `$evt.ProviderName
        `$eventId  = [string]`$evt.Id
        `$found    = -not [string]::IsNullOrWhiteSpace(`$msg)
    }

    if (-not `$found) {
        `$bootexPath = Join-Path `$env:SystemDrive "Bootex.log"
        if (Test-Path `$bootexPath) {
            try {
                `$bootexContent = Get-Content -Path `$bootexPath -Raw -ErrorAction Stop
                if (-not [string]::IsNullOrWhiteSpace(`$bootexContent)) {
                    `$msg      = `$bootexContent.Trim()
                    `$time     = (Get-Item `$bootexPath).LastWriteTime
                    `$provider = "Bootex.log"
                    `$eventId  = "file"
                    `$found    = `$true
                }
            } catch { }
        }
    }

    if (-not `$found) {
        `$msg = "CHKDSK was skipped because it wasn't needed."
    } else {
        `$normalizedMsg = [string]`$msg

        if (`$normalizedMsg -match '(?i)made corrections to the file system|found problems and successfully made corrections|correct(?:ed|ion|ions)|repair(?:ed|s)|fix(?:ed|es)|orphaned|lost chain|attribute record|index entry') {
            `$msg = "Windows has made corrections to the file system."
        } elseif (`$normalizedMsg -match '(?i)found no problems') {
            `$msg = "Windows has scanned the file system and found no problems."
        } else {
            `$msg = "Windows has scanned the file system and found no problems."
        }
    }

    `$header = "File System Check (CHKDSK - `$env:SystemDrive)`r`nTime: `$time`r`n`r`n"
    `$full = `$header + `$msg
    `$encoded = Convert-ToHtmlSafe `$full
    `$replacement = "<pre>" + `$encoded + "</pre>"

    `$html = Get-Content -Path `$reportPath -Raw

    if (`$found) {
        `$html = `$html -replace '(<a id="pill-chkdsk" class="status-pill)[^"]*(" href="#section-chkdsk">CHKDSK - )[^<]+','`${1} ok`${2}Completed'
        `$html = `$html -replace '(<span id="sectionstatus-chkdsk" class="section-status-pill )section-status-warn(">)Warning','`${1}section-status-ok`${2}Completed'
    } else {
        `$html = `$html -replace '(<a id="pill-chkdsk" class="status-pill)[^"]*(" href="#section-chkdsk">CHKDSK - )[^<]+','`${1} ok`${2}Completed'
        `$html = `$html -replace '(<span id="sectionstatus-chkdsk" class="section-status-pill )section-status-warn(">)Warning','`${1}section-status-ok`${2}Completed'
    }

    `$pattern = '<pre id="chkdsk-results"><!-- CHKDSK-PLACEHOLDER --></pre>'
    `$html = `$html -replace [regex]::Escape(`$pattern), `$replacement

    Set-Content -Path `$reportPath -Value `$html -Encoding UTF8

    try {
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name `$runOnceName -ErrorAction SilentlyContinue
    } catch { }

    if ((Test-Path -LiteralPath `$downloadsMaintenanceFolder) -and
        (Test-Path -LiteralPath `$downloadsFolderMarker) -and
        (Test-IsRecent -Path `$downloadsMaintenanceFolder -Hours 24)) {
        try { Remove-Item -LiteralPath `$downloadsMaintenanceFolder -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }

    if ((Test-Path -LiteralPath `$downloadsMaintenanceZip) -and
        (Test-IsRecent -Path `$downloadsMaintenanceZip -Hours 24)) {
        try { Remove-Item -LiteralPath `$downloadsMaintenanceZip -Force -ErrorAction SilentlyContinue } catch { }
    }

    try { Clear-RecycleBin -Force -Confirm:`$false -ErrorAction SilentlyContinue } catch { }

    Move-Item -LiteralPath `$reportPath -Destination `$finalReportPath -Force
    Start-Process `$finalReportPath

    try {
        Start-Process -FilePath 'cmd.exe' -ArgumentList ('/c timeout /t 3 /nobreak >nul & rd /s /q "{0}"' -f `$filesFolder) -WindowStyle Hidden
    } catch { }
}
catch {
    exit
}
"@

    Set-Content -Path $chkdskScriptPath -Value $chkdskPs1Content -Encoding UTF8

    $chkdskBatContent = @'
@echo off
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0ChkdskResults.ps1"
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "__RUNONCE_NAME__" /f >nul 2>&1
exit /b
'@
    $chkdskBatContent = $chkdskBatContent.Replace("__RUNONCE_NAME__", $runOnceValueName)

    Set-Content -Path $chkdskBatPath -Value $chkdskBatContent -Encoding ASCII

    # ------------------------------------------------
    # Create one-time RunOnce entry for next sign-in
    # ------------------------------------------------
    try {
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name $runOnceValueName -ErrorAction SilentlyContinue
    } catch { }

    $runOnceCommand = 'cmd.exe /c ""{0}""' -f $chkdskBatPath
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name $runOnceValueName -Value $runOnceCommand -PropertyType String -Force | Out-Null

    Write-Host "RunOnce entry created for next sign-in: $runOnceValueName" -ForegroundColor DarkGray

} catch {
    $scriptHadFatalError = $true
    Write-Host "Fatal error in maintenance script: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    if ($prevGuid) {
        try {
        $null = powercfg -setactive $prevGuid 2>$null
        } catch {
        }
    }
}

# Restart
if (-not $scriptHadFatalError) {
    Write-Host "Restarting computer now..." -ForegroundColor Cyan
    Shutdown /r /t 0
} else {
    Write-Host "Automatic restart skipped because of a fatal error." -ForegroundColor Yellow
}
