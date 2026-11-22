#requires -Version 5.1
<#
Offline regression harness for Threat Inspection v2.4.
Reads and parses the script without running its live inspection or changing settings.
#>
[CmdletBinding()]
param([string]$ScriptPath=(Join-Path $PSScriptRoot 'ThreatInspection.ps1'))
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
    $alternative = Join-Path $PSScriptRoot 'ThreatInspection_v2.4.ps1'
    if (Test-Path -LiteralPath $alternative) { $ScriptPath = $alternative }
    else { throw "Script not found: $ScriptPath" }
}
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$parseErrors)
if (@($parseErrors).Count -gt 0) {
    $messages = @($parseErrors | Select-Object -First 12 | ForEach-Object { "Line $($_.Extent.StartLineNumber): $($_.Message)" })
    throw ("PowerShell syntax validation failed: " + ($messages -join ' | '))
}
Write-Host '[PASS] PowerShell 5.1 AST parser: no syntax errors' -ForegroundColor Green
$names = @('Remove-WindowsDuplicateNameSuffix','Convert-ToArtifactFamilyKey','Get-ArtifactFamilyKeys',
    'Get-WatchlistStableArtifactAliases','Test-WatchlistStableArtifactFamilyKeys',
    'Find-WatchlistEntry','Get-ExecutablePathFromCommand','Find-WatchlistExecutable',
    'Get-ExecutionChainRisk','Get-SeverityRank','Merge-BrowserNotificationRecords',
    'Resolve-InspectionDeepScan','Get-CanonicalAntivirusName','Find-WscAntivirusProductState',
    'Test-KnownArtifactFindingEligible','Test-ExpectedOsCoverageRestriction','Get-RecentFileRisk',
    'Get-ExpectedRecentComponentContext','Get-DefenderDetectionAssessment')
$funcs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] },$true))
foreach ($name in $names) {
    $fn = $funcs | Where-Object Name -eq $name | Select-Object -First 1
    if (-not $fn) { throw "Required function missing: $name" }
    . ([ScriptBlock]::Create($fn.Extent.Text))
}
$script:WatchlistAliasCache = @{}
# Extract only the literal watchlist assignments, not the script's main program.
$assignments = @($ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -in @('$script:RemoteAccessWatchlist','$script:PupPuaWatchlist')
},$true))
foreach ($assignment in $assignments) { . ([ScriptBlock]::Create($assignment.Extent.Text)) }
if (@($script:RemoteAccessWatchlist).Count -lt 60 -or @($script:PupPuaWatchlist).Count -lt 60) {
    throw 'Full built-in watchlists were not loaded'
}
$fixtures = @(
    @{ Name='ScreenConnect changing MSI'; File='ScreenConnect.ClientSetup (26).msi'; Expected='ConnectWise ScreenConnect'; Kind='Remote' },
    @{ Name='AnyDesk changing build'; File='AnyDesk_9.99.42.exe'; Expected='AnyDesk'; Kind='Remote' },
    @{ Name='TeamViewer installer'; File='TeamViewer_Setup_15.99.123.exe'; Expected='TeamViewer'; Kind='Remote' },
    @{ Name='RustDesk installer'; File='RustDesk-1.8.201.exe'; Expected='RustDesk'; Kind='Remote' },
    @{ Name='UltraViewer installer'; File='UltraViewer_setup_6.99.exe'; Expected='UltraViewer'; Kind='Remote' },
    @{ Name='Blazer random installer'; File='blazer_installer_x7Q2.exe'; Expected='Blazer'; Kind='PUP' },
    @{ Name='Shift Templates random'; File='Shift--Templates_8737ABC.exe'; Expected='Shift'; Kind='PUP' },
    @{ Name='Clear ManualsLibrary random'; File='Clear-ManualsLibrary.b3008.SK909.red.exe'; Expected='Clear'; Kind='PUP' },
    @{ Name='OneLaunch version'; File='OneLaunch_2027_10.4.exe'; Expected='OneLaunch'; Kind='PUP' },
    @{ Name='Driver Support One'; File='DriverSupportOne_Setup_99.exe'; Expected='Driver Support'; Kind='PUP' }
)
$passed = 0
foreach ($f in $fixtures) {
    $list = if ($f.Kind -eq 'Remote') { $script:RemoteAccessWatchlist } else { $script:PupPuaWatchlist }
    $hit = Find-WatchlistEntry -Text $f.File -Watchlist $list -Mode Artifact
    if (-not $hit -or [string]$hit.Name -notmatch [regex]::Escape($f.Expected)) {
        throw "False negative for $($f.Name): $($f.File) -> $($hit.Name)"
    }
    $passed++
}
$negativeFiles = @(
    'NvDriverUpdateCheck64.dll','ProtectionManagement.dll',
    'Microsoft.VisualStudio.Utilities.Internal.dll',
    'Qt6QuickControls2Universal.dll','SSLErrorAssistant',
    'CustomTraceProfiles','cleanup_fvsdk.cmd',
    'UIEOrchestratorStub.exe','parse-command.js','parse-color.js',
    'DriverUpdateRecommendation.dll','PDFToolsDropdown.js','GmailPdfToolsFteCoachmark.js',
    'c_fsantivirus.inf_amd64_65bfe3a514f0d782'
)
foreach ($filename in $negativeFiles) {
    $hits = @(Find-WatchlistEntry -Text $filename -Watchlist $script:RemoteAccessWatchlist -Mode Artifact)
    $hits += @(Find-WatchlistEntry -Text $filename -Watchlist $script:PupPuaWatchlist -Mode Artifact)
    if (@($hits | Where-Object { $_ }).Count -gt 0) { throw "False positive: $filename" }
    $passed++
}
$taskCommand='C:\Windows\System32\UIEOrchestratorStub.exe /SendHeartbeat'
$heartbeatHit = Find-WatchlistExecutable -Executable $taskCommand -Watchlist $script:RemoteAccessWatchlist
if ($heartbeatHit) { throw "False positive for normal UpdateOrchestrator: $($heartbeatHit.Name)" }
$passed++
if (-not (Get-ExecutionChainRisk 'conhost.exe --headless C:\Users\Test\AppData\Local\0KB6bd\CtmrVX\node.exe C:\Users\Test\AppData\Local\0KB6bd\test.xml')) {
    throw 'Hidden Node.js launch chain was not detected'
}
$passed++
if (Get-ExecutionChainRisk 'C:\Windows\System32\UIEOrchestratorStub.exe /SendHeartbeat') {
    throw 'Benign Windows task was treated as a high-risk execution chain'
}
$passed++
$records=@(
    [PSCustomObject]@{Type='Notification';Browser='Edge';User='Test';Profile='Default';Name='https://bad.example.com';Detail='Allowed';Severity='Review';Path=''},
    [PSCustomObject]@{Type='NotificationToast';Browser='Edge';User='Test';Profile='';Name='bad.example.com';Detail='Fake virus warning';Severity='Warning';Path=''}
)
$merged = @(Merge-BrowserNotificationRecords -Settings $records)
if ($merged.Count -ne 1 -or $merged[0].Severity -ne 'Warning') {
    throw 'Browser notification reconciliation did not retain strongest evidence'
}
$passed++
# Scan choice must not ask for input when a CLI mode or unattended mode is set.
if (-not (Resolve-InspectionDeepScan -Requested $true -Explicit $true)) {
    throw 'Explicit -DeepScan must select Deep Scan without prompting'
}
$passed++
if (Resolve-InspectionDeepScan -Requested $false -Explicit $true) {
    throw 'Explicit -DeepScan:$false must select Standard Scan without prompting'
}
$passed++
if (Resolve-InspectionDeepScan -SkipPrompt $true) {
    throw 'NoScanPrompt must select Standard Scan without prompting'
}
$passed++
$defenderAliases=@('Windows Defender','Windows Defender Antivirus','Microsoft Defender','Microsoft Defender Antivirus')
foreach ($alias in $defenderAliases) {
    if ((Get-CanonicalAntivirusName -Name $alias) -cne 'Microsoft Defender Antivirus') {
        throw "Antivirus alias not consolidated: $alias"
    }
    $passed++
}
$defenderStates=@(
    [PSCustomObject]@{Name='Windows Defender';State='Active';Signatures='Current'},
    [PSCustomObject]@{Name='Microsoft Defender Antivirus';State='Active';Signatures='Current'}
)
$resolved=Find-WscAntivirusProductState -Name 'Microsoft Defender Antivirus' -States $defenderStates
if (-not $resolved -or $resolved.State -ne 'Active' -or $resolved.Signatures -ne 'Current') {
    throw 'Two identical Defender aliases should produce one Active result'
}
$passed++
$defenderStates[1].State='Expired'
$conflict=Find-WscAntivirusProductState -Name 'Microsoft Defender Antivirus' -States $defenderStates
if (-not $conflict -or $conflict.State -ne 'Unknown') {
    throw 'Conflicting Defender statuses must not be presented as Active'
}
$passed++

# Deep Scan v2.1 false-positive regression corpus. These must not be treated as
# evidence of the named software merely because a generic word appears.
$artifactCases = @(
    @{Name='NVIDIA driver-update DLL';Path='C:\Program Files\NVIDIA Corporation\NVIDIA App\Plugins\localuser\NvApp\DriverUpdateRecommendation.dll';Product='DriverUpdate / Slimware DriverUpdate';Dir=$false;Expected=$false},
    @{Name='Adobe PDF extension JS';Path='C:\Users\Test\AppData\Local\Google\Chrome\User Data\Default\Extensions\example\content_scripts\gmail\GmailPdfToolsFteCoachmark.js';Product='PDF Tools';Dir=$false;Expected=$false},
    @{Name='Adobe PDFToolsDropdown cache';Path='C:\ProgramData\Lian-Li\L-Connect 3\CefSharp\Cache\Extensions\Adobe\content_scripts\PdfToolsDropdown';Product='PDF Tools';Dir=$true;Expected=$false},
    @{Name='Quick Assist Windows package';Path='C:\Program Files\WindowsApps\MicrosoftCorporationII.QuickAssist_2.0.36.0_x64__8wekyb3d8bbwe';Product='Microsoft Quick Assist';Dir=$true;Expected=$false},
    @{Name='Windows Defender INF';Path='C:\Windows\System32\DriverStore\FileRepository\c_fsantivirus.inf_amd64_65bfe3a514f0d782';Product='SAntivirus / Segurazo';Dir=$true;Expected=$false},
    @{Name='Unity Shader Graph Wave';Path='C:\Users\Test\UnityProject\Library\PackageCache\com.unity.shadergraph\Editor\Data\Nodes\Math\Wave';Product='Wave Browser';Dir=$true;Expected=$false},
    @{Name='Arcade Blazer artwork';Path='A:\LaunchBox\Emulators\Arcade\artwork\blazer';Product='Blazer';Dir=$true;Expected=$false},
    @{Name='Nintendo Conduit artwork';Path='A:\LaunchBox\Emulators\Nintendo Wii\Sys\Load\GraphicMods\The Conduit';Product='Search Protect';Dir=$true;Expected=$false},
    @{Name='Real ScreenConnect MSI';Path='C:\Users\Test\Downloads\ScreenConnect.ClientSetup (24).msi';Product='ConnectWise ScreenConnect';Dir=$false;Expected=$true},
    @{Name='Real AnyDesk installer';Path='C:\Users\Test\Downloads\AnyDesk_9.99.42.exe';Product='AnyDesk';Dir=$false;Expected=$true},
    @{Name='Real Blazer installer';Path='C:\Users\Test\Downloads\blazer_installer_x7Q2.exe';Product='Blazer';Dir=$false;Expected=$true},
    @{Name='Real product directory';Path='C:\Users\Test\AppData\Local\Blazer';Product='Blazer';Dir=$true;Expected=$true}
)
foreach ($case in $artifactCases) {
    $leaf = Split-Path -Path $case.Path -Leaf
    $actual = Test-KnownArtifactFindingEligible -Path $case.Path -Leaf $leaf -Product $case.Product -IsDirectory:([bool]$case.Dir)
    if ($actual -ne $case.Expected) { throw "Evidence filter failed: $($case.Name) (actual=$actual expected=$($case.Expected))" }
    $passed++
}
# Recent-file regression tests intentionally don't touch the user's filesystem.
function Test-IsInspectionOwnPath { param([string]$Path) return $false }
$script:StartupExecutionPaths = @{}
$recentFalsePositives = @(
    'C:\Windows\WinSxS\Temp\InFlight\0123abc\WmsStatusTab.Resources.dll',
    'C:\Program Files\Git\usr\bin\sha512sum.exe',
    'C:\Program Files\Git\cmd\aslr-manager.ps1',
    'C:\Program Files\WindowsApps\OpenAI.CodexPrimaryRuntime\dependencies\node\node_modules\playwright-core\bin\install_webkit_wsl.ps1',
    'C:\Users\Test\AppData\Local\Programs\Python\Python313\Lib\test\empty.vbs'
)
foreach ($path in $recentFalsePositives) {
    $fakeFile = [PSCustomObject]@{
        FullName=$path;Name=[IO.Path]::GetFileName($path)
        Extension=[IO.Path]::GetExtension($path)
        LastWriteTime=(Get-Date);Length=1024
    }
    $result = Get-RecentFileRisk -File $fakeFile -Cutoff (Get-Date).AddDays(-30)
    if ($result) { throw "Expected normal component triggered recent-file finding: $path" }
    $passed++
}
if (-not (Test-ExpectedOsCoverageRestriction -ErrorLine 'C:\System Volume Information: Access denied')) {
    throw 'Protected Windows directory should be classified as expected coverage restriction'
}
$passed++
if (Test-ExpectedOsCoverageRestriction -ErrorLine 'C:\Users\Test\Downloads: Access denied') {
    throw 'Unexpected user-folder read error must not be downgraded'
}
$passed++


# Windows Security detection-history regression tests: previously removed Brave
# cache detections must be Info, but failed, allowed and unresolved threats must
# remain visible with their appropriate severity.
$defenderDetectionCases = @(
    @{ Name='Removed successfully (Brave cache)'; State=4; Successful=$true; Additional=0; ErrorCode=0; Execution=4; Expected='Info' },
    @{ Name='Cleaned successfully'; State=2; Successful=$true; Additional=0; ErrorCode=0; Execution=4; Expected='Info' },
    @{ Name='Quarantined successfully'; State=3; Successful=$true; Additional=0; ErrorCode=0; Execution=4; Expected='Info' },
    @{ Name='Blocked successfully'; State=6; Successful=$true; Additional=0; ErrorCode=0; Execution=1; Expected='Info' },
    @{ Name='Allowed threat'; State=5; Successful=$true; Additional=0; ErrorCode=0; Execution=2; Expected='Review' },
    @{ Name='Unresolved detection'; State=1; Successful=$false; Additional=0; ErrorCode=0; Execution=0; Expected='Review' },
    @{ Name='Removal not confirmed'; State=4; Successful=$false; Additional=0; ErrorCode=0; Execution=4; Expected='Review' },
    @{ Name='Reboot required'; State=4; Successful=$true; Additional=8; ErrorCode=0; Execution=4; Expected='Review' },
    @{ Name='Full scan required'; State=3; Successful=$true; Additional=4; ErrorCode=0; Execution=4; Expected='Review' },
    @{ Name='Removal failed'; State=103; Successful=$false; Additional=0; ErrorCode=0; Execution=4; Expected='Warning' },
    @{ Name='Quarantine failed'; State=102; Successful=$false; Additional=0; ErrorCode=0; Execution=4; Expected='Warning' },
    @{ Name='Unknown status, cleaning succeeded and blocked'; State=0; Successful=$true; Additional=0; ErrorCode=0; Execution=1; Expected='Info' },
    @{ Name='Unknown status, cleaning succeeded and not executing'; State=0; Successful=$true; Additional=0; ErrorCode=0; Execution=4; Expected='Info' },
    @{ Name='Unknown status, action incomplete'; State=0; Successful=$false; Additional=0; ErrorCode=0; Execution=1; Expected='Review' },
    @{ Name='Unknown status, reboot required'; State=0; Successful=$true; Additional=8; ErrorCode=0; Execution=1; Expected='Review' },
    @{ Name='Unknown status, execution uncertain'; State=0; Successful=$true; Additional=0; ErrorCode=0; Execution=0; Expected='Review' },
    @{ Name='Unknown status, allowed execution'; State=0; Successful=$true; Additional=0; ErrorCode=0; Execution=2; Expected='Review' },
    @{ Name='Unknown status, executing'; State=0; Successful=$true; Additional=0; ErrorCode=0; Execution=3; Expected='Warning' },
    @{ Name='Unknown status with error'; State=0; Successful=$true; Additional=0; ErrorCode=5; Execution=1; Expected='Warning' },
    @{ Name='Defender status error'; State=4; Successful=$true; Additional=0; ErrorCode=5; Execution=4; Expected='Warning' },
    @{ Name='Still executing despite removed status'; State=4; Successful=$true; Additional=0; ErrorCode=0; Execution=3; Expected='Warning' }
)
foreach ($item in $defenderDetectionCases) {
    $sample = [PSCustomObject]@{
        ThreatID = 2147927547
        ThreatStatusID = $item.State
        ActionSuccess = $item.Successful
        AdditionalActionsBitMask = $item.Additional
        ThreatStatusErrorCode = $item.ErrorCode
        CurrentThreatExecutionStatusID = $item.Execution
    }
    $actual = Get-DefenderDetectionAssessment -Detection $sample
    if ($actual.Severity -ne $item.Expected) {
        throw "Defender status test failed: $($item.Name) => $($actual.Severity), expected $($item.Expected)"
    }
    $passed++
}
$missingDefenderFields = Get-DefenderDetectionAssessment -Detection ([PSCustomObject]@{ ThreatID=999; ThreatStatusID=4; ActionSuccess=$true })
$unknownMissingFields = Get-DefenderDetectionAssessment -Detection ([PSCustomObject]@{
    ThreatID=2147927547; ThreatStatusID=0; ActionSuccess=$true
})
if ($unknownMissingFields.Severity -ne 'Review') {
    throw 'Unknown status with incomplete evidence must remain Review'
}
$passed++
$unknownBraveCache = Get-DefenderDetectionAssessment -Detection ([PSCustomObject]@{
    ThreatID=2147927547; ThreatStatusID=0; ActionSuccess=$true;
    AdditionalActionsBitMask=0; ThreatStatusErrorCode=0; CurrentThreatExecutionStatusID=1
})
if ($unknownBraveCache.Severity -ne 'Info' -or
    $unknownBraveCache.Status -notmatch 'exact action unknown' -or
    $unknownBraveCache.ExecutionStatus -ne 'Blocked (1)' -or
    $unknownBraveCache.RawStatus -ne '0') {
    throw 'November 8 Brave cache regression: unknown final status with successful block must be Info without claiming Removed'
}
$passed++
if ($missingDefenderFields.Severity -ne 'Review') {
    throw 'Incomplete Defender remediation evidence must not be silently treated as resolved'
}
$passed++

Write-Host "[PASS] $passed artifact, Defender, execution-chain and notification regression assertions" -ForegroundColor Green
Write-Host 'All tests passed. Live Windows scan behavior still requires a system test.' -ForegroundColor Green
