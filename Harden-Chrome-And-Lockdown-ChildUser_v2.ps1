<#
.SYNOPSIS
Creates a local standard (non-Microsoft) user, ensures system-wide Google Chrome is installed, and applies hardening/lockdown.

.DESCRIPTION
GET THE LATEST VERSION FROM https://github.com/philliphall/Child-School-Account-Lockdown.git!!!
1) Prompts for a local child account name and creates a STANDARD local user.
2) Ensures Google Chrome is installed system-wide. If missing, downloads the official Enterprise MSI and installs silently.
3) Applies Chrome machine policies (HKLM) to:
   - Disable Guest Mode
   - Disable Incognito
   - Disable adding new profiles
   - Force browser sign-in
   - Restrict sign-in to allowed email(s)
   - Block high-risk chrome:// pages and extension installs
4) Applies Windows per-user lockdown policies ONLY to the target child user (not admins).
   If the child has never signed in (no profile hive yet), creates a SYSTEM scheduled task to apply lockdown at first logon.

SAFETY
- Does NOT modify Administrator account.
- Chrome policies are machine-wide but reversible via -RemoveChromePolicies.
- Per-user lockdown is applied ONLY to the specified child account SID.

USAGE (run as Administrator)
  .\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1

Rollback
  .\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1 -RemoveChromePolicies
  .\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1 -RemoveUserLockdown -UserName <name>

NOTES
- RestrictSigninToPattern accepts a single pattern string. For multiple emails this script uses a regex OR pattern: ^(a@b.com|c@d.com)$
- Some Start/Search/Store policy behaviors vary across Windows versions. This script uses common registry-backed equivalents.
#>

[CmdletBinding()]
param(
  [switch]$RemoveChromePolicies,
  [switch]$RemoveUserLockdown,
  [string]$UserName,

  # Internal switches used by the scheduled task
  [switch]$InternalApplyUserLockdown,
  [string]$InternalUserSid
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must be run from an elevated PowerShell (Run as administrator).'
  }
}

function Ensure-RegistryKey([string]$Path) {
  if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

function Ensure-Directory([string]$Path) {
  if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
}

function Set-RegistryValue {
  param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$Name,
    [Parameter(Mandatory)] [AllowNull()] $Value,
    [Parameter(Mandatory)] [ValidateSet('String','DWord','QWord','MultiString','ExpandString')] [string]$Type
  )
  Ensure-RegistryKey $Path
  $t = switch ($Type) {
    'String'       { 'String' }
    'ExpandString' { 'ExpandString' }
    'MultiString'  { 'MultiString' }
    'DWord'        { 'DWord' }
    'QWord'        { 'QWord' }
  }
  New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $t -Force | Out-Null
}

function Get-LocalUserSid([string]$Name) {
  try {
    $nt  = New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME, $Name)
    $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
    return $sid.Value
  } catch {
    return $null
  }
}

function Create-LocalStandardUser([string]$Name) {
  $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Host "Local user '$Name' already exists. Skipping creation." -ForegroundColor Yellow
    return
  }

  Write-Host "Creating local STANDARD user: $Name" -ForegroundColor Cyan

  $pwChoice = Read-Host "Set a password now? (Y/N)"
  if ($pwChoice -match '^[Yy]') {
    $pw1 = Read-Host "Enter password" -AsSecureString
    $pw2 = Read-Host "Confirm password" -AsSecureString
	
    # compare secure strings by converting to plain text briefly (in-memory)
    $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw1)
    $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw2)
    try {
      $s1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
      $s2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
      if ($s1 -ne $s2) { throw 'Passwords do not match.' }
    } finally {
      if ($b1 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1) }
      if ($b2 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2) }
    }

    New-LocalUser -Name $Name -Password $pw1 -AccountNeverExpires:$true -PasswordNeverExpires:$true -UserMayNotChangePassword:$true | Out-Null
  } else {
    # Create without password only if local policy allows. If blocked, user will see a clear error.
    New-LocalUser -Name $Name -NoPassword -AccountNeverExpires:$true | Out-Null
  }

  # Ensure NOT an admin
  try { Remove-LocalGroupMember -Group 'Administrators' -Member $Name -ErrorAction SilentlyContinue } catch {}
  try { Add-LocalGroupMember -Group 'Users' -Member $Name -ErrorAction SilentlyContinue } catch {}

  Write-Host "User '$Name' created as a standard local user." -ForegroundColor Green
}

function Test-ChromeSystemWideInstalled {
  $paths = @()
  $pf = $env:ProgramFiles
  $pf86 = ${env:ProgramFiles(x86)}
  if ($pf)  { $paths += Join-Path $pf  'Google\Chrome\Application\chrome.exe' }
  if ($pf86) { $paths += Join-Path $pf86 'Google\Chrome\Application\chrome.exe' }
  foreach ($p in $paths) {
    if ($p -and (Test-Path $p)) { return $true }
  }

  $uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )
  foreach ($root in $uninstallRoots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
      try {
        $dn = (Get-ItemProperty $k.PSPath -ErrorAction Stop).DisplayName
        if ($dn -and $dn -eq 'Google Chrome') { return $true }
      } catch {}
    }
  }

  return $false
}

function Install-ChromeSystemWide {
  Write-Host "System-wide Chrome not detected. Downloading + installing..." -ForegroundColor Cyan

  # Official Google Enterprise MSI direct links (commonly used for managed deployments)
  # 64-bit: https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi
  # 32-bit: https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise.msi
  $is64 = [Environment]::Is64BitOperatingSystem
  $msiUrl = if ($is64) {
    'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
  } else {
    'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise.msi'
  }

  $tmp = Join-Path $env:TEMP ("chrome_enterprise_{0}.msi" -f ($(if ($is64) {'x64'} else {'x86'})))

  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
  } catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  }

  Write-Host "Downloading: $msiUrl" -ForegroundColor DarkCyan
  Invoke-WebRequest -Uri $msiUrl -OutFile $tmp -UseBasicParsing

  if (-not (Test-Path $tmp)) { throw 'Chrome MSI download failed.' }
  Assert-TrustedGoogleMsi -Path $tmp

  Write-Host "Installing MSI silently..." -ForegroundColor DarkCyan
  $args = "/i `"$tmp`" /qn /norestart"
  $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru
  if ($p.ExitCode -ne 0) {
    throw "Chrome MSI install failed. msiexec exit code: $($p.ExitCode)"
  }

  Remove-Item $tmp -Force -ErrorAction SilentlyContinue

  if (-not (Test-ChromeSystemWideInstalled)) {
    throw 'Chrome install completed but Chrome still not detected in standard locations.'
  }

  Write-Host "Chrome installed system-wide." -ForegroundColor Green
}

function Ensure-ChromeInstalled {
  if (Test-ChromeSystemWideInstalled) {
    Write-Host "Chrome is already installed system-wide." -ForegroundColor Green
    return
  }
  Install-ChromeSystemWide
}

function Assert-TrustedGoogleMsi([string]$Path) {
  Write-Host "Verifying MSI digital signature..." -ForegroundColor DarkCyan
  $sig = Get-AuthenticodeSignature -FilePath $Path
  if ($sig.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Downloaded MSI signature is not valid. Status: $($sig.Status)"
  }
  if (-not $sig.SignerCertificate) {
    throw 'Downloaded MSI has no signer certificate.'
  }
  if ($sig.SignerCertificate.Subject -notmatch 'Google') {
    throw "Downloaded MSI signer is unexpected: $($sig.SignerCertificate.Subject)"
  }
}

function Apply-ChromeHardening([string]$RestrictSigninPatternRegex) {
  $base = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
  Ensure-RegistryKey $base

  Write-Host "Applying Chrome hardening policies (machine-wide)..." -ForegroundColor Cyan

  # Disable Guest
  Set-RegistryValue -Path $base -Name 'BrowserGuestModeEnabled'    -Value 0 -Type DWord
  # Disable Incognito (1 = disabled)
  Set-RegistryValue -Path $base -Name 'IncognitoModeAvailability'  -Value 1 -Type DWord
  # Disable adding profiles
  Set-RegistryValue -Path $base -Name 'BrowserAddPersonEnabled'    -Value 0 -Type DWord
  # Force browser sign-in
  Set-RegistryValue -Path $base -Name 'ForceBrowserSignin'         -Value 1 -Type DWord
  # Browser sign-in mode (2 = force sign-in)
  Set-RegistryValue -Path $base -Name 'BrowserSignin'              -Value 2 -Type DWord
  # Lock down browser escape surfaces.
  Set-RegistryValue -Path $base -Name 'DeveloperToolsAvailability' -Value 2 -Type DWord
  Set-RegistryValue -Path $base -Name 'AutofillAddressEnabled'     -Value 0 -Type DWord
  Set-RegistryValue -Path $base -Name 'AutofillCreditCardEnabled'  -Value 0 -Type DWord
  Set-RegistryValue -Path $base -Name 'BlockExternalExtensions'    -Value 1 -Type DWord

  if ($RestrictSigninPatternRegex) {
    # Restrict to allowed account(s) using regex
    Set-RegistryValue -Path $base -Name 'RestrictSigninToPattern' -Value $RestrictSigninPatternRegex -Type String
  }

  # Block all extension installation by default.
  $extBlock = 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist'
  if (Test-Path $extBlock) { Remove-Item -Path $extBlock -Recurse -Force -ErrorAction SilentlyContinue }
  Ensure-RegistryKey $extBlock
  Set-RegistryValue -Path $extBlock -Name '1' -Value '*' -Type String

  # Block high-risk internal pages.
  $urlBlock = 'HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist'
  if (Test-Path $urlBlock) { Remove-Item -Path $urlBlock -Recurse -Force -ErrorAction SilentlyContinue }
  Ensure-RegistryKey $urlBlock
  $blockedUrls = @(
    'chrome://settings*',
    'chrome://extensions*',
    'chrome://flags*',
    'chrome://policy*',
    'chrome://version*',
    'chrome://inspect*'
  )
  for ($i = 0; $i -lt $blockedUrls.Count; $i++) {
    Set-RegistryValue -Path $urlBlock -Name ($i + 1).ToString() -Value $blockedUrls[$i] -Type String
  }

  Write-Host "Chrome policies written. In Chrome: open chrome://policy and click 'Reload policies'." -ForegroundColor Green
}

function Remove-ChromeHardening {
  Write-Host "Removing Chrome hardening policies..." -ForegroundColor Yellow
  $base = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
  if (Test-Path $base) {
    Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue
  }
  Write-Host "Removed HKLM Chrome policy keys. Restart Chrome to verify." -ForegroundColor Green
}

function Get-UserProfilePath([string]$Sid) {
  $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
  if (Test-Path $k) {
    return (Get-ItemProperty -Path $k).ProfileImagePath
  }
  return $null
}

function Apply-ChildExecutionDenyAcls([string]$Sid) {
  $profilePath = Get-UserProfilePath $Sid
  if (-not $profilePath -or -not (Test-Path $profilePath)) {
    Write-Host "Skipping execute-deny ACLs because profile path is not available yet." -ForegroundColor Yellow
    return
  }

  # Block running binaries from child-writable locations to reduce rename/copy bypasses.
  $targets = @(
    (Join-Path $profilePath 'Desktop'),
    (Join-Path $profilePath 'Downloads'),
    (Join-Path $profilePath 'Documents'),
    (Join-Path $profilePath 'Pictures'),
    (Join-Path $profilePath 'Music'),
    (Join-Path $profilePath 'Videos'),
    (Join-Path $profilePath 'AppData\Local\Temp')
  )

  foreach ($p in $targets) {
    if (-not (Test-Path $p)) { continue }
    Write-Host "Applying execute-deny ACL for child SID on: $p" -ForegroundColor DarkCyan
    & icacls.exe $p /deny "*${Sid}:(OI)(CI)(X)" /T /C | Out-Null
  }
}

function Remove-ChildExecutionDenyAcls([string]$Sid) {
  $profilePath = Get-UserProfilePath $Sid
  if (-not $profilePath -or -not (Test-Path $profilePath)) { return }

  $targets = @(
    (Join-Path $profilePath 'Desktop'),
    (Join-Path $profilePath 'Downloads'),
    (Join-Path $profilePath 'Documents'),
    (Join-Path $profilePath 'Pictures'),
    (Join-Path $profilePath 'Music'),
    (Join-Path $profilePath 'Videos'),
    (Join-Path $profilePath 'AppData\Local\Temp')
  )

  foreach ($p in $targets) {
    if (-not (Test-Path $p)) { continue }
    Write-Host "Removing execute-deny ACL for child SID on: $p" -ForegroundColor DarkCyan
    & icacls.exe $p /remove:d "*$Sid" /T /C | Out-Null
  }
}

function Load-UserHive([string]$Sid) {
  # Returns mount point like HKU:\TEMP_CHILD_HIVE
  $profilePath = Get-UserProfilePath $Sid
  if (-not $profilePath) { return $null }

  $ntuser = Join-Path $profilePath 'NTUSER.DAT'
  if (-not (Test-Path $ntuser)) { return $null }

  $mountName = 'TEMP_CHILD_HIVE'
  $mountPath = "Registry::HKEY_USERS\$mountName"

  # If already loaded, reuse
  if (Test-Path $mountPath) {
    return "HKU:\$mountName"
  }

  Write-Host "Loading user hive from $ntuser" -ForegroundColor DarkCyan
  & reg.exe load "HKU\$mountName" "$ntuser" | Out-Null
  return "HKU:\$mountName"
}

function Unload-UserHive {
  $mountPath = 'Registry::HKEY_USERS\TEMP_CHILD_HIVE'
  if (Test-Path $mountPath) {
    Write-Host "Unloading user hive..." -ForegroundColor DarkCyan
    & reg.exe unload 'HKU\TEMP_CHILD_HIVE' | Out-Null
  }
}

function Apply-UserLockdownToHive([string]$HiveRoot, [string]$Sid) {
  # $HiveRoot example: HKU:\TEMP_CHILD_HIVE

  Write-Host "Applying per-user lockdown policies to hive: $HiveRoot" -ForegroundColor Cyan

  # --- Run only specified Windows apps ---
  $expl = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  Set-RegistryValue -Path $expl -Name 'RestrictRun' -Value 1 -Type DWord

  $rr = "$expl\RestrictRun"
  Ensure-RegistryKey $rr
  Set-RegistryValue -Path $rr -Name '1' -Value 'chrome.exe'   -Type String
  Set-RegistryValue -Path $rr -Name '2' -Value 'StudyReel.exe' -Type String

  # Reduce common shell escape vectors.
  Set-RegistryValue -Path $expl -Name 'NoRun'     -Value 1 -Type DWord
  Set-RegistryValue -Path $expl -Name 'NoWinKeys' -Value 1 -Type DWord

  # --- Block CMD ---
  $sysPol = "$HiveRoot\Software\Policies\Microsoft\Windows\System"
  # 2 = disable cmd and also disable batch scripts
  Set-RegistryValue -Path $sysPol -Name 'DisableCMD' -Value 2 -Type DWord

  # --- Block Registry Editor ---
  $sys = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System"
  Set-RegistryValue -Path $sys -Name 'DisableRegistryTools' -Value 1 -Type DWord

  # --- Start Menu / Taskbar restrictions ---
  # Remove all programs list
  Set-RegistryValue -Path $expl -Name 'NoStartMenuMorePrograms' -Value 1 -Type DWord
  # Remove / prevent Shut Down / Restart
  Set-RegistryValue -Path $expl -Name 'NoClose'                -Value 1 -Type DWord
  # Hide notification area
  Set-RegistryValue -Path $expl -Name 'NoTrayItemsDisplay'     -Value 1 -Type DWord
  # Remove Search link / Disable find
  Set-RegistryValue -Path $expl -Name 'NoFind'                 -Value 1 -Type DWord
  # Remove pinned programs list
  Set-RegistryValue -Path $expl -Name 'NoStartMenuPinnedList'  -Value 1 -Type DWord

  # --- Disable Store ---
  $store = "$HiveRoot\Software\Policies\Microsoft\WindowsStore"
  Set-RegistryValue -Path $store -Name 'RemoveWindowsStore' -Value 1 -Type DWord
  Set-RegistryValue -Path $store -Name 'DisableStoreApps'   -Value 1 -Type DWord

  # --- File Explorer context menu removal (blocks right-click) ---
  Set-RegistryValue -Path $expl -Name 'NoViewContextMenu' -Value 1 -Type DWord

  # --- Hide / Block all drives in This PC ---
  # "Restrict all drives" bitmask = 0x03FFFFFF (26 letters)
  $allDrives = 0x03FFFFFF
  Set-RegistryValue -Path $expl -Name 'NoDrives'      -Value $allDrives -Type DWord
  Set-RegistryValue -Path $expl -Name 'NoViewOnDrive' -Value $allDrives -Type DWord

  # --- Prohibit Control Panel and Settings ---
  Set-RegistryValue -Path $expl -Name 'NoControlPanel' -Value 1 -Type DWord

  # --- Remove Task Manager ---
  Set-RegistryValue -Path $sys -Name 'DisableTaskMgr' -Value 1 -Type DWord

  # --- Reduce search surfaces (best-effort; varies by Windows build) ---
  $winExplorerPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Explorer"
  Ensure-RegistryKey $winExplorerPol
  Set-RegistryValue -Path $winExplorerPol -Name 'DisableSearchBoxSuggestions' -Value 1 -Type DWord

  # "Don't run specified Windows applications" list for common bypass binaries.
  Set-RegistryValue -Path $expl -Name 'DisallowRun' -Value 1 -Type DWord
  $dr = "$expl\DisallowRun"
  Ensure-RegistryKey $dr
  $blockedApps = @(
    'cmd.exe',
    'powershell.exe',
    'pwsh.exe',
    'wt.exe',
    'regedit.exe',
    'mmc.exe',
    'control.exe',
    'mshta.exe',
    'wscript.exe',
    'cscript.exe',
    'rundll32.exe',
    'msiexec.exe',
    'taskmgr.exe',
    'notepad.exe',
    'msedge.exe',
    'iexplore.exe'
  )
  for ($i = 0; $i -lt $blockedApps.Count; $i++) {
    Set-RegistryValue -Path $dr -Name ($i + 1).ToString() -Value $blockedApps[$i] -Type String
  }

  if ($Sid) {
    Apply-ChildExecutionDenyAcls -Sid $Sid
  }

  Write-Host "Per-user lockdown values written." -ForegroundColor Green
}

function Remove-UserLockdownFromHive([string]$HiveRoot, [string]$Sid) {
  Write-Host "Removing per-user lockdown policies from hive: $HiveRoot" -ForegroundColor Yellow

  $expl = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  $sysPol = "$HiveRoot\Software\Policies\Microsoft\Windows\System"
  $sys = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System"
  $store = "$HiveRoot\Software\Policies\Microsoft\WindowsStore"
  $winExplorerPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Explorer"

  # Remove the keys we created (best-effort)
  foreach ($k in @($expl, "$expl\RestrictRun", $sysPol, $sys, $store, $winExplorerPol)) {
    if (Test-Path $k) { Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue }
  }

  if ($Sid) {
    Remove-ChildExecutionDenyAcls -Sid $Sid
  }

  Write-Host "Per-user lockdown keys removed (where present)." -ForegroundColor Green
}

function Ensure-SecureTaskScriptCopy([string]$SourcePath) {
  $taskDir = Join-Path $env:ProgramData 'ChildLockdown'
  Ensure-Directory $taskDir

  $destPath = Join-Path $taskDir 'ApplyChildLockdown.ps1'
  Copy-Item -Path $SourcePath -Destination $destPath -Force

  # Lock task script path to SYSTEM + local admins only.
  & icacls.exe $taskDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /C | Out-Null
  & icacls.exe $destPath /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" /C | Out-Null

  return $destPath
}

function Ensure-FirstLogonTask([string]$ChildUserName, [string]$ChildSid) {
  # Creates (or replaces) a SYSTEM task that runs this script at logon of the target user to apply lockdown.
  # This avoids needing MMC per-user GPO for most settings.

  $taskName = "ApplyChildLockdown_$ChildUserName"
  $scriptPath = $PSCommandPath
  if (-not $scriptPath) { throw "Cannot determine script path. Save this script to disk and rerun." }
  $taskScriptPath = Ensure-SecureTaskScriptCopy -SourcePath $scriptPath

  $args = "-NoProfile -ExecutionPolicy Bypass -File `"$taskScriptPath`" -InternalApplyUserLockdown -InternalUserSid `"$ChildSid`""

  # Resolve schtasks path (handle Sysnative when running 32-bit PowerShell on 64-bit Windows)
  $schtasksPath = "$env:windir\Sysnative\schtasks.exe"
  if (-not (Test-Path $schtasksPath)) {
    $schtasksPath = "$env:windir\System32\schtasks.exe"
  }
  if (-not (Test-Path $schtasksPath)) {
    $schtasksPath = 'schtasks.exe'
  }

  # If resolved path doesn't exist, fall back to PATH resolution and warn
  if (($schtasksPath -ne 'schtasks.exe') -and -not (Test-Path $schtasksPath)) {
    Write-Host "schtasks not found at $schtasksPath; falling back to PATH resolution." -ForegroundColor Yellow
    $schtasksPath = 'schtasks.exe'
  }
  # Prefer ScheduledTasks cmdlets (clean) with a schtasks.exe fallback for older systems
  if (Get-Command -Name Register-ScheduledTask -ErrorAction SilentlyContinue) {
    try {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }

      $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args
      $trigger = New-ScheduledTaskTrigger -AtLogOn -User $ChildUserName
      $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

      Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop
    } catch {
      throw "Failed to create scheduled task using ScheduledTasks cmdlets: $($_.Exception.Message)"
    }
  } else {
    # Delete existing (best-effort)
    try {
      Start-Process -FilePath $schtasksPath -ArgumentList '/Delete','/TN',$taskName,'/F' -NoNewWindow -Wait -PassThru -ErrorAction Stop | Out-Null
    } catch {
      Write-Host "Existing task delete attempted but failed (may not exist): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Create the task using schtasks.exe
    try {
      $trCmd = "powershell.exe $args"
      $trArg = '"' + $trCmd + '"'
      Start-Process -FilePath $schtasksPath -ArgumentList '/Create','/TN',$taskName,'/SC','ONLOGON','/RU','SYSTEM','/RL','HIGHEST','/TR',$trArg,'/F' -NoNewWindow -Wait -PassThru -ErrorAction Stop | Out-Null
    } catch {
      throw "Failed to create scheduled task via ${schtasksPath}: $($_.Exception.Message)"
    }
  }

  Write-Host "Created logon task '$taskName' to apply user lockdown at first sign-in." -ForegroundColor Green
}

function Internal-ApplyUserLockdown([string]$Sid) {
  Assert-Admin
  $hive = $null
  try {
    $hive = Load-UserHive $Sid
    if (-not $hive) {
      Write-Host "User hive not available yet (profile not created)." -ForegroundColor Yellow
      return
    }
    Apply-UserLockdownToHive -HiveRoot $hive -Sid $Sid
  } finally {
    Unload-UserHive
  }
}

# ---------------- MAIN ----------------
Assert-Admin

if ($InternalApplyUserLockdown) {
  if (-not $InternalUserSid) { throw 'Missing -InternalUserSid' }
  Internal-ApplyUserLockdown -Sid $InternalUserSid
  return
}

if ($RemoveChromePolicies) {
  Remove-ChromeHardening
  return
}

if ($RemoveUserLockdown) {
  if (-not $UserName) { $UserName = Read-Host 'Enter the child local username to unlock' }
  $sid = Get-LocalUserSid $UserName
  if (-not $sid) { throw "Could not find SID for user '$UserName'" }

  $hive = $null
  try {
    $hive = Load-UserHive $sid
    if (-not $hive) {
      Write-Host "Cannot load hive now. Have the user sign in once to create the profile, then rerun." -ForegroundColor Yellow
      return
    }
    Remove-UserLockdownFromHive -HiveRoot $hive -Sid $sid
  } finally {
    Unload-UserHive
  }

  Write-Host "If you created a scheduled task ApplyChildLockdown_$UserName, delete it from Task Scheduler." -ForegroundColor Yellow
  return
}

# Interactive flow
$childUser = Read-Host 'Enter LOCAL child account name to create (e.g., Student01)'
if (-not $childUser) { throw 'Username cannot be empty.' }

Ensure-ChromeInstalled
Create-LocalStandardUser -Name $childUser

# Chrome RestrictSigninToPattern
Write-Host "`nChrome sign-in restriction:" -ForegroundColor Cyan
Write-Host "Enter allowed child email(s). Separate multiple emails with commas." -ForegroundColor Cyan
$emailsRaw = Read-Host 'Allowed email(s)'
$emails = @()
if ($emailsRaw) {
  $emails = @($emailsRaw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

$pattern = $null
if ($emails.Count -eq 1) {
  # exact match
  $escaped = [Regex]::Escape($emails[0])
  $pattern = "^$escaped$"
} elseif ($emails.Count -gt 1) {
  $escaped = $emails | ForEach-Object { [Regex]::Escape($_) }
  $pattern = "^($($escaped -join '|'))$"
} else {
  Write-Host "No email pattern provided; Chrome will still force sign-in but will not restrict to a specific account." -ForegroundColor Yellow
}

Apply-ChromeHardening -RestrictSigninPatternRegex $pattern

# Per-user lockdown
$sid = Get-LocalUserSid $childUser
if (-not $sid) { throw "Could not resolve SID for '$childUser'" }

Write-Host "`nApplying Windows per-user lockdown for '$childUser'..." -ForegroundColor Cyan
$hive = $null
try {
  $hive = Load-UserHive $sid
  if ($hive) {
    Apply-UserLockdownToHive -HiveRoot $hive -Sid $sid
  } else {
    Write-Host "User profile hive not found yet. The child must sign in once to create the profile." -ForegroundColor Yellow
    Write-Host "A logon task will be created so lockdown is applied automatically at first sign-in." -ForegroundColor Yellow
    Ensure-FirstLogonTask -ChildUserName $childUser -ChildSid $sid
  }
} finally {
  Unload-UserHive
}

Write-Host "`nDONE." -ForegroundColor Green
Write-Host "Next steps (manual):" -ForegroundColor Cyan
Write-Host "1) Sign in as the child once (to initialize profile), then sign out." -ForegroundColor Cyan
Write-Host "2) In Chrome for the child: sign in with the allowed account and verify chrome://policy shows status OK." -ForegroundColor Cyan
Write-Host "3) (Optional) Clean desktop icons / hide Recycle Bin using Personalization as desired." -ForegroundColor Cyan
Write-Host "`nRollback:" -ForegroundColor Yellow
Write-Host "- Remove Chrome policies:   .\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1 -RemoveChromePolicies" -ForegroundColor Yellow
Write-Host "- Remove user lockdown:     .\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1 -RemoveUserLockdown -UserName <name>" -ForegroundColor Yellow
