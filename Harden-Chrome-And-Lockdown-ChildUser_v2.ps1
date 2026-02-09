<#
.SYNOPSIS
Creates a local standard (non-Microsoft) user, ensures system-wide Google Chrome is installed, and applies hardening/lockdown.

.DESCRIPTION
1) Prompts for a local child account name and creates a STANDARD local user.
2) Ensures Google Chrome is installed system-wide. If missing, downloads the official Enterprise MSI and installs silently.
3) Applies Chrome machine policies (HKLM) to:
   - Disable Guest Mode
   - Disable Incognito
   - Disable adding new profiles
   - Force browser sign-in
   - Restrict sign-in to allowed email(s)
   - Block chrome://settings
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
  $paths = @(
    Join-Path ${env:ProgramFiles} 'Google\Chrome\Application\chrome.exe',
    Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'
  )
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
  Write-Host "System-wide Chrome not detected. Downloading + installing…" -ForegroundColor Cyan

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

  Write-Host "Installing MSI silently…" -ForegroundColor DarkCyan
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

function Apply-ChromeHardening([string]$RestrictSigninPatternRegex) {
  $base = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
  Ensure-RegistryKey $base

  Write-Host "Applying Chrome hardening policies (machine-wide)…" -ForegroundColor Cyan

  # Disable Guest
  Set-RegistryValue -Path $base -Name 'BrowserGuestModeEnabled'    -Value 0 -Type DWord
  # Disable Incognito (1 = disabled)
  Set-RegistryValue -Path $base -Name 'IncognitoModeAvailability'  -Value 1 -Type DWord
  # Disable adding profiles
  Set-RegistryValue -Path $base -Name 'BrowserAddPersonEnabled'    -Value 0 -Type DWord
  # Force browser sign-in
  Set-RegistryValue -Path $base -Name 'ForceBrowserSignin'         -Value 1 -Type DWord

  if ($RestrictSigninPatternRegex) {
    # Restrict to allowed account(s) using regex
    Set-RegistryValue -Path $base -Name 'RestrictSigninToPattern' -Value $RestrictSigninPatternRegex -Type String
  }

  # Block settings page
  $urlBlock = 'HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist'
  Ensure-RegistryKey $urlBlock
  Set-RegistryValue -Path $urlBlock -Name '1' -Value 'chrome://settings' -Type String

  Write-Host "Chrome policies written. In Chrome: open chrome://policy and click 'Reload policies'." -ForegroundColor Green
}

function Remove-ChromeHardening {
  Write-Host "Removing Chrome hardening policies…" -ForegroundColor Yellow
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
    Write-Host "Unloading user hive…" -ForegroundColor DarkCyan
    & reg.exe unload 'HKU\TEMP_CHILD_HIVE' | Out-Null
  }
}

function Apply-UserLockdownToHive([string]$HiveRoot) {
  # $HiveRoot example: HKU:\TEMP_CHILD_HIVE

  Write-Host "Applying per-user lockdown policies to hive: $HiveRoot" -ForegroundColor Cyan

  # --- Run only specified Windows apps ---
  $expl = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  Set-RegistryValue -Path $expl -Name 'RestrictRun' -Value 1 -Type DWord

  $rr = "$expl\RestrictRun"
  Ensure-RegistryKey $rr
  Set-RegistryValue -Path $rr -Name '1' -Value 'chrome.exe'   -Type String
  Set-RegistryValue -Path $rr -Name '2' -Value 'StudyReel.exe' -Type String

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

  Write-Host "Per-user lockdown values written." -ForegroundColor Green
}

function Remove-UserLockdownFromHive([string]$HiveRoot) {
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

  Write-Host "Per-user lockdown keys removed (where present)." -ForegroundColor Green
}

function Ensure-FirstLogonTask([string]$ChildUserName, [string]$ChildSid) {
  # Creates (or replaces) a SYSTEM task that runs this script at logon of the target user to apply lockdown.
  # This avoids needing MMC per-user GPO for most settings.

  $taskName = "ApplyChildLockdown_$ChildUserName"
  $scriptPath = $PSCommandPath
  if (-not $scriptPath) { throw "Cannot determine script path. Save this script to disk and rerun." }

  $args = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -InternalApplyUserLockdown -InternalUserSid `"$ChildSid`""

  # Delete existing
  & schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null

  # Create
  & schtasks.exe /Create /TN $taskName /SC ONLOGON /RU SYSTEM /RL HIGHEST /TR "powershell.exe $args" /F | Out-Null

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
    Apply-UserLockdownToHive $hive
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
    Remove-UserLockdownFromHive $hive
  } finally {
    Unload-UserHive
  }

  Write-Host "If you created a scheduled task ApplyChildLockdown_$UserName, delete it from Task Scheduler." -ForegroundColor Yellow
  return
}

# Interactive flow
$childUser = Read-Host 'Enter LOCAL child account name to create (e.g., R4)'
if (-not $childUser) { throw 'Username cannot be empty.' }

Ensure-ChromeInstalled
Create-LocalStandardUser -Name $childUser

# Chrome RestrictSigninToPattern
Write-Host "\nChrome sign-in restriction:" -ForegroundColor Cyan
Write-Host "Enter allowed child email(s). Separate multiple emails with commas." -ForegroundColor Cyan
$emailsRaw = Read-Host 'Allowed email(s)'
$emails = @()
if ($emailsRaw) {
  $emails = $emailsRaw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
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

Write-Host "\nApplying Windows per-user lockdown for '$childUser'…" -ForegroundColor Cyan
$hive = $null
try {
  $hive = Load-UserHive $sid
  if ($hive) {
    Apply-UserLockdownToHive $hive
  } else {
    Write-Host "User profile hive not found yet. The child must sign in once to create the profile." -ForegroundColor Yellow
    Write-Host "A logon task will be created so lockdown is applied automatically at first sign-in." -ForegroundColor Yellow
    Ensure-FirstLogonTask -ChildUserName $childUser -ChildSid $sid
  }
} finally {
  Unload-UserHive
}

Write-Host "\nDONE." -ForegroundColor Green
Write-Host "Next steps (manual):" -ForegroundColor Cyan
Write-Host "1) Sign in as the child once (to initialize profile), then sign out." -ForegroundColor Cyan
Write-Host "2) In Chrome for the child: sign in with the allowed account and verify chrome://policy shows status OK." -ForegroundColor Cyan
Write-Host "3) (Optional) Clean desktop icons / hide Recycle Bin using Personalization as desired." -ForegroundColor Cyan
Write-Host "\nRollback:" -ForegroundColor Yellow
Write-Host "- Remove Chrome policies:   .\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1 -RemoveChromePolicies" -ForegroundColor Yellow
Write-Host "- Remove user lockdown:     .\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1 -RemoveUserLockdown -UserName <name>" -ForegroundColor Yellow
