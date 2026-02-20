<#
.SYNOPSIS
Creates a local standard (non-Microsoft) user, ensures system-wide Google Chrome is installed, and applies hardening/lockdown.

.DESCRIPTION
GET THE LATEST VERSION FROM https://github.com/philliphall/Child-School-Account-Lockdown.git!!!
1) Prompts for a local child account name and creates a STANDARD local user.
2) Ensures Google Chrome is installed system-wide. If missing, downloads the official Enterprise MSI and installs silently.
2a) Optionally removes selected built-in distraction apps (best-effort, appx/provisioned).
3) Applies Chrome per-user policies (child user hive) to:
   - Disable Guest Mode
   - Disable Incognito
   - Disable adding new profiles
   - Force browser sign-in
   - Restrict sign-in to allowed email(s)
   - Allow approved extensions for profiles install
   - Block high-risk chrome:// pages and extension installs
4) Applies Windows per-user lockdown policies ONLY to the target child user (not admins).
   If the child has never signed in (no profile hive yet), the script exits and instructs a sign-in/sign-out,
   then rerun, so policies are applied directly to the user hive.
4a) Applies machine policy to disable Widgets/Feeds, disable location, suppress OneDrive backup/sign-in prompts,
    and creates a child logon task for taskbar UI toggles.
5) Applies shell cleanup for the child:
   - Removes desktop shortcuts except approved apps (Chrome + StudyReel + Alpha TimeBack) from child/Public desktop
   - Removes unapproved taskbar pinned shortcuts (best-effort)
   - Sets Chrome to auto-start at child sign-in
6) Copies StudyReel-Installer.exe (if present next to this script) into a secure installer path and creates a
   child-logon scheduled task (runs as the child user) to install it into that profile.

SAFETY
- Does NOT modify Administrator account.
- Chrome and Windows lockdown policies are written only to the target child user profile hive.
- Per-user lockdown is applied ONLY to the specified child account SID.

USAGE (run as Administrator)
  .\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1

Rollback
  .\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1 -RemoveChromePolicies -UserName <name>
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
  [string]$InternalUserSid,
  [string]$InternalRestrictSigninPatternRegexBase64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:TranscriptStartedByScript = $false

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

function Ensure-SecureChildLockdownRoot {
  $root = Join-Path $env:ProgramData 'ChildLockdown'
  Ensure-Directory $root
  & icacls.exe $root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /C | Out-Null
  return $root
}

function Ensure-SecureTaskScriptDirectory {
  $root = Ensure-SecureChildLockdownRoot
  $dir = Join-Path $root 'TaskScripts'
  Ensure-Directory $dir
  # Task script copies stay admin/system only.
  & icacls.exe $dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /C | Out-Null
  return $dir
}

function Ensure-SecureInstallerDirectory([string]$ChildUserName) {
  $root = Ensure-SecureChildLockdownRoot
  $dir = Join-Path $root 'Installers'
  Ensure-Directory $dir

  # Keep installer payloads separate from task scripts; grant child read/execute only here.
  $grants = @("*S-1-5-18:(OI)(CI)(F)", "*S-1-5-32-544:(OI)(CI)(F)")
  if ($ChildUserName) {
    $sid = Get-LocalUserSid $ChildUserName
    if ($sid) { $grants += "*${sid}:(OI)(CI)(RX)" }
  }
  & icacls.exe $dir /inheritance:r /grant:r $grants /C | Out-Null
  return $dir
}

function Start-SecureTranscriptLogging {
  $root = Ensure-SecureChildLockdownRoot
  $logDir = Join-Path $root 'Logs'
  Ensure-Directory $logDir
  & icacls.exe $logDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /C | Out-Null

  $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
  $mode = if ($InternalApplyUserLockdown) {
    'internal_lockdown'
  } elseif ($RemoveChromePolicies) {
    'remove_chrome_policies'
  } elseif ($RemoveUserLockdown) {
    'remove_user_lockdown'
  } else {
    'interactive'
  }
  $logPath = Join-Path $logDir ("Lockdown_{0}_{1}.log" -f $mode, $ts)

  try {
    Start-Transcript -Path $logPath -Append -Force | Out-Null
    $script:TranscriptStartedByScript = $true
    Write-Host "Transcript started: $logPath" -ForegroundColor DarkCyan
  } catch {
    Write-Host "Warning: could not start transcript logging: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

function Stop-SecureTranscriptLogging {
  if (-not $script:TranscriptStartedByScript) { return }
  try {
    Stop-Transcript | Out-Null
  } catch {
    Write-Host "Warning: could not stop transcript cleanly: $($_.Exception.Message)" -ForegroundColor Yellow
  } finally {
    $script:TranscriptStartedByScript = $false
  }
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

function Ensure-CurrentUserExecutionPolicyBypass {
  try {
    $current = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction Stop
  } catch {
    Write-Host "Warning: could not read CurrentUser execution policy: $($_.Exception.Message)" -ForegroundColor Yellow
    return
  }

  if ($current -eq 'Bypass') {
    Write-Host "ExecutionPolicy (CurrentUser) already set to Bypass." -ForegroundColor Green
    return
  }

  try {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction Stop
    Write-Host "Set ExecutionPolicy (CurrentUser) to Bypass." -ForegroundColor Green
  } catch {
    Write-Host "Warning: failed to set ExecutionPolicy (CurrentUser) to Bypass: $($_.Exception.Message)" -ForegroundColor Yellow
  }
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

function Test-LocalUserHasPasswordSet([string]$Name) {
  try {
    $u = Get-LocalUser -Name $Name -ErrorAction Stop
    return ($null -ne $u.PasswordLastSet)
  } catch {
    return $false
  }
}

function Read-ConfirmedSecurePassword([string]$Prompt1 = 'Enter password', [string]$Prompt2 = 'Confirm password') {
  $pw1 = Read-Host $Prompt1 -AsSecureString
  $pw2 = Read-Host $Prompt2 -AsSecureString

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

  return $pw1
}

function Ensure-ChildUserPasswordSettings([string]$Name, [switch]$PromptForPasswordUpdate) {
  if ($PromptForPasswordUpdate) {
    $defaultUpdate = $true
    if (Test-LocalUserHasPasswordSet -Name $Name) {
      $defaultUpdate = $false
    }
    $defaultChoiceText = if ($defaultUpdate) { 'Y' } else { 'N' }
    $pwChoice = Read-Host "Set or update password for '$Name' now? (Y/N, Enter = $defaultChoiceText)"
    $doUpdate = $defaultUpdate
    if (-not [string]::IsNullOrWhiteSpace($pwChoice)) {
      $doUpdate = ($pwChoice -match '^[Yy]')
    }

    if ($doUpdate) {
      $pw = Read-ConfirmedSecurePassword -Prompt1 'Enter password' -Prompt2 'Confirm password'
      Set-LocalUser -Name $Name -Password $pw -ErrorAction Stop
      Write-Host "Password updated for '$Name'." -ForegroundColor Green
    } else {
      Write-Host "Skipping password update for '$Name' at operator request." -ForegroundColor Yellow
    }
  }

  # Prevent forced reset prompts/expiry for this local child account.
  try { Set-LocalUser -Name $Name -PasswordNeverExpires $true -ErrorAction SilentlyContinue } catch {}
  try { & net.exe accounts /maxpwage:unlimited | Out-Null } catch {}
  try { & net.exe user $Name /logonpasswordchg:no | Out-Null } catch {}
  try { & net.exe user $Name /passwordchg:no | Out-Null } catch {}
}

function Create-LocalStandardUser([string]$Name) {
  $result = [PSCustomObject]@{
    Created            = $false
    PasswordConfigured = $false
  }

  $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Host "Local user '$Name' already exists. Skipping creation." -ForegroundColor Yellow
    return $result
  }

  Write-Host "Creating local STANDARD user: $Name" -ForegroundColor Cyan

  $pwChoice = Read-Host "Set a password now? (Y/N)"
  if ($pwChoice -match '^[Yy]') {
    $pw = Read-ConfirmedSecurePassword -Prompt1 'Enter password' -Prompt2 'Confirm password'
    New-LocalUser -Name $Name -Password $pw -AccountNeverExpires:$true -PasswordNeverExpires:$true -UserMayNotChangePassword:$true | Out-Null
    $result.PasswordConfigured = $true
  } else {
    # Create without password only if local policy allows. If blocked, user will see a clear error.
    New-LocalUser -Name $Name -NoPassword -AccountNeverExpires:$true | Out-Null
  }

  # Ensure NOT an admin
  try { Remove-LocalGroupMember -Group 'Administrators' -Member $Name -ErrorAction SilentlyContinue } catch {}
  try { Add-LocalGroupMember -Group 'Users' -Member $Name -ErrorAction SilentlyContinue } catch {}

  Write-Host "User '$Name' created as a standard local user." -ForegroundColor Green
  $result.Created = $true
  return $result
}

function Get-LocalAdministratorsMemberSids {
  $adminSids = New-Object 'System.Collections.Generic.HashSet[string]'

  $adminGroup = $null
  try {
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
  } catch {
    $adminGroup = Get-LocalGroup -Name 'Administrators' -ErrorAction Stop
  }

  $members = @(Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction SilentlyContinue)
  foreach ($m in $members) {
    if ($m.SID -and $m.SID.Value) {
      [void]$adminSids.Add($m.SID.Value)
    }
  }

  return $adminSids
}

function Test-LocalUserIsAdmin([string]$Name) {
  $sid = Get-LocalUserSid $Name
  if (-not $sid) { return $false }
  $adminSids = Get-LocalAdministratorsMemberSids
  return $adminSids.Contains($sid)
}

function Get-EligibleExistingChildUsers {
  $excluded = @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')
  $adminSids = Get-LocalAdministratorsMemberSids

  $users = @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -and $_.Enabled -and ($excluded -notcontains $_.Name)
  } | Sort-Object Name)

  $result = @()
  foreach ($u in $users) {
    $sid = Get-LocalUserSid $u.Name
    if (-not $sid) { continue }
    if ($adminSids.Contains($sid)) { continue }
    $result += $u.Name
  }

  return $result
}

function Prompt-ChildUserSelection {
  Write-Host "`nChild account selection:" -ForegroundColor Cyan
  $existing = @(Get-EligibleExistingChildUsers)

  if ($existing.Count -gt 0) {
    Write-Host "Choose an existing non-admin local account to harden, or create a new one." -ForegroundColor Cyan
    for ($i = 0; $i -lt $existing.Count; $i++) {
      Write-Host ("{0}) {1}" -f ($i + 1), $existing[$i]) -ForegroundColor Cyan
    }
    $createIndex = $existing.Count + 1
    Write-Host ("{0}) Create new local standard user" -f $createIndex) -ForegroundColor Cyan

    while ($true) {
      $choice = Read-Host ("Select option (1-{0})" -f $createIndex)
      if ($choice -match '^\d+$') {
        $idx = [int]$choice
        if (($idx -ge 1) -and ($idx -le $existing.Count)) {
          return [PSCustomObject]@{
            UserName  = $existing[$idx - 1]
            CreateNew = $false
          }
        }
        if ($idx -eq $createIndex) { break }
      }
      Write-Host ("Invalid choice. Enter a number from 1 to {0}." -f $createIndex) -ForegroundColor Yellow
    }
  } else {
    Write-Host "No eligible existing non-admin local accounts were found. Creating a new account." -ForegroundColor Yellow
  }

  while ($true) {
    $name = Read-Host 'Enter LOCAL child account name to create (e.g., Student01)'
    if ([string]::IsNullOrWhiteSpace($name)) {
      Write-Host 'Username cannot be empty.' -ForegroundColor Yellow
      continue
    }

    $existingUser = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if ($existingUser) {
      if (Test-LocalUserIsAdmin -Name $name) {
        Write-Host "User '$name' is an administrator. Choose a different account name." -ForegroundColor Yellow
        continue
      }
      Write-Host "User '$name' already exists and is non-admin; selecting it." -ForegroundColor Yellow
      return [PSCustomObject]@{
        UserName  = $name
        CreateNew = $false
      }
    }

    return [PSCustomObject]@{
      UserName  = $name
      CreateNew = $true
    }
  }
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
  $cmdArgs = "/i `"$tmp`" /qn /norestart"
  $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $cmdArgs -Wait -PassThru
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

function Ensure-WidgetsDisabledMachinePolicy {
  Write-Host "Applying machine-level Widgets/Feeds, Location, and OneDrive prompt suppression policies..." -ForegroundColor Cyan
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -Name 'AllowNewsAndInterests' -Value 0 -Type DWord
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Name 'EnableFeeds' -Value 0 -Type DWord

  # Disable Windows location feature at machine scope (Computer Configuration > Location and Sensors > Turn off location).
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Value 1 -Type DWord
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocationScripting' -Value 1 -Type DWord

  # Reduce OneDrive/backup enrollment prompts.
  # Source: IT Admins - Use OneDrive policies to control sync settings (Microsoft Learn).
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name 'KFMBlockOptIn' -Value 1 -Type DWord
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name 'DisableNewAccountDetection' -Value 1 -Type DWord
}

function Remove-AppxPackagesByPatterns {
  param(
    [Parameter(Mandatory)] [string[]]$Patterns
  )

  $pkgs = @(
    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
      $name = $_.Name
      $family = $_.PackageFamilyName
      foreach ($pat in $Patterns) {
        if (($name -like $pat) -or ($family -like $pat)) { return $true }
      }
      return $false
    }
  )

  foreach ($pkg in $pkgs) {
    try {
      Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop | Out-Null
      Write-Host "Removed installed app package: $($pkg.Name)" -ForegroundColor Green
    } catch {
      try {
        # Fallback for older builds/cmdlets where -AllUsers behavior differs.
        Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop | Out-Null
        Write-Host "Removed app package (fallback): $($pkg.Name)" -ForegroundColor Green
      } catch {
        Write-Host "Warning: could not remove app package '$($pkg.Name)': $($_.Exception.Message)" -ForegroundColor Yellow
      }
    }
  }
}

function Remove-ProvisionedPackagesByPatterns {
  param(
    [Parameter(Mandatory)] [string[]]$Patterns
  )

  $provPkgs = @(
    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {
      $display = $_.DisplayName
      foreach ($pat in $Patterns) {
        if ($display -like $pat) { return $true }
      }
      return $false
    }
  )

  foreach ($prov in $provPkgs) {
    try {
      Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
      Write-Host "Removed provisioned package: $($prov.DisplayName)" -ForegroundColor Green
    } catch {
      Write-Host "Warning: could not remove provisioned package '$($prov.DisplayName)': $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }
}

function Remove-UnnecessaryBuiltInApps {
  Write-Host "`nBuilt-in app cleanup:" -ForegroundColor Cyan
  $choice = Read-Host "Remove unnecessary built-in apps now? (Y/N, Enter = Y)"
  if ($choice -match '^[Nn]') {
    Write-Host "Skipping built-in app cleanup at operator request." -ForegroundColor Yellow
    return
  }

  # Best-effort patterns for common appx/provisioned names across Windows 10/11 variants.
  $patterns = @(
    '*Outlook*',
    '*MicrosoftSolitaireCollection*',
    '*Paint*',
    '*Xbox*',
    '*GamingApp*',
    '*LinkedIn*',
    '*WindowsCamera*',
    '*Copilot*',
    '*WindowsFeedbackHub*',
    '*Bing*',
    '*Clipchamp*',
    '*Teams*',
    '*News*'
  )

  Write-Host "Removing installed appx packages (all users)..." -ForegroundColor DarkCyan
  Remove-AppxPackagesByPatterns -Patterns $patterns

  Write-Host "Removing provisioned appx packages (new profiles)..." -ForegroundColor DarkCyan
  Remove-ProvisionedPackagesByPatterns -Patterns $patterns
}

function Ensure-SecureStudyReelInstallerCopy([string]$SourceScriptPath, [string]$ChildUserName) {
  $candidates = @()
  if ($SourceScriptPath) {
    $srcDir = Split-Path -Path $SourceScriptPath -Parent
    if ($srcDir) { $candidates += (Join-Path $srcDir 'StudyReel-Installer.exe') }
  }
  $cwd = (Get-Location).Path
  if ($cwd) { $candidates += (Join-Path $cwd 'StudyReel-Installer.exe') }

  $sourceInstaller = $null
  foreach ($candidate in @($candidates | Where-Object { $_ } | Select-Object -Unique)) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      $sourceInstaller = (Resolve-Path -LiteralPath $candidate).Path
      break
    }
  }

  if (-not $sourceInstaller) {
    Write-Host "StudyReel installer not found next to script. Expected 'StudyReel-Installer.exe'. Skipping StudyReel install task." -ForegroundColor Yellow
    return $null
  }

  $installerDir = Ensure-SecureInstallerDirectory -ChildUserName $ChildUserName

  $destInstaller = Join-Path $installerDir 'StudyReel-Installer.exe'
  Copy-Item -LiteralPath $sourceInstaller -Destination $destInstaller -Force
  $fileGrants = @("*S-1-5-18:(F)", "*S-1-5-32-544:(F)")
  if ($ChildUserName) {
    $sid = Get-LocalUserSid $ChildUserName
    if ($sid) { $fileGrants += "*${sid}:(RX)" }
  }
  & icacls.exe $destInstaller /inheritance:r /grant:r $fileGrants /C | Out-Null

  Write-Host "Copied StudyReel installer to secure path: $destInstaller" -ForegroundColor Green
  return $destInstaller
}

function Ensure-StudyReelInstallTask([string]$ChildUserName, [string]$InstallerPath) {
  if (-not $InstallerPath -or -not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
    Write-Host "StudyReel installer path is unavailable; skipping StudyReel install task." -ForegroundColor Yellow
    return
  }

  $taskName = "InstallStudyReel_$ChildUserName"
  $userId = "$env:COMPUTERNAME\$ChildUserName"
  $installArgs = '/S'

  if (Get-Command -Name Register-ScheduledTask -ErrorAction SilentlyContinue) {
    try {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }
      $action = New-ScheduledTaskAction -Execute $InstallerPath -Argument $installArgs
      $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
      $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
      Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop | Out-Null
      Write-Host "Created child logon task '$taskName' to install StudyReel in the child profile." -ForegroundColor Green
      return
    } catch {
      Write-Host "Warning: failed to create StudyReel install task with ScheduledTasks cmdlets: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }

  $schtasksPath = "$env:windir\System32\schtasks.exe"
  if (-not (Test-Path $schtasksPath)) { $schtasksPath = 'schtasks.exe' }
  try {
    Start-Process -FilePath $schtasksPath -ArgumentList '/Delete','/TN',$taskName,'/F' -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue | Out-Null
    $trCmd = "`"$InstallerPath`" $installArgs"
    $trArg = '"' + $trCmd + '"'
    $p = Start-Process -FilePath $schtasksPath -ArgumentList '/Create','/TN',$taskName,'/SC','ONLOGON','/RU',$userId,'/RL','LIMITED','/IT','/TR',$trArg,'/F' -NoNewWindow -Wait -PassThru -ErrorAction Stop
    if ($p.ExitCode -eq 0) {
      Write-Host "Created child logon task '$taskName' to install StudyReel in the child profile." -ForegroundColor Green
    } else {
      Write-Host "Warning: schtasks returned exit code $($p.ExitCode) while creating '$taskName'." -ForegroundColor Yellow
    }
  } catch {
    Write-Host "Warning: failed to create StudyReel install task via schtasks.exe: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

function Ensure-ChildTaskbarUiLockTask([string]$ChildUserName) {
  # Runs in child context at next sign-in to enforce taskbar distraction toggles where offline hive ACLs can block writes.
  # Deletes itself after successful execution.
  $taskName = "ApplyChildTaskbarUi_$ChildUserName"
  $userId = "$env:COMPUTERNAME\$ChildUserName"
  $cmdParts = @(
    'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f',
    'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f',
    'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f',
    'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f',
    'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v IsDynamicSearchBoxEnabled /t REG_DWORD /d 0 /f',
    'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f'
  )
  $cmdParts += "schtasks /Delete /TN `"$taskName`" /F"
  $cmd = $cmdParts -join ' & '
  $cmdArgs = "/c $cmd"

  if (Get-Command -Name Register-ScheduledTask -ErrorAction SilentlyContinue) {
    try {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }
      $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $cmdArgs
      $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
      $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
      Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop | Out-Null
      Write-Host "Created one-time child logon task '$taskName' for UI/taskbar lock settings." -ForegroundColor Green
      return
    } catch {
      Write-Host "Warning: failed to create child UI task with ScheduledTasks cmdlets: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }

  $schtasksPath = "$env:windir\System32\schtasks.exe"
  if (-not (Test-Path $schtasksPath)) { $schtasksPath = 'schtasks.exe' }
  try {
    Start-Process -FilePath $schtasksPath -ArgumentList '/Delete','/TN',$taskName,'/F' -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue | Out-Null
    $trCmd = "cmd.exe $cmdArgs"
    $trArg = '"' + $trCmd + '"'
    $p = Start-Process -FilePath $schtasksPath -ArgumentList '/Create','/TN',$taskName,'/SC','ONLOGON','/RU',$userId,'/RL','LIMITED','/IT','/TR',$trArg,'/F' -NoNewWindow -Wait -PassThru -ErrorAction Stop
    if ($p.ExitCode -eq 0) {
      Write-Host "Created one-time child logon task '$taskName' for UI/taskbar lock settings." -ForegroundColor Green
    } else {
      Write-Host "Warning: schtasks returned exit code $($p.ExitCode) while creating '$taskName'." -ForegroundColor Yellow
    }
  } catch {
    Write-Host "Warning: failed to create child UI task via schtasks.exe: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

function Remove-ChildTaskbarUiLockTask([string]$ChildUserName) {
  $taskName = "ApplyChildTaskbarUi_$ChildUserName"
  try {
    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }
    } else {
      & schtasks.exe /Delete /TN $taskName /F | Out-Null
    }
  } catch {}
}

function Remove-AlphaTimeBackInstallTask([string]$ChildUserName) {
  $taskName = "InstallAlphaTimeBack_$ChildUserName"
  try {
    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }
    } else {
      & schtasks.exe /Delete /TN $taskName /F | Out-Null
    }
  } catch {}
}

function Remove-StudyReelInstallTask([string]$ChildUserName) {
  $taskName = "InstallStudyReel_$ChildUserName"
  try {
    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }
    } else {
      & schtasks.exe /Delete /TN $taskName /F | Out-Null
    }
  } catch {}
}

function Remove-FirstLogonTask([string]$ChildUserName) {
  $taskName = "ApplyChildLockdown_$ChildUserName"
  try {
    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }
    } else {
      & schtasks.exe /Delete /TN $taskName /F | Out-Null
    }
  } catch {}
}

function Get-ChromeExecutablePath {
  $paths = @()
  $pf = $env:ProgramFiles
  $pf86 = ${env:ProgramFiles(x86)}
  if ($pf) { $paths += Join-Path $pf 'Google\Chrome\Application\chrome.exe' }
  if ($pf86) { $paths += Join-Path $pf86 'Google\Chrome\Application\chrome.exe' }
  foreach ($p in $paths) {
    if ($p -and (Test-Path $p)) { return $p }
  }
  return $null
}

function Get-StudyReelExecutablePath([string]$ProfilePath) {
  $patterns = @()
  if ($env:ProgramFiles) {
    $patterns += (Join-Path $env:ProgramFiles 'StudyReel\StudyReel.exe')
    $patterns += (Join-Path $env:ProgramFiles 'StudyReel\*\StudyReel.exe')
  }
  if (${env:ProgramFiles(x86)}) {
    $patterns += (Join-Path ${env:ProgramFiles(x86)} 'StudyReel\StudyReel.exe')
    $patterns += (Join-Path ${env:ProgramFiles(x86)} 'StudyReel\*\StudyReel.exe')
  }
  if ($ProfilePath) {
    $patterns += (Join-Path $ProfilePath 'AppData\Local\Programs\StudyReel\StudyReel.exe')
    $patterns += (Join-Path $ProfilePath 'AppData\Local\StudyReel\StudyReel.exe')
  }

  foreach ($pat in $patterns) {
    $hit = Get-ChildItem -Path $pat -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit -and (Test-Path $hit.FullName)) { return $hit.FullName }
  }
  return $null
}

function Get-AlphaTimeBackExecutableLeafNames {
  $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($n in @('TimeBack.exe', 'AlphaTimeBack.exe', 'Alpha TimeBack.exe')) {
    [void]$names.Add($n)
  }

  try {
    $pkgs = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
      $_.Name -match '(?i)(timeback|alpha)' -or $_.PackageFamilyName -match '(?i)(timeback|alpha)'
    })
    foreach ($pkg in $pkgs) {
      if (-not $pkg.InstallLocation) { continue }
      $manifestPath = Join-Path $pkg.InstallLocation 'AppxManifest.xml'
      if (-not (Test-Path $manifestPath)) { continue }
      try {
        [xml]$manifest = Get-Content -Path $manifestPath -Raw -ErrorAction Stop
        $apps = @($manifest.Package.Applications.Application)
        foreach ($app in $apps) {
          $exe = $app.Executable
          if (-not $exe) { continue }
          $leaf = [IO.Path]::GetFileName($exe)
          if ($leaf -and ($leaf -like '*.exe')) {
            [void]$names.Add($leaf)
          }
        }
      } catch {}
    }
  } catch {}

  return @($names)
}

function Test-ShortcutLooksLikeApprovedApp([string]$ShortcutPath, [string]$ChromeExePath, [string]$StudyReelExePath, [string[]]$AlphaTimeBackExeLeafNames) {
  if (-not (Test-Path $ShortcutPath)) { return $false }
  $name = [IO.Path]::GetFileNameWithoutExtension($ShortcutPath)
  if ($name -match '(?i)(chrome|study\s*reel|studyreel|time\s*back|timeback|alpha\s*time\s*back)') { return $true }

  if ($ShortcutPath -like '*.lnk') {
    try {
      $wsh = New-Object -ComObject WScript.Shell
      $sc = $wsh.CreateShortcut($ShortcutPath)
      if (-not $sc.TargetPath) { return $false }
      if ($ChromeExePath -and ($sc.TargetPath -ieq $ChromeExePath)) { return $true }
      if ($StudyReelExePath -and ($sc.TargetPath -ieq $StudyReelExePath)) { return $true }

      $leaf = [IO.Path]::GetFileName($sc.TargetPath)
      if ($leaf -match '^(?i)(chrome\.exe|studyreel\.exe)$') { return $true }
      foreach ($alphaLeaf in @($AlphaTimeBackExeLeafNames)) {
        if ($alphaLeaf -and ($leaf -ieq $alphaLeaf)) { return $true }
      }
    } catch {}
  }
  return $false
}

function Remove-NonApprovedDesktopShortcuts([string]$DesktopPath, [string]$ChromeExePath, [string]$StudyReelExePath, [string[]]$AlphaTimeBackExeLeafNames) {
  if (-not $DesktopPath -or -not (Test-Path $DesktopPath)) { return }

  $shortcutFiles = @(Get-ChildItem -Path $DesktopPath -File -ErrorAction SilentlyContinue | Where-Object {
    $_.Extension -in @('.lnk', '.url', '.appref-ms')
  })
  foreach ($f in $shortcutFiles) {
    if (Test-ShortcutLooksLikeApprovedApp -ShortcutPath $f.FullName -ChromeExePath $ChromeExePath -StudyReelExePath $StudyReelExePath -AlphaTimeBackExeLeafNames $AlphaTimeBackExeLeafNames) { continue }
    Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
  }
}

function Remove-NonApprovedTaskbarPins([string]$ProfilePath, [string]$ChromeExePath, [string]$StudyReelExePath, [string[]]$AlphaTimeBackExeLeafNames) {
  # Best-effort: remove unapproved taskbar pinned shortcuts without creating new ones.
  if (-not $ProfilePath -or -not (Test-Path $ProfilePath)) { return }

  $taskbarPinned = Join-Path $ProfilePath 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'
  if (-not (Test-Path $taskbarPinned)) { return }

  $shortcutFiles = @(Get-ChildItem -Path $taskbarPinned -File -ErrorAction SilentlyContinue | Where-Object {
    $_.Extension -in @('.lnk', '.url', '.appref-ms')
  })
  foreach ($f in $shortcutFiles) {
    if (Test-ShortcutLooksLikeApprovedApp -ShortcutPath $f.FullName -ChromeExePath $ChromeExePath -StudyReelExePath $StudyReelExePath -AlphaTimeBackExeLeafNames $AlphaTimeBackExeLeafNames) { continue }
    Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
  }
}

function Apply-ChildShellSurfaceLockdown([string]$HiveRoot, [string]$Sid) {
  if (-not $Sid) { return }

  $chromeExe = Get-ChromeExecutablePath
  if (-not $chromeExe) {
    Write-Host "Warning: Chrome executable path not found. Skipping shell/icon cleanup." -ForegroundColor Yellow
    return
  }

  # Autostart Chrome for the child at each sign-in.
  $runPath = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Run"
  $runCmd = "`"$chromeExe`" --no-first-run --start-maximized"
  Set-RegistryValue -Path $runPath -Name 'ChildLockdownStartChrome' -Value $runCmd -Type String

  $profilePath = Get-UserProfilePath $Sid
  if (-not $profilePath -or -not (Test-Path $profilePath)) {
    Write-Host "Profile path unavailable; shell cleanup will run on the next successful profile load." -ForegroundColor Yellow
    return
  }

  $childDesktop = Join-Path $profilePath 'Desktop'
  $publicDesktop = Join-Path $env:PUBLIC 'Desktop'
  $studyReelExe = Get-StudyReelExecutablePath -ProfilePath $profilePath
  $alphaTimeBackExeLeafNames = Get-AlphaTimeBackExecutableLeafNames

  # Remove public and per-user shortcuts except approved apps.
  Remove-NonApprovedDesktopShortcuts -DesktopPath $publicDesktop -ChromeExePath $chromeExe -StudyReelExePath $studyReelExe -AlphaTimeBackExeLeafNames $alphaTimeBackExeLeafNames
  Remove-NonApprovedDesktopShortcuts -DesktopPath $childDesktop -ChromeExePath $chromeExe -StudyReelExePath $studyReelExe -AlphaTimeBackExeLeafNames $alphaTimeBackExeLeafNames

  Remove-NonApprovedTaskbarPins -ProfilePath $profilePath -ChromeExePath $chromeExe -StudyReelExePath $studyReelExe -AlphaTimeBackExeLeafNames $alphaTimeBackExeLeafNames
}

function Remove-ChildShellSurfaceLockdown([string]$HiveRoot, [string]$Sid) {
  $runPath = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Run"
  if (Test-Path $runPath) {
    Remove-ItemProperty -Path $runPath -Name 'ChildLockdownStartChrome' -Force -ErrorAction SilentlyContinue
  }
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

function Remove-LegacyMachineChromeHardening {
  $legacyBase = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
  if (Test-Path $legacyBase) {
    Write-Host "Removing legacy machine-wide Chrome policies so per-user policies can take effect..." -ForegroundColor Yellow
    Remove-Item -Path $legacyBase -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Apply-ChromeHardening([string]$HiveRoot, [string]$RestrictSigninPatternRegex) {
  $base = "$HiveRoot\Software\Policies\Google\Chrome"
  Ensure-RegistryKey $base

  Write-Host "Applying Chrome hardening policies to user hive: $HiveRoot" -ForegroundColor Cyan

  # Disable Guest
  Set-RegistryValue -Path $base -Name 'BrowserGuestModeEnabled'    -Value 0 -Type DWord
  # Disable Incognito (1 = disabled)
  Set-RegistryValue -Path $base -Name 'IncognitoModeAvailability'  -Value 1 -Type DWord
  # Force browser sign-in
  Set-RegistryValue -Path $base -Name 'ForceBrowserSignin'         -Value 1 -Type DWord
  # Browser sign-in mode (2 = force sign-in)
  Set-RegistryValue -Path $base -Name 'BrowserSignin'              -Value 2 -Type DWord
  # Lock down browser escape surfaces.
  Set-RegistryValue -Path $base -Name 'DeveloperToolsAvailability' -Value 2 -Type DWord
  Set-RegistryValue -Path $base -Name 'AutofillAddressEnabled'     -Value 0 -Type DWord
  Set-RegistryValue -Path $base -Name 'AutofillCreditCardEnabled'  -Value 0 -Type DWord
  Set-RegistryValue -Path $base -Name 'BlockExternalExtensions'    -Value 1 -Type DWord
  Set-RegistryValue -Path $base -Name 'BlockSensitiveInternalPages' -Value 1 -Type DWord

  # Exceptions to blocking of Sensitive Internal Pages (and other URLs)
  $exceptSensitive = "$base\URLAllowList"
  if (Test-Path $exceptSensitive) { Remove-Item -Path $exceptSensitive -Recurse -Force -ErrorAction SilentlyContinue }
  Ensure-RegistryKey $exceptSensitive
  Set-RegistryValue -Path $exceptSensitive -Name '1' -Value '*' -Type String


  if ($RestrictSigninPatternRegex) {
    # Restrict to allowed account(s) using regex
    Set-RegistryValue -Path $base -Name 'RestrictSigninToPattern' -Value $RestrictSigninPatternRegex -Type String
  }

  # Block all extension installation by default.
  $extBlock = "$base\ExtensionInstallBlocklist"
  if (Test-Path $extBlock) { Remove-Item -Path $extBlock -Recurse -Force -ErrorAction SilentlyContinue }
  Ensure-RegistryKey $extBlock
  Set-RegistryValue -Path $extBlock -Name '1' -Value '*' -Type String

  # Allow specific extensions to be installed by user/profile policy despite blocklist '*'.
  $extAllow = "$base\ExtensionInstallAllowlist"
  if (Test-Path $extAllow) { Remove-Item -Path $extAllow -Recurse -Force -ErrorAction SilentlyContinue }
  # Ensure-RegistryKey $extAllow
  # Set-RegistryValue -Path $extAllow -Name '1' -Value 'ejblanogjchhnpkbplblcmdpgfahhpdi' -Type String # LearnWithAI
  # Set-RegistryValue -Path $extAllow -Name '2' -Value 'oelebjkghohmgbpkdpcblodalbhinkjj' -Type String # StudyReel
  # Set-RegistryValue -Path $extAllow -Name '3' -Value 'pkghkdhemgjcleedplodmflgdlhjefmp' -Type String # Alpha Data Collection

  # Ensure no forced extension install remains from older script versions.
  $extForce = "$base\ExtensionInstallForcelist"
  if (Test-Path $extForce) { Remove-Item -Path $extForce -Recurse -Force -ErrorAction SilentlyContinue }

  # Block pages.
  # $urlBlock = "$base\URLBlocklist"
  # if (Test-Path $urlBlock) { Remove-Item -Path $urlBlock -Recurse -Force -ErrorAction SilentlyContinue }
  # Ensure-RegistryKey $urlBlock
  # $blockedUrls = @(
  #   'example.com'
  # )
  # for ($i = 0; $i -lt $blockedUrls.Count; $i++) {
  #   Set-RegistryValue -Path $urlBlock -Name ($i + 1).ToString() -Value $blockedUrls[$i] -Type String
  # }

  Write-Host "Per-user Chrome policies written. In Chrome: open chrome://policy and click 'Reload policies'." -ForegroundColor Green
}

function Get-ChromeRestrictSigninPatternFromHive([string]$HiveRoot) {
  if (-not $HiveRoot) { return $null }
  $base = "$HiveRoot\Software\Policies\Google\Chrome"
  if (-not (Test-Path $base)) { return $null }
  try {
    $item = Get-ItemProperty -Path $base -Name 'RestrictSigninToPattern' -ErrorAction Stop
    if ($item -and $item.RestrictSigninToPattern) { return [string]$item.RestrictSigninToPattern }
  } catch {}
  return $null
}

function Convert-RestrictSigninPatternToEmails([string]$RestrictSigninPatternRegex) {
  if ([string]::IsNullOrWhiteSpace($RestrictSigninPatternRegex)) { return @() }

  $parts = @()
  if ($RestrictSigninPatternRegex -match '^\^\((.*)\)\$$') {
    $parts = @($Matches[1] -split '(?<!\\)\|')
  } elseif ($RestrictSigninPatternRegex -match '^\^(.*)\$$') {
    $parts = @($Matches[1])
  } else {
    return @()
  }

  $emails = @()
  foreach ($p in $parts) {
    $candidate = [Regex]::Unescape($p).Trim()
    if ($candidate) { $emails += $candidate }
  }

  return @($emails | Select-Object -Unique)
}

function Remove-ChromeHardening([string]$HiveRoot) {
  Write-Host "Removing per-user Chrome hardening policies from hive: $HiveRoot" -ForegroundColor Yellow
  $base = "$HiveRoot\Software\Policies\Google\Chrome"
  if (Test-Path $base) {
    Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue
  }
  Write-Host "Removed per-user Chrome policy keys. Restart Chrome to verify." -ForegroundColor Green
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
    (Join-Path $profilePath 'Videos')
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

function Resolve-UserHiveAccess([string]$Sid) {
  # Prefer the live HKEY_USERS\<SID> hive if already loaded (common during interactive sign-in).
  $liveMountPath = "Registry::HKEY_USERS\$Sid"
  if (Test-Path $liveMountPath) {
    return [PSCustomObject]@{
      HiveRoot           = "Registry::HKEY_USERS\$Sid"
      TempHiveName       = $null
      LoadedByThisScript = $false
    }
  }

  $profilePath = Get-UserProfilePath $Sid
  if (-not $profilePath) { return $null }

  $ntuser = Join-Path $profilePath 'NTUSER.DAT'
  if (-not (Test-Path $ntuser)) { return $null }

  $mountName = 'TEMP_CHILD_HIVE_{0}' -f ($Sid -replace '[^A-Za-z0-9]', '_')
  $mountPath = "Registry::HKEY_USERS\$mountName"

  if (Test-Path $mountPath) {
    return [PSCustomObject]@{
      HiveRoot           = "Registry::HKEY_USERS\$mountName"
      TempHiveName       = $mountName
      LoadedByThisScript = $false
    }
  }

  Write-Host "Loading user hive from $ntuser" -ForegroundColor DarkCyan
  & reg.exe load "HKU\$mountName" "$ntuser" | Out-Null
  if (($LASTEXITCODE -ne 0) -or -not (Test-Path $mountPath)) {
    # If profile just finished loading after task start, fallback to live SID hive.
    if (Test-Path $liveMountPath) {
      return [PSCustomObject]@{
        HiveRoot           = "Registry::HKEY_USERS\$Sid"
        TempHiveName       = $null
        LoadedByThisScript = $false
      }
    }
    Write-Host "Failed to load user hive for SID $Sid." -ForegroundColor Yellow
    return $null
  }

  return [PSCustomObject]@{
    HiveRoot           = "Registry::HKEY_USERS\$mountName"
    TempHiveName       = $mountName
    LoadedByThisScript = $true
  }
}

function Close-UserHiveAccess($HiveAccess) {
  if (-not $HiveAccess) { return }
  if (-not $HiveAccess.LoadedByThisScript) { return }
  if (-not $HiveAccess.TempHiveName) { return }

  $mountPath = "Registry::HKEY_USERS\$($HiveAccess.TempHiveName)"
  if (-not (Test-Path $mountPath)) { return }

  Write-Host "Unloading user hive..." -ForegroundColor DarkCyan
  & reg.exe unload "HKU\$($HiveAccess.TempHiveName)" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: could not unload temporary hive HKU\$($HiveAccess.TempHiveName)." -ForegroundColor Yellow
  }
}

function Ensure-TaskSchedulerHistoryEnabled {
  Write-Host "Ensuring Task Scheduler history is enabled..." -ForegroundColor Cyan

  $wevtutil = Join-Path $env:windir 'System32\wevtutil.exe'
  if (-not (Test-Path $wevtutil)) { $wevtutil = 'wevtutil.exe' }

  & $wevtutil set-log 'Microsoft-Windows-TaskScheduler/Operational' /enabled:true | Out-Null
  if ($LASTEXITCODE -eq 0) {
    Write-Host "Task Scheduler history enabled." -ForegroundColor Green
  } else {
    Write-Host "Warning: could not enable Task Scheduler history." -ForegroundColor Yellow
  }
}

function Set-SystemTimeAndLocation {
  param(
    [Parameter(Mandatory)] [string]$TimeZoneId,
    [Parameter(Mandatory)] [int]$GeoId
  )

  try {
    Set-TimeZone -Id $TimeZoneId -ErrorAction Stop
    Write-Host "Time zone set to '$TimeZoneId'." -ForegroundColor Green
  } catch {
    Write-Host "Warning: failed to set time zone '$TimeZoneId': $($_.Exception.Message)" -ForegroundColor Yellow
  }

  if (Get-Command -Name Set-WinHomeLocation -ErrorAction SilentlyContinue) {
    try {
      Set-WinHomeLocation -GeoId $GeoId -ErrorAction Stop
      Write-Host "Windows home location GeoID set to $GeoId." -ForegroundColor Green
    } catch {
      Write-Host "Warning: failed to set Windows home location GeoID ${GeoId}: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  } else {
    Write-Host "Set-WinHomeLocation cmdlet is unavailable; skipped home location update." -ForegroundColor Yellow
  }
}

function Get-CurrentSystemTimeAndLocation {
  $timeZoneId = $null
  $geoId = $null

  try {
    $tz = Get-TimeZone -ErrorAction Stop
    if ($tz -and $tz.Id) { $timeZoneId = $tz.Id }
  } catch {}

  if (-not $timeZoneId) {
    try {
      $tzText = (& tzutil.exe /g 2>$null)
      if ($tzText) { $timeZoneId = $tzText.Trim() }
    } catch {}
  }

  if (Get-Command -Name Get-WinHomeLocation -ErrorAction SilentlyContinue) {
    try {
      $loc = Get-WinHomeLocation -ErrorAction Stop
      if ($loc -and ($null -ne $loc.GeoId)) { $geoId = [int]$loc.GeoId }
    } catch {}
  }

  return [PSCustomObject]@{
    TimeZoneId = $timeZoneId
    GeoId      = $geoId
  }
}

function Prompt-TimeAndLocationSetup {
  $current = Get-CurrentSystemTimeAndLocation
  $defaultTimeZone = if ($current.TimeZoneId) { $current.TimeZoneId } else { 'Pacific Standard Time' }
  $defaultGeoId = if ($null -ne $current.GeoId) { [int]$current.GeoId } else { 244 } # 244 = United States

  Write-Host "`nTime and location setup:" -ForegroundColor Cyan
  $geoLabel = if ($null -ne $current.GeoId) { $current.GeoId } else { 'unknown' }
  Write-Host "Current system settings: Time Zone = $defaultTimeZone, GeoID = $geoLabel" -ForegroundColor Cyan
  $choice = Read-Host "Keep current system settings? (Y/N, Enter = Y)"

  if ([string]::IsNullOrWhiteSpace($choice) -or ($choice -match '^[Yy]')) {
    Write-Host "Keeping current system time/location settings." -ForegroundColor Green
    return
  }

  $tzInput = Read-Host "Enter Windows Time Zone ID (Enter = $defaultTimeZone)"
  if ([string]::IsNullOrWhiteSpace($tzInput)) { $tzInput = $defaultTimeZone }

  $geoInput = Read-Host "Enter Windows Home Location GeoID (Enter = $defaultGeoId)"
  $geoId = $defaultGeoId
  if (-not [string]::IsNullOrWhiteSpace($geoInput)) {
    if ($geoInput -match '^\d+$') {
      $geoId = [int]$geoInput
    } else {
      Write-Host "Invalid GeoID '$geoInput'; using default $defaultGeoId." -ForegroundColor Yellow
    }
  }

  Set-SystemTimeAndLocation -TimeZoneId $tzInput -GeoId $geoId
}

function Apply-UserLockdownToHive([string]$HiveRoot, [string]$Sid) {
  # $HiveRoot example: Registry::HKEY_USERS\<SID>

  Write-Host "Applying per-user lockdown policies to hive: $HiveRoot" -ForegroundColor Cyan

  # --- Run only specified Windows apps ---
  $expl = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  Set-RegistryValue -Path $expl -Name 'RestrictRun' -Value 1 -Type DWord

  $rr = "$expl\RestrictRun"
  if (Test-Path $rr) { Remove-Item -Path $rr -Recurse -Force -ErrorAction SilentlyContinue }
  Ensure-RegistryKey $rr
  $allowedApps = @('chrome.exe', 'StudyReel.exe', 'StudyReel-Installer.exe')
  $allowedApps += Get-AlphaTimeBackExecutableLeafNames
  $allowedApps = @($allowedApps | Where-Object { $_ } | Select-Object -Unique)
  for ($i = 0; $i -lt $allowedApps.Count; $i++) {
    Set-RegistryValue -Path $rr -Name ($i + 1).ToString() -Value $allowedApps[$i] -Type String
  }

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

  # --- Enforce lock screen on idle + password on resume ---
  $desktopPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
  Set-RegistryValue -Path $desktopPol -Name 'ScreenSaveActive'    -Value '1'   -Type String
  Set-RegistryValue -Path $desktopPol -Name 'ScreenSaverIsSecure' -Value '0'   -Type String
  Set-RegistryValue -Path $desktopPol -Name 'ScreenSaveTimeOut'   -Value '300' -Type String
  Set-RegistryValue -Path $desktopPol -Name 'SCRNSAVE.EXE'        -Value (Join-Path $env:WINDIR 'System32\scrnsave.scr') -Type String

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
  # Remove notification center to reduce distractions.
  Set-RegistryValue -Path $expl -Name 'DisableNotificationCenter' -Value 1 -Type DWord
  # Do not allow pinning changes on taskbar.
  # Set-RegistryValue -Path $expl -Name 'NoPinningToTaskbar'     -Value 1 -Type DWord

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

  # --- Allow Settings app, but restrict visible pages to Wi-Fi/network only ---
  Set-RegistryValue -Path $expl -Name 'NoControlPanel' -Value 0 -Type DWord
  Set-RegistryValue -Path $expl -Name 'SettingsPageVisibility' -Value 'showonly:network-status;network-wifi;network-wifisettings' -Type String

  # --- Remove Task Manager ---
  Set-RegistryValue -Path $sys -Name 'DisableTaskMgr' -Value 1 -Type DWord

  # --- Reduce search surfaces (best-effort; varies by Windows build) ---
  $winExplorerPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Explorer"
  Ensure-RegistryKey $winExplorerPol
  Set-RegistryValue -Path $winExplorerPol -Name 'DisableSearchBoxSuggestions' -Value 1 -Type DWord
  # Hide Task View to reduce virtual desktop creation/switching surfaces.
  Set-RegistryValue -Path $winExplorerPol -Name 'HideTaskViewButton' -Value 1 -Type DWord
  
  # Clear pinned Start apps.
  Set-RegistryValue -Path $winExplorerPol -Name 'ConfigureStartPins' -Value '{"pinnedList":[]}' -Type String

  # Disable widgets/feeds surfaces (best-effort across Windows builds).
  $dshPol = "$HiveRoot\Software\Policies\Microsoft\Dsh"
  Set-RegistryValue -Path $dshPol -Name 'AllowNewsAndInterests' -Value 0 -Type DWord
  $feedsPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Windows Feeds"
  Set-RegistryValue -Path $feedsPol -Name 'EnableFeeds' -Value 0 -Type DWord

  # Windows location prompt toggle in child profile:
  # "Notify when apps request location" = off.
  $locationConsent = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
  Set-RegistryValue -Path $locationConsent -Name 'ShowGlobalPrompts' -Value 0 -Type DWord

  # Per-user taskbar/search/feed UI values are applied by a one-time child logon task
  # (offline hive ACLs can block writes under Explorer\Advanced).

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
    'TaskView.exe',
    'notepad.exe',
    'msedge.exe',
    'iexplore.exe'
  )
  for ($i = 0; $i -lt $blockedApps.Count; $i++) {
    Set-RegistryValue -Path $dr -Name ($i + 1).ToString() -Value $blockedApps[$i] -Type String
  }

  if ($Sid) {
    Apply-ChildExecutionDenyAcls -Sid $Sid
    Apply-ChildShellSurfaceLockdown -HiveRoot $HiveRoot -Sid $Sid
  }

  Write-Host "Per-user lockdown values written." -ForegroundColor Green
}

function Remove-UserLockdownFromHive([string]$HiveRoot, [string]$Sid) {
  Write-Host "Removing per-user lockdown policies from hive: $HiveRoot" -ForegroundColor Yellow

  $expl = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  $sysPol = "$HiveRoot\Software\Policies\Microsoft\Windows\System"
  $sys = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System"
  $desktopPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
  $store = "$HiveRoot\Software\Policies\Microsoft\WindowsStore"
  $winExplorerPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Explorer"
  $dshPol = "$HiveRoot\Software\Policies\Microsoft\Dsh"
  $feedsPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Windows Feeds"
  $locationConsent = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
  $explorerAdvanced = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
  $search = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Search"
  $feeds = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Feeds"

  # Remove the keys we created (best-effort)
  foreach ($k in @($expl, "$expl\RestrictRun", $sysPol, $sys, $desktopPol, $store, $winExplorerPol, $dshPol, $feedsPol)) {
    if (Test-Path $k) { Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue }
  }

  # Clean up non-policy values written under regular per-user locations.
  foreach ($pair in @(
    @{ Path = $locationConsent; Name = 'ShowGlobalPrompts' },
    @{ Path = $explorerAdvanced; Name = 'TaskbarDa' },
    @{ Path = $explorerAdvanced; Name = 'TaskbarMn' },
    @{ Path = $explorerAdvanced; Name = 'ShowTaskViewButton' },
    @{ Path = $search; Name = 'SearchboxTaskbarMode' },
    @{ Path = $search; Name = 'IsDynamicSearchBoxEnabled' },
    @{ Path = $feeds; Name = 'ShellFeedsTaskbarViewMode' }
  )) {
    if (Test-Path $pair.Path) {
      Remove-ItemProperty -Path $pair.Path -Name $pair.Name -Force -ErrorAction SilentlyContinue
    }
  }

  if ($Sid) {
    Remove-ChildExecutionDenyAcls -Sid $Sid
    Remove-ChildShellSurfaceLockdown -HiveRoot $HiveRoot -Sid $Sid
  }

  Write-Host "Per-user lockdown keys removed (where present)." -ForegroundColor Green
}

function Ensure-SecureTaskScriptCopy([string]$SourcePath) {
  $taskDir = Ensure-SecureTaskScriptDirectory

  $destPath = Join-Path $taskDir 'ApplyChildLockdown.ps1'
  Copy-Item -Path $SourcePath -Destination $destPath -Force

  # Lock task script path to SYSTEM + local admins only.
  & icacls.exe $destPath /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" /C | Out-Null

  return $destPath
}

function Ensure-FirstLogonTask([string]$ChildUserName, [string]$ChildSid, [string]$RestrictSigninPatternRegex) {
  # Creates (or replaces) a SYSTEM task that runs this script at logon of the target user to apply per-user policies.
  # This avoids needing MMC per-user GPO for most settings.

  $taskName = "ApplyChildLockdown_$ChildUserName"
  $scriptPath = $PSCommandPath
  if (-not $scriptPath) { throw "Cannot determine script path. Save this script to disk and rerun." }
  $taskScriptPath = Ensure-SecureTaskScriptCopy -SourcePath $scriptPath

  $cmdArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$taskScriptPath`" -InternalApplyUserLockdown -InternalUserSid `"$ChildSid`""
  if ($RestrictSigninPatternRegex) {
    $patternBytes = [System.Text.Encoding]::Unicode.GetBytes($RestrictSigninPatternRegex)
    $patternBase64 = [Convert]::ToBase64String($patternBytes)
    $cmdArgs += " -InternalRestrictSigninPatternRegexBase64 `"$patternBase64`""
  }

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

      $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $cmdArgs
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
      $trCmd = "powershell.exe $cmdArgs"
      $trArg = '"' + $trCmd + '"'
      Start-Process -FilePath $schtasksPath -ArgumentList '/Create','/TN',$taskName,'/SC','ONLOGON','/RU','SYSTEM','/RL','HIGHEST','/TR',$trArg,'/F' -NoNewWindow -Wait -PassThru -ErrorAction Stop | Out-Null
    } catch {
      throw "Failed to create scheduled task via ${schtasksPath}: $($_.Exception.Message)"
    }
  }

  Write-Host "Created logon task '$taskName' to apply per-user Chrome + Windows lockdown at first sign-in." -ForegroundColor Green
}

function Internal-ApplyUserLockdown([string]$Sid, [string]$RestrictSigninPatternRegex) {
  Assert-Admin
  $hiveAccess = $null
  try {
    $hiveAccess = Resolve-UserHiveAccess $Sid
    if (-not $hiveAccess) {
      Write-Host "User hive not available yet (profile not created)." -ForegroundColor Yellow
      return
    }
    Remove-LegacyMachineChromeHardening
    Apply-ChromeHardening -HiveRoot $hiveAccess.HiveRoot -RestrictSigninPatternRegex $RestrictSigninPatternRegex
    Apply-UserLockdownToHive -HiveRoot $hiveAccess.HiveRoot -Sid $Sid
  } finally {
    Close-UserHiveAccess -HiveAccess $hiveAccess
  }
}

# ---------------- MAIN ----------------
Assert-Admin
try {
  Start-SecureTranscriptLogging

  if ($InternalApplyUserLockdown) {
    if (-not $InternalUserSid) { throw 'Missing -InternalUserSid' }
    $internalRestrictPattern = $null
    if ($InternalRestrictSigninPatternRegexBase64) {
      try {
        $patternBytes = [Convert]::FromBase64String($InternalRestrictSigninPatternRegexBase64)
        $internalRestrictPattern = [System.Text.Encoding]::Unicode.GetString($patternBytes)
      } catch {
        throw "Invalid -InternalRestrictSigninPatternRegexBase64 value: $($_.Exception.Message)"
      }
    }
    Internal-ApplyUserLockdown -Sid $InternalUserSid -RestrictSigninPatternRegex $internalRestrictPattern
    return
  }

  if ($RemoveChromePolicies) {
    if (-not $UserName) { $UserName = Read-Host 'Enter the child local username to remove Chrome policies from' }
    $sid = Get-LocalUserSid $UserName
    if (-not $sid) { throw "Could not find SID for user '$UserName'" }

    $hiveAccess = $null
    try {
      $hiveAccess = Resolve-UserHiveAccess $sid
      if (-not $hiveAccess) {
        Write-Host "Cannot load hive now. Have the user sign in once to create the profile, then rerun." -ForegroundColor Yellow
        return
      }
      Remove-ChromeHardening -HiveRoot $hiveAccess.HiveRoot
      Remove-LegacyMachineChromeHardening
    } finally {
      Close-UserHiveAccess -HiveAccess $hiveAccess
    }
    return
  }

  if ($RemoveUserLockdown) {
    if (-not $UserName) { $UserName = Read-Host 'Enter the child local username to unlock' }
    $sid = Get-LocalUserSid $UserName
    if (-not $sid) { throw "Could not find SID for user '$UserName'" }

    $hiveAccess = $null
    try {
      $hiveAccess = Resolve-UserHiveAccess $sid
      if (-not $hiveAccess) {
        Write-Host "Cannot load hive now. Have the user sign in once to create the profile, then rerun." -ForegroundColor Yellow
        return
      }
      Remove-UserLockdownFromHive -HiveRoot $hiveAccess.HiveRoot -Sid $sid
    } finally {
      Close-UserHiveAccess -HiveAccess $hiveAccess
    }

    Remove-FirstLogonTask -ChildUserName $UserName
    Remove-ChildTaskbarUiLockTask -ChildUserName $UserName
    Remove-AlphaTimeBackInstallTask -ChildUserName $UserName
    Remove-StudyReelInstallTask -ChildUserName $UserName
    return
  }

  # Interactive flow
  $selection = Prompt-ChildUserSelection
  $childUser = $selection.UserName
  if (-not $childUser) { throw 'Username cannot be empty.' }

  $secureTaskScriptPath = $null
  $scriptPathForSecureCopy = $PSCommandPath
  if (-not $scriptPathForSecureCopy) { $scriptPathForSecureCopy = $MyInvocation.MyCommand.Path }
  if ($scriptPathForSecureCopy -and (Test-Path $scriptPathForSecureCopy)) {
    try {
      $secureTaskScriptPath = Ensure-SecureTaskScriptCopy -SourcePath $scriptPathForSecureCopy
    } catch {
      Write-Host "Warning: could not refresh secure task script copy: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  } else {
    Write-Host "Warning: script path was not resolvable; secure task script copy was not refreshed." -ForegroundColor Yellow
  }
  
  Ensure-CurrentUserExecutionPolicyBypass
  Ensure-TaskSchedulerHistoryEnabled
  Prompt-TimeAndLocationSetup

  Ensure-WidgetsDisabledMachinePolicy
  Remove-UnnecessaryBuiltInApps
  Ensure-ChromeInstalled
  $creationResult = $null
  if ($selection.CreateNew) {
    $creationResult = Create-LocalStandardUser -Name $childUser
  } else {
    if (Test-LocalUserIsAdmin -Name $childUser) {
      throw "Selected user '$childUser' is an administrator. Choose a non-admin account."
    }
    Write-Host "Using existing non-admin local user '$childUser'." -ForegroundColor Green
  }

  $promptForPasswordUpdate = $true
  if ($selection.CreateNew -and $creationResult -and $creationResult.PasswordConfigured) {
    $promptForPasswordUpdate = $false
  }
  Ensure-ChildUserPasswordSettings -Name $childUser -PromptForPasswordUpdate:$promptForPasswordUpdate
  $sid = Get-LocalUserSid $childUser
  if (-not $sid) { throw "Could not resolve SID for '$childUser'" }

  # Always clean up stale scheduled tasks from prior script versions.
  Remove-FirstLogonTask -ChildUserName $childUser
  Remove-ChildTaskbarUiLockTask -ChildUserName $childUser
  Remove-AlphaTimeBackInstallTask -ChildUserName $childUser

  if ($selection.CreateNew) {
    Write-Host "`nNew child account '$childUser' created." -ForegroundColor Green
    Write-Host "Next step required before lockdown can be applied:" -ForegroundColor Cyan
    Write-Host "1) Sign in as '$childUser' once, then sign out." -ForegroundColor Cyan
    Write-Host "2) Run this script again and select existing user '$childUser'." -ForegroundColor Cyan
    Write-Host "No first-logon lockdown scheduled task was created." -ForegroundColor Yellow
    return
  }

  Ensure-ChildTaskbarUiLockTask -ChildUserName $childUser
  $secureStudyReelInstallerPath = Ensure-SecureStudyReelInstallerCopy -SourceScriptPath $PSCommandPath -ChildUserName $childUser
  Ensure-StudyReelInstallTask -ChildUserName $childUser -InstallerPath $secureStudyReelInstallerPath

  # Chrome RestrictSigninToPattern
  Write-Host "`nChrome sign-in restriction:" -ForegroundColor Cyan
  $emails = @()
  $defaultAllowedEmails = @()
  if (-not $selection.CreateNew) {
    $existingPattern = $null
    $existingPolicyHive = $null
    try {
      $existingPolicyHive = Resolve-UserHiveAccess $sid
      if ($existingPolicyHive) {
        $existingPattern = Get-ChromeRestrictSigninPatternFromHive -HiveRoot $existingPolicyHive.HiveRoot
      }
    } finally {
      Close-UserHiveAccess -HiveAccess $existingPolicyHive
    }
    if ($existingPattern) {
      $defaultAllowedEmails = Convert-RestrictSigninPatternToEmails -RestrictSigninPatternRegex $existingPattern
      if ($defaultAllowedEmails.Count -gt 0) {
        Write-Host ("Existing allowed email(s): {0}" -f ($defaultAllowedEmails -join ', ')) -ForegroundColor DarkCyan
      } else {
        Write-Host "Existing RestrictSigninToPattern found but not in simple email-list form; enter desired email(s)." -ForegroundColor Yellow
      }
    }
  }

  if ($defaultAllowedEmails.Count -gt 0) {
    $emailsRaw = Read-Host 'Keep existing allowed email(s)? (Y/N, Enter = Y)'
    if ([string]::IsNullOrWhiteSpace($emailsRaw) -or ($emailsRaw -match '^[Yy]')) {
      $emails = @($defaultAllowedEmails)
    } 
  } 
  if ($emails.Count -eq 0) {
    Write-Host "Enter allowed child email(s). Separate multiple emails with commas. Leave blank to allow all." -ForegroundColor Cyan
    $emailsRaw = Read-Host 'Allowed email(s)'
    if ($emailsRaw) {
      $emails = @($emailsRaw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
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

  # Per-user lockdown + Chrome policy
  Write-Host "`nApplying per-user Chrome and Windows lockdown for '$childUser'..." -ForegroundColor Cyan
  $hiveAccess = $null
  try {
    $hiveAccess = Resolve-UserHiveAccess $sid
    if ($hiveAccess) {
      Remove-LegacyMachineChromeHardening
      Apply-ChromeHardening -HiveRoot $hiveAccess.HiveRoot -RestrictSigninPatternRegex $pattern
      Apply-UserLockdownToHive -HiveRoot $hiveAccess.HiveRoot -Sid $sid
    } else {
      Write-Host "User profile hive not found yet. Sign in once as '$childUser', sign out, then rerun this script." -ForegroundColor Yellow
      return
    }
  } finally {
    Close-UserHiveAccess -HiveAccess $hiveAccess
  }

  Write-Host "`nDONE." -ForegroundColor Green
  $secureRoot = Ensure-SecureChildLockdownRoot
  if (-not $secureTaskScriptPath) {
    $secureTaskScriptPath = Join-Path (Join-Path $secureRoot 'TaskScripts') 'ApplyChildLockdown.ps1'
  }
  $secureStudyReelCopyPath = Join-Path (Join-Path $secureRoot 'Installers') 'StudyReel-Installer.exe'
  Write-Host "Reusable secure path (kept until manually removed): $secureRoot" -ForegroundColor Cyan
  if (Test-Path $secureTaskScriptPath) {
    Write-Host "- Script copy (admin/system only): $secureTaskScriptPath" -ForegroundColor Cyan
  }
  if (Test-Path $secureStudyReelCopyPath) {
    Write-Host "- StudyReel installer payload path: $secureStudyReelCopyPath" -ForegroundColor Cyan
  }
  Write-Host "Next steps (manual):" -ForegroundColor Cyan
  Write-Host "1) Sign in as the child once (to initialize profile), then sign out." -ForegroundColor Cyan
  Write-Host "2) In Chrome for the child: sign in with the allowed account and verify chrome://policy shows status OK." -ForegroundColor Cyan
  Write-Host "`nRollback (must be run as the administrative user):" -ForegroundColor Yellow
  Write-Host "- Remove Chrome policies:   $secureTaskScriptPath -RemoveChromePolicies -UserName $childUser" -ForegroundColor Yellow
  Write-Host "- Remove user lockdown:     $secureTaskScriptPath -RemoveUserLockdown -UserName $childUser" -ForegroundColor Yellow
} finally {
  Stop-SecureTranscriptLogging
}
