# Child School Account Lockdown

PowerShell automation to create or harden a local child account for school use on Windows, with a locked-down Chrome experience and reduced Windows distraction/bypass surfaces.

Primary script:
- `Harden-Chrome-And-Lockdown-ChildUser_v2.ps1`

## What This Script Does

When run as Administrator, the script performs an interactive workflow that can:

1. Select an existing non-admin local user, or create a new standard local child user.
2. Ensure system-wide Google Chrome is installed (downloads official Google Enterprise MSI if missing, verifies Authenticode signature, installs silently).
3. Optionally remove selected built-in Windows apps (best effort).
4. Apply machine-level policies (Widgets/Feeds off, location off, reduced OneDrive enrollment prompts).
5. Apply per-user Chrome policies to the child profile hive.
6. Apply per-user Windows lockdown policies to the child profile hive.
7. Apply shell cleanup/autostart behavior for the child:
   - Keep only approved desktop/taskbar shortcuts (Chrome, StudyReel, Alpha TimeBack family).
   - Autostart Chrome at child sign-in.
8. Optionally stage and schedule `StudyReel-Installer.exe` for child-logon install.
9. Create transcript logs in a secured location.

## Safety Model

The script is designed to scope lockdown to the selected child account:

- Does not change Administrator account membership.
- Writes Chrome and Windows per-user lockdown keys under the target child SID hive.
- Uses secure ACLs for generated task/script/installer folders under `C:\ProgramData\ChildLockdown`.

## Requirements

- Windows 10/11 (local account management + scheduled task cmdlets expected).
- Run from **elevated PowerShell** (`Run as administrator`).
- Internet access if Chrome must be downloaded.
- Optional: place `StudyReel-Installer.exe` next to the script (or current working directory) if you want scheduled StudyReel install support.

## Quick Start

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
cd C:\script_path\
.\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1
```

The script is interactive and will prompt for:
- child account selection/creation
- password update behavior
- time zone and home location preference
- built-in app cleanup
- StudyReel install task creation (if StudyReel is not already detected)
- allowed Chrome sign-in email(s)

## New Account vs Existing Account

### If you create a new child account
Current behavior is intentionally two-pass:

1. Script creates the local standard user.
2. You sign in once as the child (to initialize profile), then sign out.
3. Run the script again and select that existing user.

The script explicitly reports that it does **not** create the old first-logon lockdown task in this path.

### If you select an existing child account
The script applies lockdown immediately to that user hive/SID.

## Rollback

### Remove Chrome policy lockdown for one child user

```powershell
.\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1 -RemoveChromePolicies -UserName <ChildUserName>
```

### Remove Windows user lockdown for one child user

```powershell
.\Harden-Chrome-And-Lockdown-ChildUser_v2.ps1 -RemoveUserLockdown -UserName <ChildUserName>
```

## Rollback Scope Notes

- `-RemoveChromePolicies` removes per-user Chrome policy keys from the child hive.
- `-RemoveUserLockdown` removes per-user lockdown keys/values and cleanup tasks for that child.
- These rollback modes do **not** automatically restore:
  - machine-level HKLM policies
  - removed built-in AppX/provisioned apps
  - any manual system time/location changes chosen during setup

## Policy Summary

### Chrome (per child user hive)

Applies under `HKU\<ChildSID>\Software\Policies\Google\Chrome`:

- disables Guest mode
- disables Incognito
- forces browser sign-in
- restricts sign-in to entered email regex pattern (optional; cleared if blank)
- blocks extension installs by default (`ExtensionInstallBlocklist = *`)
- removes any extension force-install list from legacy versions
- allows `chrome://policy` via URL allowlist
- disables dev tools / external extensions / sensitive internal pages and autofill surfaces

### Windows Lockdown (per child user hive)

Includes:

- `RestrictRun` allowlist (Chrome, StudyReel, StudyReel installer, AlphaTimeBack exe names)
- `DisallowRun` blocklist for common bypass tools (`cmd`, `powershell`, `regedit`, `msiexec`, etc.)
- disables CMD and registry tools
- removes Task Manager
- limits Start/taskbar/search/feed surfaces
- disables Store
- removes right-click context menu
- hides/restricts all drives in Explorer
- sets restricted Settings page visibility
- applies execute-deny ACLs on child-writable profile folders (Desktop/Downloads/Documents/Pictures/Music/Videos)
- sets Chrome autostart via child `Run` key

### Machine-Level Policies (HKLM)

- disable Widgets/Feeds
- disable location + location scripting
- suppress OneDrive KFM opt-in/new-account prompts

## Scheduled Tasks and Secure Working Paths

The script may create/manage child-specific tasks such as:

- `ApplyChildTaskbarUi_<ChildUser>`
- `InstallStudyReel_<ChildUser>`

It also removes stale legacy tasks if present:

- `ApplyChildLockdown_<ChildUser>`
- `InstallAlphaTimeBack_<ChildUser>`

Secure working root:
- `C:\ProgramData\ChildLockdown`

Common subpaths:
- `C:\ProgramData\ChildLockdown\Logs`
- `C:\ProgramData\ChildLockdown\TaskScripts\ApplyChildLockdown.ps1`
- `C:\ProgramData\ChildLockdown\Installers\StudyReel-Installer.exe`

## Operational Notes

- The script enables CurrentUser execution policy `Bypass` for the admin user running it.
- Task Scheduler history is enabled for better auditing.
- Chrome policy verification tip: open `chrome://policy` and click `Reload policies`.
- Behavior of some Windows shell/search/store policies varies by Windows version.

## License

See [LICENSE](./LICENSE).
