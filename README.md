# OS-Guard + DNS-Guard

Enterprise **OS Child Lockdown** + **DNS Hijack Protection** & Installer Suite (IPv4 & IPv6 + DoH)

A PowerShell hardening tool that enforces:
1. **DNS Registry ACL locks** on network adapter configurations, browser DoH blocking, and self-healing persistence.
2. **OS Child Lockdown** — auto-creates a passwordless `Child` standard user, enforces strict machine-wide and per-user policies, maxes UAC, removes Windows Store, and blocks CMD / Run / Control Panel / Regedit / TaskMgr for the child account.

Built-in Administrator retains full privileges to install, modify, and unlock.

---

## Quick Links

- [Features](#features)
- [Security Architecture](#security-architecture)
- [OS Child Lockdown](#os-child-lockdown)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Interactive Menu](#interactive-menu)
- [Target Registry Paths](#target-registry-paths)
- [Tamper Detection](#tamper-detection)
- [Known Limitations](#known-limitations)
- [Changelog](#changelog)
- [Unreleased](#unreleased)

---

## Table of Contents

- [Features](#features)
- [Security Architecture](#security-architecture)
- [OS Child Lockdown](#os-child-lockdown)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Interactive Menu](#interactive-menu)
- [Target Registry Paths](#target-registry-paths)
- [Tamper Detection](#tamper-detection)
- [Known Limitations](#known-limitations)
- [Changelog](#changelog)
- [Unreleased](#unreleased)

---

## Features

| Feature | Description |
| :--- | :--- |
| **Adapter Registry ACL Lock** | Denies `SetValue` to `Administrators` and `SYSTEM` on each network interface GUID under `Tcpip` and `Tcpip6` |
| **Browser DoH Block** | Injects machine-wide policies to disable DNS-over-HTTPS in Edge, Chrome, and Firefox |
| **GUI Padlock** | User Group Policy restrictions gray out the adapter properties UI (`ncpa.cpl`) |
| **Auto-Heal Persistence** | Scheduled tasks run at startup, logon, and network changes to re-apply locks |
| **Dual Guardians** | Two independent hidden tasks (`OSGuard-Guardian1` and `OSGuard-Guardian2`) monitor every 5 and 10 minutes |
| **WMI Subscription** | Third hidden layer monitors the Task Scheduler service; triggers if it is stopped or modified |
| **Integrity Hash** | SHA256 stored in a misleading registry key (`WpnPlatform\Settings\OSGuardIntegrity`) plus a file backup |
| **Global CLI** | After install, type `oslock` from any terminal to run commands |
| **Menu Tamper Blocking** | If the installed script is modified, options `[1]`, `[2]`, and `[3]` are blocked; only uninstall remains available |
| **OS Child Lockdown** | Auto-creates passwordless `Child` standard user; disables TaskMgr, Regedit, CMD, Run, Control Panel, Store, UAC modification, Installer, USB, WSH, SmartScreen, Fast User Switching |
| **Child Logon Task** | Applies HKCU restrictions directly in the child's session at every logon |
| **Child Hive Mount** | Loads `NTUSER.DAT` offline to enforce per-user policies even when the child is not logged in |
| **Admin-Approval Logout Shortcut** | Creates a `Log out` shortcut on the child's desktop flagged to run as administrator, so the child cannot log out without admin UAC approval |
| **Category Status Grid** | Interactive TUI shows a two-column grid of all 25+ lock categories with [ENABLED] / [DISABLED] / [UNKNOWN] indicators at a glance |
| **Parent Mode** | Admin enters a password-protected temporary unlock mode to install software or view the child account. Auto-relocks after 5 minutes of inactivity (AFK watcher). |
| **Parent Mode Window Guard** | Background process monitors for new windows while Parent Mode is active. If a new window appears (e.g., child uses admin mouse), a password prompt is shown immediately. 3 wrong passwords triggers instant lock. |
| **Parent Mode Admin Tools** | `Admin CMD.lnk` and `Admin PowerShell.lnk` dynamically appear on the admin desktop during Parent Mode with UAC elevation so the admin can quickly open elevated terminals. They are removed when exiting. |
| **Edge-Only Browser Lockdown** | `DisallowRun` entries 51-58 block Chrome, Firefox, Brave, Opera, Vivaldi, Waterfox, Tor, and Internet Explorer. Edge is the only allowed browser. |
| **Edge Deep Lockdown** | `BookmarkBarEnabled=0`, `InPrivateModeAvailability=1`, `DeveloperToolsAvailability=2`, `DownloadRestrictions=3`, `SyncDisabled=1`, `PasswordManagerEnabled=0`, `URLBlocklist`, `ExtensionInstallBlocklist=*` disable bookmarks, incognito, dev tools, downloads, extensions, settings access, and more. |
| **Screen Time Engine** | Admin-configurable daily activity hours (`DailyStart`/`DailyEnd`), daily max minutes, and browser-specific max minutes. `OSGuard-ScreenTime` watcher runs every minute as SYSTEM to track and enforce limits. |
| **Browser Request & Grant Flow** | Child desktop has `Browser Request.lnk` which shows a tamper-proof popup when clicked. Admin uses `Grant Browser Time` desktop shortcut (password-protected) to set session minutes (15/30/60/120). The child cannot set their own timer. |
| **Start Menu Lockdown** | `NoStartMenuPinnedList`, `NoStartMenuDragDrop`, `NoTrayContextMenu`, `NoMovingBands`, `NoCloseDragDropBands`, `DisableContextMenusInStart`, `NoBalloonTips` disable pinning, drag-drop, tray context menus, and taskbar manipulation. |
| **Notification Center Block** | `DisableNotificationCenter` and `DisableWindowsConsumerFeatures` block Action Center and suggested apps in the Start Menu. |
| **Game Request Shortcut** | Child has a "Request Game Install" shortcut on the desktop that opens a simple dialog to type a game name and send it to the admin. |
| **Lock Now / Continue Parent Mode** | Admin desktop shortcuts allow instant re-locking or resetting the AFK timer without opening the terminal. |
| **Parent Mode AFK Watcher** | 1-minute heartbeat scheduled task monitors idle time; if idle exceeds 5 minutes while parent mode is active, it auto-triggers `oslock -LockNow`. |
| **Salted Parent Password** | Parent Mode password uses SHA256 with a 16-byte random salt (Base64 stored in `OSGuardParentPasswordSalt`) to resist offline brute-force. Minimum 8 characters. |
| **Inline Watch Script** | `ParentModeWatch.ps1` is embedded as a Base64 string inside the main script and rewritten fresh on every silent heal; ACL hardened to SYSTEM only. |
| **Pre-Action Integrity Check** | `Enable-OSLock`, `Disable-OSLock`, and `Enter-ParentMode` re-verify script integrity immediately before executing (not just at menu render time). |
| **WMI Health Check** | `SilentLock` re-registers the `OSGuardWmiHealth` WMI subscription if the filter, consumer, or binding is missing. |
| **Task Scheduler Watch** | `SilentLock` monitors the `Schedule` service and auto-starts it if stopped. |
| **Hardened Requests Directory** | `C:\ProgramData\OSGuard\Requests` grants the child `WriteData, AppendData` only (no read/list/delete); admins retain `ReadAndExecute`. |
| **Program Guardian Engine** | Scheduled task `OSGuard-ProgramScanner` scans the child profile every 10 minutes for newly installed programs, hardens their directories and shortcuts so the child cannot tamper with them, and blocks 50+ Windows built-in exploit tools via `DisallowRun` registry policies (Notepad, WordPad, Paint, Write, Explorer, PowerShell, pwsh, CMD, WSH, mshta, certutil, bitsadmin, wmic, regsvr32, rundll32, msiexec, msconfig, mmc, eventvwr, UAC bypass tools, taskkill, ftp, curl, robocopy, takeown, icacls, net, schtasks, at, cleanmgr, sdclt, control, .cpl, .msc, and more). Also disables `NoOpenWith`, `NoInternetOpenWith`, `NoSecurityTab`, `NoHardwareTab`, and `NoManageMyComputerVerb`. |

|---

## Security Architecture

The script targets specific SIDs with `Deny` ACLs while leaving DHCP services untouched:

| SID | Name | Access |
| :--- | :--- | :--- |
| `S-1-5-32-544` | `BUILTIN\Administrators` | Deny `SetValue` |
| `S-1-5-18` | `NT AUTHORITY\SYSTEM` | Deny `SetValue` |
| `S-1-5-19` | `NT AUTHORITY\LocalService` | **Unchanged** (DHCP works) |

**File/Directory Hardening:**
|- `C:\ProgramData\OSGuard` — SYSTEM `FullControl`, Administrators `ReadAndExecute`
|- `C:\ProgramData\OSGuard\ParentModeWatch.ps1` — SYSTEM `FullControl`, Administrators `ReadAndExecute` (rewritten fresh from embedded Base64 on every silent heal)
|- `C:\ProgramData\OSGuard\Requests` — SYSTEM `FullControl`, Administrators `ReadAndExecute`, Child `WriteData, AppendData` only (no read/list/delete)
|- `C:\Windows\oslock.cmd` — SYSTEM `FullControl`, Administrators `ReadAndExecute`
|- `C:\ProgramData\DNSGuard` — Legacy path from DNS-Guard only install (see `new2.ps1`)
|- `C:\Windows\dnslock.cmd` — Legacy CLI wrapper from DNS-Guard only install

---

## OS Child Lockdown

When `new2_OS_lockdown.ps1` is installed, the following child-safe restrictions are enforced:

**Machine-wide (HKLM) policies:**
- UAC is maxed: `EnableLUA = 1`, `ConsentPromptBehaviorAdmin = 2`, `PromptOnSecureDesktop = 1`
- Windows Store is removed: `RemoveWindowsStore = 1`
- **Windows Installer blocked** for standard users: `DisableMSI = 2`, `DisableUserInstalls = 2`
- **USB storage disabled** to prevent software installation from USB: `USBSTOR Start = 4`
- **Windows Script Host disabled** (`wscript.exe` / `cscript.exe`)
- **SmartScreen enforced** at `Block` level for unknown apps and downloads
- **Fast User Switching disabled** so the child cannot switch to the Administrator without logging out
- **Windows Update UI blocked** for standard users
- Installer detection is enabled so the child cannot bypass UAC with unsigned installers

**Per-user (HKCU) policies applied to the child account only:**
- Task Manager: `DisableTaskMgr = 1`
- Registry Editor: `DisableRegistryTools = 1`
- Command Prompt: `DisableCMD = 2`
- Run dialog: `NoRun = 1`
- Control Panel & Settings: `NoControlPanel = 1`
- Wallpaper / theme changes: `NoChangingWallPaper = 1`, `NoThemesTab = 1`
- AutoPlay: `NoDriveTypeAutoRun = 255`
- Administrative Tools from Start Menu: hidden
- Add/Remove Programs: `NoAddRemovePrograms = 1`
- Windows Update UI: disabled
- Password change: `DisableChangePassword = 1`
- Network Connections UI: grayed out (`NC_LanProperties = 0`)
- Right-click context menu: disabled (`NoViewContextMenu = 1`)
- Folder Options: hidden (`NoFolderOptions = 1`) — prevents showing hidden/system files
- Taskbar changes: blocked (`NoSetTaskbar = 1`)
- Printer add/remove: blocked (`NoAddPrinter = 1`, `NoDeletePrinter = 1`)
- "This PC" icon: hidden from desktop and start menu (`{20D04FE0-3AEA-1069-A2D8-08002B30309D} = 1`)
- **Start Menu & Taskbar restrictions**: `NoStartMenuPinnedList` (no pinning to Start or taskbar), `NoStartMenuDragDrop` (no drag-and-drop in Start), `NoTrayContextMenu` (no right-click on tray icons), `NoMovingBands` (no moving taskbar toolbars), `NoCloseDragDropBands` (no closing/dragging toolbars), `NoBalloonTips` (no tray balloon tips), `DisableContextMenusInStart` (no right-click in Start menu)
- **Start Menu special folders hidden**: `NoStartMenuNetworkPlaces`, `NoStartMenuEjectPC`, `NoStartMenuMyGames`, `NoStartMenuMyMusic`, `NoStartMenuMyPictures`, `NoStartMenuMyVideos`, `NoStartMenuDownloads`, `NoStartMenuDocuments`, `NoStartMenuRecordings`, `NoStartMenuHomegroup`, `NoStartMenuFavorites`, `NoStartMenuRecentDocs`, `NoStartMenuRun`, `NoStartMenuFind`, `NoStartMenuHelp`, `NoStartMenuLogoff`
- **Notification Center & Consumer Features blocked**: `DisableNotificationCenter` (Action Center disabled), `DisableWindowsConsumerFeatures` (suggested apps removed from Start)
- **50+ Exploit Tools Blocked** via `DisallowRun` (entries 1-50): Notepad, WordPad, Paint, Write, Explorer, PowerShell, pwsh, CMD, wscript, cscript, mshta, certutil, bitsadmin, wmic, regsvr32, rundll32, msiexec, msconfig, mmc, eventvwr, fodhelper, computerdefaults, slui, dccw, xwizard, taskkill, ftp, tftp, telnet, curl, robocopy, takeown, icacls, net, net1, schtasks, at, cleanmgr, sdclt, systempropertiesadvanced, ms-settings, control, inetcpl.cpl, appwiz.cpl, compmgmt.msc, diskmgmt.msc, devmgmt.msc, taskmgr, regedit, perfmon
- **Additional Explorer Hardening**: `NoOpenWith`, `NoInternetOpenWith`, `NoSecurityTab`, `NoHardwareTab`, `NoManageMyComputerVerb`

**Child Account:**
- Account name: `Child` (configurable via `-ChildUser` parameter)
- Password: **passwordless** (`New-LocalUser -NoPassword`)
- Password change blocked: `net user Child /passwordchg:no /passwordreq:no`
- Membership: standard `Users` group only (never `Administrators`)
- Logout shortcut on desktop: requires admin UAC approval to run

**Admin Exemption:**
The built-in Administrator account is unaffected by all child restrictions and can:
- Run `oslock` from any terminal
- Use the interactive menu to lock/unlock
- Install or uninstall the service
- Modify all system settings

---

## Installation

1. Open PowerShell as Administrator.
2. Choose the script that matches your needs:

**DNS-only protection (legacy):**
```powershell
.\new2.ps1 -Install
```

**Full OS + DNS child lockdown:**
```powershell
.\new2_OS_lockdown.ps1 -Install
```

Or open the interactive menu and select option `[3]`.

This will:
- Copy the payload to `C:\ProgramData\OSGuard` (or `C:\ProgramData\DNSGuard` for DNS-only)
- Harden the directory ACLs
- Create the `oslock` CLI wrapper in `C:\Windows` (or `dnslock` for DNS-only)
- Register scheduled tasks (main + two guardians + child logon task)
- Register a WMI event subscription
- Store the integrity hash in the registry
- Create the passwordless `Child` account (OS lockdown only)
- Apply all DNS and OS locks immediately

---

## CLI Usage

After installation, the global `oslock` command is available from any terminal:

| Flag | Action | Required Identity |
| :--- | :--- | :--- |
| `-Install` | Install persistence and service | Admin |
| `-Uninstall` | Remove everything | **SYSTEM only** |
| `-Lock` | Apply DNS + OS locks immediately | Admin |
| `-Unlock` | Remove DNS + OS locks immediately | Admin |
| `-SilentLock` | Background re-apply (used by tasks) | SYSTEM |
| `-ChildLock` | Apply HKCU restrictions in child session | Child user (auto) |
| `-ChildUser <name>` | Specify a custom child username | Admin |
| `-ParentMode` | Enter password-protected Parent Mode (temporary unlock) | Admin |
| `-SetParentPassword` | Interactively set the Parent Mode password | Admin |
| `-ChildGameRequest` | Open the child game request dialog | Child (auto) |
| `-ContinueParentMode` | Reset the AFK timer while in Parent Mode | Admin |
| `-LockNow` | Exit Parent Mode and re-lock immediately | Admin |
|| `-ProgramScan` | Trigger an immediate Program Guardian scan & hardening | Admin |
|| `-SetScreenTime` | Interactively set daily/hourly screen time limits | Admin |
|| `-ScreenTimeStatus` | Show child's current screen time usage | Child (auto) |
|| `-GrantBrowserTime` | Grant temporary browser minutes (password protected) | Admin |
|| `-ScreenTimeEnforce` | Background enforcement used by watcher task | SYSTEM |

**Uninstall from a SYSTEM shell:**

```powershell
psexec -s powershell.exe -File "C:\ProgramData\OSGuard\OS_Lockdown.ps1" -Uninstall
```

---

## Interactive Menu

Running the script without flags opens the live menu:

```text
=====================================================
   ENTERPRISE DNS LOCKOUT SUITE (INSTALLER EDITION)
=====================================================

 LIVE HARDWARE ADAPTER STATUS
=====================================================
  Hardware: Ethernet       | State: Up    | MAC: 52-54-00-CC-93-AA
  -> Security: [X] LOCKED (IPv4/IPv6)
-----------------------------------------------------

=====================================================
 SYSTEM POLICIES & PERSISTENCE
=====================================================
  [X] GPO Restrictions   -> ENFORCED (Browsers & GUI)
  [X] Background Service -> INSTALLED ('dnslock' active)
-----------------------------------------------------

=====================================================
 INTEGRITY CHECK
=====================================================
  [X] Script Integrity    -> VERIFIED
-----------------------------------------------------

 >>> SYSTEM IS SECURE: ZERO-TRUST PADLOCK ACTIVE <<<

-----------------------------------------------------
[1] DEPLOY LOCK (Secure All Active Adapters)
[2] REMOVE LOCK (Aangra / Restore Access)
|[4] UNINSTALL SERVICE (Remove background tasks & Unlock)
|[5] REFRESH SYSTEM STATUS
|[6] EXIT TERMINAL
|[7] ENTER PARENT MODE (Unlock with password)
|[8] LOCK NOW (Re-lock immediately)
|-----------------------------------------------------|
Select an administrative action (1-8):
```

- Option `[3]` is hidden when already installed.
- Options `[1]`, `[2]`, `[3]`, `[7]`, and `[8]` are blocked with a red warning if tampering is detected.
- **OS + DNS menu** (`new2_OS_lockdown.ps1`) also shows the **OS Child Lockdown** panel (UAC, Store, TaskMgr, Regedit status) and checks the `Child` account state.
- **Program Guardian** is shown in the menu as a green `[X]` when the `OSGuard-ProgramScanner` task is registered.

---

## Target Registry Paths

### Network Interfaces
- `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`
- `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{GUID}`

### Network UI Restrictions (User Policy)
- `HKCU\Software\Policies\Microsoft\Windows\Network Connections`
  - `NC_LanProperties` = `0`
  - `NC_LanChangeProperties` = `0`
  - `NC_AllowAdvancedTCPIPConfig` = `0`

### Browser DoH Policies (Machine Policy)
- `HKLM\SOFTWARE\Policies\Microsoft\Edge`
- `HKLM\SOFTWARE\Policies\Google\Chrome`
- `HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`

### OS Child Lockdown Policies (Machine Policy)
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
  - `EnableLUA = 1`
  - `ConsentPromptBehaviorAdmin = 2`
  - `PromptOnSecureDesktop = 1`
- `HKLM\SOFTWARE\Policies\Microsoft\WindowsStore`
  - `RemoveWindowsStore = 1`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
  - `DisableMSI = 2`
  - `DisableUserInstalls = 2`
  - `DisableUserInstallsViaModifications = 1`
- `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR`
  - `Start = 4`
- `HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings`
  - `Enabled = 0`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
  - `EnableSmartScreen = 1`
  - `ShellSmartScreenLevel = Block`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
  - `HideFastUserSwitching = 1`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
  - `DisableWindowsUpdateAccess = 1`

### OS Child Lockdown Policies (User Policy — Child account only)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`
  - `DisableTaskMgr = 1`
  - `DisableRegistryTools = 1`
  - `DisableChangePassword = 1`
  - `NoThemesTab = 1`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop`
  - `NoChangingWallPaper = 1`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
  - `NoRun = 1`
  - `NoControlPanel = 1`
  - `NoDriveTypeAutoRun = 255`
  - `StartMenuAdminTools = 0`
- `HKCU\Software\Policies\Microsoft\Windows\System`
  - `DisableCMD = 2`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
  - `NoViewContextMenu = 1`
  - `NoFolderOptions = 1`
  - `NoSetTaskbar = 1`
  - `NoAddPrinter = 1`
  - `NoDeletePrinter = 1`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum`
  - `{20D04FE0-3AEA-1069-A2D8-08002B30309D} = 1`

---

## Tamper Detection

If the installed script is modified without updating the integrity hash, the menu shows:

```text
  [ ] Script Integrity    -> TAMPER DETECTED

  >>> TAMPER DETECTED! ACTION REQUIRED <<<
  - Run a full antivirus scan immediately.
  - Do NOT use options [1] or [2] (they may run malicious code).
  - Use option [4] to uninstall, then reinstall from a clean source.
  - Check Task Scheduler for unknown tasks and remove them.
```

**How to check for malicious tasks:**
1. Press `Win + R`, type `taskschd.msc`, press Enter.
2. Click `Task Scheduler Library` on the left.
3. Look for tasks you do not recognize (sort by Author).
4. Double-click suspicious tasks and check the `Actions` tab.
5. Delete anything running `powershell.exe` or `cmd.exe` from unexpected paths.

Quick PowerShell check:
```powershell
Get-ScheduledTask | Where-Object {$_.TaskPath -eq '\' -and $_.Author -notmatch 'Microsoft'} | Select-Object TaskName, Author, State
```

---

## Known Limitations

- **Captive portals** (hotels, airports) may fail if you use static DNS. Unlock temporarily with option `[2]`, log in, then re-lock with `[1]`.
- **Corporate VPNs** (Cisco, Fortinet) that rewrite adapter DNS may conflict with the lock. WFP-based VPNs (Proton) are unaffected.
- **Admin attacker with `takeown` / `psexec -s`** can still bypass the script. This is a Windows discretionary ACL limitation, not a script flaw. The script raises the effort required but does not create a kernel-level security boundary.
- **Offline boot** (live USB, Safe Mode) bypasses all protections.
- **Child account must log in once** before offline NTUSER.DAT hive policies can be applied. If the child has never logged in, the `ChildLogon` scheduled task will apply HKCU policies at the first logon.
- **Windows 10/11 Home** may not have `Get-LocalUser` / `New-LocalUser` cmdlets available in older builds; the script falls back to `net user` where possible.
- **Program Guardian** only discovers programs already installed in the child profile at scan time; it does not prevent the child from running portable executables stored outside scanned directories. Admins should install software into the child Desktop, Start Menu, or `AppData\Local\Programs` so the engine can find and harden it.
- **Parent Mode Window Guard** is a best-effort heuristic: it polls every 5 seconds for new visible processes while Parent Mode is active. A determined child who can quickly interact with a newly opened window before the guard detects it may bypass the prompt. The guard catches most accidental or slow interactions.
- **DisallowRun** blocks 50+ exact executable names (including `powershell.exe`, `pwsh.exe`, `cmd.exe`, `mshta.exe`, `mmc.exe`, `eventvwr.exe`, `fodhelper.exe`, etc.). A determined attacker can rename a copy of these tools, but this defeats casual child tampering. The shell blocks launches from Run dialog, Start menu, and double-click; already-running processes are not terminated.
- **Edge-Only Lockdown** blocks other browsers via `DisallowRun` 51-58. A child could still use Edge WebView or rename a blocked binary, but casual browsing is restricted to Edge only. Edge policies can be overridden by a user with local admin rights or by booting into Safe Mode.
- **Screen Time Engine** tracks usage via a JSON tracker under `C:\ProgramData\OSGuard`. A child with local admin rights or SYSTEM access could delete or edit the tracker. The engine is best-effort and relies on the `OSGuard-ScreenTime` scheduled task running every minute. If the task is stopped, enforcement is delayed until the next minute.

---

## Changelog

See [changelog.md](changelog.md) for a full list of changes, fixes, and security improvements.

---

## Unreleased

This section tracks upcoming and recently merged changes before they are tagged in a formal release.

- **OS Child Lockdown** added to `new2_OS_lockdown.ps1` (passwordless `Child` account, UAC max, Store removal, per-user policy blocks).
- **Stricter OS Lockdown** (2026-06-30): Windows Installer blocked, USB storage disabled, Windows Script Host disabled, SmartScreen enforced, Fast User Switching disabled, Windows Update UI blocked, right-click context menu disabled, Folder Options hidden, taskbar changes blocked, printer add/remove blocked, and "This PC" hidden.
- **Admin-Approval Logout Shortcut** added to the child's desktop (requires UAC elevation to run `shutdown /l`).
- **Interactive TUI Category Status Grid** added: a compact two-column grid showing all 25+ lock categories with [ENABLED] / [DISABLED] / [UNKNOWN] indicators so you can see every enabled and disabled category at a glance.
- **CLI renamed** from `dnslock` to `oslock` for the full OS+DNS suite (`new2_OS_lockdown.ps1`). The DNS-only `new2.ps1` still uses `dnslock`.
- **New regression tests** in `tests/` folder: `syntax_check.ps1` (auto syntax checker + chmod) and `test_os_lockdown.ps1` (read-only state verification).
- **Child Logon Task** (`OSGuard-ChildLogon`) ensures HKCU restrictions are reapplied at every child logon.
- **WMI subscription** renamed to `OSGuardWmiHealth`.
- **Edge-Only Browser Lockdown** (2026-06-29): `DisallowRun` 51-58 blocks Chrome, Firefox, Brave, Opera, Vivaldi, Waterfox, Tor, and Internet Explorer. Edge deep lockdown disables bookmarks, incognito, dev tools, downloads, sync, password manager, extensions, and settings access.
- **Screen Time Engine** (2026-06-29): Admin-configurable daily activity hours (`DailyStart`/`DailyEnd`), daily max minutes, and browser-specific max minutes. `OSGuard-ScreenTime` watcher runs every minute as SYSTEM. Browser Request & Grant Flow requires admin password to set session time.

---

## Prerequisites

- Windows 10 or Windows 11
- PowerShell 5.1 or PowerShell 7+ (Admin rights required)
- `Set-ExecutionPolicy RemoteSigned` (or Bypass) to allow script execution

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

