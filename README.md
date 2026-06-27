# DNS-Guard

Enterprise DNS Hijack Protection & Installer Suite (IPv4 & IPv6 + DoH)

A PowerShell hardening tool that enforces registry ACL locks on network adapter DNS configurations, disables browser DNS-over-HTTPS (DoH) bypasses, and installs self-healing background persistence to survive reboots and network changes.

---

## Table of Contents

- [Features](#features)
- [Security Architecture](#security-architecture)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Interactive Menu](#interactive-menu)
- [Target Registry Paths](#target-registry-paths)
- [Tamper Detection](#tamper-detection)
- [Known Limitations](#known-limitations)
- [Changelog](#changelog)

---

## Features

| Feature | Description |
| :--- | :--- |
| **Adapter Registry ACL Lock** | Denies `SetValue` to `Administrators` and `SYSTEM` on each network interface GUID under `Tcpip` and `Tcpip6` |
| **Browser DoH Block** | Injects machine-wide policies to disable DNS-over-HTTPS in Edge, Chrome, and Firefox |
| **GUI Padlock** | User Group Policy restrictions gray out the adapter properties UI (`ncpa.cpl`) |
| **Auto-Heal Persistence** | Scheduled tasks run at startup, logon, and network changes to re-apply locks |
| **Dual Guardians** | Two independent hidden tasks (`Windows-Defender-Platform-Update` and `Windows-Defender-AM-Updates`) monitor every 5 and 10 minutes |
| **WMI Subscription** | Third hidden layer monitors the Task Scheduler service; triggers if it is stopped or modified |
| **Integrity Hash** | SHA256 stored in a misleading registry key (`WpnPlatform\Settings\PushConfigBackoffInterval`) plus a file backup |
| **Global CLI** | After install, type `dnslock` from any terminal to run commands |
| **Menu Tamper Blocking** | If the installed script is modified, options `[1]`, `[2]`, and `[3]` are blocked; only uninstall remains available |

---

## Security Architecture

The script targets specific SIDs with `Deny` ACLs while leaving DHCP services untouched:

| SID | Name | Access |
| :--- | :--- | :--- |
| `S-1-5-32-544` | `BUILTIN\Administrators` | Deny `SetValue` |
| `S-1-5-18` | `NT AUTHORITY\SYSTEM` | Deny `SetValue` |
| `S-1-5-19` | `NT AUTHORITY\LocalService` | **Unchanged** (DHCP works) |

**File/Directory Hardening:**
- `C:\ProgramData\DNSGuard` — SYSTEM `FullControl`, Administrators `ReadAndExecute`
- `C:\Windows\dnslock.cmd` — SYSTEM `FullControl`, Administrators `ReadAndExecute`

---

## Installation

1. Open PowerShell as Administrator.
2. Run the script with the install flag:

```powershell
.\new2.ps1 -Install
```

Or open the interactive menu and select option `[3]`.

This will:
- Copy the payload to `C:\ProgramData\DNSGuard`
- Harden the directory ACLs
- Create the `dnslock` CLI wrapper in `C:\Windows`
- Register three scheduled tasks (main + two guardians)
- Register a WMI event subscription
- Store the integrity hash in the registry
- Apply all DNS locks immediately

---

## CLI Usage

After installation, the global `dnslock` command is available from any terminal:

| Flag | Action | Required Identity |
| :--- | :--- | :--- |
| `-Install` | Install persistence and service | Admin |
| `-Uninstall` | Remove everything | **SYSTEM only** |
| `-Lock` | Apply DNS locks immediately | Admin |
| `-Unlock` | Remove DNS locks immediately | Admin |
| `-SilentLock` | Background re-apply (used by tasks) | SYSTEM |

**Uninstall from a SYSTEM shell:**

```powershell
psexec -s powershell.exe -File "C:\ProgramData\DNSGuard\DNS_Lockdown.ps1" -Uninstall
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
[4] UNINSTALL SERVICE (Remove background tasks & Unlock)
[5] REFRESH SYSTEM STATUS
[6] EXIT TERMINAL
-----------------------------------------------------
Select an administrative action (1-6):
```

- Option `[3]` is hidden when already installed.
- Options `[1]` and `[2]` are blocked with a red warning if tampering is detected.

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

---

## Changelog

See [changelog.md](changelog.md) for a full list of changes, fixes, and security improvements.

---

## Prerequisites

- Windows 10 or Windows 11
- PowerShell 5.1 or PowerShell 7+ (Admin rights required)
- `Set-ExecutionPolicy RemoteSigned` (or Bypass) to allow script execution

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```
