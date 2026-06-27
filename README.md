# dnshijack-protection

# Enterprise DNS Hijack Protection & Diagnostics Suite (IPv4 & IPv6)

A highly verbose, enterprise-grade PowerShell security tool designed to enforce a Zero-Trust Registry padlock on Windows network interface DNS configurations. This tool prevents unauthorized local modifications and advanced browser-level DNS bypasses by utilizing strict Registry Access Control Lists (ACLs) and Group Policy Objects (GPOs), while mathematically preserving local DHCP lease functionality.

---

## 🛡️ Zero-Trust Security & Architecture

Standard DNS lockdown scripts often break local networks because they apply a blanket `Deny` rule to the `Everyone` group. This breaks the Windows DHCP Client service (`DhcpConnEnableBcast`), dropping the machine off the network entirely when its local IP lease expires.

This suite acts as a surgical scalpel. It isolates and applies explicit `Deny` rules exclusively to administrative contexts, leaving the underlying network services completely functional.

### Targeted Security Identifiers (SIDs)
* **`S-1-5-32-544` (BUILTIN\Administrators):** Prevents human administrators and elevated malware from rewriting adapter configuration blocks.
* **`S-1-5-18` (NT AUTHORITY\SYSTEM):** Prevents local system-level services, automated exploits, and high-privilege scripts from modifying values.
* **`S-1-5-19` (NT AUTHORITY\LocalService):** **Exempted / Left Untouched.** This explicitly permits the Windows DHCP Client to dynamically renegotiate leases, change gateways, and adjust IP scopes seamlessly.

---

## 🗺️ Multi-Layer Defense Matrix

The suite implements a "Defense in Depth" topology, closing the loops between the underlying OS kernel, local hardware changes, user configuration tools, and application layer protocols.

| Defense Layer | Technical Mechanism | Mitigated Target Vector |
| :--- | :--- | :--- |
| **System Adapter Lock** | Explicit `Deny` (SetValue) .NET ACL entries on specific Interface Registry SubKeys. | Elevated malware, local scripts, manual command-line interventions (`netsh`, `Set-DnsClientServerAddress`). |
| **Dual-Stack Coverage** | Dual iteration loops covering both the legacy `Tcpip` stack and modern `Tcpip6` stack. | IPv6 translation tunnel exploits and unmonitored dual-stack leaks. |
| **Browser DoH Block** | Hardcoded Local Machine Administrative Policy injection via GPO Registry paths. | Malicious browser extensions, rogue user configurations, and stealth encrypted DNS tunnels inside browsers. |
| **GUI Control Padlock** | Network Connections Group Policy restrictions (`NC_LanProperties`, `NC_LanChangeProperties`). | Manual user tampering via the classic Control Panel (`ncpa.cpl`) or Windows Settings app. |
| **Active Stack Reset** | Native binary network teardown sequence execution (`ipconfig /flushdns`, `ipconfig /renew`). | Poisoned local DNS caches and stale routing paths. |

---

## ✨ System Features & Capabilities

* **Auto-Elevation Check:** Checks the execution token state at startup. If the script is executed by a standard user, it builds an elevated process wrapper string, passes `-NoProfile -ExecutionPolicy Bypass`, and forces a UAC runAs prompt.
* **Pre-Flight Infrastructure Audit:** Pulls the native `Win32_OperatingSystem` CIM instance to analyze, verify, and log the exact Windows Caption string, OS Build Number, active PowerShell Core/Desktop version, and script path context before a single bit is modified.
* **Asynchronous Hardware Discovery:** Scans all physical interfaces using `Get-NetAdapter`. Automatically filters out hidden virtual adapters, miniports, and ghost interfaces, while falling back to an un-filtered state if an unexpected hardware array is encountered.
* **Live Status Dashboard:** Evaluates interface operational states (`Up`/`Down`) dynamically using specialized color coding, mapping and displaying the explicit hardware name, link status, and hardware MAC address alongside its current lock state.
* **State Transparency (Console Dumps):** When deploying locks, the script queries the security descriptor object directly from the registry, extracts the ACL array, parses out the active `Deny` parameters, and pipes a beautifully formatted table directly to the console for live auditing.

---

## 📂 Target Registry & System Paths

The suite targets the following architectural configuration points within the Windows operating system:

### Network Interfaces (Iterative Keys)
* **IPv4 Interface Scope:** `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{Interface-GUID}`
* **IPv6 Interface Scope:** `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{Interface-GUID}`

### Core Network Connection Policies
* **GPO Configuration Hive:** `HKCU\Software\Policies\Microsoft\Windows\Network Connections`
    * `NC_LanProperties` (DWORD: `0`) -> Disables access to LAN connection properties.
    * `NC_LanChangeProperties` (DWORD: `0`) -> Blocks changes to advanced network settings.
    * `NC_AllowAdvancedTCPIPConfig` (DWORD: `0`) -> Removes access to advanced TCP/IP configuration screens.

### Enterprise Browser Policies (DNS-over-HTTPS)
* **Microsoft Edge:** `HKLM\SOFTWARE\Policies\Microsoft\Edge`
    * `DnsOverHttpsMode` = `"off"` (String)
    * `BuiltInDnsClientEnabled` = `0` (DWORD)
* **Google Chrome:** `HKLM\SOFTWARE\Policies\Google\Chrome`
    * `DnsOverHttpsMode` = `"off"` (String)
* **Mozilla Firefox:** `HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`
    * `Enabled` = `0` (DWORD)

---

## 🚀 Execution & Operating Instructions

1.  Save the code file onto the target system as `DNS_Lockdown_Enterprise.ps1`.
2.  Open an administrative terminal (or right-click the script file and choose **Run with PowerShell**).
3.  The main interactive terminal interface will continuously loop, presenting an active assessment of the network cards and four specific option buttons:

```text
=====================================================
   ENTERPRISE DNS LOCKOUT SUITE (VERBOSE EDITION)    
=====================================================

 LIVE HARDWARE ADAPTER STATUS 
=====================================================
  Hardware: Ethernet 1                | State: Up    | MAC: 00-1A-2B-3C-4D-5E
  `-> Security: [ ] UNLOCKED (Vulnerable)
-----------------------------------------------------

 >>> SYSTEM IS UNSECURE: PADLOCK INACTIVE <<< 

-----------------------------------------------------
[1] DEPLOY LOCK (Secure All Active Adapters)
[2] REMOVE LOCK (Ångra / Restore Access)
[3] REFRESH HARDWARE STATUS
[4] EXIT TERMINAL
-----------------------------------------------------
Select an administrative action (1-4):
---

### Trade-Offs & Known Limitations

While this script provides a high-security perimeter for your network configuration, deploying a registry lock introduces some friction into daily operations. The impact depends on how your DNS was configured *before* you ran the lock:

* **Captive Portals (If using Static DNS):**
  If you hard-coded a custom DNS (like Control D) before locking, public Wi-Fi captive portals (hotels, airports) will fail to route to their login pages. 
  * *Workaround:* Run the script, select `Option 2` (Unlock), connect to the network and log in, then run `Option 1` (Lock) to re-secure the connection. *(Note: If you use Automatic DHCP, captive portals will work perfectly normally).*

* **Single Point of Failure (If using Static DNS):**
  If you locked the adapter to a specific upstream DNS provider and their servers go down, you will lose web resolution. Because the GUI is locked, you cannot quickly switch back to an ISP's default DNS without running the script to unlock the system first.

* **Corporate VPN Conflicts:**
  Traditional work VPNs (e.g., Cisco AnyConnect, Fortinet) often try to rewrite your local adapter's DNS using elevated System privileges to resolve internal company domains. The registry lock will block this injection, which may cause the VPN software to crash or fail to route internal traffic. *(Note: WFP-based apps like Proton VPN are unaffected but require manual DNS entry in the app's own settings).*

* **Administrative Friction:**
  The Group Policy UI restrictions apply system-wide. If you need to perform standard network troubleshooting or change an IP address months from now, you will encounter grayed-out menus and "Access Denied" registry errors. You must keep the script accessible to temporarily unlock the system (`Option 2`) before performing maintenance.


---

## Deployment & Usage

### Prerequisites
* Windows 10 or Windows 11.
* PowerShell 5.1 or PowerShell Core running with **Administrative Privileges**.
* Pre-configured DNS addresses (the script locks whatever values are active on your network card at the time of execution).

### How to Run
1. Right-click your PowerShell console and select **Run as Administrator**.
2. Execute the script:
   ```powershell
   .\DNS_Lockdown.ps1
   

### Understanding `Set-ExecutionPolicy RemoteSigned`

By default, Windows has a strict security mechanism enabled (called `Restricted`) that prevents *any* PowerShell scripts from running, even the ones you write yourself. This command changes that rule to a much more practical, balanced security setting.

Here is the exact command:

```powershell
Set-ExecutionPolicy RemoteSigned



