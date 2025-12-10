
# 🛠️ Lab Build Notes & Disaster Recovery Plan

> **Purpose:** This document serves as the "Runbook" for rebuilding the lab environment. It contains specific configuration hacks, command-line fixes, and topology requirements to restore the lab to a working state after a reset.

---
# 🛡️ Disaster Recovery Plans

<details>
<summary><strong>📑 Table of Contents</strong></summary>

- [1. SOC-Gateway (pfSense Firewall)](#1-soc-gateway-pfsense-firewall)
- [2. Win11-Victim (Endpoint)](#2-win11-victim-endpoint)
- [3. Ubuntu-Splunk (The Watchtower)](#3-ubuntu-splunk-the-watchtower)
- [4. Kali-Attacker (Red Team)](#4-kali-attacker-red-team)
- [5. Sysmon Deployment (Windows Endpoint)](#5-sysmon-deployment-windows-endpoint)

</details>

---

# 1. SOC-Gateway (pfSense Firewall)

**Role:** The Router and Firewall. It creates the "Air Gap" (`LAN_Isolated`) that allows malware research without endangering the home network.

## VM Specifications
* **Name:** `SOC-Gateway-pfSense`
* **OS:** FreeBSD (Other 64-bit)
* **CPU:** 1 vCPU
* **RAM:** 1 GB
* **Storage:** 8 GB (Internal SSD - Thick or Thin)
* **Network Adapter 1:** `VM Network` (WAN - Connects to Home Internet)
* **Network Adapter 2:** `LAN_Isolated` (LAN - The Lab Network)
* **SCSI Controller:** LSI Logic SAS (Critical Setting)

## Key Configuration Steps

### 1. The "Invisible Disk" Fix (Pre-Boot)
* **Issue:** The installer may fail to find a hard drive.
* **Fix:** In ESXi "Edit Settings", ensure **SCSI Controller 0** is set to **LSI Logic SAS**. Do not use *VMware Paravirtual*.

### 2. Interface Assignment (Console Phase)
* **WAN Interface:** `vmx0` (Assigned via DHCP from home router).
* **LAN Interface:** `vmx1` (Static IP).

### 3. IP Address Configuration (Menu Option 2)
* **LAN IP:** `172.16.10.1`
* **Subnet Bit Count:** `24`
* **Gateway:** None (Press Enter).
* **DHCP Server:** Enable. Range: `172.16.10.100` to `172.16.10.200`.
* **Why:** This ensures your Windows and Ubuntu VMs get IPs automatically.

### 4. Firewall Rule "Gotcha" (Web Interface)
* **Issue:** By default, pfSense blocks private networks on WAN (RFC1918), which kills internet because your "WAN" is actually your home Wi-Fi (10.0.0.x).
* **Fix:** Navigate to **Interfaces > WAN** in the Web GUI.
    * **Scroll to the bottom** and **Uncheck these two boxes** (Crucial for a lab nested inside a home network):
        * **[ ] Block private networks (RFC1918)**.
        * **[ ] Block bogon networks**.

---

# 2. Win11-Victim (Endpoint)

**Role:** The Primary Target. Used for Admin tasks (clean state) and Malware detonation (dirty state).

## VM Specifications
* **Name:** `Win11-Victim-01`
* **OS:** Windows 11 Enterprise (64-bit)
* **CPU:** 2 vCPU
* **RAM:** 6 GB
* **Storage:** 60 GB (Internal SSD)
* **Network:** `LAN_Isolated`

## Critical Build Guide

### 1. The TPM Bypass (Installation Hack)
* **Issue:** ESXi cannot natively support Windows 11 requirements without complex encryption.
* **Fix:** When the installer errors out ("This PC can't run Windows 11"):
    1.  Press `Shift + F10` (or `Fn + Shift + F10` on Mac) to open CMD.
    2.  Type `regedit` and navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\Setup`.
    3.  Create a new Key named `LabConfig`.
    4.  In `LabConfig`, create three DWORD (32-bit) values set to 1:
        * `BypassTPMCheck`
        * `BypassSecureBootCheck`
        * `BypassRAMCheck`

### 2. Enable Copy/Paste (ESXi Advanced Config)
* **Issue:** Copy/Paste from Mac to VM is disabled by default.
* **Fix:** Edit VM Settings > VM Options > Advanced > **Edit Configuration**. Add:
    * `isolation.tools.copy.disable = FALSE`
    * `isolation.tools.paste.disable = FALSE`
    

### 3. Allow Ping (PowerShell Command)
* **Issue:** Windows Firewall blocks ICMP, making network troubleshooting difficult.
* **Fix:** Run in PowerShell (Admin):
    ```powershell
    New-NetFirewallRule -DisplayName "Allow Ping (ICMP)" -Protocol ICMPv4 -IcmpType 8 -Enabled True -Profile Any -Action Allow
    ```
* **Breakdown:** Creates a new firewall rule named "Allow Ping" that permits IPv4 ICMP Echo Requests (Type 8) from any network profile.

### 4. Splunk Agent Configuration (The "Access Denied" Fix)
* **Config File:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`
* **Issue A:** Windows hides the extension, naming it `inputs.conf.txt`.
    * **Fix:** View > Show > File Name Extensions. Rename to remove `.txt`.
* **Issue B:** "ErrorCode=5" (Access Denied) in `splunkd.log`.
    * **Fix:** Open `Services.msc`. Right-click **SplunkForwarder** > Properties > Log On. Change account to **Local System Account**.

---

# 3. Ubuntu-Splunk (The Watchtower)

**Role:** The SIEM (Security Information and Event Management) server.

## VM Specifications
* **Name:** `Ubuntu-Splunk-01`
* **OS:** Ubuntu Server 22.04 LTS
* **CPU:** 2 vCPU
* **RAM:** 4 GB
* **Storage:** 50 GB (Internal SSD)
* **Network:** `LAN_Isolated`

## Critical Build Guide

### 1. SSH Access (Installation)
* **Action:** During OS Install, check the box **[X] Install OpenSSH Server**.
* **Troubleshooting:** If `ssh` times out, check the firewall:
    ```bash
    sudo ufw allow 22/tcp
    sudo ufw reload
    ```

### 2. Splunk Installation (CLI)
```bash
# 1. Download (Get fresh link from splunk.com)
wget -O splunk.deb '[https://download.splunk.com/](https://download.splunk.com/)...'

# 2. Install
sudo dpkg -i splunk.deb

# 3. Create User & Start
sudo groupadd splunk
sudo useradd -d /opt/splunk -m -g splunk splunk
sudo chown -R splunk:splunk /opt/splunk
sudo -u splunk /opt/splunk/bin/splunk start --accept-license
```
### 3. Fixing "Disk Space Breached Threshold" Warning
* **Issue:** Splunk warns if free space < 10GB.
* **Fix:** Lower the limit to 2GB.
    ```bash
    # Bash command to append text to the server.conf file
    sudo bash -c 'cat >> /opt/splunk/etc/system/local/server.conf << EOF

    [diskUsage]
    minFreeSpace = 2000
    EOF'

    # Restart Splunk to apply
    sudo /opt/splunk/bin/splunk restart
    ```

### 4. Fixing Timezone Drift
* **Issue:** Logs appear 7 hours in the future (UTC).
* **Fix:** Align server to Mountain Time.
    ```bash
    sudo timedatectl set-timezone America/Denver
    ```

---

# 4. Kali-Attacker (Red Team)

**Role:** The Adversary.

## VM Specifications
* **Name:** `Kali-Attacker-01`
* **OS:** Debian GNU/Linux 11/12 (64-bit)
* **CPU:** 2 vCPU
* **RAM:** 4 GB
* **Storage:** 40 GB (Thin Provisioned)
* **Network:** `LAN_Isolated`

## Critical Build Guide
* **ESXi Warning:** "Guest OS does not match."
    * **Status: Safe to Ignore**. Kali uses a newer kernel than ESXi expects for "Debian 12."
* **Connectivity Check:**
    * **Ping Windows:** `ping 172.16.10.100`. (Requires the PowerShell Firewall rule on Windows to succeed).

---

# 5. Sysmon Deployment (Windows Endpoint)

* **Role:** The Advanced Telemetry Sensor.
* **Purpose:** Replaces standard Windows Event Logs (which are vague) with granular data on Process Creation, Network Connections, and File Changes.

## Prerequisites
* **Target:** `Win11-Victim-01`
* **Permissions:** Local Administrator
* **Dependencies:** Internet access (to download tools) OR access to your local `_ISO_Library`.

## Critical Build Guide

### 1. Tool Acquisition
* **Sysmon Binary:** Download `Sysmon.zip` from [Microsoft Sysinternals](https://www.google.com/search?q=https://download.sysinternals.com/files/Sysmon.zip).
* **Configuration File:** Download `sysmonconfig-export.xml` from the [SwiftOnSecurity GitHub](https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml).
* **Action:** Rename the XML file to `sysmonconfig.xml` for simplicity.
* **Repository Backup:** Save a copy of this XML to your Mac in `Cybersecurity-Portfolio/Lab-Infrastructure/configs/` so you always have it.

### 2. Installation (PowerShell)
* **Step:** Unzip `Sysmon.zip`. Move `sysmonconfig.xml` into the same folder. Open PowerShell as Admin and navigate to that folder.
* **The Command:**
    ```powershell
    .\Sysmon64.exe -accepteula -i sysmonconfig.xml
    ```
* **Command Breakdown:**
    * `.\Sysmon64.exe`: Runs the 64-bit version of the System Monitor executable from the current directory.
    * `-accepteula`: **"Accept End User License Agreement"**. This flag suppresses the popup window asking you to agree to terms, allowing for a silent script-based install.
    * `-i`: **"Install"**. Tells the driver to install itself as a system service and begin monitoring boot-to-shut-down.
    * `sysmonconfig.xml`: Tells Sysmon **"Use these specific rules."** Without this, Sysmon defaults to a basic configuration that misses many advanced attacks (like LSASS dumping).

### 3. Splunk Integration (The Bridge)
* **Config File:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`
* **The Code Block:**
    ```ini
    [WinEventLog://Microsoft-Windows-Sysmon/Operational]
    disabled = 0
    start_from = oldest
    current_only = 0
    checkpointInterval = 5
    renderXml=true
    ```
* **Troubleshooting:**
    * Ensure the file is NOT named `inputs.conf.txt` (Check File Explorer > View > File name extensions).
    * Restart the **SplunkForwarder** service after editing this file.

### 4. Time Drift Fix (Critical for Incident Response)
* **Issue:** Without Location Services, Windows defaults to Pacific Time (or UTC). Splunk logs will appear "in the past" or "in the future," breaking your attack timeline.
* **Fix:**
    1.  Right-click `Taskbar Clock` > **Adjust date and time**.
    2.  Set Time Zone to **Mountain Time (US & Canada)**.
    3.  Click **Sync now** (Requires pfSense WAN connection).

### 5. Verification (Event Viewer)
* **Action:** Open `Event Viewer` (eventvwr.msc).
* **Path:** `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`.
* **Check:** Look for **Event ID 1 (Process Create)**. If the log is populating, the sensor is active.