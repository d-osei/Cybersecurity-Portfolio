# 🔹 Phase 1: Foundations of Analysis

![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Packet_&_Log_Analysis-blue?style=for-the-badge)

## 🎯 Objective
The goal of Phase 1 is to master the core technical skills required for a **Tier 1 SOC Analyst**. This phase focuses on "Ground Truth"—understanding what normal vs. malicious activity looks like at the packet and log level using the agents deployed in the Lab Infrastructure.

## 🛠️ Skills & Tools Matrix

| Domain | Skill to Master | Lab Component | Tool Stack |
| :--- | :--- | :--- | :--- |
| **Network Forensics** | Deep packet inspection, handshake analysis | **Kali-Attacker** | ![Wireshark](https://img.shields.io/badge/-Wireshark-grey?logo=wireshark) ![TCPDump](https://img.shields.io/badge/-TCPDump-grey?logo=gnu-bash) |
| **Linux Forensics** | SSH Brute Force analysis, parsing `auth.log` | **Ubuntu-Splunk** | ![Linux](https://img.shields.io/badge/-Linux_CLI-grey?logo=linux) ![Bash](https://img.shields.io/badge/-Bash-grey?logo=gnu-bash) |
| **Endpoint Telemetry** | Process creation analysis & Log Shipping | **Win11-Victim** | ![Sysmon](https://img.shields.io/badge/-Sysmon-grey?logo=windows) ![Splunk](https://img.shields.io/badge/-Universal_Forwarder-black?logo=splunk) |

## 🧠 Experience Gained
* **The "Why" behind the Alert:** Validating IDS alerts by capturing raw PCAPs on the `Kali-Attacker` interface.
* **Log Navigation:** Manually extracting attacker IPs from the `Ubuntu-Splunk` server's `/var/log/auth.log` before ingesting them into a SIEM.
* **Log Pipeline Architecture:** Understanding how **Sysmon** events are generated on `Win11-Victim`, processed by the **Universal Forwarder**, and shipped to `Ubuntu-Splunk` for indexing.

## 📂 Project Modules

### 1. [SYN Flood Attack Analysis](./Network_Traffic_Analysis)
* **Infrastructure:** `Kali-Attacker` (Source) ➔ `Ubuntu-Splunk` (Target).
* **Scenario:** Simulating a DoS attack using `hping3` to overwhelm the target's network stack.
* **Deliverable:** A Wireshark investigation identifying the TCP "Three-Way Handshake" violation and calculating the attack rate.
* **Status:** 🚧 *In Progress*

### 2. [SSH Brute Force Investigation](./Log_Analysis)
* **Infrastructure:** `Kali-Attacker` (Hydra) ➔ `Ubuntu-Splunk` (SSH Service).
* **Scenario:** A simulated credential stuffing attack against the Splunk server.
* **Deliverable:** Analysis of `/var/log/auth.log` using `grep` and `awk` to isolate the attacker's IP and frequency.
* **Status:** 📝 *Planned*