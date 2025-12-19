# 🔸 Phase 2: Threat Intelligence & Hunting

![Status](https://img.shields.io/badge/Status-Planned-orange?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-SIEM_&_MITRE-red?style=for-the-badge)

## 🎯 Objective
The goal of Phase 2 is to advance to **Tier 2/3 Analyst** capabilities. Moving beyond individual packets, this phase focuses on correlating events across the enterprise using a SIEM and proactively hunting for threats that evade standard signatures.

## 🛠️ Skills & Tools Matrix

| Domain | Skill to Master | Tool Stack |
| :--- | :--- | :--- |
| **SIEM Operations** | Data ingestion, SPL (Search Processing Language), Dashboarding | ![Splunk](https://img.shields.io/badge/-Splunk-grey?logo=splunk) ![ELK](https://img.shields.io/badge/-ELK_Stack-grey?logo=elastic) |
| **Threat Hunting** | Hypothesis-driven investigation, detecting "Low and Slow" attacks | ![MITRE](https://img.shields.io/badge/-MITRE_ATT&CK-grey?logo=target) |
| **Endpoint Visibility** | Analyzing process creation and registry modification | ![Sysmon](https://img.shields.io/badge/-Sysmon-grey?logo=windows) |

## 🧠 Experience Gained
* **Contextual Awareness:** Correlating a network connection with a process execution (e.g., "Why did `powershell.exe` connect to a Russian IP?").
* **Framework Application:** Mapping observed behaviors to specific **MITRE ATT&CK** TTPs (e.g., T1059 Command and Scripting Interpreter).
* **Detection Engineering:** Writing custom detection rules (Snort/YARA/Splunk Alerts) to catch future occurrences.

## 📂 Project Modules

### 1. [Incident Response Case Study: "I'm Really Not Batman" (Botsv1)](./Threat-Hunting-BOTSv1/Incident-Report.md)
* **Scenario:** A corporate web server (`imreallynotbatman.com`) is targeted by an adversary. The attack escalates from automated reconnaissance and brute-force credential theft to the installation of a PHP web shell and the execution of a Trojanized binary for website defacement.
* **Deliverable:** A comprehensive incident report mapped to the **MITRE ATT&CK** framework, featuring **Splunk SPL** queries for detection across Network (Suricata), Web (Stream:HTTP), and Endpoint (Sysmon) logs.
* **Status:** Completed

### 2. [Lateral Movement Investigation](./)
* **Scenario:** An attacker moving from the DMZ to the Internal Network.
* **Deliverable:** Tracing the attack path using Windows Event ID 4624 (Logon) and Sysmon Event ID 1 (Process Create).
* **Status:** Planned
