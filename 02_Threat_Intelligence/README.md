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

### 1. [Splunk C2 Beacon Detection](./Splunk_C2_Hunt)
* **Scenario:** A compromised host is "beaconing" out to a Command & Control server.
* **Deliverable:** A Splunk Threat Hunt report identifying the heartbeat pattern and the malicious payload.
* **Status:** 📝 *Planned*

### 2. [Lateral Movement Investigation](./Lateral_Movement)
* **Scenario:** An attacker moving from the DMZ to the Internal Network.
* **Deliverable:** Tracing the attack path using Windows Event ID 4624 (Logon) and Sysmon Event ID 1 (Process Create).
* **Status:** 📝 *Planned*