# 🛡️ Cybersecurity Portfolio

![Phase 1](https://img.shields.io/badge/Phase_1-Foundations-blue?style=for-the-badge&logo=security-scorecard&logoColor=white)
![Phase 2](https://img.shields.io/badge/Phase_2-Threat_Intelligence-red?style=for-the-badge&logo=splunk&logoColor=white)
![Phase 3](https://img.shields.io/badge/Phase_3-AI_&_Automation-success?style=for-the-badge&logo=python&logoColor=white)

## 📖 Overview
Welcome to my primary project repository. This collection documents my progression from foundational SOC analysis to advanced Threat Hunting and AI-driven security automation.

All projects here are conducted in a **Home Lab Environment** (Dell AIO / VMware ESXi) using real-world datasets and simulated attack scenarios.

---

## 🏗️ Project Structure

This repository is organized into three distinct evolutionary phases:

### 🔹 [Phase 1: Foundations](/01_Foundations)
*Focus: The core skills of a Tier 1/Tier 2 SOC Analyst.*
* **Network Traffic Analysis:** Packet capture analysis using Wireshark and TCPDump (e.g., SYN Flood investigations).
* **Log Analysis:** Linux forensics (`auth.log`, `syslog`) and Windows Event Log review.
* **Core Skills:** PCAP analysis, OSI Model application, basic anomaly detection.

### 🔸 [Phase 2: Threat Intelligence](/02_Threat_Intelligence)
*Focus: Proactive detection and the "Art of Investigation."*
* **SIEM Operations:** End-to-end log ingestion and querying in **Splunk**.
* **Threat Hunting:** Hypothesis-driven hunts for C2 beacons, lateral movement, and persistence mechanisms.
* **Frameworks:** Mapping detections to **MITRE ATT&CK** TTPs.

### 🚀 [Phase 3: AI & Automation](/03_AI_Automation)
*Focus: Scaling analysis with Code and Logic.*
* **Data Science for Security:** Using **JupyterLabs**, **Pandas**, and **Matplotlib** to visualize large security datasets.
* **Probabilistic Triage:** Applying Bayesian logic to reduce alert fatigue and calculate false positive rates.
* **Automation:** Python scripts for log parsing and enrichment.

---

## 🌟 Featured Projects

| Project Name | Tech Stack | Type | Status |
| :--- | :--- | :--- | :--- |
| **SYN Flood Analysis** | Wireshark, Python | Traffic Analysis | ✅ Complete |
| **Splunk C2 Hunt** | Splunk, Sysmon | Threat Hunting | 🚧 In Progress |
| **Bayesian Alert Triage** | Jupyter, Pandas | Data Science | 📝 Planned |

---

## ⚙️ Lab Infrastructure used in this Repo

* **Hypervisor:** VMware ESXi 7.0
* **Analysis:** Splunk Enterprise (Free License), JupyterHub
* **Targets:** Metasploitable, Windows 10, Ubuntu Server

---

## ⚠️ Disclaimer
*These projects are for educational and defensive purposes only. All attacks are simulated in a closed, isolated sandbox environment.*
