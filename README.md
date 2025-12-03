# 🛡️ Cybersecurity Portfolio

![Phase 1](https://img.shields.io/badge/Phase_1-Foundations-blue?style=for-the-badge&logo=security-scorecard&logoColor=white)
![Phase 2](https://img.shields.io/badge/Phase_2-Threat_Intelligence-red?style=for-the-badge&logo=splunk&logoColor=white)
![Phase 3](https://img.shields.io/badge/Phase_3-AI_&_Automation-success?style=for-the-badge&logo=python&logoColor=white)

## 📖 Overview
Welcome to my primary project repository. This collection documents my progression from foundational SOC analysis to advanced Threat Hunting and AI-driven security automation.

---

## 🏗️ Lab Infrastructure
Before diving into the projects, view the **Client-Server Architecture** used to build this cyber range.
👉 **[View the Full Lab Documentation](./00_Lab_Infrastructure/README.md)**

* **Server:** Dell OptiPlex 7440 AIO (ESXi 8.0 Type-1 Hypervisor)
* **Storage:** 2TB Dedicated Datastore for VMs
* **Management:** MacBook Pro M2 (via Static IP `10.0.0.10`)

---

## 📂 Project Structure

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
| **[Lab Setup & Architecture](./00_Lab_Infrastructure/README.md)** | VMware ESXi, Dell AIO | Infrastructure | ✅ Complete |
| **SYN Flood Analysis** | Wireshark, Python | Traffic Analysis | 🚧 In Progress |
| **Splunk C2 Hunt** | Splunk, Sysmon | Threat Hunting | 📝 Planned |

---

## ⚠️ Disclaimer
*These projects are for educational and defensive purposes only. All attacks are simulated in a closed, isolated sandbox environment.*
