# Lab 2 – Azure Resource Logging & Diagnostic Settings

---

## 📝 Overview
The purpose of Lab 2 is to expand SOC visibility by enabling **resource‑level diagnostic logging** within Microsoft Azure.  
In Lab 1, telemetry was collected through identity and security connectors such as Microsoft Entra ID and Microsoft Defender XDR.  
While these connectors provide strong identity‑centric visibility, **Azure infrastructure services do not automatically forward logs** to Microsoft Sentinel.

To ingest these logs, **diagnostic settings must be configured at the resource level**.

This lab demonstrates how Azure platform logs are forwarded to a Log Analytics Workspace (LAW) where they can be queried, analysed, and used for detection and investigation.

---

## 🎯 Objectives
- Enable diagnostic logging on Azure resources  
- Forward infrastructure logs to the Log Analytics Workspace  
- Validate ingestion using KQL queries  
- Expand SOC visibility to include Azure platform activity  

---

## 🧪 Environment
- **Platform:** Microsoft Azure  
- **SIEM:** Microsoft Sentinel  
- **Workspace:** LAW‑Security‑labs  
- **Region:** UK South  

---

## 📡 Log Sources Enabled
The following Azure resource logs were configured and forwarded to the Log Analytics Workspace:

### **Azure Storage – Blob Service Logs (StorageBlobLogs)**  
These logs capture operations such as:
- Blob uploads  
- Blob downloads  
- Blob deletions  
- Client IP addresses  
- Operation timestamps  

This telemetry enables monitoring for suspicious file access patterns, including abnormal download activity or potential data exfiltration. Additional Azure resources such as **Key Vault**, **Virtual Machines**, and **Network Security Groups** can also be onboarded using diagnostic settings to expand infrastructure monitoring coverage.

---

## 🧠 Key Skills Demonstrated
- Azure monitoring configuration  
- Security telemetry ingestion  
- KQL‑based log validation  
- SOC visibility expansion across identity + infrastructure  

