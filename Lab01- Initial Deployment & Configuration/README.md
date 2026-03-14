
# 🌐 Sentinel Deployment & Configuration


---

## 📝 Overview
The goal of this lab is to deploy Microsoft Sentinel, configure log ingestion, enable detection logic, and establish the foundation for SOC operations including threat hunting and incident response.

Sentinel was deployed and managed through the **Microsoft Defender portal (security.microsoft.com)**, reflecting Microsoft’s unified security operations platform.

---

## 🧪 Environment Architecture
- **Platform:** Microsoft Azure  
- **SIEM:** Microsoft Sentinel  
- **Portal:** Microsoft Defender  
- **Log Analytics Workspace:** LAW‑Security‑labs  
- **Region:** UK South  
- **Retention:** 30 days  

### Log Flow
Security Data Sources  
(Microsoft Entra ID, Defender XDR, Azure Activity)  
  ↓  
**Log Analytics Workspace (LAW‑Security‑labs)**  
  ↓  
**Microsoft Sentinel**  
  ↓  
Analytics Rules → Incidents → SOC Investigation  

---

## 🔧 Step 1 – Log Analytics Workspace Creation
The Log Analytics Workspace serves as the central data repository for Sentinel.

LAW supports:
- Log ingestion  
- KQL querying  
- Analytics rule evaluation  
- Threat hunting  

---

## 🛡️ Step 2 – Microsoft Sentinel Deployment
Sentinel was enabled on the workspace, creating a SIEM capable of:
- Log ingestion  
- Threat detection  
- Threat hunting  
- Incident management  
- Visualisation  
- Automation (SOAR)  

---

## 🔌 Step 3 – Data Connector Configuration
The following connectors were successfully configured and verified:

- Azure Activity  
- Microsoft Entra ID  
- Microsoft Defender for Endpoint  
- Microsoft Defender for Identity  
- Microsoft Defender XDR  
- Microsoft Defender for Cloud Apps  
- Microsoft Defender for Office 365  

### Verification
- All connectors show **Connected**  
- Sign‑in and audit logs confirmed in LAW  
- Azure Activity logs successfully ingested  

---

## 📦 Step 4 – Content Hub Installation
Detection content was installed from the Content Hub, populating the **Analytics Rule Templates** section.

Installed solutions include:
- Microsoft Entra ID  
- Microsoft Defender for Identity  
- Microsoft Defender XDR  
- Microsoft 365 security content  
- Azure Activity content  

**Detection Coverage:** 146 analytics rule templates available.

---

## ⚠️ Step 5 – Analytics Rules Configuration
Templates do **not** generate incidents until converted into **active rules**.

Rules enabled:
- Multiple failed sign‑in attempts  
- Identity‑based detections  
- Azure role monitoring  
- MFA anomaly detection  
- Impossible travel  
- Suspicious sign‑in behaviour  
- Threat intelligence‑based rules  

---

## 🔐 Step 6 – Access Control (RBAC)
Least‑privilege access was configured on the workspace.

Roles assigned:
- **Sentinel Contributor**  
- **Log Analytics Reader**  
- **Security Reader**  

---

## 📊 Step 7 – Workspace Health Validation
KQL query used to validate ingestion:

```kql
union SigninLogs, AuditLogs, AzureActivity
| summarize LastEvent = max(TimeGenerated) by Type
```

---

## 🧠 Lessons Learned
- Data connectors must be configured before rule templates appear
- Content Hub installation is required for detection logic
- Sentinel management has transitioned to the Microsoft Defender portal

This lab establishes the core SIEM infrastructure for future detection engineering and incident response labs
