# Sentinel SIEM Deployment & Azure Logging Pipeline

## 🔧 Log Analytics Workspace Creation
The Log Analytics Workspace serves as the central data repository for Sentinel.

LAW supports:
- Log ingestion  
- KQL querying  
- Analytics rule evaluation  
- Threat hunting  
### Screenshot showing Log Analytics Workspace
![law](./screenshots/1-log-analytics-workspace.png)

---

## 🛡️ Microsoft Sentinel Deployment

### Screenshot - Sentinel enabled on LAW
![sentinel](./screenshots/2-Microsoft-Sentinel-enabled.png)

---

## 🔌 Data Connector Configuration
The following connectors were successfully configured and verified:

- Azure Activity  
- Microsoft Entra ID   
- Microsoft Defender for Office 365  

### Screenshot - data connectors configured
![data_connectors](./screenshots/3-Data_connectors.png)

- Sign‑in and audit logs confirmed in LAW  
- Azure Activity logs successfully ingested  



---

## 📦 Content Hub Installation
Detection content was installed from the Content Hub, populating the **Analytics Rule Templates** section.

Installed solutions include:
- Microsoft Entra ID  
- Microsoft Defender for Identity  
- Microsoft Defender XDR  
- Microsoft 365 security content  
- Azure Activity content  

**Detection Coverage:** 146 analytics rule templates available.

---

## ⚠️ Analytics Rules Configuration
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

## 🔐 Access Control (RBAC)
Least‑privilege access was configured on the workspace.

Roles assigned:
- **Sentinel Contributor**  
- **Log Analytics Reader**  
- **Security Reader**  

---

#