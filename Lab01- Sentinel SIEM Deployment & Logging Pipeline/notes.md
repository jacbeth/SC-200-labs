## Sentinel SIEM Deployment & Azure Logging Pipeline

### 🔧 Log Analytics Workspace Creation
The Log Analytics Workspace serves as the central data repository for Sentinel.

LAW supports:
- Log ingestion  
- KQL querying  
- Analytics rule evaluation  
- Threat hunting  
#### Screenshot showing Log Analytics Workspace
![law](./screenshots/1-log-analytics-workspace.png)

---

### 🛡️ Microsoft Sentinel Deployment

#### Screenshot - Sentinel enabled on LAW
![sentinel](./screenshots/2-Microsoft-Sentinel-enabled.png)

---

### 🔌 Data Connector Configuration
The following connectors were successfully configured and verified:

- Azure Activity  
- Microsoft Entra ID   
- Microsoft Defender for Office 365  

#### Screenshot - data connectors configured
![data_connectors](./screenshots/3-Data_connectors.png)

#### Screenshot - Sign‑in and audit logs in LAW 
![signin](./screenshots/4-log-verification-kql.png)
 
---

## 📦 Content Hub Installation
Detection content was installed from the Content Hub, populating the **Analytics Rule Templates** section.
#### Screenshot - Content Hub Installed
![contenthub](./screenshots/5-content-hub-installed.png)

#### Screenshot -  146 analytics rule templates available
![rulesavailable](./screenshots/6-analytics-rule-templates.png)

---

### ⚠️ Analytics Rules Configuration
Templates do **not** generate incidents until converted into **active rules**.

Rules enabled:
- Multiple failed sign‑in attempts  
- Identity‑based detections  
- Azure role monitoring  
- MFA anomaly detection  
- Impossible travel  
- Suspicious sign‑in behaviour  
- Threat intelligence‑based rules  

#### Screenshot -  Analytical Rules
![rulescreated](./screenshots/7- Analytic_rule_creation.png)

---

### 🔐 Access Control (RBAC)
Least‑privilege access was configured on the workspace.

Roles assigned:
- **Sentinel Contributor**  
- **Log Analytics Reader**  
- **Security Reader**  