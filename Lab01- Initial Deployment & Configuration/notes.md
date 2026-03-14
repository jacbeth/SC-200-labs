# Notes – Microsoft Sentinel Deployment & Initial Configuration

## 1. Platform Transition
Microsoft Sentinel is now managed through the **Microsoft Defender portal** rather than exclusively through the Azure portal.  
This reflects Microsoft’s shift toward a unified security operations platform that consolidates SIEM, XDR, and identity telemetry.

---

## 2. Data Connectors & Log Ingestion
Security data ingestion relies on configuring **data connectors** that send logs directly to the Log Analytics Workspace (LAW).

Identity and security sources such as:
- Microsoft Entra ID  
- Microsoft Defender XDR  
- Azure Activity  

…send logs **natively** to the workspace and do **not** require resource‑level diagnostic settings.

---

## 3. Diagnostic Settings
Diagnostic settings were **not enabled** in this lab because the primary data sources were identity and Defender telemetry.

Diagnostic settings are typically required for Azure resource logs such as:
- Virtual machines  
- Storage accounts  
- Azure Key Vault  
- Network security devices  

These resources send logs to LAW via diagnostic pipelines.

---

## 4. Analytics Rule Templates
Installing security solutions from the **Content Hub** populates the Analytics Rule Templates section.

Important note:
- Templates **do not generate alerts** until converted into **active analytics rules**.

---

## 5. RBAC Configuration
Role‑based access control was configured to support **least‑privilege access** for SOC analysts.

Roles assigned:
- **Sentinel Contributor** – manage detection and incident workflows  
- **Log Analytics Reader** – query and analyse logs  
- **Security Reader** – view alerts and security posture  

### Elevated Access Warning
Azure displayed a notification indicating that **elevated access** had been enabled at the tenant level.  
This occurs when administrators temporarily enable root‑level permissions to assign roles.  
The permission can be disabled once configuration is complete.

---

## 6. Log Ingestion Validation
Log ingestion was validated using KQL queries in the workspace.

Example query:
```kql
union SigninLogs, AuditLogs, AzureActivity
| summarize LastEvent = max(TimeGenerated) by Type
