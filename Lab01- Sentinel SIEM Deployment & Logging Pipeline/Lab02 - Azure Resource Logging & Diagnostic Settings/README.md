# 🌐 Lab 01 – Sentinel SIEM Deployment & Azure Logging Pipeline
## 📝 Overview
This lab establishes the core SIEM infrastructure for all future SOC operations.
It combines:

- Microsoft Sentinel deployment
- Log Analytics Workspace configuration
- Azure resource diagnostic logging
- Data connector onboarding
- Detection content installation
- Ingestion validation using KQL

The environment is deployed and managed through the Microsoft Defender portal (security.microsoft.com), reflecting Microsoft’s unified security operations platform. This lab forms the foundation for threat hunting, detection engineering, and incident response in later labs.

## 🧪 Environment Architecture
- Cloud: Microsoft Azure
- SIEM: Microsoft Sentinel
- Portal: Microsoft Defender
- Workspace: LAW‑Security‑labs
- Region: UK South
- Retention: 30 days

### Log Flow Architecture
Security Data Sources
(Microsoft Entra ID, Defender XDR, Azure Activity, Azure Resource Logs)
  ↓
Log Analytics Workspace (LAW‑Security‑labs)  
  ↓
Microsoft Sentinel  
  ↓
Analytics Rules → Incidents → SOC Investigation

## 🔧 Step 1 – Log Analytics Workspace Deployment
The Log Analytics Workspace (LAW) acts as the central repository for all security telemetry.

This enables: Log ingestion, KQL querying, Analytics rule evaluation, Threat hunting and Workbook visualisation

## 🛡️ Step 2 – Microsoft Sentinel Deployment
Sentinel was enabled on the workspace, activating SIEM capabilities including:

- Log ingestion
- Threat detection
- Threat hunting
- Incident management
- Automation (SOAR)
- Visualisation and dashboards

## 🔌 Step 3 – Data Connector Configuration
The following connectors were configured and verified as Connected:

### Identity & Security
- Microsoft Entra ID
- Microsoft Defender for Endpoint
- Microsoft Defender for Identity
- Microsoft Defender XDR
- Microsoft Defender for Cloud Apps
- Microsoft Defender for Office 365

### Cloud Activity
- Azure Activity Logs

### Verification
- Sign‑in logs visible in LAW
- Audit logs ingested
- Azure Activity logs confirmed

## 📡 Step 4 – Azure Resource Diagnostic Logging
Azure resources do not automatically forward logs to Sentinel.
Diagnostic settings were configured to forward platform logs to LAW.

### Enabled Resource Logs
Azure Storage – Blob Service Logs (StorageBlobLogs)
Captured telemetry includes:

- Blob uploads
- Blob downloads
- Blob deletions
- Client IP addresses
- Operation timestamps

This expands SOC visibility into potential:

- Data exfiltration
- Suspicious access patterns
- Abnormal download behaviour

Additional resources (Key Vault, NSGs, VMs) can be onboarded in future labs.

## 📦 Step 5 – Content Hub Installation
Detection content was installed from the Content Hub, populating the Analytics Rule Templates library.

Installed solutions include:

- Microsoft Entra ID
- Microsoft Defender for Identity
- Microsoft Defender XDR
- Microsoft 365 security content
- Azure Activity content

Detection Coverage:  146 analytics rule templates available.

## ⚠️ Step 6 – Analytics Rules Configuration
Templates do not generate incidents until converted into active rules.

Rules enabled:

- Multiple failed sign‑in attempts
- Identity‑based detections
- Azure role monitoring
- MFA anomaly detection
- Impossible travel
- Suspicious sign‑in behaviour
- Threat intelligence‑based detections

## 🔐 Step 7 – Access Control (RBAC)
Least‑privilege access was applied to the workspace and Sentinel.

Roles assigned:

- Sentinel Contributor
- Log Analytics Reader
- Security Reader

This ensures secure operational boundaries for SOC analysts.

## 📊 Step 8 – Workspace Health Validation
KQL query used to confirm ingestion across identity and cloud sources:

``` kql
union SigninLogs, AuditLogs, AzureActivity
| summarize LastEvent = max(TimeGenerated) by Type
Successful ingestion was confirmed for all configured sources.
```

## 🧠 Lessons Learned
- Diagnostic settings are required for Azure resource logs — connectors alone are not enough
- Content Hub installation is necessary before detection logic becomes available
- Sentinel management has transitioned to the Microsoft Defender portal

# 🎯 Outcome
This lab successfully deployed a fully operational SIEM with:

- Identity telemetry
- Cloud activity logs
- Azure resource logs
- Detection content
- Active analytics rules
- Verified ingestion
