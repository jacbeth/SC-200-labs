# Lab 01 – Sentinel SIEM Deployment & Azure Logging Pipeline

## 📝 1. Platform Transition
Microsoft Sentinel is now managed through the Microsoft Defender portal reflecting Microsoft’s move toward a unified security operations platform, combining:

SIEM (Sentinel)
XDR (Defender)
Identity telemetry (Entra ID)
Cloud app telemetry (Defender for Cloud Apps)

Key takeaway:  
All Sentinel configuration, analytics rules, incidents, and data connectors are now accessed through security.microsoft.com.

## 🔌 2. Data Connectors & Log Ingestion
Sentinel ingests security telemetry through data connectors that send logs directly to the Log Analytics Workspace (LAW).

Identity & Security Connectors Used
Microsoft Entra ID

Microsoft Defender XDR

Microsoft Defender for Endpoint

Microsoft Defender for Identity

Microsoft Defender for Office 365

Microsoft Defender for Cloud Apps

Azure Activity

Important 
These sources send logs natively to LAW. They do not require diagnostic settings. Identity and Defender telemetry is high‑value SOC data and forms the backbone of most detection logic.

## 📡 3. Diagnostic Settings
Diagnostic settings were not enabled in this initial deployment because the lab focused on identity and Defender telemetry.

Diagnostic settings are required for Azure resource logs, such as:

Virtual Machines

Storage Accounts

Azure Key Vault

Network Security Groups

App Services

These logs flow through the Azure Monitor diagnostic pipeline into LAW.

Key takeaway:  
Identity logs ≠ diagnostic settings
Resource logs = diagnostic settings required

## 📦 4. Analytics Rule Templates
Installing security solutions from the Content Hub populates the Analytics Rule Templates library.

Important Notes
Templates do not generate alerts until converted into active analytics rules

Content Hub installation is required before templates appear

Solutions installed included:

Entra ID

Defender XDR

Defender for Identity

Microsoft 365 security

Azure Activity

Result:  
146 rule templates available for activation.

## 🔐 5. RBAC Configuration
Role‑based access control was configured to support least‑privilege SOC operations.

### Roles Assigned
- Sentinel Contributor – manage analytics rules, incidents, automation
- og Analytics Reader – query and analyse logs
- Security Reader – view alerts and security posture

Elevated Access Warning
Azure displayed a notification indicating that elevated access had been temporarily enabled at the tenant level.

This occurs when:

- Administrators elevate permissions to assign roles
- Privileged Identity Management (PIM) activates a role
- Tenant‑wide changes require higher privileges

NB:  Elevated access can be disabled once configuration is complete.

## 📊 6. Log Ingestion Validation
Log ingestion was validated using KQL queries in the Log Analytics Workspace.

```kql
union SigninLogs, AuditLogs, AzureActivity
| summarize LastEvent = max(TimeGenerated) by Type
```

### Outcome:  All configured data sources successfully ingested into LAW.

## 🧠 Summary of Key Learnings
- Sentinel is now part of the Microsoft Defender unified SOC platform
- Identity and Defender logs ingest natively without diagnostic settings
- Diagnostic settings are required for Azure resource logs
- Content Hub must be installed before analytics rules appear
- Analytics rule templates must be activated to generate incidents
- RBAC must follow least‑privilege principles
- KQL validation is essential to confirm ingestion