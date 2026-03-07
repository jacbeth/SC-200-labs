# Azure Sentinel SOC Lab – Initial Deployment \& Configuration

## Overview

The goal of Lab 1 is to establish a functional SIEM environment capable of ingesting logs, enabling detection logic, and preparing the foundation for threat hunting and incident response.

The Microsoft Defender portal (security.microsoft.com), where Sentinel now resides, was used.



## Environment Architecture

Platform: Microsoft Azure

SIEM: Microsoft Sentinel

Portal: Microsoft Defender (security.microsoft.com)

Log Analytics Workspace : LAW-security-labs

Region: UK South

Retention: 30 days



## Step 1 – Log Analytics Workspace Creation

Log Analytics Workspace is the central data repository for Sentinel.

LAW supports:

• 	Log ingestion

• 	KQL querying

• 	Analytics rule evaluation

• 	Threat hunting

## Step 2 – Microsoft Sentinel Deployment

Microsoft Sentinel was enabled on the Log Analytics Workspace, creating a SIEM that can accomplish the following: ingest logs, threat detection, threat hunting, incident management, visualisation and automation (SOAR).

## Step 3 – Data Connector Configuration

The following data connectors were successfully connected and verified:

* Azure Activity
* Microsoft Entra ID
* Microsoft Defender for Endpoint
* Microsoft Defender for Identity
* Microsoft Defender XDR
* Microsoft Defender for Cloud Apps
* Microsoft Defender for Office 365

## Verification

* All connectors show as Connected
* Sign‑in logs and audit logs confirmed in Log Analytics
* Azure Activity logs successfully ingested

## Step 4 – Content Hub Installation

Detection content was installed from the Content Hub in the Defender portal, which populated the Analytics Rule Templates section.

Installed solutions include:

* Microsoft Entra ID
* Microsoft Defender for Identity
* Microsoft Defender XDR
* Microsoft 365 security content
* Azure Activity content

### Detection Coverage

146 Analytics Rule Templates available

## Step 5 -Analytical rules configuration

NB: Templates do not generate incidents until they are converted into active rules.

### Rules enabled

* Multiple failed sign in attempts
* Identity-based detections
* Azure role monitoring
* MFA anomaly detection
* Impossible travel detection
* Suspicious sign-in behaviour rules
* Threat intelligence-based rules



(Currently  resource level diagnostic settings disabled as they are mainly used for Azure resource logs (VMs, Key Vault, Storage, etc.).  Log Analytics Workspace is receiving logs from data connectors e.g. Azure Activity which go to Sentinel.)



## Step 6 — Access Control (RBAC)

Role‑based access control was configured to support realistic SOC operations:



• 	Sentinel Contributor
• 	Log Analytics Reader
• 	Security Reader


This ensures analysts can investigate incidents without requiring full administrative access.



## Step 7 — Workspace Health Validation

KQL queries were used to confirm ingestion health:



union SigninLogs, AuditLogs, AzureActivity
| summarize LastEvent=max(TimeGenerated) by Type



This verifies that all connected data sources are actively sending logs.



## Results

* Enabled detection logic
* Generated malicious behaviour
* Caused Sentinel to detect it
* 

## Lessons Learned

* Data connectors must be configured before rule templates appear.
* Content Hub installation is required to populate detection logic.
* Microsoft Sentinel has transitioned from Azure Portal to Microsoft Defender portal.
