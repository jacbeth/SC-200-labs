\# Azure Sentinel SOC Lab – Initial Deployment \& Configuration

\## Overview



This project documents the deployment and configuration of a Microsoft Sentinel (SIEM) lab environment using the Microsoft Defender portal. The goal is to simulate a  Security Operations Center (SOC) environment 



\## Environment Architecture



Platform: Microsoft Azure

SIEM: Microsoft Sentinel

Portal: Microsoft Defender (security.microsoft.com)

Workspace Name: law-security-labs



\## Step 1 – Log Analytics Workspace Creation



A Log Analytics Workspace was created to ingest data and was connected to Microsoft Sentinel



\## Step 2 – Microsoft Sentinel Deployment



Microsoft Sentinel was enabled on the Log Analytics Workspace, creating a SIEM that can accomplish the following: ingest logs, threat detection, threat hunting, incident management and automation.



\## Step 3 – Data Connector Configuration



The following data connectors were successfully connected and verified:



* Azure Activity



* Microsoft Entra ID (formerly Azure AD)



* Microsoft Defender for Endpoint



* Microsoft Defender for Identity



* Microsoft Defender XDR



* Microsoft Defender for Cloud Apps



* Microsoft Defender for Office 365



* Microsoft 365 Insider Risk Management



* Microsoft Entra ID Protection



\## Verification



All connectors show as connected and siign-in logs and audit logs confirmed in Log Analytics



\## Step 4 – Content Hub Installation



After connectors were configured, detection content was installed from the Content Hub in the Defender portal, which populated the Analytics Rule Templates section.



Installed solutions include:



* Microsoft Entra ID



* Microsoft Defender for Identity



* Microsoft Defender XDR



* Microsoft 365 security content



* Azure Activity content



\## Current Detection Coverage



146 Analytics Rule Templates available, confirming a properly configured  SIEM environment



* Identity-based detections



* Azure role monitoring



* MFA anomaly detection



* Impossible travel detection



* Suspicious sign-in behaviour rules



* Threat intelligence-based rules



\## Lessons Learned



Data connectors must be configured before rule templates appear.



Content Hub installation is required to populate detection logic.



Microsoft Sentinel has transitioned from Azure Portal to Microsoft Defender portal.



Identity-related content is distributed across multiple solutions (Entra ID, Defender for Identity, Defender XDR).





