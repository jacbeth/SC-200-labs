# Lab 3 – Azure Threat Detection (StorageBlobLogs + AzureActivity)

---

## 📝 Overview
Azure Storage is a high‑value target for attackers due to its use for backups, logs, application data, and sensitive files.  
This lab focuses on identifying suspicious access patterns within Azure Storage accounts using **Microsoft Sentinel** and **KQL**.

The goal is to simulate threat detection work by analysing blob access logs, identifying anomalies, and mapping detections to MITRE ATT&CK.

---

## 📡 Data Sources
This lab primarily uses:

### **StorageBlobLogs**
Operational logs for blob access, including:
- Blob downloads (GetBlob)  
- Blob deletions (DeleteBlob)  
- Authentication type (Key, OAuth, SAS)  
- Caller IP address  
- URI and container information  

### **AzureActivity**
Control‑plane operations such as:
- SAS token creation  
- Storage account key regeneration  
- Network rule changes  
- Role assignments and permission changes  

These events are essential for detecting attacker attempts to weaken storage security or establish persistence.

---

## 🔍 Detection 1 — Repeated Blob Downloads from the Same IP
```kql
StorageBlobLogs
| where OperationName == "GetBlob"
| summarize DownloadCount = count() by CallerIpAddress, bin(TimeGenerated, 15m)
| where DownloadCount > 25
| sort by DownloadCount desc
```

## Why this matters
Repeated downloads from a single IP may indicate:

- Automated scripts
- Credential misuse
- Early‑stage data exfiltration


## MITRE ATT&CK:

Exfiltration (TA0010)

Exfiltration Over Web Services (T1567)

## 🔍 Detection 2 — Blob Access from Unusual or Non‑Corporate IP Ranges

```kql
StorageBlobLogs
| where OperationName == "GetBlob"
| where CallerIpAddress !startswith "192.168."
    and CallerIpAddress !startswith "10."
    and CallerIpAddress !startswith "172.16."
| summarize AccessCount = count() by CallerIpAddress, bin(TimeGenerated, 1h)
| where AccessCount > 0
``` 

## Why this matters
Unexpected IPs may indicate:

- Credential compromise
- SAS token leakage
- External reconnaissance

## MITRE ATT&CK:

Initial Access (TA0001)

Valid Accounts (T1078)

## 🔍 Detection 3 — Blob Access Using SAS TokensStorageBlobLogs
```kql 
StorageAzureBlobbs
| where AuthenticationType == "SAS"
| summarize SASAccessCount = count(), Blobs = make_set(Uri, 5)
    by CallerIpAddress, bin(TimeGenerated, 1h)
```

## Why this matters

SAS tokens are powerful and dangerous:

- They bypass credentials
- They grant scoped access
- If leaked, they enable silent data access

## MITRE ATT&CK:

Defense Evasion (TA0005)

Use of Credentials (T1550)

## 🔍 Detection 4 — Blob Deletions (DeleteBlob)

```kql 
StorageBlobLogs
| where OperationName == "DeleteBlob"
| summarize DeleteCount = count(), DeletedBlobs = make_set(Uri, 10)
    by CallerIpAddress, bin(TimeGenerated, 1h)
```

## Why this matters
Blob deletions may indicate:

- Cleanup after data theft
- Malicious tampering
- Attempts to hide activity

## MITRE ATT&CK:

Impact (TA0040)

Data Destruction (T1485)

## 📌 Findings

- Repeated downloads from a single IP
- SAS token usage from a public IP
- Blob deletions performed by a test account
- Control‑plane activity visible in AzureActivity

These behaviours clearly distinguish normal vs suspicious access patterns.

## 🎓 Learning Outcomes

- Analysing Azure Storage access logs
- Building behavioural detections using KQL
- Mapping detections to MITRE ATT&CK
- Understanding blob access patterns and risks
- Documenting detections in a SOC‑ready format

## 🪞 Reflection
This lab strengthened my understanding of cloud storage attack surfaces and the importance of monitoring both data‑plane and control‑plane activity. Even small anomalies — such as repeated downloads or unexpected IPs — can be early indicators of compromise.