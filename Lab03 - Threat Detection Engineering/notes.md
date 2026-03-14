
---

## 📓 Lab 3: Threat Detection Notes 

These notes document the execution of Lab 3, including screenshots, observations, and commentary.

---

## 1. Environment Setup & Log Generation

### Actions Performed
- Uploaded several test blobs  
- Repeatedly downloaded the same blob (10–30 times)  
- Generated a SAS token and accessed blobs using SAS  
- Deleted blobs to generate DeleteBlob events  

**Important:**  
StorageBlobLogs only populate when real blob operations occur.  
AzureActivity logs provide context around SAS creation, key regeneration, RBAC changes, etc.

---

## 2. Verification of Log Ingestion

### Queries Run
```kql
StorageBlobLogs
| limit 10
```

```kql
AzureActivity
| limit 10
```

## Screenshots
StorageBlobLogs verification

AzureActivity verification

Both tables appeared in the workspace, confirming the environment was ready for detection engineering.

3. Detection 1 — Repeated Blob Downloads
Detects repeated blob downloads from the same IP within a 15‑minute window.

## Findings:  
IP 92.40.169.163 exceeded the threshold — expected due to simulated activity.

## Commentary:  
A sudden spike in blob downloads is a classic early indicator of data harvesting.

## MITRE:

Exfiltration (TA0010)

Exfiltration Over Web Services (T1567)

## 4. Detection 2 — Blob Access from Unusual IP Ranges
Detects blob access from non‑private IP ranges.

## Findings:  
External IPs 92.40.169.164 and 195.149.13.240 accessed blobs — expected from home network testing.

## Commentary:  
Unexpected IPs may indicate credential compromise or SAS token leakage.

## MITRE:

Initial Access (TA0001)

Valid Accounts (T1078)

5. Detection 3 — Blob Access Using SAS Tokens
Identifies blob access authenticated using SAS tokens.

## Findings:

- SAS activity originated from a single public IP
- Access counts ranged from 1 to 65 per hour
- Container listing operations confirmed SAS enumeration capability

## Commentary:  
SAS tokens are powerful and risky — any unexpected usage should be treated as a potential incident.

## MITRE:

Defense Evasion (TA0005)

Use of Credentials (T1550)

## 6. Detection 4 — Blob Deletions
Detects blob deletions, which may indicate destructive behaviour.

## Findings:

- DeleteBlob events captured successfully
- Deleted blobs still generated log entries
- SAS URLs returned 404 after deletion

## Commentary:  
All deletions were controlled and expected — no signs of mass deletion or unauthorised access.

## MITRE:

Impact (TA0040)

Data Destruction (T1485)

## 7. Summary
This lab validated:

- StorageBlobLogs ingestion
- AzureActivity ingestion
- Behavioural detections for blob access
- MITRE‑aligned threat detection logic


